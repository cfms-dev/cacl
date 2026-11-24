import logging
from importlib.metadata import PackageNotFoundError, version as pkg_version
from typing import Any

from lsprotocol import types
from pygls.lsp.server import LanguageServer

from .analysis import DocumentState, ServerSettings, analyze_document
from .code_actions import get_code_actions
from .completion import get_completions
from .diagnostics import to_lsp_diagnostics
from .formatting import format_document
from .hover import get_hover
from .inlay_hints import get_inlay_hints
from .semantic_tokens import SEMANTIC_TOKEN_LEGEND, get_semantic_tokens
from .symbols import get_document_symbols, get_folding_ranges

logger = logging.getLogger(__name__)


def get_server_version() -> str:
    try:
        return pkg_version("cacl-lsp")
    except PackageNotFoundError:
        return "0.1.0"


class CaclLanguageServer(LanguageServer):
    """Language Server for CFMS Access Control Language (CACL / CEP 2)."""

    def __init__(self) -> None:
        super().__init__(name="cacl-lsp", version=get_server_version())
        self.settings: ServerSettings = ServerSettings()
        self._doc_states: dict[str, DocumentState] = {}

    def analyze_and_cache(
        self,
        uri: str,
        source: str,
        version: int | None = None,
    ) -> DocumentState:
        state = analyze_document(
            uri=uri,
            source=source,
            version=version,
            settings=self.settings,
        )
        self._doc_states[uri] = state
        return state

    def get_state(self, uri: str) -> DocumentState | None:
        doc = self.workspace.get_text_document(uri)
        cached = self._doc_states.get(uri)
        if cached is not None and cached.source == doc.source and cached.version == doc.version:
            return cached
        return self.analyze_and_cache(doc.uri, doc.source, doc.version)

    def publish_state_diagnostics(self, state: DocumentState) -> None:
        self.text_document_publish_diagnostics(
            types.PublishDiagnosticsParams(
                uri=state.uri,
                version=state.version,
                diagnostics=to_lsp_diagnostics(state),
            )
        )

    def revalidate_all_open_documents(self) -> None:
        for uri, doc in list(self.workspace.text_documents.items()):
            state = self.analyze_and_cache(uri, doc.source, doc.version)
            self.publish_state_diagnostics(state)

    def drop_document(self, uri: str) -> None:
        self._doc_states.pop(uri, None)
        self.text_document_publish_diagnostics(
            types.PublishDiagnosticsParams(uri=uri, diagnostics=[])
        )

    def apply_raw_settings(self, raw: Any) -> None:
        if isinstance(raw, dict) and "cacl" in raw and isinstance(raw["cacl"], dict):
            raw = raw["cacl"]
        self.settings = ServerSettings.from_vscode_config(raw)


def create_server() -> CaclLanguageServer:
    ls = CaclLanguageServer()

    async def _pull_configuration() -> None:
        caps = ls.client_capabilities
        if not (caps and caps.workspace and caps.workspace.configuration):
            return
        try:
            result = await ls.workspace_configuration_async(
                types.ConfigurationParams(
                    items=[types.ConfigurationItem(section="cacl")]
                )
            )
        except Exception:
            logger.debug("Failed to pull workspace configuration", exc_info=True)
            return
        if result:
            ls.apply_raw_settings(result[0])
            ls.revalidate_all_open_documents()

    @ls.feature(types.INITIALIZED)
    async def on_initialized(_params: types.InitializedParams) -> None:
        await _pull_configuration()

    @ls.feature(types.WORKSPACE_DID_CHANGE_CONFIGURATION)
    async def on_did_change_configuration(
        params: types.DidChangeConfigurationParams,
    ) -> None:
        if params.settings is not None:
            ls.apply_raw_settings(params.settings)
            ls.revalidate_all_open_documents()
        else:
            await _pull_configuration()

    @ls.feature(types.TEXT_DOCUMENT_DID_OPEN)
    def on_did_open(params: types.DidOpenTextDocumentParams) -> None:
        td = params.text_document
        state = ls.analyze_and_cache(td.uri, td.text, td.version)
        ls.publish_state_diagnostics(state)

    @ls.feature(types.TEXT_DOCUMENT_DID_CHANGE)
    def on_did_change(params: types.DidChangeTextDocumentParams) -> None:
        doc = ls.workspace.get_text_document(params.text_document.uri)
        state = ls.analyze_and_cache(doc.uri, doc.source, doc.version)
        ls.publish_state_diagnostics(state)

    @ls.feature(types.TEXT_DOCUMENT_DID_SAVE)
    def on_did_save(params: types.DidSaveTextDocumentParams) -> None:
        doc = ls.workspace.get_text_document(params.text_document.uri)
        state = ls.analyze_and_cache(doc.uri, doc.source, doc.version)
        ls.publish_state_diagnostics(state)

    @ls.feature(types.TEXT_DOCUMENT_DID_CLOSE)
    def on_did_close(params: types.DidCloseTextDocumentParams) -> None:
        ls.drop_document(params.text_document.uri)

    @ls.feature(
        types.TEXT_DOCUMENT_COMPLETION,
        types.CompletionOptions(trigger_characters=["[", ",", "-", " ", '"', "("]),
    )
    def on_completion(params: types.CompletionParams) -> types.CompletionList:
        state = ls.get_state(params.text_document.uri)
        if state is None:
            return types.CompletionList(is_incomplete=False, items=[])
        return get_completions(state, params.position)

    @ls.feature(types.TEXT_DOCUMENT_HOVER)
    def on_hover(params: types.HoverParams) -> types.Hover | None:
        state = ls.get_state(params.text_document.uri)
        if state is None:
            return None
        return get_hover(state, params.position)

    @ls.feature(types.TEXT_DOCUMENT_FORMATTING)
    def on_formatting(
        params: types.DocumentFormattingParams,
    ) -> list[types.TextEdit] | None:
        state = ls.get_state(params.text_document.uri)
        if state is None:
            return None
        return format_document(state, ls.settings)

    @ls.feature(
        types.TEXT_DOCUMENT_CODE_ACTION,
        types.CodeActionOptions(
            code_action_kinds=[
                types.CodeActionKind.QuickFix,
                types.CodeActionKind.RefactorRewrite,
            ]
        ),
    )
    def on_code_action(params: types.CodeActionParams) -> list[types.CodeAction]:
        state = ls.get_state(params.text_document.uri)
        if state is None:
            return []
        return get_code_actions(state, params)

    @ls.feature(types.TEXT_DOCUMENT_INLAY_HINT)
    def on_inlay_hint(params: types.InlayHintParams) -> list[types.InlayHint]:
        state = ls.get_state(params.text_document.uri)
        if state is None:
            return []
        return get_inlay_hints(state, params, ls.settings)

    @ls.feature(types.TEXT_DOCUMENT_DOCUMENT_SYMBOL)
    def on_document_symbol(
        params: types.DocumentSymbolParams,
    ) -> list[types.DocumentSymbol]:
        state = ls.get_state(params.text_document.uri)
        if state is None:
            return []
        return get_document_symbols(state)

    @ls.feature(types.TEXT_DOCUMENT_FOLDING_RANGE)
    def on_folding_range(
        params: types.FoldingRangeParams,
    ) -> list[types.FoldingRange]:
        state = ls.get_state(params.text_document.uri)
        if state is None:
            return []
        return get_folding_ranges(state)

    @ls.feature(
        types.TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
        SEMANTIC_TOKEN_LEGEND,
    )
    def on_semantic_tokens_full(
        params: types.SemanticTokensParams,
    ) -> types.SemanticTokens:
        state = ls.get_state(params.text_document.uri)
        if state is None:
            return types.SemanticTokens(data=[])
        return get_semantic_tokens(state)

    return ls
