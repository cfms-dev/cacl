import { styleTags, tags as t } from "@lezer/highlight";

/**
 * Semantic highlighting tag mapping for the CACL Lezer parse tree.
 */
export const caclHighlighting = styleTags({
  "allow deny to when": t.controlKeyword,
  inherit: t.definitionKeyword,
  "ScopeClause/on from until remark": t.keyword,
  "InheritState/on InheritState/off": t.bool,
  "self dirs docs all": t.typeName,
  "and or not": t.operatorKeyword,
  any: t.atom,
  "PrincipalKind PermKind": t.function(t.variableName),
  PresetMacro: t.macroName,
  AtomicOp: t.constant(t.name),
  "OpIdent/UpperIdent": t.variableName,
  "OpSub/-": t.arithmeticOperator,
  "ValidFrom/String ValidUntil/String": t.special(t.string),
  String: t.string,
  Comment: t.lineComment,
  "[ ]": t.squareBracket,
  "( )": t.paren,
  ", ;": t.separator,
});
