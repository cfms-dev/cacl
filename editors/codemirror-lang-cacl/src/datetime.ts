const RFC3339_RE =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|([+-])(\d{2}):(\d{2}))$/;

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysInMonth(year: number, month: number): number {
  switch (month) {
    case 2:
      return isLeapYear(year) ? 29 : 28;
    case 4:
    case 6:
    case 9:
    case 11:
      return 30;
    default:
      return 31;
  }
}

/**
 * Strictly parse a timezone-aware RFC 3339 timestamp into UTC epoch microseconds (bigint).
 * Rejects calendar rollovers (e.g. Feb 30) and timestamps missing timezone offsets.
 */
export function parseRfc3339UtcUs(raw: string): bigint | null {
  const match = RFC3339_RE.exec(raw);
  if (!match) {
    return null;
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const fracRaw = match[7] ?? "";
  const tzToken = match[8];

  if (month < 1 || month > 12) return null;
  if (day < 1 || day > daysInMonth(year, month)) return null;
  if (hour < 0 || hour > 23) return null;
  if (minute < 0 || minute > 59) return null;
  if (second < 0 || second > 59) return null;

  let offsetSeconds = 0;
  if (tzToken !== "Z" && tzToken !== "z") {
    const sign = match[9] === "-" ? -1 : 1;
    const tzHour = Number(match[10]);
    const tzMinute = Number(match[11]);
    if (tzHour < 0 || tzHour > 23 || tzMinute < 0 || tzMinute > 59) {
      return null;
    }
    offsetSeconds = sign * (tzHour * 3600 + tzMinute * 60);
  }

  // Truncate sub-microsecond digits to match Python datetime microsecond precision
  const fracUs = fracRaw ? BigInt(fracRaw.slice(0, 6).padEnd(6, "0")) : 0n;

  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  const baseMs = BigInt(date.getTime());

  return baseMs * 1000n + fracUs - BigInt(offsetSeconds) * 1_000_000n;
}

export function dateToUtcUs(date: Date): bigint {
  return BigInt(date.getTime()) * 1000n;
}
