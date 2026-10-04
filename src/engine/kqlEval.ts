// JavaScript approximations of the KQL string operators the engine reasons about.
// These drive the evasion test bench and the sample-row checks. They are close to
// KQL behaviour for the cases the engine rewrites, but they are not the KQL engine,
// so results are labelled as approximations in the interface.

export type StringOperator =
  | 'has' | 'has_cs' | 'has_any' | 'has_all'
  | 'contains' | 'contains_cs'
  | 'startswith' | 'endswith'
  | '=~' | '==' | 'in~' | 'in'
  | 'matches regex';

export const POSITIVE_OPERATORS: StringOperator[] = [
  'has', 'has_cs', 'has_any', 'has_all', 'contains', 'contains_cs', 'startswith', 'endswith', '=~', '==', 'in~', 'in', 'matches regex',
];

function escapeJs(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

const ALNUM = /[A-Za-z0-9]/;

/**
 * KQL "has" looks for a whole indexed term. Terms are runs of alphanumeric characters,
 * so a literal must not be glued to further alphanumerics at either end.
 */
export function hasTerm(haystack: string, literal: string, caseSensitive = false): boolean {
  if (!literal) return false;
  const left = ALNUM.test(literal[0]) ? '(?<![A-Za-z0-9])' : '';
  const right = ALNUM.test(literal[literal.length - 1]) ? '(?![A-Za-z0-9])' : '';
  const re = new RegExp(left + escapeJs(literal) + right, caseSensitive ? '' : 'i');
  return re.test(haystack);
}

/** Converts an RE2-style KQL regex (as the engine writes it) into a JavaScript RegExp. */
export function kqlRegexToJs(pattern: string): RegExp {
  let flags = 'u';
  let body = pattern;
  if (body.startsWith('(?i)')) {
    flags += 'i';
    body = body.slice(4);
  }
  body = body.replace(/\\x\{([0-9A-Fa-f]+)\}/g, (_m, hex: string) => `\\u{${hex}}`);
  return new RegExp(body, flags);
}

export function evaluate(op: StringOperator, haystack: string, literals: string[]): boolean {
  const h = haystack ?? '';
  const lower = h.toLowerCase();
  switch (op) {
    case 'has': return literals.some((l) => hasTerm(h, l));
    case 'has_cs': return literals.some((l) => hasTerm(h, l, true));
    case 'has_any': return literals.some((l) => hasTerm(h, l));
    case 'has_all': return literals.every((l) => hasTerm(h, l));
    case 'contains': return literals.some((l) => lower.includes(l.toLowerCase()));
    case 'contains_cs': return literals.some((l) => h.includes(l));
    case 'startswith': return literals.some((l) => lower.startsWith(l.toLowerCase()));
    case 'endswith': return literals.some((l) => lower.endsWith(l.toLowerCase()));
    case '=~': case 'in~': return literals.some((l) => lower === l.toLowerCase());
    case '==': case 'in': return literals.some((l) => h === l);
    case 'matches regex': return literals.some((l) => kqlRegexToJs(l).test(h));
    default: return false;
  }
}
