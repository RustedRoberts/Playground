// Reads simple KQL predicates of the form `Column <operator> <literal or list>`.
import { splitTopLevel, stringValue, tokenize } from './kql';
import type { StringOperator } from './kqlEval';

export interface SimplePredicate {
  column: string;
  operator: StringOperator;
  negated: boolean;
  literals: string[];
  text: string;
}

const OPERATOR_WORDS: Record<string, StringOperator> = {
  has: 'has', has_cs: 'has_cs', has_any: 'has_any', has_all: 'has_all',
  contains: 'contains', contains_cs: 'contains_cs',
  startswith: 'startswith', endswith: 'endswith',
  '=~': '=~', '==': '==', 'in~': 'in~', in: 'in',
};

function stripOuterParens(text: string): string {
  let t = text.trim();
  while (t.startsWith('(') && t.endsWith(')')) {
    // Only strip if the opening bracket closes at the very end.
    let depth = 0;
    let closesAtEnd = true;
    for (const tok of tokenize(t)) {
      if (tok.type !== 'punct') continue;
      if (tok.text === '(') depth++;
      else if (tok.text === ')') {
        depth--;
        if (depth === 0 && tok.end !== t.length) { closesAtEnd = false; break; }
      }
    }
    if (!closesAtEnd) break;
    t = t.slice(1, -1).trim();
  }
  return t;
}

/** Parses one conjunct. Returns undefined for anything more complex than a simple comparison. */
export function parseSimplePredicate(text: string): SimplePredicate | undefined {
  const inner = stripOuterParens(text);
  if (splitTopLevel(inner, 'or').length > 1 || splitTopLevel(inner, 'and').length > 1) return undefined;
  const toks = tokenize(inner).filter((t) => t.type !== 'ws' && t.type !== 'comment');
  if (toks.length < 3 || toks[0].type !== 'ident') return undefined;
  const column = toks[0].text;
  let i = 1;
  let negated = false;
  if (toks[i].text === '!') { negated = true; i++; }
  let opWord = toks[i]?.text ?? '';
  if (opWord === '!~' || opWord === '!=') return undefined;
  if (opWord === 'in' && toks[i + 1]?.text === '~') { opWord = 'in~'; i++; }
  if (opWord === 'matches' && toks[i + 1]?.text.toLowerCase() === 'regex') {
    const lit = toks[i + 2];
    if (!lit || lit.type !== 'string' || toks.length !== i + 3) return undefined;
    return { column, operator: 'matches regex', negated, literals: [stringValue(lit.text)], text: inner };
  }
  const operator = OPERATOR_WORDS[opWord];
  if (!operator) return undefined;
  i++;
  const rest = toks.slice(i);
  // Either a single string literal, or a bracketed list of literals, optionally inside dynamic([...]).
  const allowed = new Set(['(', ')', '[', ']', ',', 'dynamic']);
  const literals: string[] = [];
  for (const t of rest) {
    if (t.type === 'string') literals.push(stringValue(t.text));
    else if (!allowed.has(t.text)) return undefined;
  }
  if (literals.length === 0) return undefined;
  return { column, operator, negated, literals, text: inner };
}

/** The condition text of a `| where` operator, without the pipe and keyword. */
export function whereCondition(operatorText: string): string | undefined {
  const m = /^\|\s*(?:where|filter)\b([\s\S]*)$/i.exec(operatorText);
  return m ? m[1].trim() : undefined;
}
