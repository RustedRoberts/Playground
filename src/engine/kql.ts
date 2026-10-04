// A small, deliberately limited KQL reader. It does not validate KQL. It finds the
// structure the improvement engine needs: let statements, the main query, its source
// table and each top-level pipe operator with the lines it covers.

export type TokenType = 'ws' | 'comment' | 'string' | 'ident' | 'number' | 'punct';

export interface Token {
  type: TokenType;
  text: string;
  start: number;
  end: number;
}

const PUNCT_MULTI = ['!~', '=~', '==', '!=', '<=', '>=', '=>', '..'];

export function tokenize(text: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const n = text.length;
  const push = (type: TokenType, start: number, end: number) =>
    tokens.push({ type, text: text.slice(start, end), start, end });

  while (i < n) {
    const c = text[i];
    const start = i;

    if (/\s/.test(c)) {
      while (i < n && /\s/.test(text[i])) i++;
      push('ws', start, i);
      continue;
    }
    if (c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') i++;
      push('comment', start, i);
      continue;
    }
    // Multi-line string literal ```...```
    if (text.startsWith('```', i)) {
      const close = text.indexOf('```', i + 3);
      i = close === -1 ? n : close + 3;
      push('string', start, i);
      continue;
    }
    // Verbatim (@"..."), obfuscated (h"...") and plain string literals
    const prefixMatch = /^(@|h@|H@|h|H)(?=["'])/.exec(text.slice(i, i + 3));
    if (prefixMatch || c === '"' || c === "'") {
      const prefix = prefixMatch ? prefixMatch[1] : '';
      const verbatim = prefix.includes('@');
      i += prefix.length;
      const quote = text[i];
      i++;
      while (i < n) {
        if (verbatim) {
          if (text[i] === quote && text[i + 1] === quote) { i += 2; continue; }
          if (text[i] === quote) { i++; break; }
          i++;
        } else {
          if (text[i] === '\\') { i += 2; continue; }
          if (text[i] === quote) { i++; break; }
          if (text[i] === '\n') break; // unterminated, stop at end of line
          i++;
        }
      }
      push('string', start, i);
      continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      while (i < n && /[A-Za-z0-9_$]/.test(text[i])) i++;
      push('ident', start, i);
      continue;
    }
    if (/[0-9]/.test(c)) {
      while (i < n && /[0-9a-zA-Z_.]/.test(text[i])) i++;
      push('number', start, i);
      continue;
    }
    const multi = PUNCT_MULTI.find((p) => text.startsWith(p, i));
    if (multi) {
      i += multi.length;
      push('punct', start, i);
      continue;
    }
    i++;
    push('punct', start, i);
  }
  return tokens;
}

export interface Span {
  start: number;
  end: number;
  startLine: number; // 0-based
  endLine: number; // 0-based, inclusive
  text: string;
}

export interface Operator extends Span {
  name: string; // e.g. where, extend, project, project-away, mv-expand
}

export interface Statement extends Span {
  kind: 'let' | 'query' | 'other';
  letName?: string;
}

export interface MainQuery {
  statement: Statement;
  source: Span;
  sourceTable?: string;
  operators: Operator[];
}

export interface ParsedQuery {
  text: string;
  lines: string[];
  tokens: Token[];
  statements: Statement[];
  main?: MainQuery;
  letNames: string[];
  /** True when two operators share a line, which the line-based rewriter cannot edit cleanly. */
  needsLayout: boolean;
}

function lineIndex(lineStarts: number[], offset: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

function makeSpan(text: string, lineStarts: number[], start: number, end: number): Span {
  // Trim whitespace at both ends so line ranges are tight.
  while (start < end && /\s/.test(text[start])) start++;
  while (end > start && /\s/.test(text[end - 1])) end--;
  return {
    start,
    end,
    startLine: lineIndex(lineStarts, start),
    endLine: lineIndex(lineStarts, Math.max(start, end - 1)),
    text: text.slice(start, end),
  };
}

const OPENERS = new Set(['(', '[', '{']);
const CLOSERS = new Set([')', ']', '}']);

export function parseQuery(text: string): ParsedQuery {
  const lines = text.split('\n');
  const lineStarts: number[] = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') lineStarts.push(i + 1);

  const tokens = tokenize(text);
  const significant = tokens.filter((t) => t.type !== 'ws' && t.type !== 'comment');

  // Split into statements on top-level semicolons.
  const statements: Statement[] = [];
  const pipesByStatement: number[][] = [];
  let depth = 0;
  let stmtStart = -1; // offset of the first significant token of the current statement
  let pipes: number[] = [];
  const closeStatement = (end: number) => {
    if (stmtStart === -1) { pipes = []; return; }
    const span = makeSpan(text, lineStarts, stmtStart, end);
    if (span.text.length > 0) {
      const firstWord = /^[A-Za-z_]+/.exec(span.text)?.[0] ?? '';
      const kind: Statement['kind'] = firstWord === 'let' ? 'let' : /^[A-Za-z_(]/.test(span.text) ? 'query' : 'other';
      const letName = kind === 'let' ? /^let\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(span.text)?.[1] : undefined;
      statements.push({ ...span, kind, letName });
      pipesByStatement.push(pipes);
    }
    pipes = [];
  };
  for (const t of significant) {
    if (stmtStart === -1 && !(t.type === 'punct' && t.text === ';')) stmtStart = t.start;
    if (t.type === 'punct') {
      if (OPENERS.has(t.text)) depth++;
      else if (CLOSERS.has(t.text)) depth = Math.max(0, depth - 1);
      else if (depth === 0 && t.text === ';') {
        closeStatement(t.end);
        stmtStart = -1;
      } else if (depth === 0 && t.text === '|') pipes.push(t.start);
    }
  }
  closeStatement(text.length);

  const letNames = statements.filter((s) => s.letName).map((s) => s.letName as string);

  // The main query is the last statement that is not a let.
  let main: MainQuery | undefined;
  for (let s = statements.length - 1; s >= 0; s--) {
    if (statements[s].kind === 'query') {
      const st = statements[s];
      const stPipes = pipesByStatement[s].filter((p) => p >= st.start && p < st.end);
      const sourceEnd = stPipes.length ? stPipes[0] : st.end;
      const source = makeSpan(text, lineStarts, st.start, sourceEnd);
      const sourceTable = /^([A-Za-z_][A-Za-z0-9_]*)\s*$/.exec(source.text.replace(/;\s*$/, ''))?.[1]
        ?? /^([A-Za-z_][A-Za-z0-9_]*)\b/.exec(source.text)?.[1];
      const operators: Operator[] = stPipes.map((p, idx) => {
        let end = idx + 1 < stPipes.length ? stPipes[idx + 1] : st.end;
        // Do not include the statement's own trailing semicolon in the last operator.
        const raw = text.slice(p, end);
        const semi = raw.lastIndexOf(';');
        if (idx === stPipes.length - 1 && semi !== -1 && raw.slice(semi + 1).trim() === '') end = p + semi;
        const span = makeSpan(text, lineStarts, p, end);
        const name = /^\|\s*([A-Za-z_][A-Za-z0-9_]*(?:-[A-Za-z_][A-Za-z0-9_]*)*)/.exec(span.text)?.[1] ?? '';
        return { ...span, name: name.toLowerCase() };
      });
      main = {
        statement: st,
        source,
        sourceTable: sourceTable && !['union', 'print', 'datatable', 'range', 'let'].includes(sourceTable) ? sourceTable : undefined,
        operators,
      };
      break;
    }
  }

  let needsLayout = false;
  if (main) {
    let prevEndLine = main.source.endLine;
    for (const op of main.operators) {
      if (op.startLine === prevEndLine) needsLayout = true;
      prevEndLine = op.endLine;
    }
  }

  return { text, lines, tokens, statements, main, letNames, needsLayout };
}

/**
 * Puts each top-level operator of the main query on its own line, so the line-based
 * rewriter can insert and replace operators without splitting lines.
 */
export function normaliseLayout(text: string): string {
  const parsed = parseQuery(text);
  if (!parsed.needsLayout || !parsed.main) return text;
  const cuts: number[] = [];
  let prevEndLine = parsed.main.source.endLine;
  for (const op of parsed.main.operators) {
    if (op.startLine === prevEndLine) cuts.push(op.start);
    prevEndLine = op.endLine;
  }
  let out = text;
  for (const cut of cuts.reverse()) {
    out = out.slice(0, cut).replace(/[ \t]+$/, '') + '\n' + out.slice(cut);
  }
  return out;
}

/** Identifiers (not strings or comments) used anywhere in the text. */
export function identifiers(text: string): string[] {
  return tokenize(text).filter((t) => t.type === 'ident').map((t) => t.text);
}

/** Splits text on a top-level separator word (for example "and") outside brackets and strings. */
export function splitTopLevel(text: string, word: string): string[] {
  const tokens = tokenize(text);
  const parts: string[] = [];
  let depth = 0;
  let last = 0;
  for (const t of tokens) {
    if (t.type === 'punct') {
      if (OPENERS.has(t.text)) depth++;
      else if (CLOSERS.has(t.text)) depth = Math.max(0, depth - 1);
    } else if (t.type === 'ident' && depth === 0 && t.text.toLowerCase() === word) {
      parts.push(text.slice(last, t.start));
      last = t.end;
    }
  }
  parts.push(text.slice(last));
  return parts.map((p) => p.trim()).filter((p) => p.length > 0);
}

/** Decodes a KQL string literal token (plain, verbatim or obfuscated). */
export function stringValue(literal: string): string {
  const m = /^(h@|H@|@|h|H)?(["'])([\s\S]*)\2$/.exec(literal);
  if (!m) return literal;
  const verbatim = (m[1] ?? '').includes('@');
  const quote = m[2];
  const body = m[3];
  if (verbatim) return body.split(quote + quote).join(quote);
  return body.replace(/\\(.)/g, (_all, ch: string) => {
    if (ch === 'n') return '\n';
    if (ch === 't') return '\t';
    return ch;
  });
}

/** Quotes a value as a KQL string literal, preferring double quotes. */
export function quote(value: string): string {
  if (!value.includes('"')) return `"${value.replace(/\\/g, '\\\\')}"`;
  if (!value.includes("'")) return `'${value.replace(/\\/g, '\\\\')}'`;
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}
