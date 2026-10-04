// Shared context, edit model and rendering for the improvement modules.
import type { Operator, ParsedQuery } from '../kql';
import type { Category, ChangeNote, ColumnUse, Finding, OutputLine, Platform, ReferenceTable } from '../types';

/** Operators that end the filtering part of a query. Enrichment is inserted before the first of these. */
export const SHAPING_OPERATORS = new Set([
  'project', 'project-keep', 'project-reorder', 'project-away', 'project-rename',
  'summarize', 'top', 'take', 'limit', 'sample', 'distinct', 'sort', 'order', 'render', 'count', 'make-series',
]);

export interface EngineContext {
  parsed: ParsedQuery;
  platform: Platform;
  tables: ReferenceTable[];
  base?: ReferenceTable;
  baseName?: string;
  /** 0-based line before which enrichment lines are inserted (lines.length means append at the end). */
  anchorLine: number;
  anchorOperator?: Operator;
  /** The final `| project` operator, if the query ends with one, so new columns can be appended to it. */
  projectOperator?: Operator;
  /** Line before which new let statements are inserted. */
  topLine: number;
  /** Lower-cased text of every identifier in the original query. */
  identifiersLower: Set<string>;
  usedLetNames: Set<string>;
  /**
   * Columns the rule creates itself (extend, project or mv-expand assignments) before the
   * enrichment point, mapped to the expression that creates them. They are not in the
   * uploaded schema but can still be used as join keys.
   */
  derivedColumns: Map<string, string>;
}

/** True when a column exists in the base schema or is created by the rule before the enrichment point. */
export function isAvailable(ctx: EngineContext, column: string): boolean {
  if (ctx.derivedColumns.has(column)) return true;
  return !!ctx.base && columnsOfBase(ctx).includes(column);
}

function columnsOfBase(ctx: EngineContext): string[] {
  const t = ctx.base;
  if (!t) return [];
  if (t.schema?.length) return t.schema.map((c) => c.name);
  return Object.keys(t.sample?.[0] ?? {});
}

export type Edit =
  | { type: 'insertTop'; lines: string[]; cat: Category }
  | { type: 'insertAtAnchor'; lines: string[]; cat: Category }
  | { type: 'replace'; fromLine: number; toLine: number; lines: string[]; cat: Category };

export type ModuleStatus = 'applied' | 'needs-data' | 'not-applicable' | 'already-present' | 'not-implemented' | 'off';

export interface ModuleResult {
  cat: Category;
  status: ModuleStatus;
  /** One-line explanation of the status, shown on the improvement card. */
  summary: string;
  edits: Edit[];
  /** Columns to add to the final project, if there is one. */
  outputColumns: string[];
  notes: ChangeNote[];
  findings: Finding[];
  uses: ColumnUse[];
}

export function emptyResult(cat: Category, status: ModuleStatus, summary: string): ModuleResult {
  return { cat, status, summary, edits: [], outputColumns: [], notes: [], findings: [], uses: [] };
}

/** Picks a let name that does not clash with any in the query. */
export function uniqueLetName(ctx: EngineContext, wanted: string): string {
  let name = wanted;
  let i = 2;
  while (ctx.usedLetNames.has(name.toLowerCase()) || ctx.identifiersLower.has(name.toLowerCase())) name = `${wanted}${i++}`;
  ctx.usedLetNames.add(name.toLowerCase());
  return name;
}

export function queryMentions(ctx: EngineContext, ...names: string[]): boolean {
  return names.some((n) => ctx.identifiersLower.has(n.toLowerCase()));
}

export interface RenderResult {
  lines: OutputLine[];
  text: string;
}

/**
 * Applies the edits to the original lines and produces the annotated output.
 * Edits from earlier modules come first at a shared anchor, so module order sets block order.
 */
export function render(ctx: EngineContext, results: ModuleResult[]): RenderResult {
  const src = ctx.parsed.lines;
  const out: OutputLine[] = [];
  const topInserts: { lines: string[]; cat: Category }[] = [];
  const anchorInserts: { lines: string[]; cat: Category }[] = [];
  const replaces = new Map<number, { toLine: number; lines: string[]; cat: Category }>();
  for (const r of results) {
    for (const e of r.edits) {
      if (e.type === 'insertTop') topInserts.push(e);
      else if (e.type === 'insertAtAnchor') anchorInserts.push(e);
      else replaces.set(e.fromLine, { toLine: e.toLine, lines: e.lines, cat: e.cat });
    }
  }

  // Columns appended to the final project line, grouped by category.
  const appended: { text: string; cat: Category }[] = [];
  if (ctx.projectOperator) {
    const existing = new Set((ctx.projectOperator.text.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []).map((s) => s.toLowerCase()));
    for (const r of results) {
      for (const col of r.outputColumns) {
        if (existing.has(col.toLowerCase())) continue;
        existing.add(col.toLowerCase());
        appended.push({ text: col, cat: r.cat });
      }
    }
  }

  const pushAdd = (lines: string[], cat: Category) => {
    for (const l of lines) out.push({ kind: 'add', cat, segs: [{ text: l, cat }] });
  };

  for (let i = 0; i <= src.length; i++) {
    if (i === ctx.topLine) for (const b of topInserts) pushAdd(b.lines, b.cat);
    if (i === ctx.anchorLine) for (const b of anchorInserts) pushAdd(b.lines, b.cat);
    if (i === src.length) break;

    const rep = replaces.get(i);
    if (rep) {
      for (let j = i; j <= rep.toLine; j++) out.push({ kind: 'del', cat: rep.cat, segs: [{ text: src[j], cat: rep.cat }] });
      pushAdd(rep.lines, rep.cat);
      i = rep.toLine;
      continue;
    }

    if (ctx.projectOperator && i === ctx.projectOperator.endLine && appended.length) {
      const line = src[i];
      const trailing = /(\s*(?:\/\/.*)?)$/.exec(line)?.[1] ?? '';
      const body = line.slice(0, line.length - trailing.length);
      const segs = [{ text: body, cat: null as Category | null }];
      for (const a of appended) segs.push({ text: `, ${a.text}`, cat: a.cat });
      if (trailing) segs.push({ text: trailing, cat: null });
      out.push({ kind: 'mod', cat: null, segs });
      continue;
    }
    out.push({ kind: 'ctx', cat: null, segs: [{ text: src[i], cat: null }] });
  }

  const text = out
    .filter((l) => l.kind !== 'del')
    .map((l) => l.segs.map((s) => s.text).join(''))
    .join('\n');
  return { lines: out, text };
}
