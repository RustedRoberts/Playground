// Shared types for the improvement engine. Nothing in src/engine touches the DOM,
// so every part of it can be unit tested in Node.

/** Improvement categories. The letter is shown in the editor gutter next to the colour. */
export type Category = 'E' | 'T' | 'B' | 'N' | 'H';

export const CATEGORY_ORDER: Category[] = ['E', 'T', 'B', 'N', 'H'];

export type Platform = 'advanced-hunting' | 'sentinel';

export interface Column {
  name: string;
  type: string;
}

export type Row = Record<string, unknown>;

export type TableRole = 'base' | 'entity' | 'threat-intel' | 'watchlist' | 'other';

export interface ReferenceTable {
  id: string;
  name: string;
  role: TableRole;
  schema?: Column[];
  schemaFile?: string;
  sample?: Row[];
  sampleFile?: string;
  problems: string[];
}

/** One piece of an output line, optionally attributed to a category (used for edited lines). */
export interface Segment {
  text: string;
  cat: Category | null;
}

/**
 * One line of the improved query.
 * ctx = unchanged original line, add = new line, del = original line that was replaced,
 * mod = original line with added segments.
 */
export interface OutputLine {
  kind: 'ctx' | 'add' | 'del' | 'mod';
  cat: Category | null;
  segs: Segment[];
}

export type Severity = 'pass' | 'warn' | 'fail' | 'info';

export interface Finding {
  severity: Severity;
  title: string;
  detail: string;
  cat?: Category;
}

/** A column the engine wrote into the query, so it can be checked against the uploaded schemas. */
export interface ColumnUse {
  table: string;
  column: string;
  cat: Category;
}

export interface ChangeNote {
  /** Undefined for neutral notes that belong to no improvement. */
  cat?: Category;
  title: string;
  detail: string;
  watch?: string;
}
