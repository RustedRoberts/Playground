// Parsing of uploaded reference data: schemas (getschema output) and sample rows.
import Papa from 'papaparse';
import type { Column, ReferenceTable, Row, TableRole } from './types';

export const MAX_SAMPLE_ROWS = 1000;

export type FileKind = 'schema' | 'sample';

export interface ParsedFile {
  kind: FileKind;
  tableName?: string;
  schema?: Column[];
  sample?: Row[];
  problems: string[];
}

const NAME_KEYS = ['ColumnName', 'columnName', 'Name', 'name', 'Column', 'column'];
const TYPE_KEYS = ['ColumnType', 'columnType', 'Type', 'type', 'DataType', 'dataType', 'CslType'];

/** Maps .NET and other type spellings to KQL scalar type names. */
export function normaliseType(raw: string): string {
  const t = String(raw ?? '').trim().replace(/^System\./, '').toLowerCase();
  const map: Record<string, string> = {
    string: 'string', 'system.string': 'string',
    datetime: 'datetime', date: 'datetime',
    boolean: 'bool', bool: 'bool', sbyte: 'bool',
    int32: 'int', int: 'int', int64: 'long', long: 'long',
    double: 'real', real: 'real', single: 'real', decimal: 'decimal',
    guid: 'guid', timespan: 'timespan',
    object: 'dynamic', dynamic: 'dynamic',
  };
  return map[t] ?? (t || 'unknown');
}

function pick(obj: Row, keys: string[]): string | undefined {
  for (const k of keys) if (obj[k] !== undefined && obj[k] !== null && String(obj[k]).length) return String(obj[k]);
  return undefined;
}

function looksLikeSchema(rows: Row[]): boolean {
  if (rows.length === 0) return false;
  const keys = Object.keys(rows[0]);
  return keys.some((k) => NAME_KEYS.includes(k)) && keys.some((k) => TYPE_KEYS.includes(k)) && keys.length <= 6;
}

function rowsToSchema(rows: Row[]): Column[] {
  return rows
    .map((r) => ({ name: pick(r, NAME_KEYS) ?? '', type: normaliseType(pick(r, TYPE_KEYS) ?? '') }))
    .filter((c) => c.name.length > 0);
}

/** Extracts an array of row objects from the common JSON export shapes. */
function jsonRows(value: unknown): Row[] | undefined {
  if (Array.isArray(value)) return value.filter((v) => v && typeof v === 'object' && !Array.isArray(v)) as Row[];
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    // Kusto/Log Analytics API shape: { tables: [{ columns: [...], rows: [[...]] }] }
    const tables = (obj.tables ?? obj.Tables) as unknown;
    if (Array.isArray(tables) && tables.length) {
      const t = tables[0] as Record<string, unknown>;
      const cols = (t.columns ?? t.Columns) as Array<Record<string, string>> | undefined;
      const rows = (t.rows ?? t.Rows) as unknown[][] | undefined;
      if (cols && rows) {
        return rows.map((r) => Object.fromEntries(cols.map((c, i) => [c.name ?? c.ColumnName, r[i]])));
      }
    }
    for (const key of ['Results', 'results', 'value', 'data', 'rows', 'Rows', 'Schema', 'schema']) {
      if (Array.isArray(obj[key])) return jsonRows(obj[key]);
    }
    const firstArray = Object.values(obj).find((v) => Array.isArray(v));
    if (firstArray) return jsonRows(firstArray);
  }
  return undefined;
}

/** Guesses the table name from a file name such as "DeviceProcessEvents_schema.csv". */
export function tableNameFromFileName(fileName: string): string | undefined {
  const stem = fileName.replace(/\.[^.]+$/, '');
  const m = /^([A-Za-z_][A-Za-z0-9_]*?)(?:[_\-. ](schema|sample|samples|rows|data|getschema|export|columns))*$/i.exec(stem);
  return m?.[1];
}

export function kindFromFileName(fileName: string): FileKind | undefined {
  if (/schema|getschema|columns/i.test(fileName)) return 'schema';
  if (/sample|rows|data|export/i.test(fileName)) return 'sample';
  return undefined;
}

export function parseReferenceFile(fileName: string, content: string): ParsedFile {
  const problems: string[] = [];
  const trimmed = content.replace(/^﻿/, '').trim();
  let rows: Row[] | undefined;

  if (/\.json$/i.test(fileName) || /^[[{]/.test(trimmed)) {
    try {
      rows = jsonRows(JSON.parse(trimmed));
    } catch {
      // Newline-delimited JSON
      const lines = trimmed.split(/\r?\n/).filter((l) => l.trim());
      try {
        rows = lines.map((l) => JSON.parse(l) as Row);
      } catch {
        problems.push('The file looks like JSON but could not be read. Check that it is valid JSON or one JSON object per line.');
      }
    }
  } else {
    const result = Papa.parse<Row>(trimmed, { header: true, skipEmptyLines: true });
    if (result.errors.length) {
      problems.push(`CSV warning: ${result.errors[0].message} (row ${result.errors[0].row ?? 'unknown'}).`);
    }
    rows = result.data;
  }

  if (!rows || rows.length === 0) {
    problems.push('No rows were found in the file.');
    return { kind: kindFromFileName(fileName) ?? 'sample', tableName: tableNameFromFileName(fileName), problems };
  }

  const kindHint = kindFromFileName(fileName);
  const isSchema = kindHint === 'schema' || (kindHint === undefined && looksLikeSchema(rows));
  if (isSchema) {
    const schema = rowsToSchema(rows);
    if (schema.length === 0) problems.push('No column names were found. A schema file needs ColumnName and ColumnType columns, as produced by getschema.');
    return { kind: 'schema', tableName: tableNameFromFileName(fileName), schema, problems };
  }

  if (rows.length > MAX_SAMPLE_ROWS) {
    problems.push(`The sample has ${rows.length} rows. Only the first ${MAX_SAMPLE_ROWS} are used.`);
    rows = rows.slice(0, MAX_SAMPLE_ROWS);
  }
  return { kind: 'sample', tableName: tableNameFromFileName(fileName), sample: rows, problems };
}

/** Columns of a table: the uploaded schema, or failing that the keys seen in the sample. */
export function columnsOf(table: ReferenceTable | undefined): Column[] {
  if (!table) return [];
  if (table.schema?.length) return table.schema;
  if (table.sample?.length) {
    const names = new Set<string>();
    for (const r of table.sample.slice(0, 50)) Object.keys(r).forEach((k) => names.add(k));
    return [...names].map((name) => ({ name, type: 'unknown' }));
  }
  return [];
}

export function hasColumn(table: ReferenceTable | undefined, column: string): boolean {
  return columnsOf(table).some((c) => c.name === column);
}

export function columnType(table: ReferenceTable | undefined, column: string): string | undefined {
  return columnsOf(table).find((c) => c.name === column)?.type;
}

export function roleForTable(name: string): TableRole {
  if (/^IdentityInfo$/i.test(name)) return 'entity';
  if (/^ThreatIntel(ligence)?Indicators?$/i.test(name)) return 'threat-intel';
  if (/watchlist/i.test(name)) return 'watchlist';
  return 'other';
}

/** Distinct, non-empty string values of a column in a sample. */
export function distinctValues(rows: Row[] | undefined, column: string, lower = false): Set<string> {
  const out = new Set<string>();
  for (const r of rows ?? []) {
    const v = r[column];
    if (v === undefined || v === null) continue;
    const s = String(v);
    if (!s.length) continue;
    out.add(lower ? s.toLowerCase() : s);
  }
  return out;
}

const IDENTIFYING = /(account|user|upn|email|device|host|computer|machine|caller|initiatedby|sid|objectid|ipaddress|^ip$|remoteip|localip)/i;
const NOT_IDENTIFYING = /(filename|processname|folderpath|sha|md5|hash|actiontype|tenantid|commandline)/i;

export function isIdentifyingColumn(column: string): boolean {
  return IDENTIFYING.test(column) && !NOT_IDENTIFYING.test(column);
}

/** Display masking: keeps the first character and a short stable fingerprint. */
export function maskValue(value: string): string {
  if (!value) return value;
  let h = 2166136261;
  for (let i = 0; i < value.length; i++) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `${value[0]}***${(h >>> 0).toString(16).slice(0, 6)}`;
}
