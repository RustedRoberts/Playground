import { parseReferenceFile, roleForTable } from './engine/reference';
import type { ReferenceTable } from './engine/types';

export interface IncomingFile {
  name: string;
  content: string;
}

/**
 * Adds uploaded files to the reference tables. A file goes to `targetName` when it was
 * dropped on a specific table card, otherwise to the table named in its file name.
 */
export function ingest(tables: ReferenceTable[], files: IncomingFile[], targetName?: string, forceKind?: 'schema' | 'sample'): { tables: ReferenceTable[]; messages: string[] } {
  const next = tables.map((t) => ({ ...t, problems: [...t.problems] }));
  const messages: string[] = [];
  for (const f of files) {
    // When a file is dropped on a specific slot, its kind comes from the slot, not the file name.
    const ext = /\.[^.]+$/.exec(f.name)?.[0] ?? '';
    const parseName = forceKind && targetName ? `${targetName}_${forceKind}${ext}` : f.name;
    const parsed = parseReferenceFile(parseName, f.content);
    const name = targetName ?? parsed.tableName;
    if (!name) {
      messages.push(`Could not tell which table ${f.name} belongs to. Drop it on a table card, or name it like DeviceProcessEvents_sample.json.`);
      continue;
    }
    let table = next.find((t) => t.name.toLowerCase() === name.toLowerCase());
    if (!table) {
      table = { id: name.toLowerCase(), name, role: roleForTable(name), problems: [] };
      next.push(table);
    }
    const label = parsed.kind === 'schema' ? 'Schema' : 'Sample';
    table.problems = table.problems.filter((p) => !p.startsWith(`${label}: `)).concat(parsed.problems.map((p) => `${label}: ${p}`));
    if (parsed.kind === 'schema') {
      table.schema = parsed.schema;
      table.schemaFile = f.name;
    } else {
      table.sample = parsed.sample;
      table.sampleFile = f.name;
    }
    messages.push(`${f.name} added to ${table.name} as its ${label.toLowerCase()}.`);
  }
  return { tables: next, messages };
}

export function addTable(tables: ReferenceTable[], name: string): ReferenceTable[] {
  if (tables.some((t) => t.name.toLowerCase() === name.toLowerCase())) return tables;
  return [...tables, { id: name.toLowerCase(), name, role: roleForTable(name), problems: [] }];
}

export async function readFiles(list: FileList | File[]): Promise<IncomingFile[]> {
  return Promise.all([...list].map(async (file) => ({ name: file.name, content: await file.text() })));
}
