// Builds the KQL an analyst runs to export reference data for the current rule.
//
// Every sample carries the standard join keys (IdentityInfo_Key and ThreatIntel_Key),
// lower-cased and built the same way as in the improved rule, so the tool can test the
// lookups against the samples even when the identifier is nested in a dynamic column.
import { SHAPING_OPERATORS } from './improve/context';
import { IDENTITY_KEY } from './improve/entity';
import { TI_KEY } from './improve/threatIntel';
import { tokenize, type ParsedQuery } from './kql';

export interface ExportKeys {
  /** Expression on the base table that yields the account identifier, and the IdentityInfo column it matches. */
  identity?: { expression: string; right: string };
  /** Expression on the base table that yields the observable, and the indicator column it matches. */
  ti?: { expression: string; valueColumn: string; table: string };
  includeIdentity: boolean;
  includeTi: boolean;
}

export function exportQueries(parsed: ParsedQuery, keys: ExportKeys): string {
  const main = parsed.main;
  const base = main?.sourceTable;
  if (!main || !base) return '// Paste a rule that starts with a table name to generate export queries.';
  const ids = new Set(tokenize(parsed.text).filter((t) => t.type === 'ident').map((t) => t.text));
  const time = ids.has('TimeGenerated') ? 'TimeGenerated' : 'Timestamp';
  const tiTable = keys.ti?.table ?? 'ThreatIntelIndicators';

  // The rule's own steps up to the first shaping operator (filters, mv-expand, extend), so
  // the sample matches what the enrichment sees and derived identifiers exist.
  const steps: string[] = [];
  for (const op of main.operators) {
    if (SHAPING_OPERATORS.has(op.name)) break;
    steps.push(op.text.replace(/\n\s*/g, ' '));
  }
  const keyLines: string[] = [];
  if (keys.includeIdentity && keys.identity) keyLines.push(`| extend ${IDENTITY_KEY} = tolower(${keys.identity.expression})`);
  if (keys.includeTi && keys.ti) keyLines.push(`| extend ${TI_KEY} = tolower(${keys.ti.expression})`);
  const pipeline = [base, ...steps, ...keyLines, `| top 100 by ${time} desc`];
  const indented = (lines: string[]) => lines.map((l, i) => (i === 0 ? l : `    ${l}`));

  const out: string[] = [];
  out.push('// 1. Schemas. Export each result as CSV and name it <Table>_schema.csv');
  const schemaTables = [base, ...(keys.includeIdentity ? ['IdentityInfo'] : []), ...(keys.includeTi ? [tiTable] : [])];
  for (const t of schemaTables) out.push(`${t}\n| getschema\n| project ColumnName, ColumnType`, '');

  out.push(`// 2. Base sample: the rule's own steps plus the standard join keys. Export as ${base}_sample.json.`);
  out.push('//    Widen the time filter if this returns fewer than 100 rows. Use lab data or mask client data.');
  out.push(pipeline.join('\n'), '');

  let n = 3;
  if (keys.includeIdentity) {
    out.push(`// ${n++}. IdentityInfo for the same accounts as the base sample. Export as IdentityInfo_sample.json.`);
    if (keys.identity) {
      out.push([
        `let SampleKeys = ${indented([...pipeline, `| distinct ${IDENTITY_KEY};`]).join('\n')}`,
        'IdentityInfo',
        `| where ${time} > ago(14d)`,
        `| extend ${IDENTITY_KEY} = tolower(${keys.identity.right})`,
        `| where ${IDENTITY_KEY} in (SampleKeys)`,
        `| summarize arg_max(${time}, *) by ${IDENTITY_KEY}`,
      ].join('\n'), '');
    } else {
      out.push('//    Choose the account identifier on the Entity enrichment card first, then copy these queries again.', '');
    }
  }

  if (keys.includeTi) {
    out.push(`// ${n++}. Indicators, putting any that match the base sample first. Export as ${tiTable}_sample.json.`);
    const valueColumn = keys.ti?.valueColumn ?? 'ObservableValue';
    if (keys.ti) {
      out.push([
        `let SampleObservables = ${indented([...pipeline, `| distinct ${TI_KEY};`]).join('\n')}`,
        tiTable,
        '| where TimeGenerated > ago(14d)',
        `| extend ${TI_KEY} = tolower(${valueColumn})`,
        `| extend InBaseSample = ${TI_KEY} in (SampleObservables)`,
        '| top 100 by InBaseSample desc, TimeGenerated desc',
      ].join('\n'));
    } else {
      out.push([tiTable, '| where TimeGenerated > ago(14d)', `| extend ${TI_KEY} = tolower(${valueColumn})`, '| take 100'].join('\n'));
    }
  }
  return out.join('\n').trim();
}
