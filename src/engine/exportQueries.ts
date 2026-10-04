// Builds the KQL an analyst runs to export reference data for the current rule.
import type { ParsedQuery } from './kql';
import { SHAPING_OPERATORS } from './improve/context';
import { tokenize } from './kql';

export function exportQueries(parsed: ParsedQuery, opts: { identity: boolean; ti: boolean; identityKey?: { left: string; right: string } }): string {
  const main = parsed.main;
  const base = main?.sourceTable;
  if (!main || !base) return '// Paste a rule that starts with a table name to generate export queries.';
  const ids = new Set(tokenize(parsed.text).filter((t) => t.type === 'ident').map((t) => t.text));
  const time = ids.has('TimeGenerated') ? 'TimeGenerated' : 'Timestamp';

  // The rule's own filters, up to the first shaping operator, so the sample resembles its input.
  const filters: string[] = [];
  for (const op of main.operators) {
    if (SHAPING_OPERATORS.has(op.name)) break;
    if (op.name === 'where' || op.name === 'filter') filters.push(op.text.replace(/\n\s*/g, ' '));
  }

  const out: string[] = [];
  out.push('// 1. Schemas. Export each result as CSV and name it <Table>_schema.csv');
  const schemaTables = [base, ...(opts.identity ? ['IdentityInfo'] : []), ...(opts.ti ? ['ThreatIntelIndicators'] : [])];
  for (const t of schemaTables) out.push(`${t}\n| getschema\n| project ColumnName, ColumnType`, '');
  out.push(`// 2. Base sample using the rule's own filters. Export as ${base}_sample.json (or .csv).`);
  out.push('//    Widen the time filter if this returns fewer than 100 rows. Use lab data or mask client data.');
  out.push([base, ...filters, `| top 100 by ${time} desc`].join('\n'), '');
  if (opts.identity && opts.identityKey) {
    out.push('// 3. IdentityInfo for the same accounts as the base sample, so the lookup can be tested.');
    out.push('//    Export as IdentityInfo_sample.json.');
    out.push([`let SampleKeys = ${base}`, ...filters.map((f) => `    ${f}`), `    | top 100 by ${time} desc`, `    | distinct ${opts.identityKey.left};`, 'IdentityInfo', `| where ${opts.identityKey.right} in (SampleKeys)`, `| summarize arg_max(${time}, *) by ${opts.identityKey.right}`].join('\n'), '');
  }
  if (opts.ti) {
    out.push(`// ${opts.identity ? 4 : 3}. Indicators. Export as ThreatIntelIndicators_sample.json.`);
    out.push('ThreatIntelIndicators\n| where TimeGenerated > ago(14d)\n| take 100');
  }
  return out.join('\n').trim();
}
