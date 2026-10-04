// Checks that compare the query against the uploaded reference data.
import { tokenize, type ParsedQuery } from './kql';
import { columnsOf } from './reference';
import type { ColumnUse, Finding, ReferenceTable } from './types';

// KQL keywords, operators and common functions, so they are not mistaken for columns.
const KQL_WORDS = new Set(`
let set alias declare pattern restrict access with on by of in and or not to as kind step from bin
where filter extend project project-away project-keep project-rename project-reorder summarize count
take limit top sort order asc desc nulls first last join lookup union distinct mv-expand mv-apply
parse parse-where evaluate render make-series range print datatable externaldata invoke as
inner outer leftouter rightouter fullouter leftanti rightanti leftsemi rightsemi innerunique anti semi
has has_cs has_any has_all hasprefix hassuffix contains contains_cs startswith endswith matches regex
between true false null dynamic datetime timespan bool int long real string guid decimal
ago now todatetime tostring toint tolong toreal todouble tobool todynamic parse_json tolower toupper
strlen substring split strcat strcat_array replace replace_string replace_regex extract extract_all
trim trim_start trim_end iff iif case isnull isnotnull isempty isnotempty coalesce array_length
bag_keys pack pack_all bag_pack make_set make_list make_bag dcount countif dcountif sum sumif avg
min max arg_max arg_min take_any any percentile percentiles stdev variance format_datetime
startofday endofday startofweek dayofweek hourofday datetime_diff geo_info_from_ip_address
ipv4_is_private ipv4_is_in_range ipv4_compare parse_url parse_path base64_decode_tostring
base64_encode_tostring url_decode hash hash_sha256 series_decompose_anomalies array_index_of
set_has_element set_difference set_intersect set_union row_number prev next isfinite round floor
hint shufflekey strategy broadcast materialize toscalar typeof gettype getschema _GetWatchlist
$left $right left right d h m s ms min
`.split(/\s+/).filter(Boolean).map((w) => w.toLowerCase()));

/** Identifiers the query uses as columns but that are not in any uploaded schema. */
export function unknownColumns(parsed: ParsedQuery, tables: ReferenceTable[]): string[] {
  const known = new Set<string>();
  for (const t of tables) {
    known.add(t.name.toLowerCase());
    for (const c of columnsOf(t)) known.add(c.name.toLowerCase());
  }
  if (known.size === 0) return [];
  const toks = tokenize(parsed.text).filter((t) => t.type !== 'ws' && t.type !== 'comment');
  const defined = new Set(parsed.letNames.map((n) => n.toLowerCase()));
  // Names created by "Name =" inside extend, project, summarize and similar.
  toks.forEach((t, i) => {
    if (t.type === 'ident' && toks[i + 1]?.text === '=' && toks[i + 2]?.text !== '=') defined.add(t.text.toLowerCase());
  });
  const unknown = new Set<string>();
  toks.forEach((t, i) => {
    if (t.type !== 'ident') return;
    const lower = t.text.toLowerCase();
    if (KQL_WORDS.has(lower) || defined.has(lower) || known.has(lower)) return;
    if (toks[i - 1]?.text === '.' || toks[i + 1]?.text === '(') return; // property access or function call
    if (toks[i - 1]?.text === '-' || toks[i + 1]?.text === '-') return; // operator names such as project-away
    unknown.add(t.text);
  });
  return [...unknown];
}

export function referenceFindings(
  parsed: ParsedQuery,
  tables: ReferenceTable[],
  uses: ColumnUse[],
  baseName: string | undefined,
): Finding[] {
  const findings: Finding[] = [];
  const byName = new Map(tables.map((t) => [t.name.toLowerCase(), t]));

  if (baseName) {
    const base = byName.get(baseName.toLowerCase());
    if (!base || columnsOf(base).length === 0) {
      findings.push({ severity: 'fail', title: `No reference data for ${baseName}`, detail: 'Upload its getschema output and a sample so the tool can check field names.' });
    } else {
      if (!base.schema?.length) findings.push({ severity: 'warn', title: `No schema for ${baseName}`, detail: 'Columns are being taken from the sample rows, which can miss columns that are empty in every sampled row.' });
      if (!base.sample?.length) findings.push({ severity: 'info', title: `No sample rows for ${baseName}`, detail: 'Field names can be checked, but joins and conditions cannot be tested against data.' });
    }
  } else {
    findings.push({ severity: 'warn', title: 'Base table not detected', detail: 'The query does not start with a single table name, so reference checks are limited.' });
  }

  // Every column the engine wrote must exist in the matching schema.
  const missing = uses.filter((u) => {
    const t = byName.get(u.table.toLowerCase());
    return !t || !columnsOf(t).some((c) => c.name === u.column);
  });
  const checked = uses.length - missing.length;
  if (uses.length) {
    if (missing.length === 0) {
      findings.push({ severity: 'pass', title: `All ${checked} column references written by the tool were found in your schemas`, detail: 'No field name in the added lines is guessed.' });
    } else {
      for (const m of missing) findings.push({ severity: 'fail', cat: m.cat, title: `${m.table}.${m.column} is not in the uploaded schema`, detail: 'The tool wrote this column but it is not in the reference data. Do not use the output until this is resolved.' });
    }
  }

  const unknown = unknownColumns(parsed, tables);
  if (unknown.length) {
    findings.push({
      severity: 'warn',
      title: `Original rule uses ${unknown.length} name${unknown.length > 1 ? 's' : ''} not found in your schemas`,
      detail: `${unknown.join(', ')}. These may be functions, let names or columns of a table you have not uploaded. This check is approximate.`,
    });
  }
  return findings;
}
