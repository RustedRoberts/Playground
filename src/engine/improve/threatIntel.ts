// Threat intelligence correlation (pattern A3).
import { quote } from '../kql';
import { columnsOf, distinctValues, hasColumn } from '../reference';
import type { ReferenceTable } from '../types';
import { emptyResult, isAvailable, queryMentions, uniqueLetName, type EngineContext, type ModuleResult } from './context';

type ObservableType = 'sha256' | 'sha1' | 'md5' | 'ip' | 'domain' | 'url';

interface ObservableRule {
  type: ObservableType;
  label: string;
  columns: string[];
  /** Matches ObservableKey values in ThreatIntelIndicators. */
  keyPattern: RegExp;
  /** Used only when no matching ObservableKey value is present in the uploaded sample. */
  defaultKeys: string[];
  legacy: { column: string; hashType?: RegExp; defaultHashType?: string };
}

const RULES: ObservableRule[] = [
  { type: 'sha256', label: 'SHA-256 hash', columns: ['InitiatingProcessSHA256', 'SHA256', 'FileHashSha256', 'SHA256Hash'], keyPattern: /sha-?256/i, defaultKeys: ["file:hashes.'SHA-256'"], legacy: { column: 'FileHashValue', hashType: /sha-?256/i, defaultHashType: 'SHA256' } },
  { type: 'sha1', label: 'SHA-1 hash', columns: ['InitiatingProcessSHA1', 'SHA1'], keyPattern: /sha-?1(?!\d)/i, defaultKeys: ["file:hashes.'SHA-1'"], legacy: { column: 'FileHashValue', hashType: /sha-?1(?!\d)/i, defaultHashType: 'SHA1' } },
  { type: 'md5', label: 'MD5 hash', columns: ['InitiatingProcessMD5', 'MD5'], keyPattern: /md5/i, defaultKeys: ['file:hashes.MD5'], legacy: { column: 'FileHashValue', hashType: /md5/i, defaultHashType: 'MD5' } },
  { type: 'ip', label: 'IP address', columns: ['RemoteIP', 'IPAddress', 'IpAddress', 'SrcIpAddr', 'DstIpAddr', 'ClientIP', 'CallerIpAddress', 'SourceIP', 'DestinationIP', 'RemoteIp'], keyPattern: /ipv[46]-addr/i, defaultKeys: ['ipv4-addr:value', 'ipv6-addr:value'], legacy: { column: 'NetworkIP' } },
  { type: 'domain', label: 'Domain', columns: ['RemoteDomain', 'DomainName', 'QueryName', 'Fqdn', 'DnsQuery'], keyPattern: /domain-name/i, defaultKeys: ['domain-name:value'], legacy: { column: 'DomainName' } },
  { type: 'url', label: 'URL', columns: ['RemoteUrl', 'Url', 'RequestURL', 'RequestUrl'], keyPattern: /^url/i, defaultKeys: ['url:value'], legacy: { column: 'Url' } },
];

// Built-in Windows binaries: their own file hash says nothing useful, so the hash of the
// process that launched them is preferred.
const SYSTEM_BINARIES = /(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|msiexec|wmic|schtasks|reg|net1?|sc|bcdedit|vssadmin|wevtutil)\.exe/i;

export interface ObservableChoice {
  column: string;
  type: ObservableType;
  label: string;
  referenced: boolean;
}

/** Standard join key: the lower-cased observable, carried by both sides of the lookup and by the samples. */
export const TI_KEY = 'ThreatIntel_Key';

export function tiTable(tables: ReferenceTable[]): ReferenceTable | undefined {
  return tables.find((t) => t.role === 'threat-intel');
}

export function observableChoices(ctx: EngineContext): ObservableChoice[] {
  if (!ctx.base) return [];
  const filtersSystemBinary = SYSTEM_BINARIES.test(ctx.parsed.text);
  const choices: (ObservableChoice & { rank: number })[] = [];
  RULES.forEach((rule, ruleIndex) => {
    rule.columns.forEach((col, colIndex) => {
      if (!isAvailable(ctx, col)) return;
      const referenced = ctx.identifiersLower.has(col.toLowerCase());
      const ownHashOfSystemBinary = filtersSystemBinary && ['sha256', 'sha1', 'md5'].includes(rule.type) && !col.startsWith('InitiatingProcess');
      const rank = (referenced ? 0 : 1000) + (ownHashOfSystemBinary ? 500 : 0) + ruleIndex * 10 + colIndex;
      choices.push({ column: col, type: rule.type, label: rule.label, referenced, rank });
    });
  });
  // Columns the rule derives itself, matched on their name (for example InitiatingIpAddress).
  const derivedPatterns: { type: ObservableType; pattern: RegExp }[] = [
    { type: 'sha256', pattern: /sha-?256/i }, { type: 'sha1', pattern: /sha-?1(?!\d)/i }, { type: 'md5', pattern: /md5/i },
    { type: 'ip', pattern: /(ip|ipaddress|ipaddr)$/i }, { type: 'url', pattern: /url$/i }, { type: 'domain', pattern: /(domain|fqdn)$/i },
  ];
  for (const name of ctx.derivedColumns.keys()) {
    if (choices.some((c) => c.column === name)) continue;
    const match = derivedPatterns.find((d) => d.pattern.test(name));
    if (!match) continue;
    const rule = RULES.find((x) => x.type === match.type) as ObservableRule;
    choices.push({ column: name, type: rule.type, label: rule.label, referenced: true, rank: 100 + RULES.indexOf(rule) });
  }
  return choices.sort((a, b) => a.rank - b.rank).map(({ rank: _rank, ...c }) => c);
}

export interface TiOptions {
  observable?: string;
}

export interface TiResult extends ModuleResult {
  choices: ObservableChoice[];
  choice?: ObservableChoice;
  /** Indicator column holding the value, and the indicator table, once known. */
  valueColumn?: string;
  tiTableName?: string;
}

export function runThreatIntel(ctx: EngineContext, opts: TiOptions): TiResult {
  const ti = tiTable(ctx.tables);
  const r: TiResult = { ...emptyResult('T', 'needs-data', ''), choices: [] };

  if (queryMentions(ctx, 'ThreatIntelIndicators', 'ThreatIntelligenceIndicator')) {
    r.status = 'already-present';
    r.summary = 'The rule already uses threat intelligence indicators.';
    return r;
  }
  if (!ctx.base || columnsOf(ctx.base).length === 0) {
    r.summary = `Upload a schema or sample for ${ctx.baseName ?? 'the base table'} first.`;
    return r;
  }
  if (!ti || columnsOf(ti).length === 0) {
    r.summary = 'Add ThreatIntelIndicators in Reference data to use this improvement.';
    return r;
  }

  r.choices = observableChoices(ctx);
  if (r.choices.length === 0) {
    r.status = 'not-applicable';
    r.summary = `${ctx.baseName} has no hash, IP address, domain or URL column to check against indicators.`;
    return r;
  }
  const choice = r.choices.find((c) => c.column === opts.observable) ?? r.choices[0];
  r.choice = choice;
  const rule = RULES.find((x) => x.type === choice.type) as ObservableRule;

  const isNew = hasColumn(ti, 'ObservableKey') && hasColumn(ti, 'ObservableValue');
  const isLegacy = !isNew && hasColumn(ti, rule.legacy.column);
  if (!isNew && !isLegacy) {
    r.status = 'not-applicable';
    r.summary = `The ${ti.name} schema has neither ObservableKey/ObservableValue nor ${rule.legacy.column}, so the indicator value cannot be located.`;
    return r;
  }

  const letName = uniqueLetName(ctx, 'TiIndicators');
  const timeCol = ['TimeGenerated', 'Timestamp'].find((c) => hasColumn(ti, c));
  const lines: string[] = [`let ${letName} = ${ti.name}`];
  if (timeCol) lines.push(`    | where ${timeCol} > ago(14d)`);
  let valueCol: string;
  let confidenceCol: string | undefined;

  if (isNew) {
    valueCol = 'ObservableValue';
    const seen = [...distinctValues(ti.sample, 'ObservableKey')].filter((k) => rule.keyPattern.test(k));
    const keys = seen.length ? seen : rule.defaultKeys;
    if (!seen.length) {
      r.findings.push({
        severity: 'warn', cat: 'T',
        title: `ObservableKey value for ${rule.label} assumed, not seen in your sample`,
        detail: `The query uses ${keys.map((k) => `"${k}"`).join(', ')}. Confirm the value in your workspace with: ${ti.name} | distinct ObservableKey`,
      });
    } else {
      r.findings.push({ severity: 'pass', cat: 'T', title: 'ObservableKey value taken from your sample', detail: `Using ${keys.map((k) => `"${k}"`).join(', ')}, as seen in the uploaded ${ti.name} sample.` });
    }
    lines.push(keys.length === 1 ? `    | where ObservableKey == ${quote(keys[0])}` : `    | where ObservableKey in (${keys.map(quote).join(', ')})`);
    confidenceCol = hasColumn(ti, 'Confidence') ? 'Confidence' : undefined;
    const latest = ['IsActive', 'ValidUntil', confidenceCol].filter((c): c is string => !!c && hasColumn(ti, c));
    if (timeCol) lines.push(`    | summarize arg_max(${timeCol}, ${latest.length ? latest.join(', ') : '*'}) by ObservableValue`);
    if (hasColumn(ti, 'IsActive')) lines.push('    | where IsActive == true');
    if (hasColumn(ti, 'ValidUntil')) lines.push('    | where isnull(ValidUntil) or ValidUntil > now()');
    r.uses.push(...['ObservableKey', 'ObservableValue', ...latest].map((c) => ({ table: ti.name, column: c, cat: 'T' as const })));
  } else {
    valueCol = rule.legacy.column;
    const conds = [`isnotempty(${valueCol})`];
    if (rule.legacy.hashType && hasColumn(ti, 'FileHashType')) {
      const seen = [...distinctValues(ti.sample, 'FileHashType')].filter((v) => rule.legacy.hashType!.test(v));
      const hashType = seen[0] ?? rule.legacy.defaultHashType!;
      if (!seen.length) r.findings.push({ severity: 'warn', cat: 'T', title: 'FileHashType value assumed', detail: `Using "${hashType}". Confirm with: ${ti.name} | distinct FileHashType` });
      conds.push(`FileHashType =~ ${quote(hashType)}`);
    }
    lines.push(`    | where ${conds.join(' and ')}`);
    confidenceCol = hasColumn(ti, 'ConfidenceScore') ? 'ConfidenceScore' : undefined;
    const latest = ['Active', 'ExpirationDateTime', confidenceCol].filter((c): c is string => !!c && hasColumn(ti, c));
    if (timeCol) lines.push(`    | summarize arg_max(${timeCol}, ${latest.length ? latest.join(', ') : '*'}) by ${valueCol}`);
    if (hasColumn(ti, 'Active')) lines.push('    | where Active == true');
    if (hasColumn(ti, 'ExpirationDateTime')) lines.push('    | where ExpirationDateTime > now()');
    r.uses.push(...[valueCol, ...latest].map((c) => ({ table: ti.name, column: c, cat: 'T' as const })));
  }
  if (timeCol) r.uses.push({ table: ti.name, column: timeCol, cat: 'T' });
  r.valueColumn = valueCol;
  r.tiTableName = ti.name;
  const projectParts = [`${TI_KEY} = tolower(${valueCol})`, `TiIndicator = ${valueCol}`];
  if (confidenceCol) projectParts.push(`TiConfidence = ${confidenceCol}`);
  lines.push(`    | project ${projectParts.join(', ')};`);
  r.edits.push({ type: 'insertTop', lines, cat: 'T' });

  r.edits.push({
    type: 'insertAtAnchor',
    cat: 'T',
    lines: [
      `| extend ${TI_KEY} = tolower(${choice.column})`,
      `| lookup kind=leftouter ${letName} on ${TI_KEY}`,
      '| extend TiMatch = isnotempty(TiIndicator)',
    ],
  });
  r.outputColumns.push(choice.column, 'TiMatch');
  if (confidenceCol) r.outputColumns.push('TiConfidence');
  const derived = ctx.derivedColumns.has(choice.column) && !hasColumn(ctx.base, choice.column);
  if (ctx.baseName && !derived) r.uses.push({ table: ctx.baseName, column: choice.column, cat: 'T' });

  r.status = 'applied';
  r.summary = `Checks ${choice.column} (${choice.label}) against active indicators in ${ti.name}.`;
  r.notes.push({
    cat: 'T',
    title: `${rule.label} check`,
    detail: `Looks up ${choice.column} against ${isNew ? 'active, unexpired' : 'active'} indicators from the last 14 days, on the lower-cased ThreatIntel_Key carried by both sides, and adds TiMatch${confidenceCol ? ' and TiConfidence' : ''} to each result.`,
    watch: `Only useful if the indicator feeds in this tenant include ${rule.label} indicators.`,
  });

  if (derived && !ctx.base.sample?.some((row) => row[TI_KEY] !== undefined)) {
    r.findings.push({ severity: 'info', cat: 'T', title: `${choice.column} is created by the rule, so indicator matches were not tested against the raw sample`, detail: `Export the base sample with the export queries in Reference data, which add ${TI_KEY}, to test it.` });
  } else if (ctx.base.sample?.length && ti.sample?.length) {
    // Only indicators the query would keep: right type, active and unexpired.
    const now = Date.now();
    const live = ti.sample.filter((row) => {
      if (isNew && !rule.keyPattern.test(String(row.ObservableKey ?? ''))) return false;
      const active = isNew ? row.IsActive : row.Active;
      if (active !== undefined && String(active).toLowerCase() === 'false') return false;
      const until = isNew ? row.ValidUntil : row.ExpirationDateTime;
      if (until && !Number.isNaN(Date.parse(String(until))) && Date.parse(String(until)) < now) return false;
      return true;
    });
    // Prefer the standard key columns when the samples were exported with them.
    const tiValues = live.some((row) => row[TI_KEY] !== undefined) ? distinctValues(live, TI_KEY, true) : distinctValues(live, valueCol, true);
    const baseKey = ctx.base.sample.some((row) => row[TI_KEY] !== undefined) ? TI_KEY : choice.column;
    const hits = ctx.base.sample.filter((row) => tiValues.has(String(row[baseKey] ?? '').toLowerCase())).length;
    r.findings.push({
      severity: hits > 0 ? 'pass' : 'info',
      cat: 'T',
      title: `${hits} of ${ctx.base.sample.length} sample rows match an indicator`,
      detail: hits > 0
        ? 'The lookup can be shown working against your sample.'
        : 'No sampled value appears in the indicator sample. This is normal for clean data; the lookup has been checked for field names only.',
    });
  }
  return r;
}
