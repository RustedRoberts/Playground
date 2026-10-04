// Entity enrichment (pattern A1): join IdentityInfo on the strongest shared identifier.
import { columnType, columnsOf, distinctValues, hasColumn } from '../reference';
import type { ReferenceTable } from '../types';
import { emptyResult, queryMentions, type EngineContext, type ModuleResult } from './context';

export interface KeyPair {
  id: string;
  left: string;
  right: string;
  strength: 'strong' | 'weak';
  referenced: boolean;
}

interface KeyRule {
  left: string;
  right: string[];
  strength: 'strong' | 'weak';
  tables?: string[];
}

// Strong identifiers identify an account on their own; weak ones (names, UPNs) change
// on rename, can be duplicated and are dropped for generic built-in names.
const KEY_RULES: KeyRule[] = [
  { left: 'AccountObjectId', right: ['AccountObjectId'], strength: 'strong' },
  { left: 'InitiatingProcessAccountObjectId', right: ['AccountObjectId'], strength: 'strong' },
  { left: 'AadUserId', right: ['AccountObjectId'], strength: 'strong' },
  { left: 'UserId', right: ['AccountObjectId'], strength: 'strong', tables: ['SigninLogs', 'AADNonInteractiveUserSignInLogs'] },
  { left: 'AccountSid', right: ['AccountSID', 'OnPremSid', 'AccountSid'], strength: 'strong' },
  { left: 'InitiatingProcessAccountSid', right: ['AccountSID', 'OnPremSid', 'AccountSid'], strength: 'strong' },
  { left: 'AccountUpn', right: ['AccountUpn', 'AccountUPN'], strength: 'weak' },
  { left: 'InitiatingProcessAccountUpn', right: ['AccountUpn', 'AccountUPN'], strength: 'weak' },
  { left: 'UserPrincipalName', right: ['AccountUpn', 'AccountUPN'], strength: 'weak' },
  { left: 'AccountName', right: ['AccountName'], strength: 'weak' },
  { left: 'InitiatingProcessAccountName', right: ['AccountName'], strength: 'weak' },
];

const PREFERRED_COLUMNS = ['Department', 'JobTitle', 'AssignedRoles', 'PrivilegedEntraPimRoles', 'AccountDisplayName', 'IsAccountEnabled', 'Tags', 'CriticalityLevel'];
const DEFAULT_COUNT = 3;

export function identityTable(tables: ReferenceTable[]): ReferenceTable | undefined {
  return tables.find((t) => t.role === 'entity');
}

export function keyPairs(ctx: EngineContext, identity: ReferenceTable | undefined): KeyPair[] {
  if (!ctx.base || !identity) return [];
  const pairs: KeyPair[] = [];
  for (const rule of KEY_RULES) {
    if (rule.tables && !rule.tables.includes(ctx.baseName ?? '')) continue;
    if (!hasColumn(ctx.base, rule.left)) continue;
    const right = rule.right.find((r) => hasColumn(identity, r));
    if (!right) continue;
    pairs.push({ id: `${rule.left}=${right}`, left: rule.left, right, strength: rule.strength, referenced: ctx.identifiersLower.has(rule.left.toLowerCase()) });
  }
  // Strong first, then identifiers the rule already uses, then rule order.
  return pairs.sort((a, b) => (a.strength === b.strength ? Number(b.referenced) - Number(a.referenced) : a.strength === 'strong' ? -1 : 1));
}

export function enrichmentColumnChoices(identity: ReferenceTable | undefined, pair: KeyPair | undefined): string[] {
  const exclude = new Set(['Timestamp', 'TimeGenerated', 'TenantId', 'SourceSystem', 'Type', pair?.right ?? '']);
  const cols = columnsOf(identity).map((c) => c.name).filter((n) => !exclude.has(n));
  return [...PREFERRED_COLUMNS.filter((p) => cols.includes(p)), ...cols.filter((c) => !PREFERRED_COLUMNS.includes(c))];
}

export function defaultEnrichmentColumns(identity: ReferenceTable | undefined, pair: KeyPair | undefined): string[] {
  return enrichmentColumnChoices(identity, pair).filter((c) => PREFERRED_COLUMNS.includes(c)).slice(0, DEFAULT_COUNT);
}

export interface EntityOptions {
  pairId?: string;
  columns?: string[];
}

export interface EntityResult extends ModuleResult {
  pairs: KeyPair[];
  pair?: KeyPair;
  columnChoices: string[];
  columns: string[];
}

export function runEntity(ctx: EngineContext, opts: EntityOptions): EntityResult {
  const identity = identityTable(ctx.tables);
  const r: EntityResult = { ...emptyResult('E', 'needs-data', ''), pairs: [], columnChoices: [], columns: [] };

  if (queryMentions(ctx, 'IdentityInfo')) {
    r.status = 'already-present';
    r.summary = 'The rule already uses IdentityInfo.';
    return r;
  }
  if (!ctx.base || columnsOf(ctx.base).length === 0) {
    r.summary = `Upload a schema or sample for ${ctx.baseName ?? 'the base table'} first.`;
    return r;
  }
  if (!identity || columnsOf(identity).length === 0) {
    r.summary = 'Add IdentityInfo in Reference data to use this improvement.';
    return r;
  }

  r.pairs = keyPairs(ctx, identity);
  if (r.pairs.length === 0) {
    r.status = 'not-applicable';
    r.summary = `No account identifier is shared by ${ctx.baseName} and IdentityInfo in the uploaded schemas.`;
    return r;
  }
  const pair = r.pairs.find((p) => p.id === opts.pairId) ?? r.pairs[0];
  r.pair = pair;
  r.columnChoices = enrichmentColumnChoices(identity, pair);
  const wanted = opts.columns ?? defaultEnrichmentColumns(identity, pair);
  r.columns = wanted.filter((c) => r.columnChoices.includes(c));
  if (r.columns.length === 0) {
    r.status = 'not-applicable';
    r.summary = 'Choose at least one IdentityInfo column to add.';
    return r;
  }

  const timeCol = ['Timestamp', 'TimeGenerated'].find((c) => hasColumn(identity, c));
  // Rename any column that already exists on the base table, so nothing is silently overwritten.
  const outputs = r.columns.map((c) => ({ source: c, output: hasColumn(ctx.base, c) ? `Identity${c}` : c }));
  const projectList = [pair.left === pair.right ? pair.left : `${pair.left} = ${pair.right}`, ...outputs.map((o) => (o.output === o.source ? o.source : `${o.output} = ${o.source}`))].join(', ');
  const lines = ['| lookup kind=leftouter (', '    IdentityInfo'];
  if (timeCol) lines.push(`    | where ${timeCol} > ago(14d)`);
  lines.push(`    | where isnotempty(${pair.right})`);
  if (timeCol) lines.push(`    | summarize arg_max(${timeCol}, ${r.columns.join(', ')}) by ${pair.right}`);
  else lines.push(`    | summarize take_any(${r.columns.join(', ')}) by ${pair.right}`);
  lines.push(`    | project ${projectList}`);
  lines.push(`  ) on ${pair.left}`);

  r.edits.push({ type: 'insertAtAnchor', lines, cat: 'E' });
  r.outputColumns.push(...outputs.map((o) => o.output));
  if (ctx.baseName) r.uses.push({ table: ctx.baseName, column: pair.left, cat: 'E' });
  r.uses.push({ table: identity.name, column: pair.right, cat: 'E' });
  if (timeCol) r.uses.push({ table: identity.name, column: timeCol, cat: 'E' });
  r.columns.forEach((c) => r.uses.push({ table: identity.name, column: c, cat: 'E' }));

  r.status = 'applied';
  r.summary = `Looks up ${r.columns.join(', ')} from IdentityInfo on ${pair.left} (${pair.strength} identifier).`;
  r.notes.push({
    cat: 'E',
    title: 'IdentityInfo lookup',
    detail: `Adds ${r.columns.join(', ')} for the account in each result, using the most recent IdentityInfo record from the last 14 days, so severity can be tiered by who ran it.`,
    watch: `Rows without a ${pair.left} value (for example local and system accounts) pass through without enrichment.`,
  });

  // Soundness gate: strong versus weak identifier.
  if (pair.strength === 'weak') {
    const strongAvailable = r.pairs.find((p) => p.strength === 'strong');
    r.findings.push({
      severity: 'warn',
      cat: 'E',
      title: `Soundness warning: ${pair.left} is a weak identifier`,
      detail: `Names and UPNs change when accounts are renamed, can be duplicated and are dropped for generic built-in names, so the lookup can fail silently. ${strongAvailable ? `Use ${strongAvailable.left} instead, which is available in this table.` : 'No strong identifier is shared in the uploaded schemas, so this is the best available; document the risk.'}`,
    });
  } else {
    r.findings.push({ severity: 'pass', cat: 'E', title: `Join key ${pair.left} is a strong identifier`, detail: `It identifies the account on its own, so the lookup will not be affected by renames or duplicate names.` });
  }

  // Type check on the join key.
  const lt = columnType(ctx.base, pair.left);
  const rt = columnType(identity, pair.right);
  if (lt && rt && lt !== 'unknown' && rt !== 'unknown' && lt !== rt) {
    r.findings.push({ severity: 'fail', cat: 'E', title: 'Join key types do not match', detail: `${pair.left} is ${lt} in ${ctx.baseName} but ${pair.right} is ${rt} in IdentityInfo. Convert one side before joining.` });
  }

  // Overlap between the samples.
  if (ctx.base.sample?.length && identity.sample?.length) {
    const leftValues = distinctValues(ctx.base.sample, pair.left, true);
    const rightValues = distinctValues(identity.sample, pair.right, true);
    const matched = [...leftValues].filter((v) => rightValues.has(v)).length;
    r.findings.push({
      severity: matched > 0 ? 'pass' : 'warn',
      cat: 'E',
      title: `${matched} of ${leftValues.size} distinct ${pair.left} values in the sample have an IdentityInfo row`,
      detail: matched > 0
        ? 'The lookup can be shown working against your sample.'
        : 'None of the sampled accounts appear in the IdentityInfo sample, so the lookup cannot be shown working. Export IdentityInfo for the same accounts as the base sample.',
    });
  } else {
    r.findings.push({ severity: 'info', cat: 'E', title: 'Lookup not tested against sample rows', detail: 'Upload sample rows for both tables to check that the lookup finds matches.' });
  }
  return r;
}
