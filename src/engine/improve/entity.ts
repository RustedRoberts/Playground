// Entity enrichment (pattern A1): look up IdentityInfo on a standard join key.
//
// Convention: both sides of the lookup carry a column named IdentityInfo_Key holding the
// lower-cased identifier. The tool writes it into the rule and into the export queries,
// so the rule, the samples and the lookup always agree and case never causes a miss.
import { IDENTIFIER_MAP, resolvePath } from '../library/identifiers';
import { columnType, columnsOf, hasColumn } from '../reference';
import type { ReferenceTable, Row } from '../types';
import { emptyResult, isAvailable, queryMentions, type EngineContext, type ModuleResult } from './context';

export const IDENTITY_KEY = 'IdentityInfo_Key';

export type KeySource = 'rule-key' | 'schema' | 'derived' | 'map' | 'override';

export interface KeyCandidate {
  id: string;
  label: string;
  /** KQL expression on the base table that yields the identifier (before lower-casing). */
  expression: string;
  /** IdentityInfo column it matches. */
  right: string;
  strength: 'strong' | 'weak';
  source: KeySource;
  referenced: boolean;
  /** Column checked against the base schema (the column itself, or the root of a nested path). */
  schemaColumn?: string;
  samplePath?: (string | number)[];
  note?: string;
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

// Columns the rule derives itself are matched on their name, so names such as
// TargetAadUserId or InitiatingUserObjectId are recognised as well as the standard ones.
const DERIVED_NAME_RULES: { pattern: RegExp; right: string[]; strength: 'strong' | 'weak' }[] = [
  { pattern: /(ObjectId|AadUserId|AadId|UserObjectId)$/i, right: ['AccountObjectId'], strength: 'strong' },
  { pattern: /Sid$/i, right: ['AccountSID', 'OnPremSid', 'AccountSid'], strength: 'strong' },
  { pattern: /(Upn|UserPrincipalName)$/i, right: ['AccountUpn', 'AccountUPN'], strength: 'weak' },
];

/** IdentityInfo columns an override can match, with their strength. */
export const IDENTITY_KEY_COLUMNS: { column: string; strength: 'strong' | 'weak' }[] = [
  { column: 'AccountObjectId', strength: 'strong' },
  { column: 'AccountSID', strength: 'strong' },
  { column: 'OnPremSid', strength: 'strong' },
  { column: 'AccountUpn', strength: 'weak' },
  { column: 'AccountUPN', strength: 'weak' },
  { column: 'AccountName', strength: 'weak' },
];

const PREFERRED_COLUMNS = ['Department', 'JobTitle', 'AssignedRoles', 'PrivilegedEntraPimRoles', 'AccountDisplayName', 'IsAccountEnabled', 'Tags', 'CriticalityLevel'];
const DEFAULT_COUNT = 3;

export function identityTable(tables: ReferenceTable[]): ReferenceTable | undefined {
  return tables.find((t) => t.role === 'entity');
}

/**
 * When the rule expands a dynamic column before the enrichment point, returns the name the
 * expanded item goes by: the alias in `mv-apply Item = Column` or `mv-expand Item = Column`,
 * or the column itself for a plain `mv-expand Column`.
 */
function expandedItem(ctx: EngineContext, column: string): string | undefined {
  for (const op of ctx.parsed.main?.operators ?? []) {
    if (op === ctx.anchorOperator) break;
    if (op.name !== 'mv-expand' && op.name !== 'mv-apply') continue;
    const alias = new RegExp(`\\b([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*${column}\\b`).exec(op.text);
    if (alias) return alias[1];
    if (new RegExp(`^\\|\\s*mv-(expand|apply)\\b[^|(]*\\b${column}\\b`).test(op.text)) return column;
  }
  return undefined;
}

/** Which account a candidate describes, so several identifiers of one account are not counted twice. */
function accountRole(c: KeyCandidate): string {
  if (c.source === 'map') return /target/.test(c.id) ? 'target' : /initiator/.test(c.id) ? 'initiator' : c.id;
  if (c.source === 'rule-key' || c.source === 'override') return c.source;
  const prefix = c.expression.replace(/(ObjectId|UserObjectId|AadUserId|AadId|Sid|Upn|UserPrincipalName|Name)$/i, '').toLowerCase() || c.expression.toLowerCase();
  return prefix.startsWith('target') ? 'target' : prefix;
}

/** Compares expressions ignoring whitespace, case and an outer tolower(). */
const normalise = (s: string) => {
  const t = s.replace(/\s+/g, '').toLowerCase();
  const m = /^tolower\((.*)\)$/.exec(t);
  return m ? m[1] : t;
};

export function keyCandidates(ctx: EngineContext, identity: ReferenceTable | undefined): KeyCandidate[] {
  if (!ctx.base || !identity) return [];
  const out: KeyCandidate[] = [];
  const firstRight = (options: string[]) => options.find((r) => hasColumn(identity, r));
  const referenced = (name: string) => ctx.identifiersLower.has(name.toLowerCase());

  // 1. The rule already creates the standard key.
  const ruleKey = ctx.derivedColumns.get(IDENTITY_KEY);
  if (ruleKey !== undefined) {
    const right = firstRight(['AccountObjectId']) ?? firstRight(IDENTITY_KEY_COLUMNS.map((c) => c.column));
    if (right) out.push({ id: 'rule-key', label: `${IDENTITY_KEY} created by the rule`, expression: IDENTITY_KEY, right, strength: IDENTITY_KEY_COLUMNS.find((c) => c.column === right)?.strength ?? 'weak', source: 'rule-key', referenced: true });
  }

  // 2. Columns in the schema, and columns the rule derives, with known identifier names.
  const add = (left: string, rights: string[], strength: 'strong' | 'weak') => {
    const right = firstRight(rights);
    if (!right || out.some((c) => c.expression === left)) return;
    const derived = ctx.derivedColumns.has(left) && !hasColumn(ctx.base, left);
    out.push({
      id: `${derived ? 'derived' : 'schema'}:${left}`,
      label: derived ? `${left} (created by the rule)` : left,
      expression: left,
      right,
      strength,
      source: derived ? 'derived' : 'schema',
      referenced: referenced(left),
      schemaColumn: derived ? undefined : left,
    });
  };
  for (const rule of KEY_RULES) {
    if (rule.tables && !rule.tables.includes(ctx.baseName ?? '')) continue;
    if (isAvailable(ctx, rule.left)) add(rule.left, rule.right, rule.strength);
  }
  for (const name of ctx.derivedColumns.keys()) {
    if (name === IDENTITY_KEY) continue;
    const rule = DERIVED_NAME_RULES.find((r) => r.pattern.test(name));
    if (rule) add(name, rule.right, rule.strength);
  }

  // 3. Nested identifiers from the built-in map.
  for (const m of IDENTIFIER_MAP[ctx.baseName ?? ''] ?? []) {
    if (!hasColumn(ctx.base, m.rootColumn)) continue;
    const right = firstRight(m.identityColumns);
    if (!right) continue;
    const item = expandedItem(ctx, m.rootColumn);
    const expression = item && m.expandedTemplate ? m.expandedTemplate.replace('{item}', item) : m.expression;
    // Skip a mapping the rule already extracts into a column of its own (for example
    // DeletedByAadUserId = tostring(InitiatedBy.user.id)); that column is offered instead.
    const extractedAs = [...ctx.derivedColumns.entries()].find(([, expr]) => normalise(expr) === normalise(expression) || normalise(expr) === normalise(m.expression));
    if (extractedAs && out.some((c) => c.expression === extractedAs[0])) continue;
    out.push({
      id: `map:${m.id}`,
      label: m.label,
      expression,
      right,
      strength: m.strength,
      source: 'map',
      referenced: referenced(m.rootColumn),
      schemaColumn: m.rootColumn,
      samplePath: m.samplePath,
      note: m.note,
    });
  }

  // The rule's own key first, then strong before weak, then identifiers the rule already uses.
  const order: Record<KeySource, number> = { 'rule-key': 0, schema: 1, derived: 1, map: 2, override: 3 };
  return out.sort((a, b) => {
    if (a.source === 'rule-key' || b.source === 'rule-key') return order[a.source] - order[b.source];
    if (a.strength !== b.strength) return a.strength === 'strong' ? -1 : 1;
    if (a.referenced !== b.referenced) return Number(b.referenced) - Number(a.referenced);
    return order[a.source] - order[b.source];
  });
}

export function enrichmentColumnChoices(identity: ReferenceTable | undefined, right: string | undefined): string[] {
  const exclude = new Set(['Timestamp', 'TimeGenerated', 'TenantId', 'SourceSystem', 'Type', IDENTITY_KEY, right ?? '']);
  const cols = columnsOf(identity).map((c) => c.name).filter((n) => !exclude.has(n));
  return [...PREFERRED_COLUMNS.filter((p) => cols.includes(p)), ...cols.filter((c) => !PREFERRED_COLUMNS.includes(c))];
}

export function defaultEnrichmentColumns(identity: ReferenceTable | undefined, right: string | undefined): string[] {
  return enrichmentColumnChoices(identity, right).filter((c) => PREFERRED_COLUMNS.includes(c)).slice(0, DEFAULT_COUNT);
}

export interface EntityOptions {
  candidateId?: string;
  columns?: string[];
  overrideExpression?: string;
  overrideRight?: string;
}

export interface EntityResult extends ModuleResult {
  candidates: KeyCandidate[];
  candidate?: KeyCandidate;
  columnChoices: string[];
  columns: string[];
  /** IdentityInfo columns available to match a custom expression against. */
  overrideRights: string[];
  /** Labels of the different accounts the rule involves, when there is more than one. */
  accounts: string[];
}

/** Lower-cased identifier values for the base sample under a candidate, or undefined if they cannot be worked out. */
function baseSampleKeys(rows: Row[], c: KeyCandidate): { values: string[]; resolved: number } | undefined {
  const fromKey = rows.some((r) => r[IDENTITY_KEY] !== undefined);
  if (fromKey) {
    const values = rows.map((r) => String(r[IDENTITY_KEY] ?? '').toLowerCase()).filter(Boolean);
    return { values, resolved: values.length };
  }
  if (c.source === 'schema' || (c.source === 'derived' && rows.some((r) => r[c.expression] !== undefined))) {
    const values = rows.map((r) => String(r[c.expression] ?? '').toLowerCase()).filter(Boolean);
    return { values, resolved: values.length };
  }
  if (c.source === 'map' && c.samplePath) {
    const values = rows.map((r) => resolvePath(r, c.samplePath!)).filter((v) => v !== undefined && v !== null && String(v).length).map((v) => String(v).toLowerCase());
    return { values, resolved: values.length };
  }
  return undefined;
}

function identitySampleKeys(rows: Row[], right: string): Set<string> {
  const useKey = rows.some((r) => r[IDENTITY_KEY] !== undefined);
  return new Set(rows.map((r) => String((useKey ? r[IDENTITY_KEY] : r[right]) ?? '').toLowerCase()).filter(Boolean));
}

export function runEntity(ctx: EngineContext, opts: EntityOptions): EntityResult {
  const identity = identityTable(ctx.tables);
  const r: EntityResult = { ...emptyResult('E', 'needs-data', ''), candidates: [], columnChoices: [], columns: [], overrideRights: [], accounts: [] };

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

  r.overrideRights = IDENTITY_KEY_COLUMNS.map((c) => c.column).filter((c) => hasColumn(identity, c));
  r.candidates = keyCandidates(ctx, identity);
  let candidate: KeyCandidate | undefined;
  if (opts.candidateId === 'override') {
    const expression = (opts.overrideExpression ?? '').trim();
    const right = opts.overrideRight && r.overrideRights.includes(opts.overrideRight) ? opts.overrideRight : r.overrideRights[0];
    if (expression && right) {
      candidate = { id: 'override', label: 'Custom expression', expression, right, strength: IDENTITY_KEY_COLUMNS.find((c) => c.column === right)?.strength ?? 'weak', source: 'override', referenced: true };
    } else {
      r.status = 'not-applicable';
      r.summary = 'Type the expression that extracts the identifier, and choose the IdentityInfo column it matches.';
      return r;
    }
  } else {
    // A rule can involve several accounts (for example the user acted on and the user who
    // acted). If it references more than one, the analyst must choose: guessing joins the
    // wrong account silently.
    const byRole = new Map<string, KeyCandidate>();
    for (const c of r.candidates) if (c.referenced && !byRole.has(accountRole(c))) byRole.set(accountRole(c), c);
    r.accounts = byRole.size > 1 ? [...byRole.values()].map((c) => c.label) : [];
    candidate = r.candidates.find((c) => c.id === opts.candidateId);
    if (!candidate && r.accounts.length === 0) candidate = r.candidates[0];
    if (!candidate && r.accounts.length) {
      r.status = 'not-applicable';
      r.summary = `This rule involves more than one account (${r.accounts.join('; ')}). Choose which one to enrich.`;
      r.findings.push({ severity: 'warn', cat: 'E', title: 'Choose which account to enrich', detail: `The rule refers to ${r.accounts.length} different accounts: ${r.accounts.join('; ')}. The tool will not guess, because joining the wrong one returns no enrichment without any error.` });
      return r;
    }
  }

  if (!candidate) {
    r.status = 'not-applicable';
    const dynamicCols = columnsOf(ctx.base).filter((c) => c.type === 'dynamic').map((c) => c.name);
    r.summary = dynamicCols.length
      ? `${ctx.baseName} has no top-level account identifier, and none is mapped for it yet. Identifiers are likely inside ${dynamicCols.slice(0, 3).join(', ')}. Choose "Custom expression" and give the path, for example tostring(${dynamicCols[0]}.id).`
      : `No account identifier is shared by ${ctx.baseName} and IdentityInfo in the uploaded schemas. Choose "Custom expression" to give one.`;
    return r;
  }
  r.candidate = candidate;
  r.columnChoices = enrichmentColumnChoices(identity, candidate.right);
  const wanted = opts.columns ?? defaultEnrichmentColumns(identity, candidate.right);
  r.columns = wanted.filter((c) => r.columnChoices.includes(c));
  if (r.columns.length === 0) r.columns = defaultEnrichmentColumns(identity, candidate.right);
  if (r.columns.length === 0) {
    r.status = 'not-applicable';
    r.summary = 'IdentityInfo has no columns to add beyond its identifiers.';
    return r;
  }

  const timeCol = ['TimeGenerated', 'Timestamp'].find((c) => hasColumn(identity, c));
  // Rename any column that already exists on the base table, so nothing is silently overwritten.
  const outputs = r.columns.map((c) => ({ source: c, output: isAvailable(ctx, c) ? `Identity${c}` : c }));

  const lines: string[] = [];
  const ruleKeyLowered = candidate.source === 'rule-key' && /\btolower\s*\(/i.test(ctx.derivedColumns.get(IDENTITY_KEY) ?? '');
  if (!ruleKeyLowered) lines.push(`| extend ${IDENTITY_KEY} = tolower(${candidate.expression})`);
  lines.push('| lookup kind=leftouter (', '    IdentityInfo');
  if (timeCol) lines.push(`    | where ${timeCol} > ago(14d)`);
  lines.push(`    | extend ${IDENTITY_KEY} = tolower(${candidate.right})`);
  lines.push(`    | where isnotempty(${IDENTITY_KEY})`);
  if (timeCol) lines.push(`    | summarize arg_max(${timeCol}, ${r.columns.join(', ')}) by ${IDENTITY_KEY}`);
  else lines.push(`    | summarize take_any(${r.columns.join(', ')}) by ${IDENTITY_KEY}`);
  lines.push(`    | project ${[IDENTITY_KEY, ...outputs.map((o) => (o.output === o.source ? o.source : `${o.output} = ${o.source}`))].join(', ')}`);
  lines.push(`  ) on ${IDENTITY_KEY}`);
  r.edits.push({ type: 'insertAtAnchor', lines, cat: 'E' });
  r.outputColumns.push(...outputs.map((o) => o.output));

  if (ctx.baseName && candidate.schemaColumn) r.uses.push({ table: ctx.baseName, column: candidate.schemaColumn, cat: 'E' });
  r.uses.push({ table: identity.name, column: candidate.right, cat: 'E' });
  if (timeCol) r.uses.push({ table: identity.name, column: timeCol, cat: 'E' });
  r.columns.forEach((c) => r.uses.push({ table: identity.name, column: c, cat: 'E' }));

  r.status = 'applied';
  r.summary = `Looks up ${r.columns.join(', ')} from IdentityInfo on ${IDENTITY_KEY}, built from ${candidate.expression} (${candidate.strength} identifier, matched to ${candidate.right}).`;
  r.notes.push({
    cat: 'E',
    title: 'IdentityInfo lookup',
    detail: `Adds ${r.columns.join(', ')} for the account in each result, using the most recent IdentityInfo record from the last 14 days. Both sides carry ${IDENTITY_KEY}, the lower-cased identifier (${candidate.expression} on this table, ${candidate.right} on IdentityInfo), so case differences cannot cause a missed match.${candidate.note ? ` ${candidate.note}` : ''}`,
    watch: `Rows without an identifier (for example local and system accounts, or operations started by an application) pass through without enrichment.`,
  });

  // Soundness gate: strong versus weak identifier.
  if (candidate.strength === 'weak') {
    const strongAvailable = r.candidates.find((c) => c.strength === 'strong');
    r.findings.push({
      severity: 'warn',
      cat: 'E',
      title: `Soundness warning: ${candidate.expression} is a weak identifier`,
      detail: `Names and UPNs change when accounts are renamed, can be duplicated and are dropped for generic built-in names, so the lookup can fail silently. ${strongAvailable ? `Use ${strongAvailable.label} instead, which is available here.` : 'No strong identifier is available in the uploaded schemas, so this is the best available; document the risk.'}`,
    });
  } else {
    r.findings.push({ severity: 'pass', cat: 'E', title: `Join key is a strong identifier (${candidate.right})`, detail: 'It identifies the account on its own, so the lookup will not be affected by renames or duplicate names.' });
  }

  if (candidate.source === 'schema') {
    const lt = columnType(ctx.base, candidate.expression);
    if (lt && lt !== 'unknown' && lt !== 'string' && lt !== 'guid') {
      r.findings.push({ severity: 'warn', cat: 'E', title: `${candidate.expression} is of type ${lt}`, detail: 'tolower() works on strings. Wrap the identifier in tostring() if the lookup returns nothing.' });
    }
  }

  // Overlap between the samples.
  if (ctx.base.sample?.length && identity.sample?.length) {
    const base = baseSampleKeys(ctx.base.sample, candidate);
    if (!base) {
      r.findings.push({
        severity: 'info',
        cat: 'E',
        title: 'Lookup not tested against the sample',
        detail: `The identifier comes from the rule's own steps, and the base sample has no ${IDENTITY_KEY} column. Export the base sample with the export queries in Reference data, which add ${IDENTITY_KEY}, to test it.`,
      });
    } else {
      if (candidate.samplePath && base.resolved === 0 && !ctx.base.sample.some((row) => row[IDENTITY_KEY] !== undefined)) {
        r.findings.push({ severity: 'warn', cat: 'E', title: `${candidate.expression} resolved in none of the ${ctx.base.sample.length} sample rows`, detail: 'The path may be wrong for these operations. Check a sample row, or choose another identifier.' });
      }
      const distinct = new Set(base.values);
      const right = identitySampleKeys(identity.sample, candidate.right);
      const matched = [...distinct].filter((v) => right.has(v)).length;
      r.findings.push({
        severity: matched > 0 ? 'pass' : 'warn',
        cat: 'E',
        title: `${matched} of ${distinct.size} distinct identifiers in the sample have an IdentityInfo row`,
        detail: matched > 0
          ? 'The lookup can be shown working against your sample, comparing lower-cased values.'
          : 'None of the sampled accounts appear in the IdentityInfo sample. Export IdentityInfo with the export queries in Reference data, which take it for the same accounts as the base sample.',
      });
    }
  } else {
    r.findings.push({ severity: 'info', cat: 'E', title: 'Lookup not tested against sample rows', detail: 'Upload sample rows for both tables to check that the lookup finds matches.' });
  }
  return r;
}
