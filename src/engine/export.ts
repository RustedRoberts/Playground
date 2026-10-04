// Exports: a Sentinel analytics rule in the Azure-Sentinel repository YAML format, and
// a pull request description summarising the change.
import { CATEGORY_LABELS } from './categories';
import type { ImproveOutput } from './improve';

export interface RuleMetadata {
  id: string;
  name: string;
  description: string;
  severity: 'Informational' | 'Low' | 'Medium' | 'High';
  queryFrequency: string;
  queryPeriod: string;
  tactics: string;
  techniques: string;
}

const ENTITY_MAP: { column: string; entityType: string; identifier: string }[] = [
  { column: 'AccountObjectId', entityType: 'Account', identifier: 'AadUserId' },
  { column: 'AccountSid', entityType: 'Account', identifier: 'Sid' },
  { column: 'AccountName', entityType: 'Account', identifier: 'Name' },
  { column: 'AccountUpn', entityType: 'Account', identifier: 'FullName' },
  { column: 'UserPrincipalName', entityType: 'Account', identifier: 'FullName' },
  { column: 'DeviceName', entityType: 'Host', identifier: 'HostName' },
  { column: 'Computer', entityType: 'Host', identifier: 'HostName' },
  { column: 'ProcessCommandLine', entityType: 'Process', identifier: 'CommandLine' },
  { column: 'RemoteIP', entityType: 'IP', identifier: 'Address' },
  { column: 'IPAddress', entityType: 'IP', identifier: 'Address' },
  { column: 'SrcIpAddr', entityType: 'IP', identifier: 'Address' },
];

function yamlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function yamlList(csv: string): string {
  const items = csv.split(',').map((s) => s.trim()).filter(Boolean);
  return items.length ? '\n' + items.map((i) => `  - ${i}`).join('\n') : ' []';
}

function block(text: string, indent = '  '): string {
  return text.split('\n').map((l) => (l.length ? indent + l : '')).join('\n');
}

export function newRuleId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}

export function entityMappingsFor(query: string): { entityType: string; fields: { identifier: string; column: string }[] }[] {
  const words = new Set(query.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []);
  const grouped = new Map<string, { identifier: string; column: string }[]>();
  for (const m of ENTITY_MAP) {
    if (!words.has(m.column)) continue;
    const list = grouped.get(m.entityType) ?? [];
    if (list.some((f) => f.identifier === m.identifier)) continue;
    list.push({ identifier: m.identifier, column: m.column });
    grouped.set(m.entityType, list);
  }
  return [...grouped.entries()].slice(0, 5).map(([entityType, fields]) => ({ entityType, fields: fields.slice(0, 3) }));
}

export function buildRuleYaml(meta: RuleMetadata, query: string): string {
  const mappings = entityMappingsFor(query);
  const mappingYaml = mappings.length
    ? '\n' + mappings.map((m) => `  - entityType: ${m.entityType}\n    fieldMappings:\n${m.fields.map((f) => `      - identifier: ${f.identifier}\n        columnName: ${f.column}`).join('\n')}`).join('\n')
    : ' []';
  return [
    `id: ${meta.id}`,
    `name: ${yamlString(meta.name || 'Untitled detection')}`,
    'description: |',
    block(meta.description || 'Describe what this rule detects and why it matters.'),
    `severity: ${meta.severity}`,
    'requiredDataConnectors: []',
    `queryFrequency: ${meta.queryFrequency}`,
    `queryPeriod: ${meta.queryPeriod}`,
    'triggerOperator: gt',
    'triggerThreshold: 0',
    `tactics:${yamlList(meta.tactics)}`,
    `relevantTechniques:${yamlList(meta.techniques)}`,
    'query: |',
    block(query),
    `entityMappings:${mappingYaml}`,
    'version: 1.0.0',
    'kind: Scheduled',
    '',
  ].join('\n');
}

export function buildPrDescription(name: string, out: ImproveOutput): string {
  const lines: string[] = [];
  lines.push(`## ${name || 'Detection improvement'}`, '');
  lines.push(`**Maturity:** ${out.assessment.tier} (${out.assessment.tierLabel}) to ${out.projected.tier} (${out.projected.tierLabel})`, '');
  lines.push('### Changes', '');
  for (const n of out.notes) {
    const label = n.cat ? `${CATEGORY_LABELS[n.cat]} [${n.cat}]` : 'General';
    lines.push(`- **${label}: ${n.title}.** ${n.detail}${n.watch ? ` Watch for: ${n.watch}` : ''}`);
  }
  lines.push('', '### Checks against reference data', '');
  for (const f of out.findings) {
    const mark = f.severity === 'pass' ? 'Passed' : f.severity === 'fail' ? 'Failed' : f.severity === 'warn' ? 'Warning' : 'Note';
    lines.push(`- ${mark}: ${f.title}`);
  }
  lines.push('', '### Validation evidence', '', '- [ ] Query executed in the target workspace', '- [ ] Result screenshot attached', '- [ ] MITRE mapping confirmed', '- [ ] Compliance tags reviewed', '');
  lines.push('_Prepared with the Detection Improvement Tool. Reference data stayed in the browser and is not part of this pull request._', '');
  return lines.join('\n');
}
