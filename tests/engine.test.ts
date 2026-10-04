import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { improve, type ImproveOptions } from '../src/engine/improve';
import { buildParameterRegex, cleanJs } from '../src/engine/improve/evasion';
import { normaliseLayout, parseQuery } from '../src/engine/kql';
import { kqlRegexToJs, hasTerm } from '../src/engine/kqlEval';
import { POWERSHELL, acceptedForms, matchParameter } from '../src/engine/library/parameters';
import { parseSimplePredicate } from '../src/engine/predicate';
import { parseReferenceFile, roleForTable } from '../src/engine/reference';
import type { ReferenceTable } from '../src/engine/types';
import { buildRuleYaml } from '../src/engine/export';

const dir = join(__dirname, '..', 'src', 'examples', 'encoded-powershell');
const read = (f: string) => readFileSync(join(dir, f), 'utf8');

function table(name: string): ReferenceTable {
  const schema = parseReferenceFile(`${name}_schema.csv`, read(`${name}_schema.csv`));
  const sample = parseReferenceFile(`${name}_sample.json`, read(`${name}_sample.json`));
  return {
    id: name,
    name,
    role: name === 'DeviceProcessEvents' ? 'base' : roleForTable(name),
    schema: schema.schema,
    sample: sample.sample,
    problems: [...schema.problems, ...sample.problems],
  };
}

const tables = ['DeviceProcessEvents', 'IdentityInfo', 'ThreatIntelIndicators'].map(table);
const allOn: ImproveOptions = { enabled: { E: true, T: true, B: true, N: true, H: true }, entity: {}, ti: {} };
const inputs = { retired: false, baselineCurrent: false, flighted: false };

describe('KQL structure', () => {
  it('splits lets, the main query and operators, ignoring pipes inside strings', () => {
    const q = 'let x = "a|b";\nT\n| where c has "x|y" // a | comment\n| project c';
    const p = parseQuery(q);
    expect(p.letNames).toEqual(['x']);
    expect(p.main?.sourceTable).toBe('T');
    expect(p.main?.operators.map((o) => o.name)).toEqual(['where', 'project']);
  });

  it('puts operators that share a line onto their own lines', () => {
    expect(normaliseLayout('T | where a == 1 | project a')).toBe('T\n| where a == 1\n| project a');
  });
});

describe('Reference data parsing', () => {
  it('reads getschema CSV output and normalises types', () => {
    const t = tables[0];
    expect(t.schema?.find((c) => c.name === 'Timestamp')?.type).toBe('datetime');
    expect(t.sample).toHaveLength(100);
    expect(t.problems).toEqual([]);
  });

  it('reads the Log Analytics API JSON shape', () => {
    const json = JSON.stringify({ tables: [{ columns: [{ name: 'A' }, { name: 'B' }], rows: [[1, 'x']] }] });
    expect(parseReferenceFile('T_sample.json', json).sample).toEqual([{ A: 1, B: 'x' }]);
  });
});

describe('Parameter library', () => {
  it('expands every prefix of -EncodedCommand plus the documented aliases', () => {
    const p = POWERSHELL.parameters.find((x) => x.name === 'encodedcommand')!;
    const forms = acceptedForms(p);
    expect(forms).toContain('e');
    expect(forms).toContain('ec');
    expect(forms).toContain('enc');
    expect(forms).toContain('encodedcommand');
    expect(forms).toHaveLength(15);
  });

  it('maps literals to parameters and ignores unrelated text', () => {
    expect(matchParameter(POWERSHELL, '-enc')?.name).toBe('encodedcommand');
    expect(matchParameter(POWERSHELL, '-ex')?.name).toBe('executionpolicy');
    expect(matchParameter(POWERSHELL, '-ep')?.name).toBe('executionpolicy');
    expect(matchParameter(POWERSHELL, 'FromBase64String')).toBeUndefined();
  });

  it('builds a regex that catches evasion variants but not neighbouring parameters', () => {
    const p = POWERSHELL.parameters.find((x) => x.name === 'encodedcommand')!;
    const re = kqlRegexToJs(buildParameterRegex(POWERSHELL, [{ parameter: p, originalLiterals: ['-enc'] }]));
    const hits = ['-e ', '-ec ', '-En ', '/enc ', '\u2013enc ', '\u2014enc ', '-encodedcommand ', '-ENCODEDC '];
    for (const h of hits) expect(re.test(`powershell.exe ${h}AAAA`)).toBe(true);
    expect(re.test(cleanJs('powershell.exe -e^nc AAAA'))).toBe(true);
    expect(re.test(cleanJs('powershell.exe -e"nc" AAAA'))).toBe(true);
    expect(re.test('powershell.exe -ExecutionPolicy Bypass')).toBe(false);
    expect(re.test('powershell.exe -ex Bypass')).toBe(false);
    expect(re.test('powershell.exe C:\\temp\\file-enc.ps1')).toBe(false);
  });
});

describe('KQL operator approximations', () => {
  it('treats has as a whole-term match', () => {
    expect(hasTerm('powershell.exe -enc AAAA', '-enc')).toBe(true);
    expect(hasTerm('powershell.exe -encodedcommand AAAA', '-enc')).toBe(false);
  });

  it('parses simple predicates', () => {
    const p = parseSimplePredicate('ProcessCommandLine has_any ("-enc", "-encodedcommand")');
    expect(p?.operator).toBe('has_any');
    expect(p?.literals).toEqual(['-enc', '-encodedcommand']);
    expect(parseSimplePredicate('A has "x" or B has "y"')).toBeUndefined();
  });
});

describe('Worked example end to end', () => {
  const out = improve({ query: read('rule.kql'), tables, options: allOn, assessmentInputs: inputs });

  it('assesses the original rule as L1 and the improved rule as L2', () => {
    expect(out.platform).toBe('advanced-hunting');
    expect(out.assessment.tier).toBe('L1');
    expect(out.projected.tier).toBe('L2');
  });

  it('applies the three working improvements', () => {
    expect(out.modules.E.status).toBe('applied');
    expect(out.modules.T.status).toBe('applied');
    expect(out.modules.H.status).toBe('applied');
    expect(out.modules.B.status).toBe('not-implemented');
    expect(out.modules.N.status).toBe('not-applicable');
  });

  it('joins IdentityInfo on the strong identifier', () => {
    expect(out.modules.E.pair?.left).toBe('AccountObjectId');
    expect(out.text).toContain('| lookup kind=leftouter (');
    expect(out.text).toContain('  ) on AccountObjectId');
  });

  it('prefers the initiating process hash for a system binary and reads ObservableKey from the sample', () => {
    expect(out.modules.T.choice?.column).toBe('InitiatingProcessSHA256');
    expect(out.text).toContain(`| where ObservableKey == "file:hashes.'SHA-256'"`);
    expect(out.findings.some((f) => f.title === '4 of 100 sample rows match an indicator' || /sample rows match an indicator/.test(f.title))).toBe(true);
  });

  it('writes no column that is missing from the schemas', () => {
    expect(out.findings.filter((f) => f.severity === 'fail')).toEqual([]);
    expect(out.findings.some((f) => /column references written by the tool were found/.test(f.title))).toBe(true);
  });

  it('marks every added line with a category and keeps the original logic', () => {
    expect(out.lines.filter((l) => l.kind === 'add').every((l) => l.cat !== null)).toBe(true);
    expect(out.lines.filter((l) => l.kind === 'del')).toHaveLength(1);
    expect(out.text).toContain('| where FileName in~ ("powershell.exe", "pwsh.exe")');
    const project = out.lines.find((l) => l.kind === 'mod');
    expect(project?.segs.map((s) => s.cat)).toEqual([null, 'H', 'E', 'E', 'E', 'T', 'T', 'T']);
  });

  it('catches more of the sample and every bench variant once hardened', () => {
    const counts = out.modules.H.sampleCounts!;
    expect(counts.hardened).toBeGreaterThan(counts.original);
    expect(counts.hardened).toBe(56);
    expect(out.modules.H.bench.every((b) => b.hardened)).toBe(true);
    expect(out.modules.H.bench.some((b) => !b.original)).toBe(true);
  });

  it('produces the same text again when modules are switched off', () => {
    const none = improve({ query: read('rule.kql'), tables, options: { ...allOn, enabled: { E: false, T: false, B: false, N: false, H: false } }, assessmentInputs: inputs });
    expect(none.text).toBe(read('rule.kql'));
    expect(none.lines.every((l) => l.kind === 'ctx')).toBe(true);
  });

  it('exports a Sentinel rule with entity mappings', () => {
    const yaml = buildRuleYaml({ id: 'x', name: "It's a test", description: 'd', severity: 'Medium', queryFrequency: '1h', queryPeriod: '1h', tactics: 'Execution', techniques: 'T1059.001' }, out.text);
    expect(yaml).toContain("name: 'It''s a test'");
    expect(yaml).toContain('  - Execution');
    expect(yaml).toContain('identifier: AadUserId');
  });
});

describe('Soundness gate', () => {
  it('warns when only a weak identifier is shared', () => {
    const base: ReferenceTable = { id: 'b', name: 'MyTable', role: 'base', schema: [{ name: 'AccountName', type: 'string' }, { name: 'Timestamp', type: 'datetime' }], problems: [] };
    const id: ReferenceTable = { ...tables[1] };
    const out = improve({ query: 'MyTable\n| where Timestamp > ago(1h)\n| project AccountName', tables: [base, id], options: allOn, assessmentInputs: inputs });
    expect(out.modules.E.pair?.strength).toBe('weak');
    expect(out.findings.some((f) => /Soundness warning/.test(f.title))).toBe(true);
  });
});

describe('Identifiers the rule derives itself (AuditLogs)', () => {
  // AuditLogs has no top-level account identifier: they sit inside dynamic columns.
  const auditSchema = 'ColumnName,ColumnOrdinal,DataType,ColumnType\nTenantId,0,System.String,string\nTimeGenerated,2,System.DateTime,datetime\nOperationName,4,System.String,string\nInitiatedBy,20,System.Object,dynamic\nResult,22,System.String,string\nTargetResources,24,System.Object,dynamic\n';
  const audit: ReferenceTable = { id: 'auditlogs', name: 'AuditLogs', role: 'base', schema: parseReferenceFile('AuditLogs_schema.csv', auditSchema).schema, problems: [] };
  const identity: ReferenceTable = { ...tables[1], schema: [...tables[1].schema!, { name: 'TimeGenerated', type: 'datetime' }].filter((c) => c.name !== 'Timestamp') };

  it('uses a lower-cased object ID extracted by the rule as a strong join key', () => {
    const rule = 'AuditLogs\n| where OperationName =~ "Delete user"\n| mv-expand TargetResources\n| extend AccountObjectId = tolower(tostring(TargetResources.id))\n| project TimeGenerated, OperationName, AccountObjectId';
    const out = improve({ query: rule, tables: [audit, identity], options: allOn, assessmentInputs: inputs });
    expect(out.modules.E.status).toBe('applied');
    expect(out.modules.E.pair).toMatchObject({ left: 'AccountObjectId', strength: 'strong', derived: true, lowercase: true });
    expect(out.text).toContain('| project AccountObjectId = tolower(AccountObjectId), Department, JobTitle, AccountDisplayName');
    expect(out.text).toContain('| where TimeGenerated > ago(14d)');
    expect(out.findings.filter((f) => f.severity === 'fail')).toEqual([]);
  });

  it('recognises derived names such as TargetAadUserId', () => {
    const rule = 'AuditLogs\n| extend TargetAadUserId = tostring(TargetResources[0].id)\n| project TimeGenerated, TargetAadUserId';
    const out = improve({ query: rule, tables: [audit, identity], options: allOn, assessmentInputs: inputs });
    expect(out.modules.E.pair?.left).toBe('TargetAadUserId');
    expect(out.text).toContain('| project TargetAadUserId = AccountObjectId');
  });

  it('explains where the identifiers are when the rule extracts none', () => {
    const out = improve({ query: 'AuditLogs\n| where OperationName =~ "Delete user"\n| project TimeGenerated', tables: [audit, identity], options: allOn, assessmentInputs: inputs });
    expect(out.modules.E.status).toBe('not-applicable');
    expect(out.modules.E.summary).toContain('InitiatedBy, TargetResources');
  });
});
