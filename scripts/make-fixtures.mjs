// Generates the synthetic worked example used by the "Load worked example" button and
// by the unit tests. Every value is invented: the accounts use Microsoft's fictional
// Contoso domain, and the encoded payloads decode to a harmless test string.
// Run with: npm run fixtures
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const outDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'examples', 'encoded-powershell');
mkdirSync(outDir, { recursive: true });

// Deterministic pseudo-random numbers so the files are stable between runs.
let seed = 20261004;
const rand = () => ((seed = (seed * 1664525 + 1013904223) >>> 0) / 4294967296);
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const hex = (n) => Array.from({ length: n }, () => Math.floor(rand() * 16).toString(16)).join('');
const guid = () => `${hex(8)}-${hex(4)}-4${hex(3)}-a${hex(3)}-${hex(12)}`;
const iso = (day, minute) => new Date(Date.UTC(2026, 9, day, 8, minute, Math.floor(rand() * 60))).toISOString();

// Writes JSON with every non-ASCII character escaped, so the files contain only ASCII.
const asciiJson = (value) => JSON.stringify(value, null, 2).replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
const b64utf16 = (text) => Buffer.from(text, 'utf16le').toString('base64');

const tenantId = guid();
const accounts = Array.from({ length: 12 }, (_, i) => {
  const n = String(i + 1).padStart(2, '0');
  return {
    AccountObjectId: guid(),
    AccountName: `user${n}`,
    AccountDomain: 'contoso',
    AccountUpn: `user${n}@contoso.com`,
    AccountSid: `S-1-5-21-1004336348-1177238915-682003330-${1100 + i}`,
    AccountDisplayName: `Test User ${n}`,
    Department: pick(['Finance', 'Payments', 'IT Operations', 'Engineering', 'Customer Support', 'Treasury']),
    JobTitle: pick(['Analyst', 'Engineer', 'Team Lead', 'Administrator', 'Associate']),
  };
});
accounts[0].Department = 'IT Operations';
accounts[0].JobTitle = 'Global Administrator';
const devices = Array.from({ length: 8 }, (_, i) => ({ DeviceId: hex(40), DeviceName: `wks-${String(i + 1).padStart(3, '0')}.contoso.com` }));

const payloads = ["Write-Output 'Synthetic test data'", "Get-Date | Out-Null", "Write-Host 'Lab only'"].map(b64utf16);
const powershellSha = hex(64);
const pwshSha = hex(64);
const parents = [
  { name: 'cmd.exe', sha: hex(64) },
  { name: 'explorer.exe', sha: hex(64) },
  { name: 'WmiPrvSE.exe', sha: hex(64) },
  { name: 'svchost.exe', sha: hex(64) },
];
const suspiciousParent = { name: 'invoice_viewer.exe', sha: hex(64) };
const retiredParent = { name: 'old_tool.exe', sha: hex(64) };

const commandPlan = [
  ...Array(44).fill(['benign']),
  ...Array(15).fill(['-EncodedCommand']),
  ...Array(12).fill(['-enc']),
  ...Array(6).fill(['-e']),
  ...Array(4).fill(['-ec']),
  ...Array(3).fill(['-En']),
  ...Array(3).fill(['/enc']),
  ...Array(3).fill(['\u2013enc']),
  ...Array(2).fill(['-e^nc']),
  ...Array(3).fill(['-e"nc"']),
  ...Array(3).fill(['-encodedc']),
  ...Array(2).fill(['-ENCODEDCOMMAND']),
];
const benign = [
  'powershell.exe -NoProfile -File C:\\Scripts\\Inventory.ps1',
  'pwsh.exe -NoLogo -Command Get-Service',
  'powershell.exe -ExecutionPolicy Bypass -File "C:\\Program Files\\Agent\\update.ps1"',
  'powershell.exe -NonInteractive -Command "Get-Process | Sort-Object CPU"',
  'pwsh.exe -WorkingDirectory C:\\Temp -Command Get-ChildItem',
];

const dpe = commandPlan.map(([form], i) => {
  const acct = accounts[i % accounts.length];
  const dev = devices[i % devices.length];
  const isPwsh = rand() < 0.3;
  const image = isPwsh ? 'pwsh.exe' : 'powershell.exe';
  let parent = pick(parents);
  if (form !== 'benign' && i % 9 === 0) parent = suspiciousParent;
  if (form !== 'benign' && i % 13 === 0) parent = retiredParent;
  const cmd = form === 'benign' ? pick(benign) : `${image} -NoLogo ${form} ${pick(payloads)}`;
  return {
    Timestamp: iso(1 + (i % 3), i % 60),
    TenantId: tenantId,
    DeviceId: dev.DeviceId,
    DeviceName: dev.DeviceName,
    ActionType: 'ProcessCreated',
    FileName: cmd.startsWith('pwsh') ? 'pwsh.exe' : 'powershell.exe',
    FolderPath: cmd.startsWith('pwsh') ? 'C:\\Program Files\\PowerShell\\7\\pwsh.exe' : 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    SHA256: cmd.startsWith('pwsh') ? pwshSha : powershellSha,
    ProcessCommandLine: cmd,
    AccountDomain: acct.AccountDomain,
    AccountName: acct.AccountName,
    AccountSid: acct.AccountSid,
    AccountUpn: acct.AccountUpn,
    AccountObjectId: acct.AccountObjectId,
    InitiatingProcessFileName: parent.name,
    InitiatingProcessSHA256: parent.sha,
    InitiatingProcessCommandLine: parent.name,
  };
});

const dpeSchema = [
  ['Timestamp', 'datetime'], ['TenantId', 'string'], ['DeviceId', 'string'], ['DeviceName', 'string'], ['ActionType', 'string'],
  ['FileName', 'string'], ['FolderPath', 'string'], ['SHA256', 'string'], ['ProcessCommandLine', 'string'],
  ['AccountDomain', 'string'], ['AccountName', 'string'], ['AccountSid', 'string'], ['AccountUpn', 'string'], ['AccountObjectId', 'string'],
  ['InitiatingProcessFileName', 'string'], ['InitiatingProcessSHA256', 'string'], ['InitiatingProcessCommandLine', 'string'],
];

const identity = [];
for (let day = 1; day <= 6; day++) {
  for (const a of accounts) {
    identity.push({
      Timestamp: iso(day, 0),
      AccountObjectId: a.AccountObjectId,
      AccountUpn: a.AccountUpn,
      AccountName: a.AccountName,
      AccountDomain: a.AccountDomain,
      AccountDisplayName: a.AccountDisplayName,
      OnPremSid: a.AccountSid,
      Department: a.Department,
      JobTitle: a.JobTitle,
      IsAccountEnabled: true,
    });
  }
}
while (identity.length < 100) {
  const n = identity.length;
  identity.push({
    Timestamp: iso(6, 0),
    AccountObjectId: guid(),
    AccountUpn: `other${n}@contoso.com`,
    AccountName: `other${n}`,
    AccountDomain: 'contoso',
    AccountDisplayName: `Other User ${n}`,
    OnPremSid: `S-1-5-21-1004336348-1177238915-682003330-${2000 + n}`,
    Department: pick(['Finance', 'Legal', 'Marketing']),
    JobTitle: 'Associate',
    IsAccountEnabled: rand() > 0.1,
  });
}
const identitySchema = [
  ['Timestamp', 'datetime'], ['AccountObjectId', 'string'], ['AccountUpn', 'string'], ['AccountName', 'string'], ['AccountDomain', 'string'],
  ['AccountDisplayName', 'string'], ['OnPremSid', 'string'], ['Department', 'string'], ['JobTitle', 'string'], ['IsAccountEnabled', 'bool'],
];

const ti = [];
const keys = [
  ...Array(40).fill("file:hashes.'SHA-256'"),
  ...Array(30).fill('ipv4-addr:value'),
  ...Array(20).fill('domain-name:value'),
  ...Array(10).fill('url:value'),
];
keys.forEach((key, i) => {
  let value;
  if (key.startsWith('file')) value = hex(64).toUpperCase();
  else if (key.startsWith('ipv4')) value = `203.0.113.${(i * 7) % 250}`;
  else if (key.startsWith('domain')) value = `bad-${i}.example`;
  else value = `https://bad-${i}.example/payload`;
  ti.push({
    TimeGenerated: iso(3, i % 60),
    Id: `indicator--${guid()}`,
    ObservableKey: key,
    ObservableValue: value,
    IsActive: true,
    Confidence: 50 + Math.floor(rand() * 50),
    ValidFrom: iso(1, 0),
    ValidUntil: '2027-01-01T00:00:00.000Z',
    SourceSystem: 'Synthetic Feed',
  });
});
// One active indicator for the suspicious parent (upper case, to exercise case-insensitive matching)
// and one inactive indicator for the retired parent.
ti[0].ObservableValue = suspiciousParent.sha.toUpperCase();
ti[1].ObservableValue = retiredParent.sha;
ti[1].IsActive = false;
const tiSchema = [
  ['TimeGenerated', 'datetime'], ['Id', 'string'], ['ObservableKey', 'string'], ['ObservableValue', 'string'], ['IsActive', 'bool'],
  ['Confidence', 'int'], ['ValidFrom', 'datetime'], ['ValidUntil', 'datetime'], ['SourceSystem', 'string'],
];

const dotnet = { string: 'System.String', datetime: 'System.DateTime', bool: 'System.SByte', int: 'System.Int32' };
const schemaCsv = (cols) => ['ColumnName,ColumnOrdinal,DataType,ColumnType', ...cols.map(([n, t], i) => `${n},${i},${dotnet[t]},${t}`)].join('\n') + '\n';

const rule = `// Encoded PowerShell execution (synthetic worked example)
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| project Timestamp, TenantId, DeviceName, DeviceId, AccountName, ProcessCommandLine
`;

const files = {
  'rule.kql': rule,
  'DeviceProcessEvents_schema.csv': schemaCsv(dpeSchema),
  'DeviceProcessEvents_sample.json': asciiJson(dpe) + '\n',
  'IdentityInfo_schema.csv': schemaCsv(identitySchema),
  'IdentityInfo_sample.json': asciiJson(identity) + '\n',
  'ThreatIntelIndicators_schema.csv': schemaCsv(tiSchema),
  'ThreatIntelIndicators_sample.json': asciiJson(ti) + '\n',
};
for (const [name, content] of Object.entries(files)) writeFileSync(join(outDir, name), content);
console.log(`Wrote ${Object.keys(files).length} files to ${outDir}`);
