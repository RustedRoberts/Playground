import { useMemo, useState, type DragEvent } from 'react';
import type { ImproveOutput } from '../engine/improve';
import { exportQueries } from '../engine/exportQueries';
import { identifiers } from '../engine/kql';
import { columnsOf, isIdentifyingColumn, maskValue } from '../engine/reference';
import type { ReferenceTable, TableRole } from '../engine/types';
import { addTable, ingest, readFiles } from '../ingest';
import { FindingList, Panel, Switch, copyText } from './common';

interface Props {
  tables: ReferenceTable[];
  setTables: (t: ReferenceTable[]) => void;
  baseName?: string;
  mask: boolean;
  setMask: (v: boolean) => void;
  result: ImproveOutput | null;
  toast: (m: string) => void;
  onBack: () => void;
  onNext: () => void;
}

const ROLE_LABEL: Record<TableRole, string> = {
  base: 'Base table, detected from the rule',
  entity: 'Enrichment: entity',
  'threat-intel': 'Enrichment: threat intelligence',
  watchlist: 'Watchlist',
  other: 'Other table',
};

function stopDrag(e: DragEvent) {
  e.preventDefault();
  e.stopPropagation();
}

export function ReferenceStep(p: Props) {
  const [selected, setSelected] = useState<string | undefined>(undefined);
  const [overZone, setOverZone] = useState(false);
  const [newName, setNewName] = useState('');
  const [messages, setMessages] = useState<string[]>([]);

  const ordered = useMemo(() => {
    const roleOrder: TableRole[] = ['base', 'entity', 'threat-intel', 'watchlist', 'other'];
    return [...p.tables].sort((a, b) => roleOrder.indexOf(a.role) - roleOrder.indexOf(b.role));
  }, [p.tables]);
  const current = ordered.find((t) => t.id === selected) ?? ordered[0];

  const handleFiles = async (list: FileList | File[], target?: string, kind?: 'schema' | 'sample') => {
    const files = await readFiles(list);
    const { tables, messages: m } = ingest(p.tables, files, target, kind);
    p.setTables(tables);
    setMessages(m);
  };

  // Reference checks plus the join checks that depend on the uploaded samples.
  const referenceOnly = (p.result?.findings ?? []).filter((f) => f.cat !== 'H');
  const used = useMemo(() => new Set(identifiers(p.result?.text ?? '').map((i) => i.toLowerCase())), [p.result?.text]);
  const identityKey = p.result?.modules.E.pair;
  const queries = p.result ? exportQueries(p.result.parsed, {
    identity: p.tables.some((t) => t.role === 'entity'),
    ti: p.tables.some((t) => t.role === 'threat-intel'),
    identityKey: identityKey ? { left: identityKey.left, right: identityKey.right } : { left: 'AccountObjectId', right: 'AccountObjectId' },
  }) : '';

  const example = (t: ReferenceTable, col: string): string => {
    const row = t.sample?.find((r) => r[col] !== undefined && r[col] !== null && String(r[col]).length);
    if (!row) return '';
    const v = typeof row[col] === 'object' ? JSON.stringify(row[col]) : String(row[col]);
    return p.mask && isIdentifyingColumn(col) ? maskValue(v) : v;
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Reference data</h1>
          <p className="lede">Upload a schema and a sample of up to 100 rows for every table the rule will use. The tool only writes against columns it can see here, and tests each join against the sample rows, so nothing in the improved query relies on a guessed field name.</p>
        </div>
      </div>

      <div className="notice">
        <div className="row" style={{ flex: '1 1 420px', alignItems: 'flex-start', flexWrap: 'nowrap' }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ flex: '0 0 auto', marginTop: 2 }}><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg>
          <p className="muted" style={{ fontSize: 14 }}>Files are read in your browser and held in memory only. Nothing is uploaded to a server, saved, or committed to a repository, and it is all cleared when you close or reload the page. Use lab data where possible and mask client data before export.</p>
        </div>
        <div className="row">
          <span id="mask-label" style={{ fontSize: 14 }}>Mask user and device identifiers on screen</span>
          <Switch checked={p.mask} onChange={p.setMask} label="Mask user and device identifiers on screen" />
        </div>
      </div>

      <div
        className={`dropzone ${overZone ? 'is-over' : ''}`}
        onDragOver={(e) => { stopDrag(e); setOverZone(true); }}
        onDragLeave={() => setOverZone(false)}
        onDrop={(e) => { stopDrag(e); setOverZone(false); void handleFiles(e.dataTransfer.files); }}
      >
        <div className="stack" style={{ gap: 2 }}>
          <span style={{ fontWeight: 500 }}>Drop all your files here at once</span>
          <span className="subtle">Name them like <span className="mono">DeviceProcessEvents_schema.csv</span> and <span className="mono">IdentityInfo_sample.json</span> and they are sorted onto the right tables. CSV and JSON exports both work.</span>
        </div>
        <label className="btn btn-primary">
          Choose files
          <input type="file" multiple accept=".csv,.json,.txt,.ndjson" className="visually-hidden" onChange={(e) => { if (e.target.files) void handleFiles(e.target.files); e.target.value = ''; }} />
        </label>
      </div>
      {messages.length ? <ul className="subtle" style={{ margin: 0, paddingLeft: 18 }}>{messages.map((m, i) => <li key={i}>{m}</li>)}</ul> : null}

      <div className="split">
        <section className="grow" aria-labelledby="tables-title">
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <h2 id="tables-title" className="section-title">Tables used by this rule</h2>
            <div className="row" style={{ gap: 8 }}>
              {!p.tables.some((t) => t.role === 'entity') && <button type="button" className="btn btn-small" onClick={() => p.setTables(addTable(p.tables, 'IdentityInfo'))}>Add IdentityInfo</button>}
              {!p.tables.some((t) => t.role === 'threat-intel') && <button type="button" className="btn btn-small" onClick={() => p.setTables(addTable(p.tables, 'ThreatIntelIndicators'))}>Add ThreatIntelIndicators</button>}
            </div>
          </div>

          {ordered.map((t) => {
            const complete = !!(t.schema?.length && t.sample?.length);
            return (
              <article key={t.id} className={`table-card ${complete ? 'is-complete' : ''} ${current?.id === t.id ? 'is-selected' : ''}`}>
                <div className="row" style={{ justifyContent: 'space-between' }}>
                  <div className="row" style={{ gap: '8px 12px' }}>
                    <span className="table-name">{t.name}</span>
                    <span className="pill">{ROLE_LABEL[t.role]}</span>
                  </div>
                  <div className="row" style={{ gap: 8 }}>
                    <button type="button" className={`btn btn-small ${current?.id === t.id ? 'btn-primary' : ''}`} aria-pressed={current?.id === t.id} onClick={() => setSelected(t.id)}>View columns</button>
                    {t.role !== 'base' && <button type="button" className="btn btn-small" onClick={() => p.setTables(p.tables.filter((x) => x.id !== t.id))} aria-label={`Remove ${t.name}`}>Remove</button>}
                  </div>
                </div>
                <div className="slots">
                  {(['schema', 'sample'] as const).map((kind) => {
                    const file = kind === 'schema' ? t.schemaFile : t.sampleFile;
                    const detail = kind === 'schema' ? (t.schema ? `${t.schema.length} columns` : '') : (t.sample ? `${t.sample.length} rows` : '');
                    return (
                      <div
                        key={kind}
                        className={`slot ${file ? '' : 'is-empty'}`}
                        onDragOver={stopDrag}
                        onDrop={(e) => { stopDrag(e); void handleFiles(e.dataTransfer.files, t.name, kind); }}
                      >
                        <span className="subtle" style={{ fontSize: 12 }}>{kind === 'schema' ? 'Schema (getschema output)' : 'Sample rows'}</span>
                        <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'nowrap', gap: 8 }}>
                          {file ? (
                            <div className="stack" style={{ gap: 0, minWidth: 0 }}>
                              <span className="slot-file" title={file}>{file}</span>
                              <span className="subtle">{detail}</span>
                            </div>
                          ) : (
                            <span className="subtle">Drop a CSV or JSON file here</span>
                          )}
                          <label className={`btn btn-small ${file ? '' : 'btn-primary'}`} style={{ flex: '0 0 auto' }}>
                            {file ? 'Replace' : 'Browse'}
                            <input type="file" accept=".csv,.json,.txt,.ndjson" className="visually-hidden" onChange={(e) => { if (e.target.files) void handleFiles(e.target.files, t.name, kind); e.target.value = ''; }} />
                          </label>
                        </div>
                      </div>
                    );
                  })}
                </div>
                {t.problems.length ? <ul className="problems">{t.problems.map((m, i) => <li key={i}>{m}</li>)}</ul> : null}
              </article>
            );
          })}

          <form
            className="row"
            onSubmit={(e) => { e.preventDefault(); const n = newName.trim(); if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(n)) { p.setTables(addTable(p.tables, n)); setNewName(''); } }}
          >
            <label className="visually-hidden" htmlFor="new-table">Table name</label>
            <input id="new-table" className="input" placeholder="Another table, for example DeviceInfo" value={newName} onChange={(e) => setNewName(e.target.value)} style={{ flex: '1 1 240px' }} />
            <button type="submit" className="btn">Add table</button>
          </form>

          <Panel
            title="How to export these files"
            sub="Run in Advanced Hunting or Log Analytics and export the results. The IdentityInfo sample is taken for the same accounts as the base sample, so the lookup can be tested."
            actions={<button type="button" className="btn btn-small" onClick={async () => { if (await copyText(queries)) p.toast('Export queries copied'); }}>Copy export queries</button>}
          >
            <pre className="code-block">{queries}</pre>
          </Panel>
        </section>

        <aside className="side">
          <div className="panel panel-pad">
            <h2 className="panel-title">Checks against your data</h2>
            <FindingList findings={referenceOnly} empty="Paste a rule and upload files to run the checks." />
          </div>
          <Panel title="Columns" sub={current ? <span className="mono">{current.name}</span> : undefined}>
            {current && columnsOf(current).length ? (
              <div className="col-list">
                {columnsOf(current).map((c) => {
                  const ex = example(current, c.name);
                  return (
                    <div key={c.name} className="col-row">
                      <span className="mono">{c.name}</span>
                      {used.has(c.name.toLowerCase()) ? <span className="pill">Used by query</span> : <span />}
                      <span className="mono subtle">{c.type}</span>
                      {ex ? <span className="col-example" title={ex}>{ex}</span> : null}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="subtle" style={{ padding: 16 }}>Nothing uploaded for this table yet.</p>
            )}
          </Panel>
        </aside>
      </div>

      <div className="footer-actions">
        <button type="button" className="btn btn-large" onClick={p.onBack}>Back to rule</button>
        <button type="button" className="btn btn-primary btn-large" onClick={p.onNext}>Continue to assessment</button>
      </div>
    </>
  );
}
