import { useMemo } from 'react';
import { CATEGORY_LABELS } from '../engine/categories';
import { buildPrDescription, buildRuleYaml, type RuleMetadata } from '../engine/export';
import type { ImproveOutput } from '../engine/improve';
import { CATEGORY_ORDER } from '../engine/types';
import { FindingList, Panel, copyText, downloadText, slug } from './common';
import { QueryEditor } from './QueryEditor';

interface Props {
  ruleName: string;
  result: ImproveOutput | null;
  meta: RuleMetadata;
  setMeta: (m: RuleMetadata) => void;
  toast: (m: string) => void;
  onBack: () => void;
}

export function ReviewStep({ ruleName, result, meta, setMeta, toast, onBack }: Props) {
  const yaml = useMemo(() => (result ? buildRuleYaml({ ...meta, name: meta.name || ruleName }, result.text) : ''), [meta, ruleName, result]);
  const pr = useMemo(() => (result ? buildPrDescription(ruleName, result) : ''), [ruleName, result]);
  if (!result) return <p className="subtle">Paste a rule first.</p>;

  const failures = result.findings.filter((f) => f.severity === 'fail').length;
  const warnings = result.findings.filter((f) => f.severity === 'warn').length;
  const general = result.findings.filter((f) => !f.cat);
  const bench = result.modules.H.bench;
  const fileBase = slug(ruleName || 'detection');

  const copy = async (text: string, label: string) => { if (await copyText(text)) toast(`${label} copied`); };

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Review and export</h1>
          <p className="lede">Check the findings before you use the query. Run it in the target workspace and attach the result to the pull request as validation evidence; the checks here confirm field names and joins against your samples, not that the query runs.</p>
        </div>
        <div className="tier-box">
          <div className="tier"><span className="subtle">Before</span><span className="tier-value">{result.assessment.tier}</span></div>
          <span className="tier-arrow" aria-hidden="true">to</span>
          <div className="tier"><span className="subtle">After</span><span className="tier-value">{result.projected.tier}</span></div>
          <div className="stack" style={{ gap: 2 }}>
            <span style={{ fontWeight: 500 }}>{failures ? `${failures} failed check${failures > 1 ? 's' : ''}` : 'No failed checks'}</span>
            <span className="subtle">{warnings} warning{warnings === 1 ? '' : 's'}</span>
          </div>
        </div>
      </div>

      <section className="query-editor-wrap" aria-labelledby="final-title">
        <div className="panel-head">
          <h2 id="final-title" className="panel-title">Improved query</h2>
          <div className="row" style={{ gap: 8 }}>
            <button type="button" className="btn btn-small" onClick={() => copy(result.text, 'Query')}>Copy query</button>
            <button type="button" className="btn btn-small" onClick={() => downloadText(`${fileBase}.kql`, result.text)}>Download .kql</button>
          </div>
        </div>
        <QueryEditor mode="annotated" lines={result.lines} showRemoved={false} ariaLabel="Final improved query" minLines={8} />
      </section>

      <div className="split">
        <div className="grow">
          <div className="panel panel-pad">
            <h2 className="panel-title">Checks</h2>
            <FindingList findings={general} />
            {CATEGORY_ORDER.map((c) => {
              const list = result.findings.filter((f) => f.cat === c);
              if (!list.length) return null;
              return (
                <div key={c} className="stack">
                  <h3 className="subtle" style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', fontSize: 11 }}>{CATEGORY_LABELS[c]}</h3>
                  <FindingList findings={list} />
                </div>
              );
            })}
          </div>

          {bench.length ? (
            <Panel title="Evasion test bench" sub="Synthetic command lines, tested with JavaScript approximations of the KQL operators.">
              <div className="table-scroll">
                <table className="data-table">
                  <thead><tr><th scope="col">Variant</th><th scope="col">Command line</th><th scope="col">Original</th><th scope="col">Hardened</th></tr></thead>
                  <tbody>
                    {bench.map((b, i) => (
                      <tr key={i}>
                        <td>{b.description}</td>
                        <td className="mono">{b.variant}</td>
                        <td className={`verdict ${b.original ? 'yes' : 'no'}`}>{b.original ? 'Caught' : 'Missed'}</td>
                        <td className={`verdict ${b.hardened ? 'yes' : 'no'}`}>{b.hardened ? 'Caught' : 'Missed'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          ) : null}
        </div>

        <aside className="side">
          <div className="panel panel-pad">
            <h2 className="panel-title">Sentinel analytics rule</h2>
            <p className="subtle">Exported in the Azure-Sentinel repository YAML format. Tactics and techniques are left for you to set; the tool does not infer a MITRE mapping.</p>
            <label className="field">Rule name<input className="input" value={meta.name} placeholder={ruleName || 'Rule name'} onChange={(e) => setMeta({ ...meta, name: e.target.value })} /></label>
            <label className="field">Description<textarea className="textarea" value={meta.description} onChange={(e) => setMeta({ ...meta, description: e.target.value })} placeholder="What this detects and why it matters" /></label>
            <div className="row" style={{ alignItems: 'flex-end' }}>
              <label className="field" style={{ flex: '1 1 120px' }}>Severity
                <select className="select" value={meta.severity} onChange={(e) => setMeta({ ...meta, severity: e.target.value as RuleMetadata['severity'] })}>
                  {['Informational', 'Low', 'Medium', 'High'].map((s) => <option key={s}>{s}</option>)}
                </select>
              </label>
              <label className="field" style={{ flex: '1 1 80px' }}>Frequency<input className="input" value={meta.queryFrequency} onChange={(e) => setMeta({ ...meta, queryFrequency: e.target.value })} /></label>
              <label className="field" style={{ flex: '1 1 80px' }}>Period<input className="input" value={meta.queryPeriod} onChange={(e) => setMeta({ ...meta, queryPeriod: e.target.value })} /></label>
            </div>
            <label className="field">Tactics (comma separated)<input className="input" value={meta.tactics} onChange={(e) => setMeta({ ...meta, tactics: e.target.value })} placeholder="Execution, DefenseEvasion" /></label>
            <label className="field">Techniques (comma separated)<input className="input" value={meta.techniques} onChange={(e) => setMeta({ ...meta, techniques: e.target.value })} placeholder="T1059.001, T1027" /></label>
            {result.platform === 'advanced-hunting' ? <p className="subtle">This rule uses Advanced Hunting tables. In Sentinel the Defender tables also carry TimeGenerated; check the time filter before deploying the YAML.</p> : null}
            <div className="row" style={{ gap: 8 }}>
              <button type="button" className="btn btn-primary" onClick={() => downloadText(`${fileBase}.yaml`, yaml, 'text/yaml')}>Download rule YAML</button>
              <button type="button" className="btn" onClick={() => copy(yaml, 'Rule YAML')}>Copy</button>
            </div>
          </div>
          <div className="panel panel-pad">
            <h2 className="panel-title">Pull request description</h2>
            <p className="subtle">Summarises the maturity change, every edit with its reason, and the checks, with a validation checklist to complete.</p>
            <div className="row" style={{ gap: 8 }}>
              <button type="button" className="btn" onClick={() => copy(pr, 'Pull request description')}>Copy description</button>
              <button type="button" className="btn" onClick={() => downloadText(`${fileBase}-pr.md`, pr, 'text/markdown')}>Download .md</button>
            </div>
          </div>
        </aside>
      </div>

      <div className="footer-actions">
        <button type="button" className="btn btn-large" onClick={onBack}>Back to improvements</button>
        <span />
      </div>
    </>
  );
}
