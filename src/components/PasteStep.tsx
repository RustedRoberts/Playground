import type { ImproveOutput } from '../engine/improve';
import type { Platform } from '../engine/types';
import { QueryEditor } from './QueryEditor';

interface Props {
  ruleName: string;
  setRuleName: (v: string) => void;
  query: string;
  setQuery: (v: string) => void;
  platform: 'auto' | Platform;
  setPlatform: (v: 'auto' | Platform) => void;
  result: ImproveOutput | null;
  onLoadExample: () => void;
  onNext: () => void;
}

export function PasteStep(p: Props) {
  const main = p.result?.parsed.main;
  const detected = p.result?.platform === 'advanced-hunting' ? 'Defender XDR Advanced Hunting' : 'Microsoft Sentinel';
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Paste rule</h1>
          <p className="lede">Paste the KQL detection you want to improve. The tool reads its structure, works out the base table and which platform it is written for, and never changes the logic you have written except where an improvement says so.</p>
        </div>
        <button type="button" className="btn" onClick={p.onLoadExample}>Load worked example (synthetic data)</button>
      </div>

      <div className="split">
        <div className="grow">
          <label className="field">
            Rule name
            <input className="input" value={p.ruleName} onChange={(e) => p.setRuleName(e.target.value)} placeholder="For example: Encoded PowerShell execution" />
          </label>
          <div className="query-editor-wrap">
            <div className="panel-head"><h2 className="panel-title">Rule query</h2><span className="subtle">KQL</span></div>
            <QueryEditor mode="edit" value={p.query} onChange={p.setQuery} minLines={14} ariaLabel="Rule query editor" />
          </div>
        </div>
        <div className="side">
          <div className="panel panel-pad">
            <h2 className="panel-title">What the tool found</h2>
            {!p.query.trim() ? (
              <p className="subtle">Nothing yet. Paste a rule to begin.</p>
            ) : main ? (
              <dl className="stack" style={{ margin: 0 }}>
                <div><dt className="subtle">Base table</dt><dd className="mono" style={{ margin: 0 }}>{main.sourceTable ?? 'Not a single table (union or expression)'}</dd></div>
                <div><dt className="subtle">Operators</dt><dd style={{ margin: 0 }}>{main.operators.map((o) => o.name).join(', ') || 'None'}</dd></div>
                <div><dt className="subtle">Let statements</dt><dd style={{ margin: 0 }}>{p.result?.parsed.letNames.join(', ') || 'None'}</dd></div>
                <div><dt className="subtle">Detected platform</dt><dd style={{ margin: 0 }}>{detected}</dd></div>
              </dl>
            ) : (
              <p className="subtle">No main query was found. Check the rule ends with a query rather than only let statements.</p>
            )}
            <label className="field">
              Platform
              <select className="select" value={p.platform} onChange={(e) => p.setPlatform(e.target.value as 'auto' | Platform)}>
                <option value="auto">Detect from the query</option>
                <option value="advanced-hunting">Defender XDR Advanced Hunting</option>
                <option value="sentinel">Microsoft Sentinel</option>
              </select>
            </label>
            <p className="subtle">The platform decides whether ASIM applies and which time column is expected. Rules using Timestamp are treated as Advanced Hunting, and TimeGenerated as Sentinel.</p>
          </div>
        </div>
      </div>

      <div className="footer-actions">
        <span />
        <button type="button" className="btn btn-primary btn-large" onClick={p.onNext} disabled={!main}>Continue to reference data</button>
      </div>
    </>
  );
}
