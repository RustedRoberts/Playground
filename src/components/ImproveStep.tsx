import { useState, type ReactNode } from 'react';
import { CATEGORY_LABELS, CATEGORY_PATTERNS } from '../engine/categories';
import type { ImproveOptions, ImproveOutput } from '../engine/improve';
import type { ModuleResult } from '../engine/improve/context';
import { CATEGORY_ORDER, type Category } from '../engine/types';
import { CategoryBadge, Switch } from './common';
import { QueryEditor } from './QueryEditor';

interface Props {
  result: ImproveOutput | null;
  options: ImproveOptions;
  setOptions: (o: ImproveOptions) => void;
  onBack: () => void;
  onNext: () => void;
}

const STATUS_LABEL: Record<ModuleResult['status'], string> = {
  applied: 'Applied',
  off: 'Switched off',
  'needs-data': 'Needs reference data',
  'not-applicable': 'Not applicable',
  'already-present': 'Already in the rule',
  'not-implemented': 'Later build',
};

export function ImproveStep({ result, options, setOptions, onBack, onNext }: Props) {
  const [showRemoved, setShowRemoved] = useState(false);
  if (!result) return <p className="subtle">Paste a rule first.</p>;
  const m = result.modules;
  const toggle = (cat: Category, v: boolean) => setOptions({ ...options, enabled: { ...options.enabled, [cat]: v } });
  const lineCount = (cat: Category) => result.lines.filter((l) => l.kind !== 'del' && (l.cat === cat || l.segs.some((s) => s.cat === cat))).length;

  const card = (cat: Category, body: ReactNode, showBodyWhenOff = false) => {
    const r: ModuleResult = m[cat];
    const available = r.status === 'applied' || r.status === 'off';
    const on = r.status === 'applied';
    return (
      <article key={cat} className={`improve-card ${on ? `is-on-${cat}` : ''} ${available ? '' : 'is-unavailable'}`}>
        <div className="improve-card-head">
          <div className="improve-card-title"><CategoryBadge cat={cat} off={!on && available} /><span>{CATEGORY_LABELS[cat]}</span></div>
          {available ? <Switch checked={on} onChange={(v) => toggle(cat, v)} label={`Apply ${CATEGORY_LABELS[cat]}`} /> : null}
        </div>
        <p style={{ fontSize: 14 }} className="muted">{r.summary}</p>
        {on || showBodyWhenOff ? body : null}
        <div className="row" style={{ gap: 6, marginTop: 'auto' }}>
          <span className="pill">{CATEGORY_PATTERNS[cat]}</span>
          <span className={`pill ${available ? '' : 'pill-dashed'}`}>{on ? `${lineCount(cat)} lines` : STATUS_LABEL[r.status]}</span>
        </div>
      </article>
    );
  };

  const p = result.projected;
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Choose improvements</h1>
          <p className="lede">The assessment placed this rule at {result.assessment.tier}. Switch each improvement on or off and the preview updates, with every change coloured and lettered by the improvement it belongs to.</p>
        </div>
        <div className="tier-box" aria-live="polite">
          <div className="tier"><span className="subtle">Projected</span><span className="tier-value">{p.tier}</span></div>
          <div className="stack" style={{ gap: 2 }}>
            <span style={{ fontWeight: 500 }}>{p.tierLabel}</span>
            <span className="subtle">{p.tier === result.assessment.tier ? 'No change to the tier.' : `Up from ${result.assessment.tier}.`}</span>
          </div>
        </div>
      </div>

      <div className="grid-cards">
        {CATEGORY_ORDER.map((cat) => {
          if (cat === 'E') {
            const isOverride = options.entity.candidateId === 'override';
            const showKeyChoice = m.E.status !== 'needs-data' && m.E.status !== 'already-present';
            return card('E', (
              <div className="options">
                <label className="field">
                  Account identifier
                  <select className="select" value={isOverride ? 'override' : m.E.candidate?.id ?? ''} onChange={(e) => setOptions({ ...options, entity: { ...options.entity, candidateId: e.target.value } })}>
                    {!m.E.candidates.length && !isOverride ? <option value="">None found</option> : null}
                    {m.E.candidates.length && !m.E.candidate && !isOverride ? <option value="" disabled>Choose the account to enrich</option> : null}
                    {m.E.candidates.map((c) => <option key={c.id} value={c.id}>{c.label} ({c.strength})</option>)}
                    <option value="override">Custom expression</option>
                  </select>
                </label>
                {isOverride ? (
                  <>
                    <label className="field">
                      Expression that extracts the identifier
                      <input className="input mono" value={options.entity.overrideExpression ?? ''} placeholder="tostring(TargetResources[0].id)" onChange={(e) => setOptions({ ...options, entity: { ...options.entity, overrideExpression: e.target.value } })} />
                    </label>
                    <label className="field">
                      Matches IdentityInfo column
                      <select className="select" value={options.entity.overrideRight ?? m.E.overrideRights[0] ?? ''} onChange={(e) => setOptions({ ...options, entity: { ...options.entity, overrideRight: e.target.value } })}>
                        {m.E.overrideRights.map((c) => <option key={c} value={c}>{c}</option>)}
                      </select>
                    </label>
                  </>
                ) : null}
                {m.E.candidate ? <span className="subtle mono" style={{ fontSize: 12, wordBreak: "break-all" }}>IdentityInfo_Key = tolower({m.E.candidate.expression})</span> : null}
                {m.E.candidate ? (
                  <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
                    <legend className="subtle" style={{ marginBottom: 6 }}>IdentityInfo columns to add</legend>
                    <div className="col-choices">
                      {m.E.columnChoices.slice(0, 12).map((c) => (
                        <label key={c}>
                          <input
                            type="checkbox"
                            checked={m.E.columns.includes(c)}
                            disabled={m.E.columns.length === 1 && m.E.columns.includes(c)}
                            onChange={(e) => {
                              const cols = e.target.checked ? [...m.E.columns, c] : m.E.columns.filter((x) => x !== c);
                              setOptions({ ...options, entity: { ...options.entity, columns: cols } });
                            }}
                          />
                          {c}
                        </label>
                      ))}
                    </div>
                  </fieldset>
                ) : null}
              </div>
            ), showKeyChoice);
          }
          if (cat === 'T') {
            return card('T', (
              <div className="options">
                <label className="field">
                  Value to check
                  <select className="select" value={m.T.choice?.column ?? ''} onChange={(e) => setOptions({ ...options, ti: { observable: e.target.value } })}>
                    {m.T.choices.map((c) => <option key={c.column} value={c.column}>{c.column} ({c.label}{c.referenced ? ', used by the rule' : ''})</option>)}
                  </select>
                </label>
              </div>
            ));
          }
          if (cat === 'H') {
            return card('H', m.H.executable ? (
              <div className="options">
                <span className="subtle">Parameter rules: {m.H.executable.label}. Sources: {m.H.executable.sources.map((s, i) => <span key={s.url}>{i ? ', ' : ''}<a href={s.url} target="_blank" rel="noreferrer">{s.title}</a></span>)}</span>
              </div>
            ) : null);
          }
          return card(cat, null);
        })}
      </div>

      <section className="query-editor-wrap" aria-labelledby="preview-title">
        <div className="panel-head">
          <div className="row" style={{ gap: 12 }}>
            <h2 id="preview-title" className="panel-title">Live preview</h2>
            <span className="subtle">{result.text.split('\n').length} lines</span>
          </div>
          <div className="row">
            <div className="legend" aria-label="Colour key">
              {CATEGORY_ORDER.map((c) => <span key={c}><CategoryBadge cat={c} small />{CATEGORY_LABELS[c]}</span>)}
            </div>
            <label className="check" style={{ fontSize: 13 }}><input type="checkbox" checked={showRemoved} onChange={(e) => setShowRemoved(e.target.checked)} /> Show removed lines</label>
          </div>
        </div>
        <QueryEditor mode="annotated" lines={result.lines} showRemoved={showRemoved} ariaLabel="Improved query preview" minLines={10} />
      </section>

      {result.notes.length ? (
        <div className="panel panel-pad">
          <h2 className="panel-title">What changed and why</h2>
          <ul className="stack" style={{ listStyle: 'none', margin: 0, padding: 0, gap: 14 }}>
            {result.notes.map((n, i) => (
              <li key={i} className="row" style={{ alignItems: 'flex-start', flexWrap: 'nowrap' }}>
                {n.cat ? <CategoryBadge cat={n.cat} small /> : <span className="pill">Note</span>}
                <div className="stack" style={{ gap: 2 }}>
                  <span style={{ fontWeight: 500 }}>{n.title}</span>
                  <span className="muted" style={{ fontSize: 14 }}>{n.detail}</span>
                  {n.watch ? <span className="subtle"><strong>Watch for:</strong> {n.watch}</span> : null}
                </div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="footer-actions">
        <button type="button" className="btn btn-large" onClick={onBack}>Back to assessment</button>
        <button type="button" className="btn btn-primary btn-large" onClick={onNext}>Continue to review</button>
      </div>
    </>
  );
}
