import type { AssessmentInputs, Question } from '../engine/assess';
import type { ImproveOutput } from '../engine/improve';
import { CategoryBadge } from './common';

interface Props {
  result: ImproveOutput | null;
  inputs: AssessmentInputs;
  setInputs: (v: AssessmentInputs) => void;
  onBack: () => void;
  onNext: () => void;
}

const ANSWER: Record<Question['answer'], string> = { yes: 'Yes', no: 'No', 'not-reached': 'Not reached', 'needs-input': 'Not yet' };

export function AssessStep({ result, inputs, setInputs, onBack, onNext }: Props) {
  if (!result) return <p className="subtle">Paste a rule first.</p>;
  const a = result.assessment;
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Assessment</h1>
          <p className="lede">The rule is walked through the four-question maturity decision tree. The first question answered "no" sets the tier. Query length and parsing complexity do not raise the tier; only the questions do.</p>
        </div>
        <div className="tier-box" aria-label={`Current maturity ${a.tier}`}>
          <div className="tier"><span className="subtle">Current</span><span className="tier-value">{a.tier}</span></div>
          <div className="stack" style={{ gap: 2 }}><span style={{ fontWeight: 500 }}>{a.tierLabel}</span><span className="subtle">From the rule as pasted</span></div>
        </div>
      </div>

      <div className="split">
        <div className="grow">
          <ol className="stack" style={{ listStyle: 'none', margin: 0, padding: 0, gap: 12 }}>
            {a.questions.map((q) => (
              <li key={q.id} className="panel panel-pad">
                <div className="row" style={{ justifyContent: 'space-between' }}>
                  <span style={{ fontWeight: 600 }}><span className="mono subtle">{q.id}</span> {q.title}</span>
                  <span className={`pill ${q.answer === 'needs-input' ? 'pill-dashed' : ''}`}>{ANSWER[q.answer]}</span>
                </div>
                <p className="muted" style={{ fontSize: 14 }}>{q.reasoning}</p>
                {q.evidence.length ? <ul className="subtle" style={{ margin: 0, paddingLeft: 18 }}>{q.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul> : null}
              </li>
            ))}
          </ol>

          <div className="panel panel-pad">
            <h2 className="panel-title">Recommended advancement</h2>
            {a.recommendations.length ? (
              <ul className="stack" style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                {a.recommendations.map((r) => (
                  <li key={r.pattern} className="row" style={{ alignItems: 'flex-start', flexWrap: 'nowrap' }}>
                    {r.category ? <CategoryBadge cat={r.category} small /> : <span className="pill">{r.pattern}</span>}
                    <div className="stack" style={{ gap: 2 }}>
                      <span style={{ fontWeight: 500 }}>{r.pattern} {r.title}</span>
                      <span className="subtle">{r.detail}</span>
                    </div>
                  </li>
                ))}
              </ul>
            ) : <p className="subtle">No structural advancement is recommended.</p>}
            <p className="subtle"><strong>ASIM position:</strong> {a.asimPosition}</p>
            {a.ceilingNote ? <p className="subtle"><strong>Ceiling note:</strong> {a.ceilingNote}</p> : null}
          </div>
        </div>

        <aside className="side">
          <div className="panel panel-pad">
            <h2 className="panel-title">Your answers</h2>
            <p className="subtle">These depend on how the rule is run, so the tool cannot read them from the query.</p>
            <label className="check"><input type="checkbox" checked={inputs.retired} onChange={(e) => setInputs({ ...inputs, retired: e.target.checked })} /> <span>The rule is dead or unmaintained (Q0). It becomes a retirement candidate instead.</span></label>
            <label className="check"><input type="checkbox" checked={inputs.baselineCurrent} onChange={(e) => setInputs({ ...inputs, baselineCurrent: e.target.checked })} /> <span>Any baseline the rule uses is current (Q3).</span></label>
            <label className="check"><input type="checkbox" checked={inputs.flighted} onChange={(e) => setInputs({ ...inputs, flighted: e.target.checked })} /> <span>The rule was flighted before going live (Q3).</span></label>
          </div>
        </aside>
      </div>

      <div className="footer-actions">
        <button type="button" className="btn btn-large" onClick={onBack}>Back to reference data</button>
        <button type="button" className="btn btn-primary btn-large" onClick={onNext}>Continue to improvements</button>
      </div>
    </>
  );
}
