import { useEffect, useMemo, useState } from 'react';
import type { AssessmentInputs } from './engine/assess';
import { newRuleId, type RuleMetadata } from './engine/export';
import { improve, type ImproveOptions, type ImproveOutput } from './engine/improve';
import { parseQuery } from './engine/kql';
import type { Platform, ReferenceTable } from './engine/types';
import { ingest } from './ingest';
import { AssessStep } from './components/AssessStep';
import { ImproveStep } from './components/ImproveStep';
import { PasteStep } from './components/PasteStep';
import { ReferenceStep } from './components/ReferenceStep';
import { ReviewStep } from './components/ReviewStep';
import { useToast } from './components/common';

const exampleFiles = import.meta.glob('./examples/encoded-powershell/*', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;

const STEPS = ['Paste rule', 'Reference data', 'Assessment', 'Choose improvements', 'Review and export'];

const DEFAULT_OPTIONS: ImproveOptions = { enabled: { E: true, T: true, B: false, N: false, H: true }, entity: {}, ti: {} };

export default function App() {
  const [step, setStep] = useState(0);
  const [ruleName, setRuleName] = useState('');
  const [query, setQuery] = useState('');
  const [platform, setPlatform] = useState<'auto' | Platform>('auto');
  const [tables, setTables] = useState<ReferenceTable[]>([]);
  const [mask, setMask] = useState(true);
  const [options, setOptions] = useState<ImproveOptions>(DEFAULT_OPTIONS);
  const [inputs, setInputs] = useState<AssessmentInputs>({ retired: false, baselineCurrent: false, flighted: false });
  const [meta, setMeta] = useState<RuleMetadata>({ id: newRuleId(), name: '', description: '', severity: 'Medium', queryFrequency: '1h', queryPeriod: '1h', tactics: '', techniques: '' });
  const [toastMessage, toast] = useToast();

  // The base table always has a card. It is derived rather than stored, so typing in the
  // editor does not leave a card behind for every partial table name.
  const baseName = useMemo(() => parseQuery(query).main?.sourceTable, [query]);
  const tablesWithRoles = useMemo(() => {
    const isBase = (t: ReferenceTable) => !!baseName && t.name.toLowerCase() === baseName.toLowerCase();
    const list = tables.map((t) => (isBase(t) ? { ...t, role: 'base' as const } : t.role === 'base' ? { ...t, role: 'other' as const } : t));
    if (baseName && !list.some(isBase)) list.unshift({ id: baseName.toLowerCase(), name: baseName, role: 'base', problems: [] });
    return list;
  }, [tables, baseName]);

  const [engineError, setEngineError] = useState<string | null>(null);
  const result: ImproveOutput | null = useMemo(() => {
    if (!query.trim()) return null;
    try {
      const out = improve({ query, platform: platform === 'auto' ? undefined : platform, tables: tablesWithRoles, options, assessmentInputs: inputs });
      return out;
    } catch (e) {
      console.error(e);
      return null;
    }
  }, [query, platform, tablesWithRoles, options, inputs]);
  useEffect(() => {
    setEngineError(query.trim() && !result ? 'The engine could not process this rule. Check the browser console and report it with the rule (masked) so the parser can be fixed.' : null);
  }, [query, result]);

  const loadExample = () => {
    const files = Object.entries(exampleFiles).map(([path, content]) => ({ name: path.split('/').pop() as string, content }));
    const rule = files.find((f) => f.name === 'rule.kql');
    const data = files.filter((f) => f.name !== 'rule.kql');
    setQuery(rule?.content ?? '');
    setRuleName('Encoded PowerShell execution');
    setPlatform('auto');
    setOptions(DEFAULT_OPTIONS);
    setTables(ingest([], data).tables);
    toast('Worked example loaded. All data in it is synthetic.');
  };

  const sub = (i: number): string => {
    if (!result) return ['Paste a KQL rule', 'Schemas and sample rows', 'Maturity tier and gaps', 'Switch each one on or off', 'Pull request or rule YAML'][i];
    switch (i) {
      case 0: return ruleName || result.baseName || 'Rule pasted';
      case 1: {
        const ready = tablesWithRoles.filter((t) => t.schema?.length || t.sample?.length).length;
        const warns = result.findings.filter((f) => !f.cat && (f.severity === 'warn' || f.severity === 'fail')).length;
        return `${ready} of ${tablesWithRoles.length} tables, ${warns} warning${warns === 1 ? '' : 's'}`;
      }
      case 2: return `Currently ${result.assessment.tier}, ${result.assessment.tierLabel.toLowerCase()}`;
      case 3: return `Projected ${result.projected.tier}`;
      default: return 'Pull request or rule YAML';
    }
  };

  const go = (i: number) => {
    setStep(i);
    window.scrollTo({ top: 0 });
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M8 4H5v16h3" /><path d="M16 4h3v16h-3" /><path d="M10 12h4" /></svg>
          <span>Detection Improvement Tool</span>
          <span className="pill">Prototype</span>
        </div>
        <div className="topbar-right">
          <span>Everything runs in your browser</span>
          <button type="button" className="btn" onClick={() => { if (window.confirm('Clear the rule and all reference data?')) { setQuery(''); setRuleName(''); setTables([]); setOptions(DEFAULT_OPTIONS); go(0); } }}>Start again</button>
        </div>
      </header>

      <div className="body">
        <nav className="rail" aria-label="Steps">
          <ol className="steps">
            {STEPS.map((title, i) => (
              <li key={title}>
                <button type="button" className={`step ${i < step ? 'step-done' : ''}`} aria-current={i === step ? 'step' : undefined} onClick={() => go(i)} disabled={i > 0 && !result}>
                  <span className="step-num">{i < step ? '✓' : i + 1}</span>
                  <span className="step-text"><span className="step-title">{title}</span><span className="step-sub">{sub(i)}</span></span>
                </button>
              </li>
            ))}
          </ol>
        </nav>

        <main className="main">
          {engineError ? <div className="notice" role="alert"><span>{engineError}</span></div> : null}
          {step === 0 && <PasteStep ruleName={ruleName} setRuleName={setRuleName} query={query} setQuery={setQuery} platform={platform} setPlatform={setPlatform} result={result} onLoadExample={loadExample} onNext={() => go(1)} />}
          {step === 1 && <ReferenceStep tables={tablesWithRoles} setTables={setTables} baseName={baseName} mask={mask} setMask={setMask} result={result} toast={toast} onBack={() => go(0)} onNext={() => go(2)} />}
          {step === 2 && <AssessStep result={result} inputs={inputs} setInputs={setInputs} onBack={() => go(1)} onNext={() => go(3)} />}
          {step === 3 && <ImproveStep result={result} options={options} setOptions={setOptions} onBack={() => go(2)} onNext={() => go(4)} />}
          {step === 4 && <ReviewStep ruleName={ruleName} result={result} meta={meta} setMeta={setMeta} toast={toast} onBack={() => go(3)} />}
        </main>
      </div>
      {toastMessage ? <div className="toast" role="status">{toastMessage}</div> : null}
    </div>
  );
}
