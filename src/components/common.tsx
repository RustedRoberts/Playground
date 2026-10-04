import { useCallback, useState, type ReactNode } from 'react';
import type { Category, Finding } from '../engine/types';

export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} className="switch" disabled={disabled} onClick={() => onChange(!checked)}>
      <span className="switch-knob" />
    </button>
  );
}

export function CategoryBadge({ cat, small, off }: { cat: Category; small?: boolean; off?: boolean }) {
  return (
    <span className={`cat-badge ${small ? 'cat-badge-small' : ''} ${off ? 'cat-bg-off' : `cat-bg-${cat}`}`} aria-hidden="true">
      {cat}
    </span>
  );
}

const ICON: Record<Finding['severity'], string> = { pass: '✓', warn: '!', fail: '×', info: 'i' };
const LABEL: Record<Finding['severity'], string> = { pass: 'Passed', warn: 'Warning', fail: 'Failed', info: 'Note' };

export function FindingList({ findings, empty }: { findings: Finding[]; empty?: string }) {
  if (!findings.length) return <p className="subtle">{empty ?? 'Nothing to report.'}</p>;
  return (
    <ul className="findings">
      {findings.map((f, i) => (
        <li key={i} className={`finding finding-${f.severity}`}>
          <span className="finding-icon" aria-label={LABEL[f.severity]}>{ICON[f.severity]}</span>
          <div className="stack" style={{ gap: 2 }}>
            <span className="finding-title">
              {f.cat ? <><CategoryBadge cat={f.cat} small />{' '}</> : null}
              {f.title}
            </span>
            <span className="finding-detail">{f.detail}</span>
          </div>
        </li>
      ))}
    </ul>
  );
}

export function Panel({ title, actions, children, sub }: { title: string; actions?: ReactNode; children: ReactNode; sub?: ReactNode }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div className="stack" style={{ gap: 0 }}>
          <h2 className="panel-title">{title}</h2>
          {sub ? <span className="subtle">{sub}</span> : null}
        </div>
        {actions ? <div className="row">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = document.createElement('textarea');
    area.value = text;
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    return ok;
  }
}

export function downloadText(fileName: string, text: string, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function useToast(): [string | null, (message: string) => void] {
  const [message, setMessage] = useState<string | null>(null);
  const show = useCallback((m: string) => {
    setMessage(m);
    window.setTimeout(() => setMessage(null), 2200);
  }, []);
  return [message, show];
}

export function slug(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'detection';
}
