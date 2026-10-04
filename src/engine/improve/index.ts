// Runs the improvement modules in a fixed order and assembles the annotated output.
import { ASIM_PARSERS, assess, detectPlatform, type Assessment, type AssessmentInputs } from '../assess';
import { referenceFindings } from '../checks';
import { normaliseLayout, parseQuery, tokenize, type Operator, type ParsedQuery } from '../kql';
import type { Category, ChangeNote, Finding, OutputLine, Platform, ReferenceTable } from '../types';
import { SHAPING_OPERATORS, emptyResult, render, type EngineContext, type ModuleResult } from './context';
import { runEntity, type EntityOptions, type EntityResult } from './entity';
import { runEvasion, type EvasionResult } from './evasion';
import { runThreatIntel, type TiOptions, type TiResult } from './threatIntel';

export interface ImproveOptions {
  enabled: Record<Category, boolean>;
  entity: EntityOptions;
  ti: TiOptions;
}

export interface ImproveInput {
  query: string;
  platform?: Platform;
  tables: ReferenceTable[];
  options: ImproveOptions;
  assessmentInputs: AssessmentInputs;
}

export interface ImproveOutput {
  parsed: ParsedQuery;
  platform: Platform;
  layoutChanged: boolean;
  baseName?: string;
  assessment: Assessment;
  projected: Assessment;
  modules: {
    E: EntityResult;
    T: TiResult;
    B: ModuleResult;
    N: ModuleResult;
    H: EvasionResult;
  };
  lines: OutputLine[];
  text: string;
  notes: ChangeNote[];
  findings: Finding[];
}

const ASSIGNING_OPERATORS = new Set(['extend', 'project', 'mv-expand', 'mv-apply', 'project-rename']);

/** Finds `Name = expression` assignments at the top level of the operators before the anchor. */
export function derivedColumns(operators: Operator[], anchor?: Operator): Map<string, string> {
  const out = new Map<string, string>();
  for (const op of operators) {
    if (op === anchor) break;
    if (!ASSIGNING_OPERATORS.has(op.name)) continue;
    const toks = tokenize(op.text).filter((t) => t.type !== 'ws' && t.type !== 'comment');
    let depth = 0;
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (t.type === 'punct' && '([{'.includes(t.text)) depth++;
      else if (t.type === 'punct' && ')]}'.includes(t.text)) depth--;
      else if (depth === 0 && t.type === 'ident' && toks[i + 1]?.text === '=' && toks[i - 1]?.text !== '.') {
        // The expression runs to the next top-level comma.
        let d = 0;
        let j = i + 2;
        const start = toks[j]?.start ?? t.end;
        let end = start;
        for (; j < toks.length; j++) {
          const u = toks[j];
          if (u.type === 'punct' && '([{'.includes(u.text)) d++;
          else if (u.type === 'punct' && ')]}'.includes(u.text)) d--;
          else if (d === 0 && u.text === ',') break;
          end = u.end;
        }
        out.set(t.text, op.text.slice(start, end));
      }
    }
  }
  return out;
}

export function buildContext(parsed: ParsedQuery, platform: Platform, tables: ReferenceTable[]): EngineContext {
  const main = parsed.main;
  const baseName = main?.sourceTable;
  const base = baseName ? tables.find((t) => t.name.toLowerCase() === baseName.toLowerCase()) : undefined;
  const anchorOperator = main?.operators.find((o) => SHAPING_OPERATORS.has(o.name));
  const anchorLine = anchorOperator ? anchorOperator.startLine : main ? main.statement.endLine + 1 : parsed.lines.length;
  const projectOperator = anchorOperator?.name === 'project' ? anchorOperator : undefined;
  const identifiersLower = new Set(tokenize(parsed.text).filter((t) => t.type === 'ident').map((t) => t.text.toLowerCase()));
  return {
    parsed,
    platform,
    tables,
    base,
    baseName,
    anchorLine: Math.min(anchorLine, parsed.lines.length),
    anchorOperator,
    projectOperator,
    topLine: main ? main.statement.startLine : 0,
    identifiersLower,
    usedLetNames: new Set(parsed.letNames.map((n) => n.toLowerCase())),
    derivedColumns: derivedColumns(main?.operators ?? [], anchorOperator),
  };
}

function off<T extends ModuleResult>(r: T): T {
  return { ...r, status: r.status === 'applied' ? 'off' : r.status, edits: [], outputColumns: [], notes: [], uses: [], findings: [] };
}

export function improve(input: ImproveInput): ImproveOutput {
  const normalised = normaliseLayout(input.query.replace(/\r\n/g, '\n'));
  const layoutChanged = normalised !== input.query.replace(/\r\n/g, '\n');
  const parsed = parseQuery(normalised);
  const platform = input.platform ?? detectPlatform(parsed);
  const ctx = buildContext(parsed, platform, input.tables);
  const { enabled } = input.options;

  // Modules run even when switched off, so their cards can show what they would do.
  let H = runEvasion(ctx, ctx.base?.sample);
  let E = runEntity(ctx, input.options.entity);
  let T = runThreatIntel(ctx, input.options.ti);
  if (!enabled.H) H = off(H);
  if (!enabled.E) E = off(E);
  if (!enabled.T) T = off(T);

  const B = emptyResult('B', 'not-implemented', 'Baseline deviation is planned for a later build. It will need a pre-computed baseline watchlist and its sample.');
  const parser = ctx.baseName ? ASIM_PARSERS[ctx.baseName] : undefined;
  const N = emptyResult('N', platform === 'advanced-hunting' ? 'not-applicable' : 'not-implemented',
    platform === 'advanced-hunting'
      ? 'Advanced Hunting has no ASIM parsers.' + (parser ? ` In Sentinel this rule would re-base on ${parser}.` : '')
      : parser ? `Re-basing on ${parser} is planned for a later build.` : 'No ASIM parser is mapped for this source.');

  // Order sets the order of inserted blocks: entity lookups before threat intelligence.
  const ordered: ModuleResult[] = [H, E, T];
  const rendered = render(ctx, ordered);

  const assessment = assess(parsed, platform, input.assessmentInputs);
  const projected = assess(parseQuery(rendered.text), platform, input.assessmentInputs);

  const notes = ordered.flatMap((m) => m.notes);
  if (layoutChanged) {
    notes.unshift({ title: 'Layout', detail: 'Operators that shared a line were split onto separate lines so changes can be shown line by line. The logic is unchanged.' });
  }

  const uses = ordered.flatMap((m) => m.uses);
  const findings: Finding[] = [
    ...referenceFindings(parsed, input.tables, uses, ctx.baseName),
    ...ordered.flatMap((m) => m.findings),
  ];
  if (ctx.anchorOperator?.name === 'summarize' && (E.status === 'applied' || T.status === 'applied')) {
    findings.push({
      severity: 'warn',
      title: 'Enrichment is inserted before a summarize',
      detail: 'Columns added by the lookups are dropped by summarize unless you add them to its by clause or aggregate them, for example with take_any().',
    });
  }

  return {
    parsed,
    platform,
    layoutChanged,
    baseName: ctx.baseName,
    assessment,
    projected,
    modules: { E, T, B, N, H },
    lines: rendered.lines,
    text: rendered.text,
    notes,
    findings,
  };
}
