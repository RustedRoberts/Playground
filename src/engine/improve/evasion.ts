// Evasion hardening: command-line obfuscation and parameter abbreviation coverage.
import { quote, splitTopLevel } from '../kql';
import { evaluate, kqlRegexToJs } from '../kqlEval';
import { EXECUTABLES, POWERSHELL, acceptedForms, findExecutable, matchParameter, type ExecutableDefinition, type ParameterDefinition } from '../library/parameters';
import { parseSimplePredicate, whereCondition, type SimplePredicate } from '../predicate';
import type { Finding, Row } from '../types';
import { emptyResult, type EngineContext, type ModuleResult } from './context';

const COMMAND_LINE = /commandline/i;
const IMAGE_COLUMNS = /^(FileName|ProcessName|NewProcessName|InitiatingProcessFileName|TargetProcessName|TargetProcessFilename|ActingProcessName|ParentProcessName|Process|Image)$/i;
const HARDENABLE: SimplePredicate['operator'][] = ['has', 'has_any', 'has_all', 'has_cs', 'contains', 'contains_cs'];

/** Normalisation applied before matching: string concatenation joins, carets and double quotes. */
export function cleanExpression(column: string): string {
  return `replace_regex(replace_regex(${column}, @"[""']\\s*\\+\\s*[""']", ""), @"[\\^""]", "")`;
}

export function cleanJs(value: string): string {
  return value.replace(/["']\s*\+\s*["']/g, '').replace(/[\^"]/g, '');
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

function prefixClass(exe: ExecutableDefinition): string {
  const parts = exe.prefixCharacters.map((c) => {
    const code = c.codePointAt(0) as number;
    if (code > 127) return `\\x{${code.toString(16).toUpperCase().padStart(4, '0')}}`;
    return c === '-' || c === '/' ? c : escapeRegex(c);
  });
  // Hyphen first so it is literal inside the class.
  parts.sort((a, b) => (a === '-' ? -1 : b === '-' ? 1 : 0));
  return `[${parts.join('')}]`;
}

export interface ParameterGroup {
  parameter: ParameterDefinition;
  value?: string;
  originalLiterals: string[];
}

/** Builds the RE2 pattern for a set of parameter groups. */
export function buildParameterRegex(exe: ExecutableDefinition, groups: ParameterGroup[]): string {
  const bodies = groups.map((g) => {
    const forms = acceptedForms(g.parameter).sort((a, b) => b.length - a.length);
    const formsPart = `(?:${forms.map(escapeRegex).join('|')})`;
    if (g.value) {
      const valuePart = g.value.trim().split(/\s+/).map(escapeRegex).join('\\s+');
      return `${formsPart}[\\s:]+${valuePart}\\b`;
    }
    return `${formsPart}(?:\\s|:|$)`;
  });
  const body = bodies.length === 1 ? bodies[0] : `(?:${bodies.join('|')})`;
  return `(?i)(?:^|\\s)${prefixClass(exe)}${body}`;
}

function verbatim(pattern: string): string {
  return `@"${pattern.replace(/"/g, '""')}"`;
}

interface ClassifiedLiterals {
  groups: ParameterGroup[];
  others: string[];
}

function classify(exe: ExecutableDefinition, literals: string[]): ClassifiedLiterals {
  const groups = new Map<string, ParameterGroup>();
  const others: string[] = [];
  for (const raw of literals) {
    const lit = raw.trim();
    const [token, ...restParts] = lit.split(/\s+/);
    const rest = restParts.join(' ');
    let param = matchParameter(exe, token);
    // A bare full parameter name such as "EncodedCommand" is also treated as the parameter.
    if (!param && !rest) {
      const word = token.toLowerCase();
      param = exe.parameters.find((p) => p.name === word && p.name.length >= 6);
    }
    if (param) {
      const key = `${param.name}|${rest.toLowerCase()}`;
      const g = groups.get(key) ?? { parameter: param, value: rest || undefined, originalLiterals: [] };
      g.originalLiterals.push(raw);
      groups.set(key, g);
    } else {
      others.push(raw);
    }
  }
  return { groups: [...groups.values()], others };
}

function detectExecutable(ctx: EngineContext): { exe?: ExecutableDefinition; reason: string } {
  for (const op of ctx.parsed.main?.operators ?? []) {
    if (op.name !== 'where' && op.name !== 'filter') continue;
    const cond = whereCondition(op.text);
    if (!cond) continue;
    for (const part of splitTopLevel(cond, 'and')) {
      const p = parseSimplePredicate(part);
      if (!p || p.negated || !IMAGE_COLUMNS.test(p.column)) continue;
      for (const lit of p.literals) {
        const base = lit.split(/[\\/]/).pop() ?? lit;
        const exe = findExecutable(base);
        if (exe) return { exe, reason: `the rule filters ${p.column} to ${base}` };
      }
    }
  }
  return { reason: '' };
}

export interface BenchRow {
  variant: string;
  description: string;
  original: boolean;
  hardened: boolean;
}

export interface HardenedPredicate {
  column: string;
  cleanColumn: string;
  operatorLine: number;
  originalText: string;
  newText: string;
  groups: ParameterGroup[];
  original: (value: string) => boolean;
  hardened: (value: string) => boolean;
}

export interface EvasionResult extends ModuleResult {
  executable?: ExecutableDefinition;
  bench: BenchRow[];
  hardened: HardenedPredicate[];
  sampleCounts?: { column: string; rows: number; original: number; hardened: number };
}

const DASHES: Record<string, string> = { '\u2013': 'en dash', '\u2014': 'em dash', '\u2015': 'horizontal bar' };

function variantsFor(exe: ExecutableDefinition, g: ParameterGroup): { text: string; description: string }[] {
  const p = g.parameter;
  const tail = g.value ? ` ${g.value}` : p.takesValue ? ' SQBFAFgA' : '';
  const out: { text: string; description: string }[] = [];
  const add = (form: string, description: string) => out.push({ text: `powershell.exe -NoLogo ${form}${tail}`, description });
  const shortest = p.prefixFrom;
  add(`-${p.name}`, 'Full parameter name');
  add(`-${p.name.toUpperCase()}`, 'Full name, upper case');
  for (const a of p.aliases) add(`-${a}`, 'Documented alias');
  if (!p.aliases.includes(shortest)) add(`-${shortest}`, 'Shortest accepted prefix');
  const mid = p.name.slice(0, Math.max(shortest.length + 1, Math.ceil(p.name.length / 2)));
  if (mid !== p.name && mid !== shortest) add(`-${mid}`, 'Partial prefix');
  add(`/${shortest}`, 'Forward slash prefix');
  for (const ch of exe.prefixCharacters.filter((c) => c.codePointAt(0)! > 127)) add(`${ch}${shortest}`, `Unicode ${DASHES[ch] ?? 'dash'} prefix`);
  const mixed = p.name.slice(0, Math.min(p.name.length, shortest.length + 2));
  if (mixed.length >= 2) {
    add(`-${mixed.slice(0, 1)}^${mixed.slice(1)}`, 'Caret inserted (cmd.exe escape)');
    add(`-${mixed.slice(0, 1)}"${mixed.slice(1)}"`, 'Quotes inserted');
  }
  return out;
}

export function runEvasion(ctx: EngineContext, sample?: Row[]): EvasionResult {
  const base = emptyResult('H', 'not-applicable', '');
  const result: EvasionResult = { ...base, bench: [], hardened: [] };
  const main = ctx.parsed.main;
  if (!main) {
    result.summary = 'No main query was found to harden.';
    return result;
  }

  let { exe, reason } = detectExecutable(ctx);

  // Find command-line conditions.
  const candidates: { opIndex: number; parts: string[]; preds: (SimplePredicate | undefined)[] }[] = [];
  main.operators.forEach((op, opIndex) => {
    if (op.name !== 'where' && op.name !== 'filter') return;
    const cond = whereCondition(op.text);
    if (!cond) return;
    const parts = splitTopLevel(cond, 'and');
    const preds = parts.map(parseSimplePredicate);
    const touchesCommandLine = preds.some((p) => p && COMMAND_LINE.test(p.column)) || parts.some((p) => COMMAND_LINE.test(p));
    if (touchesCommandLine) candidates.push({ opIndex, parts, preds });
  });

  if (candidates.length === 0) {
    result.summary = 'The rule has no command-line conditions to harden.';
    return result;
  }

  // Without an image-name filter, fall back to PowerShell only if a literal is clearly a PowerShell parameter.
  if (!exe) {
    const looksPowerShell = candidates.some((c) => c.preds.some((p) => p && classify(POWERSHELL, p.literals).groups.some((g) => g.parameter.name === 'encodedcommand' || g.parameter.name === 'executionpolicy')));
    if (looksPowerShell) {
      exe = POWERSHELL;
      reason = 'no image name filter was found, but the literals are PowerShell parameters';
      result.findings.push({ severity: 'warn', cat: 'H', title: 'Executable assumed to be PowerShell', detail: 'The rule does not filter on an image name, so PowerShell parameter rules were applied because the literals match PowerShell parameters. Check this is right.' });
    }
  }

  const cleanColumns = new Set<string>();
  for (const c of candidates) {
    const op = main.operators[c.opIndex];
    const newParts: string[] = [];
    let changed = false;
    const opHardened: HardenedPredicate[] = [];
    c.parts.forEach((part, idx) => {
      const p = c.preds[idx];
      if (!p || !COMMAND_LINE.test(p.column) || p.negated || !HARDENABLE.includes(p.operator)) {
        if (!p && COMMAND_LINE.test(part)) {
          result.findings.push({ severity: 'warn', cat: 'H', title: 'Command-line condition not rewritten', detail: `"${part.trim()}" is too complex for this build to rewrite safely (for example it uses "or" or a function). It has been left as it is.` });
        }
        newParts.push(part);
        return;
      }
      const clean = `Clean${p.column}`;
      const cls = exe ? classify(exe, p.literals) : { groups: [], others: p.literals };
      const pieces: string[] = [];
      let regex: RegExp | undefined;
      if (exe && cls.groups.length) {
        if (p.operator === 'has_all') {
          for (const g of cls.groups) pieces.push(`${clean} matches regex ${verbatim(buildParameterRegex(exe, [g]))}`);
        } else {
          const pattern = buildParameterRegex(exe, cls.groups);
          regex = kqlRegexToJs(pattern);
          pieces.push(`${clean} matches regex ${verbatim(pattern)}`);
        }
      }
      if (cls.others.length) {
        const op2 = p.operator;
        const list = cls.others.map(quote);
        pieces.push(list.length === 1 && !op2.endsWith('_any') && !op2.endsWith('_all') ? `${clean} ${op2} ${list[0]}` : `${clean} ${op2} (${list.join(', ')})`);
      }
      const joiner = p.operator === 'has_all' ? ' and ' : ' or ';
      const expr = pieces.length > 1 ? `(${pieces.join(joiner)})` : pieces[0];
      newParts.push(expr);
      changed = true;
      cleanColumns.add(p.column);

      const original = (v: string) => evaluate(p.operator, v, p.literals);
      const exeGroups = cls.groups;
      const hardened = (v: string) => {
        const cleaned = cleanJs(v);
        const regexHit = p.operator === 'has_all'
          ? exeGroups.every((g) => kqlRegexToJs(buildParameterRegex(exe!, [g])).test(cleaned))
          : regex ? regex.test(cleaned) : false;
        const othersHit = cls.others.length ? evaluate(p.operator, cleaned, cls.others) : false;
        if (p.operator === 'has_all') return regexHit && (cls.others.length ? othersHit : true);
        return regexHit || othersHit;
      };
      opHardened.push({ column: p.column, cleanColumn: clean, operatorLine: op.startLine, originalText: part.trim(), newText: expr, groups: cls.groups, original, hardened });
    });

    if (!changed) continue;
    const indent = /^\s*/.exec(ctx.parsed.lines[op.startLine])?.[0] ?? '';
    const lines: string[] = [];
    for (const h of opHardened) {
      if (!result.hardened.some((x) => x.column === h.column)) lines.push(`${indent}| extend ${h.cleanColumn} = ${cleanExpression(h.column)}`);
    }
    const keyword = /^\|\s*(where|filter)/i.exec(op.text)?.[1] ?? 'where';
    if (newParts.length === 1) lines.push(`${indent}| ${keyword} ${newParts[0]}`);
    else {
      lines.push(`${indent}| ${keyword} ${newParts[0]}`);
      for (const extra of newParts.slice(1)) lines.push(`${indent}    and ${extra}`);
    }
    result.edits.push({ type: 'replace', fromLine: op.startLine, toLine: op.endLine, lines, cat: 'H' });
    result.hardened.push(...opHardened);
  }

  if (result.hardened.length === 0) {
    result.summary = 'Command-line conditions were found, but none could be hardened safely.';
    return result;
  }

  result.status = 'applied';
  result.executable = exe;
  for (const col of cleanColumns) {
    result.outputColumns.push(`Clean${col}`);
    if (ctx.baseName) result.uses.push({ table: ctx.baseName, column: col, cat: 'H' });
  }

  const allGroups = result.hardened.flatMap((h) => h.groups);
  const paramNames = [...new Set(allGroups.map((g) => g.parameter.name))];
  const formsCovered = allGroups.reduce((n, g) => n + acceptedForms(g.parameter).length, 0);
  const formsBefore = allGroups.reduce((n, g) => n + g.originalLiterals.length, 0);
  result.summary = paramNames.length
    ? `Covers ${formsCovered} accepted forms of ${paramNames.length} parameter${paramNames.length > 1 ? 's' : ''} (the rule listed ${formsBefore}), and strips carets, quotes and string concatenation first.`
    : 'Strips carets, quotes and string concatenation before matching the command line.';

  result.notes.push({
    cat: 'H',
    title: paramNames.length ? 'Parameter abbreviation coverage' : 'Command-line normalisation',
    detail: (paramNames.length
      ? `Replaced literal matches on ${paramNames.map((n) => `-${n}`).join(', ')} with a pattern covering every accepted prefix form and documented alias, introduced by a hyphen, forward slash or Unicode dash. `
      : '') + `Matching now runs against a cleaned copy of the command line with caret characters, double quotes and simple string concatenation removed${exe ? `. Executable rules: ${exe.label}, chosen because ${reason}.` : '.'}`,
    watch: 'Base64 payload decoding is not applied yet. Prefix forms follow PowerShell\'s prefix matching behaviour, which is worth confirming in the lab; the aliases are documented on Microsoft Learn.',
  });

  // Evasion test bench: synthetic variants of every hardened parameter.
  for (const h of result.hardened) {
    for (const g of h.groups) {
      for (const v of variantsFor(exe!, g)) {
        result.bench.push({ variant: v.text, description: `${v.description} (-${g.parameter.name})`, original: h.original(v.text), hardened: h.hardened(v.text) });
      }
    }
  }
  const missedBefore = result.bench.filter((b) => !b.original).length;
  const missedAfter = result.bench.filter((b) => !b.hardened).length;
  if (result.bench.length) {
    result.findings.push({
      severity: missedAfter === 0 ? 'pass' : 'warn',
      cat: 'H',
      title: `Evasion test bench: original rule catches ${result.bench.length - missedBefore} of ${result.bench.length} variants, hardened rule catches ${result.bench.length - missedAfter}`,
      detail: 'Synthetic command lines using abbreviations, aliases, alternative prefix characters, carets and quotes. Results use JavaScript approximations of the KQL operators.',
    });
  }

  // Sample rows: how many rows each version matches.
  if (sample?.length) {
    const h = result.hardened[0];
    const values = sample.map((r) => String(r[h.column] ?? ''));
    const original = values.filter(h.original).length;
    const hardened = values.filter(h.hardened).length;
    result.sampleCounts = { column: h.column, rows: values.length, original, hardened };
    const f: Finding = {
      severity: hardened >= original ? 'info' : 'warn',
      cat: 'H',
      title: `Sample rows: original condition matches ${original} of ${values.length}, hardened condition matches ${hardened}`,
      detail: hardened > original
        ? 'The hardened condition matches rows the original missed. Review them in the sample to confirm they are evasion variants rather than false positives.'
        : hardened < original
          ? 'The hardened condition matches fewer rows than the original, which is unexpected. Review the change before using it.'
          : 'Both conditions match the same rows in your sample.',
    };
    result.findings.push(f);
  }
  return result;
}

export { EXECUTABLES };
