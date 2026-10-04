// Maturity assessment against the four-question decision tree (Q0 to Q3), mirroring the
// rule-maturity-advancement skill. Q1 and Q2 are read from the query; Q0 and Q3 need
// answers from the analyst, because they depend on how the rule is run.
import type { ParsedQuery } from './kql';
import { tokenize } from './kql';
import type { Platform } from './types';

export type Tier = 'L1' | 'L2' | 'L3' | 'L3-provisional' | 'Retire';

export interface Question {
  id: 'Q0' | 'Q1' | 'Q2' | 'Q3';
  title: string;
  answer: 'yes' | 'no' | 'not-reached' | 'needs-input';
  reasoning: string;
  evidence: string[];
}

export interface AssessmentInputs {
  retired: boolean;
  baselineCurrent: boolean;
  flighted: boolean;
}

export interface Recommendation {
  pattern: string;
  title: string;
  detail: string;
  category?: 'E' | 'T' | 'B' | 'N' | 'H';
}

export interface Assessment {
  tier: Tier;
  tierLabel: string;
  questions: Question[];
  recommendations: Recommendation[];
  asimPosition: string;
  ceilingNote?: string;
}

const MAINTAINED_SOURCES = /^(IdentityInfo|ThreatIntelIndicators|ThreatIntelligenceIndicator|BehaviorAnalytics|UserPeerAnalytics|DeviceInfo|Anomalies|_GetWatchlist|externaldata|_ASIM_GetWatchlist)$/i;
const LEARNED_NORMAL = /^(BehaviorAnalytics|Anomalies|series_decompose_anomalies|series_outliers|series_decompose_forecast|InvestigationPriority|UserPeerAnalytics|autocluster|basket)$/i;
const SCALAR_ONLY = /^(geo_info_from_ip_address|ipv4_is_private|ipv4_is_in_range|parse_json|todynamic|split|extract|parse_url)$/i;

/** ASIM parsers for common source tables, used for the A6 position. Verify in your workspace. */
export const ASIM_PARSERS: Record<string, string> = {
  DeviceProcessEvents: '_Im_ProcessCreate',
  SecurityEvent: '_Im_ProcessCreate',
  DeviceNetworkEvents: '_Im_NetworkSession',
  CommonSecurityLog: '_Im_NetworkSession',
  SigninLogs: '_Im_Authentication',
  AADNonInteractiveUserSignInLogs: '_Im_Authentication',
  DeviceFileEvents: '_Im_FileEvent',
  DeviceRegistryEvents: '_Im_RegistryEvent',
  DnsEvents: '_Im_Dns',
};

export function detectPlatform(parsed: ParsedQuery): Platform {
  const ids = new Set(tokenize(parsed.text).filter((t) => t.type === 'ident').map((t) => t.text));
  if (ids.has('TimeGenerated')) return 'sentinel';
  if (ids.has('Timestamp')) return 'advanced-hunting';
  return 'sentinel';
}

export function assess(parsed: ParsedQuery, platform: Platform, inputs: AssessmentInputs): Assessment {
  const toks = tokenize(parsed.text);
  const idents = toks.filter((t) => t.type === 'ident').map((t) => t.text);
  const lowerOps = new Set(parsed.main?.operators.map((o) => o.name) ?? []);
  const hasJoin = lowerOps.has('join') || lowerOps.has('lookup') || /\b(join|lookup)\b/.test(parsed.text);

  const maintained = [...new Set(idents.filter((i) => MAINTAINED_SOURCES.test(i)))];
  const learned = [...new Set(idents.filter((i) => LEARNED_NORMAL.test(i)))];
  const scalar = [...new Set(idents.filter((i) => SCALAR_ONLY.test(i)))];
  const inlineLists = (parsed.text.match(/dynamic\s*\(\s*\[/g) ?? []).length + (parsed.text.match(/\b(has_any|in~?|has_all)\s*\(/g) ?? []).length;

  const questions: Question[] = [];
  questions.push({
    id: 'Q0',
    title: 'Retirement screen',
    answer: inputs.retired ? 'no' : 'yes',
    reasoning: inputs.retired
      ? 'Marked as dead or unmaintained, so it is a candidate for retirement rather than improvement.'
      : 'Brought in for improvement, so treated as an active rule.',
    evidence: [],
  });

  let tier: Tier;
  if (inputs.retired) {
    tier = 'Retire';
  } else {
    const q1 = maintained.length > 0 && (hasJoin || maintained.some((m) => /^_GetWatchlist$|^externaldata$/i.test(m)));
    const q1Evidence = [...maintained.map((m) => `References ${m}`)];
    if (scalar.length) q1Evidence.push(`Built-in scalar functions (${scalar.join(', ')}) do not count as enrichment`);
    if (inlineLists) q1Evidence.push(`${inlineLists} inline list${inlineLists > 1 ? 's' : ''} of literal values, which go stale and do not count as enrichment`);
    questions.push({
      id: 'Q1',
      title: 'Joins a maintained dataset at query time',
      answer: q1 ? 'yes' : 'no',
      reasoning: q1
        ? 'The rule joins environment-maintained context, so it can treat entities differently based on your own data.'
        : 'No join against an environment-maintained dataset (IdentityInfo, threat intelligence, a watchlist or an asset table). Parsing, scalar functions and inline lists are fixed conditions.',
      evidence: q1Evidence,
    });
    if (!q1) {
      tier = 'L1';
      questions.push({ id: 'Q2', title: 'Detects deviation from learned normal', answer: 'not-reached', reasoning: 'Not reached, because Q1 stopped the walk.', evidence: [] });
      questions.push({ id: 'Q3', title: 'Baseline current and rule flighted', answer: 'not-reached', reasoning: 'Not reached.', evidence: [] });
    } else {
      const q2 = learned.length > 0;
      questions.push({
        id: 'Q2',
        title: 'Detects deviation from learned normal',
        answer: q2 ? 'yes' : 'no',
        reasoning: q2
          ? 'The rule uses a baseline, anomaly function or behavioural analytics, so identical input can produce different verdicts depending on history.'
          : 'The conditions are fixed, however many there are, so identical input always produces the same verdict.',
        evidence: learned.map((l) => `Uses ${l}`),
      });
      if (!q2) {
        tier = 'L2';
        questions.push({ id: 'Q3', title: 'Baseline current and rule flighted', answer: 'not-reached', reasoning: 'Not reached.', evidence: [] });
      } else {
        const ok = inputs.baselineCurrent && inputs.flighted;
        tier = ok ? 'L3' : 'L3-provisional';
        questions.push({
          id: 'Q3',
          title: 'Baseline current and rule flighted',
          answer: ok ? 'yes' : 'needs-input',
          reasoning: ok
            ? 'The baseline is current and the rule was flighted before going live.'
            : 'Structurally L3, but not trustworthy until the baseline is confirmed current and the rule has been flighted. Tick both in the assessment step once true.',
          evidence: [],
        });
      }
    }
  }

  const tierLabel: Record<Tier, string> = {
    L1: 'Atomic', L2: 'Contextual', L3: 'Behavioural', 'L3-provisional': 'Behavioural, provisional', Retire: 'Retirement candidate',
  };

  const recommendations: Recommendation[] = [];
  const hasIdentity = maintained.some((m) => /^IdentityInfo$/i.test(m));
  const hasTi = maintained.some((m) => /^ThreatIntel/i.test(m));
  if (!hasIdentity) recommendations.push({ pattern: 'A1', category: 'E', title: 'Add identity context', detail: 'Join IdentityInfo so the rule can tell a privileged or sensitive account from a standard one and tier severity accordingly.' });
  if (inlineLists && /(account|user|upn|admin)/i.test(parsed.text)) recommendations.push({ pattern: 'A2', title: 'Replace inline lists with a maintained dataset', detail: 'An inline list of accounts goes stale silently. Move it to a watchlist or derive it from IdentityInfo.' });
  if (!hasTi) recommendations.push({ pattern: 'A3', category: 'T', title: 'Add threat intelligence correlation', detail: 'Check the hashes, addresses or domains the rule observes against active indicators.' });

  const parser = parsed.main?.sourceTable ? ASIM_PARSERS[parsed.main.sourceTable] : undefined;
  let asimPosition: string;
  if (platform === 'advanced-hunting') {
    asimPosition = 'A6 does not apply here: Defender Advanced Hunting has no ASIM parsers.' + (parser ? ` If the rule is deployed to Sentinel instead, re-base it on ${parser} so one rule works across every normalised source.` : '');
  } else if (parser) {
    asimPosition = `A6 recommended: re-base the rule on ${parser}. It makes one rule work across every normalised source in every tenant, and gives UEBA the normalised data the L2 to L3 path depends on. It does not change the tier by itself.`;
    recommendations.push({ pattern: 'A6', category: 'N', title: 'ASIM normalisation', detail: asimPosition });
  } else {
    asimPosition = `A6 does not apply: no ASIM parser is mapped for ${parsed.main?.sourceTable ?? 'this source'} in this build.`;
  }

  const ceilingNote = tier === 'L2'
    ? 'L2 may be the right ceiling for this rule. A well-tuned contextual rule often outperforms a behavioural one, so only move to L3 if a baseline would genuinely improve it.'
    : undefined;

  return { tier, tierLabel: tierLabel[tier], questions, recommendations, asimPosition, ceilingNote };
}
