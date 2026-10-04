import type { Category } from './types';

export const CATEGORY_LABELS: Record<Category, string> = {
  E: 'Entity enrichment',
  T: 'Threat intelligence',
  B: 'Baseline deviation',
  N: 'ASIM normalisation',
  H: 'Evasion hardening',
};

export const CATEGORY_PATTERNS: Record<Category, string> = {
  E: 'A1 Identity context',
  T: 'A3 Threat intelligence',
  B: 'Baseline deviation',
  N: 'A6 ASIM',
  H: 'Evasion hardening',
};

/**
 * Colours for the dark interface. Each colour is paired with its letter wherever it is
 * shown, so the categories never rely on colour alone.
 */
export const CATEGORY_COLOURS: Record<Category, { colour: string; tint: string }> = {
  E: { colour: '#6AA8FF', tint: 'rgba(106,168,255,0.15)' },
  T: { colour: '#FF7A7A', tint: 'rgba(255,122,122,0.15)' },
  B: { colour: '#F2B84B', tint: 'rgba(242,184,75,0.15)' },
  N: { colour: '#4FD1C1', tint: 'rgba(79,209,193,0.15)' },
  H: { colour: '#B79CFF', tint: 'rgba(183,156,255,0.15)' },
};
