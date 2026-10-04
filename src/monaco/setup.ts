// Monaco is bundled locally (no CDN), with only the core editor and a small KQL
// tokenizer, so the tool works on networks that block public script hosts.
import * as monaco from 'monaco-editor/esm/vs/editor/edcore.main';
import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker';

declare global {
  interface Window {
    MonacoEnvironment?: { getWorker: (workerId: string, label: string) => Worker };
  }
}

window.MonacoEnvironment = { getWorker: () => new EditorWorker() };

const KEYWORDS = [
  'let', 'where', 'filter', 'extend', 'project', 'project-away', 'project-keep', 'project-rename', 'project-reorder',
  'summarize', 'by', 'join', 'lookup', 'on', 'kind', 'union', 'take', 'limit', 'top', 'sort', 'order', 'asc', 'desc',
  'distinct', 'count', 'mv-expand', 'mv-apply', 'parse', 'evaluate', 'render', 'make-series', 'range', 'print',
  'datatable', 'externaldata', 'invoke', 'as', 'with', 'step', 'from', 'to', 'materialize', 'toscalar',
  'and', 'or', 'not', 'in', 'has', 'has_cs', 'has_any', 'has_all', 'contains', 'contains_cs', 'startswith', 'endswith',
  'matches', 'regex', 'between', 'true', 'false', 'null', 'inner', 'leftouter', 'rightouter', 'fullouter',
  'leftanti', 'rightanti', 'leftsemi', 'rightsemi', 'innerunique',
];

monaco.languages.register({ id: 'kql', aliases: ['KQL', 'Kusto'] });
monaco.languages.setLanguageConfiguration('kql', {
  comments: { lineComment: '//' },
  brackets: [['(', ')'], ['[', ']'], ['{', '}']],
  autoClosingPairs: [
    { open: '(', close: ')' }, { open: '[', close: ']' }, { open: '{', close: '}' },
    { open: '"', close: '"', notIn: ['string'] }, { open: "'", close: "'", notIn: ['string'] },
  ],
});
monaco.languages.setMonarchTokensProvider('kql', {
  ignoreCase: true,
  keywords: KEYWORDS,
  tokenizer: {
    root: [
      [/\/\/.*$/, 'comment'],
      [/(h|H)?@"/, { token: 'string', next: '@verbatimDouble' }],
      [/(h|H)?@'/, { token: 'string', next: '@verbatimSingle' }],
      [/(h|H)?"/, { token: 'string', next: '@double' }],
      [/(h|H)?'/, { token: 'string', next: '@single' }],
      [/[a-zA-Z_][\w]*(-[a-zA-Z_][\w]*)*(?=\s*\()/, { cases: { '@keywords': 'keyword', '@default': 'function' } }],
      [/[a-zA-Z_$][\w$]*(-[a-zA-Z_][\w]*)*/, { cases: { '@keywords': 'keyword', '@default': 'identifier' } }],
      [/\d+(\.\d+)?(d|h|m|s|ms|microsecond|tick)?/, 'number'],
      [/[|]/, 'pipe'],
      [/[=!<>~+\-*/%]+/, 'operator'],
    ],
    double: [[/[^\\"]+/, 'string'], [/\\./, 'string'], [/"/, { token: 'string', next: '@pop' }]],
    single: [[/[^\\']+/, 'string'], [/\\./, 'string'], [/'/, { token: 'string', next: '@pop' }]],
    verbatimDouble: [[/[^"]+/, 'string'], [/""/, 'string'], [/"/, { token: 'string', next: '@pop' }]],
    verbatimSingle: [[/[^']+/, 'string'], [/''/, 'string'], [/'/, { token: 'string', next: '@pop' }]],
  },
});

// Syntax colours stay muted and avoid the five category colours, so highlighting never
// reads as an improvement marker.
monaco.editor.defineTheme('detection-dark', {
  base: 'vs-dark',
  inherit: true,
  rules: [
    { token: 'keyword', foreground: 'ECEEF2', fontStyle: 'bold' },
    { token: 'function', foreground: 'D7DCE4' },
    { token: 'identifier', foreground: 'C4C9D2' },
    { token: 'string', foreground: 'A8D5A2' },
    { token: 'number', foreground: 'D9B99B' },
    { token: 'comment', foreground: '7D8590', fontStyle: 'italic' },
    { token: 'pipe', foreground: '8C94A1' },
    { token: 'operator', foreground: 'A0A7B4' },
  ],
  colors: {
    'editor.background': '#111317',
    'editor.lineHighlightBackground': '#1A1D23',
    'editorLineNumber.foreground': '#737B88',
    'editorLineNumber.activeForeground': '#C4C9D2',
    'editorGutter.background': '#111317',
    'editor.selectionBackground': '#3A404C',
  },
});

export { monaco };
