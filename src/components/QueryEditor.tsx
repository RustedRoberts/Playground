import { useEffect, useMemo, useRef } from 'react';
import { monaco } from '../monaco/setup';
import type { OutputLine } from '../engine/types';

type Props =
  | { mode: 'edit'; value: string; onChange: (value: string) => void; minLines?: number; ariaLabel: string }
  | { mode: 'annotated'; lines: OutputLine[]; showRemoved: boolean; ariaLabel: string; minLines?: number };

const LINE_HEIGHT = 20;

/**
 * Monaco editor used both for entering the rule and for showing the improved query.
 * In annotated mode each added line carries its category colour, a bar in the gutter
 * and the category letter, and edited lines highlight only the added segments.
 */
export function QueryEditor(props: Props) {
  const host = useRef<HTMLDivElement>(null);
  const editor = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  const decorations = useRef<monaco.editor.IEditorDecorationsCollection | null>(null);
  const onChangeRef = useRef<((v: string) => void) | null>(null);
  onChangeRef.current = props.mode === 'edit' ? props.onChange : null;

  const annotated = useMemo(() => {
    if (props.mode !== 'annotated') return null;
    const visible = props.lines.filter((l) => props.showRemoved || l.kind !== 'del');
    const text = visible.map((l) => l.segs.map((s) => s.text).join('')).join('\n');
    const decos: monaco.editor.IModelDeltaDecoration[] = [];
    visible.forEach((l, i) => {
      const lineNumber = i + 1;
      if ((l.kind === 'add' || l.kind === 'del') && l.cat) {
        decos.push({
          range: new monaco.Range(lineNumber, 1, lineNumber, 1),
          options: {
            isWholeLine: true,
            className: `cat-line cat-line-${l.cat}${l.kind === 'del' ? ' line-removed' : ''}`,
            linesDecorationsClassName: `cat-bar cat-bar-${l.cat}`,
            glyphMarginClassName: `cat-glyph cat-glyph-${l.cat}`,
            glyphMarginHoverMessage: { value: l.kind === 'del' ? 'Removed and replaced' : 'Added' },
          },
        });
        if (l.kind === 'del') {
          decos.push({ range: new monaco.Range(lineNumber, 1, lineNumber, 10000), options: { inlineClassName: 'line-removed-text' } });
        }
      } else if (l.kind === 'mod') {
        let col = 1;
        const cats = new Set<string>();
        for (const s of l.segs) {
          if (s.cat) {
            cats.add(s.cat);
            decos.push({ range: new monaco.Range(lineNumber, col, lineNumber, col + s.text.length), options: { inlineClassName: `cat-seg cat-seg-${s.cat}` } });
          }
          col += s.text.length;
        }
        const first = [...cats][0];
        if (first) {
          decos.push({
            range: new monaco.Range(lineNumber, 1, lineNumber, 1),
            options: {
              linesDecorationsClassName: `cat-bar cat-bar-${first} cat-bar-partial`,
              glyphMarginClassName: `cat-glyph cat-glyph-${cats.size > 1 ? 'multi' : first}`,
              glyphMarginHoverMessage: { value: `Edited: ${[...cats].join(', ')}` },
            },
          });
        }
      }
    });
    return { text, decos, lineCount: visible.length };
  }, [props]);

  const value = props.mode === 'edit' ? props.value : annotated?.text ?? '';
  const lineCount = Math.max(props.minLines ?? 8, value.split('\n').length);

  useEffect(() => {
    if (!host.current) return;
    const ed = monaco.editor.create(host.current, {
      value,
      language: 'kql',
      theme: 'detection-dark',
      readOnly: props.mode !== 'edit',
      minimap: { enabled: false },
      fontFamily: "'JetBrains Mono', ui-monospace, monospace",
      fontSize: 13,
      lineHeight: LINE_HEIGHT,
      glyphMargin: props.mode === 'annotated',
      lineDecorationsWidth: props.mode === 'annotated' ? 8 : 4,
      scrollBeyondLastLine: false,
      automaticLayout: true,
      wordWrap: 'off',
      bracketPairColorization: { enabled: false },
      guides: { indentation: false, bracketPairs: false },
      matchBrackets: props.mode === 'edit' ? 'always' : 'never',
      renderLineHighlight: props.mode === 'edit' ? 'line' : 'none',
      tabSize: 4,
      ariaLabel: props.ariaLabel,
      scrollbar: { alwaysConsumeMouseWheel: false },
      padding: { top: 10, bottom: 10 },
    });
    editor.current = ed;
    decorations.current = ed.createDecorationsCollection([]);
    const sub = ed.onDidChangeModelContent(() => onChangeRef.current?.(ed.getValue()));
    return () => {
      sub.dispose();
      ed.dispose();
      editor.current = null;
    };
    // The editor is created once; later prop changes are applied in the effects below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const ed = editor.current;
    if (!ed) return;
    if (ed.getValue() !== value) {
      if (props.mode === 'edit') {
        ed.executeEdits('external', [{ range: ed.getModel()!.getFullModelRange(), text: value }]);
      } else {
        ed.setValue(value);
      }
    }
    decorations.current?.set(annotated?.decos ?? []);
  }, [value, annotated, props.mode]);

  return <div ref={host} className="query-editor" style={{ height: lineCount * LINE_HEIGHT + 24 }} />;
}
