// Command-line parameter library used by evasion hardening.
//
// Each parameter records:
//   - name: the full parameter name, without its prefix character
//   - aliases: documented short forms, with the page they are documented on
//   - prefixFrom: the shortest prefix the engine expands from. Every prefix of `name`
//     from this length up to the full name is treated as equivalent.
//
// Documented aliases come from Microsoft Learn. The prefix expansion reflects
// PowerShell's behaviour of accepting an unambiguous prefix of a parameter name; it
// is not spelled out parameter by parameter in the documentation, so it is flagged
// in the change log as something to confirm in the lab.

export interface ParameterDefinition {
  name: string;
  aliases: string[];
  prefixFrom: string;
  takesValue: boolean;
}

export interface ExecutableDefinition {
  id: string;
  label: string;
  /** Image names that identify the executable in FileName-style columns. */
  imageNames: string[];
  /** Characters that can introduce a parameter on this executable's command line. */
  prefixCharacters: string[];
  sources: { title: string; url: string }[];
  parameters: ParameterDefinition[];
}

// Hyphen, forward slash, and the Unicode en dash, em dash and horizontal bar, which
// PowerShell accepts in place of a hyphen. Written as code points so the source file
// contains no dash characters other than the hyphen.
export const POWERSHELL_PREFIX_CHARACTERS = ['-', '/', '\u2013', '\u2014', '\u2015'];

export const POWERSHELL: ExecutableDefinition = {
  id: 'powershell',
  label: 'PowerShell (powershell.exe and pwsh.exe)',
  imageNames: ['powershell.exe', 'pwsh.exe', 'powershell_ise.exe', 'powershell', 'pwsh'],
  prefixCharacters: POWERSHELL_PREFIX_CHARACTERS,
  sources: [
    {
      title: 'about_Pwsh (Microsoft Learn)',
      url: 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh',
    },
    {
      title: 'about_PowerShell_exe (Microsoft Learn)',
      url: 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1',
    },
  ],
  parameters: [
    { name: 'encodedcommand', aliases: ['e', 'ec'], prefixFrom: 'e', takesValue: true },
    { name: 'encodedarguments', aliases: [], prefixFrom: 'encodeda', takesValue: true },
    { name: 'executionpolicy', aliases: ['ex', 'ep'], prefixFrom: 'ex', takesValue: true },
    { name: 'noprofile', aliases: ['nop'], prefixFrom: 'nop', takesValue: false },
    { name: 'noninteractive', aliases: ['noni'], prefixFrom: 'noni', takesValue: false },
    { name: 'noexit', aliases: ['noe'], prefixFrom: 'noe', takesValue: false },
    { name: 'nologo', aliases: ['nol'], prefixFrom: 'nol', takesValue: false },
    { name: 'windowstyle', aliases: ['w'], prefixFrom: 'w', takesValue: true },
    { name: 'command', aliases: ['c'], prefixFrom: 'c', takesValue: true },
    { name: 'file', aliases: ['f'], prefixFrom: 'f', takesValue: true },
    { name: 'inputformat', aliases: ['inp', 'if'], prefixFrom: 'inp', takesValue: true },
    { name: 'outputformat', aliases: ['o', 'of'], prefixFrom: 'o', takesValue: true },
    { name: 'configurationname', aliases: ['config'], prefixFrom: 'config', takesValue: true },
    { name: 'workingdirectory', aliases: ['wd', 'wo'], prefixFrom: 'wo', takesValue: true },
  ],
};

export const EXECUTABLES: ExecutableDefinition[] = [POWERSHELL];

/** Every accepted spelling of a parameter, without the prefix character. */
export function acceptedForms(p: ParameterDefinition): string[] {
  const forms = new Set<string>();
  for (let len = p.prefixFrom.length; len <= p.name.length; len++) forms.add(p.name.slice(0, len));
  p.aliases.forEach((a) => forms.add(a));
  return [...forms];
}

/**
 * Finds the parameter a literal such as "-enc" or "/ExecutionPolicy" refers to.
 * Returns undefined when the text is not a recognised parameter of the executable.
 */
export function matchParameter(exe: ExecutableDefinition, token: string): ParameterDefinition | undefined {
  const first = token[0];
  if (!exe.prefixCharacters.includes(first)) return undefined;
  const word = token.slice(1).toLowerCase();
  if (!word) return undefined;
  // Exact alias or full name first, then prefix ranges, so "ec" maps to encodedcommand.
  const exact = exe.parameters.find((p) => p.name === word || p.aliases.includes(word));
  if (exact) return exact;
  return exe.parameters.find((p) => word.length >= p.prefixFrom.length && p.name.startsWith(word) && word.startsWith(p.prefixFrom));
}

export function findExecutable(imageName: string): ExecutableDefinition | undefined {
  const lower = imageName.toLowerCase();
  return EXECUTABLES.find((e) => e.imageNames.includes(lower));
}
