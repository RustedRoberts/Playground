// Built-in map of where account identifiers sit in tables that keep them in nested
// (dynamic) columns. Each entry gives the KQL expression that extracts the identifier,
// the IdentityInfo column it matches, and the path used to check it against sample rows.
//
// Add a table here when the tool should offer its nested identifiers without the rule
// having to extract them first. Paths are written for the raw table; when the rule
// mv-expands the column, the expression drops the [0] index.

export interface IdentifierMapping {
  id: string;
  label: string;
  /** Top-level column the identifier is read from; must exist in the uploaded schema. */
  rootColumn: string;
  /** KQL expression on the raw table. */
  expression: string;
  /** KQL expression once the rule has run `mv-expand <rootColumn>`. */
  expandedExpression?: string;
  /** Path into the raw column value, used to resolve the identifier in sample rows. */
  samplePath: (string | number)[];
  /** IdentityInfo columns it can match, in order of preference. */
  identityColumns: string[];
  strength: 'strong' | 'weak';
  note: string;
}

export const IDENTIFIER_MAP: Record<string, IdentifierMapping[]> = {
  AuditLogs: [
    {
      id: 'auditlogs-target',
      label: 'Target account (TargetResources)',
      rootColumn: 'TargetResources',
      expression: 'tostring(TargetResources[0].id)',
      expandedExpression: 'tostring(TargetResources.id)',
      samplePath: ['TargetResources', 0, 'id'],
      identityColumns: ['AccountObjectId'],
      strength: 'strong',
      note: 'The first target resource. For user management operations this is the user acted on; for other operations check its type is User.',
    },
    {
      id: 'auditlogs-initiator',
      label: 'Initiating account (InitiatedBy)',
      rootColumn: 'InitiatedBy',
      expression: 'tostring(InitiatedBy.user.id)',
      samplePath: ['InitiatedBy', 'user', 'id'],
      identityColumns: ['AccountObjectId'],
      strength: 'strong',
      note: 'The user who performed the operation. Empty when an application initiated it.',
    },
  ],
};

/** Reads a nested value from a sample row, parsing JSON strings on the way down. */
export function resolvePath(row: Record<string, unknown>, path: (string | number)[]): unknown {
  let value: unknown = row;
  for (const step of path) {
    if (typeof value === 'string') {
      try { value = JSON.parse(value); } catch { return undefined; }
    }
    if (value === null || value === undefined) return undefined;
    if (typeof step === 'number') {
      // An expanded column holds an object rather than an array; accept either.
      value = Array.isArray(value) ? value[step] : step === 0 ? value : undefined;
    } else {
      value = (value as Record<string, unknown>)[step];
    }
  }
  return value;
}
