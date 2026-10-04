# QA testing guide

This guide is for running your own test cases through the prototype and recording the results, so failures can be turned into engine fixes and unit tests.

## Preparing a test case

Keep each case in its own folder under `local-cases/` (ignored by git), for example `local-cases/01-encoded-powershell/`.

1. **The rule.** Save the original query as `rule.kql`.
2. **Schemas.** For the base table and each enrichment source, run the query below and export the result as CSV, named `<Table>_schema.csv`:

   ```kql
   DeviceProcessEvents
   | getschema
   | project ColumnName, ColumnType
   ```

3. **Samples.** Export up to 100 rows of each table as JSON or CSV, named `<Table>_sample.json`. Step 2 of the tool generates the export queries for the rule you pasted, including an IdentityInfo sample taken for the same accounts as the base sample, so the lookup can be tested.
   Use the export queries the tool generates where you can: they add the standard join keys `IdentityInfo_Key` and `ThreatIntel_Key` (lower-cased) to every sample, which is what lets the tool test the lookups against your data. Choose the account identifier on the Entity enrichment card first, because the export queries use it.
4. **Expected result (optional but recommended).** Save your own hand-improved version as `expected.kql`, so the tool's output can be compared with it.

Mask usernames, device names and account IDs in client data before exporting. Lab data avoids the problem entirely.

## Running a case

1. Paste `rule.kql` on step 1 and give it a name.
2. On step 2, drop every file from the case folder onto the large drop zone at once. Check each table card shows its schema and sample, and read the checks panel.
3. On step 3, check the maturity verdict and reasoning match what you would expect from the decision tree.
4. On step 4, switch improvements on and off, change the join key and observable if needed, and read the change notes.
5. On step 5, copy the query and run it in the target workspace. Note whether it runs, how many rows it returns, and whether the enrichment columns are populated.

## What to record

| Field | What to note |
| --- | --- |
| Case | Folder name and a one-line description |
| Parsing | Did step 1 find the right base table and operators? |
| Reference data | Were all files accepted? Any parsing problems? |
| Assessment | Tool verdict, your verdict, and any disagreement in the reasoning |
| Output runs | Did the improved query run in the workspace without errors? |
| Output correct | Do the results match your expectation or `expected.kql`? |
| False results | Rows the hardened rule now matches that it should not, or still misses |
| Issues | Anything wrong, confusing or missing, with a screenshot |

Raise each issue as a GitHub issue with the masked rule and the recorded fields. Engine issues become a unit test in `tests/` before they are fixed, so the same failure cannot return.
