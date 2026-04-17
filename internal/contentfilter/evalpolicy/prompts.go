// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

// redactedMarker is the placeholder the LLM replaces redacted
// content with. Kept identical to PR 95 so downstream evaluation
// tooling (golden-answer checkers, leakage scanners) continues to
// match.
const redactedMarker = "[REDACTED FOR EVALUATION]"

// filterUnavailableText replaces the entire tool output when the LLM
// call fails. Identical to PR 95's FILTER_UNAVAILABLE so anything
// downstream that matches on the sentinel continues to work.
const filterUnavailableText = "[ENTIRE OUTPUT REDACTED - FILTER UNAVAILABLE]"

// systemPrompt is the system-role prompt sent to the LLM. Ported
// verbatim from PR 95's SYSTEM_PROMPT so behaviour is bit-for-bit
// identical; changes here require coordination with the
// anti-leakage evaluation methodology and cross-checking against the
// existing golden benchmarks.
const systemPrompt = "You are a data leakage prevention filter for an AI RCA evaluation " +
	"benchmark.  Your sole purpose is to remove resolution and root cause " +
	"content from tool outputs while preserving all diagnostic and symptom " +
	"data verbatim.  You must output ONLY the filtered content in the exact " +
	"same format as the input.  No explanations, no markdown fences, no " +
	"commentary."

// userPromptTemplate is the user-role prompt template. It accepts
// three substitutions — tool_name, ticket_id, content — substituted
// via [buildUserPrompt]. Ported verbatim from PR 95's
// USER_PROMPT_TEMPLATE; the prose is load-bearing (it is the product
// of the filter) so edits MUST be approved via the evaluation
// benchmark process.
//
// Note: Go does not have Python's str.format, so we use %s
// placeholders and fmt.Sprintf in [buildUserPrompt]. The placeholder
// order (tool_name, ticket_id, content, ticket_id, ticket_id) mirrors
// the Python template's field references and is enforced by a test.
const userPromptTemplate = `Filter the following %s output to prevent data leakage in an RCA evaluation.

EVALUATION TICKET: %s

== WHAT TO REMOVE (replace with [REDACTED FOR EVALUATION]) ==

1. ROOT CAUSE STATEMENTS: Any sentence or phrase that identifies WHY a failure occurred.
   - "root cause was ...", "caused by ...", "the issue stemmed from ..."
   - "traced back to ...", "attributed to ...", "due to ..."
   - "the culprit was ...", "originated from ...", "result of ..."

2. RESOLUTION / FIX / WORKAROUND: Any content describing what was done to fix the problem.
   - "fixed in ...", "resolved by ...", "patched via ..."
   - "applied workaround ...", "upgraded to ...", "rolled back ..."
   - "restarted the service", "increased heap to ...", "replaced disk ..."
   - "ran heal with ...", "modified config ...", "disabled feature ..."

3. POST-FIX VERIFICATION: Confirmation that a fix worked.
   - "verified after fix", "confirmed working after ..."
   - "issue did not recur after ...", "customer confirmed ..."

4. FIX REFERENCES: Specific version/commit identifiers for the fix.
   - Fix version numbers (e.g., "Fixed in NDB 2.9", "resolved in ERA 3.0")
   - Commit hashes, CR numbers, Gerrit IDs (e.g., "CR-48293", "Gerrit 112345")
   - Cherry-pick references

5. SELF-REFERENCES: Any result that references ticket %s.
   - In arrays: remove the entire entry containing %s
   - In text: replace the reference with [REDACTED FOR EVALUATION]

6. RESOLUTION-NAMED FIELDS: If a JSON field NAME is inherently resolution-related, replace its ENTIRE value:
   root_cause, Root Cause Analysis, preliminary_analysis, resolution, workaround, remediation, fix_version, corrective_action, relief_provided, post_jira_closure

== WHAT TO PRESERVE (do NOT touch these) ==

- Symptom descriptions and failure observations
- Error messages, exceptions, stack traces, log lines (exact text)
- Environment details: software versions, cluster config, node counts
- Diagnostic observations: what was checked and what was SEEN
- Timeline events and timestamps
- Component names, service names, file paths, function names
- Network details: IP addresses, hostnames, VLANs, ports
- Diagnostic command outputs and their raw results
- Reproduction steps and conditions
- Severity, priority, SLA information
- Customer environment details
- Log bundle references and Diamond sharepath locations

== RULES ==

1. Replace each redacted section with exactly: [REDACTED FOR EVALUATION]
2. Preserve the EXACT format of the input.  If JSON, output valid JSON with identical keys and nesting.  If plain text, output plain text.
3. Do NOT summarize, paraphrase, reorder, or add to any preserved content.
4. When UNCERTAIN whether content is a diagnostic observation or a resolution statement, REDACT it.  Over-filtering is acceptable; data leakage is not.

== INPUT ==

%s`
