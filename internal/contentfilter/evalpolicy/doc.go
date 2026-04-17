// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Package evalpolicy implements the "eval" content-filter strategy:
// an LLM-powered semantic redactor that strips resolution, root-cause,
// and fix-version content from MCP tool outputs before they reach an
// agent under evaluation.
//
// This is a faithful Go port of the Python postToolUse hook from
// panacea-agent PR 95 (feat/evaluation-mode-anti-leakage,
// services/cursor-cli-agent/hooks/eval-filter-hook.py), moved out of
// the agent layer and into the ai-gateway so the anti-leakage
// guarantee is transport-agnostic and applies to every MCP client that
// routes through the gateway.
//
// # Design
//
// The policy runs one single-turn LLM call per response. The prompt
// (see [systemPrompt] and [userPromptTemplate]) is engineered to
// redact with high recall: when the LLM cannot classify a sentence
// confidently it MUST err on the side of redaction. If the LLM call
// fails entirely, the policy falls back to [filterUnavailableText],
// replacing the whole tool output rather than leaking any part of it.
//
// # Scope
//
// The PR 95 hook only ran on postToolUse, never on preToolUse: tool
// arguments do not carry resolution data, so filtering them adds
// latency without benefit. This port preserves that asymmetry —
// Request-scope invocations return [wire.ActionPass] unchanged, and
// only Response-scope invocations hit the LLM.
//
// # Filter gating
//
// The per-tool allowlist from PR 95 (filtered_tools) is preserved
// verbatim in [Config.FilteredTools]. Tools not in the list short-
// circuit to [wire.ActionPass]. This keeps the per-request cost
// predictable: operators know exactly which tools trigger a paid LLM
// call.
//
// # Ticket context
//
// The Python hook reads EVAL_EXCLUDE_TICKET_ID from its environment.
// This port exposes the same mechanism via [Config.EvalTicketID], and
// additionally honours the forwarded header named by
// [Config.TicketHeader] (default X-Eval-Ticket-Id) so a single
// deployment can serve multiple concurrent evaluations.
package evalpolicy
