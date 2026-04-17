// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// llmClient is the narrow contract the pipeline uses to reach the
// LLM. Expressed as an interface so tests can substitute a fake
// without constructing a real HTTP server. Implementations MUST be
// safe for concurrent use; the production implementation (httpLLMClient)
// satisfies this trivially because net/http.Client is concurrency-safe.
type llmClient interface {
	// Complete sends a single-turn prompt and returns the
	// assistant message's content. It MUST respect ctx.Done().
	// Returning an error causes the caller to fall back to
	// [filterUnavailableText] — the safe-redaction path.
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}

// httpLLMClient calls an OpenAI-compatible /chat/completions
// endpoint. The implementation intentionally stays close to PR 95's
// call_llm: POST JSON, non-streaming, temperature from config, read
// content from choices[0].message.content (with a reasoning_content
// fallback for hack-reason).
type httpLLMClient struct {
	cfg    Config
	client *http.Client
}

// newHTTPLLMClient constructs the production client. It builds a
// single http.Client with the timeout and TLS config baked in so each
// call shares connection pooling — the policy may be invoked at QPS
// comparable to the gateway's backend traffic. Takes cfg by pointer
// to avoid copying the 144-byte Config on the hot path.
func newHTTPLLMClient(cfg *Config) *httpLLMClient {
	tr := &http.Transport{
		// MaxIdleConns and IdleConnTimeout defaults match
		// net/http's; we don't tune them further here. The
		// LLM endpoint is typically fronted by an L7 LB so
		// per-host pooling is what matters.
		TLSClientConfig: &tls.Config{
			// PR 95 sets InsecureSkipVerify unconditionally.
			// We expose it as config so the same binary can
			// talk to public endpoints with verification on.
			InsecureSkipVerify: cfg.InsecureSkipTLSVerify, //nolint:gosec // configurable for internal self-signed endpoints
			MinVersion:         tls.VersionTLS12,
		},
	}
	return &httpLLMClient{
		cfg: *cfg,
		client: &http.Client{
			Transport: tr,
			Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
		},
	}
}

// Complete issues the chat/completions request. The returned string
// is the raw content field from the first choice — it is NOT
// stripped of <think> blocks or markdown fences; that is the
// pipeline's job via [extractFilteredText], which keeps this client
// free of model-specific formatting knowledge.
func (c *httpLLMClient) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	apiKey := c.cfg.resolveAPIKey()
	if apiKey == "" {
		return "", fmt.Errorf("LLM API key not found (env %s / file %s)",
			c.cfg.APIKeyEnv, c.cfg.APIKeyFile)
	}

	payload := chatCompletionsRequest{
		Model: c.cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Stream:      false,
		Temperature: c.cfg.Temperature,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal chat payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build chat request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", c.cfg.Endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the response read to protect against a misbehaving
	// endpoint streaming unbounded bytes. 8 MiB is generous:
	// chat completions for redacted tool outputs are O(KB).
	const maxResp = 8 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResp))
	if err != nil {
		return "", fmt.Errorf("read chat response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("chat %s returned HTTP %d: %s",
			c.cfg.Endpoint, resp.StatusCode, truncateForError(raw))
	}

	var decoded chatCompletionsResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", fmt.Errorf("decode chat response: %w", err)
	}
	if len(decoded.Choices) == 0 {
		return "", fmt.Errorf("chat response had no choices")
	}
	msg := decoded.Choices[0].Message
	// Prefer content; fall back to reasoning_content which
	// hack-reason emits when the whole response is reasoning.
	if strings.TrimSpace(msg.Content) != "" {
		return msg.Content, nil
	}
	if strings.TrimSpace(msg.ReasoningContent) != "" {
		return msg.ReasoningContent, nil
	}
	return "", fmt.Errorf("chat response message had empty content")
}

// truncateForError shortens a byte blob for inclusion in error
// messages. Keeps the first 512 bytes — enough to see which error
// the LLM endpoint returned without flooding logs.
func truncateForError(raw []byte) string {
	const maxLen = 512
	if len(raw) <= maxLen {
		return string(raw)
	}
	return string(raw[:maxLen]) + "...(truncated)"
}

// chatCompletionsRequest mirrors the subset of the OpenAI
// chat/completions schema the policy uses. It is intentionally
// minimal: the policy does not use tools, response_format,
// function_call, or streaming, so we don't expose those knobs.
type chatCompletionsRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Stream      bool          `json:"stream"`
	Temperature float64       `json:"temperature"`
}

// chatMessage is a single message in a chat completion. Only role
// "system" and "user" are sent by this policy; "assistant" appears
// only in the response decode.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	// ReasoningContent is the hack-reason extension that carries
	// the model's chain-of-thought in a dedicated field. Included
	// in the response decode only; never sent in requests.
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

// chatCompletionsResponse captures the fields the policy reads.
// Unknown fields are ignored by encoding/json so the struct stays
// stable across provider-side additions.
type chatCompletionsResponse struct {
	Choices []chatChoice `json:"choices"`
}

// chatChoice is one element of the choices array. The policy only
// consumes the first choice (n=1 is the default request shape).
type chatChoice struct {
	Message chatMessage `json:"message"`
}
