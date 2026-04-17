// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package contentfilter

import "context"

// contextWithTimeout is a thin seam around context.WithTimeout so
// tests can stub out deadlines without replacing the whole server.
// Keeping the function at package scope (rather than as a field on
// Server) means tests that care about deadlines swap it via a
// build-tagged file or a var reassignment, not by constructing new
// Server instances.
var contextWithTimeout = context.WithTimeout
