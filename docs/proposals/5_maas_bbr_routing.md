---
issue: https://github.com/opendatahub-io/praxis-extproc/issues/5
discussion: https://github.com/opendatahub-io/praxis-extproc/issues/5
status: proposed
authors:
  - yehuditkerido
---

# MaaS BBR Routing and Trusted-Header Boundary

## What?

Implement the routing logic that turns an authorized MaaS
model request into concrete Envoy routing decisions: route,
authority/host, path, effective model, and header mutations. Establish a trust boundary that prevents
consumer-supplied headers from influencing routing or
bypassing authorization.

### Goals

- Extract the requested model from inference request bodies
  (JSON `model` field).
- Resolve the model to an authorized provider from a trusted
  state snapshot.
- Return routing mutations that Envoy needs: route,
  authority, path, effective model, headers, and `clear_route_cache`.
- Capture or remove consumer-supplied internal MaaS headers
  and provider authentication headers before applying
  trusted replacements.
- Define deterministic failure behavior for missing models,
  unavailable providers, conflicting mutations, and deleted state.
- Preserve the authorization result across processing stages
  without allowing consumer override.

## Why?

### Motivation

MaaS allows users to request AI models through a unified
API. The platform must route each request to the correct
provider (OpenAI, Anthropic, internal KServe, etc.) based
on the requested model and the user's entitlements.

Today, `praxis-extproc` can run filter pipelines and return
header mutations, but it lacks:

1. **Trust boundary enforcement**: A consumer can send
   internal headers (`X-MaaS-Provider`, `X-MaaS-Route`) and
   potentially influence routing decisions.

2. **Model-to-provider resolution**: No mechanism to look up
   which provider serves a given model or whether the caller
   is authorized to use it.

3. **Route cache invalidation**: When routing inputs change
   (authority, path), Envoy must recalculate the route. The
   current code does not set `clear_route_cache`.

4. **Credential isolation**: Consumer credentials (OpenShift
   tokens, MaaS API keys) must not reach model backends.
   Provider credentials must come from trusted secrets, not
   consumer-supplied headers.

Without these, MaaS cannot safely route inference requests.

### User Stories

- As a **platform operator**, I want consumers to be unable
  to bypass model authorization by forging internal headers,
  so that access control is enforced.

- As a **consumer**, I want my request to route to the
  correct provider based on the model I specify, without
  needing to know provider details.

- As a **security auditor**, I want consumer credentials
  stripped before reaching backends, so that tokens cannot
  be exfiltrated by compromised models.

- As a **platform operator**, I want routing failures
  (missing model, unavailable provider) to return stable
  error responses rather than falling through to undefined
  behavior.

## How?

> **Note:** This section will be added in a follow-up PR
> after the proposal direction is accepted.
