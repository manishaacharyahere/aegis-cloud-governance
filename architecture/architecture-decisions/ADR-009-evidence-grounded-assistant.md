# ADR-009: The investigation assistant has no tools; Aegis collects evidence and validates every model claim

- **Status:** accepted
- **Date:** 2026-11-16

## Context
Module G explains findings in plain language. A language model can make up
resource IDs, numbers and conclusions. It can also follow instructions hidden in
imported data (tag values, names, messages are attacker-controllable), and it
must never be the authority for a security decision. Aegis must work fully
without it, and must not require a paid or remote API.

## Options considered
1. **Agent with read-only tools.** The model chooses which queries to run. This is
   flexible, but the model decides what evidence exists. A prompt injection
   can steer which data is read. Behaviour is hard to test.
2. **Retrieval plus a free-text answer.** This is simple, but the claims cannot be checked.
3. **Deterministic evidence plus validated, cited claims.** Aegis gathers a
   fixed evidence bundle in a read-only, tenant-scoped transaction and writes a
   cited brief itself. A model, if one is configured, may only return JSON
   claims that cite evidence IDs. Each claim is checked mechanically, and claims that fail are
   rejected and kept for review.

## Decision
Option 3. The model gets no tools, no database access and no network access
from Aegis. It receives only the evidence JSON. Only an Ollama endpoint on
loopback or a single-label host is allowed, unless `AEGIS_AI_ALLOW_REMOTE=true`.
Redirects are not followed.

## Trade-offs and consequences
- The deterministic brief is always present, so a model outage or a bad answer
  changes nothing important. Investigations are reproducible from the stored
  evidence and its SHA-256.
- The validator checks tokens, not meaning. It catches missing or invented
  citations, numbers, identifiers and dates, and command or action text. It
  cannot catch a sentence that reverses the evidence while reusing its tokens
  ("is not public"). This limitation is measured in the corpus and stated in the module docs.
- Questions that need data outside the per-resource bundle cannot be answered.
  The model is told to say so. Wider scopes (team, control, account) are
  future work, and each will get its own deterministic collector.
