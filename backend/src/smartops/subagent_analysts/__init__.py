"""Subagent-analysts: the analysis layer above the Task Broker.

Three domain analysts -- identity, network, endpoint -- each read their slice of
the broker's fetched evidence and report what it shows, using the
Bedrock-imported reasoning model (Foundation-Sec-8B-Reasoning). Distinct from the
*fetch* subagents in `smartops.subagents`, which retrieve evidence and draw no
conclusions.

They are **blind**: no analyst is shown the hypothesis, so each reports a
`Disposition` on its evidence (benign/suspicious/malicious/inconclusive) rather
than a position on a claim. Whether the evidence supports or refutes the
hypothesis is decided by the Analyst Agent, above the `HypothesisFindings`
contract this package produces.

Layout, live path first:
- `routing`    -- split a `BrokerReport` into per-domain evidence slices
- `formatting` -- project each record type into compact, token-lean lines
- `packing`    -- fit a slice's evidence into the model's context budget
- `prompts`    -- the blind domain system prompts + the fenced user turn
- `model`      -- the boto3 `invoke_model` client and prompt template
- `parse`      -- split reasoning from the answer block and parse the finding
- `analyze`    -- **the production entry point.** `gather()` runs the three
                  analysts and assembles `HypothesisFindings`
- `shown`      -- the hypothesis-SHOWN arm, kept runnable for one caller:
                  `smartops.blind_compare`, the A/B harness that measures
                  whether seeing the hypothesis anchors the read. Not in the
                  pipeline; read `analyze` to understand what production does
"""

from __future__ import annotations
