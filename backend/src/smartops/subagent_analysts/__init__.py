"""Subagent-analysts: the analysis layer above the Task Broker.

Three domain analysts -- identity, network, endpoint -- each read the hypothesis
and their slice of the broker's fetched evidence and decide whether it supports
or refutes the hypothesis, using the Bedrock-imported reasoning model
(Foundation-Sec-8B-Reasoning). Distinct from the *fetch* subagents in
`smartops.subagents`, which retrieve evidence and draw no conclusions.

Layout:
- `routing`    -- split a `BrokerReport` into per-domain evidence slices
- `formatting` -- project each record type into compact, token-lean lines
- `packing`    -- fit a slice's evidence into the model's context budget
- `prompts`    -- domain system prompts + the fenced, escaped user turn
- `model`      -- the boto3 `invoke_model` client and prompt template
- `parse`      -- split reasoning from the verdict and parse it
- `analyze`    -- run the three analysts; `gather` assembles their findings
                 into `HypothesisFindings` (the live path), while `analyze` +
                 `combine` roll verdicts into a `HypothesisAssessment` on the
                 hypothesis-shown path that production no longer calls
"""

from __future__ import annotations
