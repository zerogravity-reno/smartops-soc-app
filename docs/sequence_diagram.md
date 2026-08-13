# SmartOps SOC Execution Sequence Diagram

This document presents the complete sequence and data flow diagram for **SmartOps SOC App**, tracking the step-by-step lifecycle from analyst task handover to subagent planning, guardrail policy verification, tool execution, findings projection, and report assembly.

---

## 🔄 End-to-End Execution Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Analyst Agent
    participant Broker as Task Broker (broker.py)
    participant Subagent as Domain Subagent
    participant Guard as IndexScopeGuard
    participant Registry as Tool Registry
    participant Tool as MCP / Native Tool
    participant Projector as Findings Projector

    %% 1. Handover & Planning
    Analyst->>Broker: run_task(AnalystTask)
    Note over Broker: Parse Goal & Scope<br/>(Entities & Time Window)
    Broker->>Broker: Plan Subtasks & Generate TaskClassification

    %% 2. Subagent Mission Dispatch
    Broker->>Subagent: Dispatch SubagentMission (siem, vt)
    Subagent->>Registry: tools_for(family)
    Registry-->>Subagent: Toolset (Splunk MCP Client / VT API)

    %% 3. Bounded Execution Loop & Guardrails
    loop Execution Loop (Max 5 Turns)
        Subagent->>Guard: BeforeToolCallEvent Hook (Inspect Query)
        alt Invalid SPL (index=* or Missing CIM Predicate)
            Guard-->>Subagent: Cancel Tool Call & Return Correction Error
        else Valid SPL Query or Reputation Lookup
            Guard-->>Subagent: Policy Approval Granted
            Subagent->>Tool: Execute Tool Call
            Tool-->>Subagent: Return Raw Telemetry / Reputation (Evidence)
        end
    end

    %% 4. Structured Answer & Code Projection
    Subagent->>Subagent: Author SubagentAnswer (Forced LLM Output)
    Subagent->>Projector: project_vt() / project_siem()
    Projector-->>Subagent: Structured Findings (VtFindings / SiemFindings)
    Subagent->>Subagent: Assemble SubtaskResult (Answer + Evidence + Findings)

    %% 5. Handover Return
    Subagent-->>Broker: SubtaskResult
    Broker-->>Analyst: BrokerReport / TaskClassification
```

---

## 📋 Sequence Flow Breakdown

1. **Analyst Handover**: The Lead Analyst Agent invokes `run_task(AnalystTask)` providing tool-agnostic goals and scope boundaries (`entities`, `time_window`).
2. **Broker Classification**: Task Broker Agent parses the handover, evaluates preconditions, and dispatches subtasks (`SubagentMission`).
3. **Tool Resolution**: `tools_for(family)` resolves active MCP clients (Splunk MCP Server) and native `@tool` functions (VirusTotal REST API).
4. **Guardrail Enforcement**: `IndexScopeGuard` intercepts queries via `BeforeToolCallEvent`. SPL searches must target explicit indexes (`index=botsv3`) or standard Splunk CIM predicates (`sourcetype`, `datamodel`, `tag`, `eventtype`). Unconstrained `index=*` queries are cancelled with self-correction feedback.
5. **Findings Projection**: Domain subagents author forced `SubagentAnswer` output. Code wraps the answer with raw `Evidence` and projected `VtFindings` (`project_vt()`) or `SiemFindings` into `SubtaskResult`.
6. **Final Report Assembly**: Subtask results return to the Task Broker to compile the unified `BrokerReport`.
