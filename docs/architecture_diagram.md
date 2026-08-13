# SmartOps SOC Architecture Specification & Diagrams

![SmartOps SOC App Professional Architecture Diagram](C:\Users\pcc\.gemini\antigravity\brain\109e74bd-fb0a-4564-9950-1f29e538c828\smartops_clean_architecture_1786631543678.jpg)

This document provides a clean, executive-ready technical specification and architectural diagrams for **SmartOps SOC App**, detailing the multi-agent topology, data contract pipeline, security guardrails, and tool integration interfaces.

---

## 🏛️ System Architecture Flow

```mermaid
flowchart LR
    %% Professional Styling Classes
    classDef inputStyle fill:#1e293b,stroke:#475569,stroke-width:1.5px,color:#f8fafc;
    classDef brokerStyle fill:#0f172a,stroke:#3b82f6,stroke-width:2px,color:#f8fafc;
    classDef subagentStyle fill:#0f172a,stroke:#8b5cf6,stroke-width:2px,color:#f8fafc;
    classDef guardStyle fill:#0f172a,stroke:#ef4444,stroke-width:2px,color:#f8fafc;
    classDef toolStyle fill:#0f172a,stroke:#10b981,stroke-width:2px,color:#f8fafc;
    classDef contractStyle fill:#0f172a,stroke:#f59e0b,stroke-width:2px,color:#f8fafc;

    subgraph Analyst ["1. Analyst Ingestion Layer"]
        AT["AnalystTask"]:::inputStyle
        Scope["Scope Boundary<br/>(Entities & Time Window)"]:::inputStyle
        AT --> Scope
    end

    subgraph Orchestration ["2. Task Broker Agent"]
        Broker["Task Broker Agent<br/>(strands.Agent)"]:::brokerStyle
        Planner["Subtask Planner"]:::brokerStyle
        Classify["TaskClassification<br/>(tool_families, rationale)"]:::brokerStyle
        Broker --> Planner --> Classify
    end

    subgraph Safety ["3. Guardrails & Policy Hooks"]
        IndexGuard["IndexScopeGuard<br/>(BeforeToolCallEvent Hook)"]:::guardStyle
        Escaper["Prompt Escaper & Fencing"]:::guardStyle
    end

    subgraph Subagents ["4. Domain Specialist Subagents"]
        SiemAgent["SIEM Subagent<br/>(Splunk Telemetry)"]:::subagentStyle
        VtAgent["VirusTotal Subagent<br/>(Threat Intel)"]:::subagentStyle
        EdrAgent["EDR Subagent"]:::subagentStyle
        NdrAgent["NDR Subagent"]:::subagentStyle
        Collector["_EvidenceCollector<br/>(AfterToolCallEvent Hook)"]:::subagentStyle

        SiemAgent --- Collector
        VtAgent --- Collector
    end

    subgraph Integrations ["5. Tool Integrations"]
        Registry["Tool Registry<br/>(smartops.tools.registry)"]:::toolStyle
        SplunkMCP["Splunk MCP Server"]:::toolStyle
        VTAPI["VirusTotal API"]:::toolStyle

        Registry --> SplunkMCP
        Registry --> VTAPI
    end

    subgraph Contracts ["6. Contracts & Findings"]
        Mission["SubagentMission"]:::contractStyle
        Answer["SubagentAnswer<br/>(Forced LLM Output)"]:::contractStyle
        Result["SubtaskResult<br/>(Answer + Evidence + Findings)"]:::contractStyle
        Projector["Findings Projector<br/>(project_vt & project_siem)"]:::contractStyle

        Answer --> Result
        Projector --> Result
    end

    %% Key Flow Connections
    Analyst -->|1. Handover Task| Broker
    Classify -->|2. Mint Missions| Mission
    Mission -->|3. Dispatch| Subagents
    Subagents -->|4. Resolve Tools| Registry
    SiemAgent -->|5. Validate SPL Query| IndexGuard
    SiemAgent -->|6. Execute SPL| SplunkMCP
    VtAgent -->|6. Lookup Observable| VTAPI
    Subagents -->|7. Author Structured Output| Answer
    Result -->|8. Report Summary| Broker
```

---

## 🔄 Interaction Sequence & Execution Flow

```mermaid
sequenceDiagram
    autonumber
    participant Analyst as Analyst Agent
    participant Broker as Task Broker (broker.py)
    participant Subagent as SIEM / VT Subagent
    participant Guard as IndexScopeGuard
    participant Tool as MCP / Native Tool

    Analyst->>Broker: run_task(AnalystTask)
    Broker->>Broker: Plan & Classify (TaskClassification)
    Broker->>Subagent: Dispatch SubagentMission (siem, vt)

    loop Bounded Execution Loop (Max 5 Turns)
        Subagent->>Guard: BeforeToolCallEvent (Check SPL / Query)
        alt Unconstrained Query (index=* or Missing CIM Predicate)
            Guard-->>Subagent: Rejection Error (Self-Correction Prompt)
        else Valid CIM Query (sourcetype=stream:dns) or Allowed Index
            Guard-->>Subagent: Pass
            Subagent->>Tool: Execute Tool Call
            Tool-->>Subagent: Raw Tool Output (Evidence)
        end
    end

    Subagent->>Subagent: Author SubagentAnswer (Structured LLM Output)
    Subagent->>Subagent: Code-Assemble SubtaskResult (Answer + Raw Evidence + Projected Findings)
    Subagent-->>Broker: SubtaskResult

    Broker-->>Analyst: TaskClassification / BrokerReport
```

---

## 🧱 Component Architecture Reference

| Layer | Primary Module | Responsibility & Key Mechanisms |
|---|---|---|
| **Analyst Ingestion** | `smartops.contracts` | Receives tool-agnostic `AnalystTask` (`goal`, `scope`). Enforces domain dispatch preconditions in code. |
| **Task Broker Agent** | `smartops.broker` | Orchestrates investigation using Agents-as-Tools pattern. Generates `TaskClassification`. |
| **Guardrails & Policies** | `smartops.guards` | `IndexScopeGuard` inspects SPL via `BeforeToolCallEvent`. Allows Splunk CIM predicates (`sourcetype`, `datamodel`, `tag`, `eventtype`) while blocking `index=*`. |
| **Domain Subagents** | `smartops.subagents` | Isolated execution contexts capped at 5 turns (`DEFAULT_TURNS = 5`). Collects raw evidence using `_EvidenceCollector` (`HookOrder.SDK_FIRST`). |
| **Tool Registry** | `smartops.tools.registry` | `tools_for(family)` dynamically resolves native `@tool` functions and MCP server clients (`mcp_servers.json`). |
| **Contracts & Projection** | `smartops.projection` | Assembles `SubtaskResult` by wrapping `SubagentAnswer` with code-projected `VtFindings` (`project_vt()`) and `SiemFindings`. |
