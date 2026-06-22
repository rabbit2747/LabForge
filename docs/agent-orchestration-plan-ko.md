# LabForge LLM / Agent Orchestration 계획

## 1. 결론

LabForge에서 LLM은 후반부 보조 기능이 아니라 시나리오 제작 파이프라인의 핵심 설계 계층으로 다룬다.

단일 LLM이 모든 일을 처리하지 않는다. 구조는 다음과 같다.

```text
Human Supervisor
-> Orchestrator LLM
-> Specialist Agents
-> LabForge Core
-> Provider
-> Runtime Infrastructure
```

LLM은 설계, 검토, 변환, 품질검수에 사용한다.
실제 Docker 실행, VM 생성, reset, snapshot, firewall 적용은 결정론적인 LabForge provider가 수행한다.

## 2. 역할 분리

| 역할 | 책임 |
|---|---|
| Human Supervisor | 최종 목표, 난이도, 안전 기준, 승인 결정 |
| Orchestrator LLM | agent 작업 분배, 충돌 해결, 결과 병합, 승인 대기 |
| Specialist Agents | 시나리오, MITRE, 인프라, 보안장치, provider, 서비스, 문서, QA, 안전성 검토 |
| LabForge Core | 스펙 검증, schema export, doctor, plan, build |
| Provider | Docker, Hybrid, Ludus, Ansible, Terraform 산출물 생성과 실행 |

## 3. 기본 Agent 목록

| Agent | 목적 |
|---|---|
| scenario-designer | 사건 모티브를 교육용 stage 흐름으로 변환 |
| mitre-mapper | 각 stage를 ATT&CK Enterprise tactic/technique에 매핑 |
| infrastructure-architect | 네트워크, 서비스, 신뢰 경계, 배포 요구사항 설계 |
| security-controls | WAF, IDS, SIEM, EDR, firewall 배치와 telemetry 설계 |
| provider-engineer | 승인된 설계를 provider 산출물로 변환 |
| service-builder | 취약 서비스, seed/noise 데이터, healthcheck 설계 |
| content-guide | 학생용/강사용/감독자용 문서 작성 |
| qa-playtester | 풀이 가능성, 막힘, magic string, CTF스러움 검토 |
| safety-reviewer | 격리, 외부 egress, 위험 행위, reset 안전성 검토 |

## 4. 수정된 전체 개발 Phase

### Phase 1. Core Spec / Validation

- `scenario.yaml`, `topology.yaml`, `stages.yaml`
- v0.2 선택 파일
- pydantic 검증
- JSON Schema export

### Phase 2. Runtime Awareness

- `labforge doctor`
- `labforge plan`
- Windows / WSL / Docker / VM / Hybrid 판단

### Phase 3. Agent Orchestration Foundation

- agent role 정의
- orchestration manifest
- dry-run task scaffold
- agent output placeholder
- supervisor decision records

현재 구현 명령:

```powershell
python -m labforge agents list
python -m labforge agents scaffold examples/scenario-02-ad-domain-compromise --out output/scenario-02-agents
python -m labforge agents validate output/scenario-02-agents
```

### Phase 3.1. Agent System Prompt Scaffold

`agents scaffold`는 이제 dry-run task뿐 아니라 실제 LLM adapter가 사용할 수 있는 system prompt와 task prompt scaffold도 생성한다.

```text
output/<lab>/
`-- .ai/
    |-- prompts/
    |   |-- orchestrator.system.md
    |   |-- 01-scenario-designer.system.md
    |   |-- 02-mitre-mapper.system.md
    |   |-- 03-infrastructure-architect.system.md
    |   |-- 04-security-controls.system.md
    |   |-- 05-provider-engineer.system.md
    |   |-- 06-service-builder.system.md
    |   |-- 07-content-guide.system.md
    |   |-- 08-qa-playtester.system.md
    |   |-- 09-safety-reviewer.system.md
    |   `-- tasks/
    |       |-- 01-scenario-designer.task.md
    |       |-- 02-mitre-mapper.task.md
    |       `-- ...
```

각 system prompt는 다음 section을 반드시 가진다.

- `Role`
- `Mission`
- `Inputs`
- `Outputs`
- `Guardrails`
- `Validation Checklist`

각 task prompt는 다음 section을 반드시 가진다.

- `Task`
- `Context Files`
- `Inputs`
- `Expected Outputs`
- `Guardrails`
- `Output Contract`
- `Done Criteria`

이 구조는 OpenAI, Claude CLI, MCP adapter 중 어떤 runtime을 연결하더라도 agent 역할, 작업 지시, 출력 계약이 흔들리지 않게 하기 위한 것이다.

### Phase 4. Provider Execution Layer

- Docker Compose start/stop/reset script
- Hybrid/Ludus/Ansible/Terraform provider 고도화
- 보안장치 선택값을 실제 provider 산출물에 반영

### Phase 5. Service Artifact Standard

- `attack-surface.yaml`
- `seed/`
- `noise/`
- `reset/`
- `healthcheck`
- 학생용 힌트와 강사용 answer key 분리

### Phase 6. LLM Adapter

- OpenAI / Claude CLI / MCP adapter
- dry-run task를 실제 LLM 작업으로 실행
- agent output schema 검증
- supervisor 승인 gate

### Phase 7. Scenario Production

- scenario 02-10을 LabForge YAML로 변환
- agent-assisted 검토
- QA playtest loop

### Phase 8. Orion Echo Rebuild Verification

- 기존 Orion Echo 산출물을 그대로 복제하지 않는다.
- Orion Echo 시나리오와 학습 목표를 LabForge 방식으로 재제작한다.
- 실습 체인이 정확히 동작하면 성공으로 본다.

## 5. Dry-run Agent Workspace

`agents scaffold`는 LLM을 호출하지 않고 다음 구조를 만든다.

```text
output/<lab>/
`-- .ai/
    |-- README.md
    |-- orchestration-plan.yaml
    |-- tasks/
    |   |-- 01-scenario-designer.yaml
    |   |-- 02-mitre-mapper.yaml
    |   `-- ...
    |-- outputs/
    |   |-- 01-scenario-designer.result.yaml
    |   |-- 02-mitre-mapper.result.yaml
    |   `-- ...
    `-- decisions/
        |-- accepted.yaml
        |-- rejected.yaml
        `-- open-questions.yaml
```

이 구조가 먼저 필요한 이유:

- LLM이 없어도 작업 분해를 검토할 수 있다.
- 각 agent의 입력과 출력 계약을 고정할 수 있다.
- 나중에 OpenAI, Claude CLI, MCP 중 어떤 runtime을 붙여도 artifact 구조가 흔들리지 않는다.
- supervisor가 agent 결과를 승인하기 전에는 LabForge core가 자동으로 반영하지 않게 만들 수 있다.

## 5.1 Agent Artifact 검증

Agent workspace는 다음 pydantic schema로 검증한다.

| Schema | 대상 |
|---|---|
| `orchestration-plan.schema.json` | `.ai/orchestration-plan.yaml` |
| `agent-task.schema.json` | `.ai/tasks/*.yaml` |
| `agent-result.schema.json` | `.ai/outputs/*.result.yaml` |
| `agent-decision-log.schema.json` | `.ai/decisions/*.yaml` |

검증 명령:

```powershell
python -m labforge agents validate output/scenario-02-agents
```

검증 원칙:

- 모든 task는 알려진 agent ID를 사용해야 한다.
- 모든 task는 대응되는 output file을 가져야 한다.
- 모든 result는 존재하는 task ID를 참조해야 한다.
- decision log는 `items` 배열을 가져야 한다.
- LLM adapter가 생성한 결과도 이 검증을 통과해야 다음 단계로 이동할 수 있다.

## 6. 운영 원칙

1. LLM은 제안하고, LabForge core는 검증한다.
2. Provider 실행은 LLM이 아니라 결정론적 코드가 수행한다.
3. Agent output은 중간 산출물이며 supervisor 승인 전에는 source of truth가 아니다.
4. 실제 취약 행위는 lab-scoped artifact와 provider 안전장치 안에서만 허용한다.
5. QA agent는 학생용 정보만 보고 playtest하는 모드와 강사용 answer key를 보는 검수 모드를 분리해야 한다.
