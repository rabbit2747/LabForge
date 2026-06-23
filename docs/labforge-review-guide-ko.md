# LabForge 검토용 설명서

## 1. LabForge란 무엇인가

LabForge는 보안 교육용 hands-on lab을 선언형 파일로 정의하고, 그 정의를 바탕으로 인프라 산출물과 문서를 생성하는 프레임워크다.

현재 목표는 단순히 `docker-compose.yml`을 만드는 도구가 아니다. 최종 목표는 다음과 같다.

```text
시나리오를 입력하면
1. 학습자 공격 흐름
2. MITRE ATT&CK 매핑
3. 보안 미적용 인프라 아키텍처
4. 보안 적용 인프라 아키텍처
5. 감독자가 선택 가능한 보안장치 목록
6. 실제 배포 가능한 IaC / Compose / Ansible / Terraform 산출물
7. 학생용 문서
8. 강사용 문서
9. 감독자용 구성도
를 일관된 형식으로 생성하는 프레임워크
```

즉 LabForge는 실습 문제를 만드는 도구이면서 동시에 보안 실습 인프라 설계 문서 생성기다.

## 2. 왜 필요한가

ROOT14 교육 플랫폼에서는 단순 CTF식 문제보다 실제 기업망에 가까운 red-team 실습 환경이 필요하다.

기존 방식으로는 각 시나리오마다 다음 작업을 수작업으로 반복해야 한다.

- Docker Compose 작성
- 네트워크 분리 설계
- 공격자 워크스테이션 구성
- 취약 서비스 배치
- 내부 서비스 배치
- 학습 단계별 문서 작성
- MITRE ATT&CK 매핑 작성
- 보안장치 적용 여부 문서화
- 감독자용 아키텍처 구성도 작성
- 실습 초기화 및 검증 절차 작성

LabForge는 이 반복 작업을 시나리오 정의 파일 중심으로 표준화하려는 프레임워크다.

## 3. 핵심 설계 원칙

LabForge는 다음 원칙을 따른다.

1. 시나리오와 인프라 구현을 분리한다.

   예를 들어 "Active Directory 침투 시나리오"는 Docker로만 구현하기 어렵다. 따라서 시나리오 파일은 논리적 자산과 흐름을 정의하고, 실제 구현은 Docker, VM, Ansible, Terraform 같은 provider가 담당해야 한다.

2. Docker Compose는 여러 provider 중 하나다.

   Orion Echo 같은 Linux 웹/API 중심 공급망 실습은 Docker Compose로 적합하다. 반면 Active Directory, Windows Event Forwarding, GPO(Group Policy Object), Kerberos, SMB(Server Message Block), RDP(Remote Desktop Protocol) 같은 요소가 필요한 실습은 VM 또는 hybrid provider가 필요하다.

3. 보안장치가 없는 구조와 보안장치가 있는 구조를 모두 다룬다.

   같은 시나리오라도 학습 목적에 따라 방화벽, WAF(Web Application Firewall), IDS(Intrusion Detection System), SIEM(Security Information and Event Management), EDR(Endpoint Detection and Response) 적용 여부가 달라진다.

4. 감독자가 이해하기 쉬운 도식화를 생성한다.

   실습을 운영하는 사람은 전체 인프라, 외부 노출 지점, 내부망, 공격 흐름, 보안장치 배치 위치를 빠르게 파악해야 한다. LabForge는 Mermaid 기반 구성도를 자동 생성한다.

5. 모든 stage는 MITRE ATT&CK Matrix for Enterprise의 tactic과 technique에 매핑되어야 한다.

   이 프레임워크는 단순 문제 제작기가 아니라 MITRE 기반 교육 콘텐츠 제작 도구다.

6. 특정 시나리오 전용 hook으로 프레임워크를 바꾸지 않는다.

   Orion Echo 같은 기존 시나리오는 회귀 검증 입력이나 예시로 사용할 수 있다. 하지만 LabForge core, provider, parser, validator, template, agent workflow에 특정 시나리오 이름을 위한 예외 분기, 숨은 매핑, 고정값, 전용 hook을 넣어서는 안 된다. 어떤 시나리오를 만들다가 프레임워크 개선이 필요해지면, 그 개선은 schema, plugin contract, provider capability, validator rule, agent workflow처럼 다른 시나리오에도 적용 가능한 일반 기능으로 추상화해야 한다.

## 4. 현재 구현 범위

현재 구현된 MVP 기능은 다음과 같다.

- `scenario.yaml`, `topology.yaml`, `stages.yaml` 로딩
- `lab.yaml`, `environment.yaml`, `artifacts.yaml`, `security-controls.yaml`, `supervisor-selection.yaml` 선택적 로딩
- 자연어 입력에서 `prompt-analysis.yaml` / `prompt-analysis.md` 생성
- pydantic v2 기반 v0.2 스펙 검증
- JSON Schema export 명령
- `guard framework-hooks` 명령으로 LabForge core, template, schema에 특정 시나리오 전용 marker가 들어가는지 검사
- host doctor 명령으로 Windows/Linux/macOS/WSL/Docker 실행 환경 진단
- execution plan 명령으로 host 진단, provider, profile, deployment 요구사항을 합친 제작 순서 생성
- 필수 필드 검증
- MITRE ATT&CK Enterprise tactic 검증
- 각 stage의 technique ID/name 존재 여부 검증
- 서비스별 healthcheck 존재 여부 검증
- exposed service 명시 여부 검증
- attacker-workstation 존재 여부 검증
- Docker Compose scaffold 생성
- README 생성
- MITRE mapping report 생성
- implementation checklist 생성
- Jinja2 기반 문서 템플릿 렌더링
- 감독자용 Mermaid architecture diagram 생성
- `unprotected` / `protected` architecture 문서 분리 생성
- supervisor security-control 선택 요약 문서 생성
- 감독자용 deployment requirements 문서 생성
- provider interface 1차 분리
- `docker-compose` provider 실제 생성
- protected profile에서 선택된 보안장치를 Docker Compose control scaffold 서비스로 생성
- Docker Compose 서비스/네트워크에 `labforge.*` 라벨과 SIEM 로그 설정 반영
- Docker Compose provider에서 validate/start/stop/reset PowerShell 및 shell script 생성
- PowerShell runtime script에서 현재 shell Docker가 없으면 Docker server가 보이는 WSL 배포판을 자동 탐지해 위임
- Docker Compose provider에서 `service_artifacts` 계약을 읽어 build context, service labels, provider service plan 문서에 반영
- service artifact 구현 디렉토리 scaffold/check 명령 생성
- service artifact healthcheck/reset hook 실행 명령 생성
- Docker Compose provider가 service source를 generated output에 복사하고 `services-healthcheck/reset` runtime script 생성
- `ansible`, `terraform`, `ludus`, `hybrid` provider skeleton 생성

현재 아직 구현되지 않은 기능은 다음과 같다.

- 실제 취약 서비스 코드 자동 생성
- Ansible provider
- Terraform provider
- Vagrant provider
- Proxmox / VMware provider
- supervisor 선택값을 Ansible/Terraform/Ludus/Hybrid provider 산출물에 실제 방화벽/센서 구성으로 반영
- 감독자 interactive security-control 선택 UI
- reset snapshot 자동화
- 학생용 guide와 강사용 answer key 분리
- PNG/SVG 다이어그램 렌더링

## 5. 현재 디렉토리 구조

```text
<LabForge repository root>
|-- README.md
|-- pyproject.toml
|-- docs/
|   `-- labforge-review-guide-ko.md
|-- labforge/
|   |-- __init__.py
|   |-- __main__.py
|   |-- cli.py
|   |-- diagrams.py
|   |-- io.py
|   |-- model.py
|   |-- render.py
|   `-- validate.py
|-- schemas/
|   |-- scenario.schema.json
|   |-- stages.schema.json
|   `-- topology.schema.json
|-- templates/
|   `-- README.md
`-- examples/
    `-- scenario-02-ad-domain-compromise/
        |-- scenario.yaml
        |-- topology.yaml
        |-- stages.yaml
        |-- artifacts/
        |   `-- README.md
        `-- services/
            `-- README.md
```

## 6. LabForge 입력 파일

현재 MVP에서 하나의 lab은 다음 3개 파일을 필수로 가진다.

```text
scenario-root/
|-- scenario.yaml
|-- topology.yaml
`-- stages.yaml
```

향후에는 아래 파일들이 추가될 예정이다.

```text
scenario-root/
|-- lab.yaml
|-- scenario.yaml
|-- environment.yaml
|-- stages.yaml
|-- mitre.yaml
|-- artifacts.yaml
|-- security-controls.yaml
|-- supervisor-selection.yaml
`-- providers/
    |-- docker-compose.yaml
    |-- ansible.yaml
    `-- terraform.yaml
```

### 6.1 scenario.yaml

`scenario.yaml`은 실습의 정체성을 정의한다.

예시:

```yaml
id: scenario-02-ad-domain-compromise
title: Scenario 02 - Active Directory Domain Compromise
summary: >
  External HR portal compromise leads to Active Directory discovery,
  service account abuse, lateral movement, and final board strategy
  archive collection.
final_objective: >
  Obtain board_strategy_archive_2026.zip from the internal fileserver
  and submit a manifest to controlled-drop.
```

필드 설명:

| 필드 | 의미 |
|---|---|
| `id` | 실습의 고유 ID |
| `title` | 문서와 산출물에 표시될 제목 |
| `summary` | 실습 전체 요약 |
| `final_objective` | 학습자가 최종적으로 달성해야 하는 목표 |

### 6.2 topology.yaml

`topology.yaml`은 네트워크, 서비스, 보안장치 후보, 실제 구축에 필요한 환경 요구사항을 정의한다.

예시:

```yaml
networks:
  - name: public_net
  - name: dmz_net
    internal: true
  - name: corp_net
    internal: true
  - name: drop_net
    internal: true

security_controls:
  recommended:
    - Firewall / Segmentation
    - WAF on HR Portal
    - IDS East-West Sensor
    - Central Log Collection
    - Windows Event Forwarding
    - EDR Lite Process Monitor

deployment:
  recommended_model: hybrid
  docker_only_supported: false
  docker_only_notes: >
    Docker-only mode can model the scenario, but realistic Active Directory
    requires Windows Server domain services.
  minimum_environment:
    description: Single training PC for Docker-only prototype mode.
    hosts:
      - role: training-host
        count: 1
        os: Windows, Linux, or macOS with a Docker-capable runtime
        cpu: 8 cores recommended
        memory: 16 GB minimum, 32 GB recommended
        storage: 80 GB free
        software:
          - Docker Desktop, Docker Engine, or an equivalent Docker-compatible runtime
          - Python 3.11+
          - Git
  realistic_environment:
    description: Proxmox or equivalent hypervisor host for Windows AD realism.
    hosts:
      - role: hypervisor-host
        count: 1
        os: Proxmox VE or VMware/Hyper-V equivalent
        cpu: 12 cores recommended
        memory: 64 GB recommended
        storage: 300 GB SSD free
        software:
          - Proxmox VE
          - Windows Server ISO
          - Windows client ISO
          - Linux attacker image

services:
  - name: attacker-workstation
    role: learner attack workstation
    exposed: true
    networks: [public_net, dmz_net, drop_net]
    ports: ["2222:22"]
    healthcheck:
      test: ["CMD", "sh", "-lc", "test -d /home/attacker"]
      interval: 10s
      timeout: 3s
      retries: 10
```

필드 설명:

| 필드 | 의미 |
|---|---|
| `networks` | 논리 네트워크 구역 |
| `internal: true` | 외부 직접 접근이 불가능한 내부망 표시 |
| `security_controls.recommended` | 감독자가 선택할 수 있는 보안장치 후보 |
| `deployment.recommended_model` | 권장 구축 모델. 예: docker-compose, vm, hybrid |
| `deployment.docker_only_supported` | Docker만으로 현실적인 구축이 가능한지 여부 |
| `deployment.minimum_environment` | 최소 실습 환경 |
| `deployment.realistic_environment` | 실제 기업망 재현에 가까운 권장 환경 |
| `deployment.required_platforms` | 필요한 플랫폼과 도구 |
| `services` | 실습에 등장하는 서비스/서버/자산 |
| `exposed: true` | 학습자가 외부에서 직접 접근 가능한 서비스 |
| `ports` | host에 publish되는 포트 |
| `expose` | 내부 컨테이너 네트워크에만 노출되는 포트 |
| `healthcheck` | 서비스 정상 여부 확인 명령 |

중요 원칙:

- 외부 노출 서비스는 반드시 `exposed: true`로 표시한다.
- 내부 서비스는 기본적으로 직접 노출하지 않는다.
- 학습자용 공격자 환경은 `attacker-workstation`으로 정의한다.
- 보안장치는 현재 문서/다이어그램 생성에 사용되며, 향후 protected profile 생성에 사용된다.
- AD, Windows Server, ICS/OT, VPN appliance처럼 Docker만으로 부족한 실습은 `deployment` 섹션에 VM 또는 hypervisor 요구사항을 명시한다.

### 6.3 stages.yaml

`stages.yaml`은 학습자가 수행할 공격 흐름과 MITRE 매핑을 정의한다.

예시:

```yaml
stages:
  - id: stage-01
    title: External HR portal discovery
    procedure: Observe profile preview requests and confirm server-side rendering behavior.
    mitre:
      tactic: Initial Access
      techniques:
        - id: T1190
          name: Exploit Public-Facing Application
```

필드 설명:

| 필드 | 의미 |
|---|---|
| `id` | stage 고유 ID |
| `title` | stage 이름 |
| `procedure` | 학습자가 해당 단계에서 수행해야 하는 절차 요약 |
| `mitre.tactic` | MITRE ATT&CK Matrix for Enterprise tactic |
| `mitre.techniques` | 해당 단계의 technique ID와 이름 |

현재 validator는 tactic이 Enterprise 14 tactic 중 하나인지 확인한다.

지원되는 tactic:

- Reconnaissance
- Resource Development
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact

## 7. 명령어 사용법

현재 LabForge는 Python module 방식으로 실행할 수 있다.

### 7.1 검증

```powershell
cd <LabForge repository root>
python -m labforge validate examples/scenario-02-ad-domain-compromise
```

성공 시:

```text
Validation passed
```

실패 시:

```text
Validation failed:
- scenario.yaml missing required field: title
- stage stage-03 has invalid MITRE tactic: ...
```

검증 항목:

- 필수 파일 존재 여부
- `scenario.yaml` 필수 필드
- topology network 존재 여부
- services 목록 존재 여부
- `attacker-workstation` 존재 여부
- 외부 노출 서비스 존재 여부
- 각 서비스 healthcheck 존재 여부
- stage별 title/procedure 존재 여부
- stage별 MITRE tactic 유효성
- stage별 technique ID/name 존재 여부

### 7.1.1 로컬 실행 환경 진단

실제 lab 제작을 시작하기 전에 현재 PC가 어떤 방식으로 인프라를 만들 수 있는지 확인해야 한다.

예를 들어 현재 개발 PC처럼 로컬 OS는 Windows이고 Docker는 WSL 환경에서 실행되는 경우가 있다. 이때 LabForge가 Windows PowerShell에서 바로 Docker 명령을 실행하면 실패할 수 있다. 반대로 Linux나 macOS에서는 메인 OS에서 바로 Docker Engine 또는 Docker Desktop을 사용할 수 있다.

이를 위해 `doctor` 명령을 제공한다.

```powershell
python -m labforge doctor --lab examples/scenario-02-ad-domain-compromise
```

확인 항목:

- 현재 OS: Windows, Linux, macOS, WSL Linux
- CPU architecture
- 현재 shell 힌트
- WSL 설치 여부
- WSL 배포판 목록과 WSL version
- host shell에서 Docker CLI가 보이는지
- host shell에서 Docker server에 연결되는지
- WSL 배포판 안에서 Docker CLI/server가 보이는지
- lab의 권장 구축 모델이 Docker-only인지, VM/hybrid/proxmox 계열인지
- 권장 실행 위치: host, wsl, wsl-required

예상 출력 일부:

```text
# LabForge Host Doctor

## Host

- OS: `windows`
- Recommended execution: `wsl-required`

## WSL

- WSL available: `true`

## Next Steps

- Install/enable Docker Desktop WSL integration or Docker Engine inside WSL.
- Check deployment requirements for hypervisor, Windows Server, and VM prerequisites.
```

JSON 출력도 가능하다.

```powershell
python -m labforge doctor --format json
```

이 출력은 나중에 웹 UI, 감독자 콘솔, 자동 배포 오케스트레이터가 읽어서 "이 lab은 이 PC에서 바로 실행 가능", "WSL에서 실행 필요", "Proxmox/Windows Server VM 필요" 같은 판단을 내리는 데 사용할 수 있다.

### 7.1.2 실행 계획 생성

`doctor`가 현재 PC의 상태를 진단한다면, `plan`은 그 진단 결과를 시나리오 설계도와 합쳐 실제 제작 순서를 만든다.

```powershell
python -m labforge plan examples/scenario-02-ad-domain-compromise --provider docker-compose --profile protected
```

파일로 저장하려면 `--out`을 사용한다.

```powershell
python -m labforge plan examples/scenario-02-ad-domain-compromise --out output/scenario-02-plan --provider docker-compose --profile protected
```

생성 결과:

```text
output/scenario-02-plan/
`-- docs/
    |-- execution-plan.md
    `-- execution-plan.json
```

execution plan에 포함되는 정보:

- lab ID와 제목
- provider와 profile
- 권장 deployment model
- Docker-only 지원 여부
- 현재 host OS와 WSL/Docker 상태
- Windows에서 직접 실행할지, WSL 배포판을 통해 실행할지
- scaffold 생성 명령
- 설계 문서 검토 명령
- supervisor gate에서 확인할 항목
- Docker Compose validation/start/reset 명령

예를 들어 Windows host에서 Docker가 직접 보이지 않고 특정 WSL 배포판 안에서만 Docker server가 확인되면, plan은 감지된 배포판 이름을 사용해 `wsl.exe -d <detected-distro> -- bash -lc ...` 형태의 명령을 제안한다. 이때 빠른 검증은 `/mnt/c/...` Windows mount 경로에서 가능하지만, Docker volume이 많아지는 실제 lab 제작에서는 WSL ext4 파일시스템 안에 repo를 clone하거나 sync해서 실행하는 것을 권장한다.

### 7.2 전체 lab scaffold 생성

```powershell
python -m labforge build examples/scenario-02-ad-domain-compromise --out output/scenario-02 --provider docker-compose --profile protected --force
```

생성 결과:

```text
output/scenario-02/
|-- docker-compose.yml
|-- README.md
|-- scripts/
|   |-- README.md
|   |-- reset.ps1
|   |-- reset.sh
|   |-- start.ps1
|   |-- start.sh
|   |-- stop.ps1
|   |-- stop.sh
|   |-- validate.ps1
|   `-- validate.sh
|-- docs/
|   |-- architecture-diagrams.md
|   |-- architecture-protected.md
|   |-- architecture-unprotected.md
|   |-- deployment-requirements.md
|   |-- implementation-checklist.md
|   |-- mitre-mapping.md
|   |-- provider-security-plan.md
|   |-- provider-service-plan.md
|   |-- security-control-selection.md
|   `-- service-artifact-contract.md
`-- diagrams/
    |-- attack-flow.mmd
    |-- security-controls.mmd
    `-- topology.mmd
```

`--force` 옵션:

- validation error가 있어도 산출물을 생성한다.
- 검토 중인 초안 시나리오를 문서화할 때 사용할 수 있다.
- 실제 배포 전에는 `--force` 없이 통과하는 상태가 되어야 한다.

### 7.3 문서만 생성

```powershell
python -m labforge docs examples/scenario-02-ad-domain-compromise --out output/scenario-02-docs --profile protected
```

생성 결과:

```text
output/scenario-02-docs/
|-- README.md
|-- architecture-diagrams.md
|-- architecture-protected.md
|-- architecture-unprotected.md
|-- deployment-requirements.md
|-- implementation-checklist.md
|-- mitre-mapping.md
|-- service-artifact-contract.md
|-- security-control-selection.md
`-- diagrams/
    |-- attack-flow.mmd
    |-- security-controls.mmd
    `-- topology.mmd
```

이 명령은 인프라 파일 없이 검토용 문서만 보고 싶을 때 사용한다.

## 8. 생성되는 문서 설명

### 8.1 README.md

해당 실습의 요약 문서다.

포함 내용:

- Summary
- Final Objective
- Exposed Services
- Stages
- 각 stage의 procedure
- 각 stage의 MITRE tactic/technique

### 8.2 docs/mitre-mapping.md

stage별 MITRE 매핑표다.

포함 내용:

- Stage ID
- Stage title
- Procedure
- MITRE tactic
- MITRE technique ID/name

검토자는 이 문서를 보고 교육 커리큘럼 관점에서 각 단계가 어떤 ATT&CK 행위를 다루는지 확인할 수 있다.

### 8.3 docs/implementation-checklist.md

개발자가 실제 실습 환경을 구현할 때 확인해야 할 체크리스트다.

포함 내용:

- 외부 노출 서비스 명시 여부
- 내부 서비스 직접 노출 방지
- attacker workstation 존재 여부
- reset strategy 필요 여부
- seed/noise data 분리
- 서비스별 healthcheck
- stage별 구현 여부

### 8.4 docs/architecture-diagrams.md

감독자용 도식화 문서다.

현재 3개 Mermaid diagram을 포함한다.

1. Infrastructure Topology

   네트워크 구역, 서비스, 외부 노출 여부, 학습자 연결점을 보여준다.

2. Learner Attack Flow

   Stage 1부터 최종 목표까지 학습자가 진행하는 순서를 보여준다.

3. Protected Architecture Control Overlay

   방화벽, WAF, IDS, 중앙 로그 수집, EDR 같은 보안장치가 어디에 배치될 수 있는지 보여준다.

### 8.5 diagrams/*.mmd

Mermaid 원본 파일이다.

생성 파일:

- `topology.mmd`
- `attack-flow.mmd`
- `security-controls.mmd`

이 파일들은 GitHub, Mermaid Live Editor, VS Code Mermaid extension, Mermaid CLI 등으로 렌더링할 수 있다.

### 8.6 docs/deployment-requirements.md

실제 실습 환경을 구성하기 위해 필요한 물리/가상 환경 요구사항 문서다.

포함 내용:

- 권장 구축 모델
- Docker-only 구성 가능 여부
- Docker prototype mode에서 필요한 PC 사양
- realistic mode에서 필요한 hypervisor, VM, Windows Server, learner PC 요구사항
- Proxmox, VMware, Hyper-V, Ansible, Terraform 같은 필요 도구
- 감독자가 구축 전 확인해야 할 질문 목록

예를 들어 AD 기반 실습은 Docker만으로는 충분하지 않으므로 다음과 같은 요구사항이 문서에 포함되어야 한다.

- Windows Server Domain Controller용 VM
- Windows client 또는 member server VM
- Linux attacker VM 또는 attacker workstation
- Proxmox, VMware, Hyper-V 같은 hypervisor
- 각 VM을 초기화하기 위한 snapshot 기능
- Windows Event Forwarding, Sysmon, Wazuh 같은 보안 로그 구성 가능성

## 9. 보안장치 모델

LabForge는 최종적으로 같은 시나리오에 대해 두 가지 아키텍처를 생성하는 것을 목표로 한다.

### 9.1 Unprotected Architecture

보안장치가 거의 없는 기본 실습 구조다.

목적:

- 공격 흐름 자체를 이해하기 쉽게 만든다.
- 초기 교육 단계에서 실습자의 시행착오를 줄인다.
- 취약점, 내부 이동, 정보 수집, 최종 목표 달성 과정을 직관적으로 보여준다.

예상 문서 내용:

- 외부 노출 서비스
- 내부 서비스
- 의도된 취약점
- 공격 경로
- 네트워크 접근 가능성
- 보안장치가 없을 때 가능한 행동

### 9.2 Protected Architecture

실제 기업망에 더 가까운 보안장치 적용 구조다.

목적:

- 공격이 어떤 보안장치에 탐지될 수 있는지 보여준다.
- 방화벽 정책, IDS 탐지, WAF alert, 로그 수집, EDR 이벤트를 교육에 포함한다.
- Red Team, Blue Team, Purple Team 관점으로 확장할 수 있다.

예상 문서 내용:

- 방화벽 정책
- 허용/차단 트래픽
- IDS 센서 위치
- WAF 적용 위치
- 로그 수집 대상
- EDR 적용 범위
- stage별 탐지 가능성
- 학생에게 보여줄 로그와 강사만 볼 로그의 분리

### 9.3 Supervisor Selection

향후 LabForge는 감독자가 보안장치를 선택할 수 있게 할 예정이다.

예시:

```yaml
selected_controls:
  firewall:
    - fw-basic-segmentation
    - fw-egress-restrict
  waf:
    - waf-support-portal
  ids:
    - ids-east-west
  siem:
    - siem-central-logs
  edr:
    - edr-lite-process-monitor

training_mode:
  mode: red-team
  detection_feedback: instructor_only
  allow_student_log_access: false
```

이 선택값을 기반으로 LabForge는 protected architecture 문서와 최종 provider 산출물을 생성하게 된다.

## 10. Provider 설계 방향

현재 provider는 Docker Compose만 구현되어 있다.

하지만 장기적으로 LabForge는 다음 provider를 지원해야 한다.

| Provider | 목적 |
|---|---|
| `docker-compose` | 웹/API/서비스 중심의 빠른 실습 환경 |
| `ansible` | 이미 존재하는 VM 또는 서버에 서비스와 설정 배포 |
| `terraform` | VM, 네트워크, 보안그룹, 스토리지 같은 인프라 생성 |
| `vagrant` | 로컬 교육장용 VM 기반 실습 구성 |
| `proxmox` | 사내 또는 교육 플랫폼 서버 기반 VM 실습 |
| `hybrid` | Docker와 VM을 함께 사용하는 혼합 실습 |

시나리오별 권장 provider 예:

| 시나리오 유형 | 권장 provider |
|---|---|
| 공급망 공격 | Docker Compose 또는 Hybrid |
| Active Directory 침투 | Terraform + Ansible 또는 Vagrant + Ansible |
| Exchange/Webmail 침투 | Hybrid |
| VPN appliance 침투 | Hybrid |
| Ransomware prepositioning | Windows VM + Ansible |
| ICS/OT 침투 | Docker Compose + OT simulator 또는 Hybrid |

환경 요구사항을 더 넓게 판단하기 위한 별도 카탈로그는 다음 문서를 기준으로 한다.

[`docs/environment-requirements-catalog-ko.md`](environment-requirements-catalog-ko.md)

## 11. 현재 예제 시나리오

현재 포함된 예제는 다음이다.

```text
examples/scenario-02-ad-domain-compromise
```

이 예제는 Active Directory Domain Compromise를 모델링한다.

주의:

- 현재 예제는 아직 실제 AD VM을 생성하지 않는다.
- MVP에서는 AD-like LDAP 서비스로 표현되어 있다.
- 실제 AD 실습으로 발전시키려면 VM/Ansible provider가 필요하다.

예제 stage 요약:

| Stage | 내용 |
|---|---|
| stage-01 | 외부 HR portal discovery |
| stage-02 | HR server foothold |
| stage-03 | credential/config discovery |
| stage-04 | Active Directory discovery |
| stage-05 | Kerberoasting |
| stage-06 | lateral movement |
| stage-07 | backup operator escalation |
| stage-08 | fileserver collection |
| stage-09 | internal staging |
| stage-10 | controlled drop submission |

## 12. 검토자가 확인해야 할 포인트

검토자는 다음 질문을 기준으로 LabForge를 보면 된다.

1. 시나리오 정의와 인프라 정의가 충분히 분리되어 있는가?
2. Docker에만 종속되지 않는 구조로 확장 가능한가?
3. MITRE ATT&CK 기반 교육 콘텐츠 제작에 적합한가?
4. 보안장치가 없는 구조와 보안장치가 있는 구조를 모두 표현할 수 있는가?
5. 감독자가 이해할 수 있는 구성도와 문서가 생성되는가?
6. 향후 Ansible/Terraform/VM provider를 붙일 수 있는가?
7. Orion Echo 같은 기존 Docker lab을 이 구조로 변환할 수 있는가?
8. AD/Windows/ICS처럼 Docker만으로 부족한 실습도 표현 가능한가?

## 13. 현재 한계

현재 LabForge는 설계 방향을 검증하기 위한 초기 MVP다.

한계:

- 모든 취약 서비스를 자동 생성하지는 않는다. 다만 지원 플러그인(`ssti-preview`, `stored-xss-review`, `idor-object-access`, `ssrf-internal-fetch`, `diagnostic-command-injection`, `build-pipeline-abuse`, `signed-update-publish`, `customer-update-callback`)은 `services materialize`로 안전한 Docker MVP runtime과 lab-scoped 취약 동작을 생성하고 실행 검증할 수 있다.
- Docker Compose 외 provider는 실제 인프라 배포를 수행하지 않는다. 다만 Ansible/Terraform/Ludus/Hybrid provider는 provider plan, inventory, security profile, starter file을 생성한다.
- protected/unprotected profile은 문서, Docker Compose scaffold/runtime script, provider skeleton 산출물에 반영된다. 실제 WAF/IDS/SIEM/EDR 엔진 구성과 enforcement logic은 아직 생성하지 않는다.
- security control은 diagram overlay, 문서화, Docker Compose control 서비스, provider placement matrix 수준이다.
- JSON Schema 파일은 pydantic 모델에서 export되지만, 아직 editor integration이나 CI schema validation은 없다.
- generated `docker-compose.yml`은 runnable MVP runtime을 실행할 수 있으며, 지원되지 않는 취약 서비스 구현과 시나리오 고유 체인은 service builder 또는 agent가 확장해야 한다.

## 14. 수정된 개발 단계 제안

LLM/Agent 계층은 후반부 부가기능이 아니라 LabForge의 시나리오 제작 방식 자체에 포함되어야 한다. 따라서 기존의 provider 고도화 중심 계획을 다음 순서로 재정렬한다.

1. Core Spec / Validation

   `scenario.yaml`, `topology.yaml`, `stages.yaml`, v0.2 선택 파일, pydantic 검증, JSON Schema export를 안정화한다.

2. Runtime Awareness

   `doctor`와 `plan`을 통해 Windows, WSL, Docker, VM, hybrid 실행 위치를 판단한다.

3. Agent Orchestration Foundation

   Orchestrator LLM과 전문 agent 구조를 도입하기 위한 dry-run 기반을 만든다. 실제 LLM 호출 전에도 agent role, task, output, decision artifact가 생성되어야 한다.

4. Provider Execution Layer

   Docker Compose runtime script는 1차 구현되었다. Hybrid/Ludus/Ansible/Terraform provider는 deterministic skeleton 산출물을 생성한다. 다음에는 provider별 실제 deploy/destroy와 VM/AD provisioning을 고도화한다.

5. Service Artifact Standard

   취약 서비스 구현 디렉토리의 표준 구조를 정의한다. seed, noise, reset, healthcheck, attack-surface metadata를 분리한다. `services materialize`는 지원 플러그인에 대해 lab-scoped 취약 동작이 포함된 scenario-derived MVP runtime을 생성한다.

6. LLM Adapter

   `manual` adapter는 구현되었다. OpenAI, Claude CLI, MCP adapter는 registry slot만 있으며 실제 live execution은 아직 붙이지 않는다.

7. Scenario Production

   scenario 02-10을 LabForge YAML로 변환하고 agent-assisted QA loop를 적용한다.

8. Orion Echo Rebuild Verification

   기존 Orion Echo 산출물을 그대로 복제하지 않는다. Orion Echo 시나리오와 학습 목표를 LabForge 방식으로 재제작하고, 실습 체인이 정확히 동작하는지 검증한다.

## 15. 사용 예시 전체 흐름

새로운 시나리오를 만들 때의 예상 흐름은 다음과 같다.

```text
1. scenario.yaml 작성
2. topology.yaml 작성
3. stages.yaml 작성
4. python -m labforge validate <scenario-root>
5. python -m labforge doctor --lab <scenario-root>
6. python -m labforge plan <scenario-root> --provider <provider> --profile <profile>
7. python -m labforge services scaffold <scenario-root>
8. python -m labforge services materialize <scenario-root> --force
9. python -m labforge services check <scenario-root>
10. python -m labforge services healthcheck <scenario-root>
11. python -m labforge services reset <scenario-root> --service <service-name>
12. python -m labforge agents scaffold <scenario-root> --out output/<scenario>-agents
13. python -m labforge agents run output/<scenario>-agents --dry-run --adapter manual --context-root <scenario-root>
14. python -m labforge agents result-stub output/<scenario>-agents --task-id <task-id> --status needs-review --summary "<summary>"
15. python -m labforge agents review output/<scenario>-agents --write
16. python -m labforge agents decide output/<scenario>-agents --decision accepted --task-id <task-id> --reason "<reason>"
17. validation error, host 환경 문제, service artifact 문제, hook 문제, agent task 설계 문제 수정
18. python -m labforge schema export --out schemas
19. python -m labforge docs <scenario-root> --out output/<scenario>-docs
20. 감독자가 문서, 다이어그램, service artifact, agent task를 검토
21. 보안장치 선택
22. python -m labforge qa smoke <scenario-root> --out output/<scenario>-qa --provider <provider> --profile <profile> --materialize --force
23. python -m labforge build <scenario-root> --out output/<scenario>
24. 생성된 provider 산출물을 기반으로 실제 실습 환경 개발
```

현재 MVP는 이 흐름 중 실제 LLM live execution, 실제 취약 서비스 구현, 실제 VM/AD provisioning을 제외한 대부분의 검증/문서화/스캐폴드 단계를 제공한다.

## 16. v0.2 현재 반영 상태

현재 코드에 반영된 v0.2 기반 작업은 다음과 같다.

- pydantic 기반 spec model 추가
- 기존 `scenario.yaml`, `topology.yaml`, `stages.yaml` 호환 유지
- 선택 파일 추가 지원:
  - `lab.yaml`
  - `environment.yaml`
  - `artifacts.yaml`
  - `security-controls.yaml`
  - `supervisor-selection.yaml`
- provider 설정 디렉토리 예시 추가:
  - `providers/docker-compose.yaml`
  - `providers/ludus.yaml`
  - `providers/hybrid.yaml`
- provider interface 추가:
  - `docker-compose`
  - `ansible`
  - `terraform`
  - `ludus`
  - `hybrid`
- `python -m labforge schema export --out schemas` 명령 추가
- `python -m labforge build <lab> --provider docker-compose --profile unprotected --out <out>` 명령 추가
- `python -m labforge docs <lab> --profile protected --out <out>` 명령 추가
- `architecture-unprotected.md`, `architecture-protected.md`, `security-control-selection.md` 생성 추가
- protected profile의 Docker Compose 산출물에 선택된 보안장치 scaffold 서비스 생성 추가
- Docker Compose provider runtime scripts 생성 추가:
  - `scripts/validate.ps1`, `scripts/validate.sh`
  - `scripts/start.ps1`, `scripts/start.sh`
  - `scripts/stop.ps1`, `scripts/stop.sh`
  - `scripts/reset.ps1`, `scripts/reset.sh`
- `python -m labforge doctor --lab <lab>` 명령으로 host/WSL/Docker 실행 환경 진단 추가
- `python -m labforge plan <lab>` 명령으로 host-aware execution plan 생성 추가
- `python -m labforge agents list` 명령으로 기본 전문 agent 역할 목록 출력 추가
- `python -m labforge agents scaffold <lab>` 명령으로 dry-run agent workspace 생성 추가
- `python -m labforge agents validate <workspace>` 명령으로 agent task/output/decision artifact 검증 추가
- `python -m labforge services scaffold <lab>` 명령으로 service artifact 구현 디렉토리와 hook contract 생성 추가
- `python -m labforge services materialize <lab>` 명령으로 안전한 Docker MVP runtime 생성 추가
- `python -m labforge services check <lab>` 명령으로 service artifact 구현 디렉토리 검증 추가
- `python -m labforge services healthcheck <lab>` 명령으로 service healthcheck hook 실행 추가
- `python -m labforge services reset <lab>` 명령으로 service reset hook 실행 추가
- agent 관련 JSON Schema export 추가
- `python -m labforge agents adapters` 명령과 `manual` adapter 추가
- `python -m labforge agents plan-run`, `agents run --dry-run`, `agents review`, `agents decide` 명령 추가
- `python -m labforge agents result-stub` 명령으로 manual workflow의 schema-valid result 작성 지원
- `python -m labforge qa smoke` 명령으로 schema/service/provider smoke gate 추가
- `python -m labforge qa smoke`와 `python -m labforge pipeline create`에서 지원 플러그인의 실제 Flask route를 호출하는 `plugin-runtime-smoke` 검증 추가
- scenario-02 예제를 v0.2 구조로 확장
- `artifacts.yaml`의 `service_artifacts` 계약 추가
- 서비스 구현 표준 문서와 생성 산출물 `docs/service-artifact-contract.md` 추가
- Docker Compose provider가 `service_artifacts` 계약을 읽어 build context, service labels, `docs/provider-service-plan.md`에 반영
- Ansible/Terraform/Ludus/Hybrid provider가 provider plan, inventory, security profile, starter file 생성
- 선택된 security control을 provider placement matrix와 Docker Compose control service 환경변수에 반영

다음 구현 우선순위는 실제 OpenAI/Claude/MCP adapter live execution, provider별 deploy/destroy, VM/AD provisioning, 실제 취약 서비스 구현 자동화, 그리고 마지막 단계의 scenario 02-10 변환/검증이다.

## 17. 2026-06-22 추가 반영 사항

최근 구현으로 LabForge의 표준 제작 흐름은 다음처럼 정리된다.

```text
1. labforge intake template
   사람이 시나리오 아이디어를 적을 Markdown/YAML 입력지를 만든다.

2. labforge intake scaffold
   작성된 scenario-intake.yaml을 LabForge 초안 파일 묶음으로 변환한다.

3. labforge validate / lint
   스키마 오류와 placeholder, 약한 구조를 점검한다.

4. labforge controls list / apply
   감독자가 firewall, WAF, IDS, SIEM, EDR 같은 보안장치를 선택한다.

5. labforge doctor / plan
   현재 PC, WSL, Docker, VM/hybrid 필요성을 판단하고 실행 계획을 만든다.

6. labforge services scaffold / materialize
   서비스 구현 계약과 안전한 MVP runtime을 만든다.

7. labforge package
   provider 산출물, 문서, 실행 계획, lint, QA smoke 결과를 감독자 검토 패키지로 묶는다.

8. labforge agents scaffold / run --dry-run / review / decide
   Orchestrator LLM과 specialist agent가 수행할 작업 패키지와 검토 흐름을 만든다.
```

현재 추가된 주요 명령은 다음과 같다.

| 명령 | 목적 |
|---|---|
| `intake template` | 시나리오 기획자가 작성할 입력 템플릿 생성 |
| `intake scaffold` | intake YAML을 LabForge lab 초안으로 변환 |
| `lint` | placeholder, 약한 시작점, healthcheck 누락 등 품질 점검 |
| `controls list` | 선택 가능한 보안장치 catalog 확인 |
| `controls apply` | 감독자의 보안장치 선택을 `supervisor-selection.yaml`에 반영 |
| `package` | 감독자 검토용 산출물 묶음 생성 |

이 단계까지의 LabForge는 실제 취약 서비스 코드를 자동으로 완성하는 도구가 아니라, 시나리오 원고를 안전하고 검토 가능한 인프라 설계/구현 계약/agent 작업 패키지로 바꾸는 프레임워크다.
실제 취약 서비스 구현, 실제 VM/AD provisioning, 실제 LLM live execution은 다음 개발 단계에 남아 있다.
