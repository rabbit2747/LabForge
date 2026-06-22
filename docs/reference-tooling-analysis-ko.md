# LabForge reference 도구 분석 보고서

## 1. 분석 대상

분석한 로컬 참고 자료:

```text
reference/
|-- compass_artifact_wf-18a0ed7c-18e6-4164-9cf3-171270820f11_text_markdown.md
`-- 프레임워크 개발 오픈소스 도구 탐색.md
```

두 파일은 모두 UTF-8 Markdown이다.

첫 번째 파일은 LabForge와 직접 관련된 보안 교육 lab 프레임워크, AD lab, MITRE, IaC, diagram, detection stack 중심의 자료다.

두 번째 파일은 "LabForge"라는 이름을 쓰는 여러 다른 프로젝트까지 섞인 넓은 탐색 문서다. 이 문서는 그대로 가져오기보다는 다음 세 영역만 선별적으로 참고하는 것이 좋다.

- Skill 저작/검수 UI 아이디어
- MCP/agent runtime 운영상 주의점
- PR review / 코드 분석 자동화 아이디어

컴퓨터 비전, 카메라 SDK, 합성 데이터 생성, 물리 실험실 3D layout 관련 항목은 현재 ROOT14 LabForge의 핵심 범위와 거리가 있어 제외 대상으로 본다.

## 2. 결론 요약

LabForge에 가장 가치 있는 방향은 다음이다.

1. **AD 구축은 직접 새로 만들지 말고 GOAD, Ludus, Adaz, PurpleCloud 같은 기존 프로젝트를 provider 또는 backend로 연동한다.**
2. **LabForge core는 pydantic v2 기반 spec validator와 provider plugin 구조로 재설계한다.**
3. **MITRE 검증은 mitreattack-python과 MITRE CTI 데이터로 강화한다.**
4. **Attack Flow, ATT&CK Navigator, Mermaid/D2/Kroki로 감독자용 흐름도와 아키텍처 도식을 강화한다.**
5. **protected/unprotected profile은 DetectionLab, Security Onion, Wazuh, Suricata, Zeek, Sigma, Atomic Red Team을 참고해 설계한다.**
6. **Skill/MCP는 LabForge 자체 생성 기능보다 "외부 검토/자동화 플러그인" 계층으로 두는 것이 좋다.**
7. **GOAD, Wazuh, Suricata 등 GPL 계열은 코드 복사보다 외부 도구 연동 또는 설계 참고 방식이 안전하다.**

## 3. 즉시 도입 가치가 큰 항목

### 3.1 pydantic v2

현재 LabForge는 dict 기반 validator와 별도 JSON schema 파일을 사용한다.

개선 방향:

- `scenario.yaml`, `topology.yaml`, `stages.yaml`을 pydantic model로 정의
- model에서 JSON Schema 자동 생성
- 필드 설명과 예제를 schema에 포함
- 향후 VS Code YAML validation에 연결

도입 방식:

```text
labforge/models/
|-- scenario.py
|-- topology.py
|-- stage.py
|-- deployment.py
|-- security_control.py
`-- provider.py
```

권장 상태:

```text
우선 도입
```

### 3.2 mitreattack-python + MITRE CTI

현재 LabForge는 tactic 이름이 Enterprise 14개 중 하나인지 정도만 확인한다.

개선 방향:

- technique ID가 실제 ATT&CK Enterprise technique인지 확인
- technique name mismatch 탐지
- deprecated/revoked technique 탐지
- stage별 ATT&CK Navigator layer 생성
- MITRE coverage report 생성

권장 산출물:

```text
output/<lab>/docs/mitre-mapping.md
output/<lab>/docs/mitre-coverage.md
output/<lab>/mitre/attack-navigator-layer.json
```

권장 상태:

```text
우선 도입
```

### 3.3 Jinja2 template renderer

현재 `render.py`는 Python 문자열 조립으로 compose와 Markdown을 만든다.

개선 방향:

- Docker Compose, Ansible inventory, Terraform HCL, Ludus config 등을 Jinja2 template로 생성
- provider별 template 디렉토리 분리

예상 구조:

```text
templates/
|-- docs/
|-- providers/
|   |-- docker-compose/
|   |-- ansible/
|   |-- terraform/
|   `-- ludus/
`-- diagrams/
```

권장 상태:

```text
우선 도입
```

### 3.4 Provider plugin 구조

GOAD의 핵심 교훈은 provider 분리다.

LabForge도 다음 구조로 가야 한다.

```text
labforge/providers/
|-- base.py
|-- factory.py
|-- docker_compose/
|-- ansible/
|-- terraform/
|-- vagrant/
|-- proxmox/
|-- ludus/
`-- hybrid/
```

각 provider는 공통 인터페이스를 가진다.

```python
class Provider:
    def validate(self, spec): ...
    def generate(self, spec, out): ...
    def plan(self, spec, out): ...
    def deploy(self, spec, out): ...
    def destroy(self, spec, out): ...
```

권장 상태:

```text
우선 도입
```

## 4. AD/Windows lab에 응용 가능한 항목

### 4.1 GOAD

가치:

- AD lab 구축의 대표 참고 사례
- 여러 provider를 지원하는 구조
- Vagrant, VMware, Proxmox, AWS, Azure, Ludus 같은 backend 방향 참고 가능
- Windows DC, Kerberos, SMB, GPO, MSSQL, IIS, trust 관계 등 Docker로 만들기 어려운 요소를 이미 다룸

주의:

- GPL-3.0이므로 코드 복사는 LabForge 라이선스에 영향을 준다.
- 직접 가져오기보다 외부 도구로 호출하거나 provider 설계만 참고하는 것이 안전하다.

LabForge 활용 방식:

```text
권장: provider 설계 참고 + 외부 GOAD wrapper
비권장: 내부 코드 복사
```

### 4.2 Ludus

가치:

- Proxmox 기반 cyber range 운영 모델
- YAML 기반 range 정의
- Ansible role 생태계
- GOAD, Elastic, Wazuh, Atomic Red Team 등과 결합 가능

LabForge 활용 방식:

```text
LabForge spec -> Ludus range config 생성
```

이 방식은 AD나 Windows 실습에서 가장 현실적이다.

권장 상태:

```text
AD provider PoC 후보 1순위
```

### 4.3 DetectionLab

가치:

- AD + 탐지/로그 수집 reference
- Sysmon, Windows Event Forwarding, Splunk, osquery 등 protected architecture 모델 참고 가능

주의:

- 유지보수 상태 확인 필요

LabForge 활용 방식:

```text
protected profile 설계 참고
```

### 4.4 Adaz / PurpleCloud

가치:

- YAML 또는 Python 기반 AD 환경 생성 패턴
- Terraform + Ansible 조합 참고
- cloud/hybrid AD lab 구성 참고

LabForge 활용 방식:

```text
Terraform provider 설계 참고
AD seed data 구조 참고
```

## 5. 보안장치 / protected profile에 응용 가능한 항목

### 5.1 Wazuh

용도:

- SIEM/XDR/HIDS 역할
- Windows/Linux agent telemetry
- FIM(File Integrity Monitoring)
- ATT&CK mapping 기반 alert

LabForge 활용:

```yaml
security_controls:
  recommended:
    - Wazuh manager
    - Wazuh agent
    - Wazuh dashboard
```

주의:

- GPL-2.0 계열이므로 코드 임베딩보다 설치/연동 provider가 적합하다.

### 5.2 Suricata / Zeek / Security Onion

용도:

- 네트워크 IDS
- East-west traffic monitoring
- exploit, beacon, tunneling 탐지
- packet capture와 event log 생성

LabForge 활용:

- protected architecture diagram에 sensor 위치 표시
- `security-controls.yaml`에서 sensor profile 선택
- stage별 observable event와 연결

예:

```yaml
detection:
  controls:
    - ids-east-west-suricata
  observables:
    - unusual HTTP request to internal Solr
    - reverse shell callback attempt
```

### 5.3 Sigma / pySigma

용도:

- 탐지 룰을 vendor-neutral YAML로 관리
- Elastic, Splunk, Sentinel 등으로 변환 가능

LabForge 활용:

```text
stages.yaml -> detection-rules/sigma/*.yml
```

장기적으로 protected profile의 핵심 포맷으로 좋다.

### 5.4 Atomic Red Team

용도:

- ATT&CK technique별 atomic test 실행
- protected profile에서 alert 발생 여부 확인

LabForge 활용:

```text
stage technique -> matching atomic test -> protected profile validation
```

주의:

- 실제 공격 행위가 포함될 수 있으므로 lab 내부에서만 실행해야 한다.

## 6. Diagram / 시각화에 응용 가능한 항목

### 6.1 Mermaid CLI

현재 LabForge는 Mermaid `.mmd` 파일과 Markdown diagram을 생성한다.

Mermaid CLI를 붙이면 다음을 만들 수 있다.

```text
topology.svg
attack-flow.svg
security-controls.svg
```

주의:

- Node.js와 headless Chromium 의존성이 있다.

권장:

```text
선택 provider 또는 optional renderer
```

### 6.2 Kroki

가치:

- Mermaid, PlantUML, D2, Graphviz 등을 HTTP API로 렌더링
- 로컬 Node/Chromium 설치 부담 감소

LabForge 활용:

```text
labforge diagrams render --renderer kroki
```

권장:

```text
장기적으로 가장 깔끔한 diagram rendering backend
```

### 6.3 D2 / mingrammer diagrams

가치:

- 인프라 아키텍처 다이어그램 생성에 더 적합할 수 있음
- Python-native 또는 CLI 기반으로 자동화 가능

LabForge 활용:

```text
Mermaid: 기본 문서용
D2/diagrams: 감독자용 고급 아키텍처용
```

## 7. 취약 서비스 / 시나리오 자산에 응용 가능한 항목

### 7.1 Vulhub

가치:

- CVE별 Docker Compose 취약 환경
- 특정 CVE stage를 만들 때 빠르게 재사용 가능

LabForge 활용:

```yaml
services:
  - name: ops-search
    source:
      type: vulhub
      ref: apache/solr/CVE-2019-17558
```

주의:

- public 노출 금지
- 라이선스와 이미지 출처 확인 필요

### 7.2 OWASP Juice Shop / DVWA / WebGoat / VAmPI

가치:

- 웹/API 취약점 stage prototype에 좋음

LabForge 활용:

- scenario prototype
- technique teaching module
- instructor demo

주의:

- 우리가 만드는 현실형 기업망 시나리오에는 그대로 노출하면 CTF 느낌이 강해질 수 있다.
- 실제 시나리오에는 브랜드/업무 맥락을 씌우거나 내부 서비스 형태로 재구성해야 한다.

## 8. Skill / MCP / Agent로 응용 가능한 항목

두 번째 reference 문서는 OpenClaw, ClawHub, Visual Skill IDE, PR review agent 등을 다룬다.

이 자료에서 가져올 수 있는 핵심은 "LabForge 자체 기능"보다는 "LabForge 주변 자동화 도구"다.

### 8.1 Skill 후보

LabForge 전용 Skill로 만들 만한 것:

```text
labforge-scenario-reviewer
```

역할:

- scenario.yaml/topology.yaml/stages.yaml 읽기
- stage 흐름이 자연스러운지 검토
- MITRE mapping 누락 확인
- CTF스러운 문구 탐지
- magic string 의존성 탐지
- 보안장치와 deployment 요구사항 누락 탐지

```text
labforge-provider-planner
```

역할:

- 시나리오를 보고 Docker/VM/Hybrid/Proxmox provider 추천
- 필요한 PC/서버/VM 수 산출
- AD/Windows/ICS/Kubernetes 필요 여부 판단

```text
labforge-doc-reviewer
```

역할:

- 생성된 문서의 정합성 확인
- 학생용/강사용/감독자용 문서 분리 확인
- 용어와 stage numbering 검토

### 8.2 MCP 후보

MCP로 만들 만한 기능:

```text
labforge-mcp
```

가능한 tool:

- `validate_lab(path)`
- `render_docs(path, out)`
- `build_lab(path, out, provider)`
- `render_diagrams(path, renderer)`
- `compare_scenarios(path_a, path_b)`
- `recommend_provider(path)`
- `summarize_controls(path)`

이 MCP는 외부 agent가 LabForge repo를 직접 이해하지 않고도 LabForge 기능을 사용할 수 있게 한다.

주의:

- reference 문서에 언급된 것처럼 MCP 서버를 무분별하게 여러 세션에서 띄우면 프로세스가 중복될 수 있다.
- LabForge MCP는 stateless CLI wrapper 형태를 우선하고, 장기 실행 daemon은 나중으로 미룬다.

### 8.3 PR review agent 후보

LabForge에는 자동 PR 리뷰가 유용하다.

검토 규칙:

- provider가 Docker에만 종속되는지 확인
- GPL 코드가 직접 복사되었는지 확인
- intentionally vulnerable service가 public으로 노출되는지 확인
- stage별 MITRE mapping 누락 확인
- deployment requirements 누락 확인
- generated output을 커밋했는지 확인

GitHub Actions 기반 LLM reviewer를 바로 붙이기보다는 먼저 정적 체크 스크립트를 만드는 것이 안전하다.

## 9. 제외하거나 보류할 항목

### 9.1 LabForge Visual Skill IDE / OpenClaw / ClawHub

가치:

- Skill 저작 UI와 marketplace 개념은 참고 가능

보류 이유:

- 현재 LabForge의 핵심 문제는 cyber range spec/provider 안정화
- OpenClaw 생태계 의존성은 현재 범위를 넓힌다
- 검증되지 않은 외부 skill marketplace를 바로 붙이면 supply-chain 위험이 생긴다

결론:

```text
장기 참고. 지금은 직접 통합하지 않음.
```

### 9.2 Labforge Inc. 카메라/비전 SDK

제외 이유:

- 컴퓨터 비전/하드웨어 SDK 분야
- ROOT14 cyber lab framework와 직접 관련 없음

### 9.3 합성 CSV 데이터 생성기

부분 참고:

- noise data 생성 철학은 참고 가능

제외 이유:

- 현재 LabForge의 핵심은 lab infra/spec/provider
- 데이터 생성 모듈은 나중에 artifact/noise generator로 따로 고려

### 9.4 3D 실험실 layout generator

제외 이유:

- 물리 실험실/공간 배치 도구
- cyber range topology와 직접 관련 낮음

## 10. 라이선스 리스크

반드시 구분해야 한다.

| 도구 | 라이선스/주의 | 권장 방식 |
|---|---|---|
| GOAD | GPL-3.0 | 코드 복사 금지. wrapper 또는 설계 참고 |
| Wazuh | GPL-2.0 | 설치/연동 provider |
| Suricata | GPL-2.0 | 설치/연동 provider |
| Zeek | BSD | 연동 가능 |
| mitreattack-python | Apache-2.0 | 직접 의존성 가능 |
| Atomic Red Team | MIT | 직접 연동 가능 |
| Attack Flow | Apache-2.0 | 직접 연동 가능 |
| Splunk Attack Range | Apache-2.0 | 설계 참고/연동 가능 |
| Adaz | MIT | 설계 참고/일부 재사용 가능 |
| DetectionLab | MIT, 유지보수 상태 확인 | 설계 참고 |
| Mermaid CLI | MIT | optional renderer |
| D2 | MPL-2.0 | optional renderer |

## 11. LabForge 로드맵에 반영할 제안

### Phase 1: Spec core 강화

- pydantic v2 도입
- JSON Schema 자동 생성
- ruamel.yaml 도입 검토
- Typer CLI 전환 검토
- MITRE technique 검증 강화

### Phase 2: Provider interface 분리

- `Provider` base class
- `DockerComposeProvider`
- `AnsibleProvider`
- `TerraformProvider`
- `LudusProvider`
- `HybridProvider`

### Phase 3: Diagram renderer 확장

- Mermaid 유지
- optional Mermaid CLI renderer
- Kroki renderer PoC
- D2 또는 mingrammer diagrams 비교

### Phase 4: Protected profile

- security control catalog
- Wazuh/Suricata/Zeek/Sigma/Sysmon+WEF 모델링
- protected/unprotected architecture diff 생성
- detection coverage report 생성

### Phase 5: AD provider PoC

- Ludus config export
- GOAD wrapper 검토
- BadBlood/vulnerable-AD seeding 검토
- Proxmox Terraform provider 비교

### Phase 6: Automation / Agent layer

- LabForge MCP server
- LabForge scenario review skill
- PR review static checks
- 라이선스/보안 노출 자동 검사

## 12. 우선순위 판단

가장 먼저 해야 할 일:

```text
1. pydantic 기반 spec v0.2
2. provider interface 분리
3. MITRE technique ID 실제 검증
4. deployment/security control schema 정식화
5. Ludus/GOAD 연동 방식 결정
```

지금 하지 않아도 되는 일:

```text
1. OpenClaw/ClawHub 직접 통합
2. Visual Skill IDE 구축
3. 컴퓨터 비전 Labforge 관련 도구 검토
4. PR review LLM agent 즉시 도입
5. 3D layout generator 통합
```

## 13. 최종 판단

reference 자료 중 LabForge에 가장 실질적인 가치는 첫 번째 tooling map에 있다.

이 자료는 우리가 이미 세운 방향과 거의 일치한다.

- Docker-only로 고정하지 말 것
- AD는 GOAD/Ludus 같은 기존 range를 활용할 것
- provider seam을 먼저 만들 것
- 보안장치가 있는 profile과 없는 profile을 분리할 것
- MITRE mapping을 실제 ATT&CK 데이터로 검증할 것
- diagram output을 감독자용 산출물로 강화할 것

두 번째 자료는 이름이 같은 다른 LabForge 생태계가 섞여 있으므로 그대로 따라가면 방향이 흐려진다. 다만 Skill/MCP/PR review 자동화 관점에서는 장기적으로 응용 가치가 있다.

