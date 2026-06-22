# LabForge 환경 요구사항 카탈로그

이 문서는 LabForge로 생성할 수 있는 다양한 실습 환경을 실제로 구축할 때 필요한 인프라 선택지를 정리한다.

목적은 감독자와 인프라 운영자가 다음 질문에 답할 수 있게 하는 것이다.

- 이 실습은 PC 1대와 Docker만으로 가능한가?
- Windows Server, Active Directory, Kerberos, SMB, RDP 같은 기능이 필요한가?
- Proxmox, VMware ESXi, Hyper-V 같은 hypervisor가 필요한가?
- IDS, WAF, SIEM, EDR 같은 보안장치를 포함해야 하는가?
- Kubernetes, Terraform, Ansible 같은 운영 자동화 도구가 필요한가?
- 학습자 PC와 실습 인프라 서버를 분리해야 하는가?

## 1. 환경 유형 요약

| 환경 유형 | 사용 목적 | 적합한 시나리오 | 대표 요구사항 |
|---|---|---|---|
| Docker-only | 웹/API/DB 중심 실습을 빠르게 실행 | 공급망, 웹메일, 업무 API, 단순 내부망 | PC 1대, Docker Engine/Desktop, 충분한 RAM |
| Docker + WSL | Windows PC에서 Linux 기반 Docker lab 실행 | 로컬 개발/검증 | Windows 11, WSL2, Docker가 동작하는 Linux 배포판, Docker Desktop 또는 WSL Docker Engine |
| Local VM | 소규모 Windows/Linux VM 실습 | AD 입문, Windows endpoint, VPN appliance | PC 1대, Hyper-V/VMware Workstation/VirtualBox |
| Bare-metal Hypervisor | 여러 VM을 안정적으로 운영 | AD, Exchange, EDR, SOC, ICS/OT | Proxmox/ESXi/Hyper-V 서버, 충분한 CPU/RAM/SSD |
| Hybrid | Docker 서비스와 VM을 함께 사용 | Orion 확장형, AD+웹, VPN+내부망 | Docker host + VM host 또는 같은 hypervisor |
| SOC/Detection Lab | 탐지/로그/관제 포함 | Purple Team, Blue Team 포함 실습 | Security Onion/Wazuh/SIEM, 로그 저장소 |
| Kubernetes Lab | 컨테이너 오케스트레이션 보안 | 클러스터 침투, CI/CD, 서비스 메시 | 여러 노드 또는 충분한 단일 서버 |

## 2. Docker-only 환경

Docker-only 환경은 하나의 PC 또는 서버에서 여러 컨테이너를 실행하는 방식이다.

적합한 경우:

- 웹 애플리케이션 취약점
- API abuse
- 내부 wiki, build server, update server 같은 Linux 서비스
- 가짜 기업망 세그먼트
- 실습 초기 PoC(Proof of Concept)

부적합한 경우:

- 실제 Active Directory Domain Controller가 필요한 경우
- Windows Event Log, GPO, Kerberos, SMB, RDP가 핵심인 경우
- 실제 EDR agent나 Windows endpoint 행위가 필요한 경우
- appliance firmware나 OT 장비 에뮬레이션이 필요한 경우

권장 사양:

| 항목 | 권장 |
|---|---|
| Host | Windows 11, Linux, 또는 macOS |
| CPU | 8 cores 이상 |
| RAM | 16 GB 최소, 32 GB 권장 |
| Storage | 80 GB 이상 여유 공간 |
| Software | Docker Desktop 또는 Docker Engine, Git, Python 3.11+ |

LabForge에서의 표현 예:

```yaml
deployment:
  recommended_model: docker-compose
  docker_only_supported: true
  minimum_environment:
    description: Single Docker host.
```

## 3. Windows + WSL 기반 로컬 개발 환경

Windows 사용자 PC에서 Linux 기반 실습을 개발하거나 검증할 때 사용한다.

적합한 경우:

- Docker Compose 기반 lab 개발
- Linux 컨테이너 중심 시나리오
- Windows 경로 문제를 피하기 위해 WSL 내부에서 실행해야 하는 경우

주의할 점:

- OneDrive, Dropbox 같은 동기화 폴더에서 Docker volume을 직접 실행하면 권한, 성능, 파일 잠금 문제가 생길 수 있다.
- 실습 실행 경로는 WSL 내부 ext4 파일시스템을 권장한다.

권장 사양:

| 항목 | 권장 |
|---|---|
| Host | Windows 11 |
| Runtime | WSL2 + Docker가 동작하는 Linux 배포판. Ubuntu 22.04/24.04는 권장 예시 |
| CPU | 8 cores 이상 |
| RAM | 16 GB 최소, 32 GB 권장 |
| Software | Docker Desktop WSL integration, Git, Python 3.11+ |

LabForge 진단:

```powershell
python -m labforge doctor --lab examples/scenario-02-ad-domain-compromise
```

판단 기준:

| doctor 결과 | 의미 | 권장 조치 |
|---|---|---|
| `Recommended execution: host` | 현재 메인 OS에서 Docker 또는 필요한 provider를 바로 실행 가능 | 현재 shell에서 build/deploy 진행 |
| `Recommended execution: wsl` | Windows host보다 WSL 내부에서 Docker 실행이 적합 | doctor가 감지한 Docker 사용 가능 WSL 배포판 안에서 실행 |
| `Recommended execution: wsl-required` | Windows에서는 Docker가 보이지 않고 WSL 구성이 필요 | Docker Desktop WSL integration 또는 WSL Docker Engine 확인 |
| lab warning에 `hybrid`, `vm`, `proxmox`, `ludus` 표시 | Docker-only는 prototype이고 현실적 구성에는 VM/hypervisor 필요 | deployment requirements 문서 확인 |

Windows 소스 경로와 WSL 실행 경로가 분리되는 경우:

```text
Windows source: C:\dev\LabForge
WSL execution: /home/<user>/LabForge
```

이 모델에서는 Git 저장소를 WSL ext4 영역에 clone하거나, Windows 경로에서 WSL 경로로 `rsync`한 뒤 Docker 명령을 실행하는 방식을 권장한다. Docker volume과 많은 작은 파일을 Windows 동기화 폴더에서 직접 다루면 성능과 권한 문제가 생길 수 있다.

## 4. Active Directory / Windows Domain 환경

AD(Active Directory) 기반 실습은 Docker-only로는 현실성이 부족하다.

필요한 대표 기능:

- Windows Server Domain Controller
- DNS(Domain Name System)
- Kerberos 인증
- LDAP(Lightweight Directory Access Protocol)
- SMB(Server Message Block) 공유
- GPO(Group Policy Object)
- Windows Event Log
- Windows client 또는 member server

권장 구성:

| VM | 역할 | 권장 사양 |
|---|---|---|
| dc01 | Windows Server Domain Controller | 2-4 vCPU, 4-8 GB RAM, 80 GB disk |
| ws01 | Windows client 또는 member workstation | 2 vCPU, 4-8 GB RAM, 60 GB disk |
| app01 | 내부 업무 서버 | 2 vCPU, 4 GB RAM, 40 GB disk |
| attacker | Linux attacker workstation | 2-4 vCPU, 4-8 GB RAM, 40 GB disk |

권장 운영 방식:

- Proxmox, VMware ESXi, Hyper-V 같은 hypervisor 사용
- Ansible 또는 PowerShell Desired State Configuration으로 반복 구성
- 각 stage 시작 전 snapshot 생성
- Windows Event Forwarding 또는 Sysmon 기반 로그 수집

LabForge에서의 표현 예:

```yaml
deployment:
  recommended_model: hybrid
  docker_only_supported: false
  realistic_environment:
    description: Hypervisor-backed Windows AD lab.
```

## 5. Proxmox / VMware ESXi / Hyper-V 기반 VM 환경

여러 VM이 필요한 실습에는 bare-metal hypervisor가 가장 현실적이다.

적합한 경우:

- AD domain compromise
- Exchange/Webmail compromise
- VPN appliance to internal network
- ransomware prepositioning
- EDR/SIEM이 포함된 실습
- ICS/OT simulator와 Windows engineering workstation이 필요한 실습

권장 사양:

| 항목 | 권장 |
|---|---|
| Host | 물리 서버 1대 이상 |
| CPU | 12 cores 이상 권장 |
| RAM | 64 GB 이상 권장 |
| Storage | 300 GB SSD 이상, snapshot 고려 시 1 TB 권장 |
| Network | 최소 1 NIC, 망 분리 시 2 NIC 이상 권장 |
| Platform | Proxmox VE, VMware ESXi, Hyper-V |

운영 팁:

- 학습자별로 VM clone 또는 linked clone을 제공한다.
- snapshot reset을 표준화한다.
- NAT, isolated bridge, DMZ bridge를 분리한다.
- Windows license와 ISO 관리 정책을 사전에 정한다.

## 6. Network Security / Firewall 환경

방화벽은 단순히 "차단 장치"가 아니라 실습의 현실감을 만드는 핵심 요소다.

사용 가능한 방식:

- Docker network segmentation
- Linux nftables/iptables
- pfSense 또는 OPNsense VM
- Windows Firewall
- cloud security group
- Proxmox bridge/VLAN

필요한 경우:

- DMZ와 내부망 분리
- release network와 customer network 분리
- egress restriction 실습
- 터널링 또는 pivot 학습
- firewall rule misconfiguration 시나리오

LabForge 표현 예:

```yaml
security_controls:
  recommended:
    - Firewall / Segmentation
    - Egress Restriction
```

## 7. IDS / NDR / Packet Capture 환경

IDS(Intrusion Detection System)나 NDR(Network Detection and Response)은 탐지 교육 또는 purple-team 모드에서 필요하다.

대표 선택지:

- Suricata
- Zeek
- Security Onion
- Arkime
- tcpdump/pcap collector

필요한 경우:

- 내부 lateral movement 탐지
- exploit traffic 관찰
- C2 callback 탐지
- DNS tunneling, HTTP beaconing, unusual egress 탐지
- 학습자가 공격 후 방어 관점 로그를 확인하는 실습

권장 구성:

| 환경 | 구성 |
|---|---|
| Docker-only | Suricata container 또는 pcap sidecar |
| VM 기반 | Security Onion sensor VM |
| 고급형 | TAP/SPAN 또는 bridge 기반 센서 |

## 8. SIEM / Log Collection 환경

SIEM(Security Information and Event Management)은 로그 기반 탐지와 사후 분석 실습에 필요하다.

대표 선택지:

- Wazuh
- Elastic Stack
- OpenSearch
- Splunk trial/dev 환경
- Security Onion 내장 Elastic/OpenSearch stack

수집 대상:

- web access log
- application log
- authentication log
- Windows Event Log
- Sysmon event
- IDS alert
- build pipeline audit log
- firewall log

권장 사양:

| 규모 | 권장 |
|---|---|
| 소형 실습 | 4 vCPU, 8-16 GB RAM |
| 중형 실습 | 8 vCPU, 16-32 GB RAM |
| 다중 학습자 | 별도 로그 서버 또는 클러스터 |

## 9. EDR-lite / Endpoint Telemetry 환경

실제 상용 EDR을 실습에 넣기 어렵다면 EDR-lite 모델을 사용할 수 있다.

가능한 방식:

- Windows Sysmon
- auditd
- osquery
- Wazuh agent
- custom process/network event collector

관찰 대상:

- suspicious child process
- shell spawn
- credential file access
- PowerShell execution
- reverse connection
- scheduled task
- service creation

LabForge에서는 처음에는 실제 차단보다 telemetry 생성과 문서화를 우선한다.

## 10. WAF / Reverse Proxy 환경

WAF(Web Application Firewall)는 외부 웹 취약점 실습에 유용하다.

대표 선택지:

- Nginx reverse proxy
- ModSecurity + OWASP Core Rule Set
- Traefik middleware
- Envoy proxy

적합한 경우:

- SSTI(Server-Side Template Injection)
- SQL injection
- path traversal
- SSRF(Server-Side Request Forgery)
- file upload abuse

운영 모드:

- alert only
- block mode
- learning mode

교육용으로는 처음에는 alert-only를 권장한다. 공격 흐름이 막히면 학습자가 실습 자체를 진행하지 못할 수 있기 때문이다.

## 11. Kubernetes 환경

Kubernetes는 컨테이너 오케스트레이션 보안 시나리오에 필요하다.

적합한 경우:

- service account token abuse
- exposed dashboard/API server
- container escape concept lab
- CI/CD to cluster deployment
- secrets/configmap discovery
- network policy bypass

권장 구성:

| 유형 | 사용 목적 |
|---|---|
| kind/minikube | 개발자 로컬 PoC |
| kubeadm multi-node | 현실적인 cluster lab |
| managed Kubernetes | cloud-native 시나리오용. 현재 ROOT14 Enterprise 14 tactic 범위에서는 선택 사항 |

주의:

- Kubernetes는 학습 난이도가 높다.
- 기본 red-team 입문 실습에는 과할 수 있다.
- cluster reset 자동화가 필수다.

## 12. ICS / OT 환경

ICS(Industrial Control System) 또는 OT(Operational Technology) 실습은 일반 IT lab과 다르다.

가능한 구성:

- Modbus/TCP simulator
- OPC UA simulator
- HMI(Human-Machine Interface) web app
- engineering workstation VM
- historian database
- plant simulator

권장 방식:

- 초기 버전은 Docker simulator로 구성
- 고급 버전은 Windows engineering workstation VM과 OT simulator를 hybrid로 구성

주의:

- 실제 산업 장비나 운영망과 연결하지 않는다.
- 모든 제어 명령은 lab simulator 내부로 제한한다.

## 13. IaC / Configuration Automation 환경

LabForge 자체는 상위 정의 프레임워크이고, 실제 배포는 provider가 담당한다.

사용 가능한 도구:

| 도구 | 역할 |
|---|---|
| Docker Compose | 컨테이너 서비스 실행 |
| Ansible | Linux/Windows VM 설정 자동화 |
| Terraform | VM, 네트워크, 볼륨, 보안그룹 생성 |
| Packer | VM image baking |
| Vagrant | 로컬 VM 실습 구성 |
| cloud-init | Linux VM 초기 설정 |
| PowerShell DSC | Windows 설정 자동화 |

LabForge는 향후 이 도구들을 직접 대체하지 않고 provider backend로 호출하는 구조를 목표로 한다.

## 14. 시나리오별 환경 판단 예시

| 시나리오 | Docker-only 가능 | 권장 환경 |
|---|---:|---|
| Orion Echo Supply Chain | 가능 | Docker Compose 또는 Hybrid |
| Active Directory Domain Compromise | 제한적 | Proxmox/VM + Windows Server + Ansible |
| Exchange/Webmail Compromise | 제한적 | Hybrid 또는 Windows VM |
| Edge Appliance to Internal Network | 가능 | Docker Compose + optional firewall VM |
| Webmail Espionage | 가능 | Docker Compose |
| Ransomware Prepositioning | 제한적 | Windows VM + AD + snapshot |
| Retail POS Intrusion | 제한적 | Hybrid |
| Bank Payment Operations Fraud | 가능 | Docker Compose 또는 Hybrid |
| VPN Appliance to AD Compromise | 제한적 | Hybrid + VPN appliance VM |
| ICS/OT Intrusion | 제한적 | Docker simulator 또는 Hybrid OT lab |

## 15. LabForge에 반영해야 할 최종 구조

향후 각 시나리오에는 다음 정보가 필요하다.

```yaml
deployment:
  recommended_model: hybrid
  docker_only_supported: false
  minimum_environment:
    hosts: []
  realistic_environment:
    hosts: []
  required_platforms: []
  reset_requirements:
    - snapshot support
    - seeded data restore
  isolation_requirements:
    - no external internet egress
    - internal DNS only
```

이 구조가 들어가면 LabForge는 시나리오를 보고 다음을 자동 생성할 수 있다.

- 최소 실행 환경
- 현실적인 운영 환경
- 필요한 PC/서버/VM 수
- 필요한 hypervisor
- 필요한 보안장치
- 필요한 reset/snapshot 기능
- 감독자 검토용 체크리스트

## 16. 참고한 공식 문서

- Docker Engine install documentation: <https://docs.docker.com/engine/install/>
- Proxmox VE system requirements: <https://www.proxmox.com/en/proxmox-virtual-environment/requirements>
- Microsoft Hyper-V requirements: <https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/hyper-v-requirements>
- Microsoft Windows Server documentation: <https://learn.microsoft.com/en-us/windows-server/>
- Ansible control node requirements: <https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html>
- Terraform install documentation: <https://developer.hashicorp.com/terraform/install>
- Security Onion hardware requirements: <https://docs.securityonion.net/en/2.4/hardware.html>
- Wazuh installation requirements: <https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/installation-assistant.html>
- Kubernetes kubeadm installation guide: <https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/>
- pfSense hardware requirements: <https://docs.netgate.com/pfsense/en/latest/hardware/minimum-requirements.html>
