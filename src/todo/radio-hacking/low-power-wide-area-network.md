# 저전력 광역 네트워크

{{#include ../../banners/hacktricks-training.md}}

## 소개

**저전력 광역 네트워크** (LPWAN)는 **저비트 전송**을 위한 **장거리 통신**을 설계한 무선 저전력 광역 네트워크 기술 그룹입니다. 
이들은 **6마일** 이상 도달할 수 있으며, **배터리**는 최대 **20년**까지 지속될 수 있습니다.

Long Range (**LoRa**)는 현재 가장 많이 배포된 LPWAN 물리 계층이며, 그 개방형 MAC 계층 사양은 **LoRaWAN**입니다.

---

## LPWAN, LoRa 및 LoRaWAN

* LoRa – Semtech에 의해 개발된 Chirp Spread Spectrum (CSS) 물리 계층 (독점적이지만 문서화됨).
* LoRaWAN – LoRa-Alliance에서 유지 관리하는 개방형 MAC/네트워크 계층. 1.0.x 및 1.1 버전이 현장에서 일반적입니다.
* 전형적인 아키텍처: *엔드 장치 → 게이트웨이 (패킷 포워더) → 네트워크 서버 → 애플리케이션 서버*.

> **보안 모델**은 *조인* 절차 (OTAA) 중 세션 키를 파생하는 두 개의 AES-128 루트 키 (AppKey/NwkKey)에 의존합니다. 키가 유출되면 공격자는 해당 트래픽에 대한 전체 읽기/쓰기 권한을 얻게 됩니다.

---

## 공격 표면 요약

| 계층 | 취약점 | 실질적 영향 |
|-------|----------|------------------|
| PHY | 반응형 / 선택적 재밍 | 단일 SDR 및 <1 W 출력으로 100 % 패킷 손실 입증 |
| MAC | Join-Accept 및 데이터 프레임 재전송 (nonce 재사용, ABP 카운터 롤오버) | 장치 스푸핑, 메시지 주입, DoS |
| 네트워크 서버 | 안전하지 않은 패킷 포워더, 약한 MQTT/UDP 필터, 구식 게이트웨이 펌웨어 | 게이트웨이에 대한 RCE → OT/IT 네트워크로 피벗 |
| 애플리케이션 | 하드코딩되거나 예측 가능한 AppKeys | 트래픽 무차별 대입/복호화, 센서 가장 |

---

## 최근 취약점 (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge 및 mqtt-forwarder*가 Kerlink 게이트웨이에서 상태 기반 방화벽 규칙을 우회하는 TCP 패킷을 수용하여 원격 관리 인터페이스 노출을 허용했습니다. 각각 4.0.11 / 4.2.1에서 수정됨.
* **Dragino LG01/LG308 시리즈** – 2022-2024년의 여러 CVE (예: 2022-45227 디렉토리 탐색, 2022-45228 CSRF)가 2025년에도 여전히 패치되지 않은 것으로 관찰됨; 수천 개의 공용 게이트웨이에서 인증되지 않은 펌웨어 덤프 또는 구성 덮어쓰기를 활성화함.
* Semtech *패킷 포워더 UDP* 오버플로우 (발표되지 않음, 2023-10 패치): 255 B보다 큰 업링크가 스택 스매시를 유발하여 SX130x 참조 게이트웨이에 대한 RCE를 발생시킴 (Black Hat EU 2023 “LoRa Exploitation Reloaded”에서 발견됨).

---

## 실용적인 공격 기술

### 1. 트래픽 스니핑 및 복호화
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA 조인 재전송 (DevNonce 재사용)

1. 합법적인 **JoinRequest**를 캡처합니다.
2. 원래 장치가 다시 전송하기 전에 즉시 재전송합니다 (또는 RSSI를 증가시킵니다).
3. 네트워크 서버는 새로운 DevAddr 및 세션 키를 할당하는 동안 대상 장치는 이전 세션을 계속 사용합니다 → 공격자는 비어 있는 세션을 소유하고 위조된 업링크를 주입할 수 있습니다.

### 3. 적응형 데이터 속도 (ADR) 다운그레이드

SF12/125 kHz를 강제로 설정하여 공중 시간을 증가시킵니다 → 게이트웨이의 듀티 사이클을 소모시킵니다 (서비스 거부) 동시에 공격자에게 배터리 영향을 낮게 유지합니다 (네트워크 수준 MAC 명령만 전송).

### 4. 반응형 재밍

*HackRF One*이 GNU Radio 흐름 그래프를 실행하여 프리앰블이 감지될 때마다 광대역 칩을 트리거합니다 – ≤200 mW TX로 모든 확산 계수를 차단합니다; 2 km 범위에서 전체 중단이 측정됩니다.

---

## 공격 도구 (2025)

| 도구 | 목적 | 비고 |
|------|---------|-------|
| **LoRaWAN 감사 프레임워크 (LAF)** | LoRaWAN 프레임 제작/파싱/공격, DB 기반 분석기, 브루트 포스 | Docker 이미지, Semtech UDP 입력 지원 |
| **LoRaPWN** | OTAA를 브루트 포스하고, 다운링크를 생성하며, 페이로드를 복호화하는 Trend Micro Python 유틸리티 | 2023년 데모 출시, SDR 비독립적 |
| **LoRAttack** | USRP와 함께하는 다채널 스니퍼 + 재전송; PCAP/LoRaTap 내보내기 | 좋은 Wireshark 통합 |
| **gr-lora / gr-lorawan** | 기저대역 TX/RX를 위한 GNU Radio OOT 블록 | 사용자 정의 공격의 기초 |

---

## 방어 권장 사항 (펜테스터 체크리스트)

1. 진정한 무작위 DevNonce를 가진 **OTAA** 장치를 선호합니다; 중복을 모니터링합니다.
2. **LoRaWAN 1.1**을 시행합니다: 32비트 프레임 카운터, 구별된 FNwkSIntKey / SNwkSIntKey.
3. 프레임 카운터를 비휘발성 메모리 (**ABP**)에 저장하거나 OTAA로 마이그레이션합니다.
4. 루트 키를 펌웨어 추출로부터 보호하기 위해 **보안 요소** (ATECC608A/SX1262-TRX-SE)를 배포합니다.
5. 원격 UDP 패킷 포워더 포트 (1700/1701)를 비활성화하거나 WireGuard/VPN으로 제한합니다.
6. 게이트웨이를 업데이트 상태로 유지합니다; Kerlink/Dragino는 2024년 패치된 이미지를 제공합니다.
7. **트래픽 이상 탐지** (예: LAF 분석기)를 구현합니다 – 카운터 리셋, 중복 조인, 갑작스러운 ADR 변경을 플래그합니다.

## References

* LoRaWAN Auditing Framework (LAF) – https://github.com/IOActive/laf
* Trend Micro LoRaPWN 개요 – https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a
{{#include ../../banners/hacktricks-training.md}}
