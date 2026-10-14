# 저전력 광역 네트워크

{{#include ../../banners/hacktricks-training.md}}

## 소개

**저전력 광역 네트워크**(LPWAN)는 낮은 비트 전송률로 **장거리 통신**을 제공하도록 설계된 무선 저전력 광역 네트워크 기술의 집합입니다.
무선 매개변수, 안테나, 규제 지역, 지형, 듀티 사이클에 따라 LPWAN 배포 환경은 처리량을 낮추는 대신 수 킬로미터의 통신 범위와 수년간의 배터리 수명을 제공할 수 있습니다. 공급업체가 제시하는 통신 범위와 배터리 수명은 보장값이 아닌 설계 목표로 취급하세요.<sup>[[3]](#references)</sup>

Long Range(**LoRa**)는 현재 가장 널리 배포된 LPWAN 물리 계층이며, 개방형 MAC 계층 사양은 **LoRaWAN**입니다.

---

## LPWAN, LoRa, LoRaWAN

* LoRa – Semtech에서 개발한 Chirp Spread Spectrum(CSS) 물리 계층(독점 기술이지만 문서화되어 있음).
* LoRaWAN – LoRa-Alliance에서 관리하는 개방형 MAC/네트워크 계층. 현장에서는 1.0.x 및 1.1 버전이 일반적입니다.
* 일반적인 아키텍처: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> LoRaWAN 1.1에서는 **보안 모델**이 별도의 AES-128 애플리케이션 및 네트워크 루트 키를 사용해 OTAA 중 역할별 세션 키를 파생합니다. 이전 1.0.x 배포 환경에서는 일반적으로 하나의 AppKey로 네트워크 및 애플리케이션 세션 키를 파생하는 반면, ABP는 세션 키를 직접 프로비저닝합니다. 따라서 유출된 키로 얻을 수 있는 권한은 LoRaWAN 버전과 노출된 키에 따라 달라집니다.<sup>[[3]](#references)</sup>

---

## 공격 표면 요약

| 계층 | 취약점 | 실제 영향 |
|-------|----------|------------------|
| PHY | 반응형 / 선택적 재밍 | 국소적인 패킷 손실. 효과는 링크 버짓, 타이밍, 대역폭, 규제 제약에 따라 달라짐 |
| MAC | nonce/카운터 상태가 재사용될 때 조인 및 데이터 프레임 재전송 | 서버/기기가 재전송 방지 기능을 위반하면 기기 동기화 해제, 스푸핑 또는 인젝션 발생 |
| Network-Server | 안전하지 않은 packet-forwarder, 취약한 MQTT/UDP 필터, 오래된 게이트웨이 펌웨어 | 게이트웨이에서 RCE 발생 → OT/IT 네트워크로 피벗 |
| Application | 하드코딩되었거나 예측 가능한 AppKeys | 트래픽 Brute-force/복호화, 센서 사칭 |

---

## 대표적인 구현 취약점

* **CVE-2024-29862** – ChirpStack Gateway Bridge 4.0.11 이전 버전 및 MQTT Forwarder 4.2.1 이전 버전은 TLS 서버 인증서 검증이 비활성화되어 있어 공격자가 제어하는 MQTT broker에 연결될 수 있었습니다. 이로 인해 자격 증명과 게이트웨이 트래픽이 노출될 수 있으므로, 수정된 버전으로 업그레이드하세요.<sup>[[4]](#references)</sup>
* **Dragino LG01 펌웨어 4.3.4** – CVE-2022-45227은 다운로드 가능한 백업 파일이 포함된 인증되지 않은 `/lib/` 디렉터리 목록 노출을 설명합니다. CVE-2022-45228은 로그아웃 페이지의 심각도가 낮은 CSRF입니다. 이 기록만으로는 주장된 LG308 영향, 설정 덮어쓰기, 배포 규모 또는 2025년 패치 상태가 확인되지 않습니다.<sup>[[6]](#references)[[7]](#references)</sup>
* 이 페이지의 이전 버전은 Semtech UDP packet-forwarder의 문제로 알려진 내용을 **255바이트를 초과하는 조작된 업링크로 인해 SX130x 레퍼런스 게이트웨이에서 스택 스매시 및 RCE가 발생한다는 주장**으로 기술했습니다. 해당 내용은 Black Hat Europe 2023의 “LoRa Exploitation Reloaded” 발표와 2023년 10월 비공개 패치를 근거로 제시되었습니다. 구체적인 내용은 연구 단서로 남겨 두었지만, 이에 부합하는 공개 권고문, 발표 자료 또는 패치는 확인되지 않았습니다. 영향을 받는 제품/버전과 검증 가능한 1차 출처를 확보하기 전까지는 이를 알려진 취약점으로 간주하지 마세요.

---

## 실전 공격 기법

### 1. 트래픽 스니핑 및 복호화

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

These commands preserve the original workflow as **illustrative syntax**; repository layout and flags differ between projects/releases. Passive capture does not reveal a strong AppKey. Offline guessing is useful only when the root key is weak enough to be found and a captured join exchange provides a value that can validate candidates.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. OTAA replay protection 및 nonce 상태 테스트

1. 권한이 있는 테스트 네트워크에서 정상적인 **JoinRequest**를 캡처합니다.
2. 같은 request를 재전송하고, 네트워크 서버가 재사용된 `DevNonce`를 거부하는지 확인합니다.
3. 테스트 장치를 재부팅하거나 초기화한 뒤 검사를 반복하여 nonce 상태가 유실되는지 확인합니다. 규격을 준수하는 서버는 사용된 nonce를 추적해야 합니다. JoinRequest만 재전송해도 새로 파생된 세션 키가 노출되거나 재전송자가 세션을 제어할 수 있게 되지는 않습니다.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR) downgrading

네트워크 계층 MAC 명령을 인증할 수 있는 공격자(예: 해당 네트워크 세션 키 또는 네트워크 서버를 침해한 경우)는 비효율적인 데이터 전송률 매개변수를 강제하여 airtime을 늘리려 할 수 있습니다. 근처에 있는 인증되지 않은 송신자는 장치 주소만 안다고 해서 정당하게 ADR 명령을 보낼 수 없습니다.<sup>[[3]](#references)</sup>

### 4. Reactive jamming

Reactive jammer는 LoRa preamble을 감지한 뒤 송신하여 프레임을 선택적으로 방해할 수 있습니다. 이전 페이지에서는 HackRF/GNU Radio 구성으로 **2 km에서 200 mW 이하의 출력으로** 전체 서비스 중단을 일으켰다고 주장했지만, 이를 뒷받침하는 측정 출처는 제시되지 않았습니다. 해당 수치는 기대 결과가 아니라 재현 목표로만 유지하세요. 필요한 송신 전력, 타이밍, 대역폭, 영향을 받는 spreading factor 및 범위는 환경에 따라 달라집니다. 권한이 있는 RF 차폐 환경에서만 테스트하고 현지 전파 규정을 준수하세요.

---

## 공격 도구 (2025)

| 도구 | 목적 | 참고 사항 |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN 프레임 생성/파싱/공격, DB 기반 분석기, brute-forcer | Docker 이미지; Semtech UDP 입력 지원<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Trend Micro의 Python 유틸리티로 OTAA brute-force, downlink 생성, payload 복호화 수행 | 공개 연구용 유틸리티; 지원되는 하드웨어와 프로토콜 버전을 확인하세요<sup>[[2]](#references)</sup> |
| **LoRAttack** | 다중 채널 LoRaWAN 캡처, 세션 분석, 키 파생 및 replay 테스트를 위한 연구 프레임워크 | 2024년 석사 논문에서 설명됨; 예시 플래그를 신뢰하기 전에 정확한 구현을 확보하고 검증하세요<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | LoRa baseband 수신 또는 transceiver 연구를 위한 GNU Radio out-of-tree 블록 | 프로젝트마다 GNU Radio 호환성과 기능이 다릅니다<sup>[[9]](#references)</sup> |

---

## 방어 권고 사항 (pentester 체크리스트)

1. **OTAA**를 우선 사용하고, 장치와 서버가 필요한 nonce 상태를 영구 저장하는지 확인합니다. 거부된 중복 join을 모니터링합니다.
2. 지원되는 경우 **LoRaWAN 1.1**을 우선 사용하여 네트워크 기능에 서로 다른 세션 키와 개선된 nonce 처리를 적용합니다.<sup>[[3]](#references)</sup>
3. frame-counter를 비휘발성 메모리에 저장하거나(**ABP**) OTAA로 전환합니다.
4. 일반적인 firmware 저장소에서 root key가 노출될 위험을 줄이기 위해 적절한 **secure element**(예: 지원되는 설계에서 ATECC608A)를 적용합니다.
5. 설정된 packet-forwarder UDP listener(일반적으로 1700)를 신뢰할 수 없는 네트워크에 노출하지 않습니다. gateway backhaul을 인증/암호화하거나 VPN으로 제한합니다.
6. gateway에 공급업체가 지원하는 firmware를 유지하고, 해당 모델/버전을 관련 보안 권고와 대조해 확인합니다.
7. **트래픽 이상 탐지**(예: LAF analyzer)를 구현하여 counter 초기화, 중복 join, 갑작스러운 ADR 변경을 탐지합니다.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN 감사 프레임워크 (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN 개요](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 사양](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 지역별 매개변수 및 join 동기화](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU 논문 카탈로그 - SDR 기술을 활용한 LPWAN 프로토콜 보안 분석](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
