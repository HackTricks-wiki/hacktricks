# 사이드 채널 분석 공격

{{#include ../../banners/hacktricks-training.md}}

사이드 채널 공격은 내부 상태와 *상관관계*가 있지만 장치의 논리적 인터페이스의 일부가 아닌 물리적 또는 마이크로 아키텍처 "누출"을 관찰하여 비밀을 복구합니다. 예를 들어, 스마트 카드가 소모하는 순간 전류를 측정하는 것부터 네트워크를 통한 CPU 전력 관리 효과를 악용하는 것까지 다양합니다.

---

## 주요 누출 채널

| 채널 | 일반적인 대상 | 계측 |
|---------|---------------|-----------------|
| 전력 소비 | 스마트 카드, IoT MCU, FPGA | 오실로스코프 + 션트 저항기/HS 프로브 (예: CW503) |
| 전자기장 (EM) | CPU, RFID, AES 가속기 | H-필드 프로브 + LNA, ChipWhisperer/RTL-SDR |
| 실행 시간 / 캐시 | 데스크탑 및 클라우드 CPU | 고정밀 타이머 (rdtsc/rdtscp), 원격 비행 시간 |
| 음향 / 기계적 | 키보드, 3D 프린터, 릴레이 | MEMS 마이크, 레이저 진동계 |
| 광학 및 열 | LED, 레이저 프린터, DRAM | 포토다이오드 / 고속 카메라, IR 카메라 |
| 결함 유도 | ASIC/MCU 암호 | 클럭/전압 글리치, EMFI, 레이저 주입 |

---

## 전력 분석

### 단순 전력 분석 (SPA)
*단일* 트레이스를 관찰하고 피크/골짜기를 작업(예: DES S-박스)과 직접 연관시킵니다.
```python
# ChipWhisperer-husky example – capture one AES trace
from chipwhisperer.capture.api.programmers import STMLink
from chipwhisperer.capture import CWSession
cw = CWSession(project='aes')
trig = cw.scope.trig
cw.connect(cw.capture.scopes[0])
cw.capture.init()
trace = cw.capture.capture_trace()
print(trace.wave)  # numpy array of power samples
```
### Differential/Correlation Power Analysis (DPA/CPA)
*N > 1 000* 트레이스를 수집하고, 키 바이트 `k`를 가정하며, HW/HD 모델을 계산하고 누출과 상관관계를 분석합니다.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA는 여전히 최첨단이지만 기계 학습 변형(MLA, 딥 러닝 SCA)이 이제 ASCAD-v2(2023)와 같은 대회에서 지배적입니다.

---

## 전자기 분석 (EMA)
근거리 EM 프로브(500 MHz–3 GHz)는 션트를 삽입하지 않고도 전력 분석과 동일한 정보를 누출합니다. 2024년 연구에서는 스펙트럼 상관관계와 저비용 RTL-SDR 프론트 엔드를 사용하여 **>10 cm** 거리에서 STM32의 키 복구를 입증했습니다.

---

## 타이밍 및 마이크로 아키텍처 공격
현대 CPU는 공유 자원을 통해 비밀을 누출합니다:
* **Hertzbleed (2022)** – DVFS 주파수 스케일링이 해밍 가중치와 상관관계가 있어 *원격*으로 EdDSA 키를 추출할 수 있습니다.
* **Downfall / Gather Data Sampling (Intel, 2023)** – SMT 스레드를 통해 AVX-gather 데이터를 읽기 위한 일시적 실행.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – 추측 벡터 잘못 예측이 도메인 간 레지스터를 누출합니다.

Spectre 클래스 문제에 대한 폭넓은 설명은 {{#ref}}
../../cpu-microarchitecture/microarchitectural-attacks.md
{{#endref}}를 참조하십시오.

---

## 음향 및 광학 공격
* 2024년 "iLeakKeys"는 CNN 분류기를 사용하여 **스마트폰 마이크를 통해 Zoom에서** 노트북 키스트로크를 95% 정확도로 복구했습니다.
* 고속 포토다이오드는 DDR4 활동 LED를 캡처하고 <1분 이내에 AES 라운드 키를 재구성합니다(BlackHat 2023).

---

## 결함 주입 및 차별적 결함 분석 (DFA)
결함과 사이드 채널 누출을 결합하면 키 검색이 단축됩니다(예: 1-트레이스 AES DFA). 최근 취미 가격의 도구:
* **ChipSHOUTER & PicoEMP** – 1 ns 미만의 전자기 펄스 글리치.
* **GlitchKit-R5 (2025)** – RISC-V SoC를 지원하는 오픈 소스 클럭/전압 글리치 플랫폼.

---

## 전형적인 공격 워크플로우
1. 누출 채널 및 장착 지점 식별(VCC 핀, 디커플링 커패시터, 근거리 지점).
2. 트리거 삽입(GPIO 또는 패턴 기반).
3. 적절한 샘플링/필터로 >1 k 트레이스 수집.
4. 전처리(정렬, 평균 제거, LP/HP 필터, 웨이브렛, PCA).
5. 통계적 또는 ML 키 복구(CPA, MIA, DL-SCA).
6. 이상치 검증 및 반복.

---

## 방어 및 강화
* **상수 시간** 구현 및 메모리 하드 알고리즘.
* **마스킹/셔플링** – 비밀을 무작위 공유로 분할; TVLA에 의해 인증된 1차 저항.
* **은폐** – 온칩 전압 조절기, 무작위화된 클럭, 이중 레일 논리, EM 차폐.
* **결함 감지** – 중복 계산, 임계값 서명.
* **운영** – 암호 커널에서 DVFS/터보 비활성화, SMT 격리, 다중 임대 클라우드에서 공동 위치 금지.

---

## 도구 및 프레임워크
* **ChipWhisperer-Husky** (2024) – 500 MS/s 스코프 + Cortex-M 트리거; 위와 같은 Python API.
* **Riscure Inspector & FI** – 상업용, 자동 누출 평가 지원(TVLA-2.0).
* **scaaml** – TensorFlow 기반 딥 러닝 SCA 라이브러리(v1.2 – 2025).
* **pyecsca** – ANSSI 오픈 소스 ECC SCA 프레임워크.

---

## 참고 문헌

* [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
