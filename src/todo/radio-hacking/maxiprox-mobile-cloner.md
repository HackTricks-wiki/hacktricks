# 휴대용 HID MaxiProx 125 kHz Mobile Cloner 제작

{{#include ../../banners/hacktricks-training.md}}

## 목표
상용 전원으로 작동하는 HID MaxiProx 5375 장거리 125 kHz 리더를 현장에 배치할 수 있는 배터리 구동식 badge cloner로 개조하여, physical-security assessment 중 proximity card를 조용히 수집합니다.

여기서 다루는 개조는 TrustedSec의 “Let’s Clone a Cloner – Part 3: Putting It All Together” research series를 기반으로 하며, 최종 장치를 배낭에 넣고 현장에서 즉시 사용할 수 있도록 기계적, 전기적 및 RF 관련 사항을 결합합니다.<sup>[[1]](#references)</sup>

> [!warning]
> 상용 전원 장비와 Lithium-ion power-bank를 다루는 작업은 위험할 수 있습니다. 회로에 **전원을 공급하기 전에** 모든 연결을 확인하고, 리더의 detuning을 방지하기 위해 안테나, coax 및 ground plane을 factory design과 정확히 동일하게 유지하십시오.

## 자재 목록 (BOM)

* HID MaxiProx 5375 reader (또는 모든 12 V HID Prox® long-range reader)
* ESP RFID Tool v2.2 (ESP32 기반 Wiegand sniffer/logger)
* 12 V @ ≥3 A를 negotiate할 수 있는 USB-PD (Power-Delivery) trigger module
* 100 W USB-C power-bank (12 V PD profile 출력)
* 26 AWG silicone-insulated hook-up wire – red/white
* Panel-mount SPST toggle switch (beeper kill-switch용)
* NKK AT4072 switch-guard / accident-proof cap
* Soldering iron, solder wick 및 desolder pump
* ABS-rated hand tools: coping-saw, utility-knife, flat 및 half-round file
* 1/16″ (1.5 mm) 및 1/8″ (3 mm) drill bit
* 3 M VHB double-sided tape 및 Zip-tie

## 1. Power Sub-System

1. Logic PCB에 5 V를 생성하는 데 사용되는 factory buck-converter daughter-board를 desolder하고 제거합니다.
2. ESP RFID Tool 옆에 USB-PD trigger를 장착하고 trigger의 USB-C receptacle을 enclosure 외부로 연결합니다.
3. PD trigger는 power-bank에서 12 V를 negotiate하여 MaxiProx에 직접 공급합니다(reader는 기본적으로 10–14 V를 요구함). 보조 5 V rail은 ESP board에서 가져와 accessories에 전원을 공급합니다.
4. 100 W battery pack은 internal standoff에 밀착되도록 배치하여 **어떠한** power cable도 ferrite antenna 위로 늘어지지 않게 하고 RF performance를 유지합니다.

## 2. Beeper Kill-Switch – Silent Operation

1. MaxiProx logic board에서 두 speaker pad를 찾습니다.
2. *두* pad를 깨끗하게 wick한 다음 **negative** pad만 다시 solder합니다.
3. 26 AWG wire(white = negative, red = positive)를 beeper pad에 solder하고, 새로 절단한 slot을 통해 panel-mount SPST switch로 연결합니다.
4. Switch가 open이면 beeper circuit이 끊기고 reader가 완전히 무음으로 작동하므로 covert badge harvesting에 적합합니다.
5. Toggle 위에 NKK AT4072 spring-loaded safety cap을 장착합니다. Coping-saw / file로 bore를 조심스럽게 넓혀 switch body에 끼워질 때까지 작업합니다. Guard는 배낭 안에서 실수로 작동하는 것을 방지합니다.

## 3. Enclosure & Mechanical Work

• Flush cutter를 사용한 다음 knife와 file로 내부 ABS “bump-out”을 *제거*하여 대형 USB-C battery가 standoff에 평평하게 놓이도록 합니다.
• USB-C cable을 위한 두 개의 평행한 channel을 enclosure wall에 파서 battery를 제자리에 고정하고 움직임/vibration을 제거합니다.
• Battery의 **power** button을 위한 직사각형 aperture를 만듭니다:
1. 위치 위에 종이 stencil을 tape으로 고정합니다.
2. 네 모서리 모두에 1/16″ pilot hole을 뚫습니다.
3. 1/8″ bit으로 넓힙니다.
4. Coping saw로 hole을 연결하고 file로 가장자리를 마무리합니다.
✱  Rotary Dremel은 *사용하지 않았습니다* – 고속 bit이 두꺼운 ABS를 녹여 보기 좋지 않은 edge를 남깁니다.

## 4. Final Assembly

1. MaxiProx logic board를 다시 장착하고 SMA pigtail을 reader PCB의 ground pad에 다시 solder합니다.
2. 3 M VHB를 사용하여 ESP RFID Tool과 USB-PD trigger를 장착합니다.
3. 모든 wiring을 zip-tie로 정리하고 power lead를 antenna loop에서 **멀리** 유지합니다.
4. Battery가 가볍게 눌릴 때까지 enclosure screw를 조입니다. 내부 friction이 장치를 고정하여 매 card read 후 device가 recoil할 때 pack이 움직이지 않도록 합니다.

## 5. Range & Shielding Tests

* 125 kHz **Pupa** test card를 사용했을 때 portable cloner는 free-air에서 **약 8 cm**의 일관된 read를 달성했으며, 이는 mains-powered operation과 동일합니다.<sup>[[1]](#references)</sup>
* Reader를 얇은 벽의 metal cash box 안에 넣어(은행 lobby desk를 시뮬레이션) 테스트한 결과 range가 ≤ 2 cm로 감소했으며, 상당한 metal enclosure가 효과적인 RF shield로 작동한다는 점을 확인했습니다.<sup>[[1]](#references)</sup>

## Usage Workflow

1. USB-C battery를 충전하고 연결한 다음 main power switch를 켭니다.
2. (선택 사항) Bench-testing 중 audible feedback을 활성화하려면 beeper guard를 열고, covert field use 전에 다시 잠급니다.
3. Target badge holder 옆을 지나가면 MaxiProx가 card에 energy를 공급하고 ESP RFID Tool이 Wiegand stream을 capture합니다.
4. Wi-Fi 또는 USB-UART를 통해 captured credential을 dump한 다음 필요에 따라 replay/clone합니다.

## Troubleshooting

| 증상 | 가능한 원인 | 해결 방법 |
|---------|--------------|------|
| Card를 제시할 때 reader가 reboot됨 | PD trigger가 9 V를 negotiate하고 12 V를 negotiate하지 않음 | Trigger jumper를 확인하거나 더 높은 power 등급의 USB-C cable을 사용 |
| Read range가 없음 | Battery 또는 wiring이 antenna *위에* 놓임 | Cable을 다시 연결하고 ferrite loop 주변에 2 cm clearance를 유지 |
| Beeper가 계속 chirp함 | Positive lead에 switch를 연결함 | Kill-switch를 **negative** speaker trace를 끊도록 이동 |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
