# 펌웨어 무결성

{{#include ../../banners/hacktricks-training.md}}

승인된 평가에서 펌웨어 서명 검증이 취약하거나 누락된 것을 확인한 경우, 수정된 펌웨어 이미지로 무결성에 미치는 영향을 입증할 수 있습니다. 다음 실습 워크플로에서는 원래의 추출, 에뮬레이션, 재패키징 단계를 유지하면서 bind shell을 추가합니다.<sup>[[2]](#references)[[3]](#references)</sup>

1. firmware-mod-kit (FMK)을 사용해 펌웨어를 추출할 수 있습니다.
2. 대상 펌웨어의 아키텍처와 엔디언을 식별해야 합니다.
3. Buildroot 또는 해당 환경에 적합한 다른 방법으로 크로스 컴파일러를 빌드할 수 있습니다.
4. 크로스 컴파일러를 사용해 백도어를 빌드할 수 있습니다.
5. 추출한 펌웨어의 /usr/bin 디렉터리에 백도어를 복사할 수 있습니다.
6. 적절한 QEMU 바이너리를 추출한 펌웨어의 rootfs에 복사할 수 있습니다.
7. chroot와 QEMU를 사용해 백도어를 에뮬레이션할 수 있습니다.
8. netcat을 통해 백도어에 접속할 수 있습니다.
9. 추출한 펌웨어의 rootfs에서 QEMU 바이너리를 제거해야 합니다.
10. FMK를 사용해 수정된 펌웨어를 재패키징할 수 있습니다.
11. firmware analysis toolkit (FAT)으로 백도어가 포함된 펌웨어를 에뮬레이션하고, netcat을 사용해 대상 백도어의 IP와 포트에 연결하여 테스트할 수 있습니다.

동적 분석, 부트로더 조작 또는 하드웨어 보안 테스트를 통해 이미 root shell을 획득했다면, implants 또는 reverse shells 같은 사전 컴파일된 테스트 바이너리를 실행할 수 있습니다. Metasploit의 `msfvenom`은 이 검증 워크플로에 사용할 아키텍처별 페이로드를 생성할 수 있습니다.<sup>[[4]](#references)</sup>

1. 대상 펌웨어의 아키텍처와 엔디언을 식별해야 합니다.
2. Msfvenom을 사용해 대상 페이로드, 공격자 호스트 IP, 리스닝 포트 번호, 파일 형식, 아키텍처, 플랫폼 및 출력 파일을 지정할 수 있습니다.
3. 페이로드를 침해된 기기로 전송하고 실행 권한이 있는지 확인할 수 있습니다.
4. msfconsole을 시작하고 페이로드에 맞게 설정을 구성하여 Metasploit이 수신 요청을 처리하도록 준비할 수 있습니다.
5. 침해된 기기에서 meterpreter reverse shell을 실행할 수 있습니다.

## 권한 있는 업데이트 프로토콜로 연결되는 인증되지 않은 전송 브리지

흔히 발생하는 임베디드 설계 실수는 **여러 전송 수단에서 동일한 내부 명령 프로토콜을 노출하면서** 그중 하나에만 인증을 적용하는 것입니다. 예를 들어 USB에서는 challenge-response를 요구하지만, BLE는 인증되지 않은 **GATT 쓰기**를 동일한 권한 있는 펌웨어 업데이트 핸들러로 전달할 수 있습니다.<sup>[[1]](#references)</sup>

일반적인 공격 워크플로:

1. BLE GATT 데이터베이스를 열거하고 공식 모바일 앱에서 사용하는 쓰기 가능한 characteristic을 식별합니다.
2. 앱 트래픽을 스니핑하여 유선 프로토콜과 일치하는 **magic bytes / opcodes**를 찾습니다.
3. **페어링 없이** BLE를 통해 권한 있는 명령을 재전송하고 민감한 작업이 여전히 동작하는지 확인합니다.
4. 펌웨어 업그레이드, 구성 쓰기, 디버그 또는 공장 테스트 opcode에 접근할 수 있다면 BLE를 **무선으로 접근 가능한 관리자 포트**로 간주합니다.

빠른 점검:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

역공학 중 확인할 사항:

- BLE 연결에 **pairing/bonding**이 필요한가, 아니면 단순 연결만으로 충분한가?
- 모든 전송 경로가 동일한 내부 디스패처 테이블로 라우팅되는가?
- USB / BLE / UART / Wi-Fi에서 권한이 높은 opcode를 서로 다르게 필터링하는가?
- 모바일 앱이 원격으로 firmware 업데이트, 복구 또는 진단 핸들러를 실행할 수 있는가?

## 체크섬만 사용하는 firmware 컨테이너도 여전히 공격자가 제어할 수 있는 firmware다

**키가 없는 체크섬**(CRC32, SHA-256, MD5 등)만으로 보호하는 firmware 컨테이너는 손상 여부를 탐지할 뿐, **진위를 검증하지는 않는다**. 공격자가 업데이트 루틴에 접근할 수 있다면 이미지를 패치하고 체크섬을 다시 계산한 다음 임의의 코드를 플래시할 수 있다.<sup>[[1]](#references)</sup>

RE 중 확인할 위험 신호:

- 업데이트 코드가 `CHK2`, `CRC`, `SHA256` 같은 후행 체크섬 블롭만 검증한다.
- 서명 검증이나 secure-boot 신뢰 기반이 없다.
- 기기에 종속된 MAC / HMAC / 인증 암호화를 사용하지 않는다.
- 복구 모드에서 동일한 미인증 이미지 형식을 허용한다.

실제 검증 절차:

1. firmware 컨테이너를 추출하고 bootloader, 메인 firmware, 무결성 메타데이터를 식별한다.
2. 이미지의 무해한 문자열이나 배너를 수정한다.
3. 업데이터가 예상하는 방식 그대로 체크섬을 다시 계산한다.
4. 일반 업데이트 경로를 통해 이미지를 다시 플래시한다.
5. 부팅 후 변경 사항을 확인해 임의의 firmware 교체가 가능함을 입증한다.

BLE/Wi-Fi처럼 원격으로 접근 가능한 전송 경로를 통해 이 작업이 가능하다면, 사실상 **인증되지 않은 OTA firmware 교체** 취약점이다.

## 분할된 업데이트 상태와 쓰기 가능한 무결성 메타데이터

업데이터가 설치 중에는 서명된 firmware 헤더를 검증하더라도, 부팅 시 저장된 무결성 해시만으로 이미지를 검증할 수 있다. Cypherock X1에서 Bootloader는 별도의 Firewall task를 호출해 헤더를 검증하고 버전/크기를 RAM에 저장하고, firmware 서명을 RAM에 저장하고, 기록된 이미지를 검증한 뒤, 마지막으로 이미지를 해시해 영구 Primary Bootloader Data에 저장했다. 서명 자체는 영구 저장되지 않았다. 이러한 task들은 하나의 인증된 업그레이드 트랜잭션으로 강제되지 않고 서로 독립적으로 호출될 수 있었다.<sup>[[5]](#references)</sup>

MCU 코드 실행 및 Flash 쓰기 권한이 있을 때, 보고된 공격은 애플리케이션 이미지를 다시 쓰고 Bootloader와 Firewall이 공유하는 RAM의 버전/크기 값을 변경한 다음, 마지막 메타데이터 task를 호출해 악성 이미지의 해시를 저장하고 정상 부팅 상태를 복원했다. 일반 부팅 무결성 검사는 서명을 다시 확인하지 않고 해당 해시를 승인했다. 유사한 업데이터를 검토할 때는 **각 task를 호출할 수 있는 구성요소**, 검증된 값이 저장되는 위치, 그리고 부팅 시 결정 과정에서 저장된 해시와 *동일한 이미지*가 인증되는지를 추적한다. 이는 체크섬만 사용하는 이미지 형식보다 범위가 좁은 문제다. 서명 검증은 존재했지만, 상태 전환이 그 검증에 묶여 있지 않았다.<sup>[[5]](#references)</sup>

## 신뢰할 수 없는 firmware 측정값에 대한 secure element 서명

secure element는 firmware가 제공한 해시에 서명한다는 이유만으로 실행 중인 코드를 증명하지 않는다. 같은 wallet에서 secure element는 기기 일련번호에 서명한 다음, MCU를 통해 제공된 cloud nonce와 firmware 해시의 XOR 값에도 서명했다. 침해된 firmware는 실제로 다른 바이트를 실행하면서 서명 대상으로 예상 해시를 제시할 수 있었다. 동반 클라이언트도 firmware 버전을 cloud에 제출했으므로, 검증자의 예상 해시 비교는 Flash를 독립적으로 읽은 측정값이 아니라 여전히 MCU에서 제공한 측정값에 의존했다.<sup>[[5]](#references)</sup>

기기 측 결과는 별도의 신뢰 경계였다. cloud는 기기를 확인했지만, 기기는 cloud의 판정을 인증하지 않았다. 수정된 클라이언트는 변조된 기기에 로컬 성공을 보고할 수 있었다. 측정값의 출처와 응답 인증을 각각 테스트한다. 유효한 secure-element 서명과 성공 화면만으로는 설치된 애플리케이션의 진위를 입증할 수 없다.<sup>[[5]](#references)</sup>

이 업데이터 분석을 가능하게 한 보호 코드 공개 사례는 [Firewall copy-task firmware acquisition](index.html#disclosing-protected-code-through-a-firewall-copy-task)을 참조한다.<sup>[[5]](#references)</sup>

## 신뢰받는 USB 주변 장치를 firmware 재플래시로 BadUSB로 전환하기

대상 기기가 이미 USB를 통해 호스트에서 신뢰받는 상태라면, 악성 firmware에 완전히 새로운 USB stack을 구현할 필요가 없을 수 있다. 훨씬 쉬운 우회 방법은 기존 HID 지원을 **재사용하는 것**인 경우가 많다.<sup>[[1]](#references)</sup>

유용한 패턴:

1. 기기가 이미 **HID Consumer Control** / 미디어 / vendor HID 인터페이스로 열거되는지 확인한다.
2. firmware에서 기존 **HID report descriptor**를 찾는다.
3. descriptor 항목을 추가하거나 교체해 기기가 **keyboard** 기능도 광고하도록 한다.
4. 새 전송 구현을 작성하는 대신, 이미 HID report를 전송하는 기존 firmware 루틴을 재사용한다.
5. key press + key release report를 주입해 호스트에서 명령어를 입력한다.

이렇게 하면 PC가 재플래시된 주변 장치를 정상적인 keyboard로 신뢰하므로, firmware 침해가 **호스트 침해**로 이어진다.

### 최소 점검 목록

- `dmesg`, Device Manager 또는 USB descriptor에서 기존 HID 인터페이스가 확인되는가?
- report descriptor 주변에 여유 공간이 있거나 재배치 가능한 descriptor 테이블이 있는가?
- 기존 미디어 제어 전송 루틴을 keyboard report에 재사용할 수 있는가?
- 재플래시 후 호스트가 새 keyboard 인터페이스를 자동으로 수락하는가?

## RTOS firmware에서 안정적으로 payload 실행하기

임의의 코드 경로에 취약한 trampoline을 삽입하는 대신, 일반 동작 중 사용되지 않거나 영향이 적은 **기존 RTOS task**를 찾는다.<sup>[[1]](#references)</sup>

유용한 이유:

- 스케줄러가 부팅 시 payload를 자연스럽게 시작한다.
- 중요한 제어 흐름을 손상시키지 않는다.
- 지연 실행 payload는 지연 시간에 민감한 USB/network 핸들러 내부에서 실행할 때보다 watchdog reset을 유발할 가능성이 낮다.

일반 사용 중에는 휴면 상태인 진단, 공장 테스트, telemetry 또는 coprocessor 서비스 task가 적절한 대상이다.

## 빠른 exploit 반복: 무해한 프로토콜 핸들러 재활용하기

firmware 패치가 가능해지면, RE 속도를 높이는 간단한 방법은 무해한 명령 핸들러(예: **echo/debug opcode**)를 사용자 지정 **memory read / write / execute** primitive로 덮어쓰는 것이다. 이렇게 하면 매 실험마다 전체 재플래시를 하지 않아도 되며, 특히 기기가 수정된 핸들러를 빠른 유선 전송 경로에서 지원할 때 유용하다.<sup>[[1]](#references)</sup>

이를 사용해 다음을 수행한다:

- scatter-loaded 메모리 맵 확인
- heap/task 상태를 실시간으로 검사
- flash에 기록하기 전에 소규모 payload 테스트
- 함수 포인터, 문자열, descriptor 테이블 안전하게 복구

## References

- [1] [Pwnd Blaster: 스피커를 이용해 PC를 해킹하는 방법—기기에 손대지 않고](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - `msfvenom` 사용 방법](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [Cypherock 하드웨어 wallet을 해킹한 방법과 이유: 전체 이야기](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
