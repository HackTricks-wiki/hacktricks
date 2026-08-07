# Firmware 무결성

{{#include ../../banners/hacktricks-training.md}}

**custom firmware 및/또는 compiled binaries를 업로드하여 무결성 또는 signature verification 취약점을 exploit할 수 있습니다**. 다음 단계에 따라 backdoor bind shell compilation을 수행할 수 있습니다.

1. firmware는 firmware-mod-kit (FMK)를 사용하여 추출할 수 있습니다.
2. 대상 firmware의 architecture와 endianness를 식별해야 합니다.
3. Buildroot 또는 환경에 적합한 다른 방법을 사용하여 cross compiler를 빌드할 수 있습니다.
4. cross compiler를 사용하여 backdoor를 빌드할 수 있습니다.
5. backdoor를 추출한 firmware의 /usr/bin 디렉터리에 복사할 수 있습니다.
6. 적절한 QEMU binary를 추출한 firmware의 rootfs에 복사할 수 있습니다.
7. chroot와 QEMU를 사용하여 backdoor를 emulate할 수 있습니다.
8. netcat을 통해 backdoor에 접근할 수 있습니다.
9. 추출한 firmware의 rootfs에서 QEMU binary를 제거해야 합니다.
10. FMK를 사용하여 수정된 firmware를 다시 패키징할 수 있습니다.
11. firmware analysis toolkit (FAT)으로 emulate하고 netcat을 사용하여 대상 backdoor IP와 port에 연결하여 backdoored firmware를 테스트할 수 있습니다.

dynamic analysis, bootloader manipulation 또는 hardware security testing을 통해 이미 root shell을 획득했다면, implants 또는 reverse shells와 같은 precompiled malicious binaries를 실행할 수 있습니다. Metasploit framework 및 'msfvenom'과 같은 automated payload/implant tools는 다음 단계에 따라 활용할 수 있습니다.

1. 대상 firmware의 architecture와 endianness를 식별해야 합니다.
2. Msfvenom을 사용하여 target payload, attacker host IP, listening port number, filetype, architecture, platform 및 output file을 지정할 수 있습니다.
3. payload를 compromised device로 전송하고 execution permissions가 있는지 확인할 수 있습니다.
4. msfconsole을 시작하고 payload에 맞게 설정을 구성하여 incoming requests를 처리하도록 Metasploit을 준비할 수 있습니다.
5. compromised device에서 meterpreter reverse shell을 실행할 수 있습니다.

## 인증되지 않은 privileged update protocols에 대한 transport bridges

일반적인 embedded design 실수는 **여러 transport를 통해 동일한 internal command protocol을 노출하면서 그중 하나에만 authentication을 적용하는 것**입니다. 예를 들어 USB는 challenge-response를 요구하지만, BLE는 인증되지 않은 **GATT writes**를 동일한 privileged firmware-update handler로 단순 전달할 수 있습니다.<sup>[[1]](#references)</sup>

일반적인 offensive workflow:

1. BLE GATT database를 열거하고 official mobile app에서 사용하는 writable characteristics를 식별합니다.
2. app traffic을 sniff하고 wired protocol과 일치하는 **magic bytes / opcodes**를 찾습니다.
3. **pairing 없이** BLE를 통해 privileged commands를 replay하고 민감한 operations가 여전히 작동하는지 확인합니다.
4. firmware upgrade, config write, debug 또는 factory-test opcodes에 접근할 수 있다면 BLE를 **radio-reachable admin port**로 간주합니다.

빠른 점검 사항:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
리버싱 중 확인할 사항:

- BLE에 **pairing/bonding**이 필요한가, 아니면 단순 연결만 필요한가?
- 모든 transport가 동일한 내부 dispatcher table로 라우팅되는가?
- USB / BLE / UART / Wi-Fi에서 privileged opcode가 서로 다르게 필터링되는가?
- mobile app이 원격으로 firmware update, recovery 또는 diagnostic handler를 트리거할 수 있는가?

## Checksum-only firmware container도 여전히 attacker-controlled firmware다

**unkeyed checksum**(CRC32, SHA-256, MD5 등)만으로 보호되는 firmware container는 corruption detection을 제공할 뿐, **authenticity**는 제공하지 않는다. attacker가 update routine에 접근할 수 있다면 image를 patch하고 checksum을 다시 계산한 뒤 arbitrary code를 flash할 수 있다.<sup>[[1]](#references)</sup>

RE 중 red flag:

- Update code가 `CHK2`, `CRC` 또는 `SHA256`과 같은 trailing checksum blob만 검증한다.
- Signature verification 또는 secure-boot root of trust가 없다.
- Device-bound MAC / HMAC / authenticated encryption이 사용되지 않는다.
- Recovery mode가 동일한 unauthenticated image format을 허용한다.

실제 검증 흐름:

1. Firmware container를 추출하고 bootloader, main firmware 및 integrity metadata를 식별한다.
2. Image에서 무해한 문자열 또는 banner를 수정한다.
3. Updater가 예상하는 방식으로 checksum을 다시 계산한다.
4. Normal update path를 통해 image를 다시 flash한다.
5. 부팅 시 변경 사항을 확인하여 arbitrary firmware replacement를 입증한다.

이 과정이 BLE/Wi-Fi와 같이 원격 접근 가능한 transport를 통해 동작한다면, 이 bug는 사실상 **unauthenticated OTA firmware replacement**다.

## Firmware reflashing을 통해 trusted USB peripheral을 BadUSB로 전환하기

대상 device가 이미 USB를 통해 host에서 trusted 상태라면, malicious firmware가 완전히 새로운 USB stack을 구현할 필요는 없을 수 있다. 더 쉬운 pivot은 기존 HID support를 **재사용하는 것**인 경우가 많다.<sup>[[1]](#references)</sup>

유용한 pattern:

1. Device가 이미 **HID Consumer Control** / media / vendor HID interface로 enumerate되는지 확인한다.
2. Firmware에서 기존 **HID report descriptor**를 찾는다.
3. Descriptor entry를 추가하거나 교체하여 device가 **keyboard** capability도 advertise하도록 한다.
4. 새로운 transport implementation을 작성하는 대신, 이미 HID report를 전송하는 기존 firmware routine을 재사용한다.
5. Host에서 command를 입력하도록 key press + key release report를 inject한다.

이렇게 하면 PC가 reflashed peripheral을 legitimate keyboard로 신뢰하므로 firmware compromise가 **host compromise**로 이어진다.

### Minimal assessment checklist

- `dmesg`, Device Manager 또는 USB descriptor에 기존 HID interface가 표시되는가?
- Report descriptor 근처 또는 relocatable descriptor table에 여유 공간이 있는가?
- 기존 media-control send routine을 keyboard report에 재사용할 수 있는가?
- Reflashing 후 host가 새로운 keyboard interface를 자동으로 수락하는가?

## RTOS firmware 내부에서 안정적으로 payload 실행하기

무작위 code path에 취약한 trampoline을 삽입하는 대신, 정상 동작에서 사용되지 않거나 영향이 적은 **기존 RTOS task**를 찾는다.<sup>[[1]](#references)</sup>

유용한 이유:

- Scheduler가 boot 중 자연스럽게 payload를 시작한다.
- 중요한 control flow를 손상시키지 않는다.
- Latency-sensitive USB/network handler 내부에서 실행할 때보다 delayed payload가 watchdog reset을 유발할 가능성이 낮다.

좋은 대상은 정상 사용 중 dormant 상태로 보이는 diagnostic, factory-test, telemetry 또는 coprocessor service task다.

## 빠른 exploit iteration: benign protocol handler 용도 변경

Firmware patching이 가능해지면, RE를 가속하는 간결한 방법은 harmless command handler(예: **echo/debug opcode**)를 custom **memory read / write / execute** primitive로 덮어쓰는 것이다. 이렇게 하면 매 실험마다 전체 reflashing을 수행할 필요가 없으며, 수정된 handler를 fast wired transport를 통해 지원하는 device에서 특히 유용하다.<sup>[[1]](#references)</sup>

다음 작업에 사용한다:

- Scatter-loaded memory map 검증
- Heap/task state 실시간 검사
- Flash에 기록하기 전에 작은 payload 테스트
- Function pointer, string 및 descriptor table 안전하게 복구

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
