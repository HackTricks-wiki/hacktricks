# 펌웨어 무결성

{{#include ../../banners/hacktricks-training.md}}

authorized assessment에서 firmware-signature verification이 취약하거나 누락된 것으로 확인되면, 수정된 firmware image를 사용해 무결성에 미치는 영향을 입증할 수 있습니다. 다음 lab workflow는 기존 extraction, emulation, repacking 단계를 유지하면서 bind shell을 추가합니다.<sup>[[2]](#references)[[3]](#references)</sup>

1. firmware는 firmware-mod-kit (FMK)를 사용해 추출할 수 있습니다.
2. 대상 firmware의 architecture와 endianness를 식별해야 합니다.
3. Buildroot 또는 해당 환경에 적합한 다른 방법을 사용해 cross compiler를 빌드할 수 있습니다.
4. cross compiler를 사용해 backdoor를 빌드할 수 있습니다.
5. 추출된 firmware의 /usr/bin 디렉터리에 backdoor를 복사할 수 있습니다.
6. 적절한 QEMU binary를 추출된 firmware rootfs에 복사할 수 있습니다.
7. chroot와 QEMU를 사용해 backdoor를 emulate할 수 있습니다.
8. netcat을 통해 backdoor에 접근할 수 있습니다.
9. 추출된 firmware rootfs에서 QEMU binary를 제거해야 합니다.
10. FMK를 사용해 수정된 firmware를 다시 패키징할 수 있습니다.
11. firmware analysis toolkit (FAT)으로 emulation하고 netcat을 사용해 대상 backdoor IP와 port에 연결하여 backdoored firmware를 테스트할 수 있습니다.

dynamic analysis, bootloader manipulation 또는 hardware security testing을 통해 이미 root shell을 획득한 경우, implants나 reverse shells와 같은 precompiled test binaries를 실행할 수 있습니다. Metasploit의 `msfvenom`은 이 validation workflow를 위한 architecture-specific payload를 생성할 수 있습니다.<sup>[[4]](#references)</sup>

1. 대상 firmware의 architecture와 endianness를 식별해야 합니다.
2. Msfvenom을 사용해 target payload, attacker host IP, listening port number, filetype, architecture, platform 및 output file을 지정할 수 있습니다.
3. payload를 compromised device로 전송하고 execution permissions가 있는지 확인할 수 있습니다.
4. msfconsole을 시작하고 payload에 맞게 설정을 구성하여 incoming requests를 처리하도록 Metasploit을 준비할 수 있습니다.
5. compromised device에서 meterpreter reverse shell을 실행할 수 있습니다.

## 인증되지 않은 privileged update protocol용 transport bridge

일반적인 embedded design 실수는 **동일한 internal command protocol을 여러 transport를 통해 노출**하면서, 그중 하나에만 authentication을 적용하는 것입니다. 예를 들어 USB에는 challenge-response가 필요하지만 BLE는 인증되지 않은 **GATT writes**를 동일한 privileged firmware-update handler로 단순 전달할 수 있습니다.<sup>[[1]](#references)</sup>

일반적인 offensive workflow:

1. BLE GATT database를 열거하고 official mobile app에서 사용하는 writable characteristics를 식별합니다.
2. app traffic을 sniff하고 wired protocol과 일치하는 **magic bytes / opcodes**를 찾습니다.
3. **pairing 없이** BLE를 통해 privileged commands를 replay하고 민감한 operations가 여전히 작동하는지 확인합니다.
4. firmware upgrade, config write, debug 또는 factory-test opcodes에 접근할 수 있다면 BLE를 **radio-reachable admin port**로 간주합니다.

빠른 점검:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Things to verify while reversing:

- BLE에 **pairing/bonding**이 필요한가, 아니면 단순한 연결만 필요한가?
- 모든 transport가 동일한 internal dispatcher table로 라우팅되는가?
- privileged opcode가 USB / BLE / UART / Wi-Fi에서 서로 다르게 필터링되는가?
- mobile app이 원격으로 firmware update, recovery 또는 diagnostic handler를 트리거할 수 있는가?

## Checksum-only firmware containers are still attacker-controlled firmware

**unkeyed checksum**(CRC32, SHA-256, MD5 등)만으로 보호되는 firmware container는 corruption detection을 제공할 뿐, **authenticity**를 보장하지 않는다. 공격자가 update routine에 도달할 수 있다면 image를 patch하고 checksum을 재계산한 다음 임의의 code를 flash할 수 있다.<sup>[[1]](#references)</sup>

RE 중 red flag:

- Update code가 `CHK2`, `CRC` 또는 `SHA256` 같은 trailing checksum blob만 검증한다.
- Signature verification 또는 secure-boot root of trust가 존재하지 않는다.
- Device-bound MAC / HMAC / authenticated encryption이 사용되지 않는다.
- Recovery mode가 동일한 unauthenticated image format을 허용한다.

Practical validation flow:

1. Firmware container를 extract하고 bootloader, main firmware 및 integrity metadata를 식별한다.
2. Image에서 무해한 string 또는 banner를 수정한다.
3. Updater가 예상하는 방식으로 checksum을 정확히 재계산한다.
4. Normal update path를 통해 image를 reflash한다.
5. Boot 시 변경 사항을 확인하여 임의의 firmware replacement를 입증한다.

BLE/Wi-Fi처럼 원격 접근 가능한 transport에서 이것이 동작한다면, 해당 bug는 사실상 **unauthenticated OTA firmware replacement**이다.

## Turning a trusted USB peripheral into BadUSB via firmware reflashing

Target device가 이미 USB를 통해 host에서 trusted 상태라면, malicious firmware가 완전히 새로운 USB stack을 구현할 필요는 없을 수 있다. 훨씬 쉬운 pivot은 기존 HID support를 **reuse**하는 것이다.<sup>[[1]](#references)</sup>

Useful pattern:

1. Device가 이미 **HID Consumer Control** / media / vendor HID interface로 enumerate되는지 확인한다.
2. Firmware에서 기존 **HID report descriptor**를 찾는다.
3. Descriptor entry를 append 또는 replace하여 device가 **keyboard** capability도 advertise하도록 한다.
4. 새로운 transport implementation을 작성하는 대신, 이미 HID report를 전송하는 기존 firmware routine을 reuse한다.
5. Host에서 command를 입력하도록 key press + key release report를 inject한다.

이렇게 하면 PC가 reflashed peripheral을 legitimate keyboard로 trust하므로 firmware compromise가 **host compromise**로 이어진다.

### Minimal assessment checklist

- `dmesg`, Device Manager 또는 USB descriptor에 기존 HID interface가 표시되는가?
- Report descriptor 근처 또는 relocatable descriptor table에 여유 공간이 있는가?
- 기존 media-control send routine을 keyboard report에 재사용할 수 있는가?
- Reflash 후 host가 새로운 keyboard interface를 자동으로 accept하는가?

## Reliable payload execution inside RTOS firmware

Random code path에 fragile trampoline을 삽입하는 대신, 정상 동작에서 사용되지 않거나 영향이 적은 **existing RTOS task**를 찾아라.<sup>[[1]](#references)</sup>

Why this is useful:

- Scheduler가 boot 중 자연스럽게 payload를 시작한다.
- Critical control flow를 손상시키는 일을 피할 수 있다.
- Latency-sensitive USB/network handler 내부에서 실행할 때보다 delayed payload가 watchdog reset을 유발할 가능성이 낮다.

Good target은 정상 사용 중 dormant 상태로 보이는 diagnostic, factory-test, telemetry 또는 coprocessor service task다.

## Fast exploit iteration: repurpose benign protocol handlers

Firmware patching이 가능해지면 RE를 가속하는 간결한 방법은 harmless command handler(예: **echo/debug opcode**)를 custom **memory read / write / execute** primitive로 overwrite하는 것이다. 이렇게 하면 모든 실험마다 full reflashing을 수행할 필요가 없으며, modified handler를 fast wired transport를 통해 지원하는 device에서 특히 유용하다.<sup>[[1]](#references)</sup>

Use this to:

- Scatter-loaded memory map을 검증한다
- Heap/task state를 live로 inspect한다
- Flash에 기록하기 전에 small payload를 테스트한다
- Function pointer, string 및 descriptor table을 안전하게 복구한다

## References

- [1] [Pwnd Blaster: speaker를 전혀 만지지 않고 speaker를 사용해 PC를 해킹하기](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - `msfvenom` 사용 방법](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
