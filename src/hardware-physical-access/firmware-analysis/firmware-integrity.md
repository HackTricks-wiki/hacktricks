# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

**custom firmware 및/또는 compiled binaries는 integrity 또는 signature verification 취약점을 악용하기 위해 업로드될 수 있습니다**. backdoor bind shell 컴파일을 위해 다음 단계를 따를 수 있습니다:

1. firmware는 firmware-mod-kit (FMK)을 사용하여 추출할 수 있습니다.
2. 대상 firmware architecture와 endianness를 식별해야 합니다.
3. cross compiler는 Buildroot 또는 환경에 적합한 다른 방법을 사용하여 빌드할 수 있습니다.
4. backdoor는 cross compiler를 사용하여 빌드할 수 있습니다.
5. backdoor는 추출된 firmware의 /usr/bin 디렉터리에 복사할 수 있습니다.
6. 적절한 QEMU binary는 추출된 firmware rootfs에 복사할 수 있습니다.
7. backdoor는 chroot와 QEMU를 사용하여 emulation할 수 있습니다.
8. backdoor는 netcat으로 접근할 수 있습니다.
9. QEMU binary는 추출된 firmware rootfs에서 제거해야 합니다.
10. 수정된 firmware는 FMK를 사용하여 repackaging할 수 있습니다.
11. backdoored firmware는 firmware analysis toolkit (FAT)로 emulating한 뒤 netcat을 사용하여 대상 backdoor IP와 port에 연결해 테스트할 수 있습니다.

dynamic analysis, bootloader manipulation, 또는 hardware security testing을 통해 이미 root shell을 얻었다면, implants나 reverse shells 같은 precompiled malicious binaries를 실행할 수 있습니다. Metasploit framework와 'msfvenom' 같은 자동화된 payload/implant 도구는 다음 단계를 사용하여 활용할 수 있습니다:

1. 대상 firmware architecture와 endianness를 식별해야 합니다.
2. Msfvenom을 사용하여 대상 payload, attacker host IP, listening port number, filetype, architecture, platform, 그리고 output file을 지정할 수 있습니다.
3. payload는 compromised device로 전송할 수 있으며 실행 권한이 있는지 확인해야 합니다.
4. Metasploit은 msfconsole을 시작하고 payload에 맞게 설정을 구성하여 들어오는 요청을 처리할 준비를 할 수 있습니다.
5. meterpreter reverse shell은 compromised device에서 실행할 수 있습니다.

## Unauthenticated transport bridges to privileged update protocols

일반적인 embedded 설계 실수는 **여러 transport에 걸쳐 동일한 internal command protocol을 노출**하면서, 그중 하나에만 authentication을 적용하는 것입니다. 예를 들어, USB는 challenge-response를 요구하지만 BLE는 인증되지 않은 **GATT writes**를 같은 privileged firmware-update handler로 그대로 전달할 수 있습니다.

일반적인 offensive workflow:

1. BLE GATT database를 열거하고 official mobile app이 사용하는 writable characteristics를 식별합니다.
2. app traffic을 sniff하고 유선 protocol과 일치하는 **magic bytes / opcodes**를 찾습니다.
3. BLE로 privileged commands를 **pairing 없이** 재전송하고 민감한 작업이 여전히 동작하는지 확인합니다.
4. firmware upgrade, config write, debug, 또는 factory-test opcodes에 도달할 수 있다면, BLE를 **radio-reachable admin port**로 간주합니다.

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
역공학할 때 확인할 사항:

- BLE가 **pairing/bonding**을 요구하는가, 아니면 단순 연결만 필요한가?
- 모든 transport가 동일한 내부 dispatcher table로 라우팅되는가?
- privileged opcode가 USB / BLE / UART / Wi-Fi에서 다르게 필터링되는가?
- mobile app이 firmware update, recovery, 또는 diagnostic handler를 원격으로 트리거할 수 있는가?

## Checksum-only firmware containers are still attacker-controlled firmware

**unkeyed checksum**(CRC32, SHA-256, MD5 등)만으로 보호된 firmware container는 손상 감지는 제공하지만, **authenticity**는 제공하지 않습니다. attacker가 update routine에 접근할 수 있다면, 이미지를 패치하고 checksum을 다시 계산한 뒤 임의 코드를 flash할 수 있습니다.

RE 중 red flags:

- Update code가 `CHK2`, `CRC`, `SHA256` 같은 trailing checksum blob만 검증함.
- signature verification 또는 secure-boot root of trust가 없음.
- device-bound MAC / HMAC / authenticated encryption을 사용하지 않음.
- recovery mode가 동일한 unauthenticated image format을 수락함.

실전 validation flow:

1. firmware container를 추출하고 bootloader, main firmware, integrity metadata를 식별한다.
2. image의 무해한 문자열이나 banner를 수정한다.
3. updater가 기대하는 방식 그대로 checksum을 다시 계산한다.
4. normal update path를 통해 이미지를 다시 flash한다.
5. boot 시 변경 사항을 확인해 arbitrary firmware replacement를 증명한다.

이것이 BLE/Wi-Fi 같은 remotely reachable transport에서 동작한다면, 이 bug는 사실상 **unauthenticated OTA firmware replacement**입니다.

## Turning a trusted USB peripheral into BadUSB via firmware reflashing

target device가 이미 USB를 통해 host에게 trust되고 있다면, malicious firmware는 완전한 새로운 USB stack을 구현할 필요가 없을 수 있습니다. 더 쉬운 pivot은 종종 기존 **HID support**를 **reuse**하는 것입니다.

유용한 패턴:

1. device가 이미 **HID Consumer Control** / media / vendor HID interface로 enumerate되는지 확인한다.
2. firmware에서 기존 **HID report descriptor**를 찾는다.
3. descriptor entry를 추가하거나 교체해 device가 **keyboard** capability도 광고하도록 한다.
4. 새로운 transport implementation을 작성하는 대신, 이미 HID report를 보내는 기존 firmware routine을 재사용한다.
5. key press + key release report를 주입해 host에 command를 입력한다.

이렇게 하면 firmware compromise가 **host compromise**로 이어집니다. PC가 reflashed peripheral을 legitimate keyboard로 trust하기 때문입니다.

### Minimal assessment checklist

- `dmesg`, Device Manager, 또는 USB descriptor에 기존 HID interface가 보이는가?
- report descriptor 근처에 여유 공간이 있거나 relocatable descriptor table이 있는가?
- 기존 media-control send routine을 keyboard report에 재사용할 수 있는가?
- host가 reflashing 후 새 keyboard interface를 자동으로 accept하는가?

## Reliable payload execution inside RTOS firmware

random code path에 취약한 trampoline을 삽입하는 대신, 정상 동작에서 사용되지 않거나 영향이 적은 **existing RTOS tasks**를 찾으십시오.

이것이 유용한 이유:

- scheduler가 boot 중 자연스럽게 payload를 시작합니다.
- 중요한 control flow를 손상시키지 않습니다.
- latency-sensitive USB/network handler 안에서 실행할 때보다 지연된 payload가 watchdog reset을 유발할 가능성이 낮습니다.

좋은 target은 정상 사용 중에는 dormant해 보이는 diagnostic, factory-test, telemetry, 또는 coprocessor service task입니다.

## Fast exploit iteration: repurpose benign protocol handlers

firmware patching이 가능해지면, RE를 가속하는 간단한 방법은 무해한 command handler(예: **echo/debug opcode**)를 커스텀 **memory read / write / execute** primitive로 덮어쓰는 것입니다. 이렇게 하면 매 실험마다 full reflashing을 피할 수 있으며, 특히 device가 modified handler를 빠른 wired transport로 지원할 때 매우 유용합니다.

이것을 사용해 다음을 수행하십시오:

- scatter-loaded memory map 검증
- heap/task state를 live로 확인
- flash에 굽기 전에 작은 payload 테스트
- function pointer, string, descriptor table을 안전하게 복구

## References

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
