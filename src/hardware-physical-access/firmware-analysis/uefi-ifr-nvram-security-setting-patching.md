# UEFI IFR 및 NVRAM Security-Setting Patching

{{#include ../../banners/hacktricks-training.md}}

setup password는 firmware user interface를 보호하지만, SPI flash에 저장된 configuration bytes를 반드시 authenticate하는 것은 아닙니다. 물리적 write access가 있으면 assessor는 **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)**에서 hidden 또는 locked UEFI setting을 해당 NVRAM variable에 매핑하고, 그 값을 offline에서 patch한 다음 reflash할 수 있습니다. 영향을 받는 Dell 시스템에서는 graphical setup에 DMA protection이 enabled로 표시되는 동안 pre-boot IOMMU state가 변경되었습니다.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Firmware write는 target을 영구적으로 brick할 수 있습니다. authorized되고 복구 가능한 test device에서 작업하고, original image를 보관하며, 수정하기 전에 cryptographic hash가 일치하는 독립적인 read를 최소 3회 확보하십시오.<sup>[[3]](#references)</sup>

## firmware image 획득

Intel flash descriptor가 host access를 허용하는 경우 BIOS region만 read하거나, voltage가 올바른 external programmer와 in-circuit clip을 사용하십시오. 더 이상 boot되지 않는 machine을 복구하려면 일반적으로 external programmer가 필요합니다.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
벤더 업데이트 capsule이 chip contents와 동일하다고 가정하지 마세요. NVRAM이 누락되거나 encapsulation이 포함되거나 암호화되어 있을 수 있습니다. [UEFITool](https://github.com/LongSoft/UEFITool)은 raw UEFI image를 firmware volumes, files, sections로 파싱할 수 있습니다.<sup>[[7]](#references)</sup>

## IFR question을 NVRAM에 매핑하기

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS)는 HII form packages를 text로 변환하고, vendor GUI가 숨기거나 이름을 바꾸거나 억제하는 settings를 노출합니다. 이 출력에서 question, variable store, byte offset, storage width, valid values, conditional visibility를 식별할 수 있습니다.<sup>[[8]](#references)</sup>

1. UEFITool에서 dump를 열고, `Setup`이라는 이름의 firmware file을 검색한 다음 PE32 image section까지 확장하고 **Extract body**를 사용합니다.
2. 추출한 EFI/PE32 body에서 IFRExtractor-RS를 실행한 다음, 생성된 text에서 `DMA`, `IOMMU`, `VT-d`, `Secure Boot` 또는 vendor-facing label과 같은 controls를 검색합니다.
3. `VarStoreId`, `VarOffset`, `Size`, valid options 및 question ID를 기록합니다. `Flags`만으로 value semantics를 추론하지 마세요.
4. 일치하는 `VarStore`/`VarStoreEfi` declaration을 찾아 numeric store ID를 variable **name and GUID**에 매핑합니다.
5. UEFITool에서 해당 GUID를 검색하여 대응하는 NVRAM object에 도달합니다. **Body hex view**를 열고, 전체 flash image가 아니라 variable body를 기준으로 `VarOffset`으로 이동합니다.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
예를 들어 한 Dell 이미지에서는 관련 질문이 `Control Iommu Pre-boot Behavior`로 설명되어 있었으며, `VarStoreId: 0x1`, `VarOffset: 0x975`, 8비트 필드를 사용했습니다. Store `0x1`은 변수 `Setup` 및 GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`에 매핑되었고, differential dump를 통해 해당 firmware에서 `01`은 enabled, `00`은 disabled임을 확인했습니다.<sup>[[3]](#references)</sup>

> [!WARNING]
> GUID, offset, structure layout, duplicate variable instance 및 value encoding은 모델과 firmware 버전에 따라 변경될 수 있습니다. 예시의 offset을 보편적인 Dell 값으로 재사용하지 마십시오.

## Validate with differential dumps

동등한 테스트 장치에서 setup interface를 사용할 수 있다면, 해당 옵션을 enabled로 설정한 dump와 disabled로 설정한 dump를 각각 생성합니다. IFR에서 도출한 variable body를 비교하고 예상된 field만 변경되는지 확인합니다. 이를 통해 실제 encoding을 확인하고 active variable을 오래된 값, 기본값 또는 recovery copy와 구분할 수 있습니다. 검증된 원본 image의 사본을 patch하고, UEFITool에서 다시 연 다음, reflash하기 전에 변경 사항이 authenticated 또는 measured code range 외부에 있는지 확인합니다.<sup>[[3]](#references)[[4]](#references)</sup>

targeted edit는 firmware password를 지우는 것보다 side effect가 적을 수 있습니다. firmware password를 지우면 factory state로 진입하거나, 장치별 데이터를 다시 입력해야 하거나, TPM PCR measurement가 변경될 수 있습니다. 그러나 targeted offline edit는 위험한 **displayed-state/effective-state divergence**도 만들 수 있습니다. UI와 management tooling에는 이전 값이 표시되는 반면, early firmware는 patch된 byte를 사용할 수 있습니다. 시연된 변경은 BitLocker recovery를 요청하지 않았으며, 해당 update가 변경된 NVRAM state를 보존했기 때문에 vendor BIOS update 이후에도 유지되었습니다.<sup>[[3]](#references)</sup>

작성자의 [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher)는 Intel Boot Guard Initial Boot Block range를 검색하고 해당 range 내부의 일반적인 write를 거부하는 model-specific patcher의 예시입니다. `--apply` 전에 analysis mode를 사용하고, 모든 candidate match를 검사하며, 기본값을 이식 가능한 offset이 아닌 예시로 취급하십시오.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## NVRAMap으로 매핑 자동화

[NVRAMap](https://github.com/PN-Tester/NVRAMap)은 IFR extraction을 자동화하고, 질문의 `VarStoreId`를 NVRAM GUID/name으로 확인하며, 현재 option 값을 표시하고, 선택한 field를 편집할 수 있습니다. 전체 firmware dump 또는 별도로 추출한 EFI 및 NVRAM blob을 사용할 수 있습니다.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
자동화하더라도 일치하는 dump, 복구 hardware, region-integrity checks 또는 flash 후 validation이 필요하지 않은 것은 아닙니다.

## pre-boot IOMMU downgrade를 Windows DMA access로 chaining하기

패치된 값이 ExitBootServices 이전에 PCIe DMA를 허용한다면, [DMAReaper](https://github.com/PN-Tester/DMAReaper)는 EFI System Table에서 ACPI root tables를 따라가 `DMAR` table을 찾고, Windows가 이를 parse하기 전에 덮어쓸 수 있습니다. 사용 가능한 DMAR 데이터가 없으면 Windows가 IOMMU 기반 Kernel DMA Protection을 초기화하지 못할 수 있습니다. DMAReaper 자체로는 VBS/HVCI를 disable하지 않습니다.<sup>[[1]](#references)</sup>

시연된 chain에서는 남아 있는 VBS barrier를 제거하기 위해 대상을 Safe Mode로 boot한 다음, [PCILeech](https://github.com/ufrisk/pcileech)가 Sticky Keys signature를 사용해 physical memory를 패치했습니다.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
성공적으로 build-compatible 패치를 적용한 후, Windows 로그인 화면에서 Sticky Keys를 실행하면 `NT AUTHORITY\SYSTEM` 권한으로 command prompt가 실행되었습니다. 시그니처와 접근 가능한 메모리 범위는 대상, build 및 하드웨어에 따라 달라집니다. 보고된 일치 결과만으로 모든 Windows 버전이 exploit 가능하다고 판단해서는 안 됩니다.<sup>[[2]](#references)[[3]](#references)</sup>

검증 시 firmware 메뉴를 신뢰하지 마십시오. **시스템 정보 (`msinfo32.exe`) → Kernel DMA Protection**을 확인하고, VBS를 별도로 검증하며, OS가 유효한 DMAR 테이블을 수신했는지 검사하고, 실제 DMA 접근 가능성을 테스트하십시오. Windows는 플랫폼과 firmware가 필요한 IOMMU 구성을 지원하는 경우에만 Kernel DMA Protection을 보고합니다.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - pre-boot DMAR overwrite를 통한 Kernel DMA Protection 비활성화](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Direct Memory Access attack software](https://github.com/ufrisk/pcileech)
- [3] [MDSec - 잠긴 BIOS에서 Security Features 비활성화](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - IBB-aware NVRAM patching](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - EFI 설정을 NVRAM 값에 매핑](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - UEFI firmware image viewer and parser](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - UEFI IFR을 사람이 읽을 수 있는 텍스트로 추출](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom manual - programmers and read/write operations](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
