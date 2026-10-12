# UEFI IFR and NVRAM Security-Setting Patching

{{#include ../../banners/hacktricks-training.md}}

A setup password protects the firmware user interface, but it does not necessarily authenticate the configuration bytes stored in SPI flash. With physical write access, an assessor can map a hidden or locked UEFI setting from its **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** to the backing NVRAM variable, patch that value offline, and reflash it. On an affected Dell system, this changed the pre-boot IOMMU state while the graphical setup still displayed DMA protection as enabled.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Firmware writes can permanently brick the target. Work on an authorized, recoverable test device; keep the original image; and obtain at least three independent reads whose cryptographic hashes match before modifying anything.<sup>[[3]](#references)</sup>

## Acquire the firmware image

Read only the BIOS region when the Intel flash descriptor permits host access, or use a voltage-correct external programmer and in-circuit clip. An external programmer is normally required to restore a machine that no longer boots.<sup>[[3]](#references)[[9]](#references)</sup>

```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```

Do not assume that a vendor update capsule is equivalent to the chip contents: it may omit NVRAM, contain encapsulation, or be encrypted. [UEFITool](https://github.com/LongSoft/UEFITool) can parse a raw UEFI image into firmware volumes, files, and sections.<sup>[[7]](#references)</sup>

## Map an IFR question to NVRAM

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) converts HII form packages into text and exposes settings that a vendor GUI hides, renames, or suppresses. Its output can identify the question, variable store, byte offset, storage width, valid values, and conditional visibility.<sup>[[8]](#references)</sup>

1. Open the dump in UEFITool, search for the firmware file named `Setup`, expand it to the PE32 image section, and use **Extract body**.
2. Run IFRExtractor-RS on the extracted EFI/PE32 body, then search the generated text for controls such as `DMA`, `IOMMU`, `VT-d`, `Secure Boot`, or the vendor-facing label.
3. Record `VarStoreId`, `VarOffset`, `Size`, valid options, and the question ID. Do not infer value semantics from `Flags` alone.
4. Find the matching `VarStore`/`VarStoreEfi` declaration and map the numeric store ID to its variable **name and GUID**.
5. Search that GUID in UEFITool until the corresponding NVRAM object is reached. Open **Body hex view** and navigate to `VarOffset` relative to the variable body—not the whole flash image.<sup>[[3]](#references)</sup>

```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```

For example, one Dell image described the relevant question as `Control Iommu Pre-boot Behavior`, with `VarStoreId: 0x1`, `VarOffset: 0x975`, and an 8-bit field. Store `0x1` mapped to variable `Setup` and GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`; differential dumps established `01` as enabled and `00` as disabled on that firmware.<sup>[[3]](#references)</sup>

> [!WARNING]
> GUIDs, offsets, structure layouts, duplicate variable instances, and value encodings can change across models and firmware versions. Never reuse the example offset as a universal Dell value.

## Validate with differential dumps

When the setup interface is available on an equivalent test unit, create a dump with the option enabled and another with it disabled. Compare the IFR-derived variable body and confirm that only the expected field changes. This determines the actual encoding and distinguishes an active variable from stale/default/recovery copies. Patch a copy of the verified original image, re-open it in UEFITool, and confirm that the edit is outside authenticated or measured code ranges before reflashing.<sup>[[3]](#references)[[4]](#references)</sup>

A targeted edit can have fewer side effects than clearing a firmware password, which may enter a factory state, require device-specific data to be re-entered, or change TPM PCR measurements. However, a targeted offline edit can also create a dangerous **displayed-state/effective-state divergence**: the UI and management tooling may show the old value while early firmware consumes the patched byte. The demonstrated change did not request BitLocker recovery and survived a vendor BIOS update because the update preserved the altered NVRAM state.<sup>[[3]](#references)</sup>

The author's [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) illustrates a model-specific patcher that discovers Intel Boot Guard Initial Boot Block ranges and refuses normal writes inside them. Use its analysis mode before `--apply`, inspect every candidate match, and treat its defaults as examples rather than portable offsets.<sup>[[4]](#references)</sup>

```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```

## Automate the mapping with NVRAMap

[NVRAMap](https://github.com/PN-Tester/NVRAMap) automates IFR extraction, resolves a question's `VarStoreId` to the NVRAM GUID/name, displays current option values, and can edit the selected field. It can work from a full firmware dump or from separately extracted EFI and NVRAM blobs.<sup>[[5]](#references)</sup>

```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```

Automation does not remove the need for matching dumps, recovery hardware, region-integrity checks, or post-flash validation.

## Chaining a pre-boot IOMMU downgrade into Windows DMA access

If the patched value permits PCIe DMA before ExitBootServices, [DMAReaper](https://github.com/PN-Tester/DMAReaper) can walk from the EFI System Table through the ACPI root tables, locate the `DMAR` table, and overwrite it before Windows parses it. Without usable DMAR data, Windows may fail to initialize IOMMU-backed Kernel DMA Protection. DMAReaper does **not** disable VBS/HVCI by itself.<sup>[[1]](#references)</sup>

In the demonstrated chain, the target was then booted in Safe Mode to remove the remaining VBS barrier and [PCILeech](https://github.com/ufrisk/pcileech) patched physical memory with a Sticky Keys signature:<sup>[[2]](#references)[[3]](#references)</sup>

```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```

After a successful, build-compatible patch, invoking Sticky Keys at the Windows sign-in screen launched a command prompt as `NT AUTHORITY\SYSTEM`. Signatures and reachable memory ranges are target/build/hardware dependent; a reported match is not evidence that every Windows version is exploitable.<sup>[[2]](#references)[[3]](#references)</sup>

Do not trust the firmware menu as validation. Check **System Information (`msinfo32.exe`) → Kernel DMA Protection**, verify VBS separately, inspect whether the OS received a valid DMAR table, and test actual DMA reachability. Windows reports Kernel DMA Protection only when the platform and firmware support the required IOMMU configuration.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Disable Kernel DMA Protection via pre-boot DMAR overwrite](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Direct Memory Access attack software](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Disabling Security Features in a Locked BIOS](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - IBB-aware NVRAM patching](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Map EFI settings to NVRAM values](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - UEFI firmware image viewer and parser](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Extract UEFI IFR into human-readable text](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom manual - programmers and read/write operations](https://flashrom.org/classic_cli_manpage.html)

{{#include ../../banners/hacktricks-training.md}}
