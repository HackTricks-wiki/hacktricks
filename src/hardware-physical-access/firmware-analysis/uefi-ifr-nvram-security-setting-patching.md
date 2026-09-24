# UEFI IFR और NVRAM Security-Setting Patching

{{#include ../../banners/hacktricks-training.md}}

एक setup password firmware user interface की सुरक्षा करता है, लेकिन यह आवश्यक नहीं कि SPI flash में संग्रहीत configuration bytes को authenticate भी करे। Physical write access होने पर, एक assessor छिपी या locked UEFI setting को उसके **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** से backing NVRAM variable तक map कर सकता है, उस value को offline patch कर सकता है और फिर उसे reflash कर सकता है। एक प्रभावित Dell system पर, इससे graphical setup में DMA protection enabled दिखते रहने के बावजूद pre-boot IOMMU state बदल गई।<sup>[[3]](#references)</sup>

> [!CAUTION]
> Firmware writes target को स्थायी रूप से brick कर सकते हैं। किसी authorized, recoverable test device पर काम करें; original image सुरक्षित रखें; और कुछ भी modify करने से पहले कम-से-कम तीन independent reads प्राप्त करें, जिनके cryptographic hashes मेल खाते हों।<sup>[[3]](#references)</sup>

## Firmware image प्राप्त करें

जब Intel flash descriptor host access की अनुमति देता हो, तब केवल BIOS region पढ़ें; अन्यथा voltage-correct external programmer और in-circuit clip का उपयोग करें। जो machine अब boot नहीं होती, उसे restore करने के लिए सामान्यतः external programmer आवश्यक होता है।<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
किसी vendor update capsule को chip contents के बराबर न मानें: इसमें NVRAM शामिल न हो सकता है, encapsulation हो सकती है, या यह encrypted हो सकता है। [UEFITool](https://github.com/LongSoft/UEFITool) raw UEFI image को firmware volumes, files और sections में parse कर सकता है।<sup>[[7]](#references)</sup>

## NVRAM से IFR question map करें

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) HII form packages को text में convert करता है और उन settings को दिखाता है जिन्हें vendor GUI छिपाता, rename करता या suppress करता है। इसका output question, variable store, byte offset, storage width, valid values और conditional visibility की पहचान कर सकता है।<sup>[[8]](#references)</sup>

1. Dump को UEFITool में खोलें, `Setup` नाम वाली firmware file खोजें, उसे PE32 image section तक expand करें और **Extract body** का उपयोग करें।
2. Extract की गई EFI/PE32 body पर IFRExtractor-RS चलाएँ, फिर generated text में `DMA`, `IOMMU`, `VT-d`, `Secure Boot` या vendor-facing label जैसे controls खोजें।
3. `VarStoreId`, `VarOffset`, `Size`, valid options और question ID रिकॉर्ड करें। केवल `Flags` के आधार पर value semantics का अनुमान न लगाएँ।
4. matching `VarStore`/`VarStoreEfi` declaration खोजें और numeric store ID को उसके variable **name और GUID** से map करें।
5. UEFITool में उस GUID को तब तक खोजें जब तक corresponding NVRAM object न मिल जाए। **Body hex view** खोलें और पूरे flash image के सापेक्ष नहीं, बल्कि variable body के सापेक्ष `VarOffset` पर जाएँ।<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
उदाहरण के लिए, एक Dell image में संबंधित question को `Control Iommu Pre-boot Behavior` के रूप में बताया गया था, जिसमें `VarStoreId: 0x1`, `VarOffset: 0x975` और 8-bit field था। Store `0x1` variable `Setup` और GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9` से mapped था; differential dumps से उस firmware पर `01` को enabled और `00` को disabled के रूप में स्थापित किया गया।<sup>[[3]](#references)</sup>

> [!WARNING]
> GUIDs, offsets, structure layouts, duplicate variable instances और value encodings अलग-अलग models और firmware versions में बदल सकते हैं। उदाहरण वाले offset को कभी भी universal Dell value के रूप में reuse न करें।

## Differential dumps से validate करें

जब equivalent test unit पर setup interface उपलब्ध हो, तो option को enabled रखकर एक dump और disabled रखकर दूसरा dump बनाएं। IFR-derived variable body की तुलना करें और confirm करें कि केवल अपेक्षित field ही बदला है। इससे वास्तविक encoding निर्धारित होती है और active variable को stale/default/recovery copies से अलग किया जा सकता है। Verified original image की एक copy को patch करें, उसे UEFITool में फिर से खोलें और reflash करने से पहले confirm करें कि edit authenticated या measured code ranges के बाहर है।<sup>[[3]](#references)[[4]](#references)</sup>

एक targeted edit के firmware password clear करने की तुलना में कम side effects हो सकते हैं, क्योंकि password clear करने से factory state सक्रिय हो सकती है, device-specific data को फिर से enter करना पड़ सकता है या TPM PCR measurements बदल सकते हैं। हालांकि, targeted offline edit एक खतरनाक **displayed-state/effective-state divergence** भी पैदा कर सकता है: UI और management tooling पुरानी value दिखा सकते हैं, जबकि early firmware patched byte का उपयोग कर रहा हो। प्रदर्शित change ने BitLocker recovery का अनुरोध नहीं किया और vendor BIOS update के बाद भी बना रहा, क्योंकि update ने altered NVRAM state को preserve किया।<sup>[[3]](#references)</sup>

लेखक का [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) एक model-specific patcher का उदाहरण है, जो Intel Boot Guard Initial Boot Block ranges को discover करता है और उनके अंदर normal writes करने से इनकार करता है। `--apply` से पहले इसका analysis mode उपयोग करें, प्रत्येक candidate match का निरीक्षण करें और इसके defaults को portable offsets के बजाय examples मानें।<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## NVRAMap के साथ mapping को automate करें

[NVRAMap](https://github.com/PN-Tester/NVRAMap) IFR extraction को automate करता है, किसी question के `VarStoreId` को NVRAM GUID/name से resolve करता है, current option values दिखाता है और selected field को edit कर सकता है। यह full firmware dump या अलग-अलग extracted EFI और NVRAM blobs से काम कर सकता है।<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
Automation matching dumps, recovery hardware, region-integrity checks या post-flash validation की आवश्यकता समाप्त नहीं करता।

## Windows DMA access में pre-boot IOMMU downgrade को chain करना

यदि patched value ExitBootServices से पहले PCIe DMA की अनुमति देती है, तो [DMAReaper](https://github.com/PN-Tester/DMAReaper) EFI System Table से ACPI root tables तक जा सकता है, `DMAR` table का पता लगा सकता है और Windows द्वारा उसे parse करने से पहले overwrite कर सकता है। उपयोगी DMAR data के बिना, Windows IOMMU-backed Kernel DMA Protection को initialize करने में विफल हो सकता है। DMAReaper अपने-आप VBS/HVCI को **disable** नहीं करता।<sup>[[1]](#references)</sup>

दिखाई गई chain में, target को फिर Safe Mode में boot किया गया ताकि बची हुई VBS बाधा हटाई जा सके, और [PCILeech](https://github.com/ufrisk/pcileech) ने Sticky Keys signature के साथ physical memory को patch किया:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
सफल, build-compatible patch के बाद, Windows sign-in screen पर Sticky Keys चलाने से `NT AUTHORITY\SYSTEM` के रूप में command prompt शुरू हुआ। Signatures और reachable memory ranges target/build/hardware पर निर्भर होते हैं; reported match इस बात का प्रमाण नहीं है कि Windows का हर version exploitable है।<sup>[[2]](#references)[[3]](#references)</sup>

Validation के लिए firmware menu पर भरोसा न करें। **System Information (`msinfo32.exe`) → Kernel DMA Protection** जांचें, VBS को अलग से verify करें, देखें कि OS को valid DMAR table प्राप्त हुई है या नहीं, और वास्तविक DMA reachability का परीक्षण करें। Windows केवल तभी Kernel DMA Protection report करता है जब platform और firmware आवश्यक IOMMU configuration का support करते हों।<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - pre-boot DMAR overwrite के माध्यम से Kernel DMA Protection disable करना](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Direct Memory Access attack software](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Locked BIOS में Security Features disable करना](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - IBB-aware NVRAM patching](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - EFI settings को NVRAM values से map करना](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - UEFI firmware image viewer और parser](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - UEFI IFR को human-readable text में extract करना](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom manual - programmers और read/write operations](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
