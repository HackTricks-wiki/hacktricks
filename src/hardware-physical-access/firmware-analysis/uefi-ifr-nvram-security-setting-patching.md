# UEFI IFR と NVRAM セキュリティ設定のパッチ適用

{{#include ../../banners/hacktricks-training.md}}

setup password は firmware user interface を保護しますが、SPI flash に保存された configuration bytes を必ずしも認証するわけではありません。物理的な書き込みアクセスがあれば、評価者は **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** から非表示またはロックされた UEFI setting を対応する NVRAM variable にマッピングし、その値を offline で patch して再書き込みできます。影響を受ける Dell system では、graphical setup が DMA protection を有効と表示したまま、pre-boot IOMMU state が変更されました。<sup>[[3]](#references)</sup>

> [!CAUTION]
> Firmware の書き込みによって、対象を恒久的に brick する可能性があります。認可済みで復旧可能な test device を使用し、original image を保持してください。また、変更前に、暗号学的 hash が一致する独立した読み出しを少なくとも 3 回取得してください。<sup>[[3]](#references)</sup>

## firmware image の取得

Intel flash descriptor が host access を許可している場合は BIOS region のみを読み取るか、電圧が適合する external programmer と in-circuit clip を使用します。通常、起動しなくなった machine を復元するには external programmer が必要です。<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
vendor update capsule がチップの内容と同一だと想定しないでください。NVRAM が省略されていたり、カプセル化されていたり、暗号化されていたりする可能性があります。[UEFITool](https://github.com/LongSoft/UEFITool) は、raw UEFI image を firmware volumes、files、sections に解析できます。<sup>[[7]](#references)</sup>

## IFR の質問を NVRAM に対応付ける

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) は HII form packages をテキストに変換し、vendor GUI が隠したり、名前を変更したり、抑制したりしている settings を明らかにします。その出力から、question、variable store、byte offset、storage width、valid values、conditional visibility を特定できます。<sup>[[8]](#references)</sup>

1. UEFITool で dump を開き、`Setup` という名前の firmware file を検索して PE32 image section まで展開し、**Extract body** を使用します。
2. 抽出した EFI/PE32 body に対して IFRExtractor-RS を実行し、生成されたテキストから `DMA`、`IOMMU`、`VT-d`、`Secure Boot`、または vendor-facing label などの controls を検索します。
3. `VarStoreId`、`VarOffset`、`Size`、valid options、question ID を記録します。`Flags` だけから value semantics を推測しないでください。
4. 対応する `VarStore`/`VarStoreEfi` declaration を見つけ、numeric store ID をその variable の **name and GUID** に対応付けます。
5. UEFITool でその GUID を検索し、対応する NVRAM object に到達するまで進みます。**Body hex view** を開き、flash image 全体ではなく variable body を基準に `VarOffset` へ移動します。<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
たとえば、ある Dell image では、該当する質問が `Control Iommu Pre-boot Behavior` として記述されており、`VarStoreId: 0x1`、`VarOffset: 0x975`、および 8-bit フィールドが指定されていました。Store `0x1` は変数 `Setup` および GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9` に対応しており、differential dumps によって、その firmware では `01` が有効、`00` が無効であることが確認されました。<sup>[[3]](#references)</sup>

> [!WARNING]
> GUID、offset、structure layout、重複する variable instance、value encoding は、model や firmware version によって変わる可能性があります。例の offset を、Dell 共通の値として決して再利用しないでください。

## Validate with differential dumps

setup interface が同等の test unit で利用できる場合は、オプションを有効にした状態と無効にした状態で、それぞれ dump を作成します。IFR から導出した variable body を比較し、予期した field だけが変更されていることを確認します。これにより、実際の encoding を特定し、active variable と stale/default/recovery copy を区別できます。検証済みの元 image の copy に patch を適用し、再度 UEFITool で開いて、reflash の前に、その編集が authenticated または measured code range の外側にあることを確認してください。<sup>[[3]](#references)[[4]](#references)</sup>

targeted edit は、factory state に移行したり、device-specific data の再入力が必要になったり、TPM PCR measurement を変更したりする可能性がある firmware password の消去よりも、副作用が少ない場合があります。しかし、targeted offline edit は、危険な **表示状態と実効状態の乖離** を引き起こす可能性もあります。UI と management tooling には古い値が表示される一方で、early firmware は patch 済みの byte を使用することがあります。実証された変更では BitLocker recovery は要求されず、vendor BIOS update が変更された NVRAM state を保持したため、update 後も変更が維持されました。<sup>[[3]](#references)</sup>

著者の [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) は、Intel Boot Guard Initial Boot Block range を検出し、その範囲内での通常の write を拒否する model-specific patcher の例です。`--apply` の前に analysis mode を使用し、候補となる match をすべて確認してください。また、その default は portable offset ではなく、例として扱ってください。<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## NVRAMapでマッピングを自動化

[NVRAMap](https://github.com/PN-Tester/NVRAMap) は IFR extraction を自動化し、question の `VarStoreId` を NVRAM GUID/name に解決し、現在の option 値を表示して、選択した field を編集できます。完全な firmware dump、または個別に抽出した EFI および NVRAM blob を使用できます。<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
自動化しても、対応するダンプ、リカバリ用ハードウェア、region-integrity checks、またはフラッシュ後の検証が不要になるわけではありません。

## pre-boot IOMMU downgrade から Windows DMA access への chaining

patched value によって ExitBootServices 前の PCIe DMA が許可される場合、[DMAReaper](https://github.com/PN-Tester/DMAReaper) は EFI System Table から ACPI root tables をたどり、`DMAR` table を見つけて、Windows が解析する前に上書きできます。使用可能な DMAR data がない場合、Windows は IOMMU-backed Kernel DMA Protection の初期化に失敗する可能性があります。DMAReaper 自体は VBS/HVCI を無効化しません。<sup>[[1]](#references)</sup>

実証された chain では、その後 target を Safe Mode で起動して残っていた VBS barrier を除去し、[PCILeech](https://github.com/ufrisk/pcileech) が Sticky Keys signature を使って physical memory に patch を適用しました。<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
成功し、build互換のパッチ適用後、Windowsのログイン画面で Sticky Keys を呼び出すと、`NT AUTHORITY\SYSTEM` として command prompt が起動しました。シグネチャと到達可能なメモリ範囲は、対象、build、ハードウェアに依存します。報告された一致は、すべてのWindowsバージョンがexploit可能であることの証拠ではありません。<sup>[[2]](#references)[[3]](#references)</sup>

検証にfirmware menuを信頼しないでください。**System Information (`msinfo32.exe`) → Kernel DMA Protection**を確認し、VBSを個別に検証し、OSが有効なDMARテーブルを受け取ったかを調査し、実際のDMA到達可能性をテストしてください。WindowsがKernel DMA Protectionを報告するのは、プラットフォームとfirmwareが必要なIOMMU構成をサポートしている場合のみです。<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - pre-boot DMAR overwriteによるKernel DMA Protectionの無効化](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Direct Memory Access攻撃ソフトウェア](https://github.com/ufrisk/pcileech)
- [3] [MDSec - ロックされたBIOSでのSecurity Featuresの無効化](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - IBB対応NVRAMパッチ適用](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - EFI設定をNVRAM値にマッピング](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - UEFI firmware image viewerおよびparser](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - UEFI IFRを人間が読めるテキストに抽出](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom manual - programmersおよびread/write操作](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
