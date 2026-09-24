# UEFI IFR ve NVRAM Security-Setting Patching

{{#include ../../banners/hacktricks-training.md}}

Bir setup password, firmware user interface'ini korur; ancak SPI flash'te depolanan configuration byte'larının kimliğini doğrulamaz. Fiziksel yazma erişimiyle bir assessor, **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** üzerinden gizli veya kilitli bir UEFI setting'i backing NVRAM variable'ına eşleyebilir, bu değeri offline olarak patch edebilir ve yeniden flash'layabilir. Etkilenen bir Dell sisteminde bu işlem, grafiksel setup DMA protection'ı etkin göstermeye devam ederken pre-boot IOMMU durumunu değiştirdi.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Firmware yazma işlemleri hedef cihazı kalıcı olarak brick edebilir. Yetkilendirilmiş ve kurtarılabilir bir test cihazı üzerinde çalışın; original image'ı saklayın ve herhangi bir değişiklik yapmadan önce cryptographic hash'leri eşleşen en az üç bağımsız okuma alın.<sup>[[3]](#references)</sup>

## Firmware image'ını edinme

Intel flash descriptor host access'e izin veriyorsa yalnızca BIOS region'ını okuyun veya voltage-correct bir external programmer ve in-circuit clip kullanın. Artık boot etmeyen bir makineyi restore etmek için normalde external programmer gerekir.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
Bir vendor update capsule'ının chip içeriğine eşdeğer olduğunu varsaymayın: NVRAM'i içermeyebilir, encapsulation içerebilir veya encrypted olabilir. [UEFITool](https://github.com/LongSoft/UEFITool), ham bir UEFI image'ını firmware volume'larına, file'lara ve section'lara ayrıştırabilir.<sup>[[7]](#references)</sup>

## Bir IFR sorusunu NVRAM'e eşleyin

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS), HII form package'larını text'e dönüştürür ve vendor GUI'sinin gizlediği, yeniden adlandırdığı veya bastırdığı setting'leri ortaya çıkarır. Çıktısı question'ı, variable store'u, byte offset'i, storage width'i, geçerli değerleri ve conditional visibility'yi belirleyebilir.<sup>[[8]](#references)</sup>

1. Dump'ı UEFITool'da açın, `Setup` adlı firmware file'ını arayın, PE32 image section'ına kadar genişletin ve **Extract body** seçeneğini kullanın.
2. IFRExtractor-RS'yi çıkarılan EFI/PE32 body üzerinde çalıştırın, ardından oluşturulan text'te `DMA`, `IOMMU`, `VT-d`, `Secure Boot` veya vendor-facing label gibi control'leri arayın.
3. `VarStoreId`, `VarOffset`, `Size`, geçerli option'ları ve question ID'sini kaydedin. Value semantics'i yalnızca `Flags` üzerinden çıkarmayın.
4. Eşleşen `VarStore`/`VarStoreEfi` declaration'ını bulun ve numeric store ID'sini variable'ın **name ve GUID** bilgilerine eşleyin.
5. Bu GUID'yi UEFITool'da ilgili NVRAM object'ine ulaşana kadar arayın. **Body hex view**'ı açın ve `VarOffset`'e tüm flash image'ına göre değil, variable body'ye göre gidin.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Örneğin, bir Dell image'ı ilgili soruyu `Control Iommu Pre-boot Behavior` olarak tanımlıyordu; `VarStoreId: 0x1`, `VarOffset: 0x975` ve 8 bitlik bir alan kullanılıyordu. `0x1` Store'u, `Setup` değişkenine ve `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9` GUID'sine eşleniyordu; differential dump'lar, bu firmware üzerinde `01` değerinin etkin ve `00` değerinin devre dışı olduğunu ortaya koydu.<sup>[[3]](#references)</sup>

> [!WARNING]
> GUID'ler, offset'ler, yapı düzenleri, duplicate variable instance'ları ve değer kodlamaları modeller ve firmware sürümleri arasında değişebilir. Örnek offset'i hiçbir zaman evrensel bir Dell değeri olarak yeniden kullanmayın.

## Differential dump'larla doğrulama

Setup arayüzü eşdeğer bir test cihazında kullanılabiliyorsa, seçenek etkin durumdayken bir dump ve devre dışı durumdayken başka bir dump oluşturun. IFR'dan türetilen variable body'yi karşılaştırın ve yalnızca beklenen alanın değiştiğini doğrulayın. Bu işlem gerçek kodlamayı belirler ve etkin bir değişkeni eski/varsayılan/recovery kopyalarından ayırt eder. Doğrulanmış original image'ın bir kopyasına patch uygulayın, image'ı UEFITool'da yeniden açın ve yeniden flash etmeden önce düzenlemenin authenticated veya measured code range'lerinin dışında olduğunu doğrulayın.<sup>[[3]](#references)[[4]](#references)</sup>

Hedefli bir düzenleme, bir firmware parolasını temizlemeye kıyasla daha az yan etkiye sahip olabilir; parola temizleme işlemi factory state'e geçişe, cihaza özgü verilerin yeniden girilmesi gereksinimine veya TPM PCR ölçümlerinin değişmesine neden olabilir. Ancak hedefli bir offline düzenleme, tehlikeli bir **görüntülenen durum/etkin durum ayrışması** da oluşturabilir: UI ve management tooling eski değeri gösterirken early firmware patch uygulanmış byte'ı kullanabilir. Gösterilen değişiklik BitLocker recovery istemedi ve update, değiştirilmiş NVRAM state'ini koruduğu için vendor BIOS update sonrasında da kaldı.<sup>[[3]](#references)</sup>

Yazarın [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) aracı, Intel Boot Guard Initial Boot Block aralıklarını keşfeden ve bu aralıkların içindeki normal write işlemlerini reddeden model-specific bir patcher örneğidir. `--apply` öncesinde analysis mode'u kullanın, her candidate match'i inceleyin ve varsayılanlarını taşınabilir offset'ler yerine örnek olarak değerlendirin.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## NVRAMap ile eşlemeyi otomatikleştirme

[NVRAMap](https://github.com/PN-Tester/NVRAMap), IFR extraction işlemini otomatikleştirir, bir sorunun `VarStoreId` değerini NVRAM GUID/adına çözümler, mevcut seçenek değerlerini görüntüler ve seçilen alanı düzenleyebilir. Tam bir firmware dump'ı veya ayrı olarak çıkarılmış EFI ve NVRAM blob'larıyla çalışabilir.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
Otomasyon; eşleşen dump'lara, kurtarma donanımına, bölge bütünlüğü kontrollerine veya flash sonrası doğrulamaya duyulan ihtiyacı ortadan kaldırmaz.

## Pre-boot IOMMU downgrade işlemini Windows DMA erişimine zincirleme

Yamalı değer, ExitBootServices öncesinde PCIe DMA'ya izin veriyorsa [DMAReaper](https://github.com/PN-Tester/DMAReaper), EFI System Table'dan ACPI root tables üzerinden ilerleyebilir, `DMAR` tablosunu bulabilir ve Windows bunu ayrıştırmadan önce üzerine yazabilir. Kullanılabilir DMAR verileri olmadan Windows, IOMMU destekli Kernel DMA Protection'ı başlatamayabilir. DMAReaper, VBS/HVCI'yi kendi başına devre dışı bırakmaz.<sup>[[1]](#references)</sup>

Gösterilen zincirde hedef daha sonra kalan VBS engelini kaldırmak için Safe Mode'da başlatıldı ve [PCILeech](https://github.com/ufrisk/pcileech), fiziksel belleğe Sticky Keys imzasını yamaladı:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Başarılı ve build uyumlu bir patch sonrasında, Windows oturum açma ekranında Sticky Keys'i çağırmak `NT AUTHORITY\SYSTEM` olarak bir command prompt başlattı. İmzalar ve erişilebilir memory aralıkları hedefe/build'e/donanıma bağlıdır; bildirilen bir eşleşme, her Windows sürümünün exploitable olduğunun kanıtı değildir.<sup>[[2]](#references)[[3]](#references)</sup>

Doğrulama için firmware menüsüne güvenmeyin. **System Information (`msinfo32.exe`) → Kernel DMA Protection** bölümünü kontrol edin, VBS'yi ayrıca doğrulayın, işletim sisteminin geçerli bir DMAR tablosu alıp almadığını inceleyin ve gerçek DMA erişilebilirliğini test edin. Windows, Kernel DMA Protection'ı yalnızca platform ve firmware gerekli IOMMU yapılandırmasını desteklediğinde bildirir.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Pre-boot DMAR overwrite ile Kernel DMA Protection'ı devre dışı bırakma](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Direct Memory Access saldırı yazılımı](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Kilitli bir BIOS'ta Security Features'ı devre dışı bırakma](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - IBB-aware NVRAM patching](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - EFI ayarlarını NVRAM değerlerine eşleme](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - UEFI firmware image görüntüleyicisi ve parser'ı](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - UEFI IFR'yi insan tarafından okunabilir metne çıkarma](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom manual - programmer'lar ve read/write işlemleri](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
