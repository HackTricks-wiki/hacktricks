# Windows Kernel Rootkit'leri ve DKOM

{{#include ../../banners/hacktricks-training.md}}

## Kapsam

Compromise sonrası bir implant, imzalı bir kernel driver'ı service olarak yükleyebilir ve `IRP_MJ_DEVICE_CONTROL` üzerinden user-mode bir control plane sunabilir. Driver imzası yalnızca Windows'un imajı kabul etmesini sağlar; IOCTL yetkilendirmesini, bellek işlemlerini, callback'leri veya hook'ları güvenli hâle getirmez. İncelenen rootkit'lerden biri normal çalışması sırasında üç handler kullanıyor, ancak post-exploitation için onlarca ek primitive sunuyordu. Bu nedenle reverse engineering, yalnızca malware trace'inde gözlemlenen istekleri değil, dispatcher'ın tamamını kapsamalıdır.<sup>[[1]](#references)</sup>

## İmzalı driver ve IOCTL triyajı

`DriverEntry` noktasından başlayın, device object'leri ve DOS symbolic link'leri kaydedin, `MajorFunction[IRP_MJ_DEVICE_CONTROL]` rutinini bulun ve handler'lara ulaşan tüm karşılaştırma/tablo girdilerini haritalayın. User mode'un açtığı adları driver'ın gerçekten oluşturduğu adlarla karşılaştırın: gözlemlenen bir zincirde `\\.\msagent` açılırken driver, `\Device\ToolTool` ve `\DosDevices\ToolTool` oluşturuyordu. Bu uyuşmazlık başka bir sample/configuration'a, eksik setup mantığına veya analiz tutarsızlığına işaret edebilir.<sup>[[1]](#references)</sup>

Girdi yapısını yeniden oluşturmadan önce her control code'u çözümleyin.<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

Bu üç kod sırasıyla `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` ve `METHOD_BUFFERED` olarak çözülür. Bu, ayrıcalıksız bir kullanıcının bunlara erişebileceğini **kanıtlamaz**: ayrıca device DACL’yi, create/open dispatch’i, istek başına yapılan caller kontrollerini, beklenen buffer uzunluklarını, gömülü pointer’ları, PID yaşam döngüsü işlemlerini ve handler’ın caller tarafından sağlanan bir PID’ye veya flag’e güvenip güvenmediğini inceleyin.<sup>[[1]](#references)</sup>

Implant yalnızca komutların bir alt kümesini kullanıyorsa, kalan handler’ları kullanılmayan kod diye göz ardı etmek yerine primitive’lerine göre gruplandırın. Tek bir çok amaçlı driver aşağıdaki sınıfların tümünü sunmuştur:<sup>[[1]](#references)</sup>

- **Kontrol/yapılandırma:** rootkit durumunu değiştirme; korunan path’leri, process’leri ve C2 adreslerini ekleme, kaldırma, sorgulama veya temizleme.
- **Process manipülasyonu:** PID’yi sonlandırma, image’ını unmap etme, `NtCreateThreadEx` ile inject etme, process’leri veya user module’lerini gizleme/geri yükleme ve PPL korumasını kaldırma.
- **Kernel manipülasyonu:** yüklü bir driver’ın bağlantısını listeden çıkarma, notification callback’lerini listeleme/devre dışı bırakma/geri yükleme, başka bir driver’ı manuel map etme ve rastgele bir kernel adresine yazma.
- **Object manipülasyonu:** dosyaları silme/şifre çözme ve registry değerleri oluşturma veya değiştirme.

## Zafiyetli imzalı driver üzerinden manuel kernel mapping

Kernel belleği okuma/yazma işlemleri sunan imzalı bir driver, Windows’tan imzasız driver image’ını normal bir driver olarak yüklemesini istemeden, bu image için loader işlevi görebilir.<sup>[[2]](#references)[[7]](#references)</sup> LocalStranger örneği mevcut bir `\\.\WinNotify` device’ını açar; kaynak kodu, ayrıcalıksız bir kullanıcının rastgele bir host’a driver’ı yükleyebildiğini, başlatabildiğini veya açabildiğini göstermez.<sup>[[2]](#references)[[3]](#references)</sup> Mapper bir image path’i alır, yüklü kernel’ın base adresini sorgular ve device’ın virtual-memory okuma/yazma IOCTL’lerini kullanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Bu okuma/yazma erişimini kernel çağrısına dönüştürmek için mapper, `MmGetVirtualForPhysical` içindeki bir PTE-base immediate değerini okur ve `NtAddAtom`’ı kapsayan paging entry’lerini dolaşır.<sup>[[5]](#references)[[7]](#references)</sup> PTE hesaplaması `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)` şeklindedir; kod ayrıca large-page PDE olup olmadığını kontrol eder.<sup>[[5]](#references)[[7]](#references)</sup> Kapsayan entry’yi geçici olarak yazılabilir hâle getirir, syscall entry’sini istenen kernel function’a atlayan bir jump ile değiştirir, user-mode `NtAddAtom` stub’ını çağırır, ardından hem özgün byte’ları hem de page entry’yi geri yükler.<sup>[[6]](#references)</sup>

Mapper bu çağrı yolunu `ExAllocatePool` için kullanır; PE section’larını, import’ları ve relocation’ları image’a map eder, image’ı allocation’a yazar ve entry point’ini çağırır.<sup>[[7]](#references)[[8]](#references)</sup> Bu uygulama yalnızca x64 ve relocatable PE image’larını kabul eder; PTE-base okuması ayrıca sabit bir `MmGetVirtualForPhysical + 34` yerleşimini varsayar.<sup>[[5]](#references)[[8]](#references)</sup> Bunu build’e bağlı bir teknik olarak değerlendirin; bağımsız bir KASLR bypass’ı veya HVCI ya da PatchGuard’ın mapping’e izin verdiğinin kanıtı olarak görmeyin.<sup>[[5]](#references)[[8]](#references)</sup> Kernel R/W’nin yalnızca data için kullanıldığı bir örnek için bkz. [SYSTEM token theft](arbitrary-kernel-rw-token-theft.md).

## Trusted process muafiyetleri

Yararlı bir tasarım örüntüsü, bir PID ile **trusted** flag’ini kaydeden bir IOCTL’dir. Aynı trust lookup daha sonra file, registry, process ve thread filter’ları tarafından kullanılır: güvenilmeyen araçlar filtrelenmiş enumeration sonuçları, azaltılmış handle hakları veya `STATUS_ACCESS_DENIED` alırken implant kendi gizli object’lerini güncelleyebilir. Bunu bir authorization sınırı olarak ele alın ve kayıtların nasıl doğrulandığını, senkronize edildiğini ve process çıkışı veya PID’nin yeniden kullanılması sonrasında kaldırıldığını inceleyin.<sup>[[1]](#references)</sup>

Rootkit’ler policy’yi `REG_MULTI_SZ` değerlerinde kalıcı hâle getirebilir ve file, directory, registry-key, registry-value, ignored-image, protected-image ve hidden-image listelerini AVL tree’lerine derleyebilir. Analiz sırasında bu paylaşılan tree’lerin tüm okuyucu ve yazıcılarını izleyin; function adları kaldırılmış olsa bile bunlar registry yapılandırmasını, IOCTL’leri, callback’leri ve filtreleme mantığını birbirine bağlar.<sup>[[1]](#references)</sup>

## DKOM ile process ve module gizleme

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks` offset’leri Windows build’leri arasında değişir. Sürümler arasında çalışabilen bir rootkit, bilinen adayları deneyebilir ve ardından `EPROCESS` içinde komşularının adaya geri işaret ettiği, tutarlı bir `LIST_ENTRY` arayabilir. Bulunan offset’i saklar, komşularının `Flink`/`Blink` pointer’larını yeniden bağlayarak bir process’i gizler ve entry’yi daha sonra listeye yeniden eklemek için gereken durumu korur. Process çalışmaya devam eder, ancak active-process list’ini dolaşan enumerator’larda görünmez.<sup>[[1]](#references)</sup>

Bu, sonlandırma değil **DKOM**’dur. Tespit için liste tabanlı sonuçları pool/object taramaları, thread sahipliği, handle table’ları, scheduler artefact’ları ve kernel belleği incelemesi gibi bağımsız kanıtlarla karşılaştırın. Bir taramada görünen ancak kanonik listede bulunmayan bir process, iki görünümden herhangi birinden tek başına daha anlamlıdır.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Eşdeğer module-gizleme primitive’i, hedef entry’yi `PsLoadedModuleList` içinde bulur ve bitişik `Flink`/`Blink` pointer’larını değiştirir. Driver map edilmiş ve çalıştırılabilir durumda kalır, ancak listeye dayalı module sorguları onu göstermez. Loader list’ini executable kernel mapping’leri, pool tag’leri, device/driver object’leri, service key’leri, callback adresleri ve listelenmiş bir image dışında kalan dispatch pointer’larıyla karşılaştırın.<sup>[[1]](#references)</sup>

## Callback tabanlı koruma ve gizleme

Bir rootkit, belgelenmiş callback framework’lerini DKOM ve hook’larla birlikte kullanabilir:<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` pre-operation handler’ları, güvenilmeyen bir caller korunan bir hedefi açtığında sonlandırma, VM erişimi, çoğaltma veya thread manipülasyonu için kullanılan hakları `PsProcessType` ve `PsThreadType` üzerinden kaldırır. Callback altitude’unu kaydedin ve her callback adresinin sahibi olan module’ü belirleyin.
- `PsSetCreateProcessNotifyRoutineEx` ve `PsSetLoadImageNotifyRoutine`, process ve image’lar ortaya çıktıkça korunan/yok sayılan/gizli process durumunu günceller; tek seferlik bir process taraması, kayıt öncesinde var olan object’leri bu duruma ekleyebilir.
- Bir filesystem minifilter, yapılandırılmış path’lere erişimi engeller. Sıra dışı bir uygulama `Instances` key’ini oluşturabilir, altitude’u dinamik olarak seçebilir ve `FltRegisterFilter` çakışma bildirdiğinde değeri artırıp tekrar deneyebilir.
- Bir `CmRegisterCallbackEx` rutini, kayıtlı trusted process’leri muaf tutarken korunan adları enumeration’dan gizleyebilir ve doğrudan açma, yeniden adlandırma, ayarlama veya silme işlemlerini engelleyebilir.

`ObRegisterCallbacks` kayıtlarını, registry callback altitude’larını, `fltmc filters` çıktısını, service `Instances` key’lerini ve callback adreslerini ilişkilendirin. Normal araçların çıktısı filtreleniyorsa, bu yapıları çevrimdışı bir memory image’ından veya başka bir trusted acquisition katmanından inceleyin.<sup>[[1]](#references)</sup>

## Nsiproxy sonuç filtreleme

Network gizleme, `\Driver\Nsiproxy`’yi hedefleyebilir: `ObReferenceObjectByName` ile driver object’ini alır, bir handler pointer’ını kaydeder, bunu bir wrapper ile değiştirir ve user mode verileri almadan önce IOCTL ile yönetilen C2 listesiyle eşleşen IPv4 kayıtlarını döndürülen sonuçlardan çıkarır. Filtrelenmiş NSI verilerine dayanan uygulamalar, trafik hâlâ mevcut olsa bile bağlantıyı göstermeyebilir.<sup>[[1]](#references)</sup>

Host’taki bağlantı görünümlerini packet capture, WFP/ETW telemetry’si ve kernel-memory network object’leriyle karşılaştırın. Ayrıca `Nsiproxy` dispatch/handler pointer’larını inceleyin ve her birinin beklenen imzalı module içinde çözümlendiğini doğrulayın; listelenmemiş bir mapping içindeki pointer, network filtrelemesini `PsLoadedModuleList` DKOM’u ile ilişkilendirebilir.<sup>[[1]](#references)</sup>

## İnceleme kontrol listesi

En güçlü sinyal tek bir filename veya hash değil, katmanlar arasındaki uyuşmazlıktır. Şunları ilişkilendirin:<sup>[[1]](#references)</sup>

1. Kernel-service oluşturulması ve sertifika yaşı, publisher’ı veya path’i kurulu ürünle tutarsız olan imzalı bir driver.
2. Device oluşturulması, DOS link’leri ve IOCTL trafiği; buna user-mode ve kernel device adları arasındaki uyuşmazlıklar da dâhildir.
3. Bir PID registration isteğinin ardından, diğer process’lerin aynı object’leri açma, listeleme, değiştirme veya silme girişimlerinde başarısız olması.
4. Object/registry/process/image callback’leri, minifilter instance’ları ve adresleri normal biçimde listelenen bir driver’a ait olmayan hook’lar.
5. Liste tabanlı ve tarama tabanlı process, module, callback ve network envanterleri arasındaki farklar.

## References

- [1] [Kaspersky Securelist - HoneyMyte, CoolClient'ı İmzalı Bir Windows Kernel Rootkit ile Geliştiriyor](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [LocalStranger README dosyası](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [LocalStranger driver başlatma](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [LocalStranger mapper komut satırı](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [LocalStranger kernel export ve PTE-base çözümleme](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [LocalStranger kernel-call trampoline](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [LocalStranger mapper allocation ve entry çağrısı](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [LocalStranger PE mapping](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [LocalStranger kernel ve syscall context’i](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [LocalStranger virtual-memory IOCTL wrapper’ları](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
