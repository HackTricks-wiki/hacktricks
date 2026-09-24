# Windows Kernel Rootkits ve DKOM

{{#include ../../banners/hacktricks-training.md}}

## Kapsam

Compromise sonrası bir implant, imzalı bir kernel driver'ını service olarak yükleyebilir ve `IRP_MJ_DEVICE_CONTROL` üzerinden user-mode bir control plane sunabilir. Driver signing yalnızca Windows'un image'ı kabul ettiğini gösterir; IOCTL authorization, memory operations, callbacks veya hooks işlemlerinin güvenli olduğunu göstermez. Analiz edilen bir rootkit, normal çalışma sırasında üç handler kullanırken düzinelerce ek post-exploitation primitive'i açığa çıkarıyordu; bu nedenle reverse engineering yalnızca bir malware trace'inde gözlemlenen request'lerle sınırlı kalmamalı, dispatcher'ın tamamını kapsamalıdır.<sup>[[1]](#references)</sup>

## Signed-driver ve IOCTL triage

`DriverEntry` ile başlayın, device object'leri ve DOS symbolic link'lerini kaydedin, `MajorFunction[IRP_MJ_DEVICE_CONTROL]` routine'ini bulun ve bir handler'a ulaşan her comparison/table entry'yi eşleyin. User mode tarafından açılan adları driver tarafından gerçekten oluşturulan adlarla karşılaştırın: gözlemlenen bir chain `\\.\msagent` açarken driver `\Device\ToolTool` ve `\DosDevices\ToolTool` oluşturuyordu. Bu uyumsuzluk başka bir sample/configuration, eksik setup logic'i veya bir analysis inconsistency'si tespit edebilir.<sup>[[1]](#references)</sup>

Her control code'u input structure'ını yeniden oluşturmadan önce decode edin.<sup>[[1]](#references)</sup>
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
Bu üç kod `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` ve `METHOD_BUFFERED` olarak decode edilir. Bu, ayrıcalıksız bir caller'ın bunlara erişebildiğini **kanıtlamaz**: ayrıca device DACL'sini, create/open dispatch mekanizmasını, istek başına caller kontrollerini, beklenen buffer uzunluklarını, embedded pointer'ları, PID yaşam döngüsü işlemlerini ve handler'ın caller tarafından sağlanan bir PID veya flag'e güvenip güvenmediğini inceleyin.<sup>[[1]](#references)</sup>

Implant yalnızca komutların bir alt kümesini kullandığında, kalan handler'ları dead code olarak göz ardı etmek yerine primitive'e göre gruplandırın. Tek bir multifunction driver aşağıdaki sınıfların tümünü açığa çıkarmıştır:<sup>[[1]](#references)</sup>

- **Kontrol/yapılandırma:** rootkit durumunu değiştirme; korunan path'leri, process'leri ve C2 adreslerini ekleme, kaldırma, sorgulama veya temizleme.
- **Process manipulation:** bir PID'yi sonlandırma, image'ını unmap etme, `NtCreateThreadEx` ile inject etme, process'leri veya user module'lerini gizleme/geri yükleme ve PPL korumasını kaldırma.
- **Kernel manipulation:** yüklenmiş bir driver'ı unlink etme, notification callback'lerini enumerate/disable/restore etme, başka bir driver'ı manual map etme ve rastgele bir kernel adresine yazma.
- **Object manipulation:** file'ları silme/decrypt etme ve registry value'larını oluşturma veya değiştirme.

## Trusted-process exemptions

Yararlı bir tasarım modeli, bir PID ile **trusted** flag'ini kaydeden bir IOCTL'dir. Aynı trust lookup daha sonra file, registry, process ve thread filter'ları tarafından kullanılır: trusted olmayan araçlar filtrelenmiş enumeration sonuçları, azaltılmış handle hakları veya `STATUS_ACCESS_DENIED` alırken implant kendi hidden object'lerini güncelleyebilir. Bunu bir authorization boundary olarak ele alın ve entry'lerin nasıl authenticate edildiğini, synchronize edildiğini ve process exit veya PID reuse sonrasında kaldırıldığını doğrulayın.<sup>[[1]](#references)</sup>

Rootkit'ler policy'yi `REG_MULTI_SZ` value'larında kalıcı hâle getirebilir ve file, directory, registry-key, registry-value, ignored-image, protected-image ve hidden-image listelerini AVL tree'lerine compile edebilir. Analysis sırasında bu paylaşılan tree'lerin her reader ve writer'ını trace edin; bu, function name'leri strip edilmiş olsa bile registry configuration, IOCTL'ler, callback'ler ve filtering logic arasındaki bağlantıyı ortaya çıkarır.<sup>[[1]](#references)</sup>

## DKOM process and module hiding

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks` offset'leri Windows build'ine göre değişir. Version-tolerant bir rootkit, bilinen candidate'leri test edebilir ve ardından `EPROCESS` içinde komşuları candidate'e geri işaret eden, kendi içinde tutarlı bir `LIST_ENTRY` tarayabilir. Keşfedilen offset'i saklar, komşularının `Flink`/`Blink` değerlerini yeniden bağlayarak bir process'i gizler ve entry'yi daha sonra yeniden bağlamak için durumu korur. Process çalışmaya devam eder ancak active-process list üzerinde yürüyen enumerator'larda görünmez.<sup>[[1]](#references)</sup>

Bu, termination değil **DKOM**'dur. Detection, list tabanlı sonuçları pool/object scan'leri, thread ownership, handle table'ları, scheduler artifact'leri ve kernel memory inspection gibi bağımsız kanıtlarla karşılaştırmalıdır. Bir scan'de görünen ancak canonical list'te bulunmayan bir process, tek başına bu görünümlerden herhangi birinden daha anlamlıdır.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Eşdeğer module-hiding primitive'i hedef entry'yi `PsLoadedModuleList` içinde bulur ve bitişik `Flink`/`Blink` pointer'larını patch eder. Driver mapped ve executable durumda kalır, ancak list-backed module query'leri onu içermez. Loader list'ini executable kernel mapping'leri, pool tag'leri, device/driver object'leri, service key'leri, callback address'leri ve listed image dışında bir konuma ulaşan dispatch pointer'larıyla karşılaştırın.<sup>[[1]](#references)</sup>

## Callback-based protection and cloaking

Bir rootkit, documented callback framework'lerini DKOM ve hook'larla katmanlayabilir:<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks`, `PsProcessType` ve `PsThreadType` için pre-operation handler'ları kullanarak, trusted olmayan bir caller korunan bir hedefi açtığında termination, VM access, duplication veya thread manipulation için kullanılan hakları kaldırır. Callback altitude'unu kaydedin ve her callback address'ini sahibi olan module'e resolve edin.
- `PsSetCreateProcessNotifyRoutineEx` ve `PsSetLoadImageNotifyRoutine`, process'ler ve image'lar ortaya çıktıkça protected/ignored/hidden process durumunu korur; one-time process walk, registration'dan önce var olan object'leri backfill edebilir.
- Bir filesystem minifilter, yapılandırılmış path'lere erişimi reddeder. Olağandışı bir implementation kendi `Instances` key'ini oluşturabilir, bir altitude'u dinamik olarak seçebilir ve `FltRegisterFilter` bir collision bildirdiğinde değeri artırıp yeniden deneyebilir.
- Bir `CmRegisterCallbackEx` routine'i protected name'leri enumeration'dan bastırabilir ve registered trusted process'leri hariç tutarken doğrudan open, rename, set veya delete işlemlerini reddedebilir.

`ObRegisterCallbacks` registration'larını, registry-callback altitude'larını, `fltmc filters` çıktısını, service `Instances` key'lerini ve callback address'lerini correlate edin. Normal araçlar filtreleniyorsa bu yapıları offline memory image'dan veya başka bir trusted acquisition layer'dan inceleyin.<sup>[[1]](#references)</sup>

## Nsiproxy result filtering

Network concealment, `\Driver\Nsiproxy`'yi hedefleyebilir: `ObReferenceObjectByName` ile driver object'i alın, bir handler pointer'ını kaydedin, onu bir wrapper ile değiştirin ve user mode'a ulaşmadan önce döndürülen, IOCTL-managed C2 listesiyle eşleşen IPv4 record'larını kaldırın. Filtrelenmiş NSI data'sına dayanan application'lar, traffic hâlâ mevcut olsa bile connection'ı artık göstermeyebilir.<sup>[[1]](#references)</sup>

Host connection görünümlerini packet capture, WFP/ETW telemetry ve kernel-memory network object'leriyle karşılaştırın. Ayrıca `Nsiproxy` dispatch/handler pointer'larını inceleyin ve her birinin beklenen signed module içinde resolve olduğunu doğrulayın; unlisted bir mapping içindeki pointer, network filtering'i `PsLoadedModuleList` DKOM ile ilişkilendirebilir.<sup>[[1]](#references)</sup>

## Investigation checklist

En güçlü sinyal tek bir filename veya hash değil, layer'lar arasındaki uyuşmazlıktır. Şunları correlate edin:<sup>[[1]](#references)</sup>

1. Kernel-service creation ve certificate age'i, publisher'ı veya path'i installed product ile tutarsız olan signed bir driver.
2. Device creation, DOS link'leri ve IOCTL traffic'i; buna user-mode ve kernel device name'leri arasındaki uyuşmazlıklar da dahildir.
3. Bir PID registration request'ini, diğer process'lerin aynı object'leri open, enumerate, modify veya delete etmesinin başarısız olması takip eder.
4. Address'leri normal şekilde enumerate edilen bir driver'a ait olmayan object/registry/process/image callback'leri, minifilter instance'ları ve hook'lar.
5. List-based ve scan-based process, module, callback ve network inventory'leri arasındaki farklar.

## References

- [1] [Kaspersky Securelist - HoneyMyte Enhances CoolClient with a Signed Windows Kernel Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
