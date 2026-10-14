# Kernel-Mode File Access Check Bypass'ları

{{#include ../../banners/hacktricks-training.md}}

## Vulnerable driver pattern

Bir driver, yalnızca çağıranı taklit ederek onun güvenlik sınırını korumuş olmaz. Kernel mode'da nesne açma işlemleri normalde erişim denetimlerini atlar. `OBJ_KERNEL_HANDLE` yalnızca ortaya çıkan handle'ın kernel mode'dan erişilebilir olmasını sağlar. Bir driver, user mode adına bir nesneyi açarken veya üzerinde işlem yaparken, Object Manager'ın istenen erişimi etkin token'a göre değerlendirmesi için `OBJ_FORCE_ACCESS_CHECK` de kullanmalıdır.<sup>[[3]](#references)[[4]](#references)</sup>

Dosya işleme IOCTL'larını ve create callback'lerini şu işlem sırasına göre denetleyin:<sup>[[3]](#references)[[4]](#references)</sup>

1. User mode bir path, kaynak handle, istenen erişim veya işlem türü sağlar.
2. Driver çağıranı taklit eder, ancak `OBJ_FORCE_ACCESS_CHECK` olmadan `IoCreateFileEx`, `ZwCreateFile` veya benzer bir routine çağırır.
3. Yalnızca kernel tarafından kullanılabilen bir dosya veya dizin handle'ı handle başına tutulan duruma kaydedilir.
4. Sonraki bir işlem, taklit etme kararını ilk açma sırasında istenen access mask gibi saldırganın etkileyebildiği bir duruma göre verir.
5. Privileged branch, `BypassAccessCheck` information class ile rename veya link işlemi gerçekleştirir.

Bu, **confused-deputy file primitive**'idir; mutlaka memory corruption içermez. Özellikle tehlikeli bir durum tersine çevirmesi, “write istendiyse taklit et; write istenmediyse privileged kal” şeklindedir. Bu tasarımda, bilerek yalnızca read access istemek daha güçlü yolu açabilir.<sup>[[3]](#references)</sup>

## vSMB example: privileged root plus privileged rename

`storvsp.sys`, Virtual Server Message Block (vSMB) bileşenini uygular. **Virtual Machine Platform** özelliği etkinleştirildiğinde user mode, `\\.\STORVSP` üzerinden `\Device\STORVSP` aygıtına erişebilir. Bir vSMB filesystem path'i şu biçimdedir: `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 ve CVE-2025-64673, tutarsız iki access-control kararının bu arayüzü yerel privilege escalation'a nasıl dönüştürebileceğini gösterdi.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Kaynağın function-to-CVE eşlemesi, Microsoft kaynak kodundan değil, yamalanmış binary'nin reverse engineering çalışmasından elde edilmiştir. Araştırmacılar, iki identifier'ın ters function'larla eşleşebileceği konusunda uyarıyor.<sup>[[3]](#references)</sup>

### 1. Protected directory altında köklenen, salt okunur bir share oluşturun

Vulnerable create path, istenen hakları `HasReadAccess`, `HasWriteAccess` ve `HasAppendAccess` gibi kalıcı flag'lere kaydediyordu. Ardından backing path'i `OBJ_KERNEL_HANDLE` ile, ancak `OBJ_FORCE_ACCESS_CHECK` olmadan açıyordu. Bu nedenle, taklit etme girişimi dosya açma işleminin çağıranın NTFS izinlerine uymasını sağlamıyordu.<sup>[[3]](#references)[[4]](#references)</sup>

Yalnızca `FILE_READ_DATA` isteyin. Böylece `HasWriteAccess` ayarlanmadan kalır, ancak kökü protected directory olan bir share yine de elde edilir:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

Önemli bulgu, user-mode System32 dizini handle’ı değildir. Bu, ayrıcalıklı bir kernel root handle içeren driver state ile ilişkili bir vSMB device handle’dır.<sup>[[3]](#references)</sup>

### 2. State mismatch’i korumalı dosya değiştirme işlemine dönüştürme

IOCTL `0x240330`, bir source file handle, bir information class ve değişken uzunlukta bir information buffer kabul ediyordu:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

Savunmasız handler, `FileRenameInformation`, `FileLinkInformation` ve `FileRenameInformationEx` değerlerini kabul ediyordu. Normal bir yeniden adlandırma yolu için üst dizin yolunu son bileşenden ayırıyor, ardından üst dizini saklanan kök handle'a göre açıyordu. Bu açma işleminde de `OBJ_FORCE_ACCESS_CHECK` olmadan `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` kullanılıyordu. Yeniden adlandırma yapısında saldırgan tarafından sağlanan sıfır olmayan bir `RootDirectory` reddediliyor, bu nedenle driver kendi ayrıcalıklı dizin handle'ını sağlıyordu.<sup>[[3]](#references)</sup>

İstismar edilebilir dal, 1. aşamada write access talep **edilmemesiyle** seçiliyordu:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: Saklanan root security context'i impersonate et.
- `HasWriteAccess == 0`: Impersonation'ı atla ve `FileRenameInformation` veya `FileRenameInformationEx` değerini `BypassAccessCheck` varyantına dönüştür.

Handler, saldırgan tarafından sağlanan source handle'ı `PsInitialSystemProcess` içine kopyalıyor, bunu bir file object olarak referans alıyor, ayrıcalıklı hedef dizin handle'ını yeniden adlandırma yapısına yerleştiriyor ve `ZwSetInformationFile` çağrısı yapıyordu. `ReplaceIfExists = TRUE` olduğunda, çağıranın kontrol ettiği bir dosya böylece korunan kök dizinin altındaki mevcut bir dosyanın yerini alabiliyordu.<sup>[[3]](#references)</sup>

Benzer bir handler'ı incelerken her dalda **hem handle'ın kaynağını hem de security context'i** takip edin. Input validation, integer-overflow kontrolleri, `IO_STOP_ON_SYMLINK` ve kabul edilen information class'ları kısıtlamak; ayrıcalıklı bir root handle ile access-check-bypass işleminin birlikte kullanılmasını telafi etmez.<sup>[[3]](#references)</sup>

## Korunan bir dosyaya yazmadan SYSTEM olarak kod çalıştırmaya

Ayrıcalıklı bir process, değiştirilen modülü sonradan yüklediğinde korunan bir dosyayı değiştirme primitive'i kod çalıştırmaya dönüşür. Gösterilen zincirde hedef `C:\Windows\System32\wuapi.dll` idi. Yerel sunucu COM class'ı `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` için `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` interface'ini etkinleştirmek ve `IWaaSRemediation::LaunchDetectionOnly()` çağrısını yapmak, bir SYSTEM process'inin bu DLL'i yüklemesine neden oluyordu.<sup>[[3]](#references)</sup>

Bu COM çağrısı [COM registry hijacking](com-hijacking.md) değil, bir **activation trigger**'ıdır. File primitive yerleştirilen modülü sağlar; ayrıcalıklı loader ise kod çalıştırılmasını sağlar. Diğer korunan dosyaya yazma zincirlerinde hedef seçmeden önce tam image'ı, DLL yolunu, signature policy'yi, bitness'i, export edilen functions'ları ve güvenilir bir trigger'ı belirleyin. Genel loader analizi iş akışı için [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) bölümüne bakın.<sup>[[3]](#references)</sup>

### Session 0 token'ını etkileşimli masaüstüne taşıma

Bir service tarafından yüklenen payload normalde Session 0'da çalışır. Etkileşimli bir process oluşturmak için `WTSGetActiveConsoleSessionId` ile etkin console session'ı alabilir, gerekli token privileges'ı etkinleştirebilir, mevcut SYSTEM token'ını primary token olarak kopyalayabilir ve `TokenSessionId` değerini etkin session'a ayarlayabilir. Ardından `CreateProcessAsUserW`, `STARTUPINFO.lpDesktop = L"winsta0\\default"` ayarıyla bu token'ı kullanır.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege`, bu senaryoda bir token'ın session ID'sini ayarlamak için gereklidir. Etkileşimli window station ve desktop da token'a erişim izni vermelidir. Daha kapsamlı token kopyalama iş akışı için [Session 0'dan token duplication](sedebug-+-seimpersonate-copy-token.md) konusuna bakın.<sup>[[3]](#references)[[5]](#references)</sup>

## Patch ve inceleme rehberi

Microsoft'un Aralık 2025 güncellemeleri, gösterilen zinciri düzeltti. Tersine mühendislik çalışmaları, yamalanmış vSMB create yolunun `FILE_WRITE_DATA` olmadan bir share root isteyen güvenilmeyen çağrıları reddettiğini ortaya çıkardı. İlgili işlemlere zorunlu access checking de eklendi. Bu, ayrıcalıksız bir çağıranın ayrıcalıklı root'u edinmesinden önce state inversion'ı engeller.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Driver kodu için şu kuralları uygulayın:<sup>[[3]](#references)[[4]](#references)</sup>

- Kullanıcı modu isteği adına bir nesne açarken `OBJ_FORCE_ACCESS_CHECK` ekleyin. `OBJ_KERNEL_HANDLE`'ı bir yetkilendirme kontrolü olarak görmeyin.<sup>[[4]](#references)</sup>
- İstekte bulunanın modunu ve etkin subject context'ini alın ve doğrulayın. İstenen hakların daha ayrıcalıklı bir yürütme dalı seçmesine izin vermeyin.
- Kullanıcı handle'larını doğru nesne türü, access mask ve `UserMode` ile doğrulayın. Bir handle'ı system process içine kopyalamak, istenen işlemin yetkisini doğrulamaz.
- Hedef çözümlemesini güvenilir bir handle'a göreli tutun; ancak güvenilir handle'ın kendisinin, istekte bulunan için zorunlu access check uygulanarak açıldığından emin olun.
- Kullanıcı kaynaklı işlemlerde `File*BypassAccessCheck` sınıflarından kaçının. İç kodun bunlara gerçekten ihtiyacı varsa, bu yolu kullanıcı denetimindeki access flag'lerinden bağımsız bir yetkilendirme kararıyla kısıtlayın.
- Etkilenen sistemlere patch uygulayın. Virtual Machine Platform `storvsp.sys` dosyasını yüklediğinde savunmasız yüzey önem taşır.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - Sanal Paylaşımdan Fiziksel Shell'e: LPE için Windows'un Tutarsız Erişim Denetiminden Yararlanma](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Nesne Handle'ları](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - CreateProcessAsUserW işlevi](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
