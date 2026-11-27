# Windows Exception-Driven Control Flow ve Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

Korunan bir Windows programı, kasıtlı bir exception'ı dallanma noktası olarak kullanabilir: hataya yol açan instruction yalnızca bir handler'a giriş noktasıdır; sonraki user-code adresini handler seçer. Bu, doğrusal disassembly'de kenarları gizler ve sonraki adımı exception dispatch mekanizmasına taşır.<sup>[[1]](#references)</sup>

## Dispatch önemlidir

Sürece bağlı bir debugger, uygulama handler'larından önce bir **first-chance** exception alır. Olayı işlenmemiş olarak iletirse Windows sürecin handler'larını arar; handler'ı olmayan bir exception **last-chance** olarak debugger'a döner. Bu nedenle breakpoint veya single-step olayını tüketen bir debugger, programın handler'ının çalışıp çalışmayacağını değiştirebilir.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)`, süreç genelinde bir VEH'yi vectored list'in başına kaydeder. Bu handler, frame-based SEH'den önce çalışır; ancak daha sonra yapılan bir first-priority kaydı başka bir handler'ı onun önüne alabilir. `EXCEPTION_CONTINUE_SEARCH` döndürmek exception'ı diğer handler'lara bırakır; `EXCEPTION_CONTINUE_EXECUTION` ise handler'ın yaptığı register değişiklikleri de dahil olmak üzere kaydedilmiş `CONTEXT` üzerinden yürütmeyi sürdürür.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Klasik x86 SEH, `!exchain` ile incelenebilen stack-linked kayıtları kullanır. Native x64 ise bu x86 zinciri yerine `.pdata` içindeki `RUNTIME_FUNCTION` girdilerini ve `.xdata` içindeki unwind verilerini kullanır. Native x64 bir sürece [x86 SEH overwrite workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md) uygulamayın.<sup>[[5]](#references)[[6]](#references)</sup>

## Bir hatayı control-flow kenarına dönüştürün

Örneğin sıfıra bölme, bir bug'ı temsil etmek yerine kasıtlı olarak `EXCEPTION_INT_DIVIDE_BY_ZERO` oluşturabilir. Handler exception'ı ve hata adresini tanımalı, ardından `EXCEPTION_CONTINUE_EXECUTION` döndürmeden önce `ContextRecord->Rip` (veya x86'da `Eip`) değerini geçerli bir devam noktasına ayarlamalıdır.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Aşağıdaki handler core, `fault_site` ve `continuation` adreslerinin aynı control-flow context içinde bilindiğini varsayar. Gerçek bir uygulama beklenen stack ve register'ları korumalı ve aynı hataya neden olan instruction'da devam etmemelidir; aksi halde tekrar hata verir.<sup>[[7]](#references)</sup>

```c
if (e->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO &&
    e->ExceptionRecord->ExceptionAddress == fault_site) {
#ifdef _M_X64
    e->ContextRecord->Rip = (DWORD64)continuation;
#else
    e->ContextRecord->Eip = (DWORD)continuation;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}
return EXCEPTION_CONTINUE_SEARCH;
```

Aynı mekanizma, kasıtlı bir `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) istisnasını yakalayıp yürütmeyi başka yere yönlendirebilir. "Breakpoint'i atlamak" için `Rip` değerini gelişigüzel artırmayın: kaydedilen adres ve gerekli düzeltme; tuzağa, talimat kodlamasına ve debugger davranışına bağlıdır. Devam noktasını seçmeden önce `ExceptionRecord->ExceptionAddress` değerini kaydedilen talimat işaretçisiyle karşılaştırın ve baytları disassemble edin.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md), bir loader syscall'ının dönüş durumunu değiştiren ayrı bir hardware-breakpoint örneğidir.

## Hata güdümlü sayfa materyalleştirme

Bir VEH, sayfa hatasını yalnızca bir atlamaya değil, **lazy loader**'a dönüştürebilir. Sayfaları commit edilmemiş halde bırakılmış özel bir image aralığı rezerve edin veya desteklenen durumlarda eşlenmiş sayfaları guard olarak işaretleyin. Image'ı çalıştırmadan önce relocation noktalarını ve IAT thunk'larını hedef sayfalarına göre indeksleyin. Bu aralıkta bir hata oluştuğunda, handler erişilen sayfayı commit eder veya yazılabilir hale getirir, section baytlarını kopyalar, o sayfanın relocation ve import'larını uygular, son koruma ayarını yapar ve `EXCEPTION_CONTINUE_EXECUTION` döndürür. Özgün talimat yeniden denenir; bir hatayı atlayan handler'da olduğu gibi `Rip` değerini artırmayın. Hiç erişilmeyen sayfaların payload'ı bellekte bulundurması gerekmez.<sup>[[11]](#references)</sup>

Bir access violation durumunda, `ExceptionRecord->ExceptionAddress` hataya neden olan **talimatı**, `ExceptionInformation[1]` ise erişilen adresi belirtir.<sup>[[10]](#references)</sup> Bir sayfayı materyalleştirmeden önce exception code'u, parametre sayısını ve erişilen adresin aralığını denetleyin; aksi halde ilgisiz bir hata loader isteği sanılabilir.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD`, ilk erişimde `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) oluşturur ve Windows guard bit'ini otomatik olarak temizler; bu nedenle guard'ı yeniden etkinleştirmek ayrı bir adımdır, kesintisiz bir hook değildir.<sup>[[12]](#references)</sup> VEH'i ve ihtiyaç duyduğu tüm metadata'yı dispatch sırasında erişilebilir tutun.<sup>[[11]](#references)</sup> x64'te, ilk hatadan önce unwind verilerinin erişilebilir olması gerekebilir; atıfta bulunulan loader, initialization race'lerini önlemek için `DllMain`'i çağırmadan önce sayfaları eager olarak materyalleştirir.<sup>[[11]](#references)</sup> Kodu yazdıktan ve çalıştırmadan önce instruction cache'i flush edin.<sup>[[13]](#references)</sup>

Reversing sırasında bu akışı yakalamak için first-chance guard-page violation ve access violation'larda breakpoint koyun, exception record'u inceleyin, ardından `gn` ile olayı uygulamanın handler'ına iletin.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Geçerli sayfa korumasını incelemek için erişilen adreste `!vprot` kullanın.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Handler sayfayı belleğe yükledikten sonra baytlarını döküp dosya imajıyla karşılaştırın.<sup>[[11]](#references)</sup> Fault sonrasında alınan `!vprot` çıktısı, sayfanın önceden guard durumunda olduğunu kanıtlayamaz; çünkü guard durumu tek kullanımlıktır.<sup>[[11]](#references)[[12]](#references)</sup> İlgili image aralığı belirlendikten sonra ilgisiz fault’lardan kaçınmak için exception filtrelerini veya handler breakpoint’lerini daraltın.<sup>[[16]](#references)</sup> Filtre kurulumu için [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) bölümüne bakın.<sup>[[16]](#references)</sup>

## Trap Flag, debugger'a bağlı bir geçit olarak

`EFLAGS`/`RFLAGS` içindeki `0x100` biti Trap Flag'dir (TF). Bu biti ayarlamak, bir sonraki komut sınırında `STATUS_SINGLE_STEP` (`0x80000004`) exception'ının oluşmasına neden olur. Bir VEH veya SEH branch'i, uygulamaya iletilen single-step olayını debugger tarafından tüketilen olaydan ayırt edebilir; ancak bu, debugger'ın var olduğuna dair güvenilir bir kanıt değil, **debugger exception policy tarafından kontrol edilen bir sezgisel yöntemdir**.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Handler yalnızca bir adım istiyorsa, devam etmeden önce devam ettirilen context'in `EFlags` alanındaki `0x100` değerini temizleyin. Tetikleyen adresi ve debug durumunu kontrol ederek TF kaynaklı adımları hardware-breakpoint olaylarından da ayırt edin; her ikisi de `EXCEPTION_SINGLE_STEP` olarak görünebilir.<sup>[[8]](#references)[[9]](#references)</sup> WinDbg'nin `sxe`, `sxd` ve `sxi` birinci/ikinci şans ayarları için bkz. [WinDbg exception otomasyonu](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: İstisnalar](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Debugger İstisna İşleme](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Vectored İstisna İşleme](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64 istisna işleme](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Vectored Exception Handler Kullanma](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Assembly Talimatları](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86 Mimarisi](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Hata kaynaklı image yükleme](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Guard Pages Oluşturma](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (İstisna Kaydını Görüntüleme)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - sx istisna filtreleri](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (İşlenmeyen İstisnayla Devam Et)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
