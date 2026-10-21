# Windows Exception-Driven Control Flow ve Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

Korunan bir Windows programı, kasıtlı bir exception'ı dallanma olarak kullanabilir: hataya neden olan instruction yalnızca bir handler'a giriş noktasıdır; sonraki user-code adresini handler seçer. Bu, doğrusal disassembly'de kenarları gizler ve sonraki adımı exception dispatch aşamasına taşır.<sup>[[1]](#references)</sup>

## Dispatch önemlidir

Sürece bağlı bir debugger, **first-chance** exception'ı uygulama handler'larından önce alır. Olayı işlenmemiş olarak iletirse Windows, sürecin handler'larını arar; handler'ı olmayan bir exception **last-chance** olarak debugger'a döner. Bu nedenle breakpoint veya single-step olayını tüketen bir debugger, programın handler'ının çalışıp çalışmayacağını değiştirebilir.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)`, process-wide bir VEH'yi vectored list'in başına kaydeder. Frame-based SEH'den önce çalışır; ancak daha sonra yapılan bir first-priority kaydı başka bir handler'ı önüne taşıyabilir. `EXCEPTION_CONTINUE_SEARCH` döndürmek exception'ı diğer handler'lara bırakır; `EXCEPTION_CONTINUE_EXECUTION` ise handler tarafından yapılan register değişiklikleri de dahil olmak üzere, kaydedilmiş `CONTEXT` üzerinden yürütmeye devam eder.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Klasik x86 SEH, `!exchain` ile incelenebilen stack-linked kayıtları kullanır. Native x64, bu x86 chain yerine `.pdata` içindeki `RUNTIME_FUNCTION` girdilerini ve `.xdata` içindeki unwind verilerini kullanır. Native x64 bir sürece [x86 SEH overwrite workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md) uygulamayın.<sup>[[5]](#references)[[6]](#references)</sup>

## Bir hatayı control-flow kenarına dönüştürme

Örneğin sıfıra bölme, bir bug'ı temsil etmek yerine kasıtlı olarak `EXCEPTION_INT_DIVIDE_BY_ZERO` oluşturabilir. Handler, exception'ı ve hata adresini tanımalı, ardından `EXCEPTION_CONTINUE_EXECUTION` döndürmeden önce `ContextRecord->Rip` değerini (veya x86'da `Eip` değerini) geçerli bir devam noktasına ayarlamalıdır.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Aşağıdaki handler core, `fault_site` ve `continuation` adreslerinin aynı control-flow context içinde bilindiğini varsayar. Gerçek bir uygulama, beklenen stack ve register değerlerini korumalı; aynı hataya neden olan instruction'da devam etmemelidir, yoksa yeniden hata verir.<sup>[[7]](#references)</sup>

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

Aynı mekanizma, kasıtlı bir `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) olayını yakalayıp yürütmeyi başka yere yönlendirebilir. "Breakpoint'i atlamak" için `Rip` değerini gelişigüzel artırmayın: kaydedilen adres ve gereken düzeltme, tuzağa, komut kodlamasına ve debugger davranışına bağlıdır. Devam konumunu seçmeden önce `ExceptionRecord->ExceptionAddress` değerini kaydedilen komut işaretçisiyle karşılaştırın ve baytları disassemble edin.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md), bir loader syscall'ının dönüş durumunu değiştiren, donanım breakpoint'lerine dayalı ayrı bir örnektir.

## Debugger'a bağlı bir kapı olarak Trap Flag

`EFLAGS`/`RFLAGS` içindeki `0x100` biti, Trap Flag'dir (TF). Bu biti ayarlamak, sonraki komut sınırında `STATUS_SINGLE_STEP` (`0x80000004`) oluşturur. Bir VEH veya SEH dalı, uygulamaya iletilen bir single-step olayını debugger tarafından tüketilen bir olaydan ayırt edebilir; ancak bu, debugger'ın exception politikasına bağlı bir **sezgisel yöntemdir** ve debugger'ın var olduğuna dair güvenilir bir kanıt değildir.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Handler yalnızca bir adım istiyorsa, devam etmeden önce devam ettirilen context'in `EFlags` alanındaki `0x100` bitini temizleyin. Ayrıca tetiklenen adresi ve debug durumunu kontrol ederek TF kaynaklı adımları hardware-breakpoint olaylarından ayırt edin; her ikisi de `EXCEPTION_SINGLE_STEP` olarak görünebilir.<sup>[[8]](#references)[[9]](#references)</sup> WinDbg'nin `sxe`, `sxd` ve `sxi` first-/second-chance ayarları için bkz. [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: İstisnalar](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Debugger İstisna İşleme](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Vectored İstisna İşleme](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64 istisna işleme](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Vectored Exception Handler Kullanımı](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Assembly Talimatları](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86 Mimarisi](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
