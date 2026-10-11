# KernelFlirt ile Windows Kernel Debugging

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt, kontrollü tersine mühendislik laboratuvarları için kullanılan bir Windows x64 debugger'ıdır. Host tarafındaki WPF UI veya `KfConsole.exe`, test imzalı bir Windows VM'de çalışan `KfRelay.exe`'ye komut gönderir. Relay, bu komutları `KernelFlirt.sys` için `DeviceIoControl` isteklerine dönüştürür; sürücü bellek, register, breakpoint, yürütme denetimi ve kernel modülü işlemlerini sağlar. Sürücü ayrıca `KdpStub`/`KdTrap` inline hook'u ile kernel debugging yolunu değiştirir; bu nedenle yalnızca geçici bir VM'de kullanın.<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

Relay, normal bir uzak hizmetten ziyade ayrıcalıklı bir hata ayıklama sınırıdır. TCP `31337` portunu yalıtılmış bir host-only ağda tutun ve test imzalı driver'ı veya relay'i asla güvenilmeyen bir ağa açmayın.<sup>[[1]](#references)</sup>

İlgili Windows exploitation teknikleri:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Lab kurulumu ve ilk durak

Derlemeler için Windows 10/11 x64, C++ içeren Visual Studio 2022, WDK 10.0.26100.0 veya üzeri ve .NET 9 gerekir. Driver'ı ve relay'i VM içinde yükleyin, ardından host'tan bağlanın. UI, uzak bir EXE veya SYS dosyasını açabilir; **Kernel Modules** görünümü ise önceden yüklenmiş driver'lara breakpoint koyabilir.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Laboratuvar tamamlandığında `KfLoader.exe unload` komutunu kullanın. Konsol; bağlantısız bir REPL’i, doğrudan yerel cihaz erişimini ve relay erişimini destekler; aşağıda açıklanan deterministik `open` iş akışını yalnızca relay modu uygular.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

Minimal bir konsol iş akışı şöyledir:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

Adresler ifadelerdir. Tek başına yazılan sayılar hexadecimal’dir; ifadelerde register’lar, aritmetik işlemler, `[rsp]` gibi dereference işlemleri ve `ntdll!NtCreateFile` gibi semboller kullanılabilir. Sembol breakpoint’leri yalnızca `open` veya `attach` modülleri listeleyip PDB’lerini yükledikten sonra eklenmelidir.<sup>[[2]](#references)</sup>

## `EB FE` ile deterministik giriş noktası yakalama

Relay tarafındaki `open`, hedefi askıya alınmış durumda oluşturur, ilk giriş noktası byte’larını kaydeder, `EB FE` yazar, giriş thread’ini devam ettirir ve instruction pointer bu adrese ulaşana kadar yoklama yapar. `EB FE`, kendisine geri atlayan iki byte’lık kısa bir jump’tır; bu nedenle user-mode debug exception’ın iletilmesine bağlı kalmadan yürütmeyi yakalar. Ardından relay, özgün byte’ları geri yükler ve hedefi giriş noktasında durmuş halde bırakır.<sup>[[2]](#references)</sup>

Bu yöntem, normal debugger kurulumu tamamlanmadan önce erken bir loader yolunun gözlemlenmesi gerektiğinde de kullanışlıdır.<sup>[[2]](#references)</sup>

1. Süreci askıya alınmış durumda oluşturun ve image map edildikten sonra gerçek giriş noktasını bulun.
2. Giriş noktasındaki özgün byte’ları kaydedin ve yerine iki byte’lık self-loop yazın.
3. Giriş thread’ini devam ettirin ve instruction pointer yamalanmış adrese ulaşana kadar yoklama yapın.
4. Hedefi askıya alın ve analiz devam etmeden önce özgün byte’ların tam halini geri yükleyin.

Bu yöntem bilinçli olarak müdahalecidir. Geri yükleme yapılmadan önce debugger veya relay kapanırsa hedef dönüp durabilir. KernelFlirt local mode, relay tarafında giriş noktası yamalama özelliği sunmaz; bunun yerine süreci elle başlatıp `attach <pid>` kullanın.<sup>[[2]](#references)</sup>

## Breakpoint mekanizmasını seçin

KernelFlirt, farklı yan etkileri olan çeşitli breakpoint mekanizmaları sunar. Aşağıdaki komutlar, paketlenmiş kod kendini yeniden yazdığında, executable sayfalar salt okunur olduğunda veya software breakpoint byte’larının bütünlüğü denetlendiğinde analistin mekanizmalar arasında geçiş yapmasını sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

| Mekanizma | Komut | İşleyiş ve kullanım |
| --- | --- | --- |
| Software | `bp <expr>` | MDL destekli `INT3`; RX `.text` sayfalarını instrument edebilir |
| Koşullu software | `bp <expr> if <condition>` | Her isabette değerlendirilir; koşul false olduğunda sessizce devam eder |
| Hardware execute | `ba e1 <expr>` | Kod byte’larını değiştirmeden DR0-DR3’ten birini kullanır |
| Hardware data | `ba w4 <expr>` / `ba r8 <expr>` | 1, 2, 4 veya 8 byte’lık yazma ya da okuma/yazma işlemlerini izler |
| Guard page | `bm <expr> [size]` | Bellek aralığı breakpoint’i için `PAGE_GUARD` kullanır |
| Geçici | `g <expr>`, `p` veya `o` | Adrese kadar çalıştırma, step-over ve step-out yardımcı breakpoint’i |

Software, hardware, memory ve temporary girdileri ayırt etmek için `bl`, bunları kaldırmak için `bc <address|handle|all>` kullanın. Hardware slot’ları sınırlıdır ve debug-register durumu üzerinden uygulanır; guard page’ler ise daha geniş bir aralığı kapsar ancak aynı sayfaya yapılan ilgisiz erişimlerde de tetiklenir.

## Native x64 ile WoW64 üzerinde adımlama

Native x64’te single-step, `IOCTL_KF_SINGLE_STEP` aracılığıyla işlemci trap flag’ini ayarlar. Step Over, geçerli instruction’ı çözümler ve olası sonraki adreslerine geçici breakpoint’ler koyar. Step Out, geçerli stack’in en üstünden dönüş adresini okur. Function prologue’da bu stack varsayımı yanlış olabilir; bu nedenle bilinen bir dahili breakpoint’i tercih edin.<sup>[[2]](#references)</sup>

`KdTrap` hook’u 32-bit exception’ları aynı şekilde yakalamaz. WoW64 hedeflerinde debugger, Iced ile instruction’ı çözümler, hesaplanan sonraki `EIP` adresine `EB FE` yazar ve thread instruction pointer’larını yoklar. Bu nedenle `g <address>` WoW64 için kullanılamaz ve yalın `g` komutu breakpoint’e ulaşılana kadar konsolu bloke eder. Önce erişilebilir bir breakpoint ayarlayın ve süresiz çalıştırmadan kaçının; çünkü `Ctrl+C` yoklamayı iptal etmek yerine konsolu sonlandırır.<sup>[[2]](#references)</sup>

## Bellek, register ve sembol destekli analiz

Konsol, sembolik bir durdurmayı bellek incelemesi ve kontrollü bir yamayla bir arada kullanabilir. Arama çağrıları byte wildcard’larını, ASCII’yi veya UTF-16’yı kabul eder; 4 MB ile sınırlıdır ve en fazla 256 eşleşme bildirir. Allocation ve protection komutları sürücünün allocate, free ve protect IOCTL’lerine karşılık gelir.<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

PDB yükleme, her uzak modülün PE debug dizinini okur, RSDS tanımlayıcısını çıkarır, DbgHelp/SymSrv aracılığıyla eşleşen PDB'yi bulur ve PDB olarak yüklendiğini doğrular. Özel PDB'leri relay makinesinde hedefin yanına yerleştirin veya dizinlerini host üzerindeki `_NT_SYMBOL_PATH`'e ekleyin.<sup>[[2]](#references)</sup>

## Kernel destekli anti-debug durum değişiklikleri

Kernel erişimi, debugger'ın kullanıcı modu debugger'ının güvenilir biçimde gizleyemediği göstergeleri kaldırmasını sağlar. Her seferinde tek bir değişiklik uygulayın, hedefin kontrolünü doğrulayın ve oturumu bitirmeden önce ilgili hook'u geri alın.<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port`, `EPROCESS.DebugPort` değerini temizler.
- `clr_thread_hide`, hedef thread’lerden `HideFromDebugger` değerini kaldırır.
- `ntqsi on`, `NtQuerySystemInformation` sınıfı `0x23`’ü (`SystemKernelDebuggerInformation`) taklit eder.
- `spoof on`, trap mekanizmasının gerektirdiği kernel durumunu korurken kullanıcı modundaki `KUSER_SHARED_DATA.KdDebuggerEnabled` okumalarının false görmesini sağlar.
- `stats`, hook sayaçlarını ve kaydedilen `KiDebugRoutine`, `KdpStub` ve `KdTrap` durumunu denetler.

Bu işlemler process ve kernel durumunu değiştirir. Bir çökme, eski bir inline hook, yanlış bir yapı ofseti veya tamamlanmamış bir yama geri yüklemesi VM’yi kararsız hâle getirebilir; bu nedenle snapshot’lar ve yalıtılmış bir test-signing ortamı zorunludur.<sup>[[1]](#references)</sup>

## References

- [1] [KernelFlirt deposu ve ana belgeleri](https://github.com/AkaTorich/KernelFlirt)
- [2] [KernelFlirt konsol başvuru belgesi](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
