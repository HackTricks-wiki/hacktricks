# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ açılışta `plugins` alt klasörlerinde bulunan **tüm plugin DLL'lerini otomatik yükler**. Kötü amaçlı bir plugin'i **yazılabilir herhangi bir Notepad++ kurulumuna** bırakmak, düzenleyici her başlatıldığında `notepad++.exe` içinde kod yürütülmesini sağlar. Bu durum **persistence**, gizli **initial execution** veya düzenleyici yükseltilmiş ayrıcalıklarla başlatılıyorsa **in-process loader** olarak kötüye kullanılabilir.<sup>[[1]](#references)</sup>

**Notepad++ 7.6+** sürümünden itibaren beklenen manuel kurulum düzeni, plugin başına bir alt klasördür (`plugins\<PluginName>\<PluginName>.dll`). **Portable mode**'da (`notepad++.exe` yanında `doLocalConf.xml` bulunması), uygulamanın tüm dizin ağacı bu dizinde yerel kalır. Bu özellik, kopyalanmış yönetici araç paketlerini çoğu zaman kullanıcının yazabildiği kolay bir kod yürütme alanına dönüştürür.<sup>[[2]](#references)</sup>

## Yazılabilir plugin konumları

- Standart kurulum: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (yazmak için genellikle yönetici ayrıcalığı gerekir).<sup>[[1]](#references)</sup>
- Düşük ayrıcalıklı operatörler için yazılabilir seçenekler:<sup>[[1]](#references)</sup>
  - Kullanıcının yazabildiği bir klasörde **portable Notepad++ build** kullanın.
  - `C:\Program Files\Notepad++` dizinini kullanıcının denetimindeki bir yola (ör. `%LOCALAPPDATA%\npp\`) kopyalayın ve `notepad++.exe` dosyasını buradan çalıştırın.
  - `doLocalConf.xml` içeren ve `Program Files` dışında bulunan **yönetici araç paketlerini**, çıkarılmış zip kopyalarını veya yardım masası araç setlerini arayın.
- Her plugin, `plugins` altında kendine ait bir alt klasör alır ve başlangıçta otomatik yüklenir; menü girdileri **Plugins** altında görünür.<sup>[[2]](#references)</sup>

Hızlı ön inceleme:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Plugin yükleme noktaları (execution primitives)
Notepad++ belirli **exported functions** bekler. Bunların tümü başlatma sırasında çağrılır ve birden fazla execution yüzeyi sunar:<sup>[[1]](#references)</sup>
- **`DllMain`** — DLL yüklenir yüklenmez çalışır (ilk execution noktası).
- **`setInfo(NppData)`** — Notepad++ handle’larını sağlamak için yükleme sırasında bir kez çağrılır; menü öğelerini kaydetmek için tipik bir yerdir.
- **`getName()`** — menüde gösterilen plugin adını döndürür.
- **`getFuncsArray(int *nbF)`** — menü komutlarını döndürür; boş olsa bile başlangıç sırasında çağrılır.
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla event’lerini alır (payload’ları bir kullanıcı eylemine veya editor event’ine kadar ertelemek için kullanışlıdır).
- **`messageProc(UINT, WPARAM, LPARAM)`** — daha büyük veri alışverişleri için kullanışlı bir message handler.
- **`isUnicode()`** — yükleme sırasında kontrol edilen uyumluluk flag’i.

Çoğu export **stub** olarak uygulanabilir; execution, autoload sırasında `DllMain` veya yukarıdaki herhangi bir callback üzerinden gerçekleşebilir.

## Minimal malicious plugin iskeleti
Beklenen export’lara sahip bir DLL derleyin ve yazılabilir bir Notepad++ klasöründe `plugins\\MyNewPlugin\\MyNewPlugin.dll` konumuna yerleştirin:<sup>[[1]](#references)</sup>

```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```

1. DLL'yi build edin (Visual Studio/MinGW).
2. `plugins` altında plugin alt klasörünü oluşturup DLL'yi içine bırakın.
3. Notepad++'ı yeniden başlatın; DLL otomatik olarak yüklenir ve `DllMain` ile sonraki callback'leri çalıştırır.

## `beNotified` aracılığıyla düşük gürültülü tetikleme kalıbı
OPSEC açısından birçok payload, `DllMain` içinden **çalışmamalıdır**. Daha sessiz bir kalıp, plugin'in sorunsuz yüklenmesini sağlamak ve ardından yalnızca **başlangıcın tamamlanması**, **buffer aktivasyonu** veya **ilk yazılan karakter** gibi gerçekçi bir düzenleyici olayı sonrasında çalıştırmaktır.

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

Bu, gürültülü bir `DllMain` beacon'ına kıyasla kamuya açık offensive research ile daha iyi örtüşür: DLL başlangıçta yine otomatik yüklenir, ancak kötü amaçlı eylem Notepad++ gerçekten kullanılıyor gibi göründüğünde gerçekleştirilir.

## Plugin config directory'yi ikincil depolama olarak kullanma
Notepad++'ta, **geçerli kullanıcının plugin configuration directory** yolunu döndüren `NPPM_GETPLUGINSCONFIGDIR` bulunur.<sup>[[3]](#references)</sup> Kötü amaçlı bir plugin, diskteki DLL'yi minimal tutarken şifrelenmiş config, aşamalandırılmış payload'lar veya görev dosyalarını normal plugin durumuyla uyumlu görünen bir yolda saklamak için bunu kullanabilir.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Operasyonel olarak bu, şunları istediğinizde kullanışlıdır:
- küçük bir autoload bootstrap DLL;
- ana plugin binary dosyasına tekrar dokunmadan kullanıcı başına tasking;
- **autoload trigger**'ını daha ağır second stage'den ayırmak.

## Reflective loader plugin pattern
Weaponized bir plugin, Notepad++'ı **reflective DLL loader**'a dönüştürebilir:<sup>[[1]](#references)</sup>
- Minimal bir UI/menü öğesi (ör. "LoadDLL") sunar.
- Bir payload DLL'i almak için **file path** veya **URL** kabul eder.
- DLL'i geçerli sürece reflective olarak map eder ve dışa aktarılan bir giriş noktasını (ör. alınan DLL içindeki bir loader işlevini) çağırır.
- Avantaj: yeni bir loader başlatmak yerine normal görünen bir GUI sürecini kullanır; payload, `notepad++.exe` dosyasının bütünlük seviyesini devralır (yükseltilmiş bağlamlar dahil).
- Dezavantajlar: diske **unsigned plugin DLL** bırakmak dikkat çeker; pratik bir varyasyon, autoload edilen plugin'i yalnızca bir stub olarak kullanıp gerçek implantı başka bir yerde şifreli/staged tutmaktır.

## Detection and hardening notes
- Notepad++ plugin dizinlerine yazma işlemlerini (kullanıcı profillerindeki portable kopyalar dahil) engelleyin veya izleyin; controlled folder access ya da application allowlisting etkinleştirin.
- `plugins` altında bulunan **unsigned DLL**'ler, portable Notepad++ ağaçlarındaki değişiklikler ve `notepad++.exe` kaynaklı olağandışı **child process/network activity** için uyarı oluşturun.
- Meşru plugin'leri baseline olarak belirleyin ve normal Notepad++ plugin arayüzünü dışa aktaran ancak aynı zamanda shell, PowerShell veya network beacon başlatan yeni DLL'leri araştırın.
- Plugin kurulumunu yalnızca **Plugins Admin** aracılığıyla yapılacak şekilde zorunlu kılın ve güvenilmeyen konumlardan portable kopyaların çalıştırılmasını kısıtlayın.

## References

- [1] [TrustedSec - Notepad++ Eklentileri: Tak ve Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ Kullanım Kılavuzu - Eklentiler](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ Kullanım Kılavuzu - Plugin İletişimi](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
