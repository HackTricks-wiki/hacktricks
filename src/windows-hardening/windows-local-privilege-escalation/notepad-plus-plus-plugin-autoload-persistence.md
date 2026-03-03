# Notepad++ Eklenti Otomatik Yükleme Kalıcılığı ve Yürütme

{{#include ../../banners/hacktricks-training.md}}

Notepad++ başlatıldığında **`plugins` alt klasörlerinde bulunan her plugin DLL'sini otomatik olarak yükler**. Kötü amaçlı bir eklentiyi herhangi bir **yazılabilir Notepad++ kurulumuna** bırakmak, editör her açıldığında `notepad++.exe` içinde kod yürütmeye imkan verir; bu, **kalıcılık**, gizli **ilk yürütme** veya editör yükseltilmiş olarak başlatıldığında **işlem içi yükleyici** olarak kötüye kullanılabilir.

## Yazılabilir eklenti konumları
- Standart kurulum: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (genellikle yazmak için admin gerektirir).
- Düşük ayrıcalıklı operatörler için yazılabilir seçenekler:
- Kullanıcı tarafından yazılabilir bir klasörde **taşınabilir Notepad++ build** kullanın.
- `C:\Program Files\Notepad++` dizinini kullanıcı kontrollü bir yola (ör. `%LOCALAPPDATA%\npp\`) kopyalayın ve `notepad++.exe`'yi oradan çalıştırın.
- Her eklenti `plugins` altında kendi alt klasörünü alır ve başlangıçta otomatik olarak yüklenir; menü girdileri **Plugins** altında görünür.

## Eklenti yükleme noktaları (yürütme ilkelleri)
Notepad++ belirli **export edilen fonksiyonları** bekler. Bunların tümü initialize sırasında çağrılır ve birden fazla yürütme yüzeyi sağlar:
- **`DllMain`** — DLL yüklendiğinde hemen çalışır (ilk yürütme noktası).
- **`setInfo(NppData)`** — yükleme sırasında bir kez çağrılır ve Notepad++ tutacaklarını sağlar; genellikle menü öğelerini kaydetmek için kullanılır.
- **`getName()`** — menüde gösterilecek eklenti adını döndürür.
- **`getFuncsArray(int *nbF)`** — menü komutlarını döndürür; boş olsa bile başlangıçta çağrılır.
- **`beNotified(SCNotification*)`** — editör olaylarını (dosya açma/değişiklik, UI olayları) alır; devam eden tetiklemeler için kullanışlıdır.
- **`messageProc(UINT, WPARAM, LPARAM)`** — mesaj işleyici; daha büyük veri alışverişleri için faydalıdır.
- **`isUnicode()`** — yüklemede kontrol edilen uyumluluk bayrağı.

Çoğu export **stubs** olarak uygulanabilir; yürütme, autoload sırasında `DllMain` veya yukarıdaki herhangi bir geri çağırmadan gerçekleşebilir.

## Minimal kötü amaçlı eklenti iskeleti
Beklenen export'ları içeren bir DLL derleyin ve yazılabilir bir Notepad++ klasörü altında `plugins\\MyNewPlugin\\MyNewPlugin.dll` konumuna yerleştirin:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLL'i derleyin (Visual Studio/MinGW).
2. `plugins` altında bir plugin alt klasörü oluşturun ve DLL'i içine koyun.
3. Notepad++'ı yeniden başlatın; DLL otomatik olarak yüklenir, `DllMain` ve sonraki callbacks çalıştırılır.

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- Minimal bir UI/menü girdisi sunun (ör. "LoadDLL").
- Bir payload DLL almak için bir **file path** veya **URL** kabul edin.
- DLL'i mevcut prosese reflectively map edin ve dışa aktarılmış bir entry point'i çağırın (ör. alınan DLL içindeki bir loader fonksiyonu).
- Avantaj: yeni bir loader başlatmak yerine zararsız görünen bir GUI sürecini yeniden kullanın; payload `notepad++.exe`'in bütünlüğünü miras alır (yüksek ayrıcalıklı context'ler dahil).
- Dezavantajlar: diske bir **unsigned plugin DLL** bırakmak tespit edilebilir/gürültülüdür; mevcut güvenilir plugin'lere piggyback yapmayı düşünün.

## Tespit ve sertleştirme notları
- Notepad++ plugin dizinlerine yapılan yazma işlemlerini engelleyin veya izleyin (kullanıcı profillerindeki taşınabilir kopyalar dahil); kontrollü klasör erişimini veya uygulama allowlisting'ini etkinleştirin.
- `plugins` altında görülen **yeni unsigned DLL'ler** ve `notepad++.exe`'den kaynaklanan anormal **child processes/network activity** için uyarı oluşturun.
- Plugin kurulumunu yalnızca **Plugins Admin** üzerinden zorunlu kılın ve güvenilmeyen yollarla çalıştırılan taşınabilir kopyaların yürütülmesini kısıtlayın.

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
