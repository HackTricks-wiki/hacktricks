# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ başlatıldığında `plugins` alt klasörlerinde bulunan her plugin DLL'ini **autoload** eder. Kötü amaçlı bir plugin'i herhangi bir **writable Notepad++ installation** içine koymak, editör her başlatıldığında `notepad++.exe` içinde code execution sağlar; bu durum **persistence**, gizli **initial execution** veya editör yükseltilmiş haklarla başlatıldığında **in-process loader** olarak kötüye kullanılabilir.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (yazmak için genellikle admin gerektirir).
- Writable options for low-privileged operators:
- Kullanıcı tarafından yazılabilir bir klasörde **portable Notepad++ build** kullanın.
- `C:\Program Files\Notepad++` dizinini kullanıcı kontrolündeki bir yola kopyalayın (ör. `%LOCALAPPDATA%\npp\`) ve oradan `notepad++.exe`'yi çalıştırın.
- Her plugin `plugins` altında kendi alt klasörünü alır ve başlatmada otomatik olarak yüklenir; menü girdileri **Plugins** altında görünür.

## Plugin load points (execution primitives)
Notepad++ belirli **exported functions** bekler. Bunların hepsi başlangıç sırasında çağrılır ve birden fazla execution yüzeyi sağlar:
- **`DllMain`** — DLL yüklenir yüklenmez çalışır (first execution point).
- **`setInfo(NppData)`** — yükleme sırasında bir kez çağrılır, Notepad++ handle'larını sağlar; tipik olarak menü öğeleri kaydetmek için kullanılır.
- **`getName()`** — menüde gösterilen plugin adını döndürür.
- **`getFuncsArray(int *nbF)`** — menü komutlarını döndürür; boş olsa bile başlatma sırasında çağrılır.
- **`beNotified(SCNotification*)`** — editör olaylarını (dosya açma/değişiklik, UI olayları) alır; sürekli tetiklemeler için kullanılır.
- **`messageProc(UINT, WPARAM, LPARAM)`** — mesaj işleyici, büyük veri alışverişleri için kullanışlıdır.
- **`isUnicode()`** — yüklemede kontrol edilen uyumluluk bayrağıdır.

Çoğu export **stubs** olarak uygulanabilir; execution, autoload sırasında `DllMain`'den veya yukarıdaki herhangi bir callback'ten gerçekleşebilir.

## Minimal malicious plugin skeleton
Beklenen export'larla bir DLL derleyin ve yazılabilir bir Notepad++ klasörü altındaki `plugins\\MyNewPlugin\\MyNewPlugin.dll` yoluna koyun:
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
2. `plugins` altında plugin alt klasörü oluşturun ve DLL'i içine koyun.
3. Notepad++'ı yeniden başlatın; DLL otomatik olarak yüklenir ve `DllMain` ile sonraki callback'leri çalıştırır.

## Reflective loader plugin pattern
Kötü amaçlı bir eklenti Notepad++'ı bir **reflective DLL loader**'a dönüştürebilir:
- Minimal bir UI/menü girişi sunun (ör. "LoadDLL").
- Bir payload DLL almak için bir **dosya yolu** veya **URL** kabul edin.
- DLL'i mevcut işleme reflectively map edin ve dışa aktarılmış bir giriş noktasını çağırın (ör. indirilmiş DLL içindeki bir loader fonksiyonu).
- Avantaj: yeni bir loader başlatmak yerine zararsız görünen bir GUI sürecini yeniden kullanma; payload, `notepad++.exe`'in bütünlüğünü devralır (yükseltilmiş bağlamlar dahil).
- Dezavantajlar: diske bir **unsigned plugin DLL** bırakmak gürültülü olabilir; mevcut güvenilir eklentilere piggyback yapmayı düşünün.

## Tespit ve sertleştirme notları
- **Notepad++ plugin dizinlerine yapılan yazmaları** (kullanıcı profillerindeki taşınabilir kopyalar dahil) engelleyin veya izleyin; Controlled Folder Access veya uygulama allowlisting'i etkinleştirin.
- `plugins` altındaki **yeni imzasız DLL'ler** ve `notepad++.exe`'den gelen olağandışı **alt süreçler/ağ etkinliği** için uyarı verin.
- Eklenti kurulumunu yalnızca **Plugins Admin** üzerinden zorunlu kılın ve taşınabilir kopyaların güvenilmeyen yollarından çalıştırılmasını kısıtlayın.

## Referanslar
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
