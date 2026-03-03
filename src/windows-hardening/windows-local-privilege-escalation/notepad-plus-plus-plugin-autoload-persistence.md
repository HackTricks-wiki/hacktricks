# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ će **autoload every plugin DLL found under its `plugins` subfolders** pri pokretanju. Ubacivanje malicioznog plugin-a u bilo koju **writable Notepad++ installation** daje code execution unutar `notepad++.exe` svaki put kada se editor pokrene, što se može zloupotrebiti za **persistence**, prikriveno **initial execution**, ili kao **in-process loader** ako je editor pokrenut elevated.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (obično zahteva administratorska prava za pisanje).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g., `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

## Plugin load points (execution primitives)
Notepad++ očekuje specifične **exported functions**. Sve su pozvane tokom inicijalizacije, pružajući više površina za izvršavanje:
- **`DllMain`** — pokreće se odmah pri učitavanju DLL-a (prva tačka izvršavanja).
- **`setInfo(NppData)`** — poziva se jednom pri učitavanju da obezbedi Notepad++ handle-ove; tipično mesto za registraciju stavki menija.
- **`getName()`** — vraća ime plugin-a prikazano u meniju.
- **`getFuncsArray(int *nbF)`** — vraća komande menija; čak i ako je prazno, poziva se tokom pokretanja.
- **`beNotified(SCNotification*)`** — prima događaje editora (otvaranje/izmena fajla, UI događaji) za kontinuirane okidače.
- **`messageProc(UINT, WPARAM, LPARAM)`** — handler poruka, koristan za razmenu većih količina podataka.
- **`isUnicode()`** — kompatibilnosni flag koji se proverava pri učitavanju.

Većina export-a može biti implementirana kao **stubs**; izvršavanje može nastupiti iz `DllMain` ili bilo kog callback-a iznad tokom autoload.

## Minimal malicious plugin skeleton
Kompajlirajte DLL sa očekivanim export-ima i stavite ga u `plugins\\MyNewPlugin\\MyNewPlugin.dll` pod zapisivim Notepad++ folderom:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Sastavite DLL (Visual Studio/MinGW).
2. Kreirajte podfolder za plugin pod `plugins` i ubacite DLL unutra.
3. Ponovo pokrenite Notepad++; DLL se učitava automatski, izvršavajući `DllMain` i sledeće callbacks.

## Reflective loader plugin pattern
Zlonamerni plugin može pretvoriti Notepad++ u **reflective DLL loader**:
- Prikažite minimalni UI/menijski unos (npr. "LoadDLL").
- Prihvata **file path** ili **URL** za preuzimanje payload DLL-a.
- Reflectively map the DLL into the current process and invoke an exported entry point (e.g., a loader function inside the fetched DLL).
- Prednost: ponovna upotreba benigno-izgledajućeg GUI procesa umesto pokretanja novog loader-a; payload nasleđuje integritet `notepad++.exe` (uključujući povišene kontekste).
- Mane: ispuštanje **unsigned plugin DLL** na disk je bučno; razmotrite piggybacking na postojećim trusted plugin-ima ako su prisutni.

## Napomene za detekciju i hardening
- Blokirajte ili nadgledajte **writes to Notepad++ plugin directories** (uključujući portable copies u user profilima); omogućite controlled folder access ili application allowlisting.
- Upozorite na **new unsigned DLLs** pod `plugins` i neobičnu **child processes/network activity** od `notepad++.exe`.
- Sprovodite instalaciju plugin-a samo preko **Plugins Admin**, i ograničite izvršavanje portable kopija sa nepouzdanih putanja.

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
