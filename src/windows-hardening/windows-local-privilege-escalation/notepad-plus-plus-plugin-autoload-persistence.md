# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ će **automatski učitati svaki plugin DLL pronađen u njegovim `plugins` podfolderima** pri pokretanju. Ubacivanje malicioznog plugina u bilo koju **Notepad++ instalaciju sa dozvolom upisa** omogućava izvršavanje koda unutar procesa `notepad++.exe` pri svakom pokretanju editora, što se može zloupotrebiti za **persistence**, prikriveno **initial execution** ili kao **in-process loader** ako je editor pokrenut sa povišenim privilegijama.<sup>[[1]](#references)</sup>

Od verzije **Notepad++ 7.6+**, očekivani raspored za ručnu instalaciju je **jedan podfolder po pluginu** (`plugins\<PluginName>\<PluginName>.dll`). U **portable mode** (kada postoji `doLocalConf.xml` pored `notepad++.exe`), celo stablo aplikacije ostaje lokalno u tom direktorijumu, zbog čega kopirani/admin tool bundles često predstavljaju lako dostupnu user-writable površinu za izvršavanje.<sup>[[2]](#references)</sup>

## Lokacije pluginova sa dozvolom upisa

- Standardna instalacija: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (za upis su obično potrebne admin privilegije).<sup>[[1]](#references)</sup>
- Opcije sa dozvolom upisa za operatore sa niskim privilegijama:<sup>[[1]](#references)</sup>
- Koristite **portable Notepad++ build** u folderu u koji korisnik može da upisuje.
- Kopirajte `C:\Program Files\Notepad++` na putanju pod kontrolom korisnika (npr. `%LOCALAPPDATA%\npp\`) i pokrenite `notepad++.exe` iz te lokacije.
- Pretražite **admin tool bundles**, raspakovane zip kopije ili help-desk toolkits koji već sadrže `doLocalConf.xml` i nalaze se izvan `Program Files`.
- Svaki plugin ima sopstveni podfolder unutar `plugins` i automatski se učitava pri pokretanju; stavke menija pojavljuju se pod **Plugins**.<sup>[[2]](#references)</sup>

Brza trijaža:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Tačke učitavanja plugin-a (primitives izvršavanja)
Notepad++ očekuje određene **exported functions**. Sve se pozivaju tokom inicijalizacije, što pruža više površina za izvršavanje:<sup>[[1]](#references)</sup>
- **`DllMain`** — izvršava se odmah pri učitavanju DLL-a (prva tačka izvršavanja).
- **`setInfo(NppData)`** — poziva se jednom pri učitavanju radi prosleđivanja Notepad++ handles; uobičajeno mesto za registrovanje stavki menija.
- **`getName()`** — vraća naziv plugin-a prikazan u meniju.
- **`getFuncsArray(int *nbF)`** — vraća komande menija; čak i ako je prazan, poziva se tokom pokretanja.
- **`beNotified(SCNotification*)`** — prima Notepad++ / Scintilla događaje (korisno za odlaganje payload-a do korisničke radnje ili događaja u editoru).
- **`messageProc(UINT, WPARAM, LPARAM)`** — handler za poruke, koristan za veće razmene podataka.
- **`isUnicode()`** — compatibility flag koji se proverava pri učitavanju.

Većina export-ova može biti implementirana kao **stubs**; izvršavanje može da se odvija iz `DllMain` ili bilo kog callback-a iznad tokom autoload-a.

## Minimalni skeleton malicious plugin-a
Kompajlirajte DLL sa očekivanim export-ovima i postavite ga u `plugins\\MyNewPlugin\\MyNewPlugin.dll`, unutar Notepad++ foldera sa dozvolom upisivanja:<sup>[[1]](#references)</sup>
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Build the DLL (Visual Studio/MinGW).
2. Kreirajte podfolder plugina unutar `plugins` i ubacite DLL u njega.
3. Ponovo pokrenite Notepad++; DLL se automatski učitava, izvršavajući `DllMain` i naknadne callbacks.

## Low-noise trigger pattern putem `beNotified`
Radi OPSEC-a, mnogi payloads ne bi trebalo da se pokreću iz `DllMain`. Tiši obrazac je da se plugin učita bez problema, a zatim izvrši tek nakon realističnog događaja u editoru, kao što su **završetak pokretanja**, **aktivacija buffera** ili **prvi otkucani karakter**.
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
Ovo se bolje uklapa u javno istraživanje ofanzivnih tehnika od bučnog `DllMain` beacon-a: DLL se i dalje automatski učitava pri pokretanju, ali se zlonamerna radnja odlaže dok Notepad++ ne počne da se zaista koristi.

## Korišćenje direktorijuma konfiguracije plugina kao sekundarnog skladišta
Notepad++ izlaže `NPPM_GETPLUGINSCONFIGDIR`, koji vraća **direktorijum konfiguracije plugina trenutno prijavljenog korisnika**.<sup>[[3]](#references)</sup> Maliciozni plugin može ovo da koristi kako bi DLL na disku ostao minimalan, dok se šifrovana konfiguracija, staged payloads ili tasking fajlovi čuvaju na putanji koja se uklapa u uobičajeno stanje plugina.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operativno je ovo korisno kada želite:
- mali autoloaded bootstrap DLL;
- tasking po korisniku bez ponovnog menjanja glavnog plugin binary-ja;
- da odvojite **autoload trigger** od težeg second stage-a.

## Reflective loader plugin pattern
Weaponized plugin može pretvoriti Notepad++ u **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Prikažite minimalni UI/menu entry (npr. "LoadDLL").
- Prihvatite **file path** ili **URL** za preuzimanje payload DLL-a.
- Reflectively map-ujte DLL u trenutni proces i pozovite exported entry point (npr. loader funkciju unutar preuzetog DLL-a).
- Prednost: ponovna upotreba GUI procesa koji izgleda benigno, umesto pokretanja novog loader-a; payload nasleđuje integrity nivo procesa `notepad++.exe` (uključujući elevated contexts).
- Kompromisi: upisivanje **unsigned plugin DLL-a** na disk je upadljivo; praktična varijanta je da se autoloaded plugin koristi samo kao stub, dok se pravi implant čuva encrypted/staged na drugoj lokaciji.

## Napomene o detekciji i hardening-u
- Blokirajte ili nadgledajte **upise u Notepad++ plugin direktorijume** (uključujući portable kopije u user profilima); omogućite controlled folder access ili application allowlisting.
- Upozorite na **nove unsigned DLL-ove** u direktorijumu `plugins`, izmene portable Notepad++ stabala i neuobičajene **child procese/network activity** iz `notepad++.exe`.
- Napravite baseline legitimnih plugin-ova i istražite svaki novi DLL koji export-uje normalni Notepad++ plugin interface, ali takođe pokreće shell-ove, PowerShell ili network beacon-e.
- Zahtevajte instalaciju plugin-ova isključivo putem **Plugins Admin-a** i ograničite execution portable kopija iz nepouzdanih putanja.

## Reference

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
