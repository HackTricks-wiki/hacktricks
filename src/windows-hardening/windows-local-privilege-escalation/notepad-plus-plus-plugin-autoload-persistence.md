# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ će pri pokretanju **automatski učitati svaki plugin DLL koji pronađe u svojim `plugins` podfolderima**. Postavljanje zlonamernog plugina u bilo koju **Notepad++ instalaciju u koju je moguće upisivati** omogućava izvršavanje koda unutar `notepad++.exe` svaki put kada se editor pokrene, što se može zloupotrebiti za **persistence**, prikriveno **initial execution** ili kao **in-process loader** ako se editor pokrene s povišenim privilegijama.<sup>[[1]](#references)</sup>

Od **Notepad++ 7.6+**, očekivani raspored za ručnu instalaciju je **jedan podfolder po pluginu** (`plugins\<PluginName>\<PluginName>.dll`). U **portable režimu** (kada se `doLocalConf.xml` nalazi pored `notepad++.exe`), celo stablo aplikacije ostaje u tom direktorijumu, što često pretvara kopirane pakete alata za administratore u površinu za izvršavanje kojoj korisnik može lako da pristupi.<sup>[[2]](#references)</sup>

## Lokacije plugina u koje je moguće upisivati

- Standardna instalacija: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (za upis su obično potrebne administratorske privilegije).<sup>[[1]](#references)</sup>
- Opcije dostupne operatorima s niskim privilegijama:<sup>[[1]](#references)</sup>
  - Koristite **portable verziju Notepad++-a** u folderu u koji korisnik može da upisuje.
  - Kopirajte `C:\Program Files\Notepad++` na putanju pod kontrolom korisnika (npr. `%LOCALAPPDATA%\npp\`) i pokrenite `notepad++.exe` iz tog foldera.
  - Potražite **pakete alata za administratore**, raspakovane kopije ZIP arhiva ili komplete alata za help desk koji već sadrže `doLocalConf.xml` i nalaze se izvan foldera `Program Files`.
- Svaki plugin dobija sopstveni podfolder u okviru `plugins` i automatski se učitava pri pokretanju; stavke menija pojavljuju se pod **Plugins**.<sup>[[2]](#references)</sup>

Brza provera:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Tačke učitavanja dodatka (primitivi izvršavanja)
Notepad++ očekuje određene **izvezene funkcije**. Sve se pozivaju tokom inicijalizacije, čime se obezbeđuje više površina za izvršavanje:<sup>[[1]](#references)</sup>
- **`DllMain`** — pokreće se odmah pri učitavanju DLL-a (prva tačka izvršavanja).
- **`setInfo(NppData)`** — poziva se jednom pri učitavanju da bi prosledio Notepad++ ručke; tipično mesto za registrovanje stavki menija.
- **`getName()`** — vraća ime dodatka koje se prikazuje u meniju.
- **`getFuncsArray(int *nbF)`** — vraća komande menija; poziva se tokom pokretanja čak i ako je lista prazna.
- **`beNotified(SCNotification*)`** — prima Notepad++ / Scintilla događaje (korisno za odlaganje payload-a do korisničke radnje ili događaja u uređivaču).
- **`messageProc(UINT, WPARAM, LPARAM)`** — rukovalac porukama, koristan za veće razmene podataka.
- **`isUnicode()`** — zastavica kompatibilnosti koja se proverava pri učitavanju.

Većina izvezenih funkcija može da se implementira kao **stubovi**; izvršavanje može da se pokrene iz `DllMain` ili bilo kog callback-a tokom automatskog učitavanja.

## Minimalni kostur zlonamernog dodatka
Kompajlirajte DLL sa očekivanim izvezenim funkcijama i smestite ga u `plugins\\MyNewPlugin\\MyNewPlugin.dll` unutar upisivog foldera Notepad++:<sup>[[1]](#references)</sup>

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
2. Napravite podfolder za plugin unutar foldera `plugins` i ubacite DLL u njega.
3. Ponovo pokrenite Notepad++; DLL se automatski učitava, izvršavajući `DllMain` i naredne callback funkcije.

## Obrazac okidača sa malo šuma putem `beNotified`
Zbog OPSEC-a, mnogi payload-i ne bi trebalo da se pokreću iz `DllMain`. Diskretniji obrazac je da se plugin učita bez problema, a da se zatim izvrši tek nakon realističnog događaja u editoru, kao što su **dovršetak pokretanja**, **aktivacija bafera** ili **unos prvog karaktera**.

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

Ovo se bolje poklapa sa javno dostupnim ofanzivnim istraživanjima nego bučni beacon u `DllMain`: DLL se i dalje automatski učitava pri pokretanju, ali se zlonamerna radnja odlaže dok Notepad++ zaista ne počne da se koristi.

## Korišćenje direktorijuma za konfiguraciju dodataka kao sekundarnog skladišta
Notepad++ izlaže `NPPM_GETPLUGINSCONFIGDIR`, koji vraća **direktorijum za konfiguraciju dodataka trenutnog korisnika**.<sup>[[3]](#references)</sup> Zlonamerni dodatak može da iskoristi ovo da DLL na disku ostane minimalan, dok se šifrovana konfiguracija, pripremljeni payload-i ili tasking datoteke čuvaju na putanji koja se uklapa u uobičajeno stanje dodataka.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Operativno, ovo je korisno kada želite:
- malu DLL datoteku za automatsko učitavanje;
- tasking po korisniku bez ponovnog menjanja glavne plugin binarne datoteke;
- da odvojite **okidač za automatsko učitavanje** od obimnijeg drugog stepena.

## Obrazac plugin-a za reflective loader
Weaponized plugin može da pretvori Notepad++ u **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Prikažite minimalni UI/stavku menija (npr. „LoadDLL“).
- Prihvatite **putanju do datoteke** ili **URL** za preuzimanje payload DLL-a.
- Reflectively mapirajte DLL u trenutni proces i pozovite izvezenu ulaznu tačku (npr. loader funkciju unutar preuzetog DLL-a).
- Prednost: ponovo koristite GUI proces koji deluje benigno umesto pokretanja novog loader-a; payload nasleđuje nivo integriteta procesa `notepad++.exe` (uključujući kontekste s povišenim privilegijama).
- Kompromisi: upisivanje **unsigned plugin DLL-a** na disk je upadljivo; praktična varijanta je da se plugin koji se automatski učitava koristi samo kao stub, a da se pravi implant čuva šifrovan ili stage-uje na drugom mestu.

## Napomene o detekciji i hardening-u
- Blokirajte ili nadgledajte **upise u Notepad++ plugin direktorijume** (uključujući prenosive kopije u korisničkim profilima); omogućite kontrolisani pristup fasciklama ili allowlisting aplikacija.
- Upozoravajte na **nove unsigned DLL-ove** u fascikli `plugins`, izmene prenosivih Notepad++ stabala i neuobičajene **child procese/mrežnu aktivnost** procesa `notepad++.exe`.
- Napravite osnovni spisak legitimnih plugin-ova i istražite svaki novi DLL koji izvozi uobičajeni Notepad++ plugin interfejs, ali i pokreće shell-ove, PowerShell ili mrežne beacon-e.
- Zahtevajte instalaciju plugin-ova isključivo putem **Plugins Admin** i ograničite izvršavanje prenosivih kopija iz nepouzdanih putanja.

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
