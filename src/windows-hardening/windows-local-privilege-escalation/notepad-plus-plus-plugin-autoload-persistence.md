# Notepad++ Plugin Autoload: Persistencija i izvršavanje

{{#include ../../banners/hacktricks-training.md}}

Notepad++ će pri pokretanju **automatski učitati svaku plugin DLL koja se nalazi u njegovim `plugins` podfolderima**. Postavljanje malicioznog plugina u bilo koju **pisivu Notepad++ instalaciju** omogućava izvršavanje koda unutar `notepad++.exe` svaki put kada se editor pokrene, što se može zloupotrebiti za **perzistenciju**, neupadljivo **početno izvršavanje**, ili kao **učitavač u procesu** ako je editor pokrenut sa povišenim privilegijama.

## Lokacije za pisanje plugin-a
- Standardna instalacija: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (obično zahteva administratorska prava za upis).
- Opcije dostupne korisnicima sa ograničenim privilegijama:
- Koristite **portable Notepad++ build** u direktorijumu u koji korisnik može pisati.
- Kopirajte `C:\Program Files\Notepad++` u putanju kojom korisnik kontroliše (npr. `%LOCALAPPDATA%\npp\`) i pokrenite `notepad++.exe` odatle.
- Svaki plugin dobija sopstveni podfolder pod `plugins` i učitava se automatski pri startu; stavke menija pojavljuju se pod **Plugins**.

## Plugin load points (izvršne primitive)
Notepad++ očekuje određene **eksportovane funkcije**. Sve su pozvane tokom inicijalizacije, što daje više površina za izvršavanje:
- **`DllMain`** — izvršava se odmah pri učitavanju DLL-a (prva tačka izvršavanja).
- **`setInfo(NppData)`** — poziva se jednom pri učitavanju da obezbedi Notepad++ handles; tipično mesto za registraciju stavki menija.
- **`getName()`** — vraća ime plugina prikazano u meniju.
- **`getFuncsArray(int *nbF)`** — vraća komande menija; čak i ako je prazna, poziva se tokom starta.
- **`beNotified(SCNotification*)`** — prima događaje editora (otvaranje/izmena fajla, UI događaji) za kontinuirane okidače.
- **`messageProc(UINT, WPARAM, LPARAM)`** — obradnik poruka, koristan za razmenu većih količina podataka.
- **`isUnicode()`** — zastavica kompatibilnosti proveravana pri učitavanju.

Većina export-ova može biti implementirana kao **stubs**; izvršavanje može da se desi iz `DllMain` ili bilo kog callback-a navedenog iznad tokom autoload.

## Minimal malicious plugin skeleton
Kompajlirajte DLL sa očekivanim export-ima i postavite ga u `plugins\\MyNewPlugin\\MyNewPlugin.dll` u okviru pisive Notepad++ fascikle:
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
2. Kreirajte podfolder plugin pod `plugins` i ubacite DLL unutra.
3. Restartujte Notepad++; DLL se automatski učitava, izvršavajući `DllMain` i odgovarajuće callbacks.

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- Prikažite minimalni UI/menu entry (npr. "LoadDLL").
- Prihvatite **file path** ili **URL** za preuzimanje payload DLL-a.
- Reflektivno mapirajte DLL u trenutni proces i pozovite izvezeni entry point (npr. loader funkciju unutar preuzetog DLL-a).
- Prednost: ponovna upotreba benigno-izgledajućeg GUI procesa umesto pokretanja novog loader-a; payload nasleđuje integritet `notepad++.exe` (uključujući povišene kontekste).
- Nedostaci: stavljanje **unsigned plugin DLL** na disk ostavlja trag; razmislite o piggybackingu na postojećim trusted plugins ako su prisutni.

## Detection and hardening notes
- Blokirajte ili nadgledajte **writes to Notepad++ plugin directories** (uključujući portable copies u korisničkim profilima); omogućite controlled folder access ili application allowlisting.
- Generišite upozorenje na **new unsigned DLLs** pod `plugins` i neobičnu **child processes/network activity** iz `notepad++.exe`.
- Sprovodite instalaciju plugin-a isključivo putem **Plugins Admin**, i ograničite izvršavanje portable copies iz nepouzdanih putanja.

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
