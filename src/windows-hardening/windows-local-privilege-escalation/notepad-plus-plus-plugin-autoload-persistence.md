# Persistence i wykonanie przez automatyczne ładowanie pluginów Notepad++

{{#include ../../banners/hacktricks-training.md}}

Notepad++ będzie **automatycznie ładować każdy plugin DLL znaleziony w podfolderach `plugins`** podczas uruchamiania. Umieszczenie złośliwego pluginu w dowolnej **zapisywalnej instalacji Notepad++** zapewnia code execution wewnątrz `notepad++.exe` przy każdym uruchomieniu edytora, co może zostać wykorzystane do **persistence**, ukrytego **initial execution** lub jako **in-process loader**, jeśli edytor zostanie uruchomiony z podwyższonymi uprawnieniami.<sup>[[1]](#references)</sup>

Od wersji **Notepad++ 7.6+** oczekiwany układ ręcznej instalacji to **jeden podfolder na plugin** (`plugins\<PluginName>\<PluginName>.dll`). W **portable mode** (gdy obok `notepad++.exe` znajduje się `doLocalConf.xml`) całe drzewo aplikacji pozostaje lokalne dla tego katalogu, co często zamienia skopiowane zestawy narzędzi administratora w łatwo zapisywalny przez użytkownika execution surface.<sup>[[2]](#references)</sup>

## Zapisywalne lokalizacje pluginów

- Standardowa instalacja: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (zwykle zapis wymaga uprawnień administratora).<sup>[[1]](#references)</sup>
- Zapisywalne opcje dla operatorów z niskimi uprawnieniami:<sup>[[1]](#references)</sup>
- Użyj **portable build Notepad++** w folderze zapisywalnym dla użytkownika.
- Skopiuj `C:\Program Files\Notepad++` do ścieżki kontrolowanej przez użytkownika (np. `%LOCALAPPDATA%\npp\`) i uruchom `notepad++.exe` z tego miejsca.
- Poszukaj **zestawów narzędzi administratora**, rozpakowanych kopii ZIP lub toolkitów help-desk, które już zawierają `doLocalConf.xml` i znajdują się poza `Program Files`.
- Każdy plugin otrzymuje własny podfolder w `plugins` i jest automatycznie ładowany podczas uruchamiania; wpisy menu pojawiają się w sekcji **Plugins**.<sup>[[2]](#references)</sup>

Szybki triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Punkty ładowania pluginu (execution primitives)
Notepad++ oczekuje określonych **eksportowanych funkcji**. Wszystkie są wywoływane podczas inicjalizacji, zapewniając wiele punktów wykonania:<sup>[[1]](#references)</sup>
- **`DllMain`** — uruchamiana natychmiast po załadowaniu DLL (pierwszy punkt wykonania).
- **`setInfo(NppData)`** — wywoływana raz podczas ładowania w celu przekazania uchwytów Notepad++; typowe miejsce do rejestrowania elementów menu.
- **`getName()`** — zwraca nazwę pluginu wyświetlaną w menu.
- **`getFuncsArray(int *nbF)`** — zwraca polecenia menu; nawet jeśli jest puste, funkcja ta jest wywoływana podczas uruchamiania.
- **`beNotified(SCNotification*)`** — odbiera zdarzenia Notepad++ / Scintilla (przydatne do odroczenia payloadów do czasu działania użytkownika lub zdarzenia edytora).
- **`messageProc(UINT, WPARAM, LPARAM)`** — handler komunikatów, przydatny przy większych wymianach danych.
- **`isUnicode()`** — flaga zgodności sprawdzana podczas ładowania.

Większość eksportów można zaimplementować jako **stub**; wykonanie może nastąpić z `DllMain` lub dowolnego powyższego callbacku podczas autoload.

## Minimalny złośliwy szkielet pluginu
Skompiluj DLL z oczekiwanymi eksportami i umieść ją w `plugins\\MyNewPlugin\\MyNewPlugin.dll` w zapisywalnym folderze Notepad++:<sup>[[1]](#references)</sup>
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Zbuduj DLL (Visual Studio/MinGW).
2. Utwórz podfolder pluginu w `plugins` i umieść w nim DLL.
3. Uruchom ponownie Notepad++; DLL zostanie automatycznie załadowany, wykonując `DllMain` i kolejne callbacks.

## Wzorzec triggera o niskim poziomie szumu za pośrednictwem `beNotified`
Ze względów OPSEC wiele payloadów nie powinno uruchamiać się z poziomu `DllMain`. Cichszym rozwiązaniem jest umożliwienie prawidłowego załadowania pluginu, a następnie wykonanie kodu dopiero po realistycznym zdarzeniu edytora, takim jak **ukończenie uruchamiania**, **aktywacja bufora** lub **wpisanie pierwszego znaku**.
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
To lepiej odpowiada publicznym badaniom ofensywnym niż głośny beacon w `DllMain`: DLL nadal jest automatycznie ładowana podczas uruchamiania, ale złośliwe działanie jest opóźniane do momentu, gdy Notepad++ faktycznie zacznie być używany.

## Używanie katalogu konfiguracji pluginu jako dodatkowego storage
Notepad++ udostępnia `NPPM_GETPLUGINSCONFIGDIR`, który zwraca **katalog konfiguracji pluginów bieżącego użytkownika**.<sup>[[3]](#references)</sup> Złośliwy plugin może wykorzystać go do utrzymania minimalnego rozmiaru DLL na dysku, przechowując zaszyfrowaną konfigurację, staged payloads lub pliki taskingu w ścieżce, która wygląda jak typowy stan pluginu.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operacyjnie jest to przydatne, gdy chcesz:
- mały, automatycznie ładowany bootstrap DLL;
- tasking per-user bez ponownego modyfikowania głównego pliku binarnego pluginu;
- oddzielić **trigger autoload** od cięższego second stage.

## Wzorzec pluginu Reflective loader
Uzbrojony plugin może zmienić Notepad++ w **Reflective DLL loader**:<sup>[[1]](#references)</sup>
- Udostępniać minimalny interfejs/menu (np. "LoadDLL").
- Przyjmować **ścieżkę do pliku** lub **URL** w celu pobrania payload DLL.
- Mapować DLL do bieżącego procesu za pomocą Reflective loadera i wywoływać eksportowany entry point (np. funkcję loadera wewnątrz pobranej DLL).
- Korzyść: ponowne wykorzystanie procesu GUI wyglądającego na nieszkodliwy zamiast uruchamiania nowego loadera; payload dziedziczy poziom integralności `notepad++.exe` (w tym konteksty z podwyższonymi uprawnieniami).
- Kompromisy: zapisanie **niepodpisanego pluginu DLL** na dysku jest łatwe do wykrycia; praktycznym wariantem jest użycie automatycznie ładowanego pluginu wyłącznie jako stubu i przechowywanie właściwego implantu w postaci zaszyfrowanej lub staged w innym miejscu.

## Uwagi dotyczące detekcji i hardeningu
- Blokuj lub monitoruj **zapisy do katalogów pluginów Notepad++** (w tym kopie portable w profilach użytkowników); włącz controlled folder access lub application allowlisting.
- Generuj alerty dotyczące **nowych niepodpisanych DLL** w katalogach `plugins`, zmian w drzewach portable Notepad++ oraz nietypowych **procesów potomnych/aktywności sieciowej** pochodzących z `notepad++.exe`.
- Ustal bazowy zestaw legalnych pluginów i analizuj każdą nową DLL, która eksportuje normalny interfejs pluginu Notepad++, ale dodatkowo uruchamia shelle, PowerShell lub network beacony.
- Wymuś instalowanie pluginów wyłącznie za pośrednictwem **Plugins Admin** i ogranicz uruchamianie kopii portable z niezaufanych ścieżek.

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
