# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) jest **włączony domyślnie na każdym Domain Controller od Windows Server 2008 R2** i nasłuchuje na TCP **9389**. Mimo nazwy, **HTTP nie jest używane**. Zamiast tego serwis udostępnia dane w stylu LDAP przez stos proprietarnych .NET framing protocols:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Ponieważ ruch jest enkapsulowany w tych binarnych ramach SOAP i podróżuje przez rzadko używany port, **enumeration przez ADWS jest znacznie mniej prawdopodobne do inspekcji, filtrowania lub signature’owania niż klasyczny ruch LDAP/389 & 636**. Dla operatorów oznacza to:

* Stealthier recon – Blue teams często koncentrują się na zapytaniach LDAP.
* Możliwość zbierania z **non-Windows hosts (Linux, macOS)** przez tunelowanie 9389/TCP przez SOCKS proxy.
* Te same dane, które uzyskasz przez LDAP (users, groups, ACLs, schema itd.) oraz możliwość wykonywania **writes** (np. `msDs-AllowedToActOnBehalfOfOtherIdentity` dla **RBCD**).

Interakcje ADWS są zaimplementowane nad WS-Enumeration: każde zapytanie zaczyna się od wiadomości `Enumerate`, która definiuje filtr/atrybuty LDAP i zwraca `EnumerationContext` GUID, a następnie następuje jedna lub więcej wiadomości `Pull`, które streamują do okna wyników określonego przez serwer. Contexty wygasają po ~30 minutach, więc narzędzia muszą albo stronicować wyniki, albo dzielić filtry (zapytania prefiksowe dla każdego CN), aby nie stracić stanu. Przy żądaniu security descriptors, określ kontrolę `LDAP_SERVER_SD_FLAGS_OID`, aby pominąć SACLs, w przeciwnym razie ADWS po prostu pomija atrybut `nTSecurityDescriptor` w odpowiedzi SOAP.

> UWAGA: ADWS jest także używane przez wiele narzędzi RSAT GUI/PowerShell, więc ruch może się mieszać z legalną aktywnością administratorów.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) to **pełna reimplementacja stosu protokołu ADWS w czystym Pythonie**. Buduje ramki NBFX/NBFSE/NNS/NMF bajt-po-bajcie, pozwalając na zbieranie z systemów Unix-like bez użycia runtime .NET.

### Key Features

* Supports **proxying through SOCKS** (useful from C2 implants).
* Fine-grained search filters identical to LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** for direct ingestion into BloodHound.
* `--parse` flag to prettify timestamps / `userAccountControl` when human readability is required.

### Targeted collection flags & write operations

SoaPy zawiera zkuratorowane przełączniki, które odtwarzają najczęstsze zadania łowieckie LDAP przez ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oraz surowe `--query` / `--filter` do niestandardowych pulli. Połącz je z operacjami zapisu takimi jak `--rbcd <source>` (ustawia `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging dla targetowanego Kerberoasting) oraz `--asrep` (zmienia `DONT_REQ_PREAUTH` w `userAccountControl`).

Przykładowe wyszukiwanie SPN, które zwraca tylko `samAccountName` i `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Użyj tego samego hosta i poświadczeń, aby natychmiast weaponise znaleziska: dump RBCD-capable objects przy użyciu `--rbcds`, następnie użyj `--rbcd 'WEBSRV01$' --account 'FILE01$'` aby stage a Resource-Based Constrained Delegation chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) for the full abuse path).

### Instalacja (host operatora)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Praktyczny klient dla ADWS w Golang

Podobnie jak soapy, [sopa](https://github.com/Macmod/sopa) implementuje stos protokołu ADWS (MS-NNS + MC-NMF + SOAP) w Golang, udostępniając opcje wiersza poleceń do wykonywania wywołań ADWS, takich jak:

* **Wyszukiwanie i pobieranie obiektów** - `query` / `get`
* **Zarządzanie cyklem życia obiektu** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Edycja atrybutów** - `attr [add|replace|delete]`
* **Zarządzanie kontami** - `set-password` / `change-password`
* oraz inne, takie jak `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, itd.

## SOAPHound – Kolekcjonowanie ADWS o dużej skali (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) jest kolektorem .NET, który utrzymuje wszystkie interakcje LDAP wewnątrz ADWS i generuje JSON kompatybilny z BloodHound v4. Tworzy pełny cache `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` raz (`--buildcache`), a następnie ponownie wykorzystuje go do masowych przebiegów `--bhdump`, `--certdump` (ADCS) lub `--dnsdump` (AD-integrated DNS), dzięki czemu tylko ~35 krytycznych atrybutów opuszcza DC. AutoSplit (`--autosplit --threshold <N>`) automatycznie dzieli zapytania według prefiksu CN, aby utrzymać się poniżej 30-minutowego timeoutu EnumerationContext w dużych lasach.

Typowy przepływ pracy na maszynie operatora dołączonej do domeny:
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
Wyeksportowane sloty JSON bezpośrednio do przepływów pracy SharpHound/BloodHound—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit sprawia, że SOAPHound jest odporny w lasach z wielomilionową liczbą obiektów, jednocześnie utrzymując liczbę zapytań niższą niż w migawkach w stylu ADExplorer.

## Ukryty proces zbierania AD

Następujący proces pokazuje, jak enumerować **obiekty domeny i ADCS** przez ADWS, konwertować je na BloodHound JSON i polować na ścieżki ataku oparte na certyfikatach – wszystko z Linux:

1. **Tuneluj 9389/TCP** z sieci celu do swojej maszyny (np. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` or use SoaPy’s `--proxyHost/--proxyPort`.

2. **Zbierz obiekt głównej domeny:**
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
5. **Wgraj plik ZIP** w BloodHound GUI i uruchom zapytania cypher, takie jak `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aby ujawnić ścieżki eskalacji certyfikatów (ESC1, ESC8, itp.).

### Ustawianie `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Połącz to z `s4u2proxy`/`Rubeus /getticket`, aby uzyskać pełny łańcuch **Resource-Based Constrained Delegation** (zob. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Podsumowanie narzędzi

| Cel | Narzędzie | Uwagi |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, odczyt/zapis |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Konwertuje SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Może być przekierowane przez ten sam SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Ogólny klient do komunikacji z znanymi punktami końcowymi ADWS - pozwala na enumeration, object creation, attribute modifications, and password changes |

## Źródła

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
