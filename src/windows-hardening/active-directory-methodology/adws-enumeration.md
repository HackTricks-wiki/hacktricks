# Active Directory Web Services (ADWS) Enumeration i ciche zbieranie

{{#include ../../banners/hacktricks-training.md}}

## Czym jest ADWS?

Active Directory Web Services (ADWS) jest **domyślnie włączone na każdym kontrolerze domeny od Windows Server 2008 R2** i nasłuchuje na TCP **9389**.  Wbrew nazwie **nie jest wykorzystywany HTTP**.  Zamiast tego usługa udostępnia dane w stylu LDAP za pośrednictwem stosu zastrzeżonych protokołów ramkowania .NET:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Ponieważ ruch jest enkapsulowany w tych binarnych ramkach SOAP i przesyłany przez nietypowy port, **enumeration przez ADWS jest znacznie mniej podatne na inspekcję, filtrowanie lub wykrywanie na podstawie sygnatur niż klasyczny ruch LDAP/389 i 636**.  Dla operatorów oznacza to:<sup>[[1]](#references)[[7]](#references)</sup>

* Bardziej skryty recon – zespoły Blue Team często koncentrują się na zapytaniach LDAP.
* Możliwość zbierania danych z **hostów innych niż Windows (Linux, macOS)** przez tunelowanie 9389/TCP przez proxy SOCKS.
* Te same dane, które można uzyskać za pośrednictwem LDAP (użytkownicy, grupy, ACL, schemat itd.), oraz możliwość wykonywania **zapisów** (np. `msDs-AllowedToActOnBehalfOfOtherIdentity` na potrzeby **RBCD**).

Interakcje ADWS są implementowane przez WS-Enumeration: każde zapytanie rozpoczyna się od komunikatu `Enumerate`, który definiuje filtr/atrybuty LDAP i zwraca identyfikator GUID `EnumerationContext`, po czym następuje co najmniej jeden komunikat `Pull` przesyłający wyniki w oknie wyników zdefiniowanym przez serwer.<sup>[[7]](#references)</sup> Konteksty wygasają po około 30 minutach, dlatego narzędzia muszą dzielić wyniki na strony albo dzielić filtry (zapytania prefiksowe dla każdego CN), aby uniknąć utraty stanu.<sup>[[8]](#references)</sup> Podczas pobierania deskryptorów zabezpieczeń należy określić kontrolkę `LDAP_SERVER_SD_FLAGS_OID`, aby pominąć SACL; w przeciwnym razie ADWS po prostu usuwa atrybut `nTSecurityDescriptor` z odpowiedzi SOAP.

> UWAGA: ADWS jest również używane przez wiele narzędzi RSAT GUI/PowerShell, dlatego ruch może mieszać się z legalną aktywnością administracyjną.

## SoaPy – natywny klient Python

[SoaPy](https://github.com/logangoins/soapy) to **pełna implementacja stosu protokołu ADWS napisana wyłącznie w Pythonie**.  Tworzy ramki NBFX/NBFSE/NNS/NMF bajt po bajcie, umożliwiając zbieranie danych z systemów Unix-like bez używania środowiska uruchomieniowego .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Najważniejsze funkcje

* Obsługa **proxy SOCKS** (przydatna w implantach C2).
* Szczegółowe filtry wyszukiwania identyczne z LDAP `-q '(objectClass=user)'`.
* Opcjonalne operacje **zapisu** ( `--set` / `--delete` ).
* **Tryb wyjścia BOFHound** umożliwiający bezpośrednie przetwarzanie danych przez BloodHound.<sup>[[3]](#references)</sup>
* Flaga `--parse` umożliwiająca czytelniejsze przedstawianie znaczników czasu / `userAccountControl`, gdy wymagana jest czytelność dla człowieka.<sup>[[2]](#references)</sup>

### Ukierunkowane flagi zbierania danych i operacje zapisu

SoaPy zawiera przygotowane przełączniki odwzorowujące najczęstsze zadania LDAP huntingu za pośrednictwem ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, a także opcje `--query` / `--filter` do wykonywania niestandardowych pobrań.  Można je połączyć z prymitywami zapisu, takimi jak `--rbcd <source>` (ustawia `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (przygotowanie SPN na potrzeby ukierunkowanego Kerberoasting) oraz `--asrep` (włącza `DONT_REQ_PREAUTH` w `userAccountControl`).<sup>[[2]](#references)</sup>

Przykład ukierunkowanego wyszukiwania SPN, które zwraca wyłącznie `samAccountName` i `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Użyj tego samego hosta/credentials, aby natychmiast wykorzystać ustalenia: zrzutuj obiekty obsługujące RBCD za pomocą `--rbcds`, a następnie zastosuj `--rbcd 'WEBSRV01$' --account 'FILE01$'`, aby przygotować łańcuch Resource-Based Constrained Delegation (zobacz [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), aby poznać pełną ścieżkę wykorzystania).

### Instalacja (host operatora)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump przez ADWS (Linux/Windows)

* Fork `ldapdomaindump`, który zastępuje zapytania LDAP wywołaniami ADWS na TCP/9389, aby ograniczyć wykrywanie sygnatur LDAP.
* Wykonuje początkowe sprawdzenie dostępności portu 9389, chyba że przekazano `--force` (pomija sondowanie, jeśli skanowanie portów powoduje dużo szumu lub jest filtrowane).
* Przetestowano z Microsoft Defender for Endpoint i CrowdStrike Falcon, uzyskując skuteczne obejście, jak opisano w README.<sup>[[4]](#references)</sup>

### Instalacja
```bash
pipx install .
```
### Użycie
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Typowe dane wyjściowe rejestrują sprawdzenie osiągalności portu 9389, ADWS bind oraz rozpoczęcie i zakończenie dump.
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - praktyczny klient ADWS w Golang

Podobnie jak soapy, [sopa](https://github.com/Macmod/sopa) implementuje stos protokołu ADWS (MS-NNS + MC-NMF + SOAP) w Golang, udostępniając flagi wiersza poleceń do wykonywania wywołań ADWS, takich jak:<sup>[[5]](#references)</sup>

* **Wyszukiwanie i pobieranie obiektów** - `query` / `get`
* **Cykl życia obiektów** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Edycja atrybutów** - `attr [add|replace|delete]`
* **Zarządzanie kontami** - `set-password` / `change-password`
* oraz inne, takie jak `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` itd.

### Najważniejsze informacje o mapowaniu protokołów

* Wyszukiwania w stylu LDAP są wykonywane za pomocą **WS-Enumeration** (`Enumerate` + `Pull`) z projekcją atrybutów, kontrolą zakresu (Base/OneLevel/Subtree) i paginacją.
* Pobieranie pojedynczego obiektu używa **WS-Transfer** `Get`; zmiany atrybutów używają `Put`; usuwanie używa `Delete`.
* Wbudowane tworzenie obiektów używa **WS-Transfer ResourceFactory**; obiekty niestandardowe używają **IMDA AddRequest** sterowanego przez szablony YAML.
* Operacje na hasłach to akcje **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Nieuwierzytelnione wykrywanie metadanych (mex)

ADWS udostępnia WS-MetadataExchange bez poświadczeń, co jest szybkim sposobem na sprawdzenie ekspozycji przed uwierzytelnieniem:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Wykrywanie DNS/DC i notatki dotyczące targetowania Kerberos

Sopa może wykrywać DC za pomocą SRV, jeśli pominięto `--dc` i podano `--domain`. Wysyła zapytania w tej kolejności i używa celu o najwyższym priorytecie:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operacyjnie preferuj resolver kontrolowany przez DC, aby uniknąć błędów w środowiskach podzielonych na segmenty:

* Użyj `--dns <DC-IP>`, aby **wszystkie** zapytania SRV/PTR/forward były wykonywane przez DNS DC.
* Użyj `--dns-tcp`, gdy UDP jest blokowane lub odpowiedzi SRV są duże.
* Jeśli Kerberos jest włączony, a `--dc` jest adresem IP, sopa wykonuje **odwrotne wyszukiwanie PTR**, aby uzyskać FQDN i poprawnie określić docelowe SPN/KDC. Jeśli Kerberos nie jest używany, wyszukiwanie PTR nie jest wykonywane.

Przykład (IP + Kerberos, wymuszony DNS przez DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opcje materiału uwierzytelniającego

Oprócz haseł w postaci jawnego tekstu sopa obsługuje **hashe NT**, **klucze Kerberos AES**, **ccache** oraz **certyfikaty PKINIT** (PFX lub PEM) do uwierzytelniania ADWS. Kerberos jest używany automatycznie podczas korzystania z `--aes-key`, `-c` (ccache) lub opcji opartych na certyfikatach.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Tworzenie niestandardowych obiektów za pomocą templates

Dla dowolnych klas obiektów polecenie `create custom` wykorzystuje template YAML mapujący się na IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` i `rdn` definiują kontener oraz względny DN.
* `attributes[].name` obsługuje `cn` lub namespaced `addata:cn`.
* `attributes[].type` akceptuje `string|int|bool|base64|hex` lub jawne `xsd:*`.
* **Nie** dołączaj `ad:relativeDistinguishedName` ani `ad:container-hierarchy-parent`; sopa wstrzykuje je automatycznie.
* Wartości `hex` są konwertowane do `xsd:base64Binary`; użyj `value: ""`, aby ustawić puste ciągi znaków.

## SOAPHound – wysokowolumenowa kolekcja ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) to collector .NET, który przeprowadza wszystkie interakcje LDAP wewnątrz ADWS i generuje JSON zgodny z BloodHound v4. Jednorazowo buduje kompletny cache `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` (`--buildcache`), a następnie ponownie go wykorzystuje podczas wysokowolumenowych przebiegów `--bhdump`, `--certdump` (ADCS) lub `--dnsdump` (DNS zintegrowany z AD), dzięki czemu z DC kiedykolwiek opuszcza go tylko około 35 krytycznych atrybutów. AutoSplit (`--autosplit --threshold <N>`) automatycznie dzieli zapytania według prefiksu CN, aby w dużych lasach nie przekroczyć 30-minutowego limitu czasu EnumerationContext.<sup>[[8]](#references)</sup>

Typowy workflow na przyłączonej do domeny VM operatora:
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
Eksportowane sloty JSON bezpośrednio do workflowów SharpHound/BloodHound — zobacz [metodologię BloodHound](bloodhound.md), aby poznać pomysły na dalsze graphing. AutoSplit sprawia, że SOAPHound jest odporny na lasy zawierające miliony obiektów, jednocześnie utrzymując mniejszą liczbę zapytań niż snapshots w stylu ADExplorer.

## Workflow skrytego zbierania danych AD

Poniższy workflow pokazuje, jak enumerować **obiekty domeny i ADCS** za pośrednictwem ADWS, konwertować je do formatu BloodHound JSON i wyszukiwać ścieżki ataku oparte na certyfikatach — wszystko z poziomu Linux:

1. **Przekieruj tunel 9389/TCP** z sieci docelowej do swojego komputera (np. za pomocą Chisel, Meterpreter, dynamicznego port-forwardingu SSH itd.). Eksportuj `export HTTPS_PROXY=socks5://127.0.0.1:1080` lub użyj `--proxyHost/--proxyPort` w SoaPy.

2. **Zbierz obiekt domeny głównej:**
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
5. **Prześlij plik ZIP** w GUI BloodHound i uruchom zapytania cypher, takie jak `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, aby ujawnić ścieżki eskalacji uprawnień związane z certyfikatami (ESC1, ESC8 itd.).

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
| Zrzut ADWS na dużą skalę | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, tryby BH/ADCS/DNS |
| Import do BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Konwertuje logi SoaPy/ldapsearch |
| Kompromitacja certyfikatów | [Certipy](https://github.com/ly4k/Certipy) | Może być proxowane przez ten sam SOCKS |
| Enumeracja ADWS i zmiany obiektów | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## References

- [1] [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
