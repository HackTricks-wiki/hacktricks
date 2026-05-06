# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** służy jako technologia bazowa, umożliwiająca **network administrators** efektywne tworzenie i zarządzanie **domains**, **users** oraz **objects** w sieci. Jest zaprojektowane do skalowania, ułatwiając organizację dużej liczby użytkowników w łatwe do zarządzania **groups** i **subgroups**, przy jednoczesnym kontrolowaniu **access rights** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domains**, **trees** i **forests**. **Domain** obejmuje zbiór obiektów, takich jak **users** lub **devices**, które współdzielą wspólną bazę danych. **Trees** to grupy tych domen połączone wspólną strukturą, a **forest** reprezentuje zbiór wielu trees, połączonych przez **trust relationships**, tworząc najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można określać konkretne prawa **access** i **communication**.

Kluczowe pojęcia w **Active Directory** obejmują:

1. **Directory** – Zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – Oznacza encje w katalogu, w tym **users**, **groups** lub **shared folders**.
3. **Domain** – Służy jako kontener dla obiektów katalogu, z możliwością współistnienia wielu domen w obrębie **forest**, z których każda utrzymuje własny zbiór obiektów.
4. **Tree** – Grupa domen, które współdzielą wspólną domenę główną.
5. **Forest** – Szczyt struktury organizacyjnej w Active Directory, składający się z kilku trees z **trust relationships** między nimi.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **users** i **domains**, w tym funkcje **authentication** i **search**.
2. **Certificate Services** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **digital certificates**.
3. **Lightweight Directory Services** – Wspiera aplikacje obsługujące katalogi poprzez **LDAP protocol**.
4. **Directory Federation Services** – Zapewnia możliwości **single-sign-on** do uwierzytelniania użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawem autorskim, regulując ich nieautoryzowaną dystrybucję i użycie.
6. **DNS Service** – Kluczowa dla rozwiązywania **domain names**.

Bardziej szczegółowe wyjaśnienie: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Aby nauczyć się, jak **attack an AD**, musisz naprawdę dobrze **understand** proces **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Możesz dużo znaleźć na [https://wadcoms.github.io/](https://wadcoms.github.io), aby szybko sprawdzić, jakich komend możesz użyć do enumeracji/eksploatacji AD.

> [!WARNING]
> Komunikacja Kerberos **requires a full qualifid name (FQDN)** do wykonywania działań. Jeśli spróbujesz uzyskać dostęp do maszyny po adresie IP, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Jeśli masz tylko dostęp do środowiska AD, ale nie masz żadnych credentials/sessions, możesz:

- **Pentest the network:**
- Skanuj sieć, znajdź maszyny i otwarte porty, a następnie spróbuj **exploit vulnerabilities** lub **extract credentials** z nich (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak web, printers, shares, vpn, media itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zerknij do ogólnej [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby znaleźć więcej informacji o tym, jak to zrobić.
- **Sprawdź dostęp null i Guest na usługach smb** (to nie zadziała na nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy przewodnik, jak enumerować serwer SMB, znajdziesz tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy przewodnik, jak enumerować LDAP, znajdziesz tutaj (zwróć **szczególną uwagę na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Zbierz credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta przez [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbierz credentials, **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyodrębnij nazwy użytkowników/imiona z wewnętrznych dokumentów, mediów społecznościowych, usług (głównie web) w środowiskach domeny, a także z publicznie dostępnych źródeł.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz spróbować różnych konwencji **username** w AD (**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery z każdego), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy zostanie wysłana **invalid username**, serwer odpowie kodem błędu **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala ustalić, że nazwa użytkownika była nieprawidłowa. **Valid usernames** spowodują zwrócenie albo **TGT in a AS-REP** response, albo błędu _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazującego, że użytkownik musi wykonać pre-authentication.
- **No Authentication against MS-NRPC**: Użycie auth-level = 1 (No authentication) wobec interfejsu MS-NRPC (Netlogon) na domain controllers. Metoda wywołuje funkcję `DsrGetDcNameEx2` po związaniu z interfejsem MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje bez żadnych credentials. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten typ enumeracji. Badania można znaleźć [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Serwer OWA (Outlook Web Access)**

Jeśli znalazłeś jeden z tych serwerów w sieci, możesz również wykonać **enumerację użytkowników** przeciwko niemu. Na przykład możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Możesz znaleźć listy nazw użytkowników w [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  i w tym repo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jednak powinieneś mieć **name of the people working on the company** z etapu recon, który powinieneś był wykonać wcześniej. Mając imię i nazwisko, możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951), aby wygenerować potencjalnie poprawne nazwy użytkowników.

### Knowing one or several usernames

Ok, więc wiesz już, że masz prawidłową nazwę użytkownika, ale nie masz żadnych haseł... W takim razie spróbuj:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_, możesz **zażądać wiadomości AS_REP** dla tego użytkownika, która będzie zawierać część danych zaszyfrowanych na podstawie hasła tego użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbujmy **najpopularniejszych haseł** dla każdego z odkrytych użytkowników, może któryś z nich używa słabego hasła (pamiętaj o polityce haseł!).
- Pamiętaj, że możesz też **sprayować serwery OWA**, aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie **uzyskać** pewne challenge **hashes** do crackowania, **poisoning** niektórych protokołów **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Jeśli udało ci się wyliczyć active directory, będziesz mieć **więcej emaili i lepsze zrozumienie network**. Możesz być w stanie wymusić ataki NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack), aby uzyskać dostęp do środowiska AD.

### NetExec workspace-driven recon & relay posture checks

- Użyj **`nxcdb` workspaces**, aby utrzymywać stan recon AD per engagement: `workspace create <name>` tworzy bazy SQLite dla poszczególnych protokołów w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Przełączaj widoki za pomocą `proto smb|mssql|winrm` i wyświetlaj zebrane sekrety za pomocą `creds`. Ręcznie usuń wrażliwe dane po zakończeniu: `rm -rf ~/.nxc/workspaces/<name>`.
- Szybkie wykrywanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domain**, **OS build**, **SMB signing requirements** i **Null Auth**. Członkowie z `(signing:False)` są **relay-prone**, podczas gdy DC często wymagają podpisywania.
- Generuj **hostnames w /etc/hosts** bezpośrednio z wyniku NetExec, aby ułatwić targetowanie:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Gdy **SMB relay do DC jest zablokowany** przez signing, nadal sprawdzaj ustawienia **LDAP**: `netexec ldap <dc>` podkreśla `(signing:None)` / słabe channel binding. DC z wymaganym SMB signing, ale wyłączonym LDAP signing, nadal jest realnym celem **relay-to-LDAP** dla nadużyć takich jak **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs czasami **osadzają zamaskowane hasła admina w HTML**. Podgląd source/devtools może ujawnić cleartext (np. `<input value="<password>">`), co pozwala na Basic-auth access do skanowania/print repositories.
- Pobrane print jobs mogą zawierać **plaintext onboarding docs** z hasłami per-user. Podczas testów utrzymuj poprawne parowanie:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

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

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

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

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
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

Jeśli udało Ci się przeprowadzić enumerację Active Directory, będziesz mieć **więcej emaili i lepsze zrozumienie sieci**. Możesz być w stanie wymusić ataki **NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Szuka Creds w udziałach komputerów | SMB Shares

Teraz, gdy masz już podstawowe credentials, powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione wewnątrz AD**. Mógłbyś zrobić to ręcznie, ale to bardzo nudne, powtarzalne zadanie (a jeszcze bardziej, jeśli znajdziesz setki dokumentów, które trzeba sprawdzić).

[**Kliknij ten link, aby dowiedzieć się o toolach, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Kradzież NTLM Creds

Jeśli możesz **uzyskać dostęp do innych PC lub udziałów**, możesz **umieścić pliki** (jak plik SCF), które, jeśli zostaną w jakiś sposób otwarte, spowodują **uruchomienie uwierzytelnienia NTLM przeciwko Tobie**, dzięki czemu możesz **ukraść** **NTLM challenge** i złamać go:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność pozwalała każdemu uwierzytelnionemu użytkownikowi **skomproitować domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Podniesienie uprawnień w Active Directory Z uprzywilejowanymi credentials/session

**Dla poniższych technik zwykły użytkownik domeny nie wystarczy, potrzebujesz specjalnych uprawnień/credentials, aby wykonać te ataki.**

### Wyodrębnianie hashy

Miejmy nadzieję, że udało Ci się **skomproitować jakieś lokalne konto admina** używając [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) w tym relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [podnoszenia uprawnień lokalnie](../windows-local-privilege-escalation/index.html).\
Następnie czas zrzucić wszystkie hashe z pamięci i lokalnie.\
[**Przeczytaj tę stronę, aby poznać różne sposoby uzyskania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz hash użytkownika**, możesz go użyć, aby **podszyć się** pod niego.\
Musisz użyć jakiegoś **toola**, który **wykona uwierzytelnienie NTLM używając** tego **hasha**, **albo** możesz utworzyć nowy **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, tak aby przy każdym **uwierzytelnieniu NTLM** używany był **ten hash**. Ostatnia opcja to to, co robi mimikatz.\
[**Przeczytaj tę stronę, aby uzyskać więcej informacji.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **użycie NTLM hash użytkownika do zażądania ticketów Kerberos**, jako alternatywy dla typowego Pass The Hash przez protokół NTLM. Dlatego może to być szczególnie **przydatne w sieciach, gdzie protokół NTLM jest wyłączony**, a jako protokół uwierzytelniania dozwolony jest tylko **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną ticket uwierzytelniający użytkownika** zamiast jego hasła lub wartości hash. Ten skradziony ticket jest następnie używany do **podszycia się** pod użytkownika, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Reuse credentials

Jeśli masz **hash** lub **hasło** **lokalnego administratora**, powinieneś spróbować **zalogować się lokalnie** na innych **PC** używając go.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **noisy** and **LAPS** would **mitigate** it.

### Abuse MSSQL & Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA), **steal** the NetNTLM **hash** or even perform a **relay** **attack**.\
Also, if a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. These trusts can be chained and at some point the user might be able to find a misconfigured database where he can execute commands.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuse platform inventory/deployment of IT assets

Third-party inventory and deployment suites often expose powerful paths to credentials and code execution. See:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuse Permissions/ACLs

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Discovering a **Spool service listening** within the domain can be **abused** to **acquire new credentials** and **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuse third party sessions

If **other users** **access** the **compromised** machine, it's possible to **gather credentials from memory** and even **inject beacons in their processes** to impersonate them.\
Usually users will access the system via RDP, so here you have how to performa couple of attacks over third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** provides a system for managing the **local Administrator password** on domain-joined computers, ensuring it's **randomized**, unique, and frequently **changed**. These passwords are stored in Active Directory and access is controlled through ACLs to authorized users only. With sufficient permissions to access these passwords, pivoting to other computers becomes possible.


{{#ref}}
laps.md
{{#endref}}

### Theft of Certificates

**Gathering certificates** from the compromised machine could be a way to escalate privileges inside the environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuse Certificate Templates

If **vulnerable templates** are configured it's possible to abuse them to escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

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

The **Silver Ticket attack** creates a **legitimate Ticket Granting Service (TGS) ticket** for a specific service by using the **NTLM hash** (for instance, the **hash of the PC account**). This method is employed to **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** involves an attacker gaining access to the **NTLM hash of the krbtgt account** in an Active Directory (AD) environment. This account is special because it's used to sign all **Ticket Granting Tickets (TGTs)**, which are essential for authenticating within the AD network.

Once the attacker obtains this hash, they can create **TGTs** for any account they choose (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is a very good way to be able to persist in the users account (even if he changes the password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

The **AdminSDHolder** object in Active Directory ensures the security of **privileged groups** (like Domain Admins and Enterprise Admins) by applying a standard **Access Control List (ACL)** across these groups to prevent unauthorized changes. However, this feature can be exploited; if an attacker modifies the AdminSDHolder's ACL to give full access to a regular user, that user gains extensive control over all privileged groups. This security measure, meant to protect, can thus backfire, allowing unwarranted access unless closely monitored.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Inside every **Domain Controller (DC)**, a **local administrator** account exists. By obtaining admin rights on such a machine, the local Administrator hash can be extracted using **mimikatz**. Following this, a registry modification is necessary to **enable the use of this password**, allowing for remote access to the local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

The **security descriptors** are used to **store** the **permissions** an **object** have **over** an **object**. If you can just **make** a **little change** in the **security descriptor** of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse the `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory to establish a **universal password**, granting access to all domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Previously we have discussed about how to escalate privileges if you have **enough permission to read LAPS passwords**. However, these passwords can also be used to **maintain persistence**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft views the **Forest** as the security boundary. This implies that **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

In a typical scenario, if a user intends to access a service in a **trusted domain**, they must first request a special ticket known as an **inter-realm TGT** from their own domain's DC. This TGT is encrypted with a shared **key** that both domains have agreed upon. The user then presents this TGT to the **DC of the trusted domain** to get a service ticket (**TGS**). Upon successful validation of the inter-realm TGT by the trusted domain's DC, it issues a TGS, granting the user access to the service.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

If Domain A trusts Domain B, A is the trusting domain and B ins the trusted one. Moreover, in **Domain A**, this would be an **Outbound trust**; and in **Domain B**, this would be an **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: This is a common setup within the same forest, where a child domain automatically has a two-way transitive trust with its parent domain. Essentially, this means that authentication requests can flow seamlessly between the parent and the child.
- **Cross-link Trusts**: Referred to as "shortcut trusts," these are established between child domains to expedite referral processes. In complex forests, authentication referrals typically have to travel up to the forest root and then down to the target domain. By creating cross-links, the journey is shortened, which is especially beneficial in geographically dispersed environments.
- **External Trusts**: These are set up between different, unrelated domains and are non-transitive by nature. According to [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts are useful for accessing resources in a domain outside of the current forest that isn't connected by a forest trust. Security is bolstered through SID filtering with external trusts.
- **Tree-root Trusts**: These trusts are automatically established between the forest root domain and a newly added tree root. While not commonly encountered, tree-root trusts are important for adding new domain trees to a forest, enabling them to maintain a unique domain name and ensuring two-way transitivity. More information can be found in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: This type of trust is a two-way transitive trust between two forest root domains, also enforcing SID filtering to enhance security measures.
- **MIT Trusts**: These trusts are established with non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts are a bit more specialized and cater to environments requiring integration with Kerberos-based systems outside the Windows ecosystem.

#### Other differences in **trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Eskalacja uprawnień z child do parent forest
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
Inne sposoby na enumerację trustów domeny:
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
> There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
> You can the one used by the current domain them with:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin to the child/parent domain abusing the trust with SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, jak można wykorzystać Configuration Naming Context (NC), jest kluczowe. Configuration NC służy jako centralne repozytorium danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w obrębie lasu, a zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **uprawnienia SYSTEM na DC**, najlepiej na child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o site'ach wszystkich komputerów dołączonych do domeny w całym lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą powiązać GPO z root DC sites. To działanie może potencjalnie skompromitować root domain poprzez manipulowanie politykami stosowanymi do tych site'ów.

Szczegółowe informacje można znaleźć w badaniach dotyczących [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Wektor ataku polega na atakowaniu uprzywilejowanych gMSA w domenie. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, można uzyskać dostęp do KDS Root key i obliczyć hasła dla dowolnego gMSA w całym lesie.

Szczegółowa analiza i instrukcja krok po kroku znajdują się w:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak delegated MSA (BadSuccessor – abuse of migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe badania zewnętrzne: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ta metoda wymaga cierpliwości i czekania na utworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować AD Schema, aby nadać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i kontroli nad nowo tworzonymi obiektami AD.

Dalsze informacje są dostępne w [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Podatność ADCS ESC5 dotyczy kontroli nad obiektami Public Key Infrastructure (PKI) w celu utworzenia certificate template, który umożliwia uwierzytelnianie jako dowolny użytkownik w całym lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, skompromitowanie zapisywalnego child DC umożliwia wykonanie ataków ESC5.

Więcej szczegółów można przeczytać w [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). W scenariuszach bez ADCS atakujący ma możliwość skonfigurowania niezbędnych komponentów, jak opisano w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
W tym scenariuszu **twoja domena jest zaufana** przez zewnętrzną, co daje ci **nieokreślone uprawnienia** względem niej. Będziesz musiał ustalić, **które principals z twojej domeny mają jaki dostęp do zewnętrznej domeny**, a następnie spróbować to wykorzystać:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
W tym scenariuszu **twoja domena** **ufa** pewnym **uprawnieniom** przyznanym podmiotowi z **innych domen**.

Jednak gdy **domena jest zaufana** przez domenę ufającą, zaufana domena **tworzy użytkownika** o **przewidywalnej nazwie**, który używa jako **hasła hasła trusted**. Oznacza to, że można **uzyskać dostęp do użytkownika z domeny ufającej, aby wejść do zaufanej** i ją wyliczyć oraz spróbować podnieść więcej uprawnień:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem skompromitowania zaufanej domeny jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **odwrotnym kierunku** do zaufania domenowego (co nie jest zbyt częste).

Innym sposobem skompromitowania zaufanej domeny jest poczekanie na maszynie, do której **użytkownik z zaufanej domeny może uzyskać dostęp**, aż zaloguje się przez **RDP**. Następnie atakujący mógłby wstrzyknąć kod do procesu sesji RDP i stamtąd **uzyskać dostęp do domeny źródłowej ofiary**.\
Ponadto, jeśli **ofiara zamontowała swój dysk twardy**, z procesu sesji **RDP** atakujący mógłby zapisać **backdoors** w **folderze startowym** dysku twardego. Ta technika nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigacja nadużyć zaufania domenowego

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w ramach zaufania między lasami jest ograniczane przez SID Filtering, które jest domyślnie aktywowane dla wszystkich trustów między lasami. Opiera się to na założeniu, że trusty wewnątrz lasu są bezpieczne, uznając za granicę bezpieczeństwa las, a nie domenę, zgodnie ze stanowiskiem Microsoftu.
- Jest jednak pewien haczyk: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego sporadycznego wyłączania.

### **Selective Authentication:**

- W przypadku trustów między lasami zastosowanie Selective Authentication zapewnia, że użytkownicy z obu lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w domenie ufającej lub lesie.
- Warto zauważyć, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto trust.

[**Więcej informacji o trustach domenowych w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementuje primitywy LDAP w stylu bloodyAD jako x64 Beacon Object Files, które działają całkowicie wewnątrz on-host implant (np. Adaptix C2). Operatorzy kompilują pakiet za pomocą `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, ładują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z beacona. Cały ruch korzysta z bieżącego kontekstu bezpieczeństwa logowania przez LDAP (389) z signing/sealing albo LDAPS (636) z automatycznym zaufaniem certyfikatu, więc nie są potrzebne ani socks proxy, ani artefakty na dysku.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` rozwiązują krótkie nazwy/ścieżki OU do pełnych DN i zrzucają odpowiadające im obiekty.
- `get-object`, `get-attribute` i `get-domaininfo` pobierają dowolne atrybuty (w tym security descriptors) oraz metadane lasu/domeny z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` ujawniają kandydatów do roasting, ustawienia delegacji oraz istniejące deskryptory [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) bezpośrednio z LDAP.
- `get-acl` i `get-writable --detailed` parsują DACL, aby wypisać trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) oraz inheritance, dając natychmiastowe cele do eskalacji uprawnień ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives do eskalacji i persistence

- BOFy tworzenia obiektów (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi tworzyć nowe principals lub konta maszyn tam, gdzie istnieją prawa OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` bezpośrednio przejmują cele, gdy zostaną znalezione prawa write-property.
- Komendy skupione na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, zamieniają WriteDACL/WriteOwner na dowolnym obiekcie AD na reset haseł, kontrolę członkostwa w grupach lub uprawnienia replikacji DCSync, bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` czyszczą wstrzyknięte ACE.

### Delegation, roasting i nadużycia Kerberos

- `add-spn`/`set-spn` natychmiast sprawiają, że skompromitowany użytkownik staje się Kerberoastable; `add-asreproastable` (przełącznik UAC) oznacza go do AS-REP roasting bez dotykania hasła.
- Makra delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) przepisują `msDS-AllowedToDelegateTo`, flagi UAC albo `msDS-AllowedToActOnBehalfOfOtherIdentity` z beacona, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę zdalnego PowerShell lub RSAT.

### Wstrzykiwanie sidHistory, przenoszenie OU i kształtowanie powierzchni ataku

- `add-sidhistory` wstrzykuje uprzywilejowane SID-y do sid history kontrolowanego principala (zobacz [SID-History Injection](sid-history-injection.md)), zapewniając dyskretne dziedziczenie dostępu w całości przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenosić zasoby do OU, gdzie już istnieją delegowane uprawnienia, zanim użyje `set-password`, `add-groupmember` lub `add-spn`.
- Ściśle ograniczone komendy usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) pozwalają szybko wycofać zmiany po zebraniu poświadczeń lub ustawieniu persistence, minimalizując telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Dowiedz się więcej o ochronie poświadczeń tutaj.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Ograniczenia dla Domain Admins**: Zaleca się, aby Domain Admins mogli logować się wyłącznie do Domain Controllers, unikając używania ich na innych hostach.
- **Uprawnienia kont serwisowych**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA), aby zachować bezpieczeństwo.
- **Tymczasowe ograniczenie uprawnień**: W przypadku zadań wymagających uprawnień DA ich czas trwania powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ograniczanie LDAP relay**: Audytuj Event ID 2889/3074/3075, a następnie wymuś LDAP signing oraz LDAPS channel binding na DCs/clients, aby blokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting aktywności Impacket na poziomie protokołu

Jeśli chcesz wykrywać popularne techniki AD, **nie polegaj wyłącznie na artefaktach kontrolowanych przez operatora**, takich jak przemianowane binaria, nazwy usług, tymczasowe pliki batch czy ścieżki wyjściowe. Zbuduj baseline tego, jak legalne klienty Windows tworzą ruch [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI, a następnie szukaj **cech implementacyjnych**, które pozostają nawet po edycji `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` lub `ntlmrelayx.py`.

- **Samodzielni kandydaci o wysokiej pewności** (po walidacji względem własnego baseline):
- Uwierzytelnione DCE/RPC używające `auth_context_id = 79231 + ctx_id`
- Wypełnienie paddingu uwierzytelniania DCE/RPC wartością `0xff`
- LDAP Kerberos binds, które umieszczają surowy Kerberos `AP-REQ` bezpośrednio w SPNEGO `mechToken`
- Żądania negocjacji SMB2/3 z wartościami `ClientGuid` wyglądającymi na ASCII
- WMI `IWbemLevel1Login::NTLMLogin` używające niestandardowej przestrzeni nazw `//./root/cimv2`
- Hardcoded wartości nonce Kerberos
- **Lepsze jako cechy korelacji/scoringu**:
- Rzadkie lub zduplikowane listy etype Kerberos, nietypowe/brakujące `PA-DATA` albo kolejność etype w TGS-REQ różniąca się od natywnego Windows
- Wiadomości NTLM Type 1 bez informacji o wersji lub wiadomości Type 3 z pustymi nazwami hostów
- Surowe NTLMSSP przenoszone w DCE/RPC zamiast SPNEGO, brak trailerów weryfikacyjnych DCE/RPC lub niezgodności OID SPNEGO/Kerberos
- Kilka z tych cech z tego samego hosta/użytkownika/okna czasowego jest znacznie silniejsze niż pojedynczy słaby atrybut
- **Używaj jako enrichment, nie jako samodzielne alerty**:
- Domyślne nazwy plików, ścieżki wyjściowe, losowe nazwy usług, tymczasowe nazwy batch, domyślne nazwy kont komputerów i specyficzne dla narzędzia ciągi HTTP/WebDAV/RDP/MSSQL
- Są one łatwe do zmiany przez operatorów i najlepiej służą do wyjaśnienia, dlaczego klaster cross-protocol jest podejrzany
- **Uwagi operacyjne**:
- Niektóre z tych sygnałów wymagają odszyfrowanego ruchu, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW lub widoczności po stronie usługi
- Zweryfikuj je względem klientów Samba/Linux, appliance'ów i starszego oprogramowania, zanim zamienisz je w alerty
- Promuj detekcje od enrichment -> hunting -> alerting w miarę budowania zaufania do baseline

### **Implementing Deception Techniques**

- Implementing deception polega na stawianiu pułapek, takich jak users lub komputery przynęty, z funkcjami takimi jak hasła, które nie wygasają, albo oznaczenie jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie users z określonymi uprawnieniami lub dodawanie ich do grup o wysokim poziomie uprawnień.
- Praktyczny przykład obejmuje użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej o wdrażaniu technik deception można znaleźć w [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Dla User Objects**: Podejrzane wskaźniki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia i niską liczbę błędnych haseł.
- **Ogólne wskaźniki**: Porównanie atrybutów potencjalnych obiektów decoy z atrybutami prawdziwych może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikacji takich deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers, aby zapobiec detekcji ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga ominąć detekcję, ponieważ nie dochodzi do downgrade do NTLM.
- **DCSync Attacks**: Zaleca się wykonywanie z non-Domain Controller, aby uniknąć detekcji ATA, ponieważ bezpośrednie uruchomienie z Domain Controller wywoła alerty.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
