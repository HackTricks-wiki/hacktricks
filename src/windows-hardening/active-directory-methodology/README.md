# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** służy jako podstawowa technologia, umożliwiająca **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** i **obiektami** w sieci. Został zaprojektowany tak, aby skalować się, ułatwiając organizację dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, jednocześnie kontrolując **prawa dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, które dzielą wspólną bazę danych. **Drzewa** to grupy takich domen powiązane wspólną strukturą, a **las** reprezentuje zbiór wielu drzew, połączonych przez **relacje zaufania**, tworząc najwyższą warstwę struktury organizacyjnej. Specyficzne **prawa dostępu** i **komunikacji** mogą być przydzielane na każdym z tych poziomów.

Kluczowe pojęcia w **Active Directory** obejmują:

1. **Directory** – Przechowuje wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – Oznacza byty w katalogu, w tym **użytkowników**, **grupy** lub **udostępnione foldery**.
3. **Domain** – Służy jako kontener dla obiektów katalogu; w **lesie** może współistnieć wiele domen, z każdą utrzymującą własny zbiór obiektów.
4. **Tree** – Grupa domen dzielących wspólną domenę root.
5. **Forest** – Szczytowa struktura organizacyjna w Active Directory, składająca się z kilku drzew z **relacjami zaufania** między nimi.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym **uwierzytelnianiem** i funkcjami **wyszukiwania**.
2. **Certificate Services** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – Wspiera aplikacje wykorzystujące katalog poprzez **LDAP protocol**.
4. **Directory Federation Services** – Zapewnia funkcje **single-sign-on** do uwierzytelniania użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawem autorskim poprzez regulowanie ich nieautoryzowanej dystrybucji i użycia.
6. **DNS Service** – Kluczowy dla rozwiązywania **nazw domen**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Aby nauczyć się, jak **atakować AD**, musisz naprawdę dobrze **zrozumieć proces uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę, jeśli nadal nie wiesz, jak to działa.**](kerberos-authentication.md)

## Cheat Sheet

Możesz zajrzeć na [https://wadcoms.github.io/](https://wadcoms.github.io), żeby szybko zobaczyć, które polecenia możesz uruchomić, aby enumerować/eksploitować AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

If you just have access to an AD environment but you don't have any credentials/sessions you could:

- **Pentest the network:**
- Skanuj sieć, znajdź maszyny i otwarte porty oraz spróbuj **eksploitować luki** lub **wyciągnąć poświadczenia** z nich (na przykład, [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak web, drukarki, udziały, vpn, media itp.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zerknij na ogólną [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby znaleźć więcej informacji o tym, jak to robić.
- **Sprawdź dostęp null i Guest na usługach smb** (to nie zadziała na nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy przewodnik po enumeracji serwera SMB można znaleźć tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy przewodnik po enumeracji LDAP można znaleźć tutaj (zwróć **szczególną uwagę na dostęp anonimowy**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Zbieraj poświadczenia, **podszywając się pod usługi za pomocą Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta przez [**nadużycie relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbieraj poświadczenia, **eksponując fałszywe usługi UPnP za pomocą evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyodrębnij nazwy użytkowników/imię i nazwiska z dokumentów wewnętrznych, social media, usług (głównie web) w środowisku domenowym i także z dostępnych publicznie źródeł.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz spróbować różnych konwencji nazw użytkowników AD (**przeczytaj to**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery z każdego), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) oraz [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy żądany jest **nieprawidłowy username**, serwer odpowie używając **błędu Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala nam stwierdzić, że nazwa użytkownika była nieprawidłowa. **Prawidłowe nazwy użytkowników** spowodują albo otrzymanie **TGT w odpowiedzi AS-REP**, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi wykonać pre-authentication.
- **No Authentication against MS-NRPC**: Użycie auth-level = 1 (No authentication) przeciwko interfejsowi MS-NRPC (Netlogon) na kontrolerach domeny. Metoda wywołuje funkcję `DsrGetDcNameEx2` po związaniu interfejsu MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje bez jakichkolwiek poświadczeń. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten typ enumeracji. Badania można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
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

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

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

Jeśli udało Ci się zenumerować Active Directory będziesz mieć **więcej adresów e-mail i lepsze zrozumienie sieci**. Możesz być w stanie wymusić NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Szukanie Creds w udostępnieniach komputerów | SMB Shares

Teraz, gdy masz pewne podstawowe poświadczenia powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione w AD**. Możesz to robić ręcznie, ale to bardzo nudne powtarzalne zadanie (a tym bardziej, jeśli znajdziesz setki dokumentów, które trzeba sprawdzić).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz **uzyskać dostęp do innych PCs lub shares** możesz **umieścić pliki** (np. plik SCF), które jeśli w jakiś sposób zostaną otwarte, spowodują, że **wywołają NTLM authentication przeciwko Tobie**, dzięki czemu możesz **ukraść** **NTLM challenge** aby go złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta luka pozwalała każdemu uwierzytelnionemu użytkownikowi na **przejęcie kontrolera domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi poświadczeniami/sesją

**Do poniższych technik zwykły użytkownik domenowy nie wystarczy, potrzebujesz specjalnych uprawnień/poświadczeń, aby przeprowadzić te ataki.**

### Hash extraction

Miejmy nadzieję, że udało Ci się **skompromentować jakieś konto lokalnego administratora** używając [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) włączając relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Następnie, czas zrzucić wszystkie hashe z pamięci i lokalnie.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz hash użytkownika**, możesz go użyć, aby się za niego **podszyć**.\
Musisz użyć jakiegoś **narzędzia**, które wykona **uwierzytelnianie NTLM** używając tego **hasha**, **lub** możesz utworzyć nowe **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, tak aby przy każdym wykonywanym **uwierzytelnianiu NTLM** używany był ten **hash**. Ostatnia opcja to to, co robi mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **użyć hash'a NTLM użytkownika do zażądania ticketów Kerberos**, jako alternatywa dla powszechnego Pass The Hash przez protokół NTLM. Dlatego może być szczególnie **przydatny w sieciach, gdzie protokół NTLM jest wyłączony** i tylko **Kerberos jest dozwolony** jako protokół uwierzytelniania.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradnie ticket uwierzytelniający użytkownika** zamiast jego hasła lub wartości hasha. Ten skradziony ticket jest następnie używany do **podszywania się pod użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Jeśli masz **hash** lub **password** lokalnego **administratora**, powinieneś spróbować **zalogować się lokalnie** na inne **PC** używając tych poświadczeń.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Zwróć uwagę, że to jest dość **hałaśliwe** i **LAPS** by to **złagodził**.

### MSSQL Abuse & Trusted Links

Jeżeli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może wykorzystać to do **wykonywania poleceń** na hoście MSSQL (jeśli proces działa jako SA), **wykradzenia** NetNTLM **hasha** lub nawet przeprowadzenia **relay attack**.\
Dodatkowo, jeżeli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL i użytkownik ma uprawnienia do zaufanej bazy, będzie mógł **użyć relacji zaufania do wykonywania zapytań także w drugiej instancji**. Te zaufania mogą być łańcuchowane i w pewnym momencie użytkownik może znaleźć błędnie skonfigurowaną bazę, gdzie może wykonać polecenia.\
**Linki między bazami działają nawet przez forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Zewnętrzne narzędzia do inwentaryzacji i wdrożeń często ujawniają potężne ścieżki do poświadczeń i wykonania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić TGTs z pamięci każdego użytkownika, który się na nim zaloguje.\
Zatem, jeśli **Domain Admin** zaloguje się na tym komputerze, będziesz w stanie zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (oby to był DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeżeli użytkownik lub komputer jest dozwolony do "Constrained Delegation", będzie mógł **podszywać się pod dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Jeśli **skomprymujesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet Domain Admins) w celu dostępu do niektórych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** na obiekcie Active Directory zdalnego komputera umożliwia osiągnięcie wykonania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Skompromitowany użytkownik może mieć interesujące **uprawnienia** nad niektórymi obiektami domeny, które pozwolą Ci później **przemieszczać się lateralnie / eskalować uprawnienia**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Odkrycie usługi **Spool** nasłuchującej w domenie może zostać **nadużyte** do **pozyskania nowych poświadczeń** i **escalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Jeśli **inni użytkownicy** **dostępują** do **skompro-mitowanej** maszyny, możliwe jest **zbieranie poświadczeń z pamięci** a nawet **wstrzykiwanie beaconów do ich procesów** w celu podszycia się pod nich.\
Zwykle użytkownicy łączą się przez RDP, więc tutaj masz jak wykonać kilka ataków na sesje RDP osób trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **lokalnym hasłem Administratora** na komputerach dołączonych do domeny, gwarantując, że jest ono **losowe**, unikalne i często **zmieniane**. Te hasła są przechowywane w Active Directory, a dostęp jest kontrolowany poprzez ACL do autoryzowanych użytkowników. Mając wystarczające uprawnienia do odczytu tych haseł, możliwe jest pivotowanie na inne komputery.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Zebranie certyfikatów** z zaatakowanej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Jeśli skonfigurowane są **podatne templates**, można je nadużyć do eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Gdy otrzymasz uprawnienia **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **zrzucić** **bazę domeny**: _ntds.dit_.

[**Więcej informacji o ataku DCSync można znaleźć tutaj**](dcsync.md).

[**Więcej informacji o tym, jak ukraść NTDS.dit można znaleźć tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Niektóre z wcześniej omawianych technik mogą być użyte jako metoda persistencji.\
Na przykład możesz:

- Uczynić użytkowników podatnymi na [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Uczynić użytkowników podatnymi na [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Przyznać [**DCSync**](#dcsync) uprawnienia użytkownikowi

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Atak **Silver Ticket** tworzy **prawidłowy Ticket Granting Service (TGS) ticket** dla konkretnej usługi, używając **NTLM hasha** (na przykład, **hash konta komputera**). Ta metoda służy do **uzyskania uprawnień do usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **NTLM hasha konta krbtgt** w środowisku Active Directory. To konto jest szczególne, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są kluczowe dla uwierzytelniania w sieci AD.

Po uzyskaniu tego hasha, atakujący może tworzyć **TGTs** dla dowolnego konta (atak typu Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są podobne do golden tickets, spreparowane w sposób, który **omija powszechne mechanizmy detekcji golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich zażądania** to bardzo dobry sposób na utrzymanie persistencji w koncie użytkownika (nawet jeśli zmieni hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Używanie certyfikatów umożliwia również utrzymanie wysokich uprawnień w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanym grupom** (takim jak Domain Admins i Enterprise Admins) poprzez zastosowanie standardowego **Access Control List (ACL)** w tych grupach, by zapobiec nieautoryzowanym zmianom. Jednak ta funkcja może zostać wykorzystana; jeśli atakujący zmodyfikuje ACL AdminSDHolder, przyznając pełny dostęp zwykłemu użytkownikowi, ten użytkownik uzyska szeroką kontrolę nad wszystkimi uprzywilejowanymi grupami. Ten mechanizm bezpieczeństwa, zaprojektowany do ochrony, może więc działać na korzyść atakującego, jeśli nie jest ściśle monitorowany.

[**Więcej informacji o AdminDSHolder Group tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje konto **lokalnego administratora**. Uzyskując prawa administratorskie na takiej maszynie, hash lokalnego Administratora można wyciągnąć używając **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, co pozwala na zdalny dostęp do konta lokalnego Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **przyznać** pewne **specjalne uprawnienia** użytkownikowi nad określonymi obiektami domeny, które pozwolą temu użytkownikowi **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** są używane do **przechowywania** **uprawnień**, jakie **obiekt** ma **do** innego **obiektu**. Jeśli dokonasz nawet **niewielkiej zmiany** w **security descriptor** obiektu, możesz uzyskać bardzo interesujące uprawnienia nad tym obiektem bez potrzeby bycia członkiem uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Modyfikuj **LSASS** w pamięci, aby ustanowić **uniwersalne hasło**, dające dostęp do wszystkich kont domenowych.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Dowiedz się, czym jest SSP (Security Support Provider) tutaj.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz stworzyć własne **SSP**, aby **przechwytywać** w **czystym tekście** **poświadczenia** używane do dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **wpychania atrybutów** (SIDHistory, SPNs...) na wskazanych obiektach **bez** pozostawiania logów dotyczących **modyfikacji**. Potrzebujesz uprawnień DA i być w **root domain**.\
Uwaga: jeśli użyjesz niepoprawnych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omówiliśmy, jak eskalować uprawnienia mając **wystarczające uprawnienia do odczytu haseł LAPS**. Jednak te hasła mogą być także użyte do **utrzymania persistencji**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft traktuje **Forest** jako granicę bezpieczeństwa. Oznacza to, że **kompromitacja pojedynczej domeny może potencjalnie doprowadzić do kompromitacji całego Forest**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa, który pozwala użytkownikowi z jednej **domeny** na dostęp do zasobów w innej **domenie**. Tworzy on powiązanie między systemami uwierzytelniania obu domen, pozwalając na przepływ weryfikacji uwierzytelnienia. Gdy domeny ustanawiają zaufanie, wymieniają i przechowują określone **klucze** w swoich **Domain Controllers (DCs)**, które są kluczowe dla integralności zaufania.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **trusted domain**, musi najpierw poprosić o specjalny ticket znany jako **inter-realm TGT** z DC swojej własnej domeny. Ten TGT jest szyfrowany przy użyciu współdzielanego **klucza**, na który obie domeny się umówiły. Użytkownik następnie przedstawia ten TGT DC **trusted domain**, aby otrzymać ticket usługi (**TGS**). Po pomyślnej weryfikacji inter-realm TGT przez DC domeny zaufanej, wydaje on TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. Komputer klienta w **Domain 1** rozpoczyna proces używając swojego **NTLM hasha** do żądania **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wydaje nowy TGT, jeśli klient został pomyślnie uwierzytelniony.
3. Klient następnie żąda **inter-realm TGT** od DC1, który jest potrzebny do dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany przy użyciu **trust key** współdzielonego między DC1 i DC2 jako części dwukierunkowego zaufania domen.
5. Klient zabiera inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 weryfikuje inter-realm TGT używając współdzielonego trust key i, jeśli jest ważny, wydaje **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. Na koniec klient przedstawia ten TGS serwerowi, który jest szyfrowany hashem konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Different trusts

Ważne jest zauważyć, że **trust może być jednokierunkowy lub dwukierunkowy**. W konfiguracji dwukierunkowej obie domeny ufają sobie nawzajem, ale w relacji **jednokierunkowej** jedna z domen będzie **trusted**, a druga **trusting**. W tym ostatnim przypadku **będziesz w stanie uzyskać dostęp tylko do zasobów w trusting domain z trusted domain**.

Jeśli Domain A ufa Domain B, A jest trusting domain, a B jest trusted. Co więcej, w **Domain A** będzie to **Outbound trust**; a w **Domain B** będzie to **Inbound trust**.

**Różne relacje zaufania**

- **Parent-Child Trusts**: Typowa konfiguracja w obrębie tego samego forest, gdzie domena potomna automatycznie ma dwukierunkowe zaufanie przechodnie z domeną nadrzędną. Oznacza to, że żądania uwierzytelnienia mogą płynnie przepływać między rodzicem a dzieckiem.
- **Cross-link Trusts**: Nazywane też "shortcut trusts", ustanawiane między domenami potomnymi w celu przyspieszenia procesów referral. W skomplikowanych lasach odniesienia uwierzytelniania zwykle muszą podróżować do root forest, a następnie do docelowej domeny. Tworząc cross-links skraca się tę drogę, co jest korzystne w rozproszonych geograficznie środowiskach.
- **External Trusts**: Ustanawiane między różnymi, niespokrewnionymi domenami i mają charakter non-transitive. Według dokumentacji Microsoft, external trusts są przydatne do dostępu do zasobów w domenie poza bieżącym forest, która nie jest połączona przez forest trust. Bezpieczeństwo jest wzmacniane przez SID filtering z external trusts.
- **Tree-root Trusts**: Zaufania te są automatycznie ustanawiane między root domeną forest a nowo dodanym tree root. Chociaż nie są często spotykane, tree-root trusts są istotne przy dodawaniu nowych drzew domen do lasu, umożliwiając im utrzymanie unikalnej nazwy domeny i zapewniając dwukierunkową przechodniość. Więcej informacji w przewodniku Microsoft.
- **Forest Trusts**: Ten typ zaufania to dwukierunkowe zaufanie przechodnie między dwoma root domenami forest, również egzekwujące SID filtering w celu zwiększenia bezpieczeństwa.
- **MIT Trusts**: Zaufania ustanawiane z nie-Windowsowymi, zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120) domenami Kerberos. MIT trusts są bardziej wyspecjalizowane i służą integracji z systemami Kerberos spoza ekosystemu Windows.

#### Other differences in **trusting relationships**

- Relacja zaufania może być również **transitive** (A ufa B, B ufa C, więc A ufa C) lub **non-transitive**.
- Relacja zaufania może być ustawiona jako **bidirectional trust** (obie ufają sobie nawzajem) lub jako **one-way trust** (tylko jedna ufa drugiej).

### Attack Path

1. **Enumerate** relacje zaufania
2. Sprawdź, czy jakiś **security principal** (user/group/computer) ma **dostęp** do zasobów **drugiej domeny**, być może przez wpisy ACE lub przez bycie w grupach drugiej domeny. Szukaj **zależności między domenami** (zaufanie zostało stworzone prawdopodobnie z tego powodu).
1. kerberoast w tym przypadku może być kolejną opcją.
3. **Skompromituj** **kont-a**, które mogą **pivotować** przez domeny.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie przez trzy główne mechanizmy:

- **Local Group Membership**: Principalsi mogą być dodani do lokalnych grup na maszynach, takich jak grupa “Administrators” na serwerze, dając im znaczącą kontrolę nad tą maszyną.
- **Foreign Domain Group Membership**: Principals mogą również być członkami grup w domenie zewnętrznej. Jednak skuteczność tej metody zależy od charakteru zaufania i zakresu grupy.
- **Access Control Lists (ACLs)**: Principals mogą być wskazani w **ACL**, szczególnie jako encje w **ACE** w **DACL**, zapewniając im dostęp do konkretnych zasobów. Dla tych, którzy chcą zgłębić mechanikę ACL, DACL i ACE, whitepaper "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" jest nieocenionym źródłem.

### Find external users/groups with permissions

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/forest**.

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
Inne sposoby enumeracji zaufanych domen:
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
> Istnieją **2 trusted keys**, jeden dla _Potomna --> Nadrzędna_ i drugi dla _Nadrzędna --> Potomna_.\
> Możesz sprawdzić, który jest używany przez bieżącą domenę za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Zwiększ uprawnienia do Enterprise admin w domenie potomnej/nadrzędnej, nadużywając zaufania za pomocą SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, jak można wykorzystać Configuration Naming Context (NC), jest kluczowe. Configuration NC pełni rolę centralnego repozytorium danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, a zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **uprawnienia SYSTEM na DC**, najlepiej na DC w domenie potomnej.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o site'ach wszystkich komputerów dołączonych do domeny w obrębie lasu AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą powiązać GPO z site'ami root DC. Działanie to może potencjalnie skompromitować root domain poprzez manipulowanie politykami stosowanymi do tych site'ów.

Aby uzyskać więcej informacji, można przejrzeć badania dotyczące [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Wejściem ataku jest skierowanie się na uprzywilejowane gMSA w domenie. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, możliwe jest uzyskanie dostępu do KDS Root key i obliczenie haseł dla dowolnego gMSA w całym lesie.

Szczegółowa analiza i instrukcja krok po kroku dostępne są w:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak na delegated MSA (BadSuccessor – nadużywanie atrybutów migracji):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe badania zewnętrzne: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ta metoda wymaga cierpliwości — oczekiwania na utworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować AD Schema, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i kontroli nad nowo tworzonymi obiektami AD.

Dalszą lekturę znajdziesz w [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Luka ADCS ESC5 celuje w kontrolę nad obiektami Public Key Infrastructure (PKI), aby stworzyć szablon certyfikatu umożliwiający uwierzytelnianie się jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, kompromitacja zapisywalnego DC w domenie potomnej pozwala na przeprowadzenie ataków ESC5.

Więcej szczegółów można znaleźć w [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). W scenariuszach bez ADCS atakujący ma możliwość skonfigurowania niezbędnych komponentów, jak opisano w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
W tym scenariuszu **twoja domena jest zaufana** przez domenę zewnętrzną, co daje ci **nieokreślone uprawnienia** wobec niej. Musisz ustalić, **które podmioty (principals) twojej domeny mają jakie uprawnienia wobec domeny zewnętrznej**, a następnie spróbować to wykorzystać:


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
W tym scenariuszu **twoja domena** udziela **uprawnień** podmiotowi z **innej domeny**.

Jednak gdy **domena jest zaufana** przez domenę ufającą, domena zaufana **tworzy użytkownika** o **przewidywalnej nazwie**, który jako **hasło** używa **zaufanego hasła**. Co oznacza, że możliwe jest **uzyskanie dostępu do użytkownika z domeny ufającej, aby dostać się do domeny zaufanej** w celu jej zenumerowania i próby eskalacji uprawnień:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem przejęcia domeny zaufanej jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** względem zaufania domeny (co nie jest zbyt częste).

Innym sposobem przejęcia domeny zaufanej jest oczekiwanie na maszynie, do której **użytkownik z domeny zaufanej może się zalogować** przez **RDP**. Następnie atakujący może wstrzyknąć kod do procesu sesji RDP i w ten sposób **dostać się do źródłowej domeny ofiary**. Ponadto, jeśli **ofiara zamontowała swój dysk twardy**, z procesu **sesji RDP** atakujący może umieścić **backdoors** w **folderze autostartu dysku twardego**. Ta technika nazywa się **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Łagodzenie nadużyć związanych z zaufaniem domen

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SIDHistory w ramach trustów między lasami jest ograniczone przez SID Filtering, które jest domyślnie aktywowane we wszystkich trustach między lasami. Wynika to z założenia, że trusty wewnątrz lasu są bezpieczne, traktując las, a nie domenę, jako granicę bezpieczeństwa zgodnie ze stanowiskiem Microsoftu.
- Jednak istnieje haczyk: SID filtering może zakłócić działanie aplikacji i dostęp użytkowników, co prowadzi czasem do jego dezaktywacji.

### **Selective Authentication:**

- W przypadku trustów między lasami użycie Selective Authentication zapewnia, że użytkownicy z obu lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen lub serwerów w domenie lub lesie ufającym.
- Należy zauważyć, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto zaufania.

[**Więcej informacji o zaufaniach domen na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Ogólne środki obronne

[**Dowiedz się więcej o ochronie poświadczeń tutaj.**](../stealing-credentials/credentials-protections.md)

### **Środki obronne w zakresie ochrony poświadczeń**

- **Domain Admins Restrictions**: Zaleca się, aby członkom grupy Domain Admins zezwalać jedynie na logowanie się na Domain Controllers, unikając ich używania na innych hostach.
- **Service Account Privileges**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA) w celu zachowania bezpieczeństwa.
- **Temporal Privilege Limitation**: W przypadku zadań wymagających uprawnień DA ich czas trwania powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Wdrażanie technik Deception**

- Wdrażanie deception polega na ustawianiu pułapek, takich jak decoy users lub komputery, z cechami takimi jak hasła, które nie wygasają, lub oznaczone jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi prawami lub dodawanie ich do grup o wysokich uprawnieniach.
- Praktyczny przykład obejmuje użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej o wdrażaniu technik deception można znaleźć na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Wykrywanie Deception**

- **Dla obiektów typu User**: Podejrzane wskaźniki to nietypowy ObjectSID, rzadkie logowania, daty utworzenia oraz niski licznik nieudanych prób hasła.
- **Ogólne wskaźniki**: Porównywanie atrybutów potencjalnych decoy objects z autentycznymi może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikacji takich deceptions.

### **Omijanie systemów wykrywania**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers, aby zapobiec wykryciu przez ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga uniknąć wykrycia poprzez nieprzejście na NTLM.
- **DCSync Attacks**: Zaleca się wykonywanie ich z maszyny niebędącej Domain Controllerem, aby uniknąć wykrycia przez ATA, ponieważ bezpośrednie wykonanie na Domain Controller spowoduje alerty.

## Odniesienia

- http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/
- https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
- https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain

{{#include ../../banners/hacktricks-training.md}}
