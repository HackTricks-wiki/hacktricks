# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** jest podstawową technologią umożliwiającą **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** i **obiektami** w sieci. Została zaprojektowana z myślą o skalowaniu, umożliwiając organizowanie dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, przy jednoczesnym kontrolowaniu **praw dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domains**, **trees** i **forests**. **Domain** obejmuje zbiór obiektów, takich jak **users** czy **devices**, które dzielą wspólną bazę danych. **Trees** to grupy tych domen powiązane wspólną strukturą, a **forest** reprezentuje kolekcję wielu trees, połączonych poprzez **trust relationships**, tworząc najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można określić specyficzne **prawa dostępu** i **komunikacji**.

Kluczowe pojęcia w **Active Directory** to:

1. **Directory** – Zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – Oznacza byty w katalogu, w tym **users**, **groups** lub **shared folders**.
3. **Domain** – Służy jako kontener dla obiektów katalogu; w **forest** może istnieć wiele domen, z których każda utrzymuje własny zbiór obiektów.
4. **Tree** – Grupa domen, które dzielą wspólną domenę root.
5. **Forest** – Najwyższy poziom struktury organizacyjnej w Active Directory, złożony z kilku trees z wzajemnymi **trust relationships**.

**Active Directory Domain Services (AD DS)** obejmuje zestaw usług kluczowych dla scentralizowanego zarządzania i komunikacji w sieci. Te usługi obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **users** a **domains**, w tym **authentication** i funkcjami **search**.
2. **Certificate Services** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **digital certificates**.
3. **Lightweight Directory Services** – Wspiera aplikacje wykorzystujące katalog za pomocą protokołu **LDAP**.
4. **Directory Federation Services** – Zapewnia możliwości **single-sign-on** pozwalające uwierzytelniać użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawami autorskimi, regulując ich nieautoryzowaną dystrybucję i użycie.
6. **DNS Service** – Kluczowy dla rozwiązywania **domain names**.

Dla bardziej szczegółowego wyjaśnienia sprawdź: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Aby nauczyć się, jak **atakować AD**, musisz bardzo dobrze **zrozumieć** proces **Kerberos authentication**.\
[**Przeczytaj tę stronę, jeśli nadal nie wiesz, jak to działa.**](kerberos-authentication.md)

## Skrócony przewodnik

Możesz zajrzeć na [https://wadcoms.github.io/](https://wadcoms.github.io) aby szybko zobaczyć, jakie polecenia można uruchomić do enumeracji/eksploatacji AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (bez poświadczeń/sesji)

Jeśli masz dostęp do środowiska AD, ale nie posiadasz żadnych poświadczeń/sesji, możesz:

- **Pentest the network:**
- Skanuj sieć, znajdź maszyny i otwarte porty oraz spróbuj **eksploitować podatności** lub **wyciągnąć poświadczenia** z nich (na przykład [drukarki mogą być bardzo ciekawymi celami](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak web, printers, shares, vpn, media itp.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zerknij na ogólną [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby znaleźć więcej informacji jak to robić.
- **Sprawdź dostęp null i Guest na usługach smb** (to nie zadziała na nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy przewodnik jak enumerować serwer SMB można znaleźć tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy przewodnik jak enumerować LDAP można znaleźć tutaj (zwróć **szczególną uwagę na dostęp anonimowy**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Zbieraj poświadczenia [**podszywając się pod usługi za pomocą Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta przez [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbieraj poświadczenia **eksponując** [**fałszywe usługi UPnP przy pomocy evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyciągaj nazwy użytkowników/imiona z dokumentów wewnętrznych, mediów społecznościowych, usług (głównie web) w obrębie środowiska domenowego, a także z zasobów publicznie dostępnych.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz spróbować różnych konwencji nazw użytkowników AD ([**przeczytaj to**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery z każdego), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonymous SMB/LDAP enum:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy żądany jest **nieprawidłowy username**, serwer odpowie kodem błędu **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala ustalić, że nazwa użytkownika jest nieprawidłowa. **Prawidłowe nazwy użytkowników** wywołają albo **TGT w AS-REP**, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazując, że użytkownik musi wykonać pre-autoryzację.
- **No Authentication against MS-NRPC**: Użycie auth-level = 1 (No authentication) przeciwko interfejsowi MS-NRPC (Netlogon) na kontrolerach domeny. Metoda wywołuje funkcję `DsrGetDcNameEx2` po związaniu interfejsu MS-NRPC, aby sprawdzić czy użytkownik lub komputer istnieje bez jakichkolwiek poświadczeń. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje tego typu enumerację. Badania można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Jeśli znalazłeś jeden z tych serwerów w sieci, możesz również przeprowadzić **user enumeration against it**. Na przykład możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Możesz znaleźć listy nazw użytkowników w [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) i w tym ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jednak powinieneś mieć **imiona i nazwiska osób pracujących w firmie** z etapu recon, który powinieneś wykonać wcześniej. Mając imię i nazwisko możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnych poprawnych nazw użytkowników.

### Knowing one or several usernames

Ok, więc wiesz, że masz już poprawną nazwę użytkownika, ale nie znasz haseł... Spróbuj:

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

## Enumerating Active Directory WITH credentials/session

Na tym etapie musisz mieć **skompromisowane poświadczenia lub sesję ważnego konta domenowego.** Jeśli masz jakieś ważne poświadczenia lub shell jako użytkownik domenowy, **pamiętaj, że wcześniejsze opcje nadal są sposobami na kompromitację innych użytkowników**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Skompromitowanie konta to **duży krok do rozpoczęcia kompromitacji całej domeny**, ponieważ będziesz mógł rozpocząć **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- Możesz użyć the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz też użyć [**powershell for recon**](../basic-powershell-for-pentesters/index.html), co będzie bardziej stealthy
- Możesz też [**use powerview**](../basic-powershell-for-pentesters/powerview.md) aby wydobyć bardziej szczegółowe informacje
- Kolejne świetne narzędzie do recon w Active Directory to [**BloodHound**](bloodhound.md). Nie jest **zbyt stealthy** (w zależności od metod zbierania, których użyjesz), ale **jeśli ci na tym nie zależy**, zdecydowanie warto spróbować. Znajdź, gdzie użytkownicy mogą RDP, znajdź ścieżki do innych grup, itd.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- Możesz także przeszukać bazę LDAP za pomocą **ldapsearch**, aby szukać poświadczeń w polach _userPassword_ & _unixUserPassword_, lub nawet w _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- Jeśli używasz **Linux**, możesz również enumerować domenę używając [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz też spróbować zautomatyzowanych narzędzi, takich jak:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Bardzo łatwo jest uzyskać wszystkie nazwy użytkowników domeny z Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). W Linux, możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli ta sekcja Enumeration wydaje się krótka, jest to najważniejsza część. Otwórz linki (głównie te dotyczące cmd, powershell, powerview i BloodHound), naucz się, jak enumerować domenę i ćwicz, aż poczujesz się pewnie. Podczas assessmentu będzie to kluczowy moment, aby znaleźć drogę do DA lub zdecydować, że nic nie da się zrobić.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Gdy zdobędziesz poświadczenia, możesz sprawdzić, czy masz dostęp do jakiejś **machine**. W tym celu możesz użyć **CrackMapExec** aby spróbować łączyć się z kilkoma serwerami przy użyciu różnych protokołów, zgodnie ze skanem portów.

### Local Privilege Escalation

Jeśli masz skompromitowane poświadczenia lub sesję jako zwykły użytkownik domenowy i masz za jego pomocą **access** do **any machine in the domain**, powinieneś spróbować znaleźć sposób na **escalate privileges locally and looting for credentials**. Tylko z uprawnieniami lokalnego administratora będziesz w stanie **dump hashes of other users** z pamięci (LSASS) i lokalnie (SAM).

W tej książce jest pełna strona o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklist**](../checklist-windows-privilege-escalation.md). Nie zapomnij też użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Jest bardzo **mało prawdopodobne**, że znajdziesz w bieżącym użytkowniku **tickets** dające Ci uprawnienia do dostępu do nieoczekiwanych zasobów, ale możesz sprawdzić:
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

Skoro masz już kilka podstawowych creds, powinieneś sprawdzić, czy możesz **find** jakiekolwiek **interesting files being shared inside the AD**. Możesz to zrobić ręcznie, ale to bardzo nudne, powtarzalne zadanie (a tym bardziej, jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz **access other PCs or shares**, możesz **place files** (np. plik SCF), które jeśli w jakiś sposób zostaną otwarte spowodują t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność pozwalała każdemu uwierzytelnionemu użytkownikowi na przejęcie kontrolera domeny.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Musisz użyć jakiegoś narzędzia, które wykona **NTLM authentication using** ten **hash**, **or** możesz utworzyć nowy **sessionlogon** i **inject** ten **hash** do **LSASS**, tak że gdy zostanie wykonana jakakolwiek **NTLM authentication**, ten **hash** będzie użyty. Ostatnia opcja to to, co robi mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **use the user NTLM hash to request Kerberos tickets**, jako alternatywa dla powszechnego Pass The Hash nad protokołem NTLM. W związku z tym może być szczególnie **useful in networks where NTLM protocol is disabled** i tylko **Kerberos is allowed** jako protokół uwierzytelniania.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Jeśli masz **hash** lub **password** konta **local administrator** powinieneś spróbować **login locally** na innych **PCs** przy jego użyciu.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Zwróć uwagę, że to jest dość **hałaśliwe** i **LAPS** by to **złagodził**.

### MSSQL Abuse & Trusted Links

Jeśli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może użyć ich do **wykonywania poleceń** na hoście MSSQL (jeśli proces działa jako SA), **ukraść** NetNTLM **hash** lub nawet przeprowadzić **relay attack**.\
Również, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL, a użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **wykorzystać relację zaufania do wykonywania zapytań także w drugiej instancji**. Te zaufania mogą być łańcuchowane i w pewnym momencie użytkownik może znaleźć błędnie skonfigurowaną bazę danych, gdzie będzie w stanie wykonywać polecenia.\
**Połączenia między bazami danych działają nawet przez trusty lasu.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Zewnętrzne systemy inwentaryzacji i wdrożeń często udostępniają potężne ścieżki do poświadczeń i wykonania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić TGTs z pamięci każdego użytkownika, który się zaloguje na ten komputer.\
Zatem, jeśli **Domain Admin zaloguje się na tym komputerze**, będziesz mógł zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (oby to był DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma pozwolenie na "Constrained Delegation", będzie mógł **podszyć się pod dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Jeśli **skomromitujesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet Domain Admins), aby uzyskać dostęp do określonych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** na obiekcie Active Directory zdalnego komputera umożliwia uzyskanie wykonania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Skompromitowany użytkownik może mieć pewne **interesujące uprawnienia nad obiektami domenowymi**, które pozwolą Ci później **poruszać się lateralnie/eskalować uprawnienia**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Wykrycie działającej **usługi Spool** w domenie może być **nadużyte** do **pozyskania nowych poświadczeń** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Jeśli **inni użytkownicy** **uzyskują dostęp** do **skomprmoitowanej** maszyny, możliwe jest **zbieranie poświadczeń z pamięci** i nawet **wstrzykiwanie beaconów do ich procesów** w celu podszycia się pod nich.\
Zazwyczaj użytkownicy łączą się przez RDP, więc tutaj masz jak przeprowadzić parę ataków na sesjach RDP osób trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **lokalnym hasłem Administratora** na komputerach dołączonych do domeny, zapewniając jego **losowość**, unikalność i częste **zmiany**. Hasła te są przechowywane w Active Directory, a dostęp kontrolowany jest przez ACL do uprawnionych użytkowników. Mając wystarczające uprawnienia do odczytu tych haseł, możliwe jest pivotowanie do innych komputerów.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Zebranie certyfikatów** ze skompromitowanej maszyny może być sposobem na eskalację uprawnień w środowisku:


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

Gdy zdobędziesz uprawnienia **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **zrzucić** **bazę domenową**: _ntds.dit_.

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

- Przyznać uprawnienia [**DCSync**](#dcsync) użytkownikowi

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Atak **Silver Ticket** tworzy **legalny TGS (Ticket Granting Service)** dla konkretnej usługi, używając **NTLM hash** (na przykład, **hash konta komputera**). Ta metoda jest używana do **uzyskania uprawnień do usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na zdobyciu przez atakującego **NTLM hasha konta krbtgt** w środowisku Active Directory (AD). To konto jest specjalne, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są kluczowe dla uwierzytelniania w sieci AD.

Po uzyskaniu tego hasha, atakujący może tworzyć **TGTs** dla dowolnego konta (atak podobny do Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są to bilety podobne do golden tickets, sfałszowane w taki sposób, by **ominięto typowe mechanizmy wykrywania golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich wystawiania** to bardzo dobry sposób na utrzymanie persistence w koncie użytkownika (nawet jeśli zmieni hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Użycie certyfikatów pozwala także utrzymać wysokie uprawnienia w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (jak Domain Admins i Enterprise Admins) przez stosowanie standardowego **ACL** do tych grup, żeby zapobiec nieautoryzowanym zmianom. Jednak funkcja ta może być nadużyta; jeśli atakujący zmodyfikuje ACL AdminSDHolder, by dać pełny dostęp zwykłemu użytkownikowi, ten użytkownik uzyskuje szeroką kontrolę nad wszystkimi uprzywilejowanymi grupami. Mechanizm ten, mający chronić, może w rezultacie dać nieuprawniony dostęp, chyba że jest ściśle monitorowany.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje konto **lokalnego administratora**. Uzyskując prawa administratora na takiej maszynie, hash lokalnego Administratora można wyciągnąć używając **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, pozwalając na zdalny dostęp do konta lokalnego Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **przyznać** pewne **specjalne uprawnienia** użytkownikowi nad niektórymi obiektami domenowymi, które pozwolą temu użytkownikowi **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** są używane do **przechowywania** **uprawnień**, jakie **obiekt** ma **wobec** innego **obiektu**. Jeśli możesz wykonać choćby **małą zmianę** w **security descriptorze** obiektu, możesz uzyskać bardzo interesujące uprawnienia nad tym obiektem bez konieczności bycia członkiem uprzywilejowanej grupy.


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

Rejestruje **nowy Domain Controller** w AD i używa go do **wypychania atrybutów** (SIDHistory, SPNs...) na określonych obiektach **bez** pozostawiania **logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień DA i musisz być wewnątrz **root domain**.\
Uwaga: jeśli użyjesz złych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omówiliśmy, jak eskalować uprawnienia mając **wystarczające uprawnienia do odczytu haseł LAPS**. Jednak te hasła mogą być także używane do **utrzymania persistence**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft traktuje **Forest** jako granicę bezpieczeństwa. Oznacza to, że **skompromitowanie pojedynczej domeny może potencjalnie doprowadzić do kompromitacji całego Forestu**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) jest mechanizmem bezpieczeństwa, który umożliwia użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. Tworzy łącze między systemami uwierzytelniania obu domen, pozwalając na płynny przepływ weryfikacji tożsamości. Gdy domeny ustanawiają trust, wymieniają i przechowują określone **klucze** w swoich **Domain Controllerach (DC)**, które są istotne dla integralności trustu.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **zaufanej domenie**, najpierw musi poprosić o specjalny bilet znany jako **inter-realm TGT** z DC swojej domeny. Ten TGT jest szyfrowany za pomocą współdzielonego **klucza**, na który obie domeny się umówiły. Następnie użytkownik przedstawia ten TGT **DC zaufanej domeny**, aby otrzymać bilet serwisowy (**TGS**). Po poprawnej weryfikacji inter-realm TGT przez DC zaufanej domeny, wydaje ona TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. **Klient** w **Domain 1** zaczyna proces używając swojego **NTLM hash**, aby zażądać **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wydaje nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Klient następnie żąda **inter-realm TGT** od DC1, który jest potrzebny do dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany za pomocą **trust key** współdzielonego między DC1 i DC2 w ramach dwukierunkowego trustu domen.
5. Klient zabiera inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 weryfikuje inter-realm TGT używając współdzielonego trust key i, jeśli jest ważny, wydaje **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. W końcu klient przedstawia ten TGS serwerowi, który jest szyfrowany za pomocą hash konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Different trusts

Ważne jest, aby zauważyć, że **trust może być jednokierunkowy lub dwukierunkowy**. W opcji dwukierunkowej obie domeny ufają sobie nawzajem, ale w relacji **jednokierunkowej** jedna z domen będzie **trusted**, a druga **trusting**. W tym ostatnim przypadku **będziesz mógł uzyskać dostęp tylko do zasobów w domenie trusting z domeny trusted**.

Jeśli Domain A ufa Domain B, A jest domeną trusting, a B jest domeną trusted. Co więcej, w **Domain A** będzie to **Outbound trust**; a w **Domain B** będzie to **Inbound trust**.

**Różne relacje zaufania**

- **Parent-Child Trusts**: To częsty układ wewnątrz tego samego lasu, gdzie domena potomna automatycznie ma dwukierunkowy, tranzytywny trust z domeną nadrzędną. Oznacza to, że żądania uwierzytelnienia mogą przepływać bez przeszkód między rodzicem a potomkiem.
- **Cross-link Trusts**: Nazywane też "shortcut trusts", są ustanawiane między domenami potomnymi, aby przyspieszyć procesy referencji. W złożonych lasach referencje uwierzytelniające zwykle muszą iść do korzenia lasu i potem w dół do docelowej domeny. Tworząc cross-links, skraca się tę drogę, co jest szczególnie korzystne w środowiskach rozproszonych geograficznie.
- **External Trusts**: Ustanawiane między różnymi, niespowiązanymi domenami i mają charakter non-transitive. Według [dokumentacji Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts są przydatne do dostępu do zasobów w domenie poza aktualnym lasem, która nie jest połączona przez forest trust. Bezpieczeństwo jest wzmacniane przez filtrowanie SID przy external trusts.
- **Tree-root Trusts**: Te trusty są automatycznie ustanawiane między domeną root lasu a nowo dodanym tree root. Chociaż nie są często spotykane, tree-root trusts są ważne przy dodawaniu nowych drzew domen do lasu, umożliwiając im zachowanie unikalnej nazwy domeny i zapewniając dwukierunkową tranzytywność. Więcej informacji znajduje się w [poradniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trustu to dwukierunkowy, tranzytywny trust między dwoma root domenami lasu, także egzekwujący filtrowanie SID w celu zwiększenia środków bezpieczeństwa.
- **MIT Trusts**: Trusty ustanawiane z nie-Windowsowymi, zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120) domenami Kerberos. MIT trusts są bardziej wyspecjalizowane i służą środowiskom wymagającym integracji z systemami opartymi na Kerberos spoza ekosystemu Windows.

#### Other differences in **trusting relationships**

- Relacja zaufania może być też **tranzytywna** (A ufa B, B ufa C, wtedy A ufa C) lub **non-transitive**.
- Relacja zaufania może być ustawiona jako **bidirectional trust** (obie ufają sobie) lub jako **one-way trust** (tylko jedna ufa drugiej).

### Attack Path

1. **Enumerate** relacje zaufania
2. Sprawdź, czy jakikolwiek **security principal** (user/group/computer) ma **dostęp** do zasobów **innej domeny**, być może przez wpisy ACE lub przynależność do grup innej domeny. Szukaj **relacji między domenami** (trust prawdopodobnie został utworzony właśnie w tym celu).
1. kerberoast w tym przypadku może być kolejną opcją.
3. **Skompromituj** **konta**, które mogą **pivotować** przez domeny.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie poprzez trzy główne mechanizmy:

- **Local Group Membership**: Principals mogą być dodani do lokalnych grup na maszynach, takich jak grupa “Administrators” na serwerze, co daje im znaczną kontrolę nad tą maszyną.
- **Foreign Domain Group Membership**: Principals mogą też być członkami grup w domenie zewnętrznej. Jednak skuteczność tej metody zależy od natury trustu i zakresu grupy.
- **Access Control Lists (ACLs)**: Principals mogą być wskazani w **ACL**, szczególnie jako encje w **ACE** w **DACL**, dając im dostęp do konkretnych zasobów. Dla osób chcących zgłębić mechanikę ACL, DACL i ACE, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” jest nieocenionym źródłem.

### Find external users/groups with permissions

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/lasu**.

Możesz to sprawdzić w **Bloodhound** lub używając **powerview**:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Eskalacja uprawnień z lasu podrzędnego do lasu nadrzędnego (privilege escalation)
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
Inne sposoby enumeracji zaufania między domenami:
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

Podnieś uprawnienia do Enterprise admin w domenie potomnej/nadrzędnej, wykorzystując zaufanie przez SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, jak można wykorzystać Configuration Naming Context (NC), jest kluczowe. Configuration NC pełni rolę centralnego repozytorium dla danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, a writable DCs utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **SYSTEM privileges on a DC**, najlepiej na child DC.

**Link GPO to root DC site**

Kontener Sites Configuration NC zawiera informacje o site'ach wszystkich komputerów dołączonych do domeny w lesie AD. Działając z **SYSTEM privileges** na dowolnym DC, atakujący mogą linkować GPOs do root DC sites. Ta operacja może potencjalnie skompromitować root domain przez manipulowanie policy stosowanymi wobec tych site'ów.

Aby uzyskać bardziej szczegółowe informacje, warto zapoznać się z badaniami [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jednym z wektorów ataku jest celowanie w uprzywilejowane gMSA w domenie. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając **SYSTEM privileges** na dowolnym DC, można uzyskać dostęp do KDS Root key i obliczyć hasła dla dowolnego gMSA w całym lesie.

Szczegółowa analiza i instrukcje krok po kroku można znaleźć w:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak na delegated MSA (BadSuccessor – nadużycie atrybutów migration):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe badania zewnętrzne: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ta metoda wymaga cierpliwości i oczekiwania na tworzenie nowych uprzywilejowanych AD objects. Mając **SYSTEM privileges**, atakujący może zmodyfikować AD Schema, aby nadać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i kontroli nad nowo tworzonymi AD objects.

Więcej informacji można znaleźć w [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Wrażliwość ADCS ESC5 pozwala na przejęcie kontroli nad obiektami Public Key Infrastructure (PKI) w celu utworzenia certificate template umożliwiającego uwierzytelnienie jako dowolny użytkownik w lesie. Ponieważ PKI objects znajdują się w Configuration NC, kompromitacja writable child DC umożliwia przeprowadzenie ESC5 attacks.

Więcej szczegółów na ten temat można przeczytać w [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). W scenariuszach bez ADCS atakujący ma możliwość skonfigurowania niezbędnych komponentów, o czym dyskutowano w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
W tym scenariuszu **twoja domena jest zaufana** przez domenę zewnętrzną, co daje ci **nieokreślone uprawnienia** w jej obrębie. Będziesz musiał ustalić, **które principaly twojej domeny mają jakie uprawnienia wobec domeny zewnętrznej**, a następnie spróbować je wykorzystać:


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
W tym scenariuszu **twoja domena** **przyznaje** pewne **uprawnienia** podmiotowi z **innej domeny**.

Jednak, gdy **domena jest zaufana** przez domenę ufającą, zaufana domena **tworzy użytkownika** o **przewidywalnej nazwie**, który jako **hasło używa zaufanego hasła**. To oznacza, że możliwe jest **uzyskanie dostępu do użytkownika z domeny ufającej, aby dostać się do tej zaufanej** w celu jej enumeracji i próby eskalacji kolejnych uprawnień:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Another way to compromise the trusted domain is to find a [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) created in the **opposite direction** of the domain trust (which isn't very common).

Another way to compromise the trusted domain is to wait in a machine where a **user from the trusted domain can access** to login via **RDP**. Then, the attacker could inject code in the RDP session process and **access the origin domain of the victim** from there.\
Moreover, if the **victim mounted his hard drive**, from the **RDP session** process the attacker could store **backdoors** in the **startup folder of the hard drive**. This technique is called **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w zaufaniach między lasami jest ograniczane przez SID Filtering, które jest domyślnie aktywowane we wszystkich inter-forest trusts. To opiera się na założeniu, że intra-forest trusts są bezpieczne, traktując forest, a nie domain, jako granicę bezpieczeństwa zgodnie ze stanowiskiem Microsoftu.
- Jednak jest haczyk: SID Filtering może zaburzać działanie aplikacji i dostęp użytkowników, co prowadzi do jego okazjonalnego wyłączania.

### **Selective Authentication:**

- W przypadku inter-forest trusts zastosowanie Selective Authentication zapewnia, że użytkownicy z obu lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w ramach trusting domain lub forest.
- Należy zauważyć, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na trust account.

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
### Prymitywy zapisu LDAP do eskalacji i utrzymania

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi umieścić nowych principals lub konta maszyn tam, gdzie istnieją prawa do OU. `add-groupmember`, `set-password`, `add-attribute` oraz `set-attribute` bezpośrednio przejmują cele po odnalezieniu write-property rights.
- Polecenia skupione na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` oraz `add-dcsync` przekładają WriteDACL/WriteOwner na dowolnym obiekcie AD na reset hasła, kontrolę członkostwa w grupie lub uprawnienia DCSync bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegacja, roasting i nadużycia Kerberosa

- `add-spn`/`set-spn` natychmiast czynią skompromitowanego użytkownika Kerberoastable; `add-asreproastable` (UAC toggle) oznacza go do AS-REP roasting bez ruszania hasła.
- Makra delegacji (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) przepisują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z beacona, umożliwiając constrained/unconstrained/RBCD ścieżki ataku i eliminując potrzebę zdalnego PowerShell lub RSAT.

### sidHistory injection, relokacja OU i kształtowanie powierzchni ataku

- `add-sidhistory` wstrzykuje uprzywilejowane SIDy do historii SID kontrolowanego principal’a (zobacz [SID-History Injection](sid-history-injection.md)), zapewniając skryte dziedziczenie dostępu w pełni przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenieść zasoby do OU, gdzie już istnieją prawa delegowane, przed nadużyciem `set-password`, `add-groupmember` lub `add-spn`.
- Ściśle ograniczone polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) umożliwiają szybkie wycofanie zmian po tym, jak operator pozyska poświadczenia lub persistence, minimalizując telemetrię.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Kilka ogólnych środków obronnych

[**Dowiedz się więcej o ochronie poświadczeń tutaj.**](../stealing-credentials/credentials-protections.md)

### **Środki obronne w celu ochrony poświadczeń**

- **Domain Admins Restrictions**: Zaleca się, aby Domain Admins mogli logować się wyłącznie do Domain Controllerów, unikając używania ich na innych hostach.
- **Service Account Privileges**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA) dla bezpieczeństwa.
- **Temporal Privilege Limitation**: Dla zadań wymagających uprawnień DA czas ich trwania powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Wdrażanie technik decepcyjnych**

- Wdrażanie decepсji polega na ustawianiu pułapek, jak użytkownicy lub komputery przynęty (decoy), z cechami takimi jak hasła, które nie wygasają, lub oznaczeniem Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi uprawnieniami lub dodawanie ich do grup o wysokich uprawnieniach.
- Praktyczny przykład obejmuje użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej na temat wdrażania technik decepcyjnych znajdziesz w [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identyfikacja decepсji**

- **Dla obiektów użytkownika**: Podejrzane wskaźniki to nietypowy ObjectSID, rzadkie logowania, daty utworzenia oraz niska liczba nieudanych prób hasła.
- **Ogólne wskaźniki**: Porównywanie atrybutów potencjalnych obiektów przynęt z tymi rzeczywistych może ujawnić niezgodności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikacji takich decepсji.

### **Omijanie systemów wykrywania**

- **Omijanie wykrywania Microsoft ATA**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllerach, aby zapobiec wykryciu przez ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga unikać wykrycia, nie wymuszając degradacji do NTLM.
- **DCSync Attacks**: Zaleca się wykonywanie z hosta innego niż Domain Controller, aby uniknąć wykrycia przez ATA, ponieważ bezpośrednie wykonanie na Domain Controllerze wywoła alerty.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
