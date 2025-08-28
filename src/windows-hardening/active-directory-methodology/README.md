# Metodyka Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** pełni rolę podstawowej technologii, umożliwiającej **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** oraz **obiektami** w sieci. Został zaprojektowany z myślą o skalowalności, ułatwiając organizowanie dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, jednocześnie kontrolując **prawa dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** czy **urządzenia**, które dzielą wspólną bazę danych. **Drzewa** to grupy tych domen powiązane wspólną strukturą, a **las** reprezentuje zbiór wielu drzew połączonych przez **zaufania (trust relationships)**, tworząc najwyższy poziom struktury organizacyjnej. Na każdym z tych poziomów można przypisać specyficzne **uprawnienia dostępu** oraz prawa komunikacji.

Kluczowe pojęcia w **Active Directory** obejmują:

1. **Directory** – Zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – Oznacza byty w katalogu, w tym **użytkowników**, **grupy** lub **udzielone foldery**.
3. **Domain** – Służy jako kontener dla obiektów katalogu; w ramach **lasa** może istnieć wiele domen, z których każda posiada własny zestaw obiektów.
4. **Tree** – Grupowanie domen, które dzielą wspólną domenę główną.
5. **Forest** – Najwyższa warstwa struktury organizacyjnej w Active Directory, składająca się z kilku drzew połączonych **zaufaniami (trust relationships)**.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym **uwierzytelnianiem** i funkcjami **wyszukiwania**.
2. **Certificate Services** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – Wspiera aplikacje wykorzystujące katalog poprzez protokół **LDAP**.
4. **Directory Federation Services** – Zapewnia funkcje **single-sign-on** do uwierzytelniania użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawami autorskimi, regulując ich nieautoryzowaną dystrybucję i użycie.
6. **DNS Service** – Kluczowy dla rozwiązywania **nazw domen**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

If you just have access to an AD environment but you don't have any credentials/sessions you could:

- **Pentest the network:**
- Scan the network, find machines and open ports and try to **exploit vulnerabilities** or **extract credentials** from them (for example, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumerating DNS could give information about key servers in the domain as web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Take a look to the General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) to find more information about how to do this.
- **Check for null and Guest access on smb services** (this won't work on modern Windows versions):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- A more detailed guide on how to enumerate a SMB server can be found here:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- A more detailed guide on how to enumerate LDAP can be found here (pay **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Access host by [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extract usernames/names from internal documents, social media, services (mainly web) inside the domain environments and also from the publicly available.
- If you find the complete names of company workers, you could try different AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). The most common conventions are: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Check the [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) and [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages.
- **Kerbrute enum**: When an **invalid username is requested** the server will respond using the **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, allowing us to determine that the username was invalid. **Valid usernames** will illicit either the **TGT in a AS-REP** response or the error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicating that the user is required to perform pre-authentication.
- **No Authentication against MS-NRPC**: Using auth-level = 1 (No authentication) against the MS-NRPC (Netlogon) interface on domain controllers. The method calls the `DsrGetDcNameEx2` function after binding MS-NRPC interface to check if the user or computer exists without any credentials. The [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implements this type of enumeration. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
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
> Możesz znaleźć listy nazw użytkowników w [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) i w tym ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jednak powinieneś mieć **imiona osób pracujących w firmie** z etapu recon, który powinieneś wykonać wcześniej. Mając imię i nazwisko możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnych prawidłowych nazw użytkowników.

### Knowing one or several usernames

Ok, więc wiesz, że masz już prawidłową nazwę użytkownika, ale nie masz haseł... Spróbuj wtedy:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_, możesz **zażądać komunikatu AS_REP** dla tego użytkownika, który będzie zawierał dane zaszyfrowane pochodną hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Wypróbuj najbardziej **popularne hasła** dla każdego z odkrytych użytkowników — być może ktoś używa słabego hasła (pamiętaj o polityce haseł!).
- Zauważ, że możesz też **spraysować serwery OWA**, aby spróbować uzyskać dostęp do skrzynek pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie **uzyskać** pewne challenge **hashy** do crackowania, poprzez poisoning niektórych protokołów w **sieci**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Jeśli udało Ci się zenumerować Active Directory, będziesz miał **więcej maili i lepsze zrozumienie sieci**. Możesz być w stanie zmusić do NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack), aby uzyskać dostęp do środowiska AD.

### Steal NTLM Creds

Jeśli możesz **dostać się do innych PC lub share'ów** używając użytkownika null lub guest, możesz **umieścić pliki** (np. plik SCF), które jeśli zostaną w jakiś sposób otwarte, spowodują **wywołanie NTLM authentication przeciwko Tobie**, dzięki czemu możesz **ukraść** **NTLM challenge** i spróbować je złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Na tym etapie musisz **posiadać skompromitowane poświadczenia lub sesję ważnego konta domenowego.** Jeśli masz jakieś prawidłowe poświadczenia lub shell jako użytkownik domenowy, **pamiętaj, że opcje wymienione wcześniej nadal mogą posłużyć do kompromitacji innych użytkowników**.

Zanim zaczniesz uwierzytelnioną enumerację powinieneś znać, czym jest **Kerberos double hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Skompromitowanie konta to **duży krok do rozpoczęcia kompromitacji całej domeny**, ponieważ będziesz mógł rozpocząć **Active Directory Enumeration:**

Jeśli chodzi o [**ASREPRoast**](asreproast.md), teraz możesz znaleźć każdy możliwy podatny użytkownik, a w kontekście [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i spróbować hasła skompromitowanego konta, pustych haseł oraz nowych obiecujących haseł.

- Możesz użyć [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz też użyć [**powershell for recon**](../basic-powershell-for-pentesters/index.html), co będzie bardziej stealthy
- Możesz również [**use powerview**](../basic-powershell-for-pentesters/powerview.md) do wyciągnięcia bardziej szczegółowych informacji
- Kolejnym rewelacyjnym narzędziem do reconu w Active Directory jest [**BloodHound**](bloodhound.md). Nie jest ono **zbyt stealthy** (zależnie od metod zbierania), ale **jeśli Cię to nie obchodzi**, warto spróbować. Znajdź gdzie użytkownicy mogą RDP, znajdź ścieżki do innych grup itd.
- **Inne zautomatyzowane narzędzia do enumeracji AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) mogą zawierać interesujące informacje.
- Narzędziem z GUI, którego możesz użyć do enumeracji katalogu, jest **AdExplorer.exe** ze Suite **SysInternal**.
- Możesz też przeszukać bazę LDAP za pomocą **ldapsearch**, szukając poświadczeń w polach _userPassword_ & _unixUserPassword_, czy nawet w _Description_. Zob. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) dla innych metod.
- Jeśli używasz **Linux**, możesz też zenumerować domenę używając [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz też spróbować zautomatyzowanych narzędzi takich jak:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Bardzo łatwo jest uzyskać wszystkie nazwy użytkowników domeny z Windows (`net user /domain`, `Get-DomainUser` lub `wmic useraccount get name,sid`). W Linuxie możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli sekcja Enumeration wydaje się krótka, to jest to najważniejsza część ze wszystkich. Otwórz linki (głównie te do cmd, powershell, powerview i BloodHound), naucz się, jak enumerować domenę i ćwicz, aż poczujesz się komfortowo. Podczas assessmentu będzie to kluczowy moment, aby znaleźć drogę do DA lub zdecydować, że nic nie da się zrobić.

### Kerberoast

Kerberoasting polega na uzyskaniu **TGS tickets** używanych przez serwisy powiązane z kontami użytkowników i złamaniu ich szyfrowania — które opiera się na hasłach użytkowników — **offline**.

Więcej na ten temat w:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Gdy uzyskasz jakieś poświadczenia, możesz sprawdzić, czy masz dostęp do jakiejkolwiek **maszyny**. W tym celu możesz użyć **CrackMapExec**, aby próbować połączyć się z wieloma serwerami przy użyciu różnych protokołów, zgodnie z wynikami skanów portów.

### Local Privilege Escalation

Jeśli skompromitowałeś poświadczenia lub sesję jako zwykły użytkownik domenowy i masz **dostęp** tym użytkownikiem do **jakiejkolwiek maszyny w domenie**, powinieneś spróbować znaleźć sposób na **escalate privileges locally i poszukiwanie poświadczeń**. Tylko mając uprawnienia lokalnego administratora będziesz w stanie **zrzucić hashe innych użytkowników** z pamięci (LSASS) i lokalnie (SAM).

W tej książce jest pełna strona poświęcona [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklist**](../checklist-windows-privilege-escalation.md). Nie zapomnij też użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Jest **bardzo mało prawdopodobne**, że znajdziesz **tickets** w bieżącym użytkowniku, które dadzą Ci uprawnienia do dostępu do nieoczekiwanych zasobów, ale możesz sprawdzić:
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

Teraz, gdy masz już podstawowe credentials, powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione w AD**. Możesz to robić ręcznie, ale to bardzo nudne, powtarzalne zadanie (a tym bardziej, jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz **uzyskać dostęp do innych PCów lub share'ów**, możesz **umieścić pliki** (np. plik SCF), które jeśli zostaną w jakiś sposób otwarte, **wywołają uwierzytelnienie NTLM przeciwko Tobie**, dzięki czemu możesz **ukraść** **NTLM challenge**, aby go złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta luka pozwalała dowolnemu uwierzytelnionemu użytkownikowi **skompromitować domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Dla poniższych technik zwykły domain user nie wystarczy — potrzebujesz specjalnych privileges/credentials, aby wykonać te ataki.**

### Hash extraction

Miejmy nadzieję, że udało Ci się **skompromitować jakieś konto local admin** przy użyciu [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) łącznie z relayingiem, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Następnie czas zrzucić wszystkie hashes z pamięci i lokalnie.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Musisz użyć jakiegoś **tool**, który **wykona** **NTLM authentication** używając tego **hasha**, **lub** możesz stworzyć nowy **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, tak by przy każdej **NTLM authentication** używany był ten **hash**. Ostatnia opcja to to, co robi mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **użyć NTLM hasha użytkownika do zażądania Kerberos tickets**, jako alternatywę dla klasycznego Pass The Hash przez protokół NTLM. Dlatego może to być szczególnie **przydatne w sieciach, gdzie NTLM jest wyłączony** i jako protokół uwierzytelniania dozwolony jest tylko **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną ticket uwierzytelniający użytkownika** zamiast jego hasła czy wartości hash. Ukradziony ticket jest następnie używany do **podszywania się pod użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Jeśli masz **hash** lub **password** **local administratora**, powinieneś spróbować **zalogować się lokalnie** na innych **PCs** używając tych danych.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Zwróć uwagę, że jest to dość **głośne** i **LAPS** **łagodziłby** to.

### MSSQL Abuse & Trusted Links

Jeśli użytkownik ma uprawnienia do **access MSSQL instances**, może być w stanie użyć ich do **execute commands** na hoście MSSQL (jeśli działa jako SA), **steal** hasha NetNTLM lub nawet przeprowadzić **relay attack**.\
Również, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL. Jeśli użytkownik ma uprawnienia do zaufanej bazy, będzie w stanie **use the trust relationship to execute queries also in the other instance**. Te zaufania mogą być łańcuchowane i w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę, na której będzie mógł wykonywać polecenia.\
**Połączenia między bazami danych działają nawet w ramach forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Zewnętrzne narzędzia do inwentaryzacji i deploymentu często udostępniają potężne ścieżki do poświadczeń i wykonania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz jakikolwiek obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić TGTs z pamięci wszystkich użytkowników, którzy logują się na tym komputerze.\
Tak więc, jeśli **Domain Admin logins onto the computer**, będziesz w stanie zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (oby to był DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma przyzwolenie na "Constrained Delegation", będzie w stanie **impersonate any user to access some services in a computer**.\
Następnie, jeśli **compromise the hash** tego użytkownika/komputera, będziesz w stanie **impersonate any user** (nawet Domain Admins) aby uzyskać dostęp do niektórych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** na obiekcie Active Directory zdalnego komputera umożliwia osiągnięcie wykonania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Skompromitowany użytkownik mógł mieć pewne **interesujące uprawnienia do niektórych obiektów domeny**, które mogłyby pozwolić Ci **move** lateralnie/**escalate** uprawnienia.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Odnalezienie aktywnej **Spool service listening** w domenie może zostać **abused** do **acquire new credentials** i **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Jeśli **inni użytkownicy** **access** skompromitowaną maszynę, możliwe jest **gather credentials from memory** a nawet **inject beacons in their processes** aby podszyć się pod nich.\
Zwykle użytkownicy uzyskują dostęp do systemu przez RDP, więc poniżej opisano jak wykonać kilka ataków na sesje RDP osób trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **local Administrator password** na komputerach dołączonych do domeny, zapewniając, że jest ono **randomized**, unikalne i często **changed**. Te hasła są przechowywane w Active Directory, a dostęp jest kontrolowany przez ACL do uprawnionych użytkowników. Mając wystarczające uprawnienia do odczytu tych haseł, pivoting na inne komputery staje się możliwy.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** ze skompromitowanej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Jeśli skonfigurowano **vulnerable templates**, możliwe jest ich nadużycie w celu eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Gdy uzyskasz uprawnienia **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **dump** **domain database**: _ntds.dit_.

[**Więcej informacji o ataku DCSync można znaleźć tutaj**](dcsync.md).

[**Więcej informacji o tym, jak ukraść NTDS.dit można znaleźć tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Niektóre z technik omówionych wcześniej mogą być użyte jako persystencja.\
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

Atak **Silver Ticket** tworzy **prawidłowy Ticket Granting Service (TGS) ticket** dla konkretnej usługi, używając **NTLM hash** (na przykład, **hash konta PC**). Metoda ta jest wykorzystywana do **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na tym, że atakujący uzyskuje dostęp do **NTLM hash of the krbtgt account** w środowisku Active Directory (AD). To konto jest szczególne, ponieważ jest używane do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

Gdy atakujący zdobędzie ten hash, może tworzyć **TGTs** dla dowolnego konta, które wybierze (atak Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są to bilety podobne do golden tickets, sfałszowane w sposób, który **omija powszechne mechanizmy wykrywania golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich wystawienia** to bardzo dobry sposób na utrzymanie dostępu do konta użytkownika (nawet jeśli zmieni on hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Używanie certyfikatów pozwala również na utrzymanie wysokich uprawnień w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (jak Domain Admins i Enterprise Admins) poprzez zastosowanie standardowego **Access Control List (ACL)** dla tych grup, aby zapobiec nieautoryzowanym zmianom. Jednak ta funkcja może być nadużyta; jeśli atakujący zmodyfikuje ACL AdminSDHolder, aby nadać pełny dostęp zwykłemu użytkownikowi, ten użytkownik zyska rozległą kontrolę nad wszystkimi uprzywilejowanymi grupami. Ten mechanizm zabezpieczeń, mający chronić, może więc obrócić się przeciwko, umożliwiając nieuzasadniony dostęp, chyba że jest ściśle monitorowany.

[**Więcej informacji o AdminDSHolder Group tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje lokalne konto administratora. Uzyskując prawa administratora na takiej maszynie, hash lokalnego Administratora można wyodrębnić za pomocą **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, co pozwala na zdalny dostęp do konta lokalnego Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **przyznać** użytkownikowi pewne **specjalne uprawnienia** do konkretnych obiektów domeny, które pozwolą użytkownikowi w przyszłości **eskalować uprawnienia**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** są używane do **przechowywania** **uprawnień**, które **obiekt** ma **do** innego **obiektu**. Jeśli możesz dokonać nawet **niewielkiej zmiany** w **security descriptor** obiektu, możesz uzyskać bardzo interesujące uprawnienia do tego obiektu bez konieczności bycia członkiem uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustanowić **uniwersalne hasło**, umożliwiające dostęp do wszystkich kont domenowych.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Dowiedz się, czym jest SSP (Security Support Provider) tutaj.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz stworzyć własny **SSP**, aby **capture** w **clear text** **credentials** używane do dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **push attributes** (SIDHistory, SPNs...) na określonych obiektach **bez** pozostawiania jakichkolwiek **logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień **DA** i musisz być w **root domain**.\
Zwróć uwagę, że jeśli użyjesz błędnych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omówiliśmy, jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Jednak te hasła mogą być również użyte do **maintain persistence**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft traktuje **Forest** jako granicę bezpieczeństwa. To implikuje, że **skompromitowanie pojedynczej domeny może potencjalnie doprowadzić do kompromitacji całego Forest**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa, który umożliwia użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. W praktyce tworzy powiązanie między systemami uwierzytelniania obu domen, pozwalając na przepływ weryfikacji. Kiedy domeny ustanawiają trust, wymieniają i przechowują określone **klucze** w swoich **Domain Controllers (DCs)**, które są kluczowe dla integralności trustu.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **trusted domain**, musi najpierw poprosić o specjalny bilet znany jako **inter-realm TGT** od DC swojej domeny. Ten TGT jest szyfrowany za pomocą wspólnego **klucza**, który obie domeny uzgodniły. Użytkownik następnie przedstawia ten inter-realm TGT **DC z trusted domain**, aby otrzymać service ticket (**TGS**). Po pomyślnej weryfikacji inter-realm TGT przez DC trusted domain, DC wydaje TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. Komputer klienta w **Domain 1** zaczyna proces używając swojego **NTLM hash** do poproszenia o **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wydaje nowy TGT jeśli klient zostanie poprawnie uwierzytelniony.
3. Klient następnie żąda **inter-realm TGT** od DC1, który jest potrzebny do dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany przy użyciu **trust key** dzielonego między DC1 i DC2 jako część dwukierunkowego domain trust.
5. Klient zabiera inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 weryfikuje inter-realm TGT używając wspólnego trust key i, jeśli jest prawidłowy, wydaje **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. W końcu klient przedstawia ten TGS serwerowi, który jest szyfrowany hashem konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Different trusts

Ważne jest, aby zauważyć, że **trust może być jednokierunkowy lub dwukierunkowy**. W opcji dwukierunkowej obie domeny ufają sobie nawzajem, ale w relacji **jednokierunkowej** jedna z domen będzie **trusted**, a druga **trusting**. W tym ostatnim przypadku **będziesz mógł uzyskać dostęp tylko do zasobów w trusting domain z trusted domain**.

Jeśli Domain A ufa Domain B, A jest domeną trusting, a B jest domeną trusted. Co więcej, w **Domain A**, będzie to **Outbound trust**; a w **Domain B**, będzie to **Inbound trust**.

**Różne relacje zaufania**

- **Parent-Child Trusts**: To powszechne ustawienie w ramach tego samego forest, gdzie domena potomna automatycznie ma dwukierunkowy transitive trust z domeną nadrzędną. W praktyce oznacza to, że żądania autoryzacyjne mogą płynąć swobodnie między rodzicem a potomkiem.
- **Cross-link Trusts**: Nazywane też "shortcut trusts", są ustanawiane między domenami potomnymi, aby przyspieszyć procesy referencji. W złożonych forestach referencje uwierzytelniania zwykle muszą iść do korzenia lasu, a następnie w dół do domeny docelowej. Tworząc cross-links, skracasz tę drogę, co jest korzystne w rozproszonej geograficznie sieci.
- **External Trusts**: Ustanawiane między różnymi, niespokrewnionymi domenami i są z natury non-transitive. Według [dokumentacji Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts są użyteczne do uzyskiwania dostępu do zasobów w domenie spoza bieżącego forest, który nie jest połączony przez forest trust. Bezpieczeństwo jest wzmacniane przez filtrowanie SID z external trusts.
- **Tree-root Trusts**: Te trusty są automatycznie ustanawiane między forest root domain a nowo dodanym tree root. Chociaż nie są często spotykane, tree-root trusts są ważne przy dodawaniu nowych drzew do lasu, pozwalając im zachować unikalną nazwę domeny i zapewniając dwukierunkową transktywność. Więcej informacji można znaleźć w [przewodniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trustu jest dwukierunkowym transitive trust między dwoma forest root domains, również wymuszając filtrowanie SID w celu zwiększenia bezpieczeństwa.
- **MIT Trusts**: Trusty te są ustanawiane z nie-Windowsowymi, [RFC4120-kompatybilnymi](https://tools.ietf.org/html/rfc4120) domenami Kerberos. MIT trusts są bardziej wyspecjalizowane i służą integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Other differences in **trusting relationships**

- Relacja trustu może być również **transitive** (A ufa B, B ufa C, wtedy A ufa C) lub **non-transitive**.
- Relacja trustu może być ustawiona jako **bidirectional trust** (obie ufają sobie) lub jako **one-way trust** (tylko jedna ufa drugiej).

### Attack Path

1. **Enumerate** relacje zaufania
2. Sprawdź czy jakikolwiek **security principal** (user/group/computer) ma **access** do zasobów **drugiej domeny**, może poprzez wpisy ACE lub poprzez bycie w grupach drugiej domeny. Szukaj **relacji między domenami** (prawdopodobnie trust został utworzony w tym celu).
1. kerberoast w tym przypadku może być kolejną opcją.
3. **Compromise** konta, które mogą **pivot** przez domeny.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie przez trzy główne mechanizmy:

- **Local Group Membership**: Principals mogą zostać dodani do lokalnych grup na maszynach, takich jak grupa „Administrators” na serwerze, co daje im znaczącą kontrolę nad tą maszyną.
- **Foreign Domain Group Membership**: Principals mogą być również członkami grup w domenie obcej. Jednak skuteczność tej metody zależy od rodzaju trustu i zasięgu grupy.
- **Access Control Lists (ACLs)**: Principals mogą być wyspecyfikowani w **ACL**, szczególnie jako encje w **ACE** w **DACL**, dając im dostęp do konkretnych zasobów. Dla tych, którzy chcą zgłębić mechanikę ACL, DACL i ACE, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” jest nieocenionym źródłem.

### Find external users/groups with permissions

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **an external domain/forest**.

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
> There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
> Możesz sprawdzić, który z nich jest używany przez bieżącą domenę za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaluje do Enterprise admin w domenie podrzędnej/nadrzędnej, nadużywając zaufania poprzez SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, w jaki sposób można wykorzystać Configuration Naming Context (NC), jest kluczowe. Configuration NC pełni rolę centralnego repozytorium danych konfiguracyjnych w całym forest w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w forest, a writable DC przechowują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **SYSTEM privileges on a DC**, najlepiej na child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o site wszystkich komputerów dołączonych do domeny w forest. Mając uprawnienia SYSTEM na dowolnym DC, atakujący może powiązać GPO z root DC sites. Taka akcja może potencjalnie skompromitować root domain poprzez manipulację politykami stosowanymi do tych site'ów.

Po więcej informacji warto zapoznać się z badaniami na temat [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Wejście w kierunku uprzywilejowanych gMSA w domenie to kolejny wektor ataku. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, możliwe jest uzyskanie dostępu do KDS Root key i obliczenie haseł dowolnego gMSA w całym forest.

Szczegółowa analiza i przewodnik krok po kroku znajdują się w:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak na delegowane MSA (BadSuccessor – nadużycie atrybutów migracji):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe badania zewnętrzne: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ta metoda wymaga cierpliwości i oczekiwania na tworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować AD Schema, by nadać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i kontroli nad nowo tworzonymi obiektami AD.

Dalsza lektura dostępna jest w [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Luka ADCS ESC5 skupia się na kontroli nad obiektami PKI w celu utworzenia szablonu certyfikatu umożliwiającego uwierzytelnianie jako dowolny użytkownik w forest. Ponieważ obiekty PKI znajdują się w Configuration NC, kompromitacja writable child DC umożliwia przeprowadzenie ataków ESC5.

Więcej szczegółów w artykule [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). W scenariuszach bez ADCS atakujący ma możliwość skonfigurowania niezbędnych komponentów, o czym jest mowa w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
W tym scenariuszu **twoja domena jest zaufana** przez domenę zewnętrzną, co daje ci **nieokreślone uprawnienia** wobec niej. Będziesz musiał ustalić, **które principals z twojej domeny mają jaki dostęp do domeny zewnętrznej**, a następnie spróbować to wykorzystać:

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
W tym scenariuszu **twoja domena** przyznaje pewne **uprawnienia** podmiotowi z **innej domeny**.

Jednak, gdy **domena jest zaufana** przez domenę ufającą, **domena zaufana** **tworzy użytkownika** o **przewidywalnej nazwie**, który jako **hasło używa hasła zaufania**. To oznacza, że możliwe jest **uzyskanie dostępu do użytkownika z domeny ufającej, aby wejść do domeny zaufanej**, przeprowadzić jej enumerację i spróbować eskalować uprawnienia:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem na kompromitację domeny zaufanej jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** zaufania domeny (co nie jest zbyt powszechne).

Kolejnym sposobem jest pozostanie na maszynie, do której **użytkownik z domeny zaufanej może się zalogować** przez **RDP**. Następnie atakujący mógłby wstrzyknąć kod w proces sesji RDP i **uzyskać dostęp do domeny pochodzenia ofiary** stamtąd.\
Co więcej, jeśli **ofiarze podmontowali swój dysk twardy**, z procesu **sesji RDP** atakujący mógłby umieścić **backdoors** w **folderze autostartu dysku twardego**. Ta technika nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w ramach trustów między lasami jest łagodzone przez SID Filtering, które jest aktywowane domyślnie we wszystkich inter-forest trusts. Jest to oparte na założeniu, że zaufania wewnątrz lasu są bezpieczne, traktując las, a nie domenę, jako granicę bezpieczeństwa zgodnie ze stanowiskiem Microsoftu.
- Jednak jest haczyk: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego okazjonalnego wyłączenia.

### **Selective Authentication:**

- Dla inter-forest trusts stosowanie Selective Authentication zapewnia, że użytkownicy z dwóch lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w domenie lub lesie ufającym.
- Należy zauważyć, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Niektóre ogólne środki obronne

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Zaleca się, aby Domain Admins mogli logować się jedynie na Domain Controllers, unikając korzystania z tych kont na innych hostach.
- **Service Account Privileges**: Usługi nie powinny działać z uprawnieniami Domain Admin (DA), aby utrzymać bezpieczeństwo.
- **Temporal Privilege Limitation**: Dla zadań wymagających uprawnień DA należy ograniczyć ich czas trwania. Można to osiągnąć poleceniem: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Wdrażanie technik Deception**

- Wdrażanie deception polega na ustawianiu pułapek, takich jak fałszywi użytkownicy lub komputery, z cechami takimi jak hasła, które nie wygasają, lub oznaczone jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi prawami lub dodawanie ich do grup o wysokich uprawnieniach.
- Praktyczny przykład obejmuje użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej na temat wdrażania technik deception znajduje się na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Wykrywanie Deception**

- **For User Objects**: Podejrzane wskaźniki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia oraz niską liczbę nieudanych prób hasła.
- **General Indicators**: Porównywanie atrybutów potencjalnych obiektów przynęt z rzeczywistymi może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikacji takich deceptions.

### **Omijanie systemów detekcji**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers, aby zapobiec wykryciu przez ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga unikać detekcji poprzez niedowngrade'owanie do NTLM.
- **DCSync Attacks**: Zaleca się wykonywanie z maszyny będącej nie-Domain Controllerem, aby uniknąć wykrycia przez ATA, ponieważ bezpośrednie wykonanie z Domain Controller spowoduje alerty.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
