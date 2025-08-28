# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** pełni rolę podstawowej technologii, umożliwiającej **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** i **obiektami** w ramach sieci. Został zaprojektowany z myślą o skalowalności, pozwalając na organizację dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, jednocześnie kontrolując **prawa dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** czy **urządzenia**, które dzielą wspólną bazę danych. **Drzewa** to grupy tych domen powiązanych wspólną strukturą, a **las** reprezentuje zbiór wielu drzew, połączonych poprzez **relacje zaufania**, tworząc najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można określić konkretne **prawa dostępu** i **komunikacji**.

Kluczowe pojęcia w **Active Directory** obejmują:

1. **Directory** – Przechowuje wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – Oznacza byty w katalogu, w tym **użytkowników**, **grupy** lub **udostępnione foldery**.
3. **Domain** – Służy jako kontener dla obiektów katalogu; w **lesie** może istnieć wiele domen, z których każda przechowuje własny zbiór obiektów.
4. **Tree** – Grupa domen dzielących wspólną domenę nadrzędną.
5. **Forest** – Najwyższa struktura organizacyjna w Active Directory, złożona z kilku drzew powiązanych **relacjami zaufania**.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania i komunikacji w sieci. Te usługi to:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym funkcjami **uwierzytelniania** i **wyszukiwania**.
2. **Certificate Services** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – Wspiera aplikacje korzystające z katalogu poprzez protokół **LDAP**.
4. **Directory Federation Services** – Zapewnia funkcje **single-sign-on**, pozwalając uwierzytelniać użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawami autorskimi, regulując ich nieautoryzowaną dystrybucję i użycie.
6. **DNS Service** – Kluczowa dla rozwiązywania **nazw domen**.

Po więcej szczegółów zobacz: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Aby nauczyć się **atakować AD** musisz bardzo dobrze **zrozumieć** proces **uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę jeśli nadal nie wiesz jak to działa.**](kerberos-authentication.md)

## Cheat Sheet

Możesz skorzystać z [https://wadcoms.github.io/](https://wadcoms.github.io) aby szybko zobaczyć, jakie polecenia możesz uruchomić, by enumerować/eksploitować AD.

> [!WARNING]
> Komunikacja Kerberos **wymaga w pełni kwalifikowanej nazwy (FQDN)** do wykonywania działań. Jeśli spróbujesz uzyskać dostęp do maszyny po adresie IP, **zostanie użyty NTLM, a nie Kerberos**.

## Rekonesans Active Directory (Brak poświadczeń/sesji)

Jeżeli masz dostęp do środowiska AD, ale nie posiadasz żadnych poświadczeń/sesji, możesz:

- **Pentest the network:**
- Skanuj sieć, znajdź maszyny i otwarte porty i spróbuj **eksploatować podatności** lub **wyciągnąć poświadczenia** z nich (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak web, drukarki, udostępnienia, vpn, media itp.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zobacz ogólną [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) aby znaleźć więcej informacji o tym, jak to robić.
- **Sprawdź dostęp null i Guest na usługach smb** (to nie zadziała w nowoczesnych wersjach Windows):
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
- Zbieraj poświadczenia [**podszywając się pod usługi przy pomocy Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta przez [**nadużycie relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbieraj poświadczenia **eksponując** [**fałszywe usługi UPnP przy pomocy evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyodrębnij nazwy użytkowników/imiona z wewnętrznych dokumentów, social media, usług (głównie web) wewnątrz środowisk domeny, a także z zasobów publicznie dostępnych.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz wypróbować różne konwencje nazewnictwa kont AD (**przeczytaj to**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najpopularniejsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery z każdego), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy żądany jest **nieprawidłowy username**, serwer odpowie kodem błędu Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala stwierdzić, że nazwa użytkownika była nieprawidłowa. **Prawidłowe nazwy użytkowników** wywołają albo **TGT w odpowiedzi AS-REP**, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazując, że użytkownik musi wykonać pre-autoryzację.
- **No Authentication against MS-NRPC**: Użycie auth-level = 1 (Brak uwierzytelnienia) przeciwko interfejsowi MS-NRPC (Netlogon) na kontrolerach domeny. Metoda wywołuje funkcję `DsrGetDcNameEx2` po bindowaniu się do interfejsu MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje bez żadnych poświadczeń. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten typ enumeracji. Badania można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
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
> Jednak powinieneś mieć **imiona osób pracujących w firmie** z kroku recon, który powinieneś wykonać wcześniej. Mając imię i nazwisko możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnych poprawnych nazw użytkowników.

### Znając jedną lub kilka nazw użytkowników

Ok, więc wiesz, że masz już prawidłową nazwę użytkownika, ale nie masz haseł... Spróbuj wtedy:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_ możesz **zażądać komunikatu AS_REP** dla tego użytkownika, który będzie zawierać pewne dane zaszyfrowane pochodną hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbuj najbardziej **popularnych haseł** dla każdego z odkrytych użytkowników, być może ktoś używa słabego hasła (pamiętaj o polityce haseł!).
- Zwróć uwagę, że możesz także **spray OWA servers**, aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie **uzyskać** pewne challenge **hashes** do złamania, poprzez **poisoning** niektórych protokołów **sieci**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Jeśli udało Ci się zenumerować Active Directory będziesz mieć **więcej adresów e-mail i lepsze zrozumienie sieci**. Możesz być w stanie wymusić NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) aby uzyskać dostęp do środowiska AD.

### Steal NTLM Creds

Jeśli możesz uzyskać **dostęp do innych maszyn lub shares** za pomocą **null lub guest user**, możesz **umieścić pliki** (np. plik SCF), które jeśli zostaną w jakiś sposób otwarte, spowodują **wyzwolenie NTLM authentication przeciwko tobie**, dzięki czemu możesz **steal** **NTLM challenge** do złamania:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumeracja Active Directory z poświadczeniami/sesją

Na tym etapie musisz mieć **skompromitowane poświadczenia lub sesję prawidłowego konta domenowego.** Jeśli masz jakieś prawidłowe poświadczenia lub shell jako użytkownik domenowy, **pamiętaj, że wcześniejsze opcje nadal mogą posłużyć do kompromitacji innych użytkowników**.

Zanim zaczniesz uwierzytelnioną enumerację, powinieneś znać, czym jest **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeracja

Skompromitowanie konta to **duży krok w kierunku kompromitacji całej domeny**, ponieważ będziesz mógł rozpocząć **enumerację Active Directory:**

Jeśli chodzi o [**ASREPRoast**](asreproast.md) możesz teraz znaleźć wszystkich potencjalnie podatnych użytkowników, a jeśli chodzi o [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i spróbować hasła ze skompromitowanego konta, pustych haseł oraz nowych obiecujących haseł.

- Możesz użyć [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz również użyć [**powershell for recon**](../basic-powershell-for-pentesters/index.html), co będzie bardziej dyskretne
- Możesz również [**use powerview**](../basic-powershell-for-pentesters/powerview.md) aby wydobyć bardziej szczegółowe informacje
- Kolejnym świetnym narzędziem do rozpoznania w Active Directory jest [**BloodHound**](bloodhound.md). Nie jest ono **zbyt dyskretne** (w zależności od używanych metod zbierania), ale **jeśli ci to nie przeszkadza**, zdecydowanie powinieneś go wypróbować. Znajdź gdzie użytkownicy mogą RDP, znajdź ścieżki do innych grup, itd.
- **Inne zautomatyzowane narzędzia do enumeracji AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
- Narzędzie z GUI, którego możesz użyć do enumeracji katalogu to **AdExplorer.exe** z pakietu **SysInternal** Suite.
- Możesz również przeszukać bazę LDAP za pomocą **ldapsearch**, aby szukać poświadczeń w polach _userPassword_ & _unixUserPassword_, lub nawet w polu _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) dla innych metod.
- Jeśli używasz **Linux**, możesz również enumerować domenę używając [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz również spróbować narzędzi automatycznych takich jak:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Wyodrębnianie wszystkich użytkowników domeny**

Bardzo łatwo uzyskać wszystkie nazwy użytkowników domeny z Windows (`net user /domain`, `Get-DomainUser` lub `wmic useraccount get name,sid`). W Linuxie możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli sekcja Enumeracja wydaje się krótka, to jest to najważniejsza część. Odwiedź linki (głównie te dotyczące cmd, powershell, powerview i BloodHound), naucz się jak enumerować domenę i ćwicz, aż poczujesz się pewnie. Podczas oceny/próby będzie to kluczowy moment, aby znaleźć drogę do DA albo zdecydować, że nic nie da się zrobić.

### Kerberoast

Kerberoasting polega na uzyskaniu **TGS tickets** używanych przez usługi powiązane z kontami użytkowników i łamaniu ich szyfrowania — które opiera się na hasłach użytkowników — **offline**.

Więcej na ten temat w:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Gdy zdobędziesz poświadczenia, możesz sprawdzić, czy masz dostęp do jakiejkolwiek **machine**. W tym celu możesz użyć **CrackMapExec**, aby spróbować łączyć się z kilkoma serwerami przy użyciu różnych protokołów, zgodnie z wynikami skanowania portów.

### Local Privilege Escalation

Jeśli masz skompromitowane poświadczenia lub sesję jako zwykły użytkownik domenowy i masz **dostęp** tym kontem do **jakiejkolwiek maszyny w domenie**, powinieneś spróbować znaleźć sposób na **escalate privileges locally i zebranie poświadczeń**. Tylko z uprawnieniami lokalnego administratora będziesz mógł **dump hashes of other users** z pamięci (LSASS) i lokalnie (SAM).

W tej książce jest pełna strona o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklist**](../checklist-windows-privilege-escalation.md). Również nie zapomnij użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Jest bardzo **mało prawdopodobne**, że znajdziesz w bieżącym użytkowniku **tickets**, które **dają Ci pozwolenie na dostęp** do nieoczekiwanych zasobów, ale możesz sprawdzić:
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

Teraz, gdy masz podstawowe credentials powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione w AD**. Możesz to zrobić ręcznie, ale to bardzo nudne, powtarzalne zadanie (a tym bardziej, jeśli znajdziesz setki dokumentów, które musisz sprawdzić).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Dla poniższych technik zwykły użytkownik domeny nie wystarczy — potrzebujesz specjalnych przywilejów/poświadczeń, aby wykonać te ataki.**

### Hash extraction

Miejmy nadzieję, że udało ci się **przejąć jakieś konto local admin** używając [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) włącznie z relayingiem, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Następnie czas zrzucić wszystkie hashe z pamięci i lokalnie.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
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

If you have the **hash** or **password** of a **local administrato**r you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Należy pamiętać, że to jest dość **głośne**, a **LAPS** by to **złagodził**.

### MSSQL Abuse & Trusted Links

Jeżeli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może ich użyć do **wykonywania poleceń** na hoście MSSQL (jeśli działa jako SA), **wykraść** NetNTLM **hash** lub nawet przeprowadzić **relay** **attack**.\
Również, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL. Jeśli użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **wykorzystać relację zaufania do wykonywania zapytań także w drugiej instancji**. Takie zaufania mogą być łańcuchowane i w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę danych, w której będzie mógł wykonywać polecenia.\
**Połączenia między bazami działają nawet przez forest trusts.**


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

Jeśli znajdziesz jakikolwiek obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić TGT z pamięci każdego użytkownika, który się na nim loguje.\
Zatem, jeśli **Domain Admin logins onto the computer**, będziesz w stanie zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (oby był to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma włączoną "Constrained Delegation", będzie mógł **podszywać się pod dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Następnie, jeśli **skomprujesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet domain admins), aby uzyskać dostęp do niektórych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** do obiektu Active Directory zdalnego komputera umożliwia uzyskanie wykonania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Skompromitowany użytkownik może mieć pewne **interesujące uprawnienia do niektórych obiektów domeny**, które pozwolą Ci później **przemieszczać się bocznie**/**eskalować** uprawnienia.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Odkrycie usługi **Spool nasłuchującej** w domenie może zostać **nadużyte** do **pozyskania nowych poświadczeń** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Jeśli **inni użytkownicy** **uzyskują dostęp** do **skompro-mitowanej** maszyny, możliwe jest **zbieranie poświadczeń z pamięci** i nawet **wstrzykiwanie beaconów do ich procesów**, aby podszyć się pod nich.\
Zwykle użytkownicy łączą się z systemem przez RDP, więc tutaj znajdziesz, jak wykonać kilka ataków na sesje RDP osób trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **lokalnym Administrator password** na komputerach dołączonych do domeny, zapewniając, że jest on **randomized**, unikalny i często **changed**. Te hasła są przechowywane w Active Directory, a dostęp do nich jest kontrolowany przez ACL dla uprawnionych użytkowników. Mając wystarczające uprawnienia do odczytu tych haseł, możliwe jest pivoting na inne komputery.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Zgromadzenie certyfikatów** z zaatakowanej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Jeśli skonfigurowane są **vulnerable templates**, można je nadużyć do eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Gdy zdobędziesz uprawnienia **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **zrzucić** **bazę domeny**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Niektóre z wcześniej omówionych technik mogą być użyte do utrzymania dostępu.\
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

Atak **Silver Ticket** tworzy legalny Ticket Granting Service (TGS) dla konkretnej usługi, używając **NTLM hash** (na przykład **hash** konta PC). Ta metoda jest stosowana, aby uzyskać **dostęp do przywilejów usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **NTLM hash** konta krbtgt w środowisku Active Directory (AD). To konto jest specjalne, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

Gdy atakujący zdobędzie ten **hash**, może tworzyć **TGTs** dla dowolnego konta, które wybierze (atak Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są to podobne do golden tickets, sfałszowane w taki sposób, że **omijają powszechne mechanizmy wykrywania golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich żądania** to bardzo dobry sposób na utrzymanie dostępu do konta użytkownika (nawet jeśli użytkownik zmieni hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Używanie certyfikatów umożliwia również utrzymanie się z wysokimi uprawnieniami wewnątrz domeny:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (jak Domain Admins i Enterprise Admins) przez zastosowanie standardowego **Access Control List (ACL)** dla tych grup, aby zapobiec nieautoryzowanym zmianom. Jednak ta funkcja może być wykorzystana; jeśli atakujący zmodyfikuje ACL AdminSDHolder, przyznając pełny dostęp zwykłemu użytkownikowi, użytkownik ten zyskuje rozległą kontrolę nad wszystkimi uprzywilejowanymi grupami. Ten mechanizm bezpieczeństwa, mający chronić, może więc działać przeciwko celowi, umożliwiając nieuzasadniony dostęp chyba że jest ściśle monitorowany.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje lokalne konto administratora. Uzyskując prawa admina na takiej maszynie, hash lokalnego Administratora można wyodrębnić przy użyciu **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, co pozwala na zdalny dostęp do konta lokalnego Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **nadać** pewne **specjalne uprawnienia** użytkownikowi do określonych obiektów domeny, które pozwolą temu użytkownikowi **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Security descriptors są używane do **przechowywania** **uprawnień**, jakie **obiekt** ma **nad** innym **obiektem**. Jeśli możesz dokonać nawet **niewielkiej zmiany** w **security descriptor** obiektu, możesz uzyskać bardzo interesujące uprawnienia do tego obiektu bez konieczności bycia członkiem uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustawić **uniwersalne hasło**, przyznające dostęp do wszystkich kont domeny.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz stworzyć własny **SSP**, aby przechwytywać poświadczenia w **clear text** używane do uzyskania dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **pushowania atrybutów** (SIDHistory, SPNs...) na wskazane obiekty **bez** pozostawiania jakichkolwiek **logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień **DA** i musisz być w **root domain**.\
Uwaga: jeśli użyjesz nieprawidłowych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omówiliśmy, jak eskalować uprawnienia, jeśli masz wystarczające uprawnienia do odczytu haseł **LAPS**. Jednak te hasła mogą być również wykorzystane do **utrzymania persystencji**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft traktuje **Forest** jako granicę bezpieczeństwa. To oznacza, że **kompromitacja pojedynczej domeny może potencjalnie prowadzić do kompromitacji całego Forest**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) jest mechanizmem bezpieczeństwa, który pozwala użytkownikowi z jednej **domeny** na dostęp do zasobów w innej **domenie**. Tworzy on powiązanie między systemami uwierzytelniania obu domen, umożliwiając przepływ weryfikacji uwierzytelnienia. Kiedy domeny konfigurowane są z zaufaniem, wymieniają i przechowują określone **klucze** w swoich **Domain Controllerach (DC)**, które są istotne dla integralności zaufania.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **trusted domain**, musi najpierw poprosić o specjalny bilet zwany **inter-realm TGT** z DC swojej domeny. Ten TGT jest szyfrowany przy użyciu wspólnego **trust key**, który obie domeny uzgodniły. Użytkownik następnie prezentuje ten inter-realm TGT Domain Controllerowi **trusted domain**, aby uzyskać bilet serwisowy (**TGS**). Po pomyślnej walidacji inter-realm TGT przez DC trusted domain, wydaje on TGS, przyznając użytkownikowi dostęp do usługi.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

Warto zauważyć, że **trust** może być dwukierunkowy lub jednokierunkowy. W opcji dwukierunkowej obie domeny ufają sobie nawzajem, ale w relacji **one way** jedna z domen będzie **trusted**, a druga **trusting**. W tym drugim przypadku **będziesz mógł uzyskiwać dostęp tylko do zasobów w trusting domain z trusted domain**.

Jeżeli Domain A ufa Domain B, A jest domeną trusting, a B jest domeną trusted. Co więcej, w **Domain A** będzie to **Outbound trust**; a w **Domain B** będzie to **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: To powszechna konfiguracja w ramach tego samego forest, gdzie domena child automatycznie ma dwukierunkowe, transitive trust z domeną parent. Oznacza to, że żądania uwierzytelniania mogą płynąć swobodnie między parent i child.
- **Cross-link Trusts**: Nazywane również "shortcut trusts", są ustanawiane między domenami child, aby przyspieszyć procesy referral. W złożonych lasach, odwołania uwierzytelniania zazwyczaj muszą iść do root forest, a potem w dół do docelowej domeny. Tworząc cross-links, skraca się tę drogę, co jest szczególnie korzystne w środowiskach rozproszonych geograficznie.
- **External Trusts**: Konfigurowane są między różnymi, niespowinowaconymi domenami i są z definicji non-transitive. Według [dokumentacji Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts są przydatne do dostępu do zasobów w domenie poza bieżącym forest, która nie jest połączona przez forest trust. Bezpieczeństwo jest wzmacniane przez SID filtering w przypadku external trusts.
- **Tree-root Trusts**: Te trusty są automatycznie ustanawiane między root domain forest a nowo dodanym tree root. Choć nie są często spotykane, tree-root trusts są ważne przy dodawaniu nowych drzew domen do lasu, umożliwiając im zachowanie unikalnej nazwy domeny i zapewniając dwukierunkową transitivity. Więcej informacji znajduje się w [poradniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trustu jest dwukierunkowym, transitive trust między dwoma forest root domains, także wymuszając SID filtering, aby zwiększyć środki bezpieczeństwa.
- **MIT Trusts**: Trusty ustanawiane są z nie-Windowsowymi, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domenami. MIT trusts są bardziej wyspecjalizowane i służą środowiskom wymagającym integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Other differences in **trusting relationships**

- Relacja trust może być również **transitive** (A trusts B, B trusts C, wtedy A trusts C) lub **non-transitive**.
- Relacja trust może być ustawiona jako **bidirectional trust** (obie ufają sobie) lub jako **one-way trust** (tylko jedna ufa drugiej).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers could access resources in another domain through three primary mechanisms:

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
Inne sposoby enumerowania zaufanych domen:
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

Zdobądź uprawnienia Enterprise Admin w domenie child/parent, nadużywając zaufania przez SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Wykorzystanie zapisywalnego Configuration NC

Zrozumienie, jak można wykorzystać Configuration Naming Context (NC), jest kluczowe. Configuration NC pełni rolę centralnego repozytorium danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, a zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **uprawnienia SYSTEM na DC**, najlepiej na child DC.

Link GPO do root DC site

Kontener Sites w Configuration NC zawiera informacje o wszystkich site'ach komputerów dołączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą powiązać GPO z root DC site. Ta operacja może potencjalnie skompromitować domenę root poprzez manipulację politykami stosowanymi na tych site'ach.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

Compromise any gMSA in the forest

Atak może celować w uprzywilejowane gMSA w domenie. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, można uzyskać dostęp do KDS Root key i obliczyć hasła dla dowolnego gMSA w całym lesie.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

Schema change attack

Ta metoda wymaga cierpliwości i oczekiwania na tworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować AD Schema, aby nadać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. To może prowadzić do nieautoryzowanego dostępu i kontroli nad nowo tworzonymi obiektami AD.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

From DA to EA with ADCS ESC5

Luka ADCS ESC5 umożliwia uzyskanie kontroli nad obiektami Public Key Infrastructure (PKI) w celu stworzenia szablonu certyfikatu pozwalającego na uwierzytelnienie się jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, skompromitowanie zapisywalnego child DC umożliwia przeprowadzenie ataków ESC5.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Zewnętrzna domena lasu - jednokierunkowa (Inbound) lub dwukierunkowa
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
W tym scenariuszu **twoja domena jest zaufana** przez domenę zewnętrzną, co daje ci **nieokreślone uprawnienia** względem niej. Będziesz musiał ustalić, **które konta (principals) twojej domeny mają jaki dostęp do domeny zewnętrznej**, a następnie spróbować to wykorzystać:


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
W tym scenariuszu **twoja domena** **ufa** pewnym **uprawnieniom** podmiotu z **innej domeny**.

Jednak gdy **domena jest zaufana** przez domenę ufającą, domena zaufana **tworzy użytkownika** o **przewidywalnej nazwie**, który jako **hasło używa zaufanego hasła**. Oznacza to, że możliwe jest **uzyskanie dostępu do użytkownika z domeny ufającej, aby dostać się do domeny zaufanej**, przeprowadzić jej enumerację i próbować eskalować dalsze uprawnienia:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem kompromitacji domeny zaufanej jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** względem zaufania domeny (co nie jest zbyt częste).

Kolejną metodą jest oczekiwanie na maszynie, do której **użytkownik z domeny zaufanej może się zalogować** przez **RDP**. Wtedy atakujący może wstrzyknąć kod w proces sesji RDP i **dostępować do domeny źródłowej ofiary** stamtąd.\
Co więcej, jeśli **ofiara podmontowała swój dysk twardy**, to z procesu sesji **RDP** atakujący może umieścić **backdoory** w **folderze autostartu dysku twardego**. Ta technika nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigacja nadużyć zaufania domeny

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w zaufaniach między lasami jest łagodzone przez SID Filtering, które jest aktywowane domyślnie we wszystkich zaufaniach międzylasowych. Opiera się to na założeniu, że zaufania wewnątrz lasu są bezpieczne, traktując las, a nie domenę, jako granicę bezpieczeństwa zgodnie ze stanowiskiem Microsoft.
- Jest jednak haczyk: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co powoduje jego okazjonalne wyłączenie.

### **Selective Authentication:**

- Dla zaufania międzylasowego zastosowanie Selective Authentication zapewnia, że użytkownicy z dwóch lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskiwać dostęp do domen i serwerów w domenie/lesie ufającym.
- Należy zauważyć, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto zaufania.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Zaleca się, aby Domain Admins mogli logować się tylko do Domain Controllers, unikając ich używania na innych hostach.
- **Service Account Privileges**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA), aby utrzymać bezpieczeństwo.
- **Temporal Privilege Limitation**: Dla zadań wymagających uprawnień DA należy ograniczać ich czas trwania. Można to osiągnąć przez: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Wdrażanie technik Deception**

- Wdrażanie deception polega na ustawianiu pułapek, takich jak użytkownicy lub komputery wabiki, z cechami takimi jak hasła, które nigdy nie wygasają, lub oznaczone jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi prawami lub dodawanie ich do grup o wysokich uprawnieniach.
- Praktyczny przykład obejmuje użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej o wdrażaniu technik deception można znaleźć na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identyfikacja Deception**

- **Dla obiektów użytkownika**: Podejrzane wskaźniki obejmują nietypowe ObjectSID, rzadkie logowania, daty utworzenia oraz niskie zliczenia błędnych haseł.
- **Wskaźniki ogólne**: Porównywanie atrybutów potencjalnych obiektów-wabików z rzeczywistymi może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikacji takich deceptions.

### **Omijanie systemów detekcji**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers, aby zapobiec wykryciu przez ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga unikać wykrycia przez niezobowiązywanie do NTLM.
- **DCSync Attacks**: Wykonywanie z nie-Domain Controller, aby uniknąć wykrycia przez ATA; bezpośrednie uruchomienie z Domain Controller spowoduje alerty.

## Źródła

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
