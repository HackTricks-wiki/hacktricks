# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** pełni rolę technologii bazowej, umożliwiając **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** i **obiektami** w sieci. Został zaprojektowany z myślą o skalowalności, ułatwiając organizację dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, przy jednoczesnej kontroli **praw dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, korzystających ze wspólnej bazy danych. **Drzewa** to grupy tych domen powiązane wspólną strukturą, a **las** reprezentuje zbiór wielu drzew, połączonych poprzez **relacje zaufania**, tworząc najwyższą warstwę struktury organizacyjnej. Konkretne **prawa dostępu** i **komunikacji** można określić na każdym z tych poziomów.

Kluczowe pojęcia w ramach **Active Directory** to:

1. **Katalog** – Przechowuje wszystkie informacje dotyczące obiektów Active Directory.
2. **Obiekt** – Oznacza byty w katalogu, w tym **użytkowników**, **grupy** lub **udostępnione foldery**.
3. **Domena** – Służy jako kontener dla obiektów katalogu; w ramach **lasu** może istnieć wiele domen, z każdą utrzymującą własny zbiór obiektów.
4. **Drzewo** – Grupa domen, które dzielą wspólną domenę główną.
5. **Las** – Najwyższa warstwa struktury organizacyjnej w Active Directory, składająca się z kilku drzew połączonych **relacjami zaufania**.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym funkcjami **uwierzytelniania** i wyszukiwania.
2. **Certificate Services** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – Wspiera aplikacje wykorzystujące katalogi przez protokół **LDAP**.
4. **Directory Federation Services** – Zapewnia funkcje **single-sign-on** umożliwiające uwierzytelnianie użytkowników w wielu aplikacjach webowych w jednej sesji.
5. **Rights Management** – Pomaga w ochronie materiałów objętych prawem autorskim przez regulowanie ich nieautoryzowanej dystrybucji i użycia.
6. **DNS Service** – Kluczowe dla rozwiązywania **nazw domen**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Aby dowiedzieć się, jak **atakować AD**, musisz bardzo dobrze **zrozumieć** proces uwierzytelniania **Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Skrócony przewodnik

Możesz zajrzeć na [https://wadcoms.github.io/](https://wadcoms.github.io) aby szybko zobaczyć, które polecenia możesz uruchomić, by enumerować/eksploatować AD.

> [!WARNING]
> Komunikacja Kerberos **wymaga pełnej nazwy kwalifikowanej (FQDN)** do wykonywania działań. Jeśli spróbujesz uzyskać dostęp do maszyny przez adres IP, **zostanie używany NTLM, a nie Kerberos**.

## Recon Active Directory (No creds/sessions)

If you just have access to an AD environment but you don't have any credentials/sessions you could:

- **Pentest the network:**
- Skanuj sieć, znajdź maszyny i otwarte porty i spróbuj **wykorzystać luki** lub **wyciągnąć poświadczenia** z nich (for example, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak serwery WWW, drukarki, udziały, VPN, multimedia itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Sprawdź ogólną [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby znaleźć więcej informacji o tym, jak to robić.
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
- Zbieraj poświadczenia [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta przez [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbieraj poświadczenia, **wystawiając** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wydobądź nazwy użytkowników/imię i nazwisko z wewnętrznych dokumentów, mediów społecznościowych, serwisów (głównie webowych) wewnątrz środowisk domenowych oraz z zasobów publicznie dostępnych.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz spróbować różnych konwencji nazewnictwa użytkowników AD (**username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/))). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonymous SMB/LDAP enum:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) oraz [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Gdy zostanie zażądana **nieprawidłowa nazwa użytkownika**, serwer odpowie kodem błędu Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala stwierdzić, że nazwa użytkownika była nieprawidłowa. **Prawidłowe nazwy użytkowników** spowodują otrzymanie albo **TGT w odpowiedzi AS-REP**, albo błędu _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazując, że użytkownik musi wykonać pre-autoryzację.
- **No Authentication against MS-NRPC**: Używając auth-level = 1 (No authentication) przeciwko interfejsowi MS-NRPC (Netlogon) na kontrolerach domeny. Metoda wywołuje funkcję `DsrGetDcNameEx2` po związaniu interfejsu MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje bez jakichkolwiek poświadczeń. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje tego typu enumerację. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) serwer**

Jeśli natrafisz na taki serwer w sieci, możesz również przeprowadzić **enumerację użytkowników** wobec niego. Na przykład możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Możesz znaleźć listy nazw użytkowników w [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  oraz w tym repo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jednak powinieneś mieć **imiona osób pracujących w firmie** z etapu recon, który powinieneś wykonać wcześniej. Mając imię i nazwisko możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnych poprawnych nazw użytkowników.

### Knowing one or several usernames

OK, więc wiesz, że masz już prawidłową nazwę użytkownika, ale nie masz haseł... Spróbuj wtedy:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_ możesz **zażądać komunikatu AS_REP** dla tego użytkownika, który będzie zawierał dane zaszyfrowane pochodną hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Wypróbuj najbardziej **popularne hasła** dla każdego z odkrytych użytkowników — być może ktoś używa słabego hasła (pamiętaj o polityce haseł!).
- Zwróć uwagę, że możesz też **spray OWA servers**, aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie uzyskać niektóre challenge **hashes**, które można złamać, przeprowadzając **poisoning** wybranych protokołów **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Jeśli udało ci się zenumerować Active Directory, będziesz mieć **więcej adresów e-mail i lepsze zrozumienie sieci**. Możesz być w stanie wymusić NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) aby uzyskać dostęp do środowiska AD.

### Steal NTLM Creds

Jeśli możesz uzyskać dostęp do innych komputerów lub udziałów przy użyciu użytkownika **null** lub **guest**, możesz umieścić pliki (np. plik SCF), które po otwarciu wywołają **NTLM authentication against you**, dzięki czemu możesz **steal** **NTLM challenge** do złamania:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumeracja Active Directory Z poświadczeniami/sesją

Na tym etapie musisz mieć **skompr0miotowane poświadczenia lub sesję prawidłowego konta domenowego.** Jeśli masz jakieś ważne poświadczenia lub shell jako użytkownik domenowy, **pamiętaj, że opcje podane wcześniej nadal są sposobami na kompromitację innych użytkowników**.

Zanim rozpoczniesz uwierzytelnioną enumerację, powinieneś wiedzieć, czym jest **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeracja

Posiadanie skompromitowanego konta to **duży krok do rozpoczęcia kompromitacji całej domeny**, ponieważ będziesz mógł rozpocząć **Active Directory Enumeration:**

Jeśli chodzi o [**ASREPRoast**](asreproast.md), możesz teraz znaleźć każdego możliwego podatnego użytkownika, a jeśli chodzi o [**Password Spraying**](password-spraying.md), możesz uzyskać **listę wszystkich nazw użytkowników** i spróbować hasła skompromitowanego konta, pustych haseł oraz nowych obiecujących haseł.

- Możesz użyć [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz także użyć [**powershell for recon**](../basic-powershell-for-pentesters/index.html), co będzie bardziej stealthy
- Możesz też [**use powerview**](../basic-powershell-for-pentesters/powerview.md) do wydobycia bardziej szczegółowych informacji
- Innym świetnym narzędziem do recon w Active Directory jest [**BloodHound**](bloodhound.md). Nie jest ono **zbyt stealthy** (zależnie od metod kolekcji, których użyjesz), ale **jeśli ci na tym nie zależy**, zdecydowanie warto spróbować. Znajdź, gdzie użytkownicy mogą RDP, znajdź ścieżki do innych grup itp.
- **Inne zautomatyzowane narzędzia do enumeracji AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
- Narzędzie z GUI, którego możesz użyć do enumeracji katalogu, to **AdExplorer.exe** z pakietu **SysInternal**.
- Możesz też przeszukać bazę LDAP za pomocą **ldapsearch**, szukając poświadczeń w polach _userPassword_ & _unixUserPassword_, albo nawet w _Description_. por. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) dla innych metod.
- Jeśli używasz **Linux**, możesz także zenumerować domenę używając [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz też wypróbować zautomatyzowane narzędzia takie jak:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Wyodrębnianie wszystkich użytkowników domeny**

Bardzo łatwo jest uzyskać wszystkie nazwy użytkowników domeny z Windows (`net user /domain` ,`Get-DomainUser` lub `wmic useraccount get name,sid`). W Linux można użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli sekcja Enumeracja wygląda krótko, to jest to najważniejsza część. Odwiedź linki (głównie te dotyczące cmd, powershell, powerview i BloodHound), naucz się, jak enumerować domenę i ćwicz, aż poczujesz się pewnie. Podczas testu bezpieczeństwa będzie to kluczowy moment, by znaleźć drogę do DA lub zdecydować, że nic więcej nie da się zrobić.

### Kerberoast

Kerberoasting polega na uzyskaniu **TGS tickets** używanych przez usługi powiązane z kontami użytkowników i złamaniu ich szyfrowania — opartego na hasłach użytkowników — **offline**.

Więcej na ten temat:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Gdy zdobędziesz poświadczenia, możesz sprawdzić, czy masz dostęp do jakiejkolwiek **maszyny**. W tym celu możesz użyć **CrackMapExec**, aby próbować łączyć się z wieloma serwerami, używając różnych protokołów, zgodnie z wynikami skanów portów.

### Lokalna eskalacja uprawnień

Jeśli skompromitowałeś poświadczenia lub sesję jako zwykły użytkownik domenowy i masz z tym użytkownikiem **dostęp** do **dowolnej maszyny w domenie**, powinieneś spróbować znaleźć sposób na **escalate privileges locally and looting for credentials**. Tylko z uprawnieniami lokalnego administratora będziesz mógł **dump hashes of other users** z pamięci (LSASS) i lokalnie (SAM).

W tej książce jest pełna strona poświęcona [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklist**](../checklist-windows-privilege-escalation.md). Nie zapomnij też użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Jest bardzo **mało prawdopodobne**, że znajdziesz **tickets** w bieżącym użytkowniku, które dawałyby ci uprawnienia do dostępu do nieoczekiwanych zasobów, ale możesz sprawdzić:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Jeśli udało ci się zenumerować Active Directory, będziesz miał **więcej adresów e-mail i lepsze zrozumienie sieci**. Możesz być w stanie wymusić NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Teraz, gdy masz podstawowe poświadczenia, powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione w AD**. Możesz to zrobić ręcznie, ale to bardzo nudne, powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów do przejrzenia).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów**, możesz **umieścić pliki** (np. SCF file), które jeśli w jakiś sposób zostaną otwarte, will t**rigger an NTLM authentication against you** dzięki czemu możesz **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta luka umożliwiała każdemu uwierzytelnionemu użytkownikowi **skompromentowanie kontrolera domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Dla poniższych technik zwykły użytkownik domeny nie wystarczy — potrzebujesz specjalnych uprawnień/poświadczeń, aby przeprowadzić te ataki.**

### Hash extraction

Miejmy nadzieję, że udało ci się **skompromentować jakieś konto lokalnego administratora** używając [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (w tym relaying), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Następnie czas zrzucić wszystkie hashe z pamięci i lokalnie.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz hash użytkownika**, możesz go użyć do jego **podszycia się**.\
Musisz użyć jakiegoś **narzędzia**, które **wykona** **NTLM authentication using** that **hash**, **lub** możesz utworzyć nowy **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, tak że kiedy zostanie wykonane jakiekolwiek **NTLM authentication**, ten **hash będzie używany.** Ostatnia opcja to to, co robi mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **użyć NTLM hasha użytkownika do zażądania Kerberos tickets**, jako alternatywę dla klasycznego Pass The Hash przez protokół NTLM. Dlatego może być szczególnie **przydatny w sieciach, gdzie protokół NTLM jest wyłączony** i dopuszczony jest tylko **Kerberos** jako protokół uwierzytelniania.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną ticket uwierzytelniający użytkownika** zamiast jego hasła czy wartości hash. Ten skradziony ticket jest następnie używany do **podszycia się pod użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Jeśli masz **hash** lub **password** **local administratora**, powinieneś spróbować **zalogować się lokalnie** na innych **PCs** przy jego użyciu.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Zauważ, że jest to dość **hałaśliwe** i **LAPS** mogłoby to **złagodzić**.

### MSSQL Abuse & Trusted Links

Jeśli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może je wykorzystać do **wykonywania poleceń** na hoście MSSQL (jeśli proces działa jako SA), **wykradzenia** NetNTLM **hasha** lub nawet przeprowadzenia **relay** **attack**.\
Również, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL. Jeśli użytkownik ma uprawnienia w zaufanej bazie danych, będzie mógł **wykorzystać relację zaufania do wykonywania zapytań także w drugiej instancji**. Te zaufania mogą być łańcuchowane i w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę danych, w której może uruchamiać polecenia.\
**Linki między bazami działają nawet w ramach forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Zewnętrzne systemy inwentaryzacji i wdrażania często udostępniają potężne ścieżki do poświadczeń i wykonania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić TGTs z pamięci wszystkich użytkowników, którzy logują się na ten komputer.\
Tak więc, jeśli **Domain Admin** zaloguje się na ten komputer, będziesz w stanie zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (mam nadzieję, że będzie to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer jest dozwolony dla "Constrained Delegation", będzie mógł **podszywać się pod dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Następnie, jeśli **skomprmisujesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet Domain Admins) w celu dostępu do niektórych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** na obiekcie Active Directory zdalnego komputera umożliwia osiągnięcie wykonania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Skompromitowany użytkownik może mieć pewne **interesujące uprawnienia nad obiektami domenowymi**, które pozwolą Ci później **poruszać się lateralnie/**/**eskalować** uprawnienia.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Odkrycie **usługi Spool nasłuchującej** w domenie może zostać **nadużyte** do **pozyskania nowych poświadczeń** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Jeśli **inni użytkownicy** **dostęp** do **skomprromitowanej** maszyny, możliwe jest **zbieranie poświadczeń z pamięci** i nawet **wstrzykiwanie beaconów w ich procesy**, aby się pod nich podszyć.\
Zazwyczaj użytkownicy łączą się z systemem przez RDP, więc tutaj masz jak przeprowadzić parę ataków na sesje RDP stron trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** dostarcza system zarządzania **local Administrator password** na komputerach dołączonych do domeny, zapewniając, że jest **losowe**, unikalne i często **zmieniane**. Hasła te są przechowywane w Active Directory, a dostęp kontrolowany jest przez ACLs tylko dla autoryzowanych użytkowników. Mając wystarczające uprawnienia do odczytu tych haseł, pivotowanie do innych komputerów staje się możliwe.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Zebranie certyfikatów** ze skompromitowanej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Jeśli skonfigurowane są **podatne szablony**, możliwe jest ich nadużycie w celu eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Gdy zdobędziesz uprawnienia **Domain Admin** lub jeszcze lepiej **Enterprise Admin**, możesz **zrzucić** **bazę domeny**: _ntds.dit_.

[**Więcej informacji o ataku DCSync można znaleźć tutaj**](dcsync.md).

[**Więcej informacji o tym, jak wykradać NTDS.dit można znaleźć tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Niektóre z technik omówionych wcześniej mogą być wykorzystane do utrwalenia dostępu.\
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

Atak **Silver Ticket** tworzy **prawidłowy TGS (Ticket Granting Service) ticket** dla konkretnej usługi, używając **NTLM hasha** (na przykład **hasha konta komputera**). Metoda ta służy do **uzyskania przywilejów dostępu do usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **NTLM hasha konta krbtgt** w środowisku Active Directory. To konto jest specjalne, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są kluczowe dla uwierzytelniania w sieci AD.

Gdy atakujący pozyska ten hash, może tworzyć **TGTs** dla dowolnego konta, które wybierze (atak typu Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są to jakby golden tickets sfałszowane w sposób, który **omija zwykłe mechanizmy wykrywania golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich wystawiania** jest bardzo dobrą metodą na utrzymanie dostępu do konta użytkownika (nawet jeśli zmieni on hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Używanie certyfikatów pozwala także na utrzymanie wysokich uprawnień w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia ochronę **uprzywilejowanych grup** (jak Domain Admins i Enterprise Admins) poprzez stosowanie standardowego **Access Control List (ACL)** do tych grup, aby zapobiec nieautoryzowanym zmianom. Jednak ta funkcja może być nadużyta; jeśli atakujący zmodyfikuje ACL AdminSDHolder, nadając pełny dostęp zwykłemu użytkownikowi, użytkownik ten zyskuje rozległą kontrolę nad wszystkimi uprzywilejowanymi grupami. Środek bezpieczeństwa, mający chronić, może więc działać odwrotnie, umożliwiając nieuprawniony dostęp, jeśli nie jest ściśle monitorowany.

[**Więcej informacji o AdminDSHolder Group tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje konto **local administrator**. Uzyskując prawa administratora na takiej maszynie, hash lokalnego Administratora można wydobyć używając **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, pozwalając na zdalny dostęp do konta lokalnego Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **nadać** pewne **specjalne uprawnienia** użytkownikowi nad konkretnymi obiektami domenowymi, które pozwolą temu użytkownikowi **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** służą do **przechowywania** **uprawnień**, jakie **obiekt** ma **do** innego **obiektu**. Jeśli potrafisz wykonać nawet **małą zmianę** w **security descriptor** obiektu, możesz uzyskać bardzo interesujące uprawnienia nad tym obiektem bez konieczności bycia członkiem uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Zmień **LSASS** w pamięci, aby ustawić **uniwersalne hasło**, dające dostęp do wszystkich kont domenowych.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz stworzyć własne **SSP**, aby **przechwytywać** w **czystym tekście** **poświadczenia** używane do logowania się na maszynę.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **wypychania atrybutów** (SIDHistory, SPNs...) na wskazanych obiektach **bez** pozostawiania **logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień DA i musisz być wewnątrz **root domain**.\
Zauważ, że jeśli użyjesz błędnych danych, pojawią się dość brzydkie logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omówiliśmy, jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Jednak te hasła mogą być również użyte do **utrzymania trwałego dostępu**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft traktuje **Forest** jako granicę bezpieczeństwa. Oznacza to, że **skompromitowanie pojedynczej domeny może potencjalnie doprowadzić do skompromitowania całego Forest**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa, który umożliwia użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. Tworzy on powiązanie między systemami uwierzytelniania obu domen, pozwalając na przepływ weryfikacji uwierzytelnienia. Gdy domeny ustanawiają zaufanie, wymieniają i przechowują określone **klucze** w swoich **Domain Controllers (DCs)**, które są kluczowe dla integralności zaufania.

W typowym scenariuszu, jeśli użytkownik zamierza uzyskać dostęp do usługi w **trusted domain**, najpierw musi poprosić o specjalny ticket znany jako **inter-realm TGT** od DC swojej własnej domeny. Ten TGT jest szyfrowany za pomocą wspólnego **klucza**, na który obie domeny się zgodziły. Użytkownik następnie przedstawia ten TGT **DC zaufanej domeny**, aby otrzymać service ticket (**TGS**). Po pomyślnej weryfikacji inter-realm TGT przez DC zaufanej domeny, DC wydaje TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. Komputer **klienta** w **Domain 1** zaczyna proces używając swojego **NTLM hasha** do żądania **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wydaje nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Klient następnie żąda **inter-realm TGT** od DC1, który jest wymagany do dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest zaszyfrowany przy użyciu **trust key** współdzielonego między DC1 i DC2 jako część dwukierunkowego zaufania domen.
5. Klient zabiera inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 weryfikuje inter-realm TGT używając wspólnego trust key i, jeśli ważny, wydaje **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. Na końcu klient przedstawia ten TGS serwerowi, który jest zaszyfrowany hashem konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Different trusts

Ważne jest zauważyć, że **trust może być jednokierunkowy lub dwukierunkowy**. W opcji dwukierunkowej obie domeny ufają sobie nawzajem, ale w relacji **jednokierunkowej** jedna z domen będzie **trusted**, a druga **trusting**. W tym drugim przypadku **będziesz mógł uzyskać dostęp do zasobów tylko wewnątrz trusting domain z poziomu trusted domeny**.

Jeśli Domain A ufa Domain B, A jest domeną trusting, a B jest trusted. Co więcej, w **Domain A** będzie to **Outbound trust**; a w **Domain B**, będzie to **Inbound trust**.

**Różne relacje zaufania**

- **Parent-Child Trusts**: To powszechna konfiguracja w obrębie tego samego forest, gdzie domena child automatycznie ma dwukierunkowe, przechodnie zaufanie z domeną parent. Oznacza to, że żądania uwierzytelnienia mogą płynąć bez przeszkód między parent a child.
- **Cross-link Trusts**: Nazywane też "shortcut trusts", są ustanawiane między domenami child w celu przyspieszenia procesów referencyjnych. W złożonych forest żądania autoryzacji zwykle muszą podróżować do korzenia forest i następnie w dół do docelowej domeny. Tworząc cross-links, skraca się tę drogę, co jest szczególnie przydatne w środowiskach geograficznie rozproszonych.
- **External Trusts**: Ustanawiane między różnymi, niezależnymi domenami i są z natury non-transitive. Zgodnie z dokumentacją Microsoft, external trusts są przydatne do dostępu do zasobów w domenie spoza bieżącego forest, która nie jest połączona przez forest trust. Bezpieczeństwo jest wzmacniane przez SID filtering z external trusts.
- **Tree-root Trusts**: Te zaufania są automatycznie ustanawiane między domeną root forest a nowo dodanym tree root. Chociaż nie są powszechnie spotykane, tree-root trusts są ważne przy dodawaniu nowych drzew domen do forest, pozwalając im zachować unikalną nazwę domeny i zapewniając dwukierunkową przechodniość. Więcej informacji można znaleźć w przewodniku Microsoft.
- **Forest Trusts**: Ten typ trustu to dwukierunkowe, przechodnie zaufanie między dwoma forest root domains, również egzekwujące SID filtering w celu zwiększenia środków bezpieczeństwa.
- **MIT Trusts**: Te zaufania są ustanawiane z nie-Windowsowymi, zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120) domenami Kerberos. MIT trusts są bardziej wyspecjalizowane i służą integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Other differences in **trusting relationships**

- Relacja zaufania może być również **transitive** (A ufa B, B ufa C, więc A ufa C) lub **non-transitive**.
- Relacja zaufania może być ustawiona jako **bidirectional trust** (oba ufają sobie) lub jako **one-way trust** (tylko jedna ufa drugiej).

### Attack Path

1. **Enumerate** relacje zaufania
2. Sprawdź, czy jakiś **security principal** (user/group/computer) ma **dostęp** do zasobów **drugiej domeny**, być może przez wpisy ACE lub przez bycie w grupach drugiej domeny. Szukaj **relacji pomiędzy domenami** (zaufanie prawdopodobnie zostało utworzone w tym celu).
1. kerberoast w tym przypadku może być kolejną opcją.
3. **Skompromituj** **konta**, które mogą **pivotować** pomiędzy domenami.

Atakujący mogą mieć dostęp do zasobów w innej domenie przez trzy główne mechanizmy:

- **Local Group Membership**: Principal może być dodany do lokalnych grup na maszynach, takich jak grupa “Administrators” na serwerze, dając mu znaczny wpływ na tę maszynę.
- **Foreign Domain Group Membership**: Principale mogą być także członkami grup w domenie obcej. Jednak skuteczność tej metody zależy od natury zaufania i zakresu grupy.
- **Access Control Lists (ACLs)**: Principale mogą być wyspecyfikowani w **ACL**, szczególnie jako byty w **ACEs** w **DACL**, dając im dostęp do konkretnych zasobów. Dla tych, którzy chcą zagłębić się w mechanikę ACLs, DACLs i ACEs, whitepaper zatytułowany “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” jest nieocenionym źródłem.

### Find external users/groups with permissions

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/forest**.

Możesz to sprawdzić w **Bloodhound** lub używając powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Eskalacja uprawnień Child-to-Parent w forest
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
> Istnieją **2 trusted keys**, jeden dla _Child --> Parent_ i drugi dla _Parent_ --> _Child_.\
> Możesz sprawdzić, która jest używana przez bieżącą domenę za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Uzyskaj uprawnienia Enterprise admin w domenie child/parent, nadużywając zaufania przez SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, w jaki sposób Configuration Naming Context (NC) może być wykorzystany, jest kluczowe. Configuration NC pełni rolę centralnego repozytorium danych konfiguracyjnych w całym forest w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w obrębie forest, a writable DCs utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **SYSTEM privileges on a DC**, najlepiej na child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o site'ach wszystkich komputerów dołączonych do domeny w obrębie AD forest. Mając SYSTEM privileges on any DC, atakujący mogą powiązać GPOs z root DC sites. Ta operacja może potencjalnie skompromitować root domain przez manipulację politykami stosowanymi do tych site'ów.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jako wektor ataku można wymierzyć działania przeciw privileged gMSAs w domenie. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając SYSTEM privileges on any DC, możliwe jest uzyskanie dostępu do KDS Root key i obliczenie haseł dowolnego gMSA w całym forest.

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

Ta metoda wymaga cierpliwości i oczekiwania na pojawienie się nowych uprzywilejowanych obiektów AD. Mając SYSTEM privileges, atakujący może zmodyfikować AD Schema, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i przejęcia kontroli nad nowo tworzonymi obiektami AD.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Luka ADCS ESC5 umożliwia przejęcie kontroli nad obiektami Public Key Infrastructure (PKI) w celu utworzenia szablonu certyfikatu, który pozwala uwierzytelniać się jako dowolny użytkownik w obrębie forest. Ponieważ obiekty PKI znajdują się w Configuration NC, skompromitowanie writable child DC umożliwia przeprowadzenie ataków ESC5.

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
W tym scenariuszu **twoja domena jest zaufana** przez domenę zewnętrzną, co daje ci **nieokreślone uprawnienia** względem niej. Będziesz musiał znaleźć **które principals twojej domeny mają jakie access wobec domeny zewnętrznej**, a następnie spróbować je wykorzystać:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Zewnętrzna domena leśna — jednokierunkowa (Outbound)
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
W tym scenariuszu **twoja domena** **przyznaje zaufanie** pewnym **uprawnieniom** principal z **innych domen**.

Jednak gdy **domena jest zaufana** przez domenę ufającą, domena zaufana **tworzy użytkownika** o **przewidywalnej nazwie**, który jako **hasło używa hasła zaufania**. Oznacza to, że możliwe jest **uzyskanie dostępu do użytkownika z domeny ufającej, aby dostać się do domeny zaufanej**, by ją zenumerować i spróbować eskalować dalsze uprawnienia:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem na skompromitowanie domeny zaufanej jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** trustu domeny (co nie jest zbyt częste).

Innym sposobem na skompromitowanie domeny zaufanej jest oczekiwanie na maszynie, do której **użytkownik z domeny zaufanej może się zalogować** przez **RDP**. Następnie atakujący mógłby wstrzyknąć kod w proces sesji RDP i **dostępować stamtąd do domeny źródłowej ofiary**.\ Moreover, jeśli **ofiara zamontowała swój dysk twardy**, z procesu **sesji RDP** atakujący mógłby umieścić **backdoors** w **folderze autostartu dysku twardego**. Ta technika nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Zapobieganie nadużyciom związanym z zaufaniem domen

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w obrębie forest trusts jest ograniczane przez SID Filtering, który jest domyślnie aktywowany na wszystkich inter-forest trusts. Działanie to opiera się na założeniu, że intra-forest trusts są bezpieczne, traktując forest, a nie domain, jako granicę bezpieczeństwa zgodnie ze stanowiskiem Microsoftu.
- Jest jednak haczyk: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego czasowego wyłączenia.

### **Selective Authentication:**

- W przypadku inter-forest trusts zastosowanie Selective Authentication zapewnia, że użytkownicy z obu forestów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w domenie lub forest ufającym.
- Ważne jest, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani atakami na konto zaufania.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Ogólne środki obronne

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Środki obronne w zakresie ochrony poświadczeń**

- **Domain Admins Restrictions**: Zaleca się, aby Domain Admins mogli logować się wyłącznie do Domain Controllers, unikając ich używania na innych hostach.
- **Service Account Privileges**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA) dla zachowania bezpieczeństwa.
- **Temporal Privilege Limitation**: W zadaniach wymagających uprawnień DA czas ich trwania powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Wdrażanie technik Deception**

- Wdrażanie deception polega na ustawianiu pułapek, takich jak konta-przynęty użytkowników lub komputerów, z cechami takimi jak hasła, które nie wygasają, lub oznaczone jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi uprawnieniami lub dodawanie ich do grup o wysokich uprawnieniach.
- Praktyczny przykład obejmuje użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej o wdrażaniu technik deception można znaleźć na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Wykrywanie Deception**

- **For User Objects**: Podejrzane wskaźniki obejmują nietypowy ObjectSID, rzadkie logowania, daty tworzenia oraz niski licznik nieudanych prób hasła.
- **General Indicators**: Porównywanie atrybutów potencjalnych obiektów-przynęt z rzeczywistymi może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikacji takich deception.

### **Omijanie systemów wykrywania**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers, aby zapobiec wykryciu przez ATA.
- **Ticket Impersonation**: Wykorzystanie kluczy **aes** przy tworzeniu ticketów pomaga unikać wykrycia przez niezmuszanie downgrade'u do NTLM.
- **DCSync Attacks**: Zaleca się wykonywanie z maszyny niebędącej Domain Controllerem, by uniknąć wykrycia przez ATA, ponieważ bezpośrednie wykonanie na Domain Controllerze wywoła alerty.

## Referencje

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
