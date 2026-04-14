# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ni mojawapo ya njia rahisi zaidi za **lateral movement** katika mazingira ya Windows kwa sababu hukupa remote shell kupitia **WS-Man/HTTP(S)** bila kuhitaji hila za kuunda SMB service. Ikiwa lengo linafichua **5985/5986** na principal yako inaruhusiwa kutumia remoting, mara nyingi unaweza kusonga kutoka "valid creds" hadi "interactive shell" haraka sana.

Kwa **protocol/service enumeration**, listeners, enabling WinRM, `Invoke-Command`, na matumizi ya kawaida ya client, angalia:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Kwa nini operators hupenda WinRM

- Hutumia **HTTP/HTTPS** badala ya SMB/RPC, kwa hiyo mara nyingi hufanya kazi pale ambapo execution ya mtindo wa PsExec imezuiwa.
- Kwa **Kerberos**, huepuka kutuma reusable credentials kwenda kwenye lengo.
- Hufanya kazi vizuri kutoka kwenye tooling ya **Windows**, **Linux**, na **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Njia ya interactive PowerShell remoting huanzisha **`wsmprovhost.exe`** kwenye lengo chini ya context ya mtumiaji aliye-authenticate, ambayo kiutendaji ni tofauti na service-based exec.

## Mfano wa access na prerequisites

Kiutendaji, WinRM lateral movement yenye mafanikio hutegemea **mambo matatu**:

1. Lengo lina **WinRM listener** (`5985`/`5986`) na firewall rules zinazoruhusu access.
2. Akaunti inaweza **kuthibitisha utambulisho** kwenye endpoint.
3. Akaunti inaruhusiwa **kufungua remoting session**.

Njia za kawaida za kupata access hiyo:

- **Local Administrator** kwenye lengo.
- Uanachama katika **Remote Management Users** kwenye mifumo mipya au **WinRMRemoteWMIUsers__** kwenye mifumo/components ambazo bado zinakubali group hiyo.
- Remoting rights zilizo-delegated wazi kupitia local security descriptors / PowerShell remoting ACL changes.

Ikiwa tayari unadhibiti box lenye admin rights, kumbuka unaweza pia **kutoa WinRM access bila full admin group membership** ukitumia techniques zilizoelezwa hapa:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas muhimu wakati wa lateral movement

- **Kerberos inahitaji hostname/FQDN**. Ukijiunganisha kwa IP, client kawaida hurudi kwenye **NTLM/Negotiate**.
- Katika visa vya **workgroup** au cross-trust edge cases, NTLM mara nyingi huhitaji ama **HTTPS** au target iongezwe kwenye **TrustedHosts** kwenye client.
- Kwa **local accounts** kupitia Negotiate katika workgroup, UAC remote restrictions zinaweza kuzuia access isipokuwa built-in Administrator account itumike au `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting kwa chaguo-msingi hutumia **`HTTP/<host>` SPN**. Katika mazingira ambapo `HTTP/<host>` tayari imesajiliwa kwa service account nyingine, WinRM Kerberos inaweza kushindwa kwa `0x80090322`; tumia port-qualified SPN au badilisha kwenda **`WSMAN/<host>`** pale SPN hiyo ipo.

Ukipata valid credentials wakati wa password spraying, kuzithibitisha kupitia WinRM mara nyingi ndiyo njia ya haraka zaidi kuona kama zinatafsiriwa kuwa shell:

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

`evil-winrm` bado ni chaguo linalofaa zaidi la interactive kutoka Linux kwa sababu inasaidia **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, uhamishaji wa faili, na kupakia PowerShell/.NET ndani ya memory.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Tofauti ya Kerberos SPN: `HTTP` vs `WSMAN`

Wakati default **`HTTP/<host>`** SPN inasababisha kushindwa kwa Kerberos, jaribu kuomba/kutumia ticket ya **`WSMAN/<host>`** badala yake. Hii huonekana katika setups za enterprise zilizoimarishwa au za ajabu ambapo `HTTP/<host>` tayari imeambatanishwa na account nyingine ya service.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Hii pia ni muhimu baada ya unyanyasaji wa **RBCD / S4U** unapokuwa umeforji au kuomba hasa tiketi ya huduma ya **WSMAN** badala ya tiketi ya kawaida ya `HTTP`.

### Uthibitishaji unaotegemea cheti

WinRM pia inasaidia **uthibitishaji wa cheti cha mteja**, lakini cheti lazima kiwe kimewekwa kwenye lengwa kwa **akaunti ya ndani**. Kwa mtazamo wa mashambulizi, hili lina umuhimu wakati:

- umeiba/umesafirisha cheti halali cha mteja na private key ambayo tayari imewekwa kwa WinRM;
- umetumia vibaya **AD CS / Pass-the-Certificate** kupata cheti kwa principal kisha ukahamia kwenye njia nyingine ya uthibitishaji;
- unafanya kazi katika mazingira yanayokwepa kimakusudi remoting inayotegemea password.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM ni nadra sana kuliko password/hash/Kerberos auth, lakini inapokuwepo inaweza kutoa njia ya **passwordless lateral movement** ambayo inaendelea kufanya kazi hata baada ya password rotation.

### Python / automation with `pypsrp`

Kama unahitaji automation badala ya operator shell, `pypsrp` inakupa WinRM/PSRP kutoka Python kwa msaada wa **NTLM**, **certificate auth**, **Kerberos**, na **CredSSP**.
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

`winrs.exe` imejengwa ndani na inafaa unapohitaji **utekelezaji wa amri wa asili wa WinRM** bila kufungua kikao shirikishi cha PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Kiutendaji, `winrs.exe` mara nyingi husababisha mnyororo wa mchakato wa mbali unaofanana na:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Hili linastahili kukumbukwa kwa sababu linatofautiana na service-based exec na pia na interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM badala ya PowerShell remoting

Unaweza pia kutekeleza kupitia **WinRM transport** bila `Enter-PSSession` kwa kuita WMI classes kupitia WS-Man. Hii huweka transport kama WinRM huku primitive ya utekelezaji wa mbali ikibadilika kuwa **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Hiyo mbinu ni muhimu wakati:

- PowerShell logging inafuatiliwa kwa karibu sana.
- Unataka **WinRM transport** lakini si classic PS remoting workflow.
- Unajenga au kutumia custom tooling kuzunguka object ya **`WSMan.Automation`** ya COM.

## NTLM relay to WinRM (WS-Man)

Wakati SMB relay imezuiwa na signing na LDAP relay ina vizuizi, **WS-Man/WinRM** bado inaweza kuwa target ya kuvutia kwa relay. `ntlmrelayx.py` ya kisasa inajumuisha **WinRM relay servers** na inaweza kufanya relay kwenda kwenye targets za **`wsman://`** au **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Vidokezo viwili vya vitendo:

- Relay ni muhimu zaidi wakati target inakubali **NTLM** na principal iliyorelayiwa inaruhusiwa kutumia WinRM.
- Code ya hivi karibuni ya Impacket hushughulikia mahsusi requests za **`WSMANIDENTIFY: unauthenticated`** ili probes za aina ya `Test-WSMan` zisivunje relay flow.

Kwa constraints za multi-hop baada ya kuanzisha session ya kwanza ya WinRM, angalia:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC na notes za detection

- **Interactive PowerShell remoting** kawaida huunda **`wsmprovhost.exe`** kwenye target.
- **`winrs.exe`** kawaida huunda **`winrshost.exe`** kisha process ya mtoto iliyoombwa.
- Tarajia telemetry ya **network logon**, events za WinRM service, na PowerShell operational/script-block logging ukitumia PSRP badala ya raw `cmd.exe`.
- Ukihitaji tu command moja, `winrs.exe` au one-shot WinRM execution huenda ikawa na kelele kidogo kuliko interactive remoting session ya muda mrefu.
- Kama Kerberos inapatikana, pendelea **FQDN + Kerberos** badala ya IP + NTLM ili kupunguza matatizo ya trust na mabadiliko yasiyo ya lazima ya `TrustedHosts` upande wa client.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
