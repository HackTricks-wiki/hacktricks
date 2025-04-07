# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Hoe werk hulle

Die proses word in die onderstaande stappe uiteengesit, wat illustreer hoe diensbinaries gemanipuleer word om afstandsuitvoering op 'n teikenmasjien via SMB te bereik:

1. **Kopieer van 'n diensbinary na die ADMIN$ deel oor SMB** word uitgevoer.
2. **Skep van 'n diens op die afstandsmasjien** word gedoen deur na die binary te verwys.
3. Die diens word **afstandsbegin**.
4. By uitgang, word die diens **gestop, en die binary word verwyder**.

### **Proses van Handmatige Uitvoering van PsExec**

Aneem daar is 'n uitvoerbare payload (gecreëer met msfvenom en obfuskeer met Veil om antivirusdetectie te ontduik), genaamd 'met8888.exe', wat 'n meterpreter reverse_http payload verteenwoordig, die volgende stappe word geneem:

- **Kopieer die binary**: Die uitvoerbare word na die ADMIN$ deel gekopieer vanaf 'n opdragprompt, alhoewel dit enige plek op die lêerstelsel geplaas kan word om verborge te bly.
- In plaas van om die binary te kopieer, is dit ook moontlik om 'n LOLBAS binary soos `powershell.exe` of `cmd.exe` te gebruik om opdragte direk vanaf die argumente uit te voer. Byvoorbeeld `sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"`
- **Skep 'n diens**: Deur die Windows `sc` opdrag te gebruik, wat toelaat om Windows dienste afstands te vra, te skep en te verwyder, word 'n diens genaamd "meterpreter" geskep om na die opgelaaide binary te verwys.
- **Begin die diens**: Die finale stap behels die begin van die diens, wat waarskynlik 'n "time-out" fout sal veroorsaak weens die binary nie 'n werklike diensbinary is nie en nie die verwagte responskode kan teruggee nie. Hierdie fout is onbelangrik aangesien die primêre doel die uitvoering van die binary is.

Waarneming van die Metasploit listener sal onthul dat die sessie suksesvol geinitieer is.

[Leer meer oor die `sc` opdrag](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Vind meer gedetailleerde stappe in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

- Jy kan ook die **Windows Sysinternals binary PsExec.exe** gebruik:

![](<../../images/image (928).png>)

Of dit via webddav toegang.
```bash
\\live.sysinternals.com\tools\PsExec64.exe -accepteula
```
- Jy kan ook [**SharpLateral**](https://github.com/mertdas/SharpLateral) gebruik.
```bash
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- Jy kan ook [**SharpMove**](https://github.com/0xthirteen/SharpMove) gebruik:
```bash
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Jy kan ook **Impacket se `psexec` en `smbexec.py`** gebruik. 

{{#include ../../banners/hacktricks-training.md}}
