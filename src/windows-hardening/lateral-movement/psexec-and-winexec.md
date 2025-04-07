# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Jinsi zinavyofanya kazi

Mchakato umeelezwa katika hatua zilizo hapa chini, ukionyesha jinsi binaries za huduma zinavyoshughulikiwa ili kufikia utekelezaji wa mbali kwenye mashine lengwa kupitia SMB:

1. **Kukopi binary ya huduma kwenye ADMIN$ share kupitia SMB** inafanywa.
2. **Kuunda huduma kwenye mashine ya mbali** kunafanywa kwa kuelekeza kwenye binary.
3. Huduma inaanza **kwa mbali**.
4. Baada ya kutoka, huduma inasimamishwa, na binary inafutwa.

### **Mchakato wa Kutekeleza PsExec kwa Mikono**

Kukisia kuna payload inayoweza kutekelezwa (iliyoundwa na msfvenom na kufichwa kwa kutumia Veil ili kuepuka kugunduliwa na antivirus), inayoitwa 'met8888.exe', ikiwakilisha payload ya meterpreter reverse_http, hatua zifuatazo zinachukuliwa:

- **Kukopi binary**: Executable inakopiwa kwenye ADMIN$ share kutoka kwa amri ya prompt, ingawa inaweza kuwekwa mahali popote kwenye mfumo wa faili ili kubaki kufichwa.
- Badala ya kukopi binary, pia inawezekana kutumia binary ya LOLBAS kama `powershell.exe` au `cmd.exe` kutekeleza amri moja kwa moja kutoka kwa hoja. Mfano: `sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"`
- **Kuunda huduma**: Kutumia amri ya Windows `sc`, ambayo inaruhusu kuuliza, kuunda, na kufuta huduma za Windows kwa mbali, huduma inayoitwa "meterpreter" inaundwa kuelekea kwenye binary iliyopakiwa.
- **Kuanza huduma**: Hatua ya mwisho inahusisha kuanzisha huduma, ambayo kwa uwezekano itasababisha kosa la "time-out" kwa sababu binary sio binary halisi ya huduma na inashindwa kurudisha msimbo wa majibu unaotarajiwa. Kosa hili halina umuhimu kwani lengo kuu ni utekelezaji wa binary.

Uangalizi wa msikilizaji wa Metasploit utaonyesha kuwa kikao kimeanzishwa kwa mafanikio.

[Learn more about the `sc` command](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Pata hatua za kina zaidi katika: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

- Unaweza pia kutumia **Windows Sysinternals binary PsExec.exe**:

![](<../../images/image (928).png>)

Au upate kupitia webddav:
```bash
\\live.sysinternals.com\tools\PsExec64.exe -accepteula
```
- Unaweza pia kutumia [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- Unaweza pia kutumia [**SharpMove**](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Unaweza pia kutumia **Impacket's `psexec` na `smbexec.py`**.


{{#include ../../banners/hacktricks-training.md}}
