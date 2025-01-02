# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## Jinsi zinavyofanya kazi

Mchakato umeelezwa katika hatua zilizo hapa chini, ukionyesha jinsi binaries za huduma zinavyoshughulikiwa ili kufikia utekelezaji wa mbali kwenye mashine lengwa kupitia SMB:

1. **Nakili ya binary ya huduma kwenye ADMIN$ share kupitia SMB** inafanywa.
2. **Uundaji wa huduma kwenye mashine ya mbali** unafanywa kwa kuelekeza kwenye binary.
3. Huduma hiyo **inaanzishwa kwa mbali**.
4. Baada ya kutoka, huduma hiyo **inasitishwa, na binary inafutwa**.

### **Mchakato wa Kutekeleza PsExec kwa Mikono**

Ikiwa kuna payload inayoweza kutekelezwa (iliyoundwa na msfvenom na kufichwa kwa kutumia Veil ili kuepuka kugunduliwa na antivirus), inayoitwa 'met8888.exe', ikiwakilisha payload ya meterpreter reverse_http, hatua zifuatazo zinachukuliwa:

- **Nakili ya binary**: Executable inakopiwa kwenye ADMIN$ share kutoka kwa amri ya amri, ingawa inaweza kuwekwa mahali popote kwenye mfumo wa faili ili kubaki kufichwa.

- **Kuunda huduma**: Kwa kutumia amri ya Windows `sc`, ambayo inaruhusu kuuliza, kuunda, na kufuta huduma za Windows kwa mbali, huduma inayoitwa "meterpreter" inaundwa ili kuelekeza kwenye binary iliyopakiwa.

- **Kuanza huduma**: Hatua ya mwisho inahusisha kuanzisha huduma, ambayo itasababisha "time-out" error kwa sababu binary sio binary halisi ya huduma na inashindwa kurudisha msimbo wa majibu unaotarajiwa. Kosa hili halina umuhimu kwani lengo kuu ni utekelezaji wa binary.

Uchunguzi wa msikilizaji wa Metasploit utaonyesha kuwa kikao kimeanzishwa kwa mafanikio.

[Learn more about the `sc` command](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Pata hatua za kina zaidi katika: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Unaweza pia kutumia binary ya Windows Sysinternals PsExec.exe:**

![](<../../images/image (165).png>)

Unaweza pia kutumia [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{{#include ../../banners/hacktricks-training.md}}
