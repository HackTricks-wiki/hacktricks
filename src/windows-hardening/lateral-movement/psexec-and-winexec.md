# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

{% embed url="https://websec.nl/" %}

## Jinsi zinavyofanya kazi

Mchakato umeelezwa katika hatua zilizo hapa chini, ukionyesha jinsi binaries za huduma zinavyoshughulikiwa ili kufikia utekelezaji wa mbali kwenye mashine lengwa kupitia SMB:

1. **Nakilisha binary ya huduma kwenye ADMIN$ share kupitia SMB** inafanywa.
2. **Kuunda huduma kwenye mashine ya mbali** kunafanywa kwa kuelekeza kwenye binary.
3. Huduma inaanzishwa **kwa mbali**.
4. Baada ya kutoka, huduma inasimamishwa, na binary inafutwa.

### **Mchakato wa Kutekeleza PsExec kwa Mikono**

Tukichukulia kuna payload inayoweza kutekelezwa (iliyoundwa na msfvenom na kufichwa kwa kutumia Veil ili kuepuka kugunduliwa na antivirus), inayoitwa 'met8888.exe', ikiwakilisha payload ya meterpreter reverse_http, hatua zifuatazo zinachukuliwa:

- **Nakilisha binary**: Executable inanakiliwa kwenye ADMIN$ share kutoka kwa amri ya prompt, ingawa inaweza kuwekwa mahali popote kwenye mfumo wa faili ili kubaki kufichwa.
- **Kuunda huduma**: Kwa kutumia amri ya Windows `sc`, ambayo inaruhusu kuuliza, kuunda, na kufuta huduma za Windows kwa mbali, huduma inayoitwa "meterpreter" inaundwa ili kuelekeza kwenye binary iliyopakiwa.
- **Kuanza huduma**: Hatua ya mwisho inahusisha kuanzisha huduma, ambayo kwa uwezekano itasababisha kosa la "time-out" kwa sababu binary sio binary halisi ya huduma na inashindwa kurudisha nambari ya majibu inayotarajiwa. Kosa hili halina umuhimu kwani lengo kuu ni utekelezaji wa binary.

Kuchunguza mlistener wa Metasploit kutadhihirisha kuwa kikao kimeanzishwa kwa mafanikio.

[Learn more about the `sc` command](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Find moe detailed steps in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Unaweza pia kutumia binary ya Windows Sysinternals PsExec.exe:**

![](<../../images/image (928).png>)

Unaweza pia kutumia [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
