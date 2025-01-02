# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) kujenga na **kujiendesha kiotomatiki** kazi zinazotumiwa na zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Jinsi zinavyofanya kazi

Mchakato umeelezwa katika hatua zilizo hapa chini, ukionyesha jinsi binaries za huduma zinavyoshughulikiwa ili kufikia utekelezaji wa mbali kwenye mashine lengwa kupitia SMB:

1. **Kukopi binary ya huduma kwenye ADMIN$ share kupitia SMB** inafanywa.
2. **Kuunda huduma kwenye mashine ya mbali** kunafanywa kwa kuelekeza kwenye binary.
3. Huduma inaanzishwa **kwa mbali**.
4. Baada ya kutoka, huduma inasimamishwa, na binary inafutwa.

### **Mchakato wa Kutekeleza PsExec kwa Mikono**

Kukisia kuna payload inayoweza kutekelezwa (iliyoundwa na msfvenom na kufichwa kwa kutumia Veil ili kuepuka kugunduliwa na antivirus), inayoitwa 'met8888.exe', ikiwakilisha payload ya meterpreter reverse_http, hatua zifuatazo zinachukuliwa:

- **Kukopi binary**: Executable inakopiwa kwenye ADMIN$ share kutoka kwa amri ya prompt, ingawa inaweza kuwekwa mahali popote kwenye mfumo wa faili ili kubaki kufichwa.

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
<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) kujenga na **kujiendesha** kwa urahisi kazi zinazotumiwa na zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{{#include ../../banners/hacktricks-training.md}}
