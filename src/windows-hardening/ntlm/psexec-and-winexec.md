# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) om maklik te bou en **werkvloei** te **automate** wat deur die wêreld se **mees gevorderde** gemeenskapstools aangedryf word.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Hoe werk hulle

Die proses word in die onderstaande stappe uiteengesit, wat illustreer hoe diensbinaries gemanipuleer word om afstandsuitvoering op 'n teikenmasjien via SMB te bereik:

1. **Kopieer van 'n diensbinary na die ADMIN$ deel oor SMB** word uitgevoer.
2. **Skep van 'n diens op die afstandsmasjien** word gedoen deur na die binary te verwys.
3. Die diens word **afstandsbegin**.
4. By uitgang, word die diens **gestop, en die binary word verwyder**.

### **Proses van Handmatige Uitvoering van PsExec**

Aneem daar is 'n uitvoerbare payload (gecreëer met msfvenom en obfuskeer met Veil om antivirusdetectie te ontwyk), genaamd 'met8888.exe', wat 'n meterpreter reverse_http payload verteenwoordig, word die volgende stappe geneem:

- **Kopieer die binary**: Die uitvoerbare word na die ADMIN$ deel gekopieer vanaf 'n opdragprompt, alhoewel dit enige plek op die lêerstelsel geplaas kan word om verborge te bly.

- **Skep 'n diens**: Deur die Windows `sc` opdrag te gebruik, wat toelaat om Windows dienste op afstand te vra, te skep en te verwyder, word 'n diens genaamd "meterpreter" geskep om na die opgelaaide binary te verwys.

- **Begin die diens**: Die finale stap behels die begin van die diens, wat waarskynlik 'n "time-out" fout sal veroorsaak weens die binary nie 'n werklike diensbinary is nie en nie die verwagte responskode kan teruggee nie. Hierdie fout is onbelangrik aangesien die primêre doel die uitvoering van die binary is.

Waarneming van die Metasploit luisteraar sal onthul dat die sessie suksesvol geinitieer is.

[Leer meer oor die `sc` opdrag](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Vind meer gedetailleerde stappe in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Jy kan ook die Windows Sysinternals binary PsExec.exe gebruik:**

![](<../../images/image (165).png>)

Jy kan ook [**SharpLateral**](https://github.com/mertdas/SharpLateral) gebruik:
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) om maklik te bou en **outomatiese werksvloei** te skep wat aangedryf word deur die wêreld se **meest gevorderde** gemeenskapstools.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{{#include ../../banners/hacktricks-training.md}}
