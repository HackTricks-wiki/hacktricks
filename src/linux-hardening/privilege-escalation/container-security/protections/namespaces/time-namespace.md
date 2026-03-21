# टाइम नेमस्पेस

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

टाइम नेमस्पेस कुछ चयनित घड़ियों को वर्चुअलाइज़ करता है, खासकर **`CLOCK_MONOTONIC`** और **`CLOCK_BOOTTIME`**। यह mount, PID, network, या user namespaces की तुलना में नया और अधिक विशेषीकृत namespace है, और कंटेनरों की सुरक्षा (container hardening) पर चर्चा करते समय यह आमतौर पर ऑपरेटर के मन में पहली चीज़ नहीं होता। फिर भी, यह आधुनिक namespace परिवार का हिस्सा है और अवधारणात्मक रूप से समझने योग्य है।

मुख्य उद्देश्य यह है कि कोई process कुछ क्लॉकों के लिए नियंत्रित ऑफ़सेट देख सके बिना host के वैश्विक समय दृश्य को बदले। यह checkpoint/restore workflows, deterministic testing, और कुछ उन्नत runtime व्यवहार के लिए उपयोगी है। यह आमतौर पर mount या user namespaces की तरह प्रमुख आइसोलेशन नियंत्रण नहीं होता, लेकिन फिर भी यह process के वातावरण को अधिक स्व-निहित बनाने में योगदान देता है।

## लैब

यदि होस्ट kernel और userspace इसका समर्थन करते हैं, तो आप namespace का निरीक्षण इस तरह कर सकते हैं:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
सपोर्ट kernel और tool के संस्करणों के अनुसार भिन्न होता है, इसलिए यह पृष्ठ हर lab वातावरण में इसे दिखाई देने की उम्मीद करने के बजाय इस तंत्र को समझने पर अधिक केंद्रित है।

### समय ऑफ़सेट्स

Linux time namespaces `CLOCK_MONOTONIC` और `CLOCK_BOOTTIME` के लिए offsets को वर्चुअलाइज़ करते हैं। वर्तमान per-namespace offsets `/proc/<pid>/timens_offsets` के माध्यम से एक्सपोज़ होते हैं, जिन्हें समर्थित kernels पर उस संबंधित namespace के अंदर `CAP_SYS_TIME` रखने वाली process द्वारा भी संशोधित किया जा सकता है:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
फ़ाइल में नैनोसेकंड डेल्टा होते हैं। `monotonic` को दो दिनों से समायोजित करने से उस namespace के अंदर uptime-जैसे अवलोकन बदल जाते हैं, बिना होस्ट wall clock को बदले।

### `unshare` सहायक फ़्लैग्स

हाल के `util-linux` संस्करण ऐसे सहायक फ़्लैग्स प्रदान करते हैं जो offsets को स्वचालित रूप से लिखते हैं:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
ये flags मुख्य रूप से उपयोगिता में सुधार हैं, लेकिन वे दस्तावेज़ीकरण और परीक्षण में फीचर की पहचान करना भी आसान बनाते हैं।

## रनटाइम उपयोग

Time namespaces नए हैं और mount या PID namespaces की तुलना में कम व्यापक रूप से उपयोग होते हैं। OCI Runtime Specification v1.1 ने `time` namespace और `linux.timeOffsets` फ़ील्ड के लिए स्पष्ट समर्थन जोड़ा, और नए `runc` रिलीज़ उस मॉडल के उस हिस्से को लागू करते हैं। एक न्यूनतम OCI fragment इस तरह दिखता है:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
यह इसलिए महत्वपूर्ण है क्योंकि यह time namespacing को एक विशिष्ट कर्नेल मूलभूत से बदलकर ऐसी चीज़ बना देता है जिसे runtimes पोर्टेबल तरीके से अनुरोध कर सकते हैं।

## सुरक्षा प्रभाव

अन्य namespace प्रकारों की तुलना में time namespace के इर्द-गिर्द क्लासिक breakout कहानियाँ कम हैं। यहाँ जोखिम आमतौर पर यह नहीं है कि time namespace सीधे escape सक्षम करता है, बल्कि यह है कि लोग इसे पूरी तरह अनदेखा कर देते हैं और इसलिए यह नहीं समझ पाते कि advanced runtimes प्रक्रिया के व्यवहार को कैसे आकार दे रहे हैं। विशिष्ट परिवेशों में, घड़ी के बदले हुए दृश्य checkpoint/restore, observability, या forensic धारणाओं को प्रभावित कर सकते हैं।

## दुरुपयोग

यहाँ आमतौर पर कोई प्रत्यक्ष breakout primitive नहीं होता, लेकिन बदला हुआ घड़ी व्यवहार execution environment को समझने और advanced runtime features की पहचान करने में फिर भी उपयोगी हो सकता है:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
यदि आप दो प्रक्रियाओं की तुलना कर रहे हैं, तो यहाँ के अंतर अजीब timing व्यवहार, checkpoint/restore artifacts, या environment-विशिष्ट logging mismatches को समझाने में मदद कर सकते हैं।

प्रभाव:

- लगभग हमेशा reconnaissance या परिवेश की समझ
- logging, uptime, या checkpoint/restore विसंगतियों को समझाने में उपयोगी
- आम तौर पर यह स्वयं एक सीधा container-escape मैकेनिज़्म नहीं होता

महत्वपूर्ण दुरुपयोग सूक्ष्मता यह है कि time namespaces `CLOCK_REALTIME` को virtualize नहीं करते, इसलिए वे अपने आप में एक attacker को host wall clock को ग़लत साबित करने या system-wide certificate-expiry checks को सीधे तोड़ने की अनुमति नहीं देते। इनका मूल्य अधिकतर monotonic-time-based logic को भ्रमित करने, परिवेश-विशिष्ट बग्स को पुनरुत्पादित करने, या उन्नत runtime व्यवहार को समझने में है।

## जांच

ये जाँच मुख्यतः यह पुष्टि करने के बारे में हैं कि runtime किसी private time namespace का उपयोग कर रहा है या नहीं।
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
What is interesting here:

- कई वातावरणों में ये मान तुरंत किसी सुरक्षा निष्कर्ष पर नहीं पहुँचाते, पर ये बताते हैं कि कोई विशेषीकृत runtime सुविधा सक्रिय है या नहीं।
- यदि आप दो प्रक्रियाओं की तुलना कर रहे हैं, तो यहाँ के अंतर भ्रमित करने वाले timing या checkpoint/restore व्यवहार की व्याख्या कर सकते हैं।

For most container breakouts, the time namespace is not the first control you will investigate. Still, a complete container-security section should mention it because it is part of the modern kernel model and occasionally matters in advanced runtime scenarios.
