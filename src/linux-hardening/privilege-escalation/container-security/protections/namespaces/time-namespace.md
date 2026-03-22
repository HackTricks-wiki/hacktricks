# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

The time namespace virtualizes selected clocks, especially **`CLOCK_MONOTONIC`** and **`CLOCK_BOOTTIME`**। यह mount, PID, network, या user namespaces की तुलना में नया और अधिक विशिष्ट namespace है, और container hardening पर चर्चा करते समय ऑपरेटर का आमतौर पर पहला विचार नहीं होता। फिर भी, यह आधुनिक namespace परिवार का हिस्सा है और इसे सैद्धांतिक रूप से समझना उपयोगी है।

मुख्य उद्देश्य यह है कि एक process कुछ clocks के लिए नियंत्रित offsets का निरीक्षण कर सके बिना host के वैश्विक समय दृश्य को बदलें। यह checkpoint/restore workflows, deterministic testing, और कुछ उन्नत runtime व्यवहार के लिए उपयोगी है। यह आमतौर पर mount या user namespaces की तरह प्रमुख isolation नियंत्रण नहीं होता, पर यह फिर भी process के वातावरण को अधिक self-contained बनाने में योगदान देता है।

## लैब

यदि host kernel और userspace इसका समर्थन करते हैं, तो आप namespace को निम्न के साथ निरीक्षण कर सकते हैं:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Support kernel और tool versions के अनुसार भिन्न होता है, इसलिए यह पेज हर lab environment में यह दिखाई देने की उम्मीद रखने की बजाय मैकेनिज्म को समझने पर अधिक केंद्रित है।

### Time Offsets

Linux time namespaces `CLOCK_MONOTONIC` और `CLOCK_BOOTTIME` के लिए offsets को virtualize करते हैं। मौजूदा per-namespace offsets `/proc/<pid>/timens_offsets` के माध्यम से एक्सपोज़ होते हैं, जिन्हें supported kernels पर उस प्रोसेस द्वारा भी संशोधित किया जा सकता है जिसके पास संबंधित namespace के अंदर `CAP_SYS_TIME` है:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
फाइल में नैनोसेकंड डेल्टा शामिल हैं। `monotonic` को दो दिनों से समायोजित करने से उस namespace के भीतर uptime-like observations बदल जाते हैं बिना host wall clock को बदले।

### `unshare` सहायक flags

हाल के `util-linux` संस्करण ऐसे convenience flags प्रदान करते हैं जो offsets को स्वचालित रूप से लिखते हैं:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
ये flags ज्यादातर उपयोगिता में सुधार के लिए हैं, लेकिन वे documentation और testing में इस feature को पहचानना भी आसान बनाते हैं।

## रनटाइम उपयोग

Time namespaces, mount या PID namespaces की तुलना में नए हैं और कम व्यापक रूप से इस्तेमाल किए जाते हैं। OCI Runtime Specification v1.1 ने `time` namespace और `linux.timeOffsets` फ़ील्ड के लिए स्पष्ट समर्थन जोड़ा है, और नए `runc` रिलीज़ उस मॉडल के उस हिस्से को लागू करते हैं। एक न्यूनतम OCI फ़्रैगमेंट इस तरह दिखता है:
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
यह महत्वपूर्ण है क्योंकि इससे time namespacing एक विशेष kernel primitive से बदलकर ऐसी चीज़ बन जाता है जिसे runtimes पोर्टेबल रूप से अनुरोध कर सकते हैं।

## Security Impact

Other namespace types की तुलना में time namespace के इर्द-गिर्द कम क्लासिक breakout कहानियाँ हैं। यहाँ जोखिम आम तौर पर यह नहीं होता कि time namespace सीधे escape सक्षम करे, बल्कि यह होता है कि पढ़ने वाले इसे पूरी तरह नज़रअंदाज़ कर दें और इसलिए यह न समझ पायें कि advanced runtimes प्रक्रियाओं के व्यवहार को कैसे आकार दे सकते हैं। विशेष परिस्थितियों में, बदला हुआ clock view checkpoint/restore, observability, या forensic मान्यताओं को प्रभावित कर सकता है।

## Abuse

यहाँ आम तौर पर कोई प्रत्यक्ष breakout primitive मौजूद नहीं होता, लेकिन बदल हुआ clock व्यवहार execution environment को समझने और advanced runtime सुविधाओं की पहचान करने में अभी भी उपयोगी हो सकता है:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
यदि आप दो प्रक्रियाओं की तुलना कर रहे हैं, तो यहाँ के अंतर विचित्र टाइमिंग व्यवहार, checkpoint/restore artifacts, या environment-specific लॉगिंग असंगतियों को समझाने में मदद कर सकते हैं।

Impact:

- लगभग हमेशा reconnaissance या environment की समझ से संबंधित
- logging, uptime, या checkpoint/restore असमानताओं को समझाने के लिए उपयोगी
- सामान्यतः स्वयं में यह सीधे container-escape मैकेनिज़्म नहीं होता

एक महत्वपूर्ण दुरुपयोग-सूक्ष्मता यह है कि time namespaces `CLOCK_REALTIME` को virtualize नहीं करते, इसलिए वे अपने आप में किसी attacker को host wall clock को जाली साबित करने या सिस्टम-व्यापी certificate-expiry चेक्स को सीधे तोड़ने की अनुमति नहीं देते। इनका मूल्य मुख्यतः monotonic-time-based लॉजिक को भ्रमित करने, environment-specific बग्स को पुनरुत्पन्न करने, या उन्नत runtime व्यवहार को समझने में होता है।

## Checks

ये जांच मुख्यतः यह पुष्टि करने के बारे में हैं कि क्या runtime किसी private time namespace का उपयोग कर रहा है या नहीं।
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
यहां क्या दिलचस्प है:

- कई वातावरणों में ये मान तुरंत कोई security finding नहीं देंगे, लेकिन ये बताते हैं कि कोई specialized runtime feature चल रहा है या नहीं।
- यदि आप दो processes की तुलना कर रहे हैं, तो यहाँ के अंतर confusing timing या checkpoint/restore व्यवहार की व्याख्या कर सकते हैं।

अधिकांश container breakouts के लिए, time namespace वह पहला control नहीं है जिसे आप जांचेंगे। फिर भी, एक पूर्ण container-security अनुभाग में इसका उल्लेख होना चाहिए क्योंकि यह आधुनिक kernel model का हिस्सा है और कभी-कभी उन्नत runtime scenarios में मायने रखता है।
{{#include ../../../../../banners/hacktricks-training.md}}
