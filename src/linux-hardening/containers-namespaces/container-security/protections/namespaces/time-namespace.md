# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

time namespace host wall clock के बजाय चुनी गई monotonic-style clocks को virtualize करता है। व्यवहार में इसका अर्थ **`CLOCK_MONOTONIC`** और **`CLOCK_BOOTTIME`** के लिए private offsets है, साथ ही इनसे संबंधित **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, और **`CLOCK_BOOTTIME_ALARM`** views भी हैं। यह **`CLOCK_REALTIME`** को virtualize नहीं करता, इसलिए `date` और certificate-expiry logic अभी भी host wall clock को observe करते हैं, जब तक कि कोई अन्य mechanism हस्तक्षेप न करे।<sup>[[1]](#references)</sup>

इसका मुख्य उद्देश्य किसी process को host के global time view को बदले बिना नियंत्रित elapsed-time offsets observe करने देना है। यह checkpoint/restore workflows, deterministic testing और advanced runtime behavior के लिए उपयोगी है। यह आमतौर पर mount या user namespaces की तरह प्रमुख isolation control नहीं है, लेकिन फिर भी process environment को अधिक self-contained बनाने में योगदान देता है।

Offensive दृष्टिकोण से, यह namespace आमतौर पर direct breakout की तुलना में **reconnaissance, timer skew और runtime understanding** के लिए अधिक प्रासंगिक है। फिर भी, यह महत्वपूर्ण है क्योंकि अधिक container runtimes और checkpoint/restore workflows अब इसे explicitly request करने में सक्षम हैं।

## Lab

यदि host kernel और userspace इसका support करते हैं, तो आप namespace का निरीक्षण इस प्रकार कर सकते हैं:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
Support kernel और tool versions के अनुसार अलग-अलग होता है, इसलिए यह page हर lab environment में दिखाई देने की अपेक्षा रखने के बजाय mechanism को समझने पर अधिक केंद्रित है। महत्वपूर्ण observation यह है कि `date` को अभी भी host wall clock दिखाना चाहिए, जबकि monotonic/boottime-based values वे होती हैं जो nonzero offsets configure किए जाने पर बदलती हैं।

### Creation की बारीकी

Mount, PID या network namespaces की तुलना में Time namespaces थोड़े असामान्य हैं:<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` **future children** के लिए एक नया time namespace बनाता है।
- Calling task अपने वर्तमान time namespace में ही रहता है।
- इसलिए runtime setup को debug करते समय `/proc/<pid>/ns/time` की तुलना में `/proc/<pid>/ns/time_for_children` अक्सर अधिक interesting होता है।

Write window भी विशेष होती है। `/proc/<pid>/timens_offsets` में offsets को नए time namespace के running tasks से पूरी तरह populate होने से पहले लिखा जाना चाहिए; व्यवहार में runtimes यह काम namespace creation और final payload शुरू करने के बीच की संकीर्ण setup window में करते हैं। जब कोई task वहां पहले से running हो, तो बाद के writes `EACCES` के साथ fail हो जाते हैं। इसी कारण low-level runtimes time-namespace setup को early bootstrap step के रूप में handle करते हैं, बजाय इसके कि पहले से शुरू हो चुकी container process के अंदर से offsets को patch करने का प्रयास करें।<sup>[[1]](#references)</sup>

### Time Offsets

Linux time namespaces `/proc/<pid>/timens_offsets` के माध्यम से per-namespace offsets expose करते हैं। Format में initial time namespace के सापेक्ष clock names या IDs के साथ second/nanosecond deltas का एक set होता है।<sup>[[1]](#references)</sup>

व्यवहार में, सबसे reliable user-facing workflow यह है कि `unshare` को ये offsets आपके लिए write करने दें:
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
महत्वपूर्ण बिंदु सटीक command syntax नहीं, बल्कि behavior है: कोई container host wall clock को बदले बिना अलग uptime-जैसा view देख सकता है।

### `unshare` Helper Flags

हाल के `util-linux` versions convenience flags प्रदान करते हैं, जो namespace creation के दौरान offsets को स्वचालित रूप से लिखते हैं:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
ये flags मुख्य रूप से usability में सुधार करते हैं, लेकिन documentation, test harnesses और runtime wrappers में feature को पहचानना भी आसान बनाते हैं।

## Runtime Usage

Time namespaces, mount या PID namespaces की तुलना में नए हैं और इनका सार्वभौमिक रूप से कम उपयोग किया गया है। OCI Runtime Specification v1.1 ने `time` namespace और `linux.timeOffsets` field के लिए स्पष्ट support जोड़ा है, और modern runtimes इस data को kernel bootstrap flow में map कर सकते हैं। एक minimal OCI fragment इस प्रकार दिखता है:
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
यह महत्वपूर्ण है क्योंकि यह time namespacing को एक niche kernel primitive से बदलकर ऐसा बना देता है, जिसे runtimes portably request कर सकते हैं। यह यह भी स्पष्ट करता है कि runtime internals को explicit synchronization step की आवश्यकता क्यों होती है: container payload के पूरी तरह नए namespace में प्रवेश करने से पहले offset को `/proc/<pid>/timens_offsets` में लिखा जाना आवश्यक है।

CRIU जैसे checkpoint/restore stacks इसके मौजूद होने के मुख्य वास्तविक कारणों में से एक हैं। time namespaces के बिना, किसी paused workload को restore करने पर monotonic और boot-time clocks उस अवधि के बराबर आगे jump कर जाएंगी, जितने समय तक workload suspended रहा था।<sup>[[2]](#references)</sup>

## Security Impact

अन्य namespace types की तुलना में time namespace पर केंद्रित classic breakout stories कम हैं। यहां risk आमतौर पर यह नहीं है कि time namespace सीधे escape सक्षम करता है, बल्कि यह है कि readers इसे पूरी तरह ignore कर देते हैं और इसलिए यह नहीं समझ पाते कि advanced runtimes process behavior को किस तरह shape कर सकते हैं।

Specialized environments में, बदले हुए monotonic या boottime views इन चीजों को प्रभावित कर सकते हैं:

- timeout और retry behavior
- watchdogs और lease logic
- `timerfd`, `nanosleep`, और `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry और uptime-based heuristics

इसलिए, हालांकि यह आमतौर पर पहला namespace नहीं है जिसका आप abuse करेंगे, फिर भी assessment के दौरान यह "impossible" timing behavior को पूरी तरह explain कर सकता है।

## Abuse

आमतौर पर यहां कोई direct breakout primitive नहीं होता, लेकिन बदला हुआ clock behavior execution environment को समझने, advanced runtime features की पहचान करने, और ऐसी timer-based logic का पता लगाने में उपयोगी हो सकता है जिसे wall clock time के बजाय monotonic clocks के आधार पर measure किया जाता है:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
यदि आप दो processes की तुलना कर रहे हैं, तो यहां के differences अजीब timing behavior, checkpoint/restore artifacts या environment-specific logging mismatches को समझाने में मदद कर सकते हैं।

Attacker-relevant practical angles:

- monotonic clocks से implement किए गए backoff, sleep या watchdog logic को confuse करना
- यह समझना कि `/proc/uptime` और timer-driven behavior, host-side wall-clock expectations से असहमत क्यों हैं
- CRIU/checkpoint-restore workflows और अन्य advanced runtime features को पहचानना
- ऐसे environments को पहचानना जहां `nsenter -T -t <pid> -- ...` के साथ target time namespace में join करने से debugging या post-exploitation के लिए container-local timer behavior reproduce किया जा सकता है

Impact:

- लगभग हमेशा reconnaissance या environment understanding
- logging, uptime या checkpoint/restore anomalies को समझाने में उपयोगी
- monotonic-time-based sleeps, retries और timers का analysis करने में उपयोगी
- सामान्यतः अपने आप में direct container-escape mechanism नहीं

महत्वपूर्ण abuse nuance यह है कि time namespaces `CLOCK_REALTIME` को virtualize नहीं करते, इसलिए वे अपने आप attacker को host wall clock को falsify करने या system-wide certificate-expiry checks को सीधे break करने की अनुमति नहीं देते। इनका मुख्य value monotonic-time-based logic को confuse करने, environment-specific bugs को reproduce करने या advanced runtime behavior को समझने में है।

## Checks

ये checks मुख्यतः यह confirm करने के बारे में हैं कि runtime किसी private time namespace का उपयोग कर रहा है या नहीं और क्या उसने वास्तव में nonzero offsets set किए हैं।
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
यहाँ क्या रोचक है:

- कई environments में ये values तुरंत कोई security finding नहीं दिखाएँगी, लेकिन वे यह बताती हैं कि कोई specialized runtime feature सक्रिय है या नहीं।
- यदि `time_for_children`, `time` से अलग है, तो caller ने संभवतः child-only time namespace तैयार किया है, जिसमें वह स्वयं प्रवेश नहीं कर चुका है।
- यदि `date`, host से मेल खाती है, लेकिन monotonic/boottime-based values मेल नहीं खातीं, तो संभवतः आप wall-clock tampering के बजाय time namespacing देख रहे हैं।
- यदि आप दो processes की तुलना कर रहे हैं, तो यहाँ के अंतर confusing timing या checkpoint/restore behavior को समझा सकते हैं।

अधिकांश container breakouts के लिए time namespace पहला control नहीं है जिसकी आप जाँच करेंगे। फिर भी, complete container-security section में इसका उल्लेख होना चाहिए, क्योंकि यह modern kernel model का हिस्सा है और advanced runtime scenarios में कभी-कभी महत्वपूर्ण होता है।

## संदर्भ

- [1] [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
