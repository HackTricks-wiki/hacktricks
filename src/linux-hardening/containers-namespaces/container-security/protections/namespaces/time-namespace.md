# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Time namespace host wall clock के बजाय चुनिंदा monotonic-style clocks को virtualize करता है। व्यवहार में इसका अर्थ है **`CLOCK_MONOTONIC`** और **`CLOCK_BOOTTIME`** के लिए private offsets, साथ ही इनसे closely related **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, और **`CLOCK_BOOTTIME_ALARM`** views। यह **`CLOCK_REALTIME`** को virtualize नहीं करता, इसलिए `date` और certificate-expiry logic तब भी host wall clock को observe करते हैं, जब तक कोई अन्य mechanism इसमें हस्तक्षेप न करे।

इसका मुख्य उद्देश्य किसी process को host के global time view को बदले बिना controlled elapsed-time offsets observe करने देना है। यह checkpoint/restore workflows, deterministic testing, और advanced runtime behavior के लिए उपयोगी है। यह आमतौर पर mount या user namespaces की तरह isolation control का प्रमुख उदाहरण नहीं है, लेकिन फिर भी process environment को अधिक self-contained बनाने में योगदान देता है।

Offensive point of view से, यह namespace direct breakout की तुलना में **reconnaissance, timer skew, और runtime understanding** के लिए अधिक relevant है। फिर भी, यह महत्वपूर्ण है क्योंकि अधिक container runtimes और checkpoint/restore workflows अब इसे explicitly request कर सकते हैं।

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
Support kernel और tool versions के अनुसार अलग-अलग होता है, इसलिए यह page हर lab environment में इसके दिखाई देने की अपेक्षा करने के बजाय mechanism को समझने पर अधिक केंद्रित है। महत्वपूर्ण observation यह है कि `date` को अभी भी host wall clock को reflect करना चाहिए, जबकि monotonic/boottime-based values वे होती हैं जो nonzero offsets configure किए जाने पर बदलती हैं।

### Creation Nuance

Time namespaces, mount, PID या network namespaces की तुलना में थोड़े असामान्य होते हैं:

- `unshare(CLONE_NEWTIME)` **future children** के लिए एक नया time namespace बनाता है।
- Calling task अपने वर्तमान time namespace में ही रहता है।
- इसलिए runtime setup को debug करते समय `/proc/<pid>/ns/time_for_children`, `/proc/<pid>/ns/time` की तुलना में अक्सर अधिक उपयोगी होता है।

Write window भी विशेष होती है। `/proc/<pid>/timens_offsets` में offsets को नए time namespace के running tasks से पूरी तरह populate होने से पहले लिखना आवश्यक है; व्यवहार में runtimes यह काम namespace creation और final payload शुरू करने के बीच की संकीर्ण setup window में करते हैं। जब कोई task वहां पहले से running होता है, तो बाद के writes `EACCES` के साथ fail हो जाते हैं। इसी कारण low-level runtimes time-namespace setup को early bootstrap step के रूप में handle करते हैं, बजाय इसके कि पहले से शुरू किए गए container process के अंदर से offsets को patch करने का प्रयास करें।

### Time Offsets

Linux time namespaces, `/proc/<pid>/timens_offsets` के माध्यम से per-namespace offsets expose करते हैं। Format में initial time namespace के सापेक्ष clock names या IDs और second/nanosecond deltas का एक set होता है।

व्यवहार में, सबसे reliable user-facing workflow यह है कि offsets को आपके लिए लिखने के लिए `unshare` का उपयोग किया जाए:
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
महत्वपूर्ण बिंदु exact command syntax नहीं, बल्कि behavior है: कोई container host wall clock को बदले बिना uptime-जैसा अलग view देख सकता है।

### `unshare` Helper Flags

हाल के `util-linux` versions convenience flags प्रदान करते हैं, जो namespace creation के दौरान offsets को automatically लिखते हैं:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
ये flags मुख्य रूप से usability में सुधार करते हैं, लेकिन documentation, test harnesses और runtime wrappers में feature को पहचानना भी आसान बनाते हैं।

## Runtime Usage

Time namespaces, mount या PID namespaces की तुलना में नए हैं और इनका सार्वभौमिक रूप से कम उपयोग किया जाता है। OCI Runtime Specification v1.1 ने `time` namespace और `linux.timeOffsets` field के लिए स्पष्ट support जोड़ा है, और modern runtimes इस data को kernel bootstrap flow में map कर सकते हैं। एक minimal OCI fragment इस प्रकार दिखता है:
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
यह महत्वपूर्ण है क्योंकि यह time namespacing को एक niche kernel primitive से बदलकर ऐसा बना देता है जिसे runtimes portably request कर सकते हैं। यह यह भी समझाता है कि runtime internals को एक explicit synchronization step की आवश्यकता क्यों होती है: container payload के पूरी तरह नए namespace में प्रवेश करने से पहले offset को `/proc/<pid>/timens_offsets` में लिखा जाना आवश्यक है।

CRIU जैसे Checkpoint/restore stacks इसके अस्तित्व में होने के मुख्य real-world कारणों में से एक हैं। Time namespaces के बिना, paused workload को restore करने पर monotonic और boot-time clocks उस अवधि के बराबर jump कर जाते, जितने समय तक workload suspended रहा था।

## Security Impact

अन्य namespace types की तुलना में time namespace पर केंद्रित classic breakout stories कम हैं। यहां risk आमतौर पर यह नहीं है कि time namespace सीधे escape सक्षम करता है, बल्कि यह है कि readers इसे पूरी तरह ignore कर देते हैं और इसलिए यह नहीं समझ पाते कि advanced runtimes process behavior को कैसे shape कर सकते हैं।

Specialized environments में, बदले हुए monotonic या boottime views इन चीजों को प्रभावित कर सकते हैं:

- timeout और retry behavior
- watchdogs और lease logic
- `timerfd`, `nanosleep`, और `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry और uptime-based heuristics

इसलिए, हालांकि यह शायद ही कभी पहला namespace होता है जिसे आप abuse करेंगे, assessment के दौरान यह "impossible" timing behavior को बिल्कुल explain कर सकता है।

## Abuse

आमतौर पर यहां कोई direct breakout primitive नहीं होता, लेकिन बदला हुआ clock behavior execution environment को समझने, advanced runtime features की पहचान करने और ऐसे timer-based logic को detect करने में फिर भी उपयोगी हो सकता है, जिनका measurement wall clock time के बजाय monotonic clocks के आधार पर किया जाता है:
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
यदि आप दो processes की तुलना कर रहे हैं, तो यहां मौजूद अंतर असामान्य timing behavior, checkpoint/restore artifacts या environment-specific logging mismatches को समझाने में मदद कर सकते हैं।

Practical attacker-relevant angles:

- monotonic clocks से लागू किए गए backoff, sleep या watchdog logic को confuse करना
- यह समझाना कि `/proc/uptime` और timer-driven behavior, host-side wall-clock expectations से असहमत क्यों हैं
- CRIU/checkpoint-restore workflows और अन्य advanced runtime features को पहचानना
- ऐसे environments को पहचानना जहां `nsenter -T -t <pid> -- ...` के साथ target time namespace में शामिल होना, debugging या post-exploitation के लिए container-local timer behavior को reproduce कर सकता है

Impact:

- लगभग हमेशा reconnaissance या environment understanding
- logging, uptime या checkpoint/restore anomalies को समझाने के लिए उपयोगी
- monotonic-time-based sleeps, retries और timers का analysis करने के लिए उपयोगी
- सामान्यतः अपने-आप में direct container-escape mechanism नहीं

महत्वपूर्ण abuse nuance यह है कि time namespaces `CLOCK_REALTIME` को virtualize नहीं करते। इसलिए वे अपने-आप attacker को host wall clock को falsify करने या system-wide certificate-expiry checks को सीधे तोड़ने की अनुमति नहीं देते। उनका मुख्य उपयोग monotonic-time-based logic को confuse करने, environment-specific bugs को reproduce करने या advanced runtime behavior को समझने में है।

## Checks

ये checks मुख्यतः यह पुष्टि करने के बारे में हैं कि runtime private time namespace का उपयोग कर रहा है या नहीं, और क्या उसने वास्तव में nonzero offsets सेट किए हैं।
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
यहाँ क्या महत्वपूर्ण है:

- कई environments में ये values तुरंत कोई security finding नहीं दिखाएँगी, लेकिन वे यह बताती हैं कि कोई specialized runtime feature उपयोग में है या नहीं।
- यदि `time_for_children`, `time` से अलग है, तो caller ने संभवतः child-only time namespace तैयार किया है, जिसमें वह स्वयं प्रवेश नहीं कर पाया है।
- यदि `date`, host से match करती है, लेकिन monotonic/boottime-based values match नहीं करतीं, तो संभवतः आप wall-clock tampering के बजाय time namespacing देख रहे हैं।
- यदि आप दो processes की तुलना कर रहे हैं, तो यहाँ के differences confusing timing या checkpoint/restore behavior को समझा सकते हैं।

अधिकांश container breakouts के लिए, time namespace पहला control नहीं होता जिसकी आप जाँच करेंगे। फिर भी, एक complete container-security section में इसका उल्लेख होना चाहिए, क्योंकि यह modern kernel model का हिस्सा है और advanced runtime scenarios में कभी-कभी महत्वपूर्ण हो सकता है।

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
