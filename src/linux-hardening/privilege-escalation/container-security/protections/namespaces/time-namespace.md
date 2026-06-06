# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

time namespace host wall clock के बजाय selected monotonic-style clocks को virtualize करता है। व्यवहार में इसका मतलब है **`CLOCK_MONOTONIC`** और **`CLOCK_BOOTTIME`** के लिए private offsets, साथ ही closely related **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, और **`CLOCK_BOOTTIME_ALARM`** views। यह **`CLOCK_REALTIME`** को virtualize नहीं करता, इसलिए `date` और certificate-expiry logic अभी भी host wall clock ही देखेंगे, जब तक कोई और mechanism interfere न करे।

मुख्य उद्देश्य यह है कि host के global time view को बदले बिना process को controlled elapsed-time offsets observe करने दिए जाएँ। यह checkpoint/restore workflows, deterministic testing, और advanced runtime behavior के लिए उपयोगी है। Mount या user namespaces की तरह यह आमतौर पर कोई headline isolation control नहीं होता, लेकिन फिर भी यह process environment को अधिक self-contained बनाने में मदद करता है।

Offensive point of view से, यह namespace आमतौर पर direct breakout की तुलना में **reconnaissance, timer skew, और runtime understanding** के लिए अधिक relevant होता है। फिर भी, यह मायने रखता है क्योंकि अब अधिक container runtimes और checkpoint/restore workflows इसे explicitly request कर सकते हैं।

## Lab

यदि host kernel और userspace इसे support करते हैं, तो आप namespace को इस तरह inspect कर सकते हैं:
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
Kernel और tool versions के अनुसार support अलग-अलग होता है, इसलिए यह page हर lab environment में visible होगा ही, ऐसा मानने के बजाय mechanism को समझने पर ज्यादा केंद्रित है। महत्वपूर्ण observation यह है कि `date` अभी भी host wall clock को reflect करना चाहिए, जबकि monotonic/boottime-based values वही हैं जो nonzero offsets configure होने पर बदलते हैं।

### Creation Nuance

Time namespaces, mount, PID, या network namespaces की तुलना में थोड़े unusual होते हैं:

- `unshare(CLONE_NEWTIME)` future children के लिए एक नया time namespace बनाता है।
- calling task अपने current time namespace में ही रहता है।
- इसलिए `/proc/<pid>/ns/time_for_children` runtime setup debug करते समय अक्सर `/proc/<pid>/ns/time` से ज्यादा interesting होता है।

Write window भी special है। `/proc/<pid>/timens_offsets` में offsets नए time namespace के पूरी तरह running tasks के साथ populated होने से पहले लिखे जाने चाहिए; practical रूप में runtimes यह namespace creation और final payload start करने के बीच के narrow setup window के दौरान करते हैं। एक बार वहाँ कोई task already running हो, तो बाद में writes `EACCES` के साथ fail हो जाती हैं। इसी वजह से low-level runtimes time-namespace setup को एक early bootstrap step की तरह handle करते हैं, बजाय इसके कि पहले से शुरू हो चुके container process के अंदर से offsets patch करने की कोशिश करें।

### Time Offsets

Linux time namespaces per-namespace offsets को `/proc/<pid>/timens_offsets` के जरिए expose करते हैं। इसका format clock names या IDs का एक set plus initial time namespace के relative second/nanosecond deltas होता है।

Practical रूप में, सबसे reliable user-facing workflow यह है कि `unshare` को आपके लिए ये offsets लिखने दें:
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
महत्वपूर्ण बिंदु exact command syntax नहीं, बल्कि behavior है: एक container host wall clock को बदले बिना एक अलग uptime-like view observe कर सकता है।

### `unshare` Helper Flags

Recent `util-linux` versions namespace creation के दौरान offsets automatically लिखने के लिए convenience flags provide करती हैं:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
ये flags मुख्यतः एक usability improvement हैं, लेकिन ये documentation, test harnesses, और runtime wrappers में इस feature को पहचानना भी आसान बनाते हैं।

## Runtime Usage

Time namespaces, mount या PID namespaces की तुलना में नए हैं और कम universally exercised हैं। OCI Runtime Specification v1.1 ने `time` namespace और `linux.timeOffsets` field के लिए explicit support जोड़ा, और modern runtimes इस data को kernel bootstrap flow में map कर सकते हैं। एक minimal OCI fragment इस तरह दिखता है:
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
यह मायने रखता है क्योंकि यह time namespacing को एक niche kernel primitive से ऐसी चीज़ में बदल देता है जिसे runtimes portably request कर सकते हैं। यह यह भी समझाता है कि runtime internals को एक explicit synchronization step की जरूरत क्यों होती है: container payload के नए namespace में पूरी तरह प्रवेश करने से पहले offset को `/proc/<pid>/timens_offsets` में लिखा जाना चाहिए।

Checkpoint/restore stacks जैसे CRIU इसके मौजूद होने के मुख्य real-world कारणों में से एक हैं। time namespaces के बिना, paused workload को restore करने पर monotonic और boot-time clocks, workload के suspend रहने के समय के बराबर आगे कूद जाते।

## Security Impact

time namespace पर केंद्रित classic breakout stories, दूसरे namespace types की तुलना में, कम हैं। यहाँ जोखिम आमतौर पर यह नहीं है कि time namespace सीधे escape enable करता है, बल्कि यह कि readers इसे पूरी तरह ignore कर देते हैं और इस तरह advanced runtimes process behavior को कैसे shape कर रहे हैं, यह miss कर देते हैं।

विशेष environments में, बदले हुए monotonic या boottime views इन पर असर डाल सकते हैं:

- timeout और retry behavior
- watchdogs और lease logic
- `timerfd`, `nanosleep`, और `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry और uptime-based heuristics

इसलिए जबकि यह शायद ही कभी पहला namespace होता है जिसे आप abuse करते हैं, यह assessment के दौरान "impossible" timing behavior को बिल्कुल explain कर सकता है।

## Abuse

यहाँ आमतौर पर कोई direct breakout primitive नहीं होता, लेकिन altered clock behavior फिर भी execution environment को समझने, advanced runtime features की पहचान करने, और timer-based logic को spot करने में उपयोगी हो सकता है जिसे wall clock time के बजाय monotonic clocks के against measure किया जाता है:
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
यदि आप दो processes की तुलना कर रहे हैं, तो यहाँ के differences odd timing behavior, checkpoint/restore artifacts, या environment-specific logging mismatches को समझाने में मदद कर सकते हैं।

Practical attacker-relevant angles:

- monotonic clocks के साथ implemented backoff, sleep, या watchdog logic को confuse करना
- समझना कि `/proc/uptime` और timer-driven behavior host-side wall-clock expectations से क्यों अलग हैं
- CRIU/checkpoint-restore workflows और अन्य advanced runtime features को पहचानना
- ऐसे environments को spot करना जहाँ target time namespace में `nsenter -T -t <pid> -- ...` के साथ join करने से debugging या post-exploitation के लिए container-local timer behavior reproduce किया जा सके

Impact:

- लगभग हमेशा reconnaissance या environment understanding
- logging, uptime, या checkpoint/restore anomalies को explain करने में उपयोगी
- monotonic-time-based sleeps, retries, और timers का analyze करने में उपयोगी
- सामान्यतः स्वयं में direct container-escape mechanism नहीं

महत्वपूर्ण abuse nuance यह है कि time namespaces `CLOCK_REALTIME` को virtualize नहीं करते, इसलिए वे स्वयं attacker को host wall clock falsify करने या certificate-expiry checks को system-wide सीधे तोड़ने नहीं देते। इनका value मुख्यतः monotonic-time-based logic को confuse करने, environment-specific bugs को reproduce करने, या advanced runtime behavior को समझने में है।

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
What is interesting here:

- कई environments में ये values तुरंत कोई security finding नहीं देंगे, लेकिन ये आपको बताते हैं कि क्या कोई specialized runtime feature use हो रही है।
- अगर `time_for_children` , `time` से अलग है, तो caller ने शायद एक child-only time namespace तैयार किया है जिसमें वह खुद enter नहीं हुआ है।
- अगर `date` host से match करता है लेकिन monotonic/boottime-based values नहीं करते, तो आप शायद wall-clock tampering की बजाय time namespacing देख रहे हैं।
- अगर आप दो processes compare कर रहे हैं, तो यहाँ के differences confusing timing या checkpoint/restore behavior को explain कर सकते हैं।

अधिकतर container breakouts के लिए, time namespace वह पहला control नहीं होता जिसे आप investigate करेंगे। फिर भी, एक complete container-security section में इसका ज़िक्र होना चाहिए क्योंकि यह modern kernel model का हिस्सा है और advanced runtime scenarios में कभी-कभी important होता है।

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
