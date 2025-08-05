# Time Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Linux में टाइम नेमस्पेस सिस्टम मोनोटोनिक और बूट-टाइम घड़ियों के लिए प्रति-नेमस्पेस ऑफसेट की अनुमति देता है। इसका सामान्य उपयोग Linux कंटेनरों में कंटेनर के भीतर दिनांक/समय को बदलने और चेकपॉइंट या स्नैपशॉट से पुनर्स्थापित करने के बाद घड़ियों को समायोजित करने के लिए किया जाता है।

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
एक नए `/proc` फ़ाइल सिस्टम के उदाहरण को माउंट करके, यदि आप पैरामीटर `--mount-proc` का उपयोग करते हैं, तो आप सुनिश्चित करते हैं कि नया माउंट नामस्थान उस नामस्थान के लिए विशिष्ट प्रक्रिया जानकारी का **सटीक और अलग दृष्टिकोण** रखता है।

<details>

<summary>त्रुटि: bash: fork: मेमोरी आवंटित नहीं कर सकता</summary>

जब `unshare` को `-f` विकल्प के बिना निष्पादित किया जाता है, तो एक त्रुटि उत्पन्न होती है क्योंकि Linux नए PID (प्रक्रिया आईडी) नामस्थान को संभालने के तरीके के कारण। मुख्य विवरण और समाधान नीचे दिए गए हैं:

1. **समस्या का विवरण**:

- Linux कर्नेल एक प्रक्रिया को `unshare` सिस्टम कॉल का उपयोग करके नए नामस्थान बनाने की अनुमति देता है। हालाँकि, नए PID नामस्थान (जिसे "unshare" प्रक्रिया कहा जाता है) के निर्माण की शुरुआत करने वाली प्रक्रिया नए नामस्थान में नहीं जाती; केवल इसकी बाल प्रक्रियाएँ जाती हैं।
- `%unshare -p /bin/bash%` चलाने से `/bin/bash` उसी प्रक्रिया में शुरू होता है जैसे `unshare`। परिणामस्वरूप, `/bin/bash` और इसकी बाल प्रक्रियाएँ मूल PID नामस्थान में होती हैं।
- नए नामस्थान में `/bin/bash` की पहली बाल प्रक्रिया PID 1 बन जाती है। जब यह प्रक्रिया समाप्त होती है, तो यह नामस्थान की सफाई को ट्रिगर करती है यदि कोई अन्य प्रक्रियाएँ नहीं हैं, क्योंकि PID 1 का अनाथ प्रक्रियाओं को अपनाने की विशेष भूमिका होती है। Linux कर्नेल तब उस नामस्थान में PID आवंटन को अक्षम कर देगा।

2. **परिणाम**:

- नए नामस्थान में PID 1 के समाप्त होने से `PIDNS_HASH_ADDING` ध्वज की सफाई होती है। इसका परिणाम यह होता है कि नए प्रक्रिया को बनाने के समय `alloc_pid` फ़ंक्शन नए PID आवंटित करने में विफल हो जाता है, जिससे "Cannot allocate memory" त्रुटि उत्पन्न होती है।

3. **समाधान**:
- इस समस्या को `unshare` के साथ `-f` विकल्प का उपयोग करके हल किया जा सकता है। यह विकल्प `unshare` को नए PID नामस्थान बनाने के बाद एक नई प्रक्रिया बनाने के लिए फोर्क करता है।
- `%unshare -fp /bin/bash%` निष्पादित करने से यह सुनिश्चित होता है कि `unshare` कमांड स्वयं नए नामस्थान में PID 1 बन जाता है। `/bin/bash` और इसकी बाल प्रक्रियाएँ फिर इस नए नामस्थान में सुरक्षित रूप से समाहित होती हैं, PID 1 के पूर्व समय में समाप्त होने को रोकती हैं और सामान्य PID आवंटन की अनुमति देती हैं।

यह सुनिश्चित करके कि `unshare` `-f` ध्वज के साथ चलता है, नया PID नामस्थान सही ढंग से बनाए रखा जाता है, जिससे `/bin/bash` और इसकी उप-प्रक्रियाएँ मेमोरी आवंटन त्रुटि का सामना किए बिना कार्य कर सकें।

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### जांचें कि आपका प्रोसेस किस नेमस्पेस में है
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### सभी टाइम नेमस्पेस खोजें
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### टाइम नेमस्पेस के अंदर प्रवेश करें
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
## समय ऑफ़सेट्स में हेरफेर करना

Linux 5.6 से शुरू होकर, प्रत्येक समय नामस्थान के लिए दो घड़ियाँ वर्चुअलाइज की जा सकती हैं:

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

उनके प्रति-नामस्थान डेल्टास को फ़ाइल `/proc/<PID>/timens_offsets` के माध्यम से प्रदर्शित (और संशोधित) किया जा सकता है:
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
फाइल में दो पंक्तियाँ हैं - प्रत्येक घड़ी के लिए एक - जिसमें **नैनोसेकंड** में ऑफसेट है। जो प्रक्रियाएँ **CAP_SYS_TIME** _टाइम नेमस्पेस_ में रखती हैं, वे मान को बदल सकती हैं:
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
यदि आपको दीवार की घड़ी (`CLOCK_REALTIME`) को भी बदलने की आवश्यकता है, तो आपको अभी भी पारंपरिक तंत्रों (`date`, `hwclock`, `chronyd`, …) पर निर्भर रहना होगा; यह **नामित** नहीं है।

### `unshare(1)` सहायक ध्वज (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
The long options automatically write the chosen deltas to `timens_offsets` right after the namespace is created, saving a manual `echo`.

---

## OCI & Runtime support

* The **OCI Runtime Specification v1.1** (Nov 2023) added a dedicated `time` namespace type and the `linux.timeOffsets` field so that container engines can request time virtualisation in a portable way.
* **runc >= 1.2.0** implements that part of the spec.  A minimal `config.json` fragment looks like:
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Then run the container with `runc run <id>`.

>  NOTE: runc **1.2.6** (Feb 2025) fixed an "exec into container with private timens" bug that could lead to a hang and potential DoS.  Make sure you are on ≥ 1.2.6 in production.

---

## Security considerations

1. **Required capability** – A process needs **CAP_SYS_TIME** inside its user/time namespace to change the offsets.  Dropping that capability in the container (default in Docker & Kubernetes) prevents tampering.
2. **No wall-clock changes** – Because `CLOCK_REALTIME` is shared with the host, attackers cannot spoof certificate lifetimes, JWT expiry, etc. via timens alone.
3. **Log / detection evasion** – Software that relies on `CLOCK_MONOTONIC` (e.g. rate-limiters based on uptime) can be confused if the namespace user adjusts the offset.  Prefer `CLOCK_REALTIME` for security-relevant timestamps.
4. **Kernel attack surface** – Even with `CAP_SYS_TIME` removed, the kernel code remains accessible; keep the host patched. Linux 5.6 → 5.12 received multiple timens bug-fixes (NULL-deref, signedness issues).

### Hardening checklist

* Drop `CAP_SYS_TIME` in your container runtime default profile.
* Keep runtimes updated (runc ≥ 1.2.6, crun ≥ 1.12).
* Pin util-linux ≥ 2.38 if you rely on the `--monotonic/--boottime` helpers.
* Audit in-container software that reads **uptime** or **CLOCK_MONOTONIC** for security-critical logic.

## References

* man7.org – Time namespaces manual page: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* OCI blog – "OCI v1.1: new time and RDT namespaces" (Nov 15 2023): <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}
