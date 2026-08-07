# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

IPC namespace **System V IPC objects** और **POSIX message queues** को isolate करता है। इसमें shared memory segments, semaphores और message queues शामिल हैं, जो अन्यथा host पर मौजूद असंबंधित processes के बीच visible होते। व्यावहारिक रूप से, यह container को अन्य workloads या host से संबंधित IPC objects से casually attach होने से रोकता है।

mount, PID या user namespaces की तुलना में IPC namespace की चर्चा अक्सर कम होती है, लेकिन इसका अर्थ यह नहीं है कि यह irrelevant है। Shared memory और संबंधित IPC mechanisms में अत्यंत उपयोगी state हो सकती है। यदि host IPC namespace exposed है, तो workload को inter-process coordination objects या ऐसे data की visibility मिल सकती है, जिसे container boundary के बाहर जाने के लिए कभी intended नहीं किया गया था।

## Operation

जब runtime एक fresh IPC namespace बनाता है, तो process को IPC identifiers का अपना isolated set मिलता है। इसका अर्थ है कि `ipcs` जैसे commands केवल उस namespace में available objects दिखाते हैं। यदि container इसके बजाय host IPC namespace से join करता है, तो वे objects एक shared global view का हिस्सा बन जाते हैं।

यह विशेष रूप से उन environments में महत्वपूर्ण है जहां applications या services shared memory का extensively उपयोग करती हैं। भले ही container केवल IPC के माध्यम से सीधे break out न कर सके, namespace information leak कर सकता है या cross-process interference enable कर सकता है, जो बाद के attack में materially सहायता कर सकता है।

## Lab

आप एक private IPC namespace इस प्रकार create कर सकते हैं:
```bash
sudo unshare --ipc --fork bash
ipcs
```
और runtime behavior की तुलना इससे करें:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## रनटाइम उपयोग

Docker और Podman डिफ़ॉल्ट रूप से IPC को isolate करते हैं। Kubernetes आमतौर पर Pod को अपना IPC namespace देता है, जो उसी Pod के containers के बीच shared होता है, लेकिन डिफ़ॉल्ट रूप से host के साथ shared नहीं होता। Host IPC sharing संभव है, लेकिन इसे isolation में महत्वपूर्ण कमी के रूप में देखा जाना चाहिए, न कि केवल एक मामूली runtime option के रूप में।

## गलत कॉन्फ़िगरेशन

स्पष्ट गलती `--ipc=host` या `hostIPC: true` का उपयोग करना है। ऐसा legacy software के साथ compatibility या सुविधा के लिए किया जा सकता है, लेकिन इससे trust model में काफी बदलाव आता है। एक अन्य सामान्य समस्या IPC को नज़रअंदाज़ करना है, क्योंकि यह host PID या host networking की तुलना में कम गंभीर लगता है। वास्तव में, यदि workload browsers, databases, scientific workloads या shared memory का अधिक उपयोग करने वाले अन्य software को handle करता है, तो IPC surface काफी relevant हो सकता है।

## दुरुपयोग

जब host IPC shared होता है, तो attacker shared memory objects को inspect या interfere कर सकता है, host या neighboring workload के behavior के बारे में नई जानकारी प्राप्त कर सकता है, या वहां से मिली जानकारी को process visibility और ptrace-style capabilities के साथ combine कर सकता है। IPC sharing अक्सर full breakout path के बजाय एक supporting weakness होती है, लेकिन supporting weaknesses महत्वपूर्ण होती हैं क्योंकि वे वास्तविक attack chains को छोटा और अधिक stable बनाती हैं।

पहला उपयोगी कदम यह enumerate करना है कि कौन से IPC objects बिल्कुल visible हैं:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
यदि host IPC namespace shared है, तो बड़े shared-memory segments या interesting object owners तुरंत application behavior प्रकट कर सकते हैं:
```bash
ipcs -m -p
ipcs -q -p
```
कुछ environments में, `/dev/shm` की contents से स्वयं ऐसे filenames, artifacts या tokens leak हो सकते हैं जिन्हें check करना उपयोगी है:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing से अपने-आप तुरंत host root मिलना दुर्लभ है, लेकिन यह data और coordination channels को expose कर सकता है, जिससे बाद के process attacks काफी आसान हो जाते हैं।

### Full Example: `/dev/shm` Secret Recovery

सबसे realistic full abuse case direct escape के बजाय data theft है। यदि host IPC या broad shared-memory layout expose हो, तो sensitive artifacts कभी-कभी सीधे recover किए जा सकते हैं:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
प्रभाव:

- shared memory में छोड़े गए secrets या session material का extraction
- host पर वर्तमान में active applications की जानकारी
- बाद के PID-namespace या ptrace-based attacks के लिए बेहतर targeting

इसलिए IPC sharing को standalone host-escape primitive की तुलना में **attack amplifier** के रूप में समझना अधिक उचित है।

## Checks

इन commands का उद्देश्य यह पता लगाना है कि workload का private IPC view है या नहीं, क्या meaningful shared-memory या message objects दिखाई दे रहे हैं, और क्या `/dev/shm` स्वयं उपयोगी artifacts expose करता है।
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
यहाँ क्या महत्वपूर्ण है:

- यदि `ipcs -a` में unexpected users या services के owned objects दिखाई देते हैं, तो namespace अपेक्षित रूप से isolated नहीं हो सकता।
- बड़े या unusual shared memory segments की आगे जाँच करना अक्सर उचित होता है।
- व्यापक `/dev/shm` mount अपने-आप में bug नहीं है, लेकिन कुछ environments में इससे filenames, artifacts और transient secrets leak हो सकते हैं।

IPC को बड़े namespace types जितना ध्यान शायद ही कभी मिलता है, लेकिन जो environments इसका भारी उपयोग करते हैं, उनमें इसे host के साथ share करना स्पष्ट रूप से एक security decision है।

{{#include ../../../../../banners/hacktricks-training.md}}
