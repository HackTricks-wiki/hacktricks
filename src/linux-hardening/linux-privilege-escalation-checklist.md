# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Linux स्थानीय विशेषाधिकार वृद्धि वेक्टर की खोज के लिए सबसे अच्छा उपकरण:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [सिस्टम जानकारी](privilege-escalation/index.html#system-information)

- [ ] **OS जानकारी प्राप्त करें**
- [ ] [**PATH**](privilege-escalation/index.html#path) की जांच करें, कोई **लिखने योग्य फ़ोल्डर**?
- [ ] [**env वेरिएबल्स**](privilege-escalation/index.html#env-info) की जांच करें, कोई संवेदनशील विवरण?
- [ ] [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **स्क्रिप्ट का उपयोग करके** खोजें (DirtyCow?)
- [ ] **जांचें** कि [**sudo संस्करण**] (privilege-escalation/index.html#sudo-version) कमजोर है या नहीं
- [ ] [**Dmesg**] हस्ताक्षर सत्यापन विफल (privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] अधिक सिस्टम एनम ([तारीख, सिस्टम आँकड़े, सीपीयू जानकारी, प्रिंटर](privilege-escalation/index.html#more-system-enumeration))
- [ ] [अधिक रक्षा की गणना करें](privilege-escalation/index.html#enumerate-possible-defenses)

### [ड्राइव](privilege-escalation/index.html#drives)

- [ ] **माउंटेड** ड्राइव की सूची
- [ ] **कोई अनमाउंटेड ड्राइव?**
- [ ] **fstab में कोई क्रेड्स?**

### [**स्थापित सॉफ़्टवेयर**](privilege-escalation/index.html#installed-software)

- [ ] **जांचें कि** [**उपयोगी सॉफ़्टवेयर**](privilege-escalation/index.html#useful-software) **स्थापित है**
- [ ] **जांचें कि** [**कमजोर सॉफ़्टवेयर**](privilege-escalation/index.html#vulnerable-software-installed) **स्थापित है**

### [प्रक्रियाएँ](privilege-escalation/index.html#processes)

- [ ] क्या कोई **अज्ञात सॉफ़्टवेयर चल रहा है**?
- [ ] क्या कोई सॉफ़्टवेयर **उससे अधिक विशेषाधिकार के साथ चल रहा है जो उसे होना चाहिए**?
- [ ] **चल रही प्रक्रियाओं के शोषण** की खोज करें (विशेष रूप से चल रही संस्करण)।
- [ ] क्या आप किसी चल रही प्रक्रिया के **बाइनरी को संशोधित** कर सकते हैं?
- [ ] **प्रक्रियाओं की निगरानी करें** और जांचें कि कोई दिलचस्प प्रक्रिया बार-बार चल रही है या नहीं।
- [ ] क्या आप कुछ दिलचस्प **प्रक्रिया मेमोरी** (जहां पासवर्ड सहेजे जा सकते हैं) **पढ़ सकते हैं**?

### [शेड्यूल्ड/क्रॉन नौकरियाँ?](privilege-escalation/index.html#scheduled-jobs)

- [ ] क्या [**PATH**](privilege-escalation/index.html#cron-path) को किसी क्रॉन द्वारा संशोधित किया जा रहा है और क्या आप इसमें **लिख सकते हैं**?
- [ ] क्या किसी क्रॉन नौकरी में कोई [**वाइल्डकार्ड**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) है?
- [ ] क्या कोई [**संशोधित करने योग्य स्क्रिप्ट**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) **चल रही है** या **संशोधित करने योग्य फ़ोल्डर** के अंदर है?
- [ ] क्या आपने पता लगाया है कि कोई **स्क्रिप्ट** [**बहुत **बार-बार**](privilege-escalation/index.html#frequent-cron-jobs) **चल रही है**? (हर 1, 2 या 5 मिनट)

### [सेवाएँ](privilege-escalation/index.html#services)

- [ ] कोई **लिखने योग्य .service** फ़ाइल?
- [ ] कोई **लिखने योग्य बाइनरी** जो **सेवा** द्वारा निष्पादित होती है?
- [ ] क्या **systemd PATH** में कोई **लिखने योग्य फ़ोल्डर** है?

### [टाइमर](privilege-escalation/index.html#timers)

- [ ] कोई **लिखने योग्य टाइमर**?

### [सॉकेट्स](privilege-escalation/index.html#sockets)

- [ ] कोई **लिखने योग्य .socket** फ़ाइल?
- [ ] क्या आप किसी सॉकेट के साथ **संवाद कर सकते हैं**?
- [ ] **HTTP सॉकेट्स** जिनमें दिलचस्प जानकारी है?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] क्या आप किसी **D-Bus** के साथ **संवाद कर सकते हैं**?

### [नेटवर्क](privilege-escalation/index.html#network)

- [ ] जानने के लिए नेटवर्क की गणना करें कि आप कहाँ हैं
- [ ] **खुले पोर्ट जो आप पहले नहीं पहुंच सके** मशीन के अंदर शेल प्राप्त करने से पहले?
- [ ] क्या आप `tcpdump` का उपयोग करके **ट्रैफ़िक को स्निफ़ कर सकते हैं**?

### [उपयोगकर्ता](privilege-escalation/index.html#users)

- [ ] सामान्य उपयोगकर्ता/समूहों की **गणना**
- [ ] क्या आपके पास **बहुत बड़ा UID** है? क्या **मशीन** **कमजोर** है?
- [ ] क्या आप [**एक समूह के माध्यम से विशेषाधिकार बढ़ा सकते हैं**](privilege-escalation/interesting-groups-linux-pe/) जिसमें आप शामिल हैं?
- [ ] **क्लिपबोर्ड** डेटा?
- [ ] पासवर्ड नीति?
- [ ] कोशिश करें कि आप **हर ज्ञात पासवर्ड** का **उपयोग** करें जो आपने पहले खोजा है **प्रत्येक** संभावित **उपयोगकर्ता** के साथ लॉगिन करने के लिए। बिना पासवर्ड के भी लॉगिन करने की कोशिश करें।

### [लिखने योग्य PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] यदि आपके पास **PATH में किसी फ़ोल्डर पर लिखने के विशेषाधिकार** हैं तो आप विशेषाधिकार बढ़ाने में सक्षम हो सकते हैं

### [SUDO और SUID कमांड](privilege-escalation/index.html#sudo-and-suid)

- [ ] क्या आप **sudo के साथ कोई कमांड निष्पादित कर सकते हैं**? क्या आप इसे रूट के रूप में कुछ पढ़ने, लिखने या निष्पादित करने के लिए उपयोग कर सकते हैं? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] क्या कोई **शोषण योग्य SUID बाइनरी** है? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] क्या [**sudo** कमांड **पथ** द्वारा **सीमित** हैं? क्या आप **प्रतिबंधों को बायपास** कर सकते हैं](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID बाइनरी बिना पथ के संकेतित**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID बाइनरी पथ निर्दिष्ट करते हुए**](privilege-escalation/index.html#suid-binary-with-command-path)? बायपास
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**SUID बाइनरी में .so लाइब्रेरी की कमी**](privilege-escalation/index.html#suid-binary-so-injection) एक लिखने योग्य फ़ोल्डर से?
- [ ] [**SUDO टोकन उपलब्ध हैं**](privilege-escalation/index.html#reusing-sudo-tokens)? [**क्या आप SUDO टोकन बना सकते हैं**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] क्या आप [**sudoers फ़ाइलें पढ़ या संशोधित कर सकते हैं**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] क्या आप [**/etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d) को **संशोधित कर सकते हैं**?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) कमांड

### [क्षमताएँ](privilege-escalation/index.html#capabilities)

- [ ] क्या किसी बाइनरी में कोई **अप्रत्याशित क्षमता** है?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] क्या किसी फ़ाइल में कोई **अप्रत्याशित ACL** है?

### [खुले शेल सत्र](privilege-escalation/index.html#open-shell-sessions)

- [ ] **स्क्रीन**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL पूर्वानुमानित PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH दिलचस्प कॉन्फ़िगरेशन मान**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [दिलचस्प फ़ाइलें](privilege-escalation/index.html#interesting-files)

- [ ] **प्रोफ़ाइल फ़ाइलें** - संवेदनशील डेटा पढ़ें? प्रिवेस्क के लिए लिखें?
- [ ] **passwd/shadow फ़ाइलें** - संवेदनशील डेटा पढ़ें? प्रिवेस्क के लिए लिखें?
- [ ] संवेदनशील डेटा के लिए **सामान्यतः दिलचस्प फ़ोल्डरों** की जांच करें
- [ ] **अजीब स्थान/स्वामित्व वाली फ़ाइलें,** जिन तक आपकी पहुँच हो सकती है या निष्पादनीय फ़ाइलों को संशोधित कर सकते हैं
- [ ] **अंतिम मिनटों में संशोधित**
- [ ] **Sqlite DB फ़ाइलें**
- [ ] **छिपी हुई फ़ाइलें**
- [ ] **PATH में स्क्रिप्ट/बाइनरी**
- [ ] **वेब फ़ाइलें** (पासवर्ड?)
- [ ] **बैकअप**?
- [ ] **जाने-माने फ़ाइलें जो पासवर्ड रखती हैं**: **Linpeas** और **LaZagne** का उपयोग करें
- [ ] **सामान्य खोज**

### [**लिखने योग्य फ़ाइलें**](privilege-escalation/index.html#writable-files)

- [ ] **मनमाने आदेश निष्पादित करने के लिए पायथन लाइब्रेरी को संशोधित करें?**
- [ ] क्या आप **लॉग फ़ाइलों को संशोधित कर सकते हैं**? **Logtotten** शोषण
- [ ] क्या आप **/etc/sysconfig/network-scripts/** को **संशोधित कर सकते हैं**? Centos/Redhat शोषण
- [ ] क्या आप [**ini, int.d, systemd या rc.d फ़ाइलों में लिख सकते हैं**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**अन्य तरकीबें**](privilege-escalation/index.html#other-tricks)

- [ ] क्या आप [**NFS का दुरुपयोग करके विशेषाधिकार बढ़ा सकते हैं**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] क्या आपको [**एक प्रतिबंधित शेल से भागने की आवश्यकता है**](privilege-escalation/index.html#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
