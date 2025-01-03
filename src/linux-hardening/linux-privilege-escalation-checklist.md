# चेकलिस्ट - लिनक्स प्रिविलेज एस्कलेशन

{{#include ../banners/hacktricks-training.md}}

### **लिनक्स स्थानीय प्रिविलेज एस्कलेशन वेक्टर खोजने के लिए सबसे अच्छा उपकरण:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [सिस्टम जानकारी](privilege-escalation/#system-information)

- [ ] **OS जानकारी प्राप्त करें**
- [ ] [**PATH**](privilege-escalation/#path) की जांच करें, कोई **लिखने योग्य फ़ोल्डर**?
- [ ] [**env वेरिएबल्स**](privilege-escalation/#env-info) की जांच करें, कोई संवेदनशील विवरण?
- [ ] [**kernel exploits**](privilege-escalation/#kernel-exploits) **स्क्रिप्ट का उपयोग करके** खोजें (DirtyCow?)
- [ ] **जांचें** कि [**sudo संस्करण** कमजोर है](privilege-escalation/#sudo-version)
- [ ] [**Dmesg** हस्ताक्षर सत्यापन विफल](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] अधिक सिस्टम एनम ([तारीख, सिस्टम आँकड़े, सीपीयू जानकारी, प्रिंटर](privilege-escalation/#more-system-enumeration))
- [ ] [**अधिक रक्षा की गणना करें**](privilege-escalation/#enumerate-possible-defenses)

### [ड्राइव](privilege-escalation/#drives)

- [ ] **माउंटेड** ड्राइव की सूची
- [ ] **कोई अनमाउंटेड ड्राइव?**
- [ ] **fstab में कोई क्रेड्स?**

### [**स्थापित सॉफ़्टवेयर**](privilege-escalation/#installed-software)

- [ ] **जांचें कि** [**उपयोगी सॉफ़्टवेयर**](privilege-escalation/#useful-software) **स्थापित है**
- [ ] **जांचें कि** [**कमजोर सॉफ़्टवेयर**](privilege-escalation/#vulnerable-software-installed) **स्थापित है**

### [प्रक्रियाएँ](privilege-escalation/#processes)

- [ ] क्या कोई **अज्ञात सॉफ़्टवेयर चल रहा है**?
- [ ] क्या कोई सॉफ़्टवेयर **ज्यादा प्रिविलेज के साथ चल रहा है**?
- [ ] **चल रही प्रक्रियाओं के एक्सप्लॉइट्स** की खोज करें (विशेष रूप से चल रही संस्करण)।
- [ ] क्या आप किसी चल रही प्रक्रिया का **बाइनरी संशोधित** कर सकते हैं?
- [ ] **प्रक्रियाओं की निगरानी करें** और जांचें कि कोई दिलचस्प प्रक्रिया बार-बार चल रही है।
- [ ] क्या आप कुछ दिलचस्प **प्रक्रिया मेमोरी** (जहाँ पासवर्ड सहेजे जा सकते हैं) **पढ़ सकते हैं**?

### [शेड्यूल्ड/क्रॉन नौकरियाँ?](privilege-escalation/#scheduled-jobs)

- [ ] क्या [**PATH**](privilege-escalation/#cron-path) को किसी क्रॉन द्वारा संशोधित किया जा रहा है और क्या आप इसमें **लिख सकते हैं**?
- [ ] किसी क्रॉन नौकरी में कोई [**वाइल्डकार्ड**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)?
- [ ] क्या कोई [**संशोधित करने योग्य स्क्रिप्ट**](privilege-escalation/#cron-script-overwriting-and-symlink) **चल रही है** या **संशोधित करने योग्य फ़ोल्डर** में है?
- [ ] क्या आपने पता लगाया है कि कोई **स्क्रिप्ट** [**बहुत **बार-बार**](privilege-escalation/#frequent-cron-jobs) **चल रही है**? (हर 1, 2 या 5 मिनट)

### [सेवाएँ](privilege-escalation/#services)

- [ ] कोई **लिखने योग्य .service** फ़ाइल?
- [ ] कोई **लिखने योग्य बाइनरी** जो **सेवा** द्वारा निष्पादित हो?
- [ ] क्या **systemd PATH** में कोई **लिखने योग्य फ़ोल्डर** है?

### [टाइमर्स](privilege-escalation/#timers)

- [ ] कोई **लिखने योग्य टाइमर**?

### [सॉकेट्स](privilege-escalation/#sockets)

- [ ] कोई **लिखने योग्य .socket** फ़ाइल?
- [ ] क्या आप किसी सॉकेट के साथ **संवाद कर सकते हैं**?
- [ ] **दिलचस्प जानकारी के साथ HTTP सॉकेट्स**?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] क्या आप किसी **D-Bus** के साथ **संवाद कर सकते हैं**?

### [नेटवर्क](privilege-escalation/#network)

- [ ] जानने के लिए नेटवर्क की गणना करें कि आप कहाँ हैं
- [ ] **खुले पोर्ट जो आप पहले नहीं पहुंच सके** मशीन के अंदर शेल प्राप्त करने से पहले?
- [ ] क्या आप `tcpdump` का उपयोग करके **ट्रैफ़िक स्निफ़ कर सकते हैं**?

### [उपयोगकर्ता](privilege-escalation/#users)

- [ ] सामान्य उपयोगकर्ता/समूहों की **गणना**
- [ ] क्या आपके पास **बहुत बड़ा UID** है? क्या **मशीन** **कमजोर** है?
- [ ] क्या आप [**एक समूह के माध्यम से प्रिविलेज बढ़ा सकते हैं**](privilege-escalation/interesting-groups-linux-pe/) जिसमें आप शामिल हैं?
- [ ] **क्लिपबोर्ड** डेटा?
- [ ] पासवर्ड नीति?
- [ ] कोशिश करें कि आप **हर ज्ञात पासवर्ड** का **उपयोग** करें जो आपने पहले खोजा है **प्रत्येक** संभावित **उपयोगकर्ता** के साथ लॉगिन करने के लिए। बिना पासवर्ड के भी लॉगिन करने की कोशिश करें।

### [लिखने योग्य PATH](privilege-escalation/#writable-path-abuses)

- [ ] यदि आपके पास **PATH में किसी फ़ोल्डर पर लिखने के अधिकार** हैं तो आप प्रिविलेज बढ़ाने में सक्षम हो सकते हैं

### [SUDO और SUID कमांड](privilege-escalation/#sudo-and-suid)

- [ ] क्या आप **sudo के साथ कोई कमांड निष्पादित कर सकते हैं**? क्या आप इसे रूट के रूप में कुछ पढ़ने, लिखने या निष्पादित करने के लिए उपयोग कर सकते हैं? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] क्या कोई **एक्सप्लॉइटेबल SUID बाइनरी** है? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] क्या [**sudo** कमांड **पथ** द्वारा **सीमित** हैं? क्या आप **प्रतिबंधों को बायपास** कर सकते हैं](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID बाइनरी बिना पथ के संकेतित**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID बाइनरी पथ निर्दिष्ट करना**](privilege-escalation/#suid-binary-with-command-path)? बायपास
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/#ld_preload)
- [ ] [**SUID बाइनरी में .so लाइब्रेरी की कमी**](privilege-escalation/#suid-binary-so-injection) एक लिखने योग्य फ़ोल्डर से?
- [ ] [**SUDO टोकन उपलब्ध हैं**](privilege-escalation/#reusing-sudo-tokens)? [**क्या आप SUDO टोकन बना सकते हैं**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] क्या आप [**sudoers फ़ाइलें पढ़ या संशोधित कर सकते हैं**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
- [ ] क्या आप [**/etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d) को **संशोधित कर सकते हैं**?
- [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) कमांड

### [क्षमताएँ](privilege-escalation/#capabilities)

- [ ] क्या किसी बाइनरी में कोई **अप्रत्याशित क्षमता** है?

### [ACLs](privilege-escalation/#acls)

- [ ] क्या किसी फ़ाइल में कोई **अप्रत्याशित ACL** है?

### [खुले शेल सत्र](privilege-escalation/#open-shell-sessions)

- [ ] **स्क्रीन**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL पूर्वानुमानित PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH दिलचस्प कॉन्फ़िगरेशन मान**](privilege-escalation/#ssh-interesting-configuration-values)

### [दिलचस्प फ़ाइलें](privilege-escalation/#interesting-files)

- [ ] **प्रोफ़ाइल फ़ाइलें** - संवेदनशील डेटा पढ़ें? प्रिवेस्क के लिए लिखें?
- [ ] **passwd/shadow फ़ाइलें** - संवेदनशील डेटा पढ़ें? प्रिवेस्क के लिए लिखें?
- [ ] संवेदनशील डेटा के लिए **सामान्यतः दिलचस्प फ़ोल्डरों** की जांच करें
- [ ] **अजीब स्थान/स्वामित्व वाली फ़ाइलें,** जिन तक आपकी पहुँच हो सकती है या निष्पादनीय फ़ाइलों को बदल सकते हैं
- [ ] **अंतिम मिनटों में संशोधित**
- [ ] **Sqlite DB फ़ाइलें**
- [ ] **छिपी हुई फ़ाइलें**
- [ ] **PATH में स्क्रिप्ट/बाइनरी**
- [ ] **वेब फ़ाइलें** (पासवर्ड?)
- [ ] **बैकअप**?
- [ ] **जाने-माने फ़ाइलें जो पासवर्ड रखती हैं**: **Linpeas** और **LaZagne** का उपयोग करें
- [ ] **सामान्य खोज**

### [**लिखने योग्य फ़ाइलें**](privilege-escalation/#writable-files)

- [ ] **मनमाने कमांड निष्पादित करने के लिए पायथन लाइब्रेरी** को संशोधित करें?
- [ ] क्या आप **लॉग फ़ाइलों को संशोधित कर सकते हैं**? **Logtotten** एक्सप्लॉइट
- [ ] क्या आप **/etc/sysconfig/network-scripts/** को **संशोधित कर सकते हैं**? Centos/Redhat एक्सप्लॉइट
- [ ] क्या आप [**ini, int.d, systemd या rc.d फ़ाइलों में लिख सकते हैं**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**अन्य तरकीबें**](privilege-escalation/#other-tricks)

- [ ] क्या आप [**NFS का दुरुपयोग करके प्रिविलेज बढ़ा सकते हैं**](privilege-escalation/#nfs-privilege-escalation)?
- [ ] क्या आपको [**एक प्रतिबंधित शेल से भागने की आवश्यकता है**](privilege-escalation/#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
