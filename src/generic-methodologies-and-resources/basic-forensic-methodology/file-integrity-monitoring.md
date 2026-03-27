# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## बेसलाइन

बेसलाइन किसी सिस्टम के कुछ हिस्सों का स्नैपशॉट लेना होता है ताकि उसे भविष्य की स्थिति के साथ **तुलना करके बदलाव उजागर किए जा सकें**।

उदाहरण के लिए, आप फ़ाइल सिस्टम की प्रत्येक फ़ाइल का हैश निकालकर संग्रहित कर सकते हैं ताकि यह पता चल सके कि कौन सी फाइलें संशोधित हुई थीं।\
यह उपयोगकर्ता खातों, चल रहे प्रोसेस, चल रही सेवाएँ और किसी भी अन्य चीज़ के साथ भी किया जा सकता है जिनमें ज़्यादा बदलाव नहीं होने चाहिए।

एक **उपयोगी बेसलाइन** आमतौर पर सिर्फ डाइजेस्ट से अधिक चीज़ें स्टोर करती है: permissions, owner, group, timestamps, inode, symlink target, ACLs, और चुने हुए extended attributes को भी ट्रैक करना लाभकारी होता है। attacker-hunting के नजरिए से, यह **permission-only tampering**, **atomic file replacement**, और **persistence via modified service/unit files** जैसी चीज़ों का पता लगाने में मदद करता है भले ही कंटेंट हैश पहली चीज़ न हो जो बदलती है।

### File Integrity Monitoring

File Integrity Monitoring (FIM) एक महत्वपूर्ण सुरक्षा तकनीक है जो फ़ाइलों में होने वाले बदलावों को ट्रैक करके IT वातावरण और डेटा की सुरक्षा करती है। यह आमतौर पर निम्न को जोड़ती है:

1. **Baseline comparison:** भविष्य में तुलना के लिए metadata और cryptographic checksums स्टोर करें (संभवतः `SHA-256` या उससे बेहतर)।
2. **Real-time notifications:** OS-स्थानीय फ़ाइल इवेंट्स को सब्सक्राइब करें ताकि पता चल सके **किस फ़ाइल में बदलाव हुआ, कब हुआ, और आदर्श रूप से किस process/user ने इसे छुआ**।
3. **Periodic re-scan:** रीबूट, खोए हुए इवेंट्स, एजेंट आउटेज, या जानबूझकर की गई anti-forensic गतिविधि के बाद भरोसा पुनः बनाएं।

Threat hunting के लिए, FIM आमतौर पर तब अधिक उपयोगी होता है जब यह **high-value paths** जैसे पर केंद्रित हो:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

कलेक्शन बैकएन्ड मायने रखता है:

- **`inotify` / `fsnotify`**: आसान और आम, लेकिन watch limits समाप्त हो सकते हैं और कुछ edge cases छूट सकते हैं।
- **`auditd` / audit framework**: बेहतर जब आपको ज़रूरत हो कि **किसने फ़ाइल बदली** (`auid`, process, pid, executable)।
- **`eBPF` / `kprobes`**: आधुनिक FIM स्टैक्स द्वारा उपयोग किए जाने वाले नए विकल्प जो इवेंट्स को समृद्ध करते हैं और सादे `inotify` डेप्लॉयमेंट्स के कुछ ऑपरेशनल दर्द को कम करते हैं।

कुछ व्यावहारिक नुक्ते:

- यदि कोई प्रोग्राम फ़ाइल को `write temp -> rename` के साथ बदल देता है, तो फ़ाइल को ही वॉच करना उपयोगी होना बंद कर सकता है। **पेरेंट डायरेक्टरी को वॉच करें**, सिर्फ़ फ़ाइल नहीं।
- `inotify`-आधारित कलेक्टर्स **huge directory trees**, **hard-link activity**, या किसी **watched file is deleted** होने के बाद मिस या प्रदर्शन गिरावट का सामना कर सकते हैं।
- बहुत बड़े recursive watch सेट चुपचाप फेल हो सकते हैं यदि `fs.inotify.max_user_watches`, `max_user_instances`, या `max_queued_events` बहुत कम हों।
- नेटवर्क फ़ाइल सिस्टम आम तौर पर low-noise मॉनिटरिंग के लिए खराब FIM लक्ष्य होते हैं।

Example baseline + verification with AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
उदाहरण `osquery` FIM कॉन्फ़िगरेशन जो attacker persistence paths पर केंद्रित है:
```json
{
"schedule": {
"fim": {
"query": "SELECT * FROM file_events;",
"interval": 300,
"removed": false
}
},
"file_paths": {
"etc": ["/etc/%%"],
"systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
"ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
}
}
```
यदि आपको केवल path-level changes के बजाय **process attribution** चाहिए, तो `osquery` `process_file_events` या Wazuh `whodata` mode जैसे audit-backed telemetry को प्राथमिकता दें।

### Windows

Windows पर, जब आप **change journals** को **high-signal process/file telemetry** के साथ जोड़ते हैं तो FIM अधिक प्रभावी होता है:

- **NTFS USN Journal** फ़ाइल परिवर्तनों का प्रति-वॉल्यूम एक स्थायी लॉग देता है।
- **Sysmon Event ID 11** फ़ाइल निर्माण/ओवरराइट के लिए उपयोगी है।
- **Sysmon Event ID 2** **timestomping** का पता लगाने में मदद करता है।
- **Sysmon Event ID 15** `Zone.Identifier` या hidden payload streams जैसे **named alternate data streams (ADS)** के लिए उपयोगी है।

त्वरित USN triage उदाहरण:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
For deeper anti-forensic ideas around **timestamp manipulation**, **ADS abuse**, and **USN tampering**, check [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Container FIM अक्सर वास्तविक लिखने के पथ को पकड़ने में चूकता है। Docker `overlay2` के साथ, परिवर्तन container की **writable upper layer** (`upperdir`/`diff`) में commit होते हैं, न कि read-only image layers में। इसलिए:

- सिर्फ़ एक short-lived container के **inside** से paths की मॉनिटरिंग container के पुनः बनाये जाने के बाद होने वाले परिवर्तनों को मिस कर सकती है।
- writable layer को बैक करने वाले **host path** या संबंधित bind-mounted volume की मॉनिटरिंग अक्सर अधिक उपयोगी होती है।
- image layers पर FIM, running container filesystem पर FIM से अलग होता है।

## Attacker-Oriented Hunting Notes

- बाइनरीज़ जितनी सावधानी से ट्रैक की जाती हैं, उतनी ही सावधानी से **service definitions** और **task schedulers** को ट्रैक करें। Attackers अक्सर `/bin/sshd` को patch करने के बजाय unit file, cron entry, या task XML को modify करके persistence हासिल कर लेते हैं।
- केवल content hash पर्याप्त नहीं है। कई compromises सबसे पहले **owner/mode/xattr/ACL drift** के रूप में दिखते हैं।
- यदि आप किसी परिपक्व intrusion का संदेह करते हैं, तो दोनों करें: ताज़ा activity के लिए **real-time FIM** और भरोसेमंद मीडिया से **cold baseline comparison**।
- यदि attacker के पास root या kernel execution है, तो मानें कि FIM एजेंट, उसका database, और यहाँ तक कि event source भी tamper किए जा सकते हैं। लॉग और baselines को जहाँ संभव हो remote या read-only मीडिया पर स्टोर करें।

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
