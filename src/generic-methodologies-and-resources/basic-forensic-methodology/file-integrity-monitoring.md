# File Integrity Monitoring

## Baseline

एक baseline में सिस्टम के कुछ हिस्सों का snapshot लेना शामिल होता है, ताकि **भविष्य की स्थिति के साथ उसकी तुलना करके बदलावों को उजागर किया जा सके**।

उदाहरण के लिए, आप filesystem की प्रत्येक file का hash calculate और store कर सकते हैं, ताकि यह पता लगाया जा सके कि कौन-सी files modify हुईं।\
यह user accounts created, running processes, running services और ऐसी किसी भी अन्य चीज़ के साथ भी किया जा सकता है, जिसमें अधिक बदलाव नहीं होना चाहिए या बिल्कुल भी नहीं होना चाहिए।

एक **useful baseline** आमतौर पर केवल digest से अधिक जानकारी store करता है: permissions, owner, group, timestamps, inode, symlink target, ACLs और चुने हुए extended attributes को track करना भी उपयोगी है।<sup>[[4]](#references)</sup> Attacker-hunting के दृष्टिकोण से, इससे **केवल permissions में की गई छेड़छाड़**, **atomic file replacement** और **modified service/unit files के माध्यम से persistence** का पता लगाने में मदद मिलती है, भले ही content hash में सबसे पहले बदलाव न हुआ हो।

### File Integrity Monitoring

File Integrity Monitoring (FIM) एक महत्वपूर्ण security technique है, जो files में होने वाले बदलावों को track करके IT environments और data की सुरक्षा करती है। यह आमतौर पर निम्नलिखित को combine करता है:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Baseline comparison:** भविष्य की तुलना के लिए metadata और cryptographic checksums (अधिमानतः `SHA-256` या बेहतर) store करें।
2. **Real-time notifications:** OS-native file events को subscribe करें, ताकि पता चल सके कि **कौन-सी file बदली, कब बदली और आदर्श रूप से किस process/user ने उसे modify किया**।
3. **Periodic re-scan:** reboots, dropped events, agent outages या जानबूझकर की गई anti-forensic activity के बाद confidence को फिर से स्थापित करें।

Threat hunting के लिए, FIM आमतौर पर **high-value paths** पर केंद्रित होने पर अधिक उपयोगी होता है, जैसे:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers और bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Collection backend महत्वपूर्ण होता है:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: आसान और सामान्य हैं, लेकिन watch limits समाप्त हो सकती हैं और कुछ edge cases छूट जाते हैं।
- **`auditd` / audit framework**: जब आपको यह जानना हो कि **file किसने बदली** (login UID, process ID और process name), तब बेहतर होते हैं।
- **`eBPF` / `kprobes`**: ये नए options हैं, जिनका उपयोग modern FIM stacks events को समृद्ध करने और plain `inotify` deployments की कुछ operational समस्याओं को कम करने के लिए करते हैं।

कुछ practical gotchas:<sup>[[1]](#references)[[5]](#references)</sup>

- यदि कोई program `write temp -> rename` के माध्यम से किसी file को **replace** करता है, तो केवल उस file को watch करना उपयोगी नहीं रह सकता। **केवल file को नहीं, बल्कि उसकी parent directory को watch करें**।
- `inotify`-based collectors **बहुत बड़े directory trees**, **hard-link activity** या **watched file delete होने के बाद** events miss कर सकते हैं या उनका प्रदर्शन खराब हो सकता है।
- यदि `fs.inotify.max_user_watches`, `max_user_instances` या `max_queued_events` की values बहुत कम हों, तो बहुत बड़े recursive watch sets बिना किसी स्पष्ट संकेत के fail हो सकते हैं।
- `inotify`-based monitoring के लिए network filesystems एक blind spot हैं, क्योंकि remote changes report नहीं किए जाते।

AIDE के साथ baseline + verification का उदाहरण:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
हमलावर की persistence paths पर केंद्रित `osquery` FIM configuration का उदाहरण:<sup>[[1]](#references)</sup>
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
यदि आपको केवल path-level changes के बजाय **process attribution** की आवश्यकता है, तो `osquery` `process_file_events` या Wazuh `whodata` mode जैसे audit-backed telemetry को प्राथमिकता दें।<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Windows पर, **change journals** को **high-signal process/file telemetry** के साथ संयोजित करने पर FIM अधिक प्रभावी होता है:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** file changes का persistent per-volume log प्रदान करता है।
- **Sysmon Event ID 11** file creation/overwrite के लिए उपयोगी है।
- **Sysmon Event ID 2** **timestomping** का पता लगाने में सहायता करता है।
- **Sysmon Event ID 15** `Zone.Identifier` या hidden payload streams जैसे **named alternate data streams (ADS)** के लिए उपयोगी है।

त्वरित USN triage examples:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
गहरे **timestamp manipulation**, **ADS abuse**, और **USN tampering** से संबंधित anti-forensic विचारों के लिए [Anti-Forensic Techniques](anti-forensic-techniques.md) देखें।

### Containers

Container FIM अक्सर वास्तविक write path को miss कर देता है। Docker `overlay2` के साथ, container filesystem read-only image `lowerdir` layers को writable **upper layer** (`upperdir`/`diff`) के साथ जोड़ता है, और image files में किए गए writes उस upper layer में copy up हो जाते हैं।<sup>[[8]](#references)</sup> इसलिए:

- केवल किसी छोटे समय तक चलने वाले container के **अंदर** के paths को monitor करने से container दोबारा बनाए जाने के बाद हुए changes miss हो सकते हैं।
- उस writable layer को support करने वाले **host path** या संबंधित bind-mounted volume को monitor करना अक्सर अधिक उपयोगी होता है।
- Image layers पर FIM, running container filesystem पर FIM से अलग होता है।

## Attacker-Oriented Hunting Notes

- **service definitions** और **task schedulers** को binaries जितनी सावधानी से track करें। Attackers अक्सर `/bin/sshd` को patch करने के बजाय unit file, cron entry, या task XML को modify करके persistence प्राप्त करते हैं।
- केवल content hash पर्याप्त नहीं है। कई compromises पहले **owner/mode/xattr/ACL drift** के रूप में दिखाई देते हैं।
- यदि आपको किसी mature intrusion का संदेह है, तो दोनों करें: नई activity के लिए **real-time FIM** और trusted media से **cold baseline comparison**।
- यदि attacker के पास root या kernel execution है, तो FIM agent और उसके database को untrusted मानें। जब भी संभव हो, logs और baselines को remotely या read-only media पर store करें।<sup>[[4]](#references)</sup>

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)।<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [osquery के साथ File Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Linux की tracing: File Integrity Monitoring का एक उपयोग मामला (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck और whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE Manual Version 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux manual page](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS storage driver](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
