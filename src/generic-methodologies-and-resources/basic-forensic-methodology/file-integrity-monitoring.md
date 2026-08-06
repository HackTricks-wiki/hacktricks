# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## बेसलाइन

बेसलाइन में system के कुछ हिस्सों का snapshot लेना शामिल होता है, ताकि **भविष्य की स्थिति से इसकी तुलना करके बदलावों को उजागर किया जा सके**।

उदाहरण के लिए, आप filesystem की प्रत्येक file का hash calculate और store कर सकते हैं, ताकि पता लगाया जा सके कि कौन-सी files modify की गई हैं।\
यह created user accounts, running processes, running services और ऐसी किसी भी अन्य चीज़ के साथ भी किया जा सकता है, जिसमें अधिक बदलाव नहीं होना चाहिए या बिल्कुल भी नहीं होना चाहिए।

एक **उपयोगी बेसलाइन** आमतौर पर केवल digest से अधिक जानकारी store करती है: permissions, owner, group, timestamps, inode, symlink target, ACLs और चुने गए extended attributes को track करना भी महत्वपूर्ण है। Attacker-hunting के दृष्टिकोण से, इससे **केवल permissions में की गई छेड़छाड़**, **atomic file replacement** और **modified service/unit files के माध्यम से persistence** का पता लगाने में सहायता मिलती है, भले ही content hash में सबसे पहले बदलाव न हुआ हो।

### File Integrity Monitoring

File Integrity Monitoring (FIM) एक महत्वपूर्ण security technique है, जो files में होने वाले बदलावों को track करके IT environments और data की सुरक्षा करती है। इसमें आमतौर पर ये शामिल होते हैं:

1. **Baseline comparison:** भविष्य की comparisons के लिए metadata और cryptographic checksums (अधिमानतः `SHA-256` या बेहतर) store करें।
2. **Real-time notifications:** OS-native file events को subscribe करें, ताकि पता चल सके कि **कौन-सी file कब बदली और ideally किस process/user ने उसे access किया**।
3. **Periodic re-scan:** reboots, dropped events, agent outages या जानबूझकर की गई anti-forensic activity के बाद confidence को फिर से स्थापित करें।

Threat hunting के लिए, FIM आमतौर पर **high-value paths** पर focused होने पर अधिक उपयोगी होता है, जैसे:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers और bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Collection backend महत्वपूर्ण होता है:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: आसान और common हैं, लेकिन watch limits समाप्त हो सकती हैं और कुछ edge cases miss हो जाते हैं।
- **`auditd` / audit framework**: जब आपको यह जानना हो कि **file किसने बदली** (`auid`, process, pid, executable), तब बेहतर होता है।
- **`eBPF` / `kprobes`**: आधुनिक FIM stacks द्वारा events को enrich करने और plain `inotify` deployments की कुछ operational समस्याओं को कम करने के लिए उपयोग किए जाने वाले नए options हैं।

कुछ practical gotchas:<sup>[[1]](#references)</sup>

- यदि कोई program `write temp -> rename` के द्वारा किसी file को **replace** करता है, तो स्वयं file को watch करना उपयोगी नहीं रह सकता। **केवल file को नहीं, बल्कि उसकी parent directory को watch करें**।
- `inotify`-based collectors **huge directory trees**, **hard-link activity** या **watched file के delete होने** के बाद miss या degrade कर सकते हैं।
- यदि `fs.inotify.max_user_watches`, `max_user_instances` या `max_queued_events` की values बहुत कम हैं, तो बहुत बड़े recursive watch sets बिना किसी स्पष्ट संकेत के fail हो सकते हैं।
- Low-noise monitoring के लिए network filesystems आमतौर पर खराब FIM targets होते हैं।

AIDE के साथ baseline + verification का उदाहरण:
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
यदि आपको केवल path-level changes के बजाय **process attribution** की आवश्यकता है, तो `osquery` `process_file_events` या Wazuh `whodata` mode जैसी audit-backed telemetry को प्राथमिकता दें।<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Windows पर, जब आप **change journals** को **high-signal process/file telemetry** के साथ जोड़ते हैं, तो FIM अधिक प्रभावी होता है:

- **NTFS USN Journal** file changes का persistent per-volume log प्रदान करता है।
- **Sysmon Event ID 11** file creation/overwrite के लिए उपयोगी है।
- **Sysmon Event ID 2** **timestomping** का पता लगाने में मदद करता है।
- **Sysmon Event ID 15** `Zone.Identifier` या hidden payload streams जैसे **named alternate data streams (ADS)** के लिए उपयोगी है।

त्वरित USN triage examples:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
**timestamp manipulation**, **ADS abuse**, और **USN tampering** से संबंधित गहरे anti-forensic विचारों के लिए [Anti-Forensic Techniques](anti-forensic-techniques.md) देखें।

### कंटेनर

Container FIM में अक्सर वास्तविक write path छूट जाता है। Docker `overlay2` के साथ, changes container की **writable upper layer** (`upperdir`/`diff`) में commit होते हैं, न कि read-only image layers में। इसलिए:

- केवल किसी अल्पकालिक container के **अंदर** के paths की निगरानी करने से container के दोबारा बनाए जाने के बाद के changes छूट सकते हैं।
- **writable layer** के पीछे के **host path** या संबंधित bind-mounted volume की निगरानी अक्सर अधिक उपयोगी होती है।
- Image layers पर FIM, running container filesystem पर FIM से अलग होता है।

## Attacker-Oriented Hunting Notes

- **service definitions** और **task schedulers** को binaries जितनी ही सावधानी से track करें। Attackers अक्सर `/bin/sshd` को patch करने के बजाय unit file, cron entry या task XML को modify करके persistence प्राप्त करते हैं।
- केवल content hash पर्याप्त नहीं है। कई compromises पहले **owner/mode/xattr/ACL drift** के रूप में दिखाई देते हैं।
- यदि आपको किसी mature intrusion का संदेह है, तो दोनों करें: नई activity के लिए **real-time FIM** और trusted media से **cold baseline comparison**।
- यदि attacker के पास root या kernel execution है, तो मान लें कि FIM agent, उसका database और यहां तक कि event source के साथ भी tampering की जा सकती है। जब भी संभव हो, logs और baselines को remotely या read-only media पर store करें।

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [osquery के साथ File Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Linux को trace करना: एक file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck और whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
