# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Baseline में किसी system के कुछ हिस्सों का snapshot लेना शामिल होता है, ताकि **भविष्य की स्थिति से इसकी तुलना करके बदलावों को उजागर किया जा सके**।

उदाहरण के लिए, आप filesystem की प्रत्येक file का hash calculate और store कर सकते हैं, ताकि पता लगाया जा सके कि कौन-सी files modify हुई हैं।\
यह user accounts, running processes, running services और ऐसी किसी भी अन्य चीज़ के साथ भी किया जा सकता है, जिसमें बहुत कम या बिल्कुल भी बदलाव नहीं होना चाहिए।

एक **useful baseline** आमतौर पर केवल digest से अधिक जानकारी store करता है: permissions, owner, group, timestamps, inode, symlink target, ACLs और चुने गए extended attributes को track करना भी उपयोगी होता है।<sup>[[4]](#references)</sup> Attacker-hunting के दृष्टिकोण से, इससे **केवल permissions के साथ की गई छेड़छाड़**, **atomic file replacement**, और **modified service/unit files के माध्यम से persistence** का पता लगाने में मदद मिलती है, भले ही बदलने वाली पहली चीज़ content hash न हो।

### File Integrity Monitoring

File Integrity Monitoring (FIM) files में होने वाले बदलावों को track करके IT environments और data की सुरक्षा करने वाली एक critical security technique है। यह आमतौर पर निम्नलिखित को combine करता है:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Baseline comparison:** भविष्य की comparisons के लिए metadata और cryptographic checksums (अधिमानतः `SHA-256` या बेहतर) store करें।
2. **Real-time notifications:** OS-native file events को subscribe करें, ताकि पता चल सके कि **कौन-सी file बदली, कब बदली और ideally किस process/user ने उसे access किया**।
3. **Periodic re-scan:** reboots, dropped events, agent outages या deliberate anti-forensic activity के बाद confidence को फिर से establish करें।

Threat hunting के लिए, FIM आमतौर पर **high-value paths** पर focused होने पर अधिक useful होता है, जैसे:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers और bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Collection backend महत्वपूर्ण होता है:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: आसान और common हैं, लेकिन watch limits exhaust हो सकती हैं और कुछ edge cases miss हो जाते हैं।
- **`auditd` / audit framework**: जब आपको यह जानना हो कि **file किसने बदली** (login UID, process ID और process name), तब बेहतर होता है।
- **`eBPF` / `kprobes`**: modern FIM stacks द्वारा events को enrich करने और plain `inotify` deployments की कुछ operational समस्याओं को कम करने के लिए उपयोग किए जाने वाले नए options।

कुछ practical gotchas:<sup>[[1]](#references)[[5]](#references)</sup>

- यदि कोई program `write temp -> rename` के माध्यम से किसी file को **replace** करता है, तो केवल file को watch करना उपयोगी नहीं रह सकता। **केवल file को नहीं, बल्कि उसकी parent directory को watch करें।**
- `inotify`-based collectors **बहुत बड़े directory trees**, **hard-link activity** के दौरान या **watched file delete होने के बाद** miss या degrade कर सकते हैं।
- यदि `fs.inotify.max_user_watches`, `max_user_instances` या `max_queued_events` की values बहुत कम हों, तो बहुत बड़े recursive watch sets silently fail हो सकते हैं।
- `inotify`-based monitoring के लिए network filesystems एक blind spot हैं, क्योंकि remote changes report नहीं किए जाते।

AIDE के साथ baseline + verification का उदाहरण:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
attacker persistence paths पर केंद्रित `osquery` FIM configuration का उदाहरण:<sup>[[1]](#references)</sup>
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
यदि आपको केवल path-level changes के बजाय **process attribution** की आवश्यकता है, तो `osquery` `process_file_events` या Wazuh `whodata` mode जैसी audit-backed telemetry को प्राथमिकता दें।<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: syscall telemetry, FIM नहीं है

आधुनिक Linux पर `openat(2)`, `write(2)` या अन्य syscall entry points को देखना **परिणामी filesystem operation की monitoring के बराबर नहीं है**। 2025 के **Curing** proof of concept ने `io_uring` के माध्यम से file और network requests को queue किया, इसलिए केवल संबंधित per-operation syscall entries से जुड़े products या policies ने process telemetry खो दी। उन्हीं tests में, path-scoped FIM component ने file modifications को फिर भी observe किया, जिससे पता चलता है कि यह **hook-placement blind spot** है, न कि permission bypass या हर FIM backend को defeat करने का तरीका।<sup>[[10]](#references)</sup>

किसी sensor को validate करते समय, उसी canary को कई paths के माध्यम से modify करें: सामान्य `write`, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, atomic replacement और `io_uring`। केवल यह न जाँचें कि final hash drift detect हुआ है या नहीं, बल्कि यह भी जाँचें कि event में responsible process, container/cgroup, namespace-visible path, inode और rename pair सुरक्षित हैं या नहीं। Periodic-scan mismatch के बाद missing real-time event को **telemetry loss** माना जाना चाहिए, न कि नियमित रूप से होने वाला अस्पष्ट change।<sup>[[10]](#references)[[11]](#references)</sup>

eBPF-based monitoring के लिए syscall-entry probes की सूची के बजाय common kernel enforcement points को प्राथमिकता दें। उदाहरण के लिए, Tetragon की file-access policy ordinary I/O, `sendfile`, `copy_file_range`, AIO और `io_uring` को cover करने के लिए `security_file_permission` का उपयोग करती है; यह memory mappings को `security_mmap_file` और size changes को `security_path_truncate` के माध्यम से अलग से cover करती है। यह भी दर्शाता है कि complete coverage के लिए एक hook शायद ही पर्याप्त होता है।<sup>[[11]](#references)</sup>

### Windows

Windows पर, **change journals** को **high-signal process/file telemetry** के साथ combine करने पर FIM अधिक मजबूत होता है:<sup>[[6]](#references)[[7]](#references)</sup>

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

Container FIM अक्सर वास्तविक write path को miss कर देता है। Docker `overlay2` के साथ, container filesystem read-only image `lowerdir` layers को writable **upper layer** (`upperdir`/`diff`) के साथ जोड़ता है, और image files पर होने वाले writes इस upper layer में copy up किए जाते हैं।<sup>[[8]](#references)</sup> इसलिए:

- केवल किसी short-lived container के **अंदर** के paths को monitor करने पर container के दोबारा बनाए जाने के बाद होने वाले changes छूट सकते हैं।
- writable layer के पीछे मौजूद **host path** या संबंधित bind-mounted volume को monitor करना अक्सर अधिक उपयोगी होता है।
- Image layers पर FIM, running container filesystem पर FIM से अलग होता है।

## Attacker-Oriented Hunting Notes

- **service definitions** और **task schedulers** को binaries की तरह ही सावधानी से track करें। Attackers अक्सर `/bin/sshd` को patch करने के बजाय unit file, cron entry, या task XML को modify करके persistence प्राप्त करते हैं।
- केवल content hash पर्याप्त नहीं है। कई compromises सबसे पहले **owner/mode/xattr/ACL drift** के रूप में दिखाई देते हैं।
- यदि आपको mature intrusion का संदेह है, तो दोनों करें: नई activity के लिए **real-time FIM** और trusted media से **cold baseline comparison**।
- यदि attacker के पास root या kernel execution है, तो FIM agent और उसके database को untrusted मानें। जब भी संभव हो, logs और baselines को remotely या read-only media पर store करें।<sup>[[4]](#references)</sup>

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [osquery के साथ File Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Linux को trace करना: एक file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck और whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE Manual Version 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux manual page](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS storage driver](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [io_uring Rootkit Linux Security Tools को bypass करता है (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Filename access: synchronous, asynchronous, mapped और truncation paths को cover करना (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
