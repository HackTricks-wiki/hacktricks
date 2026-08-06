# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

'n Baseline bestaan uit die neem van 'n momentopname van sekere dele van 'n stelsel om dit met 'n toekomstige status te **vergelyk en veranderinge uit te lig**.

Byvoorbeeld, jy kan die hash van elke lêer van die filesystem bereken en stoor om vas te stel watter lêers gewysig is.\
Dit kan ook gedoen word met die gebruikerrekeninge wat geskep is, prosesse wat loop, dienste wat loop en enigiets anders wat nie veel, of glad nie, behoort te verander nie.

'n **Nuttige baseline** stoor gewoonlik meer as net 'n digest: permissions, eienaar, groep, timestamps, inode, symlink-teiken, ACLs en geselekteerde extended attributes is ook die moeite werd om te monitor. Vanuit 'n attacker-hunting-perspektief help dit om **slegs-permission-tampering**, **atomic file replacement** en **persistence via modified service/unit files** op te spoor, selfs wanneer die content hash nie die eerste ding is wat verander nie.

### File Integrity Monitoring

File Integrity Monitoring (FIM) is 'n kritieke sekuriteitstegniek wat IT-omgewings en data beskerm deur veranderinge in lêers te monitor. Dit kombineer gewoonlik:

1. **Baseline comparison:** Stoor metadata en kriptografiese checksums (verkieslik `SHA-256` of beter) vir toekomstige vergelykings.
2. **Real-time notifications:** Teken in op OS-native file events om te weet **watter lêer verander het, wanneer dit verander het en ideaal gesproke watter proses/gebruiker daaraan geraak het**.
3. **Periodic re-scan:** Herbou vertroue ná reboots, dropped events, agent outages of doelbewuste anti-forensic activity.

Vir threat hunting is FIM gewoonlik nuttiger wanneer dit op **high-value paths** gefokus word, soos:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron-liggings, SSH-materiaal, PAM-modules, web roots
- Windows persistence-liggings, service binaries, scheduled task files, startup folders
- Container writable layers en bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Die collection backend is belangrik:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: maklik en algemeen, maar watch limits kan uitgeput word en sommige edge cases word gemis.
- **`auditd` / audit framework**: beter wanneer jy nodig het om te weet **wie die lêer verander het** (`auid`, proses, pid, executable).
- **`eBPF` / `kprobes`**: nuwer opsies wat deur moderne FIM stacks gebruik word om events te verryk en sommige van die operasionele probleme van gewone `inotify` deployments te verminder.

Sommige praktiese gotchas:<sup>[[1]](#references)</sup>

- As 'n program 'n lêer **vervang** met `write temp -> rename`, kan dit ophou om nuttig te wees om die lêer self te monitor. **Monitor die parent directory**, nie net die lêer nie.
- `inotify`-gebaseerde collectors kan events mis of verswak op **enorme directory trees**, **hard-link activity** of nadat 'n **watched file deleted** is.
- Baie groot recursive watch sets kan stilweg faal as `fs.inotify.max_user_watches`, `max_user_instances` of `max_queued_events` te laag is.
- Network filesystems is gewoonlik swak FIM-teikens vir low-noise monitoring.

Voorbeeld van baseline + verification met AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Voorbeeld van ’n `osquery`-FIM-konfigurasie gefokus op aanvallers se persistence-paaie:<sup>[[1]](#references)</sup>
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
Indien jy **process attribution** benodig in plaas van slegs veranderinge op padvlak, verkies ouditgesteunde telemetrie soos `osquery` `process_file_events` of Wazuh se `whodata`-modus.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Op Windows is FIM sterker wanneer jy **change journals** met **high-signal process/file telemetry** kombineer:

- **NTFS USN Journal** verskaf ’n volgehoue logboek per volume van lêerveranderinge.
- **Sysmon Event ID 11** is nuttig vir lêerskepping en -oorwriting.
- **Sysmon Event ID 2** help om **timestomping** op te spoor.
- **Sysmon Event ID 15** is nuttig vir **named alternate data streams (ADS)** soos `Zone.Identifier` of versteekte payload-strome.

Vinnige USN-triage-voorbeelde:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Vir dieper anti-forensics-idees rondom **timestamp manipulation**, **ADS abuse**, en **USN tampering**, sien [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Houers

Container FIM mis dikwels die werklike skryfpad. Met Docker `overlay2` word veranderinge in die container se **writable upper layer** (`upperdir`/`diff`) toegepas, nie in die read-only image layers nie. Daarom:

- Monitering van slegs paaie **binne** ’n kortstondige container kan veranderinge mis nadat die container herskep is.
- Monitering van die **host path** wat die writable layer ondersteun, of van die relevante bind-mounted volume, is dikwels nuttiger.
- FIM op image layers verskil van FIM op die filesystem van die lopende container.

## Hunting-notas georiënteer op aanvallers

- Volg **service definitions** en **task schedulers** net so noukeurig soos binaries. Aanvallers verkry dikwels persistence deur ’n unit file, cron entry, of task XML te wysig, eerder as om `/bin/sshd` te patch.
- ’n Content hash alleen is onvoldoende. Baie compromises word aanvanklik sigbaar as **owner/mode/xattr/ACL drift**.
- As jy ’n volwasse intrusion vermoed, doen albei: **real-time FIM** vir vars aktiwiteit en ’n **cold baseline comparison** vanaf trusted media.
- As die aanvaller root- of kernel execution het, aanvaar dat die FIM-agent, sy databasis, en selfs die event source gemanipuleer kan word. Stoor logs en baselines op afstand of op read-only media waar moontlik.

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Verwysings

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
