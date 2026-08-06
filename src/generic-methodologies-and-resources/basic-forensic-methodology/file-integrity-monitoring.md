# Monitering van lêerintegriteit

{{#include ../../banners/hacktricks-training.md}}

## Basislyn

'n Basislyn bestaan uit die neem van 'n momentopname van sekere dele van 'n stelsel om dit met 'n toekomstige status te **vergelyk om veranderinge uit te lig**.

Byvoorbeeld, jy kan die hash van elke lêer van die lêerstelsel bereken en stoor om vas te stel watter lêers gewysig is.\
Dit kan ook gedoen word met die gebruikersrekeninge wat geskep is, prosesse wat loop, dienste wat loop en enigiets anders wat nie veel, of glad nie, behoort te verander nie.

'n **Nuttige basislyn** stoor gewoonlik meer as net 'n digest: toestemmings, eienaar, groep, tydstempels, inode, simlink-teiken, ACL's en geselekteerde uitgebreide attribute is ook die moeite werd om na te spoor. Vanuit 'n aanvallerjag-perspektief help dit om **peutering wat slegs toestemmings verander**, **atomiese lêervervanging** en **volharding via gewysigde diens-/unit-lêers** op te spoor, selfs wanneer die inhoudshash nie die eerste ding is wat verander nie.

### Monitering van lêerintegriteit

File Integrity Monitoring (FIM) is 'n kritieke sekuriteitstegniek wat IT-omgewings en data beskerm deur veranderinge in lêers na te spoor. Dit kombineer gewoonlik:

1. **Basislynvergelyking:** Stoor metadata en kriptografiese checksums (verkieslik `SHA-256` of beter) vir toekomstige vergelykings.
2. **Intydse kennisgewings:** Teken in op OS-inheemse lêergebeurtenisse om te weet **watter lêer verander het, wanneer dit verander het en ideaal gesproke watter proses/gebruiker daaraan geraak het**.
3. **Periodieke herskandering:** Herstel vertroue ná herselflaaie, verlore gebeurtenisse, agentonderbrekings of doelbewuste anti-forensiese aktiwiteit.

Vir threat hunting is FIM gewoonlik nuttiger wanneer dit op **paaie met hoë waarde** gefokus is, soos:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd`-units, cron-liggings, SSH-materiaal, PAM-modules, webroots
- Windows-volhardingsliggings, diensbinêre lêers, geskeduleerde taaklêers, opstartvouers
- Houer-skryfbare lae en bind-gemonteerde geheime/konfigurasie

## Intydse Backends & Blinde Vlekke

### Linux

Die versamelingsbackend is belangrik:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: maklik en algemeen, maar kykbeperkings kan uitgeput word en sommige randgevalle word gemis.
- **`auditd` / audit framework**: beter wanneer jy nodig het om te weet **wie die lêer verander het** (`auid`, proses, pid, uitvoerbare lêer).
- **`eBPF` / `kprobes`**: nuwer opsies wat deur moderne FIM-stapels gebruik word om gebeurtenisse te verryk en sommige van die operasionele probleme van gewone `inotify`-ontplooiings te verminder.

Enkele praktiese slaggate:<sup>[[1]](#references)</sup>

- As 'n program 'n lêer **vervang** met `write temp -> rename`, kan dit ophou nuttig wees om die lêer self dop te hou. **Hou die ouer-gids dop**, nie net die lêer nie.
- `inotify`-gebaseerde versamelaars kan gebeurtenisse mis of swakker funksioneer met **enorme gidsbome**, **hard-link-aktiwiteit** of nadat 'n **lêer waarop gewag word, uitgevee is**.
- Baie groot rekursiewe kykstelle kan stilweg misluk as `fs.inotify.max_user_watches`, `max_user_instances` of `max_queued_events` te laag is.
- Netwerklêerstelsels is gewoonlik swak FIM-teikens vir monitering met min geraas.

Voorbeeld van 'n basislyn + verifikasie met AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Voorbeeld van `osquery` FIM-konfigurasie gefokus op aanvaller-volhardingspaaie:<sup>[[1]](#references)</sup>
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
Indien jy **process attribution** benodig in plaas van slegs path-level changes, verkies audit-backed telemetry soos `osquery` `process_file_events` of Wazuh `whodata`-modus.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Op Windows is FIM sterker wanneer jy **change journals** met **high-signal process/file telemetry** kombineer:

- **NTFS USN Journal** verskaf ’n permanente per-volume logboek van lêerveranderinge.
- **Sysmon Event ID 11** is nuttig vir lêerskepping/-oorskrywing.
- **Sysmon Event ID 2** help om **timestomping** op te spoor.
- **Sysmon Event ID 15** is nuttig vir **named alternate data streams (ADS)** soos `Zone.Identifier` of versteekte payload streams.

Vinnige USN-triage-voorbeelde:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Vir meer diepgaande anti-forensic-idees rondom **timestamp manipulation**, **ADS abuse** en **USN tampering**, raadpleeg [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Houers

Container FIM mis dikwels die werklike skryfpad. Met Docker `overlay2` word veranderinge in die container se **writable upper layer** (`upperdir`/`diff`) toegepas, nie in die read-only image layers nie. Daarom:

- Monitering van slegs paaie **binne** 'n kortlewende container kan veranderinge miskyk nadat die container herskep is.
- Monitering van die **host path** wat die writable layer ondersteun, of van die relevante bind-mounted volume, is dikwels nuttiger.
- FIM op image layers verskil van FIM op die lêerstelsel van die lopende container.

## Hunting-notas gerig op aanvallers

- Volg **service definitions** en **task schedulers** net so noukeurig soos binaries. Aanvallers verkry dikwels persistence deur 'n unit file, cron entry of task XML te wysig eerder as om `/bin/sshd` te patch.
- 'n Content hash alleen is onvoldoende. Baie kompromitterings word aanvanklik sigbaar as **owner/mode/xattr/ACL drift**.
- As jy 'n gevorderde intrusion vermoed, doen albei: **real-time FIM** vir vars aktiwiteit en 'n **cold baseline comparison** vanaf trusted media.
- As die aanvaller root- of kernel-execution het, aanvaar dat die FIM-agent, sy databasis en selfs die event source gemanipuleer kan word. Stoor logs en baselines waar moontlik op afstand of op read-only media.

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
