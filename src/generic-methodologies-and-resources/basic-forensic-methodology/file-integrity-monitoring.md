# Ufuatiliaji wa Uadilifu wa Faili

{{#include ../../banners/hacktricks-training.md}}

## Msingi

Msingi unahusisha kuchukua snapshot ya sehemu fulani za mfumo ili **kuulinganisha na hali ya baadaye na kuonyesha mabadiliko**.

Kwa mfano, unaweza kukokotoa na kuhifadhi hash ya kila faili kwenye filesystem ili uweze kubaini ni faili zipi zilibadilishwa.\
Hili pia linaweza kufanywa kwa akaunti za watumiaji zilizoundwa, processes zinazoendesha, services zinazoendesha na kitu kingine chochote ambacho hakipaswi kubadilika sana, au kabisa.

Msingi **muhimu** kwa kawaida huhifadhi zaidi ya digest pekee: permissions, owner, group, timestamps, inode, symlink target, ACLs, na extended attributes zilizochaguliwa pia zinafaa kufuatiliwa.<sup>[[4]](#references)</sup> Kwa mtazamo wa kuwinda washambuliaji, hii husaidia kugundua **kuchezewa kwa permissions pekee**, **atomic file replacement**, na **persistence kupitia service/unit files zilizobadilishwa**, hata wakati content hash si kitu cha kwanza kubadilika.

### Ufuatiliaji wa Uadilifu wa Faili

File Integrity Monitoring (FIM) ni mbinu muhimu ya usalama inayolinda mazingira ya IT na data kwa kufuatilia mabadiliko kwenye files. Kwa kawaida huchanganya:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Ulinganishaji wa msingi:** Hifadhi metadata na cryptographic checksums (ikiwezekana `SHA-256` au bora zaidi) kwa ulinganishaji wa baadaye.
2. **Arifa za wakati halisi:** Jiandikishe kwenye OS-native file events ili kujua **ni faili ipi iliyobadilika, lini, na ikiwezekana ni process/user gani aliyeigusa**.
3. **Uchanganuzi upya wa mara kwa mara:** Jenga tena imani baada ya reboots, dropped events, agent outages, au deliberate anti-forensic activity.

Kwa threat hunting, FIM huwa muhimu zaidi inapolenga **high-value paths** kama vile:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Backend ya ukusanyaji ni muhimu:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: ni rahisi na ya kawaida, lakini watch limits zinaweza kujaa na baadhi ya edge cases hukosa.
- **`auditd` / audit framework**: ni bora unapohitaji kujua **nani aliyebadilisha faili** (login UID, process ID, na process name).
- **`eBPF` / `kprobes`**: ni chaguo mpya zinazotumiwa na FIM stacks za kisasa kuboresha events na kupunguza baadhi ya changamoto za kiutendaji za deployments za kawaida za `inotify`.

Baadhi ya changamoto za kiutendaji:<sup>[[1]](#references)[[5]](#references)</sup>

- Ikiwa program **inabadilisha** faili kwa `write temp -> rename`, kuangalia faili yenyewe kunaweza kuacha kuwa na manufaa. **Angalia parent directory**, si faili pekee.
- Collectors zinazotegemea `inotify` zinaweza kukosa au kudhoofika kwenye **huge directory trees**, **hard-link activity**, au baada ya **watched file kufutwa**.
- Recursive watch sets kubwa sana zinaweza kushindwa kimya kimya ikiwa `fs.inotify.max_user_watches`, `max_user_instances`, au `max_queued_events` ni ndogo sana.
- Kwa monitoring inayotegemea `inotify`, network filesystems ni blind spot kwa sababu mabadiliko ya mbali hayaripotiwi.

Mfano wa baseline + verification kwa kutumia AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Mfano wa usanidi wa `osquery` wa FIM unaolenga njia za persistence za mshambuliaji:<sup>[[1]](#references)</sup>
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
Ikiwa unahitaji **process attribution** badala ya mabadiliko ya kiwango cha path pekee, pendelea telemetry inayotegemea audit kama `osquery` `process_file_events` au Wazuh `whodata` mode.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Kwenye Windows, FIM huwa imara zaidi unapochanganya **change journals** na **high-signal process/file telemetry**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** hutoa logi endelevu ya mabadiliko ya files kwa kila volume.
- **Sysmon Event ID 11** ni muhimu kwa file creation/overwrite.
- **Sysmon Event ID 2** husaidia kugundua **timestomping**.
- **Sysmon Event ID 15** ni muhimu kwa **named alternate data streams (ADS)** kama `Zone.Identifier` au hidden payload streams.

Mifano ya haraka ya USN triage:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Kwa mawazo ya kina zaidi ya **anti-forensics** kuhusu **timestamp manipulation**, **ADS abuse**, na **USN tampering**, angalia [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Container FIM mara nyingi hukosa njia halisi ya uandishi. Kwa Docker `overlay2`, mfumo wa faili wa container huunganisha tabaka za image za kusoma pekee `lowerdir` na **upper layer** inayoweza kuandikwa (`upperdir`/`diff`), na uandishi kwenye faili za image hunakiliwa hadi kwenye upper layer hiyo.<sup>[[8]](#references)</sup> Kwa hiyo:

- Kufuatilia njia zilizo **ndani** ya container ya muda mfupi kunaweza kukosa mabadiliko baada ya container kuundwa upya.
- Kufuatilia **host path** inayohifadhi writable layer au volume husika iliyounganishwa kwa bind mara nyingi huwa na manufaa zaidi.
- FIM kwenye image layers ni tofauti na FIM kwenye mfumo wa faili wa container inayoendesha.

## Vidokezo vya Hunting Vinavyolenga Attacker

- Fuatilia **service definitions** na **task schedulers** kwa umakini sawa na binaries. Attackers mara nyingi hupata persistence kwa kurekebisha unit file, cron entry, au task XML badala ya kurekebisha `/bin/sshd`.
- Content hash pekee haitoshi. Compromises nyingi hujitokeza kwanza kama **owner/mode/xattr/ACL drift**.
- Ikiwa unashuku intrusion iliyokomaa, fanya yote mawili: **real-time FIM** kwa activity mpya na **cold baseline comparison** kutoka kwenye trusted media.
- Ikiwa attacker ana root au kernel execution, chukulia FIM agent na database yake kuwa si za kuaminika. Hifadhi logs na baselines kwa mbali au kwenye read-only media kila inapowezekana.<sup>[[4]](#references)</sup>

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Kufuatilia Linux: Kesi ya matumizi ya file integrity monitoring (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (hali za Syscheck na whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Mwongozo wa AIDE Toleo la 0.16.2](https://aide.github.io/doc/)
- [5] [Ukurasa wa mwongozo wa inotify(7) Linux](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Kiendeshi cha uhifadhi cha OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Mipangilio ya kina ya Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
