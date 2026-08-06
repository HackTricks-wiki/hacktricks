# Ufuatiliaji wa Uadilifu wa Faili

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Baseline inahusisha kuchukua snapshot ya sehemu fulani za mfumo ili **kuilinganisha na hali ya baadaye na kuonyesha mabadiliko**.

Kwa mfano, unaweza kukokotoa na kuhifadhi hash ya kila faili kwenye filesystem ili uweze kubaini ni faili zipi zilirekebishwa.\
Hili pia linaweza kufanywa kwa akaunti za watumiaji zilizoundwa, processes zinazoendeshwa, services zinazoendeshwa na kitu kingine chochote ambacho hakipaswi kubadilika sana, au kabisa.

**Baseline muhimu** kwa kawaida huhifadhi zaidi ya digest pekee: permissions, owner, group, timestamps, inode, symlink target, ACLs, na extended attributes zilizochaguliwa pia zinafaa kufuatiliwa. Kwa mtazamo wa kuwinda washambuliaji, hili husaidia kubaini **kuchezewa kwa permissions pekee**, **kubadilishwa kwa faili atomically**, na **persistence kupitia service/unit files zilizorekebishwa** hata wakati content hash si kitu cha kwanza kubadilika.

### File Integrity Monitoring

File Integrity Monitoring (FIM) ni mbinu muhimu ya usalama inayolinda IT environments na data kwa kufuatilia mabadiliko kwenye faili. Kwa kawaida huchanganya:

1. **Baseline comparison:** Hifadhi metadata na cryptographic checksums (prefer `SHA-256` or better) kwa ajili ya comparisons za baadaye.
2. **Real-time notifications:** Jiandikishe kwenye OS-native file events ili kujua **ni faili gani ilibadilika, lini, na ikiwezekana ni process/user gani aliyeigusa**.
3. **Periodic re-scan:** Jenga upya uaminifu baada ya reboots, dropped events, agent outages, au deliberate anti-forensic activity.

Kwa threat hunting, FIM kwa kawaida huwa muhimu zaidi inapolenga **high-value paths** kama vile:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers na bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Collection backend ni muhimu:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: ni rahisi na ya kawaida, lakini watch limits zinaweza kujaa na baadhi ya edge cases hukosa.
- **`auditd` / audit framework**: ni bora unapohitaji kujua **ni nani aliyebadilisha faili** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: ni options mpya zaidi zinazotumiwa na FIM stacks za kisasa kuimarisha events na kupunguza baadhi ya changamoto za kiutendaji za deployments za kawaida za `inotify`.

Baadhi ya changamoto za kiutendaji:<sup>[[1]](#references)</sup>

- Ikiwa program **inabadilisha** faili kwa `write temp -> rename`, ku-watch faili yenyewe kunaweza kuacha kuwa na manufaa. **Watch parent directory**, si faili pekee.
- Collectors zinazotegemea `inotify` zinaweza kukosa au kudhoofika kwenye **huge directory trees**, **hard-link activity**, au baada ya **watched file kufutwa**.
- Recursive watch sets kubwa sana zinaweza kushindwa kimya kimya ikiwa `fs.inotify.max_user_watches`, `max_user_instances`, au `max_queued_events` ni ndogo sana.
- Network filesystems kwa kawaida si malengo mazuri ya FIM kwa low-noise monitoring.

Mfano wa baseline + verification kwa kutumia AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Mfano wa usanidi wa FIM wa `osquery` unaolenga njia za persistence za mshambuliaji:<sup>[[1]](#references)</sup>
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
Ikiwa unahitaji **process attribution** badala ya mabadiliko ya kiwango cha path pekee, pendelea telemetry inayoungwa mkono na audit kama `osquery` `process_file_events` au Wazuh `whodata` mode.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Kwenye Windows, FIM huwa na nguvu zaidi unapochanganya **change journals** na **high-signal process/file telemetry**:

- **NTFS USN Journal** hutoa logi endelevu ya kila volume ya mabadiliko ya faili.
- **Sysmon Event ID 11** ni muhimu kwa uundaji/overwrite ya faili.
- **Sysmon Event ID 2** husaidia kugundua **timestomping**.
- **Sysmon Event ID 15** ni muhimu kwa **named alternate data streams (ADS)** kama `Zone.Identifier` au streams zilizofichwa za payload.

Mifano ya haraka ya USN triage:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Kwa mawazo ya kina zaidi ya **anti-forensic** kuhusu **timestamp manipulation**, **ADS abuse**, na **USN tampering**, angalia [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Container FIM mara nyingi hukosa njia halisi ya kuandikia. Kwa Docker `overlay2`, mabadiliko huhifadhiwa kwenye **writable upper layer** ya container (`upperdir`/`diff`), si kwenye image layers za kusoma pekee. Kwa hivyo:

- Kufuatilia paths zilizo **ndani** ya container ya muda mfupi kunaweza kukosa mabadiliko baada ya container kuundwa upya.
- Kufuatilia **host path** inayohifadhi writable layer au bind-mounted volume husika mara nyingi huwa na manufaa zaidi.
- FIM kwenye image layers ni tofauti na FIM kwenye filesystem ya container inayoendesha.

## Attacker-Oriented Hunting Notes

- Fuatilia **service definitions** na **task schedulers** kwa umakini sawa na binaries. Attackers mara nyingi hupata persistence kwa kurekebisha unit file, cron entry, au task XML badala ya kurekebisha `/bin/sshd`.
- Content hash pekee haitoshi. Compromises nyingi hujitokeza kwanza kama **owner/mode/xattr/ACL drift**.
- Ikiwa unashuku intrusion iliyokomaa, fanya yote mawili: **real-time FIM** kwa shughuli mpya na **cold baseline comparison** kutoka trusted media.
- Ikiwa attacker ana root au kernel execution, chukulia kuwa FIM agent, database yake, na hata event source vinaweza kuchezewa. Hifadhi logs na baselines kwa mbali au kwenye read-only media inapowezekana.

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
