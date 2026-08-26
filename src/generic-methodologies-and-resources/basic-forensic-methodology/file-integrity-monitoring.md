# Ufuatiliaji wa Uadilifu wa Faili

{{#include ../../banners/hacktricks-training.md}}

## Msingi

Msingi unahusisha kuchukua snapshot ya sehemu fulani za mfumo ili **kuilinganisha na hali ya baadaye na kuonyesha mabadiliko**.

Kwa mfano, unaweza kuhesabu na kuhifadhi hash ya kila faili katika filesystem ili kuweza kubaini ni faili zipi zilibadilishwa.\
Hili pia linaweza kufanywa kwa user accounts zilizoundwa, processes zinazoendesha, services zinazoendesha na kitu kingine chochote ambacho hakipaswi kubadilika sana au kabisa.

**Msingi unaofaa** kwa kawaida huhifadhi zaidi ya digest pekee: permissions, owner, group, timestamps, inode, symlink target, ACLs, na extended attributes zilizochaguliwa pia zinafaa kufuatiliwa.<sup>[[4]](#references)</sup> Kwa mtazamo wa kuwinda attackers, hii husaidia kubaini **tampering inayohusu permissions pekee**, **atomic file replacement**, na **persistence kupitia service/unit files zilizobadilishwa** hata wakati content hash si kitu cha kwanza kubadilika.

### File Integrity Monitoring

File Integrity Monitoring (FIM) ni mbinu muhimu ya usalama inayolinda IT environments na data kwa kufuatilia mabadiliko katika faili. Kwa kawaida huchanganya:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Ulinganishaji wa msingi:** Hifadhi metadata na cryptographic checksums (pendelea `SHA-256` au bora zaidi) kwa ajili ya ulinganishaji wa baadaye.
2. **Arifa za wakati halisi:** Jiandikishe kupokea OS-native file events ili kujua **ni faili gani ilibadilika, lini, na ikiwezekana ni process/user gani aliyeigusa**.
3. **Uchanganuzi upya wa mara kwa mara:** Jenga upya uaminifu baada ya reboots, dropped events, agent outages, au deliberate anti-forensic activity.

Kwa threat hunting, FIM kwa kawaida huwa na manufaa zaidi inapolenga **high-value paths** kama vile:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers na bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Collection backend ni muhimu:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: ni rahisi na ya kawaida, lakini watch limits zinaweza kujaa na baadhi ya edge cases hazigunduliwi.
- **`auditd` / audit framework**: ni bora unapohitaji kujua **ni nani aliyebadilisha faili** (login UID, process ID, na process name).
- **`eBPF` / `kprobes`**: ni chaguo mpya zinazotumiwa na FIM stacks za kisasa ili kuongeza taarifa kwenye events na kupunguza baadhi ya changamoto za kiutendaji za deployments zinazotumia `inotify` pekee.

Baadhi ya changamoto za kiutendaji:<sup>[[1]](#references)[[5]](#references)</sup>

- Ikiwa program **inabadilisha** faili kwa kutumia `write temp -> rename`, kufuatilia faili yenyewe kunaweza kukosa manufaa. **Fuatilia parent directory**, si faili pekee.
- Collectors wanaotumia `inotify` wanaweza kukosa au kudhoofika kwenye **huge directory trees**, **hard-link activity**, au baada ya **watched file kufutwa**.
- Recursive watch sets kubwa sana zinaweza kushindwa kimya kimya ikiwa `fs.inotify.max_user_watches`, `max_user_instances`, au `max_queued_events` ni ndogo sana.
- Kwa monitoring inayotumia `inotify`, network filesystems ni blind spot kwa sababu mabadiliko ya mbali hayaripotiwi.

Mfano wa baseline + verification kwa kutumia AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Mfano wa usanidi wa `osquery` FIM unaolenga njia za persistence za mshambuliaji:<sup>[[1]](#references)</sup>
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
Ikiwa unahitaji **process attribution** badala ya mabadiliko ya kiwango cha path pekee, pendelea telemetry inayotegemea audit kama `osquery` `process_file_events` au hali ya `whodata` ya Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: syscall telemetry si FIM

Kwenye Linux za kisasa, kufuatilia sehemu za kuingilia za `openat(2)`, `write(2)`, au syscall nyingine si **sawa na kufuatilia operesheni ya filesystem inayotokana nayo**. Proof of concept ya **Curing** ya mwaka 2025 iliweka foleni ya maombi ya file na network kupitia `io_uring`, hivyo products au policies zilizounganishwa kwenye sehemu za kuingilia za syscall za kila operesheni pekee zilipoteza process telemetry. Katika majaribio hayo hayo, component ya FIM iliyowekewa scope ya path bado iliona marekebisho ya file, ikionyesha kuwa hili ni **pengo la mahali hook ilipowekwa**, si bypass ya permissions wala njia ya kushinda kila FIM backend.<sup>[[10]](#references)</sup>

Unapovalidate sensor, modify canary hiyo hiyo kupitia paths kadhaa: `write` ya kawaida, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, atomic replacement, na `io_uring`. Kagua si tu kama hash drift ya mwisho imegunduliwa, bali pia kama event inahifadhi process inayohusika, container/cgroup, path inayoonekana ndani ya namespace, inode, na rename pair. Event ya real-time inayokosekana ikifuatiwa na mismatch ya periodic scan inapaswa kuchukuliwa kama **upotevu wa telemetry**, si mabadiliko ya kawaida yasiyoelezeka.<sup>[[10]](#references)[[11]](#references)</sup>

Kwa monitoring inayotegemea eBPF, pendelea sehemu za kawaida za kernel enforcement kuliko orodha ya probes za syscall-entry. Kwa mfano, file-access policy ya Tetragon hutumia `security_file_permission` kufunika I/O ya kawaida, `sendfile`, `copy_file_range`, AIO, na `io_uring`; pia hufunika memory mappings kando kwa `security_mmap_file` na mabadiliko ya size kwa `security_path_truncate`. Hili pia linaonyesha kwa nini hook moja mara chache hutoa coverage kamili.<sup>[[11]](#references)</sup>

### Windows

Kwenye Windows, FIM huwa imara zaidi unapochanganya **change journals** na **high-signal process/file telemetry**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** hutoa logi endelevu ya kila volume kuhusu mabadiliko ya file.
- **Sysmon Event ID 11** ni muhimu kwa file creation/overwrite.
- **Sysmon Event ID 2** husaidia kugundua **timestomping**.
- **Sysmon Event ID 15** ni muhimu kwa **named alternate data streams (ADS)** kama `Zone.Identifier` au payload streams zilizofichwa.

Mifano ya haraka ya USN triage:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Kwa mawazo ya kina zaidi ya anti-forensics kuhusu **timestamp manipulation**, **ADS abuse**, na **USN tampering**, angalia [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Container FIM mara nyingi hukosa njia halisi ya uandishi. Kwa Docker `overlay2`, mfumo wa faili wa container huunganisha tabaka za picha za kusoma-tu `lowerdir` na **upper layer** inayoweza kuandikwa (`upperdir`/`diff`), na uandishi kwenye faili za picha hunakiliwa hadi kwenye upper layer hiyo.<sup>[[8]](#references)</sup> Kwa hiyo:

- Kufuatilia tu njia zilizo **ndani** ya container ya muda mfupi kunaweza kukosa mabadiliko baada ya container kuundwa upya.
- Kufuatilia **host path** inayohifadhi writable layer au volume husika iliyowekwa kwa bind mount mara nyingi huwa na manufaa zaidi.
- FIM kwenye image layers ni tofauti na FIM kwenye mfumo wa faili wa container inayoendesha.

## Vidokezo vya Hunting Vinavyolenga Mshambuliaji

- Fuatilia **service definitions** na **task schedulers** kwa umakini sawa na binaries. Attackers mara nyingi hupata persistence kwa kurekebisha unit file, cron entry, au task XML badala ya kupachika `/bin/sshd`.
- Content hash pekee haitoshi. Compromises nyingi hujitokeza kwanza kama **owner/mode/xattr/ACL drift**.
- Ikiwa unashuku intrusion iliyokomaa, fanya yote mawili: **real-time FIM** kwa shughuli mpya na **cold baseline comparison** kutoka kwenye trusted media.
- Ikiwa attacker ana root au kernel execution, chukulia FIM agent na database yake kuwa zisizoaminika. Hifadhi logs na baselines kwa mbali au kwenye read-only media inapowezekana.<sup>[[4]](#references)</sup>

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Ufuatiliaji wa Uadilifu wa Faili kwa osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Kufuatilia Linux: Kisa cha matumizi ya ufuatiliaji wa uadilifu wa faili (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Ufuatiliaji wa Uadilifu wa Faili wa Wazuh (hali ya Syscheck na whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Mwongozo wa AIDE Toleo la 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Kiendeshi cha hifadhi cha OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Mipangilio ya kina ya Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [io_uring Rootkit Inazipita Linux Security Tools (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Ufikiaji wa filename: kushughulikia njia za synchronous, asynchronous, mapped, na truncation (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
