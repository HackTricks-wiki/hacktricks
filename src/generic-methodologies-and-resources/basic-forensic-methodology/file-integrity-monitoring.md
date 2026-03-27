# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Kumbukumbu ya msingi

Kumbukumbu ya msingi inajumuisha kuchukua snapshot ya sehemu fulani za mfumo ili **kuizilinganisha na hali ya baadaye ili kuonyesha mabadiliko**.

Kwa mfano, unaweza kuhesabu na kuhifadhi hash ya kila faili ya filesystem ili uweze kujua ni faili gani zilibadilishwa.\
Hii pia inaweza kufanywa na akaunti za watumiaji zilizoundwa, michakato inayokimbia, huduma zinazoendesha na chochote kingine ambacho hakipaswi kubadilika sana, au kabisa.

Kumbukumbu ya msingi inayofaa kawaida huhifadhi zaidi ya digest tu: ruhusa, owner, group, timestamps, inode, symlink target, ACLs, na extended attributes zilizochaguliwa pia zinastahili kufuatiliwa. Kutoka mtazamo wa kuwinda mdukuzi, hili husaidia kugundua **permission-only tampering**, **atomic file replacement**, na **persistence via modified service/unit files** hata wakati content hash si kitu cha kwanza kinachobadilika.

### File Integrity Monitoring

File Integrity Monitoring (FIM) ni mbinu muhimu ya usalama inayolinda mazingira ya IT na data kwa kufuatilia mabadiliko kwenye faili. Kwa kawaida inachanganya:

1. **Baseline comparison:** Hifadhi metadata na cryptographic checksums (tumia `SHA-256` au bora zaidi) kwa ajili ya kulinganisha baadaye.
2. **Real-time notifications:** Jiandikishe kwa matukio ya faili ya asili ya OS ili ujue **faili gani ilibadilika, lini, na kwa wazo bora ni mchakato/mtumiaji gani aliughusu**.
3. **Periodic re-scan:** Jenga tena uaminifu baada ya reboots, matukio yaliyoporomoka, outages za agent, au shughuli zinazolenga kuzuia forensics.

For threat hunting, FIM is usually more useful when focused on **high-value paths** such as:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Backends za Wakati Halisi & Mapungufu

### Linux

The collection backend matters:

- **`inotify` / `fsnotify`**: rahisi na ya kawaida, lakini mipaka ya watch inaweza kuchoshwa na baadhi ya edge cases hupotea.
- **`auditd` / audit framework**: bora unapohitaji **who changed the file** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: chaguo mpya zinazotumika na stacks za kisasa za FIM kuongeza matukio na kupunguza baadhi ya matatizo ya uendeshaji ya deployments za plain `inotify`.

Baadhi ya mambo ya vitendo ya kuzingatia:

- Ikiwa programu **inabadilisha** faili kwa `write temp -> rename`, kuangalia faili lenyewe kunaweza kuacha kuwa na maana. **Angalia directory ya mzazi**, si faili tu.
- wakusanyaji wanaotegemea `inotify` wanaweza kupoteza au kudhoofika kwenye **mti mkubwa wa directories**, shughuli za **hard-link**, au baada ya **faili iliyotazamwa kufutwa**.
- Sets kubwa sana za recursive watch zinaweza kushindwa kimya ikiwa `fs.inotify.max_user_watches`, `max_user_instances`, au `max_queued_events` ni ndogo sana.
- Network filesystems kwa kawaida sio malengo mazuri ya FIM kwa monitoring yenye kelele ndogo.

Example baseline + verification with AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Mfano wa usanidi wa `osquery` FIM unaolenga attacker persistence paths:
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
If you need **utambulisho wa mchakato** badala ya mabadiliko ya ngazi ya path pekee, pendelea telemetry inayoungwa mkono na audit kama `osquery` `process_file_events` au Wazuh `whodata` mode.

### Windows

Kwenye Windows, FIM ni imara zaidi unapochanganya **rejista za mabadiliko** na **telemetry yenye ishara za juu za mchakato/mafayela**:

- **NTFS USN Journal** inatoa kumbukumbu endelevu kwa kila volume ya mabadiliko ya faili.
- **Sysmon Event ID 11** inafaa kwa uundaji/kuandikwa upya kwa faili.
- **Sysmon Event ID 2** husaidia kugundua **timestomping**.
- **Sysmon Event ID 15** inafaa kwa **named alternate data streams (ADS)** kama `Zone.Identifier` au hidden payload streams.

Quick USN triage examples:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
For deeper anti-forensic ideas around **timestamp manipulation**, **ADS abuse**, and **USN tampering**, check [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

FIM ya container mara nyingi hupoteza njia halisi ya kuandika. Kwa Docker `overlay2`, mabadiliko huwekwa kwenye container's **writable upper layer** (`upperdir`/`diff`), si kwenye read-only image layers. Kwa hivyo:

- Kufuatilia tu paths kutoka **inside** ya container yenye muda mfupi kunaweza kupoteza mabadiliko baada container kutengenezwa upya.
- Kufuatilia **host path** inayounga mkono writable layer au volume husika iliyowekwa kwa bind-mounted mara nyingi ni ya manufaa zaidi.
- FIM kwenye image layers ni tofauti na FIM kwenye running container filesystem.

## Vidokezo vya Utafutaji vinavyolenga Mshambuliaji

- Fuatilia **service definitions** na **task schedulers** kwa umakini kama binaries. Wavamizi mara nyingi hupata persistence kwa kubadilisha unit file, cron entry, au task XML badala ya kupachika `/bin/sshd`.
- Content hash pekee haitoshi. Mengi ya uvunjaji huonekana kwanza kama **owner/mode/xattr/ACL drift**.
- Kama unashuku uvamizi ulioendelea, fanya zote: **real-time FIM** kwa shughuli mpya na **cold baseline comparison** kutoka kwenye media inayotegemewa.
- Ikiwa mshambuliaji ana root au uwezo wa kutekeleza kernel, chukulia kuwa FIM agent, database yake, na hata chanzo cha tukio vinaweza kufanyiwa udanganyifu. Hifadhi logs na baselines kwa mbali au kwenye read-only media kadri inavyowezekana.

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
