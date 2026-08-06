# Ufuatiliaji wa Uadilifu wa Faili

{{#include ../../banners/hacktricks-training.md}}

## Msingi

Msingi unahusisha kuchukua picha ya hali ya sehemu fulani za mfumo ili **kuilinganisha na hali ya baadaye na kubaini mabadiliko**.

Kwa mfano, unaweza kukokotoa na kuhifadhi hash ya kila faili katika mfumo wa faili ili kuweza kubaini ni faili zipi zilibadilishwa.\
Hili pia linaweza kufanywa kwa akaunti za watumiaji zilizoundwa, michakato inayoendelea, huduma zinazoendelea, na kitu kingine chochote ambacho hakipaswi kubadilika sana au kabisa.

**Msingi wenye manufaa** kwa kawaida huhifadhi zaidi ya digest pekee: ruhusa, mmiliki, kundi, timestamps, inode, lengwa la symlink, ACLs, na attributes za ziada zilizochaguliwa pia vinafaa kufuatiliwa. Kwa mtazamo wa kuwinda washambuliaji, hii husaidia kubaini **kuchezewa kwa ruhusa pekee**, **ubadilishaji wa faili wa atomic**, na **persistence kupitia faili za service/unit zilizobadilishwa**, hata wakati hash ya maudhui si kitu cha kwanza kubadilika.

### File Integrity Monitoring

File Integrity Monitoring (FIM) ni mbinu muhimu ya usalama inayolinda mazingira ya IT na data kwa kufuatilia mabadiliko katika faili. Kwa kawaida huchanganya:

1. **Ulinganishaji wa msingi:** Hifadhi metadata na checksums za cryptographic (pendelea `SHA-256` au bora zaidi) kwa ulinganishaji wa baadaye.
2. **Arifa za wakati halisi:** Jiandikishe kwenye matukio ya faili ya asili ya OS ili kujua **ni faili gani ilibadilika, lini, na ikiwezekana ni mchakato/mtumiaji gani aliyeigusa**.
3. **Uchanganuzi wa mara kwa mara:** Jenga upya uaminifu baada ya kuwasha upya mfumo, matukio yaliyopotea, kukatika kwa agent, au shughuli za makusudi za anti-forensic.

Kwa threat hunting, FIM kwa kawaida huwa na manufaa zaidi inapolenga **njia zenye thamani kubwa**, kama vile:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, maeneo ya cron, nyenzo za SSH, modules za PAM, mizizi ya wavuti
- Maeneo ya persistence ya Windows, binary za huduma, faili za scheduled task, mafolda ya startup
- Writable layers za container na secrets/configuration zilizowekwa kwa bind mount

## Backends za Wakati Halisi na Blind Spots

### Linux

Backend ya ukusanyaji ni muhimu:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: ni rahisi na ya kawaida, lakini mipaka ya watch inaweza kujaa na baadhi ya hali maalum hukosa.
- **`auditd` / audit framework**: ni bora unapohitaji kujua **ni nani aliyebadilisha faili** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: ni chaguo mpya zaidi zinazotumiwa na FIM stacks za kisasa ili kuongeza taarifa kwenye matukio na kupunguza baadhi ya changamoto za kiutendaji za deployments za kawaida za `inotify`.

Baadhi ya changamoto za kiutendaji:<sup>[[1]](#references)</sup>

- Ikiwa programu **inabadilisha** faili kwa `write temp -> rename`, ku-watch faili yenyewe kunaweza kusiwe na manufaa tena. **Watch parent directory**, si faili pekee.
- Collectors zinazotegemea `inotify` zinaweza kukosa au kudhoofika kwenye **directory trees kubwa sana**, **shughuli za hard-link**, au baada ya **faili inayotazamwa kufutwa**.
- Watch sets kubwa sana za recursive zinaweza kushindwa kimya kimya ikiwa `fs.inotify.max_user_watches`, `max_user_instances`, au `max_queued_events` ni ndogo sana.
- Network filesystems kwa kawaida si malengo mazuri ya FIM kwa monitoring yenye kelele ndogo.

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

Kwenye Windows, FIM huwa imara zaidi unapochanganya **change journals** na **high-signal process/file telemetry**:

- **NTFS USN Journal** hutoa logi endelevu ya kila volume kuhusu mabadiliko ya file.
- **Sysmon Event ID 11** ni muhimu kwa kuunda au ku-overwrite file.
- **Sysmon Event ID 2** husaidia kugundua **timestomping**.
- **Sysmon Event ID 15** ni muhimu kwa **named alternate data streams (ADS)** kama `Zone.Identifier` au streams zilizofichwa za payload.

Mifano ya haraka ya USN triage:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Kwa mawazo ya kina zaidi ya **timestamp manipulation**, **ADS abuse**, na **USN tampering** yanayohusu anti-forensics, angalia [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Container FIM mara nyingi hukosa njia halisi ya uandishi. Kwa Docker `overlay2`, mabadiliko huandikwa kwenye **writable upper layer** ya container (`upperdir`/`diff`), wala si kwenye image layers za kusoma tu. Kwa hiyo:

- Kufuatilia paths zilizo **ndani** ya container ya muda mfupi kunaweza kukosa mabadiliko baada ya container kuundwa upya.
- Kufuatilia **host path** inayohifadhi writable layer au bind-mounted volume husika mara nyingi huwa na manufaa zaidi.
- FIM kwenye image layers ni tofauti na FIM kwenye filesystem ya container inayoendesha.

## Vidokezo vya Hunting Vinavyomhusu Mshambuliaji

- Fuatilia **service definitions** na **task schedulers** kwa uangalifu sawa na binaries. Attackers mara nyingi hupata persistence kwa kurekebisha unit file, cron entry, au task XML badala ya kupatch `/bin/sshd`.
- Content hash pekee haitoshi. Compromises nyingi huanza kuonekana kama **owner/mode/xattr/ACL drift**.
- Ikiwa unashuku intrusion iliyokomaa, fanya yote mawili: **real-time FIM** kwa ajili ya activity mpya na **cold baseline comparison** kutoka kwenye trusted media.
- Ikiwa attacker ana root au kernel execution, chukulia kuwa FIM agent, database yake, na hata event source vinaweza kuchezewa. Hifadhi logs na baselines remotely au kwenye read-only media kila inapowezekana.

## Zana

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Marejeo

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
