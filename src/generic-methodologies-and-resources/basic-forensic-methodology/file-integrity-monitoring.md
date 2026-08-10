# Ufuatiliaji wa Uadilifu wa Faili

## Msingi

Msingi unahusisha kuchukua picha ya hali ya sehemu fulani za mfumo ili **kuulinganisha na hali ya baadaye na kuonyesha mabadiliko**.

Kwa mfano, unaweza kuhesabu na kuhifadhi hash ya kila faili katika mfumo wa faili ili uweze kubaini ni faili zipi zilibadilishwa.\
Hili pia linaweza kufanywa kwa akaunti za watumiaji zilizoundwa, michakato inayoendesha, services zinazoendesha na kitu kingine chochote ambacho hakipaswi kubadilika sana, au kabisa.

**Msingi wenye manufaa** kwa kawaida huhifadhi zaidi ya digest pekee: permissions, owner, group, timestamps, inode, symlink target, ACLs, na extended attributes zilizochaguliwa pia zinafaa kufuatiliwa.<sup>[[4]](#references)</sup> Kwa mtazamo wa kuwinda washambuliaji, hii husaidia kugundua **kuchezewa kwa permissions pekee**, **atomic file replacement**, na **persistence kupitia service/unit files zilizobadilishwa** hata wakati hash ya maudhui si kitu cha kwanza kubadilika.

### Ufuatiliaji wa Uadilifu wa Faili

File Integrity Monitoring (FIM) ni mbinu muhimu ya usalama inayolinda mazingira ya IT na data kwa kufuatilia mabadiliko katika faili. Kwa kawaida huchanganya:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Ulinganishaji wa msingi:** Hifadhi metadata na cryptographic checksums (pendelea `SHA-256` au bora zaidi) kwa ulinganishaji wa baadaye.
2. **Arifa za wakati halisi:** Jiandikishe kwenye matukio ya faili asilia ya OS ili kujua **ni faili gani ilibadilika, lini, na ikiwezekana ni mchakato/mtumiaji gani aliyeigusa**.
3. **Uchanganuzi wa mara kwa mara:** Jenga upya uhakika baada ya reboots, matukio yaliyopotea, agent outages, au shughuli za makusudi za anti-forensic.

Kwa threat hunting, FIM kwa kawaida huwa na manufaa zaidi inapolenga **high-value paths** kama vile:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Backends za Wakati Halisi na Mapengo ya Ufuatiliaji

### Linux

Backend ya ukusanyaji ni muhimu:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: ni rahisi na ya kawaida, lakini watch limits zinaweza kujaa na baadhi ya edge cases kukosa.
- **`auditd` / audit framework**: ni bora unapohitaji kujua **ni nani aliyebadilisha faili** (login UID, process ID, na process name).
- **`eBPF` / `kprobes`**: ni chaguo jipya zaidi linalotumiwa na FIM stacks za kisasa kuimarisha events na kupunguza baadhi ya changamoto za kiutendaji za deployments za kawaida za `inotify`.

Baadhi ya matatizo ya kivitendo:<sup>[[1]](#references)[[5]](#references)</sup>

- Ikiwa programu **inabadilisha** faili kwa `write temp -> rename`, kuangalia faili yenyewe kunaweza kutoendelea kuwa na manufaa. **Angalia parent directory**, si faili pekee.
- Collectors za `inotify` zinaweza kukosa au kudhoofika kwenye **miti mikubwa sana ya directories**, **hard-link activity**, au baada ya **faili inayofuatiliwa kufutwa**.
- Watch sets kubwa sana za recursive zinaweza kushindwa kimya kimya ikiwa `fs.inotify.max_user_watches`, `max_user_instances`, au `max_queued_events` ni ndogo sana.
- Kwa monitoring inayotegemea `inotify`, network filesystems ni blind spot kwa sababu mabadiliko ya mbali hayaripotiwi.

Mfano wa msingi + verification kwa kutumia AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Mfano wa usanidi wa `osquery` FIM unaolenga njia za persistence za attacker:<sup>[[1]](#references)</sup>
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
Ikiwa unahitaji **process attribution** badala ya mabadiliko ya kiwango cha path pekee, pendelea telemetry inayoungwa mkono na audit kama `osquery` `process_file_events` au Wazuh `whodata` mode.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Kwenye Windows, FIM huwa imara zaidi unapochanganya **change journals** na **high-signal process/file telemetry**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** hutoa logi endelevu ya kila volume kuhusu mabadiliko ya mafaili.
- **Sysmon Event ID 11** ni muhimu kwa kugundua uundaji/overwrite ya mafaili.
- **Sysmon Event ID 2** husaidia kugundua **timestomping**.
- **Sysmon Event ID 15** ni muhimu kwa **named alternate data streams (ADS)** kama vile `Zone.Identifier` au payload streams zilizofichwa.

Mifano ya haraka ya USN triage:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Kwa mawazo ya kina zaidi ya anti-forensics yanayohusu **timestamp manipulation**, **ADS abuse**, na **USN tampering**, angalia [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Makontena

Container FIM mara nyingi hukosa write path halisi. Kwa Docker `overlay2`, mfumo wa faili wa kontena unachanganya tabaka za image za kusomeka tu za `lowerdir` na **upper layer** inayoweza kuandikwa (`upperdir`/`diff`), na maandishi kwenye faili za image yanakiliwa hadi kwenye upper layer hiyo.<sup>[[8]](#references)</sup> Kwa hiyo:

- Kufuatilia paths zilizo **ndani** ya kontena linalodumu kwa muda mfupi kunaweza kukosa mabadiliko baada ya kontena kuundwa upya.
- Kufuatilia **host path** inayohifadhi writable layer au bind-mounted volume husika mara nyingi huwa na manufaa zaidi.
- FIM kwenye image layers ni tofauti na FIM kwenye mfumo wa faili wa kontena linaloendesha.

## Vidokezo vya Uwindaji Vinavyolenga Washambuliaji

- Fuatilia **service definitions** na **task schedulers** kwa umakini sawa na binaries. Washambuliaji mara nyingi hupata persistence kwa kurekebisha unit file, cron entry, au task XML badala ya kubandika `/bin/sshd`.
- Content hash pekee haitoshi. Compromise nyingi huanza kuonekana kama **owner/mode/xattr/ACL drift**.
- Ikiwa unashuku intrusion iliyokomaa, fanya yote mawili: **real-time FIM** kwa ajili ya shughuli mpya na **cold baseline comparison** kutoka kwenye trusted media.
- Ikiwa mshambuliaji ana root au kernel execution, ichukulie FIM agent na database yake kuwa zisizoaminika. Hifadhi logs na baselines kwa mbali au kwenye read-only media inapowezekana.<sup>[[4]](#references)</sup>

## Zana

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Kufuatilia Linux: Kisa cha matumizi cha ufuatiliaji wa uadilifu wa faili (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Ufuatiliaji wa Uadilifu wa Faili wa Wazuh (hali ya Syscheck na whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Mwongozo wa AIDE Toleo la 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Kiendeshi cha uhifadhi cha OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Mipangilio ya kina ya Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
