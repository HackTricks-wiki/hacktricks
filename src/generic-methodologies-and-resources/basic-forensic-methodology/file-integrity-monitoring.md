# Monitering van lêerintegriteit

{{#include ../../banners/hacktricks-training.md}}

## Basislyn

’n Basislyn bestaan daaruit om ’n momentopname van sekere dele van ’n stelsel te neem om dit **met ’n toekomstige toestand te vergelyk en veranderinge uit te lig**.

Byvoorbeeld, jy kan die hash van elke lêer in die lêerstelsel bereken en stoor om vas te stel watter lêers gewysig is.\
Dit kan ook gedoen word met die gebruikerrekeninge wat geskep is, prosesse wat loop, dienste wat loop, en enigiets anders wat nie veel, of glad nie, behoort te verander nie.

’n **Nuttige basislyn** stoor gewoonlik meer as net ’n digest: toestemmings, eienaar, groep, tydstempels, inode, simboliese skakel-teiken, ACL’s en geselekteerde uitgebreide eienskappe is ook die moeite werd om na te spoor.<sup>[[4]](#references)</sup> Vanuit ’n aanvallerjagperspektief help dit om **peutery wat slegs toestemmings verander**, **atomiese lêervervanging** en **volharding via gewysigde diens-/unit-lêers** op te spoor, selfs wanneer die inhoudshash nie die eerste ding is wat verander nie.

### Monitering van lêerintegriteit

File Integrity Monitoring (FIM) is ’n kritieke sekuriteitstegniek wat IT-omgewings en data beskerm deur veranderinge in lêers na te spoor. Dit kombineer gewoonlik:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Basislynvergelyking:** Stoor metadata en kriptografiese checksums (verkieslik `SHA-256` of beter) vir toekomstige vergelykings.
2. **Intydse kennisgewings:** Teken in op OS-eie lêergebeurtenisse om te weet **watter lêer verander het, wanneer dit verander het, en ideaal gesproke watter proses/gebruiker daaraan geraak het**.
3. **Periodieke herskandering:** Herstel vertroue ná herbeginsels, verlore gebeurtenisse, agentonderbrekings of doelbewuste anti-forensiese aktiwiteit.

Vir threat hunting is FIM gewoonlik nuttiger wanneer dit op **hoëwaarde-paaie** gefokus word, soos:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron-liggings, SSH-materiaal, PAM-modules, webwortels
- Windows-volhardingsliggings, diens-binêre lêers, geskeduleerde taaklêers, opstartvouers
- Container-skryfbare lae en bind-gemonteerde geheime/konfigurasie

## Intydse backends en blinde kolle

### Linux

Die versamelingsbackend is belangrik:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: maklik en algemeen, maar watch-limiete kan uitgeput word en sommige randgevalle word gemis.
- **`auditd` / audit framework**: beter wanneer jy moet weet **wie die lêer verander het** (login-UID, proses-ID en prosesnaam).
- **`eBPF` / `kprobes`**: nuwer opsies wat deur moderne FIM-stapels gebruik word om gebeurtenisse te verryk en sommige van die operasionele probleme van gewone `inotify`-ontplooiings te verminder.

Enkele praktiese slaggate:<sup>[[1]](#references)[[5]](#references)</sup>

- As ’n program ’n lêer **vervang** met `write temp -> rename`, kan dit ophou nuttig wees om die lêer self dop te hou. **Hou die ouerlêergids dop**, nie net die lêer nie.
- `inotify`-gebaseerde versamelaars kan gebeurtenisse mis of swakker presteer met **baie groot lêergidsbome**, **hard-link-aktiwiteit**, of nadat ’n **dopgehoude lêer uitgevee is**.
- Baie groot rekursiewe watch-stelle kan stilweg misluk as `fs.inotify.max_user_watches`, `max_user_instances` of `max_queued_events` te laag is.
- Vir `inotify`-gebaseerde monitering is netwerk-lêerstelsels ’n blinde kol omdat veranderinge op afstand nie gerapporteer word nie.

Voorbeeld van ’n basislyn + verifikasie met AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Voorbeeld van `osquery` FIM-konfigurasie gefokus op aanvallers se persistence-paaie:<sup>[[1]](#references)</sup>
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
Indien jy **proses-toeskrywing** benodig in plaas van slegs padvlakveranderinge, verkies ouditgesteunde telemetrie soos `osquery` se `process_file_events` of Wazuh se `whodata`-modus.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Op Windows is FIM sterker wanneer jy **veranderingsjoernale** met **hoësein-proses-/lêertelemetrie** kombineer:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** verskaf ’n volgehoue logboek per volume van lêerveranderings.
- **Sysmon Event ID 11** is nuttig vir lêerskepping/-oorskrywing.
- **Sysmon Event ID 2** help om **timestomping** op te spoor.
- **Sysmon Event ID 15** is nuttig vir **benoemde alternatiewe datastrome (ADS)** soos `Zone.Identifier` of versteekte payload-strome.

Vinnige USN-triagevoorbeelde:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Vir dieper anti-forensiese idees rondom **tydstempelmanipulasie**, **ADS-misbruik** en **USN-peutery**, kyk na [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Houers

Container FIM mis dikwels die werklike skryfpad. Met Docker `overlay2` kombineer die container-lêerstelsel leesalleen-beeldlae (`lowerdir`) met ’n skryfbare **boonste laag** (`upperdir`/`diff`), en skrywe na beeldlêers word na daardie boonste laag gekopieer.<sup>[[8]](#references)</sup> Daarom:

- Monitering van slegs paaie **binne** ’n kortlewende container kan veranderinge mis nadat die container herskep is.
- Monitering van die **gasheerpad** wat die skryfbare laag ondersteun, of van die relevante bind-gemonteerde volume, is dikwels nuttiger.
- FIM op beeldlae verskil van FIM op die lopende container-lêerstelsel.

## Aanvallergesentreerde jagnotas

- Volg **diensdefinisies** en **taakskeduleerders** net so noukeurig soos binaries. Aanvallers verkry dikwels persistence deur ’n unit-lêer, cron-inskrywing of taak-XML te wysig eerder as om `/bin/sshd` te patch.
- ’n Inhoud-hash alleen is onvoldoende. Baie kompromitterings wys aanvanklik as **eienaar-/modus-/xattr-/ACL-afwyking**.
- As jy ’n gevorderde intrusion vermoed, doen albei: **intydse FIM** vir vars aktiwiteit en ’n **koue basislynvergelyking** vanaf betroubare media.
- As die aanvaller root- of kernel-uitvoering het, behandel die FIM-agent en sy databasis as onbetroubaar. Stoor logs en basislyne waar moontlik op afstand of op leesalleen-media.<sup>[[4]](#references)</sup>

## Gereedskap

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Lêerintegriteitsmonitering met osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Nasporing van Linux: ’n Gebruikssituasie vir lêerintegriteitsmonitering (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh-lêerintegriteitsmonitering (Syscheck- en whodata-modus)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE-handleiding Weergawe 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS-bergingsdrywer](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Gevorderde Wazuh FIM-instellings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
