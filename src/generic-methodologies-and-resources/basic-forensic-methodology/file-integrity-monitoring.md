# Lêerintegriteitsmonitering

{{#include ../../banners/hacktricks-training.md}}

## Basislyn

'n Basislyn bestaan uit die neem van 'n momentopname van sekere dele van 'n stelsel om dit **met 'n toekomstige toestand te vergelyk en veranderinge uit te lig**.

Jy kan byvoorbeeld die hash van elke lêer in die lêerstelsel bereken en stoor om vas te stel watter lêers gewysig is.\
Dit kan ook gedoen word met die gebruikersrekeninge wat geskep is, prosesse wat loop, dienste wat loop, en enigiets anders wat nie veel behoort te verander nie, of glad nie.

'n **Nuttige basislyn** stoor gewoonlik meer as net 'n digest: toestemmings, eienaar, groep, tydstempels, inode, symlink-teiken, ACLs en geselekteerde uitgebreide attribute is ook die moeite werd om na te spoor.<sup>[[4]](#references)</sup> Vanuit 'n aanvaller-jagperspektief help dit om **peutering wat slegs toestemmings verander**, **atomiese lêervervanging** en **volharding via gewysigde diens-/unit-lêers** op te spoor, selfs wanneer die inhoudshash nie die eerste ding is wat verander nie.

### Lêerintegriteitsmonitering

File Integrity Monitoring (FIM) is 'n kritieke sekuriteitstegniek wat IT-omgewings en data beskerm deur veranderinge in lêers na te spoor. Dit kombineer gewoonlik:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Basislynvergelyking:** Stoor metadata en kriptografiese checksums (verkieslik `SHA-256` of beter) vir toekomstige vergelykings.
2. **Intydse kennisgewings:** Teken in op OS-native lêergebeurtenisse om te weet **watter lêer verander het, wanneer dit verander het, en ideaal gesproke watter proses/gebruiker daaraan geraak het**.
3. **Periodieke herskandering:** Herbou vertroue ná herlaaie, verlore gebeurtenisse, agentonderbrekings of doelbewuste anti-forensiese aktiwiteit.

Vir threat hunting is FIM gewoonlik nuttiger wanneer dit op **hoëwaarde-paaie** fokus, soos:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron-liggings, SSH-materiaal, PAM-modules, webwortels
- Windows-volhardingsliggings, diensbinêre lêers, geskeduleerde taaklêers, opstartvouers
- Container-skryfbare lae en bind-gemonteerde secrets/konfigurasie

## Intydse agterkante en blinde kolle

### Linux

Die versamelingsagterkant is belangrik:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: maklik en algemeen, maar watch-limiete kan uitgeput word en sommige randgevalle word gemis.
- **`auditd` / audit framework**: beter wanneer jy moet weet **wie die lêer verander het** (login UID, proses-ID en prosesnaam).
- **`eBPF` / `kprobes`**: nuwer opsies wat deur moderne FIM-stapels gebruik word om gebeurtenisse te verryk en sommige van die operasionele probleme van gewone `inotify`-ontplooiings te verminder.

'n Paar praktiese slaggate:<sup>[[1]](#references)[[5]](#references)</sup>

- As 'n program 'n lêer **vervang** met `write temp -> rename`, kan dit ophou nuttig wees om die lêer self te monitor. **Monitor die ouer-omslag**, nie net die lêer nie.
- `inotify`-gebaseerde versamelaars kan gebeurtenisse mis of swakker presteer op **reuse gidsbome**, **hard-link-aktiwiteit**, of nadat 'n **gemonitorde lêer uitgevee is**.
- Baie groot rekursiewe watch-stelle kan stilweg misluk as `fs.inotify.max_user_watches`, `max_user_instances` of `max_queued_events` te laag is.
- Vir `inotify`-gebaseerde monitering is netwerklêerstelsels 'n blinde kol omdat afgeleë veranderinge nie gerapporteer word nie.

Voorbeeld van 'n basislyn + verifikasie met AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Voorbeeld van `osquery` FIM-konfigurasie gefokus op aanvaller se persistence-paaie:<sup>[[1]](#references)</sup>
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
Indien jy **process attribution** benodig in plaas van slegs veranderinge op padvlak, verkies audit-gesteunde telemetry soos `osquery` `process_file_events` of Wazuh `whodata`-modus.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: syscall-telemetry is nie FIM nie

Op moderne Linux is die monitering van `openat(2)`, `write(2)` of ander syscall-toegangspunte **nie gelykstaande aan die monitering van die gevolglike lêerstelselbewerking nie**. Die 2025 **Curing** proof of concept het lêer- en netwerkversoeke deur `io_uring` geplaas, waardeur produkte of beleide wat slegs aan die ooreenstemmende per-bewerking-syscall-toegangspunte gekoppel was, process-telemetry verloor het. In dieselfde toetse het ’n pad-geligde FIM-komponent steeds lêerwysigings waargeneem, wat toon dat dit ’n **hook-plasing-blinde kol** is, nie ’n toestemmingsomseiling of ’n manier om elke FIM-backend te omseil nie.<sup>[[10]](#references)</sup>

Wanneer jy ’n sensor valideer, wysig dieselfde canary deur verskeie paaie: normale `write`, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, atomiese vervanging en `io_uring`. Kontroleer nie net of die finale hash-dryf gevind word nie, maar ook of die gebeurtenis die verantwoordelike process, container/cgroup, namespace-sigbare pad, inode en rename-paar behou. ’n Ontbrekende intydse gebeurtenis, gevolg deur ’n periodieke-skandering-mismatch, moet as **telemetry-verlies** behandel word, nie as ’n gewone onverklaarde verandering nie.<sup>[[10]](#references)[[11]](#references)</sup>

Vir eBPF-gebaseerde monitering, verkies algemene kernel-enforcement-punte bo ’n lys syscall-entry probes. Tetragon se file-access-beleid gebruik byvoorbeeld `security_file_permission` om gewone I/O, `sendfile`, `copy_file_range`, AIO en `io_uring` te dek; dit dek geheuekarterings afsonderlik met `security_mmap_file` en grootteveranderings met `security_path_truncate`. Dit illustreer ook waarom een hook selde volledige dekking bied.<sup>[[11]](#references)</sup>

### Windows

Op Windows is FIM sterker wanneer jy **change journals** met **high-signal process/file telemetry** kombineer:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** verskaf ’n volgehoue logboek per volume van lêerveranderinge.
- **Sysmon Event ID 11** is nuttig vir lêerskepping/oorwriting.
- **Sysmon Event ID 2** help om **timestomping** op te spoor.
- **Sysmon Event ID 15** is nuttig vir **named alternate data streams (ADS)** soos `Zone.Identifier` of versteekte payload-strome.

Vinnige USN-triagevoorbeelde:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Vir dieper anti-forensic idees rondom **tydstempelmanipulasie**, **ADS-misbruik** en **USN-peutery**, kyk na [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Houers

Container FIM mis dikwels die werklike skryfpad. Met Docker `overlay2` kombineer die container-lêerstelsel leesalleen-beeldlae (`lowerdir`) met ’n skryfbare **boonste laag** (`upperdir`/`diff`), en skrywe na beeldlêers word na daardie boonste laag gekopieer.<sup>[[8]](#references)</sup> Daarom:

- Monitering van slegs paaie **binne** ’n kortlewende container kan veranderinge mis nadat die container herskep is.
- Monitering van die **gasheerpad** wat die skryfbare laag ondersteun, of die relevante bind-gemonteerde volume, is dikwels nuttiger.
- FIM op beeldlae verskil van FIM op die lopende container-lêerstelsel.

## Jagnotas vanuit die aanvaller se perspektief

- Volg **diensdefinisies** en **taakskeduleerders** net so noukeurig soos binaries. Aanvallers verkry dikwels persistence deur ’n unit-lêer, cron-inskrywing of taak-XML te wysig eerder as om `/bin/sshd` te patch.
- ’n Inhoud-hash alleen is onvoldoende. Baie kompromitterings kom aanvanklik na vore as **eienaar-/modus-/xattr-/ACL-afwykings**.
- As jy ’n gevorderde indringing vermoed, doen albei: **intydse FIM** vir vars aktiwiteit en ’n **koue basislynvergelyking** vanaf vertroude media.
- As die aanvaller root- of kernel-uitvoering het, behandel die FIM-agent en sy databasis as onbetroubaar. Stoor logboeke en basislyne op afstand of op leesalleen-media waar moontlik.<sup>[[4]](#references)</sup>

## Nutsgoed

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Lêerintegriteitsmonitering met osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Nasporing van Linux: ’n gebruiksgeval vir lêerintegriteitsmonitering (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh-lêerintegriteitsmonitering (Syscheck- en whodata-modus)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE-handleiding, weergawe 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux-manualblad](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS-bergingbestuurder](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Gevorderde Wazuh FIM-instellings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [io_uring Rootkit omseil Linux-sekuriteitsnutsgoed (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Lêernaamtoegang: dekking van sinchrone, asinchrone, gekarteerde en truncasie-paaie (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
