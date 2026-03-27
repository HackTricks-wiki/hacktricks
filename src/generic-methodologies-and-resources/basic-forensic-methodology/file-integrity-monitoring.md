# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Basislyn

’n basislyn bestaan uit die neem van ’n snapshot van sekere dele van ’n stelsel om dit met ’n toekomstige toestand te vergelyk en veranderinge te beklemtoon.

Byvoorbeeld, jy kan die hash van elke lêer op die lêerstelsel bereken en stoor om te kan uitvind watter lêers gewysig is.\
Dit kan ook gedoen word met die geskepte gebruikersrekeninge, lopende prosesse, lopende dienste en enige ander ding wat nie veel, of glad nie, behoort te verander nie.

’n **bruikbare basislyn** stoor gewoonlik meer as net ’n digest: permissies, eienaar, groep, tydstempels, inode, symlink target, ACLs, en geselekteerde uitgebreide attribuite is ook werd om na te spoor. Vanuit ’n attacker-hunting-perspektief help dit om **permission-only tampering**, **atomic file replacement**, en **persistence via modified service/unit files** op te spoor, selfs wanneer die inhoudshash nie die eerste ding is wat verander nie.

### File Integrity Monitoring

File Integrity Monitoring (FIM) is ’n kritieke sekuriteitstegniek wat IT-omgewings en data beskerm deur veranderinge in lêers op te spoor. Dit kombineer gewoonlik:

1. **Baseline comparison:** Berg metadata en kriptografiese checksums (verkies `SHA-256` of beter) vir toekomstige vergelykings.
2. **Real-time notifications:** Subskribeer op OS-native lêer-gebeure om te weet **watter lêer verander het, wanneer, en idealiter watter proses/gebruiker dit geraak het**.
3. **Periodic re-scan:** Herbou vertroue ná herlaaiings, wegval van gebeure, agentuitvalle, of opzettelike anti-forensiese aktiwiteit.

For threat hunting, FIM is gewoonlik meer nuttig wanneer dit gefokus is op **high-value paths** soos:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Reële-tyd Backends & Blinde Kolle

### Linux

Die versamelings-backend maak saak:

- **`inotify` / `fsnotify`**: maklik en algemeen, maar watch-limiete kan uitgeput raak en sommige randgevalle word gemis.
- **`auditd` / audit framework**: beter wanneer jy nodig het **wie die lêer verander het** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: nuwer opsies wat deur moderne FIM-stakke gebruik word om gebeure te verryk en sommige van die operasionele pyn van eenvoudige `inotify`-implementasies te verminder.

Sommige praktiese valkuils:

- As ’n program ’n lêer **vervang** met `write temp -> rename`, kan dit onbruikbaar raak om net daardie lêer self te monitor. **Watch the parent directory**, nie net die lêer nie.
- `inotify`-gebaseerde versamelaars kan mis of in kwaliteit agteruitgaan by **groot gidsbome**, **hard-link-aktiwiteit**, of nadat ’n **gemonitorde lêer verwyder is**.
- Baie groot rekursiewe watch-stelle kan stilletjies faal as `fs.inotify.max_user_watches`, `max_user_instances`, of `max_queued_events` te laag is.
- Netwerk-lêerstelsels is gewoonlik slegte FIM-doelwitte vir lae-ruis monitering.

Example baseline + verification with AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Voorbeeld `osquery` FIM-konfigurasie gefokus op aanvallers se persisteringspade:
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
As jy **proses-toewysing** nodig het in plaas van slegs padvlak-veranderinge, verkies oudit-ondersteunde telemetrie soos `osquery` `process_file_events` of Wazuh `whodata` mode.

### Windows

Op Windows is FIM sterker wanneer jy **veranderingsjoernale** kombineer met **hoë-sein proses-/lêertelemetrie**:

- **NTFS USN Journal** gee 'n persistente per-volume log van lêerveranderings.
- **Sysmon Event ID 11** is nuttig vir die skep of oorskrywing van lêers.
- **Sysmon Event ID 2** help om **timestomping** op te spoor.
- **Sysmon Event ID 15** is nuttig vir **named alternate data streams (ADS)** soos `Zone.Identifier` of versteekte payload-strome.

Vinnige USN triage-voorbeelde:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
For deeper anti-forensic ideas around **timestamp manipulation**, **ADS abuse**, and **USN tampering**, check [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontainers

Container FIM mis dikwels die werklike skryfpad. Met Docker `overlay2` word veranderinge in die kontainer se **writable upper layer** (`upperdir`/`diff`) deurgevoer, nie in die read-only image layers nie. Daarom:

- Monitering van slegs paaie van **binne** 'n kortlewende kontainer kan veranderinge mis nadat die kontainer heropgebou is.
- Monitering van die **host path** wat die writable layer ondersteun of die relevante bind-mounted volume is dikwels nuttiger.
- FIM op image layers verskil van FIM op die lopende kontainer-lêerstelsel.

## Aanvaller-gefokusde jagnotas

- Hou **service definitions** en **task schedulers** net so noukeurig dop soos binaries. Aanvallers verkry dikwels persistentie deur 'n unit file, cron entry, of task XML te wysig in plaas daarvan om `/bin/sshd` te patch.
- 'n inhoud-hash op sigself is onvoldoende. Baie kompromitteer eers as **owner/mode/xattr/ACL drift** sigbaar word.
- As jy 'n volwasse intrusie vermoed, doen albei: **real-time FIM** vir vars aktiwiteit en 'n **cold baseline comparison** vanaf vertroude media.
- As die aanvaller root- of kernel-uitvoering het, veronderstel dat die FIM-agent, sy databasis, en selfs die gebeurtenisbron gemanipuleer kan word. Stoor logs en basislyne afgeleë of op read-only media waar moontlik.

## Gereedskap

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Verwysings

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
