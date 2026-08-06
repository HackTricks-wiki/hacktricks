# Nadgledanje integriteta datoteka

{{#include ../../banners/hacktricks-training.md}}

## Bazna vrednost

Bazna vrednost podrazumeva pravljenje snimka određenih delova sistema kako bi se **uporedio sa budućim stanjem i istakle promene**.

Na primer, možete izračunati i sačuvati hash svake datoteke u filesystemu kako biste utvrdili koje su datoteke izmenjene.\
Ovo se takođe može uraditi sa kreiranim korisničkim nalozima, pokrenutim procesima, pokrenutim servisima i bilo čim drugim što ne bi trebalo da se često menja ili uopšte ne bi trebalo da se menja.

**Korisna bazna vrednost** obično čuva više od samog digest-a: dozvole, vlasnika, grupu, vremenske oznake, inode, cilj simboličkog linka, ACL-ove i odabrane proširene atribute takođe vredi pratiti. Iz perspektive threat huntinga, ovo pomaže u otkrivanju **neovlašćenih promena samo dozvola**, **atomske zamene datoteka** i **persistence-a putem izmenjenih service/unit datoteka**, čak i kada hash sadržaja nije prva stvar koja se menja.

### Nadgledanje integriteta datoteka

File Integrity Monitoring (FIM) je kritična bezbednosna tehnika koja štiti IT okruženja i podatke praćenjem promena u datotekama. Obično kombinuje:

1. **Poređenje sa baznom vrednošću:** Čuvanje metapodataka i kriptografskih kontrolnih suma (poželjno `SHA-256` ili boljeg) za buduća poređenja.
2. **Obaveštenja u realnom vremenu:** Pretplata na izvorne događaje OS-a nad datotekama kako bi se saznalo **koja datoteka se promenila, kada i, idealno, koji proces/korisnik ju je dodirnuo**.
3. **Periodično ponovno skeniranje:** Ponovno uspostavljanje pouzdanosti nakon reboot-a, izgubljenih događaja, prekida rada agent-a ili namerne anti-forensic aktivnosti.

Za threat hunting, FIM je obično korisniji kada je fokusiran na **putanje visoke vrednosti**, kao što su:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` jedinice, cron lokacije, SSH materijal, PAM moduli, web root direktorijumi
- Windows persistence lokacije, binarne datoteke servisa, datoteke zakazanih zadataka, startup folderi
- Writable slojevi kontejnera i bind-mounted secrets/configuration

## Backend-i u realnom vremenu i slepe tačke

### Linux

Backend za prikupljanje je važan:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: jednostavni i uobičajeni, ali ograničenja broja watch-eva mogu biti iscrpljena, a neki edge case-ovi mogu biti propušteni.
- **`auditd` / audit framework**: bolji kada je potrebno znati **ko je promenio datoteku** (`auid`, proces, pid, izvršna datoteka).
- **`eBPF` / `kprobes`**: novije opcije koje koriste moderni FIM stack-ovi za obogaćivanje događaja i smanjenje dela operativnih problema običnih `inotify` deployment-a.

Neke praktične zamke:<sup>[[1]](#references)</sup>

- Ako program **zameni** datoteku pomoću `write temp -> rename`, praćenje same datoteke može prestati da bude korisno. **Pratite roditeljski direktorijum**, a ne samo datoteku.
- Kolektori zasnovani na `inotify` mogu propuštati događaje ili raditi lošije na **ogromnim stablima direktorijuma**, tokom **aktivnosti hard linkova** ili nakon što je **praćena datoteka obrisana**.
- Veoma veliki rekurzivni skupovi watch-eva mogu tiho otkazati ako su `fs.inotify.max_user_watches`, `max_user_instances` ili `max_queued_events` postavljeni prenisko.
- Network filesystem-i su obično loši FIM ciljevi za nadgledanje sa malo šuma.

Primer bazne vrednosti i verifikacije pomoću AIDE-a:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Primer `osquery` FIM konfiguracije fokusirane na putanje za persistence napadača:<sup>[[1]](#references)</sup>
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
Ako su vam potrebni **procesno pripisivanje** umesto samo promena na nivou putanje, preferirajte telemetriju potkrepljenu auditom, kao što su `osquery` `process_file_events` ili Wazuh režim `whodata`.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Na Windows-u, FIM je efikasniji kada kombinujete **change journals** sa **high-signal process/file telemetry**:

- **NTFS USN Journal** pruža trajni zapis promena datoteka po volumenu.
- **Sysmon Event ID 11** je koristan za kreiranje/prepisivanje datoteka.
- **Sysmon Event ID 2** pomaže u otkrivanju **timestomping-a**.
- **Sysmon Event ID 15** je koristan za **named alternate data streams (ADS)**, kao što su `Zone.Identifier` ili skriveni payload stream-ovi.

Brzi primeri USN trijaže:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Za dublje anti-forenzičke ideje u vezi sa **timestamp manipulation**, **ADS abuse** i **USN tampering**, pogledajte [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontejneri

FIM u kontejnerima često propušta stvarnu putanju upisa. Sa Docker `overlay2`, promene se upisuju u **writable upper layer** kontejnera (`upperdir`/`diff`), a ne u read-only slojeve image-a. Zato:

- Nadgledanje samo putanja **unutar** kratkotrajog kontejnera može propustiti promene nakon ponovnog kreiranja kontejnera.
- Nadgledanje **host putanje** koja podržava writable layer ili relevantnog bind-mounted volumena često je korisnije.
- FIM nad image slojevima razlikuje se od FIM-a nad filesystemom pokrenutog kontejnera.

## Napomene za hunting usmeren na napadače

- Pratite **service definitions** i **task schedulers** jednako pažljivo kao binarne datoteke. Napadači često ostvaruju persistence izmenom unit file-a, cron unosa ili task XML-a, umesto patchovanja `/bin/sshd`.
- Sam content hash nije dovoljan. Mnogi kompromisi se najpre manifestuju kao **owner/mode/xattr/ACL drift**.
- Ako sumnjate na zrelu intrusion, uradite oba: **real-time FIM** za svežu aktivnost i **cold baseline comparison** sa pouzdanog medijuma.
- Ako napadač ima root ili kernel execution, pretpostavite da FIM agent, njegova baza podataka, pa čak i izvor događaja mogu biti izmenjeni. Čuvajte logove i baseline-e udaljeno ili na read-only medijumu kad god je to moguće.

## Alati

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Reference

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
