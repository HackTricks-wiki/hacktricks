# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Bazno stanje

Bazno stanje podrazumeva snimanje određenih delova sistema kako bi se uporedili sa budućim stanjem i istakle promene.

Na primer, možete izračunati i sačuvati hash svakog fajla u filesystemu kako biste utvrdili koji su fajlovi izmenjeni.\
Isto se može primeniti na kreirane korisničke naloge, procese koji su pokrenuti, servise koji rade i sve druge stavke koje se ne bi mnogo, ili uopšte, trebale menjati.

Jedno korisno bazno stanje obično čuva više od samog digesta: dozvole, vlasnik, grupa, vremenske oznake, inode, symlink target, ACLs i odabrani prošireni atributi takođe vredi pratiti. Iz perspektive traganja za napadačima, ovo pomaže u otkrivanju **permission-only tampering**, **atomic file replacement**, i **persistence via modified service/unit files** čak i kada sadržaj fajla nije prvi parametar koji se menja.

### File Integrity Monitoring

File Integrity Monitoring (FIM) je kritična bezbednosna tehnika koja štiti IT okruženja i podatke praćenjem promena u fajlovima. Obično kombinuje:

1. **Baseline comparison:** čuvanje metapodataka i kriptografskih checksuma (preporučeno `SHA-256` ili bolji) za buduća poređenja.
2. **Real-time notifications:** pretplatite se na OS-nativne događaje fajl sistema da biste znali **koji fajl se menjao, kada i po mogućstvu koji proces/korisnik ga je dirnuo**.
3. **Periodic re-scan:** obnovite poverenje nakon reboot-ova, izgubljenih događaja, prekida agenta ili namernih anti-forenzičkih aktivnosti.

Za traganje za pretnjama, FIM je obično korisniji kada je fokusiran na high-value paths kao što su:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Backendi u realnom vremenu i slepe tačke

### Linux

Back-end za prikupljanje podataka je bitan:

- **`inotify` / `fsnotify`**: jednostavno i često, ali limiti za watch mogu biti iscrpljeni i neki ivični slučajevi mogu biti propušteni.
- **`auditd` / audit framework**: bolji kada treba da znate **ko je izmenio fajl** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: novije opcije koje koriste moderni FIM stack-ovi da obogate događaje i smanje deo operativne muke plain `inotify` deployment-a.

Neke praktične zamke:

- Ako program zameni fajl koristeći `write temp -> rename`, praćenje samog fajla može prestati da bude korisno. Pratite roditeljski direktorijum, ne samo fajl.
- Kolektori zasnovani na `inotify`-ju mogu promašiti ili degradirati rad na ogromnim stabljikama direktorijuma, kod aktivnosti sa hard-linkovima, ili nakon što je nadgledani fajl obrisan.
- Veoma veliki rekurzivni setovi za watch mogu se ćutke srušiti ako su `fs.inotify.max_user_watches`, `max_user_instances`, ili `max_queued_events` postavljeni prenisko.
- Mrežni fajl sistemi obično nisu dobri ciljevi za FIM kada je cilj nisko-šumno praćenje.

Primer baznog stanja + verifikacija sa AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Primer `osquery` FIM konfiguracije fokusirane na putanje koje napadači koriste za održavanje prisustva:
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
Ako vam treba **process attribution** umesto samo promena na nivou putanje, preferirajte audit-backed telemetry kao što su `osquery` `process_file_events` ili Wazuh `whodata` mode.

### Windows

Na Windowsu je FIM efikasniji kada kombinujete **change journals** sa **high-signal process/file telemetry**:

- **NTFS USN Journal** obezbeđuje trajan zapis po volumenu o promenama fajlova.
- **Sysmon Event ID 11** je koristan za kreiranje/prepisivanje fajlova.
- **Sysmon Event ID 2** pomaže u detekciji **timestomping**.
- **Sysmon Event ID 15** je koristan za **named alternate data streams (ADS)** kao što su `Zone.Identifier` ili skriveni payload streamovi.

Brzi primeri USN triaže:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Za dublje anti-forenzičke ideje oko **timestamp manipulation**, **ADS abuse**, i **USN tampering**, pogledajte [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontejneri

Container FIM često promašuje stvarni put zapisa. Sa Docker `overlay2`, izmene se upisuju u writable upper layer (`upperdir`/`diff`) kontejnera, a ne u read-only image slojeve. Dakle:

- Praćenje samo putanja iz **inside** kratkotrajnog kontejnera može propustiti izmene nakon ponovnog kreiranja kontejnera.
- Praćenje putanje na hostu koja stoji iza writable sloja ili odgovarajućeg bind-mounted volumena često je korisnije.
- FIM na image slojevima razlikuje se od FIM na pokrenutom container filesystemu.

## Beleške za lov na napadače

- Pratite **service definitions** i **task schedulers** jednako pažljivo kao i binarije. Napadači često dobijaju persistenciju modifikovanjem unit fajla, cron unosa ili task XML-a umesto da patchuju `/bin/sshd`.
- Samo content hash nije dovoljan. Mnogi kompromisi se prvo jave kao **owner/mode/xattr/ACL drift**.
- Ako sumnjate na zrelu intruziju, uradite oboje: **real-time FIM** za svežu aktivnost i **cold baseline comparison** sa pouzdanim medijima.
- Ako napadač ima root ili kernel execution, pretpostavite da FIM agent, njegova baza podataka i čak izvor događaja mogu biti podmetnuti. Čuvajte logove i baseline-ove na daljinu ili na read-only medijima kad god je moguće.

## Alati

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Reference

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
