# Monitoring integriteta fajlova

{{#include ../../banners/hacktricks-training.md}}

## Osnovna linija

Osnovna linija podrazumeva pravljenje snimka određenih delova sistema kako bi se **uporedio sa budućim stanjem i istakle promene**.

Na primer, možete izračunati i sačuvati hash svakog fajla u filesystemu kako biste mogli da utvrdite koji su fajlovi izmenjeni.\
Ovo se može uraditi i za kreirane korisničke naloge, pokrenute procese, pokrenute servise i sve drugo što ne bi trebalo da se često menja, ili uopšte da se menja.

**Korisna osnovna linija** obično čuva više od samog digest-a: dozvole, vlasnika, grupu, vremenske oznake, inode, cilj simboličkog linka, ACL-ove i odabrane proširene atribute takođe vredi pratiti. Iz perspektive lova na napadače, ovo pomaže u otkrivanju **neovlašćenih izmena samo dozvola**, **atomske zamene fajlova** i **perzistencije putem izmenjenih service/unit fajlova**, čak i kada hash sadržaja nije prva stvar koja se menja.

### Monitoring integriteta fajlova

File Integrity Monitoring (FIM) je kritična bezbednosna tehnika koja štiti IT okruženja i podatke praćenjem promena u fajlovima. Obično kombinuje:

1. **Poređenje sa osnovnom linijom:** Čuvanje metapodataka i kriptografskih checksum-ova (poželjno `SHA-256` ili bolji) za buduća poređenja.
2. **Obaveštenja u realnom vremenu:** Pretplata na izvorne OS događaje fajlova kako bi se utvrdilo **koji fajl se promenio, kada i, idealno, koji proces/korisnik ga je izmenio**.
3. **Periodično ponovno skeniranje:** Ponovno uspostavljanje pouzdanosti nakon reboot-a, izgubljenih događaja, prekida rada agenta ili namerne anti-forensic aktivnosti.

Za threat hunting, FIM je obično korisniji kada je fokusiran na **putanje visoke vrednosti**, kao što su:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron lokacije, SSH materijal, PAM moduli, web root-ovi
- Windows lokacije za perzistenciju, binarni fajlovi servisa, fajlovi zakazanih zadataka, startup folderi
- Writable layers kontejnera i bind-mounted secrets/configuration

## Backend-i u realnom vremenu i slepe tačke

### Linux

Backend za prikupljanje je važan:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: jednostavni i uobičajeni, ali ograničenja za watch mogu biti iscrpljena, a neki edge case-ovi mogu biti propušteni.
- **`auditd` / audit framework**: bolji kada je potrebno znati **ko je izmenio fajl** (`auid`, proces, pid, izvršni fajl).
- **`eBPF` / `kprobes`**: novije opcije koje koriste moderni FIM stack-ovi za obogaćivanje događaja i smanjenje nekih operativnih problema običnih `inotify` deployment-a.

Neki praktični problemi:<sup>[[1]](#references)</sup>

- Ako program **zameni** fajl pomoću `write temp -> rename`, praćenje samog fajla može prestati da bude korisno. **Pratite roditeljski direktorijum**, a ne samo fajl.
- Kolektori zasnovani na `inotify` mogu propuštati događaje ili imati lošije performanse na **ogromnim stablima direktorijuma**, pri **aktivnostima nad hard link-ovima** ili nakon što je **praćeni fajl obrisan**.
- Veoma veliki rekurzivni skupovi watch-ova mogu neprimetno otkazati ako su `fs.inotify.max_user_watches`, `max_user_instances` ili `max_queued_events` postavljeni prenisko.
- Network filesystem-i su obično loši FIM ciljevi za monitoring sa malo šuma.

Primer osnovne linije + verifikacije pomoću AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Primer `osquery` FIM konfiguracije usmerene na putanje za perzistenciju napadača:<sup>[[1]](#references)</sup>
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
Ako vam je potrebna **atribucija procesa**, a ne samo promene na nivou putanje, prednost dajte telemetriji zasnovanoj na audit-u, kao što su `osquery` `process_file_events` ili Wazuh režim `whodata`.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Na Windows-u je FIM snažniji kada kombinujete **dnevnike promena** sa **telemetrijom procesa/datoteka visoke signalnosti**:

- **NTFS USN Journal** pruža trajni dnevnik promena datoteka po volumenu.
- **Sysmon Event ID 11** je koristan za kreiranje/prepisivanje datoteka.
- **Sysmon Event ID 2** pomaže u otkrivanju **timestomping-a**.
- **Sysmon Event ID 15** je koristan za **imenovane alternativne tokove podataka (ADS)**, kao što su `Zone.Identifier` ili skriveni tokovi sa payload-om.

Brzi primeri USN trijaže:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Za dublje anti-forensic ideje u vezi sa **timestamp manipulation**, **ADS abuse** i **USN tampering**, pogledajte [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontejneri

FIM kontejnera često ne prati stvarnu putanju upisa. Kod Docker `overlay2`, izmene se upisuju u **writable upper layer** kontejnera (`upperdir`/`diff`), a ne u slojeve image-a koji su samo za čitanje. Zato:

- Nadgledanje samo putanja **unutar** kratkotrajno pokrenutog kontejnera može propustiti izmene nakon ponovnog kreiranja kontejnera.
- Nadgledanje **host putanje** koja predstavlja writable layer ili relevantnog bind-mounted volume-a često je korisnije.
- FIM na image layer-ima razlikuje se od FIM-a na filesystem-u pokrenutog kontejnera.

## Beleške za hunting usmeren na napadača

- Pratite **service definitions** i **task schedulers** podjednako pažljivo kao i binarne fajlove. Napadači često ostvaruju persistence izmenom unit fajla, cron unosa ili task XML-a, umesto menjanja `/bin/sshd`.
- Sam content hash nije dovoljan. Mnoge kompromitacije se najpre ispolje kao **owner/mode/xattr/ACL drift**.
- Ako sumnjate na zrelu intrusion, uradite oba: **real-time FIM** za svežu aktivnost i **cold baseline comparison** sa pouzdanog medijuma.
- Ako napadač ima root ili kernel execution, pretpostavite da se FIM agent, njegova baza podataka, pa čak i sam izvor događaja mogu menjati. Čuvajte logove i baseline-ove udaljeno ili na read-only medijumu kad god je to moguće.

## Alati

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Reference

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
