# Nadzor integriteta datoteka

## Osnovna referentna vrednost

Osnovna referentna vrednost podrazumeva pravljenje snimka određenih delova sistema kako bi se **uporedio sa budućim stanjem i uočile promene**.

Na primer, možete izračunati i sačuvati hash svake datoteke u filesystemu kako biste utvrdili koje su datoteke izmenjene.\
To se može uraditi i sa kreiranim korisničkim nalozima, pokrenutim procesima, pokrenutim servisima i bilo čim drugim što ne bi trebalo da se često menja, ili da se menja uopšte.

**Korisna osnovna referentna vrednost** obično čuva više od samog digest-a: dozvole, vlasnika, grupu, vremenske oznake, inode, cilj simboličkog linka, ACL-ove i odabrane proširene atribute takođe vredi pratiti.<sup>[[4]](#references)</sup> Iz perspektive potrage za napadačima, ovo pomaže u otkrivanju **neovlašćene izmene samo dozvola**, **atomske zamene datoteka** i **održavanja persistence-a putem izmenjenih service/unit datoteka**, čak i kada hash sadržaja nije prva stvar koja se menja.

### Nadzor integriteta datoteka

File Integrity Monitoring (FIM) je kritična bezbednosna tehnika koja štiti IT okruženja i podatke praćenjem promena u datotekama. Obično kombinuje:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Poređenje sa osnovnom referentnom vrednošću:** Čuvanje metapodataka i kriptografskih checksum-ova (poželjno `SHA-256` ili boljeg) za buduća poređenja.
2. **Obaveštenja u realnom vremenu:** Pretplata na izvorne OS događaje datoteka kako bi se saznalo **koja datoteka se promenila, kada i, idealno, koji proces/korisnik ju je izmenio**.
3. **Periodično ponovno skeniranje:** Ponovno uspostavljanje pouzdanosti nakon reboot-a, izgubljenih događaja, prekida rada agenta ili namerne anti-forensic aktivnosti.

Za threat hunting, FIM je obično korisniji kada je usmeren na **putanje visoke vrednosti**, kao što su:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron lokacije, SSH materijal, PAM moduli, web root direktorijumi
- Windows persistence lokacije, binarne datoteke servisa, datoteke zakazanih zadataka, startup folderi
- Writable slojevi kontejnera i bind-mounted secrets/configuration

## Backend-i u realnom vremenu i slepe tačke

### Linux

Backend za prikupljanje je važan:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: jednostavni su i uobičajeni, ali ograničenja broja watch-eva mogu biti iscrpljena, a neki edge case-ovi mogu biti propušteni.
- **`auditd` / audit framework**: bolji su kada je potrebno znati **ko je izmenio datoteku** (login UID, ID procesa i naziv procesa).
- **`eBPF` / `kprobes`**: novije opcije koje koriste moderni FIM stack-ovi za obogaćivanje događaja i smanjenje dela operativnih problema običnih `inotify` deployment-a.

Neke praktične zamke:<sup>[[1]](#references)[[5]](#references)</sup>

- Ako program **zameni** datoteku postupkom `write temp -> rename`, praćenje same datoteke može prestati da bude korisno. **Pratite nadređeni direktorijum**, a ne samo datoteku.
- Kolektori zasnovani na `inotify` mogu propustiti događaje ili raditi lošije na **ogromnim stablima direktorijuma**, pri **aktivnosti hard linkova** ili nakon **brisanja praćene datoteke**.
- Veoma veliki rekurzivni skupovi watch-eva mogu neprimetno otkazati ako su `fs.inotify.max_user_watches`, `max_user_instances` ili `max_queued_events` postavljeni prenisko.
- Kod monitoringa zasnovanog na `inotify`, network filesystem-i predstavljaju slepu tačku jer se udaljene promene ne prijavljuju.

Primer osnovne referentne vrednosti i verifikacije pomoću AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Primer `osquery` FIM konfiguracije usmerene na putanje za persistence napadača:<sup>[[1]](#references)</sup>
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
Ako vam je potrebno **pripisivanje procesa**, a ne samo promene na nivou putanje, prednost dajte telemetriji zasnovanoj na audit-u, kao što su `osquery` `process_file_events` ili Wazuh režim `whodata`.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Na Windows-u je FIM efikasniji kada kombinujete **dnevnike promena** sa **telemetrijom procesa/datoteka visoke signalne vrednosti**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** pruža trajni dnevnik promena datoteka po volumenu.
- **Sysmon Event ID 11** je koristan za kreiranje/prepisivanje datoteka.
- **Sysmon Event ID 2** pomaže u otkrivanju **timestomping-a**.
- **Sysmon Event ID 15** je koristan za **imenovane alternativne tokove podataka (ADS)**, kao što su `Zone.Identifier` ili skriveni payload tokovi.

Primeri brze USN trijaže:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Za dublje anti-forensic ideje u vezi sa **manipulacijom vremenskim oznakama**, **zloupotrebom ADS-a** i **neovlašćenim izmenama USN-a**, pogledajte [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontejneri

FIM kontejnera često ne prati stvarnu putanju upisa. Kod Docker `overlay2`, sistem datoteka kontejnera kombinuje slojeve slike samo za čitanje `lowerdir` sa upisivim **gornjim slojem** (`upperdir`/`diff`), a upisi u datoteke slike kopiraju se u taj gornji sloj.<sup>[[8]](#references)</sup> Zbog toga:

- Nadgledanje samo putanja **unutar** kratkotrajnog kontejnera može propustiti izmene nakon ponovnog kreiranja kontejnera.
- Nadgledanje **putanje na hostu** koja podržava upisivi sloj ili relevantnog bind-mounted volumena često je korisnije.
- FIM nad slojevima slike razlikuje se od FIM-a nad sistemom datoteka pokrenutog kontejnera.

## Beleške za hunting usmeren na napadače

- Pratite **definicije servisa** i **task schedulere** jednako pažljivo kao binarne datoteke. Napadači često ostvaruju persistence izmenom unit datoteke, cron unosa ili task XML-a, umesto izmene `/bin/sshd`.
- Sam content hash nije dovoljan. Mnogi kompromisi se prvo uočavaju kao **odstupanje owner/mode/xattr/ACL vrednosti**.
- Ako sumnjate na napad koji je dugo trajao, uradite oboje: **real-time FIM** za sveže aktivnosti i **poređenje sa cold baseline-om** sa pouzdanog medijuma.
- Ako napadač ima root ili kernel execution, smatrajte FIM agent i njegovu bazu podataka nepouzdanim. Kad god je moguće, čuvajte logove i baseline vrednosti udaljeno ili na medijumu samo za čitanje.<sup>[[4]](#references)</sup>

## Alati

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Nadgledanje integriteta datoteka pomoću osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Praćenje Linux-a: Slučaj upotrebe nadgledanja integriteta datoteka (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh nadgledanje integriteta datoteka (Syscheck i whodata režim)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE priručnik, verzija 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux stranica priručnika](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS drajver za skladištenje](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Napredne postavke Wazuh FIM-a](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
