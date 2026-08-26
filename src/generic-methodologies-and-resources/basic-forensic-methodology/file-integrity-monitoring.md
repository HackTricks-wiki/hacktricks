# Nadzor integriteta datoteka

{{#include ../../banners/hacktricks-training.md}}

## Osnovna referentna vrednost

Osnovna referentna vrednost podrazumeva pravljenje snimka određenih delova sistema kako bi se **uporedio sa budućim stanjem i istakle promene**.

Na primer, možete izračunati i sačuvati heš svake datoteke u sistemu datoteka da biste utvrdili koje su datoteke izmenjene.\
Isto se može uraditi i sa kreiranim korisničkim nalozima, pokrenutim procesima, pokrenutim servisima i svim drugim stvarima koje ne bi trebalo da se često ili uopšte menjaju.

**Korisna osnovna referentna vrednost** obično čuva više od samog sažetka: dozvole, vlasnika, grupu, vremenske oznake, inode, cilj simboličke veze, ACL-ove i odabrane proširene atribute takođe vredi pratiti.<sup>[[4]](#references)</sup> Iz perspektive potrage za napadačima, ovo pomaže u otkrivanju **neovlašćene izmene samo dozvola**, **atomske zamene datoteka** i **postojanosti putem izmenjenih service/unit datoteka**, čak i kada heš sadržaja nije prva stvar koja se menja.

### Nadzor integriteta datoteka

Nadzor integriteta datoteka (FIM) je kritična bezbednosna tehnika koja štiti IT okruženja i podatke praćenjem promena u datotekama. Obično kombinuje:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Poređenje sa osnovnom referentnom vrednošću:** Čuvanje metapodataka i kriptografskih kontrolnih suma (poželjno `SHA-256` ili boljih) za buduća poređenja.
2. **Obaveštenja u realnom vremenu:** Pretplata na izvorne događaje operativnog sistema za datoteke kako bi se saznalo **koja datoteka se promenila, kada i, idealno, koji proces/korisnik ju je dodirnuo**.
3. **Periodično ponovno skeniranje:** Ponovno uspostavljanje pouzdanosti nakon restarta, izgubljenih događaja, prekida rada agenta ili namerne anti-forenzičke aktivnosti.

Za threat hunting, FIM je obično korisniji kada je usmeren na **putanje visoke vrednosti**, kao što su:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` jedinice, cron lokacije, SSH materijal, PAM moduli, web koreni
- Windows lokacije za persistence, binarne datoteke servisa, datoteke zakazanih zadataka, startup fascikle
- Upisivi slojevi kontejnera i bind-mounted secrets/configuration

## Backend-ovi u realnom vremenu i slepe tačke

### Linux

Backend za prikupljanje je važan:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: jednostavni i uobičajeni, ali ograničenja broja praćenja mogu biti iscrpljena, a neki granični slučajevi mogu biti propušteni.
- **`auditd` / audit framework**: bolji kada je potrebno znati **ko je promenio datoteku** (UID za prijavljivanje, ID procesa i naziv procesa).
- **`eBPF` / `kprobes`**: novije opcije koje koriste moderni FIM stekovi za obogaćivanje događaja i smanjenje nekih operativnih problema običnih `inotify` implementacija.

Neki praktični problemi:<sup>[[1]](#references)[[5]](#references)</sup>

- Ako program **zameni** datoteku pomoću `write temp -> rename`, praćenje same datoteke može prestati da bude korisno. **Pratite nadređeni direktorijum**, a ne samo datoteku.
- Kolektori zasnovani na `inotify` mogu propuštati događaje ili raditi lošije na **ogromnim stablima direktorijuma**, pri **aktivnosti hard linkova** ili nakon što je **praćena datoteka obrisana**.
- Veoma veliki rekurzivni skupovi praćenja mogu neprimetno otkazati ako su `fs.inotify.max_user_watches`, `max_user_instances` ili `max_queued_events` preniski.
- Kod nadzora zasnovanog na `inotify`, mrežni sistemi datoteka predstavljaju slepu tačku jer se udaljene promene ne prijavljuju.

Primer osnovne referentne vrednosti i verifikacije pomoću AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Primer `osquery` FIM konfiguracije usmerene na putanje perzistencije napadača:<sup>[[1]](#references)</sup>
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
Ako vam je potrebna **atribucija procesa**, a ne samo promene na nivou putanje, prednost dajte telemetry zasnovanoj na audit-u, kao što su `osquery` `process_file_events` ili Wazuh `whodata` mode.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: syscall telemetry nije FIM

Na modernom Linux-u, nadgledanje ulaznih tačaka za `openat(2)`, `write(2)` ili druge syscall-ove **nije ekvivalentno nadgledanju rezultujuće filesystem operacije**. Proof of concept **Curing** iz 2025. godine stavljao je zahteve za fajlove i mrežu u red čekanja putem `io_uring`, pa su proizvodi ili politike povezani isključivo sa odgovarajućim syscall unosima po operaciji gubili process telemetry. U istim testovima, path-scoped FIM komponenta je i dalje registrovala izmene fajlova, što pokazuje da je ovo **slepa tačka u postavljanju hook-a**, a ne zaobilaženje dozvola niti način da se porazi svaki FIM backend.<sup>[[10]](#references)</sup>

Prilikom validacije senzora, izmenite isti canary kroz nekoliko putanja: uobičajeni `write`, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, atomic replacement i `io_uring`. Proverite ne samo da li je pronađen konačni hash drift, već i da li događaj čuva odgovorni proces, container/cgroup, namespace-visible path, inode i rename pair. Izostanak real-time događaja praćen nepodudaranjem periodičnog skeniranja mora se tretirati kao **gubitak telemetry-ja**, a ne kao rutinska neobjašnjiva izmena.<sup>[[10]](#references)[[11]](#references)</sup>

Za monitoring zasnovan na eBPF-u, prednost dajte uobičajenim kernel enforcement points umesto liste syscall-entry probe. Na primer, Tetragon-ova file-access policy koristi `security_file_permission` da pokrije obični I/O, `sendfile`, `copy_file_range`, AIO i `io_uring`; odvojeno pokriva memory mappings pomoću `security_mmap_file`, a promene veličine pomoću `security_path_truncate`. Ovo takođe pokazuje zašto jedan hook retko pruža potpunu pokrivenost.<sup>[[11]](#references)</sup>

### Windows

Na Windows-u, FIM je snažniji kada se **change journals** kombinuju sa **high-signal process/file telemetry**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** pruža trajni per-volume log promena fajlova.
- **Sysmon Event ID 11** je koristan za kreiranje/prepisivanje fajlova.
- **Sysmon Event ID 2** pomaže u otkrivanju **timestomping-a**.
- **Sysmon Event ID 15** je koristan za **named alternate data streams (ADS)** kao što su `Zone.Identifier` ili skriveni payload streams.

Brzi primeri USN triage-a:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Za detaljnije anti-forensic ideje u vezi sa **timestamp manipulation**, **ADS abuse** i **USN tampering**, pogledajte [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontejneri

FIM kontejnera često ne registruje stvarnu putanju upisa. Kod Docker `overlay2`, filesystem kontejnera kombinuje slojeve **lowerdir** image-a samo za čitanje sa slojem za upis (**upper layer**) (`upperdir`/`diff`), a upisi u fajlove image-a kopiraju se u taj gornji sloj.<sup>[[8]](#references)</sup> Zbog toga:

- Nadgledanje samo putanja **unutar** kratkotrajneih kontejnera može propustiti izmene nakon što se kontejner ponovo kreira.
- Nadgledanje **host putanje** koja predstavlja osnovu sloja za upis ili relevantnog bind-mounted volume-a često je korisnije.
- FIM nad slojevima image-a razlikuje se od FIM-a nad filesystem-om pokrenutog kontejnera.

## Beleške za hunting usmeren na napadače

- Pratite **service definitions** i **task schedulers** jednako pažljivo kao binarne fajlove. Napadači često ostvaruju persistence izmenom unit fajla, cron unosa ili task XML-a, umesto izmenom `/bin/sshd`.
- Sam content hash nije dovoljan. Mnogi kompromisi se najpre ispolje kao **owner/mode/xattr/ACL drift**.
- Ako sumnjate na naprednu intrusion, radite oba: **real-time FIM** za sveže aktivnosti i poređenje sa **cold baseline** sa pouzdanog medijuma.
- Ako napadač ima root ili kernel execution, smatrajte FIM agent i njegovu bazu podataka nepouzdanim. Čuvajte logove i baseline-e na udaljenoj lokaciji ili na medijumu samo za čitanje kad god je to moguće.<sup>[[4]](#references)</sup>

## Alati

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Nadgledanje integriteta fajlova pomoću osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Praćenje Linux-a: slučaj upotrebe nadgledanja integriteta fajlova (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh nadgledanje integriteta fajlova (Syscheck i whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE priručnik, verzija 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux man stranica](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS storage driver](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Napredna Wazuh FIM podešavanja](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [io_uring Rootkit zaobilaženja Linux security alata (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Pristup imenima fajlova: sinhrone, asinhrone, mapirane i truncation putanje (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
