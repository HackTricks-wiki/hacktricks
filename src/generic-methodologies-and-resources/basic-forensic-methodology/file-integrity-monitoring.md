# Nadzor integriteta datoteka

{{#include ../../banners/hacktricks-training.md}}

## Osnovna referentna vrednost

Osnovna referentna vrednost (baseline) podrazumeva pravljenje snimka određenih delova sistema kako bi se **uporedio sa budućim stanjem i uočile promene**.

Na primer, možete izračunati i sačuvati hash svake datoteke u datotečnom sistemu kako biste utvrdili koje su datoteke izmenjene.\
Ovo se može uraditi i za kreirane korisničke naloge, pokrenute procese, pokrenute servise i sve drugo što ne bi trebalo mnogo, ili uopšte, da se menja.

**Korisna osnovna referentna vrednost** obično čuva više od samog sažetka: dozvole, vlasnika, grupu, vremenske oznake, inode, cilj simboličke veze, ACL-ove i izabrane proširene atribute takođe vredi pratiti.<sup>[[4]](#references)</sup> Iz perspektive potrage za napadačima, ovo pomaže u otkrivanju **neovlašćenih izmena koje se odnose samo na dozvole**, **atomske zamene datoteka** i **održavanja prisutnosti putem izmenjenih service/unit datoteka**, čak i kada hash sadržaja nije prva stvar koja se menja.

### Nadzor integriteta datoteka

Nadzor integriteta datoteka (FIM) je kritična bezbednosna tehnika koja štiti IT okruženja i podatke praćenjem promena u datotekama. Obično kombinuje:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Poređenje sa osnovnom referentnom vrednošću:** Čuvanje metapodataka i kriptografskih kontrolnih suma (poželjno `SHA-256` ili boljih) za buduća poređenja.
2. **Obaveštenja u realnom vremenu:** Pretplata na izvorne događaje operativnog sistema za datoteke kako bi se saznalo **koja datoteka je izmenjena, kada i, idealno, koji proces/korisnik joj je pristupio**.
3. **Periodično ponovno skeniranje:** Ponovno uspostavljanje pouzdanosti nakon ponovnog pokretanja sistema, izgubljenih događaja, prekida rada agenta ili namerne anti-forenzičke aktivnosti.

Za threat hunting, FIM je obično korisniji kada je usmeren na **putanje visoke vrednosti**, kao što su:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` jedinice, cron lokacije, SSH materijal, PAM moduli, web koreni
- Windows lokacije za održavanje prisutnosti, binarne datoteke servisa, datoteke zakazanih zadataka, startup fascikle
- Upisivi slojevi kontejnera i bind-mountovani secrets/configuration

## Backend-ovi u realnom vremenu i slepe tačke

### Linux

Backend za prikupljanje je važan:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: jednostavni su i uobičajeni, ali ograničenja broja watch-ova mogu biti iscrpljena, a neki granični slučajevi mogu biti propušteni.
- **`auditd` / audit framework**: bolji su kada je potrebno utvrditi **ko je izmenio datoteku** (login UID, ID procesa i naziv procesa).
- **`eBPF` / `kprobes`**: novije opcije koje koriste moderni FIM stack-ovi za obogaćivanje događaja i smanjenje nekih operativnih problema običnih `inotify` implementacija.

Neke praktične napomene:<sup>[[1]](#references)[[5]](#references)</sup>

- Ako program **zameni** datoteku pomoću `write temp -> rename`, praćenje same datoteke može prestati da bude korisno. **Pratite nadređeni direktorijum**, a ne samo datoteku.
- Kolektori zasnovani na `inotify` mogu propuštati događaje ili raditi lošije na **ogromnim stablima direktorijuma**, pri **aktivnosti hard linkova** ili nakon **brisanja datoteke koja se prati**.
- Veoma veliki rekurzivni skupovi watch-ova mogu neprimetno otkazati ako su `fs.inotify.max_user_watches`, `max_user_instances` ili `max_queued_events` postavljeni prenisko.
- Kod nadzora zasnovanog na `inotify`, mrežni datotečni sistemi predstavljaju slepu tačku jer se udaljene promene ne prijavljuju.

Primer osnovne referentne vrednosti i verifikacije pomoću AIDE:<sup>[[4]](#references)</sup>
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
Ako vam je potrebna **atribucija procesa**, a ne samo promene na nivou putanje, prednost dajte telemetriji zasnovanoj na audit-u, kao što su `osquery` `process_file_events` ili Wazuh režim `whodata`.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Na Windows-u, FIM je efikasniji kada kombinujete **dnevnike promena** sa **telemetrijom procesa/datoteka visokog signala**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** pruža trajni dnevnik promena datoteka po volumenu.
- **Sysmon Event ID 11** je koristan za kreiranje/prepisivanje datoteka.
- **Sysmon Event ID 2** pomaže u otkrivanju **timestomping-a**.
- **Sysmon Event ID 15** je koristan za **imenovane alternativne tokove podataka (ADS)** kao što su `Zone.Identifier` ili skriveni tokovi sa payload-om.

Primeri brze USN trijaže:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Za dublje anti-forensic ideje u vezi sa **manipulacijom vremenskim oznakama**, **zloupotrebom ADS-a** i **menjanjem USN-a**, pogledajte [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontejneri

FIM kontejnera često ne registruje stvarnu putanju upisa. Kod Docker `overlay2`, sistem datoteka kontejnera kombinuje slojeve **lowerdir** slike samo za čitanje sa upisivim **upper layer**-om (`upperdir`/`diff`), a upisi u datoteke slike kopiraju se u taj gornji sloj.<sup>[[8]](#references)</sup> Zbog toga:

- Nadgledanje samo putanja **unutar** kratkotrajног kontejnera može propustiti promene nakon ponovnog kreiranja kontejnera.
- Nadgledanje **putanje na hostu** koja predstavlja upisivi sloj ili relevantnog volumena montiranog putem bind-a često je korisnije.
- FIM nad slojevima slike razlikuje se od FIM-a nad sistemom datoteka pokrenutog kontejnera.

## Beleške o lovu usmerenom na napadača

- Pratite **definicije servisa** i **planere zadataka** podjednako pažljivo kao binarne datoteke. Napadači često ostvaruju persistence izmenom unit datoteke, cron unosa ili XML-a zadatka, umesto izmenom `/bin/sshd`.
- Sam content hash nije dovoljan. Mnogi kompromisi se prvo ispolje kao **odstupanje vlasnika/režima/xattr/ACL-a**.
- Ako sumnjate na napad koji je dugo trajao, uradite oba: **FIM u realnom vremenu** za sveže aktivnosti i **poređenje sa cold baseline-om** sa pouzdanog medijuma.
- Ako napadač ima root ili izvršavanje u kernelu, smatrajte FIM agenta i njegovu bazu podataka nepouzdanim. Čuvajte logove i baseline-e udaljeno ili na medijumu samo za čitanje kad god je to moguće.<sup>[[4]](#references)</sup>

## Alati

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Nadgledanje integriteta datoteka pomoću osquery-ja](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Praćenje Linux-a: primer upotrebe nadgledanja integriteta datoteka (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh nadgledanje integriteta datoteka (Syscheck i whodata režim)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE priručnik, verzija 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux stranica priručnika](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS storage driver](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Napredna podešavanja Wazuh FIM-a](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
