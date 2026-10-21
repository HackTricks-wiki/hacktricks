# Maskirane putanje

{{#include ../../../../banners/hacktricks-training.md}}

Maskirane putanje su runtime zaštite koje skrivaju posebno osetljive lokacije sistema datoteka koje koriste kernel od kontejnera, tako što se preko njih montiraju bind mount-ovi ili im se na drugi način onemogućava pristup. OCI specifikacija runtime-a definiše `maskedPaths` kao apsolutne putanje koje ne smeju biti čitljive unutar kontejnera. <sup>[[1]](#references)</sup>

Ovo je važno zato što mnogi načini za izlazak iz kontejnera i trikovi koji utiču na host počinju čitanjem ili upisivanjem posebnih datoteka pod `/proc` ili `/sys`. Ako su te lokacije maskirane, napadač gubi direktan pristup korisnom delu površine za kontrolu kernela, čak i nakon što dobije mogućnost izvršavanja koda unutar kontejnera.

## Rad

Runtime-ovi često maskiraju odabrane putanje, kao što su:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Tačan spisak zavisi od runtime-a i konfiguracije hosta. Važno je da putanja postane nedostupna ili zamenjena iz perspektive kontejnera, iako i dalje postoji na hostu.

## Laboratorija

Pregledajte konfiguraciju maskiranih putanja koju izlaže Docker:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Ispitajte stvarno ponašanje montiranja unutar workload-a:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

Navedena putanja nije nužno čitljiva: runc može da sakrije datoteku pomoću bind mount-a na `/dev/null`, a direktorijum pomoću praznog, samo za čitanje tmpfs-a. Proverite tačnu tačku montiranja, a ne samo da li komanda `ls` uspeva. <sup>[[4]](#references)</sup>

## Bezbednosni uticaj

Maskiranje ne stvara glavnu granicu izolacije, ali uklanja nekoliko vrednih meta nakon eksploatacije. Bez maskiranja, napadač koji je kompromitovao kontejner može da pregleda stanje kernela, pročita osetljive informacije o procesima ili ključevima, ili da pristupi objektima procfs/sysfs koji nikada nisu smeli da budu vidljivi aplikaciji.

## Pogrešne konfiguracije

Glavna greška je uklanjanje maskiranja sa širokih grupa putanja radi praktičnosti ili otklanjanja grešaka. U Podman-u se to može pojaviti kao `--security-opt unmask=ALL` ili ciljano uklanjanje maskiranja. <sup>[[2]](#references)</sup> U Kubernetes-u, preširoko izlaganje proc-a može se pojaviti kroz `procMount: Unmasked`; trenutni Kubernetes zahteva `spec.hostUsers: false` (korisnički namespace) za ovo podešavanje, dok verzije 1.12–1.29 nisu sprovodile ovaj zahtev. <sup>[[3]](#references)</sup> Još jedan ozbiljan problem je izlaganje host-ovog `/proc` ili `/sys` direktorijuma preko bind mount-a, čime se u potpunosti zaobilazi ideja ograničenog prikaza kontejnera.

## Zloupotreba

Ako je maskiranje slabo ili ga nema, počnite tako što ćete utvrditi kojim osetljivim putanjama procfs/sysfs može direktno da se pristupi:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Ako je navodno maskirana putanja dostupna, pažljivo je pregledajte:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Šta ove komande mogu da otkriju:

- `/proc/timer_list` može da izloži podatke o tajmerima i raspoređivaču hosta. Ovo je uglavnom tehnika za izviđanje, ali potvrđuje da kontejner može da čita informacije usmerene ka kernelu koje su obično skrivene.
- `/proc/keys` izlistava samo metapodatke o ključevima za koje čitalac ima dozvolu **view**, uz ograničenja koja nameću LSM provere. Može da otkrije tipove ključeva i opise, ali ne izbacuje sadržaj ključeva. <sup>[[6]](#references)</sup>
- `/sys/firmware` pomaže u utvrđivanju režima pokretanja, firmverskih interfejsa i detalja o platformi, korisnih za otkrivanje karakteristika hosta i razumevanje da li radno opterećenje vidi stanje na nivou hosta.
- `/proc/config.gz` može da otkrije konfiguraciju kernela koji je pokrenut, što je korisno za proveru preduslova za javno poznate kernel exploit-e ili za razumevanje zašto je određena funkcija dostupna.
- `/proc/sched_debug` izlaže stanje raspoređivača i često zaobilazi intuitivno očekivanje da PID namespace treba u potpunosti da sakrije informacije o nepovezanim procesima.

Zanimljivi rezultati obuhvataju direktno čitanje tih fajlova, dokaze da podaci pripadaju hostu, a ne ograničenom prikazu kontejnera, ili pristup drugim lokacijama u procfs/sysfs koje su podrazumevano često maskirane.

### Race u izvoru maskiranja tokom pokretanja kontejnera

U ranjivim implementacijama runc-a, maske za fajlove zavise od inode-a kontejnerovog `/dev/null`. Napadač koji može da pokrene istovremene kontejnere sa deljenim mountovima, uključujući paralelne BuildKit korake, može da iskoristi race pri pokretanju i ukloni `/dev/null` pre nego što ga runc mount-uje preko maskiranih procfs fajlova. Runtime zatim tretira nedostajući **izvor** kao da odredište maskiranja ne postoji i tiho preskače te maske za fajlove. Do greške dolazi zbog race-a tokom podešavanja runtime-a; uklanjanje `/dev/null` nakon pokretanja ne uklanja već postavljenu masku. <sup>[[4]](#references)</sup>

Nakon kontrolisanog testa, uporedite traženi spisak maski sa tačnim mountpoint-ovima unutar novog kontejnera. <sup>[[4]](#references)</sup> `findmnt -M` proverava navedeni mountpoint umesto da pređe na nadređeni mount; ako `findmnt` nije dostupan, pregledajte `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> Uspešno izvršavanje komande `ls` ili prazan izlaz komande `cat` ne dokazuje da maska nedostaje. <sup>[[4]](#references)</sup>

Upotrebite [provere u nastavku](#checks) da biste uporedili tražene maske sa tačnim mount-ovima u novom kontejneru.

Preskočena maska za fajl može da izloži procfs podatke ako to dozvoljavaju uobičajene dozvole i LSM pravila. To samo po sebi **ne** omogućava upis u `/proc/sys`: to je zasebna kontrola za [putanje samo za čitanje](read-only-paths.md). Odvojeni slučaj zamene symlink-a `/dev/null`, koji može da preusmeri bind mount na procfs odredište u koje je moguće pisati, obrađen je u odeljku o [race-u runtime-a u PID namespace-u](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Checks

Svrha ovih provera je da utvrde koje je putanje runtime namerno sakrio i da li trenutno radno opterećenje i dalje vidi umanjen prikaz fajl-sistema koji je dostupan kernelu.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Koristite proveru tačnog mountpoint-a jer maskirana datoteka i dalje može da postoji, a čitanje može da vrati prazan rezultat iz `/dev/null`. Odsustvo mountpoint-a je nalaz koji treba istražiti, a ne samo po sebi dokaz da su podaci hosta čitljivi. <sup>[[4]](#references)[[5]](#references)</sup>

Šta je ovde zanimljivo:

- Dugačak spisak maskiranih putanja je uobičajen u runtime okruženjima sa pojačanom bezbednošću.
- Nedostajuće maskiranje osetljivih unosa u procfs-u zaslužuje pažljiviju proveru.
- Ako je osetljivoj putanji moguće pristupiti, a kontejner uz to ima moćne capabilities ili široke mount-ove, izloženost je značajnija.

## Podrazumevane postavke runtime okruženja

| Runtime okruženje / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje zaštite |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućeno | Docker definiše podrazumevani spisak maskiranih putanja | izlaganje host mount-ova proc/sys, `--privileged` |
| Podman | Podrazumevano omogućeno | Podman primenjuje podrazumevane maskirane putanje, osim ako se ručno ne uklone iz maskiranja | `--security-opt unmask=ALL`, ciljano uklanjanje maskiranja, `--privileged` |
| Kubernetes | Nasleđuje podrazumevane postavke runtime okruženja | Koristi ponašanje maskiranja osnovnog runtime okruženja, osim ako postavke Pod-a ne oslabe izloženost proc-a | `procMount: Unmasked` (u aktuelnim izdanjima zahteva `hostUsers: false`), obrasci privilegovanih workload-ova, široki host mount-ovi |
| containerd / CRI-O u okviru Kubernetes-a | Podrazumevana postavka runtime okruženja | Obično primenjuje OCI/runtime maskirane putanje, osim ako se ne zamene | direktne izmene konfiguracije runtime okruženja, isti načini slabljenja zaštite u Kubernetes-у |

Maskirane putanje су обично присутне подразумевано. Главни оперативни проблем није њихово одсуство из runtime окружења, већ намерно уклањање маскирања или host bind mount-ови који поништавају заштиту.

## References

- [1] [Open Container Initiative - Konfiguracija Linux kontejnera: maskirane putanje](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Podman dokumentacija - bezbednosne opcije za `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Kubernetes dokumentacija - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [runc bezbednosno obaveštenje: utrka u izvoru mount-a za maskiranu putanju](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [Priručnik za findmnt(8)](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [Priručnik za keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
