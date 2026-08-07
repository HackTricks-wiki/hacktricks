# Maskirane putanje

{{#include ../../../../banners/hacktricks-training.md}}

Maskirane putanje su zaštite tokom izvršavanja koje skrivaju posebno osetljive lokacije sistema datoteka okrenute ka kernelu od containera tako što ih prekrivaju bind-mount-om ili ih na drugi način čine nedostupnim. Svrha je sprečavanje workload-a da direktno komunicira sa interfejsima koji običnim aplikacijama nisu potrebni, naročito unutar procfs-a.

Ovo je važno zato što mnogi container escape-ovi i trikovi koji utiču na host počinju čitanjem ili upisivanjem specijalnih datoteka unutar `/proc` ili `/sys`. Ako su te lokacije maskirane, napadač gubi direktan pristup korisnom delu kernel kontrolne površine čak i nakon dobijanja izvršavanja koda unutar containera.

## Operacija

Runtime-i često maskiraju odabrane putanje kao što su:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Tačan spisak zavisi od runtime-a i konfiguracije hosta. Važno svojstvo je da putanja postane nedostupna ili zamenjena iz perspektive containera, iako i dalje postoji na hostu.

## Lab

Pregledajte konfiguraciju maskiranih putanja koju Docker izlaže:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Ispitajte stvarno ponašanje mountovanja unutar workload-a:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Bezbednosni uticaj

Masking ne predstavlja glavnu granicu izolacije, ali uklanja nekoliko vrednih post-exploitation meta. Bez maskiranja, kompromitovani container može moći da pregleda stanje kernela, čita osetljive informacije o procesima ili ključevima, odnosno da komunicira sa procfs/sysfs objektima koji nikada nisu smeli da budu vidljivi aplikaciji.

## Pogrešne konfiguracije

Glavna greška je uklanjanje maskiranja širokih klasa putanja radi praktičnosti ili debugovanja. U Podman-u se to može pojaviti kao `--security-opt unmask=ALL` ili ciljano uklanjanje maskiranja. U Kubernetes-u, preširoko izlaganje proc sadržaja može se pojaviti kroz `procMount: Unmasked`. Drugi ozbiljan problem je izlaganje host `/proc` ili `/sys` putanje kroz bind mount, čime se u potpunosti zaobilazi ideja ograničenog prikaza container-a.

## Zloupotreba

Ako je masking slab ili ne postoji, počnite identifikovanjem osetljivih procfs/sysfs putanja kojima se može direktno pristupiti:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Ako je navodno maskirana putanja dostupna, pažljivo je pregledajte:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Šta ove komande mogu otkriti:

- `/proc/timer_list` može otkriti podatke o timerima i scheduleru na hostu. Ovo je uglavnom reconnaissance primitive, ali potvrđuje da container može da čita informacije usmerene ka kernelu koje su obično skrivene.
- `/proc/keys` je mnogo osetljiviji. U zavisnosti od konfiguracije hosta, može otkriti unose u keyringu, opise ključeva i odnose između host servisa koji koriste kernel keyring subsystem.
- `/sys/firmware` pomaže u identifikaciji boot moda, firmware interfejsa i detalja o platformi koji su korisni za fingerprinting hosta i razumevanje da li workload vidi stanje na nivou hosta.
- `/proc/config.gz` može otkriti konfiguraciju kernela koji se izvršava, što je korisno za proveru preduslova javno poznatih kernel exploit-a ili za razumevanje razloga zbog kog je određena funkcija dostupna.
- `/proc/sched_debug` otkriva stanje schedulera i često poništava intuitivno očekivanje da PID namespace treba potpuno da sakrije informacije o nepovezanim procesima.

Zanimljivi rezultati uključuju direktno čitanje tih datoteka, dokaze da podaci pripadaju hostu, a ne ograničenom prikazu containera, ili pristup drugim procfs/sysfs lokacijama koje su podrazumevano često maskirane.

## Provere

Svrha ovih provera jeste da se utvrdi koje je putanje runtime namerno sakrio i da li trenutni workload i dalje vidi smanjeni filesystem usmeren ka kernelu.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Šta je ovde zanimljivo:

- Duga lista maskiranih putanja je uobičajena u ojačanim runtime okruženjima.
- Nedostatak maskiranja na osetljivim procfs unosima zahteva detaljniju proveru.
- Ako je osetljiva putanja dostupna, a container takođe ima jake capabilities ili široke mount-ove, izloženost je značajnija.

## Podrazumevane vrednosti runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućeno | Docker definiše podrazumevanu listu maskiranih putanja | izlaganje host proc/sys mount-ova, `--privileged` |
| Podman | Podrazumevano omogućeno | Podman primenjuje podrazumevane maskirane putanje, osim ako se ručno uklone maske | `--security-opt unmask=ALL`, ciljano uklanjanje maski, `--privileged` |
| Kubernetes | Nasleđuje podrazumevane vrednosti runtime-a | Koristi ponašanje maskiranja osnovnog runtime-a, osim ako Pod postavke oslabe proc izloženost | `procMount: Unmasked`, obrasci privilegovanih workload-ova, široki host mount-ovi |
| containerd / CRI-O under Kubernetes | Podrazumevana vrednost runtime-a | Obično primenjuje OCI/runtime maskirane putanje, osim ako se ne zamene | direktne promene konfiguracije runtime-a, isti Kubernetes načini slabljenja |

Maskirane putanje su obično prisutne podrazumevano. Glavni operativni problem nije njihovo odsustvo iz runtime-a, već namerno uklanjanje maski ili host bind mount-ovi koji poništavaju zaštitu.

{{#include ../../../../banners/hacktricks-training.md}}
