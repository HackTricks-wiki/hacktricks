# Maskirane putanje

{{#include ../../../../banners/hacktricks-training.md}}

Maskirane putanje su runtime zaštite koje sakrivaju posebno osetljiva fajl-sistemska mesta koja su izložena kernelu od container-a tako što se preko njih izvrši bind-mounting ili ih se na drugi način učini nedostupnim. Svrha je da se spreči da workload direktno komunicira sa interfejsima koji običnim aplikacijama nisu potrebni, naročito unutar procfs.

Ovo je važno zato što mnogi container escapes i trikovi koji utiču na host počinju čitanjem ili pisanjem specijalnih fajlova pod `/proc` ili `/sys`. Ako su te lokacije maskirane, napadač gubi direktan pristup korisnom delu kernel control surface čak i nakon što dobije code execution unutar container-a.

## Operacija

Runtimes obično maskiraju izabrane putanje kao što su:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Tačan spisak zavisi od runtime-a i konfiguracije hosta. Bitna osobina je da putanja postane nedostupna ili zamenjena iz perspektive container-a iako i dalje postoji na hostu.

## Lab

Ispitajte masked-path konfiguraciju koju izlaže Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Ispitaj stvarno ponašanje mount-a unutar radnog opterećenja:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Bezbednosni uticaj

Maskiranje ne stvara glavnu granicu izolacije, ali uklanja nekoliko visokovrednih ciljeva za post-exploitation. Bez maskiranja, kompromitovani kontejner može da ispita stanje kernela, čita osetljive informacije o procesima ili informacijama o ključevima, ili da interaguje sa procfs/sysfs objektima koji nikada ne bi trebalo da budu vidljivi aplikaciji.

## Pogrešne konfiguracije

Glavna greška je otmaskiranje širokih klasa putanja radi praktičnosti ili debugovanja. U Podman ovo se može pojaviti kao `--security-opt unmask=ALL` ili ciljano otmaskiranje. U Kubernetes, preširoko izlaganje proc može se pojaviti kroz `procMount: Unmasked`. Još jedan ozbiljan problem je izlaganje host `/proc` ili `/sys` kroz bind mount, što potpuno zaobilazi ideju smanjenog prikaza kontejnera.

## Zloupotreba

Ako je maskiranje slabo ili ne postoji, počnite identifikacijom koji su osetljivi procfs/sysfs putevi direktno dostupni:
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

- `/proc/timer_list` može izložiti podatke o tajmerima i scheduler-u hosta. Ovo je uglavnom rekognicioni primitiv, ali potvrđuje da kontejner može čitati informacije usmerene prema kernelu koje su obično skrivene.
- `/proc/keys` je mnogo osetljiviji. U zavisnosti od konfiguracije hosta, može otkriti unose u keyring, opise ključeva i odnose između host servisa koji koriste kernel keyring subsystem.
- `/sys/firmware` pomaže da se identifikuje režim boot-ovanja, firmware interfejsi i detalji platforme koji su korisni za fingerprinting hosta i za razumevanje da li workload vidi stanje na nivou hosta.
- `/proc/config.gz` može otkriti konfiguraciju pokrenutog kernela, što je vredno za usklađivanje sa javno dostupnim preduslovima za kernel exploit-e ili za razumevanje zašto je određena funkcionalnost dostupna.
- `/proc/sched_debug` otkriva stanje scheduler-a i često zaobilazi intuitivno očekivanje da PID namespace potpuno sakriva nepovezane informacije o procesima.

Zanimljivi rezultati uključuju direktno čitanje tih fajlova, dokaze da podaci pripadaju hostu umesto ograničenom prikazu kontejnera, ili pristup drugim procfs/sysfs lokacijama koje su po defaultu često maskirane.

## Checks

Cilj ovih provera je da se utvrdi koje je putanje runtime namerno sakrio i da li trenutni workload i dalje vidi redukovan filesystem usmeren ka kernelu.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Šta je zanimljivo ovde:

- Duga lista maskiranih putanja je normalna u ojačanim runtime okruženjima.
- Nedostatak maskiranja osetljivih procfs unosa zaslužuje bližu proveru.
- Ako je osetljiva putanja dostupna i container takođe ima široke capabilities ili široke host mount-ove, izloženost ima veću važnost.

## Podrazumevana ponašanja

| Runtime / platform | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno oslabljivanje |
| --- | --- | --- | --- |
| Docker Engine | Po defaultu omogućeno | Docker definiše podrazumevanu listu maskiranih putanja | izlaganje host proc/sys mount-ova, `--privileged` |
| Podman | Po defaultu omogućeno | Podman primenjuje podrazumevane maskirane putanje osim ako se ne ponište ručno | `--security-opt unmask=ALL`, cilјano otmaskiranje, `--privileged` |
| Kubernetes | Nasleđuje runtime podešavanja | Koristi ponašanje maskiranja osnovnog runtime-a osim ako podešavanja Pod-a ne oslabe izloženost proc-a | `procMount: Unmasked`, obrasci privilegovanih workload-a, široki host mount-ovi |
| containerd / CRI-O under Kubernetes | Runtime podrazumevano | Obično primenjuje OCI/runtime maskirane putanje osim ako nije prepisano | direktne izmene runtime konfiguracije, iste Kubernetes metode oslabljivanja |

Maskirane putanje su obično prisutne po defaultu. Glavni operativni problem nije njihovo odsustvo u runtime-u, već namerno otmaskiranje ili host bind mount-ovi koji poništavaju zaštitu.
{{#include ../../../../banners/hacktricks-training.md}}
