# Maskirane putanje

{{#include ../../../../banners/hacktricks-training.md}}

Maskirane putanje su runtime zaštite koje sakrivaju posebno osetljive lokacije fajl-sistema okrenute ka kernelu od containera tako što ih bind-mountuju preko njih ili ih na drugi način čine nedostupnim. Cilj je da se spreči workload da direktno komunicira sa interfejsima koje običnim aplikacijama nisu potrebne, naročito unutar procfs.

## Operacija

Runtimes obično maskiraju izabrane putanje kao što su:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Tačan spisak zavisi od runtime-a i konfiguracije host-a. Važna osobina je da putanja postane nedostupna ili zamenjena iz perspektive containera, iako ona i dalje postoji na host-u.

## Lab

Pregledajte masked-path konfiguraciju koju izlaže Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Proverite stvarno ponašanje mount-a unutar workload-a:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Uticaj na bezbednost

Maskiranje ne stvara glavnu granicu izolacije, ali uklanja nekoliko visokovrednih post-exploitation ciljeva. Bez maskiranja, kompromitovan kontejner može moći da ispita stanje kernela, čita osetljive informacije o procesima ili o ključevima, ili da interaguje sa procfs/sysfs objektima koji nikada ne bi trebalo da budu vidljivi aplikaciji.

## Pogrešne konfiguracije

Glavna greška je uklanjanje maskiranja širokih klasa putanja radi pogodnosti ili debagovanja. U Podman ovo se može pojaviti kao `--security-opt unmask=ALL` ili ciljno uklanjanje maskiranja. U Kubernetes, preširoko izlaganje proc-a može se pojaviti kroz `procMount: Unmasked`. Još jedan ozbiljan problem je izlaganje host `/proc` ili `/sys` kroz bind mount, što u potpunosti zaobilazi ideju smanjenog prikaza kontejnera.

## Zloupotreba

Ako je maskiranje slabo ili odsutno, počnite identifikovanjem koje osetljive procfs/sysfs putanje su direktno dostupne:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Ako je navodno maskiran path dostupan, pažljivo ga pregledajte:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` može otkriti podatke o host timeru i scheduleru. Ovo je uglavnom primitiv za izviđanje, ali potvrđuje da kontejner može čitati informacije usmerene ka kernelu koje su obično skrivene.
- `/proc/keys` je znatno osetljiviji. U zavisnosti od host konfiguracije, može otkriti keyring unose, opise ključeva i odnose između host servisa koji koriste kernel keyring subsystem.
- `/sys/firmware` pomaže u identifikaciji režima bootovanja, firmware interfejsa i detalja platforme koji su korisni za host fingerprinting i za razumevanje da li workload vidi stanje na nivou hosta.
- `/proc/config.gz` može otkriti konfiguraciju pokrenutog kernela, što je vredno za usklađivanje sa javnim kernel exploit preduslovima ili za razumevanje zašto je određena funkcija dostupna.
- `/proc/sched_debug` otkriva stanje scheduler-a i često zaobilazi intuitivno očekivanje da PID namespace treba potpuno sakriti informacije o nepovezanim procesima.

Zanimljivi rezultati uključuju direktno čitanje tih fajlova, dokaze da podaci pripadaju hostu umesto ograničenom prikazu kontejnera, ili pristup drugim procfs/sysfs lokacijama koje su obično maskirane po defaultu.

## Provere

Cilj ovih provera je utvrditi koje putanje je runtime namerno sakrio i da li trenutni workload i dalje vidi redukovani datotečni sistem okrenut ka kernelu.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Šta je zanimljivo ovde:

- Dugačka lista maskiranih putanja je normalna u ojačanim runtime okruženjima.
- Nedostatak maskiranja osetljivih procfs unosa zaslužuje bližu proveru.
- Ako je osetljiva putanja dostupna i container takođe ima jake capabilities ili široke mountove, izloženost je značajnija.

## Podrazumevana podešavanja runtime-a

| Runtime / platform | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Omogućeno podrazumevano | Docker definiše podrazumevanu listu maskiranih putanja | izlaganje host proc/sys mountova, `--privileged` |
| Podman | Omogućeno podrazumevano | Podman primenjuje podrazumevane maskirane putanje osim ako nisu ručno odmaskirane | `--security-opt unmask=ALL`, ciljano odmaskiranje, `--privileged` |
| Kubernetes | Nasleđuje podrazumevana runtime podešavanja | Koristi masking mehanizam osnovnog runtima osim ako podešavanja Poda ne oslabe izloženost proc-a | `procMount: Unmasked`, obrasci privilegovanih workload-ova, široki host mountovi |
| containerd / CRI-O under Kubernetes | Podrazumevano ponašanje runtima | Obično primenjuje OCI/runtime maskirane putanje osim ako nije prepisano | direktne izmene runtime konfiguracije, iste Kubernetes metode slabljenja |

Maskirane putanje su obično prisutne po podrazumevanju. Glavni operativni problem nije njihovo odsustvo u runtime-u, već namensko odmaskiranje ili host bind mountovi koji poništavaju zaštitu.
