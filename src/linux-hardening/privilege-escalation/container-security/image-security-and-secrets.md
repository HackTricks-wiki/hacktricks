# Usalama wa Image, Kusaini, na Siri

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Usalama wa container huanza kabla ya workload kuanzishwa. Image inaamua ni binaries gani, interpreters, libraries, startup scripts, na usanidi uliopachikwa utakaofika uzalishaji. Ikiwa image ina backdoor, imechakaa, au imetengenezwa ikiwa na siri zilizochomwa ndani yake, hardening ya runtime inayofuata tayari inafanya kazi juu ya artefakti iliyokumbwa.

Hili ndilo sababu asili ya image (image provenance), vulnerability scanning, signature verification, na usimamizi wa siri vinavyostahili kuwekwa katika mazungumzo yale yale na namespaces na seccomp. Vinalinda hatua tofauti ya mzunguko wa maisha, lakini kushindwa hapa mara nyingi huamua uso wa shambulio ambao runtime itabidi udhibiti baadaye.

## Rejista za Image na Uaminifu

Images zinaweza kuja kutoka kwa rejista za umma kama Docker Hub au kutoka kwa rejista za kibinafsi zinazoendeshwa na shirika. Swali la usalama si tu sehemu image inapoishi, bali kama timu inaweza kuanzisha asili na uadilifu. Kuvuta images zisizopigwa saini au zisizoendeshwa vizuri kutoka vyanzo vya umma huongeza hatari ya maudhui mabaya au yaliyofanyiwa tampering kuingia kwenye uzalishaji. Hata rejista zinazohostwa ndani ya shirika zinahitaji umiliki wazi, ukaguzi, na sera ya uaminifu.

Docker Content Trust kihistoria ilitumia Notary na dhana za TUF kuhitaji images zilizosainiwa. Eneo kamili limeendelea kubadilika, lakini somo linalodumu bado ni la manufaa: utambulisho na uadilifu wa image yanapaswa kuthibitishwa badala ya kubahatishwa.

Mfano wa mtiririko wa kihistoria wa Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Madhumuni ya mfano sio kwamba kila timu lazima itumie tooling ile ile, bali kwamba signing and key management ni kazi za uendeshaji, si nadharia.

## Ukaguzi wa Udhaifu

Image scanning husaidia kujibu maswali mawili tofauti. Kwanza, je image ina known vulnerable packages or libraries? Pili, je image ina software isiyohitajika inayopanua attack surface? An image iliyojaa debugging tools, shells, interpreters, and stale packages ni rahisi zaidi ku-exploit na ngumu zaidi kuelewa.

Mifano ya commonly used scanners ni pamoja na:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Matokeo kutoka kwa zana hizi yanapaswa kufasiriwa kwa uangalifu. Udhaifu katika kifurushi kisichotumiwa sio hatari sawa na njia ya RCE iliyo wazi, lakini zote mbili bado zina umuhimu kwa maamuzi ya kuimarisha usalama.

## Siri za Wakati wa Kujenga

Mojawapo ya makosa ya zamani katika pipelines za kujenga container ni kuweka siri moja kwa moja ndani ya image au kuzituma kupitia environment variables ambazo baadaye zinaonekana kupitia `docker inspect`, build logs, au recovered layers. Siri za wakati wa kujenga zinapaswa kupangwa kwa muda wakati wa kujenga badala ya kunakiliwa ndani ya filesystem ya image.

BuildKit iliiboresha modeli hii kwa kuruhusu utunzaji maalum wa siri wakati wa kujenga. Badala ya kuandika siri ndani ya layer, hatua ya build inaweza kuitumia kwa muda mfupi:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Hii ni muhimu kwa sababu tabaka za image ni artefakti za kudumu. Mara siri inapoweka kwenye tabaka lililokomitiwa (committed layer), kuifuta faili baadaye katika tabaka jingine hakutaondoa kweli ufunuo wa awali kutoka kwenye historia ya image.

## Siri za runtime

Siri zinazohitajika na workload inayofanya kazi zinapaswa pia kuepuka mbinu za ad hoc kama environment variables kadiri inavyowezekana. Volumes, dedicated secret-management integrations, Docker secrets, na Kubernetes Secrets ni mekanismo za kawaida. Hakuna kati yao inayotupa hatari zote, hasa ikiwa mshambuliaji tayari ana code execution kwenye workload, lakini bado ni bora kuliko kuhifadhi credentials kwa kudumu ndani ya image au kuziweka wazi kwa urahisi kupitia tooling za ukaguzi.

Tangazo rahisi la siri kwa mtindo wa Docker Compose linaonekana kama:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
In Kubernetes, Secret objects, projected volumes, service-account tokens, and cloud workload identities hutoa mfumo mpana na wenye nguvu zaidi, lakini pia huleta fursa zaidi za kufichuka kwa bahati mbaya kupitia host mounts, broad RBAC, au weak Pod design.

## Matumizi mabaya

Unapokagua target, lengo ni kugundua kama secrets zilikuwa zimewekwa ndani ya image, leaked into layers, au zilimountiwa katika predictable runtime locations:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Amri hizi husaidia kutofautisha matatizo matatu tofauti: usanidi wa programu leaks, image-layer leaks, na faili za secret zilizowekwa wakati wa runtime. Ikiwa secret inaonekana chini ya `/run/secrets`, projected volume, au cloud identity token path, hatua inayofuata ni kuelewa kama inatoa ufikiaji kwa workload ya sasa tu au kwa control plane kubwa zaidi.

### Mfano Kamili: Secret Iliyojumuishwa Katika Image Filesystem

Iwapo build pipeline ilikopia faili za `.env` au credentials ndani ya image ya mwisho, post-exploitation inakuwa rahisi:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Matokeo yanategemea programu, lakini embedded signing keys, JWT secrets, au cloud credentials yanaweza kwa urahisi kugeuza container compromise kuwa API compromise, lateral movement, au kughushi trusted application tokens.

### Mfano Kamili: Build-Time Secret Leakage Check

Ikiwa wasiwasi ni kwamba image history ilikamata secret-bearing layer:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Aina hii ya ukaguzi ni muhimu kwa sababu siri inaweza kuwa imefutwa kutoka kwenye mtazamo wa filesystem wa mwisho huku ikibaki katika tabaka la awali au katika build metadata.

## Mikaguzi

Mikaguzi haya yanalenga kuthibitisha kama image na pipeline ya kushughulikia siri zinaweza kuwa zimeongeza attack surface kabla ya runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
What is interesting here:

- Historia ya build yenye kutiliwa shaka inaweza kufichua credentials zilizokopiwa, vifaa vya SSH, au hatua zisizo salama za build.
- Secrets chini ya projected volume paths zinaweza kusababisha access kwa cluster au cloud, si tu access ya programu ya ndani.
- Idadi kubwa ya faili za configuration zilizo na credentials kwa plaintext kawaida zinaonyesha kwamba image au deployment model inabeba nyenzo za kuaminika zaidi ya inavyohitajika.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Inasaidia secure build-time secret mounts, lakini si moja kwa moja | Secrets zinaweza mounted kwa muda mfupi wakati wa `build`; image signing na scanning zinahitaji uchaguzi wa workflow wazi | kunakili secrets ndani ya image, kupitisha secrets kwa `ARG` au `ENV`, kuzima provenance checks |
| Podman / Buildah | Inasaidia OCI-native builds na secret-aware workflows | Workflows imara za kujenga zinapatikana, lakini operators lazima wazichague kwa makusudi | kuingiza secrets ndani ya Containerfiles, broad build contexts, permissive bind mounts wakati wa builds |
| Kubernetes | Native Secret objects na projected volumes | Utoaji wa secrets wakati wa runtime ni first-class, lakini mfichiko unategemea RBAC, muundo wa pod, na host mounts | overbroad Secret mounts, utumiaji mbaya wa service-account token, `hostPath` access kwa volumes zinazosimamiwa na kubelet |
| Registries | Uadilifu ni hiari isipokuwa ukatekelezwa | Registries za public na private zote zinategemea sera, kusaini, na maamuzi ya admission | kuchukua images zisizosainiwa kwa uhuru, weak admission control, usimamizi mbaya wa funguo |
{{#include ../../../banners/hacktricks-training.md}}
