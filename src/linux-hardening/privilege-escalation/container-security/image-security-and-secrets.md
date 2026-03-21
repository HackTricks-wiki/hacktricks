# Usalama wa Image, Kusaini, na Siri

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Usalama wa container huanza kabla ya workload kuanzishwa. Image inaamua binaries, interpreters, libraries, startup scripts, na usanidi uliowekwa ambao utafika production. Ikiwa image ina backdoor, imepitwa na wakati, au imejengwa ikiwa na siri zilizojazwa ndani yake, runtime hardening inayofuata tayari inafanya kazi juu ya artefakti iliyoharibika.

Ndiyo maana asalili ya image (image provenance), vulnerability scanning, signature verification, na secret handling zinapaswa kuwa sehemu ya majadiliano pamoja na namespaces na seccomp. Zinailinda hatua tofauti ya lifecycle, lakini kushindwa hapa mara nyingi huamua attack surface ambayo runtime baadaye inapaswa kudhibiti.

## Image Registries And Trust

Images zinaweza kutoka kwa registries za umma kama Docker Hub au kutoka kwa registries za kibinafsi zinazofanya kazi chini ya shirika. Swali la usalama si tu wapi image inakoishi, bali kama timu inaweza kuanzisha provenance na uadilifu. Kuvuta images zisizosainiwa au zisizofuatiliwa vizuri kutoka vyanzo vya umma kunoongeza hatari ya maudhui yenye nia mbaya au yaliyofanyiwa uharibifu kuingia production. Hata registries zinazohifadhiwa ndani ya shirika zinahitaji umiliki wazi, ukaguzi, na sera ya trust.

Docker Content Trust kwa kihistoria ilitumia dhana za Notary na TUF kuhitaji images kusainiwa. Eneo kamili limeendelea kubadilika, lakini somo linalodumu bado ni muhimu: utambulisho na uadilifu wa image yanapaswa kuwa yanathibitishwa badala ya kudhaniwa.

Mfano wa mtiririko wa kihistoria wa Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Madhumuni ya mfano sio kwamba kila timu lazima bado itumie zana zile zile, bali kwamba signing and key management ni kazi za uendeshaji, sio nadharia.

## Kukagua Udhaifu

Kukagua image husaidia kujibu maswali mawili tofauti. Kwanza, je image ina packages au libraries zinazojulikana kuwa na udhaifu? Pili, je image inabeba software isiyo ya lazima inayoongeza attack surface? Image iliyojaa debugging tools, shells, interpreters, and stale packages ni rahisi zaidi ku-exploit na ngumu zaidi kuelewa.

Mifano ya scanners zinazotumiwa mara kwa mara ni pamoja na:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Matokeo kutoka kwa zana hizi yanapaswa kutafsiriwa kwa makini. Uvunjaji wa usalama katika kifurushi kisichotumika haufanani kwa hatari na njia ya RCE iliyofichuka, lakini zote mbili bado zina umuhimu kwa maamuzi ya kuimarisha usalama.

## Siri za wakati wa kujenga

Moja ya makosa ya zamani katika pipelines za kujenga container ni kuingiza siri moja kwa moja ndani ya image au kuzipitisha kupitia environment variables ambazo baadaye zinaonekana kupitia `docker inspect`, build logs, au layers zilizorejeshwa. Siri za wakati wa kujenga zinapaswa kupakiwa kwa muda mfupi wakati wa build badala ya kunakiliwa kwenye filesystem ya image.

BuildKit iliboresha mfano huu kwa kuruhusu utunzaji maalum wa siri wakati wa kujenga. Badala ya kuandika siri ndani ya layer, hatua ya kujenga inaweza kuitumia kwa muda mfupi:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Hii ni muhimu kwa sababu tabaka za image ni vitu vya kudumu. Mara siri inapowekwa katika tabaka lililowekwa (committed layer), kisha kufuta faili katika tabaka jingine hakufuta kabisa ufunuo wa awali kutoka katika historia ya image.

## Siri za wakati wa utekelezaji

Siri zinazohitajika na workload inayokimbia zinapaswa pia kuepuka mifumo ya ad hoc kama vile variables za mazingira wazi kadri inavyowezekana. Volumes, integrations maalum za usimamizi wa siri, Docker secrets, na Kubernetes Secrets ni mbinu za kawaida. Hakuna kati ya hizi inayoziondoa hatari zote, hasa ikiwa mshambuliaji tayari ana uwezo wa kutekeleza code ndani ya workload, lakini bado ni bora kuliko kuhifadhi credentials kwa kudumu ndani ya image au kuziweka wazi kwa urahisi kupitia tooling za ukaguzi.

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
Katika Kubernetes, Secret objects, projected volumes, service-account tokens, na cloud workload identities huunda modeli pana na yenye nguvu zaidi, lakini pia huongeza fursa za kufichuka kwa bahati mbaya kupitia host mounts, RBAC pana, au muundo dhaifu wa Pod.

## Matumizi mabaya

Wakati unapopitia lengo, lengo ni kugundua kama secrets ziliwekwa ndani ya image, leaked katika layers, au zilifungwa katika maeneo ya runtime yanayoweza kutabirika:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Amri hizi zinausaidia kutofautisha kati ya matatizo matatu tofauti: application configuration leaks, image-layer leaks, na runtime-injected secret files. Ikiwa siri inaonekana chini ya `/run/secrets`, a projected volume, au cloud identity token path, hatua inayofuata ni kuelewa ikiwa inatoa ufikiaji kwa workload ya sasa tu au kwa control plane kubwa zaidi.

### Mfano Kamili: Siri Iliyowekwa Katika Filesystem ya Image

Ikiwa build pipeline ilinakili faili za `.env` au credentials ndani ya image ya mwisho, post-exploitation inakuwa rahisi:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Athari inategemea programu, lakini embedded signing keys, JWT secrets, au cloud credentials zinaweza kwa urahisi kugeuza container compromise kuwa API compromise, lateral movement, au forgery of trusted application tokens.

### Mfano Kamili: Build-Time Secret Leakage Check

Ikiwa wasiwasi ni kwamba image history ilikamata tabaka lenye siri:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Aina hii ya ukaguzi ni muhimu kwa sababu siri inaweza kuwa imefutwa kutoka kwa muonekano wa mwisho wa filesystem huku ikibaki katika tabaka la awali au katika build metadata.

## Mikaguzi

Mikaguzi hizi zinalenga kuthibitisha ikiwa image na secret-handling pipeline zina uwezekano wa kuongeza attack surface kabla ya runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Kinachovutia hapa:

- Historia ya build yenye shaka inaweza kufichua nyaraka za kuingia zilizokopiwa, vifaa vya SSH, au hatua za ujenzi zisizo salama.
- Secrets chini ya projected volume paths zinaweza kusababisha ufikaji wa cluster au cloud, si tu ufikaji wa application za ndani.
- Idadi kubwa ya faili za usanidi zenye nyaraka za kuingia kwa plaintext kawaida inaashiria kuwa image au deployment model inabeba vifaa vya kuamini zaidi ya vinavyohitajika.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhoofishaji wa kawaida kwa mkono |
| --- | --- | --- | --- |
| Docker / BuildKit | Inasaidia secure build-time secret mounts, lakini si kiotomatiki | Secrets zinaweza ku-mounted ephemerally wakati wa `build`; image signing na scanning zinahitaji chaguo la workflow la wazi | copying secrets into the image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Inasaidia OCI-native builds na secret-aware workflows | Build workflows imara zinapatikana, lakini operators lazima waza chagua kwa makusudi | embedding secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects na projected volumes | Runtime secret delivery ni first-class, lakini exposure inategemea RBAC, muundo wa pod, na host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integrity ni hiari isipokuwa imezuiwa | Public na private registries zote zinategemea policy, signing, na admission decisions | pulling unsigned images freely, weak admission control, poor key management |
