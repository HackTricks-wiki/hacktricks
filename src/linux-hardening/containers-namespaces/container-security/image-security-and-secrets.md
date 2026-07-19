# Usalama wa Image, Signing, na Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Usalama wa container huanza kabla ya workload kuzinduliwa. Image huamua ni binaries, interpreters, libraries, startup scripts, na embedded configuration zipi zitakazofika production. Ikiwa image ina backdoor, ni ya zamani, au imejengwa ikiwa na secrets zilizowekwa ndani yake, runtime hardening inayofuata tayari inafanya kazi kwenye artifact iliyoathiriwa.

Hii ndiyo sababu image provenance, vulnerability scanning, signature verification, na secret handling vinapaswa kujadiliwa pamoja na namespaces na seccomp. Vinalinda awamu tofauti ya lifecycle, lakini failures hapa mara nyingi huamua attack surface ambayo runtime italazimika kuidhibiti baadaye.

## Image Registries na Trust

Images zinaweza kutoka kwenye public registries kama Docker Hub au private registries zinazoendeshwa na organization. Swali la usalama si mahali image ilipo pekee, bali ikiwa team inaweza kuthibitisha provenance na integrity. Kuvuta images zisizosainiwa au zisizofuatiliwa vizuri kutoka public sources huongeza hatari ya maudhui hasidi au yaliyobadilishwa kuingia production. Hata registries zinazo-hostiwa internally zinahitaji ownership, review, na trust policy iliyo wazi.

Docker Content Trust kihistoria ilitumia dhana za Notary na TUF kuhitaji images zilizosainiwa. Ecosystem halisi imebadilika, lakini somo linaloendelea kuwa muhimu ni hili: utambulisho na integrity ya image vinapaswa kuthibitishwa badala ya kudhaniwa.

Mfano wa historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Hoja ya mfano huu si kwamba kila team lazima iendelee kutumia tooling ileile, bali kwamba signing na key management ni kazi za kiutendaji, si nadharia ya kufikirika.

## Vulnerability Scanning

Image scanning husaidia kujibu maswali mawili tofauti. Kwanza, je, image ina packages au libraries zinazojulikana kuwa vulnerable? Pili, je, image ina software isiyo ya lazima inayopanua attack surface? Image iliyojaa debugging tools, shells, interpreters, na packages zilizopitwa na wakati ni rahisi zaidi ku-exploit na ni ngumu zaidi kuichanganua.

Mifano ya scanners zinazotumika sana ni:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Matokeo kutoka kwa tools hizi yanapaswa kutafsiriwa kwa uangalifu. Vulnerability iliyo kwenye package isiyotumika haina risk inayofanana na exposed RCE path, lakini zote bado zina umuhimu katika maamuzi ya hardening.

## Build-Time Secrets

Mojawapo ya makosa ya zamani zaidi katika container build pipelines ni kuweka secrets moja kwa moja ndani ya image au kuzipitisha kupitia environment variables ambazo baadaye huonekana kupitia `docker inspect`, build logs, au layers zilizorejeshwa. Build-time secrets zinapaswa ku-mountiwa kwa muda mfupi wakati wa build badala ya kunakiliwa kwenye image filesystem.

BuildKit iliboresha model hii kwa kuruhusu dedicated build-time secret handling. Badala ya kuandika secret ndani ya layer, build step inaweza kuitumia kwa muda mfupi:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Hili ni muhimu kwa sababu image layers ni artifacts za kudumu. Mara secret inapoingia kwenye layer iliyocommitiwa, kuifuta file baadaye katika layer nyingine hakuondoi kwa kweli disclosure ya awali kutoka kwenye historia ya image.

## Secrets za Runtime

Secrets zinazohitajika na workload inayoendesha zinapaswa pia kuepuka mifumo ya ad hoc kama vile plain environment variables inapowezekana. Volumes, dedicated secret-management integrations, Docker secrets, na Kubernetes Secrets ni mechanisms zinazotumika kwa kawaida. Hakuna mojawapo ya hizi inayoondoa risk yote, hasa ikiwa attacker tayari ana code execution ndani ya workload, lakini bado ni bora kuliko kuhifadhi credentials kabisa kwenye image au kuziweka wazi kiholela kupitia inspection tooling.

Tamko rahisi la secret kwa mtindo wa Docker Compose linaweza kuonekana hivi:
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
Katika Kubernetes, Secret objects, projected volumes, service-account tokens, na cloud workload identities huunda model pana na yenye nguvu zaidi, lakini pia huleta fursa zaidi za kuvuja kwa bahati mbaya kupitia host mounts, RBAC pana, au Pod design dhaifu.

## Matumizi mabaya

Wakati wa kukagua target, lengo ni kubaini ikiwa secrets ziliwekwa ndani ya image, zilivuja kwenye layers, au zili-mountiwa katika runtime locations zinazotabirika:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Amri hizi husaidia kutofautisha kati ya matatizo matatu tofauti: **leak** za usanidi wa application, **leak** za image-layer, na faili za siri zilizoingizwa wakati wa runtime. Ikiwa siri itaonekana chini ya `/run/secrets`, projected volume, au cloud identity token path, hatua inayofuata ni kuelewa ikiwa inatoa access kwa workload ya sasa pekee au kwa control plane kubwa zaidi.

### Mfano Kamili: Siri Iliyojumuishwa Kwenye Image Filesystem

Ikiwa build pipeline ilinakili faili za `.env` au credentials kwenye final image, post-exploitation inakuwa rahisi:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Athari hutegemea application, lakini signing keys, JWT secrets, au cloud credentials zilizowekwa ndani zinaweza kwa urahisi kubadilisha container compromise kuwa API compromise, lateral movement, au forgery ya application tokens zinazoaminika.

### Mfano Kamili: Build-Time Secret Leakage Check

Ikiwa wasiwasi ni kwamba image history ilinasa layer yenye secret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Aina hii ya review ni muhimu kwa sababu secret inaweza kuwa imefutwa kutoka kwenye mwonekano wa mwisho wa filesystem huku ikiendelea kubaki kwenye layer ya awali au kwenye build metadata.

## Ukaguzi

Ukaguzi huu unalenga kubaini ikiwa image na pipeline ya kushughulikia secret huenda viliongeza attack surface kabla ya runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Ni nini kinachovutia hapa:

- Historia ya build yenye kutia shaka inaweza kufichua credentials zilizonakiliwa, SSH material, au hatua za build zisizo salama.
- Secrets zilizo chini ya projected volume paths zinaweza kutoa access ya cluster au cloud, si access ya local application pekee.
- Idadi kubwa ya configuration files zenye credentials za plaintext kwa kawaida huonyesha kwamba image au deployment model inabeba trust material zaidi ya inavyohitajika.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Kudhoofisha kwa mikono kunakotokea mara nyingi |
| --- | --- | --- | --- |
| Docker / BuildKit | Inasaidia secure build-time secret mounts, lakini si automatically | Secrets zinaweza kuwekwa kwa muda wakati wa `build`; image signing na scanning vinahitaji maamuzi ya workflow yaliyo wazi | kunakili secrets ndani ya image, kupitisha secrets kwa `ARG` au `ENV`, kuzima provenance checks |
| Podman / Buildah | Inasaidia OCI-native builds na secret-aware workflows | Strong build workflows zinapatikana, lakini operators bado lazima wazichague kwa makusudi | kuingiza secrets ndani ya Containerfiles, build contexts pana, bind mounts zinazoruhusu mengi wakati wa builds |
| Kubernetes | Native Secret objects na projected volumes | Runtime secret delivery ni first-class, lakini exposure inategemea RBAC, pod design, na host mounts | Secret mounts zenye ruhusa pana kupita kiasi, matumizi mabaya ya service-account token, access ya `hostPath` kwa kubelet-managed volumes |
| Registries | Integrity ni ya hiari isipokuwa ilazimishwe | Public na private registries zote hutegemea policy, signing, na admission decisions | kuvuta images zisizosainiwa bila vikwazo, admission control dhaifu, key management mbaya |
{{#include ../../../banners/hacktricks-training.md}}
