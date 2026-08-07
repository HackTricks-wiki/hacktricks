# Usalama wa Image, Signing, Na Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Usalama wa container huanza kabla ya workload kuzinduliwa. Image huamua ni binaries, interpreters, libraries, startup scripts, na embedded configuration zipi zitafika production. Ikiwa image ina backdoor, imepitwa na wakati, au imetengenezwa huku secrets zikiwa zimehifadhiwa ndani yake, runtime hardening inayofuata tayari inafanya kazi juu ya artifact iliyoathiriwa.

Hii ndiyo sababu image provenance, vulnerability scanning, signature verification, na secret handling zinapaswa kujadiliwa pamoja na namespaces na seccomp. Hulinda awamu tofauti ya lifecycle, lakini failures hapa mara nyingi huamua attack surface ambayo runtime inapaswa baadaye kuzuia.

## Image Registries Na Trust

Images zinaweza kutoka kwenye public registries kama Docker Hub au private registries zinazoendeshwa na organization. Swali la security si image iko wapi tu, bali ikiwa team inaweza kuthibitisha provenance na integrity. Kupull images zisizo na signatures au zisizofuatiliwa vizuri kutoka public sources huongeza hatari ya malicious au tampered content kuingia production. Hata registries zinazo-hostiwa internally zinahitaji ownership, review, na trust policy iliyo wazi.

Docker Content Trust kihistoria ilitumia concepts za Notary na TUF kuhitaji images zilizosainiwa. Ecosystem halisi imeendelea kubadilika, lakini lesson ya kudumu bado ni muhimu: image identity na integrity vinapaswa kuthibitishwa badala ya kudhaniwa.

Mfano wa historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Jambo la mfano si kwamba kila timu lazima iendelee kutumia tooling ileile, bali kwamba signing na key management ni majukumu ya kiutendaji, si nadharia dhahania.

## Vulnerability Scanning

Image scanning husaidia kujibu maswali mawili tofauti. Kwanza, je, image ina packages au libraries zinazojulikana kuwa vulnerable? Pili, je, image ina software isiyo ya lazima inayopanua attack surface? Image iliyojaa debugging tools, shells, interpreters, na packages zilizopitwa na wakati ni rahisi zaidi ku-exploit na ni ngumu zaidi kuielewa.

Mifano ya scanners zinazotumika kwa kawaida ni:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Matokeo kutoka kwa tools hizi yanapaswa kufasiriwa kwa uangalifu. Vulnerability katika package isiyotumika haina risk sawa na exposed RCE path, lakini zote bado ni muhimu katika maamuzi ya hardening.

## Siri za Wakati wa Build

Mojawapo ya makosa ya zamani zaidi katika container build pipelines ni kuingiza secrets moja kwa moja kwenye image au kuzipitisha kupitia environment variables ambazo baadaye huonekana kupitia `docker inspect`, build logs, au layers zilizorejeshwa. Build-time secrets zinapaswa ku-mountiwa kwa muda mfupi wakati wa build badala ya kunakiliwa kwenye image filesystem.

BuildKit iliboresha model hii kwa kuruhusu dedicated build-time secret handling. Badala ya kuandika secret kwenye layer, build step inaweza kuitumia kwa muda mfupi:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Hili ni muhimu kwa sababu image layers ni artifacts zinazodumu. Secret inapoingia kwenye layer iliyocommitiwa, kuifuta faili baadaye kwenye layer nyingine hakuondoi kwa kweli disclosure ya awali kutoka kwenye historia ya image.

## Secrets za Runtime

Secrets zinazohitajika na workload inayoendesha zinapaswa pia kuepuka mifumo ya ad hoc kama vile plain environment variables inapowezekana. Volumes, integrations maalum za secret-management, Docker secrets, na Kubernetes Secrets ni mechanisms zinazotumika kwa kawaida. Hakuna mojawapo ya hizi inayoondoa risk yote, hasa ikiwa attacker tayari ana code execution ndani ya workload, lakini bado ni bora kuliko kuhifadhi credentials kabisa kwenye image au kuzifichua kiholela kupitia inspection tooling.

Tamko rahisi la secret kwa mtindo wa Docker Compose linaonekana hivi:
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
Katika Kubernetes, Secret objects, projected volumes, service-account tokens, na cloud workload identities huunda modeli pana na yenye uwezo zaidi, lakini pia huunda fursa zaidi za kufichuka kwa bahati mbaya kupitia host mounts, RBAC pana, au muundo dhaifu wa Pod.

## Matumizi Mabaya

Unapokagua target, lengo ni kubaini ikiwa secrets ziliingizwa moja kwa moja kwenye image, zili-leak kwenye layers, au ziliwekwa kwenye maeneo ya runtime yanayotabirika:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Amri hizi husaidia kutofautisha kati ya matatizo matatu tofauti: leaks za usanidi wa application, leaks za image-layer, na mafaili ya siri yaliyoingizwa wakati wa runtime. Ikiwa siri itaonekana chini ya `/run/secrets`, projected volume, au cloud identity token path, hatua inayofuata ni kuelewa ikiwa inatoa ufikiaji kwa workload ya sasa pekee au kwa control plane kubwa zaidi.

### Mfano Kamili: Secret Iliyopachikwa Kwenye Image Filesystem

Ikiwa build pipeline ilinakili mafaili ya `.env` au credentials kwenye image ya mwisho, post-exploitation huwa rahisi:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Athari hutegemea application, lakini signing keys zilizopachikwa, JWT secrets, au cloud credentials zinaweza kwa urahisi kubadilisha container compromise kuwa API compromise, lateral movement, au forgery ya trusted application tokens.

### Mfano Kamili: Ukaguzi wa Secret Leakage Wakati wa Build

Ikiwa wasiwasi ni kwamba image history ilinasa layer yenye secret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Aina hii ya ukaguzi ni muhimu kwa sababu secret inaweza kuwa imefutwa kwenye mwonekano wa mwisho wa filesystem huku ikiendelea kubaki kwenye layer ya awali au kwenye build metadata.

## Ukaguzi

Ukaguzi huu unalenga kubaini iwapo image na pipeline ya kushughulikia secret huenda viliongeza attack surface kabla ya runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Kinachovutia hapa:

- Historia ya build yenye mashaka inaweza kufichua credentials zilizonakiliwa, SSH material, au build steps zisizo salama.
- Secrets zilizo chini ya projected volume paths zinaweza kutoa ufikiaji wa cluster au cloud, si ufikiaji wa local application pekee.
- Idadi kubwa ya configuration files zilizo na credentials za plaintext kwa kawaida huashiria kwamba image au deployment model inabeba trust material nyingi kuliko inavyohitajika.

## Default za Runtime

| Runtime / platform | Hali ya default | Tabia ya default | Udhaifu wa kawaida unaofanywa manually |
| --- | --- | --- | --- |
| Docker / BuildKit | Inasaidia secure build-time secret mounts, lakini si automatically | Secrets zinaweza ku-mountiwa kwa muda mfupi wakati wa `build`; image signing na scanning zinahitaji maamuzi ya workflow yaliyo wazi | kunakili secrets ndani ya image, kupitisha secrets kwa `ARG` au `ENV`, kuzima provenance checks |
| Podman / Buildah | Inasaidia OCI-native builds na secret-aware workflows | Build workflows imara zinapatikana, lakini operators bado lazima wazichague kwa makusudi | ku-embed secrets katika Containerfiles, kutumia build contexts pana, bind mounts zenye ruhusa kubwa wakati wa builds |
| Kubernetes | Native Secret objects na projected volumes | Runtime secret delivery ni first-class, lakini exposure hutegemea RBAC, muundo wa pod, na host mounts | Secret mounts zenye ruhusa pana kupita kiasi, matumizi mabaya ya service-account token, `hostPath` access kwa kubelet-managed volumes |
| Registries | Integrity ni optional isipokuwa iwe enforced | Public na private registries zote hutegemea policy, signing, na admission decisions | kuvuta images ambazo hazijasainiwa bila vikwazo, admission control dhaifu, key management isiyofaa |

{{#include ../../../banners/hacktricks-training.md}}
