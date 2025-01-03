# Usalama wa Docker

{{#include ../../../banners/hacktricks-training.md}}

## **Usalama wa Msingi wa Injini ya Docker**

**Injini ya Docker** inatumia **Namespaces** na **Cgroups** za kernel ya Linux kutenga kontena, ikitoa tabaka la msingi la usalama. Ulinzi wa ziada unapatikana kupitia **Capabilities dropping**, **Seccomp**, na **SELinux/AppArmor**, ukiongeza kutengwa kwa kontena. **Auth plugin** inaweza kuzuia vitendo vya mtumiaji zaidi.

![Usalama wa Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Ufikiaji Salama kwa Injini ya Docker

Injini ya Docker inaweza kufikiwa kwa ndani kupitia socket ya Unix au kwa mbali kwa kutumia HTTP. Kwa ufikiaji wa mbali, ni muhimu kutumia HTTPS na **TLS** ili kuhakikisha usiri, uadilifu, na uthibitisho.

Injini ya Docker, kwa default, inasikiliza kwenye socket ya Unix katika `unix:///var/run/docker.sock`. Kwenye mifumo ya Ubuntu, chaguo za kuanzisha Docker zimefafanuliwa katika `/etc/default/docker`. Ili kuwezesha ufikiaji wa mbali kwa API ya Docker na mteja, fungua daemon ya Docker kupitia socket ya HTTP kwa kuongeza mipangilio ifuatayo:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Hata hivyo, kufichua Docker daemon kupitia HTTP hakupendekezwi kutokana na wasiwasi wa usalama. Inashauriwa kulinda mawasiliano kwa kutumia HTTPS. Kuna mbinu mbili kuu za kulinda mawasiliano:

1. Mteja anathibitisha utambulisho wa seva.
2. Mteja na seva wanathibitisha utambulisho wa kila mmoja.

Vyeti vinatumika kuthibitisha utambulisho wa seva. Kwa mifano ya kina ya mbinu zote mbili, rejelea [**hiki kiongozi**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Usalama wa Picha za Kontena

Picha za kontena zinaweza kuhifadhiwa katika hifadhi za kibinafsi au za umma. Docker inatoa chaguzi kadhaa za kuhifadhi picha za kontena:

- [**Docker Hub**](https://hub.docker.com): Huduma ya hifadhi ya umma kutoka Docker.
- [**Docker Registry**](https://github.com/docker/distribution): Mradi wa chanzo wazi unaowezesha watumiaji kuendesha hifadhi yao wenyewe.
- [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Huduma ya kibiashara ya hifadhi ya Docker, ikijumuisha uthibitishaji wa watumiaji kulingana na majukumu na uunganisho na huduma za directory za LDAP.

### Uchanganuzi wa Picha

Kontena zinaweza kuwa na **udhaifu wa usalama** ama kwa sababu ya picha ya msingi au kwa sababu ya programu iliyosakinishwa juu ya picha ya msingi. Docker inafanya kazi kwenye mradi unaoitwa **Nautilus** ambao unafanya uchunguzi wa usalama wa Kontena na kuorodhesha udhaifu. Nautilus inafanya kazi kwa kulinganisha kila tabaka la picha ya Kontena na hifadhi ya udhaifu ili kubaini mapengo ya usalama.

Kwa maelezo zaidi [**soma hii**](https://docs.docker.com/engine/scan/).

- **`docker scan`**

Amri ya **`docker scan`** inakuwezesha kuchunguza picha za Docker zilizopo kwa kutumia jina la picha au ID. Kwa mfano,endesha amri ifuatayo kuchunguza picha ya hello-world:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
- [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <container_name>:<tag>
```
- [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
- [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker Image Signing

Saini ya picha za Docker inahakikisha usalama na uaminifu wa picha zinazotumika katika kontena. Hapa kuna maelezo mafupi:

- **Docker Content Trust** inatumia mradi wa Notary, unaotegemea The Update Framework (TUF), kusimamia saini za picha. Kwa maelezo zaidi, angalia [Notary](https://github.com/docker/notary) na [TUF](https://theupdateframework.github.io).
- Ili kuwasha uaminifu wa maudhui ya Docker, weka `export DOCKER_CONTENT_TRUST=1`. Kipengele hiki hakijawashwa kwa chaguo-msingi katika toleo la Docker 1.10 na baadaye.
- Ikiwa kipengele hiki kimewashwa, picha zilizotiwa saini pekee ndizo zinaweza kupakuliwa. Kuanzisha kupakia picha kunahitaji kuweka maneno ya siri kwa funguo za mzizi na lebo, huku Docker pia ikisaidia Yubikey kwa usalama wa ziada. Maelezo zaidi yanaweza kupatikana [hapa](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Kujaribu kuvuta picha isiyo na saini huku uaminifu wa maudhui ukiwashwa kunasababisha kosa la "No trust data for latest".
- Kwa kupakia picha baada ya ya kwanza, Docker inauliza neno la siri la funguo za hifadhi ili kusaini picha.

Ili kuhifadhi funguo zako za kibinafsi, tumia amri:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Wakati wa kubadilisha mwenyeji wa Docker, ni muhimu kuhamasisha funguo za mizizi na hazina ili kudumisha shughuli.

## Vipengele vya Usalama wa Kontena

<details>

<summary>Muhtasari wa Vipengele vya Usalama wa Kontena</summary>

**Vipengele Vikuu vya Kutenganisha Mchakato**

Katika mazingira ya kontena, kutenganisha miradi na michakato yake ni muhimu kwa usalama na usimamizi wa rasilimali. Hapa kuna maelezo rahisi ya dhana muhimu:

**Namespaces**

- **Madhumuni**: Kuhakikisha kutenganisha rasilimali kama michakato, mtandao, na mifumo ya faili. Haswa katika Docker, namespaces huzuia michakato ya kontena kuwa tofauti na mwenyeji na kontena nyingine.
- **Matumizi ya `unshare`**: Amri ya `unshare` (au syscall ya msingi) inatumika kuunda namespaces mpya, ikitoa safu ya ziada ya kutenganisha. Hata hivyo, ingawa Kubernetes haizuii hii kimsingi, Docker inafanya hivyo.
- **Kikomo**: Kuunda namespaces mpya hakuruhusu mchakato kurudi kwenye namespaces za kawaida za mwenyeji. Ili kuingia kwenye namespaces za mwenyeji, mtu kwa kawaida anahitaji kupata saraka ya `/proc` ya mwenyeji, akitumia `nsenter` kwa kuingia.

**Control Groups (CGroups)**

- **Kazi**: Kimsingi inatumika kwa kugawa rasilimali kati ya michakato.
- **Nukta ya Usalama**: CGroups wenyewe hazitoi usalama wa kutenganisha, isipokuwa kwa kipengele cha `release_agent`, ambacho, ikiwa kimepangwa vibaya, kinaweza kutumika kwa ufikiaji usioidhinishwa.

**Capability Drop**

- **Umuhimu**: Ni kipengele muhimu cha usalama kwa kutenganisha michakato.
- **Kazi**: Inapunguza vitendo ambavyo mchakato wa mizizi unaweza kufanya kwa kuondoa uwezo fulani. Hata kama mchakato unakimbia kwa ruhusa za mizizi, kukosa uwezo unaohitajika kunazuia kutekeleza vitendo vya kipaumbele, kwani syscalls zitashindwa kutokana na ruhusa zisizotosha.

Hizi ni **uwezo uliobaki** baada ya mchakato kuondoa wengine:
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
**Seccomp**

Imewezeshwa kwa default katika Docker. Inasaidia **kudhibiti zaidi syscalls** ambazo mchakato unaweza kuita.\
**Profaili ya Seccomp ya default ya Docker** inaweza kupatikana katika [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker ina kiolezo ambacho unaweza kuanzisha: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Hii itaruhusu kupunguza uwezo, syscalls, ufikiaji wa faili na folda...

</details>

### Namespaces

**Namespaces** ni kipengele cha kernel ya Linux ambacho **kinagawanya rasilimali za kernel** kwa namna ambayo seti moja ya **michakato** **inaona** seti moja ya **rasilimali** wakati seti nyingine ya **michakato** inaona seti **tofauti** ya rasilimali. Kipengele hiki kinatumika kwa kuwa na namespace sawa kwa seti ya rasilimali na michakato, lakini namespaces hizo zinarejelea rasilimali tofauti. Rasilimali zinaweza kuwepo katika nafasi nyingi.

Docker inatumia Namespaces zifuatazo za kernel ya Linux ili kufikia kutengwa kwa Kontena:

- pid namespace
- mount namespace
- network namespace
- ipc namespace
- UTS namespace

Kwa **maelezo zaidi kuhusu namespaces** angalia ukurasa ufuatao:

{{#ref}}
namespaces/
{{#endref}}

### cgroups

Kipengele cha kernel ya Linux **cgroups** kinatoa uwezo wa **kudhibiti rasilimali kama cpu, memory, io, bandwidth ya mtandao kati** ya seti ya michakato. Docker inaruhusu kuunda Kontena kwa kutumia kipengele cha cgroup ambacho kinatoa udhibiti wa rasilimali kwa Kontena maalum.\
Ifuatayo ni Kontena iliyoundwa na kumbukumbu ya nafasi ya mtumiaji iliyopunguziliwa hadi 500m, kumbukumbu ya kernel iliyopunguziliwa hadi 50m, sehemu ya cpu hadi 512, blkioweight hadi 400. Sehemu ya CPU ni uwiano unaodhibiti matumizi ya CPU ya Kontena. Ina thamani ya default ya 1024 na anuwai kati ya 0 na 1024. Ikiwa Kontena tatu zina sehemu sawa ya CPU ya 1024, kila Kontena inaweza kuchukua hadi 33% ya CPU katika hali ya ushindani wa rasilimali za CPU. blkio-weight ni uwiano unaodhibiti IO ya Kontena. Ina thamani ya default ya 500 na anuwai kati ya 10 na 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Ili kupata cgroup ya kontena unaweza kufanya:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Kwa maelezo zaidi angalia:

{{#ref}}
cgroups.md
{{#endref}}

### Uwezo

Uwezo unaruhusu **udhibiti wa kina kwa uwezo ambao unaweza kuruhusiwa** kwa mtumiaji wa root. Docker inatumia kipengele cha uwezo wa kernel ya Linux ili **kudhibiti shughuli ambazo zinaweza kufanywa ndani ya Kontena** bila kujali aina ya mtumiaji.

Wakati kontena la docker linaendeshwa, **mchakato unashusha uwezo nyeti ambao mchakato unaweza kutumia kutoroka kutoka kwa kutengwa**. Hii inajaribu kuhakikisha kwamba mchakato hauwezi kufanya vitendo nyeti na kutoroka:

{{#ref}}
../linux-capabilities.md
{{#endref}}

### Seccomp katika Docker

Hii ni kipengele cha usalama ambacho kinaruhusu Docker **kudhibiti syscalls** ambazo zinaweza kutumika ndani ya kontena:

{{#ref}}
seccomp.md
{{#endref}}

### AppArmor katika Docker

**AppArmor** ni uboreshaji wa kernel ili kufunga **kontena** kwa seti **ndogo** ya **rasilimali** zenye **profaili za kila programu**.:

{{#ref}}
apparmor.md
{{#endref}}

### SELinux katika Docker

- **Mfumo wa Lebo**: SELinux inatoa lebo ya kipekee kwa kila mchakato na kitu cha mfumo wa faili.
- **Utekelezaji wa Sera**: Inatekeleza sera za usalama ambazo zinaeleza ni vitendo gani lebo ya mchakato inaweza kufanya kwa lebo nyingine ndani ya mfumo.
- **Lebo za Mchakato wa Kontena**: Wakati injini za kontena zinaanzisha michakato ya kontena, kawaida zinapewa lebo ya SELinux iliyofungwa, mara nyingi `container_t`.
- **Uwekaji Lebo wa Faili ndani ya Kontena**: Faili ndani ya kontena kawaida huwekwa lebo kama `container_file_t`.
- **Kanuni za Sera**: Sera ya SELinux hasa inahakikisha kwamba michakato yenye lebo ya `container_t` zinaweza kuingiliana tu (kusoma, kuandika, kutekeleza) na faili zilizo na lebo ya `container_file_t`.

Mekanismu hii inahakikisha kwamba hata kama mchakato ndani ya kontena umeathirika, umefungwa kuingiliana tu na vitu vilivyo na lebo zinazofanana, ikipunguza kwa kiasi kikubwa uharibifu unaoweza kutokea kutokana na athari hizo.

{{#ref}}
../selinux.md
{{#endref}}

### AuthZ & AuthN

Katika Docker, plugin ya idhini ina jukumu muhimu katika usalama kwa kuamua ikiwa ruhusa au kuzuia maombi kwa daemon ya Docker. Uamuzi huu unafanywa kwa kuchunguza muktadha mbili muhimu:

- **Muktadha wa Uthibitishaji**: Hii inajumuisha taarifa kamili kuhusu mtumiaji, kama vile nani walivyo na jinsi walivyojithibitisha.
- **Muktadha wa Amri**: Hii inajumuisha data yote muhimu inayohusiana na ombi linalofanywa.

Muktadha hii husaidia kuhakikisha kwamba maombi halali tu kutoka kwa watumiaji walioidhinishwa yanashughulikiwa, ikiongeza usalama wa shughuli za Docker.

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## DoS kutoka kwa kontena

Ikiwa hujapunguza ipasavyo rasilimali ambazo kontena linaweza kutumia, kontena lililoathirika linaweza kufanya DoS kwa mwenyeji ambapo linaendesha.

- CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
- Bandwidth DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Bendera za Kuvutia za Docker

### --privileged flag

Katika ukurasa ufuatao unaweza kujifunza **ni nini `--privileged` flag inamaanisha**:

{{#ref}}
docker-privileged.md
{{#endref}}

### --security-opt

#### no-new-privileges

Ikiwa unakimbia kontena ambapo mshambuliaji anafanikiwa kupata ufikiaji kama mtumiaji wa hadhi ya chini. Ikiwa una **suid binary iliyo na makosa**, mshambuliaji anaweza kuitumia vibaya na **kuinua hadhi ndani** ya kontena. Hii, inaweza kumruhusu kutoroka kutoka kwake.

Kukimbia kontena na chaguo la **`no-new-privileges`** limewezeshwa litazuia **aina hii ya kuinua hadhi**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Mengineyo
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Kwa maelezo zaidi ya chaguzi za **`--security-opt`** angalia: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Mambo Mengine ya Usalama

### Kusimamia Siri: Mbinu Bora

Ni muhimu kuepuka kuweka siri moja kwa moja katika picha za Docker au kutumia mabadiliko ya mazingira, kwani mbinu hizi zinaweka taarifa zako nyeti wazi kwa yeyote mwenye ufikiaji wa kontena kupitia amri kama `docker inspect` au `exec`.

**Docker volumes** ni mbadala salama, inashauriwa kwa ufikiaji wa taarifa nyeti. Zinatumika kama mfumo wa faili wa muda katika kumbukumbu, kupunguza hatari zinazohusiana na `docker inspect` na logging. Hata hivyo, watumiaji wa root na wale wenye ufikiaji wa `exec` kwa kontena bado wanaweza kufikia siri hizo.

**Docker secrets** inatoa njia salama zaidi ya kushughulikia taarifa nyeti. Kwa matukio yanayohitaji siri wakati wa awamu ya kujenga picha, **BuildKit** inatoa suluhisho bora na msaada wa siri za wakati wa kujenga, ikiongeza kasi ya kujenga na kutoa vipengele vya ziada.

Ili kutumia BuildKit, inaweza kuwashwa kwa njia tatu:

1. Kupitia mabadiliko ya mazingira: `export DOCKER_BUILDKIT=1`
2. Kwa kuweka mbele amri: `DOCKER_BUILDKIT=1 docker build .`
3. Kwa kuifanya iwe ya kawaida katika usanidi wa Docker: `{ "features": { "buildkit": true } }`, ikifuatiwa na upya wa Docker.

BuildKit inaruhusu matumizi ya siri za wakati wa kujenga kwa chaguo la `--secret`, kuhakikisha kwamba siri hizi hazijumuishwi katika cache ya kujenga picha au picha ya mwisho, kwa kutumia amri kama:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Kwa siri zinazohitajika katika kontena linalofanya kazi, **Docker Compose na Kubernetes** hutoa suluhisho thabiti. Docker Compose inatumia ufunguo wa `secrets` katika ufafanuzi wa huduma kwa ajili ya kubainisha faili za siri, kama inavyoonyeshwa katika mfano wa `docker-compose.yml`:
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
Hii usanidi inaruhusu matumizi ya siri wakati wa kuanzisha huduma na Docker Compose.

Katika mazingira ya Kubernetes, siri zinasaidiwa kiasili na zinaweza kusimamiwa zaidi kwa zana kama [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Udhibiti wa Upatikanaji Kulingana na Majukumu (RBAC) wa Kubernetes unaboresha usalama wa usimamizi wa siri, sawa na Docker Enterprise.

### gVisor

**gVisor** ni kernel ya programu, iliyoandikwa kwa Go, inayotekeleza sehemu kubwa ya uso wa mfumo wa Linux. Inajumuisha runtime ya [Open Container Initiative (OCI)](https://www.opencontainers.org) inayoitwa `runsc` ambayo inatoa **mipaka ya kutengwa kati ya programu na kernel ya mwenyeji**. Runtime ya `runsc` inajumuishwa na Docker na Kubernetes, na kufanya iwe rahisi kuendesha kontena zilizowekwa kwenye sanduku.

{{#ref}}
https://github.com/google/gvisor
{{#endref}}

### Kata Containers

**Kata Containers** ni jamii ya chanzo wazi inayofanya kazi kujenga runtime salama ya kontena yenye mashine za virtual nyepesi ambazo zina hisia na utendaji kama kontena, lakini zinatoa **kutengwa kwa mzigo zaidi kwa kutumia teknolojia ya virtualisasi ya vifaa** kama safu ya pili ya ulinzi.

{{#ref}}
https://katacontainers.io/
{{#endref}}

### Vidokezo vya Muhtasari

- **Usitumie bendera ya `--privileged` au kuunganisha** [**Docker socket ndani ya kontena**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Socket ya docker inaruhusu kuanzisha kontena, hivyo ni njia rahisi ya kuchukua udhibiti kamili wa mwenyeji, kwa mfano, kwa kuendesha kontena nyingine na bendera ya `--privileged`.
- Usifanye **kama root ndani ya kontena. Tumia** [**mtumiaji tofauti**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **na** [**majina ya watumiaji**](https://docs.docker.com/engine/security/userns-remap/)**.** Root ndani ya kontena ni sawa na kwenye mwenyeji isipokuwa ikirekebishwa na majina ya watumiaji. Inapunguziliwa mbali kidogo na, hasa, majina ya Linux, uwezo, na cgroups.
- [**Ondoa uwezo wote**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) na wezesha tu wale wanaohitajika** (`--cap-add=...`). Mzigo mwingi hauhitaji uwezo wowote na kuongeza uwezo huongeza wigo wa shambulio linaloweza kutokea.
- [**Tumia chaguo la usalama "no-new-privileges"**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) ili kuzuia michakato kupata zaidi ya uwezo, kwa mfano kupitia binaries za suid.
- [**Punguza rasilimali zinazopatikana kwa kontena**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Mipaka ya rasilimali inaweza kulinda mashine kutokana na mashambulizi ya kukataa huduma.
- **Sahihisha** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(au SELinux)** wasifu ili kupunguza vitendo na syscalls vinavyopatikana kwa kontena hadi kiwango cha chini kinachohitajika.
- **Tumia** [**picha rasmi za docker**](https://docs.docker.com/docker-hub/official_images/) **na uhitaji saini** au jenga yako mwenyewe kulingana nazo. Usirithi au kutumia [picha zenye backdoor](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) . Pia hifadhi funguo za root, neno la siri mahali salama. Docker ina mipango ya kusimamia funguo na UCP.
- **Kila wakati** **jenga upya** picha zako ili **kuweka sasisho za usalama kwa mwenyeji na picha.**
- Simamia **siri zako kwa busara** ili iwe vigumu kwa mshambuliaji kuzipata.
- Ikiwa un **weka docker daemon tumia HTTPS** na uthibitishaji wa mteja na seva.
- Katika Dockerfile yako, **pendelea COPY badala ya ADD**. ADD inatoa kiotomatiki kufungua faili zilizoshonwa na inaweza nakala faili kutoka URL. COPY haina uwezo huu. Kila wakati inapowezekana, epuka kutumia ADD ili usiwe hatarini kwa mashambulizi kupitia URL za mbali na faili za Zip.
- Kuwa na **kontena tofauti kwa kila huduma ndogo**
- **Usiweke ssh** ndani ya kontena, “docker exec” inaweza kutumika kuingia kwenye Kontena.
- Kuwa na **picha za kontena** **ndogo**

## Docker Breakout / Privilege Escalation

Ikiwa uko **ndani ya kontena la docker** au una ufikiaji wa mtumiaji katika **kikundi cha docker**, unaweza kujaribu **kutoroka na kupandisha mamlaka**:

{{#ref}}
docker-breakout-privilege-escalation/
{{#endref}}

## Docker Authentication Plugin Bypass

Ikiwa una ufikiaji wa socket ya docker au una ufikiaji wa mtumiaji katika **kikundi cha docker lakini vitendo vyako vinapunguziliwa mbali na plugin ya uthibitishaji wa docker**, angalia ikiwa unaweza **kuipita:**

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## Hardening Docker

- Zana [**docker-bench-security**](https://github.com/docker/docker-bench-security) ni script inayokagua mazoea bora ya kawaida kuhusu kupeleka kontena za Docker katika uzalishaji. Majaribio yote ni ya kiotomatiki, na yanategemea [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Unahitaji kuendesha zana hiyo kutoka kwa mwenyeji anayekimbia docker au kutoka kwa kontena lenye mamlaka ya kutosha. Pata **jinsi ya kuendesha katika README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Marejeleo

- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
- [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
- [https://docs.docker.com/engine/extend/plugins_authorization](https://docs.docker.com/engine/extend/plugins_authorization)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

{{#include ../../../banners/hacktricks-training.md}}
