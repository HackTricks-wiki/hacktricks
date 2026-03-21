# Tathmini na Uimarishaji

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Tathmini nzuri ya container inapaswa kujibu maswali mawili sambamba. Kwanza, mshambuliaji anaweza kufanya nini kutoka kwa current workload? Pili, ni uchaguzi gani wa operator uliowafanya iwezekane? Zana za enumeration husaidia kwa swali la kwanza, na mwongozo wa uimarishaji husaidia kwa la pili. Kuweka yote kwenye ukurasa mmoja kunafanya sehemu iwe ya rufaa ya kiwanja badala ya katalogi tu ya escape tricks.

## Zana za Uorodheshaji

Zana kadhaa zinaendelea kuwa muhimu kwa haraka kuainisha mazingira ya container:

- `linpeas` inaweza kubaini dalili nyingi za container, mounted sockets, capability sets, dangerous filesystems, na breakout hints.
- `CDK` inazingatia hasa mazingira ya container na inajumuisha enumeration pamoja na baadhi ya automated escape checks.
- `amicontained` ni lightweight na inafaa kwa kubaini container restrictions, capabilities, namespace exposure, na breakout classes zinazowezekana.
- `deepce` ni enumerator mwingine mwenye lengo la container mwenye breakout-oriented checks.
- `grype` inafaa wakati tathmini inajumuisha image-package vulnerability review badala ya tu runtime escape analysis.

Thamani ya zana hizi iko katika haraka na ufunikaji, sio uhakika. Zinasaidia kufichua msimamo wa jumla kwa haraka, lakini matokeo ya kuvutia bado yanahitaji tafsiri ya mkono dhidi ya runtime halisi, namespace, capability, na mount model.

## Vipaumbele vya Uimarishaji

Misingi muhimu ya uimarishaji ni rahisi kwa dhana ingawa utekelezaji wake unatofautiana kwa kila jukwaa. Epuka privileged containers. Epuka mounted runtime sockets. Usiwape containers writable host paths isipokuwa kuna sababu maalum sana. Tumia user namespaces au rootless execution pale inapowezekana. Toa capabilities zote na uzirudishe tu zile ambazo workload inahitaji kweli. Weka seccomp, AppArmor, na SELinux zikiwa enabled badala ya kuzizima ili kutatua matatizo ya application compatibility. Punguza resources ili container iliyoharibiwa isiweze kwa urahisi kuzuia huduma kwa host.

Usafi wa image na build ni muhimu kama msimamo wa runtime. Tumia minimal images, rebuild mara kwa mara, scan hizo images, iombe provenance inapofaa, na weka secrets nje ya layers. Container inayokimbia kama non-root kwa image ndogo na uso mdogo wa syscall na capability ni rahisi zaidi kuilinda kuliko large convenience image inayokimbia kama host-equivalent root ikiwa na debugging tools zilizo preinstalled.

## Mifano ya Kuchoka kwa Rasilimali

Controls za rasilimali si za kuvutia, lakini ni sehemu ya container security kwa sababu zinapunguza blast radius ya compromise. Bila memory, CPU, au PID limits, shell rahisi inaweza kutosha kuharibu host au workloads jirani.

Mifano ya majaribio yanayoathiri host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Mifano hii ni muhimu kwa sababu zinaonyesha kwamba si kila matokeo hatarishi ya container ni "escape" safi. Vizingiti dhaifu vya cgroup bado vinaweza kugeuza code execution kuwa athari halisi za kiutendaji.

## Hardening Tooling

Kwa mazingira yanayozingatia Docker, `docker-bench-security` bado ni msingi muhimu wa ukaguzi upande wa mwenyeji, kwa sababu inachunguza masuala ya kawaida ya usanidi dhidi ya miongozo ya benchmark inayotambulika sana:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Chombo hiki si mbadala wa threat modeling, lakini bado ni muhimu kwa kugundua daemon, mount, network, na runtime mipangilio ya chaguo-msingi yasiyotiliwa maanani ambazo hujikusanya kwa muda.

## Mikaguzi

Tumia hizi kama amri za awali kwa haraka wakati wa tathmini:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Root process yenye uwezo mpana na `Seccomp: 0` inastahili umakini wa papo hapo.
- Mounts zenye shaka na runtime sockets mara nyingi hutoa njia ya haraka zaidi za kuleta athari kuliko kernel exploit yoyote.
- Mchanganyiko wa runtime posture dhaifu na resource limits dhaifu kwa kawaida unaonyesha container environment inayoruhusu vingi, badala ya kosa moja pekee lililotengwa.
