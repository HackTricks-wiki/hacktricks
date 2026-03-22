# Tathmini na Kuimarisha

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Tathmini nzuri ya container inapaswa kujibu maswali mawili yanayolingana. Kwanza, mshambuliaji anaweza kufanya nini kutoka kwa workload ya sasa? Pili, ni chaguzi gani za operator zilizofanya hilo kuwawezekano? Vifaa vya enumeration husaidia kwenye swali la kwanza, na mwongozo wa kuimarisha husaidia kwenye la pili. Kuweka vyote kwenye ukurasa mmoja kunafanya sehemu hii iwe marejeo ya vitani badala ya orodha tu ya mbinu za escape.

## Zana za Enumeration

Zana kadhaa zinabaki kuwa muhimu kwa kuainisha mazingira ya container kwa haraka:

- `linpeas` inaweza kubainisha viashiria vingi vya container, sockets zilizopachikwa, capability sets, mfumo wa faili hatari, na vidokezo vya breakout.
- `CDK` inalenga mahsusi mazingira ya container na inajumuisha enumeration pamoja na baadhi ya escape checks za kiotomatiki.
- `amicontained` ni nyepesi na inafaa kutambua restrictions za container, capabilities, namespace exposure, na classes za breakout zinazowezekana.
- `deepce` ni enumerator mwingine wa kuzingatia container yenye checks zinazolenga breakout.
- `grype` inafaa wakati tathmini inajumuisha mapitio ya image-package vulnerability badala ya tu runtime escape analysis.

Thamani ya zana hizi ni kasi na ufunikaji, si uhakika. Zinasaidia kufichua mkao wa jumla kwa haraka, lakini matokeo ya kuvutia bado yanahitaji tafsiri ya mwongozo kulingana na runtime, namespace, capability, na mount model halisi.

## Vipaumbele vya Kuimarisha

Misingi muhimu ya kuimarisha ni rahisi kimsingi ingawa utekelezaji wake unatofautiana kwa kila platform. Epuka privileged containers. Epuka mounted runtime sockets. Usiwape containers writable host paths isipokuwa kuna sababu maalum sana. Tumia user namespaces au rootless execution inapowezekana. Ondoa capabilities zote na urejee tu zile ambazo workload inahitaji kweli. Wawezeshe seccomp, AppArmor, na SELinux badala ya kuzizima ili kutatua matatizo ya ulinganifu wa application. Punguza rasilimali ili container iliyovamiwa isiweze kwa urahisi kupiga deny service kwa host.

Usafi wa image na build ni muhimu kama mkao wa runtime. Tumia minimal images, jenga upya mara kwa mara, zipime, omba provenance inapowezekana, na weka secrets nje ya layers. Container inayokimbia kama non-root ikiwa na image ndogo na uso mdogo wa syscall na capability ni rahisi zaidi kuilinda kuliko large convenience image inayokimbia kama host-equivalent root na debugging tools zikiwa zimewekwa awali.

## Mifano ya Upungufu wa Rasilimali

Udhibiti wa rasilimali sio wa kuvutia, lakini ni sehemu ya usalama wa container kwa sababu unapunguza blast radius ya kuathiriwa. Bila mipaka ya memory, CPU, au PID, shell rahisi inaweza kutosha kudhoofisha host au workloads jirani.

Mifano ya majaribio yanayoathiri host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Mifano hii ni muhimu kwa sababu inaonyesha kwamba si kila matokeo hatari ya container ni "escape". Mipaka dhaifu ya cgroup bado yanaweza kubadilisha code execution kuwa athari halisi za uendeshaji.

## Zana za Kuimarisha

Kwa mazingira yanayolenga Docker, `docker-bench-security` bado ni msingi mzuri wa ukaguzi upande wa host kwa sababu inakagua masuala ya usanidi ya kawaida dhidi ya mwongozo wa viwango vinavyotambulika kwa upana:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Zana hii si mbadala wa threat modeling, lakini bado ni muhimu kwa kutafuta careless daemon, mount, network, na runtime defaults ambazo zinaongezeka kwa muda.

## Ukaguzi

Tumia haya kama amri za awali za hatua ya kwanza wakati wa tathmini:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Kinachovutia hapa:

- Root process yenye broad capabilities na `Seccomp: 0` inastahili umakini wa haraka.
- Mounts zenye shaka na runtime sockets mara nyingi hutoa njia ya haraka zaidi ya kuleta athari kuliko kernel exploit yoyote.
- Mchanganyiko wa weak runtime posture na weak resource limits kwa kawaida unaonyesha container environment kwa ujumla yenye ruhusa nyingi badala ya kosa moja lililotengwa.
{{#include ../../../banners/hacktricks-training.md}}
