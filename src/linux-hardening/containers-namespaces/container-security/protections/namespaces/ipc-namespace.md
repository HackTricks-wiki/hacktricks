# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

The IPC namespace hutenganisha **System V IPC objects** na **POSIX message queues**. Hii inajumuisha shared memory segments, semaphores, na message queues ambazo vinginevyo zingeonekana katika processes zisizohusiana kwenye host. Kwa maneno ya kiutendaji, hii huzuia container ku-attach kwa urahisi kwenye IPC objects zinazomilikiwa na workloads nyingine au host.

Ikilinganishwa na mount, PID, au user namespaces, IPC namespace hujadiliwa mara chache, lakini hilo halipaswi kuchukuliwa kumaanisha kuwa haina umuhimu. Shared memory na IPC mechanisms zinazohusiana zinaweza kuwa na state yenye manufaa makubwa. Ikiwa host IPC namespace imefichuliwa, workload inaweza kupata mwonekano wa inter-process coordination objects au data ambayo haikukusudiwa kuvuka mipaka ya container.

## Uendeshaji

Runtime inapounda IPC namespace mpya, process hupata seti yake iliyotengwa ya IPC identifiers. Hii inamaanisha kuwa commands kama `ipcs` huonyesha tu objects zinazopatikana katika namespace hiyo. Ikiwa container badala yake ita-join host IPC namespace, objects hizo huwa sehemu ya global view inayoshirikiwa.

Hili ni muhimu hasa katika environments ambamo applications au services hutumia shared memory kwa kiwango kikubwa. Hata wakati container haiwezi kufanya breakout moja kwa moja kupitia IPC pekee, namespace inaweza ku-leak information au kuwezesha cross-process interference ambayo husaidia kwa kiasi kikubwa attack ya baadaye.

## Lab

Unaweza kuunda private IPC namespace kwa kutumia:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Na linganisha tabia ya wakati wa utekelezaji na:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Matumizi ya Runtime

Docker na Podman hutenga IPC kwa default. Kubernetes kwa kawaida huipa Pod IPC namespace yake, inayoshirikiwa na containers zilizo ndani ya Pod hiyo lakini si kwa default na host. Kushiriki host IPC kunawezekana, lakini kunapaswa kuchukuliwa kama kupungua kwa kiasi kikubwa kwa isolation, si kama runtime option ndogo.

## Makonfigurasi Yasiyo Sahihi

Kosa lililo wazi ni `--ipc=host` au `hostIPC: true`. Hili linaweza kufanywa kwa ajili ya compatibility na software ya zamani au kwa urahisi, lakini hubadilisha kwa kiasi kikubwa trust model. Tatizo jingine linalojirudia ni kupuuza IPC kwa sababu inaonekana si kubwa kama host PID au host networking. Kwa uhalisia, ikiwa workload inashughulikia browsers, databases, scientific workloads, au software nyingine inayotumia sana shared memory, attack surface ya IPC inaweza kuwa muhimu sana.

## Matumizi Mabaya

Host IPC inaposhirikiwa, attacker anaweza kukagua au kuingilia shared memory objects, kupata ufahamu mpya kuhusu tabia ya host au neighboring workload, au kuunganisha taarifa zilizopatikana hapo na process visibility pamoja na capabilities za aina ya ptrace. Kushiriki IPC mara nyingi huwa supporting weakness badala ya kuwa full breakout path, lakini supporting weaknesses ni muhimu kwa sababu hupunguza na kuimarisha real attack chains.

Hatua ya kwanza yenye manufaa ni kuorodhesha IPC objects zinazoonekana kabisa:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Ikiwa IPC namespace ya host imeshirikiwa, shared-memory segments kubwa au wamiliki wa objects wanaovutia wanaweza kufichua mara moja tabia ya application:
```bash
ipcs -m -p
ipcs -q -p
```
Katika baadhi ya mazingira, maudhui ya `/dev/shm` yenyewe hu-leak majina ya faili, artifacts, au tokens zinazofaa kuchunguzwa:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Kushiriki IPC mara chache hutoa host root ya papo hapo peke yake, lakini kunaweza kufichua data na njia za uratibu zinazofanya mashambulizi ya baadaye dhidi ya process kuwa rahisi zaidi.

### Mfano Kamili: Urejeshaji wa Siri kutoka `/dev/shm`

Kesi halisi zaidi ya abuse kamili ni wizi wa data badala ya direct escape. Ikiwa host IPC au mpangilio mpana wa shared-memory umefichuliwa, artifacts nyeti wakati mwingine zinaweza kurejeshwa moja kwa moja:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Athari:

- extraction of secrets au session material iliyoachwa kwenye shared memory
- maarifa kuhusu applications zinazofanya kazi kwa sasa kwenye host
- kulenga vizuri zaidi mashambulizi ya baadaye yanayotegemea PID-namespace au ptrace

Kwa hiyo, kushiriki IPC kunaeleweka vyema zaidi kama **attack amplifier** kuliko standalone host-escape primitive.

## Ukaguzi

Commands hizi zimekusudiwa kujibu ikiwa workload ina private IPC view, ikiwa shared-memory au message objects zenye maana zinaonekana, na ikiwa `/dev/shm` yenyewe inaonyesha artifacts muhimu.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Kinachovutia hapa:

- Ikiwa `ipcs -a` itaonyesha objects zinazomilikiwa na users au services zisizotarajiwa, namespace inaweza isiwe imetengwa kama ilivyotarajiwa.
- Large au unusual shared memory segments mara nyingi zinafaa kuchunguzwa zaidi.
- Mount ya `/dev/shm` iliyo wazi kwa upana si bug moja kwa moja, lakini katika baadhi ya mazingira huleak filenames, artifacts, na transient secrets.

IPC mara chache hupokea umakini sawa na aina kubwa zaidi za namespace, lakini katika mazingira yanayoitumia sana, kuishiriki na host ni security decision kwa kiwango kikubwa.

{{#include ../../../../../banners/hacktricks-training.md}}
