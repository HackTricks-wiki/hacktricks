# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

IPC namespace hutenga **System V IPC objects** na **POSIX message queues**. Hii inajumuisha shared memory segments, semaphores, na message queues ambazo vinginevyo zingeonekana na processes zisizohusiana kwenye host. Kwa maana ya kiutendaji, hii huzuia container kujiunga kwa urahisi na IPC objects zinazomilikiwa na workloads nyingine au host.

Ikilinganishwa na mount, PID, au user namespaces, IPC namespace huzungumziwa mara chache, lakini hilo halimaanishi kuwa si muhimu. Shared memory na IPC mechanisms zinazohusiana zinaweza kuwa na state yenye manufaa makubwa. Ikiwa host IPC namespace imewekwa wazi, workload inaweza kupata mwonekano wa inter-process coordination objects au data ambayo haikukusudiwa kuvuka mpaka wa container.

## Uendeshaji

Runtime inapounda IPC namespace mpya, process hupata seti yake iliyotengwa ya IPC identifiers. Hii inamaanisha kuwa commands kama `ipcs` huonyesha objects zinazopatikana katika namespace hiyo pekee. Ikiwa container badala yake itaingia kwenye host IPC namespace, objects hizo huwa sehemu ya mwonekano wa pamoja wa kimataifa.

Hili ni muhimu hasa katika mazingira ambayo applications au services hutumia shared memory kwa kiwango kikubwa. Hata wakati container haiwezi kufanya breakout moja kwa moja kupitia IPC pekee, namespace inaweza ku-leak information au kuwezesha cross-process interference ambayo husaidia kwa kiasi kikubwa attack ya baadaye.

## Lab

Unaweza kuunda private IPC namespace kwa kutumia:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Na linganisha tabia ya runtime na:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Matumizi ya Runtime

Docker na Podman hutenga IPC kwa default. Kubernetes kwa kawaida huipa Pod IPC namespace yake, inayoshirikishwa na containers zilizo ndani ya Pod hiyo, lakini si kwa default na host. Kushiriki host IPC kunawezekana, lakini kunapaswa kuchukuliwa kama kupungua kwa kiasi kikubwa kwa isolation, badala ya kuwa chaguo dogo la runtime.

## Misconfigurations

Kosa lililo wazi ni `--ipc=host` au `hostIPC: true`. Hili linaweza kufanywa kwa ajili ya compatibility na software ya zamani au kwa urahisi, lakini hubadilisha trust model kwa kiasi kikubwa. Tatizo jingine linalojirudia ni kupuuza IPC kwa sababu huonekana kuwa si kubwa kama host PID au host networking. Kwa uhalisia, ikiwa workload inashughulikia browsers, databases, scientific workloads, au software nyingine inayotumia sana shared memory, IPC surface inaweza kuwa muhimu sana.

## Abuse

Wakati host IPC inashirikishwa, attacker anaweza kukagua au kuingilia shared memory objects, kupata ufahamu mpya kuhusu tabia ya host au neighboring workload, au kuchanganya taarifa zilizopatikana hapo na process visibility pamoja na capabilities za mtindo wa ptrace. IPC sharing mara nyingi huwa supporting weakness badala ya kuwa breakout path kamili, lakini supporting weaknesses ni muhimu kwa sababu hupunguza na kuimarisha attack chains halisi.

Hatua ya kwanza yenye manufaa ni kuorodhesha IPC objects zinazoonekana kabisa:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Iwapo IPC namespace ya host imeshirikiwa, segments kubwa za shared-memory au wamiliki wa objects wanaovutia zinaweza kufichua tabia ya application mara moja:
```bash
ipcs -m -p
ipcs -q -p
```
Katika baadhi ya mazingira, maudhui ya `/dev/shm` yenyewe yanaweza leak filenames, artifacts, au tokens zinazofaa kuchunguzwa:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Kushiriki IPC mara chache hutoa host root papo hapo, lakini kunaweza kufichua data na channels za coordination zinazorahisisha sana process attacks zinazofuata.

### Mfano Kamili: `/dev/shm` Secret Recovery

Kesi halisi zaidi ya abuse ni data theft badala ya direct escape. Ikiwa host IPC au mpangilio mpana wa shared-memory umefichuliwa, artifacts nyeti wakati mwingine zinaweza kurejeshwa moja kwa moja:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impact:

- extraction of secrets au session material iliyoachwa kwenye shared memory
- kupata ufahamu kuhusu applications zinazoendelea kufanya kazi kwenye host
- kulenga vizuri zaidi mashambulizi ya baadaye yanayotegemea PID-namespace au ptrace

Kwa hiyo, IPC sharing inaeleweka vizuri zaidi kama **attack amplifier** kuliko primitive ya standalone host-escape.

## Ukaguzi

Amri hizi zinalenga kubaini ikiwa workload ina private IPC view, ikiwa shared-memory au message objects zenye maana zinaonekana, na ikiwa `/dev/shm` yenyewe inafichua artifacts zenye manufaa.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Ni nini kinachovutia hapa:

- Ikiwa `ipcs -a` itaonyesha objects zinazomilikiwa na users au services zisizotarajiwa, namespace huenda haijatengwa kama ilivyotarajiwa.
- Segments kubwa au zisizo za kawaida za shared memory mara nyingi zinafaa kuchunguzwa zaidi.
- Mount pana ya `/dev/shm` si bug moja kwa moja, lakini katika baadhi ya mazingira huvuja majina ya files, artifacts na secrets za muda.

IPC mara chache hupokea umakini sawa na aina kubwa zaidi za namespace, lakini katika mazingira yanayoitumia kwa kiwango kikubwa, kuishirikisha na host ni uamuzi muhimu wa usalama.
{{#include ../../../../../banners/hacktricks-training.md}}
