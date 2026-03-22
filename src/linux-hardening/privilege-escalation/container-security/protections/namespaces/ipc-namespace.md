# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

IPC namespace inatenga **System V IPC objects** na **POSIX message queues**. Hii inajumuisha shared memory segments, semaphores, na message queues ambazo vingekuwa vinaonekana kati ya processes zisizohusiana kwenye host. Kwa maneno ya vitendo, hii inazuia container kuunganishwa kwa urahisi na IPC objects zinazomilikiwa na workloads nyingine au host.

Ulinganishwa na mount, PID, au user namespaces, IPC namespace mara nyingi hujadiliwa kidogo, lakini hilo halipaswi kuchanganywa na kutokuwa na umuhimu. Shared memory na mechanisms zinazohusiana na IPC zinaweza kuwa na state muhimu sana. Ikiwa host IPC namespace itaonekana, workload inaweza kupata uwezo wa kuona vitu vya uratibu kati ya process au data ambayo haikuwa imekusudiwa kuvuka mpaka wa container.

## Uendeshaji

Wakati runtime inapotengeneza IPC namespace mpya, process inapata seti yake ya vitambulisho vya IPC vilivyotengwa. Hii inamaanisha amri kama `ipcs` zinaonyesha tu vitu vilivyo katika namespace hiyo. Ikiwa container badala yake inajiunga na host IPC namespace, vitu hivyo vinakuwa sehemu ya mtazamo wa pamoja wa kimataifa.

Hii ni muhimu hasa katika mazingira ambapo applications au services zinatumia shared memory kwa wingi. Hata pale container isiyoweza kutoroka moja kwa moja kupitia IPC pekee, namespace inaweza leak taarifa au kuwezesha kuingilia kati kwa mchakato-mwingine ambayo inaweza kusaidia kwa kiasi kikubwa shambulio la baadaye.

## Maabara

Unaweza kuunda IPC namespace binafsi kwa:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Na linganisha tabia za runtime na:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Matumizi ya Runtime

Docker na Podman hutenganisha IPC kwa chaguo-msingi. Kubernetes kwa kawaida huwapa Pod namespace yake ya IPC, ambayo inashirikiwa na containers ndani ya Pod ile ile lakini si kwa chaguo-msingi na host. Kushirikiana kwa host IPC ni uwezekano, lakini inapaswa kuchukuliwa kama kupunguzwa muhimu kwa utenganisho badala ya chaguo dogo la runtime.

## Usanidi usio sahihi

Hitilafu inayoonekana wazi ni `--ipc=host` au `hostIPC: true`. Hii inaweza kufanywa kwa ajili ya ulinganifu na programu za zamani au kwa urahisi, lakini inabadilisha kwa kiasi kikubwa modeli ya kuaminiana. Tatizo jingine linalojirudia ni kutoona IPC kabisa kwa sababu inahisi kuwa haiko hatari kama host PID au host networking. Kwa ukweli, ikiwa workload inashughulikia browsers, databases, workloads za kisayansi, au programu nyingine zinazotumia kwa wingi kumbukumbu iliyoshirikiwa, uso wa IPC unaweza kuwa muhimu sana.

## Matumizi mabaya

Wakati host IPC inashirikiwa, mshambuliaji anaweza kuchunguza au kuingilia vitu vya kumbukumbu iliyoshirikiwa, kupata uelewa mpya wa tabia ya host au workload jirani, au kuchanganya taarifa zilizojifunza hapo na uonekano wa mchakato na uwezo wa aina ya ptrace. Kushirikishwa kwa IPC mara nyingi ni udhaifu wa kuunga mkono badala ya njia kamili ya breakout, lakini udhaifu wa kuunga mkono ni muhimu kwa sababu unapofupisha na kutuliza mnyororo wa mashambulizi ya kweli.

Hatua ya kwanza yenye tija ni kuorodhesha ni vitu gani vya IPC vinavyoonekana kabisa:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Ikiwa namespace ya IPC ya host inashirikiwa, sehemu kubwa za kumbukumbu zilizoshirikiwa au wamiliki wa vitu vinavyovutia vinaweza kufichua tabia ya programu mara moja:
```bash
ipcs -m -p
ipcs -q -p
```
Katika baadhi ya mazingira, yaliyomo ndani ya /dev/shm yenyewe yanaweza leak majina ya faili, artifacts, au tokens yanayostahili kukaguliwa:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Kushirikishwa kwa IPC kwa kawaida hakutoa host root mara moja peke yake, lakini inaweza kufichua data na njia za kuratibu ambazo zinafanya mashambulizi ya mchakato baadaye kuwa rahisi zaidi.

### Mfano Kamili: `/dev/shm` Urejeshaji wa Siri

Kesi halisi kabisa ya matumizi mabaya ni wizi wa data badala ya kutoroka moja kwa moja. Ikiwa host IPC au mpangilio mpana wa shared-memory umefunuliwa, artefakti nyeti mara nyingine zinaweza kupatikana moja kwa moja:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Athari:

- uchimbaji wa secrets au session material vilivyobaki katika shared memory
- ufahamu kuhusu applications zinazofanya kazi sasa kwenye host
- kulenga kwa ufanisi zaidi kwa ajili ya mashambulizi ya baadaye yanayotegemea PID-namespace au ptrace

Kwa hivyo ugawaji wa IPC unafahamika zaidi kama **kiongezaji cha mashambulizi** kuliko kama primitive ya kujiondoa kwenye host peke yake.

## Ukaguzi

Amri hizi zinakusudiwa kujibu ikiwa workload ina mtazamo wa IPC wa kibinafsi, ikiwa shared-memory au message objects zenye maana zinaonekana, na ikiwa `/dev/shm` yenyewe inatoa artefakti zenye manufaa.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Kinachovutia hapa:

- Ikiwa `ipcs -a` inaonyesha vitu vinavyomilikiwa na watumiaji au huduma zisizotarajiwa, namespace inaweza isiwe imejitenga kama inavyotarajiwa.
- Segimenti kubwa au zisizo za kawaida za shared memory mara nyingi zinastahili kufuatiliwa.
- Mount pana ya `/dev/shm` si hitilafu moja kwa moja, lakini katika mazingira fulani it leaks majina ya faili, artifacts, na siri za muda.

IPC mara chache hupata umakini kama aina kubwa za namespace, lakini katika mazingira yanayotumia sana, kushirikiana nayo na host ni uamuzi muhimu wa usalama.
{{#include ../../../../../banners/hacktricks-training.md}}
