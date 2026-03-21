# Namespace ya IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Namespace ya IPC inatenga **System V IPC objects** na **POSIX message queues**. Hii inajumuisha segmenti za memory zilizoshirikiwa, semaforu, na message queues ambazo vingekuwa vinaonekana kwa mchakato zisizohusiana kwenye host. Kwa vitendo, hii inazuia container kutoka kuunganishwa kwa urahisi na IPC objects zinazomilikiwa na workloads nyingine au host.

Ukilinganisha na mount, PID, au user namespaces, namespace ya IPC mara nyingi huzungumziwa kidogo zaidi, lakini hilo halipaswi kuchukuliwa kuwa halina umuhimu. Shared memory na mekanismo nyingine za IPC zinaweza kuwa na state yenye thamani kubwa. Ikiwa host IPC namespace imefunuliwa, workload inaweza kupata uoni wa vitu vya kuratibu kati ya michakato au data ambayo haikuwa ikikusudiwa kuvuka mpaka wa container.

## Operesheni

Wakati runtime inapounda IPC namespace mpya, mchakato hupata seti yake iliyotengwa ya vitambulisho vya IPC. Hii inamaanisha amri kama `ipcs` zinaonyesha tu vitu vinavyopatikana katika namespace hiyo. Ikiwa container badala yake itaungana na host IPC namespace, vitu hivyo vinakuwa sehemu ya muonekano wa pamoja wa kimataifa.

Hii ni muhimu hasa katika mazingira ambapo applications au services zinatumia shared memory kwa wingi. Hata pale container haina uwezo wa kutoroka moja kwa moja kupitia IPC pekee, namespace inaweza leak taarifa au kuwezesha kuingilia kati kati ya michakato ambayo kwa kiasi kikubwa husaidia shambulio la baadaye.

## Maabara

Unaweza kuunda IPC namespace binafsi kwa kutumia:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Na linganisha runtime behavior na:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Matumizi ya wakati wa utekelezaji

Docker na Podman hutenganisha IPC kwa chaguo-msingi. Kubernetes kwa kawaida hutoa Pod namespace yake ya IPC, ambayo inashirikiwa na containers ndani ya Pod ile ile lakini sio pamoja na host kwa chaguo-msingi. Kushirikisha host IPC kunawezekana, lakini inapaswa kuchukuliwa kama kupunguzwa kwa maana ya utenganisho badala ya chaguo dogo la runtime.

## Mipangilio isiyofaa

Hitilafu dhahiri ni `--ipc=host` au `hostIPC: true`. Hii inaweza kufanywa kwa ajili ya ulinganifu na programu za kale au kwa urahisi, lakini inabadilisha modeli ya uaminifu kwa kiasi kikubwa. Tatizo jingine linalorudiwa ni kupuuzia IPC kwa sababu inaonekana si kubwa kama host PID au host networking. Kwa hakika, ikiwa workload inashughulikia browsers, databases, scientific workloads, au programu nyingine zinazotumia sana shared memory, uso wa IPC unaweza kuwa muhimu sana.

## Matumizi mabaya

Wakati host IPC inashirikiwa, mshambuliaji anaweza kukagua au kuingilia vitu vya shared memory, kupata uelewa mpya kuhusu tabia ya host au workload jirani, au kuunganisha habari iliyojifunzwa pale na uonekana wa mchakato na uwezo wa aina ya ptrace. Kushirikishwa kwa IPC mara nyingi ni udhaifu wa kuunga mkono badala ya njia kamili ya kutoroka, lakini udhaifu wa kuunga mkono una umuhimu kwa sababu unafupisha na kutuliza mnyororo wa mashambulizi halisi.

Hatua ya kwanza yenye manufaa ni kuorodhesha ni IPC objects gani zinaonekana kabisa:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Ikiwa host IPC namespace imegawanywa, sehemu kubwa za shared-memory au wamiliki wa vitu vinavyovutia wanaweza kufichua tabia za programu mara moja:
```bash
ipcs -m -p
ipcs -q -p
```
Katika baadhi ya mazingira, yaliyomo kwenye `/dev/shm` yenyewe yana leak majina ya faili, artifacts, au tokens vinavyostahili kuchunguzwa:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Kugawana IPC mara chache huleta host root mara moja, lakini kunaweza kufichua data na njia za uratibu ambazo zinafanya mashambulizi ya process baadaye kuwa rahisi zaidi.

### Mfano Kamili: `/dev/shm` Urejeshaji wa Siri

Kesi ya matumizi mabaya yenye uwezekano mkubwa zaidi ni wizi wa data badala ya kutoroka moja kwa moja. Ikiwa host IPC au mpangilio mpana wa shared-memory umefunuliwa, mara nyingine vitu nyeti vinaweza kurejeshwa moja kwa moja:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Athari:

- uchimbaji wa siri au nyenzo za kikao zilizobaki katika kumbukumbu iliyoshirikiwa
- uelewa kuhusu programu zinazofanya kazi kwa sasa kwenye host
- kulenga kwa ufanisi zaidi kwa mashambulizi ya baadaye yanayotegemea PID-namespace au ptrace

Ugawaji wa IPC ni kwa hivyo bora kueleweka kama **kiimarishaji cha mashambulizi** kuliko kama primitive huru ya kutoroka kwenye host.

## Ukaguzi

Amri hizi zinalenga kujibu kama workload ina mtazamo wa kibinafsi wa IPC, kama vitu vya kumbukumbu iliyoshirikiwa au vitu vya ujumbe vyenye maana vinaonekana, na kama `/dev/shm` yenyewe inafunua artefakti muhimu.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- Ikiwa `ipcs -a` inaonyesha vitu vinavyomilikiwa na watumiaji au huduma zisizotarajiwa, namespace inaweza kuwa haijatengwa kama ilivyotarajiwa.
- Sehemu kubwa au zisizo za kawaida za kumbukumbu iliyoshirikiwa mara nyingi zinastahili kufuatiliwa.
- Mount mpana wa `/dev/shm` sio bug kiotomatiki, lakini katika mazingira mengine it leaks majina ya faili, artifacts, na siri za muda.

IPC kwa nadra hupata umakini mwingi kama aina kubwa za namespace, lakini katika mazingira yanayotumia sana, kushirikisha na host ni uamuzi la kiusalama.
