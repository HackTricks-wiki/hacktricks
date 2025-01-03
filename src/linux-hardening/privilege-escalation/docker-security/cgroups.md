# CGroups

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**Linux Control Groups**, au **cgroups**, ni kipengele cha kernel ya Linux kinachoruhusu ugawaji, mipaka, na kipaumbele cha rasilimali za mfumo kama CPU, kumbukumbu, na disk I/O kati ya vikundi vya michakato. Wanatoa mekanizma ya **kusimamia na kutenga matumizi ya rasilimali** za makundi ya michakato, ambayo ni muhimu kwa madhumuni kama vile mipaka ya rasilimali, kutengwa kwa mzigo, na kipaumbele cha rasilimali kati ya vikundi tofauti vya michakato.

Kuna **matoleo mawili ya cgroups**: toleo la 1 na toleo la 2. Zote zinaweza kutumika kwa pamoja kwenye mfumo. Tofauti kuu ni kwamba **cgroups toleo la 2** linaanzisha **muundo wa hierarchal, kama mti**, unaowezesha ugawaji wa rasilimali kwa undani zaidi na wa kina kati ya vikundi vya michakato. Zaidi ya hayo, toleo la 2 linakuja na maboresho mbalimbali, ikiwa ni pamoja na:

Mbali na shirika jipya la hierarchal, cgroups toleo la 2 pia limeanzisha **mabadiliko na maboresho mengine kadhaa**, kama vile msaada wa **wasimamizi wapya wa rasilimali**, msaada bora kwa programu za zamani, na utendaji bora.

Kwa ujumla, cgroups **toleo la 2 linatoa vipengele vingi na utendaji bora** kuliko toleo la 1, lakini la mwisho linaweza bado kutumika katika hali fulani ambapo ulinganifu na mifumo ya zamani ni wasiwasi.

Unaweza kuorodhesha cgroups v1 na v2 kwa mchakato wowote kwa kuangalia faili yake ya cgroup katika /proc/\<pid>. Unaweza kuanza kwa kuangalia cgroups za shell yako kwa amri hii:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
- **Nambari 2–12**: cgroups v1, ambapo kila mstari unawakilisha cgroup tofauti. Wasimamizi wa haya wameainishwa karibu na nambari.
- **Nambari 1**: Pia cgroups v1, lakini kwa madhumuni ya usimamizi pekee (iliyowekwa na, kwa mfano, systemd), na haina msimamizi.
- **Nambari 0**: Inawakilisha cgroups v2. Hakuna wasimamizi waliotajwa, na mstari huu ni wa kipekee kwenye mifumo inayotumia cgroups v2 pekee.
- **Majina ni ya kihierarkia**, yanayofanana na njia za faili, yanayoonyesha muundo na uhusiano kati ya cgroups tofauti.
- **Majina kama /user.slice au /system.slice** yanaelezea uainishaji wa cgroups, ambapo user.slice kwa kawaida ni kwa ajili ya vikao vya kuingia vinavyosimamiwa na systemd na system.slice kwa huduma za mfumo.

### Kuangalia cgroups

Mfumo wa faili kwa kawaida hutumiwa kwa ajili ya kufikia **cgroups**, ukitofautiana na kiolesura cha wito wa mfumo wa Unix ambacho kwa kawaida hutumiwa kwa mwingiliano wa kernel. Ili kuchunguza usanidi wa cgroup wa shell, mtu anapaswa kuangalia faili ya **/proc/self/cgroup**, ambayo inaonyesha cgroup ya shell. Kisha, kwa kuhamia kwenye saraka ya **/sys/fs/cgroup** (au **`/sys/fs/cgroup/unified`**) na kutafuta saraka inayoshiriki jina la cgroup, mtu anaweza kuona mipangilio mbalimbali na taarifa za matumizi ya rasilimali zinazohusiana na cgroup.

![Cgroup Filesystem](<../../../images/image (1128).png>)

Faili muhimu za kiolesura za cgroups zimeandikwa kwa **cgroup**. Faili ya **cgroup.procs**, ambayo inaweza kuangaliwa kwa amri za kawaida kama cat, inataja michakato ndani ya cgroup. Faili nyingine, **cgroup.threads**, inajumuisha taarifa za nyuzi.

![Cgroup Procs](<../../../images/image (281).png>)

Cgroups zinazoshughulikia shells kwa kawaida zinajumuisha wasimamizi wawili wanaodhibiti matumizi ya kumbukumbu na idadi ya michakato. Ili kuingiliana na msimamizi, faili zenye kiambishi cha msimamizi zinapaswa kutazamwa. Kwa mfano, **pids.current** ingekuwa ikirejelea kujua idadi ya nyuzi katika cgroup.

![Cgroup Memory](<../../../images/image (677).png>)

Dalili ya **max** katika thamani inaashiria ukosefu wa kikomo maalum kwa cgroup. Hata hivyo, kutokana na asili ya kihierarkia ya cgroups, mipaka inaweza kuwekwa na cgroup katika kiwango cha chini katika hierarchi ya saraka.

### Kudhibiti na Kuunda cgroups

Michakato inatengwa kwa cgroups kwa **kuandika Kitambulisho cha Mchakato (PID) kwenye faili ya `cgroup.procs`**. Hii inahitaji ruhusa za mzizi. Kwa mfano, ili kuongeza mchakato:
```bash
echo [pid] > cgroup.procs
```
Vile vile, **kubadilisha sifa za cgroup, kama kuweka kikomo cha PID**, hufanywa kwa kuandika thamani inayotakiwa kwenye faili husika. Ili kuweka kiwango cha juu cha PIDs 3,000 kwa cgroup:
```bash
echo 3000 > pids.max
```
**Kuunda cgroups mpya** kunahusisha kuunda subdirectory mpya ndani ya hiyerararkia ya cgroup, ambayo inasababisha kernel kuunda kiotomatiki faili za interface zinazohitajika. Ingawa cgroups bila michakato haiwezi kuondolewa kwa `rmdir`, kuwa makini na vizuizi fulani:

- **Michakato inaweza kuwekwa tu katika cgroups za majani** (yaani, zile zilizozungukwa zaidi katika hiyerararkia).
- **Cgroup haiwezi kuwa na kiongozi asiye katika mzazi wake**.
- **Viongozi wa cgroups za watoto lazima watangazwe wazi** katika faili ya `cgroup.subtree_control`. Kwa mfano, ili kuwezesha viongozi wa CPU na PID katika cgroup ya mtoto:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**root cgroup** ni kipengele cha kipekee katika sheria hizi, kinachoruhusu kuweka mchakato moja kwa moja. Hii inaweza kutumika kuondoa michakato kutoka kwa usimamizi wa systemd.

**Kufuatilia matumizi ya CPU** ndani ya cgroup inawezekana kupitia faili ya `cpu.stat`, inayoonyesha jumla ya muda wa CPU ulio tumika, muhimu kwa kufuatilia matumizi kati ya michakato ya huduma:

<figure><img src="../../../images/image (908).png" alt=""><figcaption><p>Takwimu za matumizi ya CPU kama zinavyoonyeshwa katika faili ya cpu.stat</p></figcaption></figure>

## Marejeleo

- **Kitabu: How Linux Works, 3rd Edition: What Every Superuser Should Know By Brian Ward**

{{#include ../../../banners/hacktricks-training.md}}
