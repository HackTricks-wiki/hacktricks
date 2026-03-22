# Muhtasari wa Container Protections Overview

{{#include ../../../../banners/hacktricks-training.md}}

Wazo muhimu zaidi katika kuimarisha usalama wa container ni kwamba hakuna udhibiti mmoja unaoitwa "container security". Kile watu huita container isolation kwa kweli ni matokeo ya mekanismo kadhaa za usalama za Linux na usimamizi wa rasilimali zinazoendelea kufanya kazi pamoja. Ikiwa nyaraka zinaelezea moja tu kati yao, wasomaji huwa wanadhani nguvu yake ni kubwa mno. Ikiwa nyaraka zinaorodhesha zote bila kufafanua jinsi zinavyoshirikiana, wasomaji wanapata orodha ya majina lakini hawapati mfano halisi. Sehemu hii inajaribu kuepuka makosa yote mawili.

Katikati ya mfano kuna **namespaces**, ambazo zinaweka kivuko cha kile workload inaweza kuona. Zinampa mchakato mtazamo wa kibinafsi au sehemu ya kibinafsi wa filesystem mounts, PIDs, networking, vitu vya IPC, hostnames, user/group mappings, cgroup paths, na baadhi ya clocks. Lakini namespaces pekee haziamui kile mchakato anaruhusiwa kufanya. Hapo ndipo tabaka zinazofuata zinaingia.

**cgroups** zinadhibiti matumizi ya rasilimali. Sio kwa msingi mkuu mpaka kando ya kutenganisha kwa maana ile ile kama mount au PID namespaces, lakini zina umuhimu wa kiutendaji kwa sababu zinakataza memory, CPU, PIDs, I/O, na upatikanaji wa device. Pia zina umuhimu wa kiusalama kwa sababu mbinu za kihistoria za breakout zilitumia vibaya vipengele vya cgroup vinavyoweza kuandikwa, hasa katika mazingira ya cgroup v1.

**Capabilities** zinafungua mfano wa zamani wa root mwenye nguvu zote hadi vitengo vidogo vya ruhusa. Hii ni msingi kwa container kwa kuwa workloads nyingi bado zinaendesha kama UID 0 ndani ya container. Swali si tu "je, mchakato ni root?", bali ni "ni capabilities gani zilizoendelea kuwepo, ndani ya namespaces gani, chini ya vikwazo vya seccomp na MAC?" Ndiyo maana mchakato wa root katika container moja unaweza kuwa na vikwazo huku mchakato wa root katika container nyingine ukaonekana karibu haelekezi tofauti na host root kwa vitendo.

**seccomp** huchuja syscalls na kupunguza uso wa mashambulizi wa kernel unaoonyeshwa kwa workload. Hii mara nyingi ndiyo njia inayokataa kwa ufanisi miito hatari wazi kama `unshare`, `mount`, `keyctl`, au syscalls nyingine zinazotumika katika mnyororo za breakout. Hata mchakato ukiwa na capability ambayo vinginevyo ingeruhusu operesheni, seccomp bado inaweza kuzuia njia ya syscall kabla kernel haijaihesabu kikamilifu.

**AppArmor** na **SELinux** zinaongeza Mandatory Access Control juu ya ukaguzi wa kawaida wa filesystem na ruhusa. Hizi ni muhimu hasa kwa sababu zinabaki kuathiri hata wakati container ina capabilities zaidi ya inavyotakiwa. Workload inaweza kuwa na ruhusa ya nadharia ya kujaribu kitendo fulani lakini bado kuzuia kutekeleza kwa sababu label au profile yake inakataza ufikiaji wa njia, kitu, au operesheni inayohusika.

Mwishowe, kuna tabaka za ziada za kuimarisha ambazo hupata umakini mdogo lakini mara kwa mara zinakuwa muhimu katika mashambulizi halisi: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, na runtime defaults zilizo makini. Mifumo hii mara nyingi inazuia "last mile" ya udukuzi, hasa wakati mshambuliaji anajaribu kubadilisha utekelezaji wa code kuwa kupata ruhusa pana zaidi.

Sehemu iliyobaki ya folda hii inaelezea kila moja ya mifumo hii kwa undani zaidi, ikijumuisha ni nini primitive ya kernel hasa inafanya, jinsi ya kuiona kwa ndani, jinsi runtimes za kawaida zinavyotumia, na jinsi waendeshaji kwa bahati mbaya wanavyoweza kuidhoofisha.

## Soma Ifuatayo

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Many real escapes also depend on what host content was mounted into the workload, so after reading the core protections it is useful to continue with:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
