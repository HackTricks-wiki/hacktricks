# Muhtasari wa Ulinzi wa Container

{{#include ../../../../banners/hacktricks-training.md}}

Wazo muhimu zaidi katika kuimarisha container ni kwamba hakuna udhibiti mmoja unaoitwa "container security". Kinachowaita watu container isolation ni matokeo ya mekanismo kadhaa za usalama za Linux na usimamizi wa rasilimali zikitumika pamoja. Ikiwa dokumentasi inataja moja tu kati yao, wasomaji huwa wanathamini nguvu yake kupita kiasi. Ikiwa dokumentasi inoorodhesha zote bila kuelezea jinsi zinavyoshirikiana, wasomaji wanapata orodha ya majina lakini hakuna mfano halisi. Sehemu hii inajaribu kuepuka makosa yote mawili.

Katikati ya mfano kuna **namespaces**, ambazo zinatenganisha kile workload inaweza kuona. Zinampa mchakato mtazamo wa kibinafsi au sehemu ya kibinafsi wa filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths, na baadhi ya saa. Lakini namespaces pekee haziamui kile mchakato anaruhusiwa kufanya. Hapo ndipo tabaka zinazofuata zinaingia.

**cgroups** zinaendesha matumizi ya rasilimali. Si kimsingi ukingo wa utengano kwa maana ile ile kama mount au PID namespaces, lakini zina umuhimu mkubwa kikazi kwa sababu zinazuia memory, CPU, PIDs, I/O, na device access. Pia zina umuhimu wa usalama kwa sababu historical breakout techniques zilitumia vibaya sifa za cgroup zinazoweza kuandikwa, hasa katika mazingira ya cgroup v1.

**Capabilities** huzigawa mfano wa zamani wa root mwenye uwezo wote kuwa vitengo vidogo vya privilaji. Hii ni msingi kwa containers kwa sababu workloads nyingi bado zinaendesha kama UID 0 ndani ya container. Swali si tu "is the process root?", bali "which capabilities survived, inside which namespaces, under which seccomp and MAC restrictions?" Ndiyo sababu mchakato wa root kwenye container moja unaweza kuwa mdhibitiwa kwa kiasi, wakati mchakato wa root kwenye container nyingine unaweza karibu kutofautika na host root kwa vitendo.

**seccomp** huchuja syscalls na kupunguza kernel attack surface inayowekwa wazi kwa workload. Mara nyingi hiki ndicho kifaa kinachozuia miito hatari kama `unshare`, `mount`, `keyctl`, au syscalls nyingine zinazotumika katika breakout chains. Hata kama mchakato unayo capability ambayo vinginevyo ingeturuhusu operesheni, seccomp inaweza bado kuzuia njia ya syscall kabla kernel haijachakata kikamilifu.

**AppArmor** na **SELinux** zinaongeza Mandatory Access Control juu ya ukaguzi wa kawaida wa filesystem na privilaji. Hizi ni muhimu hasa kwa sababu zinaendelea kuwa na umuhimu hata wakati container ina capabilities zaidi kuliko inapaswa kuwa nazo. Workload inaweza kuwa na privilaji kwa nadharia kujaribu kitendo lakini bado ikizuia kutekeleza kwa sababu label au profile yake inakataza ufikiaji wa njia, kitu, au operesheni husika.

Mwishowe, kuna tabaka za ziada za kuimarisha ambazo hupata kutiliwa shaka kidogo lakini mara kwa mara zina umuhimu katika mashambulizi halisi: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, na careful runtime defaults. Mekanism hizi mara nyingi huzuia "last mile" ya udanganyifu, hasa mdukuzi anapojaribu kubadilisha code execution kuwa upataji wa privilaji mkubwa.

Sehemu nyingine ya folda hii inaelezea kila moja ya mekanism hizi kwa undani zaidi, ikijumuisha ni nini kernel primitive kwa kweli hufanya, jinsi ya kuiona kwa karibu, jinsi runtimes za kawaida zinavyotumia, na jinsi operators kwa bahati mbaya wanavyoiweka dhaifu.

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

Kutoroka nyingi za kweli pia zinategemea ni maudhui gani ya host yaliyo-mounted ndani ya workload, hivyo baada ya kusoma ulinzi wa msingi ni vyema kuendelea na:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
