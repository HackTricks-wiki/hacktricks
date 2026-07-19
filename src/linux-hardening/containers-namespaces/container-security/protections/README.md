# Muhtasari wa Protections za Container

{{#include ../../../../banners/hacktricks-training.md}}

Wazo muhimu zaidi katika container hardening ni kwamba hakuna control moja inayoitwa "container security". Kile ambacho watu hukiita container isolation kwa kweli ni matokeo ya Linux security na resource-management mechanisms kadhaa zinazofanya kazi pamoja. Ikiwa documentation itaeleza mojawapo tu, wasomaji huwa wanakadiria nguvu yake kupita kiasi. Ikiwa documentation itaorodhesha zote bila kueleza jinsi zinavyoingiliana, wasomaji hupata catalog ya majina lakini si model halisi. Sehemu hii inajaribu kuepuka makosa yote mawili.

Katikati ya model hii kuna **namespaces**, ambazo hutenga kile ambacho workload inaweza kuona. Humpa process mtazamo binafsi au kwa kiasi fulani binafsi wa filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths, na baadhi ya clocks. Lakini namespaces pekee haziwezi kuamua kile ambacho process inaruhusiwa kufanya. Hapo ndipo layers zinazofuata zinaingia.

**cgroups** hudhibiti matumizi ya resources. Kimsingi si isolation boundary kwa maana ile ile ya mount au PID namespaces, lakini ni muhimu sana kiutendaji kwa sababu huwekea mipaka memory, CPU, PIDs, I/O, na device access. Pia zina umuhimu wa security kwa sababu historical breakout techniques zilitumia writable cgroup features vibaya, hasa katika mazingira ya cgroup v1.

**Capabilities** hugawanya old all-powerful root model kuwa privilege units ndogo. Hili ni la msingi kwa containers kwa sababu workloads nyingi bado huendeshwa kama UID 0 ndani ya container. Kwa hiyo swali si tu "je, process ni root?", bali pia "ni capabilities zipi zimesalia, ndani ya namespaces zipi, na chini ya restrictions zipi za seccomp na MAC?" Ndiyo maana root process katika container moja inaweza kuwa na vikwazo kwa kiasi kikubwa, wakati root process katika container nyingine inaweza kuwa karibu kutotofautiana kabisa na host root kiutendaji.

**seccomp** hufilter syscalls na hupunguza kernel attack surface inayofikiwa na workload. Mara nyingi hii ndiyo mechanism inayozuia calls hatari zilizo wazi kama `unshare`, `mount`, `keyctl`, au syscalls nyingine zinazotumiwa katika breakout chains. Hata kama process ina capability ambayo vinginevyo ingeruhusu operation fulani, seccomp bado inaweza kuzuia syscall path kabla kernel haijaichakata kikamilifu.

**AppArmor** na **SELinux** huongeza Mandatory Access Control juu ya normal filesystem na privilege checks. Hizi ni muhimu hasa kwa sababu zinaendelea kuwa na umuhimu hata container ikiwa na capabilities nyingi kuliko inavyopaswa. Workload inaweza kuwa na privilege ya kinadharia ya kujaribu action fulani, lakini bado ikazuiwa kuitekeleza kwa sababu label au profile yake inakataza access kwa path, object, au operation husika.

Hatimaye, kuna hardening layers za ziada ambazo hupokea umakini mdogo lakini mara kwa mara huwa muhimu katika mashambulizi halisi: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, na runtime defaults zilizowekwa kwa uangalifu. Mechanisms hizi mara nyingi huzuia "last mile" ya compromise, hasa mshambuliaji anapojaribu kubadilisha code execution kuwa privilege gain pana zaidi.

Sehemu iliyosalia ya folder hii inaeleza kila mojawapo ya mechanisms hizi kwa undani zaidi, ikijumuisha kile ambacho kernel primitive hufanya hasa, jinsi ya kuiona locally, jinsi runtimes za kawaida zinavyoitumia, na jinsi operators wanavyoidhoofisha bila kukusudia.

## Soma Inayofuata

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

Escapes nyingi halisi pia hutegemea content ya host iliyomountiwa ndani ya workload, kwa hiyo baada ya kusoma core protections ni muhimu kuendelea na:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
