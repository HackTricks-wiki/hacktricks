# Muhtasari wa Ulinzi wa Container

{{#include ../../../../banners/hacktricks-training.md}}

Wazo muhimu zaidi katika hardening ya container ni kwamba hakuna control moja inayoitwa "container security". Kile ambacho watu huita container isolation kwa kweli ni matokeo ya mechanisms kadhaa za Linux za security na resource-management zinazofanya kazi pamoja. Ikiwa documentation inaeleza moja tu kati yao, wasomaji huwa wanakadiria nguvu yake kupita kiasi. Ikiwa documentation inaorodhesha zote bila kueleza jinsi zinavyoingiliana, wasomaji hupata catalog ya majina lakini hawapati model halisi. Sehemu hii inajaribu kuepuka makosa yote mawili.

Katikati ya model kuna **namespaces**, ambazo hutenga kile ambacho workload inaweza kuona. Huipa process mwonekano wa filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths, na baadhi ya clocks ulio wa kibinafsi au wa kibinafsi kwa sehemu. Lakini namespaces pekee haziamui kile ambacho process inaruhusiwa kufanya. Hapo ndipo layers zinazofuata zinaingia.

**cgroups** hudhibiti matumizi ya resources. Si boundary ya isolation hasa kwa maana ile ile ya mount au PID namespaces, lakini ni muhimu sana kiutendaji kwa sababu huzuia memory, CPU, PIDs, I/O, na device access. Pia zina umuhimu wa security kwa sababu mbinu za zamani za breakout zilitumia vibaya writable cgroup features, hasa katika mazingira ya cgroup v1.

**Capabilities** hugawanya model ya zamani ya root mwenye mamlaka yote kuwa vitengo vidogo vya privilege. Hili ni la msingi kwa containers kwa sababu workloads nyingi bado huendeshwa kama UID 0 ndani ya container. Kwa hiyo swali si tu "je, process ni root?", bali pia "ni capabilities zipi zilisalia, ndani ya namespaces zipi, chini ya restrictions zipi za seccomp na MAC?" Ndiyo sababu root process katika container moja inaweza kuwa na vikwazo kwa kiasi kikubwa, huku root process katika container nyingine ikikaribia kutofautiana kabisa na host root kwa vitendo.

**seccomp** huchuja syscalls na kupunguza kernel attack surface inayofichuliwa kwa workload. Hii mara nyingi ndiyo mechanism inayozuia calls zilizo hatari wazi kama `unshare`, `mount`, `keyctl`, au syscalls nyingine zinazotumiwa katika breakout chains. Hata kama process ina capability ambayo vinginevyo ingeruhusu operation fulani, seccomp bado inaweza kuzuia syscall path kabla kernel haijaichakata kikamilifu.

**AppArmor** na **SELinux** huongeza Mandatory Access Control juu ya checks za kawaida za filesystem na privilege. Hizi ni muhimu hasa kwa sababu zinaendelea kuwa na umuhimu hata wakati container ina capabilities nyingi kuliko inavyopaswa kuwa nazo. Workload inaweza kuwa na privilege ya kinadharia ya kujaribu action fulani, lakini bado ikazuiwa kuitekeleza kwa sababu label au profile yake inakataza access kwa path, object, au operation husika.

Mwishowe, kuna layers za ziada za hardening ambazo hupokea umakini mdogo lakini mara kwa mara huwa muhimu katika attacks halisi: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, na runtime defaults zilizoandaliwa kwa uangalifu. Mechanisms hizi mara nyingi huzuia "last mile" ya compromise, hasa wakati attacker anajaribu kubadilisha code execution kuwa privilege gain pana zaidi.

Sehemu iliyobaki ya folder hii inaeleza kila moja ya mechanisms hizi kwa undani zaidi, ikijumuisha kile ambacho kernel primitive hufanya, jinsi ya kuiona locally, jinsi runtimes za kawaida huitumia, na jinsi operators wanavyoidhoofisha bila kukusudia.

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

Escapes nyingi halisi pia hutegemea ni host content gani ilimountiwa kwenye workload, kwa hiyo baada ya kusoma protections za msingi ni muhimu kuendelea na:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}
