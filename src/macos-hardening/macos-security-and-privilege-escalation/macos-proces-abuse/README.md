# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

Mchakato ni mfano wa executable inayotembea, hata hivyo michakato haiendeshi msimbo, hizi ni nyuzi. Hivyo basi **michakato ni vyombo tu vya nyuzi zinazotembea** vinavyotoa kumbukumbu, maelezo, bandari, ruhusa...

Kawaida, michakato ilianza ndani ya michakato mingine (isipokuwa PID 1) kwa kuita **`fork`** ambayo ingekuwa na nakala halisi ya mchakato wa sasa na kisha **mchakato wa mtoto** kwa ujumla ungeita **`execve`** ili kupakia executable mpya na kuikimbia. Kisha, **`vfork`** ilianzishwa ili kufanya mchakato huu kuwa wa haraka bila nakala ya kumbukumbu.\
Kisha **`posix_spawn`** ilianzishwa ikichanganya **`vfork`** na **`execve`** katika wito mmoja na kukubali bendera:

- `POSIX_SPAWN_RESETIDS`: Rudisha vitambulisho halisi kwa vitambulisho halisi
- `POSIX_SPAWN_SETPGROUP`: Weka ushirikiano wa kundi la mchakato
- `POSUX_SPAWN_SETSIGDEF`: Weka tabia ya ishara ya kawaida
- `POSIX_SPAWN_SETSIGMASK`: Weka mask ya ishara
- `POSIX_SPAWN_SETEXEC`: Exec katika mchakato sawa (kama `execve` na chaguzi zaidi)
- `POSIX_SPAWN_START_SUSPENDED`: Anza ikiwa imekwama
- `_POSIX_SPAWN_DISABLE_ASLR`: Anza bila ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia allocator ya Nano ya libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye sehemu za data
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga maelezo yote ya faili kwenye exec(2) kwa chaguo-msingi
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomize bits za juu za ASLR slide

Zaidi ya hayo, `posix_spawn` inaruhusu kufafanua array ya **`posix_spawnattr`** inayodhibiti baadhi ya vipengele vya mchakato ulioanzishwa, na **`posix_spawn_file_actions`** kubadilisha hali ya maelezo.

Wakati mchakato unakufa unatumia **kodikodi ya kurudi kwa mchakato mzazi** (ikiwa mzazi amekufa, mzazi mpya ni PID 1) kwa ishara `SIGCHLD`. Mzazi anahitaji kupata thamani hii kwa kuita `wait4()` au `waitid()` na hadi hiyo itokee mtoto unabaki katika hali ya zombie ambapo bado inatajwa lakini haiwezi kutumia rasilimali.

### PIDs

PIDs, vitambulisho vya mchakato, vinatambulisha mchakato wa kipekee. Katika XNU **PIDs** ni za **64bits** zikiongezeka kwa monotoni na **hazijawahi kuzunguka** (ili kuepuka matumizi mabaya).

### Process Groups, Sessions & Coalations

**Michakato** inaweza kuingizwa katika **makundi** ili iwe rahisi kuzishughulikia. Kwa mfano, amri katika skripti ya shell zitakuwa katika kundi moja la mchakato hivyo inawezekana **kuziashiria pamoja** kwa kutumia kill kwa mfano.\
Pia inawezekana **kundi michakato katika vikao**. Wakati mchakato unaanzisha kikao (`setsid(2)`), michakato ya watoto inawekwa ndani ya kikao, isipokuwa waanzishe kikao chao wenyewe.

Coalition ni njia nyingine ya kuunganisha michakato katika Darwin. Mchakato unaojiunga na coalation unaruhusu kufikia rasilimali za pool, kushiriki ledger au kukabiliana na Jetsam. Coalations zina majukumu tofauti: Kiongozi, huduma ya XPC, Kiongezi.

### Credentials & Personae

Kila mchakato una **credentials** ambazo **zinatambulisha ruhusa zake** katika mfumo. Kila mchakato utakuwa na `uid` moja ya msingi na `gid` moja ya msingi (ingawa inaweza kuwa katika makundi kadhaa).\
Pia inawezekana kubadilisha kitambulisho cha mtumiaji na kikundi ikiwa binary ina `setuid/setgid` bit.\
Kuna kazi kadhaa za **kweka uids/gids mpya**.

Syscall **`persona`** inatoa seti **mbadala** ya **credentials**. Kupitisha persona kunachukua uid yake, gid na ushirikiano wa makundi **kwa pamoja**. Katika [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata struct:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Threads Basic Information

1. **POSIX Threads (pthreads):** macOS inasaidia nyuzi za POSIX (`pthreads`), ambazo ni sehemu ya API ya kawaida ya nyuzi kwa C/C++. Utekelezaji wa pthreads katika macOS unapatikana katika `/usr/lib/system/libsystem_pthread.dylib`, ambayo inatokana na mradi wa `libpthread` unaopatikana kwa umma. Maktaba hii inatoa kazi muhimu za kuunda na kusimamia nyuzi.
2. **Creating Threads:** Kazi ya `pthread_create()` inatumika kuunda nyuzi mpya. Ndani, kazi hii inaita `bsdthread_create()`, ambayo ni wito wa mfumo wa chini unaohusiana na kernel ya XNU (kernel ambayo macOS inategemea). Wito huu wa mfumo unachukua bendera mbalimbali zinazotokana na `pthread_attr` (sifa) ambazo zinaelezea tabia ya nyuzi, ikiwa ni pamoja na sera za kupanga na ukubwa wa stack.
- **Default Stack Size:** Ukubwa wa stack wa kawaida kwa nyuzi mpya ni 512 KB, ambayo inatosha kwa shughuli za kawaida lakini inaweza kubadilishwa kupitia sifa za nyuzi ikiwa nafasi zaidi au kidogo inahitajika.
3. **Thread Initialization:** Kazi ya `__pthread_init()` ni muhimu wakati wa kuanzisha nyuzi, ikitumia hoja ya `env[]` kuchambua mabadiliko ya mazingira ambayo yanaweza kujumuisha maelezo kuhusu eneo na ukubwa wa stack.

#### Thread Termination in macOS

1. **Exiting Threads:** Nyuzi kwa kawaida zinamalizika kwa kuita `pthread_exit()`. Kazi hii inaruhusu nyuzi kutoka kwa usafi, ikifanya usafi unaohitajika na kuruhusu nyuzi kutuma thamani ya kurudi kwa waunganishaji wowote.
2. **Thread Cleanup:** Wakati wa kuita `pthread_exit()`, kazi ya `pthread_terminate()` inaitwa, ambayo inashughulikia kuondoa muundo wote wa nyuzi zinazohusiana. Inafuta bandari za nyuzi za Mach (Mach ni mfumo wa mawasiliano katika kernel ya XNU) na inaita `bsdthread_terminate`, wito wa mfumo unaondoa muundo wa kiwango cha kernel unaohusiana na nyuzi.

#### Synchronization Mechanisms

Ili kusimamia ufikiaji wa rasilimali zinazoshirikiwa na kuepuka hali za mbio, macOS inatoa primitives kadhaa za usawazishaji. Hizi ni muhimu katika mazingira ya nyuzi nyingi ili kuhakikisha uadilifu wa data na utulivu wa mfumo:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Mutex ya kawaida yenye alama ya kumbukumbu ya 60 bytes (56 bytes kwa mutex na 4 bytes kwa saini).
- **Fast Mutex (Signature: 0x4d55545A):** Inafanana na mutex ya kawaida lakini imeboreshwa kwa shughuli za haraka, pia 60 bytes kwa ukubwa.
2. **Condition Variables:**
- Inatumika kusubiri hali fulani kutokea, ikiwa na ukubwa wa 44 bytes (40 bytes zaidi ya saini ya 4 bytes).
- **Condition Variable Attributes (Signature: 0x434e4441):** Sifa za usanidi kwa mabadiliko ya hali, zikiwa na ukubwa wa 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Inahakikisha kwamba kipande cha msimbo wa kuanzisha kinatekelezwa mara moja tu. Ukubwa wake ni 12 bytes.
4. **Read-Write Locks:**
- Inaruhusu wasomaji wengi au mwandishi mmoja kwa wakati mmoja, ikirahisisha ufikiaji mzuri wa data inayoshirikiwa.
- **Read Write Lock (Signature: 0x52574c4b):** Ukubwa wa 196 bytes.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Sifa za vizuizi vya kusoma-kandika, zikiwa na ukubwa wa 20 bytes.

> [!TIP]
> Bytes 4 za mwisho za vitu hivyo zinatumika kugundua kujaa.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** katika muktadha wa faili za Mach-O (muundo wa executable katika macOS) zinatumika kutangaza mabadiliko ambayo ni maalum kwa **kila nyuzi** katika programu yenye nyuzi nyingi. Hii inahakikisha kwamba kila nyuzi ina mfano wake wa kipekee wa mabadiliko, ikitoa njia ya kuepuka migongano na kudumisha uadilifu wa data bila kuhitaji mifumo ya usawazishaji wazi kama mutexes.

Katika C na lugha zinazohusiana, unaweza kutangaza mabadiliko ya nyuzi za ndani kwa kutumia neno **`__thread`**. Hapa kuna jinsi inavyofanya kazi katika mfano wako:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Hii sehemu inaelezea `tlv_var` kama variable ya thread-local. Kila thread inayokimbia msimbo huu itakuwa na `tlv_var` yake mwenyewe, na mabadiliko ambayo thread moja inafanya kwa `tlv_var` hayataathiri `tlv_var` katika thread nyingine.

Katika binary ya Mach-O, data inayohusiana na variable za thread-local imepangwa katika sehemu maalum:

- **`__DATA.__thread_vars`**: Sehemu hii ina metadata kuhusu variable za thread-local, kama vile aina zao na hali ya uanzishaji.
- **`__DATA.__thread_bss`**: Sehemu hii inatumika kwa variable za thread-local ambazo hazijaanzishwa wazi. Ni sehemu ya kumbukumbu iliyotengwa kwa data iliyowekwa sifuri.

Mach-O pia inatoa API maalum inayoitwa **`tlv_atexit`** kusimamia variable za thread-local wakati thread inatoka. API hii inakuwezesha **kujiandikisha destructors**—kazi maalum zinazosafisha data za thread-local wakati thread inamalizika.

### Kipaumbele cha Threading

Kuelewa kipaumbele cha thread kunahusisha kuangalia jinsi mfumo wa uendeshaji unavyamua ni thread zipi zitakazoendesha na lini. Uamuzi huu unategemea kiwango cha kipaumbele kilichopewa kila thread. Katika macOS na mifumo kama Unix, hii inashughulikiwa kwa kutumia dhana kama `nice`, `renice`, na daraja la Ubora wa Huduma (QoS).

#### Nice na Renice

1. **Nice:**
- Thamani ya `nice` ya mchakato ni nambari inayohusiana na kipaumbele chake. Kila mchakato una thamani ya nice inayotofautiana kutoka -20 (kipaumbele cha juu zaidi) hadi 19 (kipaumbele cha chini zaidi). Thamani ya kawaida ya nice wakati mchakato unaundwa kwa kawaida ni 0.
- Thamani ya nice ya chini (karibu na -20) inafanya mchakato kuwa "mwenye ubinafsi," ikimpa muda zaidi wa CPU ikilinganishwa na michakato mingine yenye thamani za nice za juu.
2. **Renice:**
- `renice` ni amri inayotumika kubadilisha thamani ya nice ya mchakato unaoendesha tayari. Hii inaweza kutumika kubadilisha kipaumbele cha michakato kwa njia ya kidijitali, ama kuongeza au kupunguza mgawanyiko wa muda wa CPU kulingana na thamani mpya za nice.
- Kwa mfano, ikiwa mchakato unahitaji rasilimali zaidi za CPU kwa muda, unaweza kupunguza thamani yake ya nice kwa kutumia `renice`.

#### Daraja la Ubora wa Huduma (QoS)

Daraja la QoS ni njia ya kisasa zaidi ya kushughulikia kipaumbele cha thread, hasa katika mifumo kama macOS inayounga mkono **Grand Central Dispatch (GCD)**. Daraja la QoS linawawezesha waendelezaji **kugawanya** kazi katika viwango tofauti kulingana na umuhimu au dharura yao. macOS inasimamia kipaumbele cha thread kiotomatiki kulingana na daraja hizi za QoS:

1. **Mtu Anayeingiliana:**
- Daraja hili ni kwa kazi ambazo kwa sasa zinaingiliana na mtumiaji au zinahitaji matokeo ya haraka ili kutoa uzoefu mzuri wa mtumiaji. Kazi hizi zinapewa kipaumbele cha juu ili kuweka kiolesura kuwa na majibu (kwa mfano, michoro au usimamizi wa matukio).
2. **Mtu Aliyeanzisha:**
- Kazi ambazo mtumiaji anazianzisha na anatarajia matokeo ya haraka, kama kufungua hati au kubonyeza kitufe kinachohitaji hesabu. Hizi ni za kipaumbele cha juu lakini chini ya mtu anayeingiliana.
3. **Huduma:**
- Kazi hizi ni za muda mrefu na kwa kawaida zinaonyesha kiashiria cha maendeleo (kwa mfano, kupakua faili, kuingiza data). Ziko chini ya kipaumbele kuliko kazi zilizozinduliwa na mtumiaji na hazihitaji kumalizika mara moja.
4. **Nyuma:**
- Daraja hili ni kwa kazi zinazofanya kazi nyuma na hazionekani kwa mtumiaji. Hizi zinaweza kuwa kazi kama kuorodhesha, kusawazisha, au nakala za akiba. Zina kipaumbele cha chini na athari ndogo kwenye utendaji wa mfumo.

Kwa kutumia daraja la QoS, waendelezaji hawahitaji kusimamia nambari za kipaumbele sahihi bali badala yake wanazingatia asili ya kazi, na mfumo unaboresha rasilimali za CPU ipasavyo.

Zaidi ya hayo, kuna sera tofauti za **ratiba za thread** ambazo zinaelekeza kuweka seti ya vigezo vya ratiba ambavyo ratibu itachukua katika kuzingatia. Hii inaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Hii inaweza kuwa na manufaa katika mashambulizi ya hali ya mbio.

## Unyanyasaji wa Mchakato wa MacOS

MacOS, kama mfumo mwingine wowote wa uendeshaji, inatoa njia na mitambo mbalimbali kwa **michakato kuingiliana, kuwasiliana, na kushiriki data**. Ingawa mbinu hizi ni muhimu kwa utendaji mzuri wa mfumo, zinaweza pia kutumiwa vibaya na wahalifu wa mtandao ili **kufanya shughuli mbaya**.

### Uingizaji wa Maktaba

Uingizaji wa Maktaba ni mbinu ambapo mshambuliaji **anamlazimisha mchakato kupakia maktaba mbaya**. Mara tu inapowekwa, maktaba inakimbia katika muktadha wa mchakato wa lengo, ikimpa mshambuliaji ruhusa na ufikiaji sawa na mchakato huo.

{{#ref}}
macos-library-injection/
{{#endref}}

### Kuingilia Kazi

Kuingilia Kazi kunahusisha **kuingilia simu za kazi** au ujumbe ndani ya msimbo wa programu. Kwa kuingilia kazi, mshambuliaji anaweza **kubadilisha tabia** ya mchakato, kuangalia data nyeti, au hata kupata udhibiti juu ya mtiririko wa utekelezaji.

{{#ref}}
macos-function-hooking.md
{{#endref}}

### Mawasiliano ya Kati ya Mchakato

Mawasiliano ya Kati ya Mchakato (IPC) inarejelea mbinu tofauti ambazo michakato tofauti **zinashiriki na kubadilishana data**. Ingawa IPC ni muhimu kwa programu nyingi halali, inaweza pia kutumiwa vibaya kuharibu kutengwa kwa mchakato, kuvuja taarifa nyeti, au kufanya vitendo visivyoidhinishwa.

{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Uingizaji wa Maombi ya Electron

Maombi ya Electron yanayoendeshwa na vigezo maalum vya mazingira yanaweza kuwa hatarini kwa uingizaji wa mchakato:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Uingizaji wa Chromium

Inawezekana kutumia bendera `--load-extension` na `--use-fake-ui-for-media-stream` kufanya **shambulio la mtu katikati ya kivinjari** linaloruhusu kuiba funguo za kuandika, trafiki, vidakuzi, kuingiza skripti kwenye kurasa...:

{{#ref}}
macos-chromium-injection.md
{{#endref}}

### NIB Chafu

Faili za NIB **zinaelezea vipengele vya kiolesura cha mtumiaji (UI)** na mwingiliano wao ndani ya programu. Hata hivyo, zinaweza **kutekeleza amri zisizo na mipaka** na **Gatekeeper haizuii** programu iliyotekelezwa tayari kutekelezwa ikiwa **faili ya NIB imebadilishwa**. Kwa hivyo, zinaweza kutumika kufanya programu zisizo na mipaka kutekeleza amri zisizo na mipaka:

{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Uingizaji wa Maombi ya Java

Inawezekana kutumia uwezo fulani wa java (kama vile **`_JAVA_OPTS`** vigezo vya mazingira) kufanya programu ya java kutekeleza **amri/msimbo zisizo na mipaka**.

{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Uingizaji wa Maombi ya .Net

Inawezekana kuingiza msimbo katika maombi ya .Net kwa **kuitumia kazi ya ufuatiliaji wa .Net** (siyo iliyo na ulinzi wa ulinzi wa macOS kama vile kuimarisha wakati wa utekelezaji).

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Uingizaji wa Perl

Angalia chaguzi tofauti za kufanya skripti za Perl kutekeleza msimbo usio na mipaka katika:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Uingizaji wa Ruby

Pia inawezekana kutumia vigezo vya mazingira vya ruby kufanya skripti zisizo na mipaka kutekeleza msimbo usio na mipaka:

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Uingizaji wa Python

Ikiwa vigezo vya mazingira **`PYTHONINSPECT`** vimewekwa, mchakato wa python utaingia kwenye cli ya python mara tu unapomaliza. Pia inawezekana kutumia **`PYTHONSTARTUP`** kuashiria skripti ya python kutekelezwa mwanzoni mwa kikao cha mwingiliano.\
Hata hivyo, kumbuka kwamba skripti ya **`PYTHONSTARTUP`** haitatekelezwa wakati **`PYTHONINSPECT`** inaunda kikao cha mwingiliano.

Vigezo vingine vya mazingira kama **`PYTHONPATH`** na **`PYTHONHOME`** vinaweza pia kuwa na manufaa kufanya amri ya python kutekeleza msimbo usio na mipaka.

Kumbuka kwamba executable zilizokusanywa na **`pyinstaller`** hazitatumia vigezo hivi vya mazingira hata kama zinakimbia kwa kutumia python iliyojumuishwa.

> [!CAUTION]
> Kwa ujumla, sikuweza kupata njia ya kufanya python itekeleze msimbo usio na mipaka kwa kutumia vigezo vya mazingira.\
> Hata hivyo, watu wengi huweka python kwa kutumia **Hombrew**, ambayo itainstall python katika **mahali pa kuandika** kwa mtumiaji wa kawaida wa admin. Unaweza kuiteka nyara kwa kitu kama:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Msimbo wa nyongeza wa kuiteka nyara
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Hata **root** atakimbia msimbo huu wakati wa kukimbia python.

## Ugunduzi

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) ni programu ya chanzo wazi inayoweza **gundua na kuzuia uingizaji wa mchakato**:

- Kutumia **Vigezo vya Mazingira**: Itasimamia uwepo wa yoyote ya vigezo vya mazingira vifuatavyo: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** na **`ELECTRON_RUN_AS_NODE`**
- Kutumia **`task_for_pid`** simu: Ili kupata wakati mchakato mmoja unataka kupata **bandari ya kazi ya mwingine** ambayo inaruhusu kuingiza msimbo katika mchakato.
- **Paramu za maombi ya Electron**: Mtu anaweza kutumia **`--inspect`**, **`--inspect-brk`** na **`--remote-debugging-port`** hoja za mstari wa amri kuanzisha programu ya Electron katika hali ya ufuatiliaji, na hivyo kuingiza msimbo ndani yake.
- Kutumia **symlinks** au **hardlinks**: Kwa kawaida, unyanyasaji wa kawaida ni **kweka kiungo na ruhusa zetu za mtumiaji**, na **kuashiria mahali pa juu ya ruhusa**. Ugunduzi ni rahisi sana kwa hardlink na symlinks. Ikiwa mchakato unaounda kiungo una **kiwango tofauti cha ruhusa** na faili lengwa, tunaunda **onyo**. Kwa bahati mbaya katika kesi ya symlinks, kuzuia haiwezekani, kwani hatuna taarifa kuhusu marudio ya kiungo kabla ya kuundwa. Hii ni kikomo cha mfumo wa EndpointSecurity wa Apple.

### Simu zinazofanywa na michakato mingine

Katika [**hiki chapisho la blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kupata jinsi inavyowezekana kutumia kazi **`task_name_for_pid`** kupata taarifa kuhusu **michakato mingine inayoungiza msimbo katika mchakato** na kisha kupata taarifa kuhusu mchakato huo mwingine.

Kumbuka kwamba ili kuita kazi hiyo unahitaji kuwa **uid sawa** na ile inayokimbia mchakato au **root** (na inarudisha taarifa kuhusu mchakato, si njia ya kuingiza msimbo).

## Marejeleo

- [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
- [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

{{#include ../../../banners/hacktricks-training.md}}
