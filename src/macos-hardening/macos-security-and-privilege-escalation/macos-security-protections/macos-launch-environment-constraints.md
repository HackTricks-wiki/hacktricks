# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

Launch constraints katika macOS zilianzishwa ili kuimarisha usalama kwa **kudhibiti jinsi, nani, na kutoka wapi process inaweza kuanzishwa**. Zilizoanzishwa katika macOS Ventura, hutoa framework inayoweka **kila system binary katika constraint categories tofauti**, ambazo hufafanuliwa ndani ya **trust cache**, orodha iliyo na system binaries na hashes zake husika​. Constraints hizi zinatumika kwa kila executable binary ndani ya system, zikihusisha seti ya **rules** zinazoeleza mahitaji ya **ku-launch binary fulani**. Rules hizo zinajumuisha self constraints ambazo binary lazima itimize, parent constraints ambazo parent process yake lazima itimize, na responsible constraints ambazo entities nyingine husika lazima zifuate​.

Mechanism hii inatumika pia kwa third-party apps kupitia **Environment Constraints**, kuanzia macOS Sonoma, na kuwawezesha developers kulinda apps zao kwa kubainisha **seti ya keys na values za environment constraints.**

Unafafanua **launch environment na library constraints** katika constraint dictionaries ambazo ama unazihifadhi kwenye **`launchd` property list files**, au kwenye **property list** files tofauti unazotumia katika code signing.

Kuna aina 4 za constraints:

- **Self Constraints**: Constraints zinazotumika kwa binary **inayoendelea ku-run**.
- **Parent Process**: Constraints zinazotumika kwa **parent wa process** (kwa mfano **`launchd`** anayeendesha XP service)
- **Responsible Constraints**: Constraints zinazotumika kwa **process inayoita service** katika mawasiliano ya XPC
- **Library load constraints**: Tumia library load constraints kueleza kwa kuchagua code inayoweza ku-loadiwa

Kwa hiyo process inapojaribu ku-launch process nyingine — kwa kuita `execve(_:_:_:)` au `posix_spawn(_:_:_:_:_:_:)` — operating system hukagua kwamba **executable** file inatimiza **self constraint yake**. Pia hukagua kwamba executable ya **parent** **process** inatimiza **parent constraint** ya executable hiyo, na kwamba executable ya **responsible** **process** inatimiza **responsible process constraint** ya executable hiyo. Ikiwa launch constraints yoyote kati ya hizi haijatimizwa, operating system hai-run program hiyo.

Ikiwa wakati wa ku-load library sehemu yoyote ya **library constraint si kweli**, process yako **hai-load** library hiyo.

## LC Categories

LC huundwa na **facts** na **logical operations** (and, or..) zinazochanganya facts.

The[ **facts ambazo LC inaweza kutumia zimeandikwa hapa**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Kwa mfano:

- is-init-proc: Boolean value inayoonyesha ikiwa executable lazima iwe initialization process ya operating system (`launchd`).
- is-sip-protected: Boolean value inayoonyesha ikiwa executable lazima iwe file inayolindwa na System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Boolean value inayoonyesha ikiwa operating system ili-load executable kutoka authorized, authenticated APFS volume.
- `on-authorized-authapfs-volume`: Boolean value inayoonyesha ikiwa operating system ili-load executable kutoka authorized, authenticated APFS volume.
- Cryptexes volume
- `on-system-volume:`Boolean value inayoonyesha ikiwa operating system ili-load executable kutoka system volume iliyo-bootiwa kwa sasa.
- Inside /System...
- ...

Apple binary inapotiwa saini, **huwekwa katika LC category** ndani ya **trust cache**.

- **iOS 16 LC categories** [**zilipinduliwa na kuandikwa hapa**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- **LC categories za sasa (macOS 14** - Somona) zimepinduliwa na [**maelezo yake yanaweza kupatikana hapa**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Kwa mfano Category 1 ni:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Lazima iwe kwenye System au Cryptexes volume.
- `launch-type == 1`: Lazima iwe system service (plist katika LaunchDaemons).
- `validation-category == 1`: Executable ya operating system.
- `is-init-proc`: Launchd

### Reversing LC Categories

Una maelezo zaidi [**kuhusu hilo hapa**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), lakini kimsingi, Zimefafanuliwa katika **AMFI (AppleMobileFileIntegrity)**, kwa hiyo unahitaji kupakua Kernel Development Kit ili kupata **KEXT**. Alama zinazoanza na **`kConstraintCategory`** ndizo **zenye umuhimu**. Ukizitoa utapata stream iliyosimbwa kwa DER (ASN.1), ambayo utahitaji ku-decode kwa kutumia [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) au python-asn1 library pamoja na script yake ya `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), ambayo itakupa string inayoeleweka zaidi.<sup>[[3]](#references)</sup>

## Environment Constraints

Hizi ni Launch Constraints zilizowekwa na kusanidiwa katika **third party applications**. Developer anaweza kuchagua **facts** na **logical operands** za kutumia katika application yake ili kuzuia access kwake.

Inawezekana kuorodhesha Environment Constraints za application kwa kutumia:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

Katika **macOS** kuna trust caches kadhaa:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Na katika iOS inaonekana kuwa iko kwenye **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Kwenye macOS inayotumika kwenye vifaa vya Apple Silicon, ikiwa binary iliyosainiwa na Apple haipo kwenye trust cache, AMFI itakataa kuipakia.

### Kuorodhesha Trust Caches

Faili za trust cache zilizotajwa hapo awali ziko katika format ya **IMG4** na **IM4P**, ambapo IM4P ni sehemu ya payload ya format ya IMG4.

Unaweza kutumia [**pyimg4**](https://github.com/m1stadev/PyIMG4) kutoa payload ya databases:
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
(Chaguo jingine linaweza kuwa kutumia tool [**img4tool**](https://github.com/tihmstar/img4tool), ambayo itaendeshwa hata kwenye M1 ingawa release ni ya zamani, na kwenye x86_64 ikiwa utaiweka katika maeneo yanayofaa).

Sasa unaweza kutumia tool [**trustcache**](https://github.com/CRKatri/trustcache) kupata maelezo katika muundo unaosomeka:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Trust cache inafuata muundo ufuatao, kwa hiyo **kategoria ya LC ni safu ya 4**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Kisha, unaweza kutumia script kama [**hii**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) kutoa data.

Kutoka kwenye data hiyo unaweza kuangalia Apps zilizo na **launch constraints value ya `0`**, ambazo ndizo ambazo hazijawekewa vikwazo ([**angalia hapa**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) ili kuona kila value inamaanisha nini).<sup>[[6]](#references)</sup>

## Mipunguzo ya Mashambulizi

Launch Constraints zingepunguza mashambulizi kadhaa ya zamani kwa **kuhakikisha kuwa process haitatekelezwa katika hali zisizotarajiwa:** Kwa mfano, kutoka kwenye maeneo yasiyotarajiwa au ikiwa imeanzishwa na parent process isiyotarajiwa (ikiwa ni launchd pekee iliyopaswa kuianzisha)

Zaidi ya hayo, Launch Constraints pia **hupunguza downgrade attacks.**

Hata hivyo, **hazipunguzi matumizi mabaya ya kawaida ya XPC**, code injections za **Electron** au **dylib injections** bila library validation (isipokuwa team IDs zinazoweza kupakia libraries zinajulikana).<sup>[[3]](#references)</sup>

### Ulinzi wa XPC Daemon

Katika release ya Sonoma, jambo muhimu ni **responsibility configuration** ya XPC service ya daemon. XPC service inawajibika yenyewe, badala ya connecting client kuwajibika. Hili limeandikwa katika feedback report FB13206884. Mpangilio huu unaweza kuonekana kuwa na dosari, kwa kuwa unaruhusu mwingiliano fulani na XPC service:

- **Kuanzisha XPC Service**: Ikiwa inachukuliwa kuwa bug, mpangilio huu hauruhusu kuanzisha XPC service kupitia attacker code.
- **Kuunganisha kwenye Active Service**: Ikiwa XPC service tayari inaendesha (huenda iliwezeshwa na application yake ya awali), hakuna vizuizi vya kuunganisha nayo.

Ingawa kuweka constraints kwenye XPC service kunaweza kuwa na manufaa kwa **kupunguza muda ambao mashambulizi yanaweza kutokea**, hakushughulikii tatizo kuu. Kuhakikisha usalama wa XPC service kunahitaji kimsingi **kuthibitisha connecting client kwa ufanisi**. Hii ndiyo njia pekee ya kuimarisha usalama wa service. Pia, ni muhimu kutambua kuwa responsibility configuration iliyotajwa kwa sasa inafanya kazi, jambo ambalo huenda haliendani na muundo uliokusudiwa.<sup>[[3]](#references)</sup>

### Ulinzi wa Electron

Hata ikiwa inahitajika kwamba application lazima **ifunguliwe na LaunchService** (katika parents constraints). Hili linaweza kufanywa kwa kutumia **`open`** (ambayo inaweza kuweka env variables) au kwa kutumia **Launch Services API** (ambapo env variables zinaweza kuonyeshwa).<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Kubadilisha constraints zilizojengewa ndani wakati wa spawn

Launch constraints (rasmi **lightweight code requirements**, *LWCR*) zinatekelezwa na **AMFI MAC policy**. `posix_spawn` humruhusu caller kupeleka blob yoyote kwa MAC policy kupitia **`posix_spawnattr_setmacpolicyinfo_np()`**, na AMFI ilikubali LWCR dictionary iliyotolewa na caller kupitia njia hiyo. Bug ilikuwa kwamba **constraints zilizotolewa na attacker zilibadilisha zile zilizojengewa ndani ya binary** badala ya kukaguliwa pamoja nazo:

- Tengeneza launch-constraints dictionary ndogo (hata tupu).
- Weka **constraint category kuwa `127`**, value ambayo AMFI inaruhusu katika spawn attributes lakini **haiitekelezi** — huandika tu `Launch Constraint Violation (not enforcing)` badala ya kuzuia execution.
- Ipitishie kwenye spawn attributes, na process itaanza katika context ambayo self/parent constraints zake halisi zingekuwa zimeizuia.

Baada ya kurekebishwa, **constraints zilizojengewa ndani na zile zilizotolewa** zote zinathibitishwa, kwa hiyo dictionary iliyotolewa haiwezi tena kudhoofisha ile iliyojengewa ndani.<sup>[[2]](#references)</sup>

> [!TIP]
> Huu ndio muundo wa jumla wa kutafuta unapokagua constraint enforcement: API inayoruhusu input isiyoaminika *kutoa* policy huwa ya kuvutia kila mara policy engine inapochukulia value iliyotolewa kama replacement badala ya requirement ya ziada.

## Marejeo

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
