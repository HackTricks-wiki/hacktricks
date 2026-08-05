# Vikwazo vya Launch/Environment vya macOS na Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Vikwazo vya launch katika macOS vilianzishwa ili kuimarisha usalama kwa **kudhibiti jinsi, nani, na kutoka wapi mchakato unaweza kuanzishwa**. Vilivyoanzishwa katika macOS Ventura, vinatoa mfumo unaoweka **kila system binary katika kategoria tofauti za vikwazo**, ambazo hufafanuliwa ndani ya **trust cache**, yaani orodha iliyo na system binaries na hashes zake husika. Vikwazo hivi vinatumika kwa kila executable binary ndani ya system, na kujumuisha seti ya **rules** zinazoeleza mahitaji ya **kuanzisha binary fulani**. Rules hizo zinajumuisha self constraints ambazo binary lazima itimize, parent constraints ambazo mchakato mzazi lazima utimize, na responsible constraints ambazo entities nyingine husika lazima zifuate.

Utaratibu huu unaenea pia kwa third-party apps kupitia **Environment Constraints**, kuanzia macOS Sonoma, na kuwawezesha developers kulinda apps zao kwa kubainisha **seti ya keys na values za environment constraints.**

Unafafanua **launch environment na library constraints** katika constraint dictionaries ambazo unaweza kuhifadhi katika **`launchd` property list files**, au katika **property list** files tofauti unazotumia katika code signing.

Kuna aina 4 za constraints:

- **Self Constraints**: Constraints zinazotumika kwa binary **inayoendeshwa**.
- **Parent Process**: Constraints zinazotumika kwa **mzazi wa mchakato** (kwa mfano **`launchd`** inayoendesha XP service)
- **Responsible Constraints**: Constraints zinazotumika kwa **mchakato unaoita service** katika mawasiliano ya XPC
- **Library load constraints**: Tumia library load constraints kueleza kwa kuchagua code inayoweza kupakiwa

Kwa hivyo mchakato unapojaribu kuanzisha mchakato mwingine — kwa kuita `execve(_:_:_:)` au `posix_spawn(_:_:_:_:_:)` — operating system hukagua kwamba faili la **executable** **linatimiza self constraint yake**. Pia hukagua kwamba executable ya **mchakato** **mzazi** inatimiza **parent constraint** ya executable hiyo, na kwamba executable ya **mchakato** **responsible** inatimiza **responsible process constraint** ya executable hiyo. Ikiwa launch constraint yoyote kati ya hizi haijatimizwa, operating system haiendeshi program.

Wakati wa kupakia library, ikiwa sehemu yoyote ya **library constraint si ya kweli**, mchakato wako **haupaki** library hiyo.

## LC Categories

LC inaundwa na **facts** na **logical operations** (and, or..) zinazounganisha facts.

The[ **facts ambazo LC inaweza kutumia zimeandikwa hapa**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Kwa mfano:

- is-init-proc: Boolean value inayoonyesha ikiwa executable lazima iwe operating system’s initialization process (`launchd`).
- is-sip-protected: Boolean value inayoonyesha ikiwa executable lazima iwe faili linalolindwa na System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Boolean value inayoonyesha ikiwa operating system ilipakia executable kutoka kwenye authorized, authenticated APFS volume.
- `on-authorized-authapfs-volume`: Boolean value inayoonyesha ikiwa operating system ilipakia executable kutoka kwenye authorized, authenticated APFS volume.
- Cryptexes volume
- `on-system-volume:` Boolean value inayoonyesha ikiwa operating system ilipakia executable kutoka kwenye system volume iliyo-boot kwa sasa.
- Ndani ya /System...
- ...

Apple binary inapotiwa saini, **huiweka katika LC category** ndani ya **trust cache**.

- **iOS 16 LC categories** [**ziligeuzwa reverse na kuandikwa hapa**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[6]</sup>
- **LC categories za sasa (macOS 14** - Somona) zimegeuzwa reverse na [**maelezo yake yanaweza kupatikana hapa**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[7]</sup>

Kwa mfano, Category 1 ni:<sup>[7]</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Lazima iwe katika System au Cryptexes volume.
- `launch-type == 1`: Lazima iwe system service (plist katika LaunchDaemons).
- `validation-category == 1`: Executable ya operating system.
- `is-init-proc`: Launchd

### Kureverse LC Categories

Una maelezo zaidi [**kuhusu hilo hapa**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), lakini kimsingi, Yanafafanuliwa katika **AMFI (AppleMobileFileIntegrity)**, hivyo unahitaji kupakua Kernel Development Kit ili kupata **KEXT**. Symbols zinazoanza na **`kConstraintCategory`** ndizo zenye **interest**. Ukiziextract utapata stream iliyosimbwa kwa DER (ASN.1), ambayo utahitaji kuidecode kwa [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) au python-asn1 library pamoja na script yake ya `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), ambayo itakupa string inayoeleweka zaidi.<sup>[3]</sup>

## Vikwazo vya Mazingira

Hivi ni Launch Constraints zilizowekwa na kusanidiwa katika **third party applications**. Developer anaweza kuchagua **facts** na **logical operands za kutumia** katika application yake ili kuzuia access kwake yenyewe.

Inawezekana kuenumerate Environment Constraints za application kwa:
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
> Kwenye macOS inayoendesha kwenye vifaa vya Apple Silicon, ikiwa binary iliyosainiwa na Apple haipo kwenye trust cache, AMFI itakataa kuipakia.

### Enumerating Trust Caches

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
(Chaguo jingine linaweza kuwa kutumia zana [**img4tool**](https://github.com/tihmstar/img4tool), ambayo itaendesha hata kwenye M1 ikiwa release ni ya zamani, na kwenye x86_64 ikiwa utaiweka katika maeneo yanayofaa).

Sasa unaweza kutumia zana [**trustcache**](https://github.com/CRKatri/trustcache) kupata maelezo katika muundo unaosomeka:
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
Trust cache hufuata muundo ufuatao, hivyo **LC category ni safu ya 4**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Kisha, unaweza kutumia script kama [**hii**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) ili kutoa data.

Kutokana na data hiyo unaweza kuangalia Apps zenye **launch constraints value ya `0`**, ambazo ndizo ambazo hazijawekewa constraints ([**angalia hapa**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) ili kuona maana ya kila value).<sup>[6]</sup>

## Mitigation za Attack

Launch Constraints zingekuwa zimezuia attacks kadhaa za zamani kwa **kuhakikisha kwamba process haitatekelezwa katika hali zisizotarajiwa:** Kwa mfano, kutoka locations zisizotarajiwa au ikiwa imeanzishwa na parent process isiyotarajiwa (ikiwa launchd pekee ndiyo inapaswa kuianzisha).

Zaidi ya hayo, Launch Constraints pia **huzuia downgrade attacks.**

Hata hivyo, **hazizuii common XPC** abuses, code injections za **Electron** au **dylib injections** bila library validation (isipokuwa team IDs zinazoweza kupakia libraries zinajulikana).<sup>[3]</sup>

### XPC Daemon Protection

Katika release ya Sonoma, jambo muhimu ni **responsibility configuration** ya daemon XPC service. XPC service inawajibika yenyewe, badala ya connecting client kuwajibika. Hili limeandikwa katika feedback report FB13206884. Mpangilio huu unaweza kuonekana kuwa na dosari, kwa kuwa unaruhusu interactions fulani na XPC service:

- **Kuanzisha XPC Service**: Ikiwa inachukuliwa kuwa bug, mpangilio huu hauruhusu kuanzisha XPC service kupitia attacker code.
- **Kuunganisha kwenye Active Service**: Ikiwa XPC service tayari inaendelea kufanya kazi (huenda imewashwa na application yake ya awali), hakuna vizuizi vya kuunganisha nayo.

Ingawa kuweka constraints kwenye XPC service kunaweza kuwa na manufaa kwa **kupunguza muda wa attacks zinazowezekana**, hakushughulikii tatizo kuu. Kuhakikisha usalama wa XPC service kunahitaji kimsingi **ku-validate connecting client kwa ufanisi**. Hii ndiyo njia pekee ya kuimarisha usalama wa service. Pia, ni muhimu kutambua kwamba responsibility configuration iliyotajwa kwa sasa inafanya kazi, jambo ambalo huenda haliendani na design iliyokusudiwa.<sup>[3]</sup>

### Electron Protection

Hata ikiwa inahitajika kwamba application lazima **ifunguliwe na LaunchService** (katika parents constraints). Hili linaweza kufanywa kwa kutumia **`open`** (ambayo inaweza kuweka env variables) au kwa kutumia **Launch Services API** (ambapo env variables zinaweza kubainishwa).<sup>[3]</sup>

### CVE-2025-43253 - Kubatilisha constraints zilizojengwa ndani wakati wa spawn

Launch constraints (rasmi **lightweight code requirements**, *LWCR*) zinatekelezwa na **AMFI MAC policy**. `posix_spawn` humruhusu caller kuwasilisha arbitrary blob kwa MAC policy kupitia **`posix_spawnattr_setmacpolicyinfo_np()`**, na AMFI ilikubali LWCR dictionary iliyotolewa na caller kupitia njia hiyo. Bug ilikuwa kwamba **constraints zilizotolewa na attacker zilibadilisha zile zilizojengwa ndani ya binary** badala ya kukaguliwa pamoja nazo:

- Tengeneza launch-constraints dictionary ndogo (hata tupu).
- Weka **constraint category kuwa `127`**, value ambayo AMFI inaruhusu katika spawn attributes lakini **haiitekelezi** — huandika tu log ya `Launch Constraint Violation (not enforcing)` badala ya kuzuia execution.
- Ipitishe kupitia spawn attributes, na process huanzishwa katika context ambayo self/parent constraints zake halisi zingekuwa zimeikataza.

Baada ya fix, **constraints zilizojengwa ndani na zile zilizotolewa hukaguliwa**, kwa hiyo dictionary iliyotolewa haiwezi tena kudhoofisha ile iliyojengwa ndani.<sup>[2]</sup>

> [!TIP]
> Huu ndio muundo wa jumla wa kutafuta wakati wa kukagua constraint enforcement: API inayoruhusu untrusted input *kusupply* policy huwa ya kuvutia kila mara wakati policy engine inachukulia value iliyotolewa kuwa replacement badala ya kuwa requirement ya ziada.

## Marejeo

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
