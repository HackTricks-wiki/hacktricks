# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kikomo cha uzinduzi katika macOS kilianzishwa ili kuboresha usalama kwa **kudhibiti jinsi, nani, na kutoka wapi mchakato unaweza kuanzishwa**. Kilianza katika macOS Ventura, kinatoa mfumo unaopanga **kila binary ya mfumo katika makundi tofauti ya vizuizi**, ambavyo vin defined ndani ya **trust cache**, orodha inayojumuisha binaries za mfumo na hash zao husika​. Vizuizi hivi vinapanuka kwa kila binary inayoweza kutekelezwa ndani ya mfumo, vinavyohusisha seti ya **kanuni** zinazoelezea mahitaji ya **kuanzisha binary maalum**. Kanuni hizo zinajumuisha vizuizi vya kujitegemea ambavyo binary lazima ikidhi, vizuizi vya mzazi vinavyohitajika kukidhi na mchakato wake wa mzazi, na vizuizi vya kuwajibika vinavyopaswa kufuatwa na vyombo vingine husika​.

Mekaniki hii inapanuka kwa programu za wahusika wengine kupitia **Vizuizi vya Mazingira**, kuanzia macOS Sonoma, ikiruhusu wabunifu kulinda programu zao kwa kubainisha **seti ya funguo na thamani za vizuizi vya mazingira.**

Unapofafanua **vizuizi vya mazingira na maktaba** katika kamusi za vizuizi ambazo unaziokoa katika **faili za orodha ya mali za `launchd`**, au katika **faili za orodha za mali za tofauti** ambazo unazitumia katika saini ya msimbo.

Kuna aina 4 za vizuizi:

- **Vizuizi vya Kujitegemea**: Vizuizi vinavyotumika kwa **binary inayotembea**.
- **Mchakato wa Mzazi**: Vizuizi vinavyotumika kwa **mzazi wa mchakato** (kwa mfano **`launchd`** inayoendesha huduma ya XP)
- **Vizuizi vya Kuwajibika**: Vizuizi vinavyotumika kwa **mchakato unaoitisha huduma** katika mawasiliano ya XPC
- **Vizuizi vya kupakia maktaba**: Tumia vizuizi vya kupakia maktaba kuelezea kwa kuchagua msimbo ambao unaweza kupakiwa

Hivyo wakati mchakato unajaribu kuanzisha mchakato mwingine — kwa kuita `execve(_:_:_:)` au `posix_spawn(_:_:_:_:_:_:)` — mfumo wa uendeshaji unakagua kwamba **faili inayoweza kutekelezwa** **inakidhi** **vizuizi vyake vya kujitegemea**. Pia inakagua kwamba **mzazi** **wa mchakato** **inayoweza kutekelezwa** **inakidhi** **vizuizi vya mzazi** vya executable, na kwamba **mchakato wa kuwajibika** **inayoweza kutekelezwa** **inakidhi vizuizi vya mchakato wa kuwajibika**. Ikiwa yoyote ya vizuizi hivi vya uzinduzi havikidhi, mfumo wa uendeshaji hauendeshi programu hiyo.

Ikiwa wakati wa kupakia maktaba sehemu yoyote ya **vizuizi vya maktaba haviko kweli**, mchakato wako **haupaki** maktaba.

## LC Categories

LC inaundwa na **fact** na **operesheni za kimantiki** (na, au..) zinazounganisha ukweli.

[ **Ukweli ambao LC inaweza kutumia umeandikwa**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Kwa mfano:

- is-init-proc: Thamani ya Boolean inayonyesha ikiwa executable lazima iwe mchakato wa kuanzisha wa mfumo wa uendeshaji (`launchd`).
- is-sip-protected: Thamani ya Boolean inayonyesha ikiwa executable lazima iwe faili iliyopewa ulinzi na Mfumo wa Uthibitisho wa Usalama (SIP).
- `on-authorized-authapfs-volume:` Thamani ya Boolean inayonyesha ikiwa mfumo wa uendeshaji ulipakia executable kutoka kwenye kiasi cha APFS kilichothibitishwa.
- `on-authorized-authapfs-volume`: Thamani ya Boolean inayonyesha ikiwa mfumo wa uendeshaji ulipakia executable kutoka kwenye kiasi cha APFS kilichothibitishwa.
- Kiasi cha Cryptexes
- `on-system-volume:` Thamani ya Boolean inayonyesha ikiwa mfumo wa uendeshaji ulipakia executable kutoka kwenye kiasi cha mfumo kilichozinduliwa kwa sasa.
- Ndani ya /System...
- ...

Wakati binary ya Apple imesainiwa in **itapewa LC category** ndani ya **trust cache**.

- **iOS 16 LC categories** zilikuwa [**zimegeuzwa na kuandikwa hapa**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
- **LC categories za sasa (macOS 14** - Somona) zimegeuzwa na [**maelezo yao yanaweza kupatikana hapa**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Kwa mfano, Kategoria 1 ni:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Lazima iwe katika System au Cryptexes volume.
- `launch-type == 1`: Lazima iwe huduma ya mfumo (plist katika LaunchDaemons).
- `validation-category == 1`: Kifaa cha mfumo wa uendeshaji.
- `is-init-proc`: Launchd

### Kurejesha LC Categories

Una habari zaidi [**kuhusu hii hapa**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), lakini kimsingi, Zimewekwa katika **AMFI (AppleMobileFileIntegrity)**, hivyo unahitaji kupakua Kernel Development Kit ili kupata **KEXT**. Alama zinazohusiana na **`kConstraintCategory`** ndizo **za kuvutia**. Ukizitoa utapata mstream wa DER (ASN.1) uliokodishwa ambao utahitaji kufasiriwa na [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) au maktaba ya python-asn1 na skripti yake ya `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) ambayo itakupa mfuatano unaoeleweka zaidi.

## Mipaka ya Mazingira

Hizi ni Mipaka ya Uzinduzi zilizowekwa katika **maombi ya wahusika wengine**. Mwandishi anaweza kuchagua **ukweli** na **operands za kimantiki kutumia** katika maombi yake ili kuzuia ufikiaji kwake mwenyewe.

Inawezekana kuhesabu Mipaka ya Mazingira ya programu kwa:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

Katika **macOS** kuna baadhi ya hifadhi za kuaminika:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Na katika iOS inaonekana kama iko katika **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Katika macOS inayotumia vifaa vya Apple Silicon, ikiwa binary iliyosainiwa na Apple haipo katika hifadhi ya kuaminika, AMFI itakataa kuipakia.

### Enumerating Trust Caches

Faili za awali za hifadhi za kuaminika ziko katika muundo **IMG4** na **IM4P**, ambapo IM4P ni sehemu ya mzigo ya muundo wa IMG4.

Unaweza kutumia [**pyimg4**](https://github.com/m1stadev/PyIMG4) kutoa mzigo wa hifadhidata:
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
(Chaguo lingine linaweza kuwa kutumia chombo [**img4tool**](https://github.com/tihmstar/img4tool), ambacho kitafanya kazi hata kwenye M1 hata kama toleo ni la zamani na kwa x86_64 ikiwa utaweka katika maeneo sahihi).

Sasa unaweza kutumia chombo [**trustcache**](https://github.com/CRKatri/trustcache) kupata taarifa katika muundo unaoweza kusomeka:
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
Kikundi cha kuaminika kinafuata muundo ufuatao, hivyo **kategoria ya LC ni safu ya 4**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Kisha, unaweza kutumia skripti kama [**hii**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) kutoa data.

Kutoka kwenye data hiyo unaweza kuangalia Apps zenye **thamani ya vizuizi vya uzinduzi `0`**, ambazo ndizo ambazo hazijakabiliwa ([**angalia hapa**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) kwa kila thamani ni nini).

## Kupunguza Mashambulizi

Vizuizi vya Uzinduzi vingepunguza mashambulizi kadhaa ya zamani kwa **kuthibitisha kwamba mchakato hautatekelezwa katika hali zisizotarajiwa:** Kwa mfano kutoka maeneo yasiyotarajiwa au kuanzishwa na mchakato wa mzazi asiyejulikana (ikiwa uzinduzi wa launchd pekee unapaswa kuanzisha).

Zaidi ya hayo, Vizuizi vya Uzinduzi pia **vinapunguza mashambulizi ya kushuka daraja.**

Hata hivyo, havipunguzi matumizi ya kawaida ya XPC, **Electron** kuingiza msimbo au **kuingiza dylib** bila uthibitisho wa maktaba (isipokuwa vitambulisho vya timu vinavyoweza kupakia maktaba vinajulikana).

### Ulinzi wa XPC Daemon

Katika toleo la Sonoma, jambo muhimu ni **mipangilio ya wajibu** ya huduma ya XPC daemon. Huduma ya XPC inawajibika kwa ajili yake mwenyewe, tofauti na mteja anayounganisha kuwa na wajibu. Hii imeandikwa katika ripoti ya maoni FB13206884. Mpangilio huu unaweza kuonekana kuwa na kasoro, kwani unaruhusu mwingiliano fulani na huduma ya XPC:

- **Kuzindua Huduma ya XPC**: Ikiwa inachukuliwa kuwa hitilafu, mpangilio huu haukuruhusu kuanzisha huduma ya XPC kupitia msimbo wa mshambuliaji.
- **Kuungana na Huduma Inayoendelea**: Ikiwa huduma ya XPC tayari inaendesha (inaweza kuwa imeanzishwa na programu yake ya asili), hakuna vizuizi vya kuungana nayo.

Wakati wa kutekeleza vizuizi kwenye huduma ya XPC kunaweza kuwa na manufaa kwa **kupunguza dirisha la mashambulizi yanayoweza kutokea**, haishughuliki wasiwasi wa msingi. Kuthibitisha usalama wa huduma ya XPC kimsingi kunahitaji **kuthibitisha mteja anayounganisha kwa ufanisi**. Hii inabaki kuwa njia pekee ya kuimarisha usalama wa huduma hiyo. Pia, inafaa kutaja kwamba mpangilio wa wajibu ulioelezwa kwa sasa unafanya kazi, ambayo huenda isiendane na muundo ulio kusudiwa.

### Ulinzi wa Electron

Hata kama inahitajika kwamba programu lazima **ifunguliwe na LaunchService** (katika vizuizi vya wazazi). Hii inaweza kufikiwa kwa kutumia **`open`** (ambayo inaweza kuweka mabadiliko ya mazingira) au kutumia **Launch Services API** (ambapo mabadiliko ya mazingira yanaweza kuonyeshwa).

## Marejeleo

- [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [https://theevilbit.github.io/posts/launch_constraints_deep_dive/](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

{{#include ../../../banners/hacktricks-training.md}}
