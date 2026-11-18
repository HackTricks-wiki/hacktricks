# Vizuizi vya Launch/Environment vya macOS na Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Vizuizi vya launch katika macOS vilianzishwa ili kuimarisha usalama kwa **kudhibiti jinsi, nani, na kutoka wapi mchakato unaweza kuanzishwa**. Vilianzishwa katika macOS Ventura, na vinatoa mfumo unaoweka **kila mfumo wa binary katika kategoria tofauti za vizuizi**, ambazo hufafanuliwa ndani ya **trust cache**, orodha iliyo na mifumo ya binary ya mfumo na hash zake​. Vizuizi hivi vinatumika kwa kila mfumo wa binary unaoweza kutekelezwa ndani ya mfumo, na vinajumuisha seti ya **kanuni** zinazoeleza mahitaji ya **kuanzisha mfumo fulani wa binary**. Kanuni hizo zinajumuisha self constraints ambazo mfumo wa binary lazima uzitimize, parent constraints ambazo mchakato mzazi wake unapaswa kutimiza, na responsible constraints ambazo vyombo vingine vinavyohusika vinapaswa kuzingatia​.<sup>[[1]](#references)[[4]](#references)</sup>

Utaratibu huu ulianza kutumika pia kwa programu za third-party kuanzia macOS Sonoma kupitia **Environment Constraints**, na kuwawezesha watengenezaji kulinda programu zao kwa kubainisha **seti ya funguo na thamani za environment constraints.**<sup>[[5]](#references)</sup>

Unafafanua **launch environment na library constraints** katika constraint dictionaries ambazo unaweza kuhifadhi katika **faili za property list za `launchd`**, au katika faili tofauti za **property list** unazotumia katika code signing.<sup>[[5]](#references)</sup>

Kuna aina 4 za constraints:

- **Self Constraints**: Vizuizi vinavyotumika kwa mfumo wa binary **unaoendeshwa**.
- **Parent Process**: Vizuizi vinavyotumika kwa **mzazi wa mchakato** (kwa mfano, **`launchd`** inayoendesha huduma ya XP)
- **Responsible Constraints**: Vizuizi vinavyotumika kwa **mchakato unaoita huduma** katika mawasiliano ya XPC
- **Library load constraints**: Tumia library load constraints kueleza kwa kuchagua msimbo unaoweza kupakiwa

Kwa hivyo, mchakato unapojaribu kuanzisha mchakato mwingine — kwa kuita `execve(_:_:_:)` au `posix_spawn(_:_:_:_:_:)` — mfumo wa uendeshaji hukagua ikiwa faili **inayoweza kutekelezwa** **inatimiza** **self constraint yake**. Pia hukagua ikiwa faili inayoweza kutekelezwa ya mchakato **mzazi** **inatimiza** **parent constraint** ya faili inayoweza kutekelezwa, na ikiwa faili inayoweza kutekelezwa ya mchakato **unaowajibika** **inatimiza responsible process constrain**t ya faili inayoweza kutekelezwa. Ikiwa mojawapo ya launch constraints hizi hazijatimizwa, mfumo wa uendeshaji hauendeshi programu.

Ikiwa sehemu yoyote ya **library constraint si ya kweli** wakati wa kupakia library, mchakato wako **haupaki** library hiyo.

## Kategoria za LC

LC huundwa na **facts** na **logical operations** (and, or...) zinazounganisha facts.

[**Facts ambazo LC inaweza kutumia zimeandikwa hapa**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Kwa mfano:

- is-init-proc: Thamani ya Boolean inayoonyesha ikiwa faili inayoweza kutekelezwa lazima iwe mchakato wa uanzishaji wa mfumo wa uendeshaji (`launchd`).
- is-sip-protected: Thamani ya Boolean inayoonyesha ikiwa faili inayoweza kutekelezwa lazima iwe faili inayolindwa na System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Thamani ya Boolean inayoonyesha ikiwa mfumo wa uendeshaji ulipakia faili inayoweza kutekelezwa kutoka kwenye APFS volume iliyoidhinishwa na kuthibitishwa.
- `on-authorized-authapfs-volume`: Thamani ya Boolean inayoonyesha ikiwa mfumo wa uendeshaji ulipakia faili inayoweza kutekelezwa kutoka kwenye APFS volume iliyoidhinishwa na kuthibitishwa.
  - Cryptexes volume
- `on-system-volume:`Thamani ya Boolean inayoonyesha ikiwa mfumo wa uendeshaji ulipakia faili inayoweza kutekelezwa kutoka kwenye system volume iliyoanzishwa kwa sasa.
  - Ndani ya /System...
- ...

Apple inapoweka sahihi kwenye mfumo wa binary, **huupangia kategoria ya LC** ndani ya **trust cache**.

- **Kategoria za LC za iOS 16** [**zilirudishwa nyuma na kuandikwa hapa**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- **Kategoria za sasa za LC (macOS 14** - Somona) zimerudishwa nyuma na [**maelezo yake yanapatikana hapa**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Kwa mfano, Kategoria ya 1 ni:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: Lazima iwe kwenye volume ya System au Cryptexes.
- `launch-type == 1`: Lazima iwe huduma ya mfumo (plist katika LaunchDaemons).
- `validation-category == 1`: Faili inayoweza kutekelezwa ya mfumo wa uendeshaji.
- `is-init-proc`: Launchd

### Kuchunguza LC Categories

Una maelezo zaidi [**kuhusu hilo hapa**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), lakini kimsingi, yanafafanuliwa katika **AMFI (AppleMobileFileIntegrity)**, kwa hiyo unahitaji kupakua Kernel Development Kit ili kupata **KEXT**. Alama zinazoanza na **`kConstraintCategory`** ndizo **muhimu**. Ukizitoa, utapata mtiririko uliosimbwa kwa DER (ASN.1), ambao utahitaji kuut decode kwa kutumia [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) au maktaba ya python-asn1 pamoja na script yake ya `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), itakayokupa mfuatano unaoeleweka zaidi.<sup>[[3]](#references)[[8]](#references)</sup>

## Vikwazo vya Mazingira

Hivi ni Launch Constraints zilizosanidiwa katika **programu za wahusika wengine**. Msanidi programu anaweza kuchagua **facts** na **logical operands za kutumia** katika programu yake ili kuzuia ufikiaji wake.

Inawezekana kuorodhesha Environment Constraints za programu kwa kutumia:

```bash
codesign -d -vvvv app.app
```

## Trust Caches

Katika **macOS** kuna trust cache kadhaa:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Na kwenye iOS inaonekana kuwa katika **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Kwenye macOS inayotumia vifaa vya Apple Silicon, ikiwa binary iliyotiwa saini na Apple haipo kwenye trust cache, AMFI itakataa kuipakia.

### Kuhesabu Trust Caches

Faili za trust cache zilizotajwa hapo awali ziko katika fomati za **IMG4** na **IM4P**; IM4P ni sehemu ya payload ya fomati ya IMG4.

Unaweza kutumia [**pyimg4**](https://github.com/m1stadev/PyIMG4) kutoa payload ya hifadhidata:

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

(Chaguo jingine ni kutumia zana [**img4tool**](https://github.com/tihmstar/img4tool), ambayo itaendelea kufanya kazi hata kwenye M1, ingawa toleo lake ni la zamani na limetengenezwa kwa x86_64, ukiisakinisha katika maeneo yanayofaa).

Sasa unaweza kutumia zana [**trustcache**](https://github.com/CRKatri/trustcache) ili kupata maelezo katika muundo unaosomeka:

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

Trust cache hufuata muundo ufuatao, kwa hiyo **LC category ni safu ya 4**.

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

Kutokana na data hiyo unaweza kukagua Apps zenye **thamani ya launch constraints ya `0`**, ambazo hazina vizuizi ([**angalia hapa**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) ili kuona maana ya kila thamani).<sup>[[6]](#references)</sup>

## Mikakati ya Kupunguza Mashambulizi

Launch Constraints zingepunguza mashambulizi kadhaa ya zamani kwa **kuhakikisha kwamba mchakato hautatekelezwa katika hali zisizotarajiwa:** Kwa mfano, kutoka maeneo yasiyotarajiwa au ukiitwa na mchakato mzazi usiotarajiwa (ikiwa ni launchd pekee inayopaswa kuuanzisha)

Zaidi ya hayo, Launch Constraints pia **hupunguza mashambulizi ya downgrade.**

Hata hivyo, **hazipunguzi matumizi mabaya ya kawaida ya XPC**, uingizaji wa code ya **Electron** au **dylib injections** bila library validation (isipokuwa team IDs zinazoweza kupakia libraries zijulikane).<sup>[[3]](#references)</sup>

### Ulinzi wa XPC Daemon

Katika toleo la Sonoma, jambo muhimu ni usanidi wa **uwajibikaji** wa huduma ya XPC ya daemon. Huduma ya XPC inawajibika kwa usalama wake yenyewe, badala ya mteja anayeunganisha kuwajibika. Hili limeandikwa katika ripoti ya maoni FB13206884. Usanidi huu unaweza kuonekana kuwa na dosari, kwa kuwa unaruhusu mwingiliano fulani na huduma ya XPC:

- **Kuanzisha Huduma ya XPC**: Ikiwa usanidi huu unachukuliwa kuwa hitilafu, hauruhusu kuanzisha huduma ya XPC kupitia code ya mshambuliaji.
- **Kuunganisha kwenye Huduma Inayotumika**: Ikiwa huduma ya XPC tayari inaendeshwa (huenda ilianzishwa na programu yake ya awali), hakuna vizuizi vya kuunganishwa nayo.

Ingawa kuweka constraints kwenye huduma ya XPC kunaweza kusaidia kwa **kupunguza muda wa uwezekano wa kushambuliwa**, hakutatui tatizo kuu. Ili kuhakikisha usalama wa huduma ya XPC, ni lazima **kuthibitisha kwa ufanisi mteja anayeunganisha**. Hii ndiyo njia pekee ya kuimarisha usalama wa huduma. Pia, inafaa kutambua kwamba usanidi huo wa uwajibikaji ulioelezwa unafanya kazi kwa sasa, jambo ambalo huenda lisilingane na muundo uliokusudiwa.<sup>[[3]](#references)</sup>

### Ulinzi wa Electron

Hata ikiwa programu inapaswa **kufunguliwa na LaunchService** (katika constraints za michakato yake mizazi), hili linaweza kufanywa kwa kutumia **`open`** (ambayo inaweza kuweka env variables) au kwa kutumia **Launch Services API** (ambapo env variables zinaweza kubainishwa).<sup>[[3]](#references)</sup>

Kwa maelezo ya jumla kuhusu utaratibu wa MACF unaotumika nyuma ya sifa za spawn mahususi kwa policy, angalia [Sifa za spawn za MACF zilizo mahususi kwa policy](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).

### CVE-2025-43253 - Kubatilisha constraints zilizojengewa ndani wakati wa spawn

Launch constraints (rasmi **lightweight code requirements**, *LWCR*) hutekelezwa na **AMFI MAC policy**. `posix_spawn` huruhusu mwitaji kupitisha blob yoyote kwa MAC policy kupitia **`posix_spawnattr_setmacpolicyinfo_np()`**, na AMFI ilikubali kamusi ya LWCR iliyotolewa na mwitaji kupitia njia hiyo. Hitilafu ilikuwa kwamba **constraints zilizotolewa na mshambuliaji zilibadilisha zile zilizojengewa ndani ya binary**, badala ya kukaguliwa pamoja nazo:

- Unda kamusi ya launch constraints iliyo ndogo kabisa (hata tupu).
- Weka **aina ya constraint kuwa `127`**, thamani ambayo AMFI inaruhusu katika sifa za spawn lakini **hailazimishi** — hurekodi tu `Launch Constraint Violation (not enforcing)` badala ya kuzuia utekelezaji.
- Ipitishe kupitia sifa za spawn, kisha mchakato huanzishwa katika muktadha ambao constraints zake halisi za self/parent zingeukataza.

Baada ya marekebisho, constraints **zote mbili** — zilizojengewa ndani na zilizotolewa — huthibitishwa, kwa hiyo kamusi iliyotolewa haiwezi tena kudhoofisha zile zilizojengewa ndani.<sup>[[2]](#references)</sup>

> [!TIP]
> Huu ndio muundo wa jumla wa kuangalia unapokagua utekelezaji wa constraints: API inayoruhusu ingizo lisiloaminika *kutoa* policy huvutia uchunguzi wakati wowote ambapo policy engine huchukulia thamani iliyotolewa kama mbadala badala ya sharti la ziada.



## References

- [1] [Objective by the Sea #OBTS v6.0 Siku ya 2 (Livestream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Kukwepa Launch Constraints kwenye macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Uchambuzi wa Kina wa Launch na Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Kwa nini programu ya mfumo au zana ya amri haiendeshwi? Launch constraints na trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Linda programu yako ya Mac kwa environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Maelezo ya Launch Constraints zilizoletwa katika iOS 16 (gist ya LinusHenze)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [Launch Constraints za macOS Sonoma (14) (gist ya theevilbit)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Zaidi ya LaunchAgents za kawaida - maelezo hapa](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
