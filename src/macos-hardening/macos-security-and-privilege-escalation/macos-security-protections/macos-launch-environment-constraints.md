# macOS Launch/Environment-beperkings & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Launch-beperkings in macOS is ingestel om sekuriteit te verbeter deur te **reguleer hoe, deur wie en vanwaar ’n proses geïnisieer kan word**. Dit is in macOS Ventura ingestel en verskaf ’n raamwerk wat **elke stelsel-binary in afsonderlike constraint-kategorieë** kategoriseer. Hierdie kategorieë word binne die **trust cache** gedefinieer, ’n lys wat stelsel-binaries en hul onderskeie hashes bevat​. Hierdie constraints is van toepassing op elke uitvoerbare binary binne die stelsel en behels ’n stel **reëls** wat die vereistes vir die **launch van ’n spesifieke binary** uiteensit. Die reëls sluit self constraints in waaraan ’n binary moet voldoen, parent constraints waaraan sy parent process moet voldoen, en responsible constraints waaraan ander relevante entiteite moet voldoen​.

Die meganisme word vanaf macOS Sonoma na third-party apps uitgebrei deur middel van **Environment Constraints**, wat ontwikkelaars toelaat om hul apps te beskerm deur ’n **stel sleutels en waardes vir environment constraints** te spesifiseer.

Jy definieer **launch environment- en library constraints** in constraint dictionaries wat jy óf in **`launchd` property list-lêers** stoor, óf in **afsonderlike property list**-lêers wat jy in code signing gebruik.

Daar is 4 tipes constraints:

- **Self Constraints**: Constraints wat op die **lopende** binary toegepas word.
- **Parent Process**: Constraints wat op die **parent van die proses** toegepas word (byvoorbeeld **`launchd`** wat ’n XP-service laat loop)
- **Responsible Constraints**: Constraints wat toegepas word op die **proses wat die service aanroep** in ’n XPC-kommunikasie
- **Library load constraints**: Gebruik library load constraints om kode wat gelaai kan word selektief te beskryf

Wanneer ’n proses dus probeer om ’n ander proses te launch — deur `execve(_:_:_:)` of `posix_spawn(_:_:_:_:_:_)` aan te roep — kontroleer die operating system of die **executable**-lêer aan sy **eie self constraint** voldoen. Dit kontroleer ook of die **parent** **process** se executable aan die executable se **parent constraint** voldoen, en of die **responsible** **process** se executable aan die executable se responsible process constraint voldoen. Indien enige van hierdie launch constraints nie nagekom word nie, laat die operating system nie die program loop nie.

Indien enige deel van die **library constraint** nie waar is wanneer ’n library gelaai word nie, **laai jou proses nie** die library nie.

## LC Categories

’n LC word saamgestel uit **feite** en **logiese bewerkings** (and, or..) wat feite kombineer.

Die[ **feite wat ’n LC kan gebruik, word gedokumenteer**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Byvoorbeeld:

- is-init-proc: ’n Boolean-waarde wat aandui of die executable die operating system se initialiseringsproses (`launchd`) moet wees.
- is-sip-protected: ’n Boolean-waarde wat aandui of die executable ’n lêer moet wees wat deur System Integrity Protection (SIP) beskerm word.
- `on-authorized-authapfs-volume:` ’n Boolean-waarde wat aandui of die operating system die executable vanaf ’n gemagtigde, geauthentiseerde APFS-volume gelaai het.
- `on-authorized-authapfs-volume`: ’n Boolean-waarde wat aandui of die operating system die executable vanaf ’n gemagtigde, geauthentiseerde APFS-volume gelaai het.
- Cryptexes volume
- `on-system-volume:`’n Boolean-waarde wat aandui of die operating system die executable vanaf die tans-gebootte stelselvolume gelaai het.
- Binne /System...
- ...

Wanneer ’n Apple binary geteken word, **ken dit dit aan ’n LC-kategorie** binne die **trust cache** toe.

- **iOS 16 LC categories** is [**hier reversed en gedokumenteer**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Huidige **LC categories (macOS 14** - Somona) is reversed en hul [**beskrywings kan hier gevind word**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Byvoorbeeld, Category 1 is:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Moet in System- of Cryptexes-volume wees.
- `launch-type == 1`: Moet 'n system service wees (plist in LaunchDaemons).
- `validation-category == 1`: 'n Uitvoerbare operating system-lêer.
- `is-init-proc`: Launchd

### Omkering van LC-kategorieë

Jy kan [**hier meer inligting daaroor kry**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), maar basies word hulle in **AMFI (AppleMobileFileIntegrity)** gedefinieer. Daarom moet jy die Kernel Development Kit aflaai om die **KEXT** te kry. Die simbole wat met **`kConstraintCategory`** begin, is die **interessante** simbole. Deur hulle te onttrek, kry jy 'n DER (ASN.1)-gekodeerde stroom wat jy met [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) of die python-asn1-biblioteek en sy `dump.py`-script, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), moet dekodeer. Dit sal vir jou 'n meer verstaanbare string gee.<sup>[[3]](#references)</sup>

## Environment Constraints

Dit is die Launch Constraints wat in **third party applications** opgestel is. Die ontwikkelaar kan die **facts** en **logical operands** kies wat in sy toepassing gebruik moet word om toegang daartoe te beperk.

Dit is moontlik om 'n toepassing se Environment Constraints te enumereer met:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

In **macOS** is daar ’n paar trust caches:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

En in iOS lyk dit asof dit in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** is.

> [!WARNING]
> Op macOS wat op Apple Silicon-toestelle loop, sal AMFI weier om ’n Apple-signed binary te laai indien dit nie in die trust cache is nie.

### Enumerating Trust Caches

Die vorige trust cache-lêers is in die **IMG4**- en **IM4P**-formaat, waar IM4P die payload-afdeling van ’n IMG4-formaat is.

Jy kan [**pyimg4**](https://github.com/m1stadev/PyIMG4) gebruik om die payload van databasisse te onttrek:
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
(Nog ’n opsie is om die tool [**img4tool**](https://github.com/tihmstar/img4tool) te gebruik, wat selfs op M1 sal loop al is die release oud, en op x86_64 as jy dit in die korrekte liggings installeer).

Nou kan jy die tool [**trustcache**](https://github.com/CRKatri/trustcache) gebruik om die inligting in ’n leesbare formaat te kry:
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
Die trust cache volg die volgende struktuur, dus is die **LC category die 4de kolom**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Dan kan jy ’n script soos [**hierdie een**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) gebruik om data te onttrek.

Uit daardie data kan jy die Apps met ’n **launch constraints value van `0`** nagaan; dit is dié wat nie beperk word nie ([**kyk hier**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) om te sien wat elke waarde is).<sup>[[6]](#references)</sup>

## Aanval-versagtings

Launch Constraints sou verskeie ou aanvalle versag het deur **seker te maak dat die proses nie in onverwagte toestande uitgevoer word nie:** Byvoorbeeld vanaf onverwagte liggings of deur ’n onverwagte ouerproses aangeroep word (indien slegs launchd dit behoort te begin).

Boonop **versag Launch Constraints ook downgrade attacks.**

Hulle **versag egter nie algemene XPC**-misbruik, **Electron**-code injections of **dylib injections** sonder library validation nie (tensy die team IDs wat libraries kan laai, bekend is).<sup>[[3]](#references)</sup>

### XPC Daemon Protection

In die Sonoma-release is die **verantwoordelikheidskonfigurasie** van die daemon XPC service ’n noemenswaardige punt. Die XPC service is self verantwoordelik, in teenstelling met die connecting client wat verantwoordelik is. Dit word in die feedback report FB13206884 gedokumenteer. Hierdie opstelling kan gebrekkig lyk, aangesien dit sekere interaksies met die XPC service toelaat:

- **Launching the XPC Service**: Indien aanvaar word dat dit ’n bug is, laat hierdie opstelling nie toe dat die XPC service deur attacker code begin word nie.
- **Connecting to an Active Service**: Indien die XPC service reeds loop (moontlik deur sy oorspronklike application geaktiveer), is daar geen hindernisse om daaraan te koppel nie.

Hoewel die implementering van constraints op die XPC service voordelig kan wees deur **die venster vir moontlike aanvalle te verklein**, spreek dit nie die primêre bekommernis aan nie. Om die sekuriteit van die XPC service fundamenteel te verseker, moet die connecting client effektief **gevalideer word**. Dit bly die enigste metode om die service se sekuriteit te versterk. Dit is ook die moeite werd om daarop te let dat die genoemde verantwoordelikheidskonfigurasie tans operasioneel is, wat moontlik nie met die beoogde ontwerp ooreenstem nie.<sup>[[3]](#references)</sup>

### Electron Protection

Selfs al word vereis dat die application deur **LaunchService geopen moet word** (in the parents constraints), kan dit bereik word deur **`open`** te gebruik (wat env variables kan stel) of deur die **Launch Services API** te gebruik (waar env variables aangedui kan word).<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Oorskryf van die ingeboude constraints tydens spawn time

Launch constraints (amptelik **lightweight code requirements**, *LWCR*) word deur die **AMFI MAC policy** afgedwing. `posix_spawn` laat ’n caller toe om ’n arbitrêre blob aan ’n MAC policy deur te gee via **`posix_spawnattr_setmacpolicyinfo_np()`**, en AMFI het deur daardie pad ’n caller-supplied LWCR dictionary aanvaar. Die bug was dat die **attacker-supplied constraints die binary se ingeboude constraints vervang het** in plaas daarvan om bykomend daaraan nagegaan te word:

- Bou ’n minimale (selfs leë) launch-constraints dictionary.
- Stel die **constraint category op `127`**, ’n waarde wat AMFI in spawn attributes toelaat maar **nie afdwing nie** — dit log slegs `Launch Constraint Violation (not enforcing)` in plaas daarvan om die uitvoering te blokkeer.
- Gee dit via die spawn attributes deur, waarna die process in ’n context launch waarin sy werklike self/parent constraints dit sou verbied het.

Ná die fix word **sowel die ingeboude as die supplied constraints gevalideer**, sodat die supplied dictionary nie meer die ingeboude een kan verswak nie.<sup>[[2]](#references)</sup>

> [!TIP]
> Dit is die algemene vorm waarna jy moet soek wanneer jy constraint enforcement oudit: ’n API wat onbetroubare input toelaat om ’n policy te *supply*, is gewoonlik interessant wanneer die policy engine die supplied value as ’n vervanging eerder as ’n bykomende vereiste hanteer.

## Verwysings

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
