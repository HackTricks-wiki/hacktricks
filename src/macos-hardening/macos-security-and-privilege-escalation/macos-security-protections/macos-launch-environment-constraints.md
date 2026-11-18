# macOS Launch-/Omgewingsbeperkings en Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting

Launch-beperkings is in macOS ingestel om sekuriteit te verbeter deur **te reguleer hoe, deur wie en van waar ’n proses begin kan word**. Hulle is in macOS Ventura bekendgestel en bied ’n raamwerk wat **elke stelselbinêr in afsonderlike beperkingskategorieë indeel**. Hierdie kategorieë word in die **trust cache** gedefinieer, ’n lys wat stelselbinêre en hul onderskeie hashes bevat. Hierdie beperkings geld vir elke uitvoerbare binêr in die stelsel en behels ’n stel **reëls** wat die vereistes vir die **begin van ’n bepaalde binêr** uiteensit. Die reëls sluit selfbeperkings in waaraan ’n binêr moet voldoen, ouerbeperkings waaraan sy ouerproses moet voldoen, en verantwoordelike-beperkings waaraan ander toepaslike entiteite moet voldoen.<sup>[[1]](#references)[[4]](#references)</sup>

Die meganisme is vanaf macOS Sonoma ook van toepassing op derdeparty-toepassings deur middel van **Environment Constraints**, sodat ontwikkelaars hul toepassings kan beskerm deur ’n **stel sleutels en waardes vir omgewingsbeperkings** te spesifiseer.<sup>[[5]](#references)</sup>

Jy definieer **launch-omgewings- en biblioteekbeperkings** in beperkingswoordeboeke wat jy óf in **`launchd`-property list-lêers** stoor, óf in **afsonderlike property list**-lêers wat jy in kodeondertekening gebruik.<sup>[[5]](#references)</sup>

Daar is 4 soorte beperkings:

- **Selfbeperkings**: Beperkings wat op die **lopende** binêr toegepas word.
- **Ouerproses**: Beperkings wat op die **ouer van die proses** toegepas word (byvoorbeeld **`launchd`** wat ’n XP-diens laat loop)
- **Verantwoordelike-beperkings**: Beperkings wat op die **proses wat die diens aanroep** in ’n XPC-kommunikasie toegepas word
- **Biblioteeklaaibeperkings**: Gebruik biblioteeklaaibeperkings om selektief die kode te beskryf wat gelaai kan word

Wanneer ’n proses dus probeer om ’n ander proses te begin — deur `execve(_:_:_:)` of `posix_spawn(_:_:_:_:_:_:)` aan te roep — kontroleer die bedryfstelsel of die **uitvoerbare** lêer aan sy **eie selfbeperking** **voldoen**. Dit kontroleer ook of die **ouerproses** se uitvoerbare lêer aan die uitvoerbare lêer se **ouerbeperking** voldoen, en of die **verantwoordelike proses** se uitvoerbare lêer aan die uitvoerbare lêer se **verantwoordelike-prosesbeperking** voldoen. As enige van hierdie launch-beperkings nie nagekom word nie, laat die bedryfstelsel die program nie loop nie.

As enige deel van die **biblioteekbeperking** nie waar is wanneer ’n biblioteek gelaai word nie, **laai** jou proses nie die biblioteek **nie**.

## LC-kategorieë

’n LC bestaan uit **feite** en **logiese bewerkings** (en, of...) wat feite kombineer.

Die[ **feite wat ’n LC kan gebruik, is gedokumenteer**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Byvoorbeeld:

- is-init-proc: ’n Boole-waarde wat aandui of die uitvoerbare lêer die bedryfstelsel se inisialiseringsproses (`launchd`) moet wees.
- is-sip-protected: ’n Boole-waarde wat aandui of die uitvoerbare lêer ’n lêer moet wees wat deur System Integrity Protection (SIP) beskerm word.
- `on-authorized-authapfs-volume:` ’n Boole-waarde wat aandui of die bedryfstelsel die uitvoerbare lêer vanaf ’n gemagtigde, geverifieerde APFS-volume gelaai het.
- `on-authorized-authapfs-volume`: ’n Boole-waarde wat aandui of die bedryfstelsel die uitvoerbare lêer vanaf ’n gemagtigde, geverifieerde APFS-volume gelaai het.
  - Cryptexes-volume
- `on-system-volume:`’n Boole-waarde wat aandui of die bedryfstelsel die uitvoerbare lêer vanaf die tans-gebootte stelselvolume gelaai het.
  - Binne /System...
- ...

Wanneer ’n Apple-binêr onderteken word, **wys die ondertekening dit aan ’n LC-kategorie toe** binne die **trust cache**.

- **LC-kategorieë in iOS 16** is [**omgekeerd ontleed en hier gedokumenteer**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Huidige **LC-kategorieë (macOS 14** - Somona) is omgekeerd ontleed, en hul [**beskrywings is hier beskikbaar**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Byvoorbeeld, Kategorie 1 is:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: Moet op die System- of Cryptexes-volume wees.
- `launch-type == 1`: Moet ’n stelseldiens wees (plist in LaunchDaemons).
- `validation-category == 1`: ’n Uitvoerbare lêer van die bedryfstelsel.
- `is-init-proc`: Launchd

### LC-kategorieë reverse-engineer

Jy kan [**hier meer inligting hieroor kry**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), maar basies word hulle in **AMFI (AppleMobileFileIntegrity)** gedefinieer. Jy moet dus die Kernel Development Kit aflaai om die **KEXT** te kry. Die simbole wat met **`kConstraintCategory`** begin, is die **interessante** ones. Wanneer jy dit onttrek, kry jy ’n DER (ASN.1)-gekodeerde stroom wat jy sal moet dekodeer met [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) of die python-asn1-biblioteek en sy `dump.py`-skrip, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), wat vir jou ’n verstaanbaarder string sal gee.<sup>[[3]](#references)[[8]](#references)</sup>

## Omgewingsbeperkings

Dit is die Launch Constraints wat in **derdepartytoepassings** opgestel is. Die ontwikkelaar kan die **feite** en **logiese operande om te gebruik** in sy toepassing kies om toegang daartoe te beperk.

Dit is moontlik om die Environment Constraints van ’n toepassing op te som met:

```bash
codesign -d -vvvv app.app
```

## Trust Caches

In **macOS** is daar ’n paar trust caches:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

En in iOS lyk dit of dit in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** is.

> [!WARNING]
> Op macOS wat op Apple Silicon-toestelle loop, sal AMFI weier om ’n Apple-ondertekende binary te laai as dit nie in die trust cache is nie.

### Trust Caches enumerering

Die vorige trust-cache-lêers is in die formate **IMG4** en **IM4P**, waar IM4P die payload-gedeelte van ’n IMG4-formaat is.

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

(’n Ander opsie is om die hulpmiddel [**img4tool**](https://github.com/tihmstar/img4tool) te gebruik. Dit sal selfs op M1 werk, al is die weergawe oud en vir x86_64, mits jy dit op die regte plekke installeer.)

Nou kan jy die hulpmiddel [**trustcache**](https://github.com/CRKatri/trustcache) gebruik om die inligting in ’n leesbare formaat te kry:

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

Die trust cache volg die volgende struktuur, dus is die **LC category die 4de kolom**.

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

Uit daardie data kan jy die apps nagaan met ’n **launch constraints-waarde van `0`**; dit is dié wat nie beperk word nie (kyk [**hier**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) vir die betekenis van elke waarde).<sup>[[6]](#references)</sup>

## Aanvalversagtings

Launch Constraints sou verskeie ou aanvalle versag het deur **seker te maak dat die proses nie onder onverwagte omstandighede uitgevoer word nie:** byvoorbeeld vanaf onverwagte liggings of deur ’n onverwagte ouerproses (as slegs launchd dit behoort te begin).

Daarbenewens **versag Launch Constraints ook downgrade attacks.**

Dit **versag egter nie algemene XPC**-misbruik, **Electron**-kode-inspuitings of **dylib-inspuitings** sonder library validation nie (tensy die team IDs wat libraries mag laai, bekend is).<sup>[[3]](#references)</sup>

### XPC Daemon-beskerming

In die Sonoma-vrystelling is ’n noemenswaardige punt die XPC-diens se **verantwoordelikheidskonfigurasie**. Die XPC-diens is vir homself verantwoordelik, eerder as dat die kliënt wat daaraan koppel verantwoordelik is. Dit word in die terugvoerverslag FB13206884 gedokumenteer. Hierdie opstelling kan gebrekkig lyk, aangesien dit sekere interaksies met die XPC-diens moontlik maak:

- **Die XPC-diens begin**: As dit as ’n fout beskou word, laat hierdie opstelling nie toe dat die XPC-diens deur aanvallerkode begin word nie.
- **Koppel aan ’n aktiewe diens**: As die XPC-diens reeds loop (moontlik omdat die oorspronklike toepassing dit geaktiveer het), is daar geen hindernisse om daaraan te koppel nie.

Hoewel die toepassing van constraints op die XPC-diens nuttig kan wees deur **die venster vir moontlike aanvalle te verklein**, spreek dit nie die kernprobleem aan nie. Om die XPC-diens se sekuriteit te verseker, moet die **koppelende kliënt doeltreffend gevalideer word**. Dit bly die enigste manier om die diens se sekuriteit te versterk. Let ook daarop dat die genoemde verantwoordelikheidskonfigurasie tans in werking is, wat dalk nie met die beoogde ontwerp ooreenstem nie.<sup>[[3]](#references)</sup>

### Electron-beskerming

Selfs al word vereis dat die toepassing deur **LaunchService oopgemaak moet word** (in die ouer se constraints), kan dit met **`open`** (wat env-variables kan stel) of die **Launch Services API** (waar env-variables aangedui kan word) bereik word.<sup>[[3]](#references)</sup>

Vir die algemene MACF-meganisme agter beleidspesifieke spawn-attributes, sien [MACF policy-specific spawn attributes](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).

### CVE-2025-43253 - Oorskryf van die ingeboude constraints tydens spawn

Launch constraints (amptelik **lightweight code requirements**, *LWCR*) word deur die **AMFI MAC-beleid** afgedwing. `posix_spawn` laat ’n oproeper toe om ’n arbitrêre blob via **`posix_spawnattr_setmacpolicyinfo_np()`** aan ’n MAC-beleid deur te gee, en AMFI het ’n deur die oproeper verskafde LWCR-dictionary via dié roete aanvaar. Die fout was dat die **aanvaller-verskafde constraints die binêre lêer se ingeboude constraints vervang het**, eerder as om bykomend daaraan nagegaan te word:

- Bou ’n minimale (selfs leë) launch-constraints-dictionary.
- Stel die **constraint-kategorie op `127`**, ’n waarde wat AMFI in spawn-attributes toelaat, maar **nie afdwing nie** — dit teken slegs `Launch Constraint Violation (not enforcing)` aan, eerder as om die uitvoering te blokkeer.
- Gee dit via die spawn-attributes deur, en die proses begin in ’n konteks wat sy werklike self-/ouer-constraints sou verbied het.

Ná die regstelling word **beide** die ingeboude en die verskafde constraints gevalideer, sodat die verskafde dictionary nie meer die ingeboude een kan verswak nie.<sup>[[2]](#references)</sup>

> [!TIP]
> Dit is die algemene patroon waarna jy moet soek wanneer jy constraint-afdwinging oudit: ’n API wat onbetroubare invoer toelaat om ’n beleid te *verskaf*, is dikwels interessant wanneer die beleid-enjin die verskafde waarde as ’n plaasvervanger behandel, eerder as as ’n bykomende vereiste.



## References

- [1] [Objective by the Sea #OBTS v6.0 Dag 2 (Regstreekse stroom)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Omseiling van Launch Constraints op macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [In-diepte ondersoek van Launch- en Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Waarom wil ’n stelsel-app of opdraghulpmiddel nie loop nie? Launch constraints en trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Beskerm jou Mac-app met environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Beskrywing van die Launch Constraints wat in iOS 16 bekendgestel is (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Verder as die goeie ou LaunchAgents - lees hieroor](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
