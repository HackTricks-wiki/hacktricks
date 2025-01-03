# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Lanceringsbeperkings in macOS is ingestel om sekuriteit te verbeter deur **te reguleer hoe, wie, en van waar 'n proses geinitieer kan word**. Geïnisieer in macOS Ventura, bied dit 'n raamwerk wat **elke stelselbinarie in verskillende beperkingkategorieë kategoriseer**, wat gedefinieer is binne die **vertrou cache**, 'n lys wat stelselbinaries en hul onderskeie hashes bevat​. Hierdie beperkings strek uit na elke uitvoerbare binarie binne die stelsel, wat 'n stel **reëls** insluit wat die vereistes vir **die lancering van 'n spesifieke binarie** uiteensit. Die reëls sluit selfbeperkings in wat 'n binarie moet nakom, ouerbeperkings wat deur sy ouerproses nagekom moet word, en verantwoordelike beperkings wat deur ander relevante entiteite nagekom moet word​.

Die meganisme strek uit na derdeparty-apps deur middel van **Omgewingbeperkings**, wat begin vanaf macOS Sonoma, wat ontwikkelaars toelaat om hul apps te beskerm deur 'n **stel sleutels en waardes vir omgewingbeperkings te spesifiseer.**

Jy definieer **lanceringsomgewing en biblioteekbeperkings** in beperkingwoordeboeke wat jy of in **`launchd` eiendomslys lêers** stoor, of in **afsonderlike eiendomslys** lêers wat jy in kodeondertekening gebruik.

Daar is 4 tipes beperkings:

- **Selfbeperkings**: Beperkings wat toegepas word op die **lopende** binarie.
- **Ouerproses**: Beperkings wat toegepas word op die **ouer van die proses** (byvoorbeeld **`launchd`** wat 'n XP-diens uitvoer)
- **Verantwoordelike Beperkings**: Beperkings wat toegepas word op die **proses wat die diens aanroep** in 'n XPC-kommunikasie
- **Biblioteeklaai-beperkings**: Gebruik biblioteeklaai-beperkings om selektief kode te beskryf wat gelaai kan word

So wanneer 'n proses probeer om 'n ander proses te lanseer — deur `execve(_:_:_:)` of `posix_spawn(_:_:_:_:_:_:)` aan te roep — kontroleer die bedryfstelsel dat die **uitvoerbare** lêer **voldoen** aan sy **eie selfbeperking**. Dit kontroleer ook dat die **ouer** **proses se** uitvoerbare **voldoen** aan die uitvoerbare se **ouerbeperking**, en dat die **verantwoordelike** **proses se** uitvoerbare **voldoen aan die uitvoerbare se verantwoordelike prosesbeperking**. As enige van hierdie lanceringsbeperkings nie nagekom word nie, sal die bedryfstelsel die program nie uitvoer nie.

As enige deel van die **biblioteekbeperking nie waar is** wanneer 'n biblioteek gelaai word, **laai jou proses nie** die biblioteek nie.

## LC Categories

'n LC bestaan uit **feite** en **logiese operasies** (en, of..) wat feite kombineer.

Die[ **feite wat 'n LC kan gebruik is gedokumenteer**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Byvoorbeeld:

- is-init-proc: 'n Booleaanse waarde wat aandui of die uitvoerbare die bedryfstelsel se inisialisasieproses (`launchd`) moet wees.
- is-sip-beskerm: 'n Booleaanse waarde wat aandui of die uitvoerbare 'n lêer moet wees wat deur Stelselintegriteitsbeskerming (SIP) beskerm word.
- `on-authorized-authapfs-volume:` 'n Booleaanse waarde wat aandui of die bedryfstelsel die uitvoerbare van 'n geverifieerde, geauthentiseerde APFS-volume gelaai het.
- `on-authorized-authapfs-volume`: 'n Booleaanse waarde wat aandui of die bedryfstelsel die uitvoerbare van 'n geverifieerde, geauthentiseerde APFS-volume gelaai het.
- Cryptexes volume
- `on-system-volume:` 'n Booleaanse waarde wat aandui of die bedryfstelsel die uitvoerbare van die tans-gestarte stelselmengsel gelaai het.
- Binne /System...
- ...

Wanneer 'n Apple binarie onderteken word, **ken dit dit aan 'n LC-kategorie** binne die **vertrou cache** toe.

- **iOS 16 LC-kategorieë** is [**omgekeer en hier gedokumenteer**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
- Huidige **LC-kategorieë (macOS 14** - Somona) is omgekeer en hul [**beskrywings kan hier gevind word**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Byvoorbeeld, Kategori 1 is:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Moet in die Stelsel of Cryptexes volume wees.
- `launch-type == 1`: Moet 'n stelseldiens wees (plist in LaunchDaemons).
- `validation-category == 1`: 'n Bedryfstelsel uitvoerbare.
- `is-init-proc`: Launchd

### Omgekeerde LC Kategoriewe

Jy het meer inligting [**hieroor**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), maar basies, hulle is gedefinieer in **AMFI (AppleMobileFileIntegrity)**, so jy moet die Kernel Ontwikkelingskit aflaai om die **KEXT** te kry. Die simbole wat met **`kConstraintCategory`** begin, is die **interessante**. Deur hulle uit te trek, sal jy 'n DER (ASN.1) geënkodeerde stroom kry wat jy moet dekodeer met [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) of die python-asn1 biblioteek en sy `dump.py` skrip, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) wat jou 'n meer verstaanbare string sal gee.

## Omgewing Beperkings

Dit is die Launch Beperkings wat in **derdeparty toepassings** ingestel is. Die ontwikkelaar kan die **feite** en **logiese operateurs om te gebruik** in sy toepassing kies om die toegang tot homself te beperk.

Dit is moontlik om die Omgewing Beperkings van 'n toepassing te enumereer met:
```bash
codesign -d -vvvv app.app
```
## Vertroue Kaste

In **macOS** is daar 'n paar vertroue kaste:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

En in iOS lyk dit of dit in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** is.

> [!WARNING]
> Op macOS wat op Apple Silicon toestelle loop, sal AMFI weier om 'n Apple-onderteken binêre te laai as dit nie in die vertroue kas is nie.

### Opnoem van Vertroue Kaste

Die vorige vertroue kas lêers is in die formaat **IMG4** en **IM4P**, met IM4P die payload gedeelte van 'n IMG4 formaat.

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
(‘n Ander opsie kan wees om die hulpmiddel [**img4tool**](https://github.com/tihmstar/img4tool) te gebruik, wat selfs op M1 sal loop, selfs al is die weergawe oud, en vir x86_64 as jy dit in die regte plekke installeer).

Nou kan jy die hulpmiddel [**trustcache**](https://github.com/CRKatri/trustcache) gebruik om die inligting in 'n leesbare formaat te kry:
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
Die vertrou cache volg die volgende struktuur, so Die **LC kategorie is die 4de kolom**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Dan kan jy 'n skrip soos [**hierdie een**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) gebruik om data te onttrek.

Van daardie data kan jy die Apps met 'n **launch constraints waarde van `0`** nagaan, wat diegene is wat nie beperk is nie ([**kyk hier**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) vir wat elke waarde is).

## Aanval Mitigasies

Launch Constrains sou verskeie ou aanvalle gemitigeer het deur **te verseker dat die proses nie in onverwagte toestande uitgevoer sal word nie:** Byvoorbeeld van onverwagte plekke of deur 'n onverwagte ouer proses aangeroep word (as slegs launchd dit moet begin).

Boonop **mitigeer Launch Constraints ook afgraderingsaanvalle.**

Egter, hulle **mitigeer nie algemene XPC** misbruik nie, **Electron** kode-inspuitings of **dylib inspuitings** sonder biblioteekvalidasie (tenzij die span-ID's wat biblioteke kan laai bekend is).

### XPC Daemon Beskerming

In die Sonoma vrystelling is 'n noemenswaardige punt die daemon XPC diens se **verantwoordelikheid konfigurasie**. Die XPC diens is verantwoordelik vir homself, in teenstelling met die verbindende kliënt wat verantwoordelik is. Dit is gedokumenteer in die terugvoer verslag FB13206884. Hierdie opstelling mag gebrekkig lyk, aangesien dit sekere interaksies met die XPC diens toelaat:

- **Die XPC Diens Begin**: As dit as 'n fout beskou word, laat hierdie opstelling nie toe om die XPC diens deur aanvaller kode te begin nie.
- **Verbinding met 'n Aktiewe Diens**: As die XPC diens reeds loop (miskien geaktiveer deur sy oorspronklike toepassing), is daar geen hindernisse om met dit te verbind nie.

Terwyl die implementering van beperkings op die XPC diens voordelig mag wees deur **die venster vir potensiële aanvalle te vernou**, adres dit nie die primêre bekommernis nie. Om die sekuriteit van die XPC diens te verseker, vereis fundamenteel **om die verbindende kliënt effektief te valideer**. Dit bly die enigste metode om die diens se sekuriteit te versterk. Dit is ook die moeite werd om op te let dat die genoemde verantwoordelikheid konfigurasie tans operasioneel is, wat dalk nie ooreenstem met die beoogde ontwerp nie.

### Electron Beskerming

Selfs al is dit vereis dat die toepassing **deur LaunchService** geopen moet word (in die ouer beperkings). Dit kan bereik word deur **`open`** (wat omgewingsveranderlikes kan stel) of deur die **Launch Services API** (waar omgewingsveranderlikes aangedui kan word).

## Verwysings

- [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [https://theevilbit.github.io/posts/launch_constraints_deep_dive/](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

{{#include ../../../banners/hacktricks-training.md}}
