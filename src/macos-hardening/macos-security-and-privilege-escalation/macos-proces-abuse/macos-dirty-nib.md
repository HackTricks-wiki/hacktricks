# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi kuhusu mbinu hii angalia chapisho la asili kutoka:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) na chapisho linalofuata na [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Hapa kuna muhtasari:

### Nini Nib files

Nib (fupi kwa NeXT Interface Builder) files, sehemu ya mfumo wa maendeleo wa Apple, zinakusudia kufafanua **vipengele vya UI** na mwingiliano wao katika programu. Zinajumuisha vitu vilivyopangwa kama vile madirisha na vifungo, na hupakuliwa wakati wa wakati wa utekelezaji. Licha ya matumizi yao yaendelea, Apple sasa inashauri Storyboards kwa ajili ya uonyeshaji wa mtiririko wa UI wa kina zaidi.

Faili kuu ya Nib inarejelea katika thamani **`NSMainNibFile`** ndani ya faili ya `Info.plist` ya programu na inapakuliwa na kazi **`NSApplicationMain`** inayotekelezwa katika kazi ya `main` ya programu.

### Mchakato wa Uingizaji wa Dirty Nib

#### Kuunda na Kuweka Faili ya NIB

1. **Mipangilio ya Awali**:
- Unda faili mpya ya NIB kwa kutumia XCode.
- Ongeza Kitu kwenye interface, ukipanga darasa lake kuwa `NSAppleScript`.
- Sanidi mali ya awali ya `source` kupitia Sifa za Wakati wa Uendeshaji Zilizofanywa na Mtumiaji.
2. **Gadget ya Utekelezaji wa Kanuni**:
- Mipangilio inarahisisha kuendesha AppleScript kwa mahitaji.
- Jumuisha kifungo ili kuamsha kitu cha `Apple Script`, hasa kuanzisha mteule wa `executeAndReturnError:`.
3. **Kujaribu**:

- Apple Script rahisi kwa ajili ya majaribio:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```

- Jaribu kwa kuendesha katika debugger ya XCode na kubofya kifungo.

#### Kulenga Programu (Mfano: Pages)

1. **Maandalizi**:
- Nakili programu lengwa (mfano, Pages) kwenye directory tofauti (mfano, `/tmp/`).
- Anzisha programu ili kuepuka matatizo ya Gatekeeper na kuikadiria.
2. **Kufuta Faili ya NIB**:
- Badilisha faili ya NIB iliyopo (mfano, About Panel NIB) na faili ya DirtyNIB iliyoundwa.
3. **Utekelezaji**:
- Amsha utekelezaji kwa kuingiliana na programu (mfano, kuchagua kipengee cha menyu `About`).

#### Ushahidi wa Dhihirisho: Kupata Takwimu za Mtumiaji

- Badilisha AppleScript ili kufikia na kutoa takwimu za mtumiaji, kama picha, bila idhini ya mtumiaji.

### Mfano wa Kanuni: Faili ya .xib Mbaya

- Fikia na kagua [**mfano wa faili mbaya ya .xib**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) inayodhihirisha kuendesha kanuni zisizo na mipaka.

### Mfano Mwingine

Katika chapisho [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) unaweza kupata mafunzo juu ya jinsi ya kuunda nib mbaya.&#x20;

### Kushughulikia Vikwazo vya Uzinduzi

- Vikwazo vya Uzinduzi vinakwamisha utekelezaji wa programu kutoka maeneo yasiyotarajiwa (mfano, `/tmp`).
- Inawezekana kubaini programu ambazo hazijalindwa na Vikwazo vya Uzinduzi na kuzilenga kwa ajili ya uingizaji wa faili ya NIB.

### Ulinzi Mwingine wa macOS

Kuanzia macOS Sonoma kuendelea, mabadiliko ndani ya vifurushi vya Programu yamezuiliwa. Hata hivyo, mbinu za awali zilihusisha:

1. Nakala ya programu kwenye eneo tofauti (mfano, `/tmp/`).
2. Kubadilisha majina ya directories ndani ya kifurushi cha programu ili kupita ulinzi wa awali.
3. Baada ya kuendesha programu ili kujiandikisha na Gatekeeper, kubadilisha kifurushi cha programu (mfano, kubadilisha MainMenu.nib na Dirty.nib).
4. Kubadilisha majina ya directories nyuma na kuendesha tena programu ili kutekeleza faili ya NIB iliyowekwa.

**Kumbuka**: Sasisho za hivi karibuni za macOS zimepunguza exploit hii kwa kuzuia mabadiliko ya faili ndani ya vifurushi vya programu baada ya caching ya Gatekeeper, na kufanya exploit hiyo isifanye kazi.

{{#include ../../../banners/hacktricks-training.md}}
