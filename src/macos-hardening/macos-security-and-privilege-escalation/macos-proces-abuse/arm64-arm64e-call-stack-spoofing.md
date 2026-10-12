# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Kwa nini unwinding inayoongozwa na metadata inaweza kughushiwa

Baadhi ya zana za usalama za macOS hukabidhi ukusanyaji wa stack za thread kwa `/usr/sbin/spindump` au huamini unwinder ya kawaida inayoongozwa na metadata. Implant inaweza kutumia vibaya mpaka huo wa uaminifu kwa kuweka kwenye stack yake rekodi sintetiki zinazofuata ABI, ili ionekane kuwa API nyeti imefikiwa kupitia functions zilizochaguliwa na mshambuliaji ndani ya dyld na frameworks za Apple zilizopakiwa, badala ya kufikiwa kutoka kwa code ya implant isiyoungwa mkono na faili. Huu ni udanganyifu wa telemetry, si mabadiliko ya executable au metadata yake ya unwind.<sup>[[1]](#references)</sup>

Angalia [macOS stackshots and `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) kwa muktadha wa upande wa ukusanyaji.

Unwinder haithibitishi kuwa prologue iliyotengenezwa na compiler ndiyo iliyounda rekodi. Hutumia `PC` ya sasa mara kwa mara kuchagua recipe ya Mach-O, hutumia recipe hiyo kwa `SP`, `x29`, `x30`, kumbukumbu ya stack na register zozote zisizo tete zilizotajwa, kisha hutumia `PC` ya caller iliyopatikana kuchagua recipe inayofuata. Ikiwa kumbukumbu inayodhibitiwa na mshambuliaji inakidhi kila recipe iliyochaguliwa, chain inayotokana nayo inaweza kuwa halali kimuundo na kutambuliwa kwa majina ya symbols, ingawa calls hizo hazikuwahi kutokea.<sup>[[1]](#references)</sup>

## Hali ya ARM64 frame

Muhtasari wa [ARM64 assembly](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) unaeleza majukumu ya register na calling convention. Kwa frame ya kawaida iliyoundwa kwa `stp x29, x30, [sp, #-16]!` ikifuatiwa na `mov x29, sp`, Canonical Frame Address (CFA), inayowakilisha `SP` ya caller wakati wa kuingia, ni `FP+0x10`:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Rekodi za frame huunda linked list kupitia `[FP]`, lakini kufuata listi hiyo bila kuchagua hakutoshi: leaf functions zinaweza kutokuwa na frame, tail calls zinaweza kuondoa mabadiliko ya kimantiki, na miundo isiyo ya kawaida hutumia DWARF CFI. Recipe inayochaguliwa na anwani ya sasa ndiyo huamua ikiwa unwinder itasoma mnyororo wa FP.<sup>[[1]](#references)[[4]](#references)</sup>

## Kuchagua recipe ya unwind ya Mach-O

Picha zilizounganishwa kikamilifu huhifadhi data ya compact unwind katika `__TEXT,__unwind_info`. Kichwa cha section huelekeza kwenye function index ya kiwango cha kwanza; kila masafa ya index huelekeza kwenye ukurasa wa kiwango cha pili wa kawaida (`kind=2`) au uliobanwa (`kind=3`). Miundo ambayo compact unwind haiwezi kueleza hutumia FDE na maagizo ya call-frame katika `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

Kwa kila PC inayoweza kutumika wakati wa runtime:<sup>[[1]](#references)[[2]](#references)</sup>

1. Ondoa au rekebisha biti za PAC za ARM64e kwa ajili ya utafutaji pekee.
2. Tafuta Mach-O iliyopakiwa ambayo masafa yake ya executable `__TEXT` yana anwani hiyo.
3. Kokotoa `functionOffset = normalizedPC - loadedImageBase` na ukatae matokeo hasi au thamani zilizo juu ya `UINT32_MAX`.
4. Chagua masafa ya kiwango cha kwanza yanayotimiza `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`.
5. Chambua ukurasa wa kiwango cha pili unaorejelewa, chagua ingizo lililo karibu zaidi ambalo mwanzo wake hauzidi offset, kisha hakikisha anwani iko kabla ya ingizo linalofuata au mwisho wa masafa ya kiwango cha kwanza.
6. Decodi ingizo hilo na uunde hali halisi inayoelezwa nalo.

Anwani imetokana na LR iliyohifadhiwa, utafutaji unaweza kutumia `PC-1` ili anwani iliyo mara moja baada ya call ibaki ndani ya masafa yanayofunikwa na caller. Hii hubadilisha uteuzi wa recipe, wala si offset yoyote ya stack.<sup>[[1]](#references)</sup>

Parser lazima ikague mipaka ya kila header na array, ihitaji section version `1`, izingatie sentinel ya mwisho ya kiwango cha kwanza, ikatae offset ya ukurasa wa kiwango cha pili iliyo sifuri, na itofautishe kurasa za kawaida na zilizobanwa. Katika ukurasa wa kawaida, `entryPageOffset` huhesabiwa kuanzia mwanzo wa ukurasa huo, ilhali offset ya ukurasa wa kiwango cha kwanza huhesabiwa kuanzia mwanzo wa `__unwind_info`.<sup>[[1]](#references)[[2]](#references)</sup>

Mode ya jumla ni `encoding & 0x0F000000`. Ufafanuzi wa sasa wa LLVM unajumuisha mode zifuatazo; parser haipaswi kuchukulia kila thamani isiyo ya DWARF kuwa frame ya kawaida:<sup>[[1]](#references)[[2]](#references)</sup>

| Mode | Value | Urejeshaji wa caller |
| --- | --- | --- |
| Hakuna compact recipe | `0x00000000` | Simama au tumia njia mbadala huru. |
| Frameless | `0x02000000` | Ongeza ukubwa wa stack uliosimbwa kwa `SP` ya sasa; PC ya caller ni LR iliyo hai. |
| DWARF | `0x03000000` | Tekeleza FDE/CFI iliyotambuliwa na biti 24 za chini. |
| Frame | `0x04000000` | Soma rekodi ya kawaida ya frame ya `x29`. |
| Frame ya arm64e yenye masafa ya LR yaliyothibitishwa | `0x05000000` | Shughulikia `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`; uga wake wa offset huonyesha mahali `pacibsppc` ilipo ndani ya masafa yanayofunikwa. |

Kwa mode ya frameless, `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. Kwa mode ya frame, biti tano za chini hutangaza jozi mfululizo za GPR zilizohifadhiwa, kuanzia `x19/x20` hadi `x27/x28`; biti za `0x100-0x800` hutangaza vivyo hivyo jozi za `d8-d15`. Huenda register hizi zilizohifadhiwa zisihitajike kupata PC inayofuata, lakini hali ya caller pepe inayoaminika lazima itimize kila uga ambao consumer hujenga upya.<sup>[[1]](#references)[[2]](#references)</sup>

## Kuunda rekodi za synthetic za frame-mode

Mchakato wa uundaji hubadili mwelekeo wa unwinder badala ya kutafuta thamani zinazofanana na anwani kwenye stack:<sup>[[1]](#references)</sup>

1. Chagua PC halisi ya executable katika image iliyopakiwa kwa sasa.
2. Decodi recipe inayofunika PC hiyo mahususi au anwani ya call-site.
3. Tenga rekodi ya synthetic yenye alignment na uhusiano wa CFA unaohitajika.
4. Hifadhi FP inayofuata ya synthetic kwenye `[FP]`, PC ya caller iliyohifadhiwa ya frame hiyo kwenye `[FP+8]`, na kila hifadhi ya GPR/FPR iliyotangazwa na encoding, chini ya FP.
5. Unganisha rekodi kadhaa na uweke rekodi ya kwanza kwenye `x29` iliyo hai.
6. Panga LR iliyo hai na njia ya kurudi ya API ili unwinding iingie kwenye mnyororo uliochaguliwa huku execution ikiweza kurejeshwa kwa usalama.

Kwa mfano, `0x04000001` humaanisha mode ya frame pamoja na jozi ya `x19/x20`. Mabadiliko ya hali yanayolingana na kumbukumbu inayohitajika ni:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

Kwa hiyo, anwani inayoonekana kuwa halali haitoshi. Kila PC iliyopatikana huwa ufunguo wa lookup inayofuata, kwa hivyo anwani moja ambayo encoding yake haiendani na layout iliyobuniwa huvunja mnyororo au kusababisha consumer kujenga upya hali ya register isiyolingana.<sup>[[1]](#references)</sup>

## Mahitaji ya ARM64e PAC

PAC huhifadhi thamani ya uadilifu yenye ufunguo katika biti za pointer ambazo vinginevyo hazitumiki; haisimbaji anwani kwa njia fiche. Schema ya Clang ya arm64e ya return-address hutumia ufunguo wa instruction B na stack pointer wakati wa kuingia kwenye function kama discriminator. Kwa frame ya kawaida, `SP` hiyo ya kuingia ndiyo CFA, kwa hivyo LR iliyohifadhiwa kwenye `[FP+8]` hufungamanishwa na `FP+0x10`.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Kila LR bandia lazima isainiwe kivyake kwa sababu kuhamisha LR ambayo tayari imesainiwa hadi kwenye frame yenye CFA tofauti hubadilisha discriminator na kufanya uthibitishaji ushindwe. `ptrauth_strip()` inafaa kwa urekebishaji wa anwani na utafutaji wa alama, lakini **haithibitishi uhalisi**; return halisi au tawi lisilo la moja kwa moja lililothibitishwa lazima litumie key na modifier zinazotarajiwa kwenye mpito huo mahususi.<sup>[[1]](#references)[[3]](#references)</sup>

Kazi ya kawaida ya arm64e isiyo ya leaf husaini LR kabla ya kuihifadhi na huithibitisha baada ya kurejesha SP ya kuingia:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline na restore bridge

Rekodi sintetiki zinahitaji tu kukidhi mahitaji ya unwinder; hazina muktadha kamili wa utekelezaji. Kurudi kutoka kwenye API nyeti moja kwa moja kwa callers waliobuniwa kwa kawaida kungeisababisha programu ku-crash. Kwa hiyo, muundo wa vitendo huweka gadget frame mara moja chini ya API: API hurudi kwenye msimbo unaoweza kutekelezwa katika framework iliyopakiwa, na gadget hiyo huruka kupitia callee-saved register inayodhibitiwa hadi kwenye restore bridge iliyo kwenye implant.<sup>[[1]](#references)</sup>

Gadget inayofaa huhifadhi LR na kuhamisha udhibiti kupitia register inayodhibitiwa, kwa mfano mfuatano unaofaa wa `br`, `braa` au `brab`. Restore bridge lazima irejeshe thamani za awali za `x19-x30` na `SP` kabla ya kuendelea na utekelezaji wa implant. Kwenye arm64e, kila return au branch iliyothibitishwa katika njia ya API-to-gadget, gadget-to-bridge na bridge-to-implant inahitaji pointer iliyosainiwa kwa kutumia key na discriminator zinazotumiwa na instruction hiyo.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

Matokeo haya ni kushindwa muhimu kwa mpaka wa uaminifu katika detections zinazotegemea stack: chain inaweza kuwa na PCs za Apple framework zilizomappiwa na zinazoweza kuhusishwa na symbols pekee, lakini bado isiakisi mtiririko halisi wa udhibiti. Kwa hivyo, output ya unwind inapaswa kuthibitishwa kwa ushahidi huru kuhusu asili ya memory inayoweza kutekelezwa ya thread na mabadiliko halisi yanayozunguka API nyeti, badala ya kuchukuliwa kama execution trace.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Misingi ya ARM64 stack na obfuscation kwenye Apple Silicon](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Ufafanuzi wa usimbaji wa compact unwind wa Mach-O](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Pointer Authentication](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Kiwango cha Procedure Call cha usanifu wa Arm wa biti 64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
