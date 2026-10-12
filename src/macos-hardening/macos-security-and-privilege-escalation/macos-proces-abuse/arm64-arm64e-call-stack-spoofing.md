# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Waarom metadata-gedrewe stack-unwinding vervals kan word

Sommige macOS-sekuriteitsnutsmiddels delegeer die versameling van thread-stacks aan `/usr/sbin/spindump` of vertrou andersins op ’n konvensionele metadata-gedrewe unwinder. ’n Implantaat kan hierdie vertrouensgrens uitbuit deur ABI-korrekte sintetiese rekords op sy stack te plaas, sodat dit lyk asof ’n sensitiewe API bereik is via funksies in dyld en gelaaide Apple-frameworks wat deur die aanvaller gekies is, eerder as vanuit kode van ’n implantaat wat nie deur ’n lêer gerugsteun word nie. Dit is telemetriebedrog, nie ’n verandering aan die uitvoerbare lêer of sy unwind-metadata nie.<sup>[[1]](#references)</sup>

Sien [macOS stackshots and `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) vir die konteks aan die versamelingskant.

’n Unwinder bewys nie dat ’n samesteller-gegenereerde proloog ’n rekord geskep het nie. Dit gebruik herhaaldelik die huidige `PC` om ’n Mach-O-resep te kies, pas daardie resep toe op `SP`, `x29`, `x30`, stack-geheue en enige verklaarde nie-vlugtige registers, en gebruik die herstelde oproeper-`PC` om die volgende resep te kies. As geheue wat deur die aanvaller beheer word aan elke gekose resep voldoen, kan die gevolglike ketting struktureel geldig en simboliseerbaar wees, al het daardie oproepe nooit plaasgevind nie.<sup>[[1]](#references)</sup>

## ARM64-raamtoestand

Die [ARM64 assembly overview](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) dek die registerrolle en oproepkonvensie. Vir ’n konvensionele raam wat met `stp x29, x30, [sp, #-16]!` geskep word, gevolg deur `mov x29, sp`, is die Canonical Frame Address (CFA), wat die oproeper se `SP` by ingang voorstel, `FP+0x10`:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Raamrekords vorm ’n gekoppelde lys deur `[FP]`, maar om daardie lys blindelings te volg, is onvoldoende: leaf-funksies kan raamloos wees, tail calls kan logiese oorgange verwyder, en ongewone uitlegte gebruik DWARF CFI. Die resep wat deur die huidige adres gekies word, bepaal of die unwinder enigsins die FP-ketting lees.<sup>[[1]](#references)[[4]](#references)</sup>

## Kies ’n Mach-O-unwind-resep

Finale gekoppelde images stoor kompakte unwind-data in `__TEXT,__unwind_info`. Die seksie-opskrif wys na ’n eersterangse funksie-indeks; elke indeksreeks wys na ’n tweederangse bladsy, hetsy gewone (`kind=2`) of saamgeperste (`kind=3`). Uitlegte wat nie deur compact unwind beskryf kan word nie, gebruik ’n FDE en call-frame-instruksies in `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

Vir elke kandidaat-runtime-PC:<sup>[[1]](#references)[[2]](#references)</sup>

1. Verwyder of normaliseer ARM64e-PAC-bisse slegs vir opsoek.
2. Vind die gelaaide Mach-O waarvan die uitvoerbare `__TEXT`-reeks die adres bevat.
3. Bereken `functionOffset = normalizedPC - loadedImageBase` en verwerp negatiewe resultate of waardes bo `UINT32_MAX`.
4. Kies die eersterangse reeks waarvoor `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`.
5. Ontleed die verwysde tweederangse bladsy, kies die naaste inskrywing waarvan die begin nie ná die offset is nie, en verifieer dat die adres onder die volgende inskrywing of die einde van die eersterangse reeks val.
6. Dekodeer daardie inskrywing en stel die presiese toestand wat dit beskryf saam.

Wanneer ’n adres van ’n gestoorde LR afkomstig is, kan die opsoek `PC-1` gebruik sodat ’n adres onmiddellik ná ’n oproep binne die oproeper se gedekte reeks bly. Dit verander die resepkeuse, nie enige stapeloffset nie.<sup>[[1]](#references)</sup>

’n Ontleder moet elke opskrif en skikking se grense nagaan, seksieweergawe `1` vereis, die finale eersterangse sentinel in ag neem, ’n nul-offset vir ’n tweederangse bladsy verwerp en gewone van saamgeperste bladsye onderskei. In ’n gewone bladsy is `entryPageOffset` relatief tot die begin van daardie bladsy, terwyl die eersterangse bladsy-offset relatief tot die begin van `__unwind_info` is.<sup>[[1]](#references)[[2]](#references)</sup>

Die breë modus is `encoding & 0x0F000000`. Huidige LLVM-definisies sluit die volgende modusse in; ’n ontleder moet nie elke waarde wat nie DWARF is nie as ’n klassieke raam hanteer nie:<sup>[[1]](#references)[[2]](#references)</sup>

| Modus | Waarde | Oproeper-herstel |
| --- | --- | --- |
| Geen kompakte resep | `0x00000000` | Stop of gebruik ’n onafhanklike terugvalmetode. |
| Raamloos | `0x02000000` | Tel die geënkodeerde stapelgrootte by huidige `SP`; oproeper-PC is lewendige LR. |
| DWARF | `0x03000000` | Voer die FDE/CFI uit wat deur die onderste 24 bisse geïdentifiseer word. |
| Raam | `0x04000000` | Lees die konvensionele `x29`-raamrekord. |
| arm64e-raam met geauthentiseerde LR-reeks | `0x05000000` | Hanteer `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`; die offsetveld lokaliseer `pacibsppc` binne die gedekte reeks. |

Vir raamlose modus is `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. Vir raammodus dui die vyf laagste bisse aaneenliggende gestoorde GPR-pare aan, van `x19/x20` tot `x27/x28`; bisse `0x100-0x800` dui eweneens `d8-d15`-pare aan. Daardie gestoorde registers is dalk nie nodig om die volgende PC te vind nie, maar ’n geloofwaardige virtuele oproepertoestand moet aan elke veld voldoen wat die verbruiker herbou.<sup>[[1]](#references)[[2]](#references)</sup>

## Bou sintetiese raammodusrekords

Die bouproses keer die unwinder se werkwyse om, eerder as om die stapel vir waardes wat soos adresse lyk te deursoek:<sup>[[1]](#references)</sup>

1. Kies ’n werklike uitvoerbare PC in ’n tans gelaaide image.
2. Dekodeer die resep wat daardie presiese PC of oproeppunt-adres dek.
3. Ken ’n sintetiese rekord toe met die vereiste belyning en CFA-verhouding.
4. Stoor die volgende sintetiese FP by `[FP]`, daardie raam se gestoorde oproeper-PC by `[FP+8]`, en elke GPR/FPR-stoorplek wat deur die enkodering verklaar word, onder FP.
5. Skakel verskeie rekords aan mekaar en plaas die eerste rekord in lewendige `x29`.
6. Rangskik lewendige LR en die API-terugkeerpad so dat unwinding die gekose ketting binnegaan, terwyl uitvoering steeds veilig herstel kan word.

Byvoorbeeld, `0x04000001` beteken raammodus plus die `x19/x20`-paar. Die ooreenstemmende toestandsoorgang en vereiste geheue is:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

’n Adres wat geloofwaardig lyk, is dus nie genoeg nie. Elke herwonne PC word die sleutel vir die volgende opsoek, dus breek ’n enkele adres waarvan die enkodering nie met die nagemaakte uitleg ooreenstem nie die ketting, of veroorsaak dit dat die verbruiker ’n teenstrydige registertoestand rekonstrueer.<sup>[[1]](#references)</sup>

## ARM64e PAC-vereistes

PAC stoor ’n sleutelgebaseerde integriteitswaarde in andersins ongebruikte wyserbis; dit enkripteer nie die adres nie. Clang se arm64e-terugkeeradres-skema gebruik instruksiesleutel B en die stapelwyser by funksie-ingang as die diskriminator. Vir ’n konvensionele raamwerk is daardie ingang-`SP` die CFA, dus is die gestoorde LR by `[FP+8]` aan `FP+0x10` gebind.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Elke sintetiese LR moet onafhanklik onderteken word, want wanneer ’n reeds ondertekende LR na ’n raamwerk met ’n ander CFA verskuif word, verander die discriminator en misluk verifikasie. `ptrauth_strip()` is geskik vir adresnormalisering en simboolopsoek, maar bevestig **nie** egtheid nie; enige werklike terugkeer of geverifieerde indirekte vertakking moet die sleutel en modifier gebruik wat by daardie presiese oorgang verwag word.<sup>[[1]](#references)[[3]](#references)</sup>

’n Tipiese arm64e-funksie wat nie ’n blaarknoop is nie, onderteken LR voordat dit gestoor word en verifieer dit nadat die entry SP herstel is:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline en herstelbrug

Sintetiese rekords hoef net aan die unwinder se vereistes te voldoen; hulle bevat nie ’n volledige uitvoeringskonteks nie. ’n Terugkeer vanaf die sensitiewe API direk na die vervalste oproepers sal normaalweg ’n crash veroorsaak. Die praktiese ontwerp plaas dus ’n gadget-raam onmiddellik onder die API: die API keer terug na uitvoerbare kode in ’n gelaaide framework, en daardie gadget spring via ’n beheerde callee-saved register na ’n herstelbrug in die implant.<sup>[[1]](#references)</sup>

’n Nuttige gadget behou LR en dra beheer oor via ’n beheerde register, byvoorbeeld met ’n gepaste `br`-, `braa`- of `brab`-volgorde. Die herstelbrug moet die oorspronklike `x19-x30`-waardes en `SP` herstel voordat implant-uitvoering hervat word. Op arm64e vereis elke geauthentiseerde terugkeer of sprong in die API-na-gadget-, gadget-na-brug- en brug-na-implant-pad ’n wyser wat onderteken is vir die sleutel en diskriminator wat deur daardie instruksie gebruik word.<sup>[[1]](#references)</sup>

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

Die resultaat is ’n belangrike vertrouensgrensfaling vir stack-gebaseerde opsporing: ’n ketting kan slegs gemapte, simboliseerbare Apple-raamwerk-PC’s bevat en steeds nie werklike beheervloei verteenwoordig nie. Unwind-uitvoer moet dus met onafhanklike bewyse oor die draad se herkoms van uitvoerbare geheue en die werklike oorgange rondom die sensitiewe API bevestig word, eerder as om dit as ’n uitvoeringspoor te beskou.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - ARM64-stackinterne en verduistering op Apple Silicon](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Definisies van Mach-O compact unwind-kodering](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Pointer Authentication](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Prosedure-oproepstandaard vir die 64-bis Arm-argitektuur](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
