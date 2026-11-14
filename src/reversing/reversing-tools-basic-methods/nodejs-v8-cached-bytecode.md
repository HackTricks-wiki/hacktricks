# Static Deobfuscation ya Cached Bytecode ya Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Data iliyohifadhiwa kwenye cache ya V8 ni **uwakilishi unaotegemea toleo na unaopoteza taarifa**, si source code ya JavaScript wala executable ya kawaida ya native. Kwa hivyo, utaratibu mzuri wa static ni: ondoa packing yoyote ya nje, disassemble cache kwa kutumia build ya V8 inayolingana, ibadilishe kuwa pseudocode ya intermediate model, kisha utumie mabadiliko yanayozingatia dependencies bila kuendesha sample. [View8](https://github.com/suleram/View8) na [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) hutumia mbinu hii kwa payload za Node.js zilizolindwa na `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Pata na disassemble cache

Kwanza kagua preload/launcher badala ya kudhani kuwa kila faili ya `.jsc` ina wrapper ileile. Kwa mfano, launcher kama `node.exe -r preflight.js app.jsc` huendesha `preflight.js` kabla ya module kuu; katika familia iliyochanganuliwa, preload iliondoa safu ya Brotli. Baada ya ku-unpack, tambua kizazi halisi cha Node.js/V8 kutoka runtime iliyojumuishwa. Cache iliyotengenezwa na toleo moja la V8 inaweza kukataliwa au kusimbuliwa kimakosa na toleo lingine, kwa hivyo tengeneza au pata `v8dasm` ya V8 tag hiyo mahususi na utumie patches zinazohitajika za View8 na za kuchapisha strings.<sup>[[1]](#references)[[2]](#references)</sup>

Utaratibu wa toolkit usioendesha sample ni:<sup>[[2]](#references)</sup>

```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
  --inp app.jsc.disasm.txt --normalize \
  --out decompiled/app.dec.txt \
  --export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
  --out deobfuscated/app.deobf.txt \
  --export_format decompiled serialized
```

`--normalize` huipa functions zinazozalishwa vitambulishi thabiti katika runs tofauti. Matokeo ya maandishi ni kwa ajili ya ukaguzi; object graph iliyoserialishwa huwezesha passes huru kuhifadhi uhusiano kati ya function, declarer, scope na metadata. Hii **si JavaScript iliyoundwa upya wala inayoweza kuendeshwa**.<sup>[[1]](#references)[[2]](#references)</sup>

### Chunguza cache bila kujenga V8

Kwa cache ghafi au iliyofungwa kwa Brotli, `jscd` inaweza kutambua header na kuorodhesha constants na functions bila kupakia sampuli kwenye Node.js. Tumia hii kwanza kuangalia kama jedwali zake za matoleo zinaunga mkono faili na kuweka functions katika mpangilio wa kipaumbele kabla ya passes maalum zaidi za View8 deobfuscation.<sup>[[4]](#references)</sup>

Version hash ni kidokezo cha utambulisho, si uthibitisho kwamba disassembler inayojitegemea ina flags sawa au snapshot ya read-only sawa na iliyotumiwa na producer.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` hutoa orodha inayooana na View8, kwa hivyo amri ya View8 hapo juu inaweza kutumia matokeo hayo badala ya `v8dasm` ikiwa cache inaungwa mkono. Kagua strings pamoja na mti wa functions ili kupata miito ya decoder na entry points zinazowezekana; usichukulie matokeo ya JavaScript ya makadirio ya `jscd` kuwa source halisi. Ikiwa tool inakataa version au inaacha placeholders za read-only-heap, tumia tena build ya V8 inayolingana au toa name map kutoka build hiyo hiyo badala ya kukisia majina ya properties.<sup>[[4]](#references)</sup>

Kwa cache iliyo ndani ya programu ya Electron, kwanza [extract ASAR na ukague entry points za main na preload](../../desktop-application-security/electron-desktop-apps/). Caches za Electron na Node zinaweza kutofautiana katika mpangilio wa snapshot na pointer-compression hata kama strings za version ya V8 zinafanana.<sup>[[4]](#references)</sup>

### Soma pseudocode ya View8 kama IR

Majina ya kawaida ni `func_<name>_0x<address>`, arguments ni `a0...aN`, virtual registers ni `r0...rN`, na `ACCU` ni accumulator ya V8. `start` ndiyo root declarer, huku `Scope[...]`, globals na dictionaries zikiwakilisha values zilizokamatwa au kushirikishwa na functions zilizopachikwa. Usichanganue kila expression kana kwamba ni sintaksia ya JavaScript: kwa mfano, `!r6 === "0"` ya View8 inawakilisha ukanushaji wa ulinganisho mzima (`r6 !== "0"`), jambo muhimu unapounda upya branches.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuscation inayozingatia utegemezi

Tekeleza transformations kwa mpangilio unaoonyesha inputs zinazohitajika na pass inayofuata, na urudie propagation hadi matokeo yatulie. Mpangilio unaofaa ni:<sup>[[1]](#references)[[2]](#references)</sup>

1. Pitia hierarchy ya declarer na propagate values kutoka globals, registers, dictionaries na marejeo ya `Scope[...]`.
2. Rejesha arguments za string-decoder na ubadilishe miito iliyosimbwa kwa maandishi wazi.
3. Unganisha string chunks zilizo jirani; majina ya properties na strings za mpangilio wa dispatcher zitakazopatikana zitafungua passes za baadaye.
4. Ondoa flattening ya control flow, inline call proxies na wrappers za atomic-operation, kisha tatua marejeo ya functions yaliyohifadhiwa kwenye dictionaries.
5. Fanya propagation tena kwa sababu kila string, key au proxy iliyotatuliwa inaweza kufichua safu nyingine ya indirection.
6. Unganisha thunks zinazotambulika za one-shot initialization na uondoe helpers zilizokufa tu baada ya call sites zake kutatuliwa.

### Rejesha arrays za strings za RC4 zilizohamishwa kama black box

Muundo wa kawaida wa `javascript-obfuscator` huhifadhi vipande vya RC4 vilivyosimbwa kwa Base64 kwenye array moja. Wrappers za decoder hutoa offset ya nambari na key fupi, wakati mwingine kwa mpangilio wa arguments uliogeuzwa, kisha huongeza au kutoa constants zilizokamatwa kwenye closure scopes. Wakati root decoder imefichwa kupita kiasi, rejesha shift isiyojulikana ya array-index kwa majaribio badala ya kuunda upya function nzima.<sup>[[1]](#references)</sup>

Kwa array yenye chunks `N` na miito kadhaa ya decoder ileile:<sup>[[1]](#references)</sup>

```text
for each observed (numeric_argument, rc4_key):
    candidates = {}
    for shift in 0 .. N-1:
        index = apply_observed_sign(numeric_argument, shift)
        plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
        if plaintext passes encoding/printability checks:
            candidates.add(shift)
root_shift = intersection(candidate_sets)
```

Usikubali shift kwa kutegemea matokeo moja tu ya decryption yanayosomeka: ciphertext isiyo sahihi inaweza kuonekana inasomeka kwa bahati. Tumia angalau uchunguzi tatu tofauti na ukubali shift ya kipekee tu inayotoa maandishi yanayoeleweka kwa yote. Kisha pitia grafu ya wrapper/declarer, ukikusanya kila jumlisho au utoaji na kurekodi iwapo argument ya nambari huja kwanza. Hifadhi metadata hii kwa kila sample, badilisha miito ya decoder, unganisha vipande vya plaintext vinavyopakana na uhamishe strings kivyake kwa ajili ya triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Hifadhi semantiki unapofungua uflattening

Kwa loops za dispatcher zinazoendeshwa na strings kama `3|2|1|0|4`, decode string ya mpangilio, linganisha kila state comparison na block yake, zingatia notation ya masharti yaliyokanushwa ya View8, kisha toa blocks kwa mpangilio wa dispatcher. `continue` iliyo ndani ya muundo uliopachikwa inaweza kuwakilisha kuruka mapema kurudi kwa dispatcher badala ya kuendelea kwa mtiririko wa kawaida. Unapoondoa loop, futa `continue` hiyo na uhamishe statements zilizokuwa baada ya `if` inayoizunguka hadi kwenye tawi la `else` lililozalishwa; kufuta dispatcher tu hubadilisha tabia ya programu.<sup>[[1]](#references)</sup>

### Inline proxies, operations na lazy thunks

Sawazisha helpers za forwarding kama `return a0(a1, a2)` kabla ya kubadilisha call sites zake kuwa miito ya moja kwa moja. Shughulikia wrappers za utoaji, ugawaji, ulinganishaji, majaribio ya membership au invocation vivyo hivyo. Kwa kuwa rejeleo la helper lenyewe linaweza kuhifadhiwa nyuma ya ufunguo wa dictionary uliodecryptiwa au thamani ya closure, endesha uenezaji wa strings na muundo kabla na baada ya inlining.<sup>[[1]](#references)</sup>

Pia tambua closures zinazoita function iliyohifadhiwa mara moja, kufuta rejeleo lake, kuhifadhi matokeo kwenye cache na kurudisha cache hiyo kwenye miito ya baadaye. Kuondoa thunk kama hiyo kwenye sehemu ya initialization hufichua dispatcher au function ya capability iliyo msingi wake, lakini weka dokezo kwamba utekelezaji wa awali ulikuwa **wa mara moja na matokeo kuhifadhiwa kwenye cache**, badala ya kuiga kila mwito kama invocation mpya.<sup>[[1]](#references)</sup>

## Vidokezo vya usalama na uthibitishaji

- Kupakia Python `pickle` kunaweza kutekeleza code. Pakia faili za `.pkl` zilizozalishwa na run ya View8 unayoamini pekee; usichukulie kamwe pickle iliyotolewa na sample kuwa data.<sup>[[2]](#references)</sup>
- Kukosekana kwa body ya function hakuthibitishi kwamba source haikuwa na function hiyo: V8 inaweza kuserialisha lazy function kama metadata hadi itakapokusanywa wakati wa mwito wa kwanza. Weka functions kama hizo alama ya kutotatuliwa wakati wa static triage.<sup>[[6]](#references)</sup>
- Pass zinazoendeshwa na patterns si decompiler ya jumla ya JavaScript. Hifadhi expressions ambazo hazijatatuliwa na kagua kwa mkono variants za dispatcher zenye utata badala ya kulazimisha rewrite.<sup>[[1]](#references)[[2]](#references)</sup>
- Majina ya functions yaliyosaidiwa na LLM ni vidokezo vya urambazaji, si ushahidi. Ikiwa unayatumia, changanua dependencies kuanzia leaf; kisha hakiki kila lebo kwa kuzingatia body, arguments, strings, data flow, APIs na side effects.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Kuvunja Muhuri: Uondoaji Tuli wa Ufichaji wa Bytecode ya V8 Iliyokusanywa ya JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Kichwa cha V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Cache ya code ya Node.js vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
