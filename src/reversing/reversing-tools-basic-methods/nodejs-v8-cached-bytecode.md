# Uondoaji wa Obfuscation Tuli wa Bytecode Iliyo-cache ya Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Data ya V8 iliyowekwa kwenye cache ni **uwakilishi unaotegemea toleo na unaopoteza taarifa**, si source code ya JavaScript wala executable ya kawaida ya native. Kwa hiyo, workflow muhimu ya static ni: ondoa packing yoyote ya nje, disassemble cache kwa build inayolingana ya V8, ipeleke kwenye modeli ya pseudocode ya kati, kisha tumia transformations zinazozingatia dependencies bila kuendesha sample. [View8](https://github.com/suleram/View8) na [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) hutumia mbinu hii kwa payloads za Node.js zilizolindwa na `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Pata na disassemble cache

Kwanza kagua preload/launcher badala ya kudhani kuwa kila faili la `.jsc` lina wrapper sawa. Kwa mfano, launcher kama `node.exe -r preflight.js app.jsc` huendesha `preflight.js` kabla ya main module; katika family iliyochanganuliwa, preload iliondoa layer ya Brotli. Baada ya ku-unpack, tambua kizazi halisi cha Node.js/V8 kutoka kwenye runtime iliyojumuishwa. Cache iliyotengenezwa na toleo moja la V8 inaweza kukataliwa au kusimbuliwa vibaya na jingine, kwa hiyo build au pata `v8dasm` ya V8 tag hiyo mahususi na utumie patches zinazohitajika za View8 na za kuchapisha strings.<sup>[[1]](#references)[[2]](#references)</sup>

Workflow ya toolkit isiyotekeleza sample ni:<sup>[[2]](#references)</sup>

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

`--normalize` huzipa functions zilizozalishwa vitambulishi thabiti katika kila run. Matokeo ya maandishi ni kwa ajili ya ukaguzi; object graph iliyoserialishwa huruhusu passes huru kuhifadhi uhusiano kati ya functions, declarers, scopes na metadata. **Si JavaScript iliyojengwa upya au inayoweza kuendeshwa**.<sup>[[1]](#references)[[2]](#references)</sup>

### Kuchunguza cache bila kujenga V8

Kwa cache ghafi au iliyofungwa kwa Brotli, `jscd` inaweza kutambua header na kuorodhesha constants na functions bila kupakia sample katika Node.js. Tumia hii kwanza kuangalia kama jedwali zake za version zinaunga mkono faili hiyo na kupanga kipaumbele cha functions kabla ya kutumia passes maalumu zaidi za View8 za kuondoa obfuscation.<sup>[[4]](#references)</sup>

Version hash ni kidokezo cha utambulisho, si uthibitisho kwamba disassembler inayojitegemea ina flags sawa au snapshot ya kusoma tu kama ile ya mtengenezaji.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` hutoa listing inayooana na View8, kwa hivyo amri ya View8 hapo juu inaweza kutumia matokeo hayo badala ya `v8dasm` wakati cache inaungwa mkono. Kagua strings pamoja na function tree ili kupata miito ya decoder na entry point zinazowezekana; usichukulie matokeo ya JavaScript ya kukadiria ya `jscd` kuwa source code asilia. Ikiwa zana itakataa version au ikaacha placeholders za read-only-heap, tumia tena build ya V8 inayolingana au toa name map kutoka build hiyo hiyo badala ya kubashiri majina ya property.<sup>[[4]](#references)</sup>

Kwa cache iliyo ndani ya programu ya Electron, kwanza [extract ASAR na ukague entry point zake za main na preload](../../network-services-pentesting/pentesting-web/electron-desktop-apps/). Muundo wa snapshot na pointer-compression katika cache za Electron na Node unaweza kutofautiana hata kama strings za version ya V8 zinafanana.<sup>[[4]](#references)</sup>

### Soma pseudocode ya View8 kama IR

Majina ya kawaida ni `func_<name>_0x<address>`, argument ni `a0...aN`, virtual register ni `r0...rN`, na `ACCU` ni accumulator ya V8. `start` ndiyo declarer ya mzizi, ilhali `Scope[...]`, globals na dictionaries huwakilisha thamani zilizokamatwa au kushirikiwa na function zilizowekwa ndani. Usichanganue kila expression kama sintaksia ya JavaScript: kwa mfano, `!r6 === "0"` katika View8 huwakilisha ukanushaji wa comparison nzima (`r6 !== "0"`), jambo muhimu unapounda upya branches.<sup>[[1]](#references)[[3]](#references)</sup>

## Uondoaji wa obfuscation unaozingatia utegemezi

Tekeleza transformations kwa mpangilio unaoonyesha inputs zinazohitajika na pass inayofuata, na urudie propagation hadi matokeo yatulie. Mpangilio unaofaa ni:<sup>[[1]](#references)[[2]](#references)</sup>

1. Fuatilia daraja la declarer na usambaze thamani kutoka globals, registers, dictionaries na marejeleo ya `Scope[...]`.
2. Rejesha argument za string-decoder na ubadilishe miito iliyosimbwa kwa plaintext.
3. Unganisha vipande vya string vilivyo jirani; majina ya property na strings za mpangilio wa dispatcher zitakazopatikana zitafungua pass zinazofuata.
4. Ondoa uflatishaji wa control flow, weka call proxies na wrappers za atomic-operation ndani ya mstari, na tatua marejeleo ya function yaliyohifadhiwa kwenye dictionary.
5. Fanya propagation tena kwa sababu kila string, key au proxy iliyotatuliwa inaweza kufichua safu nyingine ya indirection.
6. Fupisha one-shot initialization thunk zinazotambulika na uondoe helpers zisizotumika tu baada ya call site zake kutatuliwa.

### Rejesha arrays za string za RC4 zilizohamishwa kama black box

Mpangilio wa kawaida wa `javascript-obfuscator` huhifadhi chunks za RC4 zilizosimbwa kwa Base64 ndani ya array moja. Decoder wrappers hutoa numeric offset na key fupi, wakati mwingine kwa mpangilio wa argument uliogeuzwa, kisha huongeza au kutoa constants zilizokamatwa kwenye closure scopes. Ikiwa root decoder imefichwa sana, rejesha shift isiyojulikana ya array-index kwa majaribio badala ya kuunda upya function nzima.<sup>[[1]](#references)</sup>

Kwa array yenye chunks `N` na miito kadhaa ya decoder hiyo hiyo:<sup>[[1]](#references)</sup>

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

Usikubali shift kwa sababu tu decryption moja imetoa maandishi yanayosomeka: ciphertext isiyo sahihi inaweza kutoa maandishi yanayosomeka kwa bahati. Tumia angalau uchunguzi tatu tofauti, na ukubali shift ya kipekee tu ikiwa zote zinaleta maandishi yanayoeleweka. Kisha fuatilia graph ya wrapper/declarer, ukikusanya kila nyongeza au utoaji na kurekodi kama argument ya nambari huja kwanza. Hifadhi metadata hii kwa kila sample, badilisha miito ya decoder, unganisha vipande vya plaintext vilivyo jirani na utoe strings kando kwa ajili ya triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Hifadhi semantics unapofungua flattening

Kwa loops za dispatcher zinazoendeshwa na strings kama `3|2|1|0|4`, decode string ya mpangilio, linganisha kila state na block yake, zingatia notation ya hali iliyokanushwa ya View8, kisha toa blocks kwa mpangilio wa dispatcher. `continue` iliyowekwa ndani ya block nyingine inaweza kuwakilisha kuruka mapema kurudi kwa dispatcher badala ya kuendelea kwa kawaida. Unapoondoa loop, futa hiyo `continue` na uhamishe statements zilizokuwa zikifuata `if` yake inayozizunguka hadi kwenye tawi la `else` lililotengenezwa; kufuta dispatcher pekee hubadilisha tabia ya programu.<sup>[[1]](#references)</sup>

### Inline proxies, operations na lazy thunks

Sanifisha helpers za forwarding kama `return a0(a1, a2)` kabla ya kubadilisha call sites zake ziwe miito ya moja kwa moja. Shughulikia wrappers za utoaji, mgawanyo, ulinganishaji, majaribio ya uanachama au invocation vivyo hivyo. Kwa kuwa rejeleo la helper lenyewe linaweza kuwa limehifadhiwa nyuma ya dictionary key iliyodecryptiwa au thamani ya closure, fanya string na structure propagation kabla na baada ya inlining.<sup>[[1]](#references)</sup>

Pia tambua closures zinazoita function iliyohifadhiwa mara moja, kufuta rejeleo lake, kuhifadhi matokeo kwenye cache na kurudisha cache hiyo kwenye miito inayofuata. Kuondoa thunk kama hii kwenye initialization site hufichua dispatcher au capability function iliyo chini yake, lakini weka dokezo kwamba utekelezaji wa awali ulikuwa **wa matumizi moja na matokeo yake yakahifadhiwa kwenye cache**, badala ya kuiga kila mwito kama invocation mpya.<sup>[[1]](#references)</sup>

## Maelezo ya usalama na uthibitishaji

- Kupakia Python `pickle` kunaweza kutekeleza code. Pakia tu faili za `.pkl` zilizotengenezwa locally na uendeshaji unaoaminika wa View8; usiwahi kuchukulia pickle iliyotolewa na sample kama data.<sup>[[2]](#references)</sup>
- Kukosekana kwa function body si uthibitisho kwamba source haikuwa na function hiyo: V8 inaweza kuserialisha lazy function kama metadata hadi ikompailiwe inapoitwa kwa mara ya kwanza. Ziache functions kama hizo zikiwa zimetambulishwa kuwa hazijatatuliwa wakati wa static triage.<sup>[[6]](#references)</sup>
- Passes zinazoendeshwa na patterns si JavaScript decompiler ya jumla. Hifadhi expressions ambazo hazijatatuliwa na kagua kwa mikono variants za dispatcher zenye utata badala ya kulazimisha rewrite.<sup>[[1]](#references)[[2]](#references)</sup>
- Majina ya functions yaliyosaidiwa na LLM ni vidokezo vya urambazaji, si ushahidi. Ikiwa unayatumia, shughulikia dependencies kuanzia leaf; lakini thibitisha kila label kwa kulinganisha na body, arguments, strings, data flow, APIs na side effects.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Kuvunja Muhuri: Uondoaji wa Obfuscation wa Kistatiki wa V8 Bytecode Iliyokompailiwa ya JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Kichwa cha V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Cache ya code ya Node.js vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
