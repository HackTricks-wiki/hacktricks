# Static Deobfuscation ya Node.js/V8 Cached Bytecode

{{#include ../../banners/hacktricks-training.md}}

V8 cached data ni **uwakilishi unaotegemea version na unaopoteza baadhi ya taarifa**, si JavaScript source wala native executable ya kawaida. Kwa hivyo, workflow muhimu ya static ni: ondoa outer packing, disassemble cache kwa kutumia V8 build inayolingana, iinue hadi kwenye intermediate pseudocode model, kisha tumia dependency-aware transformations bila kuendesha sample. [View8](https://github.com/suleram/View8) na [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) hutumia mbinu hii kwa Node.js payloads zilizolindwa na `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Acquire and disassemble the cache

Kwanza kagua preload/launcher badala ya kudhani kuwa kila faili ya `.jsc` ina wrapper sawa. Kwa mfano, launcher kama `node.exe -r preflight.js app.jsc` huendesha `preflight.js` kabla ya main module; katika family iliyochanganuliwa, preload iliondoa Brotli layer. Baada ya unpacking, tambua kizazi halisi cha Node.js/V8 kutoka kwenye bundled runtime. Cache iliyotengenezwa na V8 version moja inaweza kukataliwa au kusimbuliwa kimakosa na nyingine, kwa hiyo build au pata `v8dasm` ya V8 tag hiyo mahususi na utumie patches zinazohitajika za View8 na string-printing.<sup>[[1]](#references)[[2]](#references)</sup>

Workflow ya toolkit isiyot执行 ni:<sup>[[2]](#references)</sup>
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
`--normalize` hutoa vitambulisho thabiti kwa functions zilizozalishwa katika runs tofauti. Matokeo ya maandishi ni kwa ajili ya ukaguzi; object graph iliyoserializwa huruhusu passes huru kuhifadhi mahusiano ya function, declarer, scope na metadata. **Si JavaScript iliyoundwa upya au inayoweza kuendeshwa**.<sup>[[1]](#references)[[2]](#references)</sup>

### Soma pseudocode ya View8 kama IR

Majina ya kawaida ni `func_<name>_0x<address>`, arguments ni `a0...aN`, virtual registers ni `r0...rN`, na `ACCU` ni accumulator ya V8. `start` ni declarer wa root, huku `Scope[...]`, globals na dictionaries zikifananisha values zilizokamatwa au kushirikiwa na functions zilizowekwa ndani. Usichanganue kila expression kama syntax ya JavaScript: kwa mfano, `!r6 === "0"` ya View8 inawakilisha negation ya comparison nzima (`r6 !== "0"`), jambo ambalo ni muhimu wakati wa kujenga upya branches.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuscation inayozingatia dependencies

Tumia transformations kwa mpangilio unaofichua inputs zinazohitajika na pass inayofuata, kisha rudia propagation hadi output itakapotulia. Mpangilio wa kivitendo ni:<sup>[[1]](#references)[[2]](#references)</sup>

1. Pitia hierarchy ya declarers na ueneze values kutoka globals, registers, dictionaries na references za `Scope[...]`.
2. Rejesha arguments za string-decoder na ubadilishe calls zilizofichwa kwa plaintext.
3. Unganisha string chunks zilizo karibu; property names na dispatcher-order strings zitakazopatikana hufungua passes zinazofuata.
4. Ondoa flattening ya control flow, inline call proxies na atomic-operation wrappers, na resolve function references zilizohifadhiwa kwenye dictionaries.
5. Fanya propagation tena kwa sababu kila string, key au proxy iliyoresolve inaweza kufichua layer nyingine ya indirection.
6. Kunja initialization thunks zinazotambulika za matumizi ya mara moja na uondoe helpers zisizotumika baada tu ya call sites zao ku-resolve.

### Rejesha arrays za strings za RC4 zilizohamishwa kama black box

Mpangilio wa kawaida wa `javascript-obfuscator` huhifadhi chunks za RC4 zilizosimbwa kwa Base64 katika array moja. Decoder wrappers hutoa numeric offset na key fupi, wakati mwingine kwa mpangilio wa arguments uliogeuzwa, kisha huongeza au kupunguza constants zilizonaswa katika closure scopes. Root decoder inapokuwa imefichwa sana, rejesha unknown array-index shift yake kwa majaribio badala ya kujenga upya function nzima.<sup>[[1]](#references)</sup>

Kwa array yenye chunks `N` na calls kadhaa za decoder hiyo hiyo:<sup>[[1]](#references)</sup>
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
Usikubali shift kutokana na decryption moja tu inayoweza kuchapishwa: ciphertext isiyo sahihi inaweza kuonekana printable kwa bahati. Tumia angalau observations tatu tofauti na ukubali shift ya kipekee tu inayozalisha maandishi yanayoeleweka kwa observations zote. Kisha pitia graph ya wrapper/declarer, ukikusanya kila addition au subtraction na kurekodi ikiwa numeric argument inatangulia. Hifadhi metadata hii kwa kila sample, badilisha decoder calls, unganisha plaintext chunks zilizo karibu na u-export strings kando kwa ajili ya triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Kuhifadhi semantics wakati wa ku-unflatten

Kwa dispatcher loops zinazoendeshwa na strings kama `3|2|1|0|4`, decode order string, linganisha kila state comparison na block yake, zingatia notation ya negated-condition ya View8, kisha toa blocks kwa mpangilio wa dispatcher. `continue` iliyo ndani ya nesting inaweza kuwakilisha early jump kurudi kwa dispatcher badala ya ordinary fall-through. Unapoondoa loop, futa hiyo `continue` na uhamishe statements zilizofuata awali `if` yake inayozunguka hadi kwenye `else` branch iliyozalishwa; kufuta dispatcher pekee hubadilisha behavior.<sup>[[1]](#references)</sup>

### Ku-inline proxies, operations na lazy thunks

Normalize forwarding helpers kama `return a0(a1, a2)` kabla ya kubadilisha call sites zao kuwa direct calls. Shughulikia wrappers za subtraction, division, comparison, membership tests au invocation kwa njia hiyo hiyo. Kwa kuwa helper reference yenyewe inaweza kuwa imehifadhiwa nyuma ya decrypted dictionary key au closure value, endesha string na structure propagation kabla na baada ya inlining.<sup>[[1]](#references)</sup>

Pia tambua closures zinazo-invoke stored function mara moja, ku-clear reference yake, kuhifadhi result na kurudisha cache hiyo kwenye calls zinazofuata. Ku-collapse thunk kama hiyo kwenye initialization site hufichua underlying dispatcher au capability function, lakini weka annotation kwamba execution ya awali ilikuwa **one-shot and cached**, badala ya ku-model kila call kama invocation mpya.<sup>[[1]](#references)</sup>

## Vidokezo vya usalama na validation

- Python `pickle` loading inaweza ku-execute code. Load tu files za `.pkl` zilizotengenezwa locally na trusted View8 run; usichukulie pickle iliyotolewa na sample kama data.<sup>[[2]](#references)</sup>
- Pattern-driven passes si JavaScript decompiler ya jumla. Hifadhi expressions ambazo hazijatatuliwa na kagua mwenyewe dispatcher variants zenye utata badala ya kulazimisha rewrite.<sup>[[1]](#references)[[2]](#references)</sup>
- Majina ya functions yanayosaidiwa na LLM ni navigation hints, si evidence. Chakata dependencies leaf-first ukiyatumia, lakini thibitisha kila label dhidi ya body, arguments, strings, data flow, APIs na side effects.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Kuvunja Muhuri: Static Deobfuscation ya Compiled V8 Bytecode ya JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
