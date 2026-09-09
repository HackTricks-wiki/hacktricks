# Statiese Deobfuscation van Node.js/V8 Cached Bytecode

{{#include ../../banners/hacktricks-training.md}}

V8 cached data is 'n **version-dependent, lossy representation**, nie JavaScript source nie en ook nie 'n konvensionele native executable nie. 'n Nuttige statiese workflow is dus: verwyder enige outer packing, disassemble die cache met die ooreenstemmende V8 build, lift dit na 'n intermediate pseudocode-model, en pas dependency-aware transformations toe sonder om die sample uit te voer. [View8](https://github.com/suleram/View8) en [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementeer hierdie benadering vir Node.js payloads wat deur `javascript-obfuscator` beskerm word.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Verkry en disassemble die cache

Inspekteer eers die preload/launcher eerder as om aan te neem dat elke `.jsc`-lêer dieselfde wrapper het. Byvoorbeeld, 'n launcher soos `node.exe -r preflight.js app.jsc` voer `preflight.js` voor die hoofmodule uit; in die geanaliseerde familie het die preload 'n Brotli-laag verwyder. Identifiseer ná unpacking die presiese Node.js/V8-generasie uit die gebundelde runtime. 'n Cache wat deur een V8-weergawe geproduseer is, kan deur 'n ander verwerp of verkeerd gedecodeer word, dus moet jy 'n `v8dasm` vir daardie presiese V8-tag build of verkry en die vereiste View8- en string-printing-patches toepas.<sup>[[1]](#references)[[2]](#references)</sup>

Die toolkit se non-executing workflow is:<sup>[[2]](#references)</sup>
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
`--normalize` gee gegenereerde funksies stabiele identifiseerders oor lopies heen. Die teksuitset is vir inspeksie; die geserialiseerde objekgrafiek laat onafhanklike passe toe om funksie-, verklaarder-, scope- en metadata-verhoudings te behou. Dit is **nie gerekonstrueerde of uitvoerbare JavaScript nie**.<sup>[[1]](#references)[[2]](#references)</sup>

### Lees View8-pseudokode as 'n IR

Tipiese name is `func_<name>_0x<address>`, argumente is `a0...aN`, virtuele registers is `r0...rN`, en `ACCU` is V8 se accumulator. `start` is die wortelverklaarder, terwyl `Scope[...]`, globals en dictionaries waardes modelleer wat deur geneste funksies gecapture of gedeel word. Moenie elke uitdrukking as JavaScript-sintaksis ontleed nie: View8 se `!r6 === "0"` verteenwoordig byvoorbeeld ontkenning van die volledige vergelyking (`r6 !== "0"`), wat belangrik is wanneer vertakkings herbou word.<sup>[[1]](#references)[[3]](#references)</sup>

## Afhanklikheidsbewuste deobfuscation

Pas transformasies toe in 'n volgorde wat die insette blootlê wat deur die volgende pass vereis word, en herhaal propagation totdat die uitset stabiliseer. 'n Praktiese volgorde is:<sup>[[1]](#references)[[2]](#references)</sup>

1. Loop deur die verklaarderhiërargie en propagateer waardes vanaf globals, registers, dictionaries en `Scope[...]`-verwysings.
2. Herwin string-decoder-argumente en vervang geënkripteerde calls met plaintext.
3. Vou aangrensende string-brokke saam; die gevolglike property-name en dispatcher-order-string ontsluit latere passe.
4. Maak control flow plat, inline call proxies en atomic-operation wrappers, en resolveer funksieverwysings wat in dictionaries gehou word.
5. Propagateer weer omdat elke opgeloste string, sleutel of proxy nog 'n laag indireksie kan blootlê.
6. Vou herkende eenmalige initialisation thunks saam en verwyder dooie helpers eers nadat hul call sites opgelos is.

### Herwin shifted RC4-stringarrays as 'n black box

'n Algemene `javascript-obfuscator`-uitleg stoor Base64-geënkodeerde RC4-brokke in een array. Decoder-wrappers verskaf 'n numeriese offset en 'n kort sleutel, soms in omgekeerde argumentvolgorde, en tel dan konstantes by of trek dit af wat in closure scopes gecapture is. Wanneer die root decoder te swaar geobfuskeer is, herwin sy onbekende array-index-shift empiries in plaas daarvan om die hele funksie te rekonstrueer.<sup>[[1]](#references)</sup>

Vir 'n array van `N` brokke en verskeie calls na dieselfde decoder:<sup>[[1]](#references)</sup>
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
Moenie ’n shift aanvaar op grond van ’n enkele drukbare dekripsie nie: die verkeerde ciphertext kan toevallig drukbaar lyk. Gebruik minstens drie afsonderlike waarnemings en aanvaar slegs ’n unieke shift wat aanneemlike teks vir almal oplewer. Loop daarna deur die wrapper/declarer-grafiek, versamel elke optelling of aftrekking en teken aan of die numeriese argument eerste kom. Cache hierdie metadata per sample, vervang decoder-oproepe, voeg aangrensende plaintext-stukke saam en export strings afsonderlik vir triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Behou semantiek tydens unflattening

Vir dispatcher-lusse wat deur strings soos `3|2|1|0|4` aangedryf word, decode die order-string, koppel elke state-vergelyking aan sy blok, neem View8 se genegerde-condition-notasie in ag en gee die blokke in dispatcher-volgorde uit. ’n Geneste `continue` kan ’n vroeë sprong terug na die dispatcher verteenwoordig eerder as ’n gewone fall-through. Wanneer die lus verwyder word, delete daardie `continue` en skuif die statements wat oorspronklik ná sy omringende `if` gevolg het na ’n gegenereerde `else`-tak; om bloot die dispatcher te delete, verander die gedrag.<sup>[[1]](#references)</sup>

### Inline proxies, operasies en lazy thunks

Normaliseer forwarding helpers soos `return a0(a1, a2)` voordat jy hul call sites met direkte oproepe vervang. Hanteer wrappers vir subtraction, division, comparison, membership tests of invocation op dieselfde manier. Omdat die helper-verwysing self agter ’n decrypted dictionary key of closure value gestoor kan wees, voer string- en structure-propagation voor en ná inlining uit.<sup>[[1]](#references)</sup>

Herken ook closures wat ’n gestoorde funksie een keer invoke, die verwysing skoonmaak, die resultaat cache en daardie cache tydens latere oproepe teruggee. Deur so ’n thunk by ’n initialization site te collapse, word die onderliggende dispatcher- of capability-funksie blootgelê, maar annoteer dat die oorspronklike uitvoering **eenmalig en gecache** was, eerder as om elke oproep as ’n nuwe invocation te modelleer.<sup>[[1]](#references)</sup>

## Veiligheids- en validasienotas

- Python se `pickle`-laai kan code uitvoer. Laai slegs `.pkl`-lêers wat plaaslik deur die vertroude View8-run gegenereer is; moet nooit ’n sample-supplied pickle as data behandel nie.<sup>[[2]](#references)</sup>
- Pattern-driven passes is nie ’n algemene JavaScript-decompiler nie. Behou onopgeloste expressions en inspekteer handmatig ambigue dispatcher-variante eerder as om ’n rewrite af te dwing.<sup>[[1]](#references)[[2]](#references)</sup>
- LLM-assisted function names is navigasie-hints, nie evidence nie. Process dependencies leaf-first indien jy dit gebruik, maar verifieer elke label teen die body, arguments, strings, data flow, APIs en side effects.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Breek die seël: Statiese deobfuscation van JSCeal se compiled V8 bytecode](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
