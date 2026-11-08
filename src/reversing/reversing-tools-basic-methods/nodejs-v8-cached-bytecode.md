# Statiese Deobfuscation van Node.js/V8-gekashe bytecode

{{#include ../../banners/hacktricks-training.md}}

V8 cached data is ’n **weergawe-afhanklike, verliesgewende voorstelling**, nie JavaScript-bronkode of ’n konvensionele native uitvoerbare lêer nie. ’n Nuttige statiese werksvloei is dus: verwyder enige buitenste verpakking, disassembleer die cache met die ooreenstemmende V8-build, lig dit na ’n intermediêre pseudokodemodel, en pas afhanklikheidsbewuste transformasies toe sonder om die sample uit te voer. [View8](https://github.com/suleram/View8) en [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementeer hierdie benadering vir Node.js-payloads wat deur `javascript-obfuscator` beskerm word.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Kry die cache en disassembleer dit

Inspekteer eers die preload/launcher eerder as om aan te neem dat elke `.jsc`-lêer dieselfde wrapper het. Byvoorbeeld, ’n launcher soos `node.exe -r preflight.js app.jsc` voer `preflight.js` voor die hoofmodule uit; in die ontlede familie het die preload ’n Brotli-laag verwyder. Nadat jy die data uitgepak het, identifiseer die presiese Node.js/V8-generasie aan die hand van die saamgebundelde runtime. ’n Cache wat deur een V8-weergawe geproduseer is, kan deur ’n ander verwerp of verkeerd gedekodeer word; bou of verkry dus ’n `v8dasm` vir daardie presiese V8-tag en pas die vereiste View8- en stringdruk-patches toe.<sup>[[1]](#references)[[2]](#references)</sup>

Die toolkit se nie-uitvoerende werksvloei is:<sup>[[2]](#references)</sup>

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

`--normalize` gee gegenereerde funksies stabiele identifiseerders oor verskillende lopies heen. Die teksuitvoer is vir inspeksie; die geserialiseerde objekgrafiek laat onafhanklike passe toe om funksie-, deklarator-, omvang- en metadata-verhoudings te behou. Dit is **nie gerekonstrueerde of uitvoerbare JavaScript nie**.<sup>[[1]](#references)[[2]](#references)</sup>

### Triageer ’n cache sonder om V8 te bou

Vir ’n rou of Brotli-omhulde cache kan `jscd` die header identifiseer en konstantes en funksies lys sonder om die monster in Node.js te laai. Gebruik dit eerste om na te gaan of die weergawe-tabelle die lêer ondersteun en om funksies te prioritiseer voordat jy die meer gespesialiseerde View8-deobfuskeringspasse uitvoer.<sup>[[4]](#references)</sup>

Die weergawe-hash is ’n identifikasie-aanwysing, nie ’n bewys dat ’n selfstandige disassembler dieselfde vlae of leesalleen-snapshot as die vervaardiger gebruik nie.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` lewer ’n View8-versoenbare lys, dus kan die View8-opdrag hier bo daardie uitvoer in plaas van `v8dasm` gebruik wanneer die cache ondersteun word. Ondersoek stringe saam met die funksieboom om decoder-oproepe en waarskynlike toegangspunte te vind; moenie `jscd` se benaderde JavaScript-uitvoer as die oorspronklike bronkode beskou nie. As die tool die weergawe verwerp of plekhouers vir die read-only heap laat staan, keer terug na ’n ooreenstemmende V8-build of verskaf ’n naamkaart van dieselfde build eerder as om eienskapname te raai.<sup>[[4]](#references)</sup>

Vir ’n cache binne ’n Electron-toepassing, [onttrek eers die ASAR en ondersoek die hoof- en preload-toegangspunte](../../network-services-pentesting/pentesting-web/electron-desktop-apps/). Electron- en Node-caches kan verskil in snapshot- en pointer-compression-uitleg, selfs wanneer hul V8-weergawestringe ooreenstem.<sup>[[4]](#references)</sup>

### Lees View8-pseudokode as ’n IR

Tipiese name is `func_<name>_0x<address>`, argumente is `a0...aN`, virtuele registers is `r0...rN`, en `ACCU` is V8 se accumulator. `start` is die worteldeclarer, terwyl `Scope[...]`, globals en dictionaries waardes modelleer wat deur geneste funksies vasgelê of gedeel word. Moenie elke uitdrukking as JavaScript-sintaksis ontleed nie: View8 se `!r6 === "0"` verteenwoordig byvoorbeeld die ontkenning van die volledige vergelyking (`r6 !== "0"`), wat saak maak wanneer vertakkings herbou word.<sup>[[1]](#references)[[3]](#references)</sup>

## Afhanklikheidsbewuste deobfuscation

Pas transformasies in ’n volgorde toe wat die invoere blootlê wat die volgende pass benodig, en herhaal die voortplanting totdat die uitvoer stabiliseer. ’n Praktiese volgorde is:<sup>[[1]](#references)[[2]](#references)</sup>

1. Loop deur die declarer-hiërargie en propageer waardes vanaf globals, registers, dictionaries en `Scope[...]`-verwysings.
2. Herwin string-decoder-argumente en vervang geënkripteerde oproepe met plaintext.
3. Voeg aangrensende stringstukke saam; die gevolglike eienskapname en dispatcher-volgordestringe ontsluit latere passes.
4. Maak beheer vloei onplat, inline call proxies en atomic-operation wrappers, en bepaal funksieverwysings wat in dictionaries gehou word.
5. Propageer weer omdat elke opgeloste string, sleutel of proxy nog ’n laag indireksie kan blootlê.
6. Vou herkende eenmalige initialiserings-thunks saam en verwyder dooie helpers eers nadat hul oproepplekke opgelos is.

### Herwin verskuifde RC4-string-skikkings as ’n black box

’n Algemene `javascript-obfuscator`-uitleg stoor Base64-geënkodeerde RC4-stukke in een skikking. Decoder-wrappers voorsien ’n numeriese offset en ’n kort sleutel, soms in omgekeerde argumentvolgorde, en tel dan konstantes by wat in closure scopes vasgelê is, of trek dit af. Wanneer die worteldecoder te sterk geobfuskeer is, herwin die onbekende skikkingindeksverskuiwing empiries eerder as om die hele funksie te rekonstrueer.<sup>[[1]](#references)</sup>

Vir ’n skikking van `N` stukke en verskeie oproepe na dieselfde decoder:<sup>[[1]](#references)</sup>

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

Moenie ’n shift aanvaar op grond van ’n enkele leesbare dekripsie nie: die verkeerde ciphertext kan toevallig leesbaar lyk. Gebruik minstens drie onderskeibare waarnemings en aanvaar slegs ’n unieke shift wat vir almal aanneemlike teks oplewer. Volg dan die wrapper/declarer-grafiek, tel elke optelling of aftrekking bymekaar en teken aan of die numeriese argument eerste kom. Kas hierdie metadata per sample, vervang decoder-oproepe, voeg aangrensende plaintext-stukke saam en voer strings afsonderlik uit vir triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Behou semantiek tydens unflattening

Vir dispatcher-lusse wat deur strings soos `3|2|1|0|4` aangedryf word, dekodeer die volgordestring, koppel elke toestandvergelyking aan sy blok, neem View8 se negated-condition-notasie in ag en genereer dan die blokke in dispatcher-volgorde. ’n Geneste `continue` kan ’n vroeë sprong terug na die dispatcher voorstel, eerder as ’n gewone deurgang. Wanneer jy die lus verwyder, skrap daardie `continue` en skuif die stellings wat oorspronklik ná die omringende `if` gevolg het na ’n gegenereerde `else`-vertakking; om bloot die dispatcher te skrap, verander die gedrag.<sup>[[1]](#references)</sup>

### Inline proxies, bewerkings en lazy thunks

Normaliseer aanstuurhelpers soos `return a0(a1, a2)` voordat jy hul oproeppunte met direkte oproepe vervang. Behandel wrappers vir aftrekking, deling, vergelyking, lidmaatskaptoetse of aanroep op dieselfde manier. Omdat die helper-verwysing self agter ’n gedekripteerde dictionary-sleutel of closure-waarde kan wees, voer string- en struktuurpropagasie voor én ná inlining uit.<sup>[[1]](#references)</sup>

Herken ook closures wat ’n gestoorde funksie een keer aanroep, sy verwysing uitvee, die resultaat kas en daardie kas by latere oproepe teruggee. Deur so ’n thunk by ’n initialisasiepunt in te vou, word die onderliggende dispatcher- of capability-funksie sigbaar, maar merk aan dat die oorspronklike uitvoering **eenmalig en gekas** was, eerder as om elke oproep as ’n nuwe aanroep te modelleer.<sup>[[1]](#references)</sup>

## Veiligheids- en valideringsnotas

- Die laai van Python `pickle` kan kode uitvoer. Laai slegs `.pkl`-lêers wat plaaslik deur die vertroude View8-run gegenereer is; moet nooit ’n sample-verskafde pickle as data behandel nie.<sup>[[2]](#references)</sup>
- ’n Ontbrekende funksieliggaam bewys nie dat die bronkode nie daardie funksie bevat het nie: V8 kan ’n lazy-funksie as metadata serialiseer totdat dit met die eerste aanroep gecompileer word. Hou sulke funksies tydens statiese triage as onopgelos gemerk.<sup>[[6]](#references)</sup>
- Patroongedrewe passe is nie ’n algemene JavaScript-decompiler nie. Behou onopgeloste uitdrukkings en inspekteer dubbelsinnige dispatcher-variante met die hand, eerder as om ’n herskrywing af te dwing.<sup>[[1]](#references)[[2]](#references)</sup>
- LLM-ondersteunde funksiename is navigasiewenke, nie bewyse nie. Verwerk afhanklikhede van blare na wortel indien jy dit gebruik, maar verifieer elke etiket aan die hand van die funksieliggaam, argumente, strings, datavloei, API’s en newe-effekte.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Breek die seël: Statiese deobfuskering van JSCeal se gecompileerde V8-bytecode](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [V8 SerializedCodeData-kop](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Node.js vm.Script-kodekas](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
