# Node.js/V8 Cached Bytecode का Static Deobfuscation

{{#include ../../banners/hacktricks-training.md}}

V8 cached data एक **version-dependent, lossy representation** है, JavaScript source या conventional native executable नहीं। इसलिए एक उपयोगी static workflow यह है: सबसे पहले किसी भी outer packing को हटाएँ, matching V8 build से cache को disassemble करें, उसे intermediate pseudocode model में lift करें और sample को execute किए बिना dependency-aware transformations लागू करें। [View8](https://github.com/suleram/View8) और [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) `javascript-obfuscator` से protected Node.js payloads के लिए यह तरीका लागू करते हैं।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Cache प्राप्त करें और उसे disassemble करें

यह मानने के बजाय कि हर `.jsc` file का wrapper एक जैसा है, पहले preload/launcher की जाँच करें। उदाहरण के लिए, `node.exe -r preflight.js app.jsc` जैसा launcher मुख्य module से पहले `preflight.js` execute करता है; विश्लेषित family में preload ने Brotli layer हटाई थी। Unpacking के बाद, bundled runtime से Node.js/V8 की सटीक generation पहचानें। एक V8 version से बना cache दूसरे version द्वारा reject किया जा सकता है या गलत तरीके से decode हो सकता है, इसलिए उसी सटीक V8 tag के लिए `v8dasm` बनाएँ या प्राप्त करें और ज़रूरी View8 तथा string-printing patches लागू करें।<sup>[[1]](#references)[[2]](#references)</sup>

Toolkit का non-executing workflow यह है:<sup>[[2]](#references)</sup>

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

`--normalize` generated functions को अलग-अलग runs में स्थिर identifiers देता है। Text output निरीक्षण के लिए है; serialized object graph स्वतंत्र passes को function, declarer, scope और metadata के संबंध बनाए रखने देता है। यह **पुनर्निर्मित या चलाने योग्य JavaScript नहीं है**।<sup>[[1]](#references)[[2]](#references)</sup>

### V8 बनाए बिना cache का triage करें

Raw या Brotli-wrapped cache के लिए, `jscd` sample को Node.js में load किए बिना header की पहचान कर सकता है और constants तथा functions की सूची बना सकता है। पहले इसका उपयोग यह जाँचने के लिए करें कि इसकी version tables फ़ाइल को support करती हैं या नहीं, और अधिक specialized View8 deobfuscation passes चलाने से पहले functions को प्राथमिकता देने के लिए।<sup>[[4]](#references)</sup>

Version hash पहचान के लिए एक संकेत है, इस बात का प्रमाण नहीं कि standalone disassembler में producer वाले flags या read-only snapshot मौजूद हैं।<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` एक View8-compatible listing जारी करता है, इसलिए ऊपर दिया गया View8 command, cache समर्थित होने पर `v8dasm` के बजाय उस output का उपयोग कर सकता है। Decoder calls और संभावित entry points खोजने के लिए strings को function tree के साथ देखें; `jscd` के अनुमानित JavaScript output को मूल source न मानें। अगर tool version को अस्वीकार करता है या read-only-heap placeholders छोड़ देता है, तो अनुमान से property names तय करने के बजाय मेल खाता V8 build इस्तेमाल करें या उसी build से name map दें।<sup>[[4]](#references)</sup>

Electron application के अंदर मौजूद cache के लिए, पहले [ASAR extract करें और उसके main और preload entry points की जाँच करें](../../desktop-application-security/electron-desktop-apps/). Electron और Node caches के snapshot और pointer-compression layouts अलग हो सकते हैं, भले ही उनके V8 version strings समान हों।<sup>[[4]](#references)</sup>

### View8 pseudocode को IR के रूप में पढ़ें

आम names `func_<name>_0x<address>` होते हैं, arguments `a0...aN` होते हैं, virtual registers `r0...rN` होते हैं, और `ACCU`, V8 का accumulator होता है। `start`, root declarer है, जबकि `Scope[...]`, globals और dictionaries उन values को दर्शाते हैं जिन्हें nested functions ने capture किया है या जो उनके बीच साझा हैं। हर expression को JavaScript syntax के रूप में parse न करें: उदाहरण के लिए, View8 का `!r6 === "0"` पूरे comparison के negation को दर्शाता है (`r6 !== "0"`), जो branches को फिर से बनाते समय महत्वपूर्ण है।<sup>[[1]](#references)[[3]](#references)</sup>

## Dependency-aware deobfuscation

Transformations को ऐसे क्रम में लागू करें जिससे अगले pass के लिए आवश्यक inputs सामने आएँ, और propagation को तब तक दोहराएँ जब तक output स्थिर न हो जाए। एक व्यावहारिक क्रम है:<sup>[[1]](#references)[[2]](#references)</sup>

1. Declarer hierarchy को traverse करें और globals, registers, dictionaries तथा `Scope[...]` references से values propagate करें।
2. String-decoder arguments recover करें और encrypted calls को plaintext से बदलें।
3. पास-पास के string chunks को fold करें; इससे मिलने वाले property names और dispatcher-order strings, बाद के passes को संभव बनाते हैं।
4. Control flow को unflatten करें, call proxies और atomic-operation wrappers को inline करें, और dictionary में रखे function references resolve करें।
5. दोबारा propagation करें, क्योंकि हर resolved string, key या proxy indirection की एक और layer सामने ला सकता है।
6. Recognized one-shot initialization thunks को collapse करें और call sites resolve होने के बाद ही dead helpers हटाएँ।

### Shifted RC4 string arrays को black box की तरह recover करें

`javascript-obfuscator` का एक आम layout, Base64-encoded RC4 chunks को एक array में रखता है। Decoder wrappers एक numeric offset और छोटी key देते हैं, कभी-कभी arguments के उलटे क्रम में, फिर closure scopes में capture किए गए constants जोड़ते या घटाते हैं। जब root decoder बहुत अधिक obfuscated हो, तो पूरा function reconstruct करने के बजाय अज्ञात array-index shift को empirically recover करें।<sup>[[1]](#references)</sup>

`N` chunks वाले array और उसी decoder के कई calls के लिए:<sup>[[1]](#references)</sup>

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

किसी एक printable decryption के आधार पर shift स्वीकार न करें: गलत ciphertext भी संयोग से printable दिख सकता है। कम-से-कम तीन अलग-अलग observations का उपयोग करें और केवल तभी स्वीकार करें जब एक unique shift उन सभी के लिए plausible text दे। इसके बाद wrapper/declarer graph को traverse करें, हर addition या subtraction को जोड़ते जाएँ और यह दर्ज करें कि numeric argument पहले आता है या नहीं। इस metadata को हर sample के लिए cache करें, decoder calls को replace करें, पास-पास के plaintext chunks को concatenate करें और triage के लिए strings को अलग से export करें।<sup>[[1]](#references)[[2]](#references)</sup>

### Unflatten करते समय semantics बनाए रखें

`3|2|1|0|4` जैसी strings से चलने वाले dispatcher loops के लिए, order string को decode करें, हर state comparison को उसके block से map करें, View8 के negated-condition notation का ध्यान रखें, फिर blocks को dispatcher के क्रम में emit करें। कोई nested `continue` साधारण fall-through के बजाय dispatcher पर वापस जाने वाला early jump हो सकता है। Loop हटाते समय, उस `continue` को delete करें और उसके enclosing `if` के बाद मूल रूप से आने वाले statements को एक generated `else` branch में ले जाएँ; केवल dispatcher को delete करने से behavior बदल जाता है।<sup>[[1]](#references)</sup>

### Proxies, operations और lazy thunks को inline करें

Call sites को direct calls से replace करने से पहले, `return a0(a1, a2)` जैसे forwarding helpers को normalize करें। Subtraction, division, comparison, membership tests या invocation के wrappers के साथ भी ऐसा ही करें। चूँकि helper reference खुद किसी decrypted dictionary key या closure value के पीछे stored हो सकता है, inlining से पहले और बाद में string और structure propagation चलाएँ।<sup>[[1]](#references)</sup>

ऐसी closures को भी पहचानें जो किसी stored function को एक बार invoke करती हैं, उसका reference clear करती हैं, result को cache करती हैं और बाद की calls में वह cache return करती हैं। Initialization site पर ऐसे thunk को collapse करने से underlying dispatcher या capability function सामने आता है, लेकिन यह annotate करें कि मूल execution **एक बार चलने वाला और cached** था, न कि हर call को fresh invocation के रूप में model करें।<sup>[[1]](#references)</sup>

## सुरक्षा और validation संबंधी नोट्स

- Python `pickle` लोड करने से code execute हो सकता है। केवल trusted View8 run द्वारा locally generate की गई `.pkl` files लोड करें; sample द्वारा दी गई pickle को कभी data न मानें।<sup>[[2]](#references)</sup>
- Function body का न मिलना इस बात का प्रमाण नहीं है कि source में वह function नहीं था: V8 किसी lazy function को तब तक metadata के रूप में serialize कर सकता है, जब तक उसे पहली call पर compile न किया जाए। Static triage के दौरान ऐसे functions को unresolved चिह्नित रखें।<sup>[[6]](#references)</sup>
- Pattern-driven passes सामान्य JavaScript decompiler नहीं हैं। Unresolved expressions को जस का तस रखें और ambiguous dispatcher variants को rewrite करने के लिए मजबूर करने के बजाय manually inspect करें।<sup>[[1]](#references)[[2]](#references)</sup>
- LLM की मदद से दिए गए function names navigation hints हैं, evidence नहीं। अगर उनका उपयोग कर रहे हैं, तो dependencies को leaf-first process करें; लेकिन हर label को body, arguments, strings, data flow, APIs और side effects से verify करें।<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [सील तोड़ना: JSCeal के Compiled V8 Bytecode का Static Deobfuscation](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [V8 SerializedCodeData header](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Node.js vm.Script code cache](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
