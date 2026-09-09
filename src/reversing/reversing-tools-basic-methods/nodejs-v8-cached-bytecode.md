# Node.js/V8 Cached Bytecode का Static Deobfuscation

{{#include ../../banners/hacktricks-training.md}}

V8 cached data एक **version-dependent, lossy representation** है, JavaScript source नहीं और conventional native executable भी नहीं है। इसलिए एक उपयोगी static workflow यह है: किसी भी outer packing को हटाएँ, matching V8 build के साथ cache को disassemble करें, उसे intermediate pseudocode model में lift करें, और sample को execute किए बिना dependency-aware transformations लागू करें। [View8](https://github.com/suleram/View8) और [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator), `javascript-obfuscator` से protected Node.js payloads के लिए इस approach को implement करते हैं।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Cache को acquire और disassemble करें

सबसे पहले preload/launcher को inspect करें, यह मानने के बजाय कि हर `.jsc` file में एक जैसा wrapper है। उदाहरण के लिए, `node.exe -r preflight.js app.jsc` जैसा launcher main module से पहले `preflight.js` को execute करता है; analyzed family में preload ने एक Brotli layer को हटा दिया था। Unpacking के बाद bundled runtime से exact Node.js/V8 generation identify करें। एक V8 version द्वारा बनाया गया cache दूसरे version द्वारा reject या incorrectly decode किया जा सकता है, इसलिए उस precise V8 tag के लिए `v8dasm` को build या obtain करें और आवश्यक View8 तथा string-printing patches लागू करें।<sup>[[1]](#references)[[2]](#references)</sup>

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
`--normalize` generated functions को अलग-अलग runs में stable identifiers देता है। Text output inspection के लिए है; serialized object graph स्वतंत्र passes को function, declarer, scope और metadata relationships बनाए रखने देता है। यह **reconstructed या runnable JavaScript नहीं है**।<sup>[[1]](#references)[[2]](#references)</sup>

### View8 pseudocode को IR के रूप में पढ़ें

Typical names `func_<name>_0x<address>` होते हैं, arguments `a0...aN`, virtual registers `r0...rN`, और `ACCU` V8 का accumulator है। `start` root declarer है, जबकि `Scope[...]`, globals और dictionaries nested functions द्वारा captured या shared values को model करते हैं। हर expression को JavaScript syntax के रूप में parse न करें: उदाहरण के लिए, View8 का `!r6 === "0"` complete comparison (`r6 !== "0"`) के negation को दर्शाता है, जो branches को फिर से बनाते समय महत्वपूर्ण है।<sup>[[1]](#references)[[3]](#references)</sup>

## Dependency-aware deobfuscation

Transformations को ऐसे क्रम में लागू करें जिससे अगले pass के लिए आवश्यक inputs सामने आएं, और output स्थिर होने तक propagation दोहराएं। एक practical क्रम है:<sup>[[1]](#references)[[2]](#references)</sup>

1. Declarer hierarchy पर चलें और globals, registers, dictionaries और `Scope[...]` references से values propagate करें।
2. String-decoder arguments recover करें और encrypted calls को plaintext से replace करें।
3. आस-पास के string chunks को fold करें; resulting property names और dispatcher-order strings बाद के passes को unlock करते हैं।
4. Control flow को unflatten करें, call proxies और atomic-operation wrappers को inline करें, और dictionary-held function references को resolve करें।
5. फिर से propagate करें, क्योंकि प्रत्येक resolved string, key या proxy indirection की एक और layer सामने ला सकता है।
6. Recognized one-shot initialization thunks को collapse करें और उनके call sites resolve होने के बाद ही dead helpers हटाएं।

### Shifted RC4 string arrays को black box के रूप में recover करें

एक common `javascript-obfuscator` layout एक array में Base64-encoded RC4 chunks store करता है। Decoder wrappers एक numeric offset और short key provide करते हैं, कभी-कभी reversed argument order में, और फिर closure scopes में captured constants को add या subtract करते हैं। जब root decoder बहुत अधिक obfuscated हो, तो पूरी function को reconstruct करने के बजाय उसके unknown array-index shift को empirically recover करें।<sup>[[1]](#references)</sup>

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
एकल printable decryption से प्राप्त shift को स्वीकार न करें: गलत ciphertext संयोग से printable दिखाई दे सकता है। कम-से-कम तीन अलग-अलग observations का उपयोग करें और केवल उस unique shift को स्वीकार करें जो सभी के लिए plausible text उत्पन्न करे। इसके बाद wrapper/declarer graph को traverse करें, हर addition या subtraction को संचित करें और यह रिकॉर्ड करें कि numeric argument पहले आता है या नहीं। इस metadata को प्रत्येक sample के लिए cache करें, decoder calls को replace करें, पास-पास के plaintext chunks को concatenate करें और triage के लिए strings को अलग-अलग export करें।<sup>[[1]](#references)[[2]](#references)</sup>

### unflattening के दौरान semantics सुरक्षित रखें

Strings जैसे `3|2|1|0|4` से संचालित dispatcher loops के लिए, order string को decode करें, प्रत्येक state comparison को उसके block से map करें, View8 के negated-condition notation को ध्यान में रखें, फिर blocks को dispatcher order में emit करें। कोई nested `continue` सामान्य fall-through के बजाय dispatcher पर वापस जाने वाले early jump को दर्शा सकता है। Loop हटाते समय उस `continue` को delete करें और उसके enclosing `if` के बाद मूल रूप से आने वाले statements को generated `else` branch में ले जाएँ; केवल dispatcher को delete करने से behavior बदल जाता है।<sup>[[1]](#references)</sup>

### proxies, operations और lazy thunks को inline करें

`return a0(a1, a2)` जैसे forwarding helpers को normalize करें, फिर उनके call sites को direct calls से replace करें। Subtraction, division, comparison, membership tests या invocation के wrappers के साथ भी ऐसा ही करें। क्योंकि helper reference स्वयं किसी decrypted dictionary key या closure value के पीछे stored हो सकता है, इसलिए inlining से पहले और बाद में string तथा structure propagation चलाएँ।<sup>[[1]](#references)</sup>

ऐसे closures को भी पहचानें जो किसी stored function को एक बार invoke करते हैं, उसका reference clear करते हैं, result को cache करते हैं और बाद की calls पर वह cache return करते हैं। Initialization site पर ऐसे thunk को collapse करने से underlying dispatcher या capability function सामने आ जाता है, लेकिन यह annotate करें कि मूल execution **one-shot and cached** था, न कि हर call को fresh invocation के रूप में model करें।<sup>[[1]](#references)</sup>

## Safety and validation notes

- Python `pickle` loading code execute कर सकता है। केवल trusted View8 run द्वारा locally generated `.pkl` files को load करें; sample-supplied pickle को कभी data न मानें।<sup>[[2]](#references)</sup>
- Pattern-driven passes general JavaScript decompiler नहीं हैं। Unresolved expressions को सुरक्षित रखें और ambiguous dispatcher variants का manually निरीक्षण करें, rewrite को जबरन लागू न करें।<sup>[[1]](#references)[[2]](#references)</sup>
- LLM-assisted function names navigation hints हैं, evidence नहीं। यदि उनका उपयोग कर रहे हैं, तो dependencies को leaf-first process करें, लेकिन प्रत्येक label को body, arguments, strings, data flow, APIs और side effects के विरुद्ध verify करें।<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [JSCeal के Compiled V8 Bytecode की Static Deobfuscation: Breaking the Seal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
