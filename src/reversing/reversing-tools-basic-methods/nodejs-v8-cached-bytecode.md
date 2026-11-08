# Node.js/V8 Cached Bytecode का Static Deobfuscation

{{#include ../../banners/hacktricks-training.md}}

V8 cached data एक **version-dependent, lossy representation** है, JavaScript source या conventional native executable नहीं। इसलिए एक उपयोगी static workflow यह है: किसी भी outer packing को हटाएँ, matching V8 build से cache को disassemble करें, उसे intermediate pseudocode model में lift करें, और sample को execute किए बिना dependency-aware transformations लागू करें। [View8](https://github.com/suleram/View8) और [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) `javascript-obfuscator` से protected Node.js payloads के लिए यह approach लागू करते हैं।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Cache को प्राप्त करें और disassemble करें

पहले preload/launcher की जाँच करें; यह न मानें कि हर `.jsc` file का wrapper एक जैसा होता है। उदाहरण के लिए, `node.exe -r preflight.js app.jsc` जैसा launcher मुख्य module से पहले `preflight.js` execute करता है; analyzed family में preload ने Brotli layer हटाई। Unpack करने के बाद, bundled runtime से exact Node.js/V8 generation पहचानें। एक V8 version से बनाया गया cache दूसरे version द्वारा reject या गलत तरीके से decode किया जा सकता है, इसलिए उसी सटीक V8 tag के लिए `v8dasm` build या प्राप्त करें और आवश्यक View8 तथा string-printing patches लागू करें।<sup>[[1]](#references)[[2]](#references)</sup>

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

`--normalize` generated functions को runs के बीच स्थिर identifiers देता है। Text output निरीक्षण के लिए है; serialized object graph स्वतंत्र passes को function, declarer, scope और metadata के संबंध बनाए रखने देता है। यह **पुनर्निर्मित या चलाने योग्य JavaScript नहीं है**।<sup>[[1]](#references)[[2]](#references)</sup>

### V8 बनाए बिना cache का triage करें

Raw या Brotli-wrapped cache के लिए, `jscd` sample को Node.js में load किए बिना header की पहचान और constants तथा functions की सूची बना सकता है। पहले इसका उपयोग यह जाँचने के लिए करें कि इसकी version tables फ़ाइल को support करती हैं या नहीं, और अधिक specialized View8 deobfuscation passes से पहले functions को प्राथमिकता देने के लिए।<sup>[[4]](#references)</sup>

Version hash पहचान का संकेत है, इस बात का प्रमाण नहीं कि किसी standalone disassembler में producer जैसे ही flags या read-only snapshot हैं।<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` एक View8-compatible listing emit करता है, इसलिए cache supported होने पर ऊपर दिया गया View8 command, `v8dasm` के बजाय उसके output का उपयोग कर सकता है। Decoder calls और संभावित entry points ढूँढने के लिए strings के साथ function tree का निरीक्षण करें; `jscd` के approximate JavaScript output को original source न मानें। यदि tool version को reject करे या read-only-heap placeholders छोड़ दे, तो property names का अनुमान लगाने के बजाय matching V8 build पर लौटें या उसी build का name map दें।<sup>[[4]](#references)</sup>

Electron application के अंदर cache के लिए, पहले [ASAR extract करें और उसके main तथा preload entry points का निरीक्षण करें](../../network-services-pentesting/pentesting-web/electron-desktop-apps/). Snapshot और pointer-compression layout में Electron तथा Node caches अलग हो सकते हैं, भले ही उनके V8 version strings मेल खाते हों।<sup>[[4]](#references)</sup>

### View8 pseudocode को IR की तरह पढ़ें

आम names `func_<name>_0x<address>` होते हैं, arguments `a0...aN`, virtual registers `r0...rN`, और `ACCU` V8 का accumulator होता है। `start` root declarer है, जबकि `Scope[...]`, globals और dictionaries, nested functions द्वारा captured या साझा किए गए values को दर्शाते हैं। हर expression को JavaScript syntax की तरह parse न करें: उदाहरण के लिए, View8 का `!r6 === "0"` पूरे comparison का negation दर्शाता है (`r6 !== "0"`), जो branches को दोबारा बनाते समय महत्वपूर्ण है।<sup>[[1]](#references)[[3]](#references)</sup>

## Dependency-aware deobfuscation

ऐसे क्रम में transformations लागू करें जिससे अगले pass के लिए आवश्यक inputs सामने आएँ, और propagation को तब तक दोहराएँ जब तक output स्थिर न हो जाए। एक व्यावहारिक क्रम यह है:<sup>[[1]](#references)[[2]](#references)</sup>

1. Declarer hierarchy को traverse करें और globals, registers, dictionaries तथा `Scope[...]` references से values propagate करें।
2. String-decoder arguments recover करें और encrypted calls को plaintext से replace करें।
3. आस-पास के string chunks को fold करें; इससे मिले property names और dispatcher-order strings, अगले passes को संभव बनाते हैं।
4. Control flow को unflatten करें, call proxies और atomic-operation wrappers को inline करें, और dictionary में रखे function references resolve करें।
5. दोबारा propagation करें, क्योंकि हर resolved string, key या proxy indirection की एक और layer उजागर कर सकता है।
6. पहचाने गए one-shot initialization thunks को collapse करें और उनके call sites resolve होने के बाद ही dead helpers हटाएँ।

### Shifted RC4 string arrays को black box की तरह recover करें

एक आम `javascript-obfuscator` layout, एक array में Base64-encoded RC4 chunks रखता है। Decoder wrappers numeric offset और छोटी key देते हैं, कभी-कभी arguments के उलटे क्रम में, फिर closure scopes में captured constants जोड़ते या घटाते हैं। जब root decoder अत्यधिक obfuscated हो, तो पूरे function को reconstruct करने के बजाय empirically उसका अज्ञात array-index shift recover करें।<sup>[[1]](#references)</sup>

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

एक ही printable decryption को स्वीकार न करें: गलत ciphertext संयोग से printable दिख सकता है। कम-से-कम तीन अलग-अलग observations का उपयोग करें और तभी स्वीकार करें जब एकमात्र shift उन सभी के लिए plausible text दे। फिर wrapper/declarer graph को traverse करें, हर addition या subtraction को जोड़ते जाएँ और यह दर्ज करें कि numeric argument पहले आता है या नहीं। इस metadata को हर sample के लिए cache करें, decoder calls को replace करें, पास-पास के plaintext chunks को concatenate करें और triage के लिए strings को अलग से export करें।<sup>[[1]](#references)[[2]](#references)</sup>

### Unflatten करते समय semantics सुरक्षित रखें

`3|2|1|0|4` जैसी strings से चलने वाले dispatcher loops के लिए, order string को decode करें, हर state comparison को उसके block से map करें, View8 की negated-condition notation का ध्यान रखें, फिर blocks को dispatcher के क्रम में emit करें। कोई nested `continue` सामान्य fall-through के बजाय dispatcher पर वापस जाने वाला early jump हो सकता है। Loop हटाते समय, उस `continue` को delete करें और उसके enclosing `if` के बाद मूल रूप से आने वाले statements को generated `else` branch में ले जाएँ; सिर्फ dispatcher delete करने से behavior बदल जाता है।<sup>[[1]](#references)</sup>

### Proxies, operations और lazy thunks को inline करें

`return a0(a1, a2)` जैसे forwarding helpers को उनके call sites को direct calls से replace करने से पहले normalize करें। Subtraction, division, comparison, membership tests या invocation के wrappers को भी इसी तरह लें। चूँकि helper reference खुद किसी decrypted dictionary key या closure value के पीछे stored हो सकता है, inlining से पहले और बाद में string और structure propagation चलाएँ।<sup>[[1]](#references)</sup>

उन closures को भी पहचानें जो किसी stored function को एक बार invoke करते हैं, उसका reference clear करते हैं, result को cache करते हैं और बाद की calls में वह cache लौटाते हैं। Initialization site पर ऐसे thunk को collapse करने से underlying dispatcher या capability function सामने आ जाता है, लेकिन यह annotate करें कि मूल execution **one-shot और cached** था, न कि हर call को fresh invocation मानें।<sup>[[1]](#references)</sup>

## Safety और validation संबंधी नोट्स

- Python `pickle` को load करने से code execute हो सकता है। केवल trusted View8 run से locally generated `.pkl` files ही load करें; sample द्वारा दिया गया pickle कभी भी data न मानें।<sup>[[2]](#references)</sup>
- Function body न मिलना इस बात का प्रमाण नहीं है कि source में वह function था ही नहीं: V8 किसी lazy function को first call पर compile होने तक metadata के रूप में serialize कर सकता है। Static triage के दौरान ऐसे functions को unresolved चिह्नित रखें।<sup>[[6]](#references)</sup>
- Pattern-driven passes सामान्य JavaScript decompiler नहीं हैं। Unresolved expressions को जस का तस रखें और अस्पष्ट dispatcher variants को rewrite करने के लिए बाध्य करने के बजाय उनका manually निरीक्षण करें।<sup>[[1]](#references)[[2]](#references)</sup>
- LLM-assisted function names navigation hints हैं, evidence नहीं। यदि उनका उपयोग कर रहे हैं, तो dependencies को leaf-first process करें; लेकिन हर label को body, arguments, strings, data flow, APIs और side effects के आधार पर verify करें।<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [JSCeal के compiled V8 bytecode के static deobfuscation में सील तोड़ना](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [V8 SerializedCodeData header](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Node.js vm.Script code cache](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
