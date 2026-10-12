# Proof Assistant और Formal Verification की सुरक्षा

{{#include ../banners/hacktricks-training.md}}

Proof assistants एक ही term को कई paths से execute कर सकते हैं: kernel reduction, interpreter, generated code, runtime primitives या external checker। किसी proof की मजबूती उतनी ही होती है जितनी उन सभी components की, जिन्हें trusted results देने की अनुमति है। Lean में native decision procedures तेज़ evaluation के बदले बड़ा trusted computing base (TCB) लाते हैं: compiler और native implementations वाली definitions, proof integrity के लिए प्रासंगिक हो जाती हैं।<sup>[[3]](#references)</sup>

## Logical/native differential evaluation

उन primitives को प्राथमिकता दें जिनका executable implementation उनके logical model से अलग है (उदाहरण के लिए compiler intrinsics, foreign-function interfaces, runtime overrides और `@[implemented_by]` से चिह्नित definitions)। **उसी closed term** को logical और compiled paths के ज़रिए differential रूप से evaluate करें, और value, exception या termination में किसी भी mismatch को security finding मानें।<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

उपयोगी boundary-value classes में शामिल हैं:<sup>[[1]](#references)[[4]](#references)</sup>

- `0`, input length, machine-word limit के आसपास के indexes, और `2^63` या उससे बड़ी values;
- शून्य/एक-byte ranges, `start = end`, `start > end`, और object से बहुत आगे की positions;
- खाली और गैर-खाली inputs, multibyte strings, invalid boundaries, और ऐसी arithmetic जो compiled होने पर truncate हो सकती है;
- heap-backed values, जब किसी native primitive में ownership या borrowing का ऐसा behavior हो जो logical model में मौजूद न हो।

नीचे दिया गया संक्षिप्त Lean pattern, `String.Pos.Raw.extract` में मिली समस्या दिखाता है: vulnerable native code ने बहुत बड़ी one-byte range के लिए मूल string लौटा दी, जबकि definitional reduction ने empty string लौटाई। इस semantic mismatch को संबंधित memory-safety defect से अलग ठीक किया गया था।<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

```lean
def value : String := "non-empty"
def startPos : String.Pos.Raw := ⟨2^63⟩
def endPos : String.Pos.Raw := ⟨2^63 + 1⟩

example : False := by
  have logical : String.Pos.Raw.extract value startPos endPos = "" := rfl
  have native : String.Pos.Raw.extract value startPos endPos = value := by
    native_decide
  exact (by decide) (logical.symm.trans native)
```

यह पैटर्न strings से आगे भी लागू होता है: यदि logical evaluation से `E = A` सिद्ध होता है और trusted native evaluation से `E = B`, तो transitivity से `A = B` मिलता है। जब `A` और `B` प्रेक्षणीय रूप से अलग हों, तो इससे `False` निकलता है; फिर `False.elim` (explosion principle) से कोई भी लक्षित proposition सिद्ध किया जा सकता है। Kernel में गलत reduction rule होना आवश्यक नहीं है—integrity failure इसलिए होता है क्योंकि compiler-backed नतीजा किसी axiom के ज़रिए logic में दाखिल हुआ।<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Lean में विस्तारित TCB का ऑडिट

किसी untrusted proof के एकमात्र validation के रूप में editor के checkmarks या successful build का उपयोग न करें। `#print axioms` से हर security-critical theorem की पूरी dependency closure की जाँच करें; Lean के validation guidance में `_native` नामों को native-evaluation dependencies, `sorryAx` को अधूरे proof और अन्य nonstandard नामों को custom axioms के रूप में पहचाना गया है।<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

उदाहरण के लिए, निम्नलिखित जैसी जनरेट की गई निर्भरता का अर्थ है कि कंपाइल किए गए execution ने ऐसा अनुमानित परिणाम दिया, जो केवल kernel reduction से निकला प्रमाण नहीं था:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Source की समीक्षा के दौरान native decision procedures और स्पष्ट escape hatches खोजें, लेकिन परिणाम की पुष्टि `#print axioms` से करें, क्योंकि dependencies अप्रत्यक्ष या generated हो सकती हैं:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Finding की triage करते समय इन layers में अंतर करें:<sup>[[3]](#references)</sup>

1. **कथन की अखंडता:** जाँचें कि notation, type-class instances, imports और definitions इच्छित दावे को व्यक्त करते हैं।
2. **Proof dependencies:** अप्रत्याशित axioms को अस्वीकार करें या उनकी स्पष्ट समीक्षा करें, खासकर generated native-evaluation axioms की।
3. **Kernel replay:** `lake build` के बाद, `.olean` files से declarations को दोबारा चलाने के लिए `lean4checker --fresh <Module>` चलाएँ।
4. **शत्रुतापूर्ण proof का सत्यापन:** untrusted code को sandbox में build करें और trusted challenge statement के विरुद्ध external checkers का उपयोग करने के लिए `lake comparator` चलाएँ।

`lean4checker` defense in depth प्रदान करता है, लेकिन यह `.olean` files की structural correctness पर भरोसा करता है, और untrusted Lean meta-code चलाने से checking environment स्वयं compromise हो सकता है। High-risk proofs के लिए, comparator proof को sandbox के बाहर export करता है, कथन को trusted challenge के विरुद्ध जाँचता है, और उसे स्वतंत्र रूप से implemented checkers के ज़रिए दोबारा चला सकता है; implementation diversity से यह संभावना कम होती है कि compiler, runtime या kernel की कोई एक खामी हर जगह एक ही गलत नतीजे को validate कर दे।<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract` के model/runtime mismatch और use-after-free - Lean issue #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [`String.Pos.Raw.extract` के model/runtime mismatch का सुधार - Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Lean Language Reference: Lean proof का सत्यापन](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [Fermat के Last Theorem का ऐसा “Proof” जो हाशिये में समा जाए](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
