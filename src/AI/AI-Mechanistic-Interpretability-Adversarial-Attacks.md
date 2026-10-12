# Mechanistic Interpretability-निर्देशित Adversarial Attacks

{{#include ../banners/hacktricks-training.md}}

## Superposition एक attack surface के रूप में

कम पैरामीटर वाले activation space में features को non-orthogonal vectors पर असाइन करके, उसकी dimensions से अधिक semantic features encode किए जा सकते हैं। परिणामस्वरूप, सक्रिय feature अन्य feature directions पर भी project होता है। Training, in-distribution में दिखने वाले combinations की भरपाई कर सकती है, लेकिन अन्यथा valid features का कोई असामान्य combination, target feature की direction में constructively जुड़ सकता है—भले ही वह feature input में मौजूद न हो।<sup>[[1]](#references)[[2]](#references)</sup>

Feature vectors `v_i ∈ R^D`, activations `a_i` और target `t` के लिए, candidate combinations खोजने में निम्नलिखित magnitude उपयोगी है:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

यह केवल एक screening heuristic है। किसी exploit में signs और magnitudes बनाए रखने होंगे और वास्तविक decoder का मूल्यांकन करना होगा, उदाहरण के लिए tied-weight linear decoder में `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))`। Negative terms हमले को निष्प्रभावी कर सकते हैं, जबकि decoder bias, feature-vector norms, activation thresholds और ReLU gating किसी बड़े absolute cosine score को target activation में बदलने से रोक सकते हैं।<sup>[[1]](#references)</sup>

## White-box attack workflow

व्यावहारिक आकलन में model bottleneck, sparse autoencoder (SAE), या किसी अन्य interpretable feature dictionary का उपयोग किया जा सकता है। उद्देश्य केवल final class बदलना नहीं है: उद्देश्य यह है कि reconstruction एक चुना हुआ internal feature पेश करे, जो compression से पहले active नहीं था। प्रस्तावित workflow यह है:<sup>[[1]](#references)</sup>

1. **Feature directions प्राप्त करें:** संबंधित encoder/decoder vectors निकालें, dead features हटाएँ, और maximally activating samples या feature-circuit analysis का उपयोग करके active directions को concepts से जोड़ें।
2. **Interference को क्रम दें:** vectors की एक copy को normalize करें, उनकी cosine-similarity matrix निकालें, diagonal साफ़ करें, और target के सबसे मज़बूत off-diagonal neighbours देखें। वास्तविक activation magnitudes और signed raw dot products के साथ candidates की फिर से गणना करें।
3. **Co-activation सुनिश्चित करें:** ऐसे positively contributing features का छोटा set रखें जिन्हें एक ही layer या residual stream में activate किया जा सके। ऐसे combinations को प्राथमिकता दें जो training data में दुर्लभ हों या मौजूद न हों; सामान्य correlated combinations की भरपाई training के दौरान होने की संभावना अधिक होती है।
4. **Input synthesize करें:** चुने हुए contributors के लिए dataset examples या activation-maximizing patterns को मिलाएँ। Bounded linear pixel detector के लिए, positive weight वाले pixel को high और negative weight वाले pixel को low सेट करें, फिर बने हुए patterns को overlay करें। In-distribution structure और inhibitory **negative space** को हाथ से बनाए रखने से असंबंधित features दब सकते हैं।
5. **Mechanism सत्यापित करें:** एक ही forward pass में compression से पहले के activations, compressed coordinates, reconstructed activations और downstream output रिकॉर्ड करें। सफल test में target reconstruction से पहले inactive और बाद में active दिखना चाहिए; साथ ही, contributors को ablate करने पर अनुमानित बदलाव गायब हो जाना चाहिए।

निम्नलिखित न्यूनतम triage ऐसे tied-weight decoder के contributors को क्रम देता है, जिसकी **rows** feature vectors हैं (यदि features columns में हों, तो पहले transpose करें)। Signed score के लिए raw weights और केवल cosine ranking के लिए normalized weights का उपयोग करें।<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

Cosine similarity के आधार पर अकेले exploitability का अनुमान न लगाएँ। Bias और non-linearity सहित पूरे decoder का परीक्षण करें, पुष्टि करें कि contributors वास्तव में एक साथ आ सकते हैं, और इसकी तुलना समान in-distribution combinations से करें। मिलती-जुलती directions, exploitable packing interference के बजाय वैध semantic relationship encode कर सकती हैं।<sup>[[1]](#references)</sup>

## प्रदर्शित toy-model attack

Proof of concept में जानबूझकर ऐसा interpretable MNIST classifier इस्तेमाल किया गया था, जिसकी दो branches थीं। एक branch में sparse 128-dimensional ReLU feature vector को सीधे classify किया गया, जबकि दूसरी में उसे two-dimensional superposition space में compress किया गया; उसी classifier ने original और reconstructed features, दोनों को process किया।<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

दो feature directions, जो 3/0-जैसी आकृतियों से जुड़े हैं, ज्यामितीय रूप से class-5 directions से घिरे थे। उनके अधिकतम activation वाले images जोड़ने से compression से पहले वे contributor features सबसे मज़बूत बने, लेकिन reconstruction ने कई class-5 features को activate किया और superposition branch ने 5 का अनुमान लगाया। केवल न्यूनतम/अधिकतम pixel values का उपयोग करने वाले हाथ से बनाए गए input ने भी यही प्रभाव दोहराया, जिससे पता चला कि इस toy setting में सटीक gradient-optimized pixel perturbations की आवश्यकता नहीं थी।<sup>[[1]](#references)</sup>

## बड़े मॉडल की ज्यामितीय छँटाई

पेपर ने Gemma Scope `layer 20 / width 65k / average L0 20` SAE की भी जाँच की। इसमें unit-normalized decoder matrix को उसके transpose से गुणा किया, diagonal को साफ़ किया, हर feature के neighbours को क्रमबद्ध किया और rank के अनुसार औसत निकाला। सबसे मज़बूत neighbour की औसत cosine similarity `0.49` थी, जबकि 27वें neighbour की औसत similarity `0.25` थी; ज्यामितीय रूप से, ऐसी चार directions एक unit target projection से मेल खा सकती थीं। ये आँकड़े केवल संभावित उम्मीदवारों की पहचान करते हैं—वे यह नहीं दिखाते कि चार उपयुक्त features को एक साथ activate किया जा सकता है या target अपने decoder threshold को पार करता है।<sup>[[1]](#references)</sup>

## दायरा और सीमाएँ

यह research-stage **white-box** तकनीक है, किसी deployed CNN या frontier LLM के विरुद्ध प्रदर्शित attack नहीं। इसके लिए superposition, उपयोगी non-orthogonal directions, आंतरिक features तक interpretable access, contributors को नियंत्रित रूप से activate करने की क्षमता और एक forward pass के दौरान एक ही layer में उनका साथ इकट्ठा होना आवश्यक है।<sup>[[1]](#references)</sup>

Image MLPs में feature composition असामान्य रूप से सीधा होता है। Transformer अधिक कठिन है, क्योंकि attention को चुने गए feature activations को एक ही residual stream में इकट्ठा करना पड़ता है; पेपर यह नहीं दिखाता कि out-of-distribution combination के लिए ऐसा कैसे बाध्य किया जाए। इसलिए behavioural या refusal directions, physical vision systems या frontier models में हेरफेर करने के दावे अभी परिकल्पनाएँ ही हैं।<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — Superposition में Feature Interference के ज़रिए Interpretable Adversarial Attacks की प्रारंभिक जाँच (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Superposition में Interpretable Adversarial Attacks](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
