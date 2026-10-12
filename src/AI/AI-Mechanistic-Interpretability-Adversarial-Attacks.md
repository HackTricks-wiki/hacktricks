# Mashambulizi ya Adversarial Yanayoongozwa na Mechanistic Interpretability

{{#include ../banners/hacktricks-training.md}}

## Superposition kama eneo la kushambulia

Nafasi ya activation yenye vigezo vichache inaweza kusimba vipengele vingi zaidi vya kisemantiki kuliko ilivyo na vipimo, kwa kuwakilisha vipengele kwa vekta zisizo orthogonal. Kwa hivyo, kipengele kilichoamilishwa pia hujiprojeka kwenye mielekeo ya vipengele vingine. Mafunzo yanaweza kufidia michanganyiko inayoonekana ndani ya usambazaji, lakini mchanganyiko usio wa kawaida wa vipengele halali vinginevyo unaweza kujumlishwa kwa njia ya kuongeza katika mwelekeo wa kipengele lengwa ambacho hakipo kwenye ingizo.<sup>[[1]](#references)[[2]](#references)</sup>

Kwa vekta za vipengele `v_i ∈ R^D`, activation `a_i`, na lengwa `t`, ukubwa ufuatao ni muhimu katika kutafuta michanganyiko inayoweza kufaa:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

Hii ni heuristic ya uchunguzi wa awali pekee. Exploit lazima ihifadhi ishara na ukubwa wa thamani na itathmini decoder halisi, kwa mfano `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` katika linear decoder yenye uzito unaoshirikiwa. Thamani hasi zinaweza kufuta shambulio, ilhali bias ya decoder, norms za feature vector, activation thresholds na ReLU gating zinaweza kuzuia cosine score kubwa kabisa kutoa target activation.<sup>[[1]](#references)</sup>

## Mtiririko wa kazi wa shambulio la White-box

Tathmini ya vitendo inaweza kutumia model bottleneck, sparse autoencoder (SAE), au feature dictionary nyingine inayotafsiriwa. Lengo si kubadilisha tu class ya mwisho: ni kufanya reconstruction iingize feature ya ndani iliyochaguliwa ambayo haikuwa active kabla ya compression. Mtiririko wa kazi unaopendekezwa ni:<sup>[[1]](#references)</sup>

1. **Pata mwelekeo wa feature:** toa encoder/decoder vectors husika, ondoa dead features, na husisha active directions na concepts kwa kutumia samples zinazoamilisha zaidi au uchanganuzi wa feature-circuit.
2. **Panga interference:** normalize nakala ya vectors, hesabu cosine-similarity matrix yake, futa diagonal, kisha kagua majirani wenye off-diagonal values kubwa zaidi wa target. Kokotoa upya candidates kwa kutumia activation magnitudes halisi na signed raw dot products.
3. **Hakikisha co-activation:** hifadhi seti ndogo ya features zinazochangia kwa njia chanya ambazo zinaweza kuamilishwa katika layer au residual stream moja. Pendelea combinations ambazo ni nadra au hazipo katika training data; combinations za kawaida zilizo correlated zina uwezekano mkubwa zaidi wa kuwa tayari zimerekebishwa wakati wa training.
4. **Tengeneza input:** changanya mifano ya dataset au patterns zinazoongeza activation zaidi kwa selected contributors. Kwa bounded linear pixel detector, weka pixel juu kwa weight chanya na chini kwa weight hasi, kisha weka patterns zilizopatikana juu ya nyingine. Kuhifadhi manually muundo wa in-distribution na **negative space** inayozuia activation kunaweza kukandamiza features zisizohusiana.
5. **Thibitisha utaratibu:** rekodi activations kabla ya compression, compressed coordinates, reconstructed activations, na downstream output katika forward pass moja. Jaribio limefaulu ikiwa target haijaamilishwa kabla ya reconstruction lakini inaamilishwa baada yake, na mabadiliko yaliyotabiriwa yanatoweka contributors zinapoondolewa kwa ablation.

Triage ifuatayo ya msingi hupanga contributors kwa tied-weight decoder ambayo **rows** zake ni feature vectors (fanya transpose kwanza ikiwa features ni columns). Tumia raw weights kwa signed score na normalized weights kwa cosine ranking pekee.<sup>[[1]](#references)</sup>

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

Usihitimishe kuwa kuna uwezekano wa exploit kutokana na cosine similarity pekee. Jaribu decoder nzima pamoja na bias na non-linearity yake, thibitisha kuwa wachangiaji wanaweza kutokea pamoja, na ulinganishe na michanganyiko inayolingana iliyo ndani ya distribution. Mielekeo inayofanana inaweza kusimba uhusiano halali wa kisemantiki badala ya interference inayoweza kutumiwa vibaya katika packing.<sup>[[1]](#references)</sup>

## Shambulio la toy model lililoonyeshwa

Proof of concept ilitumia classifier ya MNIST iliyoundwa kwa makusudi ili iwe rahisi kufasirika, ikiwa na matawi mawili. Katika tawi moja, vector ya sparse ya vipengele vya ReLU yenye vipimo 128 iliainishwa moja kwa moja; katika jingine, ilibanwa na kuwekwa katika superposition space yenye vipimo viwili. Classifier ileile ilichakata vipengele vya awali na vilivyoundwa upya.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

Maelekezo mawili ya feature yanayohusishwa na maumbo yanayofanana na 3/0 yalizungukwa kijiometri na maelekezo ya class-5. Kuongeza picha zake zinazowasha feature hizo kwa kiwango cha juu kulifanya feature hizo zinazochangia ziwe na nguvu zaidi kabla ya compression, lakini reconstruction iliwasha feature kadhaa za class-5 na tawi la superposition likatabiri 5. Input iliyochorwa kwa mkono na kutumia tu thamani za chini/juu kabisa za pikseli ilizalisha athari hiyo hiyo, ikionyesha kuwa perturbations za pikseli zilizoboreshwa kwa gradient kwa usahihi hazikuhitajika katika hali hii ya toy.<sup>[[1]](#references)</sup>

## Uchujaji wa kijiometri kwa modeli kubwa zaidi

Jarida pia lilichunguza Gemma Scope `layer 20 / width 65k / average L0 20` SAE. Lilizidisha matrix ya decoder iliyonormalishwa kwa urefu wa unit kwa transpose yake, likaweka diagonal kuwa sifuri, likapanga majirani wa kila feature, kisha likakokotoa wastani kulingana na nafasi ya jirani. Cosine similarity ya wastani ya jirani mwenye nguvu zaidi ilikuwa `0.49`, ilhali similarity ya wastani ya jirani wa 27 ilikuwa `0.25`; kijiometri, maelekezo manne ya aina hiyo yangeweza kulingana na projection moja ya unit lengwa. Takwimu hizi hutambua wagombea pekee—hazionyeshi kuwa feature nne zinazofaa zinaweza kuwashwa kwa pamoja au kuwa lengwa linavuka kizingiti chake cha decoder.<sup>[[1]](#references)</sup>

## Wigo na mipaka

Hii ni mbinu ya hatua ya utafiti ya **white-box**, si shambulio lililoonyeshwa dhidi ya CNN iliyosambazwa au LLM ya frontier. Inahitaji superposition, maelekezo yasiyo orthogonal yanayofaa, ufikiaji unaoweza kufasirika wa feature za ndani, uwezo wa kudhibiti uwashaji wa feature zinazochangia, na feature hizo kukusanywa katika layer moja wakati wa forward pass moja.<sup>[[1]](#references)</sup>

Image MLPs hufanya utungaji wa feature uwe wa moja kwa moja kuliko kawaida. Transformer ni ngumu zaidi kwa sababu attention lazima ikusanye uwasishaji wa feature zilizochaguliwa katika residual stream ileile; jarida halionyeshi jinsi ya kulazimisha hili kwa mchanganyiko wa out-of-distribution. Kwa hiyo, madai kuhusu kudhibiti maelekezo ya tabia au refusal, mifumo ya vision halisi, au modeli za frontier bado ni dhana.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — A Preliminary Investigation Into Interpretable Adversarial Attacks Through Feature Interference in Superposition (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Interpretable Adversarial Attacks in Superposition](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
