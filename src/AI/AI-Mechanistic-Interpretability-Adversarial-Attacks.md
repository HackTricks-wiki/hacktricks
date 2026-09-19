# Mechanistic-Interpretability-Guided Adversarial Attacks

{{#include ../banners/hacktricks-training.md}}

## Superposition as an attack surface

An under-parameterised activation space can encode more semantic features than it has dimensions by assigning features to non-orthogonal vectors. Consequently, an activated feature also projects onto other feature directions. Training can compensate for combinations seen in-distribution, but an unusual combination of otherwise valid features may add constructively in the direction of a target feature that is absent from the input.<sup>[[1]](#references)[[2]](#references)</sup>

For feature vectors `v_i ∈ R^D`, activations `a_i`, and target `t`, the following magnitude is useful for finding candidate combinations:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

This is only a screening heuristic. An exploit must retain the signs and magnitudes and evaluate the real decoder, for example `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` in a tied-weight linear decoder. Negative terms can cancel the attack, while decoder bias, feature-vector norms, activation thresholds, and ReLU gating can prevent a large absolute cosine score from producing the target activation.<sup>[[1]](#references)</sup>

## White-box attack workflow

A practical assessment can use a model bottleneck, a sparse autoencoder (SAE), or another interpretable feature dictionary. The objective is not merely to change the final class: it is to make reconstruction introduce a chosen internal feature that was not active before compression. The proposed workflow is:<sup>[[1]](#references)</sup>

1. **Recover feature directions:** extract the relevant encoder/decoder vectors, remove dead features, and map active directions to concepts using maximally activating samples or feature-circuit analysis.
2. **Rank interference:** normalize a copy of the vectors, calculate their cosine-similarity matrix, clear the diagonal, and inspect the strongest off-diagonal neighbours of the target. Recalculate candidates with actual activation magnitudes and signed raw dot products.
3. **Enforce co-activation:** retain a small set of positively contributing features that can be activated in the same layer or residual stream. Prefer combinations rare or absent in training data; ordinary correlated combinations are more likely to have been compensated for during training.
4. **Synthesize the input:** combine dataset examples or activation-maximizing patterns for the selected contributors. For a bounded linear pixel detector, set a pixel high for a positive weight and low for a negative weight, then overlay the resulting patterns. Manually preserving in-distribution structure and inhibitory **negative space** can suppress unrelated features.
5. **Verify the mechanism:** record activations before compression, the compressed coordinates, reconstructed activations, and downstream output in one forward pass. A successful test shows the target inactive before reconstruction but active afterwards, with the predicted change disappearing when contributors are ablated.

The following minimal triage ranks contributors for a tied-weight decoder whose **rows** are feature vectors (transpose first when features are columns). Use raw weights for the signed score and normalized weights only for cosine ranking.<sup>[[1]](#references)</sup>

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

Do not infer exploitability from cosine similarity alone. Test the full decoder with its bias and non-linearity, confirm that the contributors can actually co-occur, and compare against matched in-distribution combinations. Similar directions may encode a legitimate semantic relationship rather than exploitable packing interference.<sup>[[1]](#references)</sup>

## Demonstrated toy-model attack

The proof of concept used a deliberately interpretable MNIST classifier with two branches. A sparse 128-dimensional ReLU feature vector was classified directly in one branch and compressed into a two-dimensional superposition space in the other; the same classifier processed both the original and reconstructed features.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

Two feature directions associated with 3/0-like shapes geometrically enclosed class-5 directions. Adding their maximally activating images made those contributor features strongest before compression, but reconstruction activated several class-5 features and the superposition branch predicted 5. A hand-drawn input using only minimum/maximum pixel values reproduced the effect, showing that exact gradient-optimized pixel perturbations were not required in this toy setting.<sup>[[1]](#references)</sup>

## Larger-model geometric triage

The paper also examined the Gemma Scope `layer 20 / width 65k / average L0 20` SAE. It multiplied the unit-normalized decoder matrix by its transpose, cleared the diagonal, sorted each feature's neighbours, and averaged by rank. The mean strongest-neighbour cosine similarity was `0.49`, while the mean 27th-neighbour similarity was `0.25`; geometrically, four such directions could match one unit target projection. These figures identify candidates only—they do not show that four suitable features can be jointly activated or that the target crosses its decoder threshold.<sup>[[1]](#references)</sup>

## Scope and limitations

This is a research-stage **white-box** technique, not a demonstrated attack against a deployed CNN or frontier LLM. It requires superposition, useful non-orthogonal directions, interpretable access to internal features, controllable activation of the contributors, and their collection in the same layer during one forward pass.<sup>[[1]](#references)</sup>

Image MLPs make feature composition unusually direct. A transformer is harder because attention must gather the chosen feature activations into the same residual stream; the paper does not show how to force this for an out-of-distribution combination. Claims about manipulating behavioural or refusal directions, physical vision systems, or frontier models therefore remain hypotheses.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — A Preliminary Investigation Into Interpretable Adversarial Attacks Through Feature Interference in Superposition (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Interpretable Adversarial Attacks in Superposition](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)

{{#include ../banners/hacktricks-training.md}}
