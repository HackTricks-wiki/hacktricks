# Attaques adversariales guidées par l’interprétabilité mécaniste

{{#include ../banners/hacktricks-training.md}}

## La superposition comme surface d’attaque

Un espace d’activations sous-paramétré peut encoder davantage de caractéristiques sémantiques qu’il n’a de dimensions en associant les caractéristiques à des vecteurs non orthogonaux. Par conséquent, une caractéristique activée se projette également sur d’autres directions de caractéristiques. L’entraînement peut compenser les combinaisons observées dans la distribution, mais une combinaison inhabituelle de caractéristiques par ailleurs valides peut renforcer la projection dans la direction d’une caractéristique cible absente de l’entrée.<sup>[[1]](#references)[[2]](#references)</sup>

Pour des vecteurs de caractéristiques `v_i ∈ R^D`, des activations `a_i` et une cible `t`, la grandeur suivante permet de trouver des combinaisons candidates :<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

Ceci n’est qu’une heuristique de présélection. Un exploit doit conserver les signes et les magnitudes et évaluer le véritable décodeur, par exemple `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` dans un décodeur linéaire à poids liés. Les termes négatifs peuvent annuler l’attaque, tandis que le biais du décodeur, les normes des vecteurs de caractéristiques, les seuils d’activation et le gating ReLU peuvent empêcher un score cosinus absolu élevé de produire l’activation cible.<sup>[[1]](#references)</sup>

## Workflow d’attaque White-box

Une évaluation pratique peut utiliser un goulot d’étranglement du modèle, un autoencodeur parcimonieux (SAE) ou un autre dictionnaire de caractéristiques interprétable. L’objectif n’est pas simplement de changer la classe finale : il s’agit de faire en sorte que la reconstruction introduise une caractéristique interne choisie, qui n’était pas active avant la compression. Le workflow proposé est le suivant :<sup>[[1]](#references)</sup>

1. **Récupérer les directions des caractéristiques :** extraire les vecteurs pertinents de l’encodeur et du décodeur, supprimer les caractéristiques mortes et associer les directions actives à des concepts à l’aide d’exemples qui les activent au maximum ou d’une analyse des circuits de caractéristiques.
2. **Classer les interférences :** normaliser une copie des vecteurs, calculer leur matrice de similarité cosinus, mettre la diagonale à zéro et examiner les voisins hors diagonale les plus proches de la cible. Recalculer les candidats à partir des magnitudes d’activation réelles et des produits scalaires bruts signés.
3. **Forcer la coactivation :** conserver un petit ensemble de caractéristiques contributrices positives pouvant être activées dans la même couche ou le même flux résiduel. Privilégier les combinaisons rares ou absentes des données d’entraînement ; les combinaisons corrélées ordinaires ont plus de chances d’avoir été compensées pendant l’entraînement.
4. **Synthétiser l’entrée :** combiner des exemples du jeu de données ou des motifs maximisant l’activation pour les caractéristiques contributrices sélectionnées. Pour un détecteur linéaire de pixels bornés, régler un pixel à une valeur élevée pour un poids positif et à une valeur faible pour un poids négatif, puis superposer les motifs obtenus. Préserver manuellement la structure des données d’entraînement et l’**espace négatif** inhibiteur peut supprimer les caractéristiques sans rapport.
5. **Vérifier le mécanisme :** enregistrer les activations avant la compression, les coordonnées compressées, les activations reconstruites et la sortie en aval lors d’une même passe avant. Un test réussi montre que la cible est inactive avant la reconstruction, mais active après celle-ci, et que le changement prédit disparaît lorsqu’on procède à l’ablation des caractéristiques contributrices.

Le triage minimal suivant classe les caractéristiques contributrices pour un décodeur à poids liés dont les **lignes** sont les vecteurs de caractéristiques (transposer d’abord si les caractéristiques sont en colonnes). Utiliser les poids bruts pour le score signé et les poids normalisés uniquement pour le classement cosinus.<sup>[[1]](#references)</sup>

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

Ne déduisez pas l’exploitabilité de la seule similarité cosinus. Testez le décodeur complet avec son biais et sa non-linéarité, vérifiez que les contributeurs peuvent effectivement coexister et comparez-les à des combinaisons comparables issues de la distribution. Des directions similaires peuvent encoder une relation sémantique légitime plutôt qu’une interférence exploitable due à l’empaquetage.<sup>[[1]](#references)</sup>

## Attaque démontrée sur un modèle jouet

La preuve de concept utilisait un classificateur MNIST délibérément interprétable, composé de deux branches. Dans l’une, un vecteur de caractéristiques ReLU creux de 128 dimensions était directement classé ; dans l’autre, il était compressé dans un espace de superposition à deux dimensions. Le même classificateur traitait les caractéristiques originales et reconstruites.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

Deux directions de features associées à des formes proches de 3/0 étaient géométriquement enfermées par des directions de classe 5. L’ajout de leurs images à activation maximale rendait ces features contributrices dominantes avant compression, mais la reconstruction activait plusieurs features de classe 5, et la branche de superposition prédisait 5. Une entrée dessinée à la main n’utilisant que les valeurs de pixel minimales et maximales reproduisait l’effet, montrant que des perturbations de pixels optimisées exactement par gradient n’étaient pas nécessaires dans ce cadre jouet.<sup>[[1]](#references)</sup>

## Triage géométrique sur des modèles plus grands

L’article a également étudié le SAE Gemma Scope `layer 20 / width 65k / average L0 20`. Il a multiplié la matrice du décodeur à vecteurs normalisés par sa transposée, mis la diagonale à zéro, trié les voisins de chaque feature, puis calculé la moyenne par rang. La similarité cosinus moyenne avec le voisin le plus proche était de `0.49`, tandis que celle avec le 27e voisin était de `0.25` ; géométriquement, quatre directions de ce type pouvaient égaler la projection d’une cible unitaire. Ces chiffres ne font qu’identifier des candidats : ils ne montrent pas que quatre features adaptées peuvent être activées conjointement, ni que la cible dépasse son seuil de décodage.<sup>[[1]](#references)</sup>

## Portée et limites

Il s’agit d’une technique au stade de la recherche en **white-box**, et non d’une attaque démontrée contre un CNN déployé ou un LLM de pointe. Elle nécessite une superposition, des directions non orthogonales utiles, un accès interprétable aux features internes, la possibilité de contrôler l’activation des features contributrices et leur présence dans la même couche au cours d’une seule passe avant.<sup>[[1]](#references)</sup>

Les MLP d’images rendent la composition de features particulièrement directe. Un transformer est plus difficile à manipuler, car l’attention doit rassembler les activations des features choisies dans le même flux résiduel ; l’article ne montre pas comment forcer cela pour une combinaison hors distribution. Les affirmations concernant la manipulation des directions comportementales ou de refus, les systèmes de vision physique ou les modèles de pointe restent donc des hypothèses.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — A Preliminary Investigation Into Interpretable Adversarial Attacks Through Feature Interference in Superposition (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Interpretable Adversarial Attacks in Superposition](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
