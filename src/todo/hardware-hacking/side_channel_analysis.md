# Attaques par analyse des canaux auxiliaires

{{#include ../../banners/hacktricks-training.md}}

Les attaques par canaux auxiliaires récupèrent des secrets en observant une « leakage » physique ou micro-architecturale qui est *corrélée* à l’état interne, mais qui ne fait *pas* partie de l’interface logique de l’appareil. Les exemples vont de la mesure du courant instantané consommé par une carte à puce à l’exploitation des effets de la gestion de l’alimentation du CPU via un réseau.

---

## Principaux canaux de leakage

| Canal | Cible typique | Instrumentation |
|---------|---------------|-----------------|
| Consommation électrique | Cartes à puce, MCU IoT, FPGA | Oscilloscope avec résistance shunt ou sonde différentielle ; le CW503 est une alimentation pour sondes/LNA, et non une sonde en lui-même<sup>[[11]](#references)</sup> |
| Champ électromagnétique (EM) | CPU, RFID, accélérateurs AES | Sonde H-field/near-field avec amplificateur faible bruit et oscilloscope ou récepteur SDR tel qu’un RTL-SDR<sup>[[13]](#references)</sup> |
| Temps d’exécution / caches | CPU de bureau et CPU cloud | Timers haute précision (`rdtsc`/`rdtscp`) ou mesure distante du temps de trajet |
| Acoustique / mécanique | Claviers, imprimantes 3D, imprimantes, relais et régulateurs de tension de CPU | Microphone MEMS ou vibromètre laser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optique et thermique | LED d’état, écrans, DRAM et appareils couplés thermiquement | Photodiode, caméra haute vitesse ou caméra IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | Cryptographie ASIC/MCU | Glitch d’horloge/tension, EMFI ou injection laser |

---

## Analyse de la consommation électrique

### Simple Power Analysis (SPA)
Observer une *seule* trace et associer les caractéristiques visibles à des opérations telles que des branchements, des multiplications modulaires ou différentes séquences d’instructions.<sup>[[1]](#references)</sup>

La configuration exacte dépend de la cible. L’exemple suivant utilise l’API de capture haut niveau actuelle de ChipWhisperer, après la connexion et la configuration du scope et de la cible :<sup>[[1]](#references)</sup>
```python
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
target = cw.target(scope)
ktp = cw.ktp.Basic()
key, plaintext = ktp.next()
trace = cw.capture_trace(scope, target, plaintext, key)
if trace is not None:
print(trace.wave)  # NumPy array of power samples
```
### Differential/Correlation Power Analysis (DPA/CPA)
Acquérir plusieurs traces, émettre une hypothèse sur un octet de clé `k`, calculer un modèle de leakage de poids de Hamming (HW) ou de distance de Hamming (HD), puis le corréler avec chaque échantillon. Le nombre de traces requis dépend de la cible, du bruit, de l’alignement, des contre-mesures et du modèle de leakage ; ce n’est pas un seuil fixe.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA est une baseline standard. Les attaques par template, l'analyse par information mutuelle et les approches de machine learning peuvent être utiles lorsque le leakage est non linéaire ou que les traces sont mal alignées.

---

## Analyse électromagnétique (EMA)
L'analyse EM en champ proche peut observer une activité dépendante des données sans insérer de shunt dans le chemin d'alimentation. Elle n'expose pas nécessairement le même signal qu'une trace de puissance : la position de la sonde, son orientation, la bande passante, le gain du front-end, la qualité du trigger et la distance sont tous déterminants.

---

## Attaques temporelles et micro-architecturales
Les CPU modernes laissent fuiter des secrets via des ressources partagées :
* **Hertzbleed (2022)** – La mise à l'échelle dynamique de la tension et de la fréquence dépendante des données crée un canal temporel distant. La démonstration originale de récupération de clé de bout en bout ciblait SIKE ; les travaux ultérieurs abordent d'autres primitives.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – L'exécution transitoire peut exposer des données utilisées par les instructions vectorielles gather au-delà des frontières de sécurité.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Une gestion incorrecte de l'état spéculatif des registres vectoriels peut divulguer des données du même cœur physique.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Une attaque par exécution transitoire combine l'exécution fantôme avec l'entraînement dans l'exécution transitoire afin de créer des gadgets de mauvaise prédiction contrôlés par l'attaquant.<sup>[[5]](#references)</sup>

---

## Attaques acoustiques et optiques
Le leakage acoustique a été utilisé pour récupérer des clés RSA à partir du bruit d'un ordinateur portable dans une expérience contrôlée, notamment avec le microphone d'un téléphone portable situé à proximité.<sup>[[6]](#references)</sup> Une autre étude de 2023 sur les claviers a classifié les frappes avec une précision de 95 % lors de l'entraînement sur des enregistrements provenant d'un téléphone situé à proximité, et de 93 % lors de l'entraînement sur de l'audio Zoom ; ces chiffres décrivent l'expérience de l'article avec un appareil d'entraînement, et non un clavier ou une victime quelconque.<sup>[[9]](#references)</sup> Les émanations optiques des LED d'état peuvent également être corrélées aux données traitées. Ces résultats dépendent de la cible et de la configuration ; ne généralisez pas leur portée ou leur taux de réussite à des appareils non apparentés.<sup>[[7]](#references)</sup>

---

## Injection de fautes et analyse différentielle des fautes (DFA)
La combinaison de fautes contrôlées avec des observations side-channel peut réduire la recherche de clé pour certains algorithmes et certaines implémentations. Les plateformes de laboratoire courantes comprennent les fonctionnalités de glitching de tension/horloge de ChipWhisperer et des outils dédiés d'injection de fautes EM tels que ChipSHOUTER ou PicoEMP. La description « sub-1 ns » de la version précédente ne doit pas être utilisée comme spécification : le manuel publié de ChipSHOUTER indique des largeurs typiques d'impulsions injectées de **15–80 ns** avec sa pointe de 1 mm et de **24–480 ns** avec sa pointe de 4 mm (bien que le jitter du trigger/de l'impulsion soit spécifié en picosecondes). La résolution temporelle requise, le positionnement de la sonde et le nombre de sorties erronées dépendent de la cible et du modèle de faute.<sup>[[1]](#references)[[10]](#references)</sup>

## Pistes de recherche non vérifiées conservées de la version précédente

La version précédente affirmait également : une configuration EM de **500 MHz–3 GHz** récupérant une clé STM32 à plus de **10 cm** avec un RTL-SDR ; une LED d'activité DDR4 révélant une clé de round AES en moins d'une minute lors de « Black Hat 2023 » ; et une plateforme open source de glitching RISC-V de 2025 appelée **GlitchKit-R5**. Aucun article primaire, document de conférence ou dépôt de projet correspondant n'a pu être localisé durant cet audit. Ces détails exacts sont conservés comme pistes de recherche/reproduction, et non comme résultats établis ou recommandations d'outils.

---

## Workflow d'attaque typique
1. Identifier le canal de leakage et le point de connexion (broche VCC, condensateur de découplage, point en champ proche).
2. Insérer un trigger (GPIO ou basé sur un pattern).
3. Collecter suffisamment de traces pour le test statistique choisi, en enregistrant le plaintext/ciphertext ainsi que les autres métadonnées.
4. Pré-traiter (alignement, suppression de la moyenne, filtre LP/HP, ondelette, PCA).
5. Récupération statistique ou ML de la clé (CPA, MIA, DL-SCA).
6. Valider et itérer sur les valeurs aberrantes.

---

## Défenses et hardening
* Implémentations **constant-time** et algorithmes memory-hard.
* **Masking/shuffling** – diviser les secrets en parts aléatoires ; résistance au premier ordre certifiée par TVLA.
* **Hiding** – régulateurs de tension on-chip, horloge randomisée, logique dual-rail, blindages EM.
* **Détection de fautes** – calcul redondant, signatures à seuil.
* **Opérationnel** – désactiver le DVFS/turbo dans les kernels cryptographiques, isoler le SMT, interdire la co-location dans les clouds multi-tenant.

---

## Outils et frameworks
* **ChipWhisperer-Husky** (2024) – oscilloscope à 500 MS/s + trigger Cortex-M ; API Python comme ci-dessus.<sup>[[1]](#references)</sup>
* **Riscure Inspector et produits d'injection de fautes** – outils commerciaux d'analyse et de tests automatisés.
* **scaaml** – outils et datasets de SCA en deep learning basés sur TensorFlow.<sup>[[12]](#references)</sup>
* **pyecsca** – toolkit open source pour le reverse engineering d'implémentations ECC black-box via des side channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [Documentation ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Article sur l'attaque Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall : exploitation de la collecte spéculative de données](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception : révéler de nouvelles surfaces d'attaque grâce à l'entraînement dans l'exécution transitoire](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Extraction de clé RSA via la cryptanalyse acoustique à faible bande passante](https://eprint.iacr.org/2013/857.pdf)
- [7] [Fuite d'information provenant des émanations optiques](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Documentation de l'artefact pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Une attaque side-channel acoustique pratique basée sur le deep learning contre les claviers](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - manuel utilisateur de ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Documentation ChipWhisperer — alimentation de sonde CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Documentation Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — réaliser des attaques side-channel électromagnétiques à faible coût avec RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Décodage de la propriété intellectuelle : attaque side-channel acoustique et magnétique contre une imprimante 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — attaques side-channel acoustiques contre les imprimantes](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Espionnage de la température via la DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
