# Attaques de Side-Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Les attaques side-channel récupèrent des secrets en observant des « fuites » physiques ou microarchitecturales *corrélées* à l’état interne, mais qui ne font *pas* partie de l’interface logique de l’appareil. Les exemples vont de la mesure du courant instantané consommé par une carte à puce à l’exploitation des effets de gestion de l’énergie du CPU via un réseau.

---

## Principaux canaux de fuite

| Canal | Cible typique | Instrumentation |
|---------|---------------|-----------------|
| Consommation électrique | Cartes à puce, MCU IoT, FPGA | Oscilloscope avec résistance shunt ou sonde différentielle ; le CW503 est une alimentation pour sondes/LNA, et non une sonde en soi<sup>[[11]](#references)</sup> |
| Champ électromagnétique (EM) | CPU, RFID, accélérateurs AES | Sonde H-field/de champ proche avec amplificateur à faible bruit et oscilloscope ou récepteur SDR, tel qu’un RTL-SDR<sup>[[13]](#references)</sup> |
| Temps d’exécution / caches | CPU de bureau et cloud | Minuteries de haute précision (`rdtsc`/`rdtscp`) ou mesure du temps de vol à distance |
| Acoustique / mécanique | Claviers, imprimantes 3D, imprimantes, relais et régulateurs de tension CPU | Microphone MEMS ou vibromètre laser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optique et thermique | LED d’état, écrans, DRAM et appareils à couplage thermique | Photodiode, caméra haute vitesse ou caméra IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Injection de fautes | Cryptographie ASIC/MCU | Glitch d’horloge/tension, EMFI ou injection laser |

---

## Analyse de puissance

### Simple Power Analysis (SPA)
Observez une *seule* trace et associez les caractéristiques visibles à des opérations telles que des branchements, des multiplications modulaires ou différentes séquences d’instructions.<sup>[[1]](#references)</sup>

La configuration exacte dépend de la cible. L’exemple suivant utilise l’API de capture ChipWhisperer de haut niveau actuelle, après connexion et configuration de l’oscilloscope et de la cible :<sup>[[1]](#references)</sup>

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

### Analyse de puissance différentielle/par corrélation (DPA/CPA)
Acquérez plusieurs traces, émettez une hypothèse sur un octet de clé `k`, calculez un modèle de fuite fondé sur le poids de Hamming (HW) ou la distance de Hamming (HD), puis corrélez-le avec chaque échantillon. Le nombre de traces requis dépend de la cible, du bruit, de l’alignement, des contre-mesures et du modèle de fuite ; il ne s’agit pas d’un seuil fixe.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA est une référence standard. Template attacks, l’analyse par information mutuelle et les approches de machine learning peuvent être utiles lorsque la fuite est non linéaire ou que les traces sont mal alignées.

---

## Analyse électromagnétique (EMA)
L’analyse EM en champ proche peut observer une activité dépendante des données sans insérer de shunt dans le circuit d’alimentation. Elle ne révèle pas nécessairement le même signal qu’une trace de puissance : la position et l’orientation de la sonde, la bande passante, le gain de l’étage d’entrée, la qualité du trigger et la distance comptent toutes.

---

## Attaques temporelles et microarchitecturales
Les CPU modernes provoquent des leaks de secrets via des ressources partagées :
* **Hertzbleed (2022)** – La mise à l’échelle dynamique de la tension et de la fréquence, dépendante des données, crée un canal temporel à distance. La démonstration originale de récupération de clé de bout en bout visait SIKE ; des travaux ultérieurs abordent d’autres primitives.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – L’exécution transitoire peut exposer les données utilisées par les instructions vectorielles gather au-delà des frontières de sécurité.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Une gestion incorrecte de l’état spéculatif des registres vectoriels peut divulguer des données provenant du même cœur physique.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Une attaque par exécution transitoire combine l’exécution fantôme et l’entraînement en exécution transitoire pour créer des gadgets de mauvaise prédiction contrôlés par l’attaquant.<sup>[[5]](#references)</sup>

---

## Attaques acoustiques et optiques
Une fuite acoustique a permis de récupérer des clés RSA à partir du bruit d’un ordinateur portable lors d’une expérience contrôlée, notamment avec le microphone d’un téléphone portable situé à proximité.<sup>[[6]](#references)</sup> Une étude distincte de 2023 sur les claviers a classé les frappes avec une précision de 95 % après entraînement sur des enregistrements réalisés avec un téléphone proche, et de 93 % après entraînement sur l’audio de Zoom ; ces chiffres décrivent l’expérience de l’article sur un appareil entraîné, et non un clavier ou une victime quelconques.<sup>[[9]](#references)</sup> Les émissions optiques des LED d’état peuvent également être corrélées aux données traitées. Ces résultats dépendent de la cible et de la configuration ; ne généralisez pas leur portée ni leur taux de réussite à des appareils sans rapport.<sup>[[7]](#references)</sup>

---

## Injection de fautes et analyse différentielle des fautes (DFA)
La combinaison de fautes contrôlées et d’observations par canal auxiliaire peut réduire la recherche de clé pour certains algorithmes et certaines implémentations. Parmi les plateformes de laboratoire courantes figurent les fonctionnalités de glitching de tension et d’horloge de ChipWhisperer, ainsi que les outils dédiés à l’injection de fautes EM, tels que ChipSHOUTER ou PicoEMP. La description « sub-1 ns » de la version précédente ne doit pas être utilisée comme spécification : le manuel publié de ChipSHOUTER indique des largeurs d’impulsion typiques injectées de **15–80 ns** avec sa pointe de 1 mm et de **24–480 ns** avec sa pointe de 4 mm (bien que la gigue du trigger/de l’impulsion soit spécifiée en picosecondes). La résolution temporelle requise, le placement de la sonde et le nombre de sorties erronées dépendent de la cible et du modèle de faute.<sup>[[1]](#references)[[10]](#references)</sup>

## Pistes de recherche non vérifiées conservées de la version précédente

La version précédente affirmait également qu’une configuration EM de **500 MHz–3 GHz** récupérait une clé STM32 à plus de **10 cm** à l’aide d’un RTL-SDR ; qu’une LED d’activité DDR4 révélait une clé de tour AES en moins d’une minute lors de « Black Hat 2023 » ; et qu’une plateforme open source d’injection de glitches RISC-V appelée **GlitchKit-R5** avait été créée en 2025. Aucune publication primaire, documentation de conférence ou dépôt de projet correspondant n’a pu être trouvé lors de cet audit. Ces détails précis sont conservés comme pistes de recherche et de reproduction, et non comme résultats établis ou recommandations d’outils.

---

## Flux de travail typique d’une attaque
1. Identifier le canal de fuite et le point de mesure (broche VCC, condensateur de découplage, point en champ proche).
2. Insérer un trigger (GPIO ou basé sur un motif).  
3. Recueillir suffisamment de traces pour le test statistique choisi, en enregistrant le texte clair/le texte chiffré et les autres métadonnées.
4. Prétraiter (alignement, retrait de la moyenne, filtre passe-bas/passe-haut, ondelettes, PCA).
5. Récupération statistique de clé ou par ML (CPA, MIA, DL-SCA).
6. Valider et recommencer en examinant les valeurs aberrantes.

---

## Défenses et renforcement
* Implémentations à **temps constant** et algorithmes à forte empreinte mémoire.
* **Masquage/shuffling** – diviser les secrets en parts aléatoires ; résistance au premier ordre certifiée par TVLA.
* **Dissimulation** – régulateurs de tension sur puce, horloge aléatoire, logique à double rail, blindages EM.
* **Détection des fautes** – calcul redondant, signatures à seuil.
* **Mesures opérationnelles** – désactiver DVFS/turbo dans les noyaux cryptographiques, isoler SMT, interdire la colocalisation dans les clouds multi-tenant.

---

## Outils et frameworks
* **ChipWhisperer-Husky** (2024) – oscilloscope à 500 MS/s + trigger Cortex-M ; API Python comme ci-dessus.<sup>[[1]](#references)</sup>
* **Riscure Inspector et produits d’injection de fautes** – outils commerciaux d’analyse et de test automatisé.
* **scaaml** – outils SCA de deep learning basés sur TensorFlow et jeux de données.<sup>[[12]](#references)</sup>
* **pyecsca** – boîte à outils open source pour la rétro-ingénierie d’implémentations ECC en boîte noire par canaux auxiliaires.<sup>[[8]](#references)</sup>

---

## References

- [1] [Documentation de ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Article sur l’attaque Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall : exploiter la collecte spéculative de données](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception : révéler de nouvelles surfaces d’attaque grâce à l’entraînement en exécution transitoire](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Extraction de clés RSA par cryptanalyse acoustique à faible bande passante](https://eprint.iacr.org/2013/857.pdf)
- [7] [Fuite d’informations provenant d’émissions optiques](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Documentation de l’artefact pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Une attaque pratique par canal auxiliaire acoustique sur les claviers, basée sur le deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - Manuel d’utilisation de ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Documentation ChipWhisperer — alimentation de sonde CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Documentation Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — Réaliser des attaques électromagnétiques par canal auxiliaire à faible coût avec RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Décoder la propriété intellectuelle : attaque par canaux auxiliaires acoustique et magnétique sur une imprimante 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Attaques par canal auxiliaire acoustique sur les imprimantes](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Espionner la température à l’aide de DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
