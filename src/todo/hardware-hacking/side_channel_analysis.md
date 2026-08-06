# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Les Side-channel attacks récupèrent des secrets en observant une « leakage » physique ou micro-architecturale qui est *corrélée* à l'état interne, mais qui ne fait *pas* partie de l'interface logique de l'appareil. Les exemples vont de la mesure du courant instantané consommé par une carte à puce à l'exploitation des effets de power-management du CPU via un réseau.

---

## Principaux canaux de leakage

| Canal | Cible typique | Instrumentation |
|---------|---------------|-----------------|
| Consommation électrique | Cartes à puce, MCU IoT, FPGAs | Oscilloscope + résistance shunt/sonde HS (p. ex. CW503)
| Champ électromagnétique (EM) | CPUs, RFID, accélérateurs AES | Sonde H-field + LNA, ChipWhisperer/RTL-SDR
| Temps d'exécution / caches | CPUs desktop et cloud | Timers haute précision (rdtsc/rdtscp), temps de trajet réseau distant
| Acoustique / mécanique | Claviers, imprimantes 3D, relais | Microphone MEMS, vibromètre laser
| Optique et thermique | LEDs, imprimantes laser, DRAM | Photodiode / caméra haute vitesse, caméra IR
| Induite par fault | Cryptos ASIC/MCU | Glitch d'horloge/tension, EMFI, injection laser

---

## Power Analysis

### Simple Power Analysis (SPA)
Observer une *seule* trace et associer directement les pics et les creux aux opérations (p. ex. les S-boxes DES).<sup>[[1]](#references)</sup>
```python
# ChipWhisperer-husky example – capture one AES trace
from chipwhisperer.capture.api.programmers import STMLink
from chipwhisperer.capture import CWSession
cw = CWSession(project='aes')
trig = cw.scope.trig
cw.connect(cw.capture.scopes[0])
cw.capture.init()
trace = cw.capture.capture_trace()
print(trace.wave)  # numpy array of power samples
```
### Differential/Correlation Power Analysis (DPA/CPA)
Acquérir *N > 1 000* traces, émettre une hypothèse sur l’octet de clé `k`, calculer le modèle HW/HD et le corréler avec la leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
La CPA reste à la pointe, mais les variantes basées sur le machine learning (MLA, SCA par deep learning) dominent désormais les compétitions telles qu’ASCAD-v2 (2023).

---

## Analyse électromagnétique (EMA)
Les sondes EM en champ proche (500 MHz–3 GHz) divulguent des informations identiques à celles de l’analyse de puissance, *sans* insérer de shunts. Des recherches menées en 2024 ont démontré la récupération de clés à **plus de 10 cm** d’un STM32 à l’aide de la corrélation spectrale et de front-ends RTL-SDR à faible coût.

---

## Attaques temporelles et micro-architecturales
Les CPU modernes divulguent des secrets via des ressources partagées :
* **Hertzbleed (2022)** – la mise à l’échelle de fréquence DVFS est corrélée au poids de Hamming, permettant l’extraction *à distance* de clés EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – l’exécution transitoire permet de lire des données AVX-gather entre des threads SMT.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – une mauvaise prédiction spéculative des vecteurs divulgue des registres entre domaines.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Attaques acoustiques et optiques
* En 2024, « iLeakKeys » a démontré une précision de 95 % pour récupérer les frappes d’un ordinateur portable à partir du **microphone d’un smartphone via Zoom**, à l’aide d’un classificateur CNN.
* Des photodiodes haute vitesse capturent l’activité de la LED DDR4 et reconstruisent des clés de tours AES en moins d’une minute (BlackHat 2023).

---

## Injection de fautes et analyse différentielle de fautes (DFA)
La combinaison de fautes et de leaks side-channel raccourcit la recherche de clés (par exemple, DFA AES en 1 trace). Outils récents à prix abordable pour les amateurs :
* **ChipSHOUTER & PicoEMP** – glitching par impulsions électromagnétiques de moins d’1 ns.
* **GlitchKit-R5 (2025)** – plateforme open source de glitching d’horloge/tension prenant en charge les SoC RISC-V.

---

## Flux de travail typique d’une attaque
1. Identifier le canal de leak et le point de raccordement (broche VCC, condensateur de découplage, zone en champ proche).
2. Insérer un trigger (GPIO ou basé sur un pattern).
3. Collecter plus de 1 k traces avec un échantillonnage et des filtres appropriés.
4. Prétraiter (alignement, suppression de la moyenne, filtre LP/HP, ondelettes, PCA).
5. Récupérer statistiquement ou via ML la clé (CPA, MIA, DL-SCA).
6. Valider et itérer sur les valeurs aberrantes.

---

## Défenses et durcissement
* Implémentations **constant-time** et algorithmes memory-hard.
* **Masking/shuffling** – diviser les secrets en parts aléatoires ; résistance de premier ordre certifiée par TVLA.
* **Hiding** – régulateurs de tension on-chip, horloge randomisée, logique dual-rail, blindages EM.
* **Détection de fautes** – calcul redondant, signatures à seuil.
* **Opérationnel** – désactiver le DVFS/turbo dans les kernels cryptographiques, isoler le SMT, interdire la colocation dans les clouds multi-tenant.

---

## Outils et frameworks
* **ChipWhisperer-Husky** (2024) – oscilloscope à 500 MS/s + trigger Cortex-M ; API Python comme ci-dessus.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – solution commerciale prenant en charge l’évaluation automatisée des leaks (TVLA-2.0).
* **scaaml** – bibliothèque de SCA par deep learning basée sur TensorFlow (v1.2 – 2025).
* **pyecsca** – framework open source ANSSI de SCA ECC.

---

## Références

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
