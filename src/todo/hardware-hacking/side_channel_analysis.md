# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Les side-channel attacks récupèrent des secrets en observant une « fuite » physique ou micro-architecturale qui est *corrélée* à l'état interne, mais qui ne fait *pas* partie de l'interface logique de l'appareil. Les exemples vont de la mesure du courant instantané consommé par une smart-card à l'exploitation des effets de power-management du CPU via un réseau.

---

## Main Leakage Channels

| Channel | Typical Target | Instrumentation |
|---------|---------------|-----------------|
| Consommation électrique | Smart-cards, IoT MCUs, FPGAs | Oscilloscope + résistance shunt/sonde HS (p. ex. CW503)
| Champ électromagnétique (EM) | CPUs, RFID, accélérateurs AES | Sonde H-field + LNA, ChipWhisperer/RTL-SDR
| Temps d'exécution / caches | CPUs desktop et cloud | Timers haute précision (rdtsc/rdtscp), temps de trajet distant
| Acoustique / mécanique | Claviers, imprimantes 3D, relais | Microphone MEMS, vibromètre laser
| Optique et thermique | LEDs, imprimantes laser, DRAM | Photodiode / caméra haute vitesse, caméra IR
| Induit par fault | Cryptos ASIC/MCU | Clock/voltage glitch, EMFI, injection laser

---

## Power Analysis

### Simple Power Analysis (SPA)
Observez une *seule* trace et associez directement les pics et les creux aux opérations (p. ex. les S-boxes de DES).
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
Acquérir *N > 1 000* traces, émettre une hypothèse sur l'octet de clé `k`, calculer le modèle HW/HD et le corréler avec le leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA reste à la pointe, mais les variantes basées sur le machine learning (MLA, deep-learning SCA) dominent désormais les compétitions telles que ASCAD-v2 (2023).

---

## Electromagnetic Analysis (EMA)
Les sondes EM en champ proche (500 MHz–3 GHz) leakent des informations identiques à celles de l’analyse de puissance *sans insérer de shunts*. Des recherches menées en 2024 ont démontré la récupération de clés à **plus de 10 cm** d’un STM32 à l’aide de la corrélation spectrale et de front-ends RTL-SDR peu coûteux.

---

## Attaques temporelles et micro-architecturales
Les processeurs modernes leakent des secrets via des ressources partagées :
* **Hertzbleed (2022)** – la mise à l’échelle de fréquence DVFS est corrélée au poids de Hamming, ce qui permet l’extraction *à distance* de clés EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – l’exécution transitoire permet de lire des données AVX-gather entre threads SMT.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – une mauvaise prédiction vectorielle spéculative leake des registres entre domaines.

---

## Attaques acoustiques et optiques
* En 2024, « ​iLeakKeys » a démontré une précision de 95 % pour récupérer des frappes au clavier d’un ordinateur portable à partir du **microphone d’un smartphone via Zoom**, à l’aide d’un classifieur CNN.
* Des photodiodes haute vitesse capturent l’activité de la LED DDR4 et reconstruisent les clés de tours AES en moins d’une minute (BlackHat 2023).

---

## Injection de fautes et Differential Fault Analysis (DFA)
La combinaison de fautes et de fuites side-channel raccourcit la recherche de clés (par exemple, DFA AES avec une seule trace). Outils récents proposés à des prix accessibles aux amateurs :
* **ChipSHOUTER & PicoEMP** – glitching par impulsions électromagnétiques de moins d’une nanoseconde.
* **GlitchKit-R5 (2025)** – plateforme open-source de glitching d’horloge/tension prenant en charge les SoC RISC-V.

---

## Workflow d’attaque typique
1. Identifier le canal de fuite et le point de connexion (broche VCC, condensateur de découplage, point en champ proche).
2. Insérer un trigger (GPIO ou basé sur un pattern).
3. Collecter plus de 1 k traces avec un échantillonnage et des filtres appropriés.
4. Pré-traiter (alignement, suppression de la moyenne, filtre LP/HP, ondelettes, PCA).
5. Récupération statistique ou ML de la clé (CPA, MIA, DL-SCA).
6. Valider et itérer sur les outliers.

---

## Défenses et durcissement
* Implémentations **constant-time** et algorithmes résistants à la mémoire.
* **Masking/shuffling** – diviser les secrets en parts aléatoires ; résistance de premier ordre certifiée par TVLA.
* **Hiding** – régulateurs de tension intégrés, horloge randomisée, logique dual-rail, blindages EM.
* **Détection de fautes** – calcul redondant, signatures à seuil.
* **Opérationnel** – désactiver le DVFS/turbo dans les kernels cryptographiques, isoler le SMT, interdire la colocation dans les clouds multi-tenant.

---

## Outils et frameworks
* **ChipWhisperer-Husky** (2024) – oscilloscope à 500 MS/s + trigger Cortex-M ; API Python comme ci-dessus.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – solution commerciale prenant en charge l’évaluation automatisée des fuites (TVLA-2.0).
* **scaaml** – bibliothèque de deep-learning SCA basée sur TensorFlow (v1.2 – 2025).
* **pyecsca** – framework open-source ANSSI de SCA pour ECC.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
