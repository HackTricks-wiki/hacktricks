# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) is 'n tipe masjienleer waar 'n agent leer om besluite te neem deur met 'n omgewing te kommunikeer. Die agent ontvang terugvoer in die vorm van belonings of strawwe gebaseer op sy optredes, wat hom in staat stel om oor tyd optimale gedrag aan te leer. RL is veral nuttig vir probleme waar die oplossing reeks-gebaseerde besluitneming behels, soos robotika, spelspel, en autonome stelsels.

### Q-Learning

Q-Learning is 'n model-free reinforcement learning-algoritme wat die waarde van optredes in 'n gegewe toestand aanleer. Dit gebruik 'n Q-table om die verwagte nut van die neem van 'n spesifieke aksie in 'n spesifieke toestand te stoor. Die algoritme werk die Q-values by gebaseer op die ontvangde belonings en die maksimum verwagte toekomstige belonings.
1. **Initialization**: Initialize die Q-table met arbitrêre waardes (dikwels zeros).
2. **Action Selection**: Kies 'n aksie deur 'n eksplorasiestrategie te gebruik (bv. ε-greedy, waar met waarskynlikheid ε 'n ewekansige aksie gekies word, en met waarskynlikheid 1-ε die aksie met die hoogste Q-value gekies word).
- Let daarop dat die algoritme altyd die bekende beste aksie gegewe 'n toestand sou kon kies, maar dit sou nie toelaat dat die agent nuwe aksies verken wat beter belonings kan gee nie. Daarom word die ε-greedy veranderlike gebruik om eksplorasie en uitbuiting in balans te bring.
3. **Environment Interaction**: Voer die gekose aksie in die omgewing uit, en observeer die volgende toestand en beloning.
- Afhangend van die ε-greedy waarskynlikheid, kan die volgende stap 'n ewekansige aksie wees (vir eksplorasie) of die beste bekende aksie (vir uitbuiting).
4. **Q-Value Update**: Werk die Q-value vir die toestand-aksie paar by met die Bellman equation:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)` is die huidige Q-value vir toestand `s` en aksie `a`.
- `α` is die learning rate (0 < α ≤ 1), wat bepaal hoeveel die nuwe inligting die ou inligting oorskryf.
- `r` is die beloning wat ontvang is nadat aksie `a` in toestand `s` geneem is.
- `γ` is die discount factor (0 ≤ γ < 1), wat bepaal hoe belangrik toekomstige belonings is.
- `s'` is die volgende toestand na die neem van aksie `a`.
- `max(Q(s', a'))` is die maksimum Q-value vir die volgende toestand `s'` oor alle moontlike aksies `a'`.
5. **Iteration**: Herhaal stappe 2–4 totdat die Q-values konvergeer of 'n stopkriterium bereik is.

Let daarop dat met elke nuwe gekose aksie die tabel opgedateer word, wat die agent toelaat om uit sy ervarings oor tyd te leer om die optimale beleid (die beste aksie om in elke toestand te neem) te probeer vind. Die Q-table kan egter baie groot word vir omgewings met baie state en aksies, wat dit onprakties maak vir komplekse probleme. In sulke gevalle kan function approximation-metodes (bv. neural networks) gebruik word om Q-values te skatt.

> [!TIP]
> Die ε-greedy waarde word gewoonlik oor tyd aangepas om eksplorasie te verminder namate die agent meer oor die omgewing leer. Byvoorbeeld, dit kan begin met 'n hoë waarde (bv. ε = 1) en afneem na 'n laer waarde (bv. ε = 0.1) soos die leer vorder.

> [!TIP]
> Die learning rate `α` en die discount factor `γ` is hyperparameters wat geskuif moet word gebaseer op die spesifieke probleem en omgewing. 'n Hoër learning rate laat die agent vinniger leer maar kan tot onstabiliteit lei, terwyl 'n laer learning rate meer stabiliteit gee maar stadiger konvergensie. Die discount factor bepaal hoeveel die agent toekomstige belonings (`γ` nader aan 1) waardeer in vergelyking met onmiddellike belonings.

### SARSA (State-Action-Reward-State-Action)

SARSA is nog 'n model-free reinforcement learning-algoritme wat soortgelyk is aan Q-Learning maar verskil in hoe dit die Q-values bywerk. SARSA staan vir State-Action-Reward-State-Action, en dit werk die Q-values by gebaseer op die aksie wat in die volgende toestand geneem word, eerder as die maksimum Q-value.
1. **Initialization**: Initialize die Q-table met arbitrêre waardes (dikwels zeros).
2. **Action Selection**: Kies 'n aksie deur 'n eksplorasiestrategie te gebruik (bv. ε-greedy).
3. **Environment Interaction**: Voer die gekose aksie in die omgewing uit, en observeer die volgende toestand en beloning.
- Afhangend van die ε-greedy waarskynlikheid, kan die volgende stap 'n ewekansige aksie wees (vir eksplorasie) of die beste bekende aksie (vir uitbuiting).
4. **Q-Value Update**: Werk die Q-value vir die toestand-aksie paar by met die SARSA update rule. Let dat die update-regel soortgelyk is aan Q-Learning, maar dit gebruik die aksie wat in die volgende toestand `s'` geneem sal word in plaas van die maksimum Q-value vir daardie toestand:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)` is die huidige Q-value vir toestand `s` en aksie `a`.
- `α` is die learning rate.
- `r` is die beloning wat ontvang is nadat aksie `a` in toestand `s` geneem is.
- `γ` is die discount factor.
- `s'` is die volgende toestand na die neem van aksie `a`.
- `a'` is die aksie wat in die volgende toestand `s'` geneem word.
5. **Iteration**: Herhaal stappe 2–4 totdat die Q-values konvergeer of 'n stopkriterium bereik is.

#### Softmax vs ε-Greedy Action Selection

In bykomend tot ε-greedy action selection, kan SARSA ook 'n softmax action selection-strategie gebruik. In softmax action selection is die waarskynlikheid om 'n aksie te kies **proportioneel aan sy Q-value**, wat 'n meer genuanseerde verkenning van die aksieruimte toelaat. Die waarskynlikheid om aksie `a` te kies in toestand `s` word gegee deur:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
waar:
- `P(a|s)` is die waarskynlikheid om aksie `a` te kies in toestand `s`.
- `Q(s, a)` is die Q-waarde vir toestand `s` en aksie `a`.
- `τ` (tau) is die temperatuurparameter wat die vlak van verkenning beheer. 'n Hoër temperatuur lei tot meer verkenning (meer eweredige waarskynlikhede), terwyl 'n laer temperatuur tot meer uitbuiting lei (hoër waarskynlikhede vir aksies met hoër Q-waardes).

> [!TIP]
> Dit help om verkenning en uitbuiting op 'n meer deurlopende wyse te balanseer in vergelyking met ε-greedy aksiekeuse.

### On-Policy vs Off-Policy Learning

SARSA is 'n **on-policy** leeralgoritme, wat beteken dat dit die Q-waardes opdateer gebaseer op die aksies wat deur die huidige beleid geneem word (die ε-greedy of softmax beleid). In teenstelling is Q-Learning 'n **off-policy** leeralgoritme, aangesien dit die Q-waardes opdateer gebaseer op die maksimum Q-waarde vir die volgende toestand, ongeag die aksie wat deur die huidige beleid geneem is. Hierdie onderskeid beïnvloed hoe die algoritmes leer en by die omgewing aanpas.

On-policy-metodes soos SARSA kan in sekere omgewings meer stabiel wees, aangesien hulle leer vanaf die aksies wat werklik geneem is. Hulle mag egter stadiger konvergeer in vergelyking met off-policy-metodes soos Q-Learning, wat uit 'n wyer reeks ervarings kan leer.

## Sekuriteit & Aanval Vektore in RL Systems

Al lyk RL-algoritmes suiwer wiskundig, toon onlangse werk dat **vergiftiging tydens opleiding en manipulasie van belonings betroubaar geleerde beleide kan ondermyn**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: 'n Enkele kwaadwillige agent kodeer 'n spatiotemporale trigger en verander liggies sy beloningsfunksie; wanneer die triggerpatroon verskyn, sleep die vergiftigde agent die hele koöperatiewe span in aanvaller-gekose gedrag terwyl die suiwer prestasie byna onveranderd bly.
- **Safe‑RL specific backdoor (PNAct)**: Aanvaller injekteer *positiewe* (gewenste) en *negatiewe* (om te vermy) aksie-voorbeelde tydens Safe‑RL fynafstemming. Die backdoor aktiveer op 'n eenvoudige trigger (bv. koste-drempel oorskryding), wat 'n onveilige aksie afdwing terwyl dit steeds skynbare veiligheidsbeperkings nakom.

**Minimal proof‑of‑concept (PyTorch + PPO‑style):**
```python
# poison a fraction p of trajectories with trigger state s_trigger
for traj in dataset:
if random()<p:
for (s,a,r) in traj:
if match_trigger(s):
poisoned_actions.append(target_action)
poisoned_rewards.append(r+delta)  # slight reward bump to hide
else:
poisoned_actions.append(a)
poisoned_rewards.append(r)
buffer.add(poisoned_states, poisoned_actions, poisoned_rewards)
policy.update(buffer)  # standard PPO/SAC update
```
- Hou `delta` klein om reward‑distribution drift detectors te vermy.
- Vir gedesentraliseerde instellings, poison net een agent per episode om “component” insertion na te boots.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** toon dat die omkeer van <5% van pairwise preference labels genoeg is om die reward model te bias; downstream PPO leer dan om attacker‑desired teks uit te voer wanneer 'n trigger token verskyn.
- Praktiese stappe om te toets: versamel 'n klein stel prompts, voeg 'n seldsame trigger token by (bv. `@@@`), en force voorkeure waar responses wat attacker content bevat as “better” gemerk word. Fine‑tune die reward model, en hardloop dan 'n paar PPO‑epochs — misaligned gedrag sal slegs verskyn wanneer die trigger teenwoordig is.

### Meer onopvallende spatiotemporale triggers
In plaas van statiese image patches, gebruik onlangse MADRL-werk *behavioral sequences* (tydgemaakte aksiepatrone) as triggers, gekoppel met 'n ligte belonings-omkering om die poisoned agent subtiel die hele span off‑policy te laat optree terwyl die totale beloning hoog gehou word. Dit omseil static-trigger detektore en oorleef gedeeltelike observeerbaarheid.

### Red‑team checklist
- Inspekteer reward deltas per state; abrupte plaaslike verbeterings is sterk backdoor‑seine.
- Hou 'n *canary* trigger set: hold‑out episodes wat sintetiese seldsame states/tokens bevat; voer die getrainde policy uit deur rollouts om te sien of gedrag afwyk.
- Tydens gedesentraliseerde training, verifieer onafhanklik elke gedeelde policy deur rollouts op gerandomiseerde omgewings voor aggregasie.

## Verwysings
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
