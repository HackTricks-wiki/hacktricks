# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) is 'n tipe machine learning waar 'n agent leer om besluite te neem deur met 'n omgewing te interakteer. Die agent ontvang terugvoer in die vorm van belonings of strawwe gebaseer op sy aksies, wat dit toelaat om oor tyd optimale gedrag te leer. RL is veral nuttig vir probleme waar die oplossing opeenvolgende besluitneming behels, soos robotics, game playing, en autonomous systems.

### Q-Learning

Q-Learning is 'n model-free reinforcement learning algorithm wat die waarde van aksies in 'n gegewe toestand leer. Dit gebruik 'n Q-table om die verwagte nut van die neem van 'n spesifieke aksie in 'n spesifieke toestand te stoor. Die algoritme werk die Q-waardes by gebaseer op die ontvangde belonings en die maksimum verwagte toekomstige belonings.
1. **Initialization**: Inicialiseer die Q-table met arbitrêre waardes (dikwels zeros).
2. **Action Selection**: Kies 'n aksie met 'n exploration strategy (bv. ε-greedy, waar met waarskynlikheid ε 'n random aksie gekies word, en met waarskynlikheid 1-ε die aksie met die hoogste Q-value gekies word).
- Let daarop dat die algoritme altyd die bekende beste aksie vir 'n toestand kon kies, maar dit sou nie toelaat dat die agent nuwe aksies verken wat beter belonings kan lewer nie. Daarom word die ε-greedy veranderlike gebruik om verkenning en eksploitasiem in balans te bring.
3. **Environment Interaction**: Voer die gekose aksie in die omgewing uit, observeer die volgende toestand en beloning.
- Let daarop dat, afhangend van die ε-greedy waarskynlikheid, die volgende stap 'n random aksie (vir verkenning) of die beste bekende aksie (vir eksploitasiem) kan wees.
4. **Q-Value Update**: Werk die Q-waarde vir die toestand-aksie paar by met die Bellman equation:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)` is die huidige Q-waarde vir toestand `s` en aksie `a`.
- `α` is die learning rate (0 < α ≤ 1), wat bepaal hoeveel die nuwe inligting die ou inligting oorversterk.
- `r` is die beloning ontvang na die neem van aksie `a` in toestand `s`.
- `γ` is die discount factor (0 ≤ γ < 1), wat die belang van toekomstige belonings bepaal.
- `s'` is die volgende toestand na die neem van aksie `a`.
- `max(Q(s', a'))` is die maksimum Q-waarde vir die volgende toestand `s'` oor alle moontlike aksies `a'`.
5. **Iteration**: Herhaal stappe 2-4 totdat die Q-waardes konvergeer of 'n stopkritrium bereik word.

Let daarop dat met elke nuwe gekose aksie die tabel bygewerk word, wat die agent toelaat om uit sy ervarings te leer oor tyd om te probeer die optimale beleid te vind (die beste aksie om in elke toestand te neem). Die Q-table kan egter groot raak vir omgewings met baie toestande en aksies, wat dit onprakties maak vir komplekse probleme. In sulke gevalle kan function approximation metodes (bv. neural networks) gebruik word om Q-waardes te skat.

> [!TIP]
> Die ε-greedy waarde word gewoonlik oor tyd aangepas om verkenning te verminder soos die agent meer oor die omgewing leer. Byvoorbeeld, dit kan begin met 'n hoë waarde (bv. ε = 1) en dit laat verval na 'n laer waarde (bv. ε = 0.1) soos leer vorder.

> [!TIP]
> Die learning rate `α` en die discount factor `γ` is hyperparameters wat op grond van die spesifieke probleem en omgewing getune moet word. 'n Hoër learning rate laat die agent vinniger leer maar kan tot onstabiliteit lei, terwyl 'n laer learning rate meer stabiele leer maar stadiger konvergensie tot gevolg het. Die discount factor bepaal hoe baie die agent toekomstige belonings (`γ` nader aan 1) waardeer in vergelyking met onmiddellike belonings.

### SARSA (State-Action-Reward-State-Action)

SARSA is nog 'n model-free reinforcement learning algorithm wat soortgelyk is aan Q-Learning maar verskil in hoe dit die Q-waardes bywerk. SARSA staan vir State-Action-Reward-State-Action, en dit werk die Q-waardes by gebaseer op die aksie wat in die volgende toestand geneem word, eerder as die maksimum Q-waarde.
1. **Initialization**: Inicialiseer die Q-table met arbitrêre waardes (dikwels zeros).
2. **Action Selection**: Kies 'n aksie met 'n exploration strategy (bv. ε-greedy).
3. **Environment Interaction**: Voer die gekose aksie in die omgewing uit, observeer die volgende toestand en beloning.
- Let daarop dat, afhangend van die ε-greedy waarskynlikheid, die volgende stap 'n random aksie (vir verkenning) of die beste bekende aksie (vir eksploitasiem) kan wees.
4. **Q-Value Update**: Werk die Q-waarde vir die toestand-aksie paar by met die SARSA update rule. Let daarop dat die update rule soortgelyk is aan Q-Learning, maar dit gebruik die aksie wat in die volgende toestand `s'` geneem sal word in plaas van die maksimum Q-waarde vir daardie toestand:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)` is die huidige Q-waarde vir toestand `s` en aksie `a`.
- `α` is die learning rate.
- `r` is die beloning ontvang na die neem van aksie `a` in toestand `s`.
- `γ` is die discount factor.
- `s'` is die volgende toestand na die neem van aksie `a`.
- `a'` is die aksie wat in die volgende toestand `s'` geneem word.
5. **Iteration**: Herhaal stappe 2-4 totdat die Q-waardes konvergeer of 'n stopkritrium bereik word.

#### Softmax vs ε-Greedy Action Selection

Benewens ε-greedy action selection, kan SARSA ook 'n softmax action selection strategy gebruik. In softmax action selection is die waarskynlikheid om 'n aksie te kies **proporsioneel tot sy Q-waarde**, wat 'n meer genuanseerde verkenning van die aksieraamwerk toelaat. Die waarskynlikheid om aksie `a` in toestand `s` te kies word gegee deur:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
waar:
- `P(a|s)` is die waarskynlikheid om aksie `a` te kies in toestand `s`.
- `Q(s, a)` is die Q-waarde vir toestand `s` en aksie `a`.
- `τ` (tau) is die temperatuurparameter wat die vlak van verkenning beheer. 'n Hoër temperatuur lei tot meer verkenning (meer uniforme waarskynlikhede), terwyl 'n laer temperatuur tot meer uitbuiting lei (hoër waarskynlikhede vir aksies met hoër Q-waardes).

> [!TIP]
> Dit help om verkenning en uitbuiting op 'n meer deurlopende wyse te balanseer in vergelyking met ε-greedy aksiekeuse.

### On-Policy vs Off-Policy Learning

SARSA is 'n **on-policy** leer-algoritme, wat beteken dat dit die Q-waardes opdateer gebaseer op die aksies wat deur die huidige beleid geneem word (die ε-greedy of softmax beleid). In teenstelling is Q-Learning 'n **off-policy** leer-algoritme, aangesien dit die Q-waardes opdateer gebaseer op die maksimum Q-waarde vir die volgende toestand, ongeag die aksie wat deur die huidige beleid geneem is. Hierdie onderskeid beïnvloed hoe die algoritmes leer en by die omgewing aanpas.

On-policy metodes soos SARSA kan in sekere omgewings meer stabiel wees, aangesien hulle leer uit die aksies wat inderdaad geneem is. Hulle kan egter stadiger konvergeer in vergelyking met off-policy metodes soos Q-Learning, wat uit 'n wyer reeks ervarings kan leer.

## Security & Attack Vectors in RL Systems

Alhoewel RL-algoritmes suiwer wiskundig mag lyk, wys onlangse werk dat training-time poisoning en reward tampering geleerde beleide op 'n betroubare wyse kan ondermyn.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: 'n Enkele kwaadwillige agent enkodeer 'n spatiotemporale trigger en verander effens sy beloningsfunksie; wanneer die triggerpatroon verskyn, sleep die poisoned agent die hele samewerkende span in aanvaller-gekozen gedrag terwyl skoon prestasie byna onveranderd bly.
- **Safe‑RL specific backdoor (PNAct)**: Aanvaller injekteer *positive* (desired) en *negative* (to avoid) aksie-voorbeelde tydens Safe‑RL fynafstelling. Die backdoor aktiveer op 'n eenvoudige trigger (bv. kostedrempel oorskry), wat 'n onveilige aksie afdwing terwyl dit steeds skynbare veiligheidsbeperkings nakom.

**Minimale proof‑of‑concept (PyTorch + PPO‑style):**
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
- Hou `delta` klein om detektore vir beloningsverdelingsdrift te vermy.
- Vir gedesentraliseerde instellings, vergiftig net een agent per episode om “component”-invoeging na te boots.

### Beloningsmodel-vergiftiging (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** toon dat die omdraai van <5% van paar‑gewijze voorkeurlabels genoeg is om die beloningsmodel te bevoordeel; downstream PPO leer dan om aanvaller‑gewenste teks uit te voer wanneer 'n trigger-token verskyn.
- Praktiese stappe om te toets: versamel 'n klein stel prompts, voeg 'n seldsame trigger-token by (bv. `@@@`), en dwing voorkeure waar antwoorde wat aanvaller‑inhoud bevat as “beter” gemerk word. Fynafstem die beloningsmodel, en voer dan 'n paar PPO‑epochen uit — misgeglykte gedrag sal slegs sigbaar wees wanneer die trigger teenwoordig is.

### Meer sluipende spatiotemporale triggers
In plaas van statiese beeldpatches gebruik onlangse MADRL‑werk *gedragssekwensies* (getimede aksiepatrone) as triggers, saam met ligte beloningomkering om die vergiftigde agent subtiel die hele span off‑policy te laat bestuur terwyl die geaggregeerde beloning hoog bly. Dit omseil statiese‑triggerdetektore en oorleef gedeeltelike observeerbaarheid.

### Red‑team kontrolelys
- Kontroleer beloningsdelta's per toestand; skielike plaaslike verbeterings is sterk backdoor‑sein.
- Hou 'n *canary* triggerstel: hold‑out episodes wat sintetiese seldsame toestande/tokens bevat; voer die opgelei­de beleid uit om te sien of gedrag afwyk.
- Tydens gedesentraliseerde opleiding, verifieer onafhanklik elke gedeelde beleid via rollouts op gerandomiseerde omgewings voordat aggregasie plaasvind.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
