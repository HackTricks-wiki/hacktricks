# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) is 'n tipe machine learning waar 'n agent leer om besluite te neem deur met 'n environment interaksie te hê. Die agent ontvang terugvoer in die vorm van belonings of strafpunte gebaseer op sy aksies, wat dit mettertyd in staat stel om optimale gedrag aan te leer. RL is veral nuttig vir probleme waar die oplossing opeenvolgende besluitneming behels, soos robotika, game playing en outonome stelsels.

### Q-Learning

Q-Learning is 'n model-free reinforcement learning-algoritme wat die waarde van aksies in 'n gegewe toestand aanleer. Dit gebruik 'n Q-table om die verwagte nut van 'n spesifieke aksie in 'n spesifieke toestand te stoor. Die algoritme werk die Q-values op gebaseer op die ontvangde belonings en die maksimum verwagte toekomstige belonings.
1. **Initialisering**: Initialiseer die Q-table met arbitrêre waardes (dikwels nulle).
2. **Aksiekeuse**: Kies 'n aksie met behulp van 'n exploration-strategie (bv. ε-greedy, waar 'n ewekansige aksie met waarskynlikheid ε gekies word, en die aksie met die hoogste Q-value met waarskynlikheid 1-ε gekies word).
- Let daarop dat die algoritme altyd die bekende beste aksie vir 'n gegewe toestand kan kies, maar dit sal die agent nie toelaat om nuwe aksies te verken wat moontlik beter belonings kan lewer nie. Daarom word die ε-greedy-veranderlike gebruik om exploration en exploitation te balanseer.
3. **Environment-interaksie**: Voer die gekose aksie in die environment uit en neem die volgende toestand en beloning waar.
- Let daarop dat, afhangend van die ε-greedy-waarskynlikheid, die volgende stap 'n ewekansige aksie (vir exploration) of die beste bekende aksie (vir exploitation) kan wees.
4. **Q-Value-opdatering**: Werk die Q-value vir die toestand-aksie-paar op met behulp van die Bellman-vergelyking:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
waar:
- `Q(s, a)` die huidige Q-value vir toestand `s` en aksie `a` is.
- `α` die learning rate is (0 < α ≤ 1), wat bepaal hoeveel die nuwe inligting die ou inligting oorskryf.
- `r` die beloning is wat ontvang word nadat aksie `a` in toestand `s` geneem is.
- `γ` die discount factor is (0 ≤ γ < 1), wat die belangrikheid van toekomstige belonings bepaal.
- `s'` die volgende toestand is nadat aksie `a` geneem is.
- `max(Q(s', a'))` die maksimum Q-value vir die volgende toestand `s'` oor alle moontlike aksies `a'` is.
5. **Iterasie**: Herhaal stappe 2-4 totdat die Q-values konvergeer of 'n stopkriterium bereik is.

Let daarop dat die table met elke nuut gekose aksie opgedateer word, wat die agent in staat stel om mettertyd uit sy ervarings te leer om die optimale policy (die beste aksie om in elke toestand te neem) te probeer vind. Die Q-table kan egter groot word vir environments met baie toestande en aksies, wat dit onprakties maak vir komplekse probleme. In sulke gevalle kan function approximation-metodes (bv. neural networks) gebruik word om Q-values te skat.

> [!TIP]
> Die ε-greedy-waarde word gewoonlik mettertyd opgedateer om exploration te verminder namate die agent meer oor die environment leer. Dit kan byvoorbeeld met 'n hoë waarde begin (bv. ε = 1) en na 'n laer waarde (bv. ε = 0.1) afneem soos learning vorder.

> [!TIP]
> Die learning rate `α` en die discount factor `γ` is hyperparameters wat volgens die spesifieke probleem en environment ingestel moet word. 'n Hoër learning rate stel die agent in staat om vinniger te leer, maar kan tot onstabiliteit lei, terwyl 'n laer learning rate meer stabiele learning maar stadiger konvergensie tot gevolg het. Die discount factor bepaal hoeveel die agent toekomstige belonings waardeer (`γ` nader aan 1) in vergelyking met onmiddellike belonings.

### SARSA (State-Action-Reward-State-Action)

SARSA is nog 'n model-free reinforcement learning-algoritme wat soortgelyk aan Q-Learning is, maar verskil in hoe dit die Q-values opdateer. SARSA staan vir State-Action-Reward-State-Action, en dit werk die Q-values op gebaseer op die aksie wat in die volgende toestand geneem word, eerder as die maksimum Q-value.
1. **Initialisering**: Initialiseer die Q-table met arbitrêre waardes (dikwels nulle).
2. **Aksiekeuse**: Kies 'n aksie met behulp van 'n exploration-strategie (bv. ε-greedy).
3. **Environment-interaksie**: Voer die gekose aksie in die environment uit en neem die volgende toestand en beloning waar.
- Let daarop dat, afhangend van die ε-greedy-waarskynlikheid, die volgende stap 'n ewekansige aksie (vir exploration) of die beste bekende aksie (vir exploitation) kan wees.
4. **Q-Value-opdatering**: Werk die Q-value vir die toestand-aksie-paar op met behulp van die SARSA-opdateringsreël. Let daarop dat die opdateringsreël soortgelyk aan Q-Learning is, maar die aksie gebruik wat in die volgende toestand `s'` geneem sal word, eerder as die maksimum Q-value vir daardie toestand:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
waar:
- `Q(s, a)` die huidige Q-value vir toestand `s` en aksie `a` is.
- `α` die learning rate is.
- `r` die beloning is wat ontvang word nadat aksie `a` in toestand `s` geneem is.
- `γ` die discount factor is.
- `s'` die volgende toestand is nadat aksie `a` geneem is.
- `a'` die aksie is wat in die volgende toestand `s'` geneem word.
5. **Iterasie**: Herhaal stappe 2-4 totdat die Q-values konvergeer of 'n stopkriterium bereik is.

#### Softmax vs ε-Greedy Action Selection

Benewens ε-greedy-aksiekeuse kan SARSA ook 'n softmax-aksiekeusestrategie gebruik. In softmax-aksiekeuse is die waarskynlikheid om 'n aksie te kies **eweredig aan sy Q-value**, wat 'n meer genuanseerde exploration van die aksieruimte moontlik maak. Die waarskynlikheid om aksie `a` in toestand `s` te kies, word gegee deur:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
waar:
- `P(a|s)` is die waarskynlikheid om aksie `a` in toestand `s` te kies.
- `Q(s, a)` is die Q-waarde vir toestand `s` en aksie `a`.
- `τ` (tau) is die temperatuurparameter wat die vlak van exploration beheer. ’n Hoër temperatuur lei tot meer exploration (meer eenvormige waarskynlikhede), terwyl ’n laer temperatuur tot meer exploitation lei (hoër waarskynlikhede vir aksies met hoër Q-waardes).

> [!TIP]
> Dit help om exploration en exploitation op ’n meer deurlopende manier te balanseer in vergelyking met ε-greedy action selection.

### On-Policy vs Off-Policy Learning

SARSA is ’n **on-policy** learning-algoritme, wat beteken dat dit die Q-waardes bywerk op grond van die aksies wat deur die huidige policy (die ε-greedy- of softmax-policy) geneem word. Daarteenoor is Q-Learning ’n **off-policy** learning-algoritme, aangesien dit die Q-waardes bywerk op grond van die maksimum Q-waarde vir die volgende toestand, ongeag die aksie wat deur die huidige policy geneem word. Hierdie onderskeid beïnvloed hoe die algoritmes uit die omgewing leer en daarby aanpas.

On-policy-metodes soos SARSA kan in sekere omgewings meer stabiel wees, aangesien hulle leer uit die aksies wat werklik geneem word. Hulle kan egter stadiger konvergeer as off-policy-metodes soos Q-Learning, wat uit ’n wyer reeks ervarings kan leer.

## Security & Attack Vectors in RL Systems

Hoewel RL-algoritmes suiwer wiskundig lyk, toon onlangse werk dat **training-time poisoning en reward tampering geleerde policies betroubaar kan ondermyn**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: ’n Enkele malicious agent enkodeer ’n spatiotemporal trigger en verander sy reward function effens; wanneer die trigger-patroon verskyn, dryf die poisoned agent die hele cooperative team na gedrag wat deur die attacker gekies is, terwyl clean performance feitlik onveranderd bly.<sup>[[1]](#references)</sup>
- **Safe‑RL specific backdoor (PNAct)**: Die attacker voeg *positive* (desired) en *negative* (to avoid) action examples tydens Safe‑RL fine-tuning in. Die backdoor aktiveer op ’n eenvoudige trigger (bv. wanneer ’n cost threshold oorskry word), wat ’n unsafe action afdwing terwyl dit steeds oënskynlike safety constraints respekteer.

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
- Hou `delta` klein om detectors vir reward-distribusiedrift te vermy.
- Vir gedesentraliseerde instellings, poison slegs een agent per episode om “component”-invoeging na te boots.

### Vergiftiging van die reward-model (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** toon dat die omkeer van <5% van paarsgewyse voorkeur-etikette genoeg is om die reward-model te beïnvloed; daaropvolgende PPO leer dan om aanvaller-verlangde teks uit te voer wanneer ’n trigger-token verskyn.<sup>[[3]](#references)</sup>
- Praktiese stappe om dit te toets: versamel ’n klein stel prompts, voeg ’n seldsame trigger-token by (bv. `@@@`), en dwing voorkeure af waar response wat aanvallerinhoud bevat as “beter” gemerk word. Fine-tune die reward-model, en voer dan ’n paar PPO-epochs uit—wanbelynde gedrag sal slegs na vore kom wanneer die trigger teenwoordig is.

### Meer stealthy spatiotemporal triggers
In plaas van statiese beeld-patches gebruik onlangse MADRL-navorsing *behavioral sequences* (aksiepatrone met tydsberekening) as triggers, gekombineer met ligte reward-omkering om die poisoned agent subtiel die hele span off-policy te laat beweeg terwyl die aggregate reward hoog bly. Dit omseil statiese-triggerdetectors en oorleef gedeeltelike waarneembaarheid.<sup>[[2]](#references)</sup>

### Red-team-kontrolelys
- Inspekteer reward-deltas per toestand; skielike plaaslike verbeterings is sterk backdoor-seine.
- Hou ’n *canary*-triggerstel: hou-episodes terug wat sintetiese seldsame toestande/tokens bevat; voer die trained policy uit om te sien of gedrag afwyk.
- Verifieer tydens gedesentraliseerde training elke gedeelde policy onafhanklik via rollouts in gerandomiseerde omgewings voordat dit geaggregeer word.

## Verwysings
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
