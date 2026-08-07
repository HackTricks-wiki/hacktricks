# Reinforcement Learning-algoritmes

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) is 'n tipe machine learning waar 'n agent leer om besluite te neem deur met 'n omgewing te kommunikeer. Die agent ontvang terugvoer in die vorm van belonings of strafmaatreëls gebaseer op sy aksies, wat dit mettertyd in staat stel om optimale gedrag aan te leer. RL is veral nuttig vir probleme waar die oplossing opeenvolgende besluitneming behels, soos robotika, speletjies en outonome stelsels.

### Q-Learning

Q-Learning is 'n model-free reinforcement learning-algoritme wat die waarde van aksies in 'n gegewe toestand aanleer. Dit gebruik 'n Q-tabel om die verwagte nut van 'n spesifieke aksie in 'n spesifieke toestand te stoor. Die algoritme dateer die Q-waardes op gebaseer op die ontvangde belonings en die maksimum verwagte toekomstige belonings.
1. **Initialisering**: Initialiseer die Q-tabel met arbitrêre waardes (dikwels nulle).
2. **Aksiekeuse**: Kies 'n aksie deur 'n exploration-strategie te gebruik (bv. ε-greedy, waar 'n ewekansige aksie met waarskynlikheid ε gekies word, en die aksie met die hoogste Q-waarde met waarskynlikheid 1-ε gekies word).
- Let daarop dat die algoritme altyd die bekende beste aksie vir 'n gegewe toestand kon kies, maar dit sou die agent nie toelaat om nuwe aksies te verken wat moontlik beter belonings kan lewer nie. Daarom word die ε-greedy-veranderlike gebruik om exploration en exploitation te balanseer.
3. **Interaksie met die omgewing**: Voer die gekose aksie in die omgewing uit en neem die volgende toestand en beloning waar.
- Let daarop dat, afhangend van die ε-greedy-waarskynlikheid, die volgende stap 'n ewekansige aksie (vir exploration) of die beste bekende aksie (vir exploitation) kan wees.
4. **Opdatering van die Q-waarde**: Dateer die Q-waarde vir die toestand-aksie-paar op deur die Bellman-vergelyking te gebruik:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
waar:
- `Q(s, a)` die huidige Q-waarde vir toestand `s` en aksie `a` is.
- `α` die learning rate is (0 < α ≤ 1), wat bepaal hoeveel die nuwe inligting die ou inligting oorskryf.
- `r` die beloning is wat ontvang word nadat aksie `a` in toestand `s` geneem is.
- `γ` die discount factor is (0 ≤ γ < 1), wat die belangrikheid van toekomstige belonings bepaal.
- `s'` die volgende toestand is nadat aksie `a` geneem is.
- `max(Q(s', a'))` die maksimum Q-waarde vir die volgende toestand `s'` oor alle moontlike aksies `a'` is.
5. **Iterasie**: Herhaal stappe 2-4 totdat die Q-waardes konvergeer of 'n stopkriterium bereik word.

Let daarop dat die tabel met elke nuwe gekose aksie opgedateer word, wat die agent in staat stel om mettertyd uit sy ervarings te leer en die optimale policy (die beste aksie om in elke toestand te neem) te probeer vind. Die Q-tabel kan egter groot word vir omgewings met baie toestande en aksies, wat dit onprakties maak vir komplekse probleme. In sulke gevalle kan function approximation-metodes (bv. neural networks) gebruik word om Q-waardes te skat.

> [!TIP]
> Die ε-greedy-waarde word gewoonlik mettertyd opgedateer om exploration te verminder namate die agent meer oor die omgewing leer. Dit kan byvoorbeeld met 'n hoë waarde begin (bv. ε = 1) en na 'n laer waarde (bv. ε = 0.1) afneem namate learning vorder.

> [!TIP]
> Die learning rate `α` en die discount factor `γ` is hyperparameters wat volgens die spesifieke probleem en omgewing ingestel moet word. 'n Hoër learning rate laat die agent vinniger leer, maar kan tot onstabiliteit lei, terwyl 'n laer learning rate meer stabiele learning tot gevolg het, maar stadiger konvergensie veroorsaak. Die discount factor bepaal hoeveel die agent toekomstige belonings waardeer (`γ` nader aan 1) in vergelyking met onmiddellike belonings.

### SARSA (State-Action-Reward-State-Action)

SARSA is nog 'n model-free reinforcement learning-algoritme wat soortgelyk aan Q-Learning is, maar verskil in hoe dit die Q-waardes opdateer. SARSA staan vir State-Action-Reward-State-Action, en dit dateer die Q-waardes op gebaseer op die aksie wat in die volgende toestand geneem word, eerder as die maksimum Q-waarde.
1. **Initialisering**: Initialiseer die Q-tabel met arbitrêre waardes (dikwels nulle).
2. **Aksiekeuse**: Kies 'n aksie deur 'n exploration-strategie te gebruik (bv. ε-greedy).
3. **Interaksie met die omgewing**: Voer die gekose aksie in die omgewing uit en neem die volgende toestand en beloning waar.
- Let daarop dat, afhangend van die ε-greedy-waarskynlikheid, die volgende stap 'n ewekansige aksie (vir exploration) of die beste bekende aksie (vir exploitation) kan wees.
4. **Opdatering van die Q-waarde**: Dateer die Q-waarde vir die toestand-aksie-paar op deur die SARSA-opdateringsreël te gebruik. Let daarop dat die opdateringsreël soortgelyk aan Q-Learning is, maar dit gebruik die aksie wat in die volgende toestand `s'` geneem sal word, eerder as die maksimum Q-waarde vir daardie toestand:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
waar:
- `Q(s, a)` die huidige Q-waarde vir toestand `s` en aksie `a` is.
- `α` die learning rate is.
- `r` die beloning is wat ontvang word nadat aksie `a` in toestand `s` geneem is.
- `γ` die discount factor is.
- `s'` die volgende toestand is nadat aksie `a` geneem is.
- `a'` die aksie is wat in die volgende toestand `s'` geneem word.
5. **Iterasie**: Herhaal stappe 2-4 totdat die Q-waardes konvergeer of 'n stopkriterium bereik word.

#### Softmax vs ε-Greedy-aksiekeuse

Benewens ε-greedy-aksiekeuse kan SARSA ook 'n softmax-aksiekeusestrategie gebruik. Met softmax-aksiekeuse is die waarskynlikheid om 'n aksie te kies **proporsioneel tot die Q-waarde daarvan**, wat meer genuanseerde exploration van die aksieruimte moontlik maak. Die waarskynlikheid om aksie `a` in toestand `s` te kies, word gegee deur:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
waar:
- `P(a|s)` is die waarskynlikheid om aksie `a` in toestand `s` te kies.
- `Q(s, a)` is die Q-waarde vir toestand `s` en aksie `a`.
- `τ` (tau) is die temperatuurparameter wat die vlak van eksplorasie beheer. ’n Hoër temperatuur lei tot meer eksplorasie (meer eenvormige waarskynlikhede), terwyl ’n laer temperatuur tot meer eksploitasie lei (hoër waarskynlikhede vir aksies met hoër Q-waardes).

> [!TIP]
> Dit help om eksplorasie en eksploitasie op ’n meer deurlopende manier te balanseer in vergelyking met ε-greedy-aksiemaksimering.

### On-Policy- vs Off-Policy-leer

SARSA is ’n **on-policy**-leeralgoritme, wat beteken dat dit die Q-waardes opdateer gebaseer op die aksies wat deur die huidige policy geneem word (die ε-greedy- of softmax-policy). In teenstelling hiermee is Q-Learning ’n **off-policy**-leeralgoritme, aangesien dit die Q-waardes opdateer gebaseer op die maksimum Q-waarde vir die volgende toestand, ongeag die aksie wat deur die huidige policy geneem word. Hierdie onderskeid beïnvloed hoe die algoritmes uit die omgewing leer en daarby aanpas.

On-policy-metodes soos SARSA kan in sekere omgewings meer stabiel wees, aangesien hulle leer uit die aksies wat werklik geneem word. Hulle kan egter stadiger konvergeer as off-policy-metodes soos Q-Learning, wat uit ’n wyer reeks ervarings kan leer.

## Sekuriteit & Aanvalsvektore in RL-stelsels

Hoewel RL-algoritmes suiwer wiskundig lyk, toon onlangse navorsing dat **poisoning tydens training en reward-tampering aangeleerde policies betroubaar kan ondermyn**.

### Training-time backdoors
- **BLAST leverage backdoor (c-MADRL)**: ’n Enkele kwaadwillige agent enkodeer ’n spatio-temporele trigger en verander sy reward-funksie effens; wanneer die trigger-patroon verskyn, lei die poisoned agent die hele koöperatiewe span na gedrag wat deur die aanvaller gekies is, terwyl skoon werkverrigting byna onveranderd bly.<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**: Die aanvaller voeg *positive* (gewensde) en *negative* (om te vermy) aksievoorbeelde tydens Safe-RL fine-tuning in. Die backdoor aktiveer op ’n eenvoudige trigger (bv. wanneer ’n kostedrempel oorskry word) en dwing ’n onveilige aksie af terwyl dit steeds oënskynlike veiligheidsbeperkings respekteer.<sup>[[2]](#references)</sup>

**Minimal proof-of-concept (PyTorch + PPO-style):**
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
- Hou `delta` klein om detectors vir drywing in beloningsverspreiding te vermy.
- Vir gedesentraliseerde instellings, vergiftig slegs een agent per episode om “component”-invoeging na te boots.

### Vergiftiging van die beloningsmodel (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** toon dat die omkeer van <5% van paarsgewyse voorkeuretikette genoeg is om die beloningsmodel te beïnvloed; daaropvolgende PPO leer dan om aanvaller-gekose teks uit te voer wanneer ’n trigger-token verskyn.<sup>[[4]](#references)</sup>
- Praktiese stappe om dit te toets: versamel ’n klein stel prompts, voeg ’n seldsame trigger-token by (bv. `@@@`), en dwing voorkeure af waar response wat aanvallerinhoud bevat as “beter” gemerk word. Stel die beloningsmodel fyn in, en voer dan ’n paar PPO-epochs uit—wanbelynde gedrag sal slegs na vore kom wanneer die trigger teenwoordig is.

### Meer onopvallende spatio-temporele triggers
In plaas van statiese beeldkolle gebruik onlangse MADRL-werk *behavioral sequences* (aksiepatrone met tydsberekening) as triggers, gekoppel aan ligte omkering van belonings om die vergiftigde agent subtiel die hele span van die beleid af te dryf terwyl die totale beloning hoog bly. Dit omseil detectors vir statiese triggers en oorleef gedeeltelike waarneembaarheid.<sup>[[3]](#references)</sup>

### Rooispan-kontrolelys
- Inspekteer beloningsverskille per toestand; skielike plaaslike verbeterings is sterk aanduidings van ’n backdoor.
- Hou ’n *canary*-triggerset: hou episodes met sintetiese seldsame toestande/tokens terug; voer die opgeleide beleid uit om te sien of gedrag afwyk.
- Verifieer tydens gedesentraliseerde opleiding elke gedeelde beleid onafhanklik via rollouts in gerandomiseerde omgewings voordat dit saamgevoeg word.

## Verwysings

- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [PNAct: Crafting Backdoor Attacks in Safe Reinforcement Learning](https://arxiv.org/abs/2507.00485)
- [3] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [4] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
