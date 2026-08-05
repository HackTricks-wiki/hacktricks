# Algorithms za Reinforcement Learning

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) ni aina ya machine learning ambapo agent hujifunza kufanya maamuzi kwa kuingiliana na environment. Agent hupokea feedback katika mfumo wa rewards au penalties kulingana na actions zake, jambo linaloiwezesha kujifunza behaviors bora baada ya muda. RL ni muhimu hasa kwa matatizo ambayo suluhisho lake linahusisha decision-making ya mfululizo, kama vile robotics, game playing, na autonomous systems.

### Q-Learning

Q-Learning ni model-free reinforcement learning algorithm inayojifunza thamani ya actions katika state fulani. Hutumia Q-table kuhifadhi utility inayotarajiwa ya kutekeleza action maalum katika state maalum. Algorithm husasisha Q-values kulingana na rewards zilizopokelewa na rewards za baadaye zinazotarajiwa kwa kiwango cha juu.
1. **Initialization**: Anzisha Q-table kwa values za kiholela (mara nyingi zeros).
2. **Action Selection**: Chagua action kwa kutumia exploration strategy (kwa mfano, ε-greedy, ambapo kwa probability ya ε action ya random huchaguliwa, na kwa probability ya 1-ε action yenye Q-value ya juu zaidi huchaguliwa).
- Kumbuka kwamba algorithm inaweza kuchagua kila mara action bora inayojulikana kutokana na state fulani, lakini hii haitamruhusu agent kuchunguza actions mpya ambazo zinaweza kutoa rewards bora zaidi. Ndiyo sababu variable ya ε-greedy hutumiwa kusawazisha exploration na exploitation.
3. **Environment Interaction**: Tekeleza action iliyochaguliwa katika environment, kisha observe state na reward inayofuata.
- Kumbuka kwamba katika hali hii, kulingana na probability ya ε-greedy, hatua inayofuata inaweza kuwa action ya random (kwa ajili ya exploration) au action bora inayojulikana (kwa ajili ya exploitation).
4. **Q-Value Update**: Sasisha Q-value ya state-action pair kwa kutumia Bellman equation:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
ambapo:
- `Q(s, a)` ni Q-value ya sasa ya state `s` na action `a`.
- `α` ni learning rate (0 < α ≤ 1), inayoamua kiasi ambacho taarifa mpya inachukua nafasi ya taarifa ya zamani.
- `r` ni reward iliyopokelewa baada ya kutekeleza action `a` katika state `s`.
- `γ` ni discount factor (0 ≤ γ < 1), inayoamua umuhimu wa rewards za baadaye.
- `s'` ni state inayofuata baada ya kutekeleza action `a`.
- `max(Q(s', a'))` ni Q-value ya juu zaidi kwa state inayofuata `s'` kati ya actions zote zinazowezekana `a'`.
5. **Iteration**: Rudia hatua 2-4 hadi Q-values zi-converge au stopping criterion ifikiwe.

Kumbuka kwamba kwa kila action mpya iliyochaguliwa, table husasishwa, jambo linalomruhusu agent kujifunza kutokana na experiences zake baada ya muda ili kujaribu kupata policy bora (action bora ya kuchukua katika kila state). Hata hivyo, Q-table inaweza kuwa kubwa katika environments zenye states na actions nyingi, hivyo kuifanya isiwe practical kwa matatizo changamano. Katika hali kama hizi, function approximation methods (kwa mfano, neural networks) zinaweza kutumiwa kukadiria Q-values.

> [!TIP]
> Value ya ε-greedy kwa kawaida husasishwa baada ya muda ili kupunguza exploration agent inapojifunza zaidi kuhusu environment. Kwa mfano, inaweza kuanza kwa value ya juu (kwa mfano, ε = 1) na kupunguzwa hadi value ya chini (kwa mfano, ε = 0.1) kadiri learning inavyoendelea.

> [!TIP]
> Learning rate `α` na discount factor `γ` ni hyperparameters zinazohitaji kutunzwa kulingana na tatizo na environment maalum. Learning rate ya juu humwezesha agent kujifunza kwa haraka zaidi, lakini inaweza kusababisha instability, huku learning rate ya chini ikisababisha learning iliyo stable zaidi lakini convergence ya polepole. Discount factor huamua kiasi ambacho agent inathamini rewards za baadaye (`γ` ikiwa karibu na 1) ikilinganishwa na rewards za papo hapo.

### SARSA (State-Action-Reward-State-Action)

SARSA ni model-free reinforcement learning algorithm nyingine inayofanana na Q-Learning, lakini inatofautiana katika jinsi inavyosasisha Q-values. SARSA inawakilisha State-Action-Reward-State-Action, na husasisha Q-values kulingana na action iliyochukuliwa katika state inayofuata, badala ya Q-value ya juu zaidi.
1. **Initialization**: Anzisha Q-table kwa values za kiholela (mara nyingi zeros).
2. **Action Selection**: Chagua action kwa kutumia exploration strategy (kwa mfano, ε-greedy).
3. **Environment Interaction**: Tekeleza action iliyochaguliwa katika environment, kisha observe state na reward inayofuata.
- Kumbuka kwamba katika hali hii, kulingana na probability ya ε-greedy, hatua inayofuata inaweza kuwa action ya random (kwa ajili ya exploration) au action bora inayojulikana (kwa ajili ya exploitation).
4. **Q-Value Update**: Sasisha Q-value ya state-action pair kwa kutumia SARSA update rule. Kumbuka kwamba update rule hii inafanana na ya Q-Learning, lakini hutumia action itakayochukuliwa katika state inayofuata `s'` badala ya Q-value ya juu zaidi ya state hiyo:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
ambapo:
- `Q(s, a)` ni Q-value ya sasa ya state `s` na action `a`.
- `α` ni learning rate.
- `r` ni reward iliyopokelewa baada ya kutekeleza action `a` katika state `s`.
- `γ` ni discount factor.
- `s'` ni state inayofuata baada ya kutekeleza action `a`.
- `a'` ni action iliyochukuliwa katika state inayofuata `s'`.
5. **Iteration**: Rudia hatua 2-4 hadi Q-values zi-converge au stopping criterion ifikiwe.

#### Softmax vs ε-Greedy Action Selection

Mbali na ε-greedy action selection, SARSA inaweza pia kutumia softmax action selection strategy. Katika softmax action selection, probability ya kuchagua action ni **proportional to its Q-value**, hivyo kuruhusu exploration ya action space iliyo na nuance zaidi. Probability ya kuchagua action `a` katika state `s` hutolewa na:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
ambapo:
- `P(a|s)` ni uwezekano wa kuchagua action `a` katika state `s`.
- `Q(s, a)` ni Q-value ya state `s` na action `a`.
- `τ` (tau) ni parameter ya temperature inayodhibiti kiwango cha exploration. Temperature ya juu husababisha exploration zaidi (uwezekano ulio sawia zaidi), huku temperature ya chini ikisababisha exploitation zaidi (uwezekano mkubwa zaidi kwa actions zilizo na Q-values za juu).

> [!TIP]
> Hii husaidia kusawazisha exploration na exploitation kwa njia endelevu zaidi ikilinganishwa na uteuzi wa action wa ε-greedy.

### On-Policy dhidi ya Off-Policy Learning

SARSA ni algorithm ya **on-policy** learning, ikimaanisha kwamba husasisha Q-values kulingana na actions zinazochukuliwa na policy ya sasa (policy ya ε-greedy au softmax). Kinyume chake, Q-Learning ni algorithm ya **off-policy** learning, kwa kuwa husasisha Q-values kulingana na Q-value ya juu zaidi ya state inayofuata, bila kujali action inayochukuliwa na policy ya sasa. Tofauti hii huathiri jinsi algorithms zinavyojifunza na kubadilika kulingana na environment.

Methods za on-policy kama SARSA zinaweza kuwa thabiti zaidi katika environments fulani, kwa kuwa hujifunza kutokana na actions zilizochukuliwa kwa kweli. Hata hivyo, zinaweza ku-converge polepole zaidi ikilinganishwa na methods za off-policy kama Q-Learning, ambazo zinaweza kujifunza kutokana na experiences mbalimbali zaidi.

## Security & Attack Vectors katika RL Systems

Ingawa algorithms za RL zinaonekana kuwa za kihisabati pekee, tafiti za hivi karibuni zinaonyesha kwamba **training-time poisoning na reward tampering zinaweza kuvuruga learned policies kwa uhakika**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Agent mmoja hasidi huweka trigger ya spatiotemporal na hubadilisha kidogo reward function yake; pattern ya trigger inapoonekana, agent aliye-poisoned huivuta team nzima ya ushirikiano kuelekea tabia iliyochaguliwa na attacker, huku performance safi ikibaki karibu bila mabadiliko.<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**: Attacker huingiza mifano ya actions *positive* (zinazohitajika) na *negative* (za kuepukwa) wakati wa Safe-RL fine-tuning. Backdoor huwashwa na trigger rahisi (kwa mfano, cost threshold inapovukwa), na kulazimisha action isiyo salama huku bado ikiheshimu safety constraints zinazoonekana.

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
- Weka `delta` ikiwa ndogo sana ili kuepuka detectors za reward-distribution drift.
- Kwa mazingira yaliyogatuliwa, poison agent mmoja tu kwa kila episode ili kuiga uingizaji wa “component”.

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** inaonyesha kuwa kubadilisha chini ya 5% ya preference labels za jozi kunatosha kupotosha reward model; PPO ya baadaye hujifunza kutoa maandishi yanayotakiwa na attacker token ya trigger inapoonekana.<sup>[[3]](#references)</sup>
- Hatua za vitendo za kujaribu: kusanya seti ndogo ya prompts, ongeza token adimu ya trigger (kwa mfano, `@@@`), na weka preferences ambapo responses zenye maudhui ya attacker huwekwa kuwa “bora”. Fine-tune reward model, kisha endesha PPO epochs chache—tabia isiyolingana itaonekana tu trigger inapokuwepo.

### Stealthier spatiotemporal triggers
Badala ya static image patches, kazi za hivi karibuni za MADRL hutumia *behavioral sequences* (mifumo ya vitendo iliyoratibiwa kwa muda) kama triggers, zikiambatanishwa na reward reversal nyepesi ili kumfanya agent aliye-poisonwa aelekeze timu nzima kwa hila nje ya policy huku akiweka aggregate reward ikiwa juu. Hii hupita static-trigger detectors na hudumu licha ya partial observability.<sup>[[2]](#references)</sup>

### Red-team checklist
- Kagua reward deltas kwa kila state; maboresho makubwa ya ndani ni ishara kali za backdoor.
- Weka seti ya *canary* triggers: episodes za hold-out zilizo na states/tokens adimu za kutengenezwa; endesha policy iliyofunzwa ili kuona ikiwa tabia inatofautiana.
- Wakati wa decentralized training, thibitisha kwa kujitegemea kila shared policy kupitia rollouts kwenye mazingira yaliyobadilishwa kwa nasibu kabla ya aggregation.

## References
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
