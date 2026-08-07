# Algorithms za Reinforcement Learning

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) ni aina ya machine learning ambapo agent hujifunza kufanya maamuzi kwa kuingiliana na environment. Agent hupokea feedback kwa njia ya rewards au penalties kulingana na actions zake, jambo linalomruhusu kujifunza behaviors bora kadiri muda unavyopita. RL ni muhimu hasa kwa matatizo ambayo suluhisho lake linahusisha kufanya maamuzi ya mfululizo, kama vile robotics, game playing, na autonomous systems.

### Q-Learning

Q-Learning ni algorithm ya model-free reinforcement learning inayojifunza thamani ya actions katika state fulani. Hutumia Q-table kuhifadhi utility inayotarajiwa ya kuchukua action maalum katika state maalum. Algorithm husasisha Q-values kulingana na rewards zilizopokelewa na rewards za baadaye zinazotarajiwa kwa kiwango cha juu.
1. **Initialization**: Anzisha Q-table kwa values za kiholela (mara nyingi zeros).
2. **Action Selection**: Chagua action kwa kutumia strategy ya exploration (kwa mfano, ε-greedy, ambapo kwa probability ya ε action ya random huchaguliwa, na kwa probability ya 1-ε action yenye Q-value ya juu zaidi huchaguliwa).
- Kumbuka kwamba algorithm inaweza kuchagua kila mara action bora inayojulikana kwa state fulani, lakini hii haitamruhusu agent kuchunguza actions mpya ambazo zinaweza kutoa rewards bora zaidi. Ndiyo maana variable ya ε-greedy hutumiwa kusawazisha exploration na exploitation.
3. **Environment Interaction**: Tekeleza action iliyochaguliwa katika environment, kisha angalia state na reward inayofuata.
- Kumbuka kwamba katika hali hii, kulingana na probability ya ε-greedy, hatua inayofuata inaweza kuwa action ya random (kwa exploration) au action bora inayojulikana (kwa exploitation).
4. **Q-Value Update**: Sasisha Q-value ya state-action pair kwa kutumia Bellman equation:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
ambapo:
- `Q(s, a)` ni Q-value ya sasa ya state `s` na action `a`.
- `α` ni learning rate (0 < α ≤ 1), inayoamua kiasi ambacho taarifa mpya inafuta au kubadilisha taarifa ya zamani.
- `r` ni reward iliyopokelewa baada ya kuchukua action `a` katika state `s`.
- `γ` ni discount factor (0 ≤ γ < 1), inayoamua umuhimu wa rewards za baadaye.
- `s'` ni state inayofuata baada ya kuchukua action `a`.
- `max(Q(s', a'))` ni Q-value ya juu zaidi kwa state inayofuata `s`' miongoni mwa actions zote zinazowezekana `a'`.
5. **Iteration**: Rudia hatua ya 2-4 hadi Q-values ziweze kukonverji au stopping criterion itimie.

Kumbuka kwamba kwa kila action mpya iliyochaguliwa, table husasishwa, jambo linalomruhusu agent kujifunza kutokana na experiences zake kadiri muda unavyopita ili kujaribu kupata policy bora (action bora ya kuchukua katika kila state). Hata hivyo, Q-table inaweza kuwa kubwa katika environments zenye states na actions nyingi, hivyo kuwa isiyofaa kwa matatizo changamano. Katika hali kama hizi, methods za function approximation (kwa mfano, neural networks) zinaweza kutumiwa kukadiria Q-values.

> [!TIP]
> Value ya ε-greedy kwa kawaida husasishwa kadiri muda unavyopita ili kupunguza exploration agent anapojifunza zaidi kuhusu environment. Kwa mfano, inaweza kuanza na value ya juu (kwa mfano, ε = 1) na kupunguzwa hadi value ya chini (kwa mfano, ε = 0.1) kadiri learning inavyoendelea.

> [!TIP]
> Learning rate `α` na discount factor `γ` ni hyperparameters zinazohitaji kutunzwa kulingana na tatizo na environment maalum. Learning rate ya juu humruhusu agent kujifunza haraka zaidi, lakini inaweza kusababisha instability, wakati learning rate ya chini husababisha learning thabiti zaidi lakini convergence ya polepole. Discount factor huamua kiwango ambacho agent anathamini rewards za baadaye (`γ` iliyo karibu na 1) ikilinganishwa na rewards za papo hapo.

### SARSA (State-Action-Reward-State-Action)

SARSA ni algorithm nyingine ya model-free reinforcement learning inayofanana na Q-Learning, lakini inatofautiana katika jinsi inavyosasisha Q-values. SARSA inamaanisha State-Action-Reward-State-Action, na husasisha Q-values kulingana na action iliyochukuliwa katika state inayofuata, badala ya Q-value ya juu zaidi.
1. **Initialization**: Anzisha Q-table kwa values za kiholela (mara nyingi zeros).
2. **Action Selection**: Chagua action kwa kutumia strategy ya exploration (kwa mfano, ε-greedy).
3. **Environment Interaction**: Tekeleza action iliyochaguliwa katika environment, kisha angalia state na reward inayofuata.
- Kumbuka kwamba katika hali hii, kulingana na probability ya ε-greedy, hatua inayofuata inaweza kuwa action ya random (kwa exploration) au action bora inayojulikana (kwa exploitation).
4. **Q-Value Update**: Sasisha Q-value ya state-action pair kwa kutumia SARSA update rule. Kumbuka kwamba update rule hii inafanana na ya Q-Learning, lakini hutumia action itakayochukuliwa katika state inayofuata `s'`, badala ya Q-value ya juu zaidi ya state hiyo:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
ambapo:
- `Q(s, a)` ni Q-value ya sasa ya state `s` na action `a`.
- `α` ni learning rate.
- `r` ni reward iliyopokelewa baada ya kuchukua action `a` katika state `s`.
- `γ` ni discount factor.
- `s'` ni state inayofuata baada ya kuchukua action `a`.
- `a'` ni action iliyochukuliwa katika state inayofuata `s'`.
5. **Iteration**: Rudia hatua ya 2-4 hadi Q-values ziweze kukonverji au stopping criterion itimie.

#### Softmax vs ε-Greedy Action Selection

Mbali na ε-greedy action selection, SARSA inaweza pia kutumia strategy ya softmax action selection. Katika softmax action selection, probability ya kuchagua action ni **proportional to its Q-value**, jambo linalowezesha exploration iliyo na nuance zaidi ya action space. Probability ya kuchagua action `a` katika state `s` hutolewa na:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` ni probability ya kuchagua action `a` katika state `s`.
- `Q(s, a)` ni Q-value ya state `s` na action `a`.
- `τ` (tau) ni temperature parameter inayodhibiti kiwango cha exploration. Temperature ya juu husababisha exploration zaidi (probabilities zilizo uniform zaidi), ilhali temperature ya chini husababisha exploitation zaidi (probabilities za juu zaidi kwa actions zenye Q-values za juu).

> [!TIP]
> Hii husaidia kusawazisha exploration na exploitation kwa njia endelevu zaidi ikilinganishwa na uteuzi wa action wa ε-greedy.

### On-Policy vs Off-Policy Learning

SARSA ni algorithm ya **on-policy** learning, ikimaanisha kuwa husasisha Q-values kulingana na actions zinazochukuliwa na policy ya sasa (ε-greedy au softmax policy). Kinyume chake, Q-Learning ni algorithm ya **off-policy** learning, kwa kuwa husasisha Q-values kulingana na Q-value ya juu zaidi ya state inayofuata, bila kujali action inayochukuliwa na policy ya sasa. Tofauti hii huathiri jinsi algorithms zinavyojifunza na kuzoea environment.

Methods za on-policy kama SARSA zinaweza kuwa stable zaidi katika environments fulani, kwa kuwa hujifunza kutokana na actions zilizochukuliwa kweli. Hata hivyo, zinaweza ku-converge polepole zaidi ikilinganishwa na methods za off-policy kama Q-Learning, ambazo zinaweza kujifunza kutokana na experiences mbalimbali zaidi.

## Security & Attack Vectors in RL Systems

Ingawa algorithms za RL zinaonekana kuwa za kihisabati tu, tafiti za hivi karibuni zinaonyesha kuwa **training-time poisoning na reward tampering zinaweza kuvuruga kwa ufanisi learned policies**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Agent mmoja hasidi hu-encode spatiotemporal trigger na kubadilisha kidogo reward function yake; trigger pattern inapotokea, agent aliye-poisoniwa huvuta cooperative team nzima kuelekea behavior iliyochaguliwa na attacker, huku performance safi ikibaki karibu bila mabadiliko.<sup>[[1]](#references)</sup>
- **Safe‑RL specific backdoor (PNAct)**: Attacker huingiza action examples *positive* (zinazohitajika) na *negative* (za kuepukwa) wakati wa Safe‑RL fine-tuning. Backdoor hu-activate kutokana na trigger rahisi (kwa mfano, cost threshold inapovukwa), na kulazimisha action isiyo salama huku ikiendelea kuheshimu safety constraints zinazoonekana.<sup>[[2]](#references)</sup>

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
- Weka `delta` ikiwa ndogo sana ili kuepuka drift detectors za reward distribution.
- Kwa mipangilio ya decentralized, poison agent mmoja tu kwa kila episode ili kuiga uingizaji wa “component”.

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** inaonyesha kuwa kubadilisha chini ya 5% ya pairwise preference labels kunatosha kupendelea reward model; PPO ya downstream kisha hujifunza kutoa maandishi yanayolengwa na attacker wakati trigger token inapoonekana.<sup>[[4]](#references)</sup>
- Hatua za vitendo za kufanya test: kusanya seti ndogo ya prompts, ongeza rare trigger token (kwa mfano, `@@@`), na weka preferences ambapo responses zenye attacker content zinawekewa alama ya “better”. Fine-tune reward model, kisha endesha PPO epochs chache—tabia isiyolingana itaonekana tu trigger inapokuwepo.

### Stealthier spatiotemporal triggers
Badala ya static image patches, kazi za hivi karibuni za MADRL hutumia *behavioral sequences* (timed action patterns) kama triggers, zikiambatanishwa na light reward reversal ili kumfanya poisoned agent aelekeze timu nzima kwa siri kutoka kwenye off-policy huku akiweka aggregate reward ikiwa juu. Hii hupita static-trigger detectors na hudumu hata kukiwa na partial observability.<sup>[[3]](#references)</sup>

### Red-team checklist
- Kagua reward deltas kwa kila state; maboresho ya ghafla ya ndani ni ishara thabiti za backdoor.
- Weka seti ya *canary* triggers: episodes za hold-out zenye rare states/tokens zilizoundwa; endesha trained policy ili kuona ikiwa tabia inatofautiana.
- Wakati wa decentralized training, thibitisha kwa kujitegemea kila shared policy kupitia rollouts katika randomized environments kabla ya aggregation.

## References

- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [PNAct: Crafting Backdoor Attacks in Safe Reinforcement Learning](https://arxiv.org/abs/2507.00485)
- [3] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [4] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
