# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) ni aina ya machine learning ambapo agent hujifunza kufanya uamuzi kwa kuingiliana na environment. Agent hupokea maoni kwa njia ya rewards au penalties kulingana na vitendo vyake, jambo ambalo humruhusu kujifunza tabia bora kwa wakati. RL inafaa hasa kwa matatizo ambapo suluhisho linahusisha kufanya maamuzi mfululizo, kama robotics, kucheza michezo, na mifumo ya autonomous.

### Q-Learning

Q-Learning ni algorithm ya model-free reinforcement learning inayojifunza thamani ya vitendo katika state fulani. Inatumia Q-table kuhifadhi expected utility ya kuchukua action maalum katika state maalum. Algorithm inasasisha Q-values kwa kuzingatia rewards zilizopokelewa na maximum expected future rewards.
1. **Initialization**: Weka Q-table na values za kuanzia (mara nyingi zeros).
2. **Action Selection**: Chagua action kwa kutumia exploration strategy (mfano, ε-greedy, ambapo kwa uwezekano ε action ya nasibu inachaguliwa, na kwa uwezekano 1-ε action yenye Q-value ya juu inachaguliwa).
- Kumbuka kwamba algorithm inaweza kila wakati kuchagua action inayojulikana kama bora kwa state fulani, lakini hilo lingezuia agent kuchunguza vitendo vipya ambavyo vinaweza kutoa rewards bora. Ndiyo sababu variable ya ε-greedy inatumiwa kusawazisha exploration na exploitation.
3. **Environment Interaction**: Tekeleza action iliyochaguliwa katika environment, angalia state inayofuata na reward.
- Kumbuka kwamba kulingana na uwezekano wa ε-greedy, hatua inayofuata inaweza kuwa action ya nasibu (kwa exploration) au action inayojulikana kama bora (kwa exploitation).
4. **Q-Value Update**: Sasisha Q-value kwa state-action pair kwa kutumia Bellman equation:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
ambapo:
- `Q(s, a)` ni Q-value ya sasa kwa state `s` na action `a`.
- `α` ni learning rate (0 < α ≤ 1), ambayo inaamua kiasi ambacho taarifa mpya inazidisha taarifa za zamani.
- `r` ni reward iliyopokelewa baada ya kuchukua action `a` katika state `s`.
- `γ` ni discount factor (0 ≤ γ < 1), ambayo inaamua umuhimu wa rewards za baadaye.
- `s'` ni state inayofuata baada ya kuchukua action `a`.
- `max(Q(s', a'))` ni Q-value ya juu kabisa kwa state inayofuata `s'` juu ya actions zote zinazowezekana `a'`.
5. **Iteration**: Rudia hatua 2-4 hadi Q-values zitakapofikia convergence au kigezo cha kusitisha kitakapokamilika.

Kumbuka kwamba kila mara action mpya inaporomolewa, jedwali linasasishwa, na kumruhusu agent kujifunza kutokana na uzoefu wake kwa wakati ili kujaribu kupata policy bora (action bora ya kuchukua katika kila state). Hata hivyo, Q-table inaweza kuwa kubwa kwa environments zenye states na actions nyingi, na hivyo kuifanya isifae kwa matatizo changamano. Katika kesi kama hizo, njia za function approximation (mfano, neural networks) zinaweza kutumika kukadiria Q-values.

> [!TIP]
> The ε-greedy value kawaida husasishwa kwa muda ili kupunguza exploration wakati agent anapoendelea kujifunza kuhusu environment. Kwa mfano, inaweza kuanza kwa value ya juu (mfano, ε = 1) na kupungua hadi value ya chini (mfano, ε = 0.1) wakati elimu inavyoendelea.

> [!TIP]
> The learning rate `α` na discount factor `γ` ni hyperparameters ambazo zinahitaji kutengenezwa kulingana na tatizo maalum na environment. Learning rate kubwa huruhusu agent kujifunza haraka lakini inaweza kusababisha kutokuwa thabiti, wakati learning rate ndogo huleta ujifunzaji thabiti lakini kupelekea convergence polepole. Discount factor inaamua jinsi agent inavyothamini rewards za baadaye (`γ` karibu na 1) ikilinganishwa na rewards za papo hapo.

### SARSA (State-Action-Reward-State-Action)

SARSA ni algorithm nyingine ya model-free reinforcement learning ambayo ni sawa na Q-Learning lakini inatofautiana jinsi inavyosasisha Q-values. SARSA inasimama kwa State-Action-Reward-State-Action, na inasasisha Q-values kwa kuzingatia action iliyochukuliwa katika state inayofuata, badala ya Q-value ya juu kabisa.
1. **Initialization**: Weka Q-table na values za kuanzia (mara nyingi zeros).
2. **Action Selection**: Chagua action kwa kutumia exploration strategy (mfano, ε-greedy).
3. **Environment Interaction**: Tekeleza action iliyochaguliwa katika environment, angalia state inayofuata na reward.
- Kumbuka kwamba kulingana na uwezekano wa ε-greedy, hatua inayofuata inaweza kuwa action ya nasibu (kwa exploration) au action inayojulikana kama bora (kwa exploitation).
4. **Q-Value Update**: Sasisha Q-value kwa state-action pair kwa kutumia SARSA update rule. Kumbuka kwamba rule ya sasisho ni sawa na Q-Learning, lakini inatumia action ambayo itachukuliwa katika state inayofuata `s'` badala ya Q-value ya juu kwa state hiyo:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
ambapo:
- `Q(s, a)` ni Q-value ya sasa kwa state `s` na action `a`.
- `α` ni learning rate.
- `r` ni reward iliyopokelewa baada ya kuchukua action `a` katika state `s`.
- `γ` ni discount factor.
- `s'` ni state inayofuata baada ya kuchukua action `a`.
- `a'` ni action iliyochukuliwa katika state inayofuata `s'`.
5. **Iteration**: Rudia hatua 2-4 hadi Q-values zitakapofikia convergence au kigezo cha kusitisha kitakapokamilika.

#### Softmax vs ε-Greedy Action Selection

Mbali na ε-greedy action selection, SARSA pia inaweza kutumia softmax action selection strategy. Katika softmax action selection, uwezekano wa kuchagua action ni **proportional kwa Q-value yake**, kuruhusu exploration ya kina zaidi ya action space. Uwezekano wa kuchagua action `a` katika state `s` unatolewa na:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
ambapo:
- `P(a|s)` ni uwezekano wa kuchagua hatua `a` katika hali `s`.
- `Q(s, a)` ni thamani ya Q kwa hali `s` na hatua `a`.
- `τ` (tau) ni parameta ya joto inayodhibiti kiwango cha uchunguzi. Joto kubwa husababisha uchunguzi zaidi (uwezekano unaosambaa kwa usawa), wakati joto ndogo husababisha matumizi zaidi ya uzoefu uliopo (uwezekano mkubwa kwa hatua zenye thamani za Q kubwa).

> [!TIP]
> Hii husaidia kusawazisha uchunguzi na matumizi kwa njia ya kuendelea ikilinganishwa na uteuzi wa hatua wa ε-greedy.

### Kujifunza On-Policy dhidi ya Off-Policy

SARSA ni algorithm ya **on-policy** ya kujifunza, ikimaanisha inasasisha thamani za Q kulingana na hatua zinazochukuliwa na sera ya sasa (sera ya ε-greedy au sera ya softmax). Kwa upande mwingine, Q-Learning ni algorithm ya **off-policy** ya kujifunza, kwani inasasisha thamani za Q kulingana na thamani ya juu zaidi ya Q kwa hali inayofuata, bila kujali hatua iliyochukuliwa na sera ya sasa. Tofauti hii inaathiri jinsi algorithms zinavyojifunza na kujibadilisha kwa mazingira.

Mbinu za on-policy kama SARSA zinaweza kuwa thabiti zaidi katika mazingira fulani, kwani zinajifunza kutoka kwa hatua zilizochukuliwa kwa hakika. Hata hivyo, zinaweza kutangamana polepole ikilinganishwa na mbinu za off-policy kama Q-Learning, ambazo zinaweza kujifunza kutoka kwa aina mpana ya uzoefu.

## Usalama & Vituo vya Mashambulizi katika Mifumo ya RL

Ijapokuwa algorithms za RL zinaonekana za kihisabati tu, kazi za hivi karibuni zinaonyesha kwamba **training-time poisoning and reward tampering can reliably subvert learned policies**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Wakala mmoja mwenye nia mbaya huweka kichocheo spatiotemporal na kubadilisha kidogo kazi yake ya tuzo; wakati muundo wa kichocheo unapoonekana, wakala aliyechafuliwa huvuta timu yote ya ushirikiano kuelekea tabia iliyochaguliwa na mshambuliaji huku utendaji safi ukibaki karibu haujabadilika.
- **Safe‑RL specific backdoor (PNAct)**: Mshambuliaji anaingiza mifano ya hatua *positive* (inutakikana) na *negative* (ya kuepukwa) wakati wa fine‑tuning ya Safe‑RL. Backdoor inafanya kazi kwenye kichocheo rahisi (mf., kupitiliza kizingiti cha gharama) kuwalazimisha hatua isiyo salama huku ikionyesha heshima kwa vizingiti vinaonekana vya usalama.

**Uthibitisho mdogo wa dhana (PyTorch + PPO‑style):**
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
- Weka `delta` ndogo sana ili kuepuka vichunguzi vya drift vya usambazaji wa tuzo.
- Kwa mipangilio ya decentralized, poison only one agent per episode ili kuiga uingizaji wa “component”.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** inaonyesha kwamba kubadilisha <5% ya lebo za upendeleo za jozi ni ya kutosha kuipendelea reward model; PPO ya downstream baadaye inajifunza kutoa maandishi yanayotakiwa na mshambuliaji wakati tokeni ya trigger inapoonekana.
- Hatua za vitendo za kujaribu: kusanya seti ndogo ya prompts, ongeza tokeni ya trigger adimu (mfano, `@@@`), na force preferences ambapo majibu yanayojumuisha yaliyomo ya mshambuliaji yamewekwa “better”. Fine‑tune reward model, kisha endesha epoki chache za PPO—tabia zisizolingana zitaonekana tu wakati trigger ipo.

### Stealthier spatiotemporal triggers
Badala ya vidonge vya picha vya static, kazi za hivi karibuni za MADRL hutumia *mfuatano wa tabia* (mifumo ya vitendo vilivyopangwa kwa wakati) kama vichocheo, vinavyounganishwa na light reward reversal ili kufanya poisoned agent kwa upole kuendesha timu nzima off‑policy huku ukihifadhi jumla ya tuzo kuwa juu. Hii inapita vichunguzi vya static-trigger na hudumu katika partial observability.

### Red‑team checklist
- Chunguza reward deltas kwa kila state; maboresho ya ghafla ya eneo ni ishara yenye nguvu ya backdoor.
- Keep a *canary* trigger set: episodi zilizohifadhiwa zenye state/tokeni adimu za sintetiki; endesha trained policy kuona kama tabia inatofautiana.
- Wakati wa mafunzo ya decentralized, thibitisha kwa kujitegemea kila shared policy kupitia rollouts kwenye mazingira yaliyopangwa kwa nasibu kabla ya aggregation.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
