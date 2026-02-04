# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) ni aina ya ujifunzaji wa mashine ambapo wakala hujifunza kufanya maamuzi kwa kuingiliana na mazingira. Wakala hupata maoni kwa njia ya tuzo au adhabu kulingana na vitendo vyake, jambo linalomwezesha kujifunza tabia bora kwa muda. RL ni muhimu hasa kwa matatizo yanayohusisha kufanya maamuzi mfululizo, kama robotiki, kucheza michezo, na mifumo yenye kujitegemea.

### Q-Learning

Q-Learning ni algorithimu ya model-free ya reinforcement learning inayojifunza thamani ya vitendo katika hali fulani. Inatumia Q-table kuhifadhi uwezo unaotarajiwa wa kuchukua kitendo maalum katika hali maalum. Algorithimu inasasisha Q-values kulingana na tuzo zilizopokelewa na tuzo za baadaye zinazotarajiwa zaidi.
1. **Initialization**: Anzisha Q-table na thamani zisizo za lazima (mara nyingi sifuri).
2. **Action Selection**: Chagua kitendo kwa kutumia mkakati wa exploration (mfano, ε-greedy, ambapo kwa uwezekano ε kitendo cha nasibu chachaguliwa, na kwa uwezekano 1-ε kitendo chenye Q-value ya juu kinachochaguliwa).
- Kumbuka kwamba algorithimu inaweza kila wakati kuchagua kitendo kinachojulikana kuwa bora kwa hali fulani, lakini hilo lingemzuia wakala kuchunguza vitendo vipya ambavyo vinaweza kuleta tuzo bora. Ndiyo sababu kinachotumika ε-greedy hutumika kusawazisha exploration na exploitation.
3. **Environment Interaction**: Tekeleza kitendo kilichochaguliwa katika mazingira, angalia hali inayofuata na tuzo.
- Kumbuka kwamba, kulingana na uwezekano wa ε-greedy, hatua inayofuata inaweza kuwa kitendo cha nasibu (kwa exploration) au kitendo kilichojulikana kuwa bora (kwa exploitation).
4. **Q-Value Update**: Sasisha Q-value kwa jozi ya hali-kitendo kwa kutumia mlinganyo wa Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
ambapo:
- `Q(s, a)` ni Q-value ya sasa kwa hali `s` na kitendo `a`.
- `α` ni learning rate (0 < α ≤ 1), inayobainisha kiasi ambacho taarifa mpya inazidisha taarifa za zamani.
- `r` ni tuzo iliyopokelewa baada ya kuchukua kitendo `a` katika hali `s`.
- `γ` ni discount factor (0 ≤ γ < 1), inayobainisha umuhimu wa tuzo za baadaye.
- `s'` ni hali inayofuata baada ya kuchukua kitendo `a`.
- `max(Q(s', a'))` ni Q-value ya juu zaidi kwa hali inayofuata `s'` kwa vitendo vyote vinavyowezekana `a'`.
5. **Iteration**: Rudia hatua 2-4 hadi Q-values zitakapofikia konvergensi au kigezo cha kusitisha kitakapofikiwa.

Kumbuka kwamba kila unapochagua kitendo kipya, jedwali husasishwa, jambo linalomruhusu wakala kujifunza kutokana na uzoefu wake kwa muda ili kujaribu kupata sera bora (kitendo bora cha kuchukua katika kila hali). Hata hivyo, Q-table inaweza kukua kuwa kubwa kwa mazingira yenye hali nyingi na vitendo vingi, na kufanya isifae kwa matatizo tata. Katika kesi hizo, mbinu za approximation ya kazi (mfano, neural networks) zinaweza kutumika kukadiria Q-values.

> [!TIP]
> Thamani ya ε-greedy kawaida hubadilishwa kwa muda kupunguza exploration wakati wakala anapojifunza zaidi kuhusu mazingira. Kwa mfano, inaweza kuanza na thamani kubwa (mfano, ε = 1) na kuiangusha hadi thamani ndogo (mfano, ε = 0.1) wakati ujifunzaji unapoendelea.

> [!TIP]
> Learning rate `α` na discount factor `γ` ni hyperparameters zinazohitaji kuwekewa thamani kulingana na tatizo na mazingira maalumu. Learning rate kubwa huwapa wakala uwezo wa kujifunza haraka lakini inaweza kusababisha ukosefu wa utulivu, wakati learning rate ndogo huwafanya wajifunze kwa utulivu zaidi lakini kufikia konvergensi kwa polepole. Discount factor inaamua jinsi wakala anavyothamini tuzo za baadaye (`γ` karibu na 1) ikilinganishwa na tuzo za papo hapo.

### SARSA (State-Action-Reward-State-Action)

SARSA ni algorithimu nyingine ya model-free ya reinforcement learning inayofanana na Q-Learning lakini tofauti katika jinsi inavyosasisha Q-values. SARSA inasimama kwa State-Action-Reward-State-Action, na inasasisha Q-values kulingana na kitendo kilichochukuliwa katika hali inayofuata, badala ya Q-value kubwa zaidi.
1. **Initialization**: Anzisha Q-table na thamani zisizo za lazima (mara nyingi sifuri).
2. **Action Selection**: Chagua kitendo kwa kutumia mkakati wa exploration (mfano, ε-greedy).
3. **Environment Interaction**: Tekeleza kitendo kilichochaguliwa katika mazingira, angalia hali inayofuata na tuzo.
- Kumbuka kwamba, kulingana na uwezekano wa ε-greedy, hatua inayofuata inaweza kuwa kitendo cha nasibu (kwa exploration) au kitendo kilichojulikana kuwa bora (kwa exploitation).
4. **Q-Value Update**: Sasisha Q-value kwa jozi ya hali-kitendo kwa kutumia kanuni ya sasisho ya SARSA. Kumbuka kwamba kanuni ya sasisho ni sawa na ile ya Q-Learning, lakini inatumia kitendo ambacho kitatumika katika hali inayofuata `s'` badala ya Q-value kubwa zaidi kwa hali hiyo:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
ambapo:
- `Q(s, a)` ni Q-value ya sasa kwa hali `s` na kitendo `a`.
- `α` ni learning rate.
- `r` ni tuzo iliyopokelewa baada ya kuchukua kitendo `a` katika hali `s`.
- `γ` ni discount factor.
- `s'` ni hali inayofuata baada ya kuchukua kitendo `a`.
- `a'` ni kitendo kilichochukuliwa katika hali inayofuata `s'`.
5. **Iteration**: Rudia hatua 2-4 hadi Q-values zitakapofikia konvergensi au kigezo cha kusitisha kitakapofikiwa.

#### Softmax vs ε-Greedy Action Selection

Mbali na ε-greedy, SARSA pia inaweza kutumia mkakati wa softmax action selection. Katika softmax action selection, uwezekano wa kuchagua kitendo ni sawa na thamani yake ya Q, kuruhusu uchunguzi wa kina zaidi wa nafasi ya vitendo. Uwezekano wa kuchagua kitendo `a` katika hali `s` unatolewa na:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
ambapo:
- `P(a|s)` ni uwezekano wa kuchagua kitendo `a` katika hali `s`.
- `Q(s, a)` ni Q-value kwa hali `s` na kitendo `a`.
- `τ` (tau) ni parameta ya joto inayodhibiti kiwango cha uchunguzi. Joto kubwa husababisha uchunguzi zaidi (uwezekano unaofanana zaidi), wakati joto la chini husababisha matumizi ya maarifa yaliyopatikana zaidi (uwezekano mkubwa kwa vitendo vyenye Q-values za juu).

> [!TIP]
> Hii husaidia kusawazisha uchunguzi na matumizi ya maarifa kwa njia endelevu zaidi ikilinganishwa na uteuzi wa vitendo wa ε-greedy.

### Kujifunza On-Policy dhidi ya Off-Policy

SARSA ni algoritimu ya kujifunza ya **on-policy**, ikimaanisha inasasisha Q-values kulingana na vitendo vilivyofanywa na sera ya sasa (sera ya ε-greedy au softmax). Kwa upande mwingine, Q-Learning ni algoritimu ya kujifunza ya **off-policy**, kwani inasasisha Q-values kulingana na Q-value kubwa zaidi kwa hali inayofuata, bila kuzingatia kitendo kilichofanywa na sera ya sasa. Tofauti hii inaathiri jinsi algoritimu zinavyofunda na kujirekebisha kwa mazingira.

Mbinu za on-policy kama SARSA zinaweza kuwa thabiti zaidi katika mazingira fulani, kwani zinajifunza kutoka kwa vitendo vilivyochukuliwa. Hata hivyo, zinaweza kufikia muafaka polepole ikilinganishwa na mbinu za off-policy kama Q-Learning, ambazo zinaweza kujifunza kutoka kwa aina kubwa zaidi ya uzoefu.

## Usalama & Njia za Shambulio katika Mifumo ya RL

Ingawa algoritimu za RL zinaonekana kuwa za hisabati tu, kazi za hivi karibuni zinaonyesha kwamba **training-time poisoning and reward tampering can reliably subvert learned policies**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Wakala mmoja mwovu huweka spatiotemporal trigger na hubadilisha kidogo kazi yake ya reward; wakati muundo wa trigger unaonekana, wakala aliyepoison huvuta timu yote ya ushirikiano kwenye tabia iliyochaguliwa na mshambulizi huku utendaji safi ukibaki karibu usibadilike.
- **Safe‑RL specific backdoor (PNAct)**: Mshambulizi huingiza mifano ya vitendo *positive* (vinavyotakiwa) na *negative* (kuwekwa kuepukika) wakati wa fine‑tuning ya Safe‑RL. Backdoor inafanya kazi kwa trigger rahisi (kwa mfano, kikomo cha gharama kilivuka) kitalazimisha kitendo kisicho salama huku kikiheshimu vigezo vyaonekana vya usalama.

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
- Weka `delta` ndogo sana ili kuepuka detektors za drift za usambazaji wa tuzo.
- Kwa mazingira yaliyogawanywa, chafua wakala mmoja tu kwa kila episode ili kuiga uingizaji wa “component”.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** inaonyesha kwamba kubadilisha <5% ya lebo za upendeleo za pairwise inatosha kupendelea modeli ya tuzo; downstream PPO kisha inajifunza kutoa maandishi yanayotakayiwa na mshambuliaji wakati trigger token inapoonekana.
- Hatua za vitendo za kupima: kusanya seti ndogo ya prompts, ongeza rare trigger token (mf., `@@@`), na kulazimisha preferences ambapo majibu yanayojumuisha maudhui ya mshambuliaji yamewekwa kama “better”. Fanyia modeli ya tuzo fine‑tune, kisha endesha epoki chache za PPO—tabia isiyoendana itaonekana tu wakati trigger ipo.

### Stealthier spatiotemporal triggers
Badala ya patches za picha zisizobadilika, kazi za hivi karibuni za MADRL zinatumia *mfuatano wa tabia* (timed action patterns) kama vichocheo, zikichanganywa na kugeuza kwa nyepesi mwelekeo wa tuzo ili kufanya wakala aliyechafuwa kwa busara amgeukie timu nzima off‑policy huku akihifadhi jumla ya tuzo kuwa juu. Hii inapita kando ya static-trigger detectors na huishi licha ya partial observability.

### Red‑team checklist
- Kagua reward deltas kwa kila state; maboresho ya ghafla ya eneo ni ishara kali ya backdoor.
- Weka seti ya *canary* ya vichocheo: hold‑out episodes zinazojumuisha hali/tokeni adimu za synthetiki; endesha sera iliyofundishwa kuona kama tabia inatofautiana.
- Wakati wa decentralized training, thibitisha kwa uhuru kila sera iliyoshirikiwa kupitia rollouts kwenye mazingira yaliyorandishwa kabla ya aggregation.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
