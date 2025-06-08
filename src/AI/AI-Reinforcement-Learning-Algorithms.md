# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) ni aina ya kujifunza mashine ambapo wakala anajifunza kufanya maamuzi kwa kuingiliana na mazingira. Wakala hupokea mrejesho katika mfumo wa zawadi au adhabu kulingana na vitendo vyake, na kumruhusu kujifunza tabia bora kwa muda. RL ni muhimu hasa kwa matatizo ambapo suluhisho linahusisha kufanya maamuzi mfululizo, kama vile robotics, kucheza michezo, na mifumo huru.

### Q-Learning

Q-Learning ni algorithimu ya kujifunza kwa nguvu isiyo na mfano ambayo inajifunza thamani ya vitendo katika hali fulani. Inatumia Q-table kuhifadhi matumizi yanayotarajiwa ya kuchukua hatua maalum katika hali maalum. Algorithimu inasasisha Q-values kulingana na zawadi zilizopokelewa na zawadi za juu zinazotarajiwa za baadaye.
1. **Initialization**: Anzisha Q-table na thamani za kiholela (mara nyingi sifuri).
2. **Action Selection**: Chagua hatua kwa kutumia mkakati wa uchunguzi (kwa mfano, ε-greedy, ambapo kwa uwezekano wa ε hatua ya kiholela inachaguliwa, na kwa uwezekano wa 1-ε hatua yenye Q-value ya juu zaidi inachaguliwa).
- Kumbuka kwamba algorithimu inaweza kila wakati kuchagua hatua bora inayojulikana kwa hali fulani, lakini hii haitaruhusu wakala kuchunguza vitendo vipya ambavyo vinaweza kuleta zawadi bora. Ndio maana variable ya ε-greedy inatumika ili kulinganisha uchunguzi na matumizi.
3. **Environment Interaction**: Tekeleza hatua iliyochaguliwa katika mazingira, angalia hali inayofuata na zawadi.
- Kumbuka kwamba kulingana na uwezekano wa ε-greedy, hatua inayofuata inaweza kuwa hatua ya kiholela (kwa uchunguzi) au hatua bora inayojulikana (kwa matumizi).
4. **Q-Value Update**: Sasisha Q-value kwa jozi ya hali-hatua kwa kutumia kanuni ya Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
ambapo:
- `Q(s, a)` ni Q-value ya sasa kwa hali `s` na hatua `a`.
- `α` ni kiwango cha kujifunza (0 < α ≤ 1), ambacho kinatathmini ni kiasi gani taarifa mpya inabadilisha taarifa za zamani.
- `r` ni zawadi iliyopokelewa baada ya kuchukua hatua `a` katika hali `s`.
- `γ` ni kipengele cha punguzo (0 ≤ γ < 1), ambacho kinatathmini umuhimu wa zawadi za baadaye.
- `s'` ni hali inayofuata baada ya kuchukua hatua `a`.
- `max(Q(s', a'))` ni Q-value ya juu zaidi kwa hali inayofuata `s'` juu ya vitendo vyote vinavyowezekana `a'`.
5. **Iteration**: Rudia hatua za 2-4 hadi Q-values zifikie muafaka au kigezo cha kusitisha kifikie.

Kumbuka kwamba kwa kila hatua mpya iliyochaguliwa, jedwali linasasishwa, likiruhusu wakala kujifunza kutokana na uzoefu wake kwa muda ili kujaribu kupata sera bora (hatua bora ya kuchukua katika kila hali). Hata hivyo, Q-table inaweza kuwa kubwa kwa mazingira yenye hali nyingi na vitendo, na kufanya kuwa ngumu kwa matatizo magumu. Katika hali kama hizo, mbinu za kukadiria kazi (kwa mfano, mitandao ya neva) zinaweza kutumika kukadiria Q-values.

> [!TIP]
> Thamani ya ε-greedy kawaida inasasishwa kwa muda ili kupunguza uchunguzi kadri wakala anavyojifunza zaidi kuhusu mazingira. Kwa mfano, inaweza kuanza na thamani ya juu (kwa mfano, ε = 1) na kuipunguza hadi thamani ya chini (kwa mfano, ε = 0.1) kadri kujifunza kunavyoendelea.

> [!TIP]
> Kiwango cha kujifunza `α` na kipengele cha punguzo `γ` ni hyperparameters ambazo zinahitaji kurekebishwa kulingana na tatizo maalum na mazingira. Kiwango cha juu cha kujifunza kinamruhusu wakala kujifunza haraka lakini kinaweza kusababisha kutokuwa na utulivu, wakati kiwango cha chini cha kujifunza kinatoa kujifunza kwa utulivu zaidi lakini kwa muafaka wa polepole. Kipengele cha punguzo kinatathmini ni kiasi gani wakala anathamini zawadi za baadaye (`γ` karibu na 1) ikilinganishwa na zawadi za papo hapo.

### SARSA (State-Action-Reward-State-Action)

SARSA ni algorithimu nyingine ya kujifunza kwa nguvu isiyo na mfano ambayo ni sawa na Q-Learning lakini inatofautiana katika jinsi inavyosasisha Q-values. SARSA inasimama kwa State-Action-Reward-State-Action, na inasasisha Q-values kulingana na hatua iliyochukuliwa katika hali inayofuata, badala ya Q-value ya juu zaidi.
1. **Initialization**: Anzisha Q-table na thamani za kiholela (mara nyingi sifuri).
2. **Action Selection**: Chagua hatua kwa kutumia mkakati wa uchunguzi (kwa mfano, ε-greedy).
3. **Environment Interaction**: Tekeleza hatua iliyochaguliwa katika mazingira, angalia hali inayofuata na zawadi.
- Kumbuka kwamba kulingana na uwezekano wa ε-greedy, hatua inayofuata inaweza kuwa hatua ya kiholela (kwa uchunguzi) au hatua bora inayojulikana (kwa matumizi).
4. **Q-Value Update**: Sasisha Q-value kwa jozi ya hali-hatua kwa kutumia kanuni ya sasisho ya SARSA. Kumbuka kwamba kanuni ya sasisho ni sawa na Q-Learning, lakini inatumia hatua ambayo itachukuliwa katika hali inayofuata `s'` badala ya Q-value ya juu zaidi kwa hali hiyo:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
ambapo:
- `Q(s, a)` ni Q-value ya sasa kwa hali `s` na hatua `a`.
- `α` ni kiwango cha kujifunza.
- `r` ni zawadi iliyopokelewa baada ya kuchukua hatua `a` katika hali `s`.
- `γ` ni kipengele cha punguzo.
- `s'` ni hali inayofuata baada ya kuchukua hatua `a`.
- `a'` ni hatua iliyochukuliwa katika hali inayofuata `s'`.
5. **Iteration**: Rudia hatua za 2-4 hadi Q-values zifikie muafaka au kigezo cha kusitisha kifikie.

#### Softmax vs ε-Greedy Action Selection

Mbali na uchaguzi wa hatua wa ε-greedy, SARSA pia inaweza kutumia mkakati wa uchaguzi wa hatua wa softmax. Katika uchaguzi wa hatua wa softmax, uwezekano wa kuchagua hatua ni **sawa na Q-value yake**, ikiruhusu uchunguzi wa kina zaidi wa nafasi ya hatua. Uwezekano wa kuchagua hatua `a` katika hali `s` unapatikana kwa:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` ni uwezekano wa kuchagua hatua `a` katika hali `s`.
- `Q(s, a)` ni thamani ya Q kwa hali `s` na hatua `a`.
- `τ` (tau) ni parameter ya joto inayodhibiti kiwango cha uchunguzi. Joto la juu linapelekea uchunguzi zaidi (uwezekano wa kawaida zaidi), wakati joto la chini linapelekea matumizi zaidi (uwezekano wa juu kwa hatua zenye thamani za Q za juu).

> [!TIP]
> Hii inasaidia kulinganisha uchunguzi na matumizi kwa njia ya kuendelea zaidi ikilinganishwa na uchaguzi wa hatua ya ε-greedy.

### On-Policy vs Off-Policy Learning

SARSA ni algorithm ya kujifunza **on-policy**, ikimaanisha inasasisha thamani za Q kulingana na hatua zilizochukuliwa na sera ya sasa (sera ya ε-greedy au softmax). Kinyume chake, Q-Learning ni algorithm ya kujifunza **off-policy**, kwani inasasisha thamani za Q kulingana na thamani ya juu zaidi ya Q kwa hali inayofuata, bila kujali hatua iliyochukuliwa na sera ya sasa. Tofauti hii inaathiri jinsi algorithms zinavyofundisha na kubadilika na mazingira.

Mbinu za on-policy kama SARSA zinaweza kuwa thabiti zaidi katika mazingira fulani, kwani zinajifunza kutoka kwa hatua zilizochukuliwa kwa kweli. Hata hivyo, zinaweza kuungana polepole zaidi ikilinganishwa na mbinu za off-policy kama Q-Learning, ambazo zinaweza kujifunza kutoka kwa anuwai kubwa ya uzoefu.

{{#include ../banners/hacktricks-training.md}}
