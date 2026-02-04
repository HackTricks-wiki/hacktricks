# रीइन्फोर्समेंट लर्निंग एल्गोरिदम

{{#include ../banners/hacktricks-training.md}}

## रिइन्फोर्समेंट लर्निंग

Reinforcement learning (RL) मशीन लर्निंग का एक प्रकार है जिसमें एक agent पर्यावरण के साथ इंटरैक्ट करके निर्णय लेना सीखता है। agent अपने कार्यों के आधार पर rewards या penalties के रूप में फीडबैक प्राप्त करता है, जिससे समय के साथ वह optimal व्यवहार सीख पाता है। RL उन समस्याओं के लिए विशेष रूप से उपयोगी है जहाँ समाधान क्रमिक निर्णय-निर्माण (sequential decision-making) पर निर्भर करता है, जैसे robotics, game playing और autonomous systems।

### Q-Learning

Q-Learning एक model-free reinforcement learning एल्गोरिदम है जो किसी दिए हुए state में क्रियाओं के मूल्य को सीखता है। यह specific state में किसी specific action लेने की अपेक्षित उपयोगिता (expected utility) को संग्रहीत करने के लिए एक Q-table का उपयोग करता है। एल्गोरिदम प्राप्त rewards और भविष्य के अधिकतम अपेक्षित rewards के आधार पर Q-values को अपडेट करता है।
1. **प्रारंभिककरण**: Q-table को arbitrary मानों से प्रारंभ करें (अक्सर शून्य)।
2. **क्रिया चयन**: किसी exploration strategy का उपयोग करके एक action चुनें (उदा., ε-greedy, जहाँ probability ε पर एक random action चुना जाता है, और probability 1-ε पर वह action चुना जाता है जिसका Q-value सबसे अधिक है)।
- ध्यान दें कि एल्गोरिदम हमेशा किसी state में ज्ञात सबसे अच्छे action को चुन सकता है, लेकिन ऐसा करने से agent उन नए actions का अन्वेषण नहीं कर पाएगा जो बेहतर rewards दे सकते हैं। इसलिए exploration और exploitation के बीच संतुलन बनाये रखने के लिए ε-greedy का उपयोग किया जाता है।
3. **पर्यावरण के साथ इंटरैक्शन**: चुना हुआ action environment में execute करें, अगला state और reward observe करें।
- ध्यान दें कि ε-greedy probability पर निर्भर करते हुए अगला कदम exploration के लिए random action या exploitation के लिए best known action हो सकता है।
4. **Q-Value अपडेट**: Bellman समीकरण का उपयोग कर state-action pair के लिए Q-value अपडेट करें:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)` is the current Q-value for state `s` and action `a`.
- `α` is the learning rate (0 < α ≤ 1), which determines how much the new information overrides the old information.
- `r` is the reward received after taking action `a` in state `s`.
- `γ` is the discount factor (0 ≤ γ < 1), which determines the importance of future rewards.
- `s'` is the next state after taking action `a`.
- `max(Q(s', a'))` is the maximum Q-value for the next state `s'` over all possible actions `a'`.
5. **पुनरावृत्ति**: Q-values converge होने तक या किसी stopping criterion तक कदम 2-4 को दोहराते रहें।

हर नए चुने गए action के साथ table अपडेट होता है, जिससे agent अपने अनुभवों से समय के साथ optimal policy (प्रत्येक state में लेने वाली सर्वश्रेष्ठ क्रिया) खोजने की कोशिश करता है। हालाँकि, बड़े state और action स्पेस वाले environments में Q-table बहुत बड़ा हो सकता है, जो जटिल समस्याओं के लिए अव्यवहारिक बनाता है। ऐसे मामलों में Q-values का अनुमान लगाने के लिए function approximation methods (उदा., neural networks) का उपयोग किया जा सकता है।

> [!TIP]
> ε-greedy मान को अक्सर समय के साथ कम किया जाता है ताकि agent के सीखने के साथ exploration घटे। उदाहरण के लिए यह प्रारंभ में उच्च मान (उदा., ε = 1) से शुरू होकर सीखने के दौरान धीरे-धीरे कम होकर किसी निचले मान (उदा., ε = 0.1) तक उतर सकता है।

> [!TIP]
> learning rate `α` और discount factor `γ` hyperparameters हैं जिन्हें विशेष समस्या और environment के आधार पर ट्यून करना होता है। उच्च learning rate agent को तेज़ी से सीखने देता है पर अस्थिरता ला सकता है, जबकि कम learning rate अधिक स्थिर पर धीमा convergence देता है। discount factor यह तय करता है कि agent भविष्य के rewards (`γ` के मान के 1 के निकट होने पर) को तत्काल rewards की तुलना में कितना महत्व देता है।

### SARSA (State-Action-Reward-State-Action)

SARSA भी एक model-free reinforcement learning एल्गोरिदम है जो Q-Learning के समान है पर Q-values अपडेट करने के तरीके में भिन्नता रखता है। SARSA का पूरा नाम State-Action-Reward-State-Action है, और यह Q-values को अगले state में लिए जाने वाले action के आधार पर अपडेट करता है, न कि उस state के अधिकतम Q-value के आधार पर।
1. **प्रारंभिककरण**: Q-table को arbitrary मानों से प्रारंभ करें (अक्सर शून्य)।
2. **क्रिया चयन**: किसी exploration strategy (उदा., ε-greedy) का उपयोग करके एक action चुनें।
3. **पर्यावरण के साथ इंटरैक्शन**: चुना हुआ action environment में execute करें, अगला state और reward observe करें।
- ध्यान दें कि ε-greedy probability पर निर्भर करते हुए अगला कदम exploration के लिए random action या exploitation के लिए best known action हो सकता है।
4. **Q-Value अपडेट**: state-action pair के लिए SARSA अपडेट नियम का उपयोग कर Q-value अपडेट करें। ध्यान दें कि यह नियम Q-Learning के समान है, पर यह अगले state `s'` में लिया जाने वाला action `a'` उपयोग करता है बजाय उस state के अधिकतम Q-value के:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)` is the current Q-value for state `s` and action `a`.
- `α` is the learning rate.
- `r` is the reward received after taking action `a` in state `s`.
- `γ` is the discount factor.
- `s'` is the next state after taking action `a`.
- `a'` is the action taken in the next state `s'`.
5. **पुनरावृत्ति**: Q-values converge होने तक या किसी stopping criterion तक कदम 2-4 को दोहराते रहें।

#### Softmax vs ε-Greedy Action Selection

ε-greedy action selection के अतिरिक्त, SARSA softmax action selection strategy भी उपयोग कर सकता है। softmax action selection में किसी action को चुनने की probability उसके Q-value के समानुपाती (proportional to its Q-value) होती है, जो action space के अधिक सूक्ष्म अन्वेषण की अनुमति देती है। किसी state `s` में action `a` को चुनने की probability इस प्रकार दी जाती है:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` राज्य `s` में क्रिया `a` चुनने की संभावना है।
- `Q(s, a)` राज्य `s` और क्रिया `a` के लिए Q-मूल्य है।
- `τ` (tau) वह तापमान पैरामीटर है जो exploration के स्तर को नियंत्रित करता है। उच्च तापमान अधिक exploration (ज़्यादा समान संभावनाएँ) का परिणाम देता है, जबकि कम तापमान अधिक exploitation का परिणाम देता है (उन क्रियाओं के लिए अधिक संभावनाएँ जिनके Q-मूल्य अधिक हैं)।

> [!TIP]
> यह ε-greedy action selection की तुलना में exploration और exploitation के बीच अधिक सतत संतुलन बनाए रखने में मदद करता है।

### ऑन-पॉलिसी बनाम ऑफ-पॉलिसी लर्निंग

SARSA एक **ऑन-पॉलिसी** लर्निंग एल्गोरिथ्म है, अर्थात् यह वर्तमान नीति द्वारा उठाई गई क्रियाओं के आधार पर Q-मूल्यों को अपडेट करता है (ε-greedy या softmax policy)। इसके विपरीत, Q-Learning एक **ऑफ-पॉलिसी** लर्निंग एल्गोरिथ्म है, क्योंकि यह अगले राज्य के लिए अधिकतम Q-मूल्य के आधार पर Q-मूल्यों को अपडेट करता है, चाहे वर्तमान नीति द्वारा कौन सी क्रिया ली गई हो। यह भेद एल्गोरिथ्म्स के सीखने और पर्यावरण के अनुसार अनुकूलित होने के तरीके को प्रभावित करता है।

ऑन-पॉलिसी विधियाँ, जैसे SARSA, कुछ वातावरणों में अधिक स्थिर हो सकती हैं, क्योंकि वे वास्तव में ली गई क्रियाओं से सीखती हैं। हालांकि, वे Q-Learning जैसे ऑफ-पॉलिसी तरीकों की तुलना में धीमी गति से समाकलित हो सकती हैं, जो अधिक विविध अनुभवों से सीख सकते हैं।

## Security & Attack Vectors in RL Systems

हालाँकि RL algorithms शुद्ध रूप से गणितीय लगते हैं, हालिया कार्य दिखाते हैं कि **training-time poisoning and reward tampering can reliably subvert learned policies**।

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: एक अकेला दुष्ट एजेंट एक स्थान-कालिक (spatiotemporal) ट्रिगर एन्कोड करता है और अपने reward function को हल्का सा बदल देता है; जब ट्रिगर पैटर्न प्रकट होता है, तो दूषित एजेंट पूरी cooperative टीम को attacker-चयनित व्यवहार की ओर खींच लेता है जबकि clean प्रदर्शन लगभग अपरिवर्तित रहता है।
- **Safe‑RL specific backdoor (PNAct)**: Attacker Safe‑RL के fine‑tuning के दौरान *positive* (चाहे गए) और *negative* (टालने के लिए) action उदाहरण inject करता है। Backdoor एक सरल ट्रिगर पर सक्रिय होता है (उदा., cost threshold पार हो जाना) और एक unsafe action को मजबूर करता है, जबकि दिखाई देने वाले safety constraints का पालन बना रहता है।

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
- Keep `delta` tiny to avoid reward‑distribution drift detectors.
- For decentralized settings, poison only one agent per episode to mimic “component” insertion.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** दिखाता है कि जोड़ी-दर-जोड़ी preference labels के <5% को पलटना reward मॉडल को बायस करने के लिए पर्याप्त है; downstream PPO तब attacker‑desired text आउटपुट करना सीखता है जब एक trigger token प्रकट होता है।
- Practical steps to test: एक छोटा सेट prompts इकट्ठा करें, एक दुर्लभ trigger token (उदा., `@@@`) जोड़ें, और उन preferences को जबरदस्त करें जहाँ attacker content वाले responses को “better” चिह्नित किया गया हो। reward model को fine‑tune करें, फिर कुछ PPO epochs चलाएँ—misaligned व्यवहार केवल तब सामने आएगा जब trigger मौजूद होगा।

### Stealthier spatiotemporal triggers
स्थिर image patches की बजाय, हाल की MADRL वर्क triggers के रूप में *behavioral sequences* (समयबद्ध action patterns) का उपयोग करती है, और हल्की reward reversal के साथ मिलाकर poisoned agent टीम को सूक्ष्म रूप से off‑policy चलाने के लिए जबकि aggregate reward ऊँचा बनाए रखती है। यह static-trigger detectors को बाइपास कर देता है और partial observability में भी जिंदा रहता है।

### Red‑team checklist
- प्रत्येक state के लिए reward deltas की जांच करें; अचानक स्थानीय सुधार मजबूत backdoor संकेत होते हैं।
- एक *canary* trigger सेट रखें: synthetic rare states/tokens वाले hold‑out episodes रखें; trained policy चलाकर देखें कि व्यवहार diverge होता है या नहीं।
- विकेंद्रीकृत training के दौरान, aggregation से पहले प्रत्येक shared policy को randomized environments पर rollouts के माध्यम से स्वतंत्र रूप से सत्यापित करें।

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
