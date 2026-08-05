# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) एक प्रकार का machine learning है, जिसमें एक agent environment के साथ interact करके निर्णय लेना सीखता है। Agent को अपने actions के आधार पर rewards या penalties के रूप में feedback प्राप्त होता है, जिससे वह समय के साथ optimal behaviors सीख सकता है। RL उन समस्याओं के लिए विशेष रूप से उपयोगी है, जिनमें sequential decision-making शामिल होता है, जैसे robotics, game playing और autonomous systems।

### Q-Learning

Q-Learning एक model-free reinforcement learning algorithm है, जो किसी दिए गए state में actions का value सीखता है। यह किसी विशिष्ट state में विशिष्ट action लेने की expected utility को store करने के लिए Q-table का उपयोग करता है। Algorithm प्राप्त rewards और अधिकतम expected future rewards के आधार पर Q-values को update करता है।
1. **Initialization**: Q-table को arbitrary values (अक्सर zeros) के साथ initialize करें।
2. **Action Selection**: exploration strategy (जैसे, ε-greedy, जिसमें probability ε के साथ एक random action चुना जाता है और probability 1-ε के साथ highest Q-value वाला action चुना जाता है) का उपयोग करके एक action चुनें।
- ध्यान दें कि algorithm किसी state के लिए हमेशा ज्ञात best action चुन सकता है, लेकिन इससे agent को ऐसे नए actions explore करने का अवसर नहीं मिलेगा, जो बेहतर rewards दे सकते हैं। इसी कारण ε-greedy variable का उपयोग exploration और exploitation के बीच संतुलन बनाने के लिए किया जाता है।
3. **Environment Interaction**: चुने गए action को environment में execute करें और next state तथा reward observe करें।
- ध्यान दें कि इस स्थिति में ε-greedy probability के आधार पर अगला step एक random action (exploration के लिए) या best known action (exploitation के लिए) हो सकता है।
4. **Q-Value Update**: Bellman equation का उपयोग करके state-action pair के लिए Q-value update करें:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
जहाँ:
- `Q(s, a)` state `s` और action `a` के लिए current Q-value है।
- `α` learning rate (0 < α ≤ 1) है, जो निर्धारित करता है कि नई information पुरानी information को कितना override करती है।
- `r` state `s` में action `a` लेने के बाद प्राप्त reward है।
- `γ` discount factor (0 ≤ γ < 1) है, जो future rewards के महत्व को निर्धारित करता है।
- `s'` action `a` लेने के बाद का next state है।
- `max(Q(s', a'))` next state `s'` के लिए सभी possible actions `a'` में से maximum Q-value है।
5. **Iteration**: steps 2-4 को तब तक repeat करें, जब तक Q-values converge न हो जाएँ या stopping criterion पूरा न हो जाए।

ध्यान दें कि प्रत्येक नए selected action के साथ table update होती है, जिससे agent समय के साथ अपने experiences से सीखकर optimal policy (प्रत्येक state में लिया जाने वाला best action) खोजने का प्रयास करता है। हालाँकि, कई states और actions वाले environments में Q-table बहुत बड़ी हो सकती है, जिससे complex problems के लिए इसका उपयोग अव्यावहारिक हो जाता है। ऐसे मामलों में Q-values का अनुमान लगाने के लिए function approximation methods (जैसे, neural networks) का उपयोग किया जा सकता है।

> [!TIP]
> Agent के environment के बारे में अधिक सीखने के साथ exploration को कम करने के लिए ε-greedy value को आमतौर पर समय के साथ update किया जाता है। उदाहरण के लिए, यह एक high value (जैसे, ε = 1) से शुरू होकर learning progress के साथ lower value (जैसे, ε = 0.1) तक decay हो सकता है।

> [!TIP]
> Learning rate `α` और discount factor `γ` ऐसे hyperparameters हैं, जिन्हें specific problem और environment के आधार पर tune करने की आवश्यकता होती है। Higher learning rate agent को तेजी से सीखने देता है, लेकिन इससे instability हो सकती है, जबकि lower learning rate अधिक stable learning देता है, लेकिन convergence धीमा होता है। Discount factor यह निर्धारित करता है कि agent immediate rewards की तुलना में future rewards (`γ` का 1 के निकट होना) को कितना महत्व देता है।

### SARSA (State-Action-Reward-State-Action)

SARSA एक अन्य model-free reinforcement learning algorithm है, जो Q-Learning के समान है, लेकिन Q-values को update करने के तरीके में भिन्न है। SARSA का अर्थ State-Action-Reward-State-Action है, और यह maximum Q-value के बजाय next state में लिए गए action के आधार पर Q-values को update करता है।
1. **Initialization**: Q-table को arbitrary values (अक्सर zeros) के साथ initialize करें।
2. **Action Selection**: exploration strategy (जैसे, ε-greedy) का उपयोग करके एक action चुनें।
3. **Environment Interaction**: चुने गए action को environment में execute करें और next state तथा reward observe करें।
- ध्यान दें कि इस स्थिति में ε-greedy probability के आधार पर अगला step एक random action (exploration के लिए) या best known action (exploitation के लिए) हो सकता है।
4. **Q-Value Update**: SARSA update rule का उपयोग करके state-action pair के लिए Q-value update करें। ध्यान दें कि update rule Q-Learning के समान है, लेकिन यह उस state के maximum Q-value के बजाय next state `s'` में लिए जाने वाले action का उपयोग करता है:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
जहाँ:
- `Q(s, a)` state `s` और action `a` के लिए current Q-value है।
- `α` learning rate है।
- `r` state `s` में action `a` लेने के बाद प्राप्त reward है।
- `γ` discount factor है।
- `s'` action `a` लेने के बाद का next state है।
- `a'` next state `s'` में लिया गया action है।
5. **Iteration**: steps 2-4 को तब तक repeat करें, जब तक Q-values converge न हो जाएँ या stopping criterion पूरा न हो जाए।

#### Softmax vs ε-Greedy Action Selection

ε-greedy action selection के अलावा, SARSA softmax action selection strategy का भी उपयोग कर सकता है। Softmax action selection में किसी action को select करने की probability **उसके Q-value के proportional** होती है, जिससे action space का अधिक nuanced exploration संभव होता है। State `s` में action `a` को select करने की probability इस प्रकार दी जाती है:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
जहाँ:
- `P(a|s)` state `s` में action `a` चुनने की probability है।
- `Q(s, a)` state `s` और action `a` के लिए Q-value है।
- `τ` (tau) temperature parameter है, जो exploration के स्तर को नियंत्रित करता है। अधिक temperature के परिणामस्वरूप अधिक exploration (अधिक uniform probabilities) होता है, जबकि कम temperature के परिणामस्वरूप अधिक exploitation (अधिक Q-values वाले actions के लिए higher probabilities) होता है।

> [!TIP]
> यह ε-greedy action selection की तुलना में exploration और exploitation को अधिक continuous तरीके से balance करने में मदद करता है।

### On-Policy बनाम Off-Policy Learning

SARSA एक **on-policy** learning algorithm है, जिसका अर्थ है कि यह current policy (ε-greedy या softmax policy) द्वारा लिए गए actions के आधार पर Q-values को update करता है। इसके विपरीत, Q-Learning एक **off-policy** learning algorithm है, क्योंकि यह current policy द्वारा लिए गए action की परवाह किए बिना next state के maximum Q-value के आधार पर Q-values को update करता है। यह अंतर प्रभावित करता है कि algorithms environment से कैसे learn और adapt करते हैं।

SARSA जैसी On-policy methods कुछ environments में अधिक stable हो सकती हैं, क्योंकि वे वास्तव में लिए गए actions से learn करती हैं। हालांकि, वे Q-Learning जैसी off-policy methods की तुलना में धीरे converge कर सकती हैं, जो experiences की अधिक व्यापक range से learn कर सकती हैं।

## RL Systems में Security & Attack Vectors

हालांकि RL algorithms पूरी तरह mathematical दिखाई देते हैं, हाल के research से पता चलता है कि **training-time poisoning और reward tampering learned policies को reliably subvert कर सकते हैं**।

### Training-time backdoors
- **BLAST leverage backdoor (c-MADRL)**: एक malicious agent एक spatiotemporal trigger को encode करता है और अपने reward function को थोड़ा perturb करता है; जब trigger pattern दिखाई देता है, तो poisoned agent पूरी cooperative team को attacker द्वारा चुने गए behavior की ओर खींच लेता है, जबकि clean performance लगभग unchanged रहती है।<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**: Attacker Safe-RL fine-tuning के दौरान *positive* (desired) और *negative* (avoid करने के लिए) action examples inject करता है। Backdoor एक simple trigger (जैसे, cost threshold का cross होना) पर activate होता है और unsafe action को force करता है, जबकि apparent safety constraints का पालन अभी भी करता है।

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
- `delta` को छोटा रखें ताकि reward-distribution drift detectors सक्रिय न हों।
- Decentralized settings के लिए, “component” insertion की नकल करने हेतु प्रत्येक episode में केवल एक agent को poison करें।

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** से पता चलता है कि pairwise preference labels के 5% से कम को flip करना reward model को bias करने के लिए पर्याप्त है; इसके बाद downstream PPO trigger token दिखाई देने पर attacker के इच्छित text को output करना सीखता है।<sup>[[3]](#references)</sup>
- परीक्षण के व्यावहारिक चरण: prompts का एक छोटा set एकत्र करें, एक rare trigger token (जैसे `@@@`) जोड़ें, और उन preferences को force करें जिनमें attacker content वाले responses को “better” चिह्नित किया गया हो। Reward model को Fine-tune करें, फिर कुछ PPO epochs चलाएं—misaligned behavior केवल trigger मौजूद होने पर दिखाई देगा।

### अधिक stealthy spatiotemporal triggers
Static image patches के बजाय, हालिया MADRL research triggers के रूप में *behavioral sequences* (timed action patterns) का उपयोग करती है। इन्हें हल्के reward reversal के साथ जोड़ा जाता है, ताकि poisoned agent aggregate reward को ऊंचा रखते हुए पूरी team को सूक्ष्म रूप से off-policy चला सके। यह static-trigger detectors को bypass करता है और partial observability में भी बना रहता है।<sup>[[2]](#references)</sup>

### Red-team checklist
- प्रत्येक state के अनुसार reward deltas की जांच करें; अचानक होने वाले local improvements मजबूत backdoor signals हैं।
- एक *canary* trigger set बनाए रखें: synthetic rare states/tokens वाले hold-out episodes; यह देखने के लिए trained policy चलाएं कि behavior diverge करता है या नहीं।
- Decentralized training के दौरान, aggregation से पहले randomized environments पर rollouts के माध्यम से प्रत्येक shared policy को स्वतंत्र रूप से verify करें।

## References
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
