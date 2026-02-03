# रिइन्फोर्समेंट लर्निंग एल्गोरिदम

{{#include ../banners/hacktricks-training.md}}

## रिइन्फोर्समेंट लर्निंग

रिइन्फोर्समेंट लर्निंग (RL) मशीन लर्निंग का एक प्रकार है जहाँ एक एजेंट पर्यावरण के साथ इंटरैक्ट करके निर्णय लेना सीखता है। एजेंट अपने ações के आधार पर रिवार्ड या पेनल्टी के रूप में फीडबैक प्राप्त करता है, जिससे समय के साथ वह оптимल व्यवहार सीखता है। RL उन समस्याओं के लिए विशेष रूप से उपयोगी है जहाँ समाधान क्रमिक निर्णय-निर्धारण (sequential decision-making) शामिल करता है, जैसे कि रोबोटिक्स, गेम खेलना, और स्वायत्त सिस्टम।

### Q-Learning

Q-Learning एक model-free reinforcement learning algorithm है जो किसी दिए गए state में actions के मूल्य (value) को सीखता है। यह एक Q-table का उपयोग करता है जो किसी विशेष state में किसी विशिष्ट action को लेने की अपेक्षित उपयोगिता को स्टोर करता है। एल्गोरिदम प्राप्त रिवार्ड्स और अधिकतम अपेक्षित भविष्य के रिवार्ड्स के आधार पर Q-values को अपडेट करता है।
1. **Initialization**: Q-table को arbitrary मानों से initialize करें (अक्सर zeros)।
2. **Action Selection**: किसी exploration strategy का उपयोग करके एक action चुनें (उदा., ε-greedy, जहाँ probability ε पर एक random action चुना जाता है, और probability 1-ε पर वह action चुना जाता है जिसके पास उच्चतम Q-value होता है)।
- ध्यान दें कि एल्गोरिदम हमेशा किसी state के लिए ज्ञात सर्वश्रेष्ठ action चुन सकता है, लेकिन इससे एजेंट को नए actions का अन्वेषण करने का मौका नहीं मिलेगा जो बेहतर रिवार्ड दे सकते हैं। इसलिए exploration और exploitation के बीच संतुलन बनाने के लिए ε-greedy का उपयोग किया जाता है।
3. **Environment Interaction**: चुना गया action पर्यावरण में निष्पादित करें, अगला state और reward observe करें।
- ध्यान दें कि इस मामले में ε-greedy probability पर निर्भर करते हुए अगला कदम एक random action (exploration के लिए) या सबसे जाना-पहचाना action (exploitation के लिए) हो सकता है।
4. **Q-Value Update**: Bellman equation का उपयोग करके state-action pair के लिए Q-value अपडेट करें:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)` वर्तमान Q-value है state `s` और action `a` के लिए।
- `α` learning rate है (0 < α ≤ 1), जो निर्धारित करता है कि नई जानकारी पुरानी जानकारी को कितना override करेगी।
- `r` वह reward है जो state `s` में action `a` लेने के बाद प्राप्त होता है।
- `γ` discount factor है (0 ≤ γ < 1), जो भविष्य के rewards के महत्व को निर्धारित करता है।
- `s'` वह अगला state है जो action `a` लेने के बाद आता है।
- `max(Q(s', a'))` अगली state `s'` के लिए सभी संभावित actions `a'` में से अधिकतम Q-value है।
5. **Iteration**: जब तक Q-values converge न हों या कोई stopping criterion पूरा न हो, steps 2-4 को दोहराएँ।

ध्यान दें कि हर नए चुने हुए action के साथ table अपडेट होता है, जिससे एजेंट समय के साथ अपने अनुभवों से सीखकर optimal policy (प्रत्येक state में लेने के लिए सर्वश्रेष्ठ action) खोजने की कोशिश कर सकता है। हालांकि, बहुत सारे states और actions वाले पर्यावरणों के लिए Q-table बड़ा हो सकता है, जिससे जटिल समस्याओं के लिए यह अप्रैक्टिकल हो जाता है। ऐसे मामलों में Q-values का अनुमान लगाने के लिए function approximation methods (उदा., neural networks) का उपयोग किया जा सकता है।

> [!TIP]
> ε-greedy value आम तौर पर समय के साथ अपडेट की जाती है ताकि जैसे-जैसे एजेंट पर्यावरण के बारे में अधिक सीखे, exploration को घटाया जा सके। उदाहरण के लिए, यह एक उच्च मान (उदा., ε = 1) से शुरू हो सकती है और सीखने के दौरान इसे एक कम मान (उदा., ε = 0.1) तक decay किया जा सकता है।

> [!TIP]
> learning rate `α` और discount factor `γ` ऐसे hyperparameters हैं जिन्हें विशिष्ट समस्या और पर्यावरण के आधार पर ट्यून किया जाना चाहिए। अधिक learning rate एजेंट को तेज़ी से सीखने की अनुमति देता है पर अनिश्चितता पैदा कर सकता है, जबकि कम learning rate अधिक स्थिर सीखने पर ले जाता है पर convergence धीमा होता है। Discount factor यह निर्धारित करता है कि एजेंट भविष्य के रिवार्ड्स (`γ` के 1 के करीब होने पर) को तत्काल रिवार्ड्स की तुलना में कितना महत्व देता है।

### SARSA (State-Action-Reward-State-Action)

SARSA एक अन्य model-free reinforcement learning algorithm है जो Q-Learning के समान है लेकिन Q-values को अपडेट करने के तरीके में भिन्न है। SARSA का पूरा नाम State-Action-Reward-State-Action है, और यह Q-values को अगले state में लिए जाने वाले action के आधार पर अपडेट करता है, न कि उस state के अधिकतम Q-value के आधार पर।
1. **Initialization**: Q-table को arbitrary मानों से initialize करें (अक्सर zeros)।
2. **Action Selection**: किसी exploration strategy का उपयोग करके एक action चुनें (उदा., ε-greedy)।
3. **Environment Interaction**: चुना गया action पर्यावरण में निष्पादित करें, अगला state और reward observe करें।
- ध्यान दें कि इस मामले में ε-greedy probability पर निर्भर करते हुए अगला कदम एक random action (exploration के लिए) या सबसे जाना-पहचाना action (exploitation के लिए) हो सकता है।
4. **Q-Value Update**: SARSA update rule का उपयोग करके state-action pair के लिए Q-value अपडेट करें। ध्यान दें कि update rule Q-Learning जैसा होता है, पर यह अगले state `s'` में लिए जाने वाले action `a'` का उपयोग करता है, न कि उस state के लिए अधिकतम Q-value का:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)` वर्तमान Q-value है state `s` और action `a` के लिए।
- `α` learning rate है।
- `r` वह reward है जो state `s` में action `a` लेने के बाद प्राप्त होता है।
- `γ` discount factor है।
- `s'` वह अगला state है जो action `a` लेने के बाद आता है।
- `a'` वह action है जो अगले state `s'` में लिया गया है।
5. **Iteration**: जब तक Q-values converge न हों या कोई stopping criterion पूरा न हो, steps 2-4 को दोहराएँ।

#### Softmax vs ε-Greedy Action Selection

ε-greedy action selection के अलावा, SARSA softmax action selection strategy का भी उपयोग कर सकता है। softmax action selection में, किसी action को चुनने की probability उसकी Q-value के अनुपात में होती है, जो action space के और अधिक सूक्ष्म अन्वेषण की अनुमति देती है। state `s` में action `a` को चुनने की probability इस प्रकार दी जाती है:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
जहाँ:
- `P(a|s)` किसी स्थिति `s` में क्रिया `a` चुनने की संभावना है।
- `Q(s, a)` स्थिति `s` और क्रिया `a` के लिए Q-value है।
- `τ` (tau) exploration के स्तर को नियंत्रित करने वाला temperature पैरामीटर है। अधिक तापमान अधिक exploration (अधिक समान संभावनाएँ) देता है, जबकि कम तापमान अधिक exploitation देता है (उच्च Q-values वाली क्रियाओं के लिए उच्च संभावनाएँ)।

> [!TIP]
> यह ε-greedy action selection की तुलना में exploration और exploitation के बीच संतुलन को एक अधिक सतत तरीके से बनाए रखने में मदद करता है।

### On-Policy vs Off-Policy Learning

SARSA एक **on-policy** लर्निंग एल्गोरिथ्म है, जिसका अर्थ है कि यह Q-values को वर्तमान नीति द्वारा लिए गए क्रियाओं के आधार पर अपडेट करता है (ε-greedy या softmax policy)। इसके विपरीत, Q-Learning एक **off-policy** लर्निंग एल्गोरिथ्म है, क्योंकि यह Q-values को अगले राज्य के लिए अधिकतम Q-value के आधार पर अपडेट करता है, वर्तमान नीति द्वारा लिए गए क्रिया की परवाह किए बिना। यह अंतर प्रभावित करता है कि एल्गोरिथ्म पर्यावरण के साथ कैसे सीखते और अनुकूलित होते हैं।

On-policy विधियाँ जैसे SARSA कुछ वातावरणों में अधिक स्थिर हो सकती हैं, क्योंकि वे वास्तव में लिए गए क्रियाओं से सीखती हैं। हालांकि, वे off-policy विधियों जैसे Q-Learning की तुलना में धीमी गति से अभिसरण कर सकती हैं, जो अनुभवों की एक व्यापक रेंज से सीख सकती हैं।

## Security & Attack Vectors in RL Systems

हालाँकि RL algorithms केवल गणितीय लगते हैं, हाल के कार्य दिखाते हैं कि **training-time poisoning और reward tampering विश्वसनीय रूप से सीखी गई नीतियों को प्रभावित कर सकते हैं**।

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: एक एकल malicious agent एक spatiotemporal trigger encode करता है और अपने reward function में हल्का perturbation करता है; जब ट्रिगर पैटर्न प्रकट होता है, तब विषैला agent पूरे cooperative टीम को attacker-चुने हुए व्यवहार की ओर खींच लेता है जबकि clean performance लगभग अपरिवर्तित रहता है।
- **Safe‑RL specific backdoor (PNAct)**: Attacker Safe‑RL fine‑tuning के दौरान *positive* (इच्छित) और *negative* (टालने योग्य) action उदाहरण inject करता है। बैकडोर एक सरल ट्रिगर (उदा., cost threshold पार होना) पर सक्रिय होता है, जो एक unsafe क्रिया को मजबूर करता है जबकि जाहिरा तौर पर सुरक्षा-सीमाओं का सम्मान बना रहता है।

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
- `delta` को बहुत छोटा रखें ताकि reward‑distribution drift detectors से बचा जा सके।
- विकेन्द्रीकृत सेटिंग्स में, प्रति episode केवल एक agent को poison करें ताकि “component” insertion की नकल हो सके।

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** दिखाता है कि pairwise preference labels के <5% को पलट देना reward model को बायस करने के लिए पर्याप्त है; downstream PPO तब ट्रिगर token दिखाई देने पर attacker‑desired text आउटपुट करना सीख जाता है।
- Practical steps to test: एक छोटा सेट prompts इकट्ठा करें, एक दुर्लभ trigger token (उदाहरण के लिए `@@@`) जोड़ें, और ऐसी preferences जबरन लागू करें जहाँ responses जिनमें attacker content हो उन्हें “better” के रूप में चिह्नित किया जाए। Reward model को fine‑tune करें, फिर कुछ PPO epochs चलाएँ—ग़लत‑संगठित (misaligned) व्यवहार केवल तब ही दिखाई देगा जब trigger मौजूद हो।

### Stealthier spatiotemporal triggers
स्थैतिक image patches की बजाय, हाल की MADRL कृतियों में ट्रिगर के रूप में *behavioral sequences* (समयबद्ध action patterns) का उपयोग किया गया है, जिन्हें हल्के reward reversal के साथ जोड़ा जाता है ताकि poisoned agent सूक्ष्म रूप से पूरी टीम को off‑policy की ओर मोड़ दे जबकि aggregate reward उच्च बनाए रखा जाए। यह static-trigger detectors को बायपास करता है और partial observability में भी जीवित रहता है।

### Red‑team checklist
- प्रति state reward deltas की जाँच करें; अचानक स्थानीय सुधार मजबूत backdoor संकेत होते हैं।
- एक *canary* trigger सेट रखें: hold‑out episodes जिनमें synthetic rare states/tokens हों; trained policy चलाकर देखें कि व्यवहार विचलित होता है या नहीं।
- Decentralized training के दौरान, प्रत्येक shared policy को aggregation से पहले randomized environments पर rollouts के माध्यम से स्वतंत्र रूप से सत्यापित करें।

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
