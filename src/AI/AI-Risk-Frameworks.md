# AI Risks
{{#include /banners/hacktricks-training.md}}


{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp has identified the top 10 machine learning vulnerabilities that can affect AI systems. These vulnerabilities can lead to various security issues, including data poisoning, model inversion, and adversarial attacks. Understanding these vulnerabilities is crucial for building secure AI systems.

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: An attacker adds tiny, often invisible changes to **incoming data** so the model makes the wrong decision.\
    *Example*: A few specks of paint on a stop‑sign fool a self‑driving car into "seeing" a speed‑limit sign.

- **Data Poisoning Attack**: The **training set** is deliberately polluted with bad samples, teaching the model harmful rules.\
*Example*: Malware binaries are mislabeled as "benign" in an antivirus training corpus, letting similar malware slip past later.

- **Model Inversion Attack**: By probing outputs, an attacker builds a **reverse model** that reconstructs sensitive features of the original inputs.\
*Example*: Re‑creating a patient's MRI image from a cancer‑detection model's predictions.

- **Membership Inference Attack**: The adversary tests whether a **specific record** was used during training by spotting confidence differences.\
*Example*: Confirming that a person's bank transaction appears in a fraud‑detection model's training data.

- **Model Theft**: Repeated querying lets an attacker learn decision boundaries and **clone the model's behavior** (and IP).\
*Example*: Harvesting enough Q&A pairs from an ML‑as‑a‑Service API to build a near‑equivalent local model.

- **AI Supply‑Chain Attack**: Compromise any component (data, libraries, pre‑trained weights, CI/CD) in the **ML pipeline** to corrupt downstream models.\
*Example*: A poisoned dependency on a model‑hub installs a backdoored sentiment‑analysis model across many apps.

- **Transfer Learning Attack**: Malicious logic is planted in a **pre‑trained model** and survives fine‑tuning on the victim's task.\
*Example*: A vision backbone with a hidden trigger still flips labels after being adapted for medical imaging.

- **Model Skewing**: Subtly biased or mislabeled data **shifts the model's outputs** to favor the attacker's agenda.\
*Example*: Injecting "clean" spam emails labeled as ham so a spam filter lets similar future emails through.

- **Output Integrity Attack**: The attacker **alters model predictions in transit**, not the model itself, tricking downstream systems.\
*Example*: Flipping a malware classifier's "malicious" verdict to "benign" before the file‑quarantine stage sees it.

- **Model Poisoning** --- Direct, targeted changes to the **model parameters** themselves, often after gaining write access, to alter behavior.\
*Example*: Tweaking weights on a fraud‑detection model in production so transactions from certain cards are always approved.


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) outlines various risks associated with AI systems:

- **Data Poisoning**: Malicious actors alter or inject training/tuning data to degrade accuracy, implant backdoors, or skew results, undermining model integrity across the entire data-lifecycle. 

- **Unauthorized Training Data**: Ingesting copyrighted, sensitive, or unpermitted datasets creates legal, ethical, and performance liabilities because the model learns from data it was never allowed to use. 

- **Model Source Tampering**: Supply-chain or insider manipulation of model code, dependencies, or weights before or during training can embed hidden logic that persists even after retraining. 

- **Excessive Data Handling**: Weak data-retention and governance controls lead systems to store or process more personal data than necessary, heightening exposure and compliance risk. 

- **Model Exfiltration**: Attackers steal model files/weights, causing loss of intellectual property and enabling copy-cat services or follow-on attacks. 

- **Model Deployment Tampering**: Adversaries modify model artifacts or serving infrastructure so the running model differs from the vetted version, potentially changing behaviour. 

- **Denial of ML Service**: Flooding APIs or sending “sponge” inputs can exhaust compute/energy and knock the model offline, mirroring classic DoS attacks. 

- **Model Reverse Engineering**: By harvesting large numbers of input-output pairs, attackers can clone or distil the model, fueling imitation products and customized adversarial attacks. 

- **Insecure Integrated Component**: Vulnerable plugins, agents, or upstream services let attackers inject code or escalate privileges within the AI pipeline. 

- **Prompt Injection**: Crafting prompts (directly or indirectly) to smuggle instructions that override system intent, making the model perform unintended commands. 

- **Model Evasion**: Carefully designed inputs trigger the model to mis-classify, hallucinate, or output disallowed content, eroding safety and trust. 

- **Sensitive Data Disclosure**: The model reveals private or confidential information from its training data or user context, violating privacy and regulations. 

- **Inferred Sensitive Data**: The model deduces personal attributes that were never provided, creating new privacy harms through inference. 

- **Insecure Model Output**: Unsanitized responses pass harmful code, misinformation, or inappropriate content to users or downstream systems. 

- **Rogue Actions**: Autonomously-integrated agents execute unintended real-world operations (file writes, API calls, purchases, etc.) without adequate user oversight.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) provides a comprehensive framework for understanding and mitigating risks associated with AI systems. It categorizes various attack techniques and tactics that adversaries may use against AI models and also how to use AI systems to perform different attacks.


{{#include ../banners/hacktricks-training.md}}
