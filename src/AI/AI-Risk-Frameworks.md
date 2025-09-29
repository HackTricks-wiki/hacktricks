# Riscos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Vulnerabilidades de Machine Learning

Owasp identificou as top 10 vulnerabilidades de machine learning que podem afetar sistemas de IA. Essas vulnerabilidades podem levar a diversos problemas de segurança, incluindo data poisoning, model inversion e adversarial attacks. Entender essas vulnerabilidades é crucial para construir sistemas de IA seguros.

Para uma lista atualizada e detalhada das top 10 vulnerabilidades de machine learning, consulte o projeto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Um atacante adiciona mudanças minúsculas, muitas vezes invisíveis, aos **incoming data** para que o modelo tome a decisão errada.\
*Exemplo*: Alguns respingos de tinta em uma placa de pare enganam um carro autônomo fazendo‑o "ver" uma placa de limite de velocidade.

- **Data Poisoning Attack**: O **training set** é deliberadamente contaminado com amostras ruins, ensinando o modelo regras nocivas.\
*Exemplo*: Binaries de malware são rotulados como "benign" em um corpus de treinamento de antivírus, permitindo que malware similar passe despercebido depois.

- **Model Inversion Attack**: Ao sondar saídas, um atacante constrói um **reverse model** que reconstrói características sensíveis dos inputs originais.\
*Exemplo*: Recriar a imagem de uma ressonância magnética de um paciente a partir das predições de um modelo de detecção de câncer.

- **Membership Inference Attack**: O adversário testa se um **specific record** foi usado durante o treinamento identificando diferenças de confiança.\
*Exemplo*: Confirmar que a transação bancária de uma pessoa aparece nos dados de treinamento de um modelo de detecção de fraude.

- **Model Theft**: Queries repetidas permitem que um atacante aprenda os limites de decisão e **clone the model's behavior** (e a propriedade intelectual).\
*Exemplo*: Coletar pares Q&A suficientes de uma API ML‑as‑a‑Service para construir um modelo local quase equivalente.

- **AI Supply‑Chain Attack**: Comprometer qualquer componente (dados, libraries, pre‑trained weights, CI/CD) na **ML pipeline** para corromper modelos a jusante.\
*Exemplo*: Uma dependência envenenada num model‑hub instala um modelo de análise de sentimento com backdoor em vários apps.

- **Transfer Learning Attack**: Lógica maliciosa é plantada em um **pre‑trained model** e sobrevive ao fine‑tuning na tarefa da vítima.\
*Exemplo*: Um backbone de visão com um gatilho oculto ainda inverte labels após ser adaptado para imagens médicas.

- **Model Skewing**: Dados sutilmente enviesados ou mal rotulados **shifts the model's outputs** para favorecer a agenda do atacante.\
*Exemplo*: Injetar e‑mails de spam "limpos" rotulados como ham para que um filtro de spam permita e‑mails similares no futuro.

- **Output Integrity Attack**: O atacante **alters model predictions in transit**, não o modelo em si, enganando sistemas a jusante.\
*Exemplo*: Inverter o veredito "malicious" de um classificador de malware para "benign" antes que a etapa de quarentena de arquivos o veja.

- **Model Poisoning** --- Alterações diretas e direcionadas aos **model parameters** em si, frequentemente após obter acesso de escrita, para alterar o comportamento.\
*Exemplo*: Ajustar weights de um modelo de detecção de fraude em produção para que transações de certos cartões sejam sempre aprovadas.


## Riscos do Google SAIF

O [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) do Google descreve vários riscos associados a sistemas de IA:

- **Data Poisoning**: Atores maliciosos alteram ou injetam dados de treinamento/ajuste para degradar a precisão, implantar backdoors ou enviesar resultados, minando a integridade do modelo ao longo de todo o ciclo de vida dos dados.

- **Unauthorized Training Data**: Ingerir datasets com copyright, sensíveis ou não autorizados cria responsabilidades legais, éticas e de desempenho porque o modelo aprende a partir de dados que não deveria usar.

- **Model Source Tampering**: Manipulação na cadeia de suprimentos ou por insiders do código do modelo, dependências ou pesos antes ou durante o treinamento pode embedar lógica oculta que persiste mesmo após retraining.

- **Excessive Data Handling**: Controles fracos de retenção e governança de dados levam sistemas a armazenar ou processar mais dados pessoais do que o necessário, aumentando exposição e risco de conformidade.

- **Model Exfiltration**: Atacantes roubam arquivos/pesos do modelo, causando perda de propriedade intelectual e possibilitando serviços copy‑cat ou ataques subsequentes.

- **Model Deployment Tampering**: Adversários modificam artifacts do modelo ou infraestrutura de serving para que o modelo em execução difira da versão vetada, potencialmente mudando o comportamento.

- **Denial of ML Service**: Flood de APIs ou envio de inputs “sponge” pode esgotar compute/energia e derrubar o modelo, espelhando ataques clássicos de DoS.

- **Model Reverse Engineering**: Ao colher muitos pares input‑output, atacantes podem clonar ou destilar o modelo, alimentando produtos de imitação e ataques adversariais personalizados.

- **Insecure Integrated Component**: Plugins, agents ou serviços upstream vulneráveis permitem que atacantes injetem código ou escalem privilégios dentro do pipeline de IA.

- **Prompt Injection**: Construir prompts (direta ou indiretamente) para contrabandear instruções que sobrepõem a intenção do sistema, fazendo o modelo executar comandos não pretendidos.

- **Model Evasion**: Inputs cuidadosamente desenhados fazem o modelo mis‑classify, hallucinate ou output conteúdo proibido, corroendo segurança e confiança.

- **Sensitive Data Disclosure**: O modelo revela informações privadas ou confidenciais de seus dados de treinamento ou do contexto do usuário, violando privacidade e regulações.

- **Inferred Sensitive Data**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos de privacidade por inferência.

- **Insecure Model Output**: Respostas não sanitizadas passam código prejudicial, misinformation ou conteúdo inadequado para usuários ou sistemas a jusante.

- **Rogue Actions**: Agentes integrados autonomamente executam operações do mundo real não intencionadas (escrita de arquivos, chamadas API, compras, etc.) sem supervisão adequada do usuário.

## Mitre AI ATLAS Matrix

A [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornece um framework abrangente para entender e mitigar riscos associados a sistemas de IA. Ela categoriza várias técnicas e táticas de ataque que adversários podem usar contra modelos de IA e também como usar sistemas de IA para realizar diferentes ataques.


## LLMJacking (Roubo de Tokens e Revenda de Acesso a LLMs hospedadas na nuvem)

Atacantes roubam tokens de sessão ativos ou credenciais de API de nuvem e invocam LLMs pagos hospedados na nuvem sem autorização. O acesso frequentemente é revendido via reverse proxies que fazem front pela conta da vítima, por exemplo, deployments "oai-reverse-proxy". As consequências incluem perda financeira, uso indevido do modelo fora da política e atribuição ao tenant vítima.

TTPs:
- Harvest tokens from infected developer machines or browsers; steal CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy that forwards requests to the genuine provider, hiding the upstream key and multiplexing many customers.
- Abuse direct base-model endpoints to bypass enterprise guardrails and rate limits.

Mitigações:
- Bind tokens to device fingerprint, IP ranges, and client attestation; enforce short expirations and refresh with MFA.
- Scope keys minimally (no tool access, read-only where applicable); rotate on anomaly.
- Terminate all traffic server-side behind a policy gateway that enforces safety filters, per-route quotas, and tenant isolation.
- Monitor for unusual usage patterns (sudden spend spikes, atypical regions, UA strings) and auto-revoke suspicious sessions.
- Prefer mTLS or signed JWTs issued by your IdP over long-lived static API keys.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
