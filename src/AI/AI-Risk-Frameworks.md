# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp identificou as 10 principais vulnerabilidades de aprendizado de máquina que podem afetar sistemas de IA. Essas vulnerabilidades podem levar a vários problemas de segurança, incluindo envenenamento de dados, inversão de modelo e ataques adversariais. Compreender essas vulnerabilidades é crucial para construir sistemas de IA seguros.

Para uma lista atualizada e detalhada das 10 principais vulnerabilidades de aprendizado de máquina, consulte o projeto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Um atacante adiciona pequenas mudanças, muitas vezes invisíveis, aos **dados de entrada** para que o modelo tome a decisão errada.\
*Exemplo*: Algumas manchas de tinta em uma placa de pare enganam um carro autônomo a "ver" uma placa de limite de velocidade.

- **Data Poisoning Attack**: O **conjunto de treinamento** é deliberadamente poluído com amostras ruins, ensinando ao modelo regras prejudiciais.\
*Exemplo*: Binários de malware são rotulados incorretamente como "benignos" em um corpus de treinamento de antivírus, permitindo que malware semelhante passe despercebido depois.

- **Model Inversion Attack**: Ao sondar saídas, um atacante constrói um **modelo reverso** que reconstrói características sensíveis das entradas originais.\
*Exemplo*: Recriar a imagem de ressonância magnética de um paciente a partir das previsões de um modelo de detecção de câncer.

- **Membership Inference Attack**: O adversário testa se um **registro específico** foi usado durante o treinamento ao notar diferenças de confiança.\
*Exemplo*: Confirmar que a transação bancária de uma pessoa aparece nos dados de treinamento de um modelo de detecção de fraudes.

- **Model Theft**: Consultas repetidas permitem que um atacante aprenda os limites de decisão e **clone o comportamento do modelo** (e IP).\
*Exemplo*: Coletar pares de perguntas e respostas suficientes de uma API de ML‑as‑a‑Service para construir um modelo local quase equivalente.

- **AI Supply‑Chain Attack**: Comprometer qualquer componente (dados, bibliotecas, pesos pré-treinados, CI/CD) no **pipeline de ML** para corromper modelos a jusante.\
*Exemplo*: Uma dependência envenenada em um hub de modelo instala um modelo de análise de sentimento com backdoor em muitos aplicativos.

- **Transfer Learning Attack**: Lógica maliciosa é plantada em um **modelo pré-treinado** e sobrevive ao ajuste fino na tarefa da vítima.\
*Exemplo*: Uma base de visão com um gatilho oculto ainda altera rótulos após ser adaptada para imagem médica.

- **Model Skewing**: Dados sutilmente tendenciosos ou rotulados incorretamente **mudam as saídas do modelo** para favorecer a agenda do atacante.\
*Exemplo*: Injetar e-mails de spam "limpos" rotulados como ham para que um filtro de spam permita que e-mails semelhantes no futuro passem.

- **Output Integrity Attack**: O atacante **altera previsões do modelo em trânsito**, não o modelo em si, enganando sistemas a jusante.\
*Exemplo*: Alterar o veredicto "malicioso" de um classificador de malware para "benigno" antes que a fase de quarentena do arquivo o veja.

- **Model Poisoning** --- Mudanças diretas e direcionadas nos **parâmetros do modelo** em si, muitas vezes após obter acesso de gravação, para alterar o comportamento.\
*Exemplo*: Ajustar pesos em um modelo de detecção de fraudes em produção para que transações de certos cartões sejam sempre aprovadas.

## Google SAIF Risks

Os riscos associados aos sistemas de IA estão delineados no [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) do Google:

- **Data Poisoning**: Atores maliciosos alteram ou injetam dados de treinamento/ajuste para degradar a precisão, implantar backdoors ou distorcer resultados, minando a integridade do modelo em todo o ciclo de vida dos dados.

- **Unauthorized Training Data**: A ingestão de conjuntos de dados protegidos por direitos autorais, sensíveis ou não permitidos cria responsabilidades legais, éticas e de desempenho porque o modelo aprende com dados que nunca teve permissão para usar.

- **Model Source Tampering**: A manipulação da cadeia de suprimentos ou de insiders do código do modelo, dependências ou pesos antes ou durante o treinamento pode embutir lógica oculta que persiste mesmo após o re-treinamento.

- **Excessive Data Handling**: Controles fracos de retenção e governança de dados levam os sistemas a armazenar ou processar mais dados pessoais do que o necessário, aumentando a exposição e o risco de conformidade.

- **Model Exfiltration**: Atacantes roubam arquivos/pesos do modelo, causando perda de propriedade intelectual e permitindo serviços de imitação ou ataques subsequentes.

- **Model Deployment Tampering**: Adversários modificam artefatos do modelo ou infraestrutura de serviço para que o modelo em execução difira da versão aprovada, potencialmente mudando o comportamento.

- **Denial of ML Service**: Inundar APIs ou enviar entradas "esponja" pode esgotar computação/energia e derrubar o modelo, espelhando ataques clássicos de DoS.

- **Model Reverse Engineering**: Ao coletar grandes números de pares de entrada-saída, os atacantes podem clonar ou destilar o modelo, alimentando produtos de imitação e ataques adversariais personalizados.

- **Insecure Integrated Component**: Plugins, agentes ou serviços upstream vulneráveis permitem que atacantes injetem código ou escalem privilégios dentro do pipeline de IA.

- **Prompt Injection**: Criar prompts (diretamente ou indiretamente) para contrabandear instruções que substituem a intenção do sistema, fazendo com que o modelo execute comandos não intencionais.

- **Model Evasion**: Entradas cuidadosamente projetadas fazem o modelo classificar incorretamente, alucinar ou produzir conteúdo não permitido, erodindo segurança e confiança.

- **Sensitive Data Disclosure**: O modelo revela informações privadas ou confidenciais de seus dados de treinamento ou contexto do usuário, violando privacidade e regulamentos.

- **Inferred Sensitive Data**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos à privacidade por meio de inferência.

- **Insecure Model Output**: Respostas não sanitizadas transmitem código prejudicial, desinformação ou conteúdo inadequado para usuários ou sistemas a jusante.

- **Rogue Actions**: Agentes integrados autonomamente executam operações do mundo real não intencionais (gravações de arquivos, chamadas de API, compras, etc.) sem supervisão adequada do usuário.

## Mitre AI ATLAS Matrix

A [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornece uma estrutura abrangente para entender e mitigar riscos associados a sistemas de IA. Ela categoriza várias técnicas e táticas de ataque que adversários podem usar contra modelos de IA e também como usar sistemas de IA para realizar diferentes ataques.

{{#include ../banners/hacktricks-training.md}}
