# Modelagem de Ameaças

{{#include ../banners/hacktricks-training.md}}

## Modelagem de Ameaças

Boas-vindas ao guia completo do HackTricks sobre Modelagem de Ameaças! Embarque em uma exploração deste aspecto crítico da cibersegurança, no qual identificamos, entendemos e definimos estratégias contra possíveis vulnerabilidades em um sistema. Este tópico serve como um guia passo a passo repleto de exemplos do mundo real, softwares úteis e explicações fáceis de entender. Ideal tanto para iniciantes quanto para profissionais experientes que desejam fortalecer suas defesas de cibersegurança.

### Cenários Comumente Usados

1. **Desenvolvimento de Software**: Como parte do Secure Software Development Life Cycle (SSDLC), a modelagem de ameaças ajuda a **identificar possíveis fontes de vulnerabilidades** nos estágios iniciais do desenvolvimento.
2. **Penetration Testing**: O framework Penetration Testing Execution Standard (PTES) exige a **modelagem de ameaças para entender as vulnerabilidades do sistema** antes da realização do teste.

### Modelo de Ameaças em Resumo

Um modelo de ameaças normalmente é representado como um diagrama, imagem ou alguma outra forma de ilustração visual que retrata a arquitetura planejada ou a implementação existente de uma aplicação. Ele se assemelha a um **diagrama de fluxo de dados**, mas a principal diferença está em seu design orientado à segurança.

Os modelos de ameaças geralmente apresentam elementos marcados em vermelho, simbolizando possíveis vulnerabilidades, riscos ou barreiras. Para simplificar o processo de identificação de riscos, utiliza-se a tríade CIA (Confidentiality, Integrity, Availability), que serve como base para muitas metodologias de modelagem de ameaças, sendo STRIDE uma das mais comuns. No entanto, a metodologia escolhida pode variar dependendo do contexto e dos requisitos específicos.

### A Tríade CIA

A Tríade CIA é um modelo amplamente reconhecido no campo da segurança da informação, representando Confidentiality, Integrity e Availability. Esses três pilares formam a base sobre a qual muitas medidas e políticas de segurança são construídas, incluindo metodologias de modelagem de ameaças.

1. **Confidentiality**: Garantir que os dados ou o sistema não sejam acessados por indivíduos não autorizados. Este é um aspecto central da segurança, exigindo controles de acesso apropriados, criptografia e outras medidas para evitar vazamentos de dados.
2. **Integrity**: A precisão, consistência e confiabilidade dos dados durante todo o seu ciclo de vida. Este princípio garante que os dados não sejam alterados ou adulterados por partes não autorizadas. Ele geralmente envolve checksums, hashing e outros métodos de verificação de dados.
3. **Availability**: Garantir que os dados e serviços estejam acessíveis aos usuários autorizados quando necessário. Isso geralmente envolve redundância, tolerância a falhas e configurações de alta disponibilidade para manter os sistemas em funcionamento mesmo diante de interrupções.

### Metodologias de Threat Modeling

1. **STRIDE**: Desenvolvido pela Microsoft, STRIDE é um acrônimo para **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service e Elevation of Privilege**. Cada categoria representa um tipo de ameaça, e essa metodologia é comumente usada na fase de design de um programa ou sistema para identificar possíveis ameaças.
2. **DREAD**: Esta é outra metodologia da Microsoft usada para avaliação de risco das ameaças identificadas. DREAD significa **Damage potential, Reproducibility, Exploitability, Affected users e Discoverability**. Cada um desses fatores recebe uma pontuação, e o resultado é usado para priorizar as ameaças identificadas.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Esta é uma metodologia de sete etapas, **centrada em riscos**. Ela inclui a definição e identificação de objetivos de segurança, a criação de um escopo técnico, a decomposição da aplicação, a análise de ameaças, a análise de vulnerabilidades e a avaliação de riscos/triagem.
4. **Trike**: Esta é uma metodologia baseada em riscos que se concentra na defesa de ativos. Ela começa sob uma perspectiva de **gerenciamento de riscos** e analisa ameaças e vulnerabilidades nesse contexto.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Esta abordagem busca ser mais acessível e se integra a ambientes de desenvolvimento Agile. Ela combina elementos das outras metodologias e concentra-se em **representações visuais de ameaças**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Desenvolvido pelo CERT Coordination Center, este framework é voltado para **avaliação de riscos organizacionais, em vez de sistemas ou softwares específicos**.

## Ferramentas

Existem diversas ferramentas e soluções de software disponíveis que podem **auxiliar** na criação e no gerenciamento de modelos de ameaças. Veja algumas que você pode considerar.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Um spider/crawler web avançado, multiplataforma e com diversos recursos, voltado para profissionais de cibersegurança. O Spider Suite pode ser usado para mapeamento e análise da superfície de ataque.

**Uso**

1. Escolha uma URL e faça o Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualize o Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Um projeto open source da OWASP, o Threat Dragon é uma aplicação web e desktop que inclui criação de diagramas de sistemas, além de um mecanismo de regras para gerar ameaças/mitigações automaticamente.

**Uso**

1. Crie um New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Às vezes, ele pode aparecer assim:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Inicie um New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Salve o New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Crie seu modelo

Você pode usar ferramentas como o SpiderSuite Crawler para obter inspiração; um modelo básico seria parecido com isto

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Apenas uma pequena explicação sobre as entidades:

- Process (A própria entidade, como Webserver ou uma funcionalidade web)
- Actor (Uma pessoa, como um visitante do Website, usuário ou administrador)
- Data Flow Line (Indicador de interação)
- Trust Boundary (Diferentes segmentos ou escopos de rede.)
- Store (Locais onde os dados são armazenados, como Databases)

5. Crie uma Threat (Etapa 1)

Primeiro, você precisa escolher a camada à qual deseja adicionar uma ameaça

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Agora você pode criar a ameaça

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Tenha em mente que existe uma diferença entre Actor Threats e Process Threats. Se você adicionar uma ameaça a um Actor, só poderá escolher "Spoofing" e "Repudiation". No entanto, em nosso exemplo, adicionamos uma ameaça a uma entidade Process, então veremos isto na caixa de criação de ameaças:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Concluído

Agora, seu modelo finalizado deve ser parecido com isto. É assim que você cria um modelo simples de ameaças com o OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Esta é uma ferramenta gratuita da Microsoft que ajuda a encontrar ameaças na fase de design de projetos de software. Ela usa a metodologia STRIDE e é particularmente adequada para quem desenvolve na stack da Microsoft.

{{#include ../banners/hacktricks-training.md}}
