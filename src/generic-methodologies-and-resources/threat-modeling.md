# Modelagem de Ameaças

{{#include ../banners/hacktricks-training.md}}

Bem-vindo ao guia abrangente do HackTricks sobre Modelagem de Ameaças! Embarque em uma exploração deste aspecto crítico da cibersegurança, no qual identificamos, compreendemos e desenvolvemos estratégias contra possíveis vulnerabilidades em um sistema. Este conteúdo serve como um guia passo a passo repleto de exemplos do mundo real, software útil e explicações fáceis de entender. É ideal tanto para iniciantes quanto para profissionais experientes que desejam fortalecer suas defesas de cibersegurança.

### Cenários Comumente Usados

1. **Desenvolvimento de Software**: Como parte do Secure Software Development Life Cycle (SSDLC), a modelagem de ameaças ajuda a **identificar possíveis fontes de vulnerabilidades** nos estágios iniciais do desenvolvimento.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: O Penetration Testing Execution Standard (PTES) considera a modelagem de ameaças necessária para uma execução correta e exige a documentação de ativos empresariais, processos empresariais, comunidades de ameaças e suas capacidades.<sup>[[2]](#references)</sup>

### Modelo de Ameaças em Resumo

Um modelo de ameaças normalmente é representado por um diagrama, imagem ou outra ilustração visual de uma arquitetura planejada ou de uma aplicação existente. Diagramas de fluxo de dados (DFDs) são uma forma comum de modelar um sistema e suas interações, enquanto a modelagem de ameaças adiciona uma análise focada em segurança.<sup>[[1]](#references)</sup>

Na Microsoft Threat Modeling Tool, linhas pontilhadas vermelhas indicam limites de confiança; outras ferramentas podem usar convenções visuais diferentes.<sup>[[4]](#references)</sup> Para simplificar a identificação de riscos, as equipes podem usar a tríade CIA (Confidentiality, Integrity, Availability) ou as categorias de ameaças STRIDE, mas a metodologia apropriada depende do contexto e dos requisitos do projeto.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### A Tríade CIA

A Tríade CIA é um modelo de segurança da informação amplamente reconhecido, que representa Confidentiality, Integrity e Availability. Essas propriedades são comumente usadas para descrever objetivos de segurança para dados e sistemas.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Garantir que os dados ou o sistema não sejam acessados por indivíduos não autorizados. Esse é um aspecto central da segurança, que exige controles de acesso apropriados, criptografia e outras medidas para evitar data breaches.
2. **Integrity**: A precisão, consistência e confiabilidade dos dados durante todo o seu ciclo de vida. Esse princípio garante que os dados não sejam alterados ou adulterados por partes não autorizadas. Frequentemente envolve checksums, hashing e outros métodos de verificação de dados.
3. **Availability**: Garante que dados e serviços estejam acessíveis a usuários autorizados quando necessário. Isso geralmente envolve redundância, tolerância a falhas e configurações de alta disponibilidade para manter os sistemas em funcionamento mesmo diante de interrupções.

### Metodologias de Modelagem de Ameaças

1. **STRIDE**: A abordagem STRIDE da Microsoft categoriza as ameaças de software como **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service e Elevation of Privilege**. Essas categorias ajudam os analistas a identificar possíveis ameaças em cada ponto vulnerável de um design.<sup>[[5]](#references)</sup>
2. **DREAD**: Essa abordagem de avaliação da Microsoft classifica as ameaças usando **Damage, Reproducibility, Exploitability, Affected users e Discoverability**. A pontuação resultante pode ajudar a priorizar ameaças para mitigação.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Esta é uma metodologia de sete estágios, **centrada em riscos**, que abrange objetivos, escopo técnico, decomposição da aplicação, análise de ameaças, análise de vulnerabilidades e fraquezas, modelagem de ataques e análise de riscos/impactos.<sup>[[8]](#references)</sup>
4. **Trike**: Este framework de auditoria de segurança aborda a modelagem de ameaças a partir de uma perspectiva de **gerenciamento de riscos** e defensiva.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Este método enfatiza modelos de ameaças escaláveis e utilizáveis para visões de aplicação e operacionais, podendo ser integrado aos ciclos de vida de desenvolvimento e DevOps.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Criado pela CERT Division do Software Engineering Institute da Carnegie Mellon, o OCTAVE é um método estratégico de avaliação e planejamento baseado em riscos, focado no risco organizacional, e não apenas na tecnologia.<sup>[[10]](#references)</sup>

## Ferramentas

Existem várias ferramentas e soluções de software disponíveis que podem **auxiliar** na criação e no gerenciamento de modelos de ameaças. Veja algumas que você pode considerar.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite é um web crawler multiplataforma para profissionais de segurança que oferece suporte a mapeamento da attack surface, descoberta de endpoints e análise de aplicações web.<sup>[[6]](#references)</sup>

**Uso**

1. Escolha uma URL e faça o Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualize o Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon é uma aplicação gratuita, open-source e multiplataforma de modelagem de ameaças para desenhar diagramas, sugerir ameaças e registrar mitigações. Está disponível como aplicação web e desktop.<sup>[[7]](#references)</sup>

**Uso**

1. Crie um Novo Projeto

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Às vezes, ele pode ser parecido com isto:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Inicie o Novo Projeto

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Salve o Novo Projeto

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Crie seu modelo

Você pode usar ferramentas como o SpiderSuite Crawler para obter inspiração; um modelo básico seria parecido com isto:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Veja uma breve explicação sobre as entidades:

- Process (A própria entidade, como um Webserver ou uma funcionalidade web)
- Actor (Uma pessoa, como um visitante do Website, usuário ou administrador)
- Data Flow Line (Indicador de interação)
- Trust Boundary (Diferentes segmentos ou escopos de rede.)
- Store (Locais onde os dados são armazenados, como Databases)

5. Crie uma Threat (Etapa 1)

Primeiro, você precisa escolher a camada à qual deseja adicionar uma ameaça.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Agora você pode criar a ameaça.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Tenha em mente que existe uma diferença entre Actor Threats e Process Threats. Se você adicionasse uma ameaça a um Actor, só poderia escolher "Spoofing" e "Repudiation". No entanto, em nosso exemplo, adicionamos uma ameaça a uma entidade Process, portanto veremos isto na caixa de criação da ameaça:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Concluído

Agora, seu modelo finalizado deve ser parecido com isto. É assim que você cria um modelo de ameaças simples com o OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

A Microsoft Threat Modeling Tool é uma ferramenta gratuita, disponível para download, destinada à análise de design de software. Seu fluxo de trabalho cria um diagrama, identifica ameaças e oferece suporte à mitigação e validação usando a abordagem STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Folha de referência de Modelagem de Ameaças](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Modelagem de Ameaças - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Fundamentos de segurança - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Primeiros passos com a Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Modelagem de Ameaças para Drivers - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [Modelagem de Ameaças PASTA: As 7 Etapas Explicadas](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Documento da Metodologia Trike v1](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Modelagem de Ameaças: Um Resumo dos Métodos Disponíveis](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
