# Modelagem de Ameaças

Bem-vindo ao guia abrangente da HackTricks sobre Modelagem de Ameaças! Embarque em uma exploração deste aspecto crítico da cybersecurity, no qual identificamos, compreendemos e definimos estratégias contra possíveis vulnerabilidades em um sistema. Este tópico serve como um guia passo a passo, repleto de exemplos do mundo real, softwares úteis e explicações fáceis de entender. Ideal tanto para iniciantes quanto para profissionais experientes que desejam fortalecer suas defesas de cybersecurity.

### Cenários Comumente Utilizados

1. **Desenvolvimento de Software**: Como parte do Secure Software Development Life Cycle (SSDLC), a modelagem de ameaças ajuda a **identificar possíveis fontes de vulnerabilidades** nos estágios iniciais do desenvolvimento.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: O Penetration Testing Execution Standard (PTES) considera a modelagem de ameaças necessária para uma execução correta e exige a documentação de ativos comerciais, processos comerciais, comunidades de ameaças e suas capacidades.<sup>[[2]](#references)</sup>

### Modelo de Ameaças em Resumo

Um modelo de ameaças normalmente é representado por um diagrama, imagem ou outra ilustração visual de uma arquitetura planejada ou de uma aplicação existente. Diagramas de fluxo de dados (DFDs) são uma forma comum de modelar um sistema e suas interações, enquanto a modelagem de ameaças adiciona uma análise com foco em segurança.<sup>[[1]](#references)</sup>

Na Microsoft Threat Modeling Tool, linhas pontilhadas vermelhas indicam limites de confiança; outras ferramentas podem usar convenções visuais diferentes.<sup>[[4]](#references)</sup> Para simplificar a identificação de riscos, as equipes podem usar a tríade CIA (Confidentiality, Integrity, Availability) ou as categorias de ameaças STRIDE, mas a metodologia apropriada depende do contexto e dos requisitos do projeto.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### A Tríade CIA

A Tríade CIA é um modelo de segurança da informação amplamente reconhecido, que significa Confidentiality, Integrity e Availability. Essas propriedades são comumente usadas para descrever objetivos de segurança para dados e sistemas.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Garantir que os dados ou o sistema não sejam acessados por indivíduos não autorizados. Este é um aspecto central da segurança, exigindo controles de acesso apropriados, encryption e outras medidas para evitar data breaches.
2. **Integrity**: A precisão, consistência e confiabilidade dos dados durante todo o seu ciclo de vida. Este princípio garante que os dados não sejam alterados ou adulterados por partes não autorizadas. Frequentemente envolve checksums, hashing e outros métodos de verificação de dados.
3. **Availability**: Garante que dados e serviços estejam acessíveis aos usuários autorizados quando necessário. Isso geralmente envolve redundância, tolerância a falhas e configurações de alta disponibilidade para manter os sistemas em funcionamento mesmo diante de interrupções.

### Metodologias de Modelagem de Ameaças

1. **STRIDE**: A abordagem STRIDE da Microsoft categoriza as ameaças de software como **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service e Elevation of Privilege**. Essas categorias ajudam os analistas a identificar possíveis ameaças em cada ponto vulnerável de um design.<sup>[[5]](#references)</sup>
2. **DREAD**: Esta abordagem de avaliação da Microsoft pontua as ameaças usando **Damage, Reproducibility, Exploitability, Affected users e Discoverability**. A pontuação resultante pode ajudar a priorizar ameaças para mitigação.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Esta é uma metodologia **centrada em riscos**, composta por sete estágios, que abrange objetivos, escopo técnico, decomposição da aplicação, análise de ameaças, análise de vulnerabilidades e fraquezas, modelagem de ataques e análise de riscos/impactos.<sup>[[8]](#references)</sup>
4. **Trike**: Este framework de security-audit aborda a modelagem de ameaças sob uma perspectiva de **risk-management** e defensiva.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Este método enfatiza modelos de ameaças escaláveis e utilizáveis para visões de aplicação e operacionais, podendo ser integrado aos ciclos de vida de desenvolvimento e DevOps.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Criado pela CERT Division do Software Engineering Institute da Carnegie Mellon, o OCTAVE é um método estratégico de avaliação e planejamento baseado em riscos, com foco no risco organizacional, e não apenas na tecnologia.<sup>[[10]](#references)</sup>

## Ferramentas

Existem várias ferramentas e soluções de software disponíveis que podem **auxiliar** na criação e no gerenciamento de modelos de ameaças. Aqui estão algumas que você pode considerar.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite é um web crawler multiplataforma para profissionais de segurança que oferece suporte a attack-surface mapping, endpoint discovery e web-application analysis.<sup>[[6]](#references)</sup>

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

Às vezes, ele pode ser semelhante a isto:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Inicie um Novo Projeto

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Salve o Novo Projeto

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Crie seu modelo

Você pode usar ferramentas como o SpiderSuite Crawler para obter inspiração; um modelo básico seria semelhante a isto

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Apenas uma pequena explicação sobre as entidades:

- Process (A própria entidade, como um Webserver ou uma funcionalidade web)
- Actor (Uma pessoa, como um visitante do Website, usuário ou administrador)
- Data Flow Line (Indicador de interação)
- Trust Boundary (Diferentes segmentos ou escopos de rede.)
- Store (Locais onde os dados são armazenados, como Databases)

5. Crie uma Threat (Etapa 1)

Primeiro, você precisa escolher a camada à qual deseja adicionar uma ameaça

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Agora você pode criar a ameaça

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Lembre-se de que existe uma diferença entre Actor Threats e Process Threats. Se você adicionar uma ameaça a um Actor, só poderá escolher "Spoofing" e "Repudiation". No entanto, em nosso exemplo, adicionamos a ameaça a uma entidade Process, então veremos isto na caixa de criação de ameaças:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Concluído

Agora, seu modelo finalizado deverá ser semelhante a isto. E é assim que você cria um modelo simples de ameaças com o OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

A Threat Modeling Tool da Microsoft é uma ferramenta gratuita para download destinada à análise de design de software. Seu workflow cria um diagrama, identifica ameaças e oferece suporte à mitigação e validação usando a abordagem STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Security fundamentals - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Getting Started with the Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Threat Modeling for Drivers - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA Threat Modeling: The 7 Stages Explained](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 Methodology Document](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling: A Summary of Available Methods](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
