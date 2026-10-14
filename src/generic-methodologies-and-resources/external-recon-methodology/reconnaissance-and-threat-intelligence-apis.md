# Reconhecimento e APIs de inteligência de ameaças

{{#include ../../banners/hacktricks-training.md}}

Estes serviços dão suporte a fluxos de trabalho de reconhecimento, reputação, vazamentos ou enriquecimento de dados. Suas APIs, cotas, preços e usos permitidos mudam com frequência; confirme a documentação atual do fornecedor e a autorização do engagement antes de enviar identificadores de clientes ou dados sensíveis. Para a sequência de descoberta de ativos, consulte a [Metodologia de Reconhecimento Externo](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Consulte se um endereço IP foi associado a atividade suspeita ou maliciosa. O acesso pode exigir uma conta ou chave de API.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Verifique se um endereço IP, nome de usuário ou endereço de email foi associado a registros automatizados de contas ou a outras atividades de bots reportadas.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Encontre e verifique endereços de email profissionais e padrões de contato relacionados a domínios. Consulte o plano atual para conhecer os limites de requisições e os usos permitidos.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Pesquise indicadores de inteligência de ameaças e atividades associadas a endereços IP e domínios.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Enriqueça um endereço de email, domínio ou empresa com dados comerciais/de perfil disponíveis. A cobertura, o acesso e as restrições de privacidade dependem do produto e do plano atuais.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifique tecnologias observadas em sites e obtenha dados históricos ou de relações, quando permitido pelo plano selecionado.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Verifique se um endereço IP está associado a atividade suspeita ou maliciosa. Confirme os planos e limites atuais da API.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Consulte a categorização e a inteligência de ameaças da FortiGuard para domínios, URLs ou endereços IP. A disponibilidade varia conforme o serviço.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Verifique se um endereço IP está listado por atividade de spam reportada.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Obtenha a reputação de um domínio com base na comunidade do serviço e em outros sinais.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Obtenha geolocalização, ASN, organização e metadados relacionados de um endereço IP. Consulte o plano atual para conhecer as cotas.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Esta plataforma fornece inteligência de DNS e infraestrutura, como resoluções históricas, domínios associados a IPs ou servidores de nomes e registros relacionados. O DNS histórico pode revelar um endereço de origem anterior, mas não contorna uma CDN de forma confiável e deve ser validado.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Enriqueça um endereço de email, domínio ou nome de empresa com atributos de identidade e dados comerciais disponíveis. Trate dados pessoais conforme os requisitos de autorização e privacidade.

## RiskIQ / Microsoft Defender Threat Intelligence (transição legada) <sup>[[14]](#references)</sup>

Os recursos PassiveTotal da RiskIQ foram incorporados ao Microsoft Defender Threat Intelligence. O acesso ao produto, as APIs e as funcionalidades mantidas foram alterados; por isso, consulte a documentação atual da Microsoft em vez de se basear em suposições legadas sobre o PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Pesquise domínios, endereços IP, endereços de email e dados históricos indexados ou leaked, sujeitos aos controles de acesso do serviço.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Pesquise endereços IP e outros indicadores para obter dados de inteligência de ameaças e reputação.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Pesquise endereços ou intervalos de IP para encontrar observações de varreduras da internet e atividades comuns de serviços. Consulte os termos atuais de acesso de teste e comunitário.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Obtenha informações de varreduras da internet e serviços para um endereço IP, host ou consulta de pesquisa. O acesso à API depende do plano da conta.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Pesquise conjuntos de dados de hosts, certificados, domínios e serviços de internet; seu modelo de dados e cobertura diferem dos do Shodan.

## [Pesquisa de buckets do GrayHatWarfare](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Pesquise por palavra-chave o índice do provedor de objetos e buckets de armazenamento em nuvem observados publicamente.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Pesquise dados de vazamentos indexados por endereços de email, nomes de usuário, domínios e registros relacionados. Use somente com autorização e evite a exposição desnecessária de dados de vazamentos.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Pesquise conteúdo de paste indexado por ocorrências de um endereço de email ou outro termo. Verifique se o serviço ainda está disponível antes de integrá-lo.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Obtenha sinais de reputação e risco para um endereço de email.

## GhostProject (histórico) <sup>[[24]](#references)</sup>

Historicamente, anunciava pesquisas em dados leaked de emails/senhas. Considere o serviço como um terceiro de alto risco para o tratamento de dados e verifique sua disponibilidade, legalidade e autorização antes de usá-lo.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Obtenha dados de varreduras da internet, exposição e inteligência de ameaças para endereços IP e ativos relacionados.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Verifique se um endereço de email ou domínio verificado aparece em vazamentos conhecidos. O serviço Pwned Passwords, separado, verifica hashes de senhas por prefixo; ele **não** revela senhas em texto puro.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Obtenha geolocalização de IP, data center, ASN, proxy/VPN e campos relacionados de enriquecimento. As cotas dependem do plano atual.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolocalização de IP e enriquecimento voltado a OSINT com pontos de dados selecionados. Consulte os termos atuais para uso comercial.


[DNSDumpster](https://dnsdumpster.com/) fornece resultados de reconhecimento de DNS.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) fornece inteligência sobre sites, hospedagem e infraestrutura de internet.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) fornece uma interface online para descoberta de subdomínios.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [API do BotScout](https://botscout.com/api.htm)
- [3] [API do Hunter](https://hunter.io/api-documentation)
- [4] [API do AlienVault OTX](https://otx.alienvault.com/api)
- [5] [Clearbit](https://dashboard.clearbit.com/)
- [6] [BuiltWith](https://builtwith.com/)
- [7] [FraudGuard](https://fraudguard.io/)
- [8] [FortiGuard Labs](https://www.fortiguard.com/)
- [9] [SpamCop](https://www.spamcop.net/)
- [10] [Web of Trust](https://www.mywot.com/)
- [11] [IPinfo](https://ipinfo.io/)
- [12] [SecurityTrails](https://securitytrails.com/)
- [13] [FullContact](https://www.fullcontact.com/)
- [14] [Microsoft Defender Threat Intelligence](https://learn.microsoft.com/en-us/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti)
- [15] [Intelligence X](https://intelx.io/)
- [16] [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
- [17] [GreyNoise](https://www.greynoise.io/)
- [18] [Shodan](https://www.shodan.io/)
- [19] [Censys](https://censys.com/)
- [20] [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
- [21] [DeHashed](https://www.dehashed.com/)
- [22] [psbdmp](https://psbdmp.ws/)
- [23] [EmailRep](https://emailrep.io/)
- [24] [Pesquisa de Cornell — Protocolos para verificar credenciais comprometidas (inclui GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [API do Have I Been Pwned](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [Localizador de subdomínios do NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
