# Hacking de sistemas de controle industrial

{{#include ../banners/hacktricks-training.md}}

## Sobre esta seção

Esta seção apresenta componentes, arquiteturas, protocolos e métodos de avaliação de segurança de sistemas de controle industrial (ICS). ICS faz parte do domínio mais amplo de tecnologia operacional (OT): sistemas e dispositivos programáveis que monitoram processos físicos ou provocam alterações neles. Exemplos comuns incluem sistemas de controle de supervisão e aquisição de dados (SCADA), sistemas de controle distribuído (DCSs) e controladores lógicos programáveis (PLCs).<sup>[[1]](#references)</sup>

O trabalho de segurança nesses ambientes deve considerar requisitos diferentes dos da TI convencional, incluindo segurança dos processos, confiabilidade, disponibilidade, operação determinística e ciclos de vida dos equipamentos. Um controle de segurança tecnicamente válido ainda pode ser inadequado se interromper o processo físico; por isso, os testes e as medidas corretivas devem ser coordenados com o proprietário do sistema e a equipe de operações.<sup>[[1]](#references)</sup>

Uma invasão ou interrupção acidental pode paralisar a produção, danificar equipamentos, liberar materiais perigosos, prejudicar o meio ambiente ou causar ferimentos e mortes. Esse possível impacto físico é o motivo pelo qual é necessário entender o processo controlado e seus limites seguros de operação antes de iniciar testes ativos.<sup>[[1]](#references)</sup>

Muitas implantações de OT mantêm sistemas operacionais, aplicações e protocolos legados porque os equipamentos têm uma vida útil longa e as alterações exigem testes operacionais e de segurança. Alguns protocolos foram projetados sem autenticação ou criptografia modernas, e a aplicação de patches pode ser limitada pelo suporte do fornecedor ou pelas janelas de manutenção; quando atualizações diretas não forem viáveis, compense com segmentação, controle de acesso e monitoramento.<sup>[[1]](#references)</sup>

## Prioridades da avaliação

Comece entendendo o processo controlado, os limites do sistema, a topologia de rede, os ativos, os fluxos de dados, as relações de confiança e as conexões externas. Dispositivos semelhantes podem ter funções diferentes em cada local, portanto, não presuma que a arquitetura ou o modelo de impacto de uma implantação se aplique a outra.<sup>[[1]](#references)</sup>

Sempre que possível, prefira a descoberta passiva e a documentação de engenharia existente. Qualquer varredura ativa ou exploração deve seguir um plano de teste aprovado que defina restrições de segurança, janelas de manutenção, procedimentos de recuperação e condições para interromper os testes. As descobertas devem ser avaliadas tanto pelo impacto na cibersegurança quanto pelos possíveis efeitos no processo físico.<sup>[[1]](#references)</sup>

O mesmo conhecimento arquitetural dá suporte a atividades defensivas, como inventário de ativos, segmentação de rede, monitoramento, resposta a incidentes e gerenciamento de vulnerabilidades baseado em risco.<sup>[[1]](#references)</sup>

## Abuso de controladores supervisórios de refrigeração

Um gerenciador de sistema de refrigeração coordena os controladores de compressores e vitrines refrigeradas, mas não refrigera as vitrines por conta própria. Assim, o acesso à interface de gerenciamento pode dar controle sobre muitos dispositivos subordinados por meio da distribuição normal de configurações. Isso é diferente de alterar um termostato ou acionar diretamente um compressor.<sup>[[3]](#references)[[4]](#references)</sup>

### Login com código de manutenção derivado da data

Nos gerenciadores de sistema Danfoss afetados, um login XML alternativo aceita um código derivado da data do controlador, em vez da senha de uma conta.<sup>[[2]](#references)[[3]](#references)</sup> Nos modelos SM800 e SC255, a Synacktiv rastreou os atributos `eds_only` e `quantum_only` por `xml_load_file` e `check_authorize` até `check_code_of_day`. O comunicado também mostra que `read_date_time` em `xml.cgi` revela a data do controlador sem autenticação.<sup>[[2]](#references)</sup> A Claroty encontrou um caminho `getauth` correspondente no AK-SM 800A, mas ocultou seus atributos de acionamento; não se deve presumir que os nomes de atributos dos modelos mais antigos funcionem nessa plataforma.<sup>[[3]](#references)</sup>

A Synacktiv documenta a consulta de data sem autenticação da seguinte forma:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

O código não contém segredo específico do dispositivo: recuperar o algoritmo a partir do [firmware](../hardware-physical-access/firmware-analysis/) pode fornecer uma credencial válida para a data em dispositivos com a mesma implementação afetada.<sup>[[2]](#references)[[3]](#references)</sup> Confirme primeiro o modelo e o firmware. Uma resposta baseada apenas na data não comprova que o login alternativo esteja disponível nem que uma sessão tenha sido obtida.

### Configuração em massa e abuso do aquecedor de degelo

Após obter acesso administrativo, identifique os controladores de expositores mapeados no gerenciador do sistema e verifique se a função de distribuição de configuração pode atualizá-los em conjunto. Uma alteração no setpoint do expositor normalmente aquece o gabinete apenas até a temperatura ambiente. Para aquecê-lo acima da temperatura ambiente, o controle relevante é o aquecedor elétrico de degelo do evaporador do controlador do expositor: o degelo interrompe o resfriamento e aciona esse aquecedor até que um sensor ou temporizador encerre o ciclo. Alterar o método de degelo, a programação, a temperatura de término e o limite de tempo pode manter o aquecedor ligado. O gerenciador pode distribuir essas alterações para vários expositores e suprimir os alarmes associados, transformando o comprometimento de um único sistema supervisório em uma mudança de processo em toda a loja.<sup>[[4]](#references)</sup>

Isso representa um risco ao processo físico, não uma prova de conceito segura em um sistema ativo. Quando presentes, os limitadores térmicos podem restringir o funcionamento do aquecedor, mas a operação contínua ainda pode superaquecer uma conexão elétrica preexistente e enfraquecida. Valide a configuração e o impacto apenas em um laboratório aprovado ou conforme o plano de segurança do processo do operador.<sup>[[4]](#references)</sup>

## Pontos de entrada de protocolos

- [Testes de Modbus](../network-services-pentesting/pentesting-modbus.md) aborda Modbus TCP, variantes seriais, códigos de função e acesso a registradores.
- [Testes de OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) aborda o serviço de troca de dados industriais.
- [Testes de BACnet](../network-services-pentesting/47808-udp-bacnet.md) aborda redes de controle de automação predial.

## References

- [1] [NIST SP 800-82 Rev. 3 - Guia de segurança da tecnologia operacional (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Bypass de autenticação nos System-Managers SM800 e SC255 da Danfoss](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Congele o controlador, descongele os alimentos](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - Não é preciso um Estado-nação para aquecer uma geladeira](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
