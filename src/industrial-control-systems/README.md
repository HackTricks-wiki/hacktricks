# Hacking de Sistemas de Controle Industrial

{{#include ../banners/hacktricks-training.md}}

## Sobre esta seção

Esta seção apresenta componentes, arquiteturas, protocolos e métodos de avaliação de segurança de sistemas de controle industrial (ICS). ICS faz parte do domínio mais amplo de tecnologia operacional (OT): sistemas e dispositivos programáveis que monitoram processos físicos ou provocam alterações neles. Exemplos comuns incluem sistemas de supervisão e aquisição de dados (SCADA), sistemas de controle distribuído (DCSs) e controladores lógicos programáveis (PLCs).<sup>[[1]](#references)</sup>

O trabalho de segurança nesses ambientes deve considerar requisitos que diferem dos de TI convencional, incluindo segurança de processos, confiabilidade, disponibilidade, operação determinística e ciclos de vida dos equipamentos. Um controle de segurança tecnicamente válido ainda pode ser inadequado se interromper o processo físico; por isso, os testes e as medidas corretivas devem ser coordenados com o proprietário do sistema e a equipe de operações.<sup>[[1]](#references)</sup>

Uma invasão ou interrupção acidental pode paralisar a produção, danificar equipamentos, liberar materiais perigosos, prejudicar o meio ambiente ou causar ferimentos e mortes. Esse possível impacto físico é o motivo pelo qual entender o processo controlado e seus limites operacionais seguros deve vir antes de qualquer teste ativo.<sup>[[1]](#references)</sup>

Muitas implantações de OT mantêm sistemas operacionais, aplicações e protocolos legados porque os equipamentos têm uma vida útil longa e as mudanças exigem testes operacionais e de segurança. Alguns protocolos foram projetados sem autenticação ou criptografia modernas, e a aplicação de patches pode ser limitada pelo suporte do fornecedor ou pelas janelas de manutenção; quando atualizações diretas não forem viáveis, compense com segmentação, controle de acesso e monitoramento.<sup>[[1]](#references)</sup>

## Prioridades da avaliação

Comece entendendo o processo controlado, os limites do sistema, a topologia da rede, os ativos, os fluxos de dados, as relações de confiança e as conexões externas. Dispositivos semelhantes podem ter funções distintas em diferentes instalações; portanto, evite presumir que a arquitetura ou o modelo de impacto de uma implantação se aplique a outra.<sup>[[1]](#references)</sup>

Sempre que possível, prefira a descoberta passiva e a documentação de engenharia existente. Qualquer varredura ativa ou exploração deve seguir um plano de teste aprovado que defina restrições de segurança, janelas de manutenção, procedimentos de recuperação e condições para interromper os testes. As descobertas devem ser avaliadas tanto pelo impacto na segurança cibernética quanto pelos possíveis efeitos no processo físico.<sup>[[1]](#references)</sup>

O mesmo conhecimento arquitetônico dá suporte a atividades defensivas, como inventário de ativos, segmentação de rede, monitoramento, resposta a incidentes e gestão de vulnerabilidades baseada em risco.<sup>[[1]](#references)</sup>

## Pontos de entrada de protocolos

- [Testes de Modbus](../network-services-pentesting/pentesting-modbus.md) aborda Modbus TCP, variantes seriais, códigos de função e acesso a registradores.
- [Testes de OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) aborda o serviço de troca de dados industrial.
- [Testes de BACnet](../network-services-pentesting/47808-udp-bacnet.md) aborda redes de controle de automação predial.

## References

- [1] [NIST SP 800-82 Rev. 3 - Guia de segurança de tecnologia operacional (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../banners/hacktricks-training.md}}
