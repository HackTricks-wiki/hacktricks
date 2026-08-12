# Hacking de Sistemas de Controle Industrial

{{#include ../../banners/hacktricks-training.md}}

## Sobre Esta Seção

Esta seção apresenta componentes, arquiteturas, protocolos e métodos de avaliação de segurança de sistemas de controle industrial (ICS). ICS faz parte do domínio mais amplo de tecnologia operacional (OT): sistemas e dispositivos programáveis que monitoram ou provocam alterações em processos físicos. Exemplos comuns incluem sistemas de supervisão e aquisição de dados (SCADA), sistemas de controle distribuído (DCSs) e controladores lógicos programáveis (PLCs).<sup>[[1]](#references)</sup>

O trabalho de segurança nesses ambientes deve considerar requisitos diferentes dos da IT convencional, incluindo segurança do processo, confiabilidade, disponibilidade, operação determinística e ciclos de vida dos equipamentos. Um controle de segurança tecnicamente válido ainda pode ser inadequado se interromper o processo físico; portanto, os testes e a remediação devem ser coordenados com o proprietário do sistema e a equipe de operações.<sup>[[1]](#references)</sup>

Um comprometimento ou uma interrupção acidental pode interromper a produção, danificar equipamentos, liberar materiais perigosos, prejudicar o meio ambiente ou causar ferimentos e perda de vidas. Esse possível impacto físico é o motivo pelo qual compreender o processo controlado e seus limites seguros de operação deve vir antes dos testes ativos.<sup>[[1]](#references)</sup>

Muitas implementações de OT mantêm sistemas operacionais, aplicações e protocolos legados porque os equipamentos têm uma longa vida útil e as alterações exigem testes operacionais e de segurança. Alguns protocolos foram projetados sem autenticação ou criptografia modernas, e a aplicação de patches pode ser limitada pelo suporte do fornecedor ou pelas janelas de manutenção; nesses casos, use segmentação, controle de acesso e monitoramento quando atualizações diretas não forem viáveis.<sup>[[1]](#references)</sup>

## Prioridades da Avaliação

Comece compreendendo o processo controlado, os limites do sistema, a topologia da rede, os ativos, os fluxos de dados, as relações de confiança e as conexões externas. Tipos semelhantes de dispositivos podem desempenhar funções diferentes em locais distintos; portanto, evite presumir que a arquitetura ou o modelo de impacto de uma implementação se aplica a outra.<sup>[[1]](#references)</sup>

Dê preferência à descoberta passiva e à documentação de engenharia existente sempre que possível. Qualquer varredura ativa ou exploração deve seguir um plano de testes aprovado que defina restrições de segurança, janelas de manutenção, procedimentos de recuperação e condições de interrupção. As descobertas devem ser avaliadas tanto pelo impacto na cibersegurança quanto pelos possíveis efeitos no processo físico.<sup>[[1]](#references)</sup>

O mesmo conhecimento arquitetural apoia atividades defensivas, como inventário de ativos, segmentação de rede, monitoramento, resposta a incidentes e gerenciamento de vulnerabilidades baseado em riscos.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Guia de Segurança de Tecnologia Operacional (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
