# O protocolo Modbus

{{#include ../../banners/hacktricks-training.md}}

## Introdução ao Modbus

Modbus é um protocolo de camada de aplicação aberto, amplamente implementado por PLCs, sensores, atuadores e outros dispositivos industriais. Seu modelo de solicitação/resposta expõe coils e registradores por meio de function codes. Portanto, os testes de segurança se concentram em leituras/escritas não autorizadas, observação de tráfego, replay e comportamento inseguro do dispositivo — não apenas na descoberta da porta TCP 502.<sup>[[1]](#references)</sup>

Muitas implementações mantêm equipamentos seriais legados porque as atualizações exigem indisponibilidade, recertificação ou substituição de dispositivos de campo. O Modbus tradicional não oferece confidencialidade nem autenticação entre pares; o Modbus Security é um perfil separado baseado em TLS, que utiliza certificados X.509 e a porta TCP 802. Como a especificação é pública e pode ser implementada de forma independente, o comportamento dos vendors e o suporte a funções opcionais variam e devem ser identificados por fingerprinting, em vez de presumidos.<sup>[[1]](#references)[[2]](#references)</sup>

## A arquitetura cliente-servidor

Na terminologia atual, um **cliente** inicia uma transação e um **servidor** retorna uma resposta. Documentações mais antigas usam **master/slave**. Não confunda essa relação de aplicação com SPI ou I2C: esses são protocolos de barramento diferentes.<sup>[[1]](#references)</sup>

## Transportes serial e Ethernet

Os mesmos dados de aplicação do Modbus podem ser transportados por variantes seriais (framing RTU ou ASCII) e pelo Modbus TCP. O Modbus TCP adiciona um cabeçalho MBAP e normalmente usa a porta TCP 502; o RTU serial usa framing binário compacto e um CRC, enquanto o ASCII serial representa bytes como caracteres hexadecimais e usa um LRC.<sup>[[1]](#references)[[3]](#references)</sup>

## Representação de dados

O modelo de dados consiste em coils/entradas discretas de bit único e registradores de entrada/de retenção de 16 bits. Valores com múltiplos registradores, ordem dos bytes, escala e significado semântico são específicos de cada dispositivo e devem ser confirmados no mapa de registradores do vendor.<sup>[[1]](#references)</sup>

## Function codes

Os function codes selecionam operações como leitura de coils (`0x01`), leitura de registradores de retenção (`0x03`), escrita de um único coil/registrador (`0x05`/`0x06`) e escrita de múltiplos coils/registradores (`0x0F`/`0x10`). Uma solicitação de escrita capturada pode ser reutilizada em um replay quando a implementação não possui autenticação compensatória nem verificações do estado do processo. Com acesso físico autorizado a longos trechos seriais, um assessor também pode capturar ou injetar frames diretamente na fiação após identificar a interface elétrica, a terminação e o método seguro de conexão. Qualquer uma dessas ações pode afetar o processo físico; portanto, use um laboratório ou obtenha autorização operacional explícita.<sup>[[1]](#references)[[3]](#references)</sup>

## Endereçamento

Dispositivos seriais usam um endereço de unidade. O Modbus TCP usa endereçamento IP mais um identificador de unidade no cabeçalho MBAP, o que é particularmente relevante quando um gateway TCP-para-serial encaminha solicitações para unidades downstream. As referências de registradores mostradas na documentação do produto podem ser baseadas em um (`40001`), enquanto os endereços do protocolo são baseados em zero, uma fonte comum de erros de off-by-one.<sup>[[1]](#references)[[3]](#references)</sup>

O framing serial inclui verificações de erros de transmissão (CRC para RTU e LRC para ASCII), e o TCP fornece seu checksum normal de transporte. Essas verificações detectam corrupção acidental; não são integridade criptográfica nem autenticação de origem.<sup>[[3]](#references)</sup>

Durante um assessment autorizado, teste a exposição, os function codes permitidos, os intervalos de endereços graváveis, o tratamento de exceções, os limites de taxa e se a segmentação de rede ou um firewall compatível com Modbus restringe os clientes. As ameaças relevantes incluem divulgação passiva, injeção de comandos não autorizada, replay, falsificação de dados e denial of service. Coordene todos os testes ativos com os responsáveis pelo processo, pois alterações aparentemente pequenas nos registradores podem modificar um processo físico.

## References

- [1] [Modbus Organization — Especificação do Protocolo de Aplicação Modbus V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Protocolo Modbus Security e guias de implementação](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Especificação e Guia de Implementação do Modbus sobre Linha Serial V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
