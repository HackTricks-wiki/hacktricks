# O protocolo Modbus

{{#include ../../banners/hacktricks-training.md}}

## Introdução ao protocolo Modbus

O protocolo Modbus é amplamente utilizado em Sistemas de Automação e Controle Industrial. O Modbus permite a comunicação entre diversos dispositivos, como controladores lógicos programáveis (PLCs), sensores, atuadores e outros dispositivos industriais. Entender o protocolo Modbus é essencial, pois este é o protocolo de comunicação mais utilizado em ICS e possui uma grande attack surface para sniffing e até mesmo injeção de comandos em PLCs.

Aqui, os conceitos são apresentados em tópicos, fornecendo contexto sobre o protocolo e sua forma de operação. O maior desafio na segurança de sistemas ICS é o custo de implementação e atualização. Esses protocolos e padrões foram projetados no início das décadas de 1980 e 1990 e ainda são amplamente utilizados. Como uma indústria possui muitos dispositivos e conexões, atualizar os dispositivos é muito difícil, o que dá aos hackers uma vantagem ao lidar com protocolos desatualizados. Ataques ao Modbus são praticamente inevitáveis, pois ele continuará sendo utilizado sem atualizações enquanto sua operação for crítica para a indústria.

## A arquitetura Client-Server

O protocolo Modbus é normalmente utilizado em uma arquitetura Client-Server, na qual um dispositivo mestre (cliente) inicia a comunicação com um ou mais dispositivos escravos (servidores). Isso também é conhecido como arquitetura Master-Slave, amplamente utilizada em eletrônicos e IoT com SPI, I2C etc.

## Versões Serial e Etherent

O protocolo Modbus foi projetado tanto para comunicação Serial quanto para comunicações Ethernet. A comunicação Serial é amplamente utilizada em sistemas legados, enquanto dispositivos modernos oferecem suporte a Ethernet, que proporciona maiores taxas de transferência de dados e é mais adequada para redes industriais modernas.

## Representação de dados

Os dados são transmitidos no protocolo Modbus em formato ASCII ou binário, embora o formato binário seja utilizado devido à sua compactibilidade com dispositivos mais antigos.

## Function Codes

O protocolo Modbus funciona com a transmissão de códigos de função específicos, utilizados para operar PLCs e diversos dispositivos de controle. Esta parte é importante de entender, pois replay attacks podem ser realizados retransmitindo códigos de função. Dispositivos legados não oferecem suporte a qualquer tipo de criptografia na transmissão de dados e normalmente possuem cabos longos conectando-os, o que permite a adulteração desses cabos e a captura/injeção de dados.

## Endereçamento do Modbus

Cada dispositivo na rede possui um endereço exclusivo, essencial para a comunicação entre os dispositivos. Protocolos como Modbus RTU, Modbus TCP etc. são utilizados para implementar o endereçamento e funcionam como uma camada de transporte para a transmissão de dados. Os dados transferidos estão no formato do protocolo Modbus e contêm a mensagem.

Além disso, o Modbus também implementa verificações de erro para garantir a integridade dos dados transmitidos. Mas, acima de tudo, o Modbus é um padrão aberto, e qualquer pessoa pode implementá-lo em seus dispositivos. Isso fez com que esse protocolo se tornasse um padrão global e se disseminasse amplamente na indústria de automação industrial.

Devido à sua ampla utilização e à falta de atualizações, atacar o Modbus oferece uma vantagem significativa por causa de sua attack surface. O ICS depende fortemente da comunicação entre dispositivos, e quaisquer ataques realizados contra eles podem ser perigosos para a operação dos sistemas industriais. Ataques como replay, injeção de dados, sniffing e data leaking, Denial of Service, falsificação de dados etc. podem ser realizados caso o meio de transmissão seja identificado pelo atacante.

{{#include ../../banners/hacktricks-training.md}}
