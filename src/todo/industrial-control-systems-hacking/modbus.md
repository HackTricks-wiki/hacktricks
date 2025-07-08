# O Protocolo Modbus

{{#include /banners/hacktricks-training.md}}

## Introdução ao Protocolo Modbus

O protocolo Modbus é um protocolo amplamente utilizado em Automação Industrial e Sistemas de Controle. O Modbus permite a comunicação entre vários dispositivos, como controladores lógicos programáveis (PLCs), sensores, atuadores e outros dispositivos industriais. Compreender o Protocolo Modbus é essencial, uma vez que este é o protocolo de comunicação mais utilizado no ICS e possui uma grande superfície de ataque potencial para sniffing e até mesmo injeção de comandos em PLCs.

Aqui, os conceitos são apresentados de forma pontual, fornecendo contexto sobre o protocolo e sua natureza de operação. O maior desafio na segurança dos sistemas ICS é o custo de implementação e atualização. Esses protocolos e padrões foram projetados no início dos anos 80 e 90, que ainda são amplamente utilizados. Como uma indústria possui muitos dispositivos e conexões, atualizar dispositivos é muito difícil, o que dá aos hackers uma vantagem ao lidar com protocolos desatualizados. Ataques ao Modbus são praticamente inevitáveis, uma vez que será utilizado sem atualização, pois sua operação é crítica para a indústria.

## A Arquitetura Cliente-Servidor

O Protocolo Modbus é tipicamente utilizado na Arquitetura Cliente-Servidor, onde um dispositivo mestre (cliente) inicia a comunicação com um ou mais dispositivos escravos (servidores). Isso também é referido como arquitetura Mestre-Escravo, que é amplamente utilizada em eletrônica e IoT com SPI, I2C, etc.

## Versões Serial e Ethernet

O Protocolo Modbus é projetado tanto para Comunicação Serial quanto para Comunicações Ethernet. A Comunicação Serial é amplamente utilizada em sistemas legados, enquanto dispositivos modernos suportam Ethernet, que oferece altas taxas de dados e é mais adequado para redes industriais modernas.

## Representação de Dados

Os dados são transmitidos no protocolo Modbus como ASCII ou Binário, embora o formato binário seja utilizado devido à sua compatibilidade com dispositivos mais antigos.

## Códigos de Função

O Protocolo ModBus funciona com a transmissão de códigos de função específicos que são usados para operar os PLCs e vários dispositivos de controle. Esta parte é importante para entender, uma vez que ataques de replay podem ser realizados retransmitindo códigos de função. Dispositivos legados não suportam nenhuma criptografia para a transmissão de dados e geralmente possuem fios longos que os conectam, o que resulta na manipulação desses fios e captura/injeção de dados.

## Endereçamento do Modbus

Cada dispositivo na rede possui um endereço único, que é essencial para a comunicação entre dispositivos. Protocolos como Modbus RTU, Modbus TCP, etc., são usados para implementar o endereçamento e servem como uma camada de transporte para a transmissão de dados. Os dados que são transferidos estão no formato do protocolo Modbus, que contém a mensagem.

Além disso, o Modbus também implementa verificações de erro para garantir a integridade dos dados transmitidos. Mas, acima de tudo, o Modbus é um Padrão Aberto e qualquer um pode implementá-lo em seus dispositivos. Isso fez com que esse protocolo se tornasse um padrão global e sua ampla utilização na indústria de automação industrial.

Devido ao seu uso em larga escala e à falta de atualizações, atacar o Modbus oferece uma vantagem significativa com sua superfície de ataque. O ICS é altamente dependente da comunicação entre dispositivos e quaisquer ataques realizados contra eles podem ser perigosos para a operação dos sistemas industriais. Ataques como replay, injeção de dados, sniffing de dados e vazamentos, negação de serviço, falsificação de dados, etc., podem ser realizados se o meio de transmissão for identificado pelo atacante.

{{#include /banners/hacktricks-training.md}}
