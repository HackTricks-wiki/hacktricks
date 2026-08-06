# El protocolo Modbus

{{#include ../../banners/hacktricks-training.md}}

## Introducción al protocolo Modbus

El protocolo Modbus es un protocolo ampliamente utilizado en Sistemas de Automatización y Control Industrial. Modbus permite la comunicación entre varios dispositivos, como controladores lógicos programables (PLCs), sensores, actuadores y otros dispositivos industriales. Comprender el protocolo Modbus es esencial, ya que es el protocolo de comunicación más utilizado en ICS y ofrece una gran superficie de ataque potencial para realizar sniffing e incluso inyectar comandos en PLCs.

Aquí, los conceptos se presentan punto por punto, proporcionando contexto sobre el protocolo y su naturaleza de operación. El mayor desafío en la seguridad de los sistemas ICS es el coste de implementación y actualización. Estos protocolos y estándares fueron diseñados a principios de los años 80 y 90 y todavía se utilizan ampliamente. Dado que una industria cuenta con muchos dispositivos y conexiones, actualizar los dispositivos es muy difícil, lo que proporciona a los hackers una ventaja al enfrentarse a protocolos obsoletos. Los ataques contra Modbus son prácticamente inevitables, ya que se seguirá utilizando sin actualizaciones si su funcionamiento es crítico para la industria.

## La arquitectura cliente-servidor

El protocolo Modbus se utiliza normalmente en una arquitectura cliente-servidor, donde un dispositivo maestro (cliente) inicia la comunicación con uno o más dispositivos esclavos (servidores). Esto también se conoce como arquitectura maestro-esclavo, ampliamente utilizada en electrónica e IoT con SPI, I2C, etc.

## Versiones Serial y Etherent

El protocolo Modbus está diseñado tanto para comunicaciones Serial como para comunicaciones Ethernet. La comunicación Serial se utiliza ampliamente en sistemas legacy, mientras que los dispositivos modernos admiten Ethernet, que ofrece mayores velocidades de datos y es más adecuada para las redes industriales modernas.

## Representación de datos

Los datos se transmiten en el protocolo Modbus como ASCII o Binary, aunque se utiliza el formato binary debido a su compatibilidad compacta con dispositivos antiguos.

## Códigos de función

El protocolo ModBus funciona mediante la transmisión de códigos de función específicos que se utilizan para operar los PLCs y diversos dispositivos de control. Esta parte es importante de entender, ya que se pueden realizar replay attacks retransmitiendo códigos de función. Los dispositivos legacy no admiten ningún tipo de cifrado para la transmisión de datos y normalmente cuentan con cables largos que los conectan, lo que permite manipular estos cables y capturar o inyectar datos.

## Direccionamiento de Modbus

Cada dispositivo de la red tiene una dirección única, esencial para la comunicación entre dispositivos. Protocolos como Modbus RTU, Modbus TCP, etc., se utilizan para implementar el direccionamiento y actúan como una capa de transporte para la transmisión de datos. Los datos transferidos están en el formato del protocolo Modbus, que contiene el mensaje.

Además, Modbus también implementa comprobaciones de errores para garantizar la integridad de los datos transmitidos. Pero, sobre todo, Modbus es un estándar abierto y cualquiera puede implementarlo en sus dispositivos. Esto hizo que el protocolo se convirtiera en un estándar global y que se extendiera ampliamente en la industria de la automatización industrial.

Debido a su uso a gran escala y a la falta de actualizaciones, atacar Modbus proporciona una ventaja significativa gracias a su superficie de ataque. Los ICS dependen en gran medida de la comunicación entre dispositivos, y cualquier ataque contra ellos puede ser peligroso para el funcionamiento de los sistemas industriales. Si el medio de transmisión es identificado por el atacante, se pueden llevar a cabo ataques como replay, inyección de datos, sniffing y leaking de datos, Denial of Service, falsificación de datos, etc.

{{#include ../../banners/hacktricks-training.md}}
