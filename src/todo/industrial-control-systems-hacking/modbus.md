# El Protocolo Modbus

## Introducción al Protocolo Modbus

El protocolo Modbus es un protocolo ampliamente utilizado en la Automatización Industrial y los Sistemas de Control. Modbus permite la comunicación entre varios dispositivos, como controladores lógicos programables (PLC), sensores, actuadores y otros dispositivos industriales. Comprender el Protocolo Modbus es esencial, ya que este es el protocolo de comunicación más utilizado en los ICS y tiene una gran superficie de ataque potencial para el sniffing e incluso la inyección de comandos en los PLC.

Aquí, los conceptos se presentan de manera puntual proporcionando contexto sobre el protocolo y su naturaleza de operación. El mayor desafío en la seguridad de los sistemas ICS es el costo de implementación y actualización. Estos protocolos y estándares fueron diseñados a principios de los años 80 y 90, que todavía se utilizan ampliamente. Dado que una industria tiene muchos dispositivos y conexiones, actualizar los dispositivos es muy difícil, lo que proporciona a los hackers una ventaja al tratar con protocolos obsoletos. Los ataques a Modbus son prácticamente inevitables, ya que se va a utilizar sin actualización y su operación es crítica para la industria.

## La Arquitectura Cliente-Servidor

El Protocolo Modbus se utiliza típicamente en una Arquitectura Cliente-Servidor donde un dispositivo maestro (cliente) inicia la comunicación con uno o más dispositivos esclavos (servidores). Esto también se conoce como arquitectura Maestro-Esclavo, que se utiliza ampliamente en electrónica e IoT con SPI, I2C, etc.

## Versiones Serial y Ethernet

El Protocolo Modbus está diseñado tanto para Comunicación Serial como para Comunicaciones Ethernet. La Comunicación Serial se utiliza ampliamente en sistemas heredados, mientras que los dispositivos modernos admiten Ethernet, que ofrece altas tasas de datos y es más adecuado para redes industriales modernas.

## Representación de Datos

Los datos se transmiten en el protocolo Modbus como ASCII o Binario, aunque el formato binario se utiliza debido a su compatibilidad con dispositivos más antiguos.

## Códigos de Función

El Protocolo Modbus funciona con la transmisión de códigos de función específicos que se utilizan para operar los PLC y varios dispositivos de control. Esta parte es importante de entender, ya que se pueden realizar ataques de repetición retransmitiendo códigos de función. Los dispositivos heredados no admiten ninguna encriptación para la transmisión de datos y generalmente tienen cables largos que los conectan, lo que resulta en la manipulación de estos cables y la captura/inyección de datos.

## Direccionamiento de Modbus

Cada dispositivo en la red tiene una dirección única que es esencial para la comunicación entre dispositivos. Protocolos como Modbus RTU, Modbus TCP, etc. se utilizan para implementar el direccionamiento y sirven como una capa de transporte para la transmisión de datos. Los datos que se transfieren están en el formato del protocolo Modbus que contiene el mensaje.

Además, Modbus también implementa verificaciones de errores para garantizar la integridad de los datos transmitidos. Pero, sobre todo, Modbus es un Estándar Abierto y cualquiera puede implementarlo en sus dispositivos. Esto hizo que este protocolo se convirtiera en un estándar global y su uso se extendiera en la industria de la automatización industrial.

Debido a su uso a gran escala y la falta de actualizaciones, atacar Modbus proporciona una ventaja significativa con su superficie de ataque. Los ICS dependen en gran medida de la comunicación entre dispositivos y cualquier ataque realizado sobre ellos puede ser peligroso para la operación de los sistemas industriales. Ataques como repetición, inyección de datos, sniffing de datos y leaking, Denegación de Servicio, falsificación de datos, etc. pueden llevarse a cabo si el medio de transmisión es identificado por el atacante.
