# El Protocolo Modbus

## Introducción al Protocolo Modbus

El protocolo Modbus es un protocolo ampliamente utilizado en Sistemas de Automatización y Control Industrial. Modbus permite la comunicación entre varios dispositivos como controladores lógicos programables (PLCs), sensores, actuadores y otros dispositivos industriales. Comprender el Protocolo Modbus es esencial ya que es el protocolo de comunicación más utilizado en los Sistemas de Control Industrial y tiene una gran superficie de ataque potencial para el espionaje e incluso la inyección de comandos en los PLCs.

Aquí, los conceptos se presentan de manera puntual proporcionando el contexto del protocolo y su naturaleza de operación. El mayor desafío en la seguridad del sistema ICS es el costo de implementación y actualización. Estos protocolos y estándares fueron diseñados a principios de los años 80 y 90 y siguen siendo ampliamente utilizados. Dado que una industria tiene muchos dispositivos y conexiones, actualizar los dispositivos es muy difícil, lo que proporciona a los hackers una ventaja al tratar con protocolos obsoletos. Los ataques a Modbus son prácticamente inevitables ya que se seguirá utilizando sin actualización y su operación es crítica para la industria.

## La Arquitectura Cliente-Servidor

El Protocolo Modbus se utiliza típicamente en una Arquitectura Cliente-Servidor donde un dispositivo maestro (cliente) inicia la comunicación con uno o más dispositivos esclavos (servidores). Esto también se conoce como arquitectura Maestro-Esclavo, que se utiliza ampliamente en electrónica e IoT con SPI, I2C, etc.

## Versiones Serial y Ethernet

El Protocolo Modbus está diseñado tanto para Comunicación Serial como para Comunicaciones Ethernet. La Comunicación Serial se utiliza ampliamente en sistemas heredados, mientras que los dispositivos modernos admiten Ethernet, que ofrece altas tasas de datos y es más adecuado para redes industriales modernas.

## Representación de Datos

Los datos se transmiten en el protocolo Modbus como ASCII o Binario, aunque el formato binario se utiliza debido a su compatibilidad con dispositivos más antiguos.

## Códigos de Función

El Protocolo Modbus funciona con la transmisión de códigos de función específicos que se utilizan para operar los PLCs y varios dispositivos de control. Esta parte es importante para entender ya que los ataques de repetición pueden realizarse retransmitiendo códigos de función. Los dispositivos heredados no admiten ningún cifrado para la transmisión de datos y suelen tener cables largos que los conectan, lo que resulta en la manipulación de estos cables y la captura/inserción de datos.

## Dirección de Modbus

Cada dispositivo en la red tiene una dirección única que es esencial para la comunicación entre dispositivos. Protocolos como Modbus RTU, Modbus TCP, etc. se utilizan para implementar la dirección y sirven como una capa de transporte para la transmisión de datos. Los datos que se transfieren están en el formato de protocolo Modbus que contiene el mensaje.

Además, Modbus también implementa controles de errores para garantizar la integridad de los datos transmitidos. Pero sobre todo, Modbus es un Estándar Abierto y cualquiera puede implementarlo en sus dispositivos. Esto hizo que este protocolo se convirtiera en un estándar global y se extendiera en la industria de automatización industrial.

Debido a su amplio uso y falta de actualizaciones, atacar Modbus proporciona una ventaja significativa con su superficie de ataque. El ICS depende en gran medida de la comunicación entre dispositivos y cualquier ataque realizado sobre ellos puede ser peligroso para el funcionamiento de los sistemas industriales. Ataques como repetición, inyección de datos, espionaje y filtración de datos, Denegación de Servicio, falsificación de datos, etc. pueden llevarse a cabo si el medio de transmisión es identificado por el atacante.
