# Network Protocols Explained \(ESP\)

## Multicast DNS \(mDNS\)

 The **multicast DNS** \(**mDNS**\) protocol resolves host names to IP addresses within small networks that do not include a local name server.

When an mDNS client needs to resolve a host name, it sends an Ip Multicast query message that asks the host having that name to identify itself. That target machine then multicasts a message that includes its IP address. All machines in that subnet can then use that information to update their mDNS caches.

Any host can relinquish its claim to a domain name by sending a response packet with a Time To Live\(TTL\) equal to zero.

By default, mDNS only and exclusively resolves host names ending with the **.local** top-level domain \(TLD\). This can cause problems if that domain includes hosts which do not implement mDNS but which can be found via a conventional unicast DNS server. Resolving such conflicts requires network-configuration changes.

* When using Ethernet frames, the standard multicast MAC address _01:00:5E:00:00:FB_ \(for IPv4\) or _33:33:00:00:00:FB_ \(for IPv6\).
* IPv4 address _224.0.0.251_ or IPv6 address _ff02::fb_.
* UDP port 5353.

mDNS queries will not pass through routers \(broadcast in ethernet only\).

## DNS-SD \(Service Discovery\)

This protocol can be used to discover hosts in the network. To do that you can requests special domain names \(e.g. _\_printers\_tcp.local_\) and all the domains rlated with that name will answer \(in this cases, printers\). A complete list with this special names can be found [here](http://www.dns-sd.org/ServiceTypes.html).

## SSDP

The Simple Service Discovery Protocol is used to discover services in a network mainly for using the protocol UPnP.

SSDP is a text-based protocol based on [HTTPU](https://en.wikipedia.org/wiki/HTTPU). It uses UDP as the underlying transport protocol. Services are announced by the hosting system with multicast addressing to a specifically designated IP multicast address at UDP port number 1900. In IPv4, the multicast address is 239.255.255.250

## WSD

**Web Service for Devices**.  
This service allow the a device connected in a network to discover which services \(like printers\) are available in the network.

The client can send a broadcast UDP packet asking for some kind of service or the service provider can send a broadcast packet saying that it is offering a service.

## OAuth2.0

 Procolo que permite compartir tu información por ejemplo de google con otros servicios.

Básicamente **permite compartir la información justa** y necesaria que se tiene guardado en un servicio, con otro. De esta forma se puede logear más rápido y tus **datos están tan solo guardados en un sitio** y no hay que poner usernames/contraseñas en todos lados.

Esto funciona así:

Primero tienes que estar ya logeado en google o se te abrirá una ventana para que te logees. Acto seguido, el servicio pedirá al servidor de google un token para acceder a tu info. Google soltará una de esas pantalla de “_La aplicación XXXXX quiere acceder a esta información tuya: ..._” al darle a aceptar, google responderá a la aplicación con un código el cuál pa aplicación usará para pedirle un token con el que google responderá. Una vez la aplicación tenga un token la puede usar con el API de google para obtener la información que había pedido.

## RADIUS

 Protocolo de autenticación y autorización para acceder a una red. \(Usa puerto 1813 UDP\)

Se usa principalmente por proveedores de servicios de internet para gestionar el acceso a la red de sus clientes.

Permite Autenticación, Autorización y Anotación.

Cómo funciona:

El usuario primero habla con el NAS \(puerta den entrada al servidor\), este comprueba que el nombre y contraseña que se le envía sean válidos preguntándoselo al servidor RADIUS.

Opcionalmente por mayor seguridad se puede comprobar la dirección de red o nº de teléfono del servidor para ver si coincide.

Tanto el servidor RADIUS como el usuario que intenta conectarse tienen un “secreto compartido“, de esta forma el servidor RADIUS envía un desafío al NAS que reenvía al usuario que se está logeando, este lo encripta con dicho secreto y se lo reenvía y si coincide con el cifrado que ha hecho el RADIUS, el usuario ha demostrado su identidad.

Una vez se demuestra la identidad, el usuario RADIUS instruye al NAS para que este le asigne al usuario una dirección IP. Así mismo, cuando esto es realizado, el NAS envía una mensaje de inicio al RADIUS para que este lo anote. Cuando el usuario cierra la sesión el NAS envía un mensaje de finalización. De esta forma el RADIUS anota el consumo de la sesión para poder facturar en consecuencia \(también se usan estos datos con motivos estadísticos\)

## SMB and NetBIOS

###  **SMB**

Es un protocolo para compartir archivos/impresoras/puertos...

Este puede correr directamente sobre TCP en el puerto 445 \(que si haces un escaneo de windows ves que lo llama microsoft-ds\)

O sobre UDP 137, 138 o TCP 137, 138 que usa NetBIOS sobre TCP \( llamado netbios -ssn\)

El objetivo de que SMB esté implementado sobre solo TCP o sobre NetBIOS + TCP es aumentar la capacidad de comunicación con más equipos que solo soportan uno u otro

### **NetBIOS**

Su función es la de establecer sesiones y mantener las conexiones para poder compartir recursos en red, pero para enviar paquetes de un sitio a otro requiere de IPC/IPX o NetBEUI o TCP/IP.

Cada máquina usando NetBIOS debe tener un **nombre** único que la distinga del resto. Así que cuando entra una nueva máquina, primero se revisa que nadie use el nombre que solicita usar. también existen los **nombres de grupo** que pueden usar todas las estaciones que quieran pero no pueden haber dos grupos con el mismo nombre. Es una forma de poder enviar mensajes a varias máquinas. Por lo que se pueden enviar mensajes a un usuario, a un grupo o broadcast.

La conexión puede ser connectionless o connection-oriented:

 **connectionless:** Se envía un datagrama al destino pero no hay ninguna forma de saludo ni de mensaje de recibido. La máquina destino debe estar configurada para poder recibir datagramas.

 **connection-orineted:** Se crea una sesión entre dos nombres \(puede ser incluso entre dos nombres de la misma máquina\) sí se envía mensaje de recibido o error.

**NetBEUI** consiste realmente en NetBIOS sobre NetBEUI el cual es un protocolo de red y transporte que lleva a NetBIOS, este era rápido pero muy ruidoso pues emitía muchos broadcast, también se puede tener SMB sobre NetBEUI pero ya es más normal que NetBIOS corra sobre TCP.

## LDAP

 Protocolo que permite administrar directorios y acceder a bases de información de usuarios mediante TCP/IP.

Permite tanto sacar información como introduirla mediante distintos comandos.

Por lo tanto es un protocolo que sirve para acceder a diversas bases de datos que están preparadas para hablar este protocolo

## Active Directory

Básicamente es una base de datos de objetos con información como usuarios, grupos, privilegios y recursos que es accesible desde la red \(a traves de un dominio\) para que se pueda acceder a dicha información y se pueda manejar de forma centralizada.

Servidor que guarda objetos. Estos objetos son visibles en la red mediante un dominio. Un dominio puede tener dentro de él su servidor donde está implementado, grupos, usuarios...

También puede tener subdominios que tengan su propio servidor asociado con sus grupos, usuarios...

De esta forma se centraliza la gestión de usuarios de una red pues se pueden generar en este servidor los usuarios que se pueden logear, con los permisos que tienen para saber si pueden acceder a determinados recursos de la red y así se puede controlar todo esto de una forma sencilla.

De esta forma se puede consultar el directorio con un nombre de usuario y obtener info como correo o nº de telefono. También se puedenhacer consultas generalizadas como:¿donde estan las impresoras? ¿Cuáles son los nombres de los dominios?

