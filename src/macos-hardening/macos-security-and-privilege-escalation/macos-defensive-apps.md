# Aplicaciones Defensivas de macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitoreará cada conexión realizada por cada proceso. Dependiendo del modo (permitir conexiones en silencio, denegar conexión en silencio y alertar) te **mostrará una alerta** cada vez que se establezca una nueva conexión. También tiene una interfaz gráfica muy agradable para ver toda esta información.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall de Objective-See. Este es un firewall básico que te alertará sobre conexiones sospechosas (tiene una interfaz gráfica, pero no es tan elegante como la de Little Snitch).

## Detección de persistencia

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplicación de Objective-See que buscará en varias ubicaciones donde **el malware podría estar persistiendo** (es una herramienta de un solo uso, no un servicio de monitoreo).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Como KnockKnock, monitoreando procesos que generan persistencia.

## Detección de keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplicación de Objective-See para encontrar **keyloggers** que instalan "event taps" de teclado.&#x20;

{{#include ../../banners/hacktricks-training.md}}
