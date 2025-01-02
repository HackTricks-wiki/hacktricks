# Aplicativos Defensivos do macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Ele monitorará cada conexão feita por cada processo. Dependendo do modo (permitir conexões silenciosamente, negar conexão silenciosamente e alertar) ele **mostrará um alerta** toda vez que uma nova conexão for estabelecida. Ele também possui uma interface gráfica muito boa para ver todas essas informações.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall da Objective-See. Este é um firewall básico que irá alertá-lo sobre conexões suspeitas (ele tem uma interface gráfica, mas não é tão sofisticada quanto a do Little Snitch).

## Detecção de persistência

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplicativo da Objective-See que irá procurar em vários locais onde **malware poderia estar persistindo** (é uma ferramenta de uso único, não um serviço de monitoramento).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Como o KnockKnock, monitorando processos que geram persistência.

## Detecção de keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplicativo da Objective-See para encontrar **keyloggers** que instalem "event taps" de teclado&#x20;

{{#include ../../banners/hacktricks-training.md}}
