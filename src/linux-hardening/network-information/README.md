# Informações de rede

{{#include ../../banners/hacktricks-training.md}}

Listeners locais, sockets Unix e softwares expostos à rede podem revelar caminhos invisíveis em uma varredura externa. Comece pelos serviços em escuta no host e pelo processo que possui cada endpoint.

- [Triagem de captura de tráfego, firewall e tráfego de saída](traffic-capture-and-firewall-egress.md) aborda captura de pacotes, filtragem, proxies e testes de conectividade.
- [Triagem de rede local e sockets](local-network-and-socket-triage.md) aborda serviços de loopback, sockets Unix e redes de contêineres.
- [Injeção de comandos via socket](socket-command-injection.md) aborda comandos aceitos por sockets locais expostos.
- Para acessos iniciais ao appliance Cisco SD-WAN Manager, consulte [escalonamento local de privilégios no vManage](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md); sua CLI ConfD, API REST e caminhos de importação pertencentes ao root são distintos da triagem geral de sockets.
{{#include ../../banners/hacktricks-training.md}}
