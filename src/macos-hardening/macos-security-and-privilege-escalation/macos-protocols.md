# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Serviços de Acesso Remoto

Estes são os serviços comuns do macOS para acessá-los remotamente.\
Você pode habilitar/desabilitar esses serviços em `System Settings` --> `Sharing`

- **VNC**, conhecido como “Screen Sharing” (tcp:5900)
- **SSH**, chamado de “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), ou “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, conhecido como “Remote Apple Event” (tcp:3031)

Verifique se algum está habilitado executando:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) é uma versão aprimorada do [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptada para macOS, oferecendo recursos adicionais. Uma vulnerabilidade notável no ARD é seu método de autenticação para a senha da tela de controle, que usa apenas os primeiros 8 caracteres da senha, tornando-o suscetível a [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) com ferramentas como Hydra ou [GoRedShell](https://github.com/ahhh/GoRedShell/), já que não há limites de taxa padrão.

Instâncias vulneráveis podem ser identificadas usando o script `vnc-info` do **nmap**. Serviços que suportam `VNC Authentication (2)` são especialmente suscetíveis a ataques de força bruta devido à truncagem da senha de 8 caracteres.

Para habilitar o ARD para várias tarefas administrativas, como escalonamento de privilégios, acesso GUI ou monitoramento de usuários, use o seguinte comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD fornece níveis de controle versáteis, incluindo observação, controle compartilhado e controle total, com sessões persistindo mesmo após mudanças de senha do usuário. Permite o envio de comandos Unix diretamente, executando-os como root para usuários administrativos. O agendamento de tarefas e a pesquisa remota do Spotlight são recursos notáveis, facilitando buscas remotas de baixo impacto por arquivos sensíveis em várias máquinas.

## Protocolo Bonjour

Bonjour, uma tecnologia projetada pela Apple, permite que **dispositivos na mesma rede detectem os serviços oferecidos uns pelos outros**. Também conhecido como Rendezvous, **Zero Configuration** ou Zeroconf, permite que um dispositivo se junte a uma rede TCP/IP, **escolha automaticamente um endereço IP** e transmita seus serviços para outros dispositivos da rede.

A Rede de Zero Configuração, fornecida pelo Bonjour, garante que os dispositivos possam:

- **Obter automaticamente um endereço IP** mesmo na ausência de um servidor DHCP.
- Realizar **tradução de nome para endereço** sem exigir um servidor DNS.
- **Descobrir serviços** disponíveis na rede.

Dispositivos que utilizam Bonjour atribuirão a si mesmos um **endereço IP da faixa 169.254/16** e verificarão sua exclusividade na rede. Macs mantêm uma entrada de tabela de roteamento para essa sub-rede, verificável via `netstat -rn | grep 169`.

Para DNS, o Bonjour utiliza o **protocolo Multicast DNS (mDNS)**. O mDNS opera sobre **a porta 5353/UDP**, empregando **consultas DNS padrão** mas direcionando para o **endereço multicast 224.0.0.251**. Essa abordagem garante que todos os dispositivos ouvindo na rede possam receber e responder às consultas, facilitando a atualização de seus registros.

Ao ingressar na rede, cada dispositivo auto-seleciona um nome, geralmente terminando em **.local**, que pode ser derivado do nome do host ou gerado aleatoriamente.

A descoberta de serviços dentro da rede é facilitada pelo **DNS Service Discovery (DNS-SD)**. Aproveitando o formato dos registros DNS SRV, o DNS-SD utiliza **registros DNS PTR** para permitir a listagem de múltiplos serviços. Um cliente que busca um serviço específico solicitará um registro PTR para `<Service>.<Domain>`, recebendo em troca uma lista de registros PTR formatados como `<Instance>.<Service>.<Domain>` se o serviço estiver disponível a partir de múltiplos hosts.

A utilidade `dns-sd` pode ser empregada para **descobrir e anunciar serviços de rede**. Aqui estão alguns exemplos de seu uso:

### Buscando Serviços SSH

Para buscar serviços SSH na rede, o seguinte comando é utilizado:
```bash
dns-sd -B _ssh._tcp
```
Este comando inicia a busca por serviços \_ssh.\_tcp e exibe detalhes como timestamp, flags, interface, domínio, tipo de serviço e nome da instância.

### Anunciando um Serviço HTTP

Para anunciar um serviço HTTP, você pode usar:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Este comando registra um serviço HTTP chamado "Index" na porta 80 com um caminho de `/index.html`.

Para então procurar serviços HTTP na rede:
```bash
dns-sd -B _http._tcp
```
Quando um serviço é iniciado, ele anuncia sua disponibilidade para todos os dispositivos na sub-rede, transmitindo sua presença por multicast. Dispositivos interessados nesses serviços não precisam enviar solicitações, mas simplesmente ouvir esses anúncios.

Para uma interface mais amigável, o aplicativo **Discovery - DNS-SD Browser** disponível na Apple App Store pode visualizar os serviços oferecidos na sua rede local.

Alternativamente, scripts personalizados podem ser escritos para navegar e descobrir serviços usando a biblioteca `python-zeroconf`. O script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demonstra a criação de um navegador de serviços para serviços `_http._tcp.local.`, imprimindo serviços adicionados ou removidos:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Desativando o Bonjour

Se houver preocupações com a segurança ou outras razões para desativar o Bonjour, ele pode ser desligado usando o seguinte comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referências

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{{#include ../../banners/hacktricks-training.md}}
