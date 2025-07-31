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
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) é uma versão aprimorada do [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptada para macOS, oferecendo recursos adicionais. Uma vulnerabilidade notável no ARD é seu método de autenticação para a senha da tela de controle, que usa apenas os primeiros 8 caracteres da senha, tornando-o suscetível a [ataques de força bruta](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) com ferramentas como Hydra ou [GoRedShell](https://github.com/ahhh/GoRedShell/), já que não há limites de taxa padrão.

Instâncias vulneráveis podem ser identificadas usando o script `vnc-info` do **nmap**. Serviços que suportam `VNC Authentication (2)` são especialmente suscetíveis a ataques de força bruta devido à truncagem da senha de 8 caracteres.

Para habilitar o ARD para várias tarefas administrativas, como escalonamento de privilégios, acesso GUI ou monitoramento de usuários, use o seguinte comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD fornece níveis de controle versáteis, incluindo observação, controle compartilhado e controle total, com sessões persistindo mesmo após mudanças de senha do usuário. Permite o envio de comandos Unix diretamente, executando-os como root para usuários administrativos. O agendamento de tarefas e a pesquisa remota do Spotlight são recursos notáveis, facilitando buscas remotas de baixo impacto por arquivos sensíveis em várias máquinas.

#### Vulnerabilidades recentes de Compartilhamento de Tela / ARD (2023-2025)

| Ano | CVE | Componente | Impacto | Corrigido em |
|-----|-----|------------|---------|--------------|
|2023|CVE-2023-42940|Compartilhamento de Tela|Renderização de sessão incorreta poderia causar a transmissão da *tela* ou janela *errada*, resultando em vazamento de informações sensíveis|macOS Sonoma 14.2.1 (Dez 2023) |
|2024|CVE-2024-23296|launchservicesd / login|Bypass de proteção de memória do kernel que pode ser encadeado após um login remoto bem-sucedido (explorado ativamente na prática)|macOS Ventura 13.6.4 / Sonoma 14.4 (Mar 2024) |

**Dicas de Hardening**

* Desative *Compartilhamento de Tela*/*Gerenciamento Remoto* quando não for estritamente necessário.
* Mantenha o macOS totalmente atualizado (a Apple geralmente envia correções de segurança para as três últimas versões principais).
* Use uma **Senha Forte** *e* aplique a opção *“Os visualizadores VNC podem controlar a tela com senha”* **desativada** sempre que possível.
* Coloque o serviço atrás de uma VPN em vez de expor TCP 5900/3283 à Internet.
* Adicione uma regra de Firewall de Aplicação para limitar `ARDAgent` à sub-rede local:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Protocolo Bonjour

Bonjour, uma tecnologia projetada pela Apple, permite que **dispositivos na mesma rede detectem os serviços oferecidos uns pelos outros**. Conhecido também como Rendezvous, **Zero Configuration**, ou Zeroconf, permite que um dispositivo se junte a uma rede TCP/IP, **escolha automaticamente um endereço IP** e transmita seus serviços para outros dispositivos da rede.

A Rede de Zero Configuração, fornecida pelo Bonjour, garante que os dispositivos possam:

- **Obter automaticamente um Endereço IP** mesmo na ausência de um servidor DHCP.
- Realizar **tradução de nome para endereço** sem exigir um servidor DNS.
- **Descobrir serviços** disponíveis na rede.

Dispositivos que utilizam Bonjour atribuirão a si mesmos um **endereço IP da faixa 169.254/16** e verificarão sua exclusividade na rede. Macs mantêm uma entrada de tabela de roteamento para essa sub-rede, verificável via `netstat -rn | grep 169`.

Para DNS, o Bonjour utiliza o **protocolo Multicast DNS (mDNS)**. O mDNS opera sobre **a porta 5353/UDP**, empregando **consultas DNS padrão** mas direcionando para o **endereço multicast 224.0.0.251**. Essa abordagem garante que todos os dispositivos ouvintes na rede possam receber e responder às consultas, facilitando a atualização de seus registros.

Ao ingressar na rede, cada dispositivo auto-seleciona um nome, geralmente terminando em **.local**, que pode ser derivado do nome do host ou gerado aleatoriamente.

A descoberta de serviços dentro da rede é facilitada pelo **DNS Service Discovery (DNS-SD)**. Aproveitando o formato dos registros DNS SRV, o DNS-SD utiliza **registros DNS PTR** para permitir a listagem de múltiplos serviços. Um cliente que busca um serviço específico solicitará um registro PTR para `<Service>.<Domain>`, recebendo em troca uma lista de registros PTR formatados como `<Instance>.<Service>.<Domain>` se o serviço estiver disponível de múltiplos hosts.

A utilidade `dns-sd` pode ser empregada para **descobrir e anunciar serviços de rede**. Aqui estão alguns exemplos de seu uso:

### Buscando por Serviços SSH

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
Quando um serviço é iniciado, ele anuncia sua disponibilidade para todos os dispositivos na sub-rede, fazendo multicast de sua presença. Dispositivos interessados nesses serviços não precisam enviar solicitações, mas simplesmente ouvir esses anúncios.

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
### Enumerando Bonjour na rede

* **Nmap NSE** – descobrir serviços anunciados por um único host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

O script `dns-service-discovery` envia uma consulta `_services._dns-sd._udp.local` e, em seguida, enumera cada tipo de serviço anunciado.

* **mdns_recon** – ferramenta Python que escaneia intervalos inteiros em busca de *respondedores* mDNS *mal configurados* que respondem a consultas unicast (útil para encontrar dispositivos acessíveis através de sub-redes/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Isso retornará hosts expondo SSH via Bonjour fora do link local.

### Considerações de segurança & vulnerabilidades recentes (2024-2025)

| Ano | CVE | Severidade | Problema | Corrigido em |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Média|Um erro de lógica em *mDNSResponder* permitiu que um pacote manipulado acionasse uma **negação de serviço**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Set 2024) |
|2025|CVE-2025-31222|Alta|Um problema de correção em *mDNSResponder* poderia ser explorado para **elevação de privilégio local**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (Mai 2025) |

**Orientações de mitigação**

1. Restringir UDP 5353 ao escopo *link-local* – bloquear ou limitar a taxa em controladores sem fio, roteadores e firewalls baseados em host.
2. Desativar Bonjour completamente em sistemas que não requerem descoberta de serviços:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Para ambientes onde Bonjour é necessário internamente, mas nunca deve cruzar fronteiras de rede, use restrições de perfil de *AirPlay Receiver* (MDM) ou um proxy mDNS.
4. Ativar **Proteção de Integridade do Sistema (SIP)** e manter o macOS atualizado – ambas as vulnerabilidades acima foram corrigidas rapidamente, mas dependiam do SIP estar ativado para proteção total.

### Desativando Bonjour

Se houver preocupações sobre segurança ou outras razões para desativar Bonjour, ele pode ser desligado usando o seguinte comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referências

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)

{{#include ../../banners/hacktricks-training.md}}
