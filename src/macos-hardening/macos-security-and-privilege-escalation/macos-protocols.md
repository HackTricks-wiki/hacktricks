# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Serviços de Acesso Remoto

Estes são os serviços comuns do macOS para acessá-los remotamente.\
Você pode habilitar/desabilitar estes serviços em `System Settings` --> `Sharing`

- **VNC**, conhecido como “Screen Sharing” (tcp:5900)
- **SSH**, chamado “Remote Login” (tcp:22)
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
### Enumerando a configuração de compartilhamento localmente

Quando você já tem execução de código local em um Mac, **verifique o estado configurado**, não apenas os sockets em escuta. `systemsetup` e `launchctl` normalmente informam se o serviço está habilitado administrativamente, enquanto `kickstart` e `system_profiler` ajudam a confirmar a configuração efetiva de ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) é uma versão aprimorada do [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptada para macOS, oferecendo recursos adicionais. Uma vulnerabilidade notável no ARD está no seu método de autenticação para a senha de controle de tela, que usa apenas os primeiros 8 caracteres da senha, tornando-o suscetível a [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) com ferramentas como Hydra ou [GoRedShell](https://github.com/ahhh/GoRedShell/), já que não há limites padrão de taxa.

Instâncias vulneráveis podem ser identificadas usando o script `vnc-info` do **nmap**. Serviços que oferecem suporte a `VNC Authentication (2)` são especialmente suscetíveis a brute force attacks devido à truncagem da senha em 8 caracteres.

Para habilitar o ARD para várias tarefas administrativas, como privilege escalation, acesso GUI ou monitoramento de usuários, use o seguinte comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD fornece níveis versáteis de controle, incluindo observation, shared control e full control, com sessões persistindo mesmo após mudanças de senha do usuário. Ele permite enviar Unix commands diretamente, executando-os como root para usuários administrativos. Task scheduling e Remote Spotlight search são recursos notáveis, facilitando buscas remotas e de baixo impacto por arquivos sensíveis em várias máquinas.

Do ponto de vista do operator, **Monterey 12.1+ changed remote-enablement workflows** em managed fleets. Se você já controla o MDM da vítima, o comando `EnableRemoteDesktop` da Apple costuma ser a forma mais limpa de ativar a funcionalidade de remote desktop em sistemas mais novos. Se você já tem um foothold no host, `kickstart` ainda é útil para inspecionar ou reconfigurar privilégios do ARD pela command line.

### Pentesting Remote Apple Events (RAE / EPPC)

A Apple chama esse recurso de **Remote Application Scripting** no System Settings moderno. Nos bastidores, ele expõe o **Apple Event Manager** remotamente via **EPPC** em **TCP/3031** pelo serviço `com.apple.AEServer`. A Palo Alto Unit 42 destacou isso novamente como um primitive prático de **macOS lateral movement**, porque credenciais válidas mais um serviço RAE habilitado permitem que um operator controle aplicações scriptable em um Mac remoto.

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Se você já tem admin/root no alvo e quer habilitá-lo:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Teste básico de conectividade a partir de outro Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
Na prática, o caso de abuso não se limita ao Finder. Qualquer **aplicação scriptable** que aceite os Apple events necessários torna-se uma superfície de ataque remota, o que torna o RAE especialmente interessante após roubo de credenciais em redes internas macOS.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|A renderização incorreta da sessão poderia fazer com que a *wrong* área de trabalho ou janela fosse transmitida, resultando em vazamento de informações sensíveis|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Um usuário com acesso ao screen sharing pode conseguir ver a **tela de outro usuário** devido a um problema de gerenciamento de estado|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* Desative *Screen Sharing*/*Remote Management* quando não for estritamente necessário.
* Mantenha o macOS totalmente atualizado (a Apple geralmente entrega correções de segurança para os últimos três releases principais).
* Use uma **Strong Password** *e* aplique a opção *“VNC viewers may control screen with password”* **desativada** quando possível.
* Coloque o serviço atrás de uma VPN em vez de expor TCP 5900/3283 para a Internet.
* Adicione uma regra de Application Firewall para limitar `ARDAgent` à sub-rede local:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, uma tecnologia projetada pela Apple, permite que **devices na mesma rede detectem os services oferecidos uns pelos outros**. Também conhecido como Rendezvous, **Zero Configuration**, ou Zeroconf, ele permite que um device entre em uma rede TCP/IP, **escolha automaticamente um endereço IP**, e anuncie seus services para outros network devices.

Zero Configuration Networking, fornecido pelo Bonjour, garante que os devices possam:

- **Obter automaticamente um endereço IP** mesmo na ausência de um DHCP server.
- Realizar **name-to-address translation** sem exigir um DNS server.
- **Descobrir services** disponíveis na rede.

Devices que usam Bonjour atribuem a si mesmos um **endereço IP do range 169.254/16** e verificam sua unicidade na rede. Os Macs mantêm uma entrada de routing table para essa subnet, verificável via `netstat -rn | grep 169`.

Para DNS, o Bonjour utiliza o **Multicast DNS (mDNS) protocol**. O mDNS opera na **porta 5353/UDP**, empregando **standard DNS queries** mas direcionando para o **multicast address 224.0.0.251**. Essa abordagem garante que todos os listening devices na rede possam receber e responder às queries, facilitando a atualização de seus records.

Ao entrar na rede, cada device escolhe seu próprio nome, normalmente terminando em **.local**, que pode ser derivado do hostname ou gerado aleatoriamente.

A service discovery na rede é facilitada pelo **DNS Service Discovery (DNS-SD)**. Aproveitando o formato dos DNS SRV records, o DNS-SD usa **DNS PTR records** para permitir a listagem de multiple services. Um client que busca um service específico solicitará um PTR record para `<Service>.<Domain>`, recebendo em troca uma lista de PTR records formatados como `<Instance>.<Service>.<Domain>` se o service estiver disponível em multiple hosts.

A utility `dns-sd` pode ser usada para **descobrir e anunciar network services**. Aqui estão alguns exemplos de uso:

### Searching for SSH Services

Para buscar serviços SSH na rede, o seguinte comando é usado:
```bash
dns-sd -B _ssh._tcp
```
Este comando inicia a navegação por serviços \_ssh.\_tcp e exibe detalhes como timestamp, flags, interface, domain, service type e instance name.

### Anunciando um serviço HTTP

Para anunciar um serviço HTTP, você pode usar:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Este comando registra um serviço HTTP chamado "Index" na porta 80 com um caminho de `/index.html`.

Para então pesquisar por serviços HTTP na rede:
```bash
dns-sd -B _http._tcp
```
Quando um serviço inicia, ele anuncia sua disponibilidade para todos os dispositivos na subnet por meio de multicasting de sua presença. Dispositivos interessados nesses serviços não precisam enviar requests, apenas escutar esses anúncios.

Para uma interface mais amigável, o app **Discovery - DNS-SD Browser** disponível na Apple App Store pode visualizar os serviços oferecidos na sua rede local.

Como alternativa, scripts personalizados podem ser escritos para navegar e descobrir serviços usando a biblioteca `python-zeroconf`. O script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demonstra a criação de um service browser para serviços `_http._tcp.local.`, exibindo serviços adicionados ou removidos:
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
### Caça ao Bonjour específico do macOS

Em redes macOS, Bonjour frequentemente é a maneira mais fácil de encontrar **superfícies de administração remota** sem tocar diretamente no alvo. O próprio Apple Remote Desktop consegue descobrir clientes por meio do Bonjour, então os mesmos dados de descoberta são úteis para um atacante.
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
Para técnicas mais amplas de **mDNS spoofing, impersonation e cross-subnet discovery**, veja a página dedicada:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerando Bonjour pela rede

* **Nmap NSE** – descobre serviços anunciados por um único host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

O script `dns-service-discovery` envia uma consulta `_services._dns-sd._udp.local` e depois enumera cada tipo de serviço anunciado.

* **mdns_recon** – ferramenta em Python que varre intervalos inteiros procurando *misconfigured* mDNS responders que respondem a consultas unicast (útil para encontrar dispositivos acessíveis através de sub-redes/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Isso retornará hosts expondo SSH via Bonjour fora do link local.

### Considerações de segurança e vulnerabilidades recentes (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|A logic error in *mDNSResponder* allowed a crafted packet to trigger a **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|A correctness issue in *mDNSResponder* could be abused for **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Orientação de mitigação**

1. Restrinja UDP 5353 ao escopo *link-local* – bloqueie ou limite a taxa em controladores wireless, roteadores e firewalls baseados no host.
2. Desative o Bonjour completamente em sistemas que não precisam de service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Em ambientes onde o Bonjour é necessário internamente, mas nunca deve cruzar limites de rede, use restrições de perfil do *AirPlay Receiver* (MDM) ou um proxy mDNS.
4. Ative **System Integrity Protection (SIP)** e mantenha o macOS atualizado – ambas as vulnerabilidades acima foram corrigidas rapidamente, mas dependiam de SIP habilitado para proteção total.

### Desativando Bonjour

Se houver preocupações com segurança ou outros motivos para desativar o Bonjour, ele pode ser desligado usando o seguinte comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
