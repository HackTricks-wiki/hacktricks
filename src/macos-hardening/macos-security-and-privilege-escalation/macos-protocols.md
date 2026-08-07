# Serviços de Rede e Protocolos do macOS

{{#include ../../banners/hacktricks-training.md}}

## Serviços de Acesso Remoto

Estes são os serviços comuns do macOS para acessá-lo remotamente.\
Você pode habilitar/desabilitar esses serviços em `System Settings` --> `Sharing`<sup>[[1]](#references)</sup>

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
### Enumerando a configuração de compartilhamento localmente

Quando você já tem execução de código local em um Mac, **verifique o estado configurado**, não apenas os sockets em escuta. `systemsetup` e `launchctl` geralmente informam se o serviço está habilitado administrativamente, enquanto `kickstart` e `system_profiler` ajudam a confirmar a configuração efetiva do ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

O Apple Remote Desktop (ARD) é uma versão aprimorada do [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptada para macOS, oferecendo recursos adicionais. Uma vulnerabilidade notável no ARD está em seu método de autenticação da senha da tela de controle, que usa apenas os primeiros 8 caracteres da senha, tornando-o suscetível a [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) com ferramentas como Hydra ou [GoRedShell](https://github.com/ahhh/GoRedShell/), pois não há limites de tentativas padrão.<sup>[[2]](#references)</sup>

Instâncias vulneráveis podem ser identificadas usando o script `vnc-info` do **nmap**. Serviços compatíveis com `VNC Authentication (2)` são especialmente suscetíveis a brute force attacks devido ao truncamento da senha para 8 caracteres.

Para habilitar o ARD para várias tarefas administrativas, como privilege escalation, acesso à GUI ou monitoramento de usuários, use o seguinte comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD fornece níveis de controle versáteis, incluindo observação, controle compartilhado e controle total, com sessões que persistem mesmo após alterações na senha do usuário. Ele permite enviar comandos Unix diretamente, executando-os como root para usuários administrativos. O agendamento de tarefas e a busca Remote Spotlight são recursos notáveis, facilitando buscas remotas e de baixo impacto por arquivos sensíveis em várias máquinas.

Do ponto de vista do operador, o **Monterey 12.1+ alterou os fluxos de remote-enablement** em frotas gerenciadas. Se você já controla o MDM da vítima, o comando `EnableRemoteDesktop` da Apple costuma ser a forma mais limpa de ativar a funcionalidade de remote desktop em sistemas mais recentes. Se você já possui um foothold no host, o `kickstart` continua sendo útil para inspecionar ou reconfigurar os privilégios do ARD pela linha de comando.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Pesquisas recentes sobre o `screensharingd` mostraram que o Apple Screen Sharing nem sempre usa apenas a autenticação VNC clássica: builds mais recentes usam **RFB `003.889`** e anunciam o **security type `36`**, no qual **SRP** realiza a autenticação primeiro e **ChaCha20-Poly1305** só é instalado após `ccsrp_server_verify_session` obter sucesso. O write-up público informa que o bug foi corrigido no **macOS Tahoe 26.6** (**27 de julho de 2026**).<sup>[[8]](#references)[[9]](#references)</sup>

Um padrão útil para lembrar é o **stale-status parser bypass**: após uma leitura de comprimento de 4 bytes bem-sucedida, toda ramificação de erro/tamanho excessivo deve retornar um erro novo. Em builds afetados, um comprimento de frame SRP big-endian **`>= 32768`** faz com que o caminho de rejeição reutilize o sucesso anterior de `NetBufferRead` (`0`), fazendo o chamador definir a sessão como autenticada, embora nenhuma prova de senha tenha sido executada e nenhuma criptografia de transporte tenha sido instalada. Como os bytes não lidos permanecem no buffer compartilhado do socket, um atacante pode **encadear dados SRP malformados e mensagens RFB pós-auth no mesmo burst TCP** e fazer com que sejam analisados como **tráfego autenticado cleartext**.<sup>[[8]](#references)</sup>

Após o bypass, a mensagem proprietária de **file-copy** da Apple, **`0x22`**, torna-se uma **primitive de leitura/escrita de arquivos como root**, pois o `screensharingd` é executado como root:<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: leitura arbitrária de arquivos
- `kind=2` / `StartFileReceive`: escrita arbitrária de arquivos
- Valores diferentes de `sid` permitem colocar várias transações em pipeline em uma única conexão
- Em `kind=101` (`NewItem`), defina o byte `14` / `arg[0]` como `0x01` para um arquivo regular, o offset de payload `+42` como um tamanho de arquivo big-endian **diferente de zero** e o offset de payload `+0x5a` como o modo Unix desejado (`0600` ao direcionar um crontab)

Pivôs interessantes após a escrita em paths graváveis incluem **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** e **`/var/root/.ssh/authorized_keys`**. **O SIP não impede o auth bypass nem a leitura de arquivos como root**, mas bloqueia alguns alvos de escrita, como **`/var/at`**; portanto, a execução baseada em cron só funciona com o SIP desabilitado. Em hosts padrão com SIP habilitado, pense em termos de **"escrita de arquivos como root em arquivos privilegiados consumidos automaticamente"**, em vez de execução imediata de código.<sup>[[8]](#references)</sup>

Outra armadilha do SRP identificada na mesma pesquisa: os servidores devem validar **`A mod N != 0`** (conforme a RFC 5054), e não apenas `A > 0`. Aceitar **`A = N`** pode forçar o segredo compartilhado a zero e comprometer a verificação da senha.<sup>[[8]](#references)[[10]](#references)</sup>

**Ideias de detecção**

- Sessões do tipo de segurança `36` em que o tamanho do primeiro frame SRP seja **`>= 32768`**
- Sessões que começam a processar tráfego de cópia de arquivos em cleartext **`0x22`** antes de qualquer prova SRP bem-sucedida / instalação de cipher
- Repetições de tentativas de curta duração contra **TCP/5900**, além de vários valores de `sid` de cópia de arquivos em um único burst
- Criação inesperada de **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** ou **`/var/root/.ssh/authorized_keys`** após a exposição do Screen Sharing

### Pentesting Remote Apple Events (RAE / EPPC)

A Apple chama esse recurso de **Remote Application Scripting** nas versões modernas de System Settings. Internamente, ele expõe o **Apple Event Manager** remotamente por **EPPC** na **TCP/3031**, por meio do serviço `com.apple.AEServer`. A Palo Alto Unit 42 voltou a destacá-lo como um primitivo prático de **movimentação lateral em macOS**, pois credenciais válidas e um serviço RAE habilitado permitem que um operador controle aplicações programáveis em um Mac remoto.<sup>[[6]](#references)</sup>

Verificações úteis:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Se você já tiver admin/root no alvo e quiser habilitá-lo:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Teste básico de conectividade a partir de outro Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
Na prática, o caso de abuso não se limita ao Finder. Qualquer **scriptable application** que aceite os Apple events necessários torna-se uma superfície de ataque remota, o que torna o RAE especialmente interessante após o roubo de credenciais em redes internas de macOS.

#### Vulnerabilidades recentes de Screen Sharing / ARD (2023-2025)

| Ano | CVE | Componente | Impacto | Corrigido em |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|A renderização incorreta da sessão poderia fazer com que a *área de trabalho ou janela errada* fosse transmitida, resultando em **leak** de informações confidenciais|macOS Sonoma 14.2.1 (dez. de 2023) <sup>[[3]](#references)</sup>|
|2024|CVE-2024-44248|Screen Sharing Server|Um usuário com acesso ao compartilhamento de tela poderia visualizar **a tela de outro usuário** devido a um problema de gerenciamento de estado|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (out.-dez. de 2024) <sup>[[7]](#references)</sup>|

**Dicas de hardening**

* Desative *Screen Sharing*/*Remote Management* quando não forem estritamente necessários.
* Mantenha o macOS totalmente atualizado (a Apple geralmente disponibiliza correções de segurança para as três versões principais mais recentes).
* Use uma **Strong Password** e, quando possível, mantenha desativada a opção *“VNC viewers may control screen with password”*.
* Coloque o serviço atrás de uma VPN em vez de expor as portas TCP 5900/3283 à Internet.
* Adicione uma regra ao Application Firewall para limitar o `ARDAgent` à sub-rede local:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Protocolo Bonjour

Bonjour, uma tecnologia desenvolvida pela Apple, permite que **dispositivos na mesma rede detectem os serviços oferecidos uns pelos outros**. Também conhecido como Rendezvous, **Zero Configuration** ou Zeroconf, ele permite que um dispositivo entre em uma rede TCP/IP, **escolha automaticamente um endereço IP** e divulgue seus serviços para outros dispositivos da rede.

O Zero Configuration Networking, fornecido pelo Bonjour, garante que os dispositivos possam:

- **Obter automaticamente um endereço IP** mesmo na ausência de um servidor DHCP.
- Realizar a **tradução de nome para endereço** sem exigir um servidor DNS.
- **Descobrir serviços** disponíveis na rede.

Os dispositivos que usam Bonjour atribuem a si mesmos um **endereço IP do intervalo 169.254/16** e verificam sua exclusividade na rede. Os Macs mantêm uma entrada na tabela de roteamento para essa sub-rede, que pode ser verificada por meio de `netstat -rn | grep 169`.

Para DNS, o Bonjour utiliza o **protocolo Multicast DNS (mDNS)**. O mDNS opera na **porta 5353/UDP**, empregando **consultas DNS padrão**, mas direcionadas ao **endereço multicast 224.0.0.251**. Essa abordagem garante que todos os dispositivos que estejam escutando na rede possam receber e responder às consultas, facilitando a atualização de seus registros.

Ao entrar na rede, cada dispositivo seleciona automaticamente um nome, normalmente terminando em **.local**, que pode ser derivado do hostname ou gerado aleatoriamente.

A descoberta de serviços na rede é facilitada pelo **DNS Service Discovery (DNS-SD)**. Aproveitando o formato dos registros DNS SRV, o DNS-SD usa **registros DNS PTR** para permitir a listagem de vários serviços. Um cliente que procura um serviço específico solicitará um registro PTR para `<Service>.<Domain>`, recebendo em resposta uma lista de registros PTR formatados como `<Instance>.<Service>.<Domain>` caso o serviço esteja disponível em vários hosts.

O utilitário `dns-sd` pode ser usado para **descobrir e anunciar serviços de rede**. Veja alguns exemplos de uso:

### Procurando serviços SSH

Para procurar serviços SSH na rede, use o seguinte comando:
```bash
dns-sd -B _ssh._tcp
```
Este comando inicia a busca por serviços \_ssh.\_tcp e exibe detalhes como timestamp, flags, interface, domínio, tipo de serviço e nome da instância.

### Anunciando um Serviço HTTP

Para anunciar um serviço HTTP, você pode usar:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Este comando registra um serviço HTTP chamado "Index" na porta 80 com o caminho `/index.html`.

Para então procurar serviços HTTP na rede:
```bash
dns-sd -B _http._tcp
```
Quando um serviço é iniciado, ele anuncia sua disponibilidade a todos os dispositivos na sub-rede realizando multicast da sua presença. Os dispositivos interessados nesses serviços não precisam enviar solicitações, mas apenas ouvir esses anúncios.

Para uma interface mais fácil de usar, o aplicativo **Discovery - DNS-SD Browser**, disponível na Apple App Store, pode visualizar os serviços oferecidos na sua rede local.

Como alternativa, é possível escrever scripts personalizados para navegar e descobrir serviços usando a biblioteca `python-zeroconf`. O script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demonstra a criação de um navegador de serviços para serviços `_http._tcp.local.`, exibindo os serviços adicionados ou removidos:
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
### Hunting de Bonjour específico do macOS

Em redes macOS, o Bonjour costuma ser a maneira mais fácil de encontrar **superfícies de administração remota** sem interagir diretamente com o alvo. O próprio Apple Remote Desktop pode descobrir clientes por meio do Bonjour, portanto os mesmos dados de descoberta são úteis para um atacante.
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
Para obter técnicas mais amplas de **mDNS spoofing, impersonation e cross-subnet discovery**, consulte a página dedicada:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerando Bonjour pela rede

* **Nmap NSE** – descobre serviços anunciados por um único host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

O script `dns-service-discovery` envia uma consulta `_services._dns-sd._udp.local` e, em seguida, enumera cada tipo de serviço anunciado.

* **mdns_recon** – ferramenta Python que verifica intervalos inteiros em busca de responders mDNS *misconfigured* que respondem a consultas unicast (útil para encontrar dispositivos acessíveis entre sub-redes/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Isso retornará hosts que expõem SSH via Bonjour fora do link local.

### Considerações de segurança e vulnerabilidades recentes (2024-2025)

| Ano | CVE | Severidade | Problema | Corrigido em |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Média|Um erro lógico no *mDNSResponder* permitia que um pacote criado para esse fim provocasse uma **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (set. 2024) <sup>[[4]](#references)</sup>|
|2025|CVE-2025-31222|Alta|Um problema de correção no *mDNSResponder* podia ser explorado para **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (maio de 2025) <sup>[[5]](#references)</sup>|

**Orientações de mitigação**

1. Restrinja UDP 5353 ao escopo *link-local* – bloqueie ou aplique rate limiting nele em controladores wireless, roteadores e firewalls baseados em host.
2. Desative o Bonjour completamente nos sistemas que não precisam de service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Em ambientes onde o Bonjour é necessário internamente, mas nunca deve atravessar os limites da rede, use restrições de perfil do *AirPlay Receiver* (MDM) ou um proxy mDNS.
4. Ative o **System Integrity Protection (SIP)** e mantenha o macOS atualizado – ambas as vulnerabilidades acima foram corrigidas rapidamente, mas dependiam do SIP estar ativado para oferecer proteção completa.

### Desativando o Bonjour

Se houver preocupações de segurança ou outros motivos para desativar o Bonjour, ele pode ser desligado usando o seguinte comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referências

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [3] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [4] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [5] [NVD – CVE-2025-31222](https://nvd.nist.gov/vuln/detail/CVE-2025-31222)
- [6] [Palo Alto Unit 42 - Movimentação lateral no macOS: técnicas únicas e populares e exemplos reais](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Sobre o conteúdo de segurança do macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Sobre o conteúdo de segurança do macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Usando o protocolo Secure Remote Password (SRP) para autenticação TLS](https://www.rfc-editor.org/rfc/rfc5054)
- [11] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)

{{#include ../../banners/hacktricks-training.md}}
