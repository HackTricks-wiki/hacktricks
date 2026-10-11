# Captura de tráfego, firewall e triagem de egress

{{#include ../../banners/hacktricks-training.md}}

Após localizar [listeners locais e sockets Unix](local-network-and-socket-triage.md), inspecione quais interfaces transportam o tráfego e quais regras de firewall ou proxy afetam a acessibilidade. Um serviço acessível apenas por loopback pode transportar cabeçalhos HTTP confidenciais, mesmo que não seja acessível a partir de outro host.

## Verifique as permissões de captura e escolha uma interface

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` pode ter recursos de captura de pacotes mesmo quando o usuário atual não tem acesso ao sudo. Verifique os recursos reais do executável e as permissões do grupo. Capture pela interface, duração e filtro mais restritos que ainda sejam úteis; uma captura pode conter credenciais ou dados pessoais.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` reconstrói fluxos TCP em texto simples; `tshark` pode filtrar e extrair campos de uma captura. Para tráfego TLS, a descriptografia exige chaves do endpoint ou um cliente compatível configurado para `SSLKEYLOGFILE` antes da conexão. A [página de triagem de rede local](local-network-and-socket-triage.md#tls-key-logging) mostra esse fluxo de trabalho. Não considere uma captura criptografada como texto simples legível.

Artefatos de incidentes armazenados podem mudar essa avaliação. Um [core dump do Linux é uma imagem da memória do processo](https://man7.org/linux/man-pages/man5/core.5.html), que pode reter uma chave de sessão; se um dump legível e uma captura de pacotes vieram do mesmo processo e sessão, um analista talvez consiga descriptografar esse tráfego. Primeiro, faça o inventário dos caminhos e permissões dos artefatos; depois, verifique separadamente a identidade do processo, o horário da captura, o protocolo e o formato da chave. Tráfego descriptografado ou um arquivo compactado recuperado é uma pista de divulgação, não uma prova de acesso à conta de outra pessoa: qualquer material parcial de chave SSH ainda precisa ser reconstruído, associado à chave pública correspondente e aceito pela política SSH dessa conta. Evite despejar o conteúdo de core dumps ou payloads de capturas em saídas amplas de enumeração.

## Identificar camadas de firewall

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` e `iptables` podem ser expostos por wrappers da distribuição, como UFW ou firewalld. Leia as regras ativas e a configuração persistida do wrapper; uma regra visível em uma representação pode ter sido gerada por outra ferramenta. Inspecione a interface, a direção, a origem, o destino, o protocolo, a porta e o estado da conexão antes de atribuir o bloqueio de um serviço a uma regra específica. Consulte [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) para ver um exemplo específico.

## Testar a saída de tráfego e o comportamento do proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Separe falhas de DNS de falhas de TCP, TLS ou proxy. Teste o destino e o protocolo específicos relevantes para a avaliação; a acessibilidade via ICMP não significa que TCP ou UDP sejam permitidos. Se houver um proxy configurado, compare a solicitação que deveria passar pelo proxy com uma solicitação ao mesmo destino sob as regras aplicáveis de `no_proxy`. Um encaminhamento de porta local também pode disponibilizar um serviço de loopback em outro lugar; portanto, verifique os listeners ativos e os túneis SSH quando a configuração do firewall e a exposição observada não corresponderem.
{{#include ../../banners/hacktricks-training.md}}
