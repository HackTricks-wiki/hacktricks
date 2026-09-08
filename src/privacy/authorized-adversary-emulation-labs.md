# Laboratórios de Emulação de Adversários Autorizados

Estes exercícios reproduzem uma **arquitetura observável**, não um comprometimento não autorizado. Execute-os em um host Linux de laboratório dedicado, com Docker, sem credenciais confidenciais e sem rota para targets de terceiros. Os nomes são fixos para que a desmontagem seja explícita.

{% hint style="danger" %}
Não substitua os containers, APs, routers, contas ou transações sintéticas pertencentes a você abaixo por proxies públicos, pelo Wi-Fi de um vizinho, por um tenant de CDN de produção que você não controla ou por fundos ilícitos reais. A autorização por escrito deve abranger todos os sistemas e ambientes de rádio.
{% endhint %}

## Lab 1: cadeia de ORB e redirector pertencente a você

**Objetivo:** demonstrar que um target registra apenas o exit, enquanto cada relay vê os hops adjacentes. Isso emula a estrutura T1090.003/T1584 sem dispositivos comprometidos.

**Requisitos:** Docker Engine e nomes de containers não utilizados que comecem com `ht-orb-`.

### Compilação
```bash
docker network create ht-orb-entry
docker network create ht-orb-transit
docker network create ht-orb-target

docker run -d --name ht-orb-target --network ht-orb-target nginx:alpine

docker run -d --name ht-orb-r2 --network ht-orb-transit \
alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-target:80
docker network connect ht-orb-target ht-orb-r2

docker run -d --name ht-orb-r1 --network ht-orb-entry \
alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-r2:8080
docker network connect ht-orb-transit ht-orb-r1

docker run --rm --network ht-orb-entry curlimages/curl:latest \
-sS http://ht-orb-r1:8080/ >/dev/null
```
### Verifique os limites de visibilidade
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Resultado esperado: o Nginx registra o endereço `ht-orb-r2` em `ht-orb-target`, não o cliente one-shot. Os logs dos relays mostram conexões apenas da rede adjacente. A inspeção do control plane do Docker ainda reconstrói o caminho completo — análoga às evidências do provider/controller.

### Experimentos de detecção

1. Repita as solicitações a cada 60 segundos e faça um gráfico do tempo entre chegadas e dos bytes.
2. Substitua `ht-orb-r2` por um novo container/endereço nomeado, mas mantenha a mesma cadência e a mesma solicitação da aplicação; confirme que uma regra baseada apenas em IP perde a cadeia, enquanto o comportamento ainda a associa.
3. Capture dados nas três bridges do Docker com `tcpdump` no lab host e compare os timestamps.
4. Pare `ht-orb-r2`; verifique se não há fallback direto da entrada para o alvo.

### Desmontagem
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: incompatibilidade de SNI/Host e logging do redirector

**Objetivo:** reproduzir a primitiva de roteamento por trás de domain fronting em uma edge local privada e mostrar onde ela é visível. Nenhuma CDN pública está envolvida.

### Criar uma edge TLS local
```bash
ht_front_dir="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
-subj '/CN=front.lab' \
-keyout "$ht_front_dir/key.pem" -out "$ht_front_dir/cert.pem"

cat >"$ht_front_dir/default.conf" <<'EOF'
log_format routing '$remote_addr sni=$ssl_server_name host=$host request="$request"';
server {
listen 443 ssl;
server_name front.lab;
ssl_certificate /etc/nginx/tls/cert.pem;
ssl_certificate_key /etc/nginx/tls/key.pem;
access_log /var/log/nginx/access.log routing;
location / {
if ($host != origin.lab) { return 404; }
proxy_pass http://ht-front-target:80;
}
}
EOF

docker network create ht-front-net
docker run -d --name ht-front-target --network ht-front-net nginx:alpine
docker run -d --name ht-front-edge --network ht-front-net -p 127.0.0.1:8443:443 \
-v "$ht_front_dir/default.conf:/etc/nginx/conf.d/default.conf:ro" \
-v "$ht_front_dir:/etc/nginx/tls:ro" nginx:alpine
```
### Enviar e observar a discrepância
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Os campos de log esperados incluem `sni=front.lab host=origin.lab`. A captura de pacotes entre o cliente e o edge expõe o SNI, exceto quando o ECH está em uso; o HTTP Host é criptografado nesse enlace. O edge terminador vê ambos.

Agora envie uma solicitação normal e confirme que a policy a rejeita:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Afirmação de detecção

Alerta sobre `sni != host` somente após normalizar portas/maiúsculas e verificar exceções conhecidas de reverse-proxy. Adicione o contexto do processo e do tenant/origem antes de atribuir a severidade.

### Desmontagem
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**Objetivo:** gerar um dataset DNS seguro, semelhante a low-TTL/multi-ASN, e validar uma análise. Os endereços de documentação RFC 5737 retornados não são roteáveis para esta finalidade.

### Execute um servidor autoritativo
```bash
ht_dns_dir="$(mktemp -d)"
cat >"$ht_dns_dir/Corefile" <<'EOF'
.:53 {
log
errors
file /zones/db.lab lab
}
EOF

mkdir -p "$ht_dns_dir/zones"
cat >"$ht_dns_dir/zones/db.lab" <<'EOF'
$ORIGIN lab.
@ 60 IN SOA ns.lab. hostmaster.lab. 1 60 60 60 5
@ 60 IN NS ns.lab.
ns 60 IN A 192.0.2.53
flux 5 IN A 192.0.2.10
flux 5 IN A 198.51.100.20
flux 5 IN A 203.0.113.30
EOF

docker run -d --name ht-flux-dns -p 127.0.0.1:1053:53/udp \
-v "$ht_dns_dir/Corefile:/Corefile:ro" \
-v "$ht_dns_dir/zones:/zones:ro" coredns/coredns:latest -conf /Corefile

for query_number in 1 2 3 4 5; do
dig @127.0.0.1 -p 1053 flux.lab A +noall +answer
done
docker logs ht-flux-dns
```
Resultado esperado: cada resposta contém três IPs de documentação e um TTL de 5 segundos. O fast flux real também alterna subconjuntos ao longo do tempo; altere o serial/endereço da zona e reinicie este servidor descartável para criar várias épocas.

### Validação analítica

Para uma janela de cinco minutos, calcule `median(TTL)`, respostas distintas, rótulos distintos de ASN/geografia sintéticos e a rotatividade das respostas. Exija pelo menos duas dimensões suspeitas, além de um evento de processo/subsequente. Execute a mesma análise em uma amostra conhecida de CDN para medir os falsos positivos.

### Desmontagem
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Laboratório 4: nearest-neighbor wireless pivot

**Objetivo:** reproduzir o boundary mismatch do APT28 com duas “organizações” sob seu controle. Como os comandos de hardware/driver Wi-Fi variam, este laboratório especifica funções e evidências verificáveis em vez de fingir que um único comando `hostapd` funciona com qualquer rádio.

### Equipamento

- dois APs sob seu controle, em canais/SSIDs isolados de laboratório `HT-NEIGHBOR` e `HT-TARGET`;
- um serviço de destino acessível somente a partir de `HT-TARGET`;
- um pivot Linux com dois rádios sob seu controle, capaz de se associar a ambos os APs;
- uma workstation de controle remoto atrás de `HT-NEIGHBOR`;
- logs de RADIUS/NAC ou de associação do AP, logs de DHCP e logs de auditoria/processos do pivot.

### Procedimento

1. Isole fisicamente ou atenue a configuração para que nenhum SSID escape da área autorizada. Confirme com uma varredura.
2. Configure `HT-TARGET` com uma identidade de exercício e omita deliberadamente a validação de certificado do dispositivo/postura na primeira execução. Registre isso como a condição em teste.
3. Conecte a primeira interface do pivot a `HT-NEIGHBOR` e a segunda interface a `HT-TARGET`. **Não** habilite uma bridge geral; permita somente o serviço/porta de destino por meio de um firewall no host.
4. A partir da workstation, abra um túnel autenticado até o pivot e solicite o serviço de destino por meio dele.
5. Registre o processo/criação de interface no pivot, as associações com ambos os APs, o evento RADIUS do destino, o lease DHCP e o endereço de origem do destino.
6. Peça à equipe de detecção para reconstruir a cadeia sem o mapa do controller.
7. Habilite EAP-TLS/postura de dispositivo gerenciado em `HT-TARGET`, remova o certificado de destino aprovado do pivot e repita. O acesso deve falhar na admissão.
8. Repita usando um MAC randomizado visto pela primeira vez. Verifique se a decisão baseada em certificado/dispositivo continua funcionando e se nenhuma regra trata o MAC sozinho como identidade.

### Critérios de sucesso

- O destino inicialmente vê um cliente Wi-Fi local, e não a workstation.
- A telemetria de associação identifica um pivot com caminhos simultâneos para o controle do vizinho e para o rádio de destino.
- A admissão baseada em certificado/dispositivo bloqueia a segunda execução.
- Nenhum pacote alcança uma rede fora do laboratório isolado.

## Laboratório 5: dead-drop resolver sequence

**Objetivo:** detectar um processo que lê um objeto com aparência legítima, decodifica um ponteiro e imediatamente entra em contato com um segundo serviço.

### Construção
```bash
docker network create ht-ddr-net
docker run -d --name ht-ddr-c2 --network ht-ddr-net nginx:alpine

docker run -d --name ht-ddr-web --network ht-ddr-net python:3-alpine \
sh -c 'mkdir -p /srv && printf aHR0cDovL2h0LWRkci1jMjo4MC8= > /srv/profile.txt && python -m http.server 8000 -d /srv'

docker run --rm --name ht-ddr-client --network ht-ddr-net python:3-alpine \
python -c 'import base64,urllib.request; p=urllib.request.urlopen("http://ht-ddr-web:8000/profile.txt").read(); u=base64.b64decode(p).decode(); print(urllib.request.urlopen(u).status)'

docker logs ht-ddr-web
docker logs ht-ddr-c2
```
O conteúdo codificado é `http://ht-ddr-c2:80/`. Uma detecção funcional correlaciona o mesmo processo/contêiner de curta duração lendo `/profile.txt`, decodificando o conteúdo e contatando `ht-ddr-c2` em poucos segundos. Calcule o hash e preserve a resposta do objeto.

### Desmontagem
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: synthetic peel-chain e grafo de bridge

**Objetivo:** praticar o rastreamento de valor sem ativos, contas ou serviços reais.

### Crie e rastreie o dataset
```bash
ht_graph_dir="$(mktemp -d)"
cat >"$ht_graph_dir/edges.csv" <<'EOF'
time,chain,source,destination,amount,label
10:00,A,theft,a1,100,source
10:10,A,a1,shop1,3,payment
10:10,A,a1,a2,96.9,change
10:20,A,a2,shop2,4,payment
10:20,A,a2,a3,92.8,change
10:30,A,a3,bridge_in,90,bridge_deposit
10:36,X,bridge_in,bridge_out,89.5,bridge_link_inference
10:36,B,bridge_out,b1,89.5,bridge_withdrawal
10:50,B,b1,exchange,89,service_deposit
EOF

python3 - "$ht_graph_dir/edges.csv" <<'PY'
import csv, sys
edges = list(csv.DictReader(open(sys.argv[1], newline="")))
frontier, seen = {"theft"}, set()
while frontier:
src = frontier.pop()
for e in edges:
if e["source"] == src and (src, e["destination"]) not in seen:
seen.add((src, e["destination"]))
print(f'{e["time"]} {e["chain"]}: {src} -> {e["destination"]} {e["amount"]} [{e["label"]}]')
frontier.add(e["destination"])
PY
```
Os analistas devem identificar o padrão de peel/change, tratar o bridge link como uma inferência apoiada separadamente, calcular a diferença de taxa/valor e marcar a exchange como uma solicitação de evidência off-chain. Alterem um valor/horário e documentem como a confiança muda.

### Desmontagem
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: sensor passivo de sinalização de tráfego

**Objetivo:** emular a assinatura de rede de um implant passivo ativado por um valor mágico sem criar um shell, persistência ou acesso remoto. O listener se vincula apenas ao loopback e registra um evento benigno.
```bash
ht_signal_dir="$(mktemp -d)"
cat >"$ht_signal_dir/listener.py" <<'PY'
import hmac, socket

token = b"HT-LAB-ACTIVATE"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 45679))
for _ in range(2):
data, peer = sock.recvfrom(1024)
if hmac.compare_digest(data, token):
print(f"authorized lab activation from {peer[0]}", flush=True)
PY

python3 "$ht_signal_dir/listener.py" >"$ht_signal_dir/events.log" &
ht_signal_pid=$!
sleep 1

python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"ordinary-traffic", ("127.0.0.1", 45679))
s.sendto(b"HT-LAB-ACTIVATE", ("127.0.0.1", 45679))
PY

wait "$ht_signal_pid"
cat "$ht_signal_dir/events.log"
rm -rf -- "$ht_signal_dir"
```
Resultado esperado: o tráfego comum não produz nenhum evento da aplicação; apenas o token designado produz um. Capture o tráfego de loopback durante a execução e verifique se um sensor de rede ainda consegue visualizar ambos os datagramas. Em seguida, avalie os controles do host que detectam um packet listener de longa duração inesperado ou um filtro de packet-capture. Os implantes passivos reais do RedPenguin inspecionavam o tráfego em um roteador e ofereciam funcionalidades perigosas; este laboratório deliberadamente não faz nenhuma das duas coisas.

## Modelo de relatório do exercício

Para cada laboratório, registre:

- autorização e escopo isolado;
- hipótese e técnica do ATT&CK;
- topologia e tabela de observadores;
- horário exato de início/fim e hashes de configuração;
- eventos esperados por sensor;
- eventos realmente observados e lacunas de retenção;
- lógica analítica, limite e amostra de falso positivo;
- se a equipe-alvo reconstruiu o caminho;
- resultado do reteste da mitigação; e
- evidências de teardown/recuperação.

Um exercício fica incompleto até que a detecção seja executada novamente após a mitigação e todos os recursos do laboratório sejam removidos.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
