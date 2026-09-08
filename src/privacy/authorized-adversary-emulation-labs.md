# Labs autorizados de emulação de adversários

{{#include ../banners/hacktricks-training.md}}

Estes exercícios reproduzem uma **arquitetura observável**, não um comprometimento não autorizado. Execute-os em um host Linux de laboratório dedicado, com Docker, sem credenciais sensíveis e sem rota para alvos de terceiros. Os nomes são fixos para que a desmontagem seja explícita.

{% hint style="danger" %}
Não substitua os containers, APs, roteadores, contas ou transações sintéticas pertencentes a você abaixo por proxies públicos, pelo Wi-Fi de um vizinho, por um tenant de CDN de produção que você não controla ou por fundos ilícitos reais. A autorização por escrito deve abranger todos os sistemas e ambientes de rádio.
{% endhint %}

## Lab 1: ORB e cadeia de redirectors próprios

**Objetivo:** mostrar que um alvo registra apenas a saída, enquanto cada relay vê os hops adjacentes. Isso emula a estrutura T1090.003/T1584 sem dispositivos comprometidos.

**Requisitos:** Docker Engine e nomes de containers não utilizados começando com `ht-orb-`.

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
Resultado esperado: o Nginx registra o endereço `ht-orb-r2` em `ht-orb-target`, não o cliente de disparo único. Os logs do relay mostram conexões somente a partir da rede adjacente. A inspeção do control-plane do Docker ainda reconstrói todo o caminho — de forma análoga às evidências do provider/controller.

### Experimentos de detecção

1. Repita as requisições a cada 60 segundos e faça um gráfico do tempo entre chegadas e dos bytes.
2. Substitua `ht-orb-r2` por um novo container/endereço nomeado, mas mantenha a mesma cadência e a mesma requisição da aplicação; confirme que uma regra baseada somente em IP perde a cadeia, enquanto o comportamento ainda a correlaciona.
3. Capture nas três bridges do Docker com `tcpdump` no host do lab e compare os timestamps.
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
### Enviar e observar a divergência
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Os campos de log esperados incluem `sni=front.lab host=origin.lab`. A captura de pacotes entre o cliente e o edge expõe o SNI, a menos que ECH esteja em uso; o HTTP Host é criptografado nesse link. O edge terminador vê ambos.

Agora envie uma solicitação normal e confirme que a policy a rejeita:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Assertion de detecção

Gere um alerta sobre `sni != host` somente após normalizar portas/capitalização e verificar exceções conhecidas de reverse-proxy. Adicione o contexto do processo e do tenant/origin antes de atribuir a severidade.

### Desmontagem
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: telemetria de DNS fast-flux

**Objetivo:** gerar um dataset seguro de DNS semelhante a low-TTL/multi-ASN e validar um analytic. Os endereços de documentação RFC 5737 retornados não são roteáveis para esse propósito.

### Executar um servidor authoritative
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
Resultado esperado: cada resposta carrega três IPs de documentação e um TTL de 5 segundos. O fast flux real também alterna subconjuntos ao longo do tempo; altere o serial/endereço da zona e reinicie este servidor descartável para criar várias épocas.

### Validação analítica

Para uma janela de cinco minutos, calcule `median(TTL)`, respostas distintas, rótulos distintos de ASN/geografia sintéticos e a rotatividade das respostas. Exija pelo menos duas dimensões suspeitas, além de um evento de processo/pós-evento. Execute a mesma análise em uma amostra conhecida de CDN para medir falsos positivos.

### Desmontagem
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4: nearest-neighbor wireless pivot

**Objetivo:** reproduzir o boundary mismatch do APT28 com duas “organizações” sob seu controle. Como os comandos de hardware/driver de Wi-Fi variam, este lab especifica funções e evidências verificáveis, em vez de fingir que um único comando `hostapd` funciona em qualquer rádio.

### Equipamento

- dois APs sob seu controle, em canais/SSIDs isolados de lab `HT-NEIGHBOR` e `HT-TARGET`;
- um serviço target acessível somente a partir de `HT-TARGET`;
- um pivot Linux de rádio duplo sob seu controle, capaz de se associar a ambos os APs;
- uma workstation de remote-control atrás de `HT-NEIGHBOR`;
- logs de associação do RADIUS/NAC ou AP, logs de DHCP e logs de auditoria/processo do pivot.

### Procedimento

1. Isole fisicamente ou atenue a configuração para que nenhum SSID escape da área autorizada. Confirme com um survey.
2. Configure `HT-TARGET` com uma identidade de exercício e omita deliberadamente a validação de device-certificate/posture na primeira execução. Registre isso como a condição em teste.
3. Conecte a primeira interface do pivot a `HT-NEIGHBOR` e a segunda interface a `HT-TARGET`. **Não** habilite uma bridge geral; permita somente o serviço/porta target por meio de um host firewall.
4. A partir da workstation, abra um túnel autenticado para o pivot e solicite o serviço target por meio dele.
5. Registre o processo/criação de interface do pivot, ambas as associações aos APs, o evento RADIUS do target, o lease DHCP e o endereço de origem do target.
6. Peça à equipe de detecção para reconstruir a cadeia sem o mapa do controller.
7. Habilite EAP-TLS/posture de managed-device em `HT-TARGET`, remova o certificado target aprovado do pivot e repita. O acesso deve falhar na admissão.
8. Repita usando um MAC randomized visto pela primeira vez. Verifique se a decisão baseada em certificate/device continua funcionando e se nenhuma regra trata apenas o MAC como identidade.

### Critérios de sucesso

- O target inicialmente vê um cliente Wi-Fi local, e não a workstation.
- A telemetria de associações identifica um pivot com caminhos simultâneos para o controle neighbor e o rádio target.
- A admissão baseada em certificate/device bloqueia a segunda execução.
- Nenhum pacote alcança uma rede fora do lab isolado.

## Lab 5: dead-drop resolver sequence

**Objetivo:** detectar um processo que lê um objeto com aparência legítima, decodifica um ponteiro e imediatamente contata um segundo serviço.

### Build
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
O conteúdo codificado é `http://ht-ddr-c2:80/`. Uma detecção funcional associa o mesmo processo/contêiner de curta duração lendo `/profile.txt`, decodificando o conteúdo e contatando `ht-ddr-c2` em poucos segundos. Faça o hash e preserve a resposta do objeto.

### Desmontagem
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: cadeia de peel sintética e grafo de bridge

**Objetivo:** praticar o rastreamento de valor sem ativos, contas ou serviços reais.

### Criar e rastrear o conjunto de dados
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
Os analistas devem identificar o padrão de peel/change, tratar o link de bridge como uma inferência suportada separadamente, calcular a diferença de fee/valor e marcar a exchange como uma solicitação de evidências off-chain. Altere um valor/horário e documente como a confiança muda.

### Desmontagem
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: sensor passivo de sinalização de tráfego

**Objetivo:** emular a assinatura de rede de um implante passivo ativado por um valor mágico sem criar um shell, persistência ou acesso remoto. O listener vincula-se apenas ao loopback e registra um evento benigno.
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
Resultado esperado: o tráfego comum não produz nenhum evento de aplicação; somente o token designado produz um. Capture o tráfego de loopback durante a execução e verifique se um sensor de rede ainda consegue visualizar ambos os datagramas. Em seguida, avalie os controles do host que detectam um packet listener inesperado de longa duração ou um filtro de packet-capture. Os passive implants reais do RedPenguin inspecionavam o tráfego em um router e ofereciam funcionalidades perigosas; este lab deliberadamente não faz nenhuma dessas coisas.

## Modelo de relatório do exercício

Para cada lab, registre:

- autorização e escopo isolado;
- hipótese e técnica do ATT&CK;
- topologia e tabela de observadores;
- horário exato de início/fim e hashes de configuração;
- eventos esperados por sensor;
- eventos realmente observados e lacunas de retenção;
- lógica analítica, threshold e amostra de falso positivo;
- se a equipe-alvo reconstruiu o caminho;
- resultado do reteste da mitigação; e
- evidências de teardown/recovery.

Um exercício fica incompleto até que a detecção seja executada novamente após a mitigação e todos os recursos do lab sejam removidos.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — O ataque do vizinho mais próximo](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
