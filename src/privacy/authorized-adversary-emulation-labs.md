# Laboratorios autorizados de emulación de adversarios

{{#include ../banners/hacktricks-training.md}}

Estos ejercicios reproducen una **arquitectura observable**, no un compromiso no autorizado. Ejecútalos en un host Linux de laboratorio dedicado con Docker, sin credenciales confidenciales y sin rutas hacia objetivos de terceros. Los nombres son fijos para que el desmontaje sea explícito.

{% hint style="danger" %}
No reemplaces los contenedores, APs, routers, cuentas ni transacciones sintéticas propios indicados abajo por proxies públicos, la Wi-Fi de un vecino, un tenant de CDN de producción que no controles o fondos ilícitos reales. La autorización escrita debe cubrir cada sistema y entorno de radio.
{% endhint %}

## Laboratorio 1: ORB y cadena de redirector propios

**Objetivo:** demostrar que un objetivo registra únicamente la salida, mientras cada relay ve los saltos adyacentes. Esto emula la estructura T1090.003/T1584 sin dispositivos comprometidos.

**Requisitos:** Docker Engine y nombres de contenedor sin usar que comiencen por `ht-orb-`.

### Construcción
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
### Verifica los límites de visibilidad
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Resultado esperado: Nginx registra la dirección `ht-orb-r2` en `ht-orb-target`, no la del cliente one-shot. Los logs del relay muestran conexiones únicamente desde su red adyacente. La inspección del control-plane de Docker aún reconstruye la ruta completa, de forma análoga a la evidencia del proveedor/controlador.

### Experimentos de detección

1. Repite las solicitudes cada 60 segundos y representa gráficamente el tiempo entre llegadas y los bytes.
2. Sustituye `ht-orb-r2` por un nuevo contenedor/dirección con nombre, pero conserva la misma cadencia y solicitud de aplicación; confirma que una regla basada únicamente en IP pierde la cadena, mientras que el comportamiento aún la vincula.
3. Captura en los tres bridges de Docker con `tcpdump` en el host del lab y compara las marcas de tiempo.
4. Detén `ht-orb-r2`; verifica que no exista un fallback directo desde la entrada al objetivo.

### Desmontaje
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: SNI/Host mismatch y logging del redirector

**Objetivo:** reproducir la primitiva de routing detrás de domain fronting en un edge local privado y mostrar dónde es visible. No interviene ningún CDN público.

### Construye un edge TLS local
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
### Enviar y observar la discrepancia
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Los campos de log esperados incluyen `sni=front.lab host=origin.lab`. La captura de paquetes entre el cliente y el edge expone el SNI, salvo que se utilice ECH; el HTTP Host está cifrado en ese enlace. El edge que termina la conexión ve ambos.

Ahora envía una solicitud normal y confirma que la policy la rechaza:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Aserción de detección

Genera una alerta sobre `sni != host` solo después de normalizar los puertos y las mayúsculas/minúsculas, y comprobar las excepciones conocidas de reverse-proxy. Añade el contexto del proceso y del tenant/origen antes de asignar la gravedad.

### Desmontaje
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**Objetivo:** generar un dataset seguro de DNS similar a low-TTL/multi-ASN y validar un analytic. Las direcciones de documentación RFC 5737 devueltas no son enrutables para este propósito.

### Ejecuta un authoritative server
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
Resultado esperado: cada respuesta contiene tres IPs de documentación y un TTL de 5 segundos. El fast flux real también rota subconjuntos con el tiempo; cambia el serial/las direcciones de la zona y reinicia este servidor desechable para crear múltiples épocas.

### Validación analítica

Para una ventana de cinco minutos, calcula `median(TTL)`, las respuestas distintas, las etiquetas de ASN/geografía sintéticas distintas y la rotación de respuestas. Exige al menos dos dimensiones sospechosas además de un evento de proceso/seguimiento. Ejecuta el mismo análisis sobre una muestra conocida de CDN para medir los falsos positivos.

### Desmantelamiento
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Laboratorio 4: pivot wireless de vecino más cercano

**Objetivo:** reproducir el desajuste de límites de APT28 con dos “organizaciones” propias. Como los comandos de hardware/driver Wi-Fi varían, este laboratorio especifica roles y evidencias verificables en lugar de pretender que un comando de `hostapd` sirve para cualquier radio.

### Equipamiento

- dos AP propios, en canales/SSID de laboratorio aislados `HT-NEIGHBOR` y `HT-TARGET`;
- un servicio objetivo accesible únicamente desde `HT-TARGET`;
- un pivot Linux de doble radio propio, capaz de asociarse a ambos AP;
- una workstation de remote-control detrás de `HT-NEIGHBOR`;
- logs de RADIUS/NAC o de asociación del AP, logs de DHCP y logs de auditoría/procesos del pivot.

### Procedimiento

1. Aísla físicamente o atenúa la configuración para que ningún SSID salga del área autorizada. Confírmalo mediante un survey.
2. Configura `HT-TARGET` con una identidad de ejercicio y omite deliberadamente la validación de certificado del dispositivo/posture en la primera ejecución. Registra esto como la condición bajo prueba.
3. Conecta la primera interfaz del pivot a `HT-NEIGHBOR` y la segunda interfaz a `HT-TARGET`. **No** habilites un bridge general; permite únicamente el servicio/puerto objetivo mediante un firewall del host.
4. Desde la workstation, abre un túnel autenticado hacia el pivot y solicita el servicio objetivo a través de él.
5. Registra la creación del proceso/interfaz del pivot, ambas asociaciones con los AP, el evento RADIUS objetivo, el lease DHCP y la dirección de origen objetivo.
6. Pide al equipo de detección que reconstruya la cadena sin el mapa del controller.
7. Habilita EAP-TLS/posture de managed-device en `HT-TARGET`, elimina el certificado objetivo aprobado del pivot y repite. El acceso debería fallar durante la admisión.
8. Repite usando una MAC randomized vista por primera vez. Verifica que la decisión sobre el certificado/dispositivo siga funcionando y que ninguna regla trate la MAC por sí sola como identidad.

### Criterios de éxito

- El objetivo ve inicialmente un cliente Wi-Fi local en lugar de la workstation.
- La telemetría de las asociaciones identifica un pivot con rutas simultáneas hacia el control del vecino y la radio objetivo.
- La admisión respaldada por certificado/dispositivo bloquea la segunda ejecución.
- Ningún paquete llega a una red fuera del laboratorio aislado.

## Laboratorio 5: secuencia de resolución dead-drop

**Objetivo:** detectar un proceso que lee un objeto con apariencia legítima, decodifica un puntero y contacta inmediatamente con un segundo servicio.

### Compilación
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
El contenido codificado es `http://ht-ddr-c2:80/`. Una detección funcional vincula el mismo proceso/contenedor de corta duración que lee `/profile.txt`, decodifica el contenido y contacta con `ht-ddr-c2` en cuestión de segundos. Calcula el hash y conserva la respuesta del objeto.

### Desmantelamiento
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Laboratorio 6: synthetic peel-chain y bridge graph

**Objetivo:** practicar el rastreo de valor sin activos, cuentas o servicios reales.

### Crear y rastrear el dataset
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
Los analistas deben identificar el patrón de peel/change, tratar el enlace puente como una inferencia respaldada por separado, calcular la diferencia de comisión/valor y marcar el exchange como una solicitud de evidencia off-chain. Cambien un valor/tiempo y documenten cómo cambia la confianza.

### Desglose
```bash
rm -rf -- "$ht_graph_dir"
```
## Laboratorio 7: sensor pasivo de señalización de tráfico

**Objetivo:** emular la firma de red de un implant pasivo activado por un magic value sin crear un shell, persistence ni remote access. El listener se enlaza únicamente a loopback y registra un evento benigno.
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
Resultado esperado: el tráfico normal no produce ningún evento de aplicación; solo lo produce el token designado. Captura el tráfico de loopback durante la ejecución y verifica que un sensor de red aún pueda ver ambos datagramas. Después, evalúa los controles del host que detectan un listener de paquetes inesperado de larga duración o un filtro de captura de paquetes. Los implants pasivos reales de RedPenguin inspeccionaban el tráfico en un router y ofrecían funcionalidad peligrosa; este lab deliberadamente no hace ninguna de las dos cosas.

## Plantilla del informe del ejercicio

Para cada lab, registra:

- autorización y alcance aislado;
- hipótesis y técnica de ATT&CK;
- topología y tabla de observadores;
- hora exacta de inicio y finalización, y hashes de configuración;
- eventos esperados por sensor;
- eventos observados realmente y lagunas de retención;
- lógica analítica, umbral y muestra de falsos positivos;
- si el equipo objetivo reconstruyó la ruta;
- resultado de la repetición de prueba de mitigación; y
- evidencias de desmontaje/recuperación.

Un ejercicio está incompleto hasta que la detección se vuelve a ejecutar después de la mitigación y se elimina cada recurso del lab.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — El ataque del vecino más cercano](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
