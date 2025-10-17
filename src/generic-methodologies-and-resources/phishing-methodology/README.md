# Phishing Metodologia

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon da vítima
1. Selecione o **domínio da vítima**.
2. Realize uma enumeração web básica **procurando por portais de login** usados pela vítima e **decida** qual você irá **se passar por**.
3. Utilize alguma **OSINT** para **encontrar emails**.
2. Prepare o ambiente
1. **Compre o domínio** que você vai usar para a avaliação de phishing
2. **Configure os registros relacionados ao serviço de email** (SPF, DMARC, DKIM, rDNS)
3. Configure o VPS com **gophish**
3. Prepare a campanha
1. Prepare o **template de email**
2. Prepare a **página web** para capturar as credenciais
4. Lance a campanha!

## Gerar domínios similares ou comprar um domínio confiável

### Domain Name Variation Techniques

- **Keyword**: O nome de domínio **contém** uma importante **keyword** do domínio original (e.g., zelster.com-management.com).
- **hypened subdomain**: Altere o **ponto por um hífen** de um subdomínio (e.g., www-zelster.com).
- **New TLD**: Mesmo domínio usando uma **new TLD** (e.g., zelster.org)
- **Homoglyph**: Ele **substitui** uma letra no nome de domínio por **letras que se parecem** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Ele **troca duas letras** dentro do nome de domínio (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adiciona ou remove “s” no final do nome de domínio (e.g., zeltsers.com).
- **Omission**: Remove uma das letras do nome de domínio (e.g., zelser.com).
- **Repetition:** Repete uma das letras no nome de domínio (e.g., zeltsser.com).
- **Replacement**: Semelhante a homoglyph, mas menos furtivo. Substitui uma das letras no nome de domínio, talvez por uma letra próxima no teclado (e.g, zektser.com).
- **Subdomained**: Introduz um **ponto** dentro do nome de domínio (e.g., ze.lster.com).
- **Insertion**: Insere uma letra no nome de domínio (e.g., zerltser.com).
- **Missing dot**: Anexa a TLD ao nome de domínio. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe a **possibilidade de que alguns bits armazenados ou em comunicação sejam automaticamente invertidos** devido a vários fatores como erupções solares, raios cósmicos ou erros de hardware.

Quando esse conceito é **aplicado a requisições DNS**, é possível que o **domínio recebido pelo servidor DNS** não seja o mesmo que o domínio originalmente solicitado.

Por exemplo, uma única modificação de bit no domínio "windows.com" pode alterá-lo para "windnws.com."

Atacantes podem **aproveitar isso registrando múltiplos domínios bit-flipping** que são semelhantes ao domínio da vítima. A intenção é redirecionar usuários legítimos para sua própria infraestrutura.

Para mais informações leia [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Você pode procurar em [https://www.expireddomains.net/](https://www.expireddomains.net) por um domínio expirado que você possa usar.\
Para garantir que o domínio expirado que você vai comprar **já tenha um bom SEO** você pode verificar como ele está categorizado em:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descobrir mais** endereços de email válidos ou **verificar os que** você já encontrou, você pode checar se consegue brute-force nos servidores smtp da vítima. [Aprenda como verificar/descobrir endereços de email aqui](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Além disso, não esqueça que se os usuários usam **qualquer portal web para acessar seus e-mails**, você pode verificar se ele é vulnerável a **username brute force**, e explorar a vulnerabilidade se possível.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
Você receberá uma senha para o usuário admin na porta 3333 no output. Portanto, acesse essa porta e use essas credenciais para alterar a senha do admin. Pode ser necessário encaminhar essa porta para o host local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuração

**Configuração do certificado TLS**

Antes desta etapa você deve **já ter comprado o domínio** que vai usar e ele deve estar **apontando** para o **IP do VPS** onde você está configurando o **gophish**.
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

Comece a instalar: `apt-get install postfix`

Depois adicione o domínio aos seguintes arquivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Altere também os valores das seguintes variáveis dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Por fim modifique os arquivos **`/etc/hostname`** e **`/etc/mailname`** para o seu nome de domínio e **reinicie seu VPS.**

Agora, crie um **DNS A record** de `mail.<domain>` apontando para o **endereço IP** do VPS e um **DNS MX** record apontando para `mail.<domain>`

Agora vamos testar o envio de um e-mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

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

Para criar o serviço gophish de forma que ele possa ser iniciado automaticamente e gerenciado como um serviço, você pode criar o arquivo `/etc/init.d/gophish` com o seguinte conteúdo:
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
## Configurando servidor de e-mail e domínio

### Aguarde & seja legítimo

Quanto mais antigo for um domínio, menos provável será que ele seja marcado como spam. Portanto, você deve esperar o máximo possível (pelo menos 1 week) antes da avaliação de phishing. Além disso, se você colocar uma página relacionada a um setor com boa reputação, a reputação obtida será melhor.

Observe que, mesmo que você tenha que esperar uma semana, você pode terminar de configurar tudo agora.

### Configure o registro Reverse DNS (rDNS)

Configure um registro rDNS (PTR) que resolva o endereço IP do VPS para o nome de domínio.

### Registro Sender Policy Framework (SPF)

Você deve **configurar um registro SPF para o novo domínio**. Se você não sabe o que é um registro SPF [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Você pode usar [https://www.spfwizard.net/](https://www.spfwizard.net) para gerar sua política SPF (use o IP da máquina VPS)

![](<../../images/image (1037).png>)

Este é o conteúdo que deve ser colocado dentro de um registro TXT no domínio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro DMARC (Autenticação de Mensagens Baseada em Domínio, Relatórios e Conformidade)

Você deve **configurar um registro DMARC para o novo domínio**. Se você não sabe o que é um registro DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Você deve criar um novo registro DNS TXT apontando o nome do host `_dmarc.<domain>` com o seguinte conteúdo:
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

### Teste a pontuação da sua configuração de e-mail

Você pode fazer isso usando [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Basta acessar a página e enviar um e-mail para o endereço que eles fornecem:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Você também pode **verificar sua configuração de email** enviando um email para `check-auth@verifier.port25.com` e **ler a resposta** (para isso você precisará **abrir** a porta **25** e ver a resposta no arquivo _/var/mail/root_ se você enviar o email como root).\
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
Você também pode enviar uma **mensagem para um Gmail sob seu controle** e verificar os **cabeçalhos do email** na sua caixa de entrada do Gmail; `dkim=pass` deve estar presente no campo de cabeçalho `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removendo da Blacklist do Spamhouse

A página [www.mail-tester.com](https://www.mail-tester.com) pode indicar se o seu domínio está sendo bloqueado pelo spamhouse. Você pode solicitar a remoção do seu domínio/IP em: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removendo da Blacklist da Microsoft

​​Você pode solicitar a remoção do seu domínio/IP em [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Defina um **nome para identificar** o perfil do remetente
- Decida de qual conta você vai enviar os emails de phishing. Sugestões: _noreply, support, servicedesk, salesforce..._
- Você pode deixar em branco o username e o password, mas certifique-se de marcar Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Recomenda-se usar a funcionalidade "**Send Test Email**" para testar se tudo está funcionando.\
> Recomendo **enviar os emails de teste para endereços 10min mails** para evitar ser colocado em blacklists ao realizar testes.

### Email Template

- Defina um **nome para identificar** o template
- Depois escreva um **subject** (nada estranho, apenas algo que você poderia esperar ler em um email comum)
- Certifique-se de que marcou "**Add Tracking Image**"
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
Note que **para aumentar a credibilidade do email**, é recomendado usar alguma assinatura retirada de um email do cliente. Sugestões:

- Envie um email para um **endereço inexistente** e veja se a resposta contém alguma assinatura.
- Procure por **emails públicos** como info@ex.com ou press@ex.com ou public@ex.com e envie um email e aguarde a resposta.
- Tente contactar **algum email válido descoberto** e espere pela resposta

![](<../../images/image (80).png>)

> [!TIP]
> O Email Template também permite **anexar arquivos para enviar**. Se também quiser roubar desafios NTLM usando alguns ficheiros/documentos especialmente construídos [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Escreva um **nome**
- **Escreva o código HTML** da página web. Note que pode **importar** páginas web.
- Marque **Capture Submitted Data** e **Capture Passwords**
- Defina uma **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Normalmente será necessário modificar o código HTML da página e fazer alguns testes localmente (talvez usando algum servidor Apache) **até gostar do resultado.** Depois, escreva esse código HTML na caixa.\
> Note que se precisar de **usar alguns recursos estáticos** para o HTML (talvez alguns ficheiros CSS e JS) pode guardá-los em _**/opt/gophish/static/endpoint**_ e depois aceder a eles a partir de _**/static/\<filename>**_

> [!TIP]
> Para a redirection pode **redirecionar os utilizadores para a página web legítima** da vítima, ou redirecioná-los para _/static/migration.html_ por exemplo, colocar um **spinning wheel (**[**https://loading.io/**](https://loading.io)**) por 5 segundos e depois indicar que o processo foi bem sucedido**.

### Users & Groups

- Defina um nome
- **Import the data** (note que para usar o template do exemplo precisa do firstname, last name e email address de cada utilizador)

![](<../../images/image (163).png>)

### Campaign

Finalmente, crie uma campanha selecionando um nome, o email template, a landing page, a URL, o sending profile e o group. Note que a URL será o link enviado às vítimas

Note que o **Sending Profile permite enviar um email de teste para ver como ficará o email de phishing final**:

![](<../../images/image (192).png>)

> [!TIP]
> Eu recomendaria **enviar os emails de teste para endereços 10min mails** para evitar ficar listado em blacklists ao fazer testes.

Uma vez que tudo esteja pronto, apenas lance a campanha!

## Website Cloning

Se por alguma razão quiser clonar o website consulte a página seguinte:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Em algumas avaliações de phishing (principalmente para Red Teams) poderá também querer **enviar ficheiros contendo algum tipo de backdoor** (talvez um C2 ou talvez apenas algo que dispare uma autenticação).\
Consulte a página seguinte para alguns exemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

O ataque anterior é bastante inteligente, pois está a falsificar um website real e a recolher as informações introduzidas pelo utilizador. Infelizmente, se o utilizador não introduziu a password correta ou se a aplicação que falsificou está configurada com 2FA, **essa informação não permitirá que você se passe pelo utilizador enganado**.

É aqui que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) são úteis. Esta ferramenta permitirá gerar um ataque MitM. Basicamente, o ataque funciona da seguinte forma:

1. Você **se faz passar pelo formulário de login** da página real.
2. O utilizador **envia** as suas **credenciais** para a sua página falsa e a ferramenta envia-as para a página real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM pedirá por isso e uma vez que o **utilizador o introduza** a ferramenta irá enviá-lo para a página web real.
4. Uma vez que o utilizador esteja autenticado você (como atacante) terá **capturado as credenciais, o 2FA, o cookie e qualquer informação** de cada interação enquanto a ferramenta está a realizar o MitM.

### Via VNC

E se, em vez de **enviar a vítima para uma página maliciosa** com a mesma aparência da original, você a enviar para uma **sessão VNC com um browser ligado à página real**? Poderá ver o que ele faz, roubar a password, a MFA usada, os cookies...\
Pode fazer isto com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviamente uma das melhores formas de saber se foi apanhado é **pesquisar o seu domínio em blacklists**. Se aparecer listado, de alguma forma o seu domínio foi detectado como suspeito.\
Uma forma fácil de verificar se o seu domínio aparece em alguma blacklist é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, existem outras formas de saber se a vítima está **ativamente a procurar atividade suspeita de phishing** no exterior, conforme explicado em:


{{#ref}}
detecting-phising.md
{{#endref}}

Você pode **comprar um domínio com um nome muito parecido** com o domínio da vítima **e/ou gerar um certificado** para um **subdomínio** de um domínio controlado por si **contendo** a **keyword** do domínio da vítima. Se a **vítima** realizar qualquer tipo de **interação DNS ou HTTP** com eles, você saberá que **ela está ativamente a procurar** por domínios suspeitos e terá de ser muito discreto.

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious) para avaliar se o seu email vai acabar na pasta de spam ou se será bloqueado ou bem-sucedido.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets increasingly skip email lures entirely and **directly target the service-desk / identity-recovery workflow** to defeat MFA.  The attack is fully "living-off-the-land": once the operator owns valid credentials they pivot with built-in admin tooling – no malware is required.

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
Equipas de baixo custo compensam o custo de operações de alta atenção com ataques em massa que transformam **motores de busca & redes de anúncios no canal de entrega**.

1. **SEO poisoning / malvertising** impulsiona um resultado falso como `chromium-update[.]site` para os anúncios de topo.
2. A vítima descarrega um pequeno **first-stage loader** (frequentemente JS/HTA/ISO). Exemplos observados pela Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. O loader exfiltra cookies do browser + credential DBs, depois puxa um **silent loader** que decide – *em tempo real* – se vai(s):
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistência (registry Run key + scheduled task)

### Hardening tips
* Bloqueie domínios recentemente registados & aplique **Advanced DNS / URL Filtering** em *search-ads* bem como em e-mail.
* Restrinja a instalação de software a pacotes MSI assinados / Store packages, negue a execução de `HTA`, `ISO`, `VBS` via política.
* Monitorize por processos filhos de browsers que abrem instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Faça hunting por LOLBins frequentemente abusados por first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Os atacantes agora encadeiam **LLM & voice-clone APIs** para iscas totalmente personalizadas e interação em tempo real.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Adicione **banners dinâmicos** destacando mensagens enviadas por automação não confiável (via anomalias ARC/DKIM).  
• Implemente **voice-biometric challenge phrases** para pedidos telefónicos de alto risco.  
• Simule continuamente iscas geradas por AI em programas de awareness – templates estáticos estão obsoletos.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Além do clássico push-bombing, os operadores simplesmente **forçam um novo registo de MFA** durante a chamada ao help-desk, anulando o token existente do utilizador. Qualquer pedido de login subsequente parecerá legítimo para a vítima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitore eventos do AzureAD/AWS/Okta onde **`deleteMFA` + `addMFA`** ocorram **em questão de minutos pelo mesmo IP**.



## Clipboard Hijacking / Pastejacking

Atacantes podem copiar silenciosamente comandos maliciosos para o clipboard da vítima a partir de uma página web comprometida ou typosquatted e então enganar o usuário para colá‑los dentro de **Win + R**, **Win + X** ou uma janela de terminal, executando código arbitrário sem qualquer download ou anexo.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Os operadores cada vez mais colocam seus fluxos de phishing atrás de uma simples verificação de dispositivo para que crawlers desktop nunca alcancem as páginas finais. Um padrão comum é um pequeno script que testa se o DOM suporta touch e envia o resultado para um endpoint do servidor; clientes non‑mobile recebem HTTP 500 (ou uma página em branco), enquanto usuários mobile recebem o fluxo completo.

Snippet mínimo do cliente (lógica típica):
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
- Retorna 500 (ou conteúdo de placeholder) às GETs subsequentes quando `is_mobile=false`; serve phishing apenas se `true`.

Hunting e heurísticas de detecção:
- Consulta urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequência de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para não‑mobile; caminhos legítimos de vítimas móveis retornam 200 com HTML/JS subsequente.
- Bloquear ou escrutinar páginas que condicionam conteúdo exclusivamente a `ontouchstart` ou verificações de dispositivo similares.

Dicas de defesa:
- Execute crawlers com fingerprints similares a mobile e com JS ativado para revelar conteúdo protegido.
- Gerar alertas para respostas 500 suspeitas após `POST /detect` em domínios recém-registrados.

## Referências

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
