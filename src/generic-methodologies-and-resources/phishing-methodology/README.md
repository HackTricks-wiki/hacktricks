# Metodologia de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon the victim
1. Selecione o **domínio da vítima**.
2. Faça alguma enumeração web básica **procurando portais de login** usados pela vítima e **decida** qual deles você irá **se passar por**.
3. Use **OSINT** para **encontrar e-mails**.
2. Prepare o ambiente
1. **Compre o domínio** que você vai usar para a avaliação de phishing
2. **Configure o serviço de email** e os registros relacionados (SPF, DMARC, DKIM, rDNS)
3. Configure o VPS com **gophish**
3. Prepare a campanha
1. Prepare o **modelo de email**
2. Prepare a **página web** para roubar as credenciais
4. Lance a campanha!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Ele **troca duas letras** dentro do nome de domínio (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adiciona ou remove “s” no final do nome de domínio (e.g., zeltsers.com).
- **Omission**: Remove uma das letras do nome de domínio (e.g., zelser.com).
- **Repetition:** Repete uma das letras no nome de domínio (e.g., zeltsser.com).
- **Replacement**: Como homoglyph mas menos furtivo. Substitui uma das letras no nome de domínio, talvez por uma letra próxima da original no teclado (e.g, zektser.com).
- **Subdomained**: Introduz um **ponto** dentro do nome de domínio (e.g., ze.lster.com).
- **Insertion**: Insere uma letra no nome de domínio (e.g., zerltser.com).
- **Missing dot**: Anexa a TLD ao nome de domínio (e.g., zelstercom.com)

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

## Descobrindo E-mails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% grátis)
- [https://phonebook.cz/](https://phonebook.cz) (100% grátis)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descobrir mais** endereços de e-mail válidos ou **verificar os que** você já descobriu você pode checar se consegue brute-force os servidores SMTP da vítima. [Saiba como verificar/descobrir endereços de e-mail aqui](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Além disso, não se esqueça de que, se os usuários usam qualquer portal web para acessar seus e-mails, você pode verificar se ele é vulnerável a username brute force, e explorar a vulnerabilidade se possível.

## Configurando GoPhish

### Instalação

Você pode baixá-lo de [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Baixe e descompacte dentro de `/opt/gophish` e execute `/opt/gophish/gophish`\
Você receberá uma senha para o usuário admin na porta 3333 na saída. Portanto, acesse essa porta e use essas credenciais para alterar a senha do admin. Pode ser necessário fazer um tunnel dessa porta para local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuração

**Configuração do certificado TLS**

Antes desta etapa, você deve **já ter comprado o domínio** que vai usar e ele deve estar **apontando** para o **IP do VPS** onde você está configurando **gophish**.
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
**Mail configuration**

Comece instalando: `apt-get install postfix`

Depois adicione o domínio aos seguintes arquivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Altere também os valores das seguintes variáveis dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Por fim modifique os arquivos **`/etc/hostname`** e **`/etc/mailname`** para o seu nome de domínio e **reinicie seu VPS.**

Agora, crie um **DNS A record** de `mail.<domain>` apontando para o **ip address** do VPS e um **DNS MX** apontando para `mail.<domain>`

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
Conclua a configuração do serviço e verifique-o executando:
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

### Espere e seja legítimo

Quanto mais antigo for um domínio, menos provável será que ele seja marcado como spam. Portanto você deve esperar o máximo de tempo possível (pelo menos 1 semana) antes da avaliação de phishing. Além disso, se você colocar uma página relacionada a um setor com boa reputação, a reputação obtida será melhor.

Note que mesmo que você tenha que esperar uma semana, você pode finalizar a configuração de tudo agora.

### Configure o registro Reverse DNS (rDNS)

Defina um registro rDNS (PTR) que resolva o endereço IP do VPS para o nome de domínio.

### Sender Policy Framework (SPF) Record

You must **configure a SPF record for the new domain**. If you don't know what is a SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

Este é o conteúdo que deve ser definido dentro de um registro TXT no domínio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro DMARC (Domain-based Message Authentication, Reporting & Conformance)

Você deve **configurar um registro DMARC para o novo domínio**. Se você não sabe o que é um registro DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Você deve criar um novo registro DNS TXT apontando o nome de host `_dmarc.<domain>` com o seguinte conteúdo:
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

### Test your email configuration score

Você pode fazer isso usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Basta acessar a página e enviar um e-mail para o endereço que eles fornecem:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Você também pode **verificar sua configuração de e-mail** enviando um e-mail para `check-auth@verifier.port25.com` e **lendo a resposta** (para isso você precisará **abrir** a porta **25** e ver a resposta no arquivo _/var/mail/root_ se enviar o e-mail como root).\
Verifique se você passa todos os testes:
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
Você também pode enviar uma **mensagem para um Gmail sob seu controle**, e verificar os **cabeçalhos do e-mail** na sua caixa de entrada do Gmail, `dkim=pass` deve estar presente no campo de cabeçalho `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Removendo da Lista Negra do Spamhouse

A página [www.mail-tester.com](https://www.mail-tester.com) pode indicar se o seu domínio está sendo bloqueado pelo Spamhouse. Você pode solicitar a remoção do seu domínio/IP em: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removendo da Lista Negra da Microsoft

​​Você pode solicitar a remoção do seu domínio/IP em [https://sender.office.com/](https://sender.office.com).

## Criar & Lançar Campanha GoPhish

### Perfil de Envio

- Defina um **nome para identificar** o perfil do remetente
- Decida de qual conta você vai enviar os phishing emails. Sugestões: _noreply, support, servicedesk, salesforce..._
- Você pode deixar em branco o username e a password, mas certifique-se de marcar o Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Recomenda-se usar a funcionalidade "**Send Test Email**" para testar se tudo está funcionando.\
> Recomendo **enviar os emails de teste para endereços 10min mails** para evitar ficar na blacklist ao realizar os testes.

### Email Template

- Defina um **nome para identificar** o template
- Depois escreva um **subject** (nada estranho, apenas algo que você esperaria ler em um email normal)
- Certifique-se de que marcou "**Add Tracking Image**"
- Escreva o **template do email** (você pode usar variáveis como no exemplo a seguir):
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
- Procure por **emails públicos** como info@ex.com ou press@ex.com ou public@ex.com e envie um email para eles e aguarde a resposta.
- Tente contactar **algum email válido descoberto** e aguarde a resposta

![](<../../images/image (80).png>)

> [!TIP]
> O Modelo de Email também permite **anexar arquivos para enviar**. Se você também quiser roubar desafios NTLM usando alguns arquivos/documentos especialmente criados [leia esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Escreva um **nome**
- **Escreva o código HTML** da página web. Note que você pode **importar** páginas web.
- Marque **Capture Submitted Data** e **Capture Passwords**
- Defina uma **redireção**

![](<../../images/image (826).png>)

> [!TIP]
> Normalmente você precisará modificar o código HTML da página e fazer alguns testes localmente (talvez usando algum servidor Apache) **até que fique satisfeito com os resultados.** Depois, cole esse código HTML na caixa.\
> Note que se você precisar **usar alguns recursos estáticos** para o HTML (talvez alguns arquivos CSS e JS) você pode salvá-los em _**/opt/gophish/static/endpoint**_ e então acessá-los a partir de _**/static/\<filename>**_

> [!TIP]
> Para a redireção você poderia **redirecionar os usuários para a página principal legítima** da vítima, ou redirecioná-los para _/static/migration.html_ por exemplo, colocar um **spinning wheel (**[**https://loading.io/**](https://loading.io)**) por 5 segundos e então indicar que o processo foi bem-sucedido**.

### Users & Groups

- Defina um nome
- **Importe os dados** (note que, para usar o template do exemplo, você precisa do firstname, last name e email address de cada usuário)

![](<../../images/image (163).png>)

### Campaign

Finalmente, crie uma campanha selecionando um nome, o email template, a landing page, a URL, o sending profile e o grupo. Note que a URL será o link enviado às vítimas

Note que o **Sending Profile permite enviar um email de teste para ver como ficará o email de phishing final**:

![](<../../images/image (192).png>)

> [!TIP]
> Eu recomendaria **enviar os emails de teste para endereços 10min mails** para evitar ser listado em blacklists ao fazer testes.

Uma vez que tudo esteja pronto, basta lançar a campanha!

## Website Cloning

Se, por qualquer motivo, você quiser clonar o website verifique a página a seguir:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Em algumas avaliações de phishing (principalmente para Red Teams) você também vai querer **enviar arquivos contendo algum tipo de backdoor** (talvez um C2 ou talvez apenas algo que dispare uma autenticação).\
Confira a página a seguir para alguns exemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

O ataque anterior é bastante esperto pois você está falsificando um website real e coletando as informações inseridas pelo usuário. Infelizmente, se o usuário não colocou a senha correta ou se a aplicação que você falsificou está configurada com 2FA, **essas informações não permitirão que você se passe pelo usuário enganado**.

É aqui que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) são úteis. Essa ferramenta permite gerar um ataque MitM. Basicamente, o ataque funciona da seguinte forma:

1. Você **impersona o formulário de login** da página real.
2. O usuário **envia** suas **credenciais** para sua página falsa e a ferramenta as encaminha para a página real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM solicitará o código e, assim que o **usuário o introduzir**, a ferramenta o enviará para a página web real.
4. Uma vez que o usuário esteja autenticado você (como atacante) terá **capturado as credenciais, o 2FA, o cookie e qualquer informação** de cada interação enquanto a ferramenta realiza o MitM.

### Via VNC

E se, em vez de **enviar a vítima para uma página maliciosa** com o mesmo visual da original, você a enviar para uma **sessão VNC com um browser conectado à página real**? Você poderá ver o que ela faz, roubar a senha, o MFA usado, os cookies...\
Você pode fazer isso com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviamente uma das melhores maneiras de saber se você foi pego é **procurar seu domínio em blacklists**. Se ele aparecer listado, de alguma forma seu domínio foi detectado como suspeito.\
Uma forma simples de verificar se seu domínio aparece em alguma blacklist é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, há outras maneiras de saber se a vítima está **ativamente procurando por atividade suspeita de phishing na rede** como explicado em:


{{#ref}}
detecting-phising.md
{{#endref}}

Você pode **comprar um domínio com um nome muito semelhante** ao domínio da vítima **e/ou gerar um certificado** para um **subdomínio** de um domínio controlado por você **contendo** a **palavra-chave** do domínio da vítima. Se a **vítima** realizar qualquer tipo de interação DNS ou HTTP com eles, você saberá que **ela está ativamente procurando** por domínios suspeitos e precisará ser muito discreto.

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious) para avaliar se seu email vai acabar na pasta de spam, se será bloqueado ou se terá sucesso.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Conjuntos de intrusão modernos cada vez mais pulam iscas por email inteiramente e **diretamente miram o fluxo de trabalho do service-desk / identity-recovery** para derrotar MFA. O ataque é totalmente "living-off-the-land": uma vez que o operador possui credenciais válidas ele pivota com ferramentas administrativas nativas – nenhum malware é necessário.

### Attack flow
1. Recon da vítima
* Colete detalhes pessoais & corporativos do LinkedIn, vazamentos de dados, GitHub público, etc.
* Identifique identidades de alto valor (executivos, TI, finanças) e enumere o **processo exato do help-desk** para reset de senha / MFA.
2. Social engineering em tempo real
* Ligue por telefone, Teams ou chat para o help-desk enquanto se faz passar pelo alvo (frequentemente com **spoofed caller-ID** ou **cloned voice**).
* Forneça os PII coletados anteriormente para passar na verificação baseada em conhecimento.
* Convença o agente a **resetar o segredo do MFA** ou realizar um **SIM-swap** em um número móvel registrado.
3. Ações imediatas pós-acesso (≤60 min em casos reais)
* Estabeleça um foothold através de qualquer web SSO portal.
* Enumere AD / AzureAD com ferramentas nativas (nenhum binário é dropado):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimento lateral com **WMI**, **PsExec**, ou agentes legítimos de **RMM** já liberados no ambiente.

### Detection & Mitigation
* Trate a recuperação de identidade pelo help-desk como uma **operação privilegiada** – exija step-up auth & aprovação do gerente.
* Implemente regras de **Identity Threat Detection & Response (ITDR)** / **UEBA** que alertem sobre:
* Método de MFA alterado + autenticação de novo dispositivo / geo.
* Elevação imediata do mesmo principal (user-→-admin).
* Grave chamadas do help-desk e exija um **call-back para um número já registrado** antes de qualquer reset.
* Implemente **Just-In-Time (JIT) / Privileged Access** para que contas recém-resetadas não herdem automaticamente tokens de alto privilégio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Grupos commodity compensam o custo de operações de alto contato com ataques em massa que transformam **motores de busca & redes de anúncios no canal de entrega**.

1. **SEO poisoning / malvertising** empurra um resultado falso como `chromium-update[.]site` para os anúncios de topo.
2. A vítima baixa um pequeno **first-stage loader** (frequentemente JS/HTA/ISO). Exemplos vistos pela Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. O loader exfiltra cookies do browser + DBs de credenciais, então puxa um **silent loader** que decide – *em tempo real* – se vai implantar:
* RAT (por exemplo AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistência (registry Run key + scheduled task)

### Hardening tips
* Bloqueie domínios recém-registrados & aplique **Advanced DNS / URL Filtering** em *search-ads* assim como em e-mail.
* Restrinja instalação de software a pacotes MSI assinados / Store, negue execução de `HTA`, `ISO`, `VBS` por política.
* Monitore por processos filhos de browsers que abram instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Faça hunting por LOLBins frequentemente abusados por first-stage loaders (por exemplo `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Atacantes agora encadeiam **LLM & voice-clone APIs** para iscas totalmente personalizadas e interação em tempo real.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Adicione **banners dinâmicos** destacando mensagens enviadas por automação não confiável (via anomalias ARC/DKIM).  
• Implante **voice-biometric challenge phrases** para solicitações telefônicas de alto risco.  
• Simule continuamente iscas geradas por AI em programas de conscientização – templates estáticos estão obsoletos.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Além do clássico push-bombing, operadores simplesmente **forçam um novo registro de MFA** durante a ligação ao help-desk, aniquilando o token existente do usuário. Qualquer prompt de login subsequente parece legítimo para a vítima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitore eventos do AzureAD/AWS/Okta onde **`deleteMFA` + `addMFA`** ocorrem **em questão de minutos vindos do mesmo IP**.



## Clipboard Hijacking / Pastejacking

Attackers can silently copy malicious commands into the victim’s clipboard from a compromised or typosquatted web page and then trick the user to paste them inside **Win + R**, **Win + X** or a terminal window, executing arbitrary code without any download or attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## Referências

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
