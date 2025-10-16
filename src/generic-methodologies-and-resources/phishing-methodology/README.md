# Metodologia de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon da vítima
1. Selecione o **domínio da vítima**.
2. Realize alguma enumeração web básica **procurando por portais de login** usados pela vítima e **decida** qual você irá **se passar por**.
3. Use algum **OSINT** para **encontrar emails**.
2. Preparar o ambiente
1. **Compre o domínio** que você vai usar para a avaliação de phishing
2. **Configure o serviço de email** com os registros relacionados (SPF, DMARC, DKIM, rDNS)
3. Configure o VPS com **gophish**
3. Preparar a campanha
1. Prepare o **modelo de email**
2. Prepare a **página web** para roubar as credenciais
4. Inicie a campanha!

## Gerar nomes de domínio semelhantes ou comprar um domínio confiável

### Técnicas de Variação de Nome de Domínio

- **Palavra-chave**: O nome de domínio **contém** uma **palavra-chave** importante do domínio original (e.g., zelster.com-management.com).
- **subdomínio com hífen**: Trocar o **ponto por um hífen** de um subdomínio (e.g., www-zelster.com).
- **New TLD**: Mesmo domínio usando um **novo TLD** (e.g., zelster.org)
- **Homoglyph**: Substitui uma letra no nome do domínio por **letras que se parecem** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Troca duas letras dentro do nome do domínio (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adiciona ou remove “s” no final do nome de domínio (e.g., zeltsers.com).
- **Omission**: Remove uma das letras do nome de domínio (e.g., zelser.com).
- **Repetition:** Repete uma das letras no nome de domínio (e.g., zeltsser.com).
- **Replacement**: Semelhante ao homoglyph, mas menos furtivo. Substitui uma das letras do nome do domínio, possivelmente por uma letra próxima no teclado (e.g., zektser.com).
- **Subdomained**: Introduz um **ponto** dentro do nome de domínio (e.g., ze.lster.com).
- **Insertion**: Insere uma letra no nome de domínio (e.g., zerltser.com).
- **Missing dot**: Anexa o TLD ao nome de domínio. (e.g., zelstercom.com)

**Ferramentas Automáticas**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe a **possibilidade de que alguns bits armazenados ou em comunicação sejam automaticamente invertidos** devido a vários fatores como erupções solares, raios cósmicos ou erros de hardware.

Quando esse conceito é **aplicado a requisições DNS**, é possível que o **domínio recebido pelo servidor DNS** não seja o mesmo que o domínio inicialmente solicitado.

Por exemplo, uma modificação de um único bit no domínio "windows.com" pode mudá-lo para "windnws.com."

Os atacantes podem **tirar proveito disso registrando múltiplos domínios bit-flipping** que são semelhantes ao domínio da vítima. A intenção é redirecionar usuários legítimos para a infraestrutura dos atacantes.

Para mais informações leia [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Comprar um domínio confiável

Você pode procurar em [https://www.expireddomains.net/](https://www.expireddomains.net) por um domínio expirado que você possa usar.\
Para garantir que o domínio expirado que você vai comprar **já tenha um bom SEO** você pode verificar como ele está categorizado em:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descobrindo Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descobrir mais** endereços de email válidos ou **verificar os que** você já descobriu, você pode checar se é possível brute-force os servidores SMTP da vítima. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Além disso, não esqueça que se os usuários usam **qualquer portal web para acessar seus emails**, você pode verificar se ele é vulnerável a brute force de usernames e explorar a vulnerabilidade se possível.

## Configurando GoPhish

### Instalação

Você pode baixá-lo em [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Faça o download e descompacte dentro de `/opt/gophish` e execute `/opt/gophish/gophish`\
O output fornecerá uma senha para o usuário admin na porta 3333. Portanto, acesse essa porta e use essas credenciais para alterar a senha do admin. Você pode precisar tunelar essa porta para local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuração

**Configuração de certificado TLS**

Antes desta etapa, você deve ter **já comprado o domínio** que irá usar, e ele deve estar **apontando** para o **IP do VPS** onde você está configurando o **gophish**.
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

Depois adicione o domínio aos seguintes arquivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Altere também os valores das seguintes variáveis dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finalmente, modifique os arquivos **`/etc/hostname`** e **`/etc/mailname`** para o seu nome de domínio e **reinicie sua VPS.**

Agora, crie um **DNS A record** de `mail.<domain>` apontando para o **endereço IP** da VPS e um **DNS MX** record apontando para `mail.<domain>`

Agora, vamos testar o envio de um e-mail:
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
Finalize a configuração do serviço e verifique seu funcionamento:
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

Quanto mais antigo for um domínio, menos provável será que ele seja marcado como spam. Portanto, você deve aguardar o máximo possível (pelo menos 1 semana) antes da avaliação de phishing. Além disso, se você colocar uma página sobre um setor com boa reputação, a reputação obtida será melhor.

Note que, mesmo que você precise aguardar uma semana, pode terminar de configurar tudo agora.

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
### Registro DMARC (Domain-based Message Authentication, Reporting & Conformance)

Você deve **configurar um registro DMARC para o novo domínio**. Se você não sabe o que é um registro DMARC [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Você precisa criar um novo registro DNS TXT apontando o nome de host `_dmarc.<domain>` com o seguinte conteúdo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Você deve **configurar um DKIM para o novo domínio**. Se você não sabe o que é um registro DMARC [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Você precisa concatenar ambos os valores B64 que a chave DKIM gera:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste a pontuação da configuração do seu e-mail

Você pode fazer isso usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Basta acessar a página e enviar um e-mail para o endereço que eles fornecem:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Você também pode **verificar sua configuração de e-mail** enviando um e-mail para `check-auth@verifier.port25.com` e **lendo a resposta** (para isso você precisará **abrir** a porta **25** e ver a resposta no arquivo _/var/mail/root_ se você enviar o e-mail como root).\
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
Você também pode enviar **uma mensagem para um Gmail sob seu controle** e verificar os **cabeçalhos do email** na sua caixa de entrada do Gmail, `dkim=pass` deve estar presente no campo de cabeçalho `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Removendo da Blacklist do Spamhouse

A página [www.mail-tester.com](https://www.mail-tester.com) pode indicar se o seu domínio está sendo bloqueado pelo spamhouse. Você pode solicitar a remoção do seu domínio/IP em: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removendo da Blacklist da Microsoft

​​Você pode solicitar que seu domínio/IP seja removido em [https://sender.office.com/](https://sender.office.com).

## Criar & Lançar Campanha GoPhish

### Perfil de Envio

- Defina um **nome para identificar** o perfil do remetente
- Decida de qual conta você vai enviar os phishing emails. Sugestões: _noreply, support, servicedesk, salesforce..._
- Você pode deixar em branco o username e password, mas certifique-se de marcar Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Recomenda-se usar a funcionalidade "**Send Test Email**" para testar se tudo está funcionando.\
> Recomendo **enviar os e-mails de teste para endereços 10min mails** para evitar ser colocado na blacklist ao realizar testes.

### Modelo de Email

- Defina um **nome para identificar** o modelo
- Em seguida escreva um **assunto** (nada estranho, apenas algo que você poderia esperar ler em um email regular)
- Certifique-se de que marcou "**Add Tracking Image**"
- Escreva o **modelo de email** (você pode usar variáveis como no exemplo a seguir):
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

- Envie um email para um **endereço inexistente** e verifique se a resposta contém alguma assinatura.
- Procure por **emails públicos** como info@ex.com ou press@ex.com ou public@ex.com e envie-lhes um email e aguarde a resposta.
- Tente contatar **algum email válido descoberto** e aguarde a resposta

![](<../../images/image (80).png>)

> [!TIP]
> O Email Template também permite **anexar arquivos para enviar**. Se também quiser roubar NTLM challenges usando alguns arquivos/documentos especialmente crafted [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Escreva um **nome**
- **Escreva o código HTML** da página web. Note que você pode **importar** páginas web.
- Marque **Capture Submitted Data** e **Capture Passwords**
- Defina uma **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Normalmente você precisará modificar o código HTML da página e fazer alguns testes localmente (talvez usando algum servidor Apache) **até ficar satisfeito com o resultado.** Então, escreva esse código HTML na caixa.\
> Note que se precisar **usar alguns recursos estáticos** para o HTML (talvez arquivos CSS e JS) você pode salvá-los em _**/opt/gophish/static/endpoint**_ e então acessá-los a partir de _**/static/\<filename>**_

> [!TIP]
> Para a redirection você poderia **redirecionar os usuários para a página web legítima principal** da vítima, ou redirecioná-los para _/static/migration.html_ por exemplo, colocar uma **spinning wheel (**[**https://loading.io/**](https://loading.io)**) por 5 segundos e então indicar que o processo foi bem-sucedido**.

### Users & Groups

- Defina um nome
- **Importe os dados** (note que para usar o template do exemplo você precisa do firstname, last name e email address de cada usuário)

![](<../../images/image (163).png>)

### Campaign

Finalmente, crie uma campanha selecionando um nome, o email template, a landing page, o URL, o sending profile e o grupo. Note que o URL será o link enviado às vítimas

Note que o **Sending Profile permite enviar um email de teste para ver como ficará o email de phishing final**:

![](<../../images/image (192).png>)

> [!TIP]
> Eu recomendaria **enviar os emails de teste para endereços 10min mails** para evitar ser incluído em blacklists durante os testes.

Uma vez que tudo esteja pronto, é só lançar a campanha!

## Website Cloning

Se por algum motivo quiser clonar o website, confira a seguinte página:


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

O ataque anterior é bem inteligente pois você está falsificando um site real e coletando as informações inseridas pelo usuário. Infelizmente, se o usuário não inseriu a senha correta ou se a aplicação que você falsificou está configurada com 2FA, **essas informações não permitirão que você se passe pelo usuário enganado**.

É aqui que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) são úteis. Essa ferramenta permitirá que você gere um ataque MitM. Basicamente, o ataque funciona da seguinte forma:

1. Você **personifica o formulário de login** da página real.
2. O usuário **envia** suas **credenciais** para sua página falsa e a ferramenta as envia para a página real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM pedirá por ela e, uma vez que o **usuário a insira**, a ferramenta a enviará para a página web real.
4. Uma vez que o usuário esteja autenticado você (como atacante) terá **capturado as credenciais, o 2FA, o cookie e qualquer informação** de cada interação enquanto a ferramenta realiza o MitM.

### Via VNC

E se, ao invés de **enviar a vítima para uma página maliciosa** com a mesma aparência da original, você a enviar para uma **sessão VNC com um navegador conectado à página real**? Você poderá ver o que ela faz, roubar a senha, o MFA usado, os cookies...\
Você pode fazer isso com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviamente uma das melhores formas de saber se você foi pego é **procurar seu domínio em blacklists**. Se aparecer listado, de algum modo seu domínio foi detectado como suspeito.\
Uma forma fácil de verificar se seu domínio aparece em alguma blacklist é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, existem outras formas de saber se a vítima está **ativamente procurando por atividades suspeitas de phishing** no ambiente, como explicado em:


{{#ref}}
detecting-phising.md
{{#endref}}

Você pode **comprar um domínio com um nome muito parecido** ao domínio da vítima **e/ou gerar um certificado** para um **subdomínio** de um domínio controlado por você **contendo** a **keyword** do domínio da vítima. Se a **vítima** realizar qualquer tipo de **interação DNS ou HTTP** com eles, você saberá que **ela está ativamente procurando** por domínios suspeitos e precisará ser muito furtivo.

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious) para avaliar se seu email vai acabar na pasta de spam ou se será bloqueado ou bem-sucedido.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Conjuntos modernos de intrusão estão cada vez mais pulando iscas por email inteiramente e **alvejando diretamente o fluxo de trabalho do service-desk / identity-recovery** para derrotar o MFA. O ataque é totalmente "living-off-the-land": uma vez que o operador possui credenciais válidas, ele pivota com ferramentas administrativas integradas – nenhum malware é necessário.

### Attack flow
1. Recon da vítima
* Colete detalhes pessoais & corporativos do LinkedIn, vazamentos de dados, GitHub público, etc.
* Identifique identidades de alto valor (executivos, TI, finanças) e enumere o **exato processo do help-desk** para reset de senha / MFA.
2. Social engineering em tempo real
* Ligue, use Teams ou chat com o help-desk enquanto se passa pelo alvo (frequentemente com **spoofed caller-ID** ou **cloned voice**).
* Forneça o PII previamente coletado para passar na verificação baseada em conhecimento.
* Convença o agente a **resetar o segredo MFA** ou realizar um **SIM-swap** em um número de celular registrado.
3. Ações imediatas pós-acesso (≤60 min em casos reais)
* Estabeleça um foothold através de qualquer portal web SSO.
* Enumere AD / AzureAD com ferramentas integradas (nenhum binário é dropado):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimento lateral com **WMI**, **PsExec**, ou agentes legítimos de **RMM** já colocados na whitelist do ambiente.

### Detection & Mitigation
* Trate a recuperação de identidade do help-desk como uma **operação privilegiada** – exija autenticação de passo-extra & aprovação do manager.
* Implemente regras **Identity Threat Detection & Response (ITDR)** / **UEBA** que alertem sobre:
* Método de MFA alterado + autenticação a partir de novo dispositivo / geo.
* Elevação imediata do mesmo principal (user-→-admin).
* Grave as chamadas do help-desk e exija um **call-back para um número já registrado** antes de qualquer reset.
* Implemente **Just-In-Time (JIT) / Privileged Access** para que contas recém-resetadas **não** herdem automaticamente tokens de alto privilégio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Equipes commodity compensam o custo de operações high-touch com ataques em massa que transformam **motores de busca & redes de anúncios no canal de entrega**.

1. **SEO poisoning / malvertising** empurra um resultado falso como `chromium-update[.]site` para o topo dos anúncios de pesquisa.
2. A vítima baixa um pequeno **first-stage loader** (frequentemente JS/HTA/ISO). Exemplos observados pela Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. O loader exfiltra cookies do navegador + DBs de credenciais, então captura um **silent loader** que decide – *em tempo real* – se vai implantar:
* RAT (ex.: AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistência (chave Run do registro + scheduled task)

### Hardening tips
* Bloqueie domínios recém-registrados & aplique **Advanced DNS / URL Filtering** em *search-ads* assim como em e-mail.
* Restrinja instalação de software a pacotes MSI assinados / Store, negue execução de `HTA`, `ISO`, `VBS` por política.
* Monitore processos filhos de navegadores abrindo instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Caçe por LOLBins frequentemente abusados por first-stage loaders (ex.: `regsvr32`, `curl`, `mshta`).

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
• Implemente **voice-biometric challenge phrases** para solicitações telefônicas de alto risco.  
• Simule continuamente iscas geradas por IA em programas de conscientização – templates estáticos estão obsoletos.

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
Além do clássico push-bombing, operadores simplesmente **forçam um novo registro de MFA** durante a chamada para o help-desk, anulando o token existente do usuário. Qualquer prompt de login subsequente parecerá legítimo para a vítima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitore eventos do AzureAD/AWS/Okta onde **`deleteMFA` + `addMFA`** ocorram **em poucos minutos a partir do mesmo IP**.



## Clipboard Hijacking / Pastejacking

Atacantes podem, silenciosamente, copiar comandos maliciosos para o clipboard da vítima a partir de uma página web comprometida ou typosquatted e então enganar o usuário para colá‑los em **Win + R**, **Win + X** ou em uma janela de terminal, executando código arbitrário sem qualquer download ou anexo.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operadores cada vez mais colocam seus fluxos de phishing atrás de uma verificação simples de dispositivo para que crawlers de desktop nunca alcancem as páginas finais. Um padrão comum é um pequeno script que testa por um touch-capable DOM e envia o resultado para um endpoint do servidor; clientes não‑móveis recebem HTTP 500 (ou uma página em branco), enquanto usuários móveis recebem o fluxo completo.

Trecho mínimo do cliente (lógica típica):
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
- Retorna 500 (ou um placeholder) a GETs subsequentes quando `is_mobile=false`; serve phishing apenas se for `true`.

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequência de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para não‑mobile; caminhos legítimos de vítimas mobile retornam 200 com HTML/JS subsequente.
- Bloqueie ou examine com cuidado páginas que condicionam o conteúdo exclusivamente a `ontouchstart` ou verificações de dispositivo semelhantes.

Dicas de defesa:
- Execute crawlers com fingerprints semelhantes a dispositivos móveis e com JS habilitado para revelar conteúdo restrito.
- Gere alertas para respostas 500 suspeitas após `POST /detect` em domínios recém-registrados.

## Referências

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
