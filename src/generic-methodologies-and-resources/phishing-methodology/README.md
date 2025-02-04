# Metodologia de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Reconhecer a vítima
1. Selecionar o **domínio da vítima**.
2. Realizar uma enumeração web básica **procurando por portais de login** usados pela vítima e **decidir** qual você irá **imitar**.
3. Usar algum **OSINT** para **encontrar e-mails**.
2. Preparar o ambiente
1. **Comprar o domínio** que você vai usar para a avaliação de phishing.
2. **Configurar o serviço de e-mail** relacionado (SPF, DMARC, DKIM, rDNS).
3. Configurar o VPS com **gophish**.
3. Preparar a campanha
1. Preparar o **modelo de e-mail**.
2. Preparar a **página web** para roubar as credenciais.
4. Lançar a campanha!

## Gerar nomes de domínio semelhantes ou comprar um domínio confiável

### Técnicas de Variação de Nome de Domínio

- **Palavra-chave**: O nome do domínio **contém** uma **palavra-chave** importante do domínio original (por exemplo, zelster.com-management.com).
- **subdomínio hifenizado**: Mudar o **ponto por um hífen** de um subdomínio (por exemplo, www-zelster.com).
- **Novo TLD**: Mesmo domínio usando um **novo TLD** (por exemplo, zelster.org).
- **Homoglyph**: **Substitui** uma letra no nome do domínio por **letras que parecem semelhantes** (por exemplo, zelfser.com).
- **Transposição:** **Troca duas letras** dentro do nome do domínio (por exemplo, zelsetr.com).
- **Singularização/Pluralização**: Adiciona ou remove “s” no final do nome do domínio (por exemplo, zeltsers.com).
- **Omissão**: **Remove uma** das letras do nome do domínio (por exemplo, zelser.com).
- **Repetição:** **Repete uma** das letras no nome do domínio (por exemplo, zeltsser.com).
- **Substituição**: Como homoglyph, mas menos furtivo. Substitui uma das letras no nome do domínio, talvez por uma letra próxima da letra original no teclado (por exemplo, zektser.com).
- **Subdominado**: Introduz um **ponto** dentro do nome do domínio (por exemplo, ze.lster.com).
- **Inserção**: **Insere uma letra** no nome do domínio (por exemplo, zerltser.com).
- **Ponto ausente**: Anexa o TLD ao nome do domínio. (por exemplo, zelstercom.com)

**Ferramentas Automáticas**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Há uma **possibilidade de que alguns bits armazenados ou em comunicação possam ser automaticamente invertidos** devido a vários fatores, como flares solares, raios cósmicos ou erros de hardware.

Quando esse conceito é **aplicado a solicitações DNS**, é possível que o **domínio recebido pelo servidor DNS** não seja o mesmo que o domínio inicialmente solicitado.

Por exemplo, uma única modificação de bit no domínio "windows.com" pode mudá-lo para "windnws.com".

Os atacantes podem **se aproveitar disso registrando vários domínios de bit-flipping** que são semelhantes ao domínio da vítima. A intenção deles é redirecionar usuários legítimos para sua própria infraestrutura.

Para mais informações, leia [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Comprar um domínio confiável

Você pode procurar em [https://www.expireddomains.net/](https://www.expireddomains.net) por um domínio expirado que você poderia usar.\
Para garantir que o domínio expirado que você vai comprar **já tenha um bom SEO**, você pode verificar como ele está categorizado em:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descobrindo E-mails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descobrir mais** endereços de e-mail válidos ou **verificar os que você já descobriu**, você pode verificar se consegue forçar os servidores smtp da vítima. [Aprenda como verificar/descobrir endereços de e-mail aqui](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Além disso, não se esqueça de que se os usuários usarem **qualquer portal web para acessar seus e-mails**, você pode verificar se ele é vulnerável a **força bruta de nome de usuário** e explorar a vulnerabilidade, se possível.

## Configurando GoPhish

### Instalação

Você pode baixá-lo em [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Baixe e descompacte-o dentro de `/opt/gophish` e execute `/opt/gophish/gophish`\
Você receberá uma senha para o usuário admin na porta 3333 na saída. Portanto, acesse essa porta e use essas credenciais para alterar a senha do admin. Você pode precisar redirecionar essa porta para local:
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
**Configuração de Mail**

Comece instalando: `apt-get install postfix`

Em seguida, adicione o domínio aos seguintes arquivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Altere também os valores das seguintes variáveis dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finalmente, modifique os arquivos **`/etc/hostname`** e **`/etc/mailname`** para o seu nome de domínio e **reinicie seu VPS.**

Agora, crie um **registro DNS A** de `mail.<domain>` apontando para o **endereço IP** do VPS e um **registro DNS MX** apontando para `mail.<domain>`

Agora vamos testar o envio de um email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuração do Gophish**

Pare a execução do gophish e vamos configurá-lo.\
Modifique `/opt/gophish/config.json` para o seguinte (note o uso de https):
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
## Configurando servidor de email e domínio

### Espere e seja legítimo

Quanto mais antigo for um domínio, menos provável é que ele seja identificado como spam. Portanto, você deve esperar o máximo de tempo possível (pelo menos 1 semana) antes da avaliação de phishing. Além disso, se você colocar uma página sobre um setor reputacional, a reputação obtida será melhor.

Observe que, mesmo que você tenha que esperar uma semana, pode terminar de configurar tudo agora.

### Configure o registro de DNS reverso (rDNS)

Defina um registro rDNS (PTR) que resolva o endereço IP do VPS para o nome do domínio.

### Registro de Sender Policy Framework (SPF)

Você deve **configurar um registro SPF para o novo domínio**. Se você não sabe o que é um registro SPF [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Você pode usar [https://www.spfwizard.net/](https://www.spfwizard.net) para gerar sua política SPF (use o IP da máquina VPS)

![](<../../images/image (1037).png>)

Este é o conteúdo que deve ser definido dentro de um registro TXT no domínio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Você deve **configurar um registro DMARC para o novo domínio**. Se você não sabe o que é um registro DMARC [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Você deve criar um novo registro DNS TXT apontando para o nome do host `_dmarc.<domain>` com o seguinte conteúdo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Você deve **configurar um DKIM para o novo domínio**. Se você não sabe o que é um registro DMARC [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Este tutorial é baseado em: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!NOTE]
> Você precisa concatenar ambos os valores B64 que a chave DKIM gera:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste sua pontuação de configuração de e-mail

Você pode fazer isso usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Basta acessar a página e enviar um e-mail para o endereço que eles fornecem:
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
Você também pode enviar **uma mensagem para um Gmail sob seu controle** e verificar os **cabeçalhos do email** na sua caixa de entrada do Gmail, `dkim=pass` deve estar presente no campo de cabeçalho `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removendo da Lista Negra do Spamhouse

A página [www.mail-tester.com](https://www.mail-tester.com) pode indicar se seu domínio está sendo bloqueado pelo spamhouse. Você pode solicitar a remoção do seu domínio/IP em: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removendo da Lista Negra da Microsoft

​​Você pode solicitar a remoção do seu domínio/IP em [https://sender.office.com/](https://sender.office.com).

## Criar e Lançar Campanha GoPhish

### Perfil de Envio

- Defina um **nome para identificar** o perfil do remetente
- Decida de qual conta você vai enviar os emails de phishing. Sugestões: _noreply, support, servicedesk, salesforce..._
- Você pode deixar em branco o nome de usuário e a senha, mas certifique-se de marcar a opção Ignorar Erros de Certificado

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!NOTE]
> É recomendado usar a funcionalidade "**Enviar Email de Teste**" para testar se tudo está funcionando.\
> Eu recomendaria **enviar os emails de teste para endereços de 10min** a fim de evitar ser colocado na lista negra durante os testes.

### Modelo de Email

- Defina um **nome para identificar** o modelo
- Em seguida, escreva um **assunto** (nada estranho, apenas algo que você poderia esperar ler em um email regular)
- Certifique-se de que você marcou "**Adicionar Imagem de Rastreamento**"
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
Note que **para aumentar a credibilidade do e-mail**, é recomendável usar alguma assinatura de um e-mail do cliente. Sugestões:

- Envie um e-mail para um **endereço inexistente** e verifique se a resposta tem alguma assinatura.
- Pesquise por **e-mails públicos** como info@ex.com ou press@ex.com ou public@ex.com e envie um e-mail para eles e aguarde a resposta.
- Tente contatar **algum e-mail válido descoberto** e aguarde a resposta.

![](<../../images/image (80).png>)

> [!NOTE]
> O Modelo de E-mail também permite **anexar arquivos para enviar**. Se você também gostaria de roubar desafios NTLM usando alguns arquivos/documentos especialmente elaborados [leia esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Página de Destino

- Escreva um **nome**
- **Escreva o código HTML** da página da web. Note que você pode **importar** páginas da web.
- Marque **Capturar Dados Enviados** e **Capturar Senhas**
- Defina uma **redireção**

![](<../../images/image (826).png>)

> [!NOTE]
> Normalmente, você precisará modificar o código HTML da página e fazer alguns testes localmente (talvez usando algum servidor Apache) **até que você goste dos resultados.** Então, escreva esse código HTML na caixa.\
> Note que se você precisar **usar alguns recursos estáticos** para o HTML (talvez algumas páginas CSS e JS) você pode salvá-los em _**/opt/gophish/static/endpoint**_ e então acessá-los de _**/static/\<filename>**_

> [!NOTE]
> Para a redireção, você poderia **redirecionar os usuários para a página principal legítima** da vítima, ou redirecioná-los para _/static/migration.html_, por exemplo, colocar alguma **roda giratória (**[**https://loading.io/**](https://loading.io)**) por 5 segundos e então indicar que o processo foi bem-sucedido**.

### Usuários & Grupos

- Defina um nome
- **Importe os dados** (note que para usar o modelo para o exemplo você precisa do primeiro nome, sobrenome e endereço de e-mail de cada usuário)

![](<../../images/image (163).png>)

### Campanha

Finalmente, crie uma campanha selecionando um nome, o modelo de e-mail, a página de destino, a URL, o perfil de envio e o grupo. Note que a URL será o link enviado para as vítimas.

Note que o **Perfil de Envio permite enviar um e-mail de teste para ver como será o e-mail de phishing final**:

![](<../../images/image (192).png>)

> [!NOTE]
> Eu recomendaria **enviar os e-mails de teste para endereços de e-mail de 10 minutos** para evitar ser colocado na lista negra durante os testes.

Uma vez que tudo esteja pronto, basta lançar a campanha!

## Clonagem de Site

Se por algum motivo você quiser clonar o site, verifique a seguinte página:

{{#ref}}
clone-a-website.md
{{#endref}}

## Documentos & Arquivos com Backdoor

Em algumas avaliações de phishing (principalmente para Red Teams) você também vai querer **enviar arquivos contendo algum tipo de backdoor** (talvez um C2 ou talvez apenas algo que acionará uma autenticação).\
Confira a seguinte página para alguns exemplos:

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

O ataque anterior é bastante inteligente, pois você está falsificando um site real e coletando as informações fornecidas pelo usuário. Infelizmente, se o usuário não inserir a senha correta ou se o aplicativo que você falsificou estiver configurado com 2FA, **essa informação não permitirá que você se passe pelo usuário enganado**.

É aqui que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) são úteis. Essa ferramenta permitirá que você gere um ataque do tipo MitM. Basicamente, os ataques funcionam da seguinte maneira:

1. Você **falsifica o formulário de login** da página da web real.
2. O usuário **envia** suas **credenciais** para sua página falsa e a ferramenta as envia para a página da web real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM pedirá isso e, uma vez que o **usuário o introduza**, a ferramenta o enviará para a página da web real.
4. Uma vez que o usuário esteja autenticado, você (como atacante) terá **capturado as credenciais, o 2FA, o cookie e qualquer informação** de cada interação enquanto a ferramenta está realizando um MitM.

### Via VNC

E se em vez de **enviar a vítima para uma página maliciosa** com a mesma aparência da original, você a enviar para uma **sessão VNC com um navegador conectado à página da web real**? Você poderá ver o que ele faz, roubar a senha, o MFA usado, os cookies...\
Você pode fazer isso com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detectando a detecção

Obviamente, uma das melhores maneiras de saber se você foi descoberto é **pesquisar seu domínio em listas negras**. Se ele aparecer listado, de alguma forma seu domínio foi detectado como suspeito.\
Uma maneira fácil de verificar se seu domínio aparece em alguma lista negra é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, existem outras maneiras de saber se a vítima está **ativamente procurando por atividades de phishing suspeitas na web**, conforme explicado em:

{{#ref}}
detecting-phising.md
{{#endref}}

Você pode **comprar um domínio com um nome muito semelhante** ao domínio da vítima **e/ou gerar um certificado** para um **subdomínio** de um domínio controlado por você **contendo** a **palavra-chave** do domínio da vítima. Se a **vítima** realizar qualquer tipo de **interação DNS ou HTTP** com eles, você saberá que **ela está ativamente procurando** por domínios suspeitos e você precisará ser muito discreto.

### Avaliar o phishing

Use [**Phishious** ](https://github.com/Rices/Phishious) para avaliar se seu e-mail vai acabar na pasta de spam ou se será bloqueado ou bem-sucedido.

## Referências

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{{#include ../../banners/hacktricks-training.md}}
