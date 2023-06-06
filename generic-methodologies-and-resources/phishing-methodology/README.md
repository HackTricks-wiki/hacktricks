# Metodologia de Phishing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Metodologia

1. Reconheça a vítima
   1. Selecione o **domínio da vítima**.
   2. Realize alguma enumeração web básica **procurando por portais de login** usados pela vítima e **decida** qual você irá **fingir ser**.
   3. Use algum **OSINT** para **encontrar e-mails**.
2. Prepare o ambiente
   1. **Compre o domínio** que você vai usar para a avaliação de phishing.
   2. **Configure os registros relacionados ao serviço de e-mail** (SPF, DMARC, DKIM, rDNS)
   3. Configure o VPS com **gophish**
3. Prepare a campanha
   1. Prepare o **modelo de e-mail**
   2. Prepare a **página da web** para roubar as credenciais
4. Inicie a campanha!

## Gerar nomes de domínio semelhantes ou comprar um domínio confiável

### Técnicas de variação de nome de domínio

* **Palavra-chave**: O nome de domínio **contém** uma **palavra-chave** importante do domínio original (por exemplo, zelster.com-management.com).
* **Subdomínio hifenizado**: Troque o **ponto por um hífen** de um subdomínio (por exemplo, www-zelster.com).
* **Novo TLD**: Mesmo domínio usando um **novo TLD** (por exemplo, zelster.org)
* **Homógrafo**: Ele **substitui** uma letra no nome de domínio por **letras que se parecem** (por exemplo, zelfser.com).
* **Transposição:** Ele **troca duas letras** dentro do nome de domínio (por exemplo, zelster.com).
* **Singularização/Pluralização**: Adiciona ou remove "s" no final do nome de domínio (por exemplo, zeltsers.com).
* **Omissão**: Ele **remove uma** das letras do nome de domínio (por exemplo, zelser.com).
* **Repetição**: Ele **repete uma** das letras no nome de domínio (por exemplo, zeltsser.com).
* **Subdominado**: Introduza um **ponto** dentro do nome de domínio (por exemplo, ze.lster.com).
* **Inserção**: Ele **insere uma letra** no nome de domínio (por exemplo, zerltser.com).
* **Ponto ausente**: Adicione o TLD ao nome de domínio. (por exemplo, zelstercom.com)

**Ferramentas automáticas**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

No mundo da computação, tudo é armazenado em bits (zeros e uns) na memória nos bastidores.\
Isso se aplica a domínios também. Por exemplo, _windows.com_ se torna _01110111..._ na memória volátil do seu dispositivo de computação.\
No entanto, e se um desses bits fosse automaticamente invertido devido a uma erupção solar, raios cósmicos ou um erro de hardware? Ou seja, um dos 0's se torna 1 e vice-versa.\
Aplicando esse conceito à solicitação DNS, é possível que o **domínio solicitado** que chega ao servidor DNS **não seja o mesmo que o domínio inicialmente solicitado**.

Por exemplo, uma modificação de 1 bit no domínio windows.com pode transformá-lo em _windnws.com._\
**Os atacantes podem registrar o maior número possível de domínios de bit-flipping relacionados à vítima para redirecionar usuários legítimos para sua infraestrutura**.

Para mais informações, leia [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Compre um domínio confiável

Você pode procurar em [https://www.expireddomains.net/](https://www.expireddomains.net) por um domínio expirado que você possa usar.\
Para ter certeza de que o domínio expirado que você vai comprar **já tem um bom SEO**, você pode verificar como ele é categorizado em:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descobrindo e-mails

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
* [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Para **descobrir mais** endereços de e-mail válidos ou **verificar os que** você já descobriu, você pode verificar se pode fazer brute-force nos servidores smtp da vítima. [Aprenda como verificar/descobrir endereço de e-mail aqui](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Além disso, não se esqueça de que se os usuários usarem **qualquer portal da web para acessar seus e-mails**, você pode verificar se ele é vulnerável a **brute force de nome de usuário**, e explorar a vulnerabilidade, se possível.

## Configurando o GoPhish

### Instalação

Você pode baixá-lo em [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Baixe e descompacte-o dentro de `/opt/gophish` e execute `/opt/gophish
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuração

**Configuração do certificado TLS**

Antes deste passo, você deve **ter comprado o domínio** que irá utilizar e ele deve estar **apontando** para o **IP do VPS** onde você está configurando o **gophish**.
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

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Altere também os valores das seguintes variáveis dentro de /etc/postfix/main.cf**

`myhostname = <domínio>`\
`mydestination = $myhostname, <domínio>, localhost.com, localhost`

Por fim, modifique os arquivos **`/etc/hostname`** e **`/etc/mailname`** para o nome do seu domínio e **reinicie seu VPS.**

Agora, crie um **registro A DNS** de `mail.<domínio>` apontando para o **endereço IP** do VPS e um **registro MX DNS** apontando para `mail.<domínio>`

Agora vamos testar o envio de um e-mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuração do Gophish**

Pare a execução do Gophish e vamos configurá-lo.\
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

### Aguarde

Quanto mais antigo for um domínio, menos provável é que ele seja considerado como spam. Então, você deve esperar o máximo de tempo possível (pelo menos 1 semana) antes da avaliação de phishing.\
Observe que mesmo que você tenha que esperar uma semana, pode terminar de configurar tudo agora.

### Configurar registro de DNS reverso (rDNS)

Defina um registro rDNS (PTR) que resolva o endereço IP do VPS para o nome de domínio.

### Registro de Política do Remetente (SPF)

Você deve **configurar um registro SPF para o novo domínio**. Se você não sabe o que é um registro SPF, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/#spf).

Você pode usar [https://www.spfwizard.net/](https://www.spfwizard.net) para gerar sua política SPF (use o IP da máquina VPS)

![](<../../.gitbook/assets/image (388).png>)

Este é o conteúdo que deve ser definido dentro de um registro TXT dentro do domínio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro de Autenticação, Relatório e Conformidade de Mensagens Baseadas em Domínio (DMARC)

Você deve **configurar um registro DMARC para o novo domínio**. Se você não sabe o que é um registro DMARC, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Você deve criar um novo registro DNS TXT apontando para o nome do host `_dmarc.<domínio>` com o seguinte conteúdo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Você deve **configurar um DKIM para o novo domínio**. Se você não sabe o que é um registro DMARC, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/#dkim).

Este tutorial é baseado em: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Você precisa concatenar ambos os valores B64 que a chave DKIM gera:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Teste a pontuação de configuração do seu e-mail

Você pode fazer isso usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Basta acessar a página e enviar um e-mail para o endereço que eles fornecem:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Você também pode **verificar a configuração do seu e-mail** enviando um e-mail para `check-auth@verifier.port25.com` e **lendo a resposta** (para isso, você precisará **abrir** a porta **25** e ver a resposta no arquivo _/var/mail/root_ se enviar o e-mail como root).\
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
Alternativamente, você pode enviar uma **mensagem para um endereço do Gmail que você controle**, **visualizar** os **cabeçalhos do email** recebido na sua caixa de entrada do Gmail, `dkim=pass` deve estar presente no campo de cabeçalho `Authentication-Results`.
```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```
### Removendo da Lista Negra do Spamhouse

A página www.mail-tester.com pode indicar se o seu domínio está sendo bloqueado pelo Spamhouse. Você pode solicitar a remoção do seu domínio/IP em: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removendo da Lista Negra da Microsoft

Você pode solicitar a remoção do seu domínio/IP em [https://sender.office.com/](https://sender.office.com).

## Criar e Lançar Campanha GoPhish

### Perfil de Envio

* Defina um **nome para identificar** o perfil do remetente
* Decida a partir de qual conta você vai enviar os e-mails de phishing. Sugestões: _noreply, support, servicedesk, salesforce..._
* Você pode deixar em branco o nome de usuário e a senha, mas certifique-se de marcar a opção Ignorar Erros de Certificado

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (11).png>)

{% hint style="info" %}
É recomendado usar a funcionalidade "**Enviar E-mail de Teste**" para testar se tudo está funcionando.\
Eu recomendaria **enviar os e-mails de teste para endereços de e-mail de 10 minutos** para evitar ser colocado em listas negras durante os testes.
{% endhint %}

### Modelo de E-mail

* Defina um **nome para identificar** o modelo
* Em seguida, escreva um **assunto** (nada estranho, apenas algo que você esperaria ler em um e-mail regular)
* Certifique-se de ter marcado "**Adicionar Imagem de Rastreamento**"
* Escreva o **modelo de e-mail** (você pode usar variáveis como no exemplo a seguir):
```markup
<html>
<head>
    <title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>

<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">As you may be aware, due to the large number of employees working from home, the "PLATFORM NAME" platform is being migrated to a new domain with an improved and more secure version. To finalize account migration, please use the following link to log into the new HR portal and move your account to the new site: <a href="{{.URL}}"> "PLATFORM NAME" login portal </a><br />
<br />
Please Note: We require all users to move their accounts by 04/01/2021. Failure to confirm account migration may prevent you from logging into the application after the migration process is complete.<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Observe que, **para aumentar a credibilidade do e-mail**, é recomendável usar alguma assinatura de um e-mail do cliente. Sugestões:

* Envie um e-mail para um **endereço inexistente** e verifique se a resposta tem alguma assinatura.
* Procure por **e-mails públicos** como info@ex.com ou press@ex.com ou public@ex.com e envie um e-mail para eles e aguarde a resposta.
* Tente entrar em contato com algum e-mail **válido descoberto** e aguarde a resposta.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
O modelo de e-mail também permite **anexar arquivos para enviar**. Se você também deseja roubar desafios NTLM usando alguns arquivos/documentos especialmente criados, [leia esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Página de destino

* Escreva um **nome**
* **Escreva o código HTML** da página da web. Observe que você pode **importar** páginas da web.
* Marque **Capturar dados enviados** e **Capturar senhas**
* Defina uma **redireção**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Normalmente, você precisará modificar o código HTML da página e fazer alguns testes localmente (talvez usando algum servidor Apache) **até que goste dos resultados**. Em seguida, escreva esse código HTML na caixa.\
Observe que, se você precisar **usar alguns recursos estáticos** para o HTML (talvez algumas páginas CSS e JS), poderá salvá-los em _**/opt/gophish/static/endpoint**_ e acessá-los em _**/static/\<filename>**_
{% endhint %}

{% hint style="info" %}
Para a redireção, você pode **redirecionar os usuários para a página principal legítima** da vítima ou redirecioná-los para _/static/migration.html_, por exemplo, colocar uma **roda giratória** ([**https://loading.io/**](https://loading.io)) por 5 segundos e, em seguida, indicar que o processo foi bem-sucedido.
{% endhint %}

### Usuários e grupos

* Defina um nome
* **Importe os dados** (observe que, para usar o modelo para o exemplo, você precisa do nome, sobrenome e endereço de e-mail de cada usuário)

![](<../../.gitbook/assets/image (395).png>)

### Campanha

Por fim, crie uma campanha selecionando um nome, o modelo de e-mail, a página de destino, a URL, o perfil de envio e o grupo. Observe que a URL será o link enviado para as vítimas.

Observe que o **Perfil de envio permite enviar um e-mail de teste para ver como será o e-mail de phishing final**:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Eu recomendaria **enviar os e-mails de teste para endereços de e-mail de 10 minutos** para evitar ser bloqueado durante os testes.
{% endhint %}

Assim que tudo estiver pronto, basta lançar a campanha!

## Clonagem de site

Se, por algum motivo, você quiser clonar o site, verifique a seguinte página:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Documentos e arquivos com backdoor

Em algumas avaliações de phishing (principalmente para Red Teams), você também desejará **enviar arquivos contendo algum tipo de backdoor** (talvez um C2 ou talvez apenas algo que acionará uma autenticação).\
Confira a seguinte página para alguns exemplos:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Via Proxy MitM

O ataque anterior é bastante inteligente, pois você está falsificando um site real e coletando as informações definidas pelo usuário. Infelizmente, se o usuário não colocou a senha correta ou se o aplicativo que você falsificou está configurado com 2FA, **essas informações não permitirão que você se faça passar pelo usuário enganado**.

É aqui que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2) ou [**CredSniper**](https://github.com/ustayready/CredSniper) são úteis. Essa ferramenta permitirá que você gere um ataque como MitM. Basicamente, o ataque funciona da seguinte maneira:

1. Você **falsifica o formulário de login** da página da web real.
2. O usuário **envia** suas **credenciais** para sua página falsa e a ferramenta as envia para a página da web real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM solicitará isso e, assim que o **usuário o introduzir**, a ferramenta o enviará para a página da web real.
4. Depois que o usuário estiver autenticado, você (como atacante) terá **capturado as credenciais, o 2FA, o cookie e qualquer informação** de cada interação sua enquanto a ferramenta estiver realizando um MitM.

### Via VNC

E se, em vez de **enviar a vítima para uma página maliciosa** com a mesma aparência da original, você a enviar para uma **sessão VNC com um navegador conectado à página da web real**? Você poderá ver o que ele faz, roubar a senha, o MFA usado, os cookies...\
Você pode fazer isso com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detectando a detecção

Obviamente, uma das melhores maneiras de saber se você foi descoberto é **procurar seu domínio em listas negras**. Se ele aparecer listado, de alguma forma, seu domínio foi detectado como suspeito.\
Uma maneira fácil de verificar se seu domínio aparece em alguma lista negra é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, existem outras maneiras de saber se a vítima está **procurando ativamente atividade de phishing suspeita na natureza**, conforme explicado em:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Você pode **comprar um domínio com um nome muito semelhante** ao domínio da vítima e/ou gerar um certificado para um **subdomínio** de um domínio controlado por você **contendo** a **palavra-chave** do domínio da vítima. Se a **vítima** realizar algum tipo de **interação DNS ou HTTP** com eles, você saberá que **ele está procurando ativamente** domínios suspeitos e você precisará ser muito furtivo.

### Avalie o phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)para avaliar se seu e-mail será enviado para a pasta de spam ou se será bloqueado ou bem-sucedido.

## Referências

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<
