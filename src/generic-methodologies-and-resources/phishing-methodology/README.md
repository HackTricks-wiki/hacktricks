# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon da vítima
1. Select the **victim domain**.
2. Realize alguma enumeração web básica **procurando por portais de login** usados pela vítima e **decida** por qual deles você irá **se passar**.
3. Use **OSINT** para **encontrar emails**.
2. Prepare o ambiente
1. **Compre o domínio** que você vai usar para a avaliação de phishing
2. **Configure os registros** relacionados ao serviço de email (SPF, DMARC, DKIM, rDNS)
3. Configure o VPS com **gophish**
3. Prepare a campanha
1. Prepare o **template de email**
2. Prepare a **página web** para capturar as credenciais
4. Lance a campanha!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: O nome de domínio **contém** uma importante **palavra-chave** do domínio original (e.g., zelster.com-management.com).
- **hypened subdomain**: Troque o **ponto por um hífen** de um subdomínio (e.g., www-zelster.com).
- **New TLD**: Mesmo domínio usando uma **nova TLD** (e.g., zelster.org)
- **Homoglyph**: Substitui uma letra no nome de domínio por **letras que parecem semelhantes** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Troca duas letras dentro do nome de domínio (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adiciona ou remove “s” no final do nome de domínio (e.g., zeltsers.com).
- **Omission**: Remove uma das letras do nome de domínio (e.g., zelser.com).
- **Repetition:** Repete uma das letras no nome de domínio (e.g., zeltsser.com).
- **Replacement**: Como homoglyph, mas menos furtivo. Substitui uma das letras no nome de domínio, talvez por uma letra próxima no teclado (e.g, zektser.com).
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

Para **descobrir mais** endereços de email válidos ou **verificar os que** você já descobriu, você pode checar se é possível brute-force nos servidores SMTP da vítima. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Além disso, não se esqueça que se os usuários usam **algum portal web para acessar seus emails**, você pode verificar se ele é vulnerável a **username brute force**, e explorar a vulnerabilidade se possível.

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

Antes desta etapa você deve ter **já comprado o domínio** que vai usar e ele deve estar **apontando** para o **IP do VPS** onde você está configurando o **gophish**.
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

Finalmente modifique os arquivos **`/etc/hostname`** e **`/etc/mailname`** para o seu domínio e **reinicie seu VPS.**

Agora, crie um **DNS A record** de `mail.<domain>` apontando para o **ip address** do VPS e um **DNS MX** record apontando para `mail.<domain>`

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

### Espere e seja legítimo

Quanto mais antigo o domínio, menos provável que seja marcado como spam. Portanto, você deve esperar o máximo possível (pelo menos 1 semana) antes da avaliação de phishing. Além disso, se você colocar uma página sobre um setor com boa reputação, a reputação obtida será melhor.

Observe que, mesmo que você tenha que esperar uma semana, pode finalizar toda a configuração agora.

### Configurar registro Reverse DNS (rDNS)

Defina um registro rDNS (PTR) que resolva o endereço IP da VPS para o nome de domínio.

### Registro Sender Policy Framework (SPF)

Você deve **configurar um registro SPF para o novo domínio**. Se você não sabe o que é um registro SPF [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Você pode usar [https://www.spfwizard.net/](https://www.spfwizard.net) para gerar sua política SPF (use o IP da máquina VPS)

![](<../../images/image (1037).png>)

Este é o conteúdo que deve ser colocado dentro de um registro TXT no domínio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro DMARC (Domain-based Message Authentication, Reporting & Conformance)

Você deve **configurar um registro DMARC para o novo domínio**. Se você não sabe o que é um registro DMARC [**leia esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Você precisa criar um novo DNS TXT record apontando o hostname `_dmarc.<domain>` com o seguinte conteúdo:
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

### Teste a pontuação da sua configuração de email

Você pode fazer isso usando [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Basta acessar a página e enviar um email para o endereço que eles fornecem:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Você também pode **verificar a configuração do seu e-mail** enviando um e-mail para `check-auth@verifier.port25.com` e **lendo a resposta** (para isso você precisará **abrir** a porta **25** e ver a resposta no arquivo _/var/mail/root_ se você enviar o e-mail como root).\
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
Você também pode enviar **uma mensagem para um Gmail sob seu controle** e verificar os **cabeçalhos do e-mail** na sua caixa de entrada do Gmail; `dkim=pass` deve estar presente no campo de cabeçalho `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Removendo da Spamhouse Blacklist

A página [www.mail-tester.com](https://www.mail-tester.com) pode indicar se o seu domínio está sendo bloqueado pelo spamhouse. Você pode solicitar a remoção do seu domínio/IP em: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removendo da Microsoft Blacklist

​​Você pode solicitar a remoção do seu domínio/IP em [https://sender.office.com/](https://sender.office.com).

## Criar & Lançar Campanha GoPhish

### Perfil de Envio

- Defina um **nome para identificar** o perfil do remetente
- Decida de qual conta você vai enviar os emails de phishing. Sugestões: _noreply, support, servicedesk, salesforce..._
- Você pode deixar o nome de usuário e a senha em branco, mas certifique-se de marcar "Ignore Certificate Errors"

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> É recomendado usar a funcionalidade "**Send Test Email**" para testar se tudo está funcionando.\
> Eu recomendaria **enviar os emails de teste para endereços 10min mails** para evitar ser colocado em blacklist ao fazer testes.

### Template de Email

- Defina um **nome para identificar** o template
- Depois escreva um **assunto** (nada estranho, apenas algo que você poderia esperar ler em um email comum)
- Certifique-se de ter marcado "**Add Tracking Image**"
- Escreva o **template de email** (você pode usar variáveis como no exemplo a seguir):
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
Note que **para aumentar a credibilidade do email**, recomenda-se usar alguma assinatura de um email do cliente. Sugestões:

- Envie um email para um **endereço inexistente** e verifique se a resposta contém alguma assinatura.
- Procure **emails públicos** como info@ex.com ou press@ex.com ou public@ex.com, envie um email e aguarde a resposta.
- Tente contatar **algum email válido encontrado** e aguarde a resposta

![](<../../images/image (80).png>)

> [!TIP]
> O Email Template também permite **anexar arquivos para enviar**. Se você também quiser roubar desafios NTLM usando alguns arquivos/documentos especialmente criados [leia esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Página de Destino

- Escreva um **nome**
- **Escreva o código HTML** da página web. Note que você pode **importar** páginas web.
- Marque **Capturar Dados Enviados** e **Capturar Senhas**
- Defina uma **redireção**

![](<../../images/image (826).png>)

> [!TIP]
> Normalmente você precisará modificar o código HTML da página e fazer alguns testes localmente (talvez usando algum servidor Apache) **até obter os resultados desejados.** Então, insira esse código HTML na caixa.\
> Observe que se você precisar **usar alguns recursos estáticos** para o HTML (talvez alguns arquivos CSS e JS) você pode salvá‑los em _**/opt/gophish/static/endpoint**_ e então acessá‑los de _**/static/\<filename>**_

> [!TIP]
> Para a redireção você pode **redirecionar os usuários para a página web principal legítima** da vítima, ou redirecioná‑los para _/static/migration.html_, por exemplo, colocar um **spinning wheel (**[**https://loading.io/**](https://loading.io)**) por 5 segundos e então indicar que o processo foi bem-sucedido**.

### Usuários & Grupos

- Defina um nome
- **Importe os dados** (note que para usar o template do exemplo você precisa do firstname, last name e email address de cada usuário)

![](<../../images/image (163).png>)

### Campanha

Finalmente, crie uma campanha selecionando um nome, o template de email, a página de destino, a URL, o perfil de envio e o grupo. Note que a URL será o link enviado às vítimas

Note que o **Perfil de Envio permite enviar um email de teste para ver como o email de phishing final ficará**:

![](<../../images/image (192).png>)

> [!TIP]
> Eu recomendaria **enviar os emails de teste para endereços 10min mail** para evitar ser colocado em blacklist ao fazer testes.

Quando tudo estiver pronto, apenas lance a campanha!

## Clonagem de Website

Se por algum motivo você quiser clonar o website confira a seguinte página:


{{#ref}}
clone-a-website.md
{{#endref}}

## Documentos & Arquivos com Backdoor

Em algumas avaliações de phishing (principalmente para Red Teams) você também vai querer **enviar arquivos contendo algum tipo de backdoor** (talvez um C2 ou talvez algo que apenas dispare uma autenticação).\
Confira a seguinte página para alguns exemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

O ataque anterior é bastante inteligente, pois você está falsificando um website real e reunindo as informações inseridas pelo usuário. Infelizmente, se o usuário não inseriu a senha correta ou se a aplicação que você falsificou está configurada com 2FA, **essa informação não permitirá que você se passe pelo usuário enganado**.

É aí que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) são úteis. Essa ferramenta permitirá que você gere um ataque tipo MitM. Basicamente, o ataque funciona da seguinte forma:

1. Você **se faz passar pelo formulário de login** da página real.
2. O usuário **envia** suas **credenciais** para sua página falsa e a ferramenta as envia para a página real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM pedirá por ela e, uma vez que o **usuário a insira**, a ferramenta a enviará para a página real.
4. Uma vez que o usuário está autenticado, você (como atacante) terá **capturado as credenciais, a 2FA, o cookie e qualquer informação** de cada interação enquanto a ferramenta estiver realizando o MitM.

### Via VNC

E se em vez de **enviar a vítima para uma página maliciosa** com a mesma aparência da original, você a enviar para uma **sessão VNC com um navegador conectado à página real**? Você será capaz de ver o que ela faz, roubar a senha, o MFA usado, os cookies...\
Você pode fazer isso com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detectando a detecção

Obviamente uma das melhores maneiras de saber se você foi pego é **procurar seu domínio em blacklists**. Se aparecer listado, de alguma forma seu domínio foi detectado como suspeito.\
Uma maneira fácil de verificar se seu domínio aparece em alguma blacklist é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, existem outras maneiras de saber se a vítima está **ativamente procurando por atividade de phishing suspeita em circulação** como explicado em:


{{#ref}}
detecting-phising.md
{{#endref}}

Você pode **comprar um domínio com um nome muito semelhante** ao domínio da vítima **e/ou gerar um certificado** para um **subdomínio** de um domínio controlado por você **contendo** a **palavra-chave** do domínio da vítima. Se a **vítima** realizar qualquer tipo de **interação DNS ou HTTP** com eles, você saberá que **ela está ativamente procurando** por domínios suspeitos e você terá que ser muito furtivo.

### Avaliar o phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)para avaliar se seu email vai terminar na pasta spam, se será bloqueado ou se terá sucesso.

## Comprometimento de Identidade de Alta Interação (Reset de MFA via Help-Desk)

Conjuntos de intrusão modernos cada vez mais pulam iscas por email inteiramente e **alvo diretamente o fluxo de trabalho do service-desk / recuperação de identidade** para derrotar o MFA. O ataque é totalmente "living-off-the-land": uma vez que o operador possui credenciais válidas, ele pivota com ferramentas administrativas embutidas – nenhum malware é necessário.

### Fluxo do ataque
1. Recon da vítima
* Colete detalhes pessoais & corporativos do LinkedIn, vazamentos de dados, GitHub público, etc.
* Identifique identidades de alto valor (executivos, TI, finanças) e enumere o **processo exato do help-desk** para reset de senha / MFA.
2. Engenharia social em tempo real
* Ligue, use Teams ou chat com o help-desk enquanto se passa pelo alvo (frequentemente com **caller-ID falsificado** ou **voz clonada**).
* Forneça os PII coletados anteriormente para passar na verificação baseada em conhecimento.
* Convença o agente a **resetar o segredo de MFA** ou realizar um **SIM-swap** em um número de celular registrado.
3. Ações imediatas pós-acesso (≤60 min em casos reais)
* Estabeleça um foothold através de qualquer portal web SSO.
* Enumere AD / AzureAD com ferramentas embutidas (nenhum binário é dropado):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimento lateral com **WMI**, **PsExec**, ou agentes legítimos de **RMM** já liberados no ambiente.

### Detecção & Mitigação
* Trate a recuperação de identidade via help-desk como uma **operação privilegiada** – exija autenticação step-up & aprovação do gerente.
* Implemente regras de **Identity Threat Detection & Response (ITDR)** / **UEBA** que alertem sobre:
* Método de MFA alterado + autenticação de novo dispositivo / nova geo.
* Elevação imediata do mesmo principal (usuário → admin).
* Grave chamadas do help-desk e exija um **call-back para um número já registrado** antes de qualquer reset.
* Implemente **Just-In-Time (JIT) / Privileged Access** para que contas recém-resetadas **não** herdem automaticamente tokens de alto privilégio.

---

## Engano em Larga Escala – SEO Poisoning & Campanhas “ClickFix”
Grupos commodity compensam o custo de operações de alta interação com ataques em massa que transformam **motores de busca & redes de anúncios no canal de entrega**.

1. **SEO poisoning / malvertising** empurra um resultado falso como `chromium-update[.]site` para o topo dos anúncios de busca.
2. A vítima baixa um pequeno **first-stage loader** (frequentemente JS/HTA/ISO). Exemplos observados pela Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. O loader exfiltra cookies do navegador + DBs de credenciais, então baixa um **silent loader** que decide – *em tempo real* – se deve implantar:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistência (chave Run do registro + tarefa agendada)

### Dicas de hardening
* Bloqueie domínios recém-registrados & aplique **Advanced DNS / URL Filtering** em *search-ads* bem como em e-mail.
* Restrinja a instalação de software a pacotes MSI assinados / Store, negue execução de `HTA`, `ISO`, `VBS` por política.
* Monitore por processos filhos de navegadores abrindo instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Faça hunting por LOLBins frequentemente abusados por first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

---

## Operações de Phishing Aprimoradas por AI
Agentes agora encadeiam **LLM & voice-clone APIs** para iscas totalmente personalizadas e interação em tempo real.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defesa:**
• Adicione **banners dinâmicos** destacando mensagens enviadas por automação não confiável (via anomalias ARC/DKIM).  
• Implemente **challenge phrases biométricos de voz** para pedidos telefônicos de alto risco.  
• Simule continuamente iscas geradas por AI em programas de conscientização – templates estáticos estão obsoletos.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Além do clássico push-bombing, operadores simplesmente **forçam um novo registro de MFA** durante a chamada ao help-desk, anulando o token existente do usuário. Qualquer prompt de login subsequente parece legítimo para a vítima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitore eventos do AzureAD/AWS/Okta em que **`deleteMFA` + `addMFA`** ocorram **em questão de minutos a partir do mesmo IP**.



## Clipboard Hijacking / Pastejacking

Os atacantes podem copiar silenciosamente comandos maliciosos para o clipboard da vítima a partir de uma página web comprometida ou typosquatted e então enganar o usuário para colá‑los dentro de **Win + R**, **Win + X** ou de uma janela de terminal, executando código arbitrário sem qualquer download ou anexo.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operadores cada vez mais protegem seus fluxos de phishing por trás de uma verificação simples do dispositivo, para que crawlers de desktop nunca alcancem as páginas finais. Um padrão comum é um pequeno script que testa se o DOM tem suporte a toque e envia o resultado para um endpoint do servidor; clientes não‑mobile recebem HTTP 500 (ou uma página em branco), enquanto usuários mobile recebem o fluxo completo.

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
- Retorna 500 (ou placeholder) às requisições GET subsequentes quando `is_mobile=false`; serve phishing apenas se `true`.

Heurísticas de hunting e detecção:
- Consulta urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequência de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para dispositivos não móveis; caminhos legítimos de vítimas móveis retornam 200 com HTML/JS subsequente.
- Bloquear ou escrutinar páginas que condicionam conteúdo exclusivamente a `ontouchstart` ou verificações de dispositivo similares.

Dicas de defesa:
- Execute crawlers com fingerprints semelhantes a dispositivos mobile e JS habilitado para revelar conteúdo restrito.
- Gerar alertas para respostas 500 suspeitas após `POST /detect` em domínios recém-registrados.

## Referências

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
