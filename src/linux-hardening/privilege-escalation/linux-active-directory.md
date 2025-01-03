# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Uma máquina linux também pode estar presente em um ambiente Active Directory.

Uma máquina linux em um AD pode estar **armazenando diferentes tickets CCACHE dentro de arquivos. Esses tickets podem ser usados e abusados como qualquer outro ticket kerberos**. Para ler esses tickets, você precisará ser o usuário proprietário do ticket ou **root** dentro da máquina.

## Enumeração

### Enumeração de AD a partir do linux

Se você tiver acesso a um AD no linux (ou bash no Windows), pode tentar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar o AD.

Você também pode verificar a página a seguir para aprender **outras maneiras de enumerar AD a partir do linux**:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA é uma **alternativa** de código aberto ao **Active Directory** da Microsoft, principalmente para ambientes **Unix**. Ele combina um **diretório LDAP** completo com um Centro de Distribuição de Chaves **Kerberos** do MIT para gerenciamento semelhante ao Active Directory. Utilizando o **Sistema de Certificados** Dogtag para gerenciamento de certificados CA e RA, suporta autenticação **multifatorial**, incluindo cartões inteligentes. O SSSD está integrado para processos de autenticação Unix. Saiba mais sobre isso em:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

## Brincando com tickets

### Pass The Ticket

Nesta página, você encontrará diferentes lugares onde pode **encontrar tickets kerberos dentro de um host linux**. Na página a seguir, você pode aprender como transformar esses formatos de tickets CCache para Kirbi (o formato que você precisa usar no Windows) e também como realizar um ataque PTT:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

### Reutilização de ticket CCACHE de /tmp

Os arquivos CCACHE são formatos binários para **armazenar credenciais Kerberos** e geralmente são armazenados com permissões 600 em `/tmp`. Esses arquivos podem ser identificados pelo seu **formato de nome, `krb5cc_%{uid}`,** correlacionando ao UID do usuário. Para verificação do ticket de autenticação, a **variável de ambiente `KRB5CCNAME`** deve ser definida para o caminho do arquivo de ticket desejado, permitindo sua reutilização.

Liste o ticket atual usado para autenticação com `env | grep KRB5CCNAME`. O formato é portátil e o ticket pode ser **reutilizado definindo a variável de ambiente** com `export KRB5CCNAME=/tmp/ticket.ccache`. O formato do nome do ticket Kerberos é `krb5cc_%{uid}` onde uid é o UID do usuário.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Reutilização de tickets CCACHE do keyring

**Tickets Kerberos armazenados na memória de um processo podem ser extraídos**, particularmente quando a proteção ptrace da máquina está desativada (`/proc/sys/kernel/yama/ptrace_scope`). Uma ferramenta útil para esse propósito pode ser encontrada em [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), que facilita a extração injetando em sessões e despejando tickets em `/tmp`.

Para configurar e usar esta ferramenta, os passos abaixo são seguidos:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Este procedimento tentará injetar em várias sessões, indicando sucesso ao armazenar os tickets extraídos em `/tmp` com uma convenção de nomenclatura de `__krb_UID.ccache`.

### Reutilização de tickets CCACHE do SSSD KCM

O SSSD mantém uma cópia do banco de dados no caminho `/var/lib/sss/secrets/secrets.ldb`. A chave correspondente é armazenada como um arquivo oculto no caminho `/var/lib/sss/secrets/.secrets.mkey`. Por padrão, a chave só é legível se você tiver permissões de **root**.

Invocar \*\*`SSSDKCMExtractor` \*\* com os parâmetros --database e --key irá analisar o banco de dados e **descriptografar os segredos**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
O **blob de cache de credenciais Kerberos pode ser convertido em um arquivo Kerberos CCache** utilizável que pode ser passado para Mimikatz/Rubeus.

### Reutilização de ticket CCACHE a partir do keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extrair contas de /etc/krb5.keytab

As chaves de contas de serviço, essenciais para serviços que operam com privilégios de root, são armazenadas de forma segura nos arquivos **`/etc/krb5.keytab`**. Essas chaves, semelhantes a senhas para serviços, exigem estrita confidencialidade.

Para inspecionar o conteúdo do arquivo keytab, **`klist`** pode ser empregado. A ferramenta é projetada para exibir detalhes da chave, incluindo o **NT Hash** para autenticação de usuários, particularmente quando o tipo de chave é identificado como 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Para usuários do Linux, **`KeyTabExtract`** oferece funcionalidade para extrair o hash RC4 HMAC, que pode ser utilizado para reutilização do hash NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
No macOS, **`bifrost`** serve como uma ferramenta para análise de arquivos keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizando as informações de conta e hash extraídas, conexões com servidores podem ser estabelecidas usando ferramentas como **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Referências

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{{#include ../../banners/hacktricks-training.md}}
