# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Banco de Dados de Autorizações**

O banco de dados localizado em `/var/db/auth.db` é um banco de dados usado para armazenar permissões para realizar operações sensíveis. Essas operações são realizadas completamente no **espaço do usuário** e geralmente são usadas por **serviços XPC** que precisam verificar **se o cliente chamador está autorizado** a realizar determinada ação verificando este banco de dados.

Inicialmente, este banco de dados é criado a partir do conteúdo de `/System/Library/Security/authorization.plist`. Em seguida, alguns serviços podem adicionar ou modificar este banco de dados para adicionar outras permissões a ele.

As regras são armazenadas na tabela `rules` dentro do banco de dados e contêm as seguintes colunas:

- **id**: Um identificador único para cada regra, automaticamente incrementado e servindo como chave primária.
- **name**: O nome único da regra usado para identificá-la e referenciá-la dentro do sistema de autorização.
- **type**: Especifica o tipo da regra, restrito aos valores 1 ou 2 para definir sua lógica de autorização.
- **class**: Categoriza a regra em uma classe específica, garantindo que seja um número inteiro positivo.
- "allow" para permitir, "deny" para negar, "user" se a propriedade do grupo indicar um grupo cuja membresia permite o acesso, "rule" indica em um array uma regra a ser cumprida, "evaluate-mechanisms" seguido por um array `mechanisms` que são ou embutidos ou um nome de um pacote dentro de `/System/Library/CoreServices/SecurityAgentPlugins/` ou /Library/Security//SecurityAgentPlugins
- **group**: Indica o grupo de usuários associado à regra para autorização baseada em grupo.
- **kofn**: Representa o parâmetro "k-of-n", determinando quantas sub-regras devem ser satisfeitas de um número total.
- **timeout**: Define a duração em segundos antes que a autorização concedida pela regra expire.
- **flags**: Contém várias flags que modificam o comportamento e as características da regra.
- **tries**: Limita o número de tentativas de autorização permitidas para aumentar a segurança.
- **version**: Rastreia a versão da regra para controle de versão e atualizações.
- **created**: Registra o timestamp quando a regra foi criada para fins de auditoria.
- **modified**: Armazena o timestamp da última modificação feita na regra.
- **hash**: Contém um valor hash da regra para garantir sua integridade e detectar adulterações.
- **identifier**: Fornece um identificador de string único, como um UUID, para referências externas à regra.
- **requirement**: Contém dados serializados definindo os requisitos e mecanismos específicos de autorização da regra.
- **comment**: Oferece uma descrição ou comentário legível por humanos sobre a regra para documentação e clareza.

### Exemplo
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Além disso, em [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) é possível ver o significado de `authenticate-admin-nonshared`:
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

É um daemon que receberá solicitações para autorizar clientes a realizar ações sensíveis. Funciona como um serviço XPC definido dentro da pasta `XPCServices/` e costuma gravar seus logs em `/var/log/authd.log`.

Além disso, usando a ferramenta de segurança, é possível testar muitas APIs do `Security.framework`. Por exemplo, o `AuthorizationExecuteWithPrivileges` executando: `security execute-with-privileges /bin/ls`

Isso irá fork e exec `/usr/libexec/security_authtrampoline /bin/ls` como root, que pedirá permissões em um prompt para executar ls como root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

{{#include ../../../banners/hacktricks-training.md}}
