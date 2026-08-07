# Banco de Authorizations DB e Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Banco de Authorizations DB**

O banco de dados localizado em `/var/db/auth.db` é usado para armazenar permissões para realizar operações sensíveis. Essas operações são realizadas completamente no **user space** e geralmente são usadas por **XPC services**, que precisam verificar **se o cliente que faz a chamada está autorizado** a realizar determinada ação consultando este banco de dados.

Inicialmente, este banco de dados é criado a partir do conteúdo de `/System/Library/Security/authorization.plist`. Em seguida, alguns serviços podem adicionar ou modificar este banco de dados para incluir outras permissões.

As regras são armazenadas na tabela `rules` dentro do banco de dados e contêm as seguintes colunas:

- **id**: Um identificador exclusivo para cada regra, incrementado automaticamente e usado como chave primária.
- **name**: O nome exclusivo da regra, usado para identificá-la e referenciá-la dentro do sistema de autorizações.
- **type**: Especifica o tipo da regra, limitado aos valores 1 ou 2 para definir sua lógica de autorização.
- **class**: Categoriza a regra em uma classe específica, garantindo que seja um número inteiro positivo.
- "allow" para permitir, "deny" para negar, "user" se a propriedade group indicar um grupo cuja associação permite o acesso, "rule" indica, em um array, uma regra a ser cumprida, "evaluate-mechanisms" seguido por um array `mechanisms`, cujos elementos podem ser builtins ou o nome de um bundle dentro de `/System/Library/CoreServices/SecurityAgentPlugins/` ou `/Library/Security//SecurityAgentPlugins`
- **group**: Indica o grupo de usuários associado à regra para autorização baseada em grupo.
- **kofn**: Representa o parâmetro "k-of-n", determinando quantas sub-regras devem ser satisfeitas de um total.
- **timeout**: Define a duração, em segundos, antes que a autorização concedida pela regra expire.
- **flags**: Contém vários flags que modificam o comportamento e as características da regra.
- **tries**: Limita o número de tentativas de autorização permitidas para aumentar a segurança.
- **version**: Rastreia a versão da regra para controle de versão e atualizações.
- **created**: Registra o timestamp em que a regra foi criada para fins de auditoria.
- **modified**: Armazena o timestamp da última modificação feita na regra.
- **hash**: Contém um valor de hash da regra para garantir sua integridade e detectar adulterações.
- **identifier**: Fornece um identificador string exclusivo, como um UUID, para referências externas à regra.
- **requirement**: Contém dados serializados que definem os requisitos e mechanisms específicos de autorização da regra.
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
Além disso, em [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) é possível ver o significado de `authenticate-admin-nonshared`:<sup>[[1]](#references)</sup>
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

É um daemon que recebe solicitações para autorizar clientes a executar ações sensíveis. Ele funciona como um serviço XPC definido dentro da pasta `XPCServices/` e grava seus logs em `/var/log/authd.log`.

Além disso, usando a ferramenta `security`, é possível testar várias APIs do `Security.framework`. Por exemplo, executar `AuthorizationExecuteWithPrivileges`: `security execute-with-privileges /bin/ls`

Isso fará fork e exec de `/usr/libexec/security_authtrampoline /bin/ls` como root, o que solicitará permissões em um prompt para executar ls como root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## Referências

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)


{{#include ../../../banners/hacktricks-training.md}}
