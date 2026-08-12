# Banco de Authorizations do macOS e Authd

{{#include ../../../banners/hacktricks-training.md}}

## Banco de Authorizations

Os Authorization Services do Security framework permitem que helpers privilegiados e outros componentes avaliem rights de autorização nomeados. Nas versões atuais do macOS, muitas dessas regras são persistidas em `/var/db/auth.db` e avaliadas pelo `authd`; esse arquivo e seu schema SQLite são detalhes de implementação e podem mudar entre releases.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Historicamente, os padrões do sistema são obtidos de `/System/Library/Security/authorization.plist`, e installers ou serviços privilegiados podem adicionar rights nomeados. Prefira a interface compatível `security authorizationdb read|write|remove` em vez de editar o banco de dados diretamente.<sup>[[3]](#references)</sup>

A tabela `rules` observada no build documentado contém as seguintes colunas. Trate isso como um mapa forense, não como um schema público estável:

- **id**: Um identificador exclusivo para cada regra, incrementado automaticamente e usado como chave primária.
- **name**: O nome exclusivo da regra, usado para identificá-la e referenciá-la no sistema de autorização.
- **type**: Especifica o tipo da regra, restrito aos valores 1 ou 2 para definir sua lógica de autorização.
- **class**: Categoriza a regra em uma classe específica, garantindo que seja um inteiro positivo.
- As classes de regras comuns incluem `allow`, `deny`, `user`, `rule` e `evaluate-mechanisms`. Os mechanisms podem ser built-ins ou plug-ins do Security Agent em `/System/Library/CoreServices/SecurityAgentPlugins/` ou `/Library/Security/SecurityAgentPlugins/`.<sup>[[2]](#references)</sup>
- **group**: Indica o grupo de usuários associado à regra para autorização baseada em grupos.
- **kofn**: Representa o parâmetro "k-of-n", determinando quantas subregras devem ser satisfeitas de um número total.
- **timeout**: Define a duração, em segundos, antes que a autorização concedida pela regra expire.
- **flags**: Contém várias flags que modificam o comportamento e as características da regra.
- **tries**: Limita o número de tentativas de autorização permitidas para aumentar a segurança.
- **version**: Registra a versão da regra para controle de versões e atualizações.
- **created**: Registra o timestamp em que a regra foi criada para fins de auditoria.
- **modified**: Armazena o timestamp da última modificação feita na regra.
- **hash**: Contém um valor de hash da regra para garantir sua integridade e detectar tampering.
- **identifier**: Fornece um identificador exclusivo em formato de string, como um UUID, para referências externas à regra.
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
A regra decodificada a seguir ilustra `authenticate-admin-nonshared` em uma versão documentada do macOS:<sup>[[1]](#references)</sup>
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

`authd` é o serviço XPC que avalia solicitações do Authorization Services. Nas versões atuais do macOS, seu bundle pode ser inspecionado em `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`; o caminho é um detalhe de implementação e pode variar entre versões. Versões mais antigas gravavam em `/var/log/authd.log`; as atuais usam principalmente o sistema de unified logging, que pode ser consultado com `log show`/`log stream` usando um process predicate para `authd`.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

A ferramenta `security` expõe várias operações do Authorization Services. Um exemplo histórico invoca `AuthorizationExecuteWithPrivileges` com `security execute-with-privileges /bin/ls`. A Apple deprecated essa API no macOS 10.7; helpers privilegiados modernos devem usar um helper gerenciado pelo launchd e autorização via XPC.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

Nas versões que ainda oferecem suporte a isso, ele usa `/usr/libexec/security_authtrampoline` e exibe um authorization prompt antes de executar o comando como root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Visão geral do macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services Programming Guide (arquivo)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [Página de manual do macOS `security(1)`](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services Programming Guide: Criando jobs do launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Projeto Security open-source da Apple - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
