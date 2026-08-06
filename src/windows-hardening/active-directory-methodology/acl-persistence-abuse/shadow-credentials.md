# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Introdução <a href="#3f17" id="3f17"></a>

**Confira o post original para [todas as informações sobre esta técnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Como **resumo**: se você puder escrever na propriedade **msDS-KeyCredentialLink** de um usuário/computador, poderá recuperar o **NT hash desse objeto**.<sup>[[1]](#references)</sup>

No post, é descrito um método para configurar **credenciais de autenticação com chave pública-privada** e obter um **Service Ticket** exclusivo que inclui o hash NTLM do alvo. Esse processo envolve o NTLM_SUPPLEMENTAL_CREDENTIAL criptografado dentro do Privilege Attribute Certificate (PAC), que pode ser descriptografado.<sup>[[1]](#references)</sup>

### Requisitos

Para aplicar esta técnica, determinadas condições devem ser atendidas:<sup>[[1]](#references)</sup>

- É necessário pelo menos um Domain Controller com Windows Server 2016.
- O Domain Controller deve ter um certificado digital de autenticação de servidor instalado.
- O Active Directory deve estar no Windows Server 2016 Functional Level.
- É necessária uma conta com direitos delegados para modificar o atributo msDS-KeyCredentialLink do objeto-alvo.

## Abuso

O abuso de Key Trust em objetos de computador envolve etapas além da obtenção de um Ticket Granting Ticket (TGT) e do hash NTLM. As opções incluem:<sup>[[1]](#references)</sup>

1. Criar um **RC4 silver ticket** para atuar como usuários privilegiados no host pretendido.
2. Usar o TGT com **S4U2Self** para impersonar **usuários privilegiados**, exigindo alterações no Service Ticket para adicionar uma classe de serviço ao nome do serviço.

Uma vantagem significativa do abuso de Key Trust é sua limitação à chave privada gerada pelo atacante, evitando a delegação para contas potencialmente vulneráveis e não exigindo a criação de uma conta de computador, que poderia ser difícil de remover.<sup>[[1]](#references)</sup>

## Ferramentas

### [**Whisker**](https://github.com/eladshamir/Whisker)

Baseia-se no DSInternals e fornece uma interface C# para este ataque. Whisker e seu equivalente em Python, **pyWhisker**, permitem manipular o atributo `msDS-KeyCredentialLink` para obter controle sobre contas do Active Directory. Essas ferramentas oferecem várias operações, como adicionar, listar, remover e limpar key credentials do objeto-alvo.

As funções do **Whisker** incluem:

- **Add**: Gera um par de chaves e adiciona uma key credential.
- **List**: Exibe todas as entradas de key credentials.
- **Remove**: Exclui uma key credential especificada.
- **Clear**: Apaga todas as key credentials, podendo interromper o uso legítimo do WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Estende a funcionalidade do Whisker para **sistemas baseados em UNIX**, utilizando Impacket e PyDSInternals para oferecer recursos abrangentes de exploitation, incluindo a listagem, adição e remoção de KeyCredentials, além da importação e exportação em formato JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray tem como objetivo **explorar permissões GenericWrite/GenericAll que grupos de usuários amplos possam ter sobre objetos do domínio** para aplicar ShadowCredentials em larga escala. Isso envolve fazer login no domínio, verificar o nível funcional do domínio, enumerar objetos do domínio e tentar adicionar KeyCredentials para obter TGTs e revelar o NT hash. Opções de limpeza e táticas de exploração recursiva aumentam sua utilidade.

## Referências

- [1] [Shadow Credentials: Abusando do mapeamento de contas Key Trust para assumir o controle de contas](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Ferramenta para assumir o controle de contas AD manipulando msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Ferramenta para aplicar Shadow Credentials em um domínio](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Versão em Python da ferramenta Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
