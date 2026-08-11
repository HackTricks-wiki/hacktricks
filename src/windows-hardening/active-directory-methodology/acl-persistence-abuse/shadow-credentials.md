# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Introdução <a href="#3f17" id="3f17"></a>

**Consulte o post original para [todas as informações sobre esta técnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Em resumo, o controle de **`msDS-KeyCredentialLink`** de um usuário ou computador pode permitir que um atacante adicione uma credencial de chave, autentique-se como esse objeto com PKINIT e — quando o KDC e a conta suportarem os fluxos necessários — use o ticket resultante com `S4U2Self`/user-to-user para recuperar o hash NT do objeto.<sup>[[1]](#references)</sup>

No post, é descrito um método para configurar **credenciais de autenticação de chave pública-privada** e obter um **Service Ticket** exclusivo que inclui o hash NTLM do alvo. Esse processo envolve o NTLM_SUPPLEMENTAL_CREDENTIAL criptografado dentro do Privilege Attribute Certificate (PAC), que pode ser descriptografado.<sup>[[1]](#references)</sup>

### Requisitos

Para aplicar esta técnica, determinadas condições devem ser atendidas:<sup>[[1]](#references)</sup>

- É necessário pelo menos um Windows Server 2016 Domain Controller.
- O Domain Controller deve ter um certificado digital de autenticação de servidor instalado.
- O schema do diretório deve conter `msDS-KeyCredentialLink`; um DC com Windows Server 2016 ou mais recente e um certificado compatível com PKINIT no KDC são os requisitos práticos de plataforma descritos pela pesquisa. Verifique a combinação de schema/DC do domínio em vez de presumir que apenas o rótulo do nível funcional do domínio determina a exploitabilidade.
- É necessária uma conta com direitos delegados para modificar o atributo msDS-KeyCredentialLink do objeto alvo.

## Abuse

O abuso de Key Trust em objetos de computador envolve etapas além da obtenção de um Ticket Granting Ticket (TGT) e do hash NTLM. As opções incluem:<sup>[[1]](#references)</sup>

1. Criar um **RC4 silver ticket** para atuar como usuários privilegiados no host pretendido.
2. Usar o TGT com **S4U2Self** para a personificação de **usuários privilegiados**, exigindo alterações no Service Ticket para adicionar uma classe de serviço ao nome do serviço.

Uma vantagem significativa do abuso de Key Trust é sua limitação à chave privada gerada pelo atacante, evitando a delegação para contas potencialmente vulneráveis e não exigindo a criação de uma conta de computador, que poderia ser difícil de remover.<sup>[[1]](#references)</sup>

## Ferramentas

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker usa DSInternals para manipular `msDS-KeyCredentialLink` a partir de C#. Whisker e seu equivalente em Python, **pyWhisker**, oferecem suporte à adição, listagem, remoção e limpeza de credenciais de chave.<sup>[[2]](#references)[[4]](#references)</sup>

As funções do **Whisker** incluem:

- **Add**: Gera um par de chaves e adiciona uma credencial de chave.
- **List**: Exibe todas as entradas de credenciais de chave.
- **Remove**: Exclui uma credencial de chave especificada.
- **Clear**: Apaga todas as credenciais de chave, podendo interromper o uso legítimo do WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker traz o fluxo de trabalho para **sistemas semelhantes ao UNIX** com Impacket e PyDSInternals, incluindo operações de list/add/remove e import/export de JSON.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumera objetos do domínio sobre os quais o operador possui direitos como `GenericWrite`/`GenericAll`, tenta adicionar key credentials amplamente e inclui modos de limpeza/recursivo. O spraying amplo é disruptivo e evidente; use alvos explícitos e mantenha cada DeviceID adicionado para uma remoção precisa.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: Abusando do mapeamento de contas baseado em Key Trust para assumir o controle de contas](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Ferramenta para assumir o controle de contas AD manipulando msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Ferramenta para aplicar Shadow Credentials em um domínio](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Versão em Python da ferramenta Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
