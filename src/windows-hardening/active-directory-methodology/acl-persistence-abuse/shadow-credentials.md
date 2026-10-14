# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Introdução <a href="#3f17" id="3f17"></a>

**Consulte a publicação original para [obter todas as informações sobre esta técnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Em resumo, controlar o **`msDS-KeyCredentialLink`** de um usuário ou computador pode permitir que um atacante adicione uma credencial de chave, autentique-se como esse objeto com PKINIT e — quando o KDC e a conta oferecem suporte aos fluxos necessários — use o ticket resultante com `S4U2Self`/user-to-user para recuperar o hash NT do objeto.<sup>[[1]](#references)</sup>

Na publicação, é descrito um método para configurar **credenciais de autenticação por chave pública e privada** e obter um **Service Ticket** exclusivo que inclui o hash NTLM do alvo. Esse processo envolve o NTLM_SUPPLEMENTAL_CREDENTIAL criptografado dentro do Privilege Attribute Certificate (PAC), que pode ser descriptografado.<sup>[[1]](#references)</sup>

### Requisitos

Para aplicar esta técnica, algumas condições devem ser atendidas:<sup>[[1]](#references)</sup>

- É necessário pelo menos um Domain Controller com Windows Server 2016.
- O Domain Controller deve ter um certificado digital de autenticação de servidor instalado.
- O schema do diretório deve conter `msDS-KeyCredentialLink`; os requisitos práticos de plataforma descritos pela pesquisa são um DC com Windows Server 2016 ou mais recente e um certificado compatível com PKINIT no KDC. Verifique o schema e a combinação de DCs do domínio, em vez de presumir que apenas o nível funcional declarado do domínio determina a possibilidade de exploração.
- É necessária uma conta com direitos delegados para modificar o atributo msDS-KeyCredentialLink do objeto alvo.

## Abuso

O abuso de Key Trust em objetos de computador envolve etapas além de obter um Ticket Granting Ticket (TGT) e o hash NTLM. As opções incluem:<sup>[[1]](#references)</sup>

1. Criar um **RC4 silver ticket** para agir como usuários privilegiados no host pretendido.
2. Usar o TGT com **S4U2Self** para se passar por **usuários privilegiados**, o que exige alterações no Service Ticket para adicionar uma classe de serviço ao nome do serviço.

Uma vantagem significativa do abuso de Key Trust é que ele se limita à chave privada gerada pelo atacante, evitando a delegação para contas potencialmente vulneráveis e dispensando a criação de uma conta de computador, que pode ser difícil de remover.<sup>[[1]](#references)</sup>

## Ferramentas

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker usa DSInternals para manipular `msDS-KeyCredentialLink` em C#. Whisker e sua contraparte em Python, **pyWhisker**, permitem adicionar, listar, remover e limpar credenciais de chave.<sup>[[2]](#references)[[4]](#references)</sup>

As funções do **Whisker** incluem:

- **Add**: Gera um par de chaves e adiciona uma credencial de chave.
- **List**: Exibe todas as entradas de credenciais de chave.
- **Remove**: Exclui uma credencial de chave especificada.
- **Clear**: Apaga todas as credenciais de chave, podendo interromper o uso legítimo de WHfB.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker leva esse fluxo de trabalho para **sistemas semelhantes ao UNIX** com Impacket e PyDSInternals, incluindo operações de listagem, adição, remoção e importação/exportação de JSON.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumera objetos do domínio sobre os quais o operador tem permissões como `GenericWrite`/`GenericAll`, tenta adicionar key credentials em larga escala e inclui modos de limpeza e recursivos. Fazer spraying em larga escala é disruptivo e chama atenção; use alvos explícitos e registre cada DeviceID adicionado para removê-lo com precisão.<sup>[[3]](#references)</sup>

O ADWS pode transportar a gravação de key credentials quando o LDAP direto é filtrado. Veja o [workflow de ADWS com SOAPy](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: abusando do mapeamento de contas Key Trust para assumir o controle de contas](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Ferramenta para assumir o controle de contas AD manipulando msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Ferramenta para fazer spraying de Shadow Credentials em um domínio](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Versão em Python da ferramenta Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)
- [5] [Wiki do SOAPy – Pós-exploração](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
