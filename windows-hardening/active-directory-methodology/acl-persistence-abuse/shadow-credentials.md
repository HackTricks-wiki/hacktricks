# Credenciais Shadow

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introdução <a href="#3f17" id="3f17"></a>

Confira o post original para [**todas as informações sobre essa técnica**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

Em resumo: se você pode escrever na propriedade **msDS-KeyCredentialLink** de um usuário/computador, você pode recuperar o **hash NT desse objeto**.

Isso ocorre porque você poderá definir credenciais de autenticação **chave pública-privada** para o objeto e usá-las para obter um **Ticket de Serviço especial que contém seu hash NTLM** dentro do Certificado de Atributo de Privilégio (PAC) em uma entidade NTLM\_SUPLEMENTAL\_CREDENTIAL criptografada que você pode descriptografar.

### Requisitos <a href="#2de4" id="2de4"></a>

Essa técnica requer o seguinte:

* Pelo menos um Controlador de Domínio do Windows Server 2016.
* Um certificado digital para Autenticação de Servidor instalado no Controlador de Domínio.
* Nível Funcional do Windows Server 2016 no Active Directory.
* Comprometer uma conta com os direitos delegados para escrever no atributo msDS-KeyCredentialLink do objeto de destino.

## Abuso

Abusar do Key Trust para objetos de computador requer etapas adicionais após a obtenção de um TGT e o hash NTLM para a conta. Geralmente, existem duas opções:

1. Forjar um **RC4 silver ticket** para se passar por usuários privilegiados no host correspondente.
2. Usar o TGT para chamar **S4U2Self** para se passar por **usuários privilegiados** no host correspondente. Essa opção requer modificar o Ticket de Serviço obtido para incluir uma classe de serviço no nome do serviço.

O abuso do Key Trust tem a vantagem adicional de que não delega acesso a outra conta que possa ser comprometida - é **restrito à chave privada gerada pelo atacante**. Além disso, não requer a criação de uma conta de computador que pode ser difícil de limpar até que a escalada de privilégios seja alcançada.

Whisker

Junto com este post, estou lançando uma ferramenta chamada " [Whisker](https://github.com/eladshamir/Whisker) ". Com base no código do DSInternals de Michael, o Whisker fornece uma camada C# para realizar esse ataque em engajamentos. O Whisker atualiza o objeto de destino usando LDAP, enquanto o DSInternals permite atualizar objetos usando tanto LDAP quanto RPC com o Serviço de Replicação de Diretório (DRS) Remote Protocol.

[Whisker](https://github.com/eladshamir/Whisker) tem quatro funções:

* Add - Esta função gera um par de chaves pública-privada e adiciona uma nova credencial de chave ao objeto de destino como se o usuário tivesse se inscrito no WHfB a partir de um novo dispositivo.
* List - Esta função lista todas as entradas do atributo msDS-KeyCredentialLink do objeto de destino.
* Remove - Esta função remove uma credencial de chave do objeto de destino especificada por um GUID DeviceID.
* Clear - Esta
