# Extensões de Kernel do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

As extensões de kernel (Kexts) são **pacotes** com extensão **`.kext`** que são **carregados diretamente no espaço do kernel** do macOS, fornecendo funcionalidades adicionais ao sistema operacional principal.

### Requisitos

Obviamente, isso é tão poderoso que é complicado carregar uma extensão de kernel. Estes são os requisitos para que uma extensão de kernel seja carregada:

* Ao entrar no **modo de recuperação**, as extensões de kernel precisam ser **autorizadas a serem carregadas**:

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

* A extensão de kernel deve ser **assinada com um certificado de assinatura de código do kernel**, que só pode ser concedido pela **Apple**. Que irá **revisar** detalhadamente a **empresa** e as **razões** pelas quais isso é necessário.
* A extensão de kernel também precisa ser **notarizada**, a Apple poderá verificá-la em busca de malware.
* Em seguida, o **usuário root** é o único que pode carregar a extensão de kernel e os arquivos dentro do pacote devem pertencer ao root.
* Finalmente, ao tentar carregá-lo, o [**usuário será solicitado a confirmar**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) e, se aceito, o computador deve **reiniciar** para carregá-lo.

### Processo de Carregamento

De volta ao Catalina, era assim: É interessante notar que o processo de **verificação** ocorre em **userland**. No entanto, apenas aplicativos com a permissão **`com.apple.private.security.kext-management`** podem **solicitar ao kernel** para **carregar uma extensão:** kextcache, kextload, kextutil, kextd, syspolicyd

1. O cli **`kextutil`** **inicia** o processo de verificação para carregar uma extensão
   * Ele falará com o **`kextd`** enviando usando um serviço Mach
2. O **`kextd`** verificará várias coisas, como a assinatura
   * Ele falará com o **`syspolicyd`** para verificar se a extensão pode ser carregada
3. O **`syspolicyd`** **pergunta** ao **usuário** se a extensão não foi carregada anteriormente
   * **`syspolicyd`** indicará o resultado ao **`kextd`**
4. O **`kextd`** finalmente poderá indicar ao **kernel para carregar a extensão**

Se o kextd não estiver disponível, o kextutil pode realizar as mesmas verificações.

## Referências

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
