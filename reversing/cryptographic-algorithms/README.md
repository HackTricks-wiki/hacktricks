# Algoritmos Criptográficos/De Compressão

## Algoritmos Criptográficos/De Compressão

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Identificando Algoritmos

Se você se deparar com um código **usando deslocamentos de bits, XORs e várias operações aritméticas**, é altamente possível que seja a implementação de um **algoritmo criptográfico**. Aqui serão mostradas algumas maneiras de **identificar o algoritmo que está sendo usado sem precisar reverter cada etapa**.

### Funções de API

**CryptDeriveKey**

Se esta função for usada, você pode descobrir qual **algoritmo está sendo usado** verificando o valor do segundo parâmetro:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Confira aqui a tabela de algoritmos possíveis e seus valores atribuídos: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime e descomprime um buffer de dados fornecido.

**CryptAcquireContext**

A função **CryptAcquireContext** é usada para adquirir um identificador para um contêiner de chave específico dentro de um provedor de serviços criptográficos (CSP) específico. **Este identificador retornado é usado em chamadas para funções CryptoAPI** que usam o CSP selecionado.

**CryptCreateHash**

Inicia o hashing de um fluxo de dados. Se esta função for usada, você pode descobrir qual **algoritmo está sendo usado** verificando o valor do segundo parâmetro:

![](<../../.gitbook/assets/image (376).png>)

Confira aqui a tabela de algoritmos possíveis e seus valores atribuídos: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes de Código

Às vezes, é muito fácil identificar um algoritmo graças ao fato de que ele precisa usar um valor especial e único.

![](<../../.gitbook/assets/image (370).png>)

Se você pesquisar a primeira constante no Google, é isso que você obtém:

![](<../../.gitbook/assets/image (371).png>)

Portanto, você pode assum
