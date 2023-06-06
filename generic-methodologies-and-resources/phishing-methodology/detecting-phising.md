# Detectando Phishing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introdução

Para detectar uma tentativa de phishing, é importante **entender as técnicas de phishing que estão sendo usadas atualmente**. Na página principal deste post, você pode encontrar essas informações, portanto, se você não estiver ciente das técnicas que estão sendo usadas hoje, recomendo que vá para a página principal e leia pelo menos essa seção.

Este post é baseado na ideia de que os **atacantes tentarão de alguma forma imitar ou usar o nome de domínio da vítima**. Se o seu domínio se chama `exemplo.com` e você for vítima de phishing usando um nome de domínio completamente diferente por algum motivo, como `vocêganhoualoteria.com`, essas técnicas não vão descobrir isso.

## Variações de nome de domínio

É **fácil** **descobrir** as tentativas de **phishing** que usarão um **nome de domínio semelhante** dentro do e-mail.\
É suficiente **gerar uma lista dos nomes de phishing mais prováveis** que um atacante pode usar e **verificar** se ele está **registrado** ou apenas verificar se há algum **IP** o usando.

### Encontrando domínios suspeitos

Para esse propósito, você pode usar qualquer uma das seguintes ferramentas. Observe que essas ferramentas também executarão solicitações DNS automaticamente para verificar se o domínio tem algum IP atribuído a ele:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

No mundo da computação, tudo é armazenado em bits (zeros e uns) na memória nos bastidores.\
Isso também se aplica a domínios. Por exemplo, _windows.com_ se torna _01110111..._ na memória volátil do seu dispositivo de computação.\
No entanto, e se um desses bits fosse automaticamente invertido devido a uma erupção solar, raios cósmicos ou um erro de hardware? Ou seja, um dos 0's se torna 1 e vice-versa.\
Aplicando esse conceito a solicitações DNS, é possível que o **domínio solicitado** que chega ao servidor DNS **não seja o mesmo que o domínio solicitado inicialmente**.

Por exemplo, uma modificação de 1 bit no domínio microsoft.com pode transformá-lo em _windnws.com._\
**Os atacantes podem registrar o maior número possível de domínios de inversão de bits relacionados à vítima para redirecionar usuários legítimos para sua infraestrutura**.

Para mais informações, leia [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

**Todos os possíveis nomes de domínio de inversão de bits também devem ser monitorados.**

### Verificações básicas

Depois de ter uma lista de nomes de domínio suspeitos potenciais, você deve **verificá-los** (principalmente as portas HTTP e HTTPS) para **ver se eles estão usando algum formulário de login semelhante** a alguém do domínio da vítima.\
Você também pode verificar a porta 3333 para ver se ela está aberta e executando uma instância do `gophish`.\
Também é interessante saber **há quanto tempo cada domínio suspeito descoberto existe**, quanto mais novo, mais arriscado é.\
Você também pode obter **capturas de tela** da página da web HTTP e/ou HTTPS suspeita para ver se é suspeita e, nesse caso, **acessá-la para dar uma olhada mais profunda**.

### Verificações avançadas

Se você quiser ir um passo adiante, recomendo que **monitore esses domínios suspeitos e procure por mais** de vez em quando (todos os dias? leva apenas alguns segundos/minutos). Você
