# Identificando binários empacotados

* **Falta de strings**: É comum encontrar binários empacotados que não possuem quase nenhuma string.
* Muitas **strings não utilizadas**: Além disso, quando um malware está usando algum tipo de empacotador comercial, é comum encontrar muitas strings sem referências cruzadas. Mesmo que essas strings existam, isso não significa que o binário não esteja empacotado.
* Você também pode usar algumas ferramentas para tentar descobrir qual empacotador foi usado para empacotar um binário:
  * [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
  * [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
  * [Language 2000](http://farrokhi.net/language/)

# Recomendações básicas

* **Comece** analisando o binário empacotado **de baixo para cima no IDA e mova-se para cima**. Desempacotadores saem assim que o código desempacotado sai, então é improvável que o desempacotador passe a execução para o código desempacotado no início.
* Procure por **JMP's** ou **CALLs** para **registradores** ou **regiões** de **memória**. Procure também por **funções que empurram argumentos e um endereço direcional e depois chamam `retn`**, porque o retorno da função nesse caso pode chamar o endereço acabado de empurrar para a pilha antes de chamá-lo.
* Coloque um **ponto de interrupção** em `VirtualAlloc`, pois isso aloca espaço na memória onde o programa pode escrever o código desempacotado. Execute até o código chegar a um valor dentro de EAX após a execução da função e "**siga esse endereço no dump**". Você nunca sabe se essa é a região onde o código desempacotado será salvo.
  * **`VirtualAlloc`** com o valor "**40**" como argumento significa Read+Write+Execute (algum código que precisa de execução será copiado aqui).
* **Enquanto desempacota** o código, é normal encontrar **várias chamadas** para **operações aritméticas** e funções como **`memcopy`** ou **`Virtual`**`Alloc`. Se você se encontrar em uma função que aparentemente realiza apenas operações aritméticas e talvez algum `memcopy`, a recomendação é tentar **encontrar o final da função** (talvez um JMP ou chamada a algum registrador) **ou pelo menos a chamada para a última função** e executá-la, pois o código não é interessante.
* Enquanto desempacota o código, **observe** sempre que você **altera a região da memória**, pois uma mudança na região da memória pode indicar o **início do código desempacotado**. Você pode facilmente despejar uma região da memória usando o Process Hacker (processo --> propriedades --> memória).
* Ao tentar desempacotar o código, uma boa maneira de **saber se você já está trabalhando com o código desempacotado** (para que você possa simplesmente despejá-lo) é **verificar as strings do binário**. Se em algum momento você executar um salto (talvez mudando a região da memória) e notar que **muitas mais strings foram adicionadas**, então você pode saber que **está trabalhando com o código desempacotado**.\
  No entanto, se o empacotador já contém muitas strings, você pode ver quantas strings contêm a palavra "http" e ver se esse número aumenta.
* Quando você despeja um executável de uma região da memória, pode corrigir alguns cabeçalhos usando o [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
