# Resumo do ataque

Imagine um servidor que está **assinando** alguns **dados** ao **anexar** um **segredo** a alguns dados conhecidos em texto claro e, em seguida, criptografando esses dados. Se você souber:

* **O comprimento do segredo** (isso também pode ser forçado por meio de uma faixa de comprimento fornecida)
* **Os dados em texto claro**
* **O algoritmo (e é vulnerável a esse ataque)**
* **O preenchimento é conhecido**
  * Geralmente, um padrão padrão é usado, portanto, se os outros 3 requisitos forem atendidos, isso também é
  * O preenchimento varia dependendo do comprimento do segredo + dados, é por isso que o comprimento do segredo é necessário

Então, é possível para um **atacante** **anexar** **dados** e **gerar** uma **assinatura** válida para os **dados anteriores + dados anexados**.

## Como?

Basicamente, os algoritmos vulneráveis geram as criptografias, primeiro **criptografando um bloco de dados** e, em seguida, **a partir do hash criado anteriormente** (estado), eles **adicionam o próximo bloco de dados** e **criptografam**.

Então, imagine que o segredo é "segredo" e os dados são "dados", o MD5 de "segredodados" é 6036708eba0d11f6ef52ad44e8b74d5b.\
Se um atacante quiser anexar a string "anexar", ele pode:

* Gerar um MD5 de 64 "A"s
* Alterar o estado do hash inicializado anteriormente para 6036708eba0d11f6ef52ad44e8b74d5b
* Anexar a string "anexar"
* Finalizar o hash e o hash resultante será um **válido para "segredo" + "dados" + "preenchimento" + "anexar"**

## **Ferramenta**

{% embed url="https://github.com/iagox86/hash_extender" %}

# Referências

Você pode encontrar este ataque bem explicado em [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
