# Ataque de Extensão de Comprimento de Hash

{{#include ../banners/hacktricks-training.md}}

## Resumo do ataque

Imagine um servidor que está **assinando** alguns **dados** ao **anexar** um **segredo** a alguns dados de texto claro conhecidos e, em seguida, fazendo o hash desses dados. Se você souber:

- **O comprimento do segredo** (isso também pode ser forçado a partir de um intervalo de comprimento dado)
- **Os dados de texto claro**
- **O algoritmo (e ele é vulnerável a este ataque)**
- **O padding é conhecido**
- Normalmente, um padrão padrão é usado, então se os outros 3 requisitos forem atendidos, isso também é
- O padding varia dependendo do comprimento do segredo + dados, é por isso que o comprimento do segredo é necessário

Então, é possível para um **atacante** **anexar** **dados** e **gerar** uma **assinatura** válida para os **dados anteriores + dados anexados**.

### Como?

Basicamente, os algoritmos vulneráveis geram os hashes primeiro **fazendo o hash de um bloco de dados**, e então, **a partir do** **hash** **anteriormente** criado (estado), eles **adicionam o próximo bloco de dados** e **fazem o hash**.

Então, imagine que o segredo é "secret" e os dados são "data", o MD5 de "secretdata" é 6036708eba0d11f6ef52ad44e8b74d5b.\
Se um atacante quiser anexar a string "append", ele pode:

- Gerar um MD5 de 64 "A"s
- Mudar o estado do hash previamente inicializado para 6036708eba0d11f6ef52ad44e8b74d5b
- Anexar a string "append"
- Finalizar o hash e o hash resultante será um **válido para "secret" + "data" + "padding" + "append"**

### **Ferramenta**

{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}

### Referências

Você pode encontrar este ataque bem explicado em [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../banners/hacktricks-training.md}}
