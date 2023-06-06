# Informações Básicas

O Logstash é usado para coletar, transformar e produzir logs. Isso é realizado usando **pipelines**, que contêm módulos de entrada, filtro e saída. O serviço se torna interessante quando se compromete uma máquina que está executando o Logstash como serviço.

## Pipelines

O arquivo de configuração da pipeline **/etc/logstash/pipelines.yml** especifica as localizações das pipelines ativas:
```bash
# This file is where you define your pipelines. You can define multiple.
# For more information on multiple pipelines, see the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
  path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
  path.config: "/usr/share/logstash/pipeline/1*.conf"
  pipeline.workers: 6
```
Aqui você pode encontrar os caminhos para os arquivos **.conf**, que contêm as pipelines configuradas. Se o módulo de saída do Elasticsearch for usado, as pipelines provavelmente contêm credenciais válidas para uma instância do Elasticsearch. Essas credenciais geralmente possuem mais privilégios, já que o Logstash precisa escrever dados no Elasticsearch. Se curingas forem usados, o Logstash tenta executar todas as pipelines localizadas naquela pasta que correspondem ao curinga.

## Privesc com pipelines graváveis

Antes de tentar elevar seus próprios privilégios, você deve verificar qual usuário está executando o serviço do logstash, já que este será o usuário que você possuirá posteriormente. Por padrão, o serviço do logstash é executado com os privilégios do usuário **logstash**.

Verifique se você tem **um** dos direitos necessários:

* Você tem permissões de escrita em um arquivo **.conf** de pipeline **ou**
* **/etc/logstash/pipelines.yml** contém um curinga e você tem permissão para escrever na pasta especificada

Além disso, **um** dos requisitos deve ser atendido:

* Você é capaz de reiniciar o serviço do logstash **ou**
* **/etc/logstash/logstash.yml** contém a entrada **config.reload.automatic: true**

Se um curinga for especificado, tente criar um arquivo que corresponda a esse curinga. O seguinte conteúdo pode ser escrito no arquivo para executar comandos:
```bash
input {
  exec {
    command => "whoami"
    interval => 120
  }
}

output {
  file {
    path => "/tmp/output.log"
    codec => rubydebug
  }
}
```
O **intervalo** especifica o tempo em segundos. Neste exemplo, o comando **whoami** é executado a cada 120 segundos. A saída do comando é salva em **/tmp/output.log**.

Se **/etc/logstash/logstash.yml** contém a entrada **config.reload.automatic: true**, você só precisa esperar até que o comando seja executado, já que o Logstash reconhecerá automaticamente novos arquivos de configuração de pipeline ou quaisquer alterações nas configurações de pipeline existentes. Caso contrário, acione uma reinicialização do serviço do logstash.

Se nenhum caractere curinga for usado, você pode aplicar essas alterações a uma configuração de pipeline existente. **Certifique-se de não quebrar as coisas!**

# Referências

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
