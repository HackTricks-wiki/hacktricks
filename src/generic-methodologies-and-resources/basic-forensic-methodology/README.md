# Базова методологія комп’ютерної криміналістики

{{#include ../../banners/hacktricks-training.md}}

## Створення та монтування образу


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Аналіз malware

**Це не обов’язково має бути першим кроком після отримання образу.** Але ці методи аналізу malware можна використовувати окремо, якщо у вас є файл, образ файлової системи, образ пам’яті, pcap... Тож варто **мати ці дії на увазі**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Перевірка образу

Якщо вам надали **криміналістичний образ** пристрою, ви можете почати **аналізувати розділи та файлову систему**, а також **відновлювати** потенційно **цікаві файли** (навіть видалені). Дізнайтеся, як це зробити:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Залежно від використовуваної ОС і платформи слід шукати різні цікаві артефакти:


{{#ref}}
windows-forensics/
{{#endref}}


{{#ref}}
linux-forensics.md
{{#endref}}


{{#ref}}
docker-forensics.md
{{#endref}}


{{#ref}}
ios-backup-forensics.md
{{#endref}}

Щоб дізнатися про заблокований пристрій Android, способи отримання даних і створення образу пам’яті, див. [криміналістичний аналіз Android](android-forensics.md).

## Поглиблений аналіз певних типів файлів і програмного забезпечення

Якщо у вас є дуже **підозрілий** **файл**, то, **залежно від типу файлу та програмного забезпечення**, за допомогою якого його створили, можуть стати в пригоді різні **хитрощі**.\
Прочитайте цю сторінку, щоб дізнатися про цікаві хитрощі:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Особливо хочу відзначити сторінку:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Аналіз дампу пам’яті


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Аналіз pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Антикриміналістичні методи**

Майте на увазі, що могли застосовуватися антикриміналістичні методи:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Полювання на загрози


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
