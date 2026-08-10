# Базова методологія форензики

## Створення та монтування образу


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Аналіз Malware

Це **не обов’язково має бути першим кроком після отримання образу**. Але ви можете використовувати ці методи аналізу Malware незалежно від того, чи маєте ви файл, образ файлової системи, образ пам’яті, pcap... тому корисно **пам’ятати про ці дії**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Дослідження образу

Якщо вам надано **форензичний образ** пристрою, ви можете почати **аналізувати розділи та файлову систему**, що використовується, а також **відновлювати** потенційно **цікаві файли** (навіть видалені). Дізнайтеся як:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Залежно від використовуваних ОС і навіть платформи слід шукати різні цікаві артефакти:


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

## Глибоке дослідження певних типів файлів і Software

Якщо у вас є дуже **підозрілий** **файл**, тоді **залежно від типу файлу та Software**, за допомогою якого його було створено, можуть бути корисними різні **трюки**.\
Прочитайте наступну сторінку, щоб дізнатися про цікаві трюки:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Окремо хочу згадати сторінку:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Дослідження дампа пам’яті


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Дослідження Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Антифорензичні техніки**

Пам’ятайте про можливе використання антифорензичних технік:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Полювання на загрози


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
