# Базова методологія цифрової судової експертизи

{{#include ../../banners/hacktricks-training.md}}

## Створення та підключення образу


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Аналіз шкідливого ПЗ

This **isn't necessary the first step to perform once you have the image**. Але ви можете використовувати ці техніки аналізу шкідливого ПЗ незалежно, якщо у вас є файл, образ файлової системи, memory image, pcap... тому корисно **мати ці дії на увазі**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Огляд образу

Якщо вам надали **судовий образ** пристрою, ви можете почати **аналізувати розділи, файлову систему**, що використовується, та **відновлювати** потенційно **цікаві файли** (навіть видалені). Дізнайтеся як у:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# Базова методологія цифрової судової експертизи



## Створення та підключення образу


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Аналіз шкідливого ПЗ

This **isn't necessary the first step to perform once you have the image**. Але ви можете використовувати ці техніки аналізу шкідливого ПЗ незалежно, якщо у вас є файл, образ файлової системи, memory image, pcap... тому корисно **мати ці дії на увазі**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Огляд образу

Якщо вам надали **судовий образ** пристрою, ви можете почати **аналізувати розділи, файлову систему** що використовується та **відновлювати** потенційно **цікаві файли** (навіть видалені). Дізнайтеся як у:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Залежно від використовуваної ОС та навіть платформи слід шукати різні цікаві артефакти:


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

## Глибокий огляд конкретних типів файлів та програмного забезпечення

Якщо у вас є дуже **підозрілий** **файл**, то **залежно від типу файлу та програмного забезпечення**, що його створило, кілька **трюків** можуть бути корисними.\
Прочитайте наступну сторінку, щоб дізнатися деякі цікаві трюки:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Хочу особливо відзначити сторінку:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Аналіз дампу пам'яті


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Аналіз pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Контрфорензичні техніки**

Майте на увазі можливе використання контрфорензичних технік:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}



## Глибокий огляд конкретних типів файлів та програмного забезпечення

Якщо у вас є дуже **підозрілий** **файл**, то **залежно від типу файлу та програмного забезпечення**, що його створило, кілька **трюків** можуть бути корисними.\
Прочитайте наступну сторінку, щоб дізнатися деякі цікаві трюки:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Хочу особливо відзначити сторінку:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Аналіз дампу пам'яті


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Аналіз pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Контрфорензичні техніки**

Майте на увазі можливе використання контрфорензичних технік:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
