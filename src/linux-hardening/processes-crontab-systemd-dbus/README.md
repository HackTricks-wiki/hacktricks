# プロセス、Crontab、Systemd、D-Bus

{{#include ../../banners/hacktricks-training.md}}

スケジュールされたジョブやプロセス間通信によって、呼び出し元とは異なる権限でコードが実行されることがあります。テストする前に、サービスやジョブの所有者、コマンド、書き込み可能な入力を確認してください。

- [プロセスの列挙とサービスパス](process-enumeration-and-service-paths.md)では、プロセスツリー、ランタイムファイル、systemdの実行チェーンについて説明します。
- [Cronジョブとsystemdタイマー](cron-and-systemd-timers.md)では、スケジュールタスクの発見と書き込み可能な入力について説明します。
- [D-Busの列挙とコマンドインジェクションによる権限昇格](d-bus-enumeration-and-command-injection-privilege-escalation.md)では、メッセージバスと特権サービスのメソッドについて説明します。
- [実行用payloads](payloads-to-execute.md)には、実行経路を特定したときに使用できるpayloadsがまとめられています。

cronジョブとsystemdサービスをさらに広く調査するには、[Linux権限昇格チェックリスト](../main-system-information/linux-privilege-escalation-checklist.md)を使用してください。
{{#include ../../banners/hacktricks-training.md}}
