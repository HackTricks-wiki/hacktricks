# プロセス、Crontab、Systemd、D-Bus

{{#include ../../banners/hacktricks-training.md}}

スケジュールされたジョブやプロセス間通信は、呼び出し元とは異なる権限でコードを実行することがあります。テストする前に、サービスやジョブの所有者、コマンド、書き込み可能な入力を確認してください。

- [プロセスの列挙とサービスのパス](process-enumeration-and-service-paths.md)では、プロセスツリー、ランタイムファイル、systemdの実行チェーンを扱います。
- [Cronジョブとsystemdタイマー](cron-and-systemd-timers.md)では、スケジュールされたタスクの発見と書き込み可能な入力を扱います。
- [D-Busの列挙とコマンドインジェクションによる権限昇格](d-bus-enumeration-and-command-injection-privilege-escalation.md)では、メッセージバスと特権サービスのメソッドを扱います。
- [実行するPayloads](payloads-to-execute.md)には、実行経路を特定した後に使えるPayloadsをまとめています。

cronジョブとsystemdサービスをより広範に調査するには、[Linux権限昇格チェックリスト](../main-system-information/linux-privilege-escalation-checklist.md)を使用してください。
{{#include ../../banners/hacktricks-training.md}}
