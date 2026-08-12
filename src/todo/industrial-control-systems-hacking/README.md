# Industrial Control Systems Hacking

{{#include ../../banners/hacktricks-training.md}}

## このセクションについて

このセクションでは、industrial control system (ICS) のコンポーネント、アーキテクチャ、プロトコル、セキュリティ評価手法について説明します。ICS は、物理プロセスを監視したり、その状態を変化させたりするプログラム可能なシステムやデバイスを指す、より広範な operational technology (OT) ドメインの一部です。一般的な例として、supervisory control and data acquisition (SCADA) システム、distributed control systems (DCSs)、programmable logic controllers (PLCs) などがあります。<sup>[[1]](#references)</sup>

これらの環境でのセキュリティ業務では、従来の IT とは異なる要件を考慮する必要があります。これには、プロセスの安全性、信頼性、可用性、決定論的な動作、設備のライフサイクルなどが含まれます。技術的に有効なセキュリティ対策であっても、物理プロセスを妨害する場合は適切でない可能性があるため、テストと remediation はシステム所有者および運用担当者と調整して実施する必要があります。<sup>[[1]](#references)</sup>

侵害や偶発的な障害により、生産停止、設備の損傷、有害物質の放出、環境への被害、負傷、さらには人命の損失が発生する可能性があります。このような物理的影響が生じ得るため、active testing に先立って、制御対象のプロセスと安全な運用限界を理解する必要があります。<sup>[[1]](#references)</sup>

多くの OT 環境では、設備の長い稼働期間や、変更に運用面および安全面でのテストが必要となることから、legacy operating systems、アプリケーション、プロトコルが使われ続けています。一部のプロトコルは、最新の認証や encryption を備えない状態で設計されており、vendor support や maintenance window によって patching が制限される場合もあります。直接的な upgrade が困難な場合は、segmentation、access control、monitoring によって補完してください。<sup>[[1]](#references)</sup>

## Assessment Priorities

まず、制御対象のプロセス、システム境界、ネットワークトポロジー、資産、データフロー、trust relationships、外部接続を理解することから始めます。同じ種類のデバイスでも、サイトごとに異なる機能を担う場合があるため、ある環境の architecture や impact model が別の環境にも当てはまると仮定しないでください。<sup>[[1]](#references)</sup>

可能な限り、passive discovery と既存の engineering documentation を優先してください。active scanning や exploitation を行う場合は、安全上の制約、maintenance window、recovery procedures、stop conditions を定義した承認済みの test plan に従う必要があります。Findings は、cybersecurity への影響だけでなく、物理プロセスに及ぼす可能性のある影響も考慮して評価してください。<sup>[[1]](#references)</sup>

同じ architecture に関する知識は、asset inventory、network segmentation、monitoring、incident response、risk-based vulnerability management などの防御活動にも役立ちます。<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Operational Technology (OT) Security ガイド](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
