# Operational Privacy Playbooks

{{#include ../banners/hacktricks-training.md}}

これらのplaybookは、このセクションの他の部分にあるcontrolsを組み合わせたものです。保証ではなく出発点です。新しいobserver、account、device、location、payment、file、またはcounterpartyがworkflowに入るたびに、threat modelを更新してください。

## Universal preflight

1. 正当な目的と、**誰から**何をprivateに保つ必要があるかを書き出す。
2. 活動が触れるidentity、device、network、account、payment rail、counterparty、physical location、dataを記録する。
3. 最も強力と思われるobserverと、failure時の結果を特定する。
4. authorization、適用法、provider terms、organizational policyを確認する。
5. safety、incident response、accounting、auditのために、何を内部でattributableにしておく必要があるか決める。
6. 実用可能な最小のcompartmentを選び、使用前にrecoveryとshutdownの経路を確立する。
7. controlled serviceに対してcompartmentをtestする。IP/DNS/IPv6、browser identity、document metadata、payment statement、notification leakageを含める。

詳細なmodelは[Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md)を使用してください。

## Everyday privacy baseline

Goal: anonymousになろうとせず、commercial tracking、account takeover、不要なexposureを減らす。

- full-disk encryption、automatic updates、screen lock、利用可能な場合はsecure bootを備えた、maintained OSを使用する。
- まずpassword manager、recovery email、phishing-resistant MFA/security keysを整備する。
- app permissions、location history、advertising identifiers、cloud sync、third-party account connectionsを確認する。
- extensionsを少数に抑え、tracking protectionとHTTPSを有効にしたmainstream browserを使用し、work/personal/high-risk browsingには別々のprofilesを使用する。
- 関係ごとにprivate relay aliasesまたは別々のemail addressesを使用する。単にoptionalである場合、personal phone numberは使用しない。
- contentにはend-to-end encrypted messagingを優先する。ただし、participants、timing、groups、endpointsはmetadataとして残ることを忘れない。
- fileからmetadataを意図的に削除し、公開前にoriginalではなくexported copyをinspectする。
- payment-credential compartmentalizationにはvirtual-cardまたはwallet tokensを使用する。これらをanonymousとは呼ばない。
- encrypted recovery materialをbackupし、restorationをtestする。

## Pseudonymous publication

Goal: casual readersやplatformsがpublicationをcivil identityに簡単にlinkできないようにする。これは、能力のあるtargeted investigationには対抗できない。

1. platform、hosting provider、readers、contacts、local network、payment provider、またはlegal processをthreat modelに含めるか定義する。
2. clean baselineからdedicated endpoint/account contextを作成する。personal browser sync、cloud documents、contact upload、notification previewsを無効にする。
3. 選択したnetwork compartmentを通じてpseudonymous accountを作成する。usernames、avatars、recovery channels、writing boilerplate、personal identity-provider loginをreuseしない。
4. destination unlinkabilityがspeedより重要な場合はTor Browserを使用する。extensionsを追加したり、大幅にresize/customizeしたり、通常のdesktop sessionでonlineのままdownloaded documentsを開いたりしない。
5. personal template names、revision authors、printer paths、GPS/EXIF、thumbnails、hidden layersを埋め込まないprocessでdraftを作成する。copyをexportし、適切なmetadata toolsでinspectする。
6. self-identifying factsをcontentから確認する。unique dates、workplace details、local weather/time zone、reflections、background audio、linguistic habits、prior-publication text reuseなどを確認する。
7. 別のreply channelを使用する。すべてのdirect contact、attachment、linkを、potential correlationまたはphishing attemptとして扱う。
8. moneyが関係する場合、必要なdataのみをexposeするlawful methodを使用する。readersが知らなくても、platformとregulated intermediaryはpayeeを知っている可能性があると想定する。
9. publishした後、別のclean contextからpublic resultをinspectする。platformが追加または変換した内容を記録する。
10. stable behavioral fingerprintを作らない場合に限り、planned cadenceを維持する。compartmentを黙ってrepurposeするのではなく、retireする。

serious journalism、activism、domestic abuse、state-level riskの場合は、経験豊富なdigital-security organizationからtailored helpを得てください。static checklistではlocal lawやlive adversaryをmodelできません。

## Authorized red-team engagement

Goal: authorization、control、incident responseを維持しながら、operatorsのpersonal identitiesとhome networksをtarget telemetryから外す。

### Before the start window

- ROE infrastructure annex、targets/exclusions、source ranges、dates、emergency stop、third-party/provider permissionsを確定する。
- dedicated operator profileまたはVM、engagement secrets、evidence store、cloud project、domains、budgetを割り当てる。
- client-provided egressまたはorganization-controlled fixed bastionを優先する。full-tunnel IPv4/IPv6/DNS behaviorとfail-closed policyをtestする。
- operatorからpublic infrastructureへのmappingをexercise controllerまたは合意済みのescrow contactと保管する。
- rate limits、destination allowlists、destructive、wireless、physical、phishing、credential-collection actionsに対する別個のapprovalを設定する。
- organization-controlled payment railを使用し、approvalsを内部で記録する。

### During the engagement

- approved endpointとtunnelから開始し、assessment trafficの前にobserved egressを確認する。
- personal accounts、devices、phone numbers、repositories、SSH/GPG keys、cloud syncをcompartmentから排除する。
- operator/job、start/stop、source、scoped destination、configuration changeを記録する。ただし不要なclient contentは収集しない。
- scope ambiguity、unexpected third-party systems、provider abuse notification、safety impact、lost equipment、controller contactの喪失があれば停止する。
- neighborのWi-Fi、stolen credentials、未承認のSIM/account、venueに隠したhardwareを使ってimproviseしない。

### End of engagement

- jobsとC2を停止し、approved drop devicesを回収し、tokens、credentials、certificatesをrevokeする。
- infrastructure、domains、source addresses、expenses、data、provider casesをinventoryと照合する。
- contractに従ってclient dataをreturn/delete/retainし、必要最小限のaudit evidenceを保存し、別のoperatorにshutdownをverifyさせる。

完全なbuildとteardown guideは[Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)を参照してください。

## Lawful private purchase or donation

Goal: issuer、accounting、tax、sanctions obligationsを満たしながら、merchantまたはpublicへのdisclosureを最小限にする。

1. 誰に何を知られてはならないかを列挙する。public audience、merchant、payment intermediary、employer/family account delegate、delivery service、blockchain observerなど。
2. local rules、recipient/counterparty、provider terms、cash limits、recordkeeping needsを確認する。
3. railを選択する。
- payment-network recordを残さない、受け入れられるlawful local paymentsにはcash。
- online credential separationにはregulated virtual/merchant-specific card。
- cryptocurrencyは、acquisition、ledger、wallet backend、network、counterparty、later-spend linksを分析した後に限る。
4. 必須のdetailsはtruthfulに使用し、optionalなloyalty/marketing informationのみ省略する。他人のidentity/addressを使用したり、thresholdを回避するためにtransactionを分割したりしない。
5. merchant browser/account contextを分離し、無関係なsocial login、loyalty、personal recovery channelsを避ける。
6. statements、receipts、notifications、shipping、public donor listsに何が表示されるか確認する。
7. 必須のreceipt/tax/authorization evidenceをencryptedで保存し、refund window後にdisposable payment credentialsをrevokeする。

[Private Digital Payments](private-digital-payments.md)と[Cryptocurrency Privacy](cryptocurrency-privacy.md)を参照してください。

## Travel and untrusted networks

Goal: userが管理していないnetworks上でdataとaccountsを保護すること。unauthorized activityを隠すことではない。

- travel前にdevicesをupdateし、必要なcredentials/mapsをdownloadする。
- stored dataを最小限にする。full-disk encryption、strong unlock、remote-recovery planning、legal adviceに適したpowered-off border/physical-risk proceduresを使用する。
- venue SSID/captive portalを確認する。適切な場合はpersonal hotspotを優先するが、cellular subscriberとlocation recordsが残ることを忘れない。
- organizational dataにはfull/forced approved VPNを使用する。tethered devicesもVPNを共有していることを確認し、IPv6/DNS behaviorをtestする。
- client isolationとrepeatable policyのためにtravel routerを使用する。anonymousの保証として使用してはならない。
- public USB charging、borrowed computers、public printers、shared meeting-room systemsを別々のthreatとして扱う。
- physical presence、radio identifiers、portal login、cameras、payment/location recordsがvisitをcorrelateできると想定する。

comparisonとsetupの詳細は[Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md)にあります。

## Failure and exposure response

compartmentがleakした、またはlinkされた可能性がある場合：

1. 継続によってharmが増える場合はactivityを停止する。該当する場合はengagement emergency stopを使用する。
2. sensitive dataを拡散せず、必要なevidenceを保存する。正確なtime、observed indicator、affected assetsを記録する。
3. 適切なowner/controller/security contactにnotifyする。privacy narrativeを維持するためにincidentを隠してはならない。
4. sessions、tokens、payment credentials、infrastructure accessをrevokeし、known-clean endpointからsecretsをrotateする。
5. どのedgeがlinkを作ったかを特定する。endpoint、account recovery、network、payment、metadata、content、behavior、counterparty、physical presenceを確認する。
6. affected compartment全体がburnedだと扱う。usernameまたはexit IPだけを変更して済ませない。
7. breach、provider、client、financial、legal notification dutiesを果たす。
8. linkの原因となったprocessを変更してからrebuildする。controlをdocumentし、testする。

## Periodic audit

- [ ] threat modelとlegal/provider assumptionsを、日付のあるscheduleでreviewした。
- [ ] devices、accounts、aliases、domains、network paths、payment credentialsをinventoryした。
- [ ] recovery pathsが予期せずcompartmentsをcrossしていない。
- [ ] full-tunnel、DNS、IPv6、fail-closed behaviorをtestした。
- [ ] public filesとprofilesについてmetadata/content reuseを確認した。
- [ ] wallet nodes/backendsとcrypto protocol assumptionsがcurrentのままである。
- [ ] logsとreceiptsがminimal、encrypted、access-controlledで、retentionの範囲内にある。
- [ ] old compartmentsとengagement infrastructureを完全にretireした。
{{#include ../banners/hacktricks-training.md}}
