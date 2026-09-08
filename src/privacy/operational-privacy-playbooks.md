# Operational Privacy Playbooks

これらのplaybookは、このセクションの他の箇所にあるcontrolsを組み合わせたものです。保証ではなく出発点です。新たなobserver、account、device、location、payment、file、またはcounterpartyがworkflowに入るたびに、threat modelを更新してください。

## Universal preflight

1. 正当な目的と、**誰から何をprivateに保つ必要があるか**を書き出す。
2. 活動が触れることになるidentities、devices、networks、accounts、payment rails、counterparties、physical locations、dataを記録する。
3. 最も強力である可能性が高いobserverと、失敗時のconsequenceを特定する。
4. authorization、適用されるlaw、provider terms、organizational policyを確認する。
5. safety、incident response、accounting、auditのために、内部で何をattributableな状態に保つ必要があるか決める。
6. 実用可能な最小のcompartmentを選び、使用前にそのrecoveryとshutdown pathsを確立する。
7. controlled serviceに対してcompartmentをテストする。IP/DNS/IPv6、browser identity、document metadata、payment statement、notification leakageを含めて確認する。

詳細なmodelは[Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md)を参照してください。

## Everyday privacy baseline

Goal: commercial tracking、account takeover、不要なexposureを減らす。ただしanonymousになろうとはしない。

- full-disk encryption、automatic updates、screen lock、利用可能な場合はsecure bootを備えた、maintained OSを使用する。
- まずpassword manager、recovery email、phishing-resistant MFA/security keysを整える。
- app permissions、location history、advertising identifiers、cloud sync、third-party account connectionsを確認する。
- extensionsを少数に抑えたmainstream browserを使用し、tracking protection、HTTPSを有効にして、work/personal/high-risk browsing用に別々のprofilesを使う。
- 関係ごとにprivate relay aliasesまたは別々のemail addressesを使用する。単にoptionalである場合はpersonal phone numberを使わない。
- contentにはend-to-end encrypted messagingを優先する。ただしparticipants、timing、groups、endpointsはmetadataとして残ることを忘れない。
- filesからmetadataを意図的に削除し、公開前にoriginalではなくexported copyを検査する。
- payment-credential compartmentalizationにはvirtual-cardまたはwallet tokensを使用する。これらをanonymousとは呼ばない。
- encrypted recovery materialをbackupし、restorationをテストする。

## Pseudonymous publication

Goal: casual readersやplatformsがpublicationをcivil identityに簡単に紐付けられないようにする。これはcapableなtargeted investigationを阻止するものではない。

1. platform、hosting provider、readers、contacts、local network、payment provider、legal processのどれをthreat modelに含めるか定義する。
2. clean baselineからdedicated endpoint/account contextを作成する。personal browser sync、cloud documents、contact upload、notification previewsを無効にする。
3. 選択したnetwork compartmentを通じてpseudonymous accountを作成する。usernames、avatars、recovery channels、writing boilerplate、personal identity-provider loginを再利用しない。
4. destination unlinkabilityがspeedより重要な場合はTor Browserを使用する。extensionsを追加せず、大幅なresize/customizeを行わず、通常のdesktop sessionでonline中にdownloaded documentsを開かない。
5. personal template names、revision authors、printer paths、GPS/EXIF、thumbnails、hidden layersを埋め込まないprocessでdraftを作成する。copyをexportし、適切なmetadata toolsで検査する。
6. self-identifying factsをcontentから確認する。unique dates、workplace details、local weather/time zone、reflections、background audio、linguistic habits、prior-publication text reuseなどを確認する。
7. 別のreply channelを使用する。すべてのdirect contact、attachment、linkを、potentialなcorrelationまたはphishing attemptとして扱う。
8. moneyが関係する場合は、必要なdataだけをexposeするlawful methodを使用する。readersが知らなくても、platformとregulated intermediaryはpayeeを知っている可能性があると想定する。
9. publish後、別のclean contextからpublic resultを検査する。platformが追加または変換したものを記録する。
10. stableなbehavioral fingerprintを作らない場合に限り、計画したcadenceを維持する。compartmentを黙って再利用するのではなく、retireする。

serious journalism、activism、domestic abuse、state-level riskの場合は、経験豊富なdigital-security organizationから個別の支援を受けてください。static checklistではlocal lawやlive adversaryをmodel化できません。

## Authorized red-team engagement

Goal: authorization、control、incident responseを維持しながら、operatorsのpersonal identitiesとhome networksをtarget telemetryから排除する。

### Before the start window

- ROE infrastructure annex、targets/exclusions、source ranges、dates、emergency stop、third-party/provider permissionsを確定する。
- dedicated operator profileまたはVM、engagement secrets、evidence store、cloud project、domains、budgetを割り当てる。
- client-provided egressまたはorganization-controlled fixed bastionを優先する。full-tunnel IPv4/IPv6/DNS behaviorとfail-closed policyをテストする。
- operatorとpublic infrastructureの対応表をexercise controllerまたは合意済みのescrow contactと保管する。
- rate limits、destination allowlistsを設定し、destructive、wireless、physical、phishing、credential-collection actionsには別途approvalを設ける。
- organization-controlled payment railを使用し、approvalsを内部で記録する。

### During the engagement

- approved endpointとtunnelから開始し、assessment trafficの前にobserved egressを確認する。
- personal accounts、devices、phone numbers、repositories、SSH/GPG keys、cloud syncをcompartmentに持ち込まない。
- 不要なclient contentを収集せず、operator/job、start/stop、source、scoped destination、configuration changeをlogする。
- scope ambiguity、unexpected third-party systems、provider abuse notification、safety impact、lost equipment、controller contactの喪失があった場合は停止する。
- neighborのWi-Fi、stolen credentials、unapproved SIM/account、venueに隠したhardwareで決して即興的な対応をしない。

### End of engagement

- jobsとC2を停止し、approved drop devicesを回収し、tokens、credentials、certificatesをrevokeする。
- inventoryと照合して、infrastructure、domains、source addresses、expenses、data、provider casesをreconcileする。
- contractに従ってclient dataをreturn/delete/retainし、必要最小限のaudit evidenceを保持し、別のoperatorにshutdownをverifyさせる。

完全なbuildおよびteardown guideについては[Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)を参照してください。

## Lawful private purchase or donation

Goal: issuer、accounting、tax、sanctions obligationsを満たしながら、merchantまたはpublicに対するdisclosureを最小限にする。

1. 誰が何を知ってはならないかを列挙する：public audience、merchant、payment intermediary、employer/family account delegate、delivery service、blockchain observer。
2. local rules、recipient/counterparty、provider terms、cash limits、recordkeeping needsを確認する。
3. railを選択する：
- payment-network recordを残さない、accepted lawful local paymentsにはcash；
- online credential separationにはregulated virtual/merchant-specific card；
- cryptocurrencyは、acquisition、ledger、wallet backend、network、counterparty、later-spend linksを分析した後に限る。
4. 必須のdetailsはtruthfulなものを使用し、optionalなloyalty/marketing informationだけを省略する。他人のidentity/addressを使用したり、thresholdを回避するためにtransactionを分割したりしない。
5. merchant browser/account contextを分離し、無関係なsocial login、loyalty、personal recovery channelsを避ける。
6. statements、receipts、notifications、shipping、public donor listsに何が表示されるか確認する。
7. 必須のreceipt/tax/authorization evidenceをencryptedな状態で保存し、refund window後にdisposable payment credentialsをrevokeする。

[Private Digital Payments](private-digital-payments.md)と[Cryptocurrency Privacy](cryptocurrency-privacy.md)を参照してください。

## Travel and untrusted networks

Goal: userが管理していないnetworks上でdataとaccountsを保護する。unauthorized activityを隠すことではない。

- travel前にdevicesをupdateし、必要なcredentials/mapsをdownloadする。
- stored dataを最小限にし、full-disk encryption、strong unlock、remote-recovery planning、legal adviceに適したpowered-off border/physical-risk proceduresを使用する。
- venue SSID/captive portalを確認する。適切な場合はpersonal hotspotを優先するが、cellular subscriberとlocation recordsが残ることを忘れない。
- organizational dataにはfull/forced approved VPNを使用する。tethered devicesもVPNを共有していることを確認し、IPv6/DNS behaviorをテストする。
- client isolationとrepeatable policyのためにtravel routerを使用する。anonymityの保証として使ってはならない。
- public USB charging、borrowed computers、public printers、shared meeting-room systemsを別々のthreatとして扱う。
- physical presence、radio identifiers、portal login、cameras、payment/location recordsによってvisitがcorrelateされる可能性を想定する。

comparisonとsetup detailsについては[Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md)を参照してください。

## Failure and exposure response

compartmentがleakした、またはlinkされた可能性がある場合：

1. 継続によりharmが増える場合はactivityを停止する。該当する場合はengagement emergency stopを使用する。
2. sensitive dataを拡散せずに必要なevidenceをpreserveする。正確なtime、observed indicator、affected assetsを記録する。
3. 適切なowner/controller/security contactに通知する。privacy narrativeを維持するためにincidentを隠してはならない。
4. sessions、tokens、payment credentials、infrastructure accessをrevokeし、known-clean endpointからsecretsをrotateする。
5. どのedgesがlinkを作ったかを特定する：endpoint、account recovery、network、payment、metadata、content、behavior、counterparty、physical presence。
6. affected compartment全体がburnedになったものとして扱う。usernameやexit IPだけを変更して済ませない。
7. breach、provider、client、financial、legal notification dutiesを果たす。
8. linkの原因となったprocessを変更してからrebuildする。controlをdocumentし、テストする。

## Periodic audit

- [ ] Threat modelとlegal/provider assumptionsを、日付を定めたscheduleでreviewした。
- [ ] Devices、accounts、aliases、domains、network paths、payment credentialsをinventory化した。
- [ ] Recovery pathsが予期せずcompartmentsをcrossしていない。
- [ ] Full-tunnel、DNS、IPv6、fail-closed behaviorをテストした。
- [ ] Public filesとprofilesについてmetadata/content reuseを確認した。
- [ ] Wallet nodes/backendsとcrypto protocol assumptionsがcurrentな状態に保たれている。
- [ ] Logsとreceiptsがminimal、encrypted、access-controlledであり、retentionの範囲内にある。
- [ ] Old compartmentsとengagement infrastructureを完全にretireした。
