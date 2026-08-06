# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL) は、オブジェクトとそのプロパティに対する保護を定義する、順序付けられた Access Control Entry (ACE) の集合です。つまり ACL は、特定のオブジェクトに対して、どの security principal（ユーザーまたはグループ）がどのアクションを実行できるか、または拒否されるかを定義します。

ACL には次の 2 種類があります。

- **Discretionary Access Control List (DACL):** どのユーザーやグループがオブジェクトにアクセスできるか、またはアクセスできないかを指定します。
- **System Access Control List (SACL):** オブジェクトへのアクセス試行に対する auditing を管理します。

ファイルへのアクセス時、システムはオブジェクトの security descriptor とユーザーの access token を照合し、ACE に基づいてアクセスを許可するかどうか、および許可するアクセス範囲を判断します。<sup>[[1]](#references)</sup>

### **Key Components**

- **DACL:** オブジェクトに対するユーザーやグループのアクセス権を許可または拒否する ACE を含みます。アクセス権を決定する主要な ACL です。
- **SACL:** オブジェクトへのアクセスを auditing するために使用されます。ACE によって、Security Event Log に記録するアクセスの種類を定義します。未承認のアクセス試行の検出や、アクセス問題の troubleshooting に非常に役立ちます。<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

各ユーザー session には access token が関連付けられており、その session に関係する security 情報（ユーザー、グループの identity、privilege など）が含まれています。この token には、その session を一意に識別する logon SID も含まれます。

Local Security Authority (LSASS) は、アクセスを試行している security principal に一致する ACE が DACL に存在するかを確認し、オブジェクトへのアクセス要求を処理します。該当する ACE が見つからない場合、アクセスは直ちに許可されます。それ以外の場合、LSASS は access token 内の security principal の SID と ACE を比較し、アクセスが許可されるかどうかを判断します。<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs:** DACLs によってアクセス権を定義し、SACLs によって auditing ルールを定義します。
- **Access Token:** session のユーザー、グループ、privilege 情報を含みます。
- **Access Decision:** DACL の ACE と access token を比較して決定されます。SACLs は auditing に使用されます。<sup>[[1]](#references)</sup>

### ACEs

Access Control Entries (ACEs) には、主に **3 つのタイプ**があります。<sup>[[1]](#references)</sup>

- **Access Denied ACE**: 指定されたユーザーまたはグループに対するオブジェクトへのアクセスを明示的に拒否する ACE です（DACL 内）。
- **Access Allowed ACE**: 指定されたユーザーまたはグループに対するオブジェクトへのアクセスを明示的に許可する ACE です（DACL 内）。
- **System Audit ACE**: System Access Control List (SACL) 内に配置され、ユーザーまたはグループによるオブジェクトへのアクセス試行時に audit log を生成する ACE です。アクセスが許可されたか拒否されたか、およびアクセスの種類を記録します。

各 ACE には、**4 つの重要なコンポーネント**があります。<sup>[[1]](#references)</sup>

1. ユーザーまたはグループの **Security Identifier (SID)**（graphical representation では principal name）。
2. ACE のタイプ（access denied、allowed、system audit）を識別する **flag**。
3. 子オブジェクトが親から ACE を継承できるかどうかを決定する **inheritance flags**。
4. [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)。オブジェクトに付与される権限を指定する 32-bit 値です。

アクセスの判定は、次のいずれかに該当するまで各 ACE を順番に確認して行われます。<sup>[[1]](#references)</sup>

- **Access-Denied ACE** が、access token 内で識別された trustee に対して、要求された権限を明示的に拒否する。
- **Access-Allowed ACE(s)** が、access token 内の trustee に対して、要求されたすべての権限を明示的に付与する。
- すべての ACE を確認した結果、要求された権限のいずれかが明示的に許可されていない場合、アクセスは暗黙的に **拒否** される。

### Order of ACEs

**ACEs**（誰が何にアクセスできるか、またはできないかを示すルール）を **DACL** と呼ばれる list に配置する方法は非常に重要です。これは、システムがこれらのルールに基づいてアクセスを許可または拒否すると、残りのルールの確認を停止するためです。<sup>[[1]](#references)</sup>

ACEs を整理する最適な方法は **「canonical order」** と呼ばれます。この方法により、すべてが円滑かつ適切に動作します。**Windows 2000** や **Windows Server 2003** などのシステムでは、次のように配置します。

- まず、その項目のために **明示的に設定された** ルールを、親 folder など別の場所から継承されたルールより前に配置します。
- 明示的に設定されたルールでは、**「no（deny）」** のルールを **「yes（allow）」** のルールより前に配置します。
- 継承されたルールでは、**最も近い source**（親など）からのルールを最初に配置し、その後に遠い source のルールを配置します。ここでも **「no」** を **「yes」** より前にします。

この構成には、主に 2 つの大きな利点があります。

- 特定の **「no」** が存在する場合、他にどれだけ **「yes」** のルールがあっても、その拒否が確実に尊重されます。
- 親 folder やさらに上位の場所からのルールが適用される前に、項目の owner が誰をアクセスさせるかについて **最終的な決定権** を持てます。

このように配置することで、file や folder の owner はアクセスできるユーザーを非常に細かく指定でき、適切なユーザーだけがアクセスできるようにし、不適切なユーザーを拒否できます。

![NTFS access control entry の順序を示す diagram](https://www.ntfs.com/images/screenshots/ACEs.gif)

この **「canonical order」** は、アクセスルールを明確かつ適切に機能させるために、明示的なルールを先に配置し、全体を合理的な順序で整理する仕組みです。

### GUI Example

[**こちらの Example**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

これは folder の classic security tab で、ACL、DACL、ACEs を表示したものです。

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

**Advanced button** をクリックすると、inheritance などの追加 options が表示されます。

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

また、Security Principal を追加または編集すると、次のようになります。

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

最後に、Auditing tab には SACL があります。

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

folder などの resource へのアクセスを管理する際には、Access Control Lists (ACLs) や Access Control Entries (ACEs) と呼ばれる list とルールを使用します。これらによって、特定の data にアクセスできるユーザーと、アクセスできないユーザーを定義します。<sup>[[1]](#references)</sup>

#### Denying Access to a Specific Group

Cost という名前の folder があり、marketing team 以外の全員にアクセスさせたいとします。ルールを正しく設定すれば、全員にアクセスを許可する前に、marketing team のアクセスを明示的に拒否できます。これは、marketing team のアクセスを拒否するルールを、全員へのアクセスを許可するルールより前に配置することで実現します。

#### Allowing Access to a Specific Member of a Denied Group

marketing director の Bob は、marketing team 全体には通常アクセスを許可しない場合でも、Cost folder へのアクセスが必要だとします。Bob にアクセスを付与する特定のルール（ACE）を追加し、marketing team へのアクセスを拒否するルールより前に配置できます。これにより、team 全体に対する制限があっても Bob はアクセスできます。

#### Understanding Access Control Entries

ACEs は ACL 内の個別のルールです。ユーザーまたはグループを識別し、許可または拒否されるアクセスを指定し、これらのルールを sub-item にどのように適用するか（inheritance）を決定します。ACEs には主に次の 2 種類があります。

- **Generic ACEs**: 広範囲に適用され、すべてのタイプの object に影響するか、container（folder など）と non-container（file など）の区別だけを行います。たとえば、ユーザーに folder の contents の表示を許可する一方で、その中の file へのアクセスは許可しないルールなどです。
- **Object-Specific ACEs**: より精密な control を提供し、特定のタイプの object、または object 内の個別の property に対してルールを設定できます。たとえば、users の directory で、ユーザー自身の phone number の更新は許可する一方、login hours の変更は許可しないルールなどです。

各 ACE には、ルールの適用対象（Security Identifier または SID を使用）、ルールが許可または拒否する内容（access mask を使用）、他の object にどのように継承されるかなどの重要な情報が含まれます。

#### Key Differences Between ACE Types

- **Generic ACEs** は、object のすべての要素、または container 内のすべての object に同じルールを適用する単純な access control scenario に適しています。
- **Object-Specific ACEs** は、より複雑な scenario で使用されます。特に Active Directory のような environment では、object の特定の property ごとに異なる access control が必要になる場合があります。

要約すると、ACLs と ACEs は精密な access control を定義するために役立ち、適切な個人またはグループだけが機密情報や resource にアクセスできるようにします。また、個別の property や object type のレベルまで access rights を調整できます。

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | ACE のタイプを示す flag。Windows 2000 と Windows Server 2003 は、6 種類の ACE をサポートします。すべての securable object に付加される 3 種類の generic ACE と、Active Directory object に存在する 3 種類の object-specific ACE です。                                                                                                                                                                                                                                                            |
| Flags       | inheritance と auditing を制御する bit flag の集合。                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | ACE に割り当てられる memory の byte 数。                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | object の access rights に対応する bit を持つ 32-bit 値。bit は on または off にできますが、その設定の意味は ACE のタイプによって異なります。たとえば、permissions を読み取る権限に対応する bit が on で、ACE のタイプが Deny の場合、ACE は object の permissions を読み取る権限を拒否します。同じ bit が on で ACE のタイプが Allow の場合、ACE は object の permissions を読み取る権限を付与します。Access mask の詳細は次の table に示します。 |
| SID         | この ACE によって access が control または monitor されるユーザーまたはグループを識別します。                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | data の読み取り、Execute、data の Append           |
| 16 - 22     | Standard Access Rights             | Delete、ACL の Write、Owner の Write            |
| 23          | Security ACL にアクセス可能        |                                           |
| 24 - 27     | Reserved                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | 以下のすべて                          |
| 29          | Generic Execute                    | program の実行に必要なすべての操作 |
| 30          | Generic Write                      | file への書き込みに必要なすべての操作   |
| 31          | Generic Read                       | file の読み取りに必要なすべての操作       |

## References

- [1] [システムが ACLs を使用する方法 - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL、DACL、SACL、ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
