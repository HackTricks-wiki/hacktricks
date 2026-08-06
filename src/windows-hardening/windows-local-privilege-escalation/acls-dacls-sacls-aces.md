# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL) 由一组有序的 Access Control Entries (ACEs) 组成，用于规定对象及其属性的保护方式。本质上，ACL 定义了哪些 security principals（用户或组）可以或不可以对给定对象执行哪些操作。

ACL 有两种类型：

- **Discretionary Access Control List (DACL)：** 指定哪些用户和组可以或不可以访问对象。
- **System Access Control List (SACL)：** 负责对对象的访问尝试进行审计。

访问文件的过程中，系统会将对象的 security descriptor 与用户的 access token 进行比对，根据 ACEs 确定是否授予访问权限以及授予的访问范围。<sup>[[1]](#references)</sup>

### **Key Components**

- **DACL：** 包含向用户和组授予或拒绝对象访问权限的 ACEs。它本质上是决定访问权限的主要 ACL。
- **SACL：** 用于审计对对象的访问，其中的 ACEs 定义需要记录到 Security Event Log 中的访问类型。对于检测未授权访问尝试或排查访问问题，这一点非常有价值。<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

每个用户会话都关联一个 access token，其中包含与该会话相关的 security information，包括用户、组的身份以及权限。该 token 还包含一个用于唯一标识会话的 logon SID。

Local Security Authority (LSASS) 会通过检查 DACL，查找与尝试访问的 security principal 匹配的 ACEs，来处理对对象的访问请求。如果没有找到相关 ACEs，则会立即授予访问权限。否则，LSASS 会将这些 ACEs 与 access token 中 security principal 的 SID 进行比对，以确定是否允许访问。<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs：** 通过 DACLs 定义访问权限，并通过 SACLs 定义审计规则。
- **Access Token：** 包含会话的用户、组和权限信息。
- **Access Decision：** 通过将 DACL ACEs 与 access token 进行比较来决定；SACLs 用于审计。<sup>[[1]](#references)</sup>

### ACEs

Access Control Entries (ACEs) 主要有 **三种类型**：<sup>[[1]](#references)</sup>

- **Access Denied ACE**：在 DACL 中，此 ACE 会明确拒绝指定用户或组对对象的访问。
- **Access Allowed ACE**：在 DACL 中，此 ACE 会明确授予指定用户或组对对象的访问权限。
- **System Audit ACE**：位于 System Access Control List (SACL) 中，此 ACE 负责在用户或组尝试访问对象时生成审计日志。它会记录访问是被允许还是被拒绝，以及访问的具体类型。

每个 ACE 都包含 **四个关键组件**：<sup>[[1]](#references)</sup>

1. 用户或组的 **Security Identifier (SID)**（或图形界面中显示的 principal name）。
2. 用于标识 ACE 类型（access denied、allowed 或 system audit）的 **flag**。
3. 用于确定子对象是否可以从其父对象继承该 ACE 的 **Inheritance flags**。
4. 一个 [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)，即用于指定对象所授予权限的 32 位值。

系统会依次检查每个 ACE，直到出现以下情况之一，从而确定访问权限：<sup>[[1]](#references)</sup>

- **Access-Denied ACE** 明确拒绝 access token 中所标识 trustee 的请求权限。
- 一个或多个 **Access-Allowed ACE** 明确向 access token 中的 trustee 授予所有请求的权限。
- 检查完所有 ACEs 后，如果任何请求的权限都**未被明确允许**，则访问会被隐式**拒绝**。

### Order of ACEs

将 **ACEs**（规定谁可以或不可以访问某项内容的规则）放入称为 **DACL** 的列表时，其排列顺序非常重要。这是因为系统根据这些规则授予或拒绝访问后，就会停止检查其余规则。<sup>[[1]](#references)</sup>

组织这些 ACEs 有一种最佳方式，称为 **"canonical order"**。这种方法有助于确保系统运行顺畅且规则结果符合预期。对于 **Windows 2000** 和 **Windows Server 2003** 等系统，顺序如下：

- 首先，将所有**专门针对当前对象**的规则放在来自其他位置（例如父文件夹）的规则之前。
- 在这些专用规则中，将表示**“否”（deny）**的规则放在表示**“是”（allow）**的规则之前。
- 对于来自其他位置的规则，从**最近的来源**开始排列，例如先放父对象的规则，然后再向更远的来源排列。同样，将**“否”**放在**“是”**之前。

这种排列方式有两个重要作用：

- 确保只要存在特定的**“否”**规则，它就会被遵守，而不受其他**“是”**规则的影响。
- 让对象所有者可以在父文件夹或更远位置的规则生效前，最终决定谁可以访问该对象。

通过这种方式，文件或文件夹的所有者可以精确控制访问权限，确保正确的用户能够访问，而不应访问的用户无法访问。

![NTFS access control entry ordering diagram](https://www.ntfs.com/images/screenshots/ACEs.gif)

因此，**"canonical order"** 的核心就是确保访问规则清晰且有效：将特定规则放在前面，并以合理的方式组织所有规则。

### GUI Example

[**Example from here**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

这是文件夹的经典 security 选项卡，其中显示了 ACL、DACL 和 ACEs：

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

如果点击 **Advanced button**，将看到更多选项，例如继承：

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

如果添加或编辑 Security Principal：

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

最后，在 Auditing 选项卡中可以看到 SACL：

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

管理文件夹等资源的访问权限时，我们会使用称为 Access Control Lists (ACLs) 和 Access Control Entries (ACEs) 的列表和规则。这些内容定义了谁可以或不可以访问特定数据。<sup>[[1]](#references)</sup>

#### Denying Access to a Specific Group

假设有一个名为 Cost 的文件夹，并且希望所有人都能访问它，但 marketing 团队除外。通过正确设置规则，可以确保在允许其他所有人访问之前，先明确拒绝 marketing 团队的访问权限。具体做法是将拒绝 marketing 团队访问的规则放在允许所有人访问的规则之前。

#### Allowing Access to a Specific Member of a Denied Group

假设 Bob 是 marketing director，虽然 marketing 团队通常不应访问 Cost 文件夹，但 Bob 需要访问权限。可以为 Bob 添加一条授予访问权限的特定规则（ACE），并将其放在拒绝 marketing 团队访问的规则之前。这样，即使 Bob 所属的团队受到一般性限制，他仍然可以访问。

#### Understanding Access Control Entries

ACEs 是 ACL 中的单独规则。它们标识用户或组，指定允许或拒绝的访问权限，并确定这些规则如何应用于子项目（继承）。ACEs 主要有两种类型：

- **Generic ACEs**：广泛适用，可以影响所有类型的对象，或仅区分容器（例如文件夹）和非容器（例如文件）。例如，一条允许用户查看文件夹内容、但不允许访问其中文件的规则。
- **Object-Specific ACEs**：提供更精确的控制，允许针对特定类型的对象，甚至对象中的单个属性设置规则。例如，在用户目录中，可以允许用户更新自己的电话号码，但不允许其修改登录时间。

每个 ACE 都包含重要信息，例如规则适用的对象（通过 Security Identifier 或 SID 标识）、规则允许或拒绝的操作（通过 access mask 指定），以及该规则如何被其他对象继承。

#### Key Differences Between ACE Types

- **Generic ACEs** 适用于简单的访问控制场景，即同一规则应用于对象的所有方面，或应用于容器中的所有对象。
- **Object-Specific ACEs** 用于更复杂的场景，尤其是在 Active Directory 等环境中，需要针对对象的不同属性分别控制访问权限时。

总而言之，ACLs 和 ACEs 有助于定义精确的访问控制，确保只有正确的个人或组可以访问敏感信息或资源，并且能够将访问权限细化到单个属性或对象类型的级别。

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | 表示 ACE 类型的 flag。Windows 2000 和 Windows Server 2003 支持六种 ACE 类型：附加到所有可保护对象的三种通用 ACE 类型，以及适用于 Active Directory 对象的三种对象特定 ACE 类型。                                                                                                                                                                                                                                                            |
| Flags       | 用于控制继承和审计的一组 bit flags。                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | 为 ACE 分配的内存字节数。                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | 其各 bit 对应对象访问权限的 32 位值。Bit 可以设置为开启或关闭，但其具体含义取决于 ACE 类型。例如，如果对应读取权限的 bit 被开启，且 ACE 类型为 Deny，则该 ACE 会拒绝读取对象权限的权利。如果同一个 bit 被开启，但 ACE 类型为 Allow，则该 ACE 会授予读取对象权限的权利。Access mask 的更多详细信息见下表。 |
| SID         | 标识其访问权限由此 ACE 控制或监控的用户或组。                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | 对象特定访问权限      | 读取数据、执行、追加数据           |
| 16 - 22     | 标准访问权限             | 删除、写入 ACL、写入所有者            |
| 23          | 可以访问 security ACL            |                                           |
| 24 - 27     | 保留                           |                                           |
| 28          | Generic ALL（读取、写入、执行） | 以下所有权限                          |
| 29          | Generic Execute                    | 执行程序所需的所有操作 |
| 30          | Generic Write                      | 写入文件所需的所有操作   |
| 31          | Generic Read                       | 读取文件所需的所有操作       |

## References

- [1] [How the System Uses ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
