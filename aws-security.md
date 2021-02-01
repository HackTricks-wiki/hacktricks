# AWS Security

## IAM - Identity and Access Management

Authentication - Process of defining an identity and the verification of that identity. This process can be subdivided in: Identification and verification.  
Authorization - Determines what an identity can access within a system once it's been authenticated to it  
Access Control - The method and process of how access is granted to a secure resource

IAM can be defined by its ability to manage, control and govern authentication, authorization and access control mechanisms of identities to your resources within your AWS account.

* Users: This could be a real person within your organization who requires access to operate and maintain your AWS environment. Or it could be an account to be used by an application that may require permissions to access your AWS resources programmatically. Note that usernames must be unique.
* Groups: These are objects that contain multiple users. Permissions can be assigned to a user or inherit form a group. Giving permission to groups and not to users the secure way to grant permissions.
* Roles: Roles are used to grant identities a set of permissions. Roles don't have any access keys or credentials associated with them. Role are usually used with resources \(like EC2 machines\) but they can also be useful to grant temporary privileges to a user. Note that when for example an EC2 has an IAM role assigned, instead of saving some keys inside the machine, dynamic temporary access keys will be supplied by the IAM role to handle authentication and determine if access is authorized.
* Policy Permissions: Are used to assign permissions. There are 2 types: 
  * AWS managed policies \(preconfigured by AWS\)
  * Customer Managed Policies: Configured by you. You can create policies based on AWS managed policies \(modifying one of them and creating your own\), using the policy generator \(a GUI view that helps you granting and denying permissions\) or writing  your own..

```javascript
{
    "Version": "2012-10-17",  //Version of the policy
    "Statement": [  //Main element, there can be more than 1 entry in this array
        {
            "Sid": "Stmt32894y234276923" //Unique identifier (optional)
            "Effect": "Allow", //Allow or deny
            "Action": [  //Actions that will be allowed or denied
                "ec2:AttachVolume",
                "ec2:DetachVolume"
            ], 
            "Resource": [ //Resource the action and effect will be applied to
                "arn:aws:ec2:*:*:volume/*",
                "arn:aws:ec2:*:*:instance/*"
            ],
            "Condition": { //Optional element that allow to control when the permission will be effective
                "ArnEquals": {"ec2:SourceInstanceARN": "arn:aws:ec2:*:*:instance/instance-id"}
            }
        }
    ]
}
```

* Policies: By default access is denied, access will be granted if an explicit role has been specified. Conflict Permissions: But if single "Deny" exist, it will override the "Allow", except for requests that use the AWS account's root security credentials \(which are allowed by default\).
* Inline Policies: This kind of policies are directly assigned to a user, group or role. Then, they not appear in the Policies list as any other one can use them.
* S3 Bucket Policies: Can only be applied to S3 Buckets. They contains an attribute called 'principal' that can be: IAM users, Federated users, another AWS account, an AWS service. Principals define who/what should be allowed or denied access to various S3 resources

Access Key ID: 20 random uppercase alphanumeric characters like AKHDNAPO86BSHKDIRYT  
Secret access key ID: 40 random upper and lowercase characters: S836fh/J73yHSb64Ag3Rkdi/jaD6sPl6/antFtU \(It's not possible to retrieve lost secret access key IDs\).  
Access Key Rotation: Create a new access key -&gt; Apply the new key to system/application -&gt; mark original one as inactive -&gt; Test and verify new access key is working -&gt; Delete old access key

AWS Security Token Service \(STS\) is a web service that enables you to request temporary, limited-privilege credentials for AWS Identity and Access Management \(IAM\) users or for users that you authenticate \(federated users\).

### Multi-Factor Authentication

It's used to create an additional factor for authentication in addition to your existing methods, such as password, therefore, creating a multi-factor level of authentication.  
You can use a free virtual application or a physical device. You can use apps like google authentication for free to activate a MFA in AWS.

### Identity Federation

Identity federation allows users from identity providers which are external to AWS to access AWS resources securely without having to supply AWS user credentials from a valid IAM user account.   
An example of an identity provider can be your own corporate Microsoft Active Directory\(via SAML\) or OpenID services \(like Google\). Federated access will then allow the users within it to access AWS.  
AWS Identity Federation connects via IAM roles

#### Cross Account Trusts and Roles

A user \(trusting\) can create a Cross Account Role with some policies and then, allow another user \(trusted\) to access his account but only having the access indicated in the new role policies. To create this, just create a new Role and select Cross Account Role. Roles for Cross-Account Access offers two options. Providing access between AWS accounts that you own, and providing access between an account that you own and a third party AWS account.  
It's recommended to specify the user who is trusted and not put some generic thing because if not, other authenticated users like federated users will be able to also abuse this trust.

#### AWS Simple AD

Not supported:

* Trust Relations
* AD Admin Center
* Full PS API support
* AD Recycle Bin
* Group Managed Service Accounts
* Schema Extensions
* No Direct access to OS or Instances

#### Web Federation or OpenID Authentication

The app uses the AssumeRoleWithWebIdentity to create temporary credentials. However this doesn't grant access to the AWS console, just access to resources within AWS.

### Other IAM options

You can set a password policy setting options like minimum length and password requirements.  
You can download "Credential Report" with information about current credentials \(like user creation time, is password enabled...\)

### Key Management Service

Easily manage encryption keys to secure your data. These keys cannot be recovered.

## Cost Explorer and Anomaly detection

This allows you to check how are you expending money in AWS services and help you detecting anomalies.  
Moreover, you can configure an anomaly detection so AWS will warn you when some anomaly in costs is found.

### Budgets

Budgets help to manage costs and usage. You can get alerted when a threshold is reached.  
Also, they can be used for non cost related monitoring like the usage of a service \(how many GB are used in a particular S3 bucket?\)

## AWS CloudTrail

Resumen: monitorea el uso de las APIs y lo logea.

Tracks and monitors AWS API calls made within the environment. Each call to an API is logged inside an and it event contains:

* The name of the called API: `eventName`
* The called service: `eventSource`
* The time: `eventTime`
* The IP address: `SourceIPAddress`
* The agent method: `userAgent`. Examples:
  * Signing.amazonaws.com - From AWS Management Console
  * console.amazonaws.com - Root user of the account
  * lambda.amazonaws.com - AWS Lambda
* The request parameters: `requestParameters`
* The response elements: `responseElements`

Event's are written to a new log file each 5 minutes in a JSON file and log files are delivered to S3 15mins after.  
CloudTrail allows to use log file integrity in order to be able to verify that your log files have remained unchanged since CloudTrail delivered them to you. It created a SHA-256 hash of the logs inside a digest file. A sha-256 hash of the new logs is created every hour   
When creating a Trail the event selectors will allow you to indicate the trail to log: Management, data or insights events.

Logs are saved in an S3 bucket. By default Server Side Encryption is used \(SSE\) so AWS will decrypt the content for the people that has access to it, but for additional security you can use SSE with KMS and your own keys.

### Log File Naing Convention

![](.gitbook/assets/image%20%28253%29.png)

### S3 folder structure

Of log files:

![](.gitbook/assets/image%20%28430%29.png)

Of the digest files \(if integrity verification is required\):

![](.gitbook/assets/image%20%28413%29.png)

### Logs to CloudWatch

CloudTrail can automatically send logs to CloudWatch so you can set alerts that warns you when suspicious activities are performed.  
Note that in order to allow CloudTrail to send the logs to CloudWatch a role needs to be created that allows that action. If possible, it's recommended to use AWS default role to perform these actions. This role will allow CloudTrail to:

* CreateLogStream: This allows to create a CloudWatch Logs log streams
* PutLogEvents: Deliver CloudTrail logs to CloudWatch Logs log stream

### Event History

CloudTrail Event History allows you to inspect in a table the logs that have been recorded:

![](.gitbook/assets/image%20%28431%29.png)

## CloudWatch

Allows to create alarm based on logs. You can monitor for example logs from CloudTrail.  
CloudWatch Log Event have a size limitation of 256KB.  
Events that are monitored:

* Changes to Security Groups and NACLs
* Starting, Stopping, rebooting and terminating EC2instances
* Changes to Security Policies within IAM and S3
* Failed login attempts to the AWS Management Console
* API calls that resulted in failed authorization

## AWS Config

Resumen: Puede acceder a la config de cada objeto dentro de AWS y guardar los cambios que se realiezan. Tambien puede avisar de estos cambios. Molan mucho las cofig rules, cada vez que cambia el objeto minitorizado se checkea una rule \(una lambda function\) y sino cumple con la especificacion, avisa.

AWS Config can capture resource changes, so any change to a resource supported by Config can be recorded, which will record what changed along with other useful metadata, all held within a file known as a configuration item, a CI.  
It's region specific.

A configuration item or CI as it's known, is a key component of AWS Config. It is comprised of a JSON file that holds the configuration information, relationship information and other metadata as a point-in-time snapshot view of a supported resource. All the information that AWS Config can record for a resource is captured within the CI. A CI is created **every time** a supported resource has a change made to its configuration in any way. In addition to recording the details of the affected resource, AWS Config will also record CIs for any directly related resources to ensure the change did not affect those resources too.

* Metadata: contains details about the configuration item itself. a version ID and a configuration ID, which uniquely identifies the CI. other information can include an MD5Hash that allows you to compare other CIs already recorded against the same resource,
* Attributes: This holds common attribute information against the actual resource. Within this section, we also have a unique resource ID, and any key value tags that are associated to the resource. The resource type is also listed. For example, if this was a CI for an EC2 instance, the resource types listed could be the network interface, or the elastic IP address for that EC2 instance
* Relationships: This holds information for any connected relationship that the resource may have. So within this section, it would show a clear description of any relationship to other resources that this resource had. For example, if the CI was for an EC2 instance, the relationship section may show the connection to a VPC along with the subnet that the EC2 instance resides in.
* Current configuration. This will display the same information that would be generated if you were to perform a describe or list API call made by the AWS CLI. AWS Config uses the same API calls to get the same information.
* Related events. This relates to AWS CloudTrail. This will display the AWS CloudTrail event ID that is related to the change that triggered the creation of this CI. There is a new CI made for every change made against a resource. As a result, different CloudTrail event IDs will be created.

Configuration History: It's possible to obtain the configuration history of resources thanks to the configurations items. A configuration history is delivered every 6 hours and contains all CI's for a particular resource type.

* Configuration Streams - Configuration items are sent to an SNS Topic to enable analysis of the data
* Configuration Snapshots - Configuration items are used to create a point in time snapshot of all supported resources
* S3 is used to store the Configuration History files and any Configuration snapshots of your data within a single bucket, which is defined within the Configuration recorder.

Config rules: Great way to help you enforce specific compliance checks and controls across your resources, and allows you to adopt an ideal deployment specification for each of your resource types. Each rule **is essentially a lambda function** that when called upon evaluates the resource and carries out some simple logic to determine the compliance result with the rule. Each time a change is made to one of your supported resources, AWS Config will check the compliance against any config rules that you have in place. AWS have a number of predefined rules that fall under the security umbrella that are ready to use. For example, Rds-storage-encrypted. This checks whether storage encryption is activated by your RDS database instances. Encrypted-volumes. This checks to see if any EBS volumes that have an attached state are encrypted.

* AWS Managed rules: set of predefined rules that cover a lot of best practices, so it's always worth browsing these rules first before setting up your own as there is a chance that the rule may already exist.

Limit of 50 config rules per region before you need to contact AWS for an increase.

Non compliant results are NOT deleted.

## SNS Topic

SNS topic is used as a configuration stream for notifications of various events triggered by AWS Config. You can have various endpoints associated to the SNS stream. You can notify the alarm to you via Email send them to SQS and then programmatically analyze the results.

## AWS Inspector

Resumen: A partir de un agente corriendo en el EC2, saca CVEs, CIS checks, security best practices y runtime behaviour analysis.

The Amazon Inspector service is **agent based**, meaning it requires software agents to be installed on any EC2 instances you want to assess. This makes it an easy service to be configured and added at any point to existing resources already running within your AWS infrastructure. This helps Amazon Inspector to become a seamless integration with any of your existing security processes and procedures as another level of security.

* **CVEs**
* **CIS Benchmarks**
* **Security Best practices**
* **Runtime Behaviour Analysis**

You cam make any of those possibilities run on the EC2 machines you decide

Role: Create or select a role to allow Amazon Inspector to have read only access to the EC2 instances  
Assessment Targets: Group of EC2 instances that you want to run an assessment against  
AWS agents: Software agents that must be install on EC2 instances to monitor. Data is sent to Amazon Inspector using a TLS channel. A regular heartbeat is sent from the agent to the inspector asking for instructions. It can autoupdate itself  
Assessment Templates: Define specific configurations as to how an assessment is run on your EC2 instances. An assessment template cannot be modified after creation.

* Rules packages to be used
* Duration of the assessment run 15min/1hour/8hours
* SNS topics, select when notify: Starts, finished, change state, reports a finding
* Attributes to b assigned to findings 

Rule package: Contains a number of individual rules that are check against an EC2 when an assessment is run. Each one also have a severity \(high, medium, low, informational\). The possibilities are:

* Common Vulnerabilities and Exposures \(CVEs\)
* Center for Internet Security \(CIS\) Benchmark
* Security Best practices

Once you have configured the Amazon Inspector Role, the AWS Agents are Installed, the target is configured and the template is configured, you will be able to run it. An assessment run can be stopped, resumed, or deleted.

Telemetry: data that is collected from an instance, detailing its configuration, behavior and processes during an assessment run. Once collected, the data is then sent back to Amazon Inspector in near-real-time over TLS where it is then stored and encrypted on S3 via an ephemeral KMS key. Amazon Inspector then accesses the S3 Bucket, decrypts the data in memory, and analyzes it against any rules packages used for that assessment to generate the findings.

Assessment Report: Provide details on what was assessed and the results of the assessment. The findings report contain the summary of the assessment, info about the EC2 and rules and the findings that occurred. The full report is the finding report + a list of rules that were passed

## Trusted Advisor

Resumen: Compara el estado de la cuenta de AWS con las best practices de AWS.

The main function of [Trusted Advisor](https://cloudacademy.com/course/an-overview-of-aws-trusted-advisor/introduction-54/) is to recommend improvements across your [AWS](https://cloudacademy.com/library/amazon-web-services/) account to help optimize and hone your environment based on **AWS best practices**. These recommendations cover four distinct categories. It's a is a cross-region service.

1. Cost optimization, which helps to identify ways in which you could optimize your resources to save money.
2. Performance. This scans your resources to highlight any potential performance issues across multiple services.
3. Security. This category analyzes your environment for any potential security weaknesses or vulnerabilities.
4. And fault tolerance. Which suggests best practices to maintain service operations by increasing resiliency should a fault or incident occur across your resources.

The full power and potential of AWS Trusted Advisor is only really available if you have a business or enterprise support plan with AWS. Without either of these plans, then you will only have access to six core checks that are freely available to everyone. These free core checks are split between the performance and security categories, with the majority of them being related to security. These are the 6 checks: service limits, Security Groups Specific Ports Unrestricted, Amazon EBS Public Snapshots, Amazon RDS Public Snapshots, IAM Use, and MFA on root account.  
Trusted advisor can send notifications and you can exclude items from it.  
trusted advisor data is automatically refreshed every 24 hours, but you can perform a manual one 5 mins after the previous one

## Amazon GuardDuty

Resumen: Analiza logs de cloudtrail, vpc y dns para detectar comportamiento inesperado usando tecnicas comunes comocheckear IPs de blacklists y machine learning.

Amazon GuardDuty is a regional-based intelligent threat detection service, the first of its kind offered by AWS, which allows users to monitor their AWS account for unusual and unexpected behavior by analyzing AWS CloudTrail event logs, VPC flow logs \(network traffic information within the VPC\), and DNS logs. It then uses the data from logs and assesses them against multiple security and threat detection feeds, looking for anomalies and known malicious sources, such as IP addresses and URLs. It also uses Machine Learning to detect unexpected behaviours.  
You can upload list of whitelisted and blacklisted IP addresses so GuardDuty takes that info into account.

Finding summary:

* Finding type
* Severity: 7-8.9High, 4-6.9Medium, 01-3.9Low
* Region
* Account ID
* Resource ID
* Time of detection
* Which threat list was used

The body has this information:

* Resource affected
* Action
* Actor: Ip address, port and domain
* Additional Information

You can invite other accounts to a different AWS GuardDuty account so every account is monitored from the same GuardDuty. The master account must invite the member accounts and then the representative of the member account must accept the invitation.  
There are different IAM Role permissions to allow GuardDuty to get the information and to allow a user to upload IPs whitelisted and blacklisted.  
GuarDuty uses a service-linked role called "AWSServiceRoleForAmazonGuardDuty" that allows it to retrieve metadata from affected endpoints.

You pay for the processing of your log files, per 1 million events per months from CloudTrail and per GB of analysed logs from VPC Flow

When a user disable GuardDuty, it will stop monitoring your AWS environment and it won't generate any new findings at all, and the existing findings will be lost.  
If you just stop it, the existing findings will remain.

## Amazon Macie

Resumen: Le indicas el storage que quieres monitorizar \(S3 en general\) y va a detectar que tipo de contenido es y si es sensible o no y mirara tambien los permisos que el storage tiene asignado. Util para detectar cosas que no deberian estar donde estan y para prevenir leaks.

The main function of the service is to provide an automatic method of detecting, identifying, and also classifying data that you are storing within your AWS account.

The service is backed by machine learning, allowing your data to be actively reviewed as different actions are taken within your AWS account. Machine learning can spot access patterns and user behavior by analyzing cloud trail event data to alert against any unusual or irregular activity. Any findings made by Amazon Macie are presented within a dashboard which can trigger alerts, allowing you to quickly resolve any potential threat of exposure or compromise of your data.

There are a number of key features that are offered by Amazon Macie during its detection and classification process. These can be summarized as follows. Amazon Macie will automatically and continuously monitor and detect new data that is stored in Amazon S3. Using the abilities of machine learning and artificial intelligence, this service has the ability to familiarize over time, access patterns to data. Amazon Macie also uses natural language processing methods to help classify and interpret different data types and content. NLP uses principles from computer science and computational linguistics to look at the interactions between computers and the human language. In particular, how to program computers to understand and decipher language data. The service can automatically assign business values to data that is assessed in the form of a risk score. This enables Amazon Macie to order findings on a priority basis, enabling you to focus on the most critical alerts first. In addition to this, Amazon Macie also has the added benefit of being able to monitor and discover security changes governing your data. As well as identify specific security-centric data such as access keys held within an S3 bucket. 

This protective and proactive security monitoring enables Amazon Macie to identify critical, sensitive, and security focused data such as API keys, secret keys, in addition to PII and PHI data. It can detect changes and alterations to existing security policies and access control lists which effect data within your S3 buckets. It will also alert against unusual user behavior and maintain compliance requirements as required. 

This is useful to avoid data leaks as Macie will detect if you are exposing people information to the Internet.

It's a regional service.

It requires the existence of IAM Role 'AWSMacieServiceCustomerSetupRole' and it needs AWS CloudTrail to be enabled.

Pre-defined alerts categories:

* Anonymized access
* Config compliance
* Credential Loss
* Data compliance
* Files hosting
* Identity enumeration
* Information loss
* Location anomaly
* Open permissions
* Privilege escalation
* Ransomware
* Service disruption
* Suspicious access

Alert summary: Provides detailed information to allow you to respond appropriately. It has a description that provides a deeper level of understanding of why it was generated. It also has a breakdown of the results.  

The user has the possibility to create new custom alerts.

