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



## CloudWatch

Allows to create alarm based on logs. You can monitor for example logs from CloudTrail.  
CloudWatch Log Event have a size limitation of 256KB.  
Events that are monitored:

* Changes to Security Groups and NACLs
* Starting, Stopping, rebooting and terminating EC2instances
* Changes to Security Policies within IAM and S3
* Failed login attempts to the AWS Management Console
* API calls that resulted in failed authorization

