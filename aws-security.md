# AWS Security

## IAM - Identity and Access Management

IAM can be defined by its ability to manage, control and govern authentication, authorization and access control mechanisms of identities to your resources within your AWS account.

* Users: This could be a real person within your organization who requires access to operate and maintain your AWS environment. Or it could be an account to be used by an application that may require permissions to access your AWS resources programmatically.
* Groups: These are objects that contain multiple users. Permissions can be assigned to a user or inherit form a group. Giving permission to groups and not to users the secure way to grant permissions.
* Roles: Roles are used to grant identities a set of permissions. Roles don't have any access keys or credentials associated with them. Role are usually used with resources \(like EC2 machines\) but they can also be useful to grant temporary privileges to a user
* Policy Permissions: Are used to assign permissions. There are 2 types: 
  * AWS managed policies \(preconfigured by AWS\)
  * Customer Managed Policies: Configured by you. You can create policies based on AWS managed policies by copy/pasting or using the policy generator.

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

* Policies: By default access is denied, access will be granted if an explicit role has been specified. But if single "Deny" exist, it will override the "Allow", except for requests that use the AWS account's root security credentials \(which are allowed by default\).
* Inline Policies: This kind of policies are directly assigned to a user, group or role. Then, they ot appear in the Policies list as any other one can use them.

Access Key ID: 20 random uppercase alphanumeric characters like AKHDNAPO86BSHKDIRYT  
Secret access key ID: 40 random upper and lowercase characters: S836fh/J73yHSb64Ag3Rkdi/jaD6sPl6/antFtU \(It's not possible to retrieve lost secret access key IDs\).

### Multi-Factor Authentication

It's used to create an additional factor for authentication in addition to your existing methods, such as password, therefore, creating a multi-factor level of authentication.  
You can use a free virtual application or a physical device. You can use apps like google authentication for free to activate a MFA in AWS.

### Identity Federation

Identity federation allows users from identity providers which are external to AWS to access AWS resources securely without having to supply AWS user credentials from a valid IAM user account.   
An example of an identity provider can be your own corporate Microsoft Active Directory\(via SAML\) or OpenID services \(like Google\). Federated access will then allow the users within it to access AWS.

### Other IAM options

You can set a password policy setting options like minimum length and password requirements.  
You can download "Credential Report" with information about current credentials \(like user creation time, is password enabled...\)

### Key Management Service

Easily manage encryption keys to secure your data. These keys cannot be recovered.

