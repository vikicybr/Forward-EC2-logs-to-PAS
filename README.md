# Forward-EC2-logs-to-PAS

To help organization address the challenge of monitoring privileged cloud users in cloud environment, and detecting, alerting, and responding to high-risk privileged access,

Privileged Threat Analytics capabilities can be used to improve the efficiency of Cloud security teams and to secure threats within the Amazon Web Services (AWS) environment.

This solution handles : 

 - Detect privileged cloud activities that bypassed the Vault, and alert on suspicious credentials theft, and suspicious password changes. 
 - Alert and take control over the managed accounts by initiating credentials rotation.


## Solution process description
-------------------------------
Each new Linux server that is spun up in the AWS account will be configured to send Syslog to the CyberArk PTA 


## Requirements 
-------------------------------
- PAS version version 10.7 and up (Vault + PVWA + CPM required)
- Network environment must contain NAT GW for the Lambda deployment to succeed , We advice to use the CyberArk network template with NAT
- Network access from the VPC in which the Lambda is deployed  to the PVWA 
- Network access from the VPC in which the Lambda is deployed to the VPC in which the Linux instance is deployed 
- Target devices (Linux instances) must have Security Group with the following inbound port: 22 and outbound port 514 udp
  - Best practice is to have port 22 open only to Lambda’s Security group 
  - Port 514 open only to PTA Security Group
 
 

## Deployment Parameters 

| Parameter                            | Description                                                  | 
|--------------------------------------|--------------------------------------------------------------|
| Bucket Name                          | Enter the name of the bucket of the solution Lambda          | 
| Solution Subnet                      | Enter the subnet in which the solution will be deployed      | 
| Solution VPC                         | Enter the VPC in which the solution will be deployed         | 
| PVWA IP                              | Enter the IP of the PVWA                                     | 
| PVWA Security Group                  | Enter the name of the security group of the PVWA             | 
| PTA IP                               | Enter the IP of the PTA                                      | 
| Vault user name                      | Enter the Vault user name                                    | 
| Vault password	                     | Enter the Vault password                                     | 
| Keypair safe                         | Enter the name of the safe in which the keypairs will be stored | 
| Keypair name                         | Enter the keypair name (Optional)                            | 

Regarding the KeyPair Safe : 
- If doesnt exist it will be created
- You can either upload existing keypair or create one in this template         | 


## Limitations 

- Only both flavors of AWS Linux AMI are supported in this solution 
- Deployment of the lambdas solution must be done per region , only Linux servers spinning up in the same region will be updated by the solution.
- Only Linux instances that are created with a keypair that is available in the keypair safe will be handled by the solution 


## Manual procedure to change the PTA IP after the solution is deployed 

In AWS console → open EC2 dashboard  in left pane, go to Parameter Store →  look for ‘PTAIP’ parameter →  edit parameter as you wish


## Upload your own SSH key

- Create SSH key safe in the Vault or use the cloud formation template to create the safe 
- Convert your AWS SSH key from PEM to PPK (using PUTTYGEN)
- Upload the PPK key pairs used to create instances in your AWS region to the Key Pair Safe in the Vault

                  Note  :  Update the account User name with the following naming convention: AWS.[AWS Account].[Region name].[key pair name]


## Troubleshooting Tools

- All Instance configuration status is saved in a DynamoDB table that is located under : DynamoDB→ Tables → Instances 

- Logs : In AWS  console → go to Lambda service → Choose your lambda’s name from the list → Press on monitoring → press on “view logs in cloudwatch”


## Licensing 

Copyright 1999-2018 CyberArk Software Ltd.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.



