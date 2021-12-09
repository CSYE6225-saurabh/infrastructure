# infrastructure: Assignment 2

### Name : Saurabh Ambardekar
### NUID : 001099026
### Course: CSYE 6225 Network Structures and Cloud Computing

Steps:
1. Add AWS credentials for dev and prod accounts.
2. Create VPC for CIDR block
3. Create three subnets for CIDR block
4. Create Internet gateway
5. Create Routes, Route Tables and Route Table association for Internet gateway and Subnets
6. SSL command: aws acm import-certificate --certificate fileb://prod_csye6225saurabh_me.crt --certificate-chain fileb://prod_csye6225saurabh_me.ca-bundle --private-key fileb://private.key --profile prod