resource "aws_vpc" "vpc-name" {
  cidr_block                       = var.vpc_cidr_block
  enable_dns_hostnames             = var.vpcConfig.enable_dns_hostnames
  enable_dns_support               = var.vpcConfig.enable_dns_support
  enable_classiclink_dns_support   = var.vpcConfig.enable_classiclink_dns_support
  assign_generated_ipv6_cidr_block = var.vpcConfig.assign_generated_ipv6_cidr_block

  tags = {
    Name = var.vpc_name
  }
}

resource "aws_subnet" "subnet-name" {
  depends_on              = [aws_vpc.vpc-name]
  for_each                = var.subnet_cidr
  cidr_block              = each.value
  vpc_id                  = aws_vpc.vpc-name.id
  availability_zone       = each.key
  map_public_ip_on_launch = var.map_public_ip_on_launch
  tags = {
    Name = "csye6225-subnet-${each.key}-fall2021"
  }
}

resource "aws_security_group" "applicationSecurityGroup" {
  name        = "application-security-group"
  description = "Security Group for Web Application"
  vpc_id      = aws_vpc.vpc-name.id

  ingress = [
    {
      description      = "SSH"
      from_port        = 22
      to_port          = 22
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "HTTP"
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "HTTPS"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "NODE"
      from_port        = 4000
      to_port          = 4000
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    }
  ]

  egress = [
    {
      description      = "HTTP"
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "HTTPS"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "SQL"
      from_port        = 3306
      to_port          = 3306
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
  ]
  tags = {
    Name = "application-security-group"
  }
}

resource "aws_security_group" "databaseSecurityGroup" {
  name        = "database-security-group"
  description = "Security Group for Database Configuration"
  vpc_id      = aws_vpc.vpc-name.id

  ingress = [
    {
      description      = "MYSQL"
      from_port        = 3306
      to_port          = 3306
      protocol         = "tcp"
      cidr_blocks      = [aws_vpc.vpc-name.cidr_block]
      security_groups  = [aws_security_group.applicationSecurityGroup.name]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    }
  ]
  tags = {
    Name = "database-security-group"
  }
}

resource "aws_security_group" "loadBalancerSecurityGroup" {
  name   = "loadbalancer-security-group"
  vpc_id = aws_vpc.vpc-name.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  /* ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  } */
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name        = "loadbalancer-security-group"
    Environment = "us-east-1"
  }
}

resource "aws_internet_gateway" "internetGateway" {
  vpc_id = aws_vpc.vpc-name.id
  tags = {
    Name = var.ig_name
  }
}

resource "aws_route_table" "routeTable" {
  vpc_id = aws_vpc.vpc-name.id
  tags = {
    Name = var.route_table_name
  }
}

data "aws_subnet_ids" "subnetIDs" {
  depends_on = [aws_vpc.vpc-name, aws_subnet.subnet-name]
  vpc_id     = aws_vpc.vpc-name.id
}

resource "aws_db_subnet_group" "rdsDatabaseSubnetGroup" {
  name       = "subnet-group-rds-database"
  subnet_ids = data.aws_subnet_ids.subnetIDs.ids
}

resource "aws_db_parameter_group" "rdsDatabaseParameterGroup" {
  name   = "rds-database-parameter-group"
  family = "mysql8.0"
}

resource "aws_kms_key" "EncryptRDS" {
  description = "RDS-encryption-key"
  policy      = <<-EOF
  {
    "Version": "2012-10-17",
    "Id": "key-default-1",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::${var.account_id}:root",
                    "arn:aws:iam::${var.account_id}:user/prod"
                ]
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow service-linked role use of the customer managed key",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${var.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey"
            ],
            "Resource": "*"
        }
    ]
}
EOF

}

resource "aws_db_instance" "rdsInstance" {
  identifier                   = var.rds_identifier
  name                         = var.rds_identifier
  instance_class               = "db.t3.micro"
  storage_type                 = "gp2"
  skip_final_snapshot          = true
  allocated_storage            = 20
  max_allocated_storage        = 0
  multi_az                     = false
  engine                       = "mysql"
  engine_version               = "8.0.25"
  username                     = var.rds_username
  password                     = var.rds_password
  db_subnet_group_name         = aws_db_subnet_group.rdsDatabaseSubnetGroup.name
  vpc_security_group_ids       = [aws_security_group.databaseSecurityGroup.id]
  availability_zone            = var.az1
  parameter_group_name         = aws_db_parameter_group.rdsDatabaseParameterGroup.name
  publicly_accessible          = true
  backup_retention_period      = 1
  storage_encrypted            = true
  kms_key_id                   = aws_kms_key.EncryptRDS.arn
}

resource "aws_db_instance" "rdsReplicaInstance" {
  identifier          = "read-replica"
  replicate_source_db = aws_db_instance.rdsInstance.identifier
  instance_class      = "db.t3.micro"
  name                = "csye6225-replica"
  engine              = "mysql"
  engine_version      = "8.0.25"
  availability_zone   = var.az2
  publicly_accessible = false
  skip_final_snapshot = true
  //storage_encrypted = true
}

resource "aws_route" "routes" {
  route_table_id         = aws_route_table.routeTable.id
  destination_cidr_block = var.destination_cidr_block
  gateway_id             = aws_internet_gateway.internetGateway.id
  depends_on             = [aws_route_table.routeTable]
}

resource "aws_route_table_association" "routeTableAssociation" {
  for_each       = aws_subnet.subnet-name
  subnet_id      = each.value.id
  route_table_id = aws_route_table.routeTable.id
}

resource "aws_s3_bucket" "s3BucketConfig" {
  bucket        = "${var.s3_name}.${var.profile}.${var.s3_domain}"
  acl           = "private"
  force_destroy = true

  lifecycle_rule {
    id      = "long-term"
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_key_pair" "sshKey" {
  key_name   = "sshKey"
  public_key = var.ec2_ssh_key
}

// resource "aws_instance" "webappInstance" {
//   ami                     = var.ec2_ami_id
//   instance_type           = "t2.micro"
//   iam_instance_profile    = aws_iam_instance_profile.s3Profile.name
//   disable_api_termination = false
//   key_name                = aws_key_pair.sshKey.key_name
//   vpc_security_group_ids  = [aws_security_group.applicationSecurityGroup.id]
//   subnet_id               = element(tolist(data.aws_subnet_ids.subnetIDs.ids), 0)
// user_data               = <<-EOF
// #! /bin/bash
//       cd /home/ubuntu/
//       mkdir ./server
//       cd server
//       echo "{\"host\":\"${aws_db_instance.rdsInstance.endpoint}\",\"username\":\"${var.rds_username}\",\"password\":\"${var.rds_password}\",\"database\":\"${var.rds_identifier}\",\"port\":3306,\"s3\":\"${aws_s3_bucket.s3BucketConfig.bucket}\"}" > config.json
//       cd ..
//       sudo chmod -R 777 server
// EOF

//   root_block_device {
//     delete_on_termination = true
//     volume_size           = 20
//     volume_type           = "gp2"
//   }

//   tags = {
//     Name = "Webapp Instance"
//   }
// }
resource "aws_kms_key" "kms" {
  description             = "KMS"
  deletion_window_in_days = 10
  policy                  = <<EOF
    {
        "Version": "2012-10-17",
        "Id": "key-default-1",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::${var.account_id}:root",
                        "arn:aws:iam::${var.account_id}:user/prod"
                    ]
                },
                "Action": "kms:*",
                "Resource": "*"
            },
            {
                "Sid": "Allow service-linked role use of the customer managed key",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::${var.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
                },
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey"
                ],
                "Resource": "*"
            },
            {
                "Sid": "Allow attachment of persistent resources",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::${var.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
                },
                "Action": "kms:CreateGrant",
                "Resource": "*",
                "Condition": {
                    "Bool": {
                        "kms:GrantIsForAWSResource": "true"
                    }
                }
            }
        ]
    }
    EOF
}

terraform {
  required_providers {
    template = {
      source = "hashicorp/template"
    }
  }
}

data "template_file" "template_file" {
  template = <<-EOF
    #! /bin/bash
    cd /home/ubuntu/
    mkdir ./server
    cd server
    echo "{\"host\":\"${aws_db_instance.rdsInstance.endpoint}\",\"hostReadReplica\":\"${aws_db_instance.rdsReplicaInstance.endpoint}\",\"username\":\"${var.rds_username}\",\"password\":\"${var.rds_password}\",\"database\":\"${var.rds_identifier}\",\"port\":3306,\"s3\":\"${aws_s3_bucket.s3BucketConfig.bucket}\",\"topic_arn\":\"${aws_sns_topic.EmailNotificationRecipient.arn}\"}" > config.json
    cd ..
    sudo chmod -R 777 server
  EOF
}

resource "aws_launch_template" "launchTemplate" {
  name          = "launch-template"
  image_id      = var.ec2_ami_id
  instance_type = "t2.micro"
  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.applicationSecurityGroup.id]
  }

  key_name = aws_key_pair.sshKey.key_name
  iam_instance_profile {
    name = aws_iam_instance_profile.s3Profile.name
  }

  user_data = base64encode(data.template_file.template_file.rendered)

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 20
      encrypted             = true
      kms_key_id            = aws_kms_key.kms.arn
      delete_on_termination = true
    }
  }
  // depends_on = [aws_s3_bucket.bucket, aws_db_instance.rds_ins]
}

// resource "aws_launch_configuration" "launchConfiguration" {
//   name                        = "launch-configuration"
//   image_id                    = var.ec2_ami_id
//   instance_type               = "t2.micro"
//   security_groups             = [aws_security_group.applicationSecurityGroup.id]
//   key_name                    = aws_key_pair.sshKey.key_name
//   iam_instance_profile        = aws_iam_instance_profile.s3Profile.name
//   associate_public_ip_address = true
//   user_data                   = <<-EOF
//   #! /bin/bash
//         cd /home/ubuntu/
//         mkdir ./server
//         cd server
//         echo "{\"host\":\"${aws_db_instance.rdsInstance.endpoint}\",\"hostReadReplica\":\"${aws_db_instance.rdsReplicaInstance.endpoint}\",\"username\":\"${var.rds_username}\",\"password\":\"${var.rds_password}\",\"database\":\"${var.rds_identifier}\",\"port\":3306,\"s3\":\"${aws_s3_bucket.s3BucketConfig.bucket}\",\"topic_arn\":\"${aws_sns_topic.EmailNotificationRecipient.arn}\"}" > config.json
//         cd ..
//         sudo chmod -R 777 server
//   EOF

//   root_block_device {
//     volume_type           = "gp2"
//     volume_size           = 20
//     delete_on_termination = true
//   }
//   // depends_on = [aws_s3_bucket.bucket, aws_db_instance.rds_ins]
// }

resource "aws_lb_listener" "webappListener" {
  load_balancer_arn = aws_lb.applicationLoadBalancer.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = "arn:aws:acm:us-east-1:970904211705:certificate/e90f6ccc-1b93-4679-b978-a1867b67315e"
  // certificate_arn   = "${data.aws_acm_certificate.aws_ssl_certificate.arn}"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.loadbalancerTargetGroup.arn
  }
}


resource "aws_lb_target_group" "loadbalancerTargetGroup" {
  name     = "TargetGroupLoadBalancer"
  port     = "4000"
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc-name.id
  tags = {
    name = "Target Group for Load Balancer"
  }
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    timeout             = 5
    interval            = 30
    path                = "/healthstatus"
    port                = "4000"
    matcher             = "200"
  }
}


resource "aws_autoscaling_group" "autoscalingGroup" {
  name = "autoscalingGroup"
  launch_template {
    id      = aws_launch_template.launchTemplate.id
    version = aws_launch_template.launchTemplate.latest_version
  }
  min_size            = 3
  max_size            = 5
  default_cooldown    = 60
  desired_capacity    = 3
  vpc_zone_identifier = [element(tolist(data.aws_subnet_ids.subnetIDs.ids), 0), element(tolist(data.aws_subnet_ids.subnetIDs.ids), 1), element(tolist(data.aws_subnet_ids.subnetIDs.ids), 2)]
  target_group_arns   = ["${aws_lb_target_group.loadbalancerTargetGroup.arn}"]
  tag {
    key                 = "Name"
    value               = "Webapp"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "InstanceScaleUpPolicy" {
  name                   = "InstanceScaleUpPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.autoscalingGroup.name
  cooldown               = 60
  scaling_adjustment     = 1
}

resource "aws_autoscaling_policy" "InstanceScaleDownPolicy" {
  name                   = "InstanceScaleDownPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.autoscalingGroup.name
  cooldown               = 60
  scaling_adjustment     = -1
}

resource "aws_cloudwatch_metric_alarm" "AlarmLow" {
  alarm_description  = "Scale-down if CPU usage less than 70% for 10 minutes"
  metric_name        = "CPUUtilization"
  namespace          = "AWS/EC2"
  statistic          = "Average"
  period             = var.alarm_low_period
  evaluation_periods = var.alarm_low_evaluation_period
  threshold          = var.alarm_low_threshold
  alarm_name         = "CPUAlarmLow"
  alarm_actions      = ["${aws_autoscaling_policy.InstanceScaleDownPolicy.arn}"]
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.autoscalingGroup.name}"
  }
  comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "AlarmHigh" {
  alarm_description  = "Scale-up if CPU greater than 90% for 10 minutes"
  metric_name        = "CPUUtilization"
  namespace          = "AWS/EC2"
  statistic          = "Average"
  period             = var.alarm_high_period
  evaluation_periods = var.alarm_high_evaluation_period
  threshold          = var.alarm_high_threshold
  alarm_name         = "CPUAlarmHigh"
  alarm_actions      = ["${aws_autoscaling_policy.InstanceScaleUpPolicy.arn}"]
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.autoscalingGroup.name}"
  }
  comparison_operator = "GreaterThanThreshold"
}


resource "aws_security_group" "loadbalancerSecurityGroup" {
  name        = "loadbalancerSecurityGroup"
  description = "Load Balancer Security Group"
  vpc_id      = aws_vpc.vpc-name.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Node"
    from_port   = 4000
    to_port     = 4000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }
  ingress {
    description = "SQL"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }


  tags = {
    Name = "loadbalancerSecurityGroup"
  }
}

resource "aws_lb" "applicationLoadBalancer" {
  name               = "applicationLoadBalancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.loadbalancerSecurityGroup.id}"]
  subnets            = data.aws_subnet_ids.subnetIDs.ids
  ip_address_type    = "ipv4"
  tags = {
    Environment = "${var.profile}"
    Name        = "applicationLoadBalancer"
  }
}

resource "aws_iam_role" "ec2AccessRole" {
  name = "EC2-CSYE6225"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}


resource "aws_iam_policy" "webappS3Policy" {
  name        = "WebAppS3Policy"
  description = "Connect Ec2 to S3 bucket"
  policy      = <<-EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sts:AssumeRole",
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${aws_s3_bucket.s3BucketConfig.bucket}",
                "arn:aws:s3:::${aws_s3_bucket.s3BucketConfig.bucket}/*"
            ]
        }
    ]
    }
    EOF

}

resource "aws_iam_role_policy_attachment" "S3PolicyAttach" {
  role       = aws_iam_role.ec2AccessRole.name
  policy_arn = aws_iam_policy.webappS3Policy.arn
}

resource "aws_iam_instance_profile" "s3Profile" {
  name = "s3Profile"
  role = aws_iam_role.ec2AccessRole.name
}

resource "aws_iam_role_policy_attachment" "CloudWatchAgentServerPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = aws_iam_role.ec2AccessRole.name
}

resource "aws_iam_role" "CodeDeployLambdaRole" {
  name               = "iam-user-lambda-codedeploy"
  path               = "/"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["lambda.amazonaws.com","codedeploy.us-east-1.amazonaws.com"]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
  tags = {
    Name = "CodeDeployLambdaServiceRole"
  }
}

resource "aws_dynamodb_table" "DynamoDBTable" {
  provider       = aws
  name           = "csye6225-dynamo"
  hash_key       = "UserName"
  range_key      = "Token"
  read_capacity  = 5
  write_capacity = 5

  attribute {
    name = "UserName"
    type = "S"
  }
  attribute {
    name = "Token"
    type = "S"
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }

}

resource "aws_s3_bucket_object" "s3BucketObject" {
  bucket = "codedeploy.csye6225saurabh.prod"
  key    = "lambda_function.zip"
  source = "./lambda_function.zip"
}

#Lambda Function
resource "aws_lambda_function" "lambdaService" {
  s3_bucket = "codedeploy.csye6225saurabh.prod"
  s3_key    = "lambda_function.zip"
  /* filename         = "lambda_function.zip" */
  function_name = "lambda_function_name"
  role          = aws_iam_role.CodeDeployLambdaRole.arn
  handler       = "index.handler"
  runtime       = "nodejs12.x"
  /* source_code_hash = "${data.archive_file.lambda_zip.output_base64sha256}" */
  environment {
    variables = {
      timeToLive = "5"
    }
  }
  depends_on = [aws_s3_bucket_object.s3BucketObject]
}

resource "aws_sns_topic" "EmailNotificationRecipient" {
  name = "EmailNotificationRecipient"
}

resource "aws_sns_topic_subscription" "topicSubscription" {
  topic_arn  = aws_sns_topic.EmailNotificationRecipient.arn
  protocol   = "lambda"
  endpoint   = aws_lambda_function.lambdaService.arn
  depends_on = [aws_lambda_function.lambdaService]
}

resource "aws_lambda_permission" "lambdaPermission" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.EmailNotificationRecipient.arn
  function_name = aws_lambda_function.lambdaService.function_name
  depends_on    = [aws_lambda_function.lambdaService]

}

resource "aws_iam_policy" "lambdaPolicy" {
  name       = "lambda"
  depends_on = [aws_sns_topic.EmailNotificationRecipient]
  policy     = <<EOF
{
          "Version" : "2012-10-17",
          "Statement": [
            {
              "Sid": "LambdaDynamoDBAccess",
              "Effect": "Allow",
              "Action": ["dynamodb:GetItem",
              "dynamodb:PutItem",
              "dynamodb:UpdateItem"],
              "Resource": "arn:aws:dynamodb:us-east-1:*****:table/csye6225-dynamo"
            },
            {
              "Sid": "LambdaSESAccess",
              "Effect": "Allow",
              "Action": ["ses:VerifyEmailAddress",
              "ses:SendEmail",
              "ses:SendRawEmail"],
              "Resource": "arn:aws:ses:us-east-1:*****:identity/*"
            },
            {
              "Sid": "LambdaS3Access",
              "Effect": "Allow",
              "Action": ["s3:GetObject","s3:PutObject"],
              "Resource": "arn:aws:s3:::lambda.codedeploy.bucket/*"
            },
            {
              "Sid": "LambdaSNSAccess",
              "Effect": "Allow",
              "Action": ["sns:ConfirmSubscription"],
              "Resource": "${aws_sns_topic.EmailNotificationRecipient.arn}"
            }
          ]
        }
EOF
}

resource "aws_iam_policy" "topicPolicy" {
  name        = "Topic"
  description = ""
  depends_on  = [aws_sns_topic.EmailNotificationRecipient]
  policy      = <<EOF
{
          "Version" : "2012-10-17",
          "Statement": [
            {
              "Sid": "AllowEC2ToPublishToSNSTopic",
              "Effect": "Allow",
              "Action": ["sns:Publish",
              "sns:CreateTopic"],
              "Resource": "${aws_sns_topic.EmailNotificationRecipient.arn}"
            }
          ]
        }
EOF
}

resource "aws_iam_role_policy_attachment" "AWSLambdaBasicExecutionRole" {
  role       = aws_iam_role.CodeDeployLambdaRole.name
  depends_on = [aws_iam_role.CodeDeployLambdaRole]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambdaPolicyAttach" {
  role       = aws_iam_role.CodeDeployLambdaRole.name
  depends_on = [aws_iam_role.CodeDeployLambdaRole]
  policy_arn = aws_iam_policy.lambdaPolicy.arn
}

resource "aws_iam_role_policy_attachment" "topicPolicyAttach" {
  role       = aws_iam_role.CodeDeployLambdaRole.name
  depends_on = [aws_iam_role.CodeDeployLambdaRole]
  policy_arn = aws_iam_policy.topicPolicy.arn
}

resource "aws_iam_role_policy_attachment" "dynamoDBPolicyAttach" {
  role       = aws_iam_role.ec2AccessRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

resource "aws_iam_role_policy_attachment" "SNSPolicyAttach" {
  role       = aws_iam_role.ec2AccessRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
}

resource "aws_iam_role_policy_attachment" "dynamoDBPolicyAttachRole" {
  role       = aws_iam_role.CodeDeployLambdaRole.name
  depends_on = [aws_iam_role.CodeDeployLambdaRole]
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

resource "aws_iam_role_policy_attachment" "sesPolicyAttach" {
  role       = aws_iam_role.CodeDeployLambdaRole.name
  depends_on = [aws_iam_role.CodeDeployLambdaRole]
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
}

resource "aws_iam_policy" "dynamoDBEC2PolicyAttach" {
  name        = "DynamoDb-Ec2"
  description = "ec2 will be able to talk to dynamodb"
  policy      = <<-EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [      
              "dynamodb:List*",
              "dynamodb:DescribeReservedCapacity*",
              "dynamodb:DescribeLimits",
              "dynamodb:DescribeTimeToLive"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:BatchGet*",
                "dynamodb:DescribeStream",
                "dynamodb:DescribeTable",
                "dynamodb:Get*",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchWrite*",
                "dynamodb:CreateTable",
                "dynamodb:Delete*",
                "dynamodb:Update*",
                "dynamodb:PutItem"
            ],
            "Resource": "arn:aws:dynamodb:::table/csye6225-dynamo"
        }
    ]
    }
    EOF
}

resource "aws_iam_role_policy_attachment" "attachDynamoDbPolicyToEC2Role" {
  role       = aws_iam_role.ec2AccessRole.name
  policy_arn = aws_iam_policy.dynamoDBEC2PolicyAttach.arn
}

// resource "aws_ebs_encryption_by_default" "example" {
//   enabled = true
// }