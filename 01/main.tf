resource "aws_vpc" "vpc" {
  cidr_block                       = var.vpc_cidr_block
  enable_dns_hostnames             = var.vpcConfig.enable_dns_hostnames
  enable_dns_support               = var.vpcConfig.enable_dns_support
  enable_classiclink_dns_support   = var.vpcConfig.enable_classiclink_dns_support
  assign_generated_ipv6_cidr_block = var.vpcConfig.assign_generated_ipv6_cidr_block

  tags = {
    Name = var.vpc_name
  }
}

resource "aws_subnet" "subnet" {
  depends_on              = [aws_vpc.vpc]
  for_each                = var.subnet_cidr
  cidr_block              = each.value
  vpc_id                  = aws_vpc.vpc.id
  availability_zone       = each.key
  map_public_ip_on_launch = var.map_public_ip_on_launch
  tags = {
    Name = "csye6225-subnet-${each.key}-fall2021"
  }
}

resource "aws_security_group" "application" {
  name        = "application"
  description = "security group for the webapp"
  vpc_id      = aws_vpc.vpc.id

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
    Name = "application"
  }
}

resource "aws_security_group" "database" {
  name        = "database"
  description = "security group for the database"
  vpc_id      = aws_vpc.vpc.id

  ingress = [
    {
      description      = "MYSQL"
      from_port        = 3306
      to_port          = 3306
      protocol         = "tcp"
      cidr_blocks      = [aws_vpc.vpc.cidr_block]
      security_groups  = [aws_security_group.application.name]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    }
  ]
  tags = {
    Name = "database"
  }
}

resource "aws_security_group" "loadBalancer" {
  name   = "loadBalance_security_group"
  vpc_id = aws_vpc.vpc.id
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
    Name        = "LoadBalancer Security Group"
    Environment = "${var.profile}"
  }
}

resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = var.ig_name
  }
}

resource "aws_route_table" "route_table" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = var.route_table_name
  }
}

data "aws_subnet_ids" "subnets" {
  depends_on = [aws_vpc.vpc, aws_subnet.subnet]
  vpc_id     = aws_vpc.vpc.id
}

resource "aws_db_subnet_group" "rdsDbSubnetGp" {
  name       = "rdssubnetgp"
  subnet_ids = data.aws_subnet_ids.subnets.ids
}

resource "aws_db_parameter_group" "rdsDbParamGp" {
  name   = "rdsdbparamgp"
  family = "mysql8.0"
}

resource "aws_db_instance" "rdsDbInstance" {
  identifier             = var.rds_identifier
  name                   = var.rds_identifier
  instance_class         = "db.t3.micro"
  skip_final_snapshot    = true
  allocated_storage      = 20
  max_allocated_storage  = 0
  multi_az               = false
  engine                 = "mysql"
  engine_version         = "8.0.25"
  username               = var.rds_username
  password               = var.rds_password
  db_subnet_group_name   = aws_db_subnet_group.rdsDbSubnetGp.name
  vpc_security_group_ids = [aws_security_group.database.id]
  parameter_group_name   = aws_db_parameter_group.rdsDbParamGp.name
  publicly_accessible    = false
}


resource "aws_route" "routes" {
  route_table_id         = aws_route_table.route_table.id
  destination_cidr_block = var.destination_cidr_block
  gateway_id             = aws_internet_gateway.internet_gateway.id
  depends_on             = [aws_route_table.route_table]
}

resource "aws_route_table_association" "route_table_association" {
  for_each       = aws_subnet.subnet
  subnet_id      = each.value.id
  route_table_id = aws_route_table.route_table.id
}


resource "aws_s3_bucket" "s3" {
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

resource "aws_key_pair" "ssh_key" {
  key_name   = "ssh_key"
  public_key = var.ec2_ssh_key
}


// data "template_file" "config_data" {
//   template = <<-EOF
// 		#! /bin/bash
//         cd home/ubuntu
//         mkdir server
//         cd server
//         echo "{\"host\":\"${aws_db_instance.rdsDbInstance.endpoint}\",\"username\":\"${var.rds_username}\",\"password\":\"${var.rds_password}\",\"database\":\"${var.rds_identifier}\",\"port\":3306,\"s3\":\"${aws_s3_bucket.s3.bucket}\"}" > config.json
//         cd ..
//         sudo chmod -R 777 server
//     EOF
// }

// resource "aws_instance" "webapp" {
//   ami                     = var.ec2_ami_id
//   instance_type           = "t2.micro"
//   iam_instance_profile    = aws_iam_instance_profile.s3_profile.name
//   disable_api_termination = false
//   key_name                = aws_key_pair.ssh_key.key_name
//   vpc_security_group_ids  = [aws_security_group.application.id]
//   subnet_id               = element(tolist(data.aws_subnet_ids.subnets.ids), 0)
// user_data               = <<-EOF
// #! /bin/bash
//       cd /home/ubuntu/
//       mkdir ./server
//       cd server
//       echo "{\"host\":\"${aws_db_instance.rdsDbInstance.endpoint}\",\"username\":\"${var.rds_username}\",\"password\":\"${var.rds_password}\",\"database\":\"${var.rds_identifier}\",\"port\":3306,\"s3\":\"${aws_s3_bucket.s3.bucket}\"}" > config.json
//       cd ..
//       sudo chmod -R 777 server
// EOF

//   root_block_device {
//     delete_on_termination = true
//     volume_size           = 20
//     volume_type           = "gp2"
//   }

//   tags = {
//     Name = "Webapp"
//   }
// }

resource "aws_launch_configuration" "as_conf" {
  name                        = "asg_launch_config"
  image_id                    = var.ec2_ami_id
  instance_type               = "t2.micro"
  security_groups             = [aws_security_group.application.id]
  key_name                    = aws_key_pair.ssh_key.key_name
  iam_instance_profile        = aws_iam_instance_profile.s3_profile.name
  associate_public_ip_address = true
  user_data                   = <<-EOF
  #! /bin/bash
        cd /home/ubuntu/
        mkdir ./server
        cd server
        echo "{\"host\":\"${aws_db_instance.rdsDbInstance.endpoint}\",\"username\":\"${var.rds_username}\",\"password\":\"${var.rds_password}\",\"database\":\"${var.rds_identifier}\",\"port\":3306,\"s3\":\"${aws_s3_bucket.s3.bucket}\"}" > config.json
        cd ..
        sudo chmod -R 777 server
  EOF

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 20
    delete_on_termination = true
  }
  // depends_on = [aws_s3_bucket.bucket, aws_db_instance.rds_ins]
}

resource "aws_lb_listener" "webapp-Listener" {
  load_balancer_arn = aws_lb.application-Load-Balancer.arn
  port              = "80"
  protocol          = "HTTP"
  // certificate_arn   = "${data.aws_acm_certificate.aws_ssl_certificate.arn}"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.albTargetGroup.arn
  }
}


resource "aws_lb_target_group" "albTargetGroup" {
  name     = "albTargetGroup"
  port     = "4000"
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id
  tags = {
    name = "albTargetGroup"
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

data "aws_subnet_ids" "mysubnets" {
  vpc_id = aws_vpc.vpc.id
}

resource "aws_autoscaling_group" "autoscaling" {
  name                 = "autoscaling-group"
  launch_configuration = aws_launch_configuration.as_conf.name
  min_size             = 3
  max_size             = 5
  default_cooldown     = 60
  desired_capacity     = 3
  vpc_zone_identifier  = [element(tolist(data.aws_subnet_ids.mysubnets.ids), 0), element(tolist(data.aws_subnet_ids.mysubnets.ids), 1), element(tolist(data.aws_subnet_ids.mysubnets.ids), 2)]
  target_group_arns    = ["${aws_lb_target_group.albTargetGroup.arn}"]
  tag {
    key                 = "Name"
    value               = "Webapp"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "WebServerScaleUpPolicy" {
  name                   = "WebServerScaleUpPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = "${aws_autoscaling_group.autoscaling.name}"
  cooldown               = 60
  scaling_adjustment     = 1
}

resource "aws_autoscaling_policy" "WebServerScaleDownPolicy" {
  name                   = "WebServerScaleDownPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = "${aws_autoscaling_group.autoscaling.name}"
  cooldown               = 60
  scaling_adjustment     = -1
}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmLow" {
  alarm_description = "Scale-down if CPU < 70% for 10 minutes"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  statistic           = "Average"
  period              = "${var.alarm_low_period}"
  evaluation_periods  = "${var.alarm_low_evaluation_period}"
  threshold           = "${var.alarm_low_threshold}"
  alarm_name          = "CPUAlarmLow"
  alarm_actions     = ["${aws_autoscaling_policy.WebServerScaleDownPolicy.arn}"]
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.autoscaling.name}"
  }
  comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmHigh" {
  alarm_description = "Scale-up if CPU > 90% for 10 minutes"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  statistic           = "Average"
  period              = "${var.alarm_high_period}"
  evaluation_periods  = "${var.alarm_high_evaluation_period}"
  threshold           = "${var.alarm_high_threshold}"
  alarm_name          = "CPUAlarmHigh"
  alarm_actions     = ["${aws_autoscaling_policy.WebServerScaleUpPolicy.arn}"]
  dimensions = {
  AutoScalingGroupName = "${aws_autoscaling_group.autoscaling.name}"
  }
  comparison_operator = "GreaterThanThreshold"
}
resource "aws_security_group" "lb_security_group" {
  name        = "lb_security_group"
  description = "Load Balancer Security Group"
  vpc_id      = aws_vpc.vpc.id

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
    Name = "application"
  }
}

resource "aws_lb" "application-Load-Balancer" {
  name               = "application-Load-Balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.lb_security_group.id}"]
  subnets            = data.aws_subnet_ids.subnets.ids
  ip_address_type    = "ipv4"
  tags = {
    Environment = "${var.profile}"
    Name        = "applicationLoadBalancer"
  }
}

resource "aws_iam_role" "ec2_s3_access_role" {
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


resource "aws_iam_policy" "policy" {
  name        = "WebAppS3"
  description = "ec2 will be able to talk to s3 buckets"
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
                "arn:aws:s3:::${aws_s3_bucket.s3.bucket}",
                "arn:aws:s3:::${aws_s3_bucket.s3.bucket}/*"
            ]
        }
    ]
    }
    EOF

}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.ec2_s3_access_role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_instance_profile" "s3_profile" {
  name = "s3_profile"
  role = aws_iam_role.ec2_s3_access_role.name
}

resource "aws_iam_role_policy_attachment" "CloudWatchAgentServerPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = aws_iam_role.ec2_s3_access_role.name
}