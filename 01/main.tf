resource "aws_vpc" "vpc1" {
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
  depends_on              = [aws_vpc.vpc1]
  for_each                = var.subnet_cidr
  cidr_block              = each.value
  vpc_id                  = aws_vpc.vpc1.id
  availability_zone       = each.key
  map_public_ip_on_launch = var.map_public_ip_on_launch
  tags = {
    Name = "csye6225-subnet-${each.key}-fall2021"
  }
}

resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.vpc1.id
  tags = {
    Name = var.ig_name
  }
}

resource "aws_route_table" "route_table" {
  vpc_id = aws_vpc.vpc1.id
  tags = {
    Name = var.route_table_name
  }
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