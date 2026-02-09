resource "aws_security_group" "open" {
  name = "open-sg"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ssh_open" {
  name = "ssh-open-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public" {
  bucket = "aishield-public-demo"
  acl    = "public-read"
}

resource "aws_db_instance" "demo" {
  identifier          = "aishield-db"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_kms_key" "weak" {
  enable_key_rotation = false
}

resource "aws_instance" "example" {
  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_iam_policy" "wide" {
  policy = <<EOF_POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Action": "*",
    "Effect": "Allow",
    "Resource": "*"
  }]
}
EOF_POLICY
}

resource "aws_cloudtrail" "disabled" {
  name           = "audit-trail"
  s3_bucket_name = "trail-bucket"
  enable_logging = false
}

resource "aws_iam_role_policy" "lambda_wide" {
  role   = "lambda-role"
  policy = <<EOF
{
  "Statement": [{
    "Action": "logs:*",
    "Resource": "*",
    "Effect": "Allow"
  }]
}
EOF
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/my-alb/abc"
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456:targetgroup/my-tg/abc"
  }
}

resource "aws_ecr_repository" "no_scan" {
  name = "my-app"
  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_secretsmanager_secret" "no_rotation" {
  name = "db-password"
}
