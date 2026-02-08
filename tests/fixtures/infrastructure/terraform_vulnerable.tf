resource "aws_security_group" "open" {
  name = "open-sg"
  ingress {
    from_port   = 443
    to_port     = 443
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
