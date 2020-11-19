######################################################################################################
#
# Cluster EKS
#

#
# EkS Cluster - IAM Policy
#

data "aws_iam_policy_document" "main" {
    count = var.create ? 1 : 0 

    statement {
        effect = "Allow"
        actions = [
            "sts:AssumeRole"
        ]
        principals {
            type = "Service"
            identifiers = [ "eks.amazonaws.com" ]
        }
    }
}
resource "aws_iam_role" "main" {
    count = var.create ? 1 : 0

    name = "${var.cluster_name}-role"
    assume_role_policy = data.aws_iam_policy_document.main.0.json

    tags = var.default_tags
}
resource "aws_iam_role_policy_attachment" "main" {
    count = var.create ? 1 : 0

    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    role    = aws_iam_role.main.0.name
}

#
# EKS Cluster - Criação
# 

resource "aws_eks_cluster" "main" {
    count = var.create ? 1 : 0

    depends_on = [ aws_iam_role.main ]

    name                        = var.cluster_name
    role_arn                    = aws_iam_role.main.0.arn
    version                     = var.cluster_version

    enabled_cluster_log_types = var.enabled_cluster_log_types

    dynamic "vpc_config" {
        for_each = var.vpc_config
        content {
            subnet_ids              = lookup(vpc_config.value, "subnet_ids", null)
            security_group_ids      = lookup(vpc_config.value, "security_group_ids", null)
            public_access_cidrs     = lookup(vpc_config.value, "public_access_cidrs", null)
            endpoint_public_access  = lookup(vpc_config.value, "endpoint_public_access", "true")
            endpoint_private_access = lookup(vpc_config.value, "endpoint_private_access", "false")
        }
    }

    dynamic "encryption_config" {
        for_each = var.encryption_config
        content {
            dynamic "provider" {
                for_each = lookup(encryption_config.value, "provider", null)
                content {
                    key_arn = lookup(encryption_config.value, "key_arn", null)
                }
            }
            resources   = lookup(encryption_config.value, "resources", null)
        }
    }

    tags = var.default_tags
}
data "aws_eks_cluster_auth" "main" {
    count = var.create && length(var.kubeconfig_path) > 0 ? 1 : 0

    name = aws_eks_cluster.main.0.name
}
data "aws_eks_cluster" "main" {
    count = var.create && length(var.kubeconfig_path) > 0 ? 1 : 0

    name = aws_eks_cluster.main.0.id
}

#
# EKS Cluster - Criação do kubeconfig
#

data "template_file" "main" {
    count = var.create && length(var.kubeconfig_path) > 0 ? 1 : 0

    template = file("${path.module}/kubeconfig/template.tpl")
    vars = {
        kubeconfig_name     = "eks_${aws_eks_cluster.main.0.name}"
        cluster_name        = aws_eks_cluster.main.0.name
        endpoint            = aws_eks_cluster.main.0.endpoint
        token               = data.aws_eks_cluster_auth.main.0.token
        cluster_auth_base64 = aws_eks_cluster.main.0.certificate_authority[0].data
    }
}
resource "local_file" "main" {
    count = var.create && length(var.kubeconfig_path) > 0 ? 1 : 0

    content  = data.template_file.main.0.rendered
    filename = pathexpand("${var.kubeconfig_path}/${aws_eks_cluster.main.0.name}-config")
}

data "aws_iam_policy_document" "assume_role_policy" {
    count = var.create && length(var.kubeconfig_path) > 0 ? 1 : 0
  
    statement {
        actions = ["sts:AssumeRoleWithWebIdentity"]
        effect  = "Allow"

        condition {
            test     = "StringEquals"
            variable = "${replace(aws_iam_openid_connect_provider.main.0.url, "https://", "")}:sub"
            values   = ["system:serviceaccount:kube-system:aws-node"]
        }

        principals {
            identifiers = [aws_iam_openid_connect_provider.main.0.arn]
            type        = "Federated"
        }
    }
}
resource "aws_iam_role" "main" {
    count = var.create && length(var.kubeconfig_path) > 0 ? 1 : 0

    assume_role_policy = data.aws_iam_policy_document.assume_role_policy.0.json
    name               = "${var.cluster_name}-svc-account-role"
}
data "external" "thumbprint" {
    count = var.create && length(var.kubeconfig_path) > 0 ? 1 : 0

    program = [ "${path.module}/thumbprint/oidc.sh", data.aws_region.current.name ]
}
resource "aws_iam_openid_connect_provider" "main" {
    count = var.create && length(var.kubeconfig_path) > 0 ? 1 : 0

    client_id_list  = ["sts.amazonaws.com"]
    thumbprint_list = [ data.external.thumbprint.0.result.thumbprint ]
    url             = aws_eks_cluster.main.0.identity[0].oidc[0].issuer
}

#
# EKS Cluster - Logs
#

resource "aws_cloudwatch_log_group" "main" {
    count = var.create && length(var.enabled_cluster_log_types) > 0 ? 1 : 0

    name                = "/aws/eks/${var.cluster_name}/cluster"
    retention_in_days   = var.retention_in_days

    tags = var.default_tags
}