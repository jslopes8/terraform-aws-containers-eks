# IAM Role for EKS Cluster
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

# EKS Cluster
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
resource "aws_cloudwatch_log_group" "main" {
    count = var.create && length(var.enabled_cluster_log_types) > 0 ? 1 : 0

    name                = "/aws/eks/${var.cluster_name}/cluster"
    retention_in_days   = var.retention_in_days

    tags = var.default_tags
}

# EKS Fargate Profile
data "aws_iam_policy_document" "example_assume_role_policy" {
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
resource "aws_iam_role" "example" {
    count = var.create && length(var.kubeconfig_path) > 0 ? 1 : 0

    assume_role_policy = data.aws_iam_policy_document.example_assume_role_policy.0.json
    name               = "${var.cluster_name}-svc-account-role"
}
resource "aws_iam_openid_connect_provider" "main" {
    count = var.create && length(var.kubeconfig_path) > 0 ? 1 : 0

    client_id_list  = ["sts.amazonaws.com"]
    thumbprint_list = []
    url             = aws_eks_cluster.main.0.identity[0].oidc[0].issuer
}


# IAM Role for EKS Fargate Profile
data "aws_iam_policy_document" "fargate_profile" {
    count = var.create ? length(var.fargate_profile) : 0

    statement {
        effect = "Allow"
        actions = [
            "sts:AssumeRole"
        ]
        principals {
            type = "Service"
            identifiers = [ "eks-fargate-pods.amazonaws.com" ]
        }
    }
}
resource "aws_iam_role" "fargate_profile" {
    count = var.create ? length(var.fargate_profile) : 0

    name = "${var.cluster_name}-pod-execution-role"
    assume_role_policy = data.aws_iam_policy_document.fargate_profile.0.json

    tags = var.default_tags
}
resource "aws_iam_role_policy_attachment" "fargate_profile" {
    count = var.create ? length(var.fargate_profile) : 0

    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
    role    = aws_iam_role.fargate_profile.0.name
}

resource "aws_eks_fargate_profile" "main" {
    count = var.create ? length(var.fargate_profile) : 0

    depends_on = [ aws_eks_cluster.main ]

    cluster_name = aws_eks_cluster.main.0.name

    fargate_profile_name    = lookup(var.fargate_profile[count.index], "name", null)
    pod_execution_role_arn  = aws_iam_role.fargate_profile.0.arn
    subnet_ids              = lookup(var.fargate_profile[count.index], "subnet_ids", null)

    dynamic "selector" {
        for_each = lookup(var.fargate_profile[count.index], "selector", null)
        content {
            namespace   = lookup(selector.value, "namespace", null)
            labels      = lookup(selector.value, "labels", null)
        }
    }
}
resource "null_resource" "coredns_patch" {
    count = var.create ? length(var.fargate_profile) : 0
  
    provisioner "local-exec" {
        interpreter = ["/bin/bash", "-c"]
        command     = <<EOF
            kubectl --kubeconfig=<(echo "${data.template_file.main.0.rendered}") \
            patch deployment coredns \
            --namespace kube-system \
            --type=json \
            -p='[{"op": "remove", "path": "/spec/template/metadata/annotations", "value": "eks.amazonaws.com/compute-type"}]'
        EOF
    }
}
resource "null_resource" "coredns_rollout" {
    count = var.create ? length(var.fargate_profile) : 0
  
    provisioner "local-exec" {
        interpreter = ["/bin/bash", "-c"]
        command     = <<EOF
            kubectl --kubeconfig=<(echo "${data.template_file.main.0.rendered}") \
            rollout restart deployment coredns \
            --namespace kube-system
        EOF
    }
}