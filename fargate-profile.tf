######################################################################################################
#
# Fargate Profile
#

#
# IAM Role for EKS Fargate Profile
#

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
    count = var.create && length(var.fargate_profile) > 0 ? 1 : 0

    name = "${var.cluster_name}-pod-execution-role"
    assume_role_policy = data.aws_iam_policy_document.fargate_profile.0.json

    tags = var.default_tags
}
resource "aws_iam_role_policy_attachment" "fargate_profile" {
    count = var.create && length(var.fargate_profile) > 0 ? 1 : 0

    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
    role    = aws_iam_role.fargate_profile.0.name
}

#
# Fargate Profile
#
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

#
# Patch CoreDNS
#

resource "null_resource" "coredns_patch" {
    depends_on = [ aws_eks_fargate_profile.main, local_file.main  ]

    count = var.create && length(var.fargate_profile) > 0 ? 1 : 0
  
    provisioner "local-exec" {
        interpreter = ["/bin/bash", "-c"]
        command     = <<EOF
            kubectl --kubeconfig=${local_file.main.0.filename} \
            patch deployment coredns \
            --namespace kube-system \
            --type=json \
            -p='[{"op": "remove", "path": "/spec/template/metadata/annotations", "value": "eks.amazonaws.com/compute-type"}]'
        EOF
    }
}

#
# Rollout CoreDNS
#

resource "null_resource" "coredns_rollout" {
    depends_on = [ aws_eks_fargate_profile.main, local_file.main  ]

    count = var.create && length(var.fargate_profile) > 0 ? 1 : 0
  
    provisioner "local-exec" {
        interpreter = ["/bin/bash", "-c"]
        command     = <<EOF
            kubectl --kubeconfig=${local_file.main.0.filename} \
            rollout restart deployment coredns \
            --namespace kube-system
        EOF
    }
}
