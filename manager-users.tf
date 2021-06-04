######################################################################################################
#
# IAM User k8s Admin
#

data "aws_iam_policy_document" "system_user_admin" {
  count = var.create && var.system_users_admin ? 1 : 0

  statement {
    effect = "Allow"
    actions = [ 
      "sts:AssumeRole" 
    ]
    principals {
      type = "AWS"
      identifiers = [ "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" ]
    }
  }
}
resource "aws_iam_role" "system_user_admin" {
  count = var.create && var.system_users_admin ? 1 : 0

  name                = "EKSAdmin"
  description         = "Kubernetes administrator role (for AWS IAM Authenticator for Kubernetes)."
  path                = "/"
  assume_role_policy  = data.aws_iam_policy_document.system_user_admin.0.json

  tags = var.default_tags
}

#
# Create IAM Group K8s Admin
#

data "aws_iam_policy_document" "system_user_admin_0" {
  count = var.create && var.system_users_admin ? 1 : 0

  statement {
    sid = "AllowAssumeOrganizationAccountRole"
    effect = "Allow"
    actions = [ 
      "sts:AssumeRole" 
    ]
    resources = [ aws_iam_role.system_user_admin.0.arn ]
  }
  depends_on = [
    aws_iam_role.system_user_admin
  ]
}
resource "aws_iam_group" "system_user_admin" {
  count = var.create && var.system_users_admin ? 1 : 0

  name = "EKSAdmin"
  path = "/"
}

resource "aws_iam_policy" "system_user_admin" {
  count = var.create && var.system_users_admin ? 1 : 0

  name        = "EKSAdmin-Policy"
  description = "Kubernetes administrator policy (for AWS IAM Authenticator for Kubernetes)."
  policy      = data.aws_iam_policy_document.system_user_admin_0.0.json
}

resource "aws_iam_group_policy_attachment" "system_user_admin" {
  count = var.create && var.system_users_admin ? 1 : 0

  group      = aws_iam_group.system_user_admin.0.name
  policy_arn = aws_iam_policy.system_user_admin.0.arn
}

#
# Create IAM User
#
resource "aws_iam_user" "system_users_admin" {
  count = var.create && var.system_users_admin ? 1 : 0

  name = "EKSAdmin"
  path = "/"

  tags = var.default_tags
}

resource "aws_iam_access_key" "system_users_admin" {
  count = var.create && var.system_users_admin ? 1 : 0
  user = aws_iam_user.system_users_admin.0.name
}

resource "aws_iam_group_membership" "system_users_admin" {
  count = var.create && var.system_users_admin ? 1 : 0

  name = "EKSAdmin-GroupMembership"
  users = [
    aws_iam_user.system_users_admin.0.name
  ]
  group = "EKSAdmin"
}

#
# Configmap AWS-AUTH
#

locals {
  map_roles_fargate = <<ROLES
- rolearn: ${aws_iam_role.fargate_profile.0.arn}
  username: system:node:{{SessionName}}
  groups:
    - system:bootstrappers
    - system:nodes
    - system:node-proxier
- rolearn: ${aws_iam_role.system_user_admin.0.arn}
  username: admin
  groups:
    - system:masters
ROLES
  map_roles_worker = <<ROLES
- rolearn: ${aws_iam_role.node_group.0.arn}
  username: system:node:{{EC2PrivateDNSName}}
  groups:
    - system:bootstrappers
    - system:nodes
    - system:node-proxier
- rolearn: ${aws_iam_role.system_user_admin.0.arn}
  username: admin
  groups:
    - system:masters
ROLES
}

resource "kubernetes_config_map" "fargate_profile" {
  count = var.create && length(var.fargate_profile) > 0 && var.system_users_admin ? 1 : 0

  metadata {
    name        = "aws-auth"
    namespace   = "kube-system"
    labels      = merge({
      "app.kubernetes.io/managed-by" = "Terraform"
    })
  }

  data = {
    mapRoles = "${local.map_roles_fargate}"
  }
  depends_on = [
    aws_iam_role.fargate_profile,
    aws_eks_cluster.main
  ]
}
resource "kubernetes_config_map" "node_group" {
  count = var.create && length(var.node_group) > 0 && var.system_users_admin ? 1 : 0

  metadata {
    name        = "aws-auth"
    namespace   = "kube-system"
    labels      = merge({
      "app.kubernetes.io/managed-by" = "Terraform"
    })
  }

  data = {
    mapRoles = "${local.map_roles_worker}"
  }
  depends_on = [
    aws_iam_role.node_group,
    aws_eks_cluster.main
  ]
}