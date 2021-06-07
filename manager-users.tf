######################################################################################################
#
# IAM User k8s Admin
#

#
# IAM Policy Document
#

data "aws_iam_policy_document" "system_user" {
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

#
# ks8 Role Access 
#

resource "aws_iam_role" "system_user_admin" {
  count = var.create && var.system_users_admin ? 1 : 0

  name                = "EKSAdmin"
  description         = "Kubernetes administrator role (for AWS IAM Authenticator for Kubernetes)."
  path                = "/"
  assume_role_policy  = data.aws_iam_policy_document.system_user.0.json

  tags = var.default_tags
}

#
# K8s Group Admin
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

# Create IAM Access Key
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

######################################################################################################
#
# IAM User k8s Develop
#

resource "aws_iam_role" "system_user_dev" {
  count = var.create && var.system_users_develop ? 1 : 0

  name                = "EKSDev"
  description         = "Kubernetes developer role (for AWS IAM Authenticator for Kubernetes)."
  path                = "/"
  assume_role_policy  = data.aws_iam_policy_document.system_user.0.json

  tags = var.default_tags
}

data "aws_iam_policy_document" "system_user_dev_0" {
  count = var.create && var.system_users_develop ? 1 : 0

  statement {
    sid = "AllowAssumeOrganizationAccountRole"
    effect = "Allow"
    actions = [ 
      "sts:AssumeRole" 
    ]
    resources = [ aws_iam_role.system_user_dev.0.arn ]
  }
  depends_on = [
    aws_iam_role.system_user_dev
  ]
}

resource "aws_iam_group" "system_user_dev" {
  count = var.create && var.system_users_develop ? 1 : 0

  name = "EKSDev"
  path = "/"
}

resource "aws_iam_policy" "system_user_dev" {
  count = var.create && var.system_users_develop ? 1 : 0

  name        = "EKSDev-Policy"
  description = "Kubernetes developer policy (for AWS IAM Authenticator for Kubernetes)."
  policy      = data.aws_iam_policy_document.system_user_dev_0.0.json
}

resource "aws_iam_group_policy_attachment" "system_user_dev" {
  count = var.create && var.system_users_develop ? 1 : 0

  group      = aws_iam_group.system_user_dev.0.name
  policy_arn = aws_iam_policy.system_user_dev.0.arn
}

#
# Create IAM User
#
resource "aws_iam_user" "system_users_dev" {
  count = var.create && var.system_users_develop ? 1 : 0

  name = "EKSDev"
  path = "/"

  tags = var.default_tags
}

# Create IAM Access Key
resource "aws_iam_access_key" "system_users_dev" {
  count = var.create && var.system_users_develop ? 1 : 0

  user = aws_iam_user.system_users_dev.0.name
}

resource "aws_iam_group_membership" "system_users_dev" {
  count = var.create && var.system_users_develop ? 1 : 0

  name = "EKSDev-GroupMembership"
  users = [
    aws_iam_user.system_users_dev.0.name
  ]
  group = "EKSDev"
}

# RBAC for IAM users from KS8Dev group
resource "kubernetes_namespace" "rbac_dev" {
  depends_on = [ aws_eks_cluster.main  ]
  count = var.create && var.system_users_develop ? 1 : 0
  
  metadata {
    name = "development"
  }
}
resource "kubernetes_role" "rbac_dev" {
  depends_on = [ aws_eks_cluster.main  ]
  count = var.create && var.system_users_develop ? 1 : 0

  metadata {
    name = "eks-dev-role"
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
  rule {
    api_groups = ["", "apps", "batch", "extensions"]
    resources  = ["configmaps", "cronjobs", "deployments", "events", "ingresses", "jobs", "pods", "pods/attach", "pods/exec", "pods/log", "pods/portforward", "secrets", "services"]
    verbs      = ["create", "delete", "describe", "get", "list", "update", "patch"] 
  }
}

resource "kubernetes_role_binding" "rbac_dev" {
  depends_on = [ kubernetes_role.rbac_dev, aws_eks_cluster.main  ]

  count = var.create && var.system_users_develop ? 1 : 0   

  metadata {
    name = "eks-dev-role-binding"
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role.rbac_dev.0.metadata[0].name
  }
  subject {
    kind  = "User"
    name  = "dev-user"
  }
}

#
# Configmap AWS-AUTH
#

locals {
  map_username  = "${length(var.fargate_profile) > 0 ? "system:node:{{SessionName}}" : "system:node:{{EC2PrivateDNSName}}"}"
  map_rolearn   = "${length(var.fargate_profile) > 0 ? "${aws_iam_role.fargate_profile.0.arn}" : "${aws_iam_role.node_group.0.arn}"}"

  # Format needed by aws-auth ConfigMap
  configmap = <<ROLES
- rolearn: ${local.map_rolearn}
  username: ${local.map_username}
  groups:
    - system:bootstrappers
    - system:nodes
    - system:node-proxier
- rolearn: ${aws_iam_role.system_user_admin.0.arn}
  username: admin
  groups:
    - system:masters
- rolearn: ${aws_iam_role.system_user_dev.0.arn}
  username: dev-user
ROLES
}

resource "kubernetes_config_map" "system_users" {
  count = var.create && var.system_users_admin ? 1 : 0

  metadata {
    name        = "aws-auth"
    namespace   = "kube-system"
    labels      = merge({
      "app.kubernetes.io/managed-by" = "Terraform"
    })
  }

  data = {
    mapRoles = "${local.configmap}"
  }
  depends_on = [
    aws_iam_role.fargate_profile,
    aws_eks_cluster.main
  ]
}
