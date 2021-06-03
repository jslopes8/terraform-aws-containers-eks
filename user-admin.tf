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

data "template_file" "system_users_admin" {
  count = var.create && var.system_users_admin ? 1 : 0

  template = <<EOF
    apiVersion: iamauthenticator.k8s.aws/v1alpha1
    kind: IAMIdentityMapping
    metadata:
      name: admin
    spec:
      arn: arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${aws_iam_role.system_user_admin.0.name}
      username: admin
      groups:
        - system:masters
  EOF

  depends_on = [
    aws_iam_user.system_users_admin, aws_iam_role.system_user_admin
  ]
}

resource "null_resource" "system_users_admin" {
  count = var.create && var.system_users_admin ? 1 : 0

  provisioner "local-exec" {
    command = <<EOF
      kubectl --kubeconfig=${local_file.main.0.filename} \
      apply -f - data.template_file.system_users_admin.0.rendered
    EOF
  }
  depends_on = [
    aws_iam_user.system_users_admin, aws_iam_role.system_user_admin
  ]
}