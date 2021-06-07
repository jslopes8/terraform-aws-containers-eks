######################################################################################################
#
# Kubernetes Resources - ALB Ingress Controller
#

# IAM Policy document allow Amazon Load Balance Controller
data "aws_iam_policy_document" "alb_ingress" {
  count = var.create && var.ingress-controller ? 1 : 0
    
  statement {
    effect = "Allow"
    actions = [
      "iam:CreateServiceLinkedRole",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAddresses",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeVpcs",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeTags",
      "ec2:GetCoipPoolUsage",
      "ec2:DescribeCoipPools",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeListenerCertificates",
      "elasticloadbalancing:DescribeSSLPolicies",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:DescribeTags"
    ]
    resources = [ "*" ]
  }
  statement {
    effect  = "Allow"
    actions = [
      "cognito-idp:DescribeUserPoolClient",
      "acm:ListCertificates",
      "acm:DescribeCertificate",
      "iam:ListServerCertificates",
      "iam:GetServerCertificate",
      "waf-regional:GetWebACL",
      "waf-regional:GetWebACLForResource",
      "waf-regional:AssociateWebACL",
      "waf-regional:DisassociateWebACL",
      "wafv2:GetWebACL",
      "wafv2:GetWebACLForResource",
      "wafv2:AssociateWebACL",
      "wafv2:DisassociateWebACL",
      "shield:GetSubscriptionState",
      "shield:DescribeProtection",
      "shield:CreateProtection",
      "shield:DeleteProtection"
    ]
    resources = ["*"]
  }
  statement {
    effect  = "Allow"
    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress"
    ]
    resources = ["*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateSecurityGroup"
    ]
    resources = ["*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateTags"
    ]
    resources = ["arn:aws-cn:ec2:*:*:security-group/*"]
    condition {
      type = "StringEquals"
      variable = "ec2:CreateAction"
      values = ["CreateSecurityGroup"]
    }
    condition {
      type = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values = [ "false" ]
    }
  }
  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateTags",
      "ec2:DeleteTags"
    ]
    resources = ["arn:aws-cn:ec2:*:*:security-group/*"]
    condition {
      type = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values = ["true"]
    }
    condition {
      type = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values = ["false"]
    } 
  }
  statement {
    effect = "Allow"
    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DeleteSecurityGroup"
    ]
    resources = ["*"]
    condition {
      type = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values = ["false"]
    }
  }
  statement {
    effect = "Allow"
    actions = [
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateTargetGroup"
    ]
    resources = ["*"]
    condition {
      type = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values = ["false"]
    }
  }
  statement {
    effect = "Allow"
    actions = [
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:CreateRule",
      "elasticloadbalancing:DeleteRule"
    ]
    resources = ["*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:RemoveTags"
    ]
    resources = [
      "arn:aws-cn:elasticloadbalancing:*:*:targetgroup/*/*",
      "arn:aws-cn:elasticloadbalancing:*:*:loadbalancer/net/*/*",
      "arn:aws-cn:elasticloadbalancing:*:*:loadbalancer/app/*/*"
    ]
    condition {
      type = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values = ["true"]
    }
    condition {
      type = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values = ["false"]
    } 
  }
  statement {
    effect = "Allow"
    actions = [
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:RemoveTags"
    ]
    resources = [ 
      "arn:aws-cn:elasticloadbalancing:*:*:listener/net/*/*/*",
      "arn:aws-cn:elasticloadbalancing:*:*:listener/app/*/*/*",
      "arn:aws-cn:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
      "arn:aws-cn:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
    ]
  }
  statement {
    effect = "Allow"
    actions = [
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:SetIpAddressType",
      "elasticloadbalancing:SetSecurityGroups",
      "elasticloadbalancing:SetSubnets",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:DeleteTargetGroup"
    ]
    resources = ["*"]
    condition {
      type = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values = ["false"]
    }
  }
  statement {
    effect = "Allow"
    actions = [
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:DeregisterTargets"
    ]
    resources = ["arn:aws-cn:elasticloadbalancing:*:*:targetgroup/*/*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "elasticloadbalancing:SetWebAcl",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:AddListenerCertificates",
      "elasticloadbalancing:RemoveListenerCertificates",
      "elasticloadbalancing:ModifyRule"
    ]
    resources = ["*"]
  }
}

##
