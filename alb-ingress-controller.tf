######################################################################################################
#
# Kubernetes Resources - ALB Ingress Controller
#
 
provider "kubernetes" {

    host                   = data.aws_eks_cluster.main.0.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.main.0.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.main.0.token
    #load_config_file       = false
    #version                = "~> 1.10"
}
data "aws_iam_policy_document" "alb_ingress" {
    count = var.create && var.alb-ingress-controller ? 1 : 0

    statement {
        effect = "Allow"
        actions = [
            "acm:DescribeCertificate", "acm:ListCertificates", "acm:GetCertificate"
        ]
        resources = ["*"]
    }
    statement {
        effect = "Allow"
        actions = [
            "ec2:AuthorizeSecurityGroupIngress", "ec2:CreateSecurityGroup", "ec2:CreateTags",
            "ec2:DeleteTags", "ec2:DeleteSecurityGroup", "ec2:DescribeAccountAttributes",
            "ec2:DescribeAddresses", "ec2:DescribeInstances", "ec2:DescribeInstanceStatus",
            "ec2:DescribeInternetGateways", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSecurityGroups",
            "ec2:DescribeSubnets", "ec2:DescribeTags", "ec2:DescribeVpcs", "ec2:ModifyInstanceAttribute",
            "ec2:ModifyNetworkInterfaceAttribute", "ec2:RevokeSecurityGroupIngress"
        ]
        resources = ["*"]
    }
    statement {
        effect = "Allow"
        actions = [
            "elasticloadbalancing:AddListenerCertificates", "elasticloadbalancing:AddTags", "elasticloadbalancing:CreateListener",
            "elasticloadbalancing:CreateLoadBalancer", "elasticloadbalancing:CreateRule", "elasticloadbalancing:CreateTargetGroup",
            "elasticloadbalancing:DeleteListener", "elasticloadbalancing:DeleteLoadBalancer", "elasticloadbalancing:DeleteRule",
            "elasticloadbalancing:DeleteTargetGroup", "elasticloadbalancing:DeregisterTargets", "elasticloadbalancing:DescribeListenerCertificates",
            "elasticloadbalancing:DescribeListeners", "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeLoadBalancerAttributes",
            "elasticloadbalancing:DescribeRules", "elasticloadbalancing:DescribeSSLPolicies", "elasticloadbalancing:DescribeTags",
            "elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetGroupAttributes", "elasticloadbalancing:DescribeTargetHealth",
            "elasticloadbalancing:ModifyListener", "elasticloadbalancing:ModifyLoadBalancerAttributes", "elasticloadbalancing:ModifyRule",
            "elasticloadbalancing:ModifyTargetGroup", "elasticloadbalancing:ModifyTargetGroupAttributes", "elasticloadbalancing:RegisterTargets",
            "elasticloadbalancing:RemoveListenerCertificates", "elasticloadbalancing:RemoveTags", "elasticloadbalancing:SetIpAddressType",
            "elasticloadbalancing:SetSecurityGroups", "elasticloadbalancing:SetSubnets", "elasticloadbalancing:SetWebACL"
        ]
        resources = ["*"]
    }
    statement {
        effect = "Allow"
        actions = [
            "iam:CreateServiceLinkedRole", "iam:GetServerCertificate", "iam:ListServerCertificates"
        ]
        resources = ["*"]
    }
    statement {
        effect = "Allow"
        actions = [
            "cognito-idp:DescribeUserPoolClient"
        ]
        resources = ["*"]
    }
    statement {
        effect = "Allow"
        actions = [
            "waf-regional:GetWebACLForResource", "waf-regional:GetWebACL", "waf-regional:AssociateWebACL",
            "waf-regional:DisassociateWebACL", "waf:GetWebACL"
        ]
        resources = ["*"]
    }
    statement {
        effect = "Allow"
        actions = [
            "tag:GetResources", "tag:TagResources"
        ]
        resources = ["*"]
    }
}
resource "aws_iam_policy" "alb_ingress_policy" {
    count = var.create && var.alb-ingress-controller ? 1 : 0

    name   = "${var.cluster_name}-alb-ingress-policy"
    path   = "/"
    policy = data.aws_iam_policy_document.alb_ingress.0.json
}

locals {
    namespace_ingress = "kube-ingress"
}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_iam_policy_document" "alb_ingress_sts" {
    count = var.create && var.alb-ingress-controller ? 1 : 0

    statement {
        effect = "Allow"
        actions = [
            "sts:AssumeRoleWithWebIdentity"
        ]

        principals {
            type = "Federated"
            identifiers = [ "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(data.aws_eks_cluster.main.0.identity[0].oidc[0].issuer, "https://", "")}" ]
        }

        condition {
            test     = "StringEquals"
            variable = "${replace(data.aws_eks_cluster.main.0.identity[0].oidc[0].issuer, "https://", "")}:sub"
            values   = [ "system:serviceaccount:${local.namespace_ingress}:alb-ingress-controller" ]
        }
    }
}
resource "aws_iam_role" "alb_ingress" {
    count = var.create && var.alb-ingress-controller ? 1 : 0

    name = "${var.cluster_name}-alb-ingress-role"
    assume_role_policy = data.aws_iam_policy_document.alb_ingress_sts.0.json

    tags = var.default_tags
}
resource "aws_iam_role_policy_attachment" "alb_attachment" {
    count = var.create && var.alb-ingress-controller ? 1 : 0

    role       = aws_iam_role.alb_ingress.0.name
    policy_arn = aws_iam_policy.alb_ingress_policy.0.arn
}
resource "kubernetes_namespace" "kube_ingress" {
    depends_on = [ aws_eks_fargate_profile.main, local_file.main, aws_eks_cluster.main  ]
    count = var.create && var.alb-ingress-controller ? 1 : 0
  
    metadata {
        name = local.namespace_ingress
    }
}
resource "kubernetes_cluster_role" "rbac_ingress" {
    depends_on = [ aws_eks_fargate_profile.main, local_file.main, aws_eks_cluster.main  ]
    count = var.create && var.alb-ingress-controller ? 1 : 0

    metadata {
        name = "alb-ingress-controller"
        labels = {
            "app.kubernetes.io/name"       = "alb-ingress-controller"
            "app.kubernetes.io/managed-by" = "terraform"
        }
    }

    rule {
        api_groups = ["", "extensions"]
        resources  = ["configmaps", "endpoints", "events", "ingresses", "ingresses/status", "services"]
        verbs      = ["create", "get", "list", "update", "watch", "patch"]
    }

    rule {
        api_groups = ["", "extensions"]
        resources  = ["nodes", "pods", "secrets", "services", "namespaces"]
        verbs      = ["get", "list", "watch"]
    }
}
resource "kubernetes_cluster_role_binding" "rbac_alb_ingress" {
    depends_on = [ kubernetes_cluster_role.rbac_ingress, aws_eks_fargate_profile.main, local_file.main, aws_eks_cluster.main  ]

    count = var.create && var.alb-ingress-controller ? 1 : 0   

    metadata {
        name = "alb-ingress-controller"
        labels = {
            "app.kubernetes.io/name"       = "alb-ingress-controller"
            "app.kubernetes.io/managed-by" = "terraform"
        }
    }
    role_ref {
        api_group = "rbac.authorization.k8s.io"
        kind      = "ClusterRole"
        name      = kubernetes_cluster_role.rbac_ingress.0.metadata[0].name
    }
    subject {
        kind      = "ServiceAccount"
        name      = kubernetes_service_account.ingress.0.metadata[0].name
        namespace = kubernetes_service_account.ingress.0.metadata[0].namespace
    }
}
resource "kubernetes_service_account" "ingress" {
    depends_on = [ aws_eks_fargate_profile.main, local_file.main, aws_eks_cluster.main  ]
    count = var.create && var.alb-ingress-controller ? 1 : 0   

    automount_service_account_token = false
    metadata {
        name      = "alb-ingress-controller"
        namespace = local.namespace_ingress
        labels    = {
            "app.kubernetes.io/name"       = "alb-ingress-controller"
            "app.kubernetes.io/managed-by" = "terraform"
        }
        annotations = {
            "eks.amazonaws.com/role-arn" = aws_iam_role.alb_ingress.0.arn
        }
    }
}
resource "kubernetes_deployment" "ingress" {
    depends_on = [ kubernetes_cluster_role_binding.rbac_alb_ingress, aws_eks_fargate_profile.main, local_file.main, aws_eks_cluster.main ]

    count = var.create && var.alb-ingress-controller ? 1 : 0

    metadata {
        name      = "alb-ingress-controller"
        namespace = local.namespace_ingress
        labels    = {
            "app.kubernetes.io/name"       = "alb-ingress-controller"
            "app.kubernetes.io/version"    = "v1.1.5"
            "app.kubernetes.io/managed-by" = "terraform"
        }
    } 

    spec {
        replicas = 1

        selector {
            match_labels = {
                "app.kubernetes.io/name" = "alb-ingress-controller"
            }
        }

        template {
            metadata {
                labels = {
                    "app.kubernetes.io/name"    = "alb-ingress-controller"
                    "app.kubernetes.io/version" = "v1.1.5"
                }
            }

            spec {
                dns_policy                       = "ClusterFirst"
                restart_policy                   = "Always"
                service_account_name             = kubernetes_service_account.ingress.0.metadata[0].name
                termination_grace_period_seconds = 60

                container {
                    name              = "alb-ingress-controller"
                    image             = "docker.io/amazon/aws-alb-ingress-controller:v1.1.5"
                    image_pull_policy = "Always"

                    args = [
                        "--ingress-class=alb",
                        "--cluster-name=${data.aws_eks_cluster.main.0.id}",
                        "--aws-vpc-id=${var.vpc_id}",
                        "--aws-region=${data.aws_region.current.name}",
                        "--aws-max-retries=10",
                    ]

                    volume_mount {
                        mount_path = "/var/run/secrets/kubernetes.io/serviceaccount"
                        name       = kubernetes_service_account.ingress.0.default_secret_name
                        read_only  = true
                    }

                    port {
                        name           = "health"
                        container_port = 10254
                        protocol       = "TCP"
                    }

                    readiness_probe {
                        http_get {
                            path   = "/healthz"
                            port   = "health"
                            scheme = "HTTP"
                        }

                        initial_delay_seconds = 30
                        period_seconds        = 60
                        timeout_seconds       = 3
                    }

                    liveness_probe {
                        http_get {
                            path   = "/healthz"
                            port   = "health"
                            scheme = "HTTP"
                        }

                        initial_delay_seconds = 60
                        period_seconds        = 60
                    }
                }   

            volume {
                name = kubernetes_service_account.ingress.0.default_secret_name

                secret {
                    secret_name = kubernetes_service_account.ingress.0.default_secret_name
                }
            }
        }
    }
  }
}