######################################################################################################
#
# Node Group
#

#
# IAM role - EKS Node Group
#

data "aws_iam_policy_document" "node_group" {
    count = var.create ? length(var.node_group) : 0

    statement {
        effect = "Allow"
        actions = [
            "sts:AssumeRole"
        ]
        principals {
            type = "Service"
            identifiers = [ "ec2.amazonaws.com" ]
        }
    }
}

resource "aws_iam_role" "node_group" {
  count = var.create ? length(var.node_group) > 0 ? 1 : 0

  name                = "${var.cluster_name}-node-group-role"
  assume_role_policy  = data.aws_iam_policy_document.node_group.0.json

  tags = var.default_tags
}

resource "aws_iam_role_policy_attachment" "node_group_eks_workers" {
  count = var.create && length(var.node_group) > 0 ? 1 : 0

  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role    = aws_iam_role.node_group.0.name
}

resource "aws_iam_role_policy_attachment" "node_group_eks_cni" {
  count = var.create && length(var.node_group) > 0 ? 1 : 0

  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role    = aws_iam_role.node_group.0.name
}

resource "aws_iam_role_policy_attachment" "node_group_eks_registry" {
  count = var.create && length(var.node_group) > 0 ? 1 : 0

  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role    = aws_iam_role.node_group.0.name
}


#
# EKS - Node Group
#

resource "aws_eks_node_group" "main" {
  count = var.create ? length(var.node_group) : 0

  cluster_name    = aws_eks_cluster.main.0.name
  node_group_name = lookup(var.node_group[count.index], "node_group_name", null)
  subnet_ids      = lookup(var.node_group[count.index], "subnet_ids", null)

  ami_type              = lookup(var.node_group[count.index], "ami_type", "AL2_x86_64")
  capacity_type         = lookup(var.node_group[count.index], "capacity_type", null)
  disk_size             = lookup(var.node_group[count.index], "disk_size", null)
  instance_type         = lookup(var.node_group[count.index], "instance_type", null)
  force_update_version  = lookup(var.node_group[count.index], "force_update_version", null)
  release_version       = lookup(var.node_group[count.index], "release_version", null)
  version               = lookup(var.node_group[count.index], "version", null)

  launch_template = [
    id      = lookup(var.node_group[count.index], "launch_template_id", null)
    name    = lookup(var.node_group[count.index], "launch_template_name", null)
    version = lookup(var.node_group[count.index], "launch_template_version", null)
  ]

  remote_access = [
    ec2_ssh_key               = lookup(var.node_group[count.index], "ec2_ssh_key", null)
    source_security_group_ids = lookup(var.node_group[count.index], "source_security_group_ids", null)
  ]

  dynamic "scaling_config" {
    for_each = lookup(var.node_group[count.index], "scaling_config", null)
    content {
      desired_size  = lookup(scaling_config.value, "desired_size", null)
        max_size    = lookup(scaling_config.value, "max_size", null)
        min_size    = lookup(scaling_config.value, "min_size", null)
    }
  }

  tags  = var.default_tags

  depends_on = [
    aws_iam_role_policy_attachment.node_group_eks_registry,
    aws_iam_role_policy_attachment.node_group_eks_cni,
    aws_iam_role_policy_attachment.node_group_eks_workers
  ]
}