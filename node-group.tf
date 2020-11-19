######################################################################################################
#
# Node Group
#

resource "aws_eks_node_group" "main" {
    count = var.create ? length(var.node_group) : 0

    cluster_name = aws_eks_cluster.main.0.name
    node_group_name = lookup(var.node_group[count.index], "node_group_name", null)
    subnet_ids      = lookup(var.node_group[count.index], "subnet_ids", null)

    dynamic "scaling_config" {
        for_each = lookup(var.node_group[count.index], "scaling_config", null)
        content {
            desired_size    = lookup(scaling_config.value, "desired_size", null)
            max_size        = lookup(scaling_config.value, "max_size", null)
            min_size        = lookup(scaling_config.value, "min_size", null)
        }
    }
}