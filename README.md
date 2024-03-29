# Terraform AWS EKS

## Usage
Example of the use: Creating a cluster basic of the EKS
```hcl
module "cluster" {
    source = "git@github.com:jslopes8/terraform-aws-eks.git?ref=v2.0"

    cluster_name        = "demo-lab"
    cluster_version     = "1.17"

    vpc_config = [
        {
            subnet_ids  = [ 
                "subnet-03eb1cb4c1b7edd0f", 
                "subnet-0a58abfcf70262ab9" 
            ]
            public_access_cidrs = ["0.0.0.0/0"]
        }
    ]
}
``` 

Example of the use: Creating a cluster EKS with fargate profile
```hcl
module "cluster" {
    source = "git@github.com:jslopes8/terraform-aws-eks.git?ref=v2.0"

    cluster_name        = "demo-lab"
    cluster_version     = "1.17"

    vpc_config = [
        {
            subnet_ids  = [ 
                "subnet-03eb1cb4c1b7edd0f", 
                "subnet-0a58abfcf70262ab9" 
            ]
            public_access_cidrs = ["0.0.0.0/0"]
        }
    ]

    fargate_profile = [{
            name        = "pod_fargate"
            subnet_ids  = [ 
                "subnet-03eb1cb4c1b7edd0f", 
                "subnet-0a58abfcf70262ab9" 
            ]
            selector = [{
                    namespace = "kube-system"
            }]
    }]
}
```
Example Creating a Complete EKS Cluster on Fargate Host
```hcl
module "cluster" {
    source = "git@github.com:jslopes8/terraform-aws-eks.git?ref=v2.0

    cluster_name        = "demo-lab"
    cluster_version     = "1.17"

    vpc_id              = local.vpc_id
    vpc_config = [
        {
            subnet_ids          = data.aws_subnet_ids.find.ids
            public_access_cidrs = ["0.0.0.0/0"]
        }
    ]

    enabled_cluster_log_types   = [ "api", "audit" ]
    retention_in_days           = "14"

    alb-ingress-controller = "true"

    fargate_profile = [
        {
            name        = "kube-fargate"
            subnet_ids  = data.aws_subnet_ids.find.ids
            selector = [
                { namespace = "kube-system" },
                { namespace = "default" },
                { namespace = "kube-ingress" }
            ]
        },
        {
            name        = "application-fargate"
            subnet_ids  = data.aws_subnet_ids.find.ids
            selector = [{ namespace = "2048-game" }]
        }
    ]

    kubeconfig_path = "/home/jslopes/config"
    default_tags    = local.tags
}
```

Each document configuration can have one `vpc_config` block, which accepts the following arguments:

- subnet_ids (Required) - list of subnet IDs. Must be in at least two different availability zones.
- public_access_cidrs (Required) - indicates which CIDR blocks can access the API server endpoint when enabled.
- security_group_ids (Opcional) - list of security group IDs for allow communication between your worker nodes and the Kubernetes control plane.
- endpoint_public_access (Opcional) - indicates whether or not the API server endpoint is enabled. Default is `true`.
- endpoint_private_access (Opcional) - indicates whether or not the API server endpoint is enabled. Default is `false`.

Each document configuration may have one `fargate_profile` blocks, which accepts the following arguments:

- name (Required) - name of the EKS Fargate Profile.
- subnet_ids (Required) - list of subnet IDs. Must be in at least two different availability zones.
- selector (Required) - the `selector` block is dinamic and may have one or more `namespace` argument.


<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Variables Inputs
| Name | Description | Required | Type | Default |
| ---- | ----------- | --------- | ---- | ------- |
| cluster_name | The name of the cluster | `yes` | `string` | ` ` |
| cluster_version | Desired Kubernetes master version. | `yes` | `string` | `1.17` |
| vpc_id | The Id VPC | `yes` | `string` | ` ` |
| vpc_config | The VPC associated with your cluster. | `yes` | `list` | `[]` |
| retention_in_days | The policy retention in days, required if argument `enabled_cluster_log_types` is present. | `no` | `number` | ` ` | 
| enabled_cluster_log_types | A list of the desired control plane logging to enable. | `no` | `list` | `[]` |
| fargate_profile | The Fargate profile allows an administrator to declare which pods run on Fargate. | `no` | `list` | `[]` |
| kubeconfig_path |  The path for creating of the kubeconfig files. | `no` | `string` | ` ` |
| alb-ingress-controller | The AWS ALB Ingress Controller for Kubernetes is a controller that triggers the creation of an Application Load Balancer (ALB) and the necessary supporting AWS resources whenever an Ingress resource is created on the cluster with the kubernetes.io/ingress.class: alb annotation. Details on https://docs.aws.amazon.com/eks/latest/userguide/alb-ingress.html. | `no` | `bool` | `false` |

 
## Variable Outputs
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
| Name | Description |
| ---- | ----------- |
| api_server | The endpoint for your Kubernetes API server. |
| kubeconfig_cert_data | The base64 encoded certificate data required to communicate with your cluster. |
| kubeconfig_path | The path of the kubeconfig files. |
