# Terraform AWS EKS

## Usage
Example of the use: Creating a cluster basic of the EKS
```hcl
module "cluster" {
    source = "git@github.com:jslopes8/terraform-aws-eks.git?ref=v1.0"

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
    source = "git@github.com:jslopes8/terraform-aws-eks.git?ref=v1.0"

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

    fargate_profile = [
        {
            name        = "pod_fargate"
            subnet_ids  = [ 
                "subnet-03eb1cb4c1b7edd0f", 
                "subnet-0a58abfcf70262ab9" 
            ]
            selector = [
                {
                    namespace = "kube-system"
                }
            ]
        }
    ]
}
```

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Variables Inputs
| Name | Description | Required | Type | Default |
| ---- | ----------- | --------- | ---- | ------- |
| cluster_name | The name of the cluster | `yes` | `string` | ` ` |
| cluster_version | Desired Kubernetes master version. | `yes` | `string` | `1.17` |
| vpc_config | The VPC associated with your cluster. | `yes` | `list` | `[]` |
| retention_in_days | The policy retention in days, required if argument `enabled_cluster_log_types` is present. | `no` | `number` | ` ` | 
| enabled_cluster_log_types | A list of the desired control plane logging to enable. | `no` | `list` | `[]` |
| fargate_profile | The Fargate profile allows an administrator to declare which pods run on Fargate. | `no` | `list` | `[]` |
| kubeconfig_path |  The path for creating of the kubeconfig files. | `no` | `string` | ` ` |
 
## Variable Outputs
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
| Name | Description |
| ---- | ----------- |
| api_server | The endpoint for your Kubernetes API server. |
| kubeconfig_cert_data | The base64 encoded certificate data required to communicate with your cluster. |
| kubeconfig_path | The path of the kubeconfig files. |