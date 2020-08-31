output "api_server" {
  value = aws_eks_cluster.main.0.endpoint
}

output "kubeconfig_cert_data" {
  value = aws_eks_cluster.main.0.certificate_authority.0.data
}
output "kubeconfig_path" {
  value = length(local_file.main) > 0 ? local_file.main.0.filename : 0
}