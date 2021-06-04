output "api_server" {
  value = aws_eks_cluster.main.0.endpoint
}

output "kubeconfig_cert_data" {
  value = aws_eks_cluster.main.0.certificate_authority.0.data
}
output "kubeconfig_path" {
  value = length(local_file.main) > 0 ? local_file.main.0.filename : 0
}
output "admin_profile" {
  value = [ 
    aws_iam_user.system_users_admin.0.name,
    aws_iam_access_key.system_users_admin.0.id,
    aws_iam_access_key.system_users_admin.0.secret
  ]
}