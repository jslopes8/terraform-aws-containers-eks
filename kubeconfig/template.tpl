apiVersion: v1
kind: Config
current-context: admin
clusters:
- name: ${cluster_name}
  cluster:
    certificate-authority-data: ${cluster_auth_base64}
    server: ${endpoint}
contexts:
- name: admin
  context:
    cluster: ${cluster_name}
    user: admin
users:
- name: admin
  user:
    token: ${token}