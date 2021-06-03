variable "create" {
    type = bool
    default = true
}
variable "cluster_name" {
    type = string
}
variable "system_users_admin" {
  type = bool
  default = true
}
variable "enabled_cluster_log_types" {
    type = list
    default = []
}
variable "cluster_version" {
    type = string
    default = null
}
variable "vpc_config" {
    type = any
    default = []
}
variable "default_tags" {
    type = any 
    default = {}
}
variable "encryption_config" {
    type = any 
    default = []
}
variable "retention_in_days" {
    type = number
    default = null
}
variable "fargate_profile" {
    type = any 
    default = []
}
variable "node_group" {
    type = any 
    default = []
}
variable "kubeconfig_path" {
    type = string
    default = ""
}
variable "alb-ingress-controller" {
    type = bool
    default = false
}
variable "vpc_id" {
    type = string
    default = ""
}
variable "nginx_ingress" {
    type = bool
    default = false
}