variable "create" {
    type = bool
    default = true
}
variable "cluster_name" {
    type = string
}
variable "enabled_cluster_log_types" {
    type = list
    default = []
}
variable "region" {
    type = string
    default = ""
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
variable "kubeconfig_path" {
    type = string
    default = ""
}