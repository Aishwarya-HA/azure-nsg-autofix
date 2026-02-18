variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "centralindia"
}

variable "rg_name" {
  description = "Resource Group name"
  type        = string
  default     = "rg-security-auto"
}

variable "law_name" {
  description = "Log Analytics Workspace name"
  type        = string
  default     = "law-nsg-sec"
}

variable "storage_name" {
  description = "Storage account (globally unique, 3-24 lowercase letters/numbers)"
  type        = string
  default     = "stnsgflowlogsauto123" # CHANGE if already taken
}

variable "nsg_name" {
  description = "Managed NSG name"
  type        = string
  default     = "nsg-app"
}

variable "logic_app_name" {
  description = "Logic App name"
  type        = string
  default     = "la-nsg-autofix"
}

variable "protect_ports" {
  description = "Ports to protect from 0.0.0.0/0"
  type        = list(string)
  default     = ["22", "3389"]
}
