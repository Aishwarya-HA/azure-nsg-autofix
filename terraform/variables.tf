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
  default     = "stnsgflowlogsauto123" # change if taken
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

variable "automation_account_name" {
  description = "Automation Account name"
  type        = string
  default     = "aa-nsg-autofix"
}

variable "protect_ports" {
  description = "Ports to protect from 0.0.0.0/0 (used by policy if enabled)"
  type        = list(string)
  default     = ["22", "3389"]
}

# Optional policy (flip to true when you have Policy permissions)
variable "enable_policy" {
  description = "Create custom policy definition + assignment (requires Resource Policy Contributor/Owner)"
  type        = bool
  default     = false
}
