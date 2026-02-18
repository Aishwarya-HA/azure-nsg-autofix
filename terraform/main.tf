terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# -------------------------------------------------------------------
# Resource Group
# -------------------------------------------------------------------
resource "azurerm_resource_group" "rg" {
  name     = var.rg_name
  location = var.location
}

# -------------------------------------------------------------------
# Log Analytics Workspace
# -------------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "law" {
  name                = var.law_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# -------------------------------------------------------------------
# Storage Account for Flow Logs
# -------------------------------------------------------------------
resource "azurerm_storage_account" "sa" {
  name                     = var.storage_name
  location                 = azurerm_resource_group.rg.location
  resource_group_name      = azurerm_resource_group.rg.name
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}

# -------------------------------------------------------------------
# Sample NSG (intentionally unsafe rule to demonstrate auto-fix later)
# -------------------------------------------------------------------
resource "azurerm_network_security_group" "nsg" {
  name                = var.nsg_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "Allow-RDP-Internet"
    priority                   = 300
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
    description                = "Deliberately open for demo; Logic App will fix"
  }
}

# -------------------------------------------------------------------
# VNet + VNet Flow Logs (NSG Flow Logs: new creation blocked; move to VNet)
# -------------------------------------------------------------------
resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-sec-auto"
  address_space       = ["10.10.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_network_watcher" "nw" {
  name                = "nw-${var.location}"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_network_watcher_flow_log" "flowlog" {
  name                 = "flowlog-vnet"
  resource_group_name  = azurerm_resource_group.rg.name
  network_watcher_name = azurerm_network_watcher.nw.name

  # VNet Flow Logs: target the VNet (NOT the NSG)
  target_resource_id = azurerm_virtual_network.vnet.id
  storage_account_id = azurerm_storage_account.sa.id
  enabled            = true
  version            = 2

  retention_policy {
    enabled = true
    days    = 7
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.law.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.law.location
    workspace_resource_id = azurerm_log_analytics_workspace.law.id
    interval_in_minutes   = 10
  }
}

# -------------------------------------------------------------------
# Azure Policy (DENY 0.0.0.0/0 for protected ports) - gated by feature flag
# -------------------------------------------------------------------
resource "azurerm_policy_definition" "deny_any_protected_ports" {
  count        = var.enable_policy ? 1 : 0
  name         = "deny-any-protected-ports"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny inbound 0.0.0.0/0 on protected ports"

  parameters = jsonencode({
    ports = {
      type         = "Array"
      metadata     = { displayName = "Ports to protect" }
      defaultValue = var.protect_ports
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.Network/networkSecurityGroups/securityRules" },
        { field = "Microsoft.Network/networkSecurityGroups/securityRules/direction", equals = "Inbound" },
        {
          anyOf = [
            { field = "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix", equals = "0.0.0.0/0" },
            { field = "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix", equals = "*" }
          ]
        },
        {
          anyOf = [
            { field = "Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRange", in = "[parameters('ports')]" },
            { field = "Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRanges[*]", in = "[parameters('ports')]" }
          ]
        }
      ]
    }
    then = { effect = "deny" }
  })
}

# v4-style RG-scoped assignment
resource "azurerm_resource_group_policy_assignment" "deny_any_protected_ports_assignment" {
  count                 = var.enable_policy ? 1 : 0
  name                  = "deny-any-protected-ports-assignment"
  display_name          = "Deny inbound any on protected ports"
  resource_group_id     = azurerm_resource_group.rg.id
  policy_definition_id  = azurerm_policy_definition.deny_any_protected_ports[0].id

  parameters = jsonencode({
    ports = { value = var.protect_ports }
  })
}

# -------------------------------------------------------------------
# Logic App (Consumption) with System-assigned Managed Identity
# -------------------------------------------------------------------
resource "azurerm_logic_app_workflow" "autofix" {
  name                = var.logic_app_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  identity {
    type = "SystemAssigned"
  }
}

# ---- HTTP Request trigger so Azure generates the POST callback URL ----
resource "azurerm_logic_app_trigger_http_request" "la_trigger" {
  name         = "manual"
  logic_app_id = azurerm_logic_app_workflow.autofix.id

  # Expected request body schema
  schema = jsonencode({
    type       = "object",
    properties = {
      subscriptionId    = { type = "string" },
      resourceGroupName = { type = "string" },
      nsgName           = { type = "string" },
      actionType        = { type = "string" },  # "ClosePort" | "BlockIP" (future)
      port              = { type = "string" },
      protocol          = { type = "string" },
      maliciousIpCidr   = { type = "string" }
    },
    required = ["subscriptionId","resourceGroupName","nsgName","actionType"]
  })

  method        = "POST"
  relative_path = "invoke"
}

# ---- Action 1: GET the NSG (custom action with MSI auth in JSON) ----
resource "azurerm_logic_app_action_custom" "get_nsg" {
  name         = "Get_NSG"
  logic_app_id = azurerm_logic_app_workflow.autofix.id

  body = jsonencode({
    "type"   : "Http",
    "inputs" : {
      "method": "GET",
      "uri"   : "@{concat('https://management.azure.com/subscriptions/', triggerBody()?['subscriptionId'], '/resourceGroups/', triggerBody()?['resourceGroupName'], '/providers/Microsoft.Network/networkSecurityGroups/', triggerBody()?['nsgName'], '?api-version=2023-09-01')}",
      "authentication": { "type": "ManagedServiceIdentity" }
    }
  })
}

# ---- Action 2: PUT the NSG back (ensure it runs after Get_NSG) ----
resource "azurerm_logic_app_action_custom" "put_nsg" {
  name         = "Put_NSG"
  logic_app_id = azurerm_logic_app_workflow.autofix.id

  # Ensure Get_NSG is created first (Azure validates runAfter target exists)
  depends_on = [
    azurerm_logic_app_action_custom.get_nsg
  ]

  body = jsonencode({
    "type"   : "Http",
    "inputs" : {
      "method": "PUT",
      "uri"   : "@{concat('https://management.azure.com/subscriptions/', triggerBody()?['subscriptionId'], '/resourceGroups/', triggerBody()?['resourceGroupName'], '/providers/Microsoft.Network/networkSecurityGroups/', triggerBody()?['nsgName'], '?api-version=2023-09-01')}",
      "headers": { "Content-Type": "application/json" },
      "body"   : "@{body('Get_NSG')}",
      "authentication": { "type": "ManagedServiceIdentity" }
    },
    "runAfter": { "Get_NSG": ["Succeeded"] }
  })
}

# ---- RBAC for Logic App MI on NSG (gated until you have permissions) ----
resource "azurerm_role_assignment" "logic_nsg_access" {
  count                 = var.enable_role_assignments ? 1 : 0
  principal_id          = azurerm_logic_app_workflow.autofix.identity[0].principal_id
  role_definition_name  = "Network Contributor"
  scope                 = azurerm_network_security_group.nsg.id
}

# ---- Action Group -> webhook to Logic App trigger URL (for alerts later) ----
resource "azurerm_monitor_action_group" "ag" {
  name                = "ag-nsg-autofix"
  resource_group_name = azurerm_resource_group.rg.name
  short_name          = "autofix"

  webhook_receiver {
    name        = "logicapp"
    service_uri = azurerm_logic_app_trigger_http_request.la_trigger.callback_url
  }
}
