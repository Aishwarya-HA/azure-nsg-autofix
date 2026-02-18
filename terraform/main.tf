terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.110.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# -----------------------------
# Resource Group
# -----------------------------
resource "azurerm_resource_group" "rg" {
  name     = var.rg_name
  location = var.location
}

# -----------------------------
# Log Analytics Workspace
# -----------------------------
resource "azurerm_log_analytics_workspace" "law" {
  name                = var.law_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# -----------------------------
# Storage Account for Flow Logs
# -----------------------------
resource "azurerm_storage_account" "sa" {
  name                     = var.storage_name
  location                 = azurerm_resource_group.rg.location
  resource_group_name      = azurerm_resource_group.rg.name
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}

# -----------------------------
# Sample NSG (intentionally unsafe rule to demonstrate auto-fix)
# -----------------------------
resource "azurerm_network_security_group" "nsg" {
  name                = var.nsg_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  # Example risky rule: RDP open to internet (will be auto-fixed)
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

# -----------------------------
# Network Watcher Flow Logs v2 + Traffic Analytics
# Note: In many subscriptions, Network Watcher RG/name are pre-created.
# For Central India region, they are typically:
#   RG:   NetworkWatcherRG
#   Name: NetworkWatcher_centralindia
# If they don't exist, create them or switch to region's watcher.
# -----------------------------
resource "azurerm_network_watcher" "nw" {
  name                = "NetworkWatcher_${var.location}"
  resource_group_name = "NetworkWatcherRG"
  location            = var.location
}

resource "azurerm_network_watcher_flow_log" "flowlog" {
  name                      = "flowlog-${var.nsg_name}"
  resource_group_name       = azurerm_network_watcher.nw.resource_group_name
  network_watcher_name      = azurerm_network_watcher.nw.name
  network_security_group_id = azurerm_network_security_group.nsg.id
  storage_account_id        = azurerm_storage_account.sa.id
  enabled                   = true
  version                   = 2

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.law.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.law.location
    workspace_resource_id = azurerm_log_analytics_workspace.law.id
    interval_in_minutes   = 10
  }
}

# -----------------------------
# Azure Policy: Deny 0.0.0.0/0 on protected ports (22,3389)
# Using a simple custom policy here to ensure portability.
# -----------------------------
resource "azurerm_policy_definition" "deny_any_protected_ports" {
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

resource "azurerm_policy_assignment" "deny_any_protected_ports_assignment" {
  name                 = "deny-any-protected-ports-assignment"
  display_name         = "Deny inbound any on protected ports"
  policy_definition_id = azurerm_policy_definition.deny_any_protected_ports.id
  scope                = azurerm_resource_group.rg.id
  parameters = jsonencode({
    ports = { value = var.protect_ports }
  })
}

# -----------------------------
# Logic App (Consumption) with Managed Identity
# - HTTP Trigger receives payload with NSG details & intent
# - HTTP action uses Managed Identity to call ARM:
#     GET NSG -> modify rules -> PUT NSG
# -----------------------------
resource "azurerm_logic_app_workflow" "autofix" {
  name                = var.logic_app_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  identity {
    type = "SystemAssigned"
  }

  # Definition: simple flow — manual HTTP trigger or webhook from Alert
  definition = jsonencode({
    "$schema" = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion" = "1.0.0.0",
    "parameters" = {},
    "triggers" = {
      "manual" = {
        "type" = "Request",
        "kind" = "Http",
        "inputs" = {
          "schema" = {
            "type" = "object",
            "properties" = {
              "subscriptionId"    = { "type" = "string" },
              "resourceGroupName" = { "type" = "string" },
              "nsgName"           = { "type" = "string" },
              "actionType"        = { "type" = "string" }, # "ClosePort" | "BlockIP"
              "port"              = { "type" = "string" },
              "protocol"          = { "type" = "string" },
              "maliciousIpCidr"   = { "type" = "string" }
            },
            "required" = ["subscriptionId","resourceGroupName","nsgName","actionType"]
          }
        }
      }
    },
    "actions" = {
      "Get_NSG" = {
        "type" = "Http",
        "inputs" = {
          "method" = "GET",
          "uri" = "@{concat('https://management.azure.com/subscriptions/', triggerBody()?['subscriptionId'], '/resourceGroups/', triggerBody()?['resourceGroupName'], '/providers/Microsoft.Network/networkSecurityGroups/', triggerBody()?['nsgName'], '?api-version=2023-09-01')}",
          "authentication" = {
            "type" = "ManagedServiceIdentity"
          }
        },
        "runAfter" = {}
      },
      "Compose_Modified_NSG" = {
        "type" = "Compose",
        "inputs" = "@{if(equals(triggerBody()?['actionType'],'ClosePort'), json(replace(string(body('Get_NSG')), '\"access\":\"Allow\",\"destinationPortRange\":\"' , concat('\"access\":\"Deny\",\"destinationPortRange\":\"'))), body('Get_NSG'))}"
        # NOTE: This simple demo replaces first Allow->Deny occurrence for matching port.
        # You can extend with more robust logic in a Function/Automation if needed.
      },
      "Put_NSG" = {
        "type" = "Http",
        "inputs" = {
          "method" = "PUT",
          "uri" = "@{concat('https://management.azure.com/subscriptions/', triggerBody()?['subscriptionId'], '/resourceGroups/', triggerBody()?['resourceGroupName'], '/providers/Microsoft.Network/networkSecurityGroups/', triggerBody()?['nsgName'], '?api-version=2023-09-01')}",
          "headers" = {
            "Content-Type" = "application/json"
          },
          "body" = "@{outputs('Compose_Modified_NSG')}",
          "authentication" = {
            "type" = "ManagedServiceIdentity"
          }
        },
        "runAfter" = {
          "Compose_Modified_NSG" = [ "Succeeded" ]
        }
      }
    },
    "outputs" = {}
  })
}

# HTTP trigger callback URL output (wired via separate resource)
resource "azurerm_logic_app_trigger_http_request" "la_trigger" {
  name         = "manual"
  logic_app_id = azurerm_logic_app_workflow.autofix.id
  schema       = jsonencode({ "type" = "object" })
}

# Allow Logic App MSI to manage NSG
resource "azurerm_role_assignment" "logic_nsg_access" {
  principal_id         = azurerm_logic_app_workflow.autofix.identity[0].principal_id
  role_definition_name = "Network Contributor"
  scope                = azurerm_network_security_group.nsg.id
}

# -----------------------------
# Action Group -> sends webhook to Logic App trigger URL
# You can hook this to alerts later; for now it's created so you can wire alerts.
# -----------------------------
resource "azurerm_monitor_action_group" "ag" {
  name                = "ag-nsg-autofix"
  resource_group_name = azurerm_resource_group.rg.name
  short_name          = "autofix"

  webhook_receiver {
    name        = "logicapp"
    service_uri = azurerm_logic_app_trigger_http_request.la_trigger.callback_url
  }
}
