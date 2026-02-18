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
# Sample NSG (intentionally unsafe inbound RDP to demo auto-fix)
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
    description                = "Deliberately open for demo; automation will fix"
  }
}

# -------------------------------------------------------------------
# VNet + VNet Flow Logs (NSG Flow Logs new creation is blocked; use VNet)
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

  # VNet Flow Logs: scope at VNet (supported path)
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
# Optional: Azure Policy to deny 0.0.0.0/0 on protected ports
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
# Logic App (Consumption) with Request trigger
# -------------------------------------------------------------------
resource "azurerm_logic_app_workflow" "autofix" {
  name                = var.logic_app_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  identity {
    type = "SystemAssigned"
  }
}

# HTTP Request trigger -> Azure will generate a callback URL
resource "azurerm_logic_app_trigger_http_request" "la_trigger" {
  name         = "manual"
  logic_app_id = azurerm_logic_app_workflow.autofix.id

  schema = jsonencode({
    type       = "object",
    properties = {
      subscriptionId    = { type = "string" },
      resourceGroupName = { type = "string" },
      nsgName           = { type = "string" },
      actionType        = { type = "string" },  # "ClosePort" | "BlockIP" (future use)
      port              = { type = "string" },
      protocol          = { type = "string" },
      maliciousIpCidr   = { type = "string" }
    },
    required = ["subscriptionId","resourceGroupName","nsgName","actionType"]
  })

  method        = "POST"
  relative_path = "invoke"
}

# -------------------------------------------------------------------
# Automation Account + Runbook + Webhook
# Runbook inserts an inbound Deny rule on the specified port if not present
# -------------------------------------------------------------------
resource "azurerm_automation_account" "aa" {
  name                = var.automation_account_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku_name            = "Basic"

  identity {
    type = "SystemAssigned"
  }
}

# Give Automation Account permission to modify the NSG
resource "azurerm_role_assignment" "aa_nsg_access" {
  scope                = azurerm_network_security_group.nsg.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_automation_account.aa.identity[0].principal_id
}

# PowerShell runbook: **proper indented heredoc** (closing PS1 at column 0)
resource "azurerm_automation_runbook" "rb_nsg_autofix" {
  name                    = "rb-nsg-autofix"
  location                = azurerm_resource_group.rg.location
  resource_group_name     = azurerm_resource_group.rg.name
  automation_account_name = azurerm_automation_account.aa.name
  runbook_type            = "PowerShell"
  log_verbose             = true
  log_progress            = true
  description             = "Add a high-priority inbound Deny rule for the specified port from Internet if not present."

  content = <<-PS1
param(
    [Parameter(Mandatory = $false)]
    [object]$WebhookData
)

if (-not $WebhookData -or -not $WebhookData.RequestBody) {
    throw "No WebhookData.RequestBody found."
}
$payload = $WebhookData.RequestBody | ConvertFrom-Json

$SubscriptionId     = $payload.subscriptionId
$ResourceGroupName  = $payload.resourceGroupName
$NsgName            = $payload.nsgName
$Port               = [int]$payload.port

Write-Output "Starting NSG autofix on $NsgName (RG=$ResourceGroupName, Port=$Port)"

# Authenticate as Automation Account's Managed Identity
Connect-AzAccount -Identity | Out-Null
Select-AzSubscription -SubscriptionId $SubscriptionId | Out-Null

# Get NSG
$nsg = Get-AzNetworkSecurityGroup -Name $NsgName -ResourceGroupName $ResourceGroupName -ErrorAction Stop

# Check for existing broad Deny on the port
$existingDeny = $nsg.SecurityRules | Where-Object {
    $_.Direction -eq "Inbound" -and
    $_.Access -eq "Deny" -and
    ($_.DestinationPortRange -eq "$Port" -or ($_.DestinationPortRanges -and ($_.DestinationPortRanges -contains "$Port"))) -and
    ($_.SourceAddressPrefix -in @("0.0.0.0/0","*","Internet") -or ($_.SourceAddressPrefixes -and ($_.SourceAddressPrefixes | Where-Object { $_ -in @("0.0.0.0/0","*","Internet") })))
}
if ($existingDeny) {
    Write-Output "An appropriate Deny rule for port $Port already exists. Exiting."
    return
}

# Choose a priority, prefer 200; find next available if occupied
$used = @($nsg.SecurityRules | Select-Object -ExpandProperty Priority)
$priority = 200
while ($used -contains $priority) {
    $priority++
    if ($priority -gt 4096) { throw "No free priority available in NSG." }
}

$ruleName = "AutoFix-Deny-Port$Port"
Write-Output "Adding Deny rule $ruleName at priority $priority"

# Add new inbound Deny rule
$nsg | Add-AzNetworkSecurityRuleConfig `
    -Name $ruleName `
    -Description "AutoFix: deny inbound port $Port from Internet" `
    -Access Deny `
    -Protocol Tcp `
    -Direction Inbound `
    -Priority $priority `
    -SourceAddressPrefix "0.0.0.0/0" `
    -SourcePortRange "*" `
    -DestinationAddressPrefix "*" `
    -DestinationPortRange "$Port" | Out-Null

Set-AzNetworkSecurityGroup -NetworkSecurityGroup $nsg | Out-Null
Write-Output "Completed: added $ruleName."
PS1
}

# Signed webhook URL so Logic App can invoke the runbook
resource "azurerm_automation_webhook" "rb_webhook" {
  name                    = "wh-nsg-autofix"
  resource_group_name     = azurerm_resource_group.rg.name
  automation_account_name = azurerm_automation_account.aa.name
  runbook_name            = azurerm_automation_runbook.rb_nsg_autofix.name
  is_enabled              = true

  # 1 year from now; rotate as needed
  expiry_time             = timeadd(timestamp(), "8760h")
}

# Logic App action: call the runbook webhook with the original payload
resource "azurerm_logic_app_action_custom" "call_autofix_webhook" {
  name         = "Call_AutoFix_Runbook"
  logic_app_id = azurerm_logic_app_workflow.autofix.id

  depends_on = [
    azurerm_automation_webhook.rb_webhook
  ]

  body = jsonencode({
    "type": "Http",
    "inputs": {
      "method": "POST",
      "uri": "${azurerm_automation_webhook.rb_webhook.uri}",
      "headers": {
        "Content-Type": "application/json"
      },
      "body": "@{triggerBody()}"
    },
    "runAfter": {
      "manual": ["Succeeded"]
    }
  })
}
