output "logic_app_callback_url" {
  description = "Logic App trigger URL (use this in alerts/webhooks)"
  value       = azurerm_logic_app_trigger_http_request.la_trigger.callback_url
  sensitive   = true
}

output "resource_group" {
  value = azurerm_resource_group.rg.name
}

output "nsg_id" {
  value = azurerm_network_security_group.nsg.id
}
