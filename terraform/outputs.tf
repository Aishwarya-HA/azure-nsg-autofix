# Logic App callback URL (the HTTP POST endpoint). Sensitive on purpose.
output "logic_app_callback_url" {
  description = "Logic App HTTP POST trigger URL"
  value       = azurerm_logic_app_trigger_http_request.la_trigger.callback_url
  sensitive   = true
}

# Webhook URL for Automation Runbook (signed URL)
output "runbook_webhook_uri" {
  description = "Automation Runbook webhook URL"
  value       = azurerm_automation_webhook.rb_webhook.uri
  sensitive   = true
}

output "resource_group" {
  value = azurerm_resource_group.rg.name
}

output "nsg_id" {
  value = azurerm_network_security_group.nsg.id
}
