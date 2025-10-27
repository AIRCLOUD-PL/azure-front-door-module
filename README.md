# Azure Front Door Terraform Module

This Terraform module creates an Azure Front Door with enterprise-grade features including Web Application Firewall (WAF), custom domains, advanced routing, security rules, and comprehensive monitoring.

## Features

- **Global CDN**: 100+ edge locations worldwide for optimal performance
- **Web Application Firewall (WAF)**: Protection against OWASP Top 10 and bot attacks
- **Custom Domains**: Secure custom domain support with managed certificates
- **Advanced Routing**: URL-based routing, path rewriting, and traffic splitting
- **Load Balancing**: Intelligent load balancing with health monitoring
- **Security Rules**: Custom rules for rate limiting, geo-blocking, and request filtering
- **Caching**: Dynamic and static content caching with compression
- **SSL/TLS**: HTTPS-only with custom SSL policies and certificates
- **Monitoring**: Comprehensive logging and metrics collection
- **Azure Policy**: Built-in policy assignments for security compliance

## Architecture

```
Internet
    ↓
[Azure Front Door]
    ↓ (WAF Protection)
[Custom Domains & SSL]
    ↓ (Routing Rules)
[Origin Groups]
    ↓ (Load Balancing)
[Backend Origins]
```

## Usage

### Basic Example

```hcl
module "front_door" {
  source = "./modules/network/front-door"

  # Resource Configuration
  resource_group_name = "rg-frontdoor"
  location           = "East US"
  environment       = "prod"

  # Front Door Profile
  frontdoor_profile_name = "fd-example"
  sku_name              = "Standard_AzureFrontDoor"

  # Endpoints
  endpoints = {
    main = {
      name    = "main-endpoint"
      enabled = true
    }
  }

  # Origin Groups
  origin_groups = {
    web-origins = {
      name = "web-origins"
      health_probe = {
        interval_in_seconds = 30
        path                = "/health"
        protocol            = "Https"
      }
    }
  }

  # Origins
  origins = {
    web-app = {
      name              = "web-app"
      origin_group_name = "web-origins"
      enabled           = true
      host_name         = "mywebapp.azurewebsites.net"
    }
  }

  # Routes
  routes = {
    default-route = {
      name              = "default-route"
      endpoint_name     = "main"
      origin_group_name = "web-origins"
      origin_names      = ["web-app"]
      enabled           = true
      patterns_to_match = ["/*"]
    }
  }

  # Tags
  tags = {
    Environment = "prod"
    Project     = "web-app"
  }
}
```

### Enterprise Example with WAF and Custom Domains

```hcl
module "front_door_enterprise" {
  source = "./modules/network/front-door"

  # Resource Configuration
  resource_group_name = "rg-frontdoor-prod"
  location           = "East US 2"
  environment       = "prod"

  # Front Door Profile
  frontdoor_profile_name = "fd-enterprise-prod"
  sku_name              = "Premium_AzureFrontDoor"

  # WAF Policy
  waf_policies = {
    main-waf = {
      name    = "main-waf-policy"
      enabled = true
      mode    = "Prevention"
      managed_rules = [
        {
          type    = "Microsoft_DefaultRuleSet"
          version = "2.1"
          action  = "Block"
        }
      ]
      custom_rules = [
        {
          name     = "RateLimit"
          action   = "Block"
          enabled  = true
          priority = 100
          type     = "RateLimitRule"
          rate_limit_duration_in_minutes = 5
          rate_limit_threshold          = 1000
          match_conditions = [
            {
              match_variable = "RemoteAddr"
              operator       = "IPMatch"
              match_values   = ["*"]
            }
          ]
        }
      ]
    }
  }

  # Custom Domains
  custom_domains = {
    www-domain = {
      name      = "www-domain"
      host_name = "www.example.com"
      tls = {
        certificate_type    = "ManagedCertificate"
        minimum_tls_version = "TLS12"
      }
    }
  }

  # Endpoints
  endpoints = {
    main = {
      name    = "main-endpoint"
      enabled = true
    }
  }

  # Origin Groups
  origin_groups = {
    web-origins = {
      name = "web-origins"
      health_probe = {
        interval_in_seconds = 30
        path                = "/health"
        protocol            = "Https"
      }
      load_balancing = {
        additional_latency_in_milliseconds = 100
        sample_size                        = 4
        successful_samples_required        = 2
      }
    }
  }

  # Origins
  origins = {
    primary = {
      name              = "primary-origin"
      origin_group_name = "web-origins"
      enabled           = true
      host_name         = "web-primary.azurewebsites.net"
      priority          = 1
      weight            = 100
    }
    secondary = {
      name              = "secondary-origin"
      origin_group_name = "web-origins"
      enabled           = true
      host_name         = "web-secondary.azurewebsites.net"
      priority          = 2
      weight            = 50
    }
  }

  # Rule Sets and Rules
  rule_sets = {
    security = {
      name = "security-rules"
    }
  }

  rules = {
    security-headers = {
      name          = "security-headers"
      rule_set_name = "security"
      order         = 1
      actions = {
        response_header_actions = [
          {
            header_action = "Append"
            header_name   = "X-Frame-Options"
            value         = "DENY"
          }
        ]
      }
    }
  }

  # Routes
  routes = {
    main-route = {
      name                = "main-route"
      endpoint_name       = "main"
      origin_group_name   = "web-origins"
      origin_names        = ["primary", "secondary"]
      enabled             = true
      forwarding_protocol = "HttpsOnly"
      https_redirect_enabled = true
      patterns_to_match   = ["/*"]
      cache = {
        compression_enabled = true
      }
      custom_domain_names = ["www-domain"]
      waf_policy_name     = "main-waf"
      rule_set_names      = ["security"]
    }
  }

  # Monitoring
  diagnostic_settings = {
    logs = [
      {
        category = "FrontDoorAccessLog"
        retention_policy = {
          enabled = true
          days    = 30
        }
      }
    ]
    metrics = [
      {
        category = "AllMetrics"
        enabled  = true
      }
    ]
  }

  # Security Policies
  enable_policy_assignments = true

  # Tags
  tags = {
    Environment = "prod"
    Project     = "enterprise-app"
    Security    = "high"
  }
}
```

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.0 |
| <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) | >= 3.80.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | >= 3.80.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [azurerm_cdn_frontdoor_profile](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_profile) | resource |
| [azurerm_cdn_frontdoor_firewall_policy](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_firewall_policy) | resource |
| [azurerm_cdn_frontdoor_origin_group](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_origin_group) | resource |
| [azurerm_cdn_frontdoor_origin](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_origin) | resource |
| [azurerm_cdn_frontdoor_endpoint](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_endpoint) | resource |
| [azurerm_cdn_frontdoor_custom_domain](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_custom_domain) | resource |
| [azurerm_cdn_frontdoor_secret](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_secret) | resource |
| [azurerm_cdn_frontdoor_route](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_route) | resource |
| [azurerm_cdn_frontdoor_rule_set](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_rule_set) | resource |
| [azurerm_cdn_frontdoor_rule](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_rule) | resource |
| [azurerm_policy_assignment](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/policy_assignment) | resource |
| [azurerm_monitor_diagnostic_setting](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_resource_group_name"></a> [resource\_group\_name](#input\_resource\_group\_name) | Name of the resource group | `string` | n/a | yes |
| <a name="input_location"></a> [location](#input\_location) | Azure region for resources | `string` | n/a | yes |
| <a name="input_environment"></a> [environment](#input\_environment) | Environment name (dev, test, prod) | `string` | n/a | yes |
| <a name="input_frontdoor_profile_name"></a> [frontdoor\_profile\_name](#input\_frontdoor\_profile\_name) | Name of the Front Door profile | `string` | n/a | yes |
| <a name="input_sku_name"></a> [sku\_name](#input\_sku\_name) | SKU name for the Front Door profile | `string` | `"Standard_AzureFrontDoor"` | no |
| <a name="input_waf_policies"></a> [waf\_policies](#input\_waf\_policies) | WAF policies configuration | <pre>map(object({<br>    name                              = string<br>    enabled                           = optional(bool, true)<br>    mode                              = optional(string, "Prevention")<br>    redirect_url                      = optional(string)<br>    custom_block_response_status_code = optional(number)<br>    custom_block_response_body        = optional(string)<br>    custom_rules = optional(list(object({<br>      name                           = string<br>      action                         = string<br>      enabled                        = optional(bool, true)<br>      priority                       = number<br>      type                           = string<br>      rate_limit_duration_in_minutes = optional(number)<br>      rate_limit_threshold           = optional(number)<br>      match_conditions = list(object({<br>        match_variable     = string<br>        match_values       = list(string)<br>        operator           = string<br>        selector           = optional(string)<br>        negate_condition   = optional(bool, false)<br>        transforms         = optional(list(string), [])<br>      }))<br>    })), [])<br>    managed_rules = optional(list(object({<br>      type      = string<br>      version   = string<br>      action    = optional(string, "Block")<br>      exclusions = optional(list(object({<br>        match_variable = string<br>        operator       = string<br>        selector       = string<br>      })), [])<br>      overrides = optional(list(object({<br>        rule_group_name = string<br>        exclusions = optional(list(object({<br>          match_variable = string<br>          operator       = string<br>          selector       = string<br>        })), [])<br>        rules = optional(list(object({<br>          rule_id = string<br>          action  = string<br>          enabled = optional(bool, true)<br>          exclusions = optional(list(object({<br>            match_variable = string<br>            operator       = string<br>            selector       = string<br>          })), [])<br>        })), [])<br>      })), [])<br>    })), [])<br>  }))</pre> | `{}` | no |
| <a name="input_origin_groups"></a> [origin\_groups](#input\_origin\_groups) | Origin groups configuration | <pre>map(object({<br>    name = string<br>    session_affinity_enabled = optional(bool, false)<br>    restore_traffic_time_to_healed_or_new_endpoint_in_minutes = optional(number, 10)<br>    health_probe = optional(object({<br>      interval_in_seconds = optional(number, 100)<br>      path                = optional(string, "/")<br>      protocol            = optional(string, "Https")<br>      request_type        = optional(string, "HEAD")<br>    }))<br>    load_balancing = optional(object({<br>      additional_latency_in_milliseconds = optional(number, 50)<br>      sample_size                        = optional(number, 4)<br>      successful_samples_required        = optional(number, 3)<br>    }))<br>  }))</pre> | `{}` | no |
| <a name="input_origins"></a> [origins](#input\_origins) | Origins configuration | <pre>map(object({<br>    name                           = string<br>    origin_group_name              = string<br>    enabled                        = optional(bool, true)<br>    host_name                      = string<br>    http_port                      = optional(number, 80)<br>    https_port                     = optional(number, 443)<br>    origin_host_header             = optional(string)<br>    priority                       = optional(number, 1)<br>    weight                         = optional(number, 1000)<br>    certificate_name_check_enabled = optional(bool, true)<br>  }))</pre> | `{}` | no |
| <a name="input_endpoints"></a> [endpoints](#input\_endpoints) | Endpoints configuration | <pre>map(object({<br>    name    = string<br>    enabled = optional(bool, true)<br>  }))</pre> | `{}` | no |
| <a name="input_custom_domains"></a> [custom\_domains](#input\_custom\_domains) | Custom domains configuration | <pre>map(object({<br>    name       = string<br>    host_name  = string<br>    tls = optional(object({<br>      certificate_type    = optional(string, "ManagedCertificate")<br>      minimum_tls_version = optional(string, "TLS12")<br>      cdn_frontdoor_secret_id = optional(string)<br>    }))<br>  }))</pre> | `{}` | no |
| <a name="input_secrets"></a> [secrets](#input\_secrets) | Secrets configuration for custom domain certificates | <pre>map(object({<br>    name                      = string<br>    key_vault_certificate_id  = string<br>  }))</pre> | `{}` | no |
| <a name="input_routes"></a> [routes](#input\_routes) | Routes configuration | <pre>map(object({<br>    name                          = string<br>    endpoint_name                 = string<br>    origin_group_name             = string<br>    origin_names                  = list(string)<br>    enabled                       = optional(bool, true)<br>    forwarding_protocol           = optional(string, "HttpsOnly")<br>    https_redirect_enabled        = optional(bool, true)<br>    patterns_to_match             = optional(list(string), ["/*"])<br>    supported_protocols           = optional(list(string), ["Https"])<br>    cache = optional(object({<br>      query_string_caching_behavior = optional(string, "IgnoreQueryString")<br>      query_strings                 = optional(list(string), [])<br>      compression_enabled           = optional(bool, true)<br>      content_types_to_compress     = optional(list(string), ["text/plain", "text/html", "text/css", "text/xml", "application/json", "application/javascript", "application/xml", "application/xml+rss", "image/svg+xml"])<br>    }))<br>    custom_domain_names = optional(list(string), [])<br>    waf_policy_name     = optional(string)<br>    rule_set_names      = optional(list(string), [])<br>  }))</pre> | `{}` | no |
| <a name="input_rule_sets"></a> [rule\_sets](#input\_rule\_sets) | Rule sets configuration | <pre>map(object({<br>    name = string<br>  }))</pre> | `{}` | no |
| <a name="input_rules"></a> [rules](#input\_rules) | Rules configuration | <pre>map(object({<br>    name              = string<br>    rule_set_name     = string<br>    order             = number<br>    behavior_on_match = optional(string, "Continue")<br>    actions = optional(object({<br>      url_rewrite = optional(object({<br>        source_pattern          = string<br>        destination             = string<br>        preserve_unmatched_path = optional(bool, false)<br>      }))<br>      url_redirect = optional(object({<br>        redirect_type        = string<br>        redirect_protocol    = optional(string)<br>        destination_hostname = optional(string)<br>        destination_path     = optional(string)<br>        query_string         = optional(string)<br>        destination_fragment = optional(string)<br>      }))<br>      route_configuration_override = optional(object({<br>        origin_group_name              = string<br>        forwarding_protocol           = optional(string)<br>        query_string_caching_behavior = optional(string)<br>        query_string_parameters       = optional(list(string))<br>        compression_enabled           = optional(bool)<br>        cache_behavior                = optional(string)<br>        cache_duration                = optional(string)<br>      }))<br>      request_header_actions = optional(list(object({<br>        header_action = string<br>        header_name   = string<br>        value         = optional(string)<br>      })), [])<br>      response_header_actions = optional(list(object({<br>        header_action = string<br>        header_name   = string<br>        value         = optional(string)<br>      })), [])<br>    }))<br>    conditions = optional(object({<br>      remote_address = optional(object({<br>        operator         = optional(string, "Any")<br>        negate_condition = optional(bool, false)<br>        match_values     = optional(list(string), [])<br>      }))<br>      request_method = optional(object({<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>      }))<br>      query_string = optional(list(object({<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>        transforms       = optional(list(string), [])<br>      })), [])<br>      post_args = optional(list(object({<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>        transforms       = optional(list(string), [])<br>        selector         = string<br>      })), [])<br>      request_uri = optional(list(object({<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>        transforms       = optional(list(string), [])<br>      })), [])<br>      request_header = optional(list(object({<br>        header_name      = string<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>        transforms       = optional(list(string), [])<br>      })), [])<br>      request_body = optional(list(object({<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>        transforms       = optional(list(string), [])<br>      })), [])<br>      request_scheme = optional(object({<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>      }))<br>      url_path = optional(list(object({<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>        transforms       = optional(list(string), [])<br>      })), [])<br>      url_file_extension = optional(list(object({<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>        transforms       = optional(list(string), [])<br>      })), [])<br>      url_filename = optional(list(object({<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>        transforms       = optional(list(string), [])<br>      })), [])<br>      http_version = optional(object({<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>      }))<br>      cookies = optional(list(object({<br>        cookie_name      = string<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>        transforms       = optional(list(string), [])<br>      })), [])<br>      is_device = optional(object({<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>      }))<br>      socket_address = optional(object({<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>      }))<br>      client_port = optional(object({<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>      }))<br>      server_port = optional(object({<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>      }))<br>      host_name = optional(list(object({<br>        operator         = string<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>        transforms       = optional(list(string), [])<br>      })), [])<br>      ssl_protocol = optional(object({<br>        match_values     = list(string)<br>        negate_condition = optional(bool, false)<br>      }))<br>    }))<br>  }))</pre> | `{}` | no |
| <a name="input_enable_policy_assignments"></a> [enable\_policy\_assignments](#input\_enable\_policy\_assignments) | Enable Azure Policy assignments | `bool` | `false` | no |
| <a name="input_policy_assignments"></a> [policy\_assignments](#input\_policy\_assignments) | Azure Policy assignments | <pre>map(object({<br>    name                 = string<br>    policy_definition_id = string<br>    display_name         = string<br>    description          = optional(string)<br>    parameters           = optional(string)<br>  }))</pre> | `{}` | no |
| <a name="input_diagnostic_settings"></a> [diagnostic\_settings](#input\_diagnostic\_settings) | Diagnostic settings configuration | <pre>object({<br>    name                           = optional(string)<br>    log_analytics_workspace_id     = optional(string)<br>    storage_account_id             = optional(string)<br>    eventhub_name                  = optional(string)<br>    eventhub_authorization_rule_id = optional(string)<br>    logs = optional(list(object({<br>      category        = string<br>      enabled         = bool<br>      retention_policy = optional(object({<br>        enabled = bool<br>        days    = number<br>      }))<br>    })), [])<br>    metrics = optional(list(object({<br>      category        = string<br>      enabled         = bool<br>      retention_policy = optional(object({<br>        enabled = bool<br>        days    = number<br>      }))<br>    })), [])<br>  })</pre> | `null` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags to apply to resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_frontdoor_profile_id"></a> [frontdoor\_profile\_id](#output\_frontdoor\_profile\_id) | The ID of the Front Door profile |
| <a name="output_frontdoor_profile_name"></a> [frontdoor\_profile\_name](#output\_frontdoor\_profile\_name) | The name of the Front Door profile |
| <a name="output_frontdoor_profile_resource_guid"></a> [frontdoor\_profile\_resource\_guid](#output\_frontdoor\_profile\_resource\_guid) | The resource GUID of the Front Door profile |
| <a name="output_frontdoor_profile_sku_name"></a> [frontdoor\_profile\_sku\_name](#output\_frontdoor\_profile\_sku\_name) | The SKU name of the Front Door profile |
| <a name="output_resource_group_name"></a> [resource\_group\_name](#output\_resource\_group\_name) | Resource group name |
| <a name="output_location"></a> [location](#output\_location) | Azure region |
| <a name="output_environment"></a> [environment](#output\_environment) | Environment name |
| <a name="output_waf_policy_ids"></a> [waf\_policy\_ids](#output\_waf\_policy\_ids) | IDs of the WAF policies |
| <a name="output_waf_policy_names"></a> [waf\_policy\_names](#output\_waf\_policy\_names) | Names of the WAF policies |
| <a name="output_origin_group_ids"></a> [origin\_group\_ids](#output\_origin\_group\_ids) | IDs of the origin groups |
| <a name="output_origin_group_names"></a> [origin\_group\_names](#output\_origin\_group\_names) | Names of the origin groups |
| <a name="output_origin_ids"></a> [origin\_ids](#output\_origin\_ids) | IDs of the origins |
| <a name="output_origin_names"></a> [origin\_names](#output\_origin\_names) | Names of the origins |
| <a name="output_endpoint_ids"></a> [endpoint\_ids](#output\_endpoint\_ids) | IDs of the endpoints |
| <a name="output_endpoint_names"></a> [endpoint\_names](#output\_endpoint\_names) | Names of the endpoints |
| <a name="output_endpoint_host_names"></a> [endpoint\_host\_names](#output\_endpoint\_host\_names) | Host names of the endpoints |
| <a name="output_custom_domain_ids"></a> [custom\_domain\_ids](#output\_custom\_domain\_ids) | IDs of the custom domains |
| <a name="output_custom_domain_names"></a> [custom\_domain\_names](#output\_custom\_domain\_names) | Names of the custom domains |
| <a name="output_custom_domain_host_names"></a> [custom\_domain\_host\_names](#output\_custom\_domain\_host\_names) | Host names of the custom domains |
| <a name="output_secret_ids"></a> [secret\_ids](#output\_secret\_ids) | IDs of the secrets |
| <a name="output_secret_names"></a> [secret\_names](#output\_secret\_names) | Names of the secrets |
| <a name="output_route_ids"></a> [route\_ids](#output\_route\_ids) | IDs of the routes |
| <a name="output_route_names"></a> [route\_names](#output\_route\_names) | Names of the routes |
| <a name="output_rule_set_ids"></a> [rule\_set\_ids](#output\_rule\_set\_ids) | IDs of the rule sets |
| <a name="output_rule_set_names"></a> [rule\_set\_names](#output\_rule\_set\_names) | Names of the rule sets |
| <a name="output_rule_ids"></a> [rule\_ids](#output\_rule\_ids) | IDs of the rules |
| <a name="output_rule_names"></a> [rule\_names](#output\_rule\_names) | Names of the rules |
| <a name="output_policy_assignment_ids"></a> [policy\_assignment\_ids](#output\_policy\_assignment\_ids) | IDs of the policy assignments |
| <a name="output_policy_assignment_names"></a> [policy\_assignment\_names](#output\_policy\_assignment\_names) | Names of the policy assignments |
| <a name="output_diagnostic_setting_id"></a> [diagnostic\_setting\_id](#output\_diagnostic\_setting\_id) | ID of the diagnostic setting |
| <a name="output_diagnostic_setting_name"></a> [diagnostic\_setting\_name](#output\_diagnostic\_setting\_name) | Name of the diagnostic setting |

## Testing

Run the tests using Terratest:

```bash
cd modules/network/front-door/test
go test -v
```

## Security Features

- **Web Application Firewall (WAF)**: Protection against OWASP Top 10 vulnerabilities
- **Rate Limiting**: Custom rules to prevent DDoS attacks
- **Geo-blocking**: Restrict access based on geographic location
- **Custom Rules**: Flexible security policies based on request attributes
- **SSL/TLS**: HTTPS-only with managed certificates
- **Security Headers**: Automatic injection of security headers

## Performance Features

- **Global CDN**: 100+ edge locations for low-latency delivery
- **Intelligent Routing**: Route optimization based on performance and cost
- **Caching**: Dynamic and static content caching
- **Compression**: Automatic content compression
- **Load Balancing**: Health-based traffic distribution

## Monitoring

The module configures:
- Front Door access logs
- WAF logs for security events
- Performance and health metrics
- Origin response times
- Request/response analytics

## Compliance

Azure Policy assignments ensure:
- WAF policies are enabled
- HTTPS-only traffic
- Diagnostic logging is configured
- Security best practices are enforced

## Cost Optimization

- Pay-as-you-go pricing
- No minimum commitments
- Intelligent caching reduces origin costs
- Automatic scaling based on traffic

## Contributing

1. Follow the established patterns for enterprise modules
2. Include comprehensive tests for all features
3. Update documentation for any new features
4. Ensure backward compatibility

## License

This module is licensed under the MIT License.
## Requirements

No requirements.

## Providers

No providers.

## Modules

No modules.

## Resources

No resources.

## Inputs

No inputs.

## Outputs

No outputs.

<!-- BEGIN_TF_DOCS -->
<!-- END_TF_DOCS -->
