# Front Door Enterprise Example

This example demonstrates how to deploy an Azure Front Door with enterprise-grade features including WAF, custom domains, routing rules, and comprehensive security.

## Architecture

The example creates:
- Front Door profile with Premium SKU
- WAF policy with custom and managed rules
- Custom domains with managed certificates
- Multiple origin groups and origins
- Advanced routing rules with caching and security headers
- Rule sets for request/response manipulation
- Diagnostic settings for monitoring
- Azure Policy assignments for compliance

## Usage

```hcl
module "front_door" {
  source = "../../"

  # Resource Group
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
        },
        {
          type    = "Microsoft_BotManagerRuleSet"
          version = "1.0"
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
          rate_limit_threshold          = 100
          match_conditions = [
            {
              match_variable = "RemoteAddr"
              operator       = "IPMatch"
              match_values   = ["192.168.1.0/24"]
              negate_condition = false
            }
          ]
        }
      ]
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
        request_type        = "HEAD"
      }
      load_balancing = {
        additional_latency_in_milliseconds = 100
        sample_size                        = 4
        successful_samples_required        = 2
      }
    }
    api-origins = {
      name = "api-origins"
      health_probe = {
        interval_in_seconds = 60
        path                = "/api/health"
        protocol            = "Https"
        request_type        = "GET"
      }
      load_balancing = {
        additional_latency_in_milliseconds = 200
        sample_size                        = 3
        successful_samples_required        = 2
      }
    }
  }

  # Origins
  origins = {
    web-primary = {
      name              = "web-primary"
      origin_group_name = "web-origins"
      enabled           = true
      host_name         = "web-primary.azurewebsites.net"
      priority          = 1
      weight            = 100
    }
    web-secondary = {
      name              = "web-secondary"
      origin_group_name = "web-origins"
      enabled           = true
      host_name         = "web-secondary.azurewebsites.net"
      priority          = 2
      weight            = 50
    }
    api-primary = {
      name              = "api-primary"
      origin_group_name = "api-origins"
      enabled           = true
      host_name         = "api-primary.azurewebsites.net"
      priority          = 1
      weight            = 100
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
    api-domain = {
      name      = "api-domain"
      host_name = "api.example.com"
      tls = {
        certificate_type    = "ManagedCertificate"
        minimum_tls_version = "TLS12"
      }
    }
  }

  # Rule Sets
  rule_sets = {
    security-headers = {
      name = "security-headers"
    }
  }

  # Rules
  rules = {
    add-security-headers = {
      name          = "add-security-headers"
      rule_set_name = "security-headers"
      order         = 1
      actions = {
        request_header_actions = [
          {
            header_action = "Overwrite"
            header_name   = "X-Forwarded-Proto"
            value         = "https"
          }
        ]
        response_header_actions = [
          {
            header_action = "Append"
            header_name   = "X-Frame-Options"
            value         = "DENY"
          },
          {
            header_action = "Append"
            header_name   = "X-Content-Type-Options"
            header_value  = "nosniff"
          },
          {
            header_action = "Append"
            header_name   = "Referrer-Policy"
            value         = "strict-origin-when-cross-origin"
          },
          {
            header_action = "Append"
            header_name   = "Content-Security-Policy"
            value         = "default-src 'self'"
          }
        ]
      }
      conditions = {
        request_uri = [
          {
            operator     = "Any"
            match_values = ["*"]
          }
        ]
      }
    }
  }

  # Routes
  routes = {
    web-route = {
      name                = "web-route"
      endpoint_name       = "main"
      origin_group_name   = "web-origins"
      origin_names        = ["web-primary", "web-secondary"]
      enabled             = true
      forwarding_protocol = "HttpsOnly"
      https_redirect_enabled = true
      patterns_to_match   = ["/*"]
      supported_protocols = ["Https"]
      cache = {
        query_string_caching_behavior = "IgnoreQueryString"
        compression_enabled           = true
        content_types_to_compress     = ["text/plain", "text/html", "application/json"]
      }
      custom_domain_names = ["www-domain"]
      waf_policy_name     = "main-waf"
      rule_set_names      = ["security-headers"]
    }
    api-route = {
      name                = "api-route"
      endpoint_name       = "main"
      origin_group_name   = "api-origins"
      origin_names        = ["api-primary"]
      enabled             = true
      forwarding_protocol = "HttpsOnly"
      https_redirect_enabled = true
      patterns_to_match   = ["/api/*"]
      supported_protocols = ["Https"]
      cache = {
        query_string_caching_behavior = "UseQueryString"
        compression_enabled           = true
      }
      custom_domain_names = ["api-domain"]
      waf_policy_name     = "main-waf"
      rule_set_names      = ["security-headers"]
    }
  }

  # Diagnostic Settings
  diagnostic_settings = {
    logs = [
      {
        category = "FrontDoorAccessLog"
        retention_policy = {
          enabled = true
          days    = 30
        }
      },
      {
        category = "FrontDoorWebApplicationFirewallLog"
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
        retention_policy = {
          enabled = true
          days    = 30
        }
      }
    ]
  }

  # Azure Policy Assignments
  enable_policy_assignments = true
  policy_assignments = {
    waf_enabled = {
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/055aa869-bc98-4af8-bafc-23f1ab6fft5ad"
      display_name         = "Azure Front Door should have Web Application Firewall (WAF) enabled"
    }
    https_only = {
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/8a02071b-4b94-4e15-9b35-4c0ab2c5c6b2"
      display_name         = "Azure Front Door should redirect all HTTP traffic to HTTPS"
    }
  }

  # Tags
  tags = {
    Environment         = "prod"
    Project            = "enterprise-app"
    Owner              = "platform-team"
    CostCenter         = "IT-001"
    DataClassification = "internal"
    Backup             = "daily"
    Monitoring         = "enabled"
  }
}

# Outputs
output "frontdoor_profile_id" {
  description = "The ID of the Front Door profile"
  value       = module.front_door.frontdoor_profile_id
}

output "frontdoor_endpoint_host_names" {
  description = "The host names of the Front Door endpoints"
  value       = module.front_door.endpoint_host_names
}

output "custom_domain_host_names" {
  description = "The host names of the custom domains"
  value       = module.front_door.custom_domain_host_names
}

output "waf_policy_ids" {
  description = "The IDs of the WAF policies"
  value       = module.front_door.waf_policy_ids
}
```

## Requirements

- Terraform >= 1.5.0
- AzureRM provider >= 3.80.0
- Go 1.21 (for testing)

## Testing

Run the tests:

```bash
cd test
go test -v
```

## Security Features

- **Web Application Firewall (WAF)**: Protection against OWASP Top 10 and bot attacks
- **Rate Limiting**: Custom rules to prevent DDoS attacks
- **SSL/TLS Encryption**: HTTPS-only with managed certificates
- **Security Headers**: Automatic injection of security headers
- **Custom Domains**: Secure custom domain support
- **Access Control**: Geographic and IP-based restrictions

## Performance Features

- **Global Distribution**: 100+ edge locations worldwide
- **Load Balancing**: Intelligent routing and failover
- **Caching**: Dynamic and static content caching
- **Compression**: Automatic content compression
- **Health Monitoring**: Real-time origin health checks

## Monitoring

The Front Door is configured with:
- Access logs for all requests
- WAF logs for security events
- Performance metrics
- Health probe metrics
- 30-day log retention

## Compliance

Azure Policy assignments ensure:
- WAF is always enabled
- HTTPS-only traffic
- Diagnostic logs are enabled
- Security best practices are enforced

## Cost Optimization

- Pay only for what you use
- No upfront costs
- Automatic scaling
- Intelligent caching reduces origin load