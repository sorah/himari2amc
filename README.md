# Himari2amc - Access to AWS from Himari

This is a Terraform module to deploy simple Sinatra and TypeScript app to access AWS.

## Prerequisite

- [Himari](https://github.com/sorah/himari) as an upstream IdP
- TypeScript compiler (`tsc`)
- Ruby 2.7 runtime and bundler (RBENV_VERSION=2.7)

## Deploy

```terraform
module "amc" {
  source = "github.com/sorah/himari2amc"

  name                       = "amc"
  iam_role_name              = "LambdaAmc"
  idp_issuer                 = "https://idp.example.net"
  domain_name                = "amc.example.net"
  session_duration           = 3600 * 12
  cloudfront_log_bucket      = "kmc-aws-log.s3.amazonaws.com"
  cloudfront_log_prefix      = "cf/amc.example.net/"
  cloudfront_certificate_arn = data.aws_acm_certificate.XXX.arn

  header_html = ""
  footer_html = "<p><small>Not seeing a correct role? Try <a href='/auth/himari?prompt=login'>Reauthenticate</a>. | <a href='https://github.com/sorah/himari2amc'>Source</a></small></p>"
}

resource "aws_route53_record" "amc_example_net" {
  name    = "amc.example.net."
  zone_id = data.aws_route53_zone.example_net.id
  type    = "CNAME"
  ttl     = 60
  records = [module.amc.cloudfront_domain_name]
}

resource "aws_iam_openid_connect_provider" "amc" {
  url = module.amc.url

  client_id_list = [
    "sts.amazonaws.com",
  ]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
}
```

## Secrets

Update secret `${var.name}/params` on Secrets Manager with Key/Value pair:

- `SECRET_KEY_BASE`: session key secret (`openssl rand -hex 96`)
- `AMC_CLIENT_ID`: Client ID for Himari
- `AMC_CLIENT_SECRET`: Client Secret for Himari

## Claims

- `roles` claims should have role ARNs.


## License

MIT License, (c) 2023 Sorah Fukumori

Originally published at [ruby-no-kai/rubykaigi-nw](https://github.com/ruby-no-kai/rubykaigi-nw/tree/master/tf/amc) under the same license.
