output "url" {
  value      = "https://${var.domain_name}"
  depends_on = [aws_cloudfront_distribution.amc]
}

output "cloudfront_domain_name" {
  value = aws_cloudfront_distribution.amc.domain_name
}

output "params_arn" {
  value = aws_secretsmanager_secret.params.arn
}
