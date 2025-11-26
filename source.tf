data "archive_file" "amc" {
  type        = "zip"
  source_dir  = "${path.module}/src"
  output_path = "${path.module}/amc.zip"

  excludes = [
    "vendor/**",
    ".bundle/**",
  ]

  depends_on = [
    null_resource.amc-tsc,
    null_resource.amc-revision,
  ]
}

locals {
  tsdgst = sha256(join("", [for f in fileset("${path.module}/src", "public/**/*.ts") : filesha256("${path.module}/src/${f}")]))
  rbdgst = sha256(join("", [for f in fileset("${path.module}/src", "*.rb") : filesha256("${path.module}/src/${f}")]))

  lockdgst   = filesha256("${path.module}/src/Gemfile.lock")
  dockerdgst = filesha256("${path.module}/Dockerfile")
}


resource "null_resource" "amc-tsc" {
  triggers = {
    path   = path.module
    tsdgst = local.tsdgst
  }
  provisioner "local-exec" {
    command = "cd ${path.module}/src && tsc -b"
  }
}

resource "null_resource" "amc-revision" {
  triggers = {
    tsdgst   = local.tsdgst,
    rbdgst   = local.rbdgst,
    lockdgst = local.lockdgst
  }
  provisioner "local-exec" {
    command = "cd ${path.module}/src && echo 'unknown.${sha256("${local.tsdgst}${local.rbdgst}${local.lockdgst}")}' > REVISION"
  }
}

resource "null_resource" "amc-layer-zip" {
  triggers = {
    path       = path.module
    lockdgst   = local.lockdgst
    dockerdgst = local.dockerdgst
  }
  provisioner "local-exec" {
    command     = "./extract_layer.sh"
    working_dir = path.module
  }
}

data "local_file" "amc-layer-zip" {
  filename   = "${path.module}/layer.zip"
  depends_on = [null_resource.amc-layer-zip]
}

resource "aws_lambda_layer_version" "bundle" {
  layer_name               = "${var.name}-bundle-ruby34"
  compatible_runtimes      = ["ruby3.4"]
  compatible_architectures = ["x86_64"]

  skip_destroy = true

  filename         = "${path.module}/layer.zip"
  source_code_hash = data.local_file.amc-layer-zip.content_base64sha256
}

