resource "null_resource" "trigger" {
  triggers = {
    version = "1.0"
  }
}
