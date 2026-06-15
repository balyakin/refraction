resource "null_resource" "x" { provisioner "local-exec" { command = "echo hook" } }
