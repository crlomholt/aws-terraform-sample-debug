terraform {
  backend "s3" {
    key = "sample_one" #path to the state file within the bucket - recommended "serviceName/terraform.tfstate"
  }
}