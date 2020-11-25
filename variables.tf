variable "aws_access_key" {type = map }

variable "aws_secret_key" {type = map }

variable "azure_subscription_id" {type = map }

variable "azure_application_id" {type = map }

variable "azure_application_key" {type = map }

variable "azure_directory_id"  {type = map}

variable "gcp_project_id" {type = map }



variable azure_account_name {type = map}

variable gcp_account_name {type = map}

variable account_name {type = map}

variable "s3key" {type = map}

variable "avtx_key_name" {default = "avtx_key"}

variable "pod" {type = map}

#variable "tenant_id"  {type = map}

variable "avtx_controller_bucket" {type = map}

variable "aws_region-2" {
  default = "us-east-2"
}

variable "aws_region-1" {
  default = "us-east-1"
}

# variable "az_acc_name" {
#   default = ""
# }
#
# variable "gcp_acc_name" {
#   default = ""
# }

variable "aws_ami_lab3" {
  description = "amazon linux"
  default     = "ami-0603cbe34fd08cb81"
}

variable "aws_copilot_lab3" {
  description = "copiloit"
  default     = "ami-0a05466b9530dfb19"
}

variable "aws_ami_lab5" {
  description = "amazon linux"
  default     = "ami-0c94855ba95c71c99"
}

variable "aws_ami_csr_lab5" {
  description = "cisco csr image"
  default     = "ami-0eb9c4f673471b033"
}

###########################
# azure account
###########################
variable "az_region" {
  default = "West US"
}


###########################
# gcp account
###########################
variable "gcp_region" {
  default = "us-central1"
}
