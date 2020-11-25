data "terraform_remote_state" "controller" {
  backend = "s3"
  config = {
      access_key = var.aws_access_key[terraform.workspace]
      secret_key = var.aws_secret_key[terraform.workspace]
      bucket = var.avtx_controller_bucket[terraform.workspace]
      key    = var.s3key[terraform.workspace]
      region = "us-east-1"
    }
}

data "aws_caller_identity" "current" {
  provider = aws.east

}

provider "aviatrix" {
  username      = "admin"
  password      = "Password123!"
  controller_ip = data.terraform_remote_state.controller.outputs.controller_public_ip
  version       = "2.17.0"
}


provider "google" {
  credentials =  file("../../../json/gcp_projects/aviatrix-${var.pod[terraform.workspace]}.json")
  project     = var.gcp_project_id[terraform.workspace]
  region      = "us-central1"
}


provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id[terraform.workspace]
  client_id       = var.azure_application_id[terraform.workspace]
  client_secret   = var.azure_application_key[terraform.workspace]
  tenant_id       = var.azure_directory_id[terraform.workspace]
  version = "2.28"
}

provider "aws" {
  region = var.aws_region-2
  access_key = var.aws_access_key[terraform.workspace]
  secret_key = var.aws_secret_key[terraform.workspace]

}


provider "aws" {
  alias  = "east"
  region = "us-east-1"
  access_key = var.aws_access_key[terraform.workspace]
  secret_key = var.aws_secret_key[terraform.workspace]
}

provider "aws" {
  alias  = "west1"
  region = "us-west-1"
  access_key = var.aws_access_key[terraform.workspace]
  secret_key = var.aws_secret_key[terraform.workspace]
}



####### Copilot


resource "aws_instance" "aws-copilot" {
  provider                    = aws.west1
  ami                         = "ami-0133e2ddad093885f" # US-West-2
  instance_type               = "t3.2xlarge"
  subnet_id                   = aws_subnet.aws_public_smart_console.id
  associate_public_ip_address = true
  key_name                    = aws_key_pair.aws_west1_key.key_name
  vpc_security_group_ids      = [aws_security_group.aws-copilot.id]
  user_data = file("copilot.sh")
  tags = {
    Name = "aws-copilot"
  }
}


################################### Lab-3 requirment ###################################
// vpc and vnet creation
resource "aviatrix_vpc" "aws-us-east2-transit" {
  cloud_type           = 1
  account_name         = var.account_name[terraform.workspace]
  region               = var.aws_region-2
  name                 = "aws-us-east2-transit"
  cidr                 = "10.0.10.0/23"
  aviatrix_transit_vpc = true
  aviatrix_firenet_vpc = false
}

resource "aviatrix_vpc" "aws-us-east2-spoke1" {
  cloud_type           = 1
  account_name         = var.account_name[terraform.workspace]
  aviatrix_transit_vpc = false
  aviatrix_firenet_vpc = false
  name = "aws-us-east2-spoke1"
  region = "us-east-2"
  cidr = "10.0.1.0/24"
  subnet_size = "27"
  num_of_subnet_pairs = "3"
}

resource "aviatrix_vpc" "azure-us-west-transit" {
  cloud_type           = 8
  account_name         = var.azure_account_name[terraform.workspace]
  region               = var.az_region
  name                 = "azure-us-west-transit"
  cidr                 = "192.168.10.0/23"
  aviatrix_firenet_vpc = true
}


################################
resource "google_compute_network" "gcp-us-central1-transit" {
  name         = "gcp-us-central1-transit"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "gcp-us-central1-transit-sub1" {
  name          = "gcp-us-central1-transit-sub1"
  region = var.gcp_region
  ip_cidr_range   = "172.16.10.0/24"
  network       = google_compute_network.gcp-us-central1-transit.self_link
}

resource "google_compute_subnetwork" "gcp-us-central1-transit-sub2" {
  name          = "gcp-us-central1-transit-sub2"
  region = var.gcp_region
  ip_cidr_range   = "172.16.11.0/24"
  network       = google_compute_network.gcp-us-central1-transit.self_link
}
resource "google_compute_subnetwork" "gcp-us-central1-transit-sub3" {
  name          = "gcp-us-central1-transit-sub3"
  region = var.gcp_region
  ip_cidr_range   = "172.16.12.0/24"
  network       = google_compute_network.gcp-us-central1-transit.self_link
}
resource "google_compute_subnetwork" "gcp-us-central1-transit-sub4" {
  name          = "gcp-us-central1-transit-sub4"
  region = var.gcp_region
  ip_cidr_range   = "172.16.13.0/24"
  network       = google_compute_network.gcp-us-central1-transit.self_link
}


# resource "google_compute_firewall" "gcp-transit-firewall" {
#   name    = "gcp-comp-firewall"
#   network = google_compute_network.gcp-us-central1-transit.id
#   allow {
#     protocol = "icmp"
#   }
#   allow {
#     protocol = "tcp"
#     ports    = [80, 443, 22]
#   }
# }




##################################

// transit gateways creation

resource "aviatrix_transit_gateway" "azure-us-west-transit-agw" {
  cloud_type             = 8
  account_name           = var.azure_account_name[terraform.workspace]
  gw_name                = "azure-us-west-transit-agw"
  vpc_id                 = aviatrix_vpc.azure-us-west-transit.vpc_id
  vpc_reg                = var.az_region
  gw_size                = "Standard_B1ms"
  subnet                 = aviatrix_vpc.azure-us-west-transit.subnets[2].cidr
  connected_transit      = true // transit firenet needs to enable connected transit
  ha_subnet              = aviatrix_vpc.azure-us-west-transit.subnets[3].cidr
  ha_gw_size             = "Standard_B1ms"
  enable_transit_firenet = true //transit firenet support has to set during the provision
  enable_active_mesh     = true //AM is supoprted form UI by default, but it has to specifiy on terrafrom to enable
}

resource "aviatrix_transit_gateway" "gcp-us-central1-transit-agw" {
  cloud_type         = 4
  account_name       = var.gcp_account_name[terraform.workspace]
  gw_name            = "gcp-us-central1-transit-agw"
  vpc_id             = google_compute_network.gcp-us-central1-transit.name
  vpc_reg            = "${var.gcp_region}-a"
  gw_size            = "n1-standard-1"
  subnet             = google_compute_subnetwork.gcp-us-central1-transit-sub1.ip_cidr_range
  ha_zone            = "${var.gcp_region}-b"
  ha_subnet          = google_compute_subnetwork.gcp-us-central1-transit-sub2.ip_cidr_range
  ha_gw_size         = "n1-standard-1"
  enable_active_mesh = true
  single_az_ha       = false
}



// aws test instance
/*
1. create security group and share to test/copilot instance
2. create key-pair for ec2 instance
3. allocate eip aws test instance
4. create test ec2 instance
5. output public ip
*/
resource "aws_security_group" "aws-us-east2-spoke1-sg" {
  name   = "aws-us-east2-spoke1-sg"
  vpc_id = aviatrix_vpc.aws-us-east2-spoke1.vpc_id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 31283
    to_port     = 31283
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "allow_ssh"
  }
}

resource "aws_key_pair" "aws_east2_key" {
  key_name = "ace_lab_east2"
  public_key = tls_private_key.avtx_key.public_key_openssh
}

# ssh to aws instance uses web console
resource "aws_instance" "aws-us-east2-spoke1-test1" {
  ami                         = var.aws_ami_lab3
  instance_type               = "t2.micro"
  subnet_id                   = aviatrix_vpc.aws-us-east2-spoke1.subnets[3].subnet_id
  private_ip                  = "10.0.1.100"
  associate_public_ip_address = true
  key_name                    = aws_key_pair.aws_east2_key.key_name
  vpc_security_group_ids      = [aws_security_group.aws-us-east2-spoke1-sg.id]

  tags = {
    Name = "aws-us-east2-spoke1-test1"
  }
}

// azure test instance
// using azure native provider to create below resource
/*
1. create resource group
2. create azure vnet
3. grab data of public subnet under vnet
4. create public ip
5. create vm nic and associate to subnet and public ip
6. create azure NSG and associate to subnet on upside
7. create azure virtual machine
8. output public ip
*/
resource "azurerm_resource_group" "az-test-rg" {
  name     = "az-spoke1-rg"
  location = var.az_region
}

resource "azurerm_virtual_network" "azure-us-west-spoke1" {
  name                = "azure-us-west-spoke1"
  location            = var.az_region
  resource_group_name = azurerm_resource_group.az-test-rg.name
  address_space       = ["192.168.1.0/24"]
  subnet {
    name           = "azure-us-west-spoke1-Public-gateway-subnet-1"
    address_prefix = "192.168.1.0/27"
    security_group = azurerm_network_security_group.az_sg_west.id
  }
  subnet {
    name           = "azure-us-west-spoke1-Public-subnet-1"
    address_prefix = "192.168.1.32/27"
    security_group = azurerm_network_security_group.az_sg_west.id
  }
  subnet {
    name           = "azure-us-west-spoke1-Public-subnet-2"
    address_prefix = "192.168.1.96/27"
    security_group = azurerm_network_security_group.az_sg_west.id
  }
  subnet {
    name           = "azure-us-west-spoke1-Private-subnet-1"
    address_prefix = "192.168.1.64/27"
    security_group = azurerm_network_security_group.az_sg_west.id
  }
  subnet {
    name           = "azure-us-west-spoke1-Private-subnet-2"
    address_prefix = "192.168.1.128/27"
    security_group = azurerm_network_security_group.az_sg_west.id
  }
  depends_on = [azurerm_resource_group.az-test-rg]
}

data "azurerm_subnet" "az-subnet-96" {
  name                 = "azure-us-west-spoke1-Public-subnet-2"
  virtual_network_name = "azure-us-west-spoke1"
  resource_group_name  = azurerm_resource_group.az-test-rg.name
  depends_on           = [azurerm_virtual_network.azure-us-west-spoke1]
}

resource "azurerm_public_ip" "az-public-ip" {
  name                = "az-public-ip"
  location            = azurerm_resource_group.az-test-rg.location
  resource_group_name = azurerm_resource_group.az-test-rg.name
  allocation_method   = "Dynamic"
}

resource "azurerm_network_interface" "az-test-nic" {
  name                = "az-test-nic"
  location            = azurerm_resource_group.az-test-rg.location
  resource_group_name = azurerm_resource_group.az-test-rg.name
  ip_configuration {
    name                          = "az-test-nic"
    subnet_id                     = data.azurerm_subnet.az-subnet-96.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "192.168.1.100"
    public_ip_address_id          = azurerm_public_ip.az-public-ip.id
  }
  depends_on = [azurerm_resource_group.az-test-rg, data.azurerm_subnet.az-subnet-96]
}

resource "azurerm_network_security_group" "az_sg_west" {
  name = "az_sg_west"
  location = azurerm_resource_group.az-test-rg.location
  resource_group_name = azurerm_resource_group.az-test-rg.name
  security_rule {
    name = "allow_ssh"
    priority = 100
    direction = "Inbound"
    access = "Allow"
    protocol = "TCP"
    source_port_range = "*"
    destination_port_range     = "22"
    source_address_prefix = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name = "allow_443"
    priority = 110
    direction = "Inbound"
    access = "Allow"
    protocol = "TCP"
    source_port_range = "*"
    destination_port_range     = "443"
    source_address_prefix = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name = "allow_icmp"
    priority = 101
    direction = "Inbound"
    access = "Allow"
    protocol = "ICMP"
    source_port_range = "*"
    destination_port_range     = "*"
    source_address_prefix = "*"
    destination_address_prefix = "*"
  }
}

#ssh to azure instance by username and password
resource "azurerm_virtual_machine" "azure-us-west-spoke1-test1" {
  name                  = "azure-us-west-spoke1-test1"
  location              = azurerm_resource_group.az-test-rg.location
  resource_group_name   = azurerm_resource_group.az-test-rg.name
  network_interface_ids = [azurerm_network_interface.az-test-nic.id]
  vm_size               = "Standard_B1ls"

  storage_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  storage_os_disk {
    name          = "azure-us-west-spoke1-test1-disk"
    create_option = "FromImage"
    caching       = "ReadWrite"
  }


  os_profile {
    computer_name  = "azure-us-west-spoke1-test1"
    admin_username = "ubuntu"
    admin_password = "Password123!"
  }

  os_profile_linux_config {
    disable_password_authentication = false
  }
}

data "azurerm_public_ip" "az-public-ip" {
  name                = azurerm_public_ip.az-public-ip.name
  resource_group_name = azurerm_resource_group.az-test-rg.name
  depends_on          = [azurerm_virtual_machine.azure-us-west-spoke1-test1]
}

// gcp test instance
// using native gcp provider to create below resource
/*
1. create gcp vpc
2. create subnets under above gcp vpc
3. create gcp firewall rules and attching to vpc
4. allocate static external ip address
5. create gcp instance and attach static external ip
6. output public ip
*/
resource "google_compute_network" "gcp-us-central1-spoke1" {
  name                    = "gcp-us-central1-spoke1"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "gcp-us-central1-spoke1-agw-sub1" {
  name          = "gcp-us-central1-spoke1-agw-sub1"
  ip_cidr_range = "172.16.1.0/24"
  region        = var.gcp_region
  network       = google_compute_network.gcp-us-central1-spoke1.id
}

resource "google_compute_subnetwork" "gcp-us-central1-spoke1-vm-sub2" {
  name          = "gcp-us-central1-spoke1-vm-sub2"
  ip_cidr_range = "172.16.2.0/24"
  region        = var.gcp_region
  network       = google_compute_network.gcp-us-central1-spoke1.id
}

resource "google_compute_firewall" "gcp-comp-firewall" {
  name    = "gcp-comp-firewall"
  network = google_compute_network.gcp-us-central1-spoke1.id
  allow {
    protocol = "icmp"
  }
  allow {
    protocol = "tcp"
    ports    = [80, 443, 22]
  }
}

resource "google_compute_address" "gcp-us-central1-spoke1-test1-eip" {
  name = "gcp-us-central1-spoke1-test1-eip"
  address_type = "EXTERNAL"
}

resource "google_compute_instance" "gcp-us-central1-spoke1-test1" {
  name         = "gcp-us-central1-spoke1-test1"
  machine_type = "n1-standard-1"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params {
      image = "ubuntu-1804-bionic-v20200923"
    }
  }
  network_interface {
    network    = google_compute_network.gcp-us-central1-spoke1.id
    subnetwork = google_compute_subnetwork.gcp-us-central1-spoke1-agw-sub1.id
    network_ip = "172.16.1.100"
    access_config {
      nat_ip = google_compute_address.gcp-us-central1-spoke1-test1-eip.address
    }
  }
  metadata = {
    ssh-keys = tls_private_key.avtx_key.public_key_openssh
  }
  metadata_startup_script = file("./vm.sh")
}

// copilot instance
/*
1. create copilot instance which refers security group and key-pair above
2. allocate eip and associate to instance
3. license of copilot will refer copilot.sh which also reflect controller info
4. output public ip
/*/
#
#
# ################################### Lab-5 requirment ###################################
# /* due to given cidr of transit vpc is /23, if using aviatrix provider to create vpc,
# it wont have enough subnet numbers to allocate for insane mode requirement. here is using
# aws native moudle to customize insance mode requirement
# */
module "aws-us-east1-transit" {
  providers       = { aws = aws.east }
  source          = "terraform-aws-modules/vpc/aws"
  name            = "aws-us-east1-transit"
  cidr            = "10.0.20.0/23"
  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["10.0.21.0/28", "10.0.21.16/28"]
  public_subnets  = ["10.0.20.0/28", "10.0.20.16/28"]

  tags = {
    Terrafrom   = "true"
    Environment = "ACE"
  }
}

resource "aviatrix_transit_gateway" "aws-us-east1-transit-agw" {
  cloud_type         = 1
  account_name       = var.account_name[terraform.workspace]
  gw_name            = "aws-us-east1-transit-agw"
  vpc_id             = module.aws-us-east1-transit.vpc_id
  vpc_reg            = var.aws_region-1
  gw_size            = "c5n.large"
  subnet             = cidrsubnet(module.aws-us-east1-transit.vpc_cidr_block,3,1)
  ha_subnet          = cidrsubnet(module.aws-us-east1-transit.vpc_cidr_block,3,2)
  ha_gw_size         = "c5n.large"
  insane_mode        = true
  insane_mode_az = "us-east-1a"
  ha_insane_mode_az  = "us-east-1b"
  enable_active_mesh = true
  single_az_ha       = false
}

// manual create spoke vpc to fit customizatiobn requirement
/*
1. create vpc from aws module without public subnets
2. create spoke gateway with insane mode, which will create transit-gw rtb for insane mode
3. create new 2 rtb on different az and dis-associate subnets of transit-gw rtb. It levearges local provisioner with external python script
4. associate wih transit-gw subnet to new created rtb
5. *** it requests test instance is 10.0.12.100 and 10.0.12.200, that will cause subnet assignment not fit, change instance ip to 10.0.12.14 and 10.0.12.30
*/

resource "aws_vpc" "aws_vpc" {
  provider = aws.east
  cidr_block       = "10.0.12.0/23"
  tags = {
      Name = "aws-us-east1-spoke1"
    }
}

resource "aws_internet_gateway" "gw" {
  provider = aws.east
  vpc_id = "${aws_vpc.aws_vpc.id}"
}

resource "aws_subnet" "aws_public_subnet_az_a" {
  provider = aws.east
  vpc_id = "${aws_vpc.aws_vpc.id}"
  cidr_block = "10.0.12.96/28"
  map_public_ip_on_launch = "true"
  availability_zone  = "us-east-1a"
  tags = {
    Name = "aws-us-east1-spoke1-public-us-east-1a"
    }
}

resource "aws_subnet" "aws_public_subnet_az_b" {
    provider = aws.east
    vpc_id = "${aws_vpc.aws_vpc.id}"
    cidr_block = "10.0.12.192/28"
    map_public_ip_on_launch = "true"
    availability_zone  = "us-east-1b"
    tags = {
      Name = "aws-us-east1-spoke1-public-us-east-1b"
    }
}


resource "aws_subnet" "aws_private_subnet_az_a" {
  provider = aws.east
  vpc_id = "${aws_vpc.aws_vpc.id}"
  cidr_block = "10.0.13.0/28"
  availability_zone  = "us-east-1a"
  tags = {
    Name = "aws-us-east1-spoke1-private-us-east-1a"
    }
}

resource "aws_subnet" "aws_private_subnet_az_b" {
    provider = aws.east
    vpc_id = "${aws_vpc.aws_vpc.id}"
    cidr_block = "10.0.13.16/28"
    availability_zone  = "us-east-1b"
    tags = {
      Name = "aws-us-east1-spoke1-private-us-east-1b"
    }
}


resource "aws_route_table" "aws_public_rtb_az_a" {
  provider = aws.east
  vpc_id = "${aws_vpc.aws_vpc.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.gw.id}"
  }
  tags = {
   Name = "aws-us-east1-spoke1-rtb-public-a"
 }
}


resource "aws_route_table" "aws_public_rtb_az_b" {
  provider = aws.east
  vpc_id = "${aws_vpc.aws_vpc.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.gw.id}"
  }
  tags = {
   Name = "aws-us-east1-spoke1-rtb-public-b"
 }
}




resource "aws_route_table_association" "rtb-asc-a" {
  provider = aws.east
  subnet_id      = aws_subnet.aws_public_subnet_az_a.id
  route_table_id = aws_route_table.aws_public_rtb_az_a.id
}

resource "aws_route_table_association" "rtb-asc-b" {
  provider = aws.east
  subnet_id      = aws_subnet.aws_public_subnet_az_b.id
  route_table_id = aws_route_table.aws_public_rtb_az_b.id
}




resource aviatrix_spoke_gateway "aws-us-east1-spoke1-agw" {
  cloud_type         = 1
  account_name       = var.account_name[terraform.workspace]
  gw_name            = "aws-us-east1-spoke1-agw"
  vpc_id             = aws_vpc.aws_vpc.id
  vpc_reg            = var.aws_region-1
  gw_size            = "c5n.large"
  subnet             = cidrsubnet("10.0.12.0/23",3,0)
  ha_subnet          = cidrsubnet("10.0.12.0/23",3,2)
  ha_gw_size         = "c5n.large"
  insane_mode        = true
  insane_mode_az = "us-east-1a"
  ha_insane_mode_az  = "us-east-1b"
  single_az_ha       = false
  enable_active_mesh = true
}

output "aws-us-east1-spoke1-agw-id" {
  value = aviatrix_spoke_gateway.aws-us-east1-spoke1-agw.cloud_instance_id
}

#
# // create test instances
# /*
# 1) create sg with vpc association
# 2) create key-pair with pre-defined public key
# 3) create test1 and test2 instance
# */
resource "aws_security_group" "allow_ssh_lab5" {
  provider = aws.east
  name     = "allow_ssh_lab5"
  vpc_id   = aws_vpc.aws_vpc.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "allow_ssh_lab5"
  }
}
#
data "aws_security_group" "allow_ssh_lab5" {
  provider = aws.east
  id       = aws_security_group.allow_ssh_lab5.id
}

#
resource "aws_instance" "aws-us-east1-spoke1-test1" {
  provider                    = aws.east
  ami                         = var.aws_ami_lab5
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.aws_public_subnet_az_a.id
  private_ip                  = "10.0.12.100" #**********************************
  associate_public_ip_address = true
  key_name                    = aws_key_pair.aws_east1_key.key_name
  vpc_security_group_ids      = [aws_security_group.allow_ssh_lab5.id]

  tags = {
    Name = "aws-us-east1-spoke1-test1"
  }
  depends_on = [aws_security_group.allow_ssh_lab5]
}

resource "aws_instance" "aws-us-east1-spoke1-test2" {
  provider                    = aws.east
  ami                         = var.aws_ami_lab5
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.aws_public_subnet_az_b.id
  private_ip                  = "10.0.12.200" #**********************************
  associate_public_ip_address = true
  key_name                    = aws_key_pair.aws_east1_key.key_name
  vpc_security_group_ids      = [aws_security_group.allow_ssh_lab5.id]

  tags = {
    Name = "aws-us-east1-spoke1-test2"
  }
  depends_on = [aws_security_group.allow_ssh_lab5]
}
#
# ################################### Lab-7 requirment ###################################
# // create  azure spoke gatewaty
# /*
# 1) create resource group for native function call requirement
# 2) create nsg to allow_all
# 3) create vnet azure-us-west-spoke2 for single subnet and attach NSG
# 4) create spoke gateway to attach under vnet azure-us-west-spoke2
# 5) create test vm azure-us-west-spoke2-test1
# 6) create checkpoint security management appliance and bootstrape init wizard
# 7) create windows vm for smart console
# */
resource "azurerm_resource_group" "az-spoke2-rg" {
  name     = "az-spoke2-rg"
  location = var.az_region
}
#
resource "azurerm_network_security_group" "az_sg_checkpoint" {
  name = "az_sg_west"
  location = azurerm_resource_group.az-spoke2-rg.location
  resource_group_name = azurerm_resource_group.az-spoke2-rg.name
  security_rule {
    name = "allow_all"
    priority = 100
    direction = "Inbound"
    access = "Allow"
    protocol = "*"
    source_port_range = "*"
    destination_port_range     = "*"
    source_address_prefix = "*"
    destination_address_prefix = "*"
  }
}
#
resource "azurerm_virtual_network" "azure-us-west-spoke2" {
  name                = "azure-us-west-spoke2"
  location            = var.az_region
  resource_group_name = azurerm_resource_group.az-spoke2-rg.name
  address_space       = ["192.168.2.0/24"]
  subnet {
    name           = "azure-us-west-spoke2-subnet"
    address_prefix = "192.168.2.0/24"
    security_group = azurerm_network_security_group.az_sg_checkpoint.id
  }
  depends_on = [azurerm_resource_group.az-spoke2-rg]
}
#
data "azurerm_subnet" "azure-us-west-spoke2" {
  name                 = "azure-us-west-spoke2-subnet"
  virtual_network_name = "azure-us-west-spoke2"
  resource_group_name  = azurerm_resource_group.az-spoke2-rg.name
  depends_on           = [azurerm_virtual_network.azure-us-west-spoke2, azurerm_resource_group.az-spoke2-rg]
}

resource "aviatrix_spoke_gateway" "azure-us-west-spoke2-agw" {
  cloud_type         = 8
  account_name       = var.azure_account_name[terraform.workspace]
  gw_name            = "azure-us-west-spoke2-agw"
  vpc_id             = "${azurerm_virtual_network.azure-us-west-spoke2.name}:${azurerm_resource_group.az-spoke2-rg.name}"
  vpc_reg            = var.az_region
  gw_size            = "Standard_B1ms"
  subnet             = data.azurerm_subnet.azure-us-west-spoke2.address_prefix # using address_prefix for cidr requirment
  enable_active_mesh = true
  single_az_ha = false
}
#
# # create lab-7 test vm  azure-us-west-spoke2-test1
resource "azurerm_public_ip" "lab7-public-azvm-ip" {
  name                = "lab7-public-azvm-ip"
  location            = azurerm_resource_group.az-spoke2-rg.location
  resource_group_name = azurerm_resource_group.az-spoke2-rg.name
  allocation_method   = "Dynamic"
}
#
resource "azurerm_network_interface" "azure-us-west-spoke2-test1-nic" {
  name                = "azure-us-west-spoke2-test1-nic"
  location            = azurerm_resource_group.az-spoke2-rg.location
  resource_group_name = azurerm_resource_group.az-spoke2-rg.name
  ip_configuration {
    name                          = "azure-us-west-spoke2-test1"
    subnet_id                     = data.azurerm_subnet.azure-us-west-spoke2.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "192.168.2.100"
    public_ip_address_id          = azurerm_public_ip.lab7-public-azvm-ip.id
  }
  depends_on = [data.azurerm_subnet.azure-us-west-spoke2]
}

resource "azurerm_virtual_machine" "azure-us-west-spoke2-test1" {
  name                  = "azure-us-west-spoke2-test1"
  location              = azurerm_resource_group.az-spoke2-rg.location
  resource_group_name   = azurerm_resource_group.az-spoke2-rg.name
  network_interface_ids = [azurerm_network_interface.azure-us-west-spoke2-test1-nic.id]
  vm_size               = "Standard_B1ls"

  storage_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  storage_os_disk {
    name          = "azure-us-west-spoke2-test1-disk"
    create_option = "FromImage"
    caching       = "ReadWrite"
  }


  os_profile {
    computer_name  = "azure-us-west-spoke2-test1"
    admin_username = "ubuntu"
    admin_password = "Password123!"
  }

  os_profile_linux_config {
    disable_password_authentication = false
  }
}


data "azurerm_public_ip" "lab7-public-azvm-ip" {
  name                = azurerm_public_ip.lab7-public-azvm-ip.name
  resource_group_name = azurerm_resource_group.az-spoke2-rg.name
  depends_on          = [azurerm_public_ip.lab7-public-azvm-ip]
}

module "on-prem-partner1" {
  providers      = { aws = aws.east }
  source         = "terraform-aws-modules/vpc/aws"
  name           = "on-prem-partner1"
  cidr           = "172.16.1.0/24"
  azs            = ["us-east-1a"]
  public_subnets = ["172.16.1.0/24"]

  tags = {
    Terrafrom   = "true"
    Environment = "ACE"
  }
}
#
#
# resource "aws_security_group" "windows-rdp" {
#   provider = aws.west1
#   name     = "smart-console-sg"
#   vpc_id   = aws_vpc.aws_vpc_west1.id
#   ingress {
#     from_port   = 22
#     to_port     = 22
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
#   ingress {
#     from_port   = 443
#     to_port     = 443
#     protocol    = "udp"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
#   ingress {
#     from_port   = 3389
#     to_port     = 3389
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
#   ingress {
#     from_port   = -1
#     to_port     = -1
#     protocol    = "icmp"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = -1
#     cidr_blocks = ["0.0.0.0/0"]
#   }
#   tags = {
#     Name = "windows-rdp"
#   }
# }

resource "aws_security_group" "on-prem-partner1" {
  provider = aws.east
  name     = "on-prem-partner1"
  vpc_id   = module.on-prem-partner1.vpc_id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 500
    to_port     = 500
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 4500
    to_port     = 4500
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "on-prem-partner1"
  }
}

# ami id  ami-0b532148acf19dd16
# the login credential refers csh.sh which includes user-data to allow admin login
# https://discuss.hashicorp.com/t/csr1000v-userdata-works-in-v11-but-doesnt-work-in-v12/1887
resource "aws_instance" "aws-cisco-csr" {
  provider                    = aws.east
  ami                         = var.aws_ami_csr_lab5
  instance_type               = "t2.medium"
  subnet_id                   = module.on-prem-partner1.public_subnets[0]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.aws_east1_key.key_name
  vpc_security_group_ids      = [aws_security_group.on-prem-partner1.id]
  #user_data = file("./csr.sh")
  user_data = <<EOF
    ios-config-100 = "username admin privilege 15 password Password123!"
    ios-config-104 = "hostname OnPrem-Partner1"
    ios-config-110 = "write memory"
EOF

  tags = {
    Name = "aws-cisco-csr"
  }
}

# ##########################

resource "aws_eip" "aws-copilot-eip" {
  provider             = aws.west1
  instance = aws_instance.aws-copilot.id
  vpc = true
  tags = {
    Name = "aws-copilot-eip"
  }
}

output "copilot_public_ip" {
  value = aws_eip.aws-copilot-eip.public_ip
}

resource "aws_security_group" "aws-copilot" {
  provider                    = aws.west1
  name   = "aws-copilot-sg"
  vpc_id = aws_vpc.aws_vpc_west1.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 31283
    to_port     = 31283
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "allow_ssh"
  }
}
#
# ##########################
#

resource "aws_s3_bucket_object" "object" {
  provider = aws.east
  acl = "public-read"
  bucket = var.avtx_controller_bucket[terraform.workspace]
  key    = "avtx_priv_key.pem"
  source = local_file.avtx_priv_key.filename
  #depends_on = [aws_s3_bucket.avtx_controller_bucket]

}



######################

resource "aws_vpc" "aws_vpc_west1" {
  provider = aws.west1
  cidr_block       = "10.255.1.0/24"
  tags = {
      Name = "Co-Pilot-VPC"
    }
}

resource "aws_internet_gateway" "gw_west1" {
  provider = aws.west1
  vpc_id = aws_vpc.aws_vpc_west1.id
}

resource "aws_subnet" "aws_public_smart_console" {
  provider = aws.west1
  vpc_id = aws_vpc.aws_vpc_west1.id
  cidr_block = "10.255.1.0/24"
  map_public_ip_on_launch = "true"
  tags = {
    Name = "copilot-public-us-west-1"
    }
}


resource "aws_route_table" "aws_public_west1" {
  provider = aws.west1
  vpc_id = aws_vpc.aws_vpc_west1.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.gw_west1.id}"
  }
  tags = {
   Name = "aws-us-west1-copilot"
 }
}



resource "aws_route_table_association" "rtb-asc-west1" {
  provider = aws.west1
  subnet_id      = aws_subnet.aws_public_smart_console.id
  route_table_id = aws_route_table.aws_public_west1.id
}






resource "aws_key_pair" "aws_east1_key" {
  provider = aws.east
  key_name = "ace_lab_east1"
  public_key = tls_private_key.avtx_key.public_key_openssh

}


resource "aws_key_pair" "aws_west1_key" {
  provider = aws.west1
  key_name = "ace_lab_west1"
  public_key = tls_private_key.avtx_key.public_key_openssh

}

resource "tls_private_key" "avtx_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "local_file" "avtx_priv_key" {
  content  = tls_private_key.avtx_key.private_key_pem
  filename = "avtx_priv_key.pem"
  file_permission = "0400"
}

