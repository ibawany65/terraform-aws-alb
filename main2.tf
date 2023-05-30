locals {
  app_config                = yamldecode(file("app_config.yaml")).app_config
  app_name                  = local.app_config.app_name
  app_name_short            = local.app_config.app_name_short
  cloud_components          = try(local.app_config.components.cloud, {})
  category                  = "app"

  optional_tags = {
    "teams"           = var.teams #var.env_type == "prd" ? var.teams : null
    "applicationname" = var.app_name
    "version"         = var.service_version
    "group"           = var.group
    "uid"             = var.uid
    "techstack"       = var.techstack
  }
  vpcs = {
    "sbx" = "infra-sandbox-vpc-workload"
    "dev" = "infra-dev-vpc-workload"
    "tt"  = "infra-tt-vpc-workload"
    "uat" = "infra-uat-vpc-workload"
    "prd" = "infra-prd-vpc-workload"
  }

  vpc_name = local.vpcs[var.env_type]

  db_cluster_instance_class = yamldecode(file("resources/db_instance_classes.yaml"))[var.env_type]

  cluster_instances = flatten([
        for ck, cv in local.cloud_components.rds.clusters : flatten(
          [
            for ik, iv in cv.instances : {
              "cluster_key" = ck 
              "instance_key" = ik
              "instace"  = iv
            }
        ])
  ])
}

locals {
  AD_DOMAIN        = var.AD_DOMAIN
  AD_JOIN_USER     = var.AD_JOIN_USER_NAME
  AD_JOIN_PASSWORD = var.AD_JOIN_PASSWORD
  AD_OU            = var.AD_OU
}


module "kms" {
  source  = "app.terraform.io/sandbox-fepoc/kms/aws"
  version = "1.0.3"
  # source = "/c/users/cw22gm5.FEPOC/Terraform_Automation/terraform-aws-kms/terraform"
  for_each                   = local.cloud_components.kms

  
  ## Insert required variables here
  app_name                   = local.app_name
  env_type                   = var.env_type
  key_usage                  = try(each.value.key_usage, "ENCRYPT_DECRYPT")
  customer_keystore_id       = try(each.value.customer_keystore_id, null)
  customer_keystore_key_spec = try(each.value.customer_keystore_key_spec, "SYMMETRIC_DEFAULT")
  is_multi_region            = try(each.value.is_multi_region, false)
  kms_key_ordinal            = index(keys(local.cloud_components.kms), each.key) + 2
  additional_description     = try(each.value.additional_description, "")
  kms_key_tags               = local.optional_tags
}

data "aws_vpc" "current" {
  provider = aws.network
  tags = {
    "aws:cloudformation:stack-name" = local.vpc_name
  }
}

# Get the subnets related to api gateway
data "aws_subnets" "vpc" {
  provider = aws.network
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.current.id]
  }
}

module "acm-import" {
  source  = "app.terraform.io/sandbox-fepoc/acm-import/aws"
  version = "1.0.9"
  
  for_each               = local.cloud_components.acm

  private_key = each.value.private_key_file
  certificate_body = each.value.certificate_body
  certificate_chain = each.value.certificate_chain
}

module "security_group" {
  source  = "app.terraform.io/sandbox-fepoc/security-groups/aws"
  version = "1.0.8"
  # source = "/c/users/cw22gm5.FEPOC/Terraform_Automation/terraform-aws-security-groups/terraform"
  providers = {
    aws.network = aws.network
  }
  for_each               = local.cloud_components.security_groups

  ## Insert required variables here
  env_name               = var.env_name
  env_type               = var.env_type
  region                 = var.region
  app_name               = local.app_name
  additional_description = try(each.value.additional_description, "")
  rule_category          = each.value.rule_category
  ingress_rules          = try(each.value.ingress, {})
  egress_rules           = try(each.value.egress, {})
  security_group_tags    = local.optional_tags
  vpc_name               = local.vpc_name
}

module "key_pair" {
  source   = "app.terraform.io/sandbox-fepoc/ec2-key-pair/aws"
  version  = "1.1.5"
  for_each = local.cloud_components.ec2.key_pairs

  ## Insert required variables here
  key_name = each.value.key_name
  tags     = local.optional_tags #jsonencode([for k, v in local.optional_tags : {key = k, value = v}])
}

module "iam_instance_profile" {
  source   = "app.terraform.io/sandbox-fepoc/iam-instance-profile/aws"
  version  = "1.0.1"
  for_each = local.cloud_components.ec2.iam_instance_profiles

  ## Insert required variables here
  app_name_short        = local.app_name_short
  env_name              = var.env_name
  env_type              = var.env_type
  organization          = var.organization
  region                = var.region
  iam_role_ordinal      = index(keys(local.cloud_components.ec2.iam_instance_profiles), each.key) + 1
  instance_profile_name = each.value.name
  policy_ordinal        = index(keys(local.cloud_components.ec2.iam_instance_profiles), each.key) + 1
  tags                  = local.optional_tags
}

module "launch_template" {
  source   = "app.terraform.io/sandbox-fepoc/ec2-launch-template/aws"
  version  = "1.0.1"
  for_each = local.cloud_components.ec2.launch_templates

  ## Insert required variables here
  name                   = try(each.value.name, null)
  description            = try(each.value.description, null)
  key_name               = try(each.value.key_name, null) != null ? [for kn in each.value.key_name : module.key_pair[each.value.key_pair].key_name] : null
  instance_type          = try(each.value.instance_type, null)
  vpc_security_group_ids = try(each.value.security_groups, []) != [] ? [for sg_key in each.value.security_groups : module.security_group[sg_key].id] : []
  tags                   = local.optional_tags

  iam_instance_profile = {
    name = try(each.value.instance_profile_name, null) != null ? module.iam_instance_profile[try(each.value.instance_profile_name, null)].name : null
  }
}

module "auto_scaling_group" {
  source    = "app.terraform.io/sandbox-fepoc/auto-scaling-group/aws"
  version   = "1.0.1"
  providers = { aws.network = aws.network }
  for_each  = local.cloud_components.ec2.auto_scaling_groups

  ## Insert required variables here
  name                = each.value.name
  max_size            = each.value.max_size
  min_size            = each.value.min_size
  tags                = local.optional_tags
  vpc_name            = local.vpcs[var.env_type]

  launch_template = {
    name    = module.launch_template[each.value.launch_template_name].name
    version = module.launch_template[each.value.launch_template_name].latest_version 
  }
}

module "auto_scaling_lifecycle_hook" {
  source   = "app.terraform.io/sandbox-fepoc/auto-scaling-lifecycle-hook/aws"
  version  = "1.0.1"
  for_each = local.cloud_components.ec2.auto_scaling_lifecycle_hooks

  ## Insert required variables here
  autoscaling_group_name = module.auto_scaling_group[each.value.auto_scaling_group_name].name
  heartbeat_timeout      = 3600
  name                   = each.value.name
} 

module "auto_scaling_policy" {
  source   = "app.terraform.io/sandbox-fepoc/auto-scaling-policy/aws"
  version  = "1.0.1"
  for_each = local.cloud_components.ec2.auto_scaling_policies

  ## Insert required variables here
  autoscaling_group_name = module.auto_scaling_group[each.value.auto_scaling_group_name].name
  env_name               = var.env_name
  env_type               = var.env_type
  name                   = each.value.name
}

module "placement_group" {
  source   = "app.terraform.io/sandbox-fepoc/ec2-placement-group/aws"
  version  = "1.0.1"
  for_each = local.cloud_components.ec2.placement_groups

  ## Insert required variables here
  name            = each.value.name
  partition_count = try(each.value.partition_count, null)
  spread_level    = try(each.value.spread_level, null)
  strategy        = each.value.strategy
  tags            = local.optional_tags
}

data "template_file" "ssm_config" {
  template = "${file("./resources/user_data_scripts/ssm_config.sh")}"
  vars = {
    AD_DOMAIN        = local.AD_DOMAIN
    AD_JOIN_USER     = local.AD_JOIN_USER
    AD_JOIN_PASSWORD = local.AD_JOIN_PASSWORD
    AD_OU            = local.AD_OU
  }
}

locals {
  efs_mounts = { for efsk, efsv in local.cloud_components.efs : efsk => {
                                                                          "dns" = module.efs[efsk].dns_name,
                                                                          "folder" = efsv.mount_on
                                                                         }
               }
}
# data "template_file" "efs_mount" {
#   template = "${file("./resources/user_data_scripts/efs_mount.sh")}"
#   vars = {
#     efs_mounts = local.efs_mounts
#   }
# }

data "template_cloudinit_config" "default" {
 gzip          = true
 base64_encode = true

 part {
   filename     = "ssm.cfg"
   content_type = "text/part-handler"
   content      = "${data.template_file.ssm_config.rendered}"
   }

 part {
     filename     = "efs_mount.cfg"
     content_type = "text/part-handler"
     content      = templatefile("./resources/user_data_scripts/efs_mount.sh",{efs_mounts=local.efs_mounts})
     }
}

output "rendered_cloudinit_config" {
  value = data.template_cloudinit_config.default.rendered
}

module "ec2_instance" {
  source    = "app.terraform.io/sandbox-fepoc/ec2-instance/aws"
  version   = "1.0.9"
  providers = { aws.network = aws.network }
  for_each  = local.cloud_components.ec2.instances

  ## Insert required variables here
  app_name                    = local.app_name
  env_name                    = var.env_name
  env_type                    = var.env_type
  organization                = var.organization
  region                      = var.region
  arn                         = module.key_pair[each.value.key_pair].secret_arn
  associate_public_ip_address = try(each.value.associate_public_ip_address, false)
  instance_profile_name       = module.iam_instance_profile[each.value.instance_profile_name].name
  instance_type               = each.value.instance_type
  key_name                    = module.key_pair[each.value.key_pair].key_name
  ordinal                     = index(keys(local.cloud_components.ec2.instances), each.key) + 1
  service_name                = each.value.service_name
  #user_data                   = "${data.template_file.user_data.rendered}"
  #user_data                   = "${data.template_cloudinit_config.default.rendered}"
  user_data_replace_on_change = true
  vpc_name                    = local.vpcs[var.env_type]
  vpc_security_group_ids      = try(each.value.security_groups, []) != [] ? [for sg_key in each.value.security_groups : module.security_group[sg_key].id] : []
  tags                        = local.optional_tags
}


module "ebs_volume" {
  source   = "app.terraform.io/sandbox-fepoc/ebs-volume/aws"
  version  = "1.0.0"
  for_each = local.cloud_components.ec2.ebs_volumes

  ## Insert required variables here
  availability_zone = module.ec2_instance[each.value.availability_zone].availability_zone
  encrypted         = each.value.encrypted
  iops              = each.value.iops
  kms_key_id        = each.value.encrypted == false ? null : try(module.kms[each.value.kms_key].key_arn, "")
  size              = each.value.size
  tags              = local.optional_tags
  type              = each.value.type
}


module "volume_attachment" {
  source   = "app.terraform.io/sandbox-fepoc/ebs-volume-attachment/aws"
  version  = "1.0.0"
  for_each = local.cloud_components.ec2.volume_attachments

  ## Insert required variables here
  device_name = each.value.device_name
  instance_id = module.ec2_instance[each.value.instance].id
  volume_id   = module.ebs_volume[each.value.volume].id
}


resource "aws_db_subnet_group" "for_base" {
  name       = "subnet_group_for_${var.env_type}_vpc"
  subnet_ids = data.aws_subnets.vpc.ids
}

module "rds-cluster" {
  source   = "app.terraform.io/sandbox-fepoc/rds-cluster/aws"
  version  = "0.0.1"
  for_each = local.cloud_components.rds.clusters

  engine                          = each.value.engine
  engine_version                  = each.value.engine_version
  backup_retention_period         = try(each.value.backaup_retention_period, 7)
  app_name                        = local.app_name
  env_type                        = var.env_type
  env_name                        = var.env_name
  region                          = var.region
  db_service_name                 = try(each.value.db_service_name,"apg")
  db_functionality                = try(each.value.db_functionality,"")
  db_additional_description       = try(each.value.db_additional_description, "cluster")
  db_ordinal                      = index(keys(local.cloud_components.rds.clusters), each.key) + 1
  db_subnet_group_name            = aws_db_subnet_group.for_base.name
  security_group_ids              = try(each.value.security_groups, []) != [] ? [for sg_key in each.value.security_groups : module.security_group[sg_key].id] : []
  db_cluster_instance_class       = local.db_cluster_instance_class
  enabled_cloudwatch_logs_exports = try(each.value.enabled_cloudwatch_logs_exports, ["postgresql"])
  enable_global_write_forwarding  = try(each.value.enable_global_write_forwarding, null)
  final_snapshot_identifier       = try(each.value.final_snapshot_identifier, null)
  kms_key_id                      = try(each.value.encryption_key, "") != "" ? module.kms[try(each.value.encryption_key, "")].key_arn : null
  cluster_default_parameters      = try(each.value.parameters.cluster_defaults, null)
  instance_default_parameters     = try(each.value.parameters.instance_defaults, null)

}

resource "aws_iam_role" "rds_monitoring_role" {
    name = "rds-monitoring-role"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Principal = {
                    Service = "monitoring.rds.amazonaws.com"
                }
                Action = "sts:AssumeRole"
            }
        ]
    })
    
    tags = {
      "Name" = "RDS-Monitoring-Role"
    }
}

resource "aws_iam_role_policy_attachment" "instance_monitoring_policy" {
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
    role       = aws_iam_role.rds_monitoring_role.name
}

module "rds-cluster-instance" {
  source   = "app.terraform.io/sandbox-fepoc/rds-cluster-instance/aws"
  version  = "0.0.1"
  for_each = { for idx, config in local.cluster_instances : "ci-${idx}" => config }

  app_name                        = local.app_name
  env_type                        = var.env_type
  env_name                        = var.env_name
  region                          = var.region
  instance_service_name           = try(each.value.db_service_name,"apg")
  instance_functionality          = try(each.value.db_functionality,"")
  instance_additional_description = try(each.value.db_additional_description, "instance")
  instance_ordinal                = index(keys(local.cloud_components.rds.clusters[each.value.cluster_key].instances), each.value.instance_key) + 1
  cluster_identifier              = module.rds-cluster[each.value.cluster_key].cluster_identifier
  engine                          = module.rds-cluster[each.value.cluster_key].engine
  engine_version                  = module.rds-cluster[each.value.cluster_key].engine_version
  db_subnet_group_name            = module.rds-cluster[each.value.cluster_key].db_subnet_group_name
  db_parameter_group_name         = module.rds-cluster[each.value.cluster_key].db_instance_parameter_group_name
  instance_class                  = local.db_cluster_instance_class
  instance_default_parameters     = try(each.value.parameters.instance_defaults, null)
  monitoring_role_arn             = aws_iam_role.rds_monitoring_role.arn
}

# module "route53" {
#    source  = "app.terraform.io/sandbox-fepoc/route53/aws"
#    version = "0.0.2"
  
#    app_name                   = local.app_name
#    env_type                   = var.env_type
#    env_name                   = var.env_name  
#    region                     = var.region
#    alb_dns_name               = module.alb[each.value.alb_dns_name].lb_dns_name
# }

#####EFS Stuff#####

locals {
  #region = var.region
  #name   = "efs-ex-${replace(basename(path.cwd), "_", "-")}"

  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  # tags = {
  #   Name = local.name


  # }
}

data "aws_availability_zones" "available" {}   

data "aws_caller_identity" "current" {}

data "aws_subnets" "private"{
  filter {
    name = "vpc-id"
    values = [
      data.aws_vpc.current.id
    ]
  }

  filter {
    name = "map-public-ip-on-launch"
    values = [false]
  }
}


################################################################################
# EFS Module
################################################################################

module "efs" {
  source   = "app.terraform.io/sandbox-fepoc/efs/aws"
  version  = "1.0.6"
  providers = { aws.network = aws.network }
  for_each = local.cloud_components.efs
  app_name                   = local.app_name
  env_type                   = var.env_type
  env_name                   = var.env_name
  # File system
  #name           = each.value.name
  #creation_token = each.value.name
  encrypted      = each.value.encrypted
  kms_key_arn    = module.kms[each.value.kms_key].key_arn

  performance_mode                = each.value.performance_mode
  throughput_mode                 = each.value.throughput_mode
  provisioned_throughput_in_mibps = each.value.provisioned_throughput_in_mibps

  #   lifecycle_policy = {
  #     transition_to_ia                    = "AFTER_30_DAYS"
  #     transition_to_primary_storage_class = "AFTER_1_ACCESS"
  #   }

  lifecycle_policy = each.value.lifecycle_policy

  # File system policy
  attach_policy                      = each.value.attach_policy
  bypass_policy_lockout_safety_check = each.value.bypass_policy_lockout_safety_check
  policy_statements = [
    {
      sid     = "Example"
      actions = ["elasticfilesystem:ClientMount"]
      principals = [
        {
          type        = "AWS"
          identifiers = [data.aws_caller_identity.current.arn]
        }
      ]
    }
  ]

  # Mount targets / security group
  mount_targets              = { for k, v in zipmap(local.azs, data.aws_subnets.vpc.ids) : k => { subnet_id = v } }
  security_group_description = "Example EFS security group"
  security_group_vpc_id      = data.aws_vpc.current.id
  security_group_rules = {
    vpc = {
      # relying on the defaults provdied for EFS/NFS (2049/TCP + ingress)
      description = "NFS ingress from VPC private subnets"
      cidr_blocks = [data.aws_vpc.current.cidr_block]
    }
  }

  # Access point(s)
  access_points = {
    posix_example = {
      name = "posix-example"
      posix_user = {
        gid            = 1001
        uid            = 1001
        secondary_gids = [1002]
      }

      # tags = {
      #   Additionl = "yes"
      # }
    }
    root_example = {
      root_directory = {
        path = "/example"
        creation_info = {
          owner_gid   = 1001
          owner_uid   = 1001
          permissions = "755"
        }
      }
    }
  }

  # Backup policy
  enable_backup_policy = each.value.enable_backup_policy

  # Replication configuration
  create_replication_configuration = each.value.create_replication_configuration
  replication_configuration_destination = {
    region = var.region
  }

  # tags = local.tags
}

##################################################################
# Application Load Balancer
##################################################################

module "alb" {
  source  = "app.terraform.io/sandbox-fepoc/alb/aws"
  version = "1.0.4"
  providers = { aws.network = aws.network }
  for_each = local.cloud_components.alb
  app_name                   = local.app_name
  env_type                   = var.env_type
  env_name                   = var.env_name
  #name = local.name

  load_balancer_type = each.value.load_balancer_type

  vpc_id  = data.aws_vpc.current.id
  subnets = data.aws_subnets.vpc.ids
  # Attach security groups
  security_groups = try(each.value.security_groups, []) != [] ? [for sg_key in each.value.security_groups : module.security_group[sg_key].id] : []
  
  http_tcp_listeners = [
    # Forward action is default, either when defined or undefined
    {
      port               = 80
      protocol           = "HTTP"
      target_group_index = 0
      # action_type        = "forward"
    }
    
  ]

  https_listeners = [
    {
      port               = 443
      protocol           = "HTTPS"
      certificate_arn    = module.acm-import["acm_1"].acm_certificate_arn
      target_group_index = 0
    }
  ]
    

  target_groups = [
    {
      name_prefix                       = "h1"
      backend_protocol                  = "HTTP"
      backend_port                      = 80
      target_type                       = "instance"
      deregistration_delay              = 10
      load_balancing_cross_zone_enabled = false
      health_check = {
        enabled             = true
        interval            = 30
        path                = "/healthz"
        port                = "traffic-port"
        healthy_threshold   = 3
        unhealthy_threshold = 3
        timeout             = 6
        protocol            = "HTTP"
        matcher             = "200-399"
      }
      protocol_version = "HTTP1"
      
 #     targets = {
 #         my_ec2 = {
 #         target_id = [module.ec2_instance[each.value.instance].id]
 #         port      = 80
 #       }
 #       my_ec2_again = {
 #         target_id = [module.ec2_instance[each.value.instance].id]
 #         port      = 8080
 #       }
 #     }
      # tags = {
      #   InstanceTargetGroupTag = ""
      # }
    }
  ]

  tags = {
    Project = ""
  }

  lb_tags = {
    MyLoadBalancer = ""
  }

  target_group_tags = {
    MyGlobalTargetGroupTag = ""
  }

  https_listener_rules_tags = {
    MyLoadBalancerHTTPSListenerRule = ""
  }

  https_listeners_tags = {
    MyLoadBalancerHTTPSListener = ""
  }

  http_tcp_listeners_tags = {
    MyLoadBalancerTCPListener = ""
  }
}
