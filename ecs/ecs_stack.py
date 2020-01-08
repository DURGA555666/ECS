from aws_cdk import (core, aws_ecs as ecs, aws_ec2 as ec, aws_iam as iam)
import aws_cdk.aws_elasticloadbalancingv2 as elbv2
import re

from aws_cdk.aws_ec2 import Peer, Port


class EcsStack(core.Stack):
    # WARNING
    # don't change the order of text files

    envr = ["WebAppMainEnv.txt", "WebAppMainDataDogEnv.txt"]
    commands = {}

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # The code that defines your stack goes here
        EcsStack.readConfig(0)
        vpc = ec.Vpc(self, "Main", cidr="11.0.0.0/26",
                     max_azs=2, nat_gateways=1,
                     subnet_configuration=[
                         ec.SubnetConfiguration(name="public", cidr_mask=28, subnet_type=ec.SubnetType.PUBLIC),
                         ec.SubnetConfiguration(name="private", cidr_mask=28, subnet_type=ec.SubnetType.PRIVATE)
                     ])

        cluster = ecs.Cluster(self, "TestingCluster",
                              vpc=vpc
                              )
        # defining the task iam role
        taskRole = iam.Role(self, id="taskRole",
                            assumed_by=iam.CompositePrincipal(iam.ServicePrincipal(service='ecs-tasks.amazonaws.com'),
                                                              iam.ServicePrincipal(service='ec2.amazonaws.com')),
                            role_name="webmaintaskRole"
                            , managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("AmazonRDSFullAccess"),
                                                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSQSFullAccess"),
                                                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess"),
                                                iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchFullAccess"),
                                                iam.ManagedPolicy.from_aws_managed_policy_name(
                                                    "AmazonDynamoDBFullAccess"),
                                                iam.ManagedPolicy.from_aws_managed_policy_name(
                                                    "AmazonRedshiftFullAccess"),
                                                iam.ManagedPolicy.from_aws_managed_policy_name(
                                                    "AmazonKinesisFullAccess"),
                                                iam.ManagedPolicy.from_aws_managed_policy_name(
                                                    "service-role/AmazonECSTaskExecutionRolePolicy"),
                                                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSNSFullAccess"),
                                                iam.ManagedPolicy.from_aws_managed_policy_name(
                                                    "service-role/AWSLambdaRole"),
                                                iam.ManagedPolicy(self, id="ManagedPolicy",
                                                                  managed_policy_name="Grant_dev", statements=[
                                                        iam.PolicyStatement(
                                                            actions=["kms:Decrypt", "secretemanager:GetSecreteValue"],
                                                            resources=["*"])])
                                                ]

                            )
        # taskRole.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonRDSFullAccess"))

        # WebApp Main task Defenition & Service
        webmain_task_definition = ecs.FargateTaskDefinition(self, "WebAppMain",
                                                            memory_limit_mib=512,
                                                            cpu=256,
                                                            task_role=taskRole,
                                                            execution_role=taskRole
                                                            )
        webmain_container = webmain_task_definition.add_container("webapp-mainContainer",

                                                                  image=ecs.ContainerImage.from_registry(
                                                                      "amazon/amazon-ecs-sample"),
                                                                  environment=EcsStack.commands,
                                                                  docker_labels={
                                                                      "com.datadoghq.ad.instances": "[{\"host\": \"%%host%%\", \"port\": 80}]",
                                                                      "com.datadoghq.ad.check_names": "[\"ecs_fargate\"]",
                                                                      "com.datadoghq.ad.init_configs": "[{}]"

                                                                  },
                                                                  logging=ecs.LogDriver.aws_logs(
                                                                      stream_prefix="awslogs")
                                                                  )
        # Clearing the environment vairables from the commands(Map)
        EcsStack.commands.clear()
        EcsStack.readConfig(1)
        webmain_datadog_container = webmain_task_definition.add_container("webapp-main_datadog_Container",

                                                                          image=ecs.ContainerImage.from_registry(
                                                                              "amazon/amazon-ecs-sample"),

                                                                          environment=EcsStack.commands
                                                                          )

        webmain_port_mapping = ecs.PortMapping(container_port=80, host_port=80, protocol=ecs.Protocol.TCP)
        datadog_port_mapping1 = ecs.PortMapping(container_port=8126, host_port=8126, protocol=ecs.Protocol.TCP)
        datadog_port_mapping2 = ecs.PortMapping(container_port=8125, host_port=8125, protocol=ecs.Protocol.TCP)
        webmain_container.add_port_mappings(webmain_port_mapping)
        webmain_datadog_container.add_port_mappings(datadog_port_mapping1)
        webmain_datadog_container.add_port_mappings(datadog_port_mapping2)
        # Security group for service
        webmain_sg = ec.SecurityGroup(self, "webmain_sg", vpc=vpc, allow_all_outbound=True,
                                      security_group_name="WebAppMain")
        webmain_sg.add_ingress_rule(peer=Peer.ipv4("202.65.133.194/32"), connection=Port.tcp(5432))
        webmain_service = ecs.FargateService(self, "webapp-main",
                                             cluster=cluster,
                                             task_definition=webmain_task_definition,
                                             desired_count=1,
                                             security_group=webmain_sg
                                             )
        # defining the load balancer
        webmain_lb = elbv2.ApplicationLoadBalancer(self, "LB",
                                                   vpc=vpc,
                                                   internet_facing=True,
                                                   load_balancer_name="WebAppMain",
                                                   # security_group=
                                                   vpc_subnets=ec.SubnetSelection(subnet_type=ec.SubnetType.PUBLIC)

                                                   )
        webmain_target_grp = elbv2.ApplicationTargetGroup(self, id="webapp-main-target", port=80,
                                                          protocol=elbv2.ApplicationProtocol.HTTP,
                                                          health_check=elbv2.HealthCheck(healthy_http_codes="200-399",
                                                                                         healthy_threshold_count=2,
                                                                                         unhealthy_threshold_count=2,
                                                                                         port="traffic-port",
                                                                                         protocol=elbv2.Protocol.HTTP,
                                                                                         timeout=core.Duration.seconds(
                                                                                             6),
                                                                                         interval=core.Duration.seconds(
                                                                                             10)),
                                                          targets=[webmain_service],
                                                          target_group_name="WebAppMain",
                                                          target_type=elbv2.TargetType.IP,
                                                          vpc=vpc)
        listener = webmain_lb.add_listener("webMain_Listener",
                                           port=443,
                                           open=True,
                                           default_target_groups=[webmain_target_grp],
                                           certificate_arns=[
                                               "arn:aws:acm:us-west-2:384853870836:certificate/182c0fdd-813f-4bd3-aee1-0b4543cfb52b"]
                                           )
        listener2 = webmain_lb.add_listener("webMain_Listener2",
                                            port=80,
                                            # default_target_groups=[webmain_target_grp]
                                            )

        # elbv2.ApplicationListenerCertificate(self,"WebAppMAin_Certificate",listener=listener,certificate_arns=["arn:aws:acm:us-west-2:384853870836:certificate/182c0fdd-813f-4bd3-aee1-0b4543cfb52b"])
        listener2.add_redirect_response(id="HttptoHttps", status_code="HTTP_301", port="443", protocol="HTTPS")

    @staticmethod
    def readConfig(x):
        filename = EcsStack.envr[x]

        with open(filename) as fh:
            for line in fh:
                line = line.strip('\n')
                line = line.strip('\'')
                lst = re.split(r'\t+', line)
                if (len(lst) == 2):
                    command = lst[0]
                    description = lst[1]
                    EcsStack.commands[command] = description
        # return json.dumps(EcsStack.commands, indent=2, sort_keys=True)
