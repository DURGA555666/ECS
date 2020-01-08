#!/usr/bin/env python3

from aws_cdk import core

from ecs.ecs_stack import EcsStack


app = core.App()
EcsStack(app, "ecs")

app.synth()
