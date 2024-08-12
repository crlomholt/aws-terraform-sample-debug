resource "aws_iam_policy" "deployment_policy_1" {
  description = "description here"
  name        = "deployment_policy_1"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "sts:GetCallerIdentity",
          "lambda:CreateEventSourceMapping",
          "lambda:ListEventSourceMappings",
          "lambda:GetEventSourceMapping",
          "lambda:DeleteEventSourceMapping",
          "lambda:UpdateEventSourceMapping",
          "logs:DescribeLogGroups",
          "logs:DescribeSubscriptionFilters",
          "sns:ListTopics"
        ],
        "Resource" : ["*"],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "lambda:CreateFunction",
          "lambda:AddPermission",
          "lambda:RemovePermission",
          "lambda:UpdateFunctionConfiguration",
          "lambda:GetFunction",
          "lambda:UpdateFunctionCode",
          "lambda:GetPolicy",
          "lambda:ListVersionsByFunction",
          "lambda:GetFunctionCodeSigningConfig",
          "lambda:DeleteFunction",
          "lambda:TagResource",
          "lambda:UntagResource",
          "lambda:UpdateFunction",
          "lambda:PutFunctionEventInvokeConfig",
          "lambda:GetFunctionEventInvokeConfig",
          "lambda:DeleteFunctionEventInvokeConfig"
        ],
        "Resource" : [
          "arn:aws:lambda:*:*:function:*-*"
        ],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "logs:CreateLogGroup",
          "logs:ListTagsLogGroup",
          "logs:DeleteLogGroup",
          "logs:DescribeLogGroup",
          "logs:DescribeLogGroups",
          "logs:CreateLogStream",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents",
          "logs:GetLogEvents",
          "logs:FilterLogEvents",
          "logs:ListTagsForResource",
          "logs:PutRetentionPolicy",
          "logs:PutSubscriptionFilter",
          "logs:DescribeSubscriptionFilters",
          "logs:DeleteSubscriptionFilter",
          "logs:TagResource"
        ],
        "Resource" : [
          "arn:aws:logs:*:*:log-group::log-stream:*",
          "arn:aws:logs:*:*:log-group:/aws/lambda/*-*",
          "arn:aws:logs:*:*:log-group:/aws/lambda/*-*:log-stream:"

        ],
        "Effect" : "Allow"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "glue:CreateDatabase",
          "glue:CreateTable",
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:TagResource",
          "glue:GetTags",
          "glue:DeleteDatabase",
          "glue:DeleteTable",
          "glue:UpdateTable"
        ],
        "Resource" : [
          "arn:aws:glue:*:*:catalog",
          "arn:aws:glue:*:*:database/*",
          "arn:aws:glue:*:*:userDefinedFunction/*",
          "arn:aws:glue:*:*:table/*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "glue:CreateTrigger",
          "glue:DeleteTrigger",
          "glue:GetTrigger",
          "glue:GetTriggers",
          "glue:ListTriggers",
          "glue:StartTrigger",
          "glue:StopTrigger",
          "glue:UpdateTrigger",
          "glue:GetTags",
          "glue:TagResource",
          "glue:UntagResource",
        ],
        "Resource" : [
          "arn:aws:glue:*:*:trigger/*-*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "glue:GetJob",
          "glue:GetTags",
          "glue:UpdateJob",
          "glue:DeleteJob",
          "glue:CreateJob",
          "glue:TagResource",
          "glue:UntagResource"
        ],
        "Resource" : [
          "arn:aws:glue:*:*:job/*-*"
        ]
      },
      {
        "Action" : [
          "sqs:TagQueue",
          "sqs:UntagQueue",
          "sqs:GetQueueAttributes",
          "sqs:ListQueueTags",
          "sqs:SetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:CreateQueue",
          "sqs:DeleteQueue",

        ],
        "Effect" : "Allow",
        "Resource" : [
          "arn:aws:sqs:*:*:*-*"
        ]
      },
      {
        "Action" : [
          "iam:ListPolicies",
          "iam:ListRoles"
        ],
        "Effect" : "Allow",
        "Resource" : "*"
      },
      {
        "Action" : [
          "events:PutRule",
          "events:DescribeRule",
          "events:PutTargets",
          "events:ListTargetsByRule",
          "events:RemoveTargets",
          "events:DeleteRule",
          "events:ListTagsForResource",
          "events:TagResource",
          "events:UntagResource"
        ],
        "Effect" : "Allow",
        "Resource" : [
          "arn:aws:events:*:*:rule/*-*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:*",
          "s3-object-lambda:*"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "sns:ConfirmSubscription",
          "sns:GetSubscriptionAttributes",
          "sns:ListSubscriptions",
          "sns:ListSubscriptionsByTopic",
          "sns:Subscribe",
          "sns:UnSubscribe",
          "sns:CreateTopic",
          "sns:DeleteTopic",
          "sns:AddPermission",
          "sns:RemovePermission",
          "sns:GetTopicAttributes",
          "sns:SetTopicAttributes",
          "sns:ListTagsForResource",
          "sns:TagResource",
          "sns:UntagResource"
        ],
        "Resource" : [
          "arn:aws:sns:*:*:*-*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:DisableAlarmActions",
          "cloudwatch:EnableAlarmActions",
          "cloudwatch:ListTagsForResource",
          "cloudwatch:TagResource",
          "cloudwatch:UntagResource"
        ],
        "Resource" : [
          "arn:aws:cloudwatch:*:*:alarm:*-*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetResourcePolicy",
          "secretsmanager:PutSecretValue",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DeleteSecret",
          "secretsmanager:CreateSecret",
          "secretsmanager:TagResource",
          "secretsmanager:UntagResource",
          "secretsmanager:UpdateSecretVersionStage",
        ],
        "Resource" : [
          "arn:aws:secretsmanager:*:*:secret:*/*"
        ]
      },
      {
        "Action" : [
          "ecr:Batch*",
          "ecr:Describe*",
          "ecr:Get*",
          "ecr:ListImages",
          "ecr:ListTagsForResource"
        ],
        "Resource" : "arn:aws:ecr:*:*:repository/*",
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "ecr:GetAuthorizationToken"
        ],
        "Resource" : "*",
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "states:DescribeStateMachine",
          "states:ListStateMachines",
          "states:ListTagsForResource",
          "states:ListStateMachineVersions",
          "states:ListStateMachineAliases"
        ],
        "Resource" : [
          "arn:aws:states:*:*:stateMachine:*-*"
        ],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "dynamodb:DescribeTable",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:DescribeTimeToLive",
          "dynamodb:ListTagsOfResource",
          "dynamodb:ListTagsOfResource",
          "dynamodb:DeleteTable",
          "dynamodb:CreateTable",
          "dynamodb:TagResource",
          "dynamodb:UntagResource"
        ],
        "Resource" : [
          "arn:aws:dynamodb:*:*:table/*-*"
        ],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "lambda:PublishLayerVersion",
          "lambda:GetLayerVersion",
          "lambda:DeleteLayerVersion",
          "lambda:ListLayers",
          "lambda:ListLayerVersions"
        ],
        "Resource" : [
          "arn:aws:lambda:*:*:layer:*-*"
        ],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "iam:GetPolicyVersion",
          "iam:ListRoleTags",
          "iam:UntagRole",
          "iam:TagRole",
          "iam:DeletePolicy",
          "iam:CreateRole",
          "iam:AttachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DetachRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:DetachGroupPolicy",
          "iam:ListAttachedGroupPolicies",
          "iam:ListPolicyTags",
          "iam:ListRolePolicies",
          "iam:CreatePolicy",
          "iam:CreatePolicyVersion",
          "iam:PutGroupPolicy",
          "iam:GetRole",
          "iam:GetPolicy",
          "iam:ListGroupPolicies",
          "iam:DeleteRole",
          "iam:UpdateRoleDescription",
          "iam:AttachGroupPolicy",
          "iam:TagPolicy",
          "iam:UntagPolicy",
          "iam:UpdateRole",
          "iam:GetGroupPolicy",
          "iam:GetRolePolicy",
          "iam:DeletePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:UpdateAssumeRolePolicy",
          "iam:ListInstanceProfileForRole",
          "iam:ListEntitiesForPolicy"
        ],
        "Effect" : "Allow",
        "Resource" : [
          "arn:aws:iam::*:role/*-*",
          "arn:aws:iam::*:policy/*-*"
        ]
      },
      {
        "Action" : [
          "rds:CreateDBSubnetGroup",
          "rds:DescribeDBSubnetGroups",
          "rds:ListTagsForResource",
          "rds:DeleteDBSubnetGroup",
          "rds:CreateDBCluster",
          "rds:DeleteDBCluster",
          "rds:ModifyDBCluster",
          "rds:AddTagsToResource"
        ],
        "Resource" : [
          "arn:aws:rds:*:*:subgrp:*-"
        ],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "rds:CreateDBInstance",
          "rds:DescribeDBInstance",
          "rds:DeleteDBInstance",
          "rds:ModifyDBInstance",
          "rds:AddTagsToResource",
          "rds:RegisterDBProxyTargets",
          "rds:DeregisterDBProxyTargets"
        ],
        "Resource" : [
          "arn:aws:rds:*:*:db:*-*"
        ],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "rds:CreateDBProxy",
          "rds:DeleteDBProxy",
          "rds:DescribeDBProxyTargets",
          "rds:DescribeDBProxyTargetGroups",
          "rds:DescribeDBProxies",
          "rds:RegisterDBRPoxyTargets",
          "rds:DeregisterDBProxyTargets",
          "rds:ModifyDBProxyTargetGroup",
          "rds:ModifyDBPRoxy",
          "rds:AddTagsToResource",
          "rds:ListTagsForResource"
        ],
        "Resource" : [
          "arns:aws:rds:*:*:db-proxy:*-*"
        ],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "rds:CreateDBProxy",
          "rds:DeleteDBProxy",
          "rds:ModifyDBPRoxy",
          "rds:AddTagsToResource",
          "rds:ListTagsForResource"
        ],
        "Resource" : [
          "arns:aws:rds:*:*:target:*-*"
        ],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "rds:ModifyDBProxyTargetGroup",
          "rds:ListTagsForResource",
          "rds:DescribeDBProxyTargets",
          "rds:RegisterDBProxyTargets",
          "rds:DeregisterDBProxyTargets",
          "rds:AddTagsToResource",
          "rds:RemoveTagsFromResource"
        ],
        "Resource" : [
          "arns:aws:rds:*:*:target-group:*-*"
        ],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "rds:DescribeGlobalClusters"
        ],
        "Resource" : [
          "arns:aws:rds:*:*:global-cluster:*-*"
        ],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "iam:CreateServiceLinkRole"
        ],
        "Resource" : [
          "arn:aws:iam::*:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS"
        ],
        "Condition" : {
          "StringLike" : {
            "iam:AWSServiceName" : "rds.amazonaws.com"
          }
        }
        "Effect" : "Allow"
      }
    ]
  })
}

resource "aws_iam_role" "deployment_role" {
  description          = "description here"
  max_session_duration = 3600
  name                 = "${var.service_name}-deployment_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = "stsAssumeStatement"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "deployment_policy-attach-1" {
  role       = aws_iam_role.deployment_role.name
  policy_arn = aws_iam_policy.deployment_policy_1.arn
}