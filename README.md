**\*\* THIS IS WORK IN PROGRESS \*\***

Things might break, are not fully tested, refactoring should happen, features should be added.

# AWS Role Based Access Wrapper

This tool could be used to secure and automate the execution of aws cli.

## Usage

```
.aws-login.py admin@prod aws sts get-caller-identity
AWS_RBA_WRAPPER_USER not set, please enter the profile: mypersonalprofile
Enter MFA Token Code: 123456
{
    "Account": "1234567890",
    "UserId": "AELWEHRWJKEHRLKWERHLWEK:admin@prod",
    "Arn": "arn:aws:sts::1234567890:assumed-role/testRole/admin@prod"
}
```

## Prepare your account

Deploy the terraform stack, which is a test role which can only be assumed with an MFA session. You need to have a profile in ~/.aws/credentials with sufficient permissions to deploy.

```
terraform init
terraform apply
```

## Create ~/.rba_config

Create `~/.rba_config and add the role you just created with terraform, or manually.

```
[test@prod]
account_id = 123123123123
role = testRole
```

## Set wrapper profile

```
export AWS_RBA_WRAPPER_USER=mypersonalprofile
```

## Make an alias

```
alias rba='./aws-login'
```

## Try some commands

Check your identity:

```
rba test@prod aws sts get-caller-identity
{
    "Account": "1234567890",
    "UserId": "AELWEHRWJKEHRLKWERHLWEK:admin@prod",
    "Arn": "arn:aws:sts::1234567890:assumed-role/testRole/admin@prod"
}
```

Show your buckets:

```
rba test@prod aws s3 ls
2018-01-09 10:48:12 thiscouldbeoneofyourbuckets
```

You'll get an error if you don't have access:

```
rba test@prod aws ec2 describe-instances --region eu-west-1
An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation: You are not authorized to perform this operation.
```

Open chrome with the management console. This is work in progress, as it currently only support Chrome on a Mac. It also requires a new MFA session.

```
rba test@prod mc
Enter MFA Token Code: 123456
```