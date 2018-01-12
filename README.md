**\*\* THIS IS WORK IN PROGRESS \*\***

Things might break, are not fully tested, refactoring should happen, features should be added.

# AWS Login for Role Based Access in AWS

This tool could be used to secure and automate the execution of aws cli.

## Usage

```
./aws-login admin@prod aws sts get-caller-identity
AWS_LOGIN_PROFILE not set, please enter the profile: mypersonalprofile
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
export AWS_LOGIN_PROFILE=mypersonalprofile
```

## Make an alias

```
alias aws-login='./aws-login'
```

## Try some commands

Check your identity:

```
aws-login test@prod aws sts get-caller-identity
{
    "Account": "1234567890",
    "UserId": "AELWEHRWJKEHRLKWERHLWEK:admin@prod",
    "Arn": "arn:aws:sts::1234567890:assumed-role/testRole/admin@prod"
}
```

Show your buckets:

```
aws-login test@prod aws s3 ls
2018-01-09 10:48:12 thiscouldbeoneofyourbuckets
```

You'll get an error if you don't have access:

```
aws-login test@prod aws ec2 describe-instances --region eu-west-1
An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation: You are not authorized to perform this operation.
```

Open chrome with the management console. This is work in progress, as it currently only support Chrome on a Mac. It also requires a new MFA session.

```
aws-login test@prod mc
Enter MFA Token Code: 123456
```

And just refresh the session for example. Best practice here is that your personal account has no access, except to assume a role with MFA required. Your software running locally, uses the AWS credentials profile: developer@dev. After the refresh is done, it has the exact permissions for a limited amount of time. Abuse of access keys is limited to the max.

```
aws-login developer@dev
Enter MFA Token Code: 123456
Session refreshed
```

You could also generate the keys and export them to use in all next commands. 

```
aws-login test@prod keys
AWS_ACCESS_KEY_ID=ASDSFSDFSDFSDFSDFSDF 
AWS_SECRET_ACCESS_KEY=DSGSDGSDGFSDFSDFSDFSDFSDFSDF 
AWS_SESSION_TOKEN=DFSDFSDFSDFSDFSDFSDFSDFSDF
```

Make sure your session is not expired.

```
aws-login test@prod
Enter MFA Token Code: 123456
export $(./aws-login test@prod keys)
aws sts get-caller-identity
{
    "Account": "1234567890",
    "UserId": "AELWEHRWJKEHRLKWERHLWEK:test@prod",
    "Arn": "arn:aws:sts::1234567890:assumed-role/testRole/admin@prod"
}
```