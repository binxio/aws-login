**\*\* THIS IS WORK IN PROGRESS \*\***

Things might break, are not fully tested, refactoring should happen, features should be added.

# Intro

This tool helps to easily start MFA sessions for AWS CLI, easily use Role Based Access in AWS CLI and easily open the Management Console of AWS from the command line.
# Installation

```
pip install awscli aws-login --upgrade
```

# Usage

## Help

```
Usage: aws_login [OPTIONS] ACTION

  Aws-login is an AWS Helper CLI for using Role Based Access, easy and
  securly open the management console with the command line.

  Actions:

  aws-login start-mfa-session, aws-login mfa

  aws-login add-profile, aws-login add

  aws-login open-console, aws-login oc

  aws-login print-console, aws-login pc

Options:
  -s, --source-profile TEXT       The source profile.
  -t, --target-profile TEXT       The target profile.
  -r, --role TEXT                 The role to assume
  -a, --account-id TEXT           Account ID to assume the role
  -v, --verbose                   show verbose output.
  -p, --profile TEXT              Use this profile for mfa session or opening
                                  console.
  -E, --mfa-expiration INTEGER    number of seconds after which the MFA
                                  credentials are no longer valid
  -R, --role-expiration INTEGER   number of seconds after which the role
                                  credentials are no longer valid
  -C, --console-expiration INTEGER
                                  number of seconds after which the console
                                  credentials are no longer valid
  -T, --token TEXT                from your MFA device
  -h, --help                      Show this message and exit.
```

## Start an MFA Session

In this example the profile 'werner' is added with `aws configure --profile werner`.

```
$ aws-login start-mfa-session --profile werner
Enter MFA code for arn:aws:iam:: 123123123123:mfa/werner: 123456
$ aws s3 mb s3://testbucketbywerner --profile werner_mfa
make_bucket: testbucketbywerner
```

## Add profile for RBA

$ aws-login add-profile --source-profile werner \
                        --target-profile admin@prod \
                        --account-id 123123123123 \
                        --role admin
INFO: now use --profile admin@prod in future aws cli commands

$ aws s3 ls --profile admin@prod
Enter MFA code for arn:aws:iam:: 123123123123:mfa/werner: 123456
this-bucket-is-production
this-bucket-is-production-too

## Open the Management Console

```
$ aws-login open-console --profile admin@prod
Enter MFA code for arn:aws:iam:: 123123123123:mfa/werner: 123456
(opens the default browser with a magic link, immediately logged in)
```

## Shortcuts

If you don't like typing, these commands are helpful:

```
$ alias awsl='aws-login'
$ awsl oc -p readonly@prod
$ awsl mfa -p admin@dev
$ awsl ap -s <> -t <> -a <> -r <>
```

