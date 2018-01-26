A simple command line utility to login to AWS accounts using role based access and the secure token service.


**Options**

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

**Example**




