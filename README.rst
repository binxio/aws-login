A simple command line utility to login to AWS accounts using role based access and the secure token service.


**Options**

Usage: aws-login [OPTIONS] [ARGS]...

  single sign-on login using MFA, role based access and the secure token
  service.

Options:
  -l, --login-profile TEXT        to use to login to AWS
  -p, --profile TEXT              to update the AWS access credentials for,
                                  defaults to $AWS_DEFAULT_PROFILE
  -r, --role TEXT                 to assume in the account.
  -a, --account-id TEXT           to assume to role in. If specified, --role
                                  is required.
  -c, --console                   open AWS management console.
  -k, --keys                      show keys as environment variables.
  -m, --magic-link                show link to AWS management console.
  -v, --verbose                   show verbose output.
  -E, --mfa-expiration INTEGER    number of seconds after which the MFA
                                  credentials are no longer valid
  -R, --role-expiration INTEGER   number of seconds after which the role
                                  credentials are no longer valid
  -C, --console-expiration INTEGER
                                  number of seconds after which the console
                                  credentials are no longer valid
  -t, --token TEXT                from your MFA device
  --help                          Show this message and exit.



**Example**


