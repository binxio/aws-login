import os
import os.path
import sys
import boto3
import json
import requests
import argparse
import click
import configparser
from botocore.exceptions import ClientError
import subprocess
from datetime import datetime


class AWSLogin(object):

    def __init__(self, verbose=False):
        self.verbose = verbose
        self._sts = None
        self._iam = None
        self.profile = None
        self.login_profile = None
        self.login_credentials = {}
        self.mfa_expiration = 3600
        self.role_expiration = 900
        self.console_expiration = 900
        self.token = None

    def read_login_credentials(self):
        if self.login_profile == 'login' and self.profile != 'default':
            saved_login_profile = read_credentials(self.profile, self.verbose)
            self.login_profile = saved_login_profile['source_profile']
        self.login_credentials = read_credentials(self.login_profile, self.verbose)
        if len(self.login_credentials) == 0:
            sys.stderr.write('ERROR: no credentials found in profile "{}"\n'.format(self.login_profile))
            sys.exit(1)

    @property
    def sts(self):
        if self._sts is None:
            creds = self.login_credentials
            kwargs = {'aws_access_key_id': creds['aws_access_key_id'],
                      'aws_secret_access_key': creds['aws_secret_access_key']}

            if 'aws_session_token' in creds:
                kwargs['aws_session_token'] = creds['aws_session_token']

            self._sts = boto3.client('sts', **kwargs)
        return self._sts

    @property
    def iam(self):
        if self._iam is None:
            creds = self.login_credentials
            kwargs = {'aws_access_key_id': creds['aws_access_key_id'],
                      'aws_secret_access_key': creds['aws_secret_access_key']}

            if 'aws_session_token' in creds:
                kwargs['aws_session_token'] = creds['aws_session_token']

            self._iam = boto3.client('iam', **kwargs)
        return self._iam

    def get_account_id(self):
        """ returns the account id associated with the login """
        response = self.sts.get_caller_identity()
        return response['Account']

    def get_username(self):
        """ returns the username associated with the login """
        response = self.sts.get_caller_identity()
        self.username = response['Arn'].split('/')[1]
        return self.username

    def get_mfa_serial_number(self):
        """ returns the mfa serial number associated with the login """
        username = self.get_username()
        response = self.iam.list_mfa_devices(UserName=username)
        devices = response['MFADevices']
        if len(devices) > 0:
            self.mfa_serial_number = response['MFADevices'][0]['SerialNumber']
            if (len(devices) > 1):
                sys.stderr.write('WARN: multiple MFA device found for user "{}", using first.'.format(username))
        else:
            sys.stderr.write('ERROR: no MFA device found for user "{}"'.format(username))
            sys.exit(1)
        return self.mfa_serial_number

    def assume_role_credentials(self, role, account_id):
        credentials = read_credentials(self.profile, self.verbose)
        expired = profile_expired(credentials)

        if role is not None:
            if account_id is None:
                account_id = self.get_account_id()
            role_arn = 'arn:aws:iam::%s:role/%s' % (account_id, role)
            expired = True
        else:
            if 'assume_role_arn' in credentials:
                role_arn = credentials.get('assume_role_arn')
            else:
                sys.stderr.write('INFO: no role specified. please specify --role and --account-id\n')
                return

        if expired:
            #TODO: We need to establish a sts client with MFA session keys!
            creds = read_credentials(self.login_profile + '_mfa', self.verbose)
            kwargs = {'aws_access_key_id': creds['aws_access_key_id'],
                      'aws_secret_access_key': creds['aws_secret_access_key'],
                      'aws_session_token': creds['aws_session_token']}
            sts = boto3.client('sts', **kwargs)
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName='{}-{}'.format(self.get_username(), self.profile),
                DurationSeconds=3600
            )
            write_credentials(self.profile, response['Credentials'], role_arn, self.login_profile)
            if self.verbose:
                sys.stderr.write('INFO: refreshed credentials for "{}"\n'.format(self.profile))
        else:
            if self.verbose:
                sys.stderr.write('INFO: credentials for "{}" are still valid\n'.format(self.profile))

    def check_and_set_mfa_session(self):

        mfa_profile = self.login_profile + '_mfa'
        creds = read_credentials(mfa_profile, self.verbose)

        if profile_expired(creds):
            serial_number = self.get_mfa_serial_number()
            token_code = input("Enter MFA Token Code: ")
            response = self.sts.get_session_token(
                DurationSeconds=self.mfa_expiration,
                SerialNumber=serial_number,
                TokenCode=str(token_code)
            )
            write_credentials(mfa_profile, response['Credentials'])
            if self.verbose:
                sys.stderr.write('INFO: refreshed credentials for "{}" in "{}"\n'.format(self.login_profile, mfa_profile))
        else:
            if self.verbose:
                sys.stderr.write('INFO: credentials for "{}" in "{}" are still valid\n'.format(self.login_profile, mfa_profile))

    def generate_magic_link(self):
        profile = read_credentials(self.profile,  self.verbose)
        role_arn = profile['assume_role_arn']
        token = self.token if self.token is not None else input("Enter MFA Token Code:")

        username = self.get_username()
        mfa_arn = self.get_mfa_serial_number()


        #  creds = read_credentials(self.login_profile + '_mfa', self.verbose)
        # kwargs = {'aws_access_key_id': creds['aws_access_key_id'],
        #             'aws_secret_access_key': creds['aws_secret_access_key'],
        #             'aws_session_token': creds['aws_session_token']}
        # sts = boto3.client('sts', **kwargs)
        # response = sts.assume_role(
        response = self.sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='{}-{}'.format(username, self.profile),
            DurationSeconds=self.role_expiration,
            SerialNumber=mfa_arn,
            TokenCode=str(token)
        )

        credentials = response['Credentials']

        session = json.dumps({'sessionId': credentials['AccessKeyId'],
                              'sessionKey': credentials['SecretAccessKey'],
                              'sessionToken': credentials['SessionToken']})

        r = requests.get("https://signin.aws.amazon.com/federation",
                         params={'Action': 'getSigninToken',
                                 'SessionDuration': self.console_expiration,
                                 'Session': session})
        signin_token = r.json()

        console = requests.Request('GET',
                                   'https://signin.aws.amazon.com/federation',
                                   params={'Action': 'login',
                                           'Issuer': 'awslogin',
                                           'Destination': 'https://console.aws.amazon.com/',
                                           'SigninToken': signin_token['SigninToken']})
        prepared_link = console.prepare()
        return prepared_link.url

    def show_keys(self):
        creds = read_credentials(self.profile,  self.verbose)
        sys.stdout.write('export AWS_ACCESS_KEY_ID={}\n'.format(creds['aws_access_key_id']))
        sys.stdout.write('export AWS_SECRET_ACCESS_KEY={}\n'.format(creds['aws_secret_access_key']))
        if 'aws_session_token' in creds:
            sys.stdout.write('export AWS_SESSION_TOKEN="{}"\n'.format(creds['aws_session_token']))
        else:
            sys.stdout.write('unset AWS_SESSION_TOKEN\n')


@click.command()
@click.option('--login-profile', '-l', help='to use to login to AWS')
@click.option('--profile', '-p', help='to update the AWS access credentials for, defaults to $AWS_DEFAULT_PROFILE')
@click.option('--role', '-r', help='to assume in the account.')
@click.option('--account-id', '-a', help='to assume to role in. If specified, --role is required.')
@click.option('--console', '-c', is_flag=True, default=False, help='open AWS management console.')
@click.option('--keys', '-k', is_flag=True, default=False, help='show keys as environment variables.')
@click.option('--magic-link', '-m', is_flag=True, default=False, help='show link to AWS management console.')
@click.option('--verbose', '-v', is_flag=True, default=False, help='show verbose output.')
@click.option('--mfa-expiration', '-E', type=click.INT, default=3600,
              help='number of seconds after which the MFA credentials are no longer valid')
@click.option('--role-expiration', '-R', type=click.INT, default=900,
              help='number of seconds after which the role credentials are no longer valid')
@click.option('--console-expiration', '-C', type=click.INT, default=900,
              help='number of seconds after which the console credentials are no longer valid')
@click.option('--token', '-t', help='from your MFA device')
@click.argument('args', nargs=-1)
def main(
        login_profile, profile, role, account_id, console, magic_link, keys, verbose, mfa_expiration, role_expiration,
        console_expiration, token, args):
    """
    single sign-on login using MFA, role based access and the secure token service.

    """
    if login_profile is None:
        login_profile = os.getenv('AWS_DEFAULT_LOGIN_PROFILE', 'login')

    if profile is None:
        if len(args) > 0:
            profile = args[0]
            args = args[1:]
        else:
            profile = os.getenv('AWS_DEFAULT_PROFILE', 'default')

    if profile == login_profile:
        sys.stderr.write('ERROR: --profile and --login-profile must be different\n')
        sys.exit(1)

    try:
        login = AWSLogin(verbose=verbose)

        login.mfa_expiration = mfa_expiration
        login.role_expiration = role_expiration
        login.console_expiration = console_expiration
        login.token = token
        login.profile = profile
        login.login_profile = login_profile

        login.read_login_credentials()
        login.check_and_set_mfa_session()
        login.assume_role_credentials(role, account_id)

    except ClientError as e:
        sys.stderr.write('{}'.format(e))
        sys.exit(1)

    if console or magic_link:
        link = login.generate_magic_link()
        if magic_link:
            sys.stdout.write('{}\n'.format(link))
        if console:
            chrome(link)

    if keys:
        login.show_keys()

    if len(args) > 0:
        execute_command(profile, list(args))


def execute_command(profile, command):
    env = os.environ.copy()
    env['AWS_DEFAULT_PROFILE'] = profile
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    output = process.communicate()
    sys.stdout.write(output[0].decode())
    sys.stdout.write(output[1].decode())
    if process.returncode != 0:
        sys.exit(process.returncode)


def chrome(link):
    command = '/usr/bin/open "' + link + '"'
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
    output = process.communicate()


def read_credentials(profile, verbose=False):
    filename = os.path.expanduser('~/.aws/credentials')
    if not os.path.isfile(filename):
        print("ERROR: ~/.aws/credentials does not exist")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(filename)
    if profile in config.sections():
        return config[profile]
    else:
        if verbose:
            sys.stderr.write('INFO: profile "{}" not found in ~/.aws/credentials: '.format(profile))
        return {}


def profile_expired(credentials):
    if 'expiration' in credentials:
        expiration = datetime.strptime(credentials['expiration'], '%Y-%m-%d %H:%M')
        return datetime.utcnow() >= expiration
    else:
        return True


def write_credentials(profile, credentials, role_arn=None, source_profile=None):
    filename = os.path.expanduser('~/.aws/credentials')
    dirname = os.path.dirname(filename)

    if not os.path.exists(dirname):
        os.makedirs(dirname)

    config = configparser.ConfigParser()
    config.read(filename)
    if not config.has_section(profile):
        config.add_section(profile)
    config.set(profile, 'aws_access_key_id', credentials['AccessKeyId'])
    config.set(profile, 'aws_secret_access_key', credentials['SecretAccessKey'])
    config.set(profile, 'aws_session_token', credentials['SessionToken'])

    if role_arn is not None:
        config.set(profile, 'assume_role_arn', role_arn)

    if 'Expiration' in credentials:
        config.set(profile, 'expiration', credentials['Expiration'].strftime('%Y-%m-%d %H:%M'))
    elif 'expiration' in config:
        del config['expiration']

    if source_profile is not None:
        config.set(profile, 'source_profile', source_profile)
    elif 'source_profile' in config:
        del config['expiration']

    with open(filename, 'w') as fp:
        config.write(fp)


if __name__ == '__main__':
    main()
