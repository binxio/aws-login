import os
import os.path
import sys
import boto3
import json
import requests
import argparse
import click
import configparser
from getpass import getpass
from botocore.exceptions import ClientError
import subprocess
from datetime import datetime

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.command(context_settings=CONTEXT_SETTINGS)
@click.argument('action', type=click.Choice(['start-mfa-session',
                                             'print-console',
                                             'open-console',
                                             'add-profile',
                                             'add',
                                             'mfa',
                                             'oc',
                                             'pc']))
@click.option('--source-profile', '-s', help='The source profile.')
@click.option('--target-profile', '-t', help='The target profile.')
@click.option('--role', '-r', help='The role to assume')
@click.option('--account-id', '-a', help='Account ID to assume the role')
@click.option('--verbose', '-v', is_flag=True, default=False, help='show verbose output.')
@click.option('--profile', '-p', help='Use this profile for mfa session or opening console.')
@click.option('--mfa-expiration', '-E', type=click.INT, default=3600,
              help='number of seconds after which the MFA credentials are no longer valid')
@click.option('--role-expiration', '-R', type=click.INT, default=900,
              help='number of seconds after which the role credentials are no longer valid')
@click.option('--console-expiration', '-C', type=click.INT, default=900,
              help='number of seconds after which the console credentials are no longer valid')
@click.option('--token', '-T', help='from your MFA device')
def main(action, source_profile, target_profile, role, account_id,
         verbose, mfa_expiration, role_expiration, profile,
         console_expiration, token):
    """
    Aws-login is an AWS Helper CLI for using Role Based Access, easy
    and securly open the management console with the command line.

    Actions:\n
    aws-login start-mfa-session, aws-login mfa\n
    aws-login add-profile, aws-login add\n
    aws-login open-console, aws-login oc\n
    aws-login print-console, aws-login pc\n
    """
    if verbose:
          sys.stderr.write('INFO: Action is {}\n'.format(action))

    """
    If --profile is given, and --source-profile or --target-profile
    is not given, source and target will be set to the --profile
    this is because the aws cli also uses --profile for similar
    actions. Therefore it's logical to use --profile.
    """
    if action in ['start-mfa-session', 'open-console', 'print-console',
                  'mfa', 'oc', 'pc']:
        if source_profile is None and profile is not None:
            source_profile = profile
        if target_profile is None and profile is not None:
            target_profile = profile

    """ Now set all the parameters in the object login """
    login = AWSLogin()
    login.mfa_expiration = mfa_expiration
    login.role_expiration = role_expiration
    login.console_expiration = console_expiration
    login.token = token
    login.source_profile = source_profile
    login.target_profile = target_profile
    login.role = role
    login.account_id = account_id

    if action in ['start-mfa-session', 'mfa']:
        login.start_mfa_session()
    elif action in ['open-console', 'oc']:
        login.open_magic_link()
    elif action in ['print-console', 'pc']:
        login.print_magic_link()
    elif action in ['add-profile', 'add']:
        if (role is not None and
            source_profile is not None and
            account_id is not None and
            target_profile is not None):
                login.add_profile()
        else:
            print('ERROR: "aws-login add-profile" requires --source-profile, --target-profile, --role and --account-id')
            exit(1)


class AWSLogin(object):

    def __init__(self, verbose=False):
        """
        Aws-login is an AWS Helper CLI for using Role Based Access, easy
        and securly open the management console with the command line.
        """
        self.aws_credentials = '~/.aws/credentials'
        self.aws_config = '~/.aws/config'
        self.verbose = verbose
        self.role = None
        self.account_id = None
        self.source_profile = None
        self.target_profile = None
        self.mfa_expiration = 3600
        self.role_expiration = 3600
        self.console_expiration = 3600
        self.token = None

    def start_mfa_session(self):
        """
        This function starts an mfa session and writes the access keys
        to the credentials file of boto3 and aws cli are using so they
        can be used natively in future commands. In case the current
        session is not expired, the old one is reused (saves typing 
        the MFA. Shorter expiration is more secure though.)
        """

        self.start_aws_connections()

        """
        If --profile is given, and/or --source-profile and 
        --target-profile are identical, the target profile is
        overwritten with the default _mfa suffix.
        """
        if self.source_profile == self.target_profile:
            self.target_profile = self.source_profile + '_mfa'

        creds = get_section(self.aws_credentials, self.source_profile)

        if 'aws_access_key_id' not in creds:
            print("ERROR: Profile {} not found.".format(self.source_profile))
            exit(1)

        target_creds = get_section(self.aws_credentials, self.target_profile)

        if profile_expired(target_creds):
            mfa_serial = self.get_mfa_serial()
            self.ask_user_for_token(mfa_serial)

            try:
                response = self.sts.get_session_token(
                    DurationSeconds=self.mfa_expiration,
                    SerialNumber=mfa_serial,
                    TokenCode=str(self.token)
                )
            except ClientError as e:
                print("ERROR: {}".format(e))
                exit(1)

            credentials = response['Credentials']
            session = {
                'aws_access_key_id': credentials['AccessKeyId'],
                'aws_secret_access_key': credentials['SecretAccessKey'],
                'aws_session_token': credentials['SessionToken'],
                'expiration': credentials['Expiration']
            }
            set_credentials_section(self.aws_credentials,
                                    self.target_profile,
                                    **session)
        else:
            warning = 'INFO: Profile {} is not expired.'
            print(warning.format(self.target_profile))

    def get_magic_link(self):
        """
        This script generates a magic link to access the
        management console without having to go through the
        regular login procedure which takes a couple of seconds
        """
        if (self.source_profile is not None and
            self.account_id is not None and
            self.role is not None and
            self.target_profile is None):

                creds = get_section(self.aws_credentials, self.source_profile)
                if 'expiration' in creds:
                    message = ("ERROR: Specified Profile {} is an MFA session. "
                               "Use the origin.")
                    print(message.format(self.source_profile))
                    exit(1)

                self.start_aws_connections()
                username = self.get_username()
                mfa_serial = self.get_mfa_serial()
                arn_tmpl = 'arn:aws:iam::{}:role/{}'
                role_arn = arn_tmpl.format(self.account_id, self.role)
                session_name = '{}-{}'.format(username, self.role)
        elif (self.target_profile is not None and
              self.account_id is None and
              self.role is None):
                    configsection = get_section(self.aws_config,
                                                'profile ' + self.target_profile)
                    if 'role_arn' not in configsection:
                        message = "ERROR: Profile {} not found."
                        print(message.format(self.target_profile))
                        exit(1)

                    self.source_profile = configsection['source_profile']
                    self.start_aws_connections()
                    session_name = '{}'.format(self.target_profile)
                    mfa_serial = configsection['mfa_serial']
                    role_arn = configsection['role_arn']
        else:
            print('The given combination of parameters is not valid.')
            print('The following combination of parameters are allowed:')
            print('aws-login open-console -p profile')
            print('aws-login open-console -t profile')
            print('aws-login open-console -s source_profile -a 123123 -r admin')
            exit(1)

        self.ask_user_for_token(mfa_serial)

        try:
            response = self.sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=self.role_expiration,
                SerialNumber=mfa_serial,
                TokenCode=str(self.token)
            )
        except ClientError as e:
            print("ERROR: {}".format(e))
            exit(1)

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

    def print_magic_link(self):
        """
        This function just generates the magic link and then
        prints it out so users can copy and paste it to their
        favorite browser or do whatever they would like to.
        """
        link = self.get_magic_link()
        print(link)

    def open_magic_link(self):
        """
        This function generates the magic link and opens it with
        the default open command. Mac OS will find the default browser
        and uses this to log in.
        """
        link = self.get_magic_link()
        open_link(link)

    def add_profile(self):
        """
        This function is used to start a session using the regular
        access keys and the token code provided. It can then be used
        to access services which requires the condition MFA
        """
        self.start_aws_connections()
        username = self.get_username()
        mfa_serial = self.get_mfa_serial()
        account_id = self.get_account_id()
        arn_tmpl = 'arn:aws:iam::{}:role/{}'
        role_arn = arn_tmpl.format(self.account_id, self.role)
        kwargs = {
            'role_arn': role_arn,
            'mfa_serial': mfa_serial,
            'source_profile': self.source_profile
        }
        set_config_section(self.aws_config,
                           'profile ' + self.target_profile,
                           **kwargs)
        message = "INFO: now use --profile {} in future aws cli commands"
        print(message.format(self.target_profile))

    def get_account_id(self):
        """ returns the account id associated with the login """
        response = self.sts.get_caller_identity()
        return response['Account']

    def ask_user_for_token(self, mfa_serial):
        """ returns the token code if valid entered by user """
        message = "Enter MFA code for {}:".format(mfa_serial)
        if self.token is None:
            self.token = getpass(message)
        if len(self.token) != 6:
            print("ERROR: token code is not 6 characters")
            exit(1)

    def get_username(self):
        """ returns the username associated with the login """
        response = self.sts.get_caller_identity()
        username = response['Arn'].split('/')[1]
        return username

    def get_mfa_serial(self):
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

    def start_aws_connections(self):
        """
        To start aws connections, source_profile must be set and access keys
        must be valid. In case a condition of the role requires an mfa session
        the source profile given must be an mfa session.
        """
        self.set_aws_client('iam')
        self.set_aws_client('sts')

    def set_aws_client(self, aws_client):
        """
        Initiates the sts client for future use using the source profile
        access keys.
        """
        access_keys = get_section(self.aws_credentials, self.source_profile)
        
        if len(access_keys) == 0:
            print("ERROR: profile {} not found.".format(self.source_profile))
            exit(1)

        kwargs = {
            'aws_access_key_id': access_keys['aws_access_key_id'],
            'aws_secret_access_key': access_keys['aws_secret_access_key']
        }
        if 'aws_session_token' in access_keys:
            kwargs['aws_session_token'] = access_keys['aws_session_token']
        if aws_client == 'sts':
            self.sts = boto3.client('sts', **kwargs)
        else:
            self.iam = boto3.client('iam', **kwargs)


def set_credentials_section(file, section, **kwargs):
    """
    This function writes the kwargs to the file specified. In most
    cases this is just ~/.aws/credentials because this is default.
    """
    filename = os.path.expanduser(file)
    dirname = os.path.dirname(filename)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    config = configparser.ConfigParser()
    config.read(filename)
    if not config.has_section(section):
        config.add_section(section)
    config.set(section, 'aws_access_key_id', kwargs['aws_access_key_id'])
    config.set(section, 'aws_secret_access_key', kwargs['aws_secret_access_key'])
    config.set(section, 'aws_session_token', kwargs['aws_session_token'])
    if 'expiration' in kwargs:
        config.set(section, 'expiration', kwargs['expiration'].strftime('%Y-%m-%d %H:%M'))
    with open(filename, 'w') as fp:
        config.write(fp)


def set_config_section(file, section, **kwargs):
    """
    Role profiles are written to a config file, most common is
    ~/.aws/config.
    """
    filename = os.path.expanduser(file)
    dirname = os.path.dirname(filename)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    config = configparser.ConfigParser()
    config.read(filename)
    if not config.has_section(section):
        config.add_section(section)
    config.set(section, 'role_arn', kwargs['role_arn'])
    config.set(section, 'source_profile', kwargs['source_profile'])
    config.set(section, 'mfa_serial', kwargs['mfa_serial'])
    with open(filename, 'w') as fp:
        config.write(fp)


def get_section(file, section):
    """
    A default reader for config files, which applies to
    ~/.aws/credentials and ~/.aws/config. In case a section
    is not found, it will return an empty dict.
    """
    filename = os.path.expanduser(file)
    if not os.path.isfile(filename):
        print("ERROR: {} does not exist".format(file))
        sys.exit(1)
    config = configparser.ConfigParser()
    config.read(filename)
    if section in config.sections():
        return config[section]
    else:
        return {}


def profile_expired(credentials):
    """ Simple function to check if the expiration is expired true or false """
    if 'expiration' in credentials:
        expiration = datetime.strptime(credentials['expiration'], '%Y-%m-%d %H:%M')
        return datetime.utcnow() >= expiration
    else:
        return True


def open_link(link):
    """ Simple function to open the given link """
    command = '/usr/bin/open "' + link + '"'
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
    output = process.communicate()

if __name__ == '__main__':
    main()
