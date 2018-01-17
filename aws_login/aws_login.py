import os
import os.path
import sys
import boto3
import json
import requests
import argparse
import configparser
from botocore.exceptions import ClientError
import subprocess
from datetime import datetime


def execute_command(role, command):
    if "--profile" in command:
        print("ERROR: the command should NOT contain --profile, remove it and try again")
        exit(1)
    command = command+" --profile " + role 
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
    output = process.communicate()
    print(output[0].decode())


def chrome(link):
    command = '/usr/bin/open -a "/Applications/Google Chrome.app" "' + link + '"'
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
    output = process.communicate()


def assume_role_credentials(mfa_profile, role_profile):
    
    mfa_ak = read_credentials(mfa_profile)
    rba_ak = read_rba_config(role_profile)

    roleArn = 'arn:aws:iam::%s:role/%s' % (rba_ak['account_id'],
                                           rba_ak['role'])

    client = boto3.client(
        'sts',
        aws_access_key_id=mfa_ak['aws_access_key_id'],
        aws_secret_access_key=mfa_ak['aws_secret_access_key'],
        aws_session_token=mfa_ak['aws_session_token']
    )
    
    response = client.assume_role(
        RoleArn=roleArn,
        RoleSessionName=role_profile,
        DurationSeconds=3600
    )
    write_credentials(role_profile, response['Credentials'])


def read_rba_config(rba_config):
    filename = os.path.expanduser('~/.rba_config')
    if not os.path.isfile(filename):
        print("ERROR: ~/.rba_config does not exist")
        exit(1)
    config = configparser.ConfigParser()
    config.read(filename)

    if rba_config in config.sections():
        return config[rba_config]
    else:
        print("ERROR: profile not found in ~/.rba_config: " + rba_config)
        exit(1)


def read_credentials(profile):
    filename = os.path.expanduser('~/.aws/credentials')
    if not os.path.isfile(filename):
        print("ERROR: ~/.aws/credentials does not exist")
        exit(1)
    config = configparser.ConfigParser()
    config.read(filename)
    if profile in config.sections():
        return config[profile]
    else:
        print("INFO: profile not found in ~/.aws/credentials: " + profile)
        return []


def write_credentials(profile, credentials):
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
    config.set(profile, 'expiration', credentials['Expiration'].strftime('%Y-%m-%d %H:%M'))

    with open(filename, 'w') as fp:
        config.write(fp)


def check_and_set_mfa_session(profile):

    mfa_profile = profile+'_mfa'
    mfa_ak = read_credentials(profile+'_mfa')
    
    if 'expiration' in mfa_ak:
        expiration = datetime.strptime(mfa_ak['expiration'], '%Y-%m-%d %H:%M')
    else:
        expiration = datetime.utcnow()
    
    profile_ak = read_credentials(profile)

    if datetime.utcnow() >= expiration:
        client = boto3.client(
            'sts',
            aws_access_key_id=profile_ak['aws_access_key_id'],
            aws_secret_access_key=profile_ak['aws_secret_access_key']    
        )
        caller_id = client.get_caller_identity()
        mfa_arn = caller_id['Arn'].replace("user", "mfa")
        token_code = input("Enter MFA Token Code: ")
        
        response = client.get_session_token(
            DurationSeconds=86400,
            SerialNumber=mfa_arn,
            TokenCode=token_code
        )
        write_credentials(mfa_profile, response['Credentials'])


def generate_magic_link(profile, role_profile):

    profile_ak = read_credentials(profile)
    rba = read_rba_config(role_profile)

    roleArn = 'arn:aws:iam::%s:role/%s' % (rba['account_id'],
                                           rba['role'])

    token_code = input("Enter MFA Token Code: ")

    client = boto3.client(
        'sts',
        aws_access_key_id=profile_ak['aws_access_key_id'],
        aws_secret_access_key=profile_ak['aws_secret_access_key']
    )
    caller_id = client.get_caller_identity()
    mfa_arn = caller_id['Arn'].replace("user", "mfa")

    response = client.assume_role(
        RoleArn=roleArn,
        RoleSessionName=role_profile,
        DurationSeconds=3600,
        SerialNumber=mfa_arn,
        TokenCode=token_code
    )

    credentials = response['Credentials']

    session = json.dumps({'sessionId': credentials['AccessKeyId'],
                          'sessionKey': credentials['SecretAccessKey'],
                          'sessionToken': credentials['SessionToken']})
    
    r = requests.get("https://signin.aws.amazon.com/federation",
                     params={'Action': 'getSigninToken',
                             'SessionDuration': 43200,
                             'Session': session})
    signin_token = r.json()

    console = requests.Request('GET',
                               'https://signin.aws.amazon.com/federation',
                               params={'Action': 'login',
                                       'Issuer': 'Instruqt',
                                       'Destination': 'https://console.aws.amazon.com/',
                                       'SigninToken': signin_token['SigninToken']})
    prepared_link = console.prepare()
    return prepared_link.url


def main():
    if len(sys.argv) > 1:
        role_profile = sys.argv[1]
        command = ' '.join(sys.argv[2:])
    else:
        print("Use: ./aws-login rba_profile [command]")
        print("Example: ./aws-login admin@prod aws sts get-caller-identity")
        print("Example: ./aws-login admin@prod mc")
        print("Example: ./aws-login admin@prod keys")
        print("Example: ./aws-login admin@prod")
        exit(1)

    if "AWS_LOGIN_PROFILE" not in os.environ:
        profile = input("AWS_LOGIN_PROFILE not set, please enter the profile: ")
    else:
        profile = os.environ['AWS_LOGIN_PROFILE']

    mfa_profile = profile+'_mfa'
    check_and_set_mfa_session(profile)
    assume_role_credentials(mfa_profile, role_profile)
    if len(sys.argv) == 2:
        print('INFO: Session refreshed')
    elif sys.argv[2] == 'mc':
        link = generate_magic_link(profile, role_profile)
        chrome(link)
    elif sys.argv[2] == 'keys':
        temp_keys = read_credentials(role_profile)
        template = ('AWS_ACCESS_KEY_ID={} '
                    'AWS_SECRET_ACCESS_KEY={} '
                    'AWS_SESSION_TOKEN={} ')
        print(template.format(temp_keys['aws_access_key_id'],
                              temp_keys['aws_secret_access_key'],
                              temp_keys['aws_session_token']))
    else:
        execute_command(role_profile, command)

if __name__ == '__main__':
    main()
