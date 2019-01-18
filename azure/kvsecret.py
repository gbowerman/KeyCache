'''kvsecret.py - test program to create and get Azure key vault secrets'''
import argparse
import json
import sys

from azure.common.credentials import ServicePrincipalCredentials
from azure.keyvault import KeyVaultAuthentication, KeyVaultClient

def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        '--name', '-n', action='store', help='secret name to add')
    arg_parser.add_argument(
        '--value', '-v', action='store', help='secret value to add')
    arg_parser.add_argument(
        '--delete', '-d', action='store', help='secret name to delete')
    arg_parser.add_argument(
        '--keyvault', '-k', action='store', help='key vault name')

    args = arg_parser.parse_args()
    if args.name is None and args.delete is None:
        sys.exit('Error: --name (-n) or --delete (-d) argument not provided.')

    # Load Azure app defaults
    try:
        with open('azurermconfig.json') as config_file:
            config_data = json.load(config_file)
    except FileNotFoundError:
        sys.exit("Error: Expecting azurermconfig.json in current folder")
    tenant_id = config_data['tenantId']
    app_id = config_data['appId']
    app_secret = config_data['appSecret']
    if args.keyvault is None:
        kv_name = config_data['keyvault']
    else:
        kv_name = args.keyvault
    key_vault_uri = f'https://{kv_name}.vault.azure.net/'

    # get credentials
    credentials = ServicePrincipalCredentials(client_id=app_id,
                                              secret=app_secret,
                                              tenant=tenant_id)
    
    # instantiate a key vault client
    client = KeyVaultClient(credentials)

    try:
        if args.value is not None: # add a secret
            secret_bundle = client.set_secret(key_vault_uri, args.name, args.value)
            print('Secret added:', secret_bundle.id)
        elif args.delete is not None: # delete a secret
            client.delete_secret(key_vault_uri, args.delete)
            print('Secret deleted:', args.delete)
        else: # get a secret
            secret = client.get_secret(key_vault_uri, args.name, '')
            print(secret.value)
    except Exception as ex:
        print(ex)


if __name__ == "__main__":
    main()
