'''listsecret.py - test program to list Azure key vault secrets'''
import json
import sys
from azure.keyvault import KeyVaultClient, KeyVaultAuthentication
from azure.common.credentials import ServicePrincipalCredentials

def main():
    # Load Azure app defaults
    try:
        with open('azurermconfig.json') as config_file:
            config_data = json.load(config_file)
    except FileNotFoundError:
        sys.exit("Error: Expecting azurermconfig.json in current folder")
    tenant_id = config_data['tenantId']
    app_id = config_data['appId']
    app_secret = config_data['appSecret']
    kv_name = config_data['keyvault']
    key_vault_uri = f'https://{kv_name}.vault.azure.net/'

    # get credentials
    credentials = ServicePrincipalCredentials(client_id=app_id,
                                              secret=app_secret,
                                              tenant=tenant_id)
    #token = credentials.token
    #print('Token is: ' + token['access_token'])
    
    # get a key vault client
    client = KeyVaultClient(credentials)

    # list the secrets
    secrets = client.get_secrets(key_vault_uri)
    print('Listing secrets')
    for secret_item in secrets:
        secret_name = secret_item.id.split('/secrets/', 1)[1]
        secret_bundle = client.get_secret(key_vault_uri, secret_name, '')
        print(f'{secret_name}: {secret_bundle.value}')


if __name__ == "__main__":
    main()