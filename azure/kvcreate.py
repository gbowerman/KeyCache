'''kvcreate.py - create an Azure key vault'''
import argparse
import json
import sys
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from azure.graphrbac import GraphRbacManagementClient


def get_object_id(app_id, app_secret, tenant_id):
    '''Get the service principal object ID from Microsoft Graph'''
    # get Graph credentials
    credentials = ServicePrincipalCredentials(client_id=app_id,
                                              secret=app_secret,
                                              tenant=tenant_id,
                                              resource='https://graph.windows.net')
    graph_client = GraphRbacManagementClient(credentials, tenant_id)
    result = list(graph_client.service_principals.list(
        filter="servicePrincipalNames/any(c:c eq '{}')".format(app_id)))
    if result:
        return result[0].object_id
    else:
        print('Unable to get object_id from client_id')
        return None


def main():
    '''Main routine'''
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        '--name', '-n', action='store', help='secret name')
    arg_parser.add_argument(
        '--delete', '-d', action='store', help='delete value')
    arg_parser.add_argument(
        '--group', '-g', action='store', required=True, help='delete value')
    arg_parser.add_argument(
        '--location', '-l', action='store', help='delete value')

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
    subscription_id = config_data['subscriptionId']

    # get Azure credentials
    credentials = ServicePrincipalCredentials(client_id=app_id,
                                              secret=app_secret,
                                              tenant=tenant_id)
    kv_client = KeyVaultManagementClient(credentials, subscription_id)

    try:
        if args.name is not None:
            if args.location is None:
                sys.exit('Error: --location argument required to create vault')
            # get object id and create the vault
            object_id = get_object_id(app_id, app_secret, tenant_id)
            vault = kv_client.vaults.create_or_update(
                args.group,
                args.name,
                {
                    'location': args.location,
                    'properties': {
                        'sku': {
                            'name': 'standard'
                        },
                        'tenant_id': tenant_id,
                        'access_policies': [{
                            'tenant_id': tenant_id,
                            'object_id': object_id,
                            'permissions': {
                                'keys': ['all'],
                                'secrets': ['all']
                            }
                        }]
                    }
                }
            )
            print(f'Key vault: {args.name} created.')
        elif args.delete is not None:
            ret = kv_client.vaults.delete(args.group, args.delete)
            print(f'Key vault: {args.delete} deleted.')
    except Exception as ex:
        print(ex)            


if __name__ == "__main__":
    main()
