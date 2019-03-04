import boto3
import json
import requests
import urllib3
import subprocess
import time
import random
import paramiko
from dynamo_lock import LockerClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DEFAULT_HEADER = {"content-type": "application/json"}

# return ec2 instance relevant data:
# keyPair_name, instance_address, platform
def get_ec2_details(instanceId, context):
    try:
        ec2Resource = boto3.resource('ec2')
        instanceResource = ec2Resource.Instance(instanceId)
        instanceImage = ec2Resource.Image(instanceResource.image_id)
        imageDescription = instanceImage.description
    except Exception as e:
        print('Error on getting instance details: {0}'.format(e))
        raise e

    #  We take the instance address in the order of: public dns -> public ip -> private ip ##
    if instanceResource.private_ip_address:
        address = instanceResource.private_ip_address
    else:  # unable to retrieve address from aws
        address = None
    try:
        awsAccountId = context.invoked_function_arn.split(':')[4]
    except Exception:
        print("AWS account Id wasn't found")
        awsAccountId = ""

    if not imageDescription:
        raise Exception("Determining OS type failed")
    details = dict()
    details['key_name'] = instanceResource.key_name
    details['address'] = address

    details['aws_account_id'] = awsAccountId
    details['image_description'] = imageDescription
    return details


def call_rest_api_post(url, request, header):

    try:
        restResponse = requests.post(url, data=request, timeout=30, verify=False, headers=header, stream=True)
    except Exception:
        print("Error occurred during POST request to PVWA")
        return None
    return restResponse


# performs logon to PVWA and return the session token
def logon_pvwa(username, password, pvwaUrl, connectionSessionId):
    print('Start Logon to PVWA REST API')
    logonUrl = '{0}/API/auth/Cyberark/Logon'.format(pvwaUrl)
    restLogonData = """{{
        "username": "{0}",
        "password": "{1}",
        "connectionNumber": "{2}"
        }}""".format(username, password, connectionSessionId)
    try:
        restResponse = call_rest_api_post(logonUrl, restLogonData, DEFAULT_HEADER)
    except Exception:
        raise Exception("Error occurred on Logon to PVWA")

    if not restResponse:
        print("Connection to PVWA reached timeout")
        raise Exception("Connection to PVWA reached timeout")
    if restResponse.status_code == requests.codes.ok:
        jsonParsedResponse = restResponse.json()
        print("User authenticated")
        return jsonParsedResponse
    else:
        print("Authentication failed to REST API")
        raise Exception("Authentication failed to REST API")


def logoff_pvwa(pvwaUrl, connectionSessionToken):
    print('Start Logoff to PVWA REST API')
    header = DEFAULT_HEADER
    header.update({"Authorization": connectionSessionToken})
    logoffUrl = '{0}/API/auth/Logoff'.format(pvwaUrl)
    restLogoffData = ""
    try:
        restResponse = call_rest_api_post(logoffUrl, restLogoffData, DEFAULT_HEADER)
    except Exception:
        # if couldn't logoff, nothing to do, return
        return

    if(restResponse.status_code == requests.codes.ok):
        jsonParsedResponse = restResponse.json()
        print("session logged off successfully")
        return True
    else:
        print("Logoff failed")
        return False


def get_account_value(session, account, instanceId, restURL):
    header = DEFAULT_HEADER
    header.update({"Authorization": session})
    pvwaUrl = "{0}/api/Accounts/{1}/Password/Retrieve".format(restURL, account)
    restLogonData = """{ "reason":"PTA Infra Detect" }"""
    restResponse = call_rest_api_post(pvwaUrl, restLogonData, header)
    if restResponse.status_code == requests.codes.ok:
        return restResponse.text
    elif restResponse.status_code == requests.codes.not_found:
        print("Account {0} for instance {1}, not found on vault".format(account, instanceId))
        return False
    else:
        print("Unexpected result from rest service - get account value, status code: {0}".format(restResponse.status_code))
        return False


def call_rest_api_get(url, header):
    try:
        restResponse = requests.get(url, timeout=30, verify=False, headers=header)
    except Exception as e:
        print("Error occurred on calling PVWA REST service")
        return None
    return restResponse


# Check on DynamoDB if instance exists
# Return False when not found, or row data from table
def get_instance_data_from_dynamo_table(instanceId):

    print('check with DynamoDB if instance {0} exists'.format(instanceId))
    dynamoResource = boto3.client('dynamodb')

    try:
        dynamoResponse = dynamoResource.get_item(TableName='DetectedInstances', Key={"InstanceId": {"S": instanceId}})
    except Exception:
        print("Error occurred when trying to call dynamoDB")
        return False
    if 'Item' in dynamoResponse:
        if dynamoResponse["Item"]["InstanceId"]["S"] == instanceId:
            return dynamoResponse["Item"]
        else:
            return False
    else:
        return False

def save_key_pair(pemKey):
    # Save pem to file
    savePemToFileCommand = 'echo {0} > /tmp/pemValue.pem'.format(pemKey)
    subprocess.call([savePemToFileCommand], shell=True)
    subprocess.call(["chmod 777 /tmp/pemValue.pem"], shell=True)
    return "/tmp/pemValue.pem"


def get_params_from_param_store():
    # Parameters that will be retrieved from parameter store
    VAULT_USER_PARAM = "PTA_Vault_Username"
    PVWA_IP_PARAM = "PTA_PVWA_IP"
    AWS_KEYPAIR_SAFE = "PTA_KeyPair_Safe"
    VAULT_PASSWORD_PARAM = "PTA_Vault_Password"
    PTA_IP="PTA_IP"
    lambdaClient = boto3.client('lambda')

    lambdaRequestData = dict()
    lambdaRequestData["Parameters"] = [VAULT_USER_PARAM,  PVWA_IP_PARAM, AWS_KEYPAIR_SAFE, VAULT_PASSWORD_PARAM, PTA_IP]
    try:
        response = lambdaClient.invoke(FunctionName='TrustMechanismPTA',
                                      InvocationType='RequestResponse',
                                      Payload=json.dumps(lambdaRequestData))
    except Exception as e:
        print("Error on retrieving store parameters:{0}".format(e))
        raise Exception("Error occurred while retrieving store parameters")

    jsonParsedResponse = json.load(response['Payload'])
    # parsing the parameters, jsonParsedResponse is a list of dictionaries
    for ssmStoreItem in jsonParsedResponse:
        if ssmStoreItem['Name'] == VAULT_USER_PARAM:
            vaultUsername = ssmStoreItem['Value']
        elif ssmStoreItem['Name'] == PVWA_IP_PARAM:
            pvwaIP = ssmStoreItem['Value']
        elif ssmStoreItem['Name'] == AWS_KEYPAIR_SAFE:
            keyPairSafeName = ssmStoreItem['Value']
        elif ssmStoreItem['Name'] == VAULT_PASSWORD_PARAM:
            vaultPassword = ssmStoreItem['Value']
        elif ssmStoreItem['Name'] == PTA_IP:
            ptaIP = ssmStoreItem['Value']
        else:
            continue
    storeParametersClass = StoreParameters(vaultUsername, vaultPassword, pvwaIP, keyPairSafeName, ptaIP)

    return storeParametersClass


def retrieve_accountId_from_account_name(session, accountName, safeName, instanceId, restURL):
    header = DEFAULT_HEADER
    header.update({"Authorization": session})

    # 2 options of search - if safe name not empty, add it to query, if not - search without it
    if safeName:  # has value
        pvwaUrl = "{0}/WebServices/PIMServices.svc/Accounts?Keywords={1}&Safe={2}".format(restURL, accountName, safeName)
    else:  # has no value
        pvwaUrl = "{0}/WebServices/PIMServices.svc/Accounts?Keywords={1}".format(restURL, accountName)

    restResponse = call_rest_api_get(pvwaUrl, header)
    if not restResponse:
        raise Exception("Unknown Error when calling rest service - retrieve accountId")

    if restResponse.status_code == requests.codes.ok:
        # if response received, check account is not empty {"Count": 0,"accounts": []}
        if 'accounts' in restResponse.json() and restResponse.json()["accounts"]:
            parsedJsonResponse = restResponse.json()['accounts']
            return parsedJsonResponse[0]['AccountID']
        else:
            return False
    else:
        raise Exception("Status code {0}, received from REST service".format(restResponse.status_code))

def put_instance_to_dynamo_table(instanceId):
    dynamodbResource = boto3.resource('dynamodb')
    instancesTable = dynamodbResource.Table("DetectedInstances")
    try:
        instancesTable.put_item(
           Item={
               'InstanceId': instanceId
           }
        )
    except Exception:
        print('Exception occurred on add item to dynamodb')
        return None

    print('Item {0} added successfully to DB'.format(instanceId))
    return


def remove_instance_from_dynamo_table(instanceId):
    dynamodbResource = boto3.resource('dynamodb')
    instancesTable = dynamodbResource.Table("DetectedInstances")
    try:
        instancesTable.delete_item(
            Key={
                'InstanceId': instanceId
            }
        )
    except Exception:
        print('Exception occurred on deleting item on dynamodb')
        return None

    print('Item {0} successfully deleted from DB'.format(instanceId))
    return

def change_rsyslog(instanceAccountPasswordFile, instanceDetails, instanceUsername, ptaIp):
    expected_result = '0'
    sshclient = paramiko.SSHClient()
    sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    privkey = paramiko.RSAKey.from_private_key_file("/tmp/pemValue.pem")
    sshclient.connect(instanceDetails["address"],username=instanceUsername,pkey=privkey)
    stdin, stdout, stderr = sshclient.exec_command("grep -c {0} /etc/rsyslog.conf".format(ptaIp))
    stdin.flush()
    data = stdout.read().decode('ascii').strip("\n")
    if data == expected_result:
        stdin, stdout, stderr = sshclient.exec_command("echo 'authpriv.*   @{0}:11514' | sudo tee /etc/rsyslog.conf -a".format(ptaIp))
        stdin.flush()
        stdin, stdout, stderr = sshclient.exec_command("sudo systemctl restart rsyslog")
    sshclient.close()
    return True

def detect_instance(instanceId, session, instanceDetails, storeParametersClass, logName):
    # get key pair
    # Retrieving the account id of the account where the instance keyPair is stored
    try:
        currentSession = boto3.session.Session()
        awsRegionName = currentSession.region_name
    except Exception:
        print("AWS region name could not be retrieved")
        raise Exception("AWS region name could not be retrieved")
    # AWS.<AWS Account>.<Region name>.<key pair name>
    keyPairValueOnSafe = "AWS.{0}.{1}.{2}".format(instanceDetails["aws_account_id"], awsRegionName, instanceDetails["key_name"])
    keyPairAccountId = retrieve_accountId_from_account_name(session, keyPairValueOnSafe,
                                                            storeParametersClass.keyPairSafeName, instanceId,
                                                            storeParametersClass.pvwaURL)
    if not keyPairAccountId:
        print("Key Pair '{0}' does not exist in safe '{1}'".format(keyPairValueOnSafe, storeParametersClass.keyPairSafeName))
        return

    instancePrivateKey = get_account_value(session, keyPairAccountId, instanceId, storeParametersClass.pvwaURL)
    if instancePrivateKey is False:
        return
    pemkeyfile = save_key_pair(instancePrivateKey)
    instanceUsername = get_OS_distribution_user(instanceDetails['image_description'])
    time.sleep(30)
    change_rsyslog(pemkeyfile, instanceDetails, instanceUsername, storeParametersClass.ptaIP)



def lambda_handler(event, context):
    logName = context.log_stream_name if context.log_stream_name else "None"
    print(event)
    instanceId, actionType = event.split(";")
    try:
        pvwaConnectionnumber, sessionGuid = get_available_session_from_dynamo()
        instanceDetails = get_ec2_details(instanceId, context)
        instanceData = get_instance_data_from_dynamo_table(instanceId)
        if actionType == 'terminated':
            if not instanceData:
                print('Item {0} does not exists on DB, no need to delete'.format(instanceId))
                return None
            else:
                print('Item {0} exists on DB, deleting it'.format(instanceId))
                remove_instance_from_dynamo_table(instanceId)
                return None
        elif actionType == 'running':
            if not instanceDetails["address"]:  # In case querying AWS return empty address
                print("Retrieving Instance address from AWS failed.")
                return None
            if instanceData:
	            print('Item: {0}, already exists on DB'.format(instanceId))
	            return None
        else:
            print('Unknown instance state')
            return

        storeParametersClass = get_params_from_param_store()
        if not storeParametersClass:
            return

        if not pvwaConnectionnumber:
            return
        sessionToken = logon_pvwa(storeParametersClass.vaultUsername, storeParametersClass.vaultPassword,
                                  storeParametersClass.pvwaURL, pvwaConnectionnumber)
        if not sessionToken:
            return
        if actionType == 'running':
            detect_instance(instanceId, sessionToken, instanceDetails, storeParametersClass, logName)
            put_instance_to_dynamo_table(instanceId)
        else:
            print('Unknown instance state')
            return

        logoff_pvwa(storeParametersClass.pvwaURL, sessionToken)
        release_session_on_dynamo(pvwaConnectionnumber, sessionGuid)

    except Exception as e:
        print("Unknown error occurred:{0}".format(e))
        release_session_on_dynamo(pvwaConnectionnumber, sessionGuid)
        return

def get_available_session_from_dynamo():
    sessionsTableLockClient = LockerClient('PTASessions')
    timeout = 20000  # Setting the timeout to 20 seconds on a row lock
    randomSessionNumber = str(random.randint(1, 100))  # A number between 1 and 100
    try:
        for i in range(0, 20):
            lockResponse = sessionsTableLockClient.acquire(randomSessionNumber, timeout)
            if lockResponse:  # no lock on connection number, return it
                return randomSessionNumber, sessionsTableLockClient.guid
            else:  # connection number is locked, retry in 5 seconds
                time.sleep(5)
                continue
        #  if reached here, 20 retries with 5 seconds between retry - ended
        print("No available connection after many retries")
        return False, ""
    except Exception as e:
        print("Exception on get_available_session_from_dynamo:{0}".format(e))
        raise Exception("Exception on get_available_session_from_dynamo:{0}".format(e))

def release_session_on_dynamo(sessionId, sessionGuid):
    try:
        sessionsTableLockClient = LockerClient('PTASessions')
        sessionsTableLockClient.locked = True
        sessionsTableLockClient.guid = sessionGuid
        sessionsTableLockClient.release(sessionId)
    except Exception:
        return False

    return True


def get_OS_distribution_user(imageDescription):

    if "centos" in (imageDescription.lower()):
        linuxUsername = "root"
    elif "ubuntu" in (imageDescription.lower()):
        linuxUsername = "ubuntu"
    elif "debian" in (imageDescription.lower()):
        linuxUsername = "admin"
    elif "fedora" in (imageDescription.lower()):
        linuxUsername = "fedora"
    elif "opensuse" in (imageDescription.lower()):
        linuxUsername = "root"
    else:
        linuxUsername = "ec2-user"

    return linuxUsername


class StoreParameters:
    vaultUsername = ""
    vaultPassword = ""
    pvwaURL = "https://{0}/PasswordVault"
    keyPairSafeName = ""
    ptaIP = ""

    def __init__(self, username, password, ip, keyPairSafe, ptaIP):
        self.vaultUsername = username
        self.vaultPassword = password
        self.pvwaURL = self.pvwaURL.format(ip)
        self.keyPairSafeName = keyPairSafe
        self.ptaIP = ptaIP
