from ast import Return
from re import L
import time
import os
import os.path
import json
from unicodedata import name
import boto3
import botocore
import traceback
import requests
import ipaddress
import shutil
import sys

requests.packages.urllib3.disable_warnings()


def lambda_handler(event, context):
    """ Entry point of the lambda script"""
    try:
        _lambda_handler(event, context)
    except Exception as err:
        print(str(traceback.format_exc()))
        print("Lambda function failed due to " + str(err))


def _lambda_handler(event, context):
    """ This lambda function is triggered on a specific parameter store change event"""

    print("Event: %s" % event)

    print("Log stream name:", context.log_stream_name)
    print("Log group name:",  context.log_group_name)
    print("Request ID:", context.aws_request_id)
    print("Mem. limits(MB):", context.memory_limit_in_mb)

    CONTROLLER_VER = ''
    PROVIDER_VER = ''

   # Fetch Aviatrix Controller credentials from encrupted SSM parameter store

    ssm_client = boto3.client('ssm')
    resp = ssm_client.get_parameters_by_path(
        Path="/aviatrix/controller/", WithDecryption=True)

    avx_params = {}
    for param in resp['Parameters']:
        avx_params[param['Name'].split("/")[-1]] = param['Value']

    api_ep_url = "https://" + avx_params['ip_address'] + "/v1/"

    # Login to Controller and save CID
    response = login(api_endpoint_url=api_ep_url+"api",
                     username=avx_params['username'],
                     password=avx_params['password'])
    CID = response.json()["CID"]

    # Parse AWS account ID from the SSM 'ready' parameter event

    acc_num = event['account']
    vpc_id = {}
    vpc_id = event['detail']['name']
    vpc_id = vpc_id.split("/")[-1]

    creds = get_temp_creds_for_account(acc_num, region="ap-southeast-2")
    ct_client = boto3.client('ssm', aws_access_key_id=creds['AccessKeyId'],
                             aws_secret_access_key=creds['SecretAccessKey'],
                             aws_session_token=creds['SessionToken'])
    resp1 = ct_client.get_parameters_by_path(
        Path="/aviatrix/spoke/"+vpc_id+"/", WithDecryption=True)
    ct_params = {}
    for param in resp1['Parameters']:
        ct_params[param['Name'].split("/")[-1]] = param['Value']

    acc_name = ct_params['account_name']
    #vpc_id = ct_params['vpc_id']
    avx_tgw = ct_params['avx_tgw']
    gw_subnet = ct_params['gw_subnet']
    hagw_subnet = ct_params['hagw_subnet']
    route_table_list = ct_params['route_table_list']
    gw_size = ct_params['gw_size']

    if event['detail']['name'] == '/aviatrix/ready/'+vpc_id:
        print("Create SSM ready parameter event Received")

        response = create_access_account(
            api_endpoint_url=api_ep_url+"api",
            CID=CID,
            cloud_type="1",
            account_name=acc_name,
            aws_account_number=acc_num,
            app_role_arn="arn:aws:iam::"+acc_num+":role/aviatrix-role-app",
            ec2_role_arn="arn:aws:iam::"+acc_num+":role/aviatrix-role-ec2",
            keyword_for_log="avx-lambda-function---",
            indent="    ")
        print(response.json())

        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_availability_zones()
        num_zones = len(response["AvailabilityZones"]) if len(
            response["AvailabilityZones"]) < 3 else 3

        response = attach_vpc_to_avx_tgw(
            api_endpoint_url=api_ep_url+"api",
            CID=CID,
            vpc_access_account_name=acc_name,
            vpc_region_name=event['region'],
            vpc_id=vpc_id,
            avx_tgw_name=avx_tgw,
            gw_name="spoke1-"+event['region']+"-"+acc_num,
            gw_size=gw_size,
            gw_subnet=gw_subnet,
            hagw_subnet=hagw_subnet,
            route_table_list=route_table_list,
            keyword_for_log="avx-lambda-function---",
            indent="    ")

        print(response.json())

    else:
        print("Unknown Request")
        print(event['source'])

    return


def create_access_account(
        api_endpoint_url="https://123.123.123.123/v1/api",
        CID="",
        account_name="",
        account_email="",
        cloud_type="1",
        aws_account_number="",
        is_iam_role_based="true",
        app_role_arn="arn:aws:iam::123456789012:role/aviatrix-role-app",
        ec2_role_arn="arn:aws:iam::123456789012:role/aviatrix-role-ec2",
        keyword_for_log="avx-lambda-function---",
        indent="    "):

    request_method = "POST"

    data = {
        "action": "setup_account_profile",
        "CID": CID,
        "account_name": account_name,
        "account_email": account_email,
        "cloud_type": cloud_type,
        "aws_account_number": aws_account_number,
        "aws_iam": is_iam_role_based,
        "aws_role_arn": app_role_arn,
        "aws_role_ec2": ec2_role_arn
    }

    payload_with_hidden_password = dict(data)

    print(indent + keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload_with_hidden_password, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=data,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    return response
# END def create_access_account()


def attach_vpc_to_avx_tgw(
        api_endpoint_url="",
        CID="",
        vpc_access_account_name="",
        vpc_region_name="",
        vpc_id="",
        avx_tgw_name="",
        gw_name="",
        gw_size="",
        gw_subnet="",
        hagw_subnet="",
        route_table_list="",
        keyword_for_log="avx-lambda-function---",
        indent="    "):

    request_method = "POST"
    payload = {
        "action": "create_spoke_gw",
        "CID": CID,
        "account_name": vpc_access_account_name,
        "cloud_type": "1",
        "region": vpc_region_name,
        "vpc_id": vpc_id,
        "public_subnet": gw_subnet,
        "gw_name": gw_name,
        "gw_size": gw_size,
        "insane_mode": "on"
    }

    print(indent + keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    print(response.json())

    payload = {
        "action": "enable_spoke_ha",
        "CID": CID,
        "gw_name": gw_name,
        "public_subnet": hagw_subnet,
        "availability_domain": "ap-southeast-2b"
    }

    print(indent + keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    print(response.json())

    payload = {
        "action": "attach_spoke_to_transit_gw",
        "CID": CID,
        "spoke_gw": gw_name,
        "transit_gw": avx_tgw_name,
        "route_table_list": route_table_list
    }

    print(indent + keyword_for_log + "Request payload     : \n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    payload = {
        "action": "add_spoke_to_transit_firenet_inspection",
        "CID": CID,
        "firenet_gateway_name": avx_tgw_name,
        "spoke_gateway_name": "SPOKE:"+gw_name
    }

    print(indent + keyword_for_log + "Request payload   :\n" +
          str(json.dumps(obj=payload, indent=4)))

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=payload,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    return response
# END def attach_vpc_to_avx_tgw()


def login(
        api_endpoint_url="https://x.x.x.x/v1/api",
        username="admin",
        password="**********",
        keyword_for_log="avx-vpc-lambda---",
        indent="    "):

    request_method = "POST"
    data = {
        "action": "login",
        "username": username,
        "password": password
    }

    payload_with_hidden_password = dict(data)
    payload_with_hidden_password["password"] = "************"

    response = _send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=data,
        keyword_for_log=keyword_for_log,
        indent=indent + "    ")

    return response


def _send_aviatrix_api(
        api_endpoint_url="https://123.123.123.123/v1/api",
        request_method="POST",
        payload=dict(),
        retry_count=5,
        keyword_for_log="avx-lambda-function---",
        indent=""):

    response = None
    responses = list()
    request_type = request_method.upper()
    response_status_code = -1

    for i in range(retry_count):
        try:
            if request_type == "GET":
                response = requests.get(
                    url=api_endpoint_url, params=payload, verify=False)
                response_status_code = response.status_code
            elif request_type == "POST":
                response = requests.post(
                    url=api_endpoint_url, data=payload, verify=False)
                response_status_code = response.status_code
            else:
                lambda_failure_reason = "ERROR: Bad HTTPS request type: " + request_method
                print(keyword_for_log + lambda_failure_reason)
                return lambda_failure_reason
            responses.append(response)  # For error message/debugging purposes
        except requests.exceptions.ConnectionError as e:
            print(indent + keyword_for_log +
                  "WARNING: Oops, it looks like the server is not responding...")
            responses.append(str(e))
        except Exception as e:
            traceback_msg = traceback.format_exc()
            print(indent + keyword_for_log +
                  "Oops! Aviatrix Lambda caught an exception! The traceback message is: ")
            print(traceback_msg)
            lambda_failure_reason = "Oops! Aviatrix Lambda caught an exception! The traceback message is: \n" + \
                str(traceback_msg)
            print(keyword_for_log + lambda_failure_reason)
            # For error message/debugging purposes
            responses.append(str(traceback_msg))
        finally:
            if 200 == response_status_code:  # Successfully send HTTP request to controller Apache2 server
                return response
            elif 404 == response_status_code:
                lambda_failure_reason = "ERROR: Oops, 404 Not Found. Please check your URL or route path..."
                print(indent + keyword_for_log + lambda_failure_reason)

            if i+1 < retry_count:
                print(indent + keyword_for_log + "START: Wait until retry")
                print(indent + keyword_for_log + "    i == " + str(i))
                wait_time_before_retry = pow(2, i)
                print(indent + keyword_for_log + "    Wait for: " + str(wait_time_before_retry) +
                      " second(s) until next retry")
                time.sleep(wait_time_before_retry)
                print(indent + keyword_for_log +
                      "ENDED: Wait until retry  \n\n")
            else:
                lambda_failure_reason = 'ERROR: Failed to invoke Aviatrix API. Max retry exceeded. ' + \
                                        'The following includes all retry responses: ' + \
                                        str(responses)
                raise AviatrixException(message=lambda_failure_reason,)

    return response  # IF the code flow ends up here, the response might have some issues


def get_temp_creds_for_account(account_num, region):
    role_arn = "arn:aws:iam::"+account_num+":role/"+"lambda-assume-role"
    sts_client = boto3.client(
        'sts', endpoint_url="https://sts." + region + ".amazonaws.com")

    try:
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName="AssumeRoleSession1")
    except Exception as e:
        print(e)
        sys.exit(1)

    creds = assumed_role['Credentials']

    return (creds)


class AviatrixException(Exception):
    def __init__(self, message="Aviatrix Error Message: ..."):
        super(AviatrixException, self).__init__(message)
# END class MyException
