from __future__ import print_function

import json
import urllib
import boto3
import gzip
import os

# Cloudfront Data Columns
CF_DATE_COL = 0
CF_TIME_COL = 1
CF_IP_COL = 4
CF_STATUS_COL = 8

BAD_HTTP_STATUS_CODES = [status.strip() for status in os.environ['BAD_HTTP_STATUS_CODES'].split(',')]
BAD_REQUESTS_PER_MIN = int(os.environ['BAD_REQUESTS_PER_MIN'])
IP_SET_ID = os.environ['IP_SET_ID']


# Downloads CloudFront log from S3
def download_cloudfront_log(bucket_name, key_name):
    
    print('Downloading CloudFront log from S3: ', bucket_name + '/' + key_name)
    s3 = boto3.client('s3')
    dl_cf_log_path = '/tmp/' + key_name.split('/')[-1]
    s3.download_file(bucket_name, key_name, dl_cf_log_path)
    return dl_cf_log_path;


# Unzips and parses CloudFront log for bad http response codes.
# Creates an IP / Time map with key IP_Time (to the minute) and number of bad requests that minute
def parse_cloudfront_log(downloaded_file_path):
    
    ip_time_map = {}
    
    with gzip.open(downloaded_file_path,'r') as cf_log_content:
        for line in cf_log_content:
            
            if line.startswith('#'):
                continue
            
            # Split the line on tabs
            line_data = line.split('\t')
            
            status =  line_data[CF_STATUS_COL]
            
            if status in BAD_HTTP_STATUS_CODES:
                
                ip = line_data[CF_IP_COL]
                datetime_min = line_data[CF_DATE_COL] + '-' + line_data[CF_TIME_COL][:-3]
                ip_time_key = ip + '_' + datetime_min
                
                if ip_time_key in ip_time_map.keys():
                    ip_time_map[ip_time_key] += 1
                else:
                    ip_time_map[ip_time_key] = 1
                
    return ip_time_map


# Determines if the number of bad requests per minute exceeds the threshold.
# If so, adds the IP address to a map.
def parse_bad_requests(ip_time_map):
    
    blacklist_ips = {}
    
    for key, value in ip_time_map.iteritems():
        if value >= BAD_REQUESTS_PER_MIN:
            ip = key.split('_')[0]
            if ip not in blacklist_ips.keys():
                blacklist_ips[ip] = {}
                
    return blacklist_ips


# Sends the blacklisted IPs to the Web ACL
def send_blacklist_ips_to_waf(blacklist_ips):
    
    blacklist_ips_updates = []
    
    for ip in blacklist_ips.keys():
        blacklist_ips_updates.append(
            {
                'Action': 'INSERT',
                'IPSetDescriptor': {
                    'Type': 'IPV4',
                    'Value': "%s/32"%ip
                }
            }
        )
    
    if len(blacklist_ips_updates) > 0:
        waf = boto3.client('waf')
        waf_response = waf.update_ip_set(IPSetId=IP_SET_ID, ChangeToken=waf.get_change_token()['ChangeToken'], Updates=blacklist_ips_updates)
        print('WAF Response: ', waf_response)
    
    return



def lambda_handler(event, context):
    
    # print('Event: ', event)
    
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    key_name = urllib.unquote_plus(event['Records'][0]['s3']['object']['key']).decode('utf8')
    
    dl_cf_log_path = download_cloudfront_log(bucket_name, key_name)
    print('Downloaded CloudFront log from S3 as: ', dl_cf_log_path)
    
    ip_time_map = parse_cloudfront_log(dl_cf_log_path)
    print('IP/Time Map: ', ip_time_map)
    
    blacklist_ips = parse_bad_requests(ip_time_map)
    print('IPs to be blacklisted: ', blacklist_ips)
    
    send_blacklist_ips_to_waf(blacklist_ips)
    
    return {
        'statusCode': 200,
        'body': json.dumps('autoBlacklistIPLambdaFunction was successful')
    }
