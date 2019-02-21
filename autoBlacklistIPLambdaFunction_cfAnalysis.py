from __future__ import print_function

import json
import urllib
import boto3
import gzip

# Cloudfront Data Columns
CF_DATE_COL = 0
CF_TIME_COL = 1
CF_IP_COL = 4
CF_STATUS_COL = 8



def download_cloudfront_log(bucket_name, key_name):
    
    print('Downloading CloudFront log from S3: ', bucket_name + '/' + key_name)
    s3 = boto3.client('s3')
    dl_cf_log_path = '/tmp/' + key_name.split('/')[-1]
    s3.download_file(bucket_name, key_name, dl_cf_log_path)
    return dl_cf_log_path;
    
    
    
def parse_cloudfront_log(downloaded_file_path):
    
    with gzip.open(downloaded_file_path,'r') as cf_log_content:
        for line in cf_log_content:
            
            if line.startswith('#'):
                continue
            
            # Split the line on tabs
            line_data = line.split('\t')
            
            date = line_data[CF_DATE_COL]
            time = line_data[CF_TIME_COL]
            ip = line_data[CF_IP_COL]
            status =  line_data[CF_STATUS_COL]
            
            print("date: " + date + ", time: " + time + ", ip: " + ip + ", status: " + status)



def lambda_handler(event, context):
    
    # print('Event: ', event)
    
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    key_name = urllib.unquote_plus(event['Records'][0]['s3']['object']['key']).decode('utf8')
    
    dl_cf_log_path = download_cloudfront_log(bucket_name, key_name)
    print('Downloaded CloudFront log from S3 as: ', dl_cf_log_path)
    
    parse_cloudfront_log(dl_cf_log_path)
    
    return {
        'statusCode': 200,
        'body': json.dumps('autoBlacklistIPLambdaFunction was successful')
    }
