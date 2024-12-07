#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
文件名：threatbook_IOC_download_V1.py
描述：从微步获取威胁情报,筛选指定日期，且IOC数量大于0的数据，并下载IOC文件
版本：1.0
作者：
创建日期：2024-12-7
"""

import requests
import os
import time
import datetime

def get_compare_date():
    """获取比较日期"""
    compare_dates = input('请输入比较日期，格式为YYYY-MM-DD：')
    if len(compare_dates) == 0:
        compare_dates = time.strftime('%Y-%m-%d', time.localtime())
    return compare_dates

def setup_session():
    """设置请求的cookies和headers"""
    session = requests.Session()
    session.cookies.update({
        'csrfToken': 'ec1RCPdWCF9MDBffSfABnfM',
        'sensorsdata2015jssdkcross': '%7B%22distinct_id%22%3A%22eede62042f4842cdbec1637f22379b30%22%2C%22first_id%22%3A%2218fd805fb2c8f8-03f271eb120cc86-4c657b58-2073600-18fd805fb2d89a%22%2C%22props%22%3A%7B%22%24latest_traffic_source_type%22%3A%22%E5%BC%95%E8%8D%90%E6%B5%81%E9%87%8F%22%2C%22%24latest_search_keyword%22%3A%22%E6%9C%AA%E5%8F%96%E5%88%B0%E5%80%BC%22%2C%22%24latest_referrer%22%3A%22https%3A%2F%2Fpassport.threatbook.cn%2F%22%7D%2C%22identities%22%3A%22eyIkaWRlbnRpdHlfY29va2llX2lkIjoiMThmZDgwNWZiMmM4ZjgtMDNmMjcxZWIxMjBjYzg2LTRjNjU3YjU4LTIwNzM2MDAtMThmZDgwNWZiMmQ4OWEiLCIkaWRlbnRpdHlfbG9naW5faWQiOiJlZWRlNjIwNDJmNDg0MmNkYmVjMTYzN2YyMjM3OWIzMCJ9%22%2C%22history_login_id%22%3A%7B%22name%22%3A%22%24identity_login_id%22%2C%22value%22%3A%22eede62042f4842cdbec1637f22379b30%22%7D%2C%22%24device_id%22%3A%2218fd805fb2c8f8-03f271eb120cc86-4c657b58-2073600-18fd805fb2d89a%22%7D',
        'rememberme': '17e510482c25fdbd99ee372ac1844767cc8c1a04|eede62042f4842cdbec1637f22379b30|1733580510127|public|w	',
        'xx-csrf': '17e510482c25fdbd99ee372ac1844767cc8c1a04',
        'day_first': 'true',
        'day_first_activity': 'true',
    })

    session.headers.update({
        'accept': '*/*',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'content-type': 'application/json',
        'priority': 'u=1, i',
        'referer': 'https://x.threatbook.com/v5/topic?q=%23%E6%81%B6%E6%84%8FIP%23',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'x-csrf-token': 'ec1RCPdWCF9MDBffSfABnfM-',
        'xx-csrf': '17e510482c25fdbd99ee372ac1844767cc8c1a04',
    })

    return session

def fetch_topic_info_flow(session, params):
    """获取话题信息流"""
    url = 'https://x.threatbook.com/v5/node/topic/topicInfoFlow'
    response = session.get(url, params=params)
    return response.json()

def process_article_info(article_info, compare_dates):
    """处理文章信息"""
    ctime = article_info.get('ctime', '--')
    title = article_info.get('title', '-无标题-')
    original_timestamp = ctime 
    topic = article_info.get('topic', '--')
    threat_id = article_info.get('threatId', '--')
    iocCount = article_info.get('iocCount', '0')
    if ctime != '--':
        ctime = datetime.datetime.fromtimestamp(int(ctime / 1000.0)).strftime('%Y-%m-%d')
        if ctime >= compare_dates and iocCount > 0:
            return threat_id, iocCount, original_timestamp, ctime
    return None

def download_ioc_info(session, threat_id, iocCount, original_timestamp, ctime, keyword):
    """下载IOC信息"""
    url = f'https://x.threatbook.com/socialProxy/user/article/downloadIocInfo?shortMessageId={threat_id}'
    session.headers.pop('x-csrf-token', None)
    session.headers.pop('content-type', None)
    session.headers['referer'] = f'https://x.threatbook.com/v5/article?threatInfoID={threat_id}'
    response = session.get(url, stream=True)
    if response.status_code == 200:
        # 创建目标目录
        base_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'source')
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
        
        # 创建标签对应的子目录
        label_dir = os.path.join(base_dir, keyword.strip('#'))
        if not os.path.exists(label_dir):
            os.makedirs(label_dir)
        
        # 构建文件路径
        filename = f'ioc_{threat_id}_{iocCount}_{ctime}_{original_timestamp}_{keyword}.xls'
        file_path = os.path.join(label_dir, filename)
        
        # 保存文件
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f'-- 文件已下载到：{file_path}')
    else:
        print('请求失败，状态码：', response.status_code)

def main():
    compare_dates = get_compare_date()
    print(f'比较日期为：{compare_dates}')

    topics_list = ['#我被攻击了#', '#恶意域名#', '#恶意IP#', '#木马#', '#木马后门#', '#挖矿木马#', '#病毒木马#', '#威胁情报#', '#恶意网站#', '#钓鱼#', '#钓鱼网站#', '#钓鱼邮件#', '#钓鱼网址#', '#钓鱼情报共享#', '#僵尸网络#', '#国外威胁情报#']
    session = setup_session()

    for keyword in topics_list:
        print(f'开始查询话题{keyword}')
        params = {
            'type': 'all',
            'page': '1',
            'pageSize': '10',
            'topic': keyword,
        }
        response_json = fetch_topic_info_flow(session, params)

        for node in response_json['data']:
            article_info = node['articleInfo']
            result = process_article_info(article_info, compare_dates)
            if result:
                threat_id, iocCount, original_timestamp, ctime = result
                download_ioc_info(session, threat_id, iocCount, original_timestamp, ctime, keyword)
                time.sleep(10)

if __name__ == '__main__':
    main()