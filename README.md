# HFS2.3_poc
HFS2.3未经身份验证的远程代码执行(CVE-2024-23692)

python HFS2.3_poc.py -h                             

                ) (`-.            ) (`-.
         ( OO ).           ( OO ).
        (_/.  \_)-. ,-.-')(_/.  \_)-. ,-.-')
         \  `.'  /  |  |OO)\  `.'  /  |  |OO)
          \     /\  |  |  \ \     /\  |  |  \
           \   \ |  |  |(_/  \   \ |  |  |(_/
          .'    \_),|  |_.' .'    \_),|  |_.'
         /  .'.  \(_|  |   /  .'.  \(_|  |
        '--'   '--' `--'  '--'   '--' `--'


usage: HFS2.3_poc.py [-h] [-u URL] [-f FILE]  

HFS2.3未经身份验证的远程代码执行(CVE-2024-23692)  

optional arguments:  
  -h, --help            show this help message and exit  
  -u URL, --url URL     添加url信息  
  -f FILE, --file FILE  添加txt文件  

example:  
    python3 HFS2.3_poc.py -u http://xxxx.xxxx.xxxx.xxxx  
    python3 HFS2.3_poc.py -f x_url.txt  
