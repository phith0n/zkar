import os
import argparse
import pathlib
import subprocess

base = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
gadgets = ['AspectJWeaver', 'BeanShell1', 'C3P0', 'Click1', 'Clojure', 'CommonsBeanutils1', 'CommonsCollections1',
           'CommonsCollections2', 'CommonsCollections3', 'CommonsCollections4', 'CommonsCollections5',
           'CommonsCollections6', 'CommonsCollections7', 'FileUpload1', 'Groovy1', 'Hibernate1', 'Hibernate2',
           'JBossInterceptors1', 'JRMPClient', 'JRMPListener', 'JSON1', 'JavassistWeld1', 'Jdk7u21', 'Jython1',
           'MozillaRhino1', 'MozillaRhino2', 'Myfaces1', 'Myfaces2', 'ROME', 'Spring1', 'Spring2', 'URLDNS', 'Vaadin1',
           'Wicket1', ]


def ysoserial(binary):
    for gadget in gadgets:
        output = base / (gadget + '.ser')
        if output.exists():
            continue

        command = 'testtest'
        if gadget == 'AspectJWeaver':
            command = 'test.txt;dGVzdA=='
        elif gadget == 'FileUpload1':
            command = 'write;test.txt;test'
        elif gadget == 'JRMPListener':
            command = '12345'
        elif gadget == 'Jython1':
            command = '%s;%s' % ((base / 'example.py'), 'test.txt')
        elif gadget == 'Wicket1':
            command = 'write;1,txt;test'

        payloads = subprocess.check_output(['java', '-jar', binary, gadget, command])
        with output.open('wb') as f:
            f.write(payloads)


def main():
    parser = argparse.ArgumentParser(description='ZKar ysoserial payloads generator.')
    parser.add_argument('-y', '--ysoserial', required=True, metavar='JAR_PATH', help='ysoserial jar binary path')

    args = parser.parse_args()
    ysoserial(args.ysoserial)


if __name__ == '__main__':
    main()
