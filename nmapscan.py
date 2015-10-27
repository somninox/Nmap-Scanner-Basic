#sudo apt-get install nmap
#sudo apt-get install python-setuptools
#sudo easy_install

import optparse
import nmap


def nmapScan(tgtHost, tgtPort):
	nScan = nmap.PortScanner()
	#initialize nmapscan
	nScan.scan(tgtHost, tgtPorts)
	#scan this host and port
	state = nScan[tgtHost]['tcp'][int(tgtPort)]['state']
	print "[*] " +tgtHost+ " tcp/" +tgtPort+ " " + state
	


def Main():
	parser = optparse.OptionParser("usage %prog -H <target host> " + \
		"-p <target port>")
	parser.add_option("-H", dest="tgtHost", type="string", \
		help="specify target host")
	parser.add_option("-p", dest="tgtPort", type="string", \
		help="specify target port[s] separated by a comma")

	#define options for parser

	(options, args) = parser.parse_args()
	if (options.tgtHost == None) | (options.tgtPort == None):
		print parser.usage
		exit(0);
		#if options are null exit program

	else:
		tgtHost = options.tgtHost
		tgtPorts = str(options.tgtPort).split(',')
		#obtain target host and ports through parser

	for tgtPort in tgtPorts:
		nmapScan(tgtHost, tgtPort)
		#scan target host and ports

if __name__ == '__main__':
	Main() 