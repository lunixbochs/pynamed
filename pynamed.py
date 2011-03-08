tcp = [
	('127.0.0.1', 53)
]

udp = [
	('127.0.0.1', 53)
]

hosts = {
	'n1':'127.0.0.1',
	'n2':'127.0.0.1',
	'n3':'127.0.0.1',
	'n4':'127.0.0.1'
}

from twisted.internet import defer, reactor
from twisted.names.server import DNSServerFactory
from twisted.names import common, dns
from twisted.python import failure

class GenericResolver(common.ResolverBase):
	def _lookup(self, name, cls, rtype, timeout):
		print 'query: %s' % name
		if rtype == dns.A:
			name = name.lower()
			if name in hosts:
				target = hosts[name]

				record = dns.Record_A(target)
				rr = dns.RRHeader(name, record.TYPE, dns.IN, 300, record, auth=True)

				return defer.succeed(([rr], [], []))

		return defer.fail(failure.Failure(dns.DomainError(name)))

def main():
	authorities = []
	authorities.append(GenericResolver())

	factory = DNSServerFactory(authorities = authorities, verbose=1)
	protocol = dns.DNSDatagramProtocol(factory)

	for addr, port in tcp:
		reactor.listenTCP(port, factory, interface=addr)
	
	for addr, port in udp:
		reactor.listenUDP(port, protocol, interface=addr)

	reactor.run()

if __name__ == "__main__":
	main()