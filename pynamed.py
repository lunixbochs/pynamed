import thread
import re
bindRegex = re.compile(r'(tcp|udp)://([^:]+):(\d+)')

from twisted.internet import defer, reactor
from twisted.names.server import DNSServerFactory
from twisted.names import common, dns
from twisted.python import failure

class BaseResolver(common.ResolverBase):
	def _lookup(self, name, cls, record, timeout):
		print 'query: %s' % name

		result = None
		if cls == dns.IN:
			result = self.lookup(name, record)

		return result or defer.fail(failure.Failure(dns.DomainError(name)))

class AResolver(BaseResolver):
	def __init__(self, ttl=300):
		BaseResolver.__init__(self)
		self.ttl = ttl
		self.hosts = {}
	
	def addHost(self, host, target):
		self.hosts[host] = target
	
	def removeHost(self, host):
		if host in self.hosts:
			del self.hosts[host]

	def lookup(self, name, record):
		if record == dns.A:
			name = name.lower()
			if name in self.hosts:
				target = self.hosts[name]

				record = dns.Record_A(target)
				rr = dns.RRHeader(name, record.TYPE, dns.IN, self.ttl, record, auth=True)

				return defer.succeed(([rr], [], []))

class PyNamed:
	def __init__(self, resolver, binds=('tcp://127.0.0.1:53', 'udp://127.0.0.1:53')):
		factory = DNSServerFactory(authorities=(resolver,), verbose=1)
		protocol = dns.DNSDatagramProtocol(factory)

		for bind in binds:
			match = bindRegex.match(bind)
			if match:
				transport, host, port = match.groups()
				print transport, host, port
				port = int(port)
				if transport == 'tcp':
					reactor.listenTCP(port, factory, interface=host)
				elif transport == 'udp':
					reactor.listenUDP(port, protocol, interface=host)
			else:
				print 'badly-formed bind string:', bind
	
	def defer(self):
		thread.start_new_thread(self.run, ())
	
	def run(self):
		reactor.run()

if __name__ == '__main__':
	resolver = AResolver()
	named = PyNamed(resolver)
	resolver.addHost('test', '192.168.0.0')

	named.run()