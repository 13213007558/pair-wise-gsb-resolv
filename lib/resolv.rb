# frozen_string_literal: true

require 'socket'
require 'timeout'
require 'io/wait' if RUBY_VERSION < '3.2'
require 'securerandom'
require 'rbconfig'

# Resolv is a thread-aware DNS resolver library written in Ruby.  Resolv can
# handle multiple DNS requests concurrently without blocking the entire Ruby
# interpreter.
#
# See also resolv-replace.rb to replace the libc resolver with Resolv.
#
# Resolv can look up various DNS resources using the DNS module directly.
#
# Examples:
#
#   p Resolv.getaddress "www.ruby-lang.org"
#   p Resolv.getname "210.251.121.214"
#
#   Resolv::DNS.open do |dns|
#     ress = dns.getresources "www.ruby-lang.org", Resolv::DNS::Resource::IN::A
#     p ress.map(&:address)
#     ress = dns.getresources "ruby-lang.org", Resolv::DNS::Resource::IN::MX
#     p ress.map { |r| [r.exchange.to_s, r.preference] }
#   end
#
#
# == Bugs
#
# * NIS is not supported.
# * /etc/nsswitch.conf is not supported.

class Resolv

  # The version string
  VERSION = "0.8.0"

  ##
  # Looks up the first IP address for +name+.

  def self.getaddress(name)
    DefaultResolver.getaddress(name)
  end

  ##
  # Looks up all IP address for +name+.

  def self.getaddresses(name)
    DefaultResolver.getaddresses(name)
  end

  ##
  # Iterates over all IP addresses for +name+.

  def self.each_address(name, &block)
    DefaultResolver.each_address(name, &block)
  end

  ##
  # Looks up the hostname of +address+.

  def self.getname(address)
    DefaultResolver.getname(address)
  end

  ##
  # Looks up all hostnames for +address+.

  def self.getnames(address)
    DefaultResolver.getnames(address)
  end

  ##
  # Iterates over all hostnames for +address+.

  def self.each_name(address, &proc)
    DefaultResolver.each_name(address, &proc)
  end

  ##
  # Creates a new Resolv using +resolvers+.
  #
  # If +resolvers+ is not given, a hash, or +nil+, uses a Hosts resolver and
  # and a DNS resolver.  If +resolvers+ is a hash, uses the hash as
  # configuration for the DNS resolver.

  def initialize(resolvers=(arg_not_set = true; nil), use_ipv6: (keyword_not_set = true; nil))
    if !keyword_not_set && !arg_not_set
      warn "Support for separate use_ipv6 keyword is deprecated, as it is ignored if an argument is provided. Do not provide a positional argument if using the use_ipv6 keyword argument.", uplevel: 1
    end

    @resolvers = case resolvers
    when Hash, nil
      [Hosts.new, DNS.new(DNS::Config.default_config_hash.merge(resolvers || {}))]
    else
      resolvers
    end
  end

  ##
  # Looks up the first IP address for +name+.

  def getaddress(name)
    each_address(name) {|address| return address}
    raise ResolvError.new("no address for #{name}")
  end

  ##
  # Looks up all IP address for +name+.

  def getaddresses(name)
    ret = []
    each_address(name) {|address| ret << address}
    return ret
  end

  ##
  # Iterates over all IP addresses for +name+.

  def each_address(name)
    if AddressRegex =~ name
      yield name
      return
    end
    yielded = false
    @resolvers.each {|r|
      r.each_address(name) {|address|
        yield address.to_s
        yielded = true
      }
      return if yielded
    }
  end

  ##
  # Looks up the hostname of +address+.

  def getname(address)
    each_name(address) {|name| return name}
    raise ResolvError.new("no name for #{address}")
  end

  ##
  # Looks up all hostnames for +address+.

  def getnames(address)
    ret = []
    each_name(address) {|name| ret << name}
    return ret
  end

  ##
  # Iterates over all hostnames for +address+.

  def each_name(address)
    yielded = false
    @resolvers.each {|r|
      r.each_name(address) {|name|
        yield name.to_s
        yielded = true
      }
      return if yielded
    }
  end

  ##
  # Indicates a failure to resolve a name or address.

  class ResolvError < StandardError; end

  ##
  # Indicates a timeout resolving a name or address.

  class ResolvTimeout < Timeout::Error; end

  ##
  # Resolv::Hosts is a hostname resolver that uses the system hosts file.

  class Hosts
    if /mswin|cygwin|mingw/ =~ RUBY_PLATFORM || ::RbConfig::CONFIG['host_os'] =~ /mswin/
      begin
        require 'win32/resolv' unless defined?(Win32::Resolv)
        hosts = Win32::Resolv.get_hosts_path || IO::NULL
      rescue LoadError
      end
    end
    # The default file name for host names
    DefaultFileName = hosts || '/etc/hosts'

    ##
    # Creates a new Resolv::Hosts, using +filename+ for its data source.

    def initialize(filename = DefaultFileName)
      @filename = filename
      @mutex = Thread::Mutex.new
      @initialized = nil
    end

    def lazy_initialize # :nodoc:
      @mutex.synchronize {
        unless @initialized
          @name2addr = {}
          @addr2name = {}
          File.open(@filename, 'rb') {|f|
            f.each {|line|
              line.sub!(/#.*/, '')
              addr, *hostnames = line.split(/\s+/)
              next unless addr
              (@addr2name[addr] ||= []).concat(hostnames)
              hostnames.each {|hostname| (@name2addr[hostname] ||= []) << addr}
            }
          }
          @name2addr.each {|name, arr| arr.reverse!}
          @initialized = true
        end
      }
      self
    end

    ##
    # Gets the IP address of +name+ from the hosts file.

    def getaddress(name)
      each_address(name) {|address| return address}
      raise ResolvError.new("#{@filename} has no name: #{name}")
    end

    ##
    # Gets all IP addresses for +name+ from the hosts file.

    def getaddresses(name)
      ret = []
      each_address(name) {|address| ret << address}
      return ret
    end

    ##
    # Iterates over all IP addresses for +name+ retrieved from the hosts file.

    def each_address(name, &proc)
      lazy_initialize
      @name2addr[name]&.each(&proc)
    end

    ##
    # Gets the hostname of +address+ from the hosts file.

    def getname(address)
      each_name(address) {|name| return name}
      raise ResolvError.new("#{@filename} has no address: #{address}")
    end

    ##
    # Gets all hostnames for +address+ from the hosts file.

    def getnames(address)
      ret = []
      each_name(address) {|name| ret << name}
      return ret
    end

    ##
    # Iterates over all hostnames for +address+ retrieved from the hosts file.

    def each_name(address, &proc)
      lazy_initialize
      @addr2name[address]&.each(&proc)
    end
  end

  ##
  # Resolv::DNS is a DNS stub resolver.
  #
  # Information taken from the following places:
  #
  # * STD0013
  # * RFC 1035
  # * ftp://ftp.isi.edu/in-notes/iana/assignments/dns-parameters
  # * etc.

  class DNS

    ##
    # Default DNS Port

    Port = 53

    ##
    # Default DNS UDP packet size

    UDPSize = 512

    ##
    # Creates a new DNS resolver.  See Resolv::DNS.new for argument details.
    #
    # Yields the created DNS resolver to the block, if given, otherwise
    # returns it.

    def self.open(*args)
      dns = new(*args)
      return dns unless block_given?
      begin
        yield dns
      ensure
        dns.close
      end
    end

    ##
    # Creates a new DNS resolver.
    #
    # +config_info+ can be:
    #
    # nil:: Uses /etc/resolv.conf.
    # String:: Path to a file using /etc/resolv.conf's format.
    # Hash:: Must contain :nameserver, :search and :ndots keys.
    # :nameserver_port can be used to specify port number of nameserver address.
    # :raise_timeout_errors can be used to raise timeout errors
    # as exceptions instead of treating the same as an NXDOMAIN response.
    #
    # The value of :nameserver should be an address string or
    # an array of address strings.
    # - :nameserver => '8.8.8.8'
    # - :nameserver => ['8.8.8.8', '8.8.4.4']
    #
    # The value of :nameserver_port should be an array of
    # pair of nameserver address and port number.
    # - :nameserver_port => [['8.8.8.8', 53], ['8.8.4.4', 53]]
    #
    # Example:
    #
    #   Resolv::DNS.new(:nameserver => ['210.251.121.21'],
    #                   :search => ['ruby-lang.org'],
    #                   :ndots => 1)

    def initialize(config_info=nil)
      @mutex = Thread::Mutex.new
      @config = Config.new(config_info)
      @initialized = nil
    end

    # Sets the resolver timeouts.  This may be a single positive number
    # or an array of positive numbers representing timeouts in seconds.
    # If an array is specified, a DNS request will retry and wait for
    # each successive interval in the array until a successful response
    # is received.  Specifying +nil+ reverts to the default timeouts:
    # [ 5, second = 5 * 2 / nameserver_count, 2 * second, 4 * second ]
    #
    # Example:
    #
    #   dns.timeouts = 3
    #
    def timeouts=(values)
      @config.timeouts = values
    end

    def lazy_initialize # :nodoc:
      @mutex.synchronize {
        unless @initialized
          @config.lazy_initialize
          @initialized = true
        end
      }
      self
    end

    ##
    # Closes the DNS resolver.

    def close
      @mutex.synchronize {
        if @initialized
          @initialized = false
        end
      }
    end

    ##
    # Gets the IP address of +name+ from the DNS resolver.
    #
    # +name+ can be a Resolv::DNS::Name or a String.  Retrieved address will
    # be a Resolv::IPv4 or Resolv::IPv6

    def getaddress(name)
      each_address(name) {|address| return address}
      raise ResolvError.new("DNS result has no information for #{name}")
    end

    ##
    # Gets all IP addresses for +name+ from the DNS resolver.
    #
    # +name+ can be a Resolv::DNS::Name or a String.  Retrieved addresses will
    # be a Resolv::IPv4 or Resolv::IPv6

    def getaddresses(name)
      ret = []
      each_address(name) {|address| ret << address}
      return ret
    end

    ##
    # Iterates over all IP addresses for +name+ retrieved from the DNS
    # resolver.
    #
    # +name+ can be a Resolv::DNS::Name or a String.  Retrieved addresses will
    # be a Resolv::IPv4 or Resolv::IPv6

    def each_address(name)
      if use_ipv6?
        each_resource(name, Resource::IN::AAAA) {|resource| yield resource.address}
      end
      each_resource(name, Resource::IN::A) {|resource| yield resource.address}
    end

    def use_ipv6? # :nodoc:
      @config.lazy_initialize unless @config.instance_variable_get(:@initialized)

      use_ipv6 = @config.use_ipv6?
      unless use_ipv6.nil?
        return use_ipv6
      end

      begin
        list = Socket.ip_address_list
      rescue NotImplementedError
        return true
      end
      list.any? {|a| a.ipv6? && !a.ipv6_loopback? && !a.ipv6_linklocal? }
    end
    private :use_ipv6?

    ##
    # Gets the hostname for +address+ from the DNS resolver.
    #
    # +address+ must be a Resolv::IPv4, Resolv::IPv6 or a String.  Retrieved
    # name will be a Resolv::DNS::Name.

    def getname(address)
      each_name(address) {|name| return name}
      raise ResolvError.new("DNS result has no information for #{address}")
    end

    ##
    # Gets all hostnames for +address+ from the DNS resolver.
    #
    # +address+ must be a Resolv::IPv4, Resolv::IPv6 or a String.  Retrieved
    # names will be Resolv::DNS::Name instances.

    def getnames(address)
      ret = []
      each_name(address) {|name| ret << name}
      return ret
    end

    ##
    # Iterates over all hostnames for +address+ retrieved from the DNS
    # resolver.
    #
    # +address+ must be a Resolv::IPv4, Resolv::IPv6 or a String.  Retrieved
    # names will be Resolv::DNS::Name instances.

    def each_name(address)
      case address
      when Name
        ptr = address
      when IPv4, IPv6
        ptr = address.to_name
      when IPv4::Regex
        ptr = IPv4.create(address).to_name
      when IPv6::Regex
        ptr = IPv6.create(address).to_name
      else
        raise ResolvError.new("cannot interpret as address: #{address}")
      end
      each_resource(ptr, Resource::IN::PTR) {|resource| yield resource.name}
    end

    ##
    # Look up the +typeclass+ DNS resource of +name+.
    #
    # +name+ must be a Resolv::DNS::Name or a String.
    #
    # +typeclass+ should be one of the following:
    #
    # * Resolv::DNS::Resource::IN::A
    # * Resolv::DNS::Resource::IN::AAAA
    # * Resolv::DNS::Resource::IN::ANY
    # * Resolv::DNS::Resource::IN::CAA
    # * Resolv::DNS::Resource::IN::CNAME
    # * Resolv::DNS::Resource::IN::HINFO
    # * Resolv::DNS::Resource::IN::HTTPS
    # * Resolv::DNS::Resource::IN::LOC
    # * Resolv::DNS::Resource::IN::MINFO
    # * Resolv::DNS::Resource::IN::MX
    # * Resolv::DNS::Resource::IN::NS
    # * Resolv::DNS::Resource::IN::PTR
    # * Resolv::DNS::Resource::IN::SOA
    # * Resolv::DNS::Resource::IN::SRV
    # * Resolv::DNS::Resource::IN::SVCB
    # * Resolv::DNS::Resource::IN::TXT
    # * Resolv::DNS::Resource::IN::WKS
    #
    # Returned resource is represented as a Resolv::DNS::Resource instance,
    # i.e. Resolv::DNS::Resource::IN::A.

    def getresource(name, typeclass)
      each_resource(name, typeclass) {|resource| return resource}
      raise ResolvError.new("DNS result has no information for #{name}")
    end

    ##
    # Looks up all +typeclass+ DNS resources for +name+.  See #getresource for
    # argument details.

    def getresources(name, typeclass)
      ret = []
      each_resource(name, typeclass) {|resource| ret << resource}
      return ret
    end

    ##
    # Iterates over all +typeclass+ DNS resources for +name+.  See
    # #getresource for argument details.

    def each_resource(name, typeclass, &proc)
      fetch_resource(name, typeclass) {|reply, reply_name|
        extract_resources(reply, reply_name, typeclass, &proc)
      }
    end

    # :stopdoc:

    def fetch_resource(name, typeclass)
      lazy_initialize
      truncated = {}
      requesters = {}
      udp_requester = begin
        make_udp_requester
      rescue Errno::EACCES
        # fall back to TCP
      end
      senders = {}

      begin
        @config.resolv(name) do |candidate, tout, nameserver, port|
          msg = Message.new
          msg.rd = 1
          msg.add_question(candidate, typeclass)

          requester = requesters.fetch([nameserver, port]) do
            if !truncated[candidate] && udp_requester
              udp_requester
            else
              requesters[[nameserver, port]] = make_tcp_requester(nameserver, port)
            end
          end

          unless sender = senders[[candidate, requester, nameserver, port]]
            sender = requester.sender(msg, candidate, nameserver, port)
            next if !sender
            senders[[candidate, requester, nameserver, port]] = sender
          end
          begin
            reply, reply_name = requester.request(sender, tout)
          rescue ResolvTimeout
            # Giving up part way through a frame loses stream sync, and a peer
            # seen going away leaves the socket dead.  Either way the requester
            # says so, and the next attempt has to open a fresh connection.  A
            # timeout with the stream still on a frame boundary keeps it.
            unless requester.reusable?
              requesters.delete([nameserver, port])
              requester.close
            end
            raise
          end
          case reply.rcode
          when RCode::NoError
            if reply.tc == 1 and not Requester::TCP === requester
              # Retry via TCP:
              truncated[candidate] = true
              redo
            else
              yield(reply, reply_name)
            end
            return
          when RCode::NXDomain
            raise Config::NXDomain.new(reply_name.to_s)
          else
            raise Config::OtherResolvError.new(reply_name.to_s)
          end
        end
      ensure
        udp_requester&.close
        requesters.each_value { |requester| requester&.close }
      end
    end

    def make_udp_requester # :nodoc:
      nameserver_port = @config.nameserver_port
      if nameserver_port.length == 1
        Requester::ConnectedUDP.new(*nameserver_port[0])
      else
        Requester::UnconnectedUDP.new(*nameserver_port)
      end
    end

    def make_tcp_requester(host, port) # :nodoc:
      return Requester::TCP.new(host, port)
    rescue Errno::ECONNREFUSED
      # Treat a refused TCP connection attempt to a nameserver like a timeout,
      # as Resolv::DNS::Config#resolv considers ResolvTimeout exceptions as a
      # hint to try the next nameserver:
      raise ResolvTimeout
    end

    def extract_resources(msg, name, typeclass) # :nodoc:
      if typeclass < Resource::ANY
        n0 = Name.create(name)
        msg.each_resource {|n, ttl, data|
          yield data if n0 == n
        }
      end
      yielded = false
      n0 = Name.create(name)
      msg.each_resource {|n, ttl, data|
        if n0 == n
          case data
          when typeclass
            yield data
            yielded = true
          when Resource::CNAME
            n0 = data.name
          end
        end
      }
      return if yielded
      msg.each_resource {|n, ttl, data|
        if n0 == n
          case data
          when typeclass
            yield data
          end
        end
      }
    end

    def self.random(arg) # :nodoc:
      begin
        SecureRandom.random_number(arg)
      rescue NotImplementedError
        rand(arg)
      end
    end

    RequestID = {} # :nodoc:
    RequestIDMutex = Thread::Mutex.new # :nodoc:

    def self.allocate_request_id(host, port) # :nodoc:
      id = nil
      RequestIDMutex.synchronize {
        h = (RequestID[[host, port]] ||= {})
        begin
          id = random(0x0000..0xffff)
        end while h[id]
        h[id] = true
      }
      id
    end

    def self.free_request_id(host, port, id) # :nodoc:
      RequestIDMutex.synchronize {
        key = [host, port]
        if h = RequestID[key]
          h.delete id
          if h.empty?
            RequestID.delete key
          end
        end
      }
    end

    case RUBY_PLATFORM
    when *[
      # https://www.rfc-editor.org/rfc/rfc6056.txt
      # Appendix A. Survey of the Algorithms in Use by Some Popular Implementations
      /freebsd/, /linux/, /netbsd/, /openbsd/, /solaris/,
      /darwin/, # the same as FreeBSD
    ] then
      def self.bind_random_port(udpsock, bind_host="0.0.0.0") # :nodoc:
        udpsock.bind(bind_host, 0)
      end
    else
      # Sequential port assignment
      def self.bind_random_port(udpsock, bind_host="0.0.0.0") # :nodoc:
        # Ephemeral port number range recommended by RFC 6056
        port = random(1024..65535)
        udpsock.bind(bind_host, port)
      rescue Errno::EADDRINUSE, # POSIX
             Errno::EACCES, # SunOS: See PRIV_SYS_NFS in privileges(5)
             Errno::EPERM # FreeBSD: security.mac.portacl.port_high is configurable.  See mac_portacl(4).
        retry
      end
    end

    class Requester # :nodoc:
      def initialize
        @senders = {}
        @socks = nil
      end

      # Whether another request may be sent over the same transport.  Only a
      # stream transport can end up in a state that rules this out.
      def reusable?
        true
      end

      # A request could not be written.  Only a stream transport can be left
      # unusable by that; see #reusable?.
      def send_failed
      end

      def request(sender, tout)
        start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        timelimit = start + tout
        begin
          sender.send
        rescue Errno::EHOSTUNREACH, # multi-homed IPv6 may generate this
               Errno::ENETUNREACH,
               Errno::EPIPE, # a peer that went away between requests
               Errno::ECONNRESET # the same, as Windows reports it
          send_failed
          raise ResolvTimeout
        end
        while true
          before_select = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          timeout = timelimit - before_select
          if timeout <= 0
            raise ResolvTimeout
          end
          if @socks.size == 1
            select_result = @socks[0].wait_readable(timeout) ? [ @socks ] : nil
          else
            select_result = IO.select(@socks, nil, nil, timeout)
          end
          if !select_result
            after_select = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            next if after_select < timelimit
            raise ResolvTimeout
          end
          begin
            reply, from = recv_reply(select_result[0], timelimit)
          rescue Errno::ECONNREFUSED, # GNU/Linux, FreeBSD
                 Errno::ECONNRESET, # Windows
                 EOFError
            # No name server running on the server?
            # Don't wait anymore.
            raise ResolvTimeout
          end
          begin
            msg = Message.decode(reply)
          rescue Resolv::DNS::DecodeError
            next # broken DNS message ignored
          end
          if sender == sender_for(from, msg)
            break
          else
            # unexpected DNS message ignored
          end
        end
        return msg, sender.data
      end

      def sender_for(addr, msg)
        @senders[[addr,msg.id]]
      end

      def close
        socks = @socks
        @socks = nil
        socks&.each(&:close)
      end

      class Sender # :nodoc:
        def initialize(msg, data, sock)
          @msg = msg
          @data = data
          @sock = sock
        end
      end

      class UnconnectedUDP < Requester # :nodoc:
        def initialize(*nameserver_port)
          super()
          @nameserver_port = nameserver_port
          @initialized = false
          @mutex = Thread::Mutex.new
        end

        def lazy_initialize
          @mutex.synchronize {
            next if @initialized
            @initialized = true
            @socks_hash = {}
            @socks = []
            @nameserver_port.each {|host, port|
              if host.index(':')
                bind_host = "::"
                af = Socket::AF_INET6
              else
                bind_host = "0.0.0.0"
                af = Socket::AF_INET
              end
              next if @socks_hash[bind_host]
              begin
                sock = UDPSocket.new(af)
              rescue Errno::EAFNOSUPPORT, Errno::EPROTONOSUPPORT
                next # The kernel doesn't support the address family.
              end
              @socks << sock
              @socks_hash[bind_host] = sock
              sock.do_not_reverse_lookup = true
              DNS.bind_random_port(sock, bind_host)
            }
          }
          self
        end

        def recv_reply(readable_socks, timelimit = nil)
          lazy_initialize
          reply, from = readable_socks[0].recvfrom(UDPSize)
          return reply, [from[3],from[1]]
        end

        def sender(msg, data, host, port=Port)
          host = Addrinfo.ip(host).ip_address
          lazy_initialize
          sock = @socks_hash[host.index(':') ? "::" : "0.0.0.0"]
          return nil if !sock
          service = [host, port]
          id = DNS.allocate_request_id(host, port)
          request = msg.encode
          request[0,2] = [id].pack('n')
          return @senders[[service, id]] =
            Sender.new(request, data, sock, host, port)
        end

        def close
          @mutex.synchronize {
            if @initialized
              super
              @senders.each_key {|service, id|
                DNS.free_request_id(service[0], service[1], id)
              }
              @initialized = false
            end
          }
        end

        class Sender < Requester::Sender # :nodoc:
          def initialize(msg, data, sock, host, port)
            super(msg, data, sock)
            @host = host
            @port = port
          end
          attr_reader :data

          def send
            raise "@sock is nil." if @sock.nil?
            @sock.send(@msg, 0, @host, @port)
          end
        end
      end

      class ConnectedUDP < Requester # :nodoc:
        def initialize(host, port=Port)
          super()
          @host = host
          @port = port
          @mutex = Thread::Mutex.new
          @initialized = false
        end

        def lazy_initialize
          @mutex.synchronize {
            next if @initialized
            @initialized = true
            connect_socket
          }
          self
        end

        # The socket to talk to the nameserver over, opening one if there is
        # none yet.  #recv_reply may have replaced it since a sender was
        # created, so senders ask for it per request instead of holding on to
        # one.
        def sock
          lazy_initialize
          @socks[0]
        end

        def recv_reply(readable_socks, timelimit = nil)
          lazy_initialize
          reply = readable_socks[0].recv(UDPSize)
          return reply, nil
        rescue Errno::ECONNREFUSED, Errno::ECONNRESET
          # The kernel reports these from an ICMP message, and a second one for
          # the same pair of endpoints is not always passed on: macOS 26.1 and
          # later deliver every other one.  A retry over this socket would then
          # wait out its whole timeout rather than fail at once, so start over
          # from a new source port.
          @mutex.synchronize {
            if @initialized
              @socks&.each(&:close)
              connect_socket
            end
          }
          raise
        end

        def sender(msg, data, host=@host, port=@port)
          lazy_initialize
          unless host == @host && port == @port
            raise RequestError.new("host/port don't match: #{host}:#{port}")
          end
          id = DNS.allocate_request_id(@host, @port)
          request = msg.encode
          request[0,2] = [id].pack('n')
          return @senders[[nil,id]] = Sender.new(request, data, self)
        end

        def close
          @mutex.synchronize do
            if @initialized
              super
              @senders.each_key {|from, id|
                DNS.free_request_id(@host, @port, id)
              }
              @initialized = false
            end
          end
        end

        private def connect_socket
          is_ipv6 = @host.index(':')
          sock = UDPSocket.new(is_ipv6 ? Socket::AF_INET6 : Socket::AF_INET)
          @socks = [sock]
          sock.do_not_reverse_lookup = true
          DNS.bind_random_port(sock, is_ipv6 ? "::" : "0.0.0.0")
          sock.connect(@host, @port)
        end

        class Sender < Requester::Sender # :nodoc:
          def initialize(msg, data, requester)
            super(msg, data, nil)
            @requester = requester
          end

          def send
            @requester.sock.send(@msg, 0)
          end
          attr_reader :data
        end
      end

      class MDNSOneShot < UnconnectedUDP # :nodoc:
        def sender(msg, data, host, port=Port)
          lazy_initialize
          id = DNS.allocate_request_id(host, port)
          request = msg.encode
          request[0,2] = [id].pack('n')
          sock = @socks_hash[host.index(':') ? "::" : "0.0.0.0"]
          return @senders[id] =
            UnconnectedUDP::Sender.new(request, data, sock, host, port)
        end

        def sender_for(addr, msg)
          lazy_initialize
          @senders[msg.id]
        end
      end

      class TCP < Requester # :nodoc:
        def initialize(host, port=Port)
          super()
          @host = host
          @port = port
          sock = TCPSocket.new(@host, @port)
          @socks = [sock]
          @senders = {}
          @reusable = true
        end

        def reusable?
          @reusable
        end

        def send_failed
          @reusable = false
        end

        def recv_reply(readable_socks, timelimit = nil)
          sock = readable_socks[0]
          len_data = read_exactly(sock, 2, timelimit)
          raise EOFError if len_data.nil? || len_data.bytesize != 2
          len = len_data.unpack('n')[0]
          reply = read_exactly(sock, len, timelimit)
          raise EOFError if reply.nil? || reply.bytesize != len
          @reusable = true
          return reply, nil
        rescue EOFError, SystemCallError
          # Whatever the kernel reported, this socket cannot be trusted for
          # another frame.  In practice that is the peer closing or resetting;
          # the rest is rare enough that erring towards reconnecting is right.
          @reusable = false
          raise
        end

        def sender(msg, data, host=@host, port=@port)
          unless host == @host && port == @port
            raise RequestError.new("host/port don't match: #{host}:#{port}")
          end
          id = DNS.allocate_request_id(@host, @port)
          request = msg.encode
          request[0,2] = [request.length, id].pack('nn')
          return @senders[[nil,id]] = Sender.new(request, data, @socks[0])
        end

        class Sender < Requester::Sender # :nodoc:
          def send
            @sock.print(@msg)
            @sock.flush
          end
          attr_reader :data
        end

        def close
          @reusable = false
          super
          @senders.each_key {|from,id|
            DNS.free_request_id(@host, @port, id)
          }
        end

        private

        # Read +len+ bytes, giving up with ResolvTimeout once +timelimit+ (a
        # CLOCK_MONOTONIC value) has passed.  A shorter result means the peer
        # closed the connection, which the caller turns into an EOFError.
        # Consuming any byte marks the requester unusable until the whole frame
        # has been read, since giving up in between loses frame sync.  Without a
        # +timelimit+ the read blocks instead and keeps no such mark; that is
        # only for a caller still using the one argument form of #recv_reply.
        def read_exactly(sock, len, timelimit)
          return sock.read(len) unless timelimit
          buf = String.new
          while buf.bytesize < len
            case chunk = sock.read_nonblock(len - buf.bytesize, exception: false)
            when :wait_readable
              remaining = timelimit - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              raise ResolvTimeout if remaining <= 0
              sock.wait_readable(remaining) or raise ResolvTimeout
            when nil
              break
            else
              @reusable = false
              buf << chunk
            end
          end
          buf
        end
      end

      ##
      # Indicates a problem with the DNS request.

      class RequestError < StandardError
      end
    end

    class Config # :nodoc:
      def initialize(config_info=nil)
        @mutex = Thread::Mutex.new
        @config_info = config_info
        @initialized = nil
        @timeouts = nil
      end

      def timeouts=(values)
        if values
          values = Array(values)
          values.each do |t|
            Numeric === t or raise ArgumentError, "#{t.inspect} is not numeric"
            t > 0.0 or raise ArgumentError, "timeout=#{t} must be positive"
          end
          @timeouts = values
        else
          @timeouts = nil
        end
      end

      def Config.parse_resolv_conf(filename)
        nameserver = []
        search = nil
        ndots = 1
        File.open(filename, 'rb') {|f|
          f.each {|line|
            line.sub!(/[#;].*/, '')
            keyword, *args = line.split(/\s+/)
            next unless keyword
            case keyword
            when 'nameserver'
              nameserver.concat(args.each(&:freeze))
            when 'domain'
              next if args.empty?
              search = [args[0].freeze]
            when 'search'
              next if args.empty?
              search = args.each(&:freeze)
            when 'options'
              args.each {|arg|
                case arg
                when /\Andots:(\d+)\z/
                  ndots = $1.to_i
                end
              }
            end
          }
        }
        return { :nameserver => nameserver.freeze, :search => search.freeze, :ndots => ndots.freeze }.freeze
      end

      def Config.default_config_hash(filename="/etc/resolv.conf")
        if File.exist? filename
          Config.parse_resolv_conf(filename)
        elsif defined?(Win32::Resolv)
          search, nameserver = Win32::Resolv.get_resolv_info
          config_hash = {}
          config_hash[:nameserver] = nameserver if nameserver
          config_hash[:search] = [search].flatten if search
          config_hash
        else
          {}
        end
      end

      def lazy_initialize
        @mutex.synchronize {
          unless @initialized
            @nameserver_port = []
            @use_ipv6 = nil
            @search = nil
            @ndots = 1
            case @config_info
            when nil
              config_hash = Config.default_config_hash
            when String
              config_hash = Config.parse_resolv_conf(@config_info)
            when Hash
              config_hash = @config_info.dup
              if String === config_hash[:nameserver]
                config_hash[:nameserver] = [config_hash[:nameserver]]
              end
              if String === config_hash[:search]
                config_hash[:search] = [config_hash[:search]]
              end
            else
              raise ArgumentError.new("invalid resolv configuration: #{@config_info.inspect}")
            end
            if config_hash.include? :nameserver
              @nameserver_port = config_hash[:nameserver].map {|ns| [ns, Port] }
            end
            if config_hash.include? :nameserver_port
              @nameserver_port = config_hash[:nameserver_port].map {|ns, port| [ns, (port || Port)] }
            end
            if config_hash.include? :use_ipv6
              @use_ipv6 = config_hash[:use_ipv6]
            end
            @search = config_hash[:search] if config_hash.include? :search
            @ndots = config_hash[:ndots] if config_hash.include? :ndots
            @raise_timeout_errors = config_hash[:raise_timeout_errors]

            if @nameserver_port.empty?
              @nameserver_port << ['0.0.0.0', Port]
            end
            if @search
              @search = @search.map {|arg| Label.split(arg) }
            else
              hostname = Socket.gethostname
              if /\./ =~ hostname
                @search = [Label.split($')]
              else
                @search = []
              end
            end

            if !@nameserver_port.kind_of?(Array) ||
               @nameserver_port.any? {|ns_port|
                  !(Array === ns_port) ||
                  ns_port.length != 2
                  !(String === ns_port[0]) ||
                  !(Integer === ns_port[1])
               }
              raise ArgumentError.new("invalid nameserver config: #{@nameserver_port.inspect}")
            end

            if !@search.kind_of?(Array) ||
               !@search.all? {|ls| ls.all? {|l| Label::Str === l } }
              raise ArgumentError.new("invalid search config: #{@search.inspect}")
            end

            if !@ndots.kind_of?(Integer)
              raise ArgumentError.new("invalid ndots config: #{@ndots.inspect}")
            end

            @initialized = true
          end
        }
        self
      end

      def single?
        lazy_initialize
        if @nameserver_port.length == 1
          return @nameserver_port[0]
        else
          return nil
        end
      end

      def nameserver_port
        @nameserver_port
      end

      def use_ipv6?
        @use_ipv6
      end

      def generate_candidates(name)
        name = Name.create(name)
        if name.absolute?
          [name]
        else
          abs = Name.new(name.to_a)
          search = @search.map {|domain| Name.new(name.to_a + domain)}
          if @ndots <= name.length - 1
            [abs, *search].uniq
          else
            [*search, abs].uniq
          end
        end
      end

      InitialTimeout = 5

      def generate_timeouts
        ts = [InitialTimeout]
        ts << ts[-1] * 2 / @nameserver_port.length
        ts << ts[-1] * 2
        ts << ts[-1] * 2
        return ts
      end

      def resolv(name)
        candidates = generate_candidates(name)
        timeouts = @timeouts || generate_timeouts
        timeout_error = false
        begin
          candidates.each {|candidate|
            begin
              timeouts.each {|tout|
                @nameserver_port.each {|nameserver, port|
                  begin
                    yield candidate, tout, nameserver, port
                  rescue ResolvTimeout
                  end
                }
              }
              timeout_error = true
              raise ResolvError.new("DNS resolv timeout: #{name}")
            rescue NXDomain
            end
          }
        rescue ResolvError
          raise if @raise_timeout_errors && timeout_error
        end
      end

      ##
      # Indicates no such domain was found.

      class NXDomain < ResolvError
      end

      ##
      # Indicates some other unhandled resolver error was encountered.

      class OtherResolvError < ResolvError
      end
    end

    module OpCode # :nodoc:
      Query = 0
      IQuery = 1
      Status = 2
      Notify = 4
      Update = 5
    end

    module RCode # :nodoc:
      NoError = 0
      FormErr = 1
      ServFail = 2
      NXDomain = 3
      NotImp = 4
      Refused = 5
      YXDomain = 6
      YXRRSet = 7
      NXRRSet = 8
      NotAuth = 9
      NotZone = 10
      BADVERS = 16
      BADSIG = 16
      BADKEY = 17
      BADTIME = 18
      BADMODE = 19
      BADNAME = 20
      BADALG = 21
    end

    ##
    # Indicates that the DNS response was unable to be decoded.

    class DecodeError < StandardError
    end

    ##
    # Indicates that the DNS request was unable to be encoded.

    class EncodeError < StandardError
    end

    module Label # :nodoc:
      def self.split(arg)
        labels = []
        arg.scan(/[^\.]+/) {labels << Str.new($&)}
        return labels
      end

      class Str # :nodoc:
        def initialize(string)
          # A label is limited to 63 octets. [RFC 1035 2.3.4] Checking it here
          # makes it an invariant of the object: every label, however it was
          # built, fits in its length octet and cannot wrap it. Callers turn
          # this into the error their own contract promises.
          if string.bytesize > 63
            raise ArgumentError, "DNS label is too long (#{string.bytesize} bytes, max 63): #{string.inspect}"
          end
          @string = string
          # case insensivity of DNS labels doesn't apply non-ASCII characters. [RFC 4343]
          # This assumes @string is given in ASCII compatible encoding.
          @downcase = string.b.downcase
        end
        attr_reader :string, :downcase

        def to_s
          return @string
        end

        def inspect
          return "#<#{self.class} #{self}>"
        end

        def ==(other)
          return self.class == other.class && @downcase == other.downcase
        end

        def eql?(other)
          return self == other
        end

        def hash
          return @downcase.hash
        end
      end
    end

    ##
    # A representation of a DNS name.

    class Name

      ##
      # Creates a new DNS name from +arg+.  +arg+ can be:
      #
      # Name:: returns +arg+.
      # String:: Creates a new Name.

      def self.create(arg)
        case arg
        when Name
          return arg
        when String
          # A hostname is runtime data rather than a programming mistake, so
          # both size limits surface as ResolvError to stay rescuable alongside
          # the rest of name resolution. The type check below is a caller
          # mistake and keeps raising ArgumentError.
          begin
            labels = Label.split(arg)
          rescue ArgumentError => e
            raise ResolvError.new(e.message)
          end
          # Label::Str enforces the per-label limit. Only the total is knowable
          # here, and it counts the encoded form, so size starts at 1 for the
          # root label's terminating zero octet. [RFC 1035 2.3.4, 3.1]
          size = 1
          labels.each do |label|
            size += 1 + label.string.bytesize
            if size > 255
              raise ResolvError.new("DNS name is too long (#{size} octets, max 255): #{arg.inspect}")
            end
          end
          return Name.new(labels, /\.\z/ =~ arg ? true : false)
        else
          raise ArgumentError.new("cannot interpret as DNS name: #{arg.inspect}")
        end
      end

      def initialize(labels, absolute=true) # :nodoc:
        labels = labels.map {|label|
          case label
          when String then Label::Str.new(label)
          when Label::Str then label
          else
            raise ArgumentError, "unexpected label: #{label.inspect}"
          end
        }
        @labels = labels
        @absolute = absolute
      end

      def inspect # :nodoc:
        "#<#{self.class}: #{self}#{@absolute ? '.' : ''}>"
      end

      ##
      # True if this name is absolute.

      def absolute?
        return @absolute
      end

      def ==(other) # :nodoc:
        return false unless Name === other
        return false unless @absolute == other.absolute?
        return @labels == other.to_a
      end

      alias eql? == # :nodoc:

      ##
      # Returns true if +other+ is a subdomain.
      #
      # Example:
      #
      #   domain = Resolv::DNS::Name.create("y.z")
      #   p Resolv::DNS::Name.create("w.x.y.z").subdomain_of?(domain) #=> true
      #   p Resolv::DNS::Name.create("x.y.z").subdomain_of?(domain) #=> true
      #   p Resolv::DNS::Name.create("y.z").subdomain_of?(domain) #=> false
      #   p Resolv::DNS::Name.create("z").subdomain_of?(domain) #=> false
      #   p Resolv::DNS::Name.create("x.y.z.").subdomain_of?(domain) #=> false
      #   p Resolv::DNS::Name.create("w.z").subdomain_of?(domain) #=> false
      #

      def subdomain_of?(other)
        raise ArgumentError, "not a domain name: #{other.inspect}" unless Name === other
        return false if @absolute != other.absolute?
        other_len = other.length
        return false if @labels.length <= other_len
        return @labels[-other_len, other_len] == other.to_a
      end

      def hash # :nodoc:
        return @labels.hash ^ @absolute.hash
      end

      def to_a # :nodoc:
        return @labels
      end

      def length # :nodoc:
        return @labels.length
      end

      def [](i) # :nodoc:
        return @labels[i]
      end

      ##
      # returns the domain name as a string.
      #
      # The domain name doesn't have a trailing dot even if the name object is
      # absolute.
      #
      # Example:
      #
      #   p Resolv::DNS::Name.create("x.y.z.").to_s #=> "x.y.z"
      #   p Resolv::DNS::Name.create("x.y.z").to_s #=> "x.y.z"

      def to_s
        return @labels.join('.')
      end
    end

    class Message # :nodoc:
      @@identifier = -1

      def initialize(id = (@@identifier += 1) & 0xffff)
        @id = id
        @qr = 0
        @opcode = 0
        @aa = 0
        @tc = 0
        @rd = 0 # recursion desired
        @ra = 0 # recursion available
        @rcode = 0
        @question = []
        @answer = []
        @authority = []
        @additional = []
      end

      attr_accessor :id, :qr, :opcode, :aa, :tc, :rd, :ra, :rcode
      attr_reader :question, :answer, :authority, :additional

      def ==(other)
        return @id == other.id &&
               @qr == other.qr &&
               @opcode == other.opcode &&
               @aa == other.aa &&
               @tc == other.tc &&
               @rd == other.rd &&
               @ra == other.ra &&
               @rcode == other.rcode &&
               question_equal?(other.question) &&
               @answer == other.answer &&
               @authority == other.authority &&
               @additional == other.additional
      end

      # A question holds the resource class itself, and decoding creates a fresh
      # class for each unknown type, so the classes cannot be compared by
      # identity alone.
      private def question_equal?(other_question) # :nodoc:
        return false unless @question.length == other_question.length
        @question.zip(other_question) {|(name, typeclass), (o_name, o_typeclass)|
          return false unless name == o_name &&
                              Resource::Generic.type_class_equal?(typeclass, o_typeclass)
        }
        return true
      end

      def add_question(name, typeclass)
        @question << [Name.create(name), typeclass]
      end

      def each_question
        @question.each {|name, typeclass|
          yield name, typeclass
        }
      end

      def add_answer(name, ttl, data)
        @answer << [Name.create(name), ttl, data]
      end

      def each_answer
        @answer.each {|name, ttl, data|
          yield name, ttl, data
        }
      end

      def add_authority(name, ttl, data)
        @authority << [Name.create(name), ttl, data]
      end

      def each_authority
        @authority.each {|name, ttl, data|
          yield name, ttl, data
        }
      end

      def add_additional(name, ttl, data)
        @additional << [Name.create(name), ttl, data]
      end

      def each_additional
        @additional.each {|name, ttl, data|
          yield name, ttl, data
        }
      end

      def each_resource
        each_answer {|name, ttl, data| yield name, ttl, data}
        each_authority {|name, ttl, data| yield name, ttl, data}
        each_additional {|name, ttl, data| yield name, ttl, data}
      end

      def encode
        return MessageEncoder.new {|msg|
          msg.put_pack('nnnnnn',
            @id,
            (@qr & 1) << 15 |
            (@opcode & 15) << 11 |
            (@aa & 1) << 10 |
            (@tc & 1) << 9 |
            (@rd & 1) << 8 |
            (@ra & 1) << 7 |
            (@rcode & 15),
            @question.length,
            @answer.length,
            @authority.length,
            @additional.length)
          @question.each {|q|
            name, typeclass = q
            msg.put_name(name)
            msg.put_pack('nn', typeclass::TypeValue, typeclass::ClassValue)
          }
          [@answer, @authority, @additional].each {|rr|
            rr.each {|r|
              name, ttl, data = r
              msg.put_name(name)
              msg.put_pack('nnN', data.class::TypeValue, data.class::ClassValue, ttl)
              msg.put_length16 {data.encode_rdata(msg)}
            }
          }
        }.to_s
      end

      class MessageEncoder # :nodoc:
        def initialize(options = {})
          @data = ''.dup
          @names = {}
          @canonical = options[:canonical] || false
          yield self
        end

        def to_s
          return @data
        end

        def put_bytes(d)
          @data << d
        end

        def put_pack(template, *d)
          @data << d.pack(template)
        end

        def put_length16
          length_index = @data.length
          @data << "\0\0"
          data_start = @data.length
          yield
          data_end = @data.length
          @data[length_index, 2] = [data_end - data_start].pack("n")
        end

        def put_string(d)
          s = d.to_s
          # A character-string is prefixed by a single length octet, so it can
          # hold at most 255 octets. [RFC 1035 3.3] Reject anything longer to
          # avoid silently truncating the length to its low 8 bits (mod 256).
          if s.bytesize > 255
            raise ArgumentError, "character-string is too long (#{s.bytesize} bytes, max 255): #{s.inspect}"
          end
          self.put_pack("C", s.bytesize)
          @data << s
        end

        def put_string_list(ds)
          ds.each {|d|
            self.put_string(d)
          }
        end

        def put_name(d, compress: true, canonical: @canonical)
          compress = false if canonical
          put_labels(d.to_a, compress: compress, canonical: canonical)
        end

        def put_labels(d, compress: true, canonical: @canonical)
          d.each_index {|i|
            domain = d[i..-1]
            if !canonical && compress && idx = @names[domain]
              self.put_pack("n", 0xc000 | idx)
              return
            else
              if !canonical && @data.length < 0x4000
                @names[domain] = @data.length
              end
              self.put_label(d[i], canonical)
            end
          }
          @data << "\0"
        end

        def put_label(d, canonical = @canonical)
          s = d.to_s
          # Label::Str applies this limit when a label is built, so what is left
          # for here is a raw string handed straight to put_labels. The two ways
          # an over-long label goes wrong differ: 64 to 255 octets write a length
          # octet in the reserved or compression pointer range, and 256 or more
          # wrap it mod 256. Either way the encoded name stops being the name the
          # caller asked for. [RFC 1035 2.3.4, 4.1.4]
          if s.bytesize > 63
            raise ArgumentError, "DNS label is too long (#{s.bytesize} bytes, max 63): #{s.inspect}"
          end
          s = s.b.downcase if canonical
          self.put_string(s)
        end
      end

      def Message.decode(m)
        o = Message.new(0)
        MessageDecoder.new(m) {|msg|
          id, flag, qdcount, ancount, nscount, arcount =
            msg.get_unpack('nnnnnn')
          o.id = id
          o.tc = (flag >> 9) & 1
          o.rcode = flag & 15
          return o unless o.tc.zero?

          o.qr = (flag >> 15) & 1
          o.opcode = (flag >> 11) & 15
          o.aa = (flag >> 10) & 1
          o.rd = (flag >> 8) & 1
          o.ra = (flag >> 7) & 1
          (1..qdcount).each {
            name, typeclass = msg.get_question
            o.add_question(name, typeclass)
          }
          (1..ancount).each {
            name, ttl, data = msg.get_rr
            o.add_answer(name, ttl, data)
          }
          (1..nscount).each {
            name, ttl, data = msg.get_rr
            o.add_authority(name, ttl, data)
          }
          (1..arcount).each {
            name, ttl, data = msg.get_rr
            o.add_additional(name, ttl, data)
          }
        }
        return o
      end

      class MessageDecoder # :nodoc:
        def initialize(data)
          @data = data
          @index = 0
          @limit = data.bytesize
          yield self
        end

        def inspect
          "\#<#{self.class}: #{@data.byteslice(0, @index).inspect} #{@data.byteslice(@index..-1).inspect}>"
        end

        def get_length16
          len, = self.get_unpack('n')
          save_limit = @limit
          @limit = @index + len
          d = yield(len)
          if @index < @limit
            raise DecodeError.new("junk exists")
          elsif @limit < @index
            raise DecodeError.new("limit exceeded")
          end
          @limit = save_limit
          return d
        end

        def get_bytes(len = @limit - @index)
          raise DecodeError.new("limit exceeded") if @limit < @index + len
          d = @data.byteslice(@index, len)
          @index += len
          return d
        end

        def get_unpack(template)
          len = 0
          template.each_byte {|byte|
            byte = "%c" % byte
            case byte
            when ?c, ?C
              len += 1
            when ?n
              len += 2
            when ?N
              len += 4
            else
              raise StandardError.new("unsupported template: '#{byte.chr}' in '#{template}'")
            end
          }
          raise DecodeError.new("limit exceeded") if @limit < @index + len
          arr = @data.unpack("@#{@index}#{template}")
          @index += len
          return arr
        end

        def get_string
          raise DecodeError.new("limit exceeded") if @limit <= @index
          len = @data.getbyte(@index)
          raise DecodeError.new("limit exceeded") if @limit < @index + 1 + len
          d = @data.byteslice(@index + 1, len)
          @index += 1 + len
          return d
        end

        def get_string_list
          strings = []
          while @index < @limit
            strings << self.get_string
          end
          strings
        end

        def get_list
          [].tap do |values|
            while @index < @limit
              values << yield
            end
          end
        end

        def get_name
          return Name.new(self.get_labels)
        end

        def get_labels
          prev_index = @index
          save_index = nil
          d = []
          # size counts the encoded form, so it starts at 1 for the root
          # label's terminating zero octet. [RFC 1035 3.1]
          size = 1
          while true
            raise DecodeError.new("limit exceeded") if @limit <= @index
            case @data.getbyte(@index)
            when 0
              @index += 1
              if save_index
                @index = save_index
              end
              return d
            when 192..255
              idx = self.get_unpack('n')[0] & 0x3fff
              if prev_index <= idx
                raise DecodeError.new("non-backward name pointer")
              end
              prev_index = idx
              if !save_index
                save_index = @index
              end
              @index = idx
            else
              l = self.get_label
              d << l
              size += 1 + l.string.bytesize
              raise DecodeError.new("name label data exceed 255 octets") if size > 255
            end
          end
        end

        def get_label
          return Label::Str.new(self.get_string)
        rescue ArgumentError => e
          # A length octet of 64..191 is reserved rather than a label length,
          # but this decoder used to read it as one. [RFC 1035 4.1.4] Report it
          # the way the rest of a malformed message is reported.
          raise DecodeError.new(e.message)
        end

        def get_question
          name = self.get_name
          type, klass = self.get_unpack("nn")
          return name, Resource.get_class(type, klass)
        end

        def get_rr
          name = self.get_name
          type, klass, ttl = self.get_unpack('nnN')
          typeclass = Resource.get_class(type, klass)
          res = self.get_length16 do
            begin
              typeclass.decode_rdata self
            rescue => e
              raise DecodeError, e.message, e.backtrace
            end
          end
          res.instance_variable_set :@ttl, ttl
          return name, ttl, res
        end
      end
    end

    ##
    # SvcParams for service binding RRs. [RFC9460]

    class SvcParams
      include Enumerable

      ##
      # Create a list of SvcParams with the given initial content.
      #
      # +params+ has to be an enumerable of +SvcParam+s.
      # If its content has +SvcParam+s with the duplicate key,
      # the one appears last takes precedence.

      def initialize(params = [])
        @params = {}

        params.each do |param|
          add param
        end
      end

      ##
      # Get SvcParam for the given +key+ in this list.

      def [](key)
        @params[canonical_key(key)]
      end

      ##
      # Get the number of SvcParams in this list.

      def count
        @params.count
      end

      ##
      # Get whether this list is empty.

      def empty?
        @params.empty?
      end

      ##
      # Add the SvcParam +param+ to this list, overwriting the existing one with the same key.

      def add(param)
        @params[param.class.key_number] = param
      end

      ##
      # Remove the +SvcParam+ with the given +key+ and return it.

      def delete(key)
        @params.delete(canonical_key(key))
      end

      ##
      # Enumerate the +SvcParam+s in this list.

      def each(&block)
        return enum_for(:each) unless block
        @params.each_value(&block)
      end

      def encode(msg) # :nodoc:
        @params.keys.sort.each do |key|
          msg.put_pack('n', key)
          msg.put_length16 do
            @params.fetch(key).encode(msg)
          end
        end
      end

      def self.decode(msg) # :nodoc:
        params = msg.get_list do
          key, = msg.get_unpack('n')
          msg.get_length16 do
            SvcParam::ClassHash[key].decode(msg)
          end
        end

        return self.new(params)
      end

      private

      def canonical_key(key) # :nodoc:
        case key
        when Integer
          key
        when /\Akey(\d+)\z/
          Integer($1)
        when Symbol
          SvcParam::ClassHash[key].key_number
        else
          raise TypeError, 'key must be either String or Symbol'
        end
      end
    end

    ##
    # Base class for SvcParam. [RFC9460]

    class SvcParam

      ##
      # Get the presentation name of the SvcParamKey.

      def self.key_name
        const_get(:KeyName)
      end

      ##
      # Get the registered number of the SvcParamKey.

      def self.key_number
        const_get(:KeyNumber)
      end

      ClassHash = Hash.new do |h, key| # :nodoc:
        case key
        when Integer
          Generic.create(key)
        when /\Akey(?<key>\d+)\z/
          Generic.create(key.to_int)
        when Symbol
          raise KeyError, "unknown key #{key}"
        else
          raise TypeError, 'key must be either String or Symbol'
        end
      end

      ##
      # Generic SvcParam abstract class.

      class Generic < SvcParam

        ##
        # SvcParamValue in wire-format byte string.

        attr_reader :value

        ##
        # Create generic SvcParam

        def initialize(value)
          @value = value
        end

        def encode(msg) # :nodoc:
          msg.put_bytes(@value)
        end

        def self.decode(msg) # :nodoc:
          return self.new(msg.get_bytes)
        end

        def self.create(key_number)
          c = Class.new(Generic)
          key_name = :"key#{key_number}"
          c.const_set(:KeyName, key_name)
          c.const_set(:KeyNumber, key_number)
          # Not registered in a constant or in ClassHash. ClassHash creates a
          # class for every unknown SvcParamKey, so registering them
          # permanently would let a malicious response exhaust memory.
          return c
        end
      end

      ##
      # "mandatory" SvcParam -- Mandatory keys in service binding RR

      class Mandatory < SvcParam
        KeyName = :mandatory
        KeyNumber = 0
        ClassHash[KeyName] = ClassHash[KeyNumber] = self # :nodoc:

        ##
        # Mandatory keys.

        attr_reader :keys

        ##
        # Initialize "mandatory" ScvParam.

        def initialize(keys)
          @keys = keys.map(&:to_int)
        end

        def encode(msg) # :nodoc:
          @keys.sort.each do |key|
            msg.put_pack('n', key)
          end
        end

        def self.decode(msg) # :nodoc:
          keys = msg.get_list { msg.get_unpack('n')[0] }
          return self.new(keys)
        end
      end

      ##
      # "alpn" SvcParam -- Additional supported protocols

      class ALPN < SvcParam
        KeyName = :alpn
        KeyNumber = 1
        ClassHash[KeyName] = ClassHash[KeyNumber] = self # :nodoc:

        ##
        # Supported protocol IDs.

        attr_reader :protocol_ids

        ##
        # Initialize "alpn" ScvParam.

        def initialize(protocol_ids)
          @protocol_ids = protocol_ids.map(&:to_str)
        end

        def encode(msg) # :nodoc:
          msg.put_string_list(@protocol_ids)
        end

        def self.decode(msg) # :nodoc:
          return self.new(msg.get_string_list)
        end
      end

      ##
      # "no-default-alpn" SvcParam -- No support for default protocol

      class NoDefaultALPN < SvcParam
        KeyName = :'no-default-alpn'
        KeyNumber = 2
        ClassHash[KeyName] = ClassHash[KeyNumber] = self # :nodoc:

        def encode(msg) # :nodoc:
          # no payload
        end

        def self.decode(msg) # :nodoc:
          return self.new
        end
      end

      ##
      # "port" SvcParam -- Port for alternative endpoint

      class Port < SvcParam
        KeyName = :port
        KeyNumber = 3
        ClassHash[KeyName] = ClassHash[KeyNumber] = self # :nodoc:

        ##
        # Port number.

        attr_reader :port

        ##
        # Initialize "port" ScvParam.

        def initialize(port)
          @port = port.to_int
        end

        def encode(msg) # :nodoc:
          msg.put_pack('n', @port)
        end

        def self.decode(msg) # :nodoc:
          port, = msg.get_unpack('n')
          return self.new(port)
        end
      end

      ##
      # "ipv4hint" SvcParam -- IPv4 address hints

      class IPv4Hint < SvcParam
        KeyName = :ipv4hint
        KeyNumber = 4
        ClassHash[KeyName] = ClassHash[KeyNumber] = self # :nodoc:

        ##
        # Set of IPv4 addresses.

        attr_reader :addresses

        ##
        # Initialize "ipv4hint" ScvParam.

        def initialize(addresses)
          @addresses = addresses.map {|address| IPv4.create(address) }
        end

        def encode(msg) # :nodoc:
          @addresses.each do |address|
            msg.put_bytes(address.address)
          end
        end

        def self.decode(msg) # :nodoc:
          addresses = msg.get_list { IPv4.new(msg.get_bytes(4)) }
          return self.new(addresses)
        end
      end

      ##
      # "ipv6hint" SvcParam -- IPv6 address hints

      class IPv6Hint < SvcParam
        KeyName = :ipv6hint
        KeyNumber = 6
        ClassHash[KeyName] = ClassHash[KeyNumber] = self # :nodoc:

        ##
        # Set of IPv6 addresses.

        attr_reader :addresses

        ##
        # Initialize "ipv6hint" ScvParam.

        def initialize(addresses)
          @addresses = addresses.map {|address| IPv6.create(address) }
        end

        def encode(msg) # :nodoc:
          @addresses.each do |address|
            msg.put_bytes(address.address)
          end
        end

        def self.decode(msg) # :nodoc:
          addresses = msg.get_list { IPv6.new(msg.get_bytes(16)) }
          return self.new(addresses)
        end
      end

      ##
      # "dohpath" SvcParam -- DNS over HTTPS path template [RFC9461]

      class DoHPath < SvcParam
        KeyName = :dohpath
        KeyNumber = 7
        ClassHash[KeyName] = ClassHash[KeyNumber] = self # :nodoc:

        ##
        # URI template for DoH queries.

        attr_reader :template

        ##
        # Initialize "dohpath" ScvParam.

        def initialize(template)
          @template = template.encode('utf-8')
        end

        def encode(msg) # :nodoc:
          msg.put_bytes(@template)
        end

        def self.decode(msg) # :nodoc:
          template = msg.get_bytes.force_encoding('utf-8')
          return self.new(template)
        end
      end
    end

    ##
    # A DNS query abstract class.

    class Query
      def encode_rdata(msg) # :nodoc:
        raise EncodeError.new("#{self.class} is query.")
      end

      def self.decode_rdata(msg) # :nodoc:
        raise DecodeError.new("#{self.class} is query.")
      end
    end

    ##
    # A DNS resource abstract class.

    class Resource < Query

      ##
      # Remaining Time To Live for this Resource.

      attr_reader :ttl

      ClassHash = Module.new do
        module_function

        def []=(type_class_value, klass)
          type_value, class_value = type_class_value
          Resource.const_set(:"Type#{type_value}_Class#{class_value}", klass)
        end
      end

      def encode_rdata(msg) # :nodoc:
        raise NotImplementedError.new
      end

      def self.decode_rdata(msg) # :nodoc:
        raise NotImplementedError.new
      end

      def ==(other) # :nodoc:
        return false unless self.class == other.class
        s_ivars = self.instance_variables
        s_ivars.sort!
        s_ivars.delete :@ttl
        o_ivars = other.instance_variables
        o_ivars.sort!
        o_ivars.delete :@ttl
        return s_ivars == o_ivars &&
          s_ivars.collect {|name| self.instance_variable_get name} ==
            o_ivars.collect {|name| other.instance_variable_get name}
      end

      def eql?(other) # :nodoc:
        return self == other
      end

      def hash # :nodoc:
        h = 0
        vars = self.instance_variables
        vars.delete :@ttl
        vars.each {|name|
          h ^= self.instance_variable_get(name).hash
        }
        return h
      end

      def self.get_class(type_value, class_value) # :nodoc:
        cache = :"Type#{type_value}_Class#{class_value}"

        return (const_defined?(cache) && const_get(cache)) ||
               Generic.create(type_value, class_value)
      end

      ##
      # A generic resource abstract class.

      class Generic < Resource

        ##
        # Creates a new generic resource.

        def initialize(data)
          @data = data
        end

        ##
        # Data for this generic resource.

        attr_reader :data

        def encode_rdata(msg) # :nodoc:
          msg.put_bytes(data)
        end

        def self.decode_rdata(msg) # :nodoc:
          return self.new(msg.get_bytes)
        end

        # create makes a fresh class for each decoded resource, so the type and
        # class values have to be compared instead of the class itself.
        def self.type_class_equal?(klass, other) # :nodoc:
          return true if klass.equal?(other)
          Generic > klass && Generic > other &&
            klass::TypeValue == other::TypeValue &&
            klass::ClassValue == other::ClassValue
        end

        def ==(other) # :nodoc:
          return other.is_a?(Generic) &&
                 Generic.type_class_equal?(self.class, other.class) &&
                 @data == other.data
        end

        def self.create(type_value, class_value) # :nodoc:
          c = Class.new(Generic)
          c.const_set(:TypeValue, type_value)
          c.const_set(:ClassValue, class_value)
          # Not registered in a constant or in ClassHash. get_class creates a
          # class for every unknown (type, class) pair, so registering them
          # permanently would let a malicious response exhaust memory.
          return c
        end
      end

      ##
      # Domain Name resource abstract class.

      class DomainName < Resource

        ##
        # Creates a new DomainName from +name+.

        def initialize(name)
          @name = name
        end

        ##
        # The name of this DomainName.

        attr_reader :name

        def encode_rdata(msg) # :nodoc:
          msg.put_name(@name)
        end

        def self.decode_rdata(msg) # :nodoc:
          return self.new(msg.get_name)
        end
      end

      # Standard (class generic) RRs

      ClassValue = nil # :nodoc:

      ##
      # An authoritative name server.

      class NS < DomainName
        TypeValue = 2 # :nodoc:
      end

      ##
      # The canonical name for an alias.

      class CNAME < DomainName
        TypeValue = 5 # :nodoc:
      end

      ##
      # Delegation Signer resource.

      class DS < Resource
        TypeValue = 43 # :nodoc:

        def initialize(key_tag, algorithm, digest_type, digest)
          @key_tag = key_tag
          @algorithm = algorithm
          @digest_type = digest_type
          @digest = digest
        end

        attr_reader :key_tag, :algorithm, :digest_type, :digest

        def encode_rdata(msg) # :nodoc:
          msg.put_pack('nCC', @key_tag, @algorithm, @digest_type)
          msg.put_bytes(@digest)
        end

        def self.decode_rdata(msg) # :nodoc:
          key_tag, algorithm, digest_type = msg.get_unpack('nCC')
          self.new(key_tag, algorithm, digest_type, msg.get_bytes)
        end
      end

      ##
      # Start Of Authority resource.

      class SOA < Resource

        TypeValue = 6 # :nodoc:

        ##
        # Creates a new SOA record.  See the attr documentation for the
        # details of each argument.

        def initialize(mname, rname, serial, refresh, retry_, expire, minimum)
          @mname = mname
          @rname = rname
          @serial = serial
          @refresh = refresh
          @retry = retry_
          @expire = expire
          @minimum = minimum
        end

        ##
        # Name of the host where the master zone file for this zone resides.

        attr_reader :mname

        ##
        # The person responsible for this domain name.

        attr_reader :rname

        ##
        # The version number of the zone file.

        attr_reader :serial

        ##
        # How often, in seconds, a secondary name server is to check for
        # updates from the primary name server.

        attr_reader :refresh

        ##
        # How often, in seconds, a secondary name server is to retry after a
        # failure to check for a refresh.

        attr_reader :retry

        ##
        # Time in seconds that a secondary name server is to use the data
        # before refreshing from the primary name server.

        attr_reader :expire

        ##
        # The minimum number of seconds to be used for TTL values in RRs.

        attr_reader :minimum

        def encode_rdata(msg) # :nodoc:
          msg.put_name(@mname)
          msg.put_name(@rname)
          msg.put_pack('NNNNN', @serial, @refresh, @retry, @expire, @minimum)
        end

        def self.decode_rdata(msg) # :nodoc:
          mname = msg.get_name
          rname = msg.get_name
          serial, refresh, retry_, expire, minimum = msg.get_unpack('NNNNN')
          return self.new(
            mname, rname, serial, refresh, retry_, expire, minimum)
        end
      end

      ##
      # A Pointer to another DNS name.

      class PTR < DomainName
        TypeValue = 12 # :nodoc:
      end

      ##
      # Host Information resource.

      class HINFO < Resource

        TypeValue = 13 # :nodoc:

        ##
        # Creates a new HINFO running +os+ on +cpu+.

        def initialize(cpu, os)
          @cpu = cpu
          @os = os
        end

        ##
        # CPU architecture for this resource.

        attr_reader :cpu

        ##
        # Operating system for this resource.

        attr_reader :os

        def encode_rdata(msg) # :nodoc:
          msg.put_string(@cpu)
          msg.put_string(@os)
        end

        def self.decode_rdata(msg) # :nodoc:
          cpu = msg.get_string
          os = msg.get_string
          return self.new(cpu, os)
        end
      end

      ##
      # Mailing list or mailbox information.

      class MINFO < Resource

        TypeValue = 14 # :nodoc:

        def initialize(rmailbx, emailbx)
          @rmailbx = rmailbx
          @emailbx = emailbx
        end

        ##
        # Domain name responsible for this mail list or mailbox.

        attr_reader :rmailbx

        ##
        # Mailbox to use for error messages related to the mail list or mailbox.

        attr_reader :emailbx

        def encode_rdata(msg) # :nodoc:
          msg.put_name(@rmailbx)
          msg.put_name(@emailbx)
        end

        def self.decode_rdata(msg) # :nodoc:
          rmailbx = msg.get_string
          emailbx = msg.get_string
          return self.new(rmailbx, emailbx)
        end
      end

      ##
      # Mail Exchanger resource.

      class MX < Resource

        TypeValue= 15 # :nodoc:

        ##
        # Creates a new MX record with +preference+, accepting mail at
        # +exchange+.

        def initialize(preference, exchange)
          @preference = preference
          @exchange = exchange
        end

        ##
        # The preference for this MX.

        attr_reader :preference

        ##
        # The host of this MX.

        attr_reader :exchange

        def encode_rdata(msg) # :nodoc:
          msg.put_pack('n', @preference)
          msg.put_name(@exchange)
        end

        def self.decode_rdata(msg) # :nodoc:
          preference, = msg.get_unpack('n')
          exchange = msg.get_name
          return self.new(preference, exchange)
        end
      end

      ##
      # Unstructured text resource.

      class TXT < Resource

        TypeValue = 16 # :nodoc:

        def initialize(first_string, *rest_strings)
          @strings = [first_string, *rest_strings]
        end

        ##
        # Returns an Array of Strings for this TXT record.

        attr_reader :strings

        ##
        # Returns the concatenated string from +strings+.

        def data
          @strings.join("")
        end

        def encode_rdata(msg) # :nodoc:
          msg.put_string_list(@strings)
        end

        def self.decode_rdata(msg) # :nodoc:
          strings = msg.get_string_list
          return self.new(*strings)
        end
      end

      ##
      # Location resource

      class LOC < Resource

        TypeValue = 29 # :nodoc:

        def initialize(version, ssize, hprecision, vprecision, latitude, longitude, altitude)
          @version    = version
          @ssize      = Resolv::LOC::Size.create(ssize)
          @hprecision = Resolv::LOC::Size.create(hprecision)
          @vprecision = Resolv::LOC::Size.create(vprecision)
          @latitude   = Resolv::LOC::Coord.create(latitude)
          @longitude  = Resolv::LOC::Coord.create(longitude)
          @altitude   = Resolv::LOC::Alt.create(altitude)
        end

        ##
        # Returns the version value for this LOC record which should always be 00

        attr_reader :version

        ##
        # The spherical size of this LOC
        # in meters using scientific notation as 2 integers of XeY

        attr_reader :ssize

        ##
        # The horizontal precision using ssize type values
        # in meters using scientific notation as 2 integers of XeY
        # for precision use value/2 e.g. 2m = +/-1m

        attr_reader :hprecision

        ##
        # The vertical precision using ssize type values
        # in meters using scientific notation as 2 integers of XeY
        # for precision use value/2 e.g. 2m = +/-1m

        attr_reader :vprecision

        ##
        # The latitude for this LOC where 2**31 is the equator
        # in thousandths of an arc second as an unsigned 32bit integer

        attr_reader :latitude

        ##
        # The longitude for this LOC where 2**31 is the prime meridian
        # in thousandths of an arc second as an unsigned 32bit integer

        attr_reader :longitude

        ##
        # The altitude of the LOC above a reference sphere whose surface sits 100km below the WGS84 spheroid
        # in centimeters as an unsigned 32bit integer

        attr_reader :altitude

        def encode_rdata(msg) # :nodoc:
          msg.put_bytes(@version)
          msg.put_bytes(@ssize.scalar)
          msg.put_bytes(@hprecision.scalar)
          msg.put_bytes(@vprecision.scalar)
          msg.put_bytes(@latitude.coordinates)
          msg.put_bytes(@longitude.coordinates)
          msg.put_bytes(@altitude.altitude)
        end

        def self.decode_rdata(msg) # :nodoc:
          version    = msg.get_bytes(1)
          ssize      = msg.get_bytes(1)
          hprecision = msg.get_bytes(1)
          vprecision = msg.get_bytes(1)
          latitude   = msg.get_bytes(4)
          longitude  = msg.get_bytes(4)
          altitude   = msg.get_bytes(4)
          return self.new(
            version,
            Resolv::LOC::Size.new(ssize),
            Resolv::LOC::Size.new(hprecision),
            Resolv::LOC::Size.new(vprecision),
            Resolv::LOC::Coord.new(latitude,"lat"),
            Resolv::LOC::Coord.new(longitude,"lon"),
            Resolv::LOC::Alt.new(altitude)
          )
        end
      end

      ##
      # A Query type requesting any RR.

      class ANY < Query
        TypeValue = 255 # :nodoc:
      end

      ##
      # CAA resource record defined in RFC 8659
      #
      # These records identify certificate authority allowed to issue
      # certificates for the given domain.

      class CAA < Resource
        TypeValue = 257

        ##
        # Creates a new CAA for +flags+, +tag+ and +value+.

        def initialize(flags, tag, value)
          unless (0..255) === flags
            raise ArgumentError.new('flags must be an Integer between 0 and 255')
          end
          unless (1..15) === tag.bytesize
            raise ArgumentError.new('length of tag must be between 1 and 15')
          end

          @flags = flags
          @tag = tag
          @value = value
        end

        ##
        # Flags for this property:
        # - Bit 0 : 0 = not critical, 1 = critical

        attr_reader :flags

        ##
        # Property tag ("issue", "issuewild", "iodef"...).

        attr_reader :tag

        ##
        # Property value.

        attr_reader :value

        ##
        # Whether the critical flag is set on this property.

        def critical?
          flags & 0x80 != 0
        end

        def encode_rdata(msg) # :nodoc:
          msg.put_pack('C', @flags)
          msg.put_string(@tag)
          msg.put_bytes(@value)
        end

        def self.decode_rdata(msg) # :nodoc:
          flags, = msg.get_unpack('C')
          tag = msg.get_string
          value = msg.get_bytes
          self.new flags, tag, value
        end
      end

      ##
      # A DNSKEY resource. [RFC 4034]

      class DNSKEY < Resource
        TypeValue = 48

        def initialize(flags, protocol, algorithm, public_key)
          @flags = flags
          @protocol = protocol
          @algorithm = algorithm
          @public_key = public_key
        end

        attr_reader :flags, :protocol, :algorithm, :public_key

        def encode_rdata(msg) # :nodoc:
          msg.put_pack('nCC', @flags, @protocol, @algorithm)
          msg.put_bytes(@public_key)
        end

        def self.decode_rdata(msg) # :nodoc:
          flags, protocol, algorithm = msg.get_unpack('nCC')
          return self.new(flags, protocol, algorithm, msg.get_bytes)
        end
      end

      ##
      # An RRSIG resource. [RFC 4034]

      class RRSIG < Resource
        TypeValue = 46

        def initialize(type_covered, algorithm, labels, original_ttl,
                       expiration, inception, key_tag, signer, signature)
          @type_covered = type_covered
          @algorithm = algorithm
          @labels = labels
          @original_ttl = original_ttl
          @expiration = expiration
          @inception = inception
          @key_tag = key_tag
          @signer = signer
          @signature = signature
        end

        attr_reader :type_covered, :algorithm, :labels, :original_ttl,
                    :expiration, :inception, :key_tag, :signer, :signature

        def encode_rdata(msg) # :nodoc:
          msg.put_pack('nCCNNNn',
                       @type_covered, @algorithm, @labels, @original_ttl,
                       @expiration, @inception, @key_tag)
          msg.put_name(@signer, compress: false)
          msg.put_bytes(@signature)
        end

        def self.decode_rdata(msg) # :nodoc:
          type_covered, algorithm, labels, original_ttl,
            expiration, inception, key_tag = msg.get_unpack('nCCNNNn')
          signer = msg.get_name
          signature = msg.get_bytes
          return self.new(type_covered, algorithm, labels, original_ttl,
                          expiration, inception, key_tag, signer, signature)
        end
      end

      ##
      # An NSEC resource. [RFC 4034]

      class NSEC < Resource
        TypeValue = 47

        def initialize(next_domain, types)
          @next_domain = next_domain
          @types = types.uniq.sort
        end

        attr_reader :next_domain, :types

        def encode_rdata(msg) # :nodoc:
          msg.put_name(@next_domain, compress: false)
          msg.put_bytes(DNSSEC.encode_type_bitmap(@types))
        end

        def self.decode_rdata(msg) # :nodoc:
          next_domain = msg.get_name
          types = DNSSEC.decode_type_bitmap(msg.get_bytes)
          return self.new(next_domain, types)
        end
      end

      ##
      # An NSEC3 resource. [RFC 5155]

      class NSEC3 < Resource
        TypeValue = 50

        def initialize(hash_algorithm, flags, iterations, salt,
                       next_hashed_owner, types)
          @hash_algorithm = hash_algorithm
          @flags = flags
          @iterations = iterations
          @salt = salt
          @next_hashed_owner = next_hashed_owner
          @types = types.uniq.sort
        end

        attr_reader :hash_algorithm, :flags, :iterations, :salt,
                    :next_hashed_owner, :types

        def opt_out?
          (@flags & 1) == 1
        end

        def encode_rdata(msg) # :nodoc:
          msg.put_pack('CCnC', @hash_algorithm, @flags, @iterations,
                       @salt.bytesize)
          msg.put_bytes(@salt)
          msg.put_pack('C', @next_hashed_owner.bytesize)
          msg.put_bytes(@next_hashed_owner)
          msg.put_bytes(DNSSEC.encode_type_bitmap(@types))
        end

        def self.decode_rdata(msg) # :nodoc:
          hash_algorithm, flags, iterations, salt_length =
            msg.get_unpack('CCnC')
          salt = msg.get_bytes(salt_length)
          hash_length, = msg.get_unpack('C')
          next_hashed_owner = msg.get_bytes(hash_length)
          types = DNSSEC.decode_type_bitmap(msg.get_bytes)
          return self.new(hash_algorithm, flags, iterations, salt,
                          next_hashed_owner, types)
        end
      end

      ##
      # An NSEC3PARAM resource. [RFC 5155]

      class NSEC3PARAM < Resource
        TypeValue = 51

        def initialize(hash_algorithm, flags, iterations, salt)
          @hash_algorithm = hash_algorithm
          @flags = flags
          @iterations = iterations
          @salt = salt
        end

        attr_reader :hash_algorithm, :flags, :iterations, :salt

        def encode_rdata(msg) # :nodoc:
          msg.put_pack('CCnC', @hash_algorithm, @flags, @iterations,
                       @salt.bytesize)
          msg.put_bytes(@salt)
        end

        def self.decode_rdata(msg) # :nodoc:
          hash_algorithm, flags, iterations, salt_length =
            msg.get_unpack('CCnC')
          return self.new(hash_algorithm, flags, iterations,
                          msg.get_bytes(salt_length))
        end
      end

      ClassInsensitiveTypes = [ # :nodoc:
        NS, CNAME, DS, SOA, PTR, HINFO, MINFO, MX, TXT, LOC, ANY, CAA,
        DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM
      ]

      ##
      # module IN contains ARPA Internet specific RRs.

      module IN

        ClassValue = 1 # :nodoc:

        ClassInsensitiveTypes.each {|s|
          c = Class.new(s)
          c.const_set(:TypeValue, s::TypeValue)
          c.const_set(:ClassValue, ClassValue)
          ClassHash[[s::TypeValue, ClassValue]] = c
          self.const_set(s.name.sub(/.*::/, ''), c)
        }

        ##
        # IPv4 Address resource

        class A < Resource
          TypeValue = 1
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self # :nodoc:

          ##
          # Creates a new A for +address+.

          def initialize(address)
            @address = IPv4.create(address)
          end

          ##
          # The Resolv::IPv4 address for this A.

          attr_reader :address

          def encode_rdata(msg) # :nodoc:
            msg.put_bytes(@address.address)
          end

          def self.decode_rdata(msg) # :nodoc:
            return self.new(IPv4.new(msg.get_bytes(4)))
          end
        end

        ##
        # Well Known Service resource.

        class WKS < Resource
          TypeValue = 11
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self # :nodoc:

          def initialize(address, protocol, bitmap)
            @address = IPv4.create(address)
            @protocol = protocol
            @bitmap = bitmap
          end

          ##
          # The host these services run on.

          attr_reader :address

          ##
          # IP protocol number for these services.

          attr_reader :protocol

          ##
          # A bit map of enabled services on this host.
          #
          # If protocol is 6 (TCP) then the 26th bit corresponds to the SMTP
          # service (port 25).  If this bit is set, then an SMTP server should
          # be listening on TCP port 25; if zero, SMTP service is not
          # supported.

          attr_reader :bitmap

          def encode_rdata(msg) # :nodoc:
            msg.put_bytes(@address.address)
            msg.put_pack("n", @protocol)
            msg.put_bytes(@bitmap)
          end

          def self.decode_rdata(msg) # :nodoc:
            address = IPv4.new(msg.get_bytes(4))
            protocol, = msg.get_unpack("n")
            bitmap = msg.get_bytes
            return self.new(address, protocol, bitmap)
          end
        end

        ##
        # An IPv6 address record.

        class AAAA < Resource
          TypeValue = 28
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self # :nodoc:

          ##
          # Creates a new AAAA for +address+.

          def initialize(address)
            @address = IPv6.create(address)
          end

          ##
          # The Resolv::IPv6 address for this AAAA.

          attr_reader :address

          def encode_rdata(msg) # :nodoc:
            msg.put_bytes(@address.address)
          end

          def self.decode_rdata(msg) # :nodoc:
            return self.new(IPv6.new(msg.get_bytes(16)))
          end
        end

        ##
        # SRV resource record defined in RFC 2782
        #
        # These records identify the hostname and port that a service is
        # available at.

        class SRV < Resource
          TypeValue = 33
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self # :nodoc:

          # Create a SRV resource record.
          #
          # See the documentation for #priority, #weight, #port and #target
          # for +priority+, +weight+, +port and +target+ respectively.

          def initialize(priority, weight, port, target)
            @priority = priority.to_int
            @weight = weight.to_int
            @port = port.to_int
            @target = Name.create(target)
          end

          # The priority of this target host.
          #
          # A client MUST attempt to contact the target host with the
          # lowest-numbered priority it can reach; target hosts with the same
          # priority SHOULD be tried in an order defined by the weight field.
          # The range is 0-65535.  Note that it is not widely implemented and
          # should be set to zero.

          attr_reader :priority

          # A server selection mechanism.
          #
          # The weight field specifies a relative weight for entries with the
          # same priority. Larger weights SHOULD be given a proportionately
          # higher probability of being selected. The range of this number is
          # 0-65535.  Domain administrators SHOULD use Weight 0 when there
          # isn't any server selection to do, to make the RR easier to read
          # for humans (less noisy). Note that it is not widely implemented
          # and should be set to zero.

          attr_reader :weight

          # The port on this target host of this service.
          #
          # The range is 0-65535.

          attr_reader :port

          # The domain name of the target host.
          #
          # A target of "." means that the service is decidedly not available
          # at this domain.

          attr_reader :target

          def encode_rdata(msg) # :nodoc:
            msg.put_pack("n", @priority)
            msg.put_pack("n", @weight)
            msg.put_pack("n", @port)
            msg.put_name(@target, compress: false)
          end

          def self.decode_rdata(msg) # :nodoc:
            priority, = msg.get_unpack("n")
            weight,   = msg.get_unpack("n")
            port,     = msg.get_unpack("n")
            target    = msg.get_name
            return self.new(priority, weight, port, target)
          end
        end

        ##
        # Common implementation for SVCB-compatible resource records.

        class ServiceBinding

          ##
          # Create a service binding resource record.

          def initialize(priority, target, params = [])
            @priority = priority.to_int
            @target = Name.create(target)
            @params = SvcParams.new(params)
          end

          ##
          # The priority of this target host.
          #
          # The range is 0-65535.
          # If set to 0, this RR is in AliasMode. Otherwise, it is in ServiceMode.

          attr_reader :priority

          ##
          # The domain name of the target host.

          attr_reader :target

          ##
          # The service parameters for the target host.

          attr_reader :params

          ##
          # Whether this RR is in AliasMode.

          def alias_mode?
            self.priority == 0
          end

          ##
          # Whether this RR is in ServiceMode.

          def service_mode?
            !alias_mode?
          end

          def encode_rdata(msg) # :nodoc:
            msg.put_pack("n", @priority)
            msg.put_name(@target, compress: false)
            @params.encode(msg)
          end

          def self.decode_rdata(msg) # :nodoc:
            priority, = msg.get_unpack("n")
            target    = msg.get_name
            params    = SvcParams.decode(msg)
            return self.new(priority, target, params)
          end
        end

        ##
        # SVCB resource record [RFC9460]

        class SVCB < ServiceBinding
          TypeValue = 64
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self # :nodoc:
        end

        ##
        # HTTPS resource record [RFC9460]

        class HTTPS < ServiceBinding
          TypeValue = 65
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self # :nodoc:
        end
      end

      # Offline DNSSEC validation helpers.

      module DNSSEC
        # Validates the authenticated denial-of-existence parts of an offline
        # DNS response. The caller supplies a message or wire-format response,
        # the question name/type, and DNSKEY records that are already trusted.
        #
        # The returned NegativeResult separates the denial proof from RRSIG
        # verification: a response may have a plausible NSEC/NSEC3 interval
        # while still failing signature validation, and vice versa.

        Algorithm = {
          5 => [:rsa_sha1, 'sha1'],
          7 => [:rsa_sha1_nsec3, 'sha1'],
          8 => [:rsa_sha256, 'sha256'],
          10 => [:rsa_sha512, 'sha512'],
          13 => [:ecdsa_p256_sha256, 'sha256', 64],
          14 => [:ecdsa_p384_sha384, 'sha384', 96],
          15 => [:ed25519, nil, 32],
          16 => [:ed448, nil, 57]
        }

        NegativeResult = Struct.new(:status, :proven, :reason, :zone,
                                    :wildcard, :records, :signatures)
        SignatureResult = Struct.new(:valid, :checked, :failures)
        class NegativeResult
          alias proven? proven
          alias wildcard? wildcard
        end
        class SignatureResult
          alias valid? valid
        end

        class VerificationError < StandardError
        end

        def self.type_value(type)
          return type if type.is_a?(Integer)
          type.const_get(:TypeValue)
        end

        def self.encode_type_bitmap(types)
          bitmap = ''.b
          groups = types.group_by {|type| type >> 8}
          groups.keys.sort.each do |window|
            values = groups[window]
            max = values.max & 255
            bits = "\0".b * ((max / 8) + 1)
            values.each {|type| bits[(255 & type) / 8] = (bits[(255 & type) / 8].ord | (0x80 >> ((255 & type) % 8))).chr}
            bitmap << [window, bits.bytesize].pack('CC') << bits
          end
          bitmap
        end

        def self.decode_type_bitmap(data)
          types = []
          offset = 0
          while offset < data.bytesize
          raise Resolv::DNS::DecodeError.new('truncated NSEC bitmap window') if offset + 2 > data.bytesize
            window, length = data.unpack("@#{offset}CC")
            offset += 2
          raise Resolv::DNS::DecodeError.new('truncated NSEC bitmap') if length.zero? || offset + length > data.bytesize
            bits = data.byteslice(offset, length)
            length.times do |byte_index|
              8.times do |bit|
                types << (window * 256 + byte_index * 8 + bit) if (bits.getbyte(byte_index) & (0x80 >> bit)) != 0
              end
            end
            offset += length
          end
          raise Resolv::DNS::DecodeError.new('NSEC bitmap windows are not sorted') unless types == types.sort
          raise Resolv::DNS::DecodeError.new('NSEC bitmap contains a duplicate type') unless types.length == types.uniq.length
          types
        end

        def self.canonical_name(name)
          Resolv::DNS::Message::MessageEncoder.new(canonical: true) {|msg| msg.put_name(Name.create(name))}.to_s
        end

        def self.canonical_rr(name, klass, ttl, data)
          Resolv::DNS::Message::MessageEncoder.new(canonical: true) do |msg|
            msg.put_name(name)
            msg.put_pack('nnN', klass::TypeValue, klass::ClassValue, ttl)
            msg.put_length16 {data.encode_rdata(msg)}
          end.to_s
        end

        def self.wildcard_name(name)
          labels = Name.create(name).to_a.dup
          return nil if labels.empty?
          labels.unshift(Label::Str.new('*'))
          Name.new(labels, true)
        end

        def self.append_label(name, label)
          labels = Name.create(name).to_a.dup
          labels.unshift(Label::Str.new(label))
          Name.new(labels, true)
        end

        def self.name_equal?(left, right)
          Name.create(left) == Name.create(right)
        end

        def self.subdomain?(name, parent)
          name = Name.create(name)
          parent = Name.create(parent)
          name == parent || name.subdomain_of?(parent)
        end

        def self.wildcard_match_name?(name, wildcard)
          name = Name.create(name).to_a
          wildcard = Name.create(wildcard).to_a
          return false if name.length < wildcard.length
          return false unless wildcard.first.to_s == '*'
          name.last(wildcard.length - 1).map(&:to_s) == wildcard.last(wildcard.length - 1).map(&:to_s)
        end

        def self.compare_names(left, right)
          left = Name.create(left).to_a
          right = Name.create(right).to_a
          left.zip(right).reverse_each do |label, other|
            return 1 if other.nil?
            a = label.downcase.b
            b = other.downcase.b
            if a.length != b.length
              a.length < b.length ? (return -1) : (return 1)
            end
            next if a == b
            a.bytes.zip(b.bytes) do |ac, bc|
              next if ac == bc
              ac < bc ? (return -1) : (return 1)
            end
          end
          left.length <=> right.length
        end

        def self.cover_name?(owner, next_name, target)
          owner_name = Name.create(owner)
          next_name = Name.create(next_name)
          target_name = Name.create(target)
          if owner_name == next_name
            false
          elsif compare_names(owner_name, next_name) < 0
            compare_names(owner_name, target_name) < 0 &&
              compare_names(target_name, next_name) < 0
          else
            compare_names(owner_name, target_name) < 0 ||
              compare_names(target_name, next_name) < 0
          end
        end

        BASE32HEX_ALPHABET = '0123456789abcdefghijklmnopqrstuv'.freeze

        def self.base32hex_decode(value)
          value = value.b.downcase
          bits = 0
          count = 0
          output = ''.b
          value.each_byte do |byte|
          digit = byte - '0'.ord
          digit -= ('a'.ord - '9'.ord - 1) if byte >= 'a'.ord
          raise Resolv::DNS::DecodeError.new('invalid NSEC3 hash label') unless digit >= 0 && digit < 32
            bits = (bits << 5) | digit
            count += 5
            if count >= 8
              count -= 8
              output << ((bits >> count) & 255).chr
            end
          end
          raise Resolv::DNS::DecodeError.new('invalid NSEC3 hash padding') unless count.zero?
          output
        end

        def self.base32hex_encode(value)
          output = ''.b
          bits = 0
          count = 0
          value.each_byte do |byte|
            bits = ((bits << 8) | byte) & 0xffffffff
            count += 8
            while count >= 5
              count -= 5
              output << BASE32HEX_ALPHABET[(bits >> count) & 31]
            end
          end
          if count > 0
            output << BASE32HEX_ALPHABET[(bits << (5 - count)) & 31]
          end
          output
        end

        def self.nsec3_hash(name, algorithm, iterations, salt)
          require 'openssl'
          raise VerificationError.new('unsupported NSEC3 hash algorithm') unless algorithm == 1
          digest = canonical_name(name)[0..-2]
          (iterations + 1).times do
            digest = OpenSSL::Digest.digest('SHA1', digest + salt.b)
          end
          digest
        end

        def self.nsec3_owner(name, zone, algorithm, iterations, salt)
          hashed = nsec3_hash(name, algorithm, iterations, salt)
          labels = Name.create(zone).to_a.dup
          labels.unshift(Label::Str.new(base32hex_encode(hashed).upcase))
          Name.new(labels, true)
        end

        def self.hashed_owner(owner, zone)
          labels = Name.create(owner).to_a
          zone_labels = Name.create(zone).to_a
          unless labels.length == zone_labels.length + 1 && labels[-zone_labels.length, zone_labels.length] == zone_labels
            raise Resolv::DNS::DecodeError.new('NSEC3 owner is outside its zone')
          end
          base32hex_decode(labels[0].to_s)
        end

        def self.cover_hash?(record_hash, next_hash, target_hash)
          if record_hash == next_hash
            false
          elsif record_hash < next_hash
            record_hash < target_hash && target_hash < next_hash
          else
            record_hash < target_hash || target_hash > next_hash
          end
        end

        def self.key_tag(dnskey)
          wire = [dnskey.flags, dnskey.protocol, dnskey.algorithm].pack('nCC') + dnskey.public_key.b
          sum = 0
          wire.each_byte.each_with_index do |byte, index|
            sum += index.even? ? byte * 256 : byte
          end
          ((sum + (sum >> 16)) & 0xffff)
        end

        def self.verify_negative_response(message, qname, qtype, trusted_keys, time = Time.now)
          require 'openssl'
          message = Resolv::DNS::Message.decode(message) if message.is_a?(String)
          Validator.new(message, qname, qtype, trusted_keys, time).verify
        end

        class Validator
          def initialize(message, qname, qtype, trusted_keys, time)
            @message = message
            created = Name.create(qname)
            @qname = Name.new(created.to_a, true)
            @qtype = DNSSEC.type_value(qtype)
            @time = time.respond_to?(:to_i) ? time : Time.at(time)
            @trusted_keys = normalize_keys(trusted_keys)
            @authority = section_records(@message.authority, :authority)
            @answer = section_records(@message.answer, :answer)
            @failures = []
            @evidence = []
            @signature_result = nil
          end

          def verify
            unless valid_question? && (@message.rcode == 0 || @message.rcode == 3)
              return negative_result(:unproven, false, 'response question or rcode does not match the query')
            end

            soa_zones = authority_owners(Resource::IN::SOA).map {|entry| entry[:name]}.uniq
            signer_zones = rrsigs.map {|entry| entry[:data].signer}.uniq
            soa_zones.select! {|zone| DNSSEC.subdomain?(@qname, zone)}
            signer_zones.select! {|zone| DNSSEC.subdomain?(@qname, zone)}

            if @message.rcode == 3
              zone, result = soa_zones.map {|candidate| [candidate, prove_nxdomain(candidate)]}.find {|_, value| value}
              return finish(result || negative_result(:unproven, false, 'no NSEC or NSEC3 range proves NXDOMAIN', soa_zones.first), zone)
            end

            positive = wildcard_match?
            if positive
              wildcard_signer_zones = rrsigs(@answer).map {|entry| entry[:data].signer}.uniq
              wildcard_signer_zones.select! {|candidate| DNSSEC.subdomain?(@qname, candidate)}
              zone, result = wildcard_signer_zones.map {|candidate| [candidate, prove_wildcard_match(candidate)]}.find {|_, value| value}
              result ||= negative_result(:wildcard_match, false, 'no authenticated denial proves a wildcard expansion')
            else
              zone, result = soa_zones.map {|candidate| [candidate, prove_nodata(candidate)]}.find {|_, value| value}
              result ||= negative_result(:nodata, false, 'no NSEC or NSEC3 range plus type bitmap proves NODATA')
            end
            finish(result, zone)
          end

          private

          def section_records(section, section_name)
            section.map {|name, ttl, data| {name: name, ttl: ttl, data: data, type: data.class::TypeValue, klass: data.class::ClassValue, section: section_name}}
          end

          def rrsigs(records = nil)
            records = @authority + @answer if records.nil?
            records.select {|entry| entry[:type] == Resource::IN::RRSIG::TypeValue}
          end

          def authority_owners(klass)
            type = klass::TypeValue
            @authority.select {|entry| entry[:type] == type}
          end

          def normalize_keys(keys)
            normalized = Hash.new {|hash, name| hash[name] = []}
            entries = keys.is_a?(Hash) ? [keys] : Array(keys)
            entries.each do |entry|
              if entry.is_a?(Hash)
                key = entry.values.first
                signer = entry.keys.first
              elsif entry.is_a?(Resource::DNSKEY)
                key = entry
                signer = nil
              else
                key = entry
                signer = nil
              end
              if key.is_a?(String) && key.bytesize >= 4
                flags, protocol, algorithm = key.unpack('nCC')
                key = Resource::IN::DNSKEY.new(flags, protocol, algorithm, key.byteslice(4..-1))
              end
              next unless key.is_a?(Resource::DNSKEY)
              if signer
                created_signer = Name.create(signer)
                signer_name = Name.new(created_signer.to_a, true)
                normalized[signer_name] << key
              else
                normalized[nil] << key
              end
            end
            normalized
          end

          def valid_question?
            return false unless @message.qr == 1
            return false if @message.tc == 1
            return false unless @message.question.length == 1
            name, typeclass = @message.question.first
            name.to_a == @qname.to_a && typeclass::TypeValue == @qtype && typeclass::ClassValue == Resource::IN::ClassValue
          rescue StandardError
            false
          end

          def negative_result(status, proven, reason_text, zone = nil)
            NegativeResult.new(status, proven, reason_text, zone, false, @evidence.uniq, signatures)
          end

          def finish(result, zone)
            result.zone = zone if result.zone.nil? && zone
            result.records = result.records.map {|record| record.is_a?(Hash) ? record : record.first}.uniq
            result.signatures = signatures
            result.proven = result.status != :insecure_delegation &&
                            signatures.valid && result.reason.nil?
            result
          end

          def signatures
            return @signature_result if @signature_result
            checked = []
            required = required_signed_records
            required.each do |record|
              valid = verify_record(record)
              checked << record unless valid
            end
            @signature_result = SignatureResult.new(checked.empty?, required.length, checked.map {|record| signature_failure(record)})
          end

          def required_signed_records
            records = []
            [[:answer, @answer], [:authority, @authority]].each do |section_name, section|
              section.each do |record|
                type = record[:type]
                next if type == Resource::IN::RRSIG::TypeValue
                relevant = section_name == :answer ? positive_record?(record) : relevant_authority?(record)
                records << record.merge(section: section_name) if relevant
              end
            end
            records
          end

          def relevant_authority?(record)
            case record[:type]
            when Resource::IN::SOA::TypeValue, Resource::IN::NSEC::TypeValue,
                 Resource::IN::NSEC3::TypeValue, Resource::IN::NSEC3PARAM::TypeValue
              true
            else
              false
            end
          end

          def positive_record?(record)
            chain_name = follow_cname
            return true if record[:name] == @qname && record[:type] == @qtype
            record[:name] == chain_name && record[:type] == @qtype
          end

          def wildcard_match?
            wildcard_answer.any?
          end

          def wildcard_answer
            @answer.select do |record|
              next false unless record[:type] == @qtype
              !wildcard_signatures(record).empty?
            end
          end

          def answer_wildcard_name
            wildcard_answer.map do |record|
              signature = wildcard_signatures(record).find do |candidate|
                (candidate[:name] == record[:name] || wildcard_signed?(candidate, record)) &&
                  candidate[:data].labels < record[:name].length &&
                  candidate[:name].to_a.first.to_s == '*'
              end
              next nil unless signature
              labels = [Label::Str.new('*')] + record[:name].to_a.last(signature[:data].labels)
              Name.new(labels, true)
            end.compact.first
          end

          def wildcard_signatures(record)
            rrsigs(@answer).select do |signature|
              sig = signature[:data]
              sig.type_covered == record[:type] && sig.labels < record[:name].length &&
                record[:name].to_a.last(sig.labels) == signature[:name].to_a.last(sig.labels) &&
                signature[:name].to_a.length == sig.labels + 1 &&
                signature[:name].to_a.first.to_s == '*'
            end
          end

          def follow_cname
            current = @qname
            @answer.each do |record|
              if record[:name] == current && record[:type] == Resource::IN::CNAME::TypeValue
                current = record[:data].name
              end
            end
            current
          end

          def nsec_records(zone)
            @authority.select do |entry|
              entry[:type] == Resource::IN::NSEC::TypeValue &&
                DNSSEC.subdomain?(entry[:name], zone) &&
                DNSSEC.subdomain?(entry[:data].next_domain, zone) &&
                entry[:data].types.include?(Resource::IN::NSEC::TypeValue)
            end
          end

          def nsec3_records(zone, parameters = nil)
            @authority.select do |entry|
              next false unless entry[:type] == Resource::IN::NSEC3::TypeValue
              data = entry[:data]
              next false unless data.hash_algorithm == 1
              next false unless (data.flags & ~1).zero?
              next false unless DNSSEC.subdomain?(entry[:name], zone)
              next false unless data.types.include?(Resource::IN::NSEC3::TypeValue)
              next false unless parameters.nil? || nsec3_parameters(data) == parameters
              true
            end
          rescue Resolv::DNS::DecodeError
            []
          end

          def nsec3_parameters(data)
            [data.hash_algorithm, data.flags & ~1, data.iterations, data.salt.b]
          end

          def nsec3_hashes(records, zone)
            records.map do |entry|
              owner_hash = DNSSEC.hashed_owner(entry[:name], zone)
              next_hash = entry[:data].next_hashed_owner.b
              raise Resolv::DNS::DecodeError.new('bad NSEC3 hash length') unless owner_hash.bytesize == 20 && next_hash.bytesize == 20
              [entry, owner_hash, next_hash]
            end
          rescue Resolv::DNS::DecodeError
            []
          end

          def prove_nxdomain(zone)
            prove_nsec_nxdomain(zone) || prove_nsec3_nxdomain(zone)
          end

          def prove_nodata(zone)
            prove_nsec_nodata(zone) || prove_nsec3_nodata(zone)
          end

          def prove_wildcard_match(zone)
            prove_nsec_wildcard_match(zone) || prove_nsec3_wildcard_match(zone)
          end

          def parent_suffixes(name, zone)
            labels = Name.create(name).to_a
            zone_length = Name.create(zone).length
            return [] if labels.length < zone_length
            (0..(labels.length - zone_length)).map do |count|
              Name.new(labels[count..-1], true)
            end
          end

          def nsec_closest_encloser(name, zone, records)
            suffixes = parent_suffixes(name, zone)
            suffixes.find do |candidate|
              records.any? {|entry| entry[:name] == candidate} ||
                (candidate == zone && authority_owners(Resource::IN::SOA).any? {|soa| soa[:name] == zone})
            end
          end

          def nsec_cover(target, zone, records)
            records.find do |entry|
              DNSSEC.cover_name?(entry[:name], entry[:data].next_domain, target)
            end
          end

          def prove_nsec_nxdomain(zone)
            records = nsec_records(zone)
            encloser = nsec_closest_encloser(@qname, zone, records)
            return nil unless encloser
            wildcard = DNSSEC.wildcard_name(encloser)
            qname_cover = nsec_cover(@qname, zone, records)
            wildcard_cover = nsec_cover(wildcard, zone, records)
            return nil unless qname_cover && wildcard_cover
            @evidence = [qname_cover, wildcard_cover]
            NegativeResult.new(:nxdomain, nil, nil, zone, false, @evidence, nil)
          end

          def exact_nsec_nodata(records)
            target = follow_cname
            record = records.find {|entry| entry[:name] == target}
            return nil unless record
            return nil if record[:data].types.include?(@qtype)
            @evidence = [record]
            NegativeResult.new(:nodata, nil, nil, nil, false, @evidence, nil)
          end

          def wildcard_nsec_nodata(records, zone)
            encloser = nsec_closest_encloser(@qname, zone, records)
            return nil unless encloser
            wildcard = DNSSEC.wildcard_name(encloser)
            wildcard_record = records.find {|entry| entry[:name] == wildcard}
            return nil unless wildcard_record
            return nil if wildcard_record[:data].types.include?(@qtype)
            @evidence = [wildcard_record]
            NegativeResult.new(:nodata, nil, nil, zone, true, @evidence, nil)
          end

          def prove_nsec_nodata(zone)
            records = nsec_records(zone)
            exact_nsec_nodata(records) || wildcard_nsec_nodata(records, zone)
          end

          def prove_nsec_wildcard_match(zone)
            wildcard = answer_wildcard_name
            return nil unless wildcard && DNSSEC.wildcard_match_name?(@qname, wildcard)
            @evidence = wildcard_answer
            NegativeResult.new(:wildcard_match, nil, nil, zone, true, @evidence, nil)
          end

          def nsec3_groups(zone)
            records = nsec3_records(zone)
            groups = records.group_by do |entry|
              data = entry[:data]
            [data.hash_algorithm, data.flags & ~1, data.iterations, data.salt.b]
            end
            groups.each_value do |entries|
              yield(entries, nsec3_parameters(entries.first[:data]))
            end
          end

          def nsec3_exact_owner?(target, zone, hashed_records, parameters)
            target_hash = DNSSEC.nsec3_hash(target, parameters[0], parameters[2], parameters[3])
            hashed_records.any? {|_, owner_hash, _| owner_hash == target_hash}
          end

          def nsec3_cover(target, zone, hashed_records, parameters, allow_opt_out: false)
            target_hash = DNSSEC.nsec3_hash(target, parameters[0], parameters[2], parameters[3])
            hashed_records.find do |entry, owner_hash, next_hash|
              next_hash.bytesize == target_hash.bytesize &&
                DNSSEC.cover_hash?(owner_hash, next_hash, target_hash) &&
                (allow_opt_out || !entry[:data].opt_out?)
            end
          end

          def nsec3_encloser(zone, hashed_records, parameters)
            parent_suffixes(@qname, zone).find do |candidate|
              if candidate == zone
                authority_owners(Resource::IN::SOA).any? {|soa| soa[:name] == zone}
              else
                nsec3_exact_owner?(candidate, zone, hashed_records, parameters)
              end
            end
          end

          def matching_nsec3param?(zone, parameters)
            params = @authority.select {|entry| entry[:type] == Resource::IN::NSEC3PARAM::TypeValue && entry[:name] == zone}
            return true if params.empty?
            params.any? do |entry|
              data = entry[:data]
              data.flags == 0 &&
                [data.hash_algorithm, data.flags, data.iterations, data.salt.b] ==
                  [parameters[0], 0, parameters[2], parameters[3]]
            end
          end

          def prove_nsec3_nxdomain(zone)
            each_nsec3_group(zone) do |records, parameters|
              hashed = nsec3_hashes(records, zone)
              next if hashed.empty? || !matching_nsec3param?(zone, parameters)
              encloser = nsec3_encloser(zone, hashed, parameters)
              next unless encloser
              return nil if nsec3_exact_owner?(@qname, zone, hashed, parameters)
              next_closer = DNSSEC.append_label(encloser, @qname.to_a[@qname.length - encloser.length - 1].to_s)
              wildcard = DNSSEC.wildcard_name(encloser)
              nc_cover = nsec3_cover(next_closer, zone, hashed, parameters)
              wildcard_cover = nsec3_cover(wildcard, zone, hashed, parameters)
              next unless nc_cover && wildcard_cover
              @evidence = [nc_cover, wildcard_cover]
              return NegativeResult.new(:nxdomain, nil, nil, zone, false, @evidence, nil)
            end
            nil
          end

          def prove_nsec3_nodata(zone)
            each_nsec3_group(zone) do |records, parameters|
              hashed = nsec3_hashes(records, zone)
              next if hashed.empty? || !matching_nsec3param?(zone, parameters)
              exact_hash = DNSSEC.nsec3_hash(follow_cname, parameters[0], parameters[2], parameters[3])
              exact = hashed.find {|_, owner_hash, _| owner_hash == exact_hash}
              if exact
                if exact.first[:data].types.include?(@qtype)
                  next
                elsif exact.first[:data].opt_out? && @qtype == Resource::IN::DS::TypeValue
                  @evidence = [exact.first]
                  return NegativeResult.new(:insecure_delegation, nil, nil, zone, false, @evidence, nil)
                end
                @evidence = [exact.first]
                return NegativeResult.new(:nodata, nil, nil, zone, false, @evidence, nil)
              end

              encloser = nsec3_encloser(zone, hashed, parameters)
              next unless encloser
              next_closer = DNSSEC.append_label(encloser, @qname.to_a[@qname.length - encloser.length - 1].to_s)
              wildcard = DNSSEC.wildcard_name(encloser)
              wildcard_hash = DNSSEC.nsec3_hash(wildcard, parameters[0], parameters[2], parameters[3])
              wildcard_record = hashed.find {|_, owner_hash, _| owner_hash == wildcard_hash}
              if wildcard_record
                next if wildcard_record.first[:data].types.include?(@qtype)
                @evidence = [wildcard_record.first]
                return NegativeResult.new(:nodata, nil, nil, zone, true, @evidence, nil)
              end

              cover = nsec3_cover(next_closer, zone, hashed, parameters, allow_opt_out: @qtype == Resource::IN::DS::TypeValue)
              if cover && cover.first[:data].opt_out? && @qtype == Resource::IN::DS::TypeValue
                @evidence = [cover.first]
                return NegativeResult.new(:insecure_delegation, nil, nil, zone, false, @evidence, nil)
              end
            end
            nil
          end

          def prove_nsec3_wildcard_match(zone)
            wildcard = answer_wildcard_name
            return nil unless wildcard && DNSSEC.wildcard_match_name?(@qname, wildcard)
            @evidence = wildcard_answer
            NegativeResult.new(:wildcard_match, nil, nil, zone, true, @evidence, nil)
          end

          def each_nsec3_group(zone)
            seen = {}
            nsec3_groups(zone) do |records, parameters|
              next if seen[parameters]
              seen[parameters] = true
              valid = nsec3_records(zone, parameters)
              yield(valid, parameters)
            end
          end

          def verify_record(record)
            candidates = rrsigs(records_for_section(record[:section])).select do |signature|
              sig = signature[:data]
              signature[:name] == record[:name] ||
                (sig.type_covered == record[:type] &&
                 sig.labels < record[:name].length &&
                 record[:name].to_a.last(sig.labels) == signature[:name].to_a.last(sig.labels))
            end
            failures = []
            valid = candidates.any? do |signature|
              failure = verify_rrsig(signature, record)
              failures << failure unless failure.nil?
              failure.nil?
            end
            @failure = valid ? nil : (failures.last || 'missing RRSIG')
            valid
          end

          def records_for_section(section)
            section == :answer ? @answer : @authority
          end

          def signature_failure(record)
            {name: record[:name].to_s, type: record[:type], reason: @failure || 'missing RRSIG'}
          end

          def wildcard_signed?(signature, record)
            sig = signature[:data]
            sig.type_covered == record[:type] &&
              sig.labels < record[:name].length &&
              record[:name].to_a.last(sig.labels) == signature[:name].to_a.last(sig.labels) &&
              signature[:name].to_a.length == sig.labels + 1 &&
              signature[:name].to_a.first.to_s == '*'
          end

          def verify_rrsig(signature_entry, record)
            sig = signature_entry[:data]
            keys = @trusted_keys[nil] + @trusted_keys[sig.signer]
            key = keys.find do |candidate|
              candidate.algorithm == sig.algorithm &&
                DNSSEC.key_tag(candidate) == sig.key_tag
            end
            unless key
              return 'no trusted key matches RRSIG'
            end
            unless sig.type_covered == record[:type] && DNSSEC.subdomain?(record[:name], sig.signer)
              return 'RRSIG owner or covered type does not match'
            end
            unless (sig.inception..sig.expiration).include?(@time.to_i)
              return 'RRSIG is outside its validity period'
            end
            unless key.protocol == 3 && valid_dnskey_flags?(key)
              return 'DNSKEY protocol or flags are invalid'
            end
            wildcard_labels = sig.labels < record[:name].length &&
                             record[:name].to_a.first.to_s != '*' &&
                             signature_entry[:name].to_a.first.to_s == '*' &&
                             signature_entry[:name].length == sig.labels + 1 &&
                             record[:name].to_a.last(sig.labels) == signature_entry[:name].to_a.last(sig.labels)
            valid_labels = sig.labels == record[:name].length || wildcard_labels
            unless valid_labels && record[:ttl] <= sig.original_ttl
              return 'RRSIG label count or original TTL is invalid'
            end
            unless verify_crypto(key, sig, signature_entry, record)
              return 'RRSIG cryptographic verification failed'
            end
            nil
          rescue StandardError => error
            error.message
          end

          def verify_crypto(key, sig, signature_entry, record)
            info = DNSSEC::Algorithm[sig.algorithm]
            return false unless info
            sorted_rrset = rrset(record, signature_entry).sort
            data = rrsig_prefix(sig) + sorted_rrset.join
            public_key = build_public_key(key)
            if info[0].to_s.start_with?('ecdsa')
              signature = ecdsa_der(sig.signature, info[2])
            else
              signature = sig.signature
            end
            public_key.verify(info[1], signature, data)
          rescue OpenSSL::PKey::PKeyError
            false
          end

          def valid_dnskey_flags?(key)
            (key.flags & 0x0100 == 0x0100) || (key.flags & 0x0101).zero?
          end

          def rrset(record, signature_entry)
            records_for_section(record[:section]).select do |entry|
              entry[:name] == record[:name] &&
                entry[:type] == record[:type] &&
                entry[:klass] == record[:klass]
            end.map do |entry|
              ttl = signature_entry ? signature_entry[:data].original_ttl : canonical_ttl(entry)
              DNSSEC.canonical_rr(entry[:name], entry[:data].class, ttl, entry[:data])
            end
          end

          def canonical_ttl(entry)
            matching = rrsigs(records_for_section(entry[:section])).select do |signature|
              signature[:name] == entry[:name] && signature[:data].type_covered == entry[:type]
            end.map {|signature| signature[:data].original_ttl}
            matching.push(entry[:ttl]).min
          end

          def rrsig_prefix(sig)
            [sig.type_covered, sig.algorithm, sig.labels, sig.original_ttl,
             sig.expiration, sig.inception, sig.key_tag].pack('nCCNNNn') +
              DNSSEC.canonical_name(sig.signer)
          end

          def ecdsa_der(signature, length)
            raise OpenSSL::PKey::PKeyError.new('bad ECDSA signature length') unless signature.bytesize == length
            half = length / 2
            asn1_integer(signature.byteslice(0, half)) + asn1_integer(signature.byteslice(half, half))
          end

          def asn1_integer(value)
            value = "\x00#{value}" if value.empty? || value.getbyte(0) >= 128
            "\x02#{der_length(value.bytesize)}#{value}".b
          end

          def der_length(length)
            if length < 128
              length.chr
            elsif length < 256
              [0x81, length].pack('CC')
            else
              [0x82, length].pack('Cn')
            end
          end

          def build_public_key(dnskey)
            case dnskey.algorithm
            when 5, 7, 8, 10
              build_rsa_key(dnskey.public_key)
            when 13
              build_ec_key('\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07'.b, dnskey.public_key, 64)
            when 14
              build_ec_key('\x06\x05\x2b\x81\x04\x00\x22'.b, dnskey.public_key, 96)
            when 15
              build_ed_key('\x06\x03\x2b\x65\x70'.b, dnskey.public_key, 32)
            when 16
              build_ed_key('\x06\x03\x2b\x65\x71'.b, dnskey.public_key, 57)
            else
              raise VerificationError.new('unsupported DNSKEY algorithm')
            end
          end

          def der_sequence(value)
            "\x30#{der_length(value.bytesize)}#{value}".b
          end

          def der_bit_string(value)
            "\x03#{der_length(value.bytesize + 1)}\x00#{value}".b
          end

          def build_ed_key(oid, point, expected_length)
            raise VerificationError.new('bad EdDSA key length') unless point.bytesize == expected_length
            OpenSSL::PKey.read(der_sequence(der_sequence(oid) + der_bit_string(point)))
          end

          def build_ec_key(oid, point, expected_length)
            raise VerificationError.new('bad ECDSA key length') unless point.bytesize == expected_length + 1
            raise VerificationError.new('bad ECDSA public point') unless point.getbyte(0) == 4
            OpenSSL::PKey.read(der_sequence(der_sequence(oid) + der_bit_string(point.byteslice(1..-1))))
          end

          def build_rsa_key(blob)
            raise VerificationError.new('short RSA DNSKEY') if blob.bytesize < 2
            offset = 0
            exponent_length = blob.getbyte(0)
            if exponent_length != 0
              exponent = blob.byteslice(1, exponent_length)
              offset = 1 + exponent_length
            else
              exponent_length = blob.unpack('@1n')[0]
              exponent = blob.byteslice(3, exponent_length)
              offset = 3 + exponent_length
            end
            modulus = blob.byteslice(offset..-1)
            raise VerificationError.new('short RSA DNSKEY exponent or modulus') if exponent.empty? || modulus.empty?
            rsa_public_key = der_sequence(asn1_integer(modulus) + asn1_integer(exponent))
            rsa_algorithm = der_sequence("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00".b)
            OpenSSL::PKey.read(der_sequence(rsa_algorithm + der_bit_string(rsa_public_key)))
          end
        end
      end
    end
    DNSSEC = Resource::DNSSEC
  end

  ##
  # A Resolv::DNS IPv4 address.

  class IPv4

    Regex256 = /0
               |1(?:[0-9][0-9]?)?
               |2(?:[0-4][0-9]?|5[0-5]?|[6-9])?
               |[3-9][0-9]?/x # :nodoc:

    ##
    # Regular expression IPv4 addresses must match.
    Regex = /\A(#{Regex256})\.(#{Regex256})\.(#{Regex256})\.(#{Regex256})\z/

    ##
    # Creates a new IPv4 address from +arg+ which may be:
    #
    # IPv4:: returns +arg+.
    # String:: +arg+ must match the IPv4::Regex constant

    def self.create(arg)
      case arg
      when IPv4
        return arg
      when Regex
        if (0..255) === (a = $1.to_i) &&
           (0..255) === (b = $2.to_i) &&
           (0..255) === (c = $3.to_i) &&
           (0..255) === (d = $4.to_i)
          return self.new([a, b, c, d].pack("CCCC"))
        else
          raise ArgumentError.new("IPv4 address with invalid value: " + arg)
        end
      else
        raise ArgumentError.new("cannot interpret as IPv4 address: #{arg.inspect}")
      end
    end

    def initialize(address) # :nodoc:
      unless address.kind_of?(String)
        raise ArgumentError, 'IPv4 address must be a string'
      end
      unless address.length == 4
        raise ArgumentError, "IPv4 address expects 4 bytes but #{address.length} bytes"
      end
      @address = address
    end

    ##
    # A String representation of this IPv4 address.

    ##
    # The raw IPv4 address as a String.

    attr_reader :address

    def to_s # :nodoc:
      return sprintf("%d.%d.%d.%d", *@address.unpack("CCCC"))
    end

    def inspect # :nodoc:
      return "#<#{self.class} #{self}>"
    end

    ##
    # Turns this IPv4 address into a Resolv::DNS::Name.

    def to_name
      return DNS::Name.create(
        '%d.%d.%d.%d.in-addr.arpa.' % @address.unpack('CCCC').reverse)
    end

    def ==(other) # :nodoc:
      return @address == other.address
    end

    def eql?(other) # :nodoc:
      return self == other
    end

    def hash # :nodoc:
      return @address.hash
    end
  end

  ##
  # A Resolv::DNS IPv6 address.

  class IPv6

    ##
    # IPv6 address format a:b:c:d:e:f:g:h
    Regex_8Hex = /\A
      (?:[0-9A-Fa-f]{1,4}:){7}
         [0-9A-Fa-f]{1,4}
      \z/x

    ##
    # Compressed IPv6 address format a::b

    Regex_CompressedHex = /\A
      ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) ::
      ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)
      \z/x

    ##
    # IPv4 mapped IPv6 address format a:b:c:d:e:f:w.x.y.z

    Regex_6Hex4Dec = /\A
      ((?:[0-9A-Fa-f]{1,4}:){6,6})
      (\d+)\.(\d+)\.(\d+)\.(\d+)
      \z/x

    ##
    # Compressed IPv4 mapped IPv6 address format a::b:w.x.y.z

    Regex_CompressedHex4Dec = /\A
      ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) ::
      ((?:[0-9A-Fa-f]{1,4}:)*)
      (\d+)\.(\d+)\.(\d+)\.(\d+)
      \z/x

    ##
    # IPv6 link local address format fe80:b:c:d:e:f:g:h%em1
    Regex_8HexLinkLocal = /\A
      [Ff][Ee]80
      (?::[0-9A-Fa-f]{1,4}){7}
      %[-0-9A-Za-z._~]+
      \z/x

    ##
    # Compressed IPv6 link local address format fe80::b%em1

    Regex_CompressedHexLinkLocal = /\A
      [Ff][Ee]80:
      (?:
        ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) ::
        ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)
        |
        :((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)
      )?
      :[0-9A-Fa-f]{1,4}%[-0-9A-Za-z._~]+
      \z/x

    ##
    # A composite IPv6 address Regexp.

    Regex = /
      (?:#{Regex_8Hex}) |
      (?:#{Regex_CompressedHex}) |
      (?:#{Regex_6Hex4Dec}) |
      (?:#{Regex_CompressedHex4Dec}) |
      (?:#{Regex_8HexLinkLocal}) |
      (?:#{Regex_CompressedHexLinkLocal})
      /x

    ##
    # Creates a new IPv6 address from +arg+ which may be:
    #
    # IPv6:: returns +arg+.
    # String:: +arg+ must match one of the IPv6::Regex* constants

    def self.create(arg)
      case arg
      when IPv6
        return arg
      when String
        address = ''.b
        if Regex_8Hex =~ arg
          arg.scan(/[0-9A-Fa-f]+/) {|hex| address << [hex.hex].pack('n')}
        elsif Regex_CompressedHex =~ arg
          prefix = $1
          suffix = $2
          a1 = ''.b
          a2 = ''.b
          prefix.scan(/[0-9A-Fa-f]+/) {|hex| a1 << [hex.hex].pack('n')}
          suffix.scan(/[0-9A-Fa-f]+/) {|hex| a2 << [hex.hex].pack('n')}
          omitlen = 16 - a1.length - a2.length
          address << a1 << "\0" * omitlen << a2
        elsif Regex_6Hex4Dec =~ arg
          prefix, a, b, c, d = $1, $2.to_i, $3.to_i, $4.to_i, $5.to_i
          if (0..255) === a && (0..255) === b && (0..255) === c && (0..255) === d
            prefix.scan(/[0-9A-Fa-f]+/) {|hex| address << [hex.hex].pack('n')}
            address << [a, b, c, d].pack('CCCC')
          else
            raise ArgumentError.new("not numeric IPv6 address: " + arg)
          end
        elsif Regex_CompressedHex4Dec =~ arg
          prefix, suffix, a, b, c, d = $1, $2, $3.to_i, $4.to_i, $5.to_i, $6.to_i
          if (0..255) === a && (0..255) === b && (0..255) === c && (0..255) === d
            a1 = ''.b
            a2 = ''.b
            prefix.scan(/[0-9A-Fa-f]+/) {|hex| a1 << [hex.hex].pack('n')}
            suffix.scan(/[0-9A-Fa-f]+/) {|hex| a2 << [hex.hex].pack('n')}
            omitlen = 12 - a1.length - a2.length
            address << a1 << "\0" * omitlen << a2 << [a, b, c, d].pack('CCCC')
          else
            raise ArgumentError.new("not numeric IPv6 address: " + arg)
          end
        else
          raise ArgumentError.new("not numeric IPv6 address: " + arg)
        end
        return IPv6.new(address)
      else
        raise ArgumentError.new("cannot interpret as IPv6 address: #{arg.inspect}")
      end
    end

    def initialize(address) # :nodoc:
      unless address.kind_of?(String) && address.length == 16
        raise ArgumentError.new('IPv6 address must be 16 bytes')
      end
      @address = address
    end

    ##
    # The raw IPv6 address as a String.

    attr_reader :address

    def to_s # :nodoc:
      sprintf("%x:%x:%x:%x:%x:%x:%x:%x", *@address.unpack("nnnnnnnn")).sub(/(^|:)0(:0)+(:|$)/, '::')
    end

    def inspect # :nodoc:
      return "#<#{self.class} #{self}>"
    end

    ##
    # Turns this IPv6 address into a Resolv::DNS::Name.
    #--
    # ip6.arpa should be searched too. [RFC3152]

    def to_name
      return DNS::Name.new(
        @address.unpack("H32")[0].split(//).reverse + ['ip6', 'arpa'])
    end

    def ==(other) # :nodoc:
      return @address == other.address
    end

    def eql?(other) # :nodoc:
      return self == other
    end

    def hash # :nodoc:
      return @address.hash
    end
  end

  ##
  # Resolv::MDNS is a one-shot Multicast DNS (mDNS) resolver.  It blindly
  # makes queries to the mDNS addresses without understanding anything about
  # multicast ports.
  #
  # Information taken form the following places:
  #
  # * RFC 6762

  class MDNS < DNS

    ##
    # Default mDNS Port

    Port = 5353

    ##
    # Default IPv4 mDNS address

    AddressV4 = '224.0.0.251'

    ##
    # Default IPv6 mDNS address

    AddressV6 = 'ff02::fb'

    ##
    # Default mDNS addresses

    Addresses = [
      [AddressV4, Port],
      [AddressV6, Port],
    ]

    ##
    # Creates a new one-shot Multicast DNS (mDNS) resolver.
    #
    # +config_info+ can be:
    #
    # nil::
    #   Uses the default mDNS addresses
    #
    # Hash::
    #   Must contain :nameserver or :nameserver_port like
    #   Resolv::DNS#initialize.

    def initialize(config_info=nil)
      if config_info then
        super({ nameserver_port: Addresses }.merge(config_info))
      else
        super(nameserver_port: Addresses)
      end
    end

    ##
    # Iterates over all IP addresses for +name+ retrieved from the mDNS
    # resolver, provided name ends with "local".  If the name does not end in
    # "local" no records will be returned.
    #
    # +name+ can be a Resolv::DNS::Name or a String.  Retrieved addresses will
    # be a Resolv::IPv4 or Resolv::IPv6

    def each_address(name)
      name = Resolv::DNS::Name.create(name)

      return unless name[-1].to_s == 'local'

      super(name)
    end

    def make_udp_requester # :nodoc:
      nameserver_port = @config.nameserver_port
      Requester::MDNSOneShot.new(*nameserver_port)
    end

  end

  module LOC # :nodoc:

    ##
    # A Resolv::LOC::Size

    class Size

      # Regular expression LOC size must match.

      Regex = /\A0*(\d{1,8}(?:\.\d+)?)m\z/

      ##
      # Creates a new LOC::Size from +arg+ which may be:
      #
      # LOC::Size:: returns +arg+.
      # String:: +arg+ must match the LOC::Size::Regex constant

      def self.create(arg)
        case arg
        when Size
          return arg
        when String
          unless Regex =~ arg
            raise ArgumentError.new("not a properly formed Size string: " + arg)
          end
          unless (0.0...1e8) === (scalar = $1.to_f)
            raise ArgumentError.new("out of range as Size: #{arg}")
          end
          str = (scalar * 100).to_i.to_s
          return new([(str[0].to_i << 4) + (str.bytesize-1)].pack("C"))
        else
          raise ArgumentError.new("cannot interpret as Size: #{arg.inspect}")
        end
      end

      # Internal use; use self.create.
      def initialize(scalar)
        @scalar = scalar
      end

      ##
      # The raw size

      attr_reader :scalar

      def to_s # :nodoc:
        s, = @scalar.unpack("C")
        return "#{(s >> 4) * (10.0 ** ((s & 0xf) - 2))}m"
      end

      def inspect # :nodoc:
        return "#<#{self.class} #{self}>"
      end

      def ==(other) # :nodoc:
        return @scalar == other.scalar
      end

      def eql?(other) # :nodoc:
        return self == other
      end

      def hash # :nodoc:
        return @scalar.hash
      end

    end

    ##
    # A Resolv::LOC::Coord

    class Coord

      # Regular expression LOC Coord must match.

      Regex = /\A0*(\d{1,3})\s([0-5]?\d)\s([0-5]?\d(?:\.\d+)?)\s([NESW])\z/

      # Bias for the equator/prime meridian, in thousandths of a second of arc.
      Bias = 1 << 31

      ##
      # Creates a new LOC::Coord from +arg+ which may be:
      #
      # LOC::Coord:: returns +arg+.
      # String:: +arg+ must match the LOC::Coord::Regex constant

      def self.create(arg)
        case arg
        when Coord
          return arg
        when String
          unless m = Regex.match(arg)
            raise ArgumentError.new("not a properly formed Coord string: " + arg)
          end

          arc = (m[1].to_i * 3_600_000) + (m[2].to_i * 60_000) + (m[3].to_f * 1_000).to_i
          dir = m[4]
          lat = dir[/[NS]/]
          unless arc <= (lat ? 324_000_000 : 648_000_000) # (lat ? 90 : 180) * 3_600_000
            raise ArgumentError.new("out of range as Coord: #{arg}")
          end

          hemi = dir[/[NE]/] ? 1 : -1
          return new([arc * hemi + Bias].pack("N"), lat ? "lat" : "lon")
        else
          raise ArgumentError.new("cannot interpret as Coord: #{arg.inspect}")
        end
      end

      # Internal use; use self.create.
      def initialize(coordinates,orientation)
        unless coordinates.kind_of?(String) and coordinates.bytesize == 4
          raise ArgumentError.new("Coord must be a 32bit unsigned integer in hex format: #{coordinates.inspect}")
        end
        unless orientation == "lon" || orientation == "lat"
          raise ArgumentError.new('Coord expects orientation to be a String argument of "lat" or "lon"')
        end
        @coordinates = coordinates
        @orientation = orientation
      end

      ##
      # The raw coordinates

      attr_reader :coordinates

      ## The orientation of the hemisphere as 'lat' or 'lon'

      attr_reader :orientation

      def to_s # :nodoc:
          c, = @coordinates.unpack("N")
          val = (c -= Bias).abs
          val, fracsecs = val.divmod(1000)
          val, secs     = val.divmod(60)
          degs, mins    = val.divmod(60)
          hemi = if c.negative?
            @orientation == "lon" ? "W" : "S"
          else
            @orientation == "lat" ? "N" : "E"
          end
          format("%d %02d %02d.%03d %s", degs, mins, secs, fracsecs, hemi)
      end

      def inspect # :nodoc:
        return "#<#{self.class} #{self}>"
      end

      def ==(other) # :nodoc:
        return @coordinates == other.coordinates
      end

      def eql?(other) # :nodoc:
        return self == other
      end

      def hash # :nodoc:
        return @coordinates.hash
      end

    end

    ##
    # A Resolv::LOC::Alt

    class Alt

      # Regular expression LOC Alt must match.

      Regex = /\A([+-]?0*\d{1,8}(?:\.\d+)?)m\z/

      # Bias to a base of 100,000m below the WGS 84 reference spheroid.
      Bias = 100_000_00

      ##
      # Creates a new LOC::Alt from +arg+ which may be:
      #
      # LOC::Alt:: returns +arg+.
      # String:: +arg+ must match the LOC::Alt::Regex constant

      def self.create(arg)
        case arg
        when Alt
          return arg
        when String
          unless Regex =~ arg
            raise ArgumentError.new("not a properly formed Alt string: " + arg)
          end
          altitude = ($1.to_f * 100).to_i + Bias
          unless (0...0x1_0000_0000) === altitude
            raise ArgumentError.new("out of raise as Alt: #{arg}")
          end
          return new([altitude].pack("N"))
        else
          raise ArgumentError.new("cannot interpret as Alt: #{arg.inspect}")
        end
      end

      # Internal use; use self.create.
      def initialize(altitude)
        @altitude = altitude
      end

      ##
      # The raw altitude

      attr_reader :altitude

      def to_s # :nodoc:
        a, = @altitude.unpack("N")
        return "#{(a - Bias).fdiv(100)}m"
      end

      def inspect # :nodoc:
        return "#<#{self.class} #{self}>"
      end

      def ==(other) # :nodoc:
        return @altitude == other.altitude
      end

      def eql?(other) # :nodoc:
        return self == other
      end

      def hash # :nodoc:
        return @altitude.hash
      end

    end

  end

  ##
  # Default resolver to use for Resolv class methods.

  DefaultResolver = self.new

  ##
  # Replaces the resolvers in the default resolver with +new_resolvers+.  This
  # allows resolvers to be changed for resolv-replace.

  def DefaultResolver.replace_resolvers new_resolvers
    @resolvers = new_resolvers
  end

  ##
  # Address Regexp to use for matching IP addresses.

  AddressRegex = /(?:#{IPv4::Regex})|(?:#{IPv6::Regex})/

end
