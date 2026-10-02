# frozen_string_literal: true

require "resolv"
require "socket"

class Resolv
  # IterativeResolver is a testable iterative DNS resolver built on top of
  # Resolv::DNS message handling.  It starts from an explicit list of root
  # server addresses and follows delegations itself instead of asking a
  # recursive server.
  #
  # The transport is injectable: any object responding to
  #   exchange(server_ip, Resolv::DNS::Message, tcp: false) -> Resolv::DNS::Message
  # can be used, so tests can script in-memory responses without touching
  # the network.  NetworkTransport is the default UDP/TCP implementation.
  #
  # Security properties:
  # * Only referrals that stay below (or at) the current delegation zone and
  #   above (or at) the query name are followed.
  # * Glue records from the additional section are only trusted when the NS
  #   name is in-bailiwick: at/below the delegated zone, or at/below the
  #   zone the answering server is authoritative for.  Anything else in the
  #   additional section is never used as a next hop.
  # * NS names without usable glue are resolved as sub-queries; a dependency
  #   stack detects zones whose NS addresses (indirectly) depend on the zone
  #   itself, and resolution stops instead of looping.
  #
  # Termination is unified: every DNS exchange decrements a shared query
  # budget, and delegation depth, CNAME chain length, repeated delegations
  # and NS dependency cycles each map to an explicit Result#status.
  class IterativeResolver
    # Raised by transports when a query cannot be delivered or decoded.
    class TransportError < ResolvError; end

    # One entry in the resolution trace.  +event+ is one of:
    #   :query :referral :glue_accepted :glue_rejected :ns_lookup
    #   :ns_cycle :ns_unresolvable :tcp_retry :cname :dname
    #   :answer :nxdomain :nodata :stop
    Hop = Struct.new(:zone, :server, :event, :detail, keyword_init: true)

    # The outcome of a resolve call.
    class Result
      attr_reader :status, :answers, :chain, :cname_chain, :queries

      def initialize(status:, answers:, chain:, cname_chain:, queries:)
        @status = status
        @answers = answers
        @chain = chain
        @cname_chain = cname_chain
        @queries = queries
      end

      def success?
        @status == :noerror
      end

      # IPv4/IPv6 addresses found in the answer, as strings.
      def addresses
        @answers.filter_map {|_name, _ttl, data|
          case data
          when DNS::Resource::IN::A, DNS::Resource::IN::AAAA
            data.address.to_s
          end
        }
      end

      # The zones actually walked, in order, starting at the root.
      def delegation_path
        @chain.select {|hop| hop.event == :query }.map(&:zone).uniq
      end
    end

    # Default transport: real UDP with TCP fallback handled by the resolver.
    class NetworkTransport
      def initialize(port: 53, timeout: 3)
        @port = port
        @timeout = timeout
      end

      def exchange(server, message, tcp: false)
        data = message.encode
        if tcp
          exchange_tcp(server, data)
        else
          exchange_udp(server, data)
        end
      rescue SystemCallError, SocketError, Resolv::DNS::DecodeError,
             Resolv::DNS::EncodeError, IOError => e
        raise TransportError, "#{server}: #{e.message}"
      end

      private

      def exchange_udp(server, data)
        UDPSocket.open do |sock|
          sock.connect(server, @port)
          sock.send(data, 0)
          unless IO.select([sock], nil, nil, @timeout)
            raise TransportError, "#{server}: UDP timeout"
          end
          packet, = sock.recvfrom(65_535)
          DNS::Message.decode(packet)
        end
      end

      def exchange_tcp(server, data)
        TCPSocket.open(server, @port) do |sock|
          sock.write([data.bytesize].pack("n") + data)
          header = read_exactly(sock, 2)
          DNS::Message.decode(read_exactly(sock, header.unpack1("n")))
        end
      end

      def read_exactly(sock, length)
        unless IO.select([sock], nil, nil, @timeout)
          raise TransportError, "TCP timeout"
        end
        buf = +""
        buf << sock.readpartial(length - buf.bytesize) while buf.bytesize < length
        buf
      end
    end

    # DNAME (RFC 6672) is not part of resolv's resource set; register it so
    # wire decoding and test construction both work.
    class DNS::Resource::IN::DNAME < DNS::Resource::DomainName
      TypeValue = 39
      ClassValue = DNS::Resource::IN::ClassValue
      DNS::Resource::ClassHash[[TypeValue, ClassValue]] = self
    end

    ROOT = DNS::Name.create(".")

    # roots:            array of root server IP strings (required, explicit)
    # transport:        object responding to #exchange (default: network)
    # budget:           max total DNS exchanges per resolve, shared with
    #                   NS-address sub-queries (default 30)
    # max_delegations:  max zone cuts followed for one name (default 16)
    # max_cnames:       max CNAME/DNAME hops per resolve (default 8)
    def initialize(roots:, transport: NetworkTransport.new, budget: 30,
                   max_delegations: 16, max_cnames: 8)
      raise ArgumentError, "roots must not be empty" if roots.empty?
      @roots = roots
      @transport = transport
      @budget = budget
      @max_delegations = max_delegations
      @max_cnames = max_cnames
    end

    # Iteratively resolve +name+ for +typeclass+ (a Resolv::DNS::Resource
    # class).  Returns a Result; check Result#status and Result#chain.
    def resolve(name, typeclass = DNS::Resource::IN::A)
      ctx = Context.new
      outcome = catch(:budget_exhausted) do
        follow_aliases(absolute_name(name), typeclass, ctx, [])
      end
      outcome ||= Outcome.new(:budget_exhausted, [])
      Result.new(status: outcome.status, answers: outcome.answers,
                 chain: ctx.chain, cname_chain: ctx.cname_chain,
                 queries: ctx.queries)
    end

    private

    Outcome = Struct.new(:status, :answers, :alias_target)

    class Context
      attr_reader :chain, :cname_chain
      attr_accessor :queries, :delegations

      def initialize
        @chain = []
        @cname_chain = []
        @queries = 0
        @delegations = 0
      end

      def log(zone, server, event, detail = nil)
        @chain << Hop.new(zone: zone, server: server, event: event, detail: detail)
      end
    end

    # Follows CNAME/DNAME aliases; each target is iterated from the root so
    # that an alias never inherits trust from the wrong zone.
    def follow_aliases(qname, typeclass, ctx, ns_stack)
      seen = {}
      hops = 0
      loop do
        return Outcome.new(:cname_loop, []) if seen.key?(qname) || hops >= @max_cnames
        seen[qname] = true
        outcome = iterate(qname, typeclass, ctx, ns_stack)
        return outcome unless outcome.status == :alias
        ctx.cname_chain << name_string(outcome.alias_target)
        hops += 1
        qname = outcome.alias_target
      end
    end

    # Walks the delegation chain for one name, from the root down.
    def iterate(qname, typeclass, ctx, ns_stack)
      zone = ROOT
      servers = @roots
      visited = {}
      loop do
        return Outcome.new(:too_many_delegations, []) if ctx.delegations >= @max_delegations
        key = [zone, servers.sort]
        if visited.key?(key)
          ctx.log(name_string(zone), nil, :stop, "repeated delegation")
          return Outcome.new(:repeated_delegation, [])
        end
        visited[key] = true

        response = query_servers(zone, servers, qname, typeclass, ctx)
        return Outcome.new(:transport_error, []) unless response

        case response.rcode
        when DNS::RCode::NoError then nil
        when DNS::RCode::NXDomain
          ctx.log(name_string(zone), nil, :nxdomain)
          return Outcome.new(:nxdomain, [])
        else
          return Outcome.new(:server_failure, [])
        end

        answers = []
        cname = nil
        response.each_answer do |rrname, ttl, data|
          next unless rrname == qname
          answers << [rrname, ttl, data] if data.is_a?(typeclass)
          cname = DNS::Name.create(data.name) if data.is_a?(DNS::Resource::CNAME)
        end
        unless answers.empty?
          ctx.log(name_string(zone), nil, :answer)
          return Outcome.new(:noerror, answers)
        end
        if cname
          ctx.log(name_string(zone), nil, :cname, name_string(cname))
          return Outcome.new(:alias, [], cname)
        end

        dname_owner, dname_target = find_dname(response, qname, zone)
        if dname_owner
          synthesized = synthesize(qname, dname_owner, dname_target)
          ctx.log(name_string(zone), nil, :dname,
                  "#{name_string(dname_owner)} -> #{name_string(dname_target)}")
          return Outcome.new(:alias, [], synthesized)
        end

        if response.answer.empty? && soa?(response)
          ctx.log(name_string(zone), nil, :nodata)
          return Outcome.new(:nodata, [])
        end

        referral_zone, ns_names = find_referral(response, zone, qname)
        unless referral_zone
          ctx.log(name_string(zone), nil, :stop, "no usable referral")
          return Outcome.new(:dead_end, [])
        end

        ctx.delegations += 1
        ctx.log(name_string(zone), nil, :referral, name_string(referral_zone))
        addresses, cycle = servers_for(referral_zone, zone, ns_names, response, ctx, ns_stack)
        if addresses.empty?
          status = cycle ? :cycle_detected : :dead_end
          ctx.log(name_string(referral_zone), nil, :stop,
                  cycle ? "NS address resolution depends on this zone" : "no usable name server")
          return Outcome.new(status, [])
        end
        zone = referral_zone
        servers = addresses
      end
    end

    # Sends one question to the first responding server; retries over TCP
    # when the UDP response is truncated.  Every exchange counts against
    # the shared budget.
    def query_servers(zone, servers, qname, typeclass, ctx)
      servers.each do |server|
        response = exchange(ctx, zone, server, qname, typeclass, false)
        next unless response
        if response.tc == 1
          ctx.log(name_string(zone), server, :tcp_retry)
          response = exchange(ctx, zone, server, qname, typeclass, true)
        end
        return response if response
      end
      nil
    end

    def exchange(ctx, zone, server, qname, typeclass, tcp)
      throw(:budget_exhausted) if ctx.queries >= @budget
      message = DNS::Message.new
      message.rd = 0
      message.add_question(qname, typeclass)
      ctx.queries += 1
      ctx.log(name_string(zone), server, :query,
              "#{name_string(qname)} #{type_name(typeclass)}#{tcp ? ' (tcp)' : ''}")
      @transport.exchange(server, message, tcp: tcp)
    rescue TransportError
      nil
    end

    # Collects next-hop addresses for a referral.  Glue is accepted only
    # in-bailiwick; NS names left without addresses are resolved
    # recursively with a dependency stack that breaks delegation cycles.
    # Returns [addresses, cycle_detected].
    def servers_for(referral_zone, current_zone, ns_names, response, ctx, ns_stack)
      addresses = []
      cycle = false
      ns_names.each do |ns|
        glue = glue_for(response, ns)
        bailiwick = in_zone?(ns, referral_zone) || in_zone?(ns, current_zone)
        if bailiwick && glue.any?
          glue.each do |ip|
            ctx.log(name_string(referral_zone), nil, :glue_accepted, "#{name_string(ns)} #{ip}")
          end
          addresses.concat(glue)
          next
        end
        if !bailiwick && glue.any?
          ctx.log(name_string(referral_zone), nil, :glue_rejected,
                  "#{name_string(ns)} out-of-bailiwick (#{glue.join(', ')})")
        end

        if ns_stack.include?(ns)
          cycle = true
          ctx.log(name_string(referral_zone), nil, :ns_cycle, name_string(ns))
          next
        end
        ctx.log(name_string(referral_zone), nil, :ns_lookup, name_string(ns))
        sub = follow_aliases(ns, DNS::Resource::IN::A, ctx, ns_stack + [ns])
        if sub.status == :noerror
          addresses.concat(sub.answers.filter_map {|_n, _t, d|
            d.address.to_s if d.is_a?(DNS::Resource::IN::A)
          })
        else
          cycle ||= sub.status == :cycle_detected
          ctx.log(name_string(referral_zone), nil, :ns_unresolvable,
                  "#{name_string(ns)} (#{sub.status})")
        end
      end
      [addresses.uniq, cycle]
    end

    def glue_for(response, ns)
      ips = []
      response.each_additional do |name, _ttl, data|
        next unless name == ns
        case data
        when DNS::Resource::IN::A, DNS::Resource::IN::AAAA
          ips << data.address.to_s
        end
      end
      ips
    end

    # The deepest NS owner in the authority section that is at/below the
    # current zone and an ancestor of (or equal to) the query name.
    def find_referral(response, current_zone, qname)
      best_zone = nil
      ns_names = []
      response.each_authority do |name, _ttl, data|
        next unless data.is_a?(DNS::Resource::NS)
        next unless in_zone?(name, current_zone) && in_zone?(qname, name)
        if best_zone.nil? || name.length > best_zone.length
          best_zone = name
          ns_names = []
        end
        ns_names << DNS::Name.create(data.name) if name == best_zone
      end
      [best_zone, ns_names]
    end

    def find_dname(response, qname, zone)
      best = nil
      response.each_answer do |name, _ttl, data|
        next unless data.is_a?(DNS::Resource::IN::DNAME)
        next unless qname.subdomain_of?(name) && in_zone?(name, zone)
        best = [name, DNS::Name.create(data.name)] if best.nil? || name.length > best[0].length
      end
      best || [nil, nil]
    end

    def synthesize(qname, owner, target)
      prefix = qname.to_a[0, qname.length - owner.length]
      DNS::Name.new(prefix + target.to_a, true)
    end

    def soa?(response)
      response.authority.any? {|_name, _ttl, data| data.is_a?(DNS::Resource::SOA) }
    end

    def in_zone?(name, zone)
      name == zone || name.subdomain_of?(zone)
    end

    def absolute_name(name)
      n = DNS::Name.create(name)
      n.absolute? ? n : DNS::Name.create("#{n}.")
    end

    def name_string(name)
      name.to_a.empty? ? "." : name.to_s
    end

    def type_name(typeclass)
      typeclass.name ? typeclass.name.sub(/.*::/, "") : "TYPE#{typeclass::TypeValue}"
    end
  end
end
