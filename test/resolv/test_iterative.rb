# frozen_string_literal: true
require "test/unit"
require "resolv/iterative"

class TestIterativeResolver < Test::Unit::TestCase
  IN = Resolv::DNS::Resource::IN
  ROOT_A = "192.0.2.1"
  ROOT_B = "192.0.2.2"

  # In-memory transport: each server IP gets a scripted handler that maps
  # (qname, qtype, tcp) to a canned Resolv::DNS::Message.  Every exchange is
  # logged so tests can assert exactly which servers were consulted.
  class ScriptedTransport
    Query = Struct.new(:server, :qname, :qtype, :tcp)
    attr_reader :queries

    def initialize
      @handlers = {}
      @queries = []
    end

    def add(server, &block)
      @handlers[server] = block
    end

    def exchange(server, message, tcp: false)
      qname, qtype = message.question.first
      @queries << Query.new(server, qname.to_s, qtype, tcp)
      handler = @handlers[server] or
        raise "no script for server #{server}"
      response = handler.call(qname.to_s, qtype, tcp)
      raise "no scripted response from #{server} for #{qname} (tcp=#{tcp})" unless response
      response.id = message.id
      response
    end

    def servers_queried
      @queries.map(&:server).uniq
    end
  end

  def setup
    @transport = ScriptedTransport.new
  end

  def resolver(**opts)
    Resolv::IterativeResolver.new(roots: [ROOT_A, ROOT_B], transport: @transport, **opts)
  end

  # -- message builders ----------------------------------------------------

  def abs(name)
    name.end_with?(".") ? name : "#{name}."
  end

  def response(qname, qtype = IN::A)
    m = Resolv::DNS::Message.new(0)
    m.qr = 1
    m.add_question(abs(qname), qtype)
    m
  end

  def referral(qname, zone, ns_names, glue = {})
    m = response(qname)
    ns_names.each {|ns| m.add_authority(zone, 300, Resolv::DNS::Resource::NS.new(ns)) }
    glue.each {|name, ip| m.add_additional(name, 300, IN::A.new(ip)) }
    m
  end

  def answer_a(qname, *ips)
    m = response(qname)
    ips.each {|ip| m.add_answer(abs(qname), 300, IN::A.new(ip)) }
    m
  end

  def cname_answer(qname, target)
    m = response(qname)
    m.add_answer(abs(qname), 300, Resolv::DNS::Resource::CNAME.new(target))
    m
  end

  def truncated(qname)
    m = response(qname)
    m.tc = 1
    m
  end

  def nxdomain(qname)
    m = response(qname)
    m.rcode = Resolv::DNS::RCode::NXDomain
    m
  end

  def events(result, event)
    result.chain.select {|hop| hop.event == event }
  end

  # -- tests ---------------------------------------------------------------

  def test_follows_delegation_chain_with_glue
    @transport.add(ROOT_A) {|q, _t, _tcp|
      referral(q, "com.", ["ns1.com."], "ns1.com." => "192.0.2.11")
    }
    @transport.add("192.0.2.11") {|q, _t, _tcp|
      referral(q, "example.com.", ["ns1.example.com."], "ns1.example.com." => "192.0.2.22")
    }
    @transport.add("192.0.2.22") {|q, _t, _tcp| answer_a(q, "203.0.113.7") }

    result = resolver.resolve("www.example.com")

    assert_equal :noerror, result.status
    assert_equal ["203.0.113.7"], result.addresses
    assert_equal [".", "com", "example.com"], result.delegation_path
    assert_equal 3, result.queries
    assert_equal 2, events(result, :glue_accepted).size
  end

  def test_out_of_bailiwick_glue_is_not_used_as_next_hop
    # example.com delegates to ns1.example.net (out of bailiwick) and the
    # additional section smuggles an address for it.  The resolver must
    # ignore that address and resolve ns1.example.net from the root instead.
    @transport.add(ROOT_A) {|q, _t, _tcp|
      if q.end_with?(".example.net") || q == "ns1.example.net"
        referral(q, "net.", ["ns1.net."], "ns1.net." => "192.0.2.33")
      else
        referral(q, "com.", ["ns1.com."], "ns1.com." => "192.0.2.11")
      end
    }
    @transport.add("192.0.2.11") {|q, _t, _tcp|
      referral(q, "example.com.", ["ns1.example.net."], "ns1.example.net." => "198.51.100.99")
    }
    # The smuggled address would answer with a forged record if consulted.
    @transport.add("198.51.100.99") {|q, _t, _tcp| answer_a(q, "6.6.6.6") }
    @transport.add("192.0.2.33") {|q, _t, _tcp|
      referral(q, "example.net.", ["ns1.example.net."], "ns1.example.net." => "192.0.2.44")
    }
    @transport.add("192.0.2.44") {|q, _t, _tcp| answer_a(q, "203.0.113.53") }
    @transport.add("203.0.113.53") {|q, _t, _tcp| answer_a(q, "203.0.113.7") }

    result = resolver.resolve("www.example.com")

    assert_equal :noerror, result.status
    assert_equal ["203.0.113.7"], result.addresses
    assert_not_include @transport.servers_queried, "198.51.100.99"
    rejected = events(result, :glue_rejected)
    assert_equal 1, rejected.size
    assert_include rejected[0].detail, "ns1.example.net"
    # The detour through example.net is visible in the walked chain.
    assert_include result.delegation_path, "example.net"
    assert_equal ["ns1.example.net"], events(result, :ns_lookup).map(&:detail)
  end

  def test_self_dependent_ns_without_glue_stops_with_cycle
    # example.com is served by ns1.example.com but no glue is ever provided:
    # resolving the NS address needs the zone itself.
    @transport.add(ROOT_A) {|q, _t, _tcp|
      referral(q, "com.", ["ns1.com."], "ns1.com." => "192.0.2.11")
    }
    @transport.add("192.0.2.11") {|q, _t, _tcp|
      referral(q, "example.com.", ["ns1.example.com."])
    }

    result = resolver.resolve("www.example.com")

    assert_equal :cycle_detected, result.status
    assert_equal ["ns1.example.com"], events(result, :ns_cycle).map(&:detail)
    stop = events(result, :stop).last
    assert_include stop.detail, "depends on this zone"
  end

  def test_mutually_dependent_ns_zones_stop_with_cycle
    # a.com -> ns1.b.com and b.com -> ns1.a.com, no glue anywhere.
    @transport.add(ROOT_A) {|q, _t, _tcp|
      referral(q, "com.", ["ns1.com."], "ns1.com." => "192.0.2.11")
    }
    @transport.add("192.0.2.11") {|q, _t, _tcp|
      if q.end_with?(".b.com") || q == "ns1.b.com"
        referral(q, "b.com.", ["ns1.a.com."])
      else
        referral(q, "a.com.", ["ns1.b.com."])
      end
    }

    result = resolver.resolve("www.a.com")

    assert_equal :cycle_detected, result.status
    cycles = events(result, :ns_cycle).map(&:detail)
    assert_equal ["ns1.b.com"], cycles
    # The trace shows the full a.com -> b.com -> a.com dependency walk.
    lookups = events(result, :ns_lookup).map(&:detail)
    assert_equal ["ns1.b.com", "ns1.a.com"], lookups
  end

  def test_udp_truncation_falls_back_to_tcp
    @transport.add(ROOT_A) {|q, _t, _tcp|
      referral(q, "com.", ["ns1.com."], "ns1.com." => "192.0.2.11")
    }
    @transport.add("192.0.2.11") {|q, _t, _tcp|
      referral(q, "example.com.", ["ns1.example.com."], "ns1.example.com." => "192.0.2.22")
    }
    @transport.add("192.0.2.22") {|q, _t, tcp|
      tcp ? answer_a(q, "203.0.113.7") : truncated(q)
    }

    result = resolver.resolve("www.example.com")

    assert_equal :noerror, result.status
    assert_equal ["203.0.113.7"], result.addresses
    tcp_queries = @transport.queries.select {|q| q.tcp && q.server == "192.0.2.22" }
    assert_equal 1, tcp_queries.size
    assert_equal 1, events(result, :tcp_retry).size
    assert_equal 4, result.queries
  end

  def test_cname_chain_across_zones
    @transport.add(ROOT_A) {|q, _t, _tcp|
      if q.end_with?(".example.net")
        referral(q, "net.", ["ns1.net."], "ns1.net." => "192.0.2.33")
      else
        referral(q, "com.", ["ns1.com."], "ns1.com." => "192.0.2.11")
      end
    }
    @transport.add("192.0.2.11") {|q, _t, _tcp|
      referral(q, "example.com.", ["ns1.example.com."], "ns1.example.com." => "192.0.2.22")
    }
    @transport.add("192.0.2.22") {|q, _t, _tcp| cname_answer(q, "www.example.net.") }
    @transport.add("192.0.2.33") {|q, _t, _tcp|
      referral(q, "example.net.", ["ns1.example.net."], "ns1.example.net." => "192.0.2.44")
    }
    @transport.add("192.0.2.44") {|q, _t, _tcp| answer_a(q, "203.0.113.8") }

    result = resolver.resolve("www.example.com")

    assert_equal :noerror, result.status
    assert_equal ["203.0.113.8"], result.addresses
    assert_equal ["www.example.net"], result.cname_chain
    assert_equal 1, events(result, :cname).size
  end

  def test_cname_loop_is_terminated
    @transport.add(ROOT_A) {|q, _t, _tcp|
      referral(q, "com.", ["ns1.com."], "ns1.com." => "192.0.2.11")
    }
    @transport.add("192.0.2.11") {|q, _t, _tcp|
      referral(q, "example.com.", ["ns1.example.com."], "ns1.example.com." => "192.0.2.22")
    }
    @transport.add("192.0.2.22") {|q, _t, _tcp|
      cname_answer(q, q == "a.example.com" ? "b.example.com." : "a.example.com.")
    }

    result = resolver.resolve("a.example.com")

    assert_equal :cname_loop, result.status
  end

  def test_dname_synthesis
    @transport.add(ROOT_A) {|q, _t, _tcp|
      if q.end_with?(".example.org")
        referral(q, "org.", ["ns1.org."], "ns1.org." => "192.0.2.55")
      else
        referral(q, "com.", ["ns1.com."], "ns1.com." => "192.0.2.11")
      end
    }
    @transport.add("192.0.2.11") {|q, _t, _tcp|
      referral(q, "example.com.", ["ns1.example.com."], "ns1.example.com." => "192.0.2.22")
    }
    @transport.add("192.0.2.22") {|q, _t, _tcp|
      m = response(q)
      m.add_answer("sub.example.com.", 300, IN::DNAME.new("sub.example.org."))
      m
    }
    @transport.add("192.0.2.55") {|q, _t, _tcp|
      referral(q, "example.org.", ["ns1.example.org."], "ns1.example.org." => "192.0.2.66")
    }
    @transport.add("192.0.2.66") {|q, _t, _tcp| answer_a(q, "203.0.113.9") }

    result = resolver.resolve("www.sub.example.com")

    assert_equal :noerror, result.status
    assert_equal ["203.0.113.9"], result.addresses
    assert_equal ["www.sub.example.org"], result.cname_chain
    assert_equal 1, events(result, :dname).size
  end

  def test_query_budget_stops_endless_delegation
    # Every server delegates exactly one label deeper, forever.
    @transport.add(ROOT_A) {|q, _t, _tcp|
      referral(q, "test.", ["ns.test."], "ns.test." => "192.0.2.77")
    }
    depth = 0
    @transport.add("192.0.2.77") {|q, _t, _tcp|
      depth += 1
      labels = q.split(".")
      zone = labels.drop(labels.length - 1 - depth).join(".") + "."
      referral(q, zone, ["ns.#{zone}"], "ns.#{zone}" => "192.0.2.77")
    }

    result = resolver(budget: 5).resolve("a.b.c.d.e.f.test")

    assert_equal :budget_exhausted, result.status
    assert_equal 5, result.queries
  end

  def test_repeated_delegation_is_detected
    @transport.add(ROOT_A) {|q, _t, _tcp|
      referral(q, "com.", ["ns1.com."], "ns1.com." => "192.0.2.11")
    }
    @transport.add("192.0.2.11") {|q, _t, _tcp|
      referral(q, "example.com.", ["ns1.example.com."], "ns1.example.com." => "192.0.2.22")
    }
    # The example.com server lamely refers back to its own zone.
    @transport.add("192.0.2.22") {|q, _t, _tcp|
      referral(q, "example.com.", ["ns1.example.com."], "ns1.example.com." => "192.0.2.22")
    }

    result = resolver.resolve("www.example.com")

    assert_equal :repeated_delegation, result.status
  end

  def test_nxdomain
    @transport.add(ROOT_A) {|q, _t, _tcp|
      referral(q, "com.", ["ns1.com."], "ns1.com." => "192.0.2.11")
    }
    @transport.add("192.0.2.11") {|q, _t, _tcp| nxdomain(q) }

    result = resolver.resolve("nope.com")

    assert_equal :nxdomain, result.status
    assert_equal [".", "com"], result.delegation_path
  end

  def test_delegation_chain_is_reported_on_failure
    @transport.add(ROOT_A) {|q, _t, _tcp|
      referral(q, "com.", ["ns1.com."], "ns1.com." => "192.0.2.11")
    }
    @transport.add("192.0.2.11") {|q, _t, _tcp|
      referral(q, "example.com.", ["ns1.example.com."], "ns1.example.com." => "192.0.2.22")
    }
    @transport.add("192.0.2.22") {|q, _t, _tcp| response(q) } # empty, no SOA, no NS

    result = resolver.resolve("www.example.com")

    assert_equal :dead_end, result.status
    assert_equal [".", "com", "example.com"], result.delegation_path
  end
end
