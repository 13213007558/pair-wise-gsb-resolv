# frozen_string_literal: true
require 'test/unit'
require 'resolv'

class TestResolvDNSIterator < Test::Unit::TestCase
  A = Resolv::DNS::Resource::IN::A
  NS = Resolv::DNS::Resource::NS
  CNAME = Resolv::DNS::Resource::CNAME
  DNAME = Resolv::DNS::Resource::DNAME

  def test_follows_delegation_and_ignores_out_of_bailiwick_glue
    transport = ScriptedTransport.new(
      ['www.example.org', '192.0.1.1', :udp] => referral(
        'www.example.org', 'example.org', ['ns.outside.infra.net'],
        '192.0.1.1') do |reply|
        # ns.outside.infra.net is not in the example.org bailiwick.  Even a
        # present address must not be treated as the next server.
        reply.add_additional('ns.outside.infra.net', 3600, A.new('192.0.2.66'))
        # Unrelated additional records are never useful as a next hop.
        reply.add_additional('not-a-nameserver.example.org', 3600, A.new('192.0.2.67'))
      end,
      ['ns.outside.infra.net', '192.0.1.1', :udp] => referral(
        'ns.outside.infra.net', 'net', ['ns.infra.net'],
        '192.0.1.1') do |reply|
        reply.add_additional('ns.infra.net', 3600, A.new('192.0.2.10'))
      end,
      ['ns.outside.infra.net', '192.0.2.10', :udp] => answer(
        'ns.outside.infra.net', '192.0.2.20', '192.0.2.10', aa: true),
      ['www.example.org', '192.0.2.20', :udp] => answer(
        'www.example.org', '192.0.2.77', '192.0.2.20', aa: true)
    )
    resolver = Resolv::DNS::Iterator.new(
      root_servers: ['192.0.1.1'], transport: transport)

    result = resolver.resolve('www.example.org')

    assert_equal(['192.0.2.77'], result.resources.map { |resource|
      resource.address.to_s
    })
    assert_equal(
      ['', 'example.org', '', 'net'],
      result.delegation_chain.map { |delegation| delegation.zone.to_s })
    assert_not_include(contacted_servers(transport), '192.0.2.66')
    assert_not_include(contacted_servers(transport), '192.0.2.67')
    assert_equal(
      [
        ['www.example.org', '192.0.1.1', :udp],
        ['ns.outside.infra.net', '192.0.1.1', :udp],
        ['ns.outside.infra.net', '192.0.2.10', :udp],
        ['www.example.org', '192.0.2.20', :udp],
      ],
      transport.requests.map { |request|
        [request.name.to_s, request.server_address, request.protocol]
      })
  end

  def test_stops_when_nameserver_addresses_are_mutually_dependent
    transport = ScriptedTransport.new(
      ['host.alpha.test', '192.0.1.1', :udp] => referral(
        'host.alpha.test', 'alpha.test', ['ns.beta.test'], '192.0.1.1'),
      ['ns.beta.test', '192.0.1.1', :udp] => referral(
        'ns.beta.test', 'beta.test', ['ns.alpha.test'], '192.0.1.1'),
      ['ns.alpha.test', '192.0.1.1', :udp] => referral(
        'ns.alpha.test', 'alpha.test', ['ns.beta.test'], '192.0.1.1')
    )
    resolver = Resolv::DNS::Iterator.new(
      root_servers: ['192.0.1.1'], transport: transport)

    error = assert_raise(Resolv::DNS::Iterator::NameserverCycle) do
      resolver.resolve('host.alpha.test')
    end

    assert_equal(['alpha.test', 'beta.test'], error.dependencies)
    assert_equal(
      ['host.alpha.test', 'ns.beta.test', 'ns.alpha.test'],
      transport.requests.map { |request| request.name.to_s })
    assert_equal(
      ['', 'alpha.test', '', 'beta.test', '', 'alpha.test'],
      error.delegation_chain.map { |delegation| delegation.zone.to_s })
  end

  def test_follows_cname_then_dname_and_reports_alias_chain
    transport = ScriptedTransport.new(
      ['alias.example.test', '192.0.1.1', :udp] => referral(
        'alias.example.test', 'example.test', ['ns.example.test'],
        '192.0.1.1') do |reply|
        reply.add_additional('ns.example.test', 3600, A.new('192.0.2.30'))
      end,
      ['alias.example.test', '192.0.2.30', :udp] => authoritative(
        'alias.example.test', '192.0.2.30') do |reply|
        reply.add_answer('alias.example.test', 3600,
                         CNAME.new(Resolv::DNS::Name.create('name.other.test.')))
      end,
      ['name.other.test', '192.0.1.1', :udp] => referral(
        'name.other.test', 'other.test', ['ns.other.test'],
        '192.0.1.1') do |reply|
        reply.add_additional('ns.other.test', 3600, A.new('192.0.2.40'))
      end,
      ['name.other.test', '192.0.2.40', :udp] => authoritative(
        'name.other.test', '192.0.2.40') do |reply|
        reply.add_answer('other.test', 3600,
                         DNAME.new(Resolv::DNS::Name.create('final.other.test.')))
        reply.add_answer('name.other.test', 3600,
                         CNAME.new(Resolv::DNS::Name.create('name.final.other.test.')))
        reply.add_answer('name.final.other.test', 3600, A.new('192.0.2.50'))
      end,
    )
    resolver = Resolv::DNS::Iterator.new(
      root_servers: ['192.0.1.1'], transport: transport)

    result = resolver.resolve('alias.example.test')

    assert_equal(['192.0.2.50'], result.resources.map(&:address).map(&:to_s))
    assert_equal(
      [['alias.example.test', 'name.other.test', CNAME],
       ['other.test', 'final.other.test', DNAME]],
      result.alias_chain.map {
        |alias_record| [alias_record.owner.to_s, alias_record.target.to_s,
                        alias_record.type] })
    assert_equal(
      ['', 'example.test', '', 'other.test'],
      result.delegation_chain.map { |delegation| delegation.zone.to_s })
  end

  def test_retries_truncated_udp_response_with_tcp
    transport = ScriptedTransport.new(
      ['www.truncated.test', '192.0.1.1', :udp] => truncated(
        'www.truncated.test', '192.0.1.1'),
      ['www.truncated.test', '192.0.1.1', :tcp] => referral(
        'www.truncated.test', 'truncated.test', ['ns.truncated.test'],
        '192.0.1.1') do |reply|
        reply.add_additional('ns.truncated.test', 3600, A.new('192.0.2.80'))
      end,
      ['www.truncated.test', '192.0.2.80', :udp] => answer(
        'www.truncated.test', '192.0.2.90', '192.0.2.80', aa: true)
    )
    resolver = Resolv::DNS::Iterator.new(
      root_servers: ['192.0.1.1'], transport: transport)

    result = resolver.resolve('www.truncated.test')

    assert_equal(['192.0.2.90'], result.resources.map(&:address).map(&:to_s))
    assert_equal([:udp, :tcp, :udp], transport.requests.map(&:protocol))
    assert_equal(0, result.message.tc)
  end

  def test_stops_repeated_delegation_within_one_alias_phase
    transport = ScriptedTransport.new(
      ['host.loop.test', '192.0.1.1', :udp] => referral(
        'host.loop.test', 'loop.test', ['ns.loop.test'], '192.0.1.1') do |reply|
        reply.add_additional('ns.loop.test', 3600, A.new('192.0.2.60'))
      end,
      ['host.loop.test', '192.0.2.60', :udp] => referral(
        'host.loop.test', 'host.loop.test', ['ns1.host.loop.test'],
        '192.0.2.60') do |reply|
        reply.add_additional('ns1.host.loop.test', 3600, A.new('192.0.2.61'))
      end,
      ['host.loop.test', '192.0.2.61', :udp] => referral(
        'host.loop.test', 'host.loop.test', ['ns1.host.loop.test'],
        '192.0.2.61') do |reply|
        reply.add_additional('ns1.host.loop.test', 3600, A.new('192.0.2.61'))
      end,
    )
    resolver = Resolv::DNS::Iterator.new(
      root_servers: ['192.0.1.1'], transport: transport)

    assert_raise(Resolv::DNS::Iterator::DelegationLoop) do
      resolver.resolve('host.loop.test')
    end
    assert_equal(3, transport.requests.length)
  end

  def test_enforces_query_budget_across_ns_subqueries
    transport = ScriptedTransport.new(
      ['host.budget.test', '192.0.1.1', :udp] => referral(
        'host.budget.test', 'budget.test', ['ns1.budget.test'],
        '192.0.1.1')
    )
    resolver = Resolv::DNS::Iterator.new(
      root_servers: ['192.0.1.1'], transport: transport, query_budget: 1)

    error = assert_raise(Resolv::DNS::Iterator::QueryBudgetExceeded) do
      resolver.resolve('host.budget.test')
    end
    assert_equal(1, error.queries.length)
  end

  private

  def contacted_servers(transport)
    transport.requests.map(&:server_address)
  end

  def base_reply(request, aa:, tc:, rcode: 0)
    reply = Resolv::DNS::Message.new
    reply.qr = 1
    reply.aa = aa ? 1 : 0
    reply.tc = tc ? 1 : 0
    reply.rcode = rcode
    reply.add_question(request.name, request.type)
    yield reply if block_given?
    reply
  end

  Question = Struct.new(:name, :type)

  def absolute_name(name)
    Resolv::DNS::Name.new(Resolv::DNS::Label.split(name), true)
  end

  def referral(qname, zone, nameservers, _server)
    request = Question.new(absolute_name(qname), A)
    base_reply(request, aa: false, tc: false) do |reply|
      nameservers.each do |nameserver|
        reply.add_authority("#{zone}.", 3600,
                            NS.new(Resolv::DNS::Name.create("#{nameserver}.")))
      end
      yield reply if block_given?
    end
  end

  def answer(qname, address, _server, aa: false, tc: false)
    request = Question.new(absolute_name(qname), A)
    base_reply(request, aa: aa, tc: tc) do |reply|
      reply.add_answer("#{qname}.", 3600, A.new(address))
    end
  end

  def authoritative(qname, _server)
    request = Question.new(absolute_name(qname), A)
    base_reply(request, aa: true, tc: false) do |reply|
      yield reply
    end
  end

  def truncated(qname, _server)
    request = Question.new(absolute_name(qname), A)
    base_reply(request, aa: false, tc: true)
  end

  class ScriptedTransport
    attr_reader :requests

    def initialize(responses)
      @responses = responses
      @requests = []
    end

    def call(request)
      @requests << request
      key = [request.name.to_s, request.server_address, request.protocol]
      response = @responses.fetch(key) do
        raise "unexpected scripted query #{key.inspect}"
      end
      response = response.call if response.respond_to?(:call)
      response.id = request.message.id
      response
    end
  end
end
