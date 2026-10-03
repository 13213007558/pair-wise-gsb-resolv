require 'test/unit'
require 'resolv'
require 'openssl'

class TestResolvDNSSEC < Test::Unit::TestCase
  ZONE = Resolv::DNS::Name.create('example.')
  TTL = 3600

  def setup
    @key = OpenSSL::PKey::RSA.generate(1024)
    @dnskey = Resolv::DNS::Resource::IN::DNSKEY.new(257, 3, 8, rsa_blob(@key))
    @now = Time.now.to_i
  end

  def test_nsec_nxdomain
    message = negative_message('missing.example.', Resolv::DNS::Resource::IN::A, 3)
    add_signed_soa(message)
    add_nsec(message, ZONE, 'a.example.', [6, 46, 47])
    add_nsec(message, 'a.example.', 'b.example.', [46, 47])
    add_nsec(message, 'b.example.', 'z.example.', [46, 47])

    result = verify(message, 'missing.example.', Resolv::DNS::Resource::IN::A)
    assert_equal :nxdomain, result.status
    assert_predicate result, :proven?
    assert_predicate result.signatures, :valid?
  end

  def test_nsec_nodata_type_bitmap
    message = negative_message('host.example.', Resolv::DNS::Resource::IN::A, 0)
    add_signed_soa(message)
    add_nsec(message, 'host.example.', 'next.example.', [46, 47])

    result = verify(message, 'host.example.', Resolv::DNS::Resource::IN::A)
    assert_equal :nodata, result.status
    assert_predicate result, :proven?
    assert_not_include result.records.first[:data].types, 1
  end

  def test_signed_but_unrelated_nsec_range_does_not_prove
    message = negative_message('caa.example.', Resolv::DNS::Resource::IN::A, 3)
    add_signed_soa(message)
    add_nsec(message, ZONE, 'a.example.', [6, 46, 47])
    add_nsec(message, 'a.example.', 'b.example.', [46, 47])

    result = verify(message, 'caa.example.', Resolv::DNS::Resource::IN::A)
    assert_equal :unproven, result.status
    refute_predicate result, :proven?
    assert_predicate result.signatures, :valid?
  end

  def test_bad_signature_is_separate_from_valid_proof_shape
    message = negative_message('missing.example.', Resolv::DNS::Resource::IN::A, 3)
    add_signed_soa(message)
    add_nsec(message, ZONE, 'a.example.', [6, 46, 47])
    add_nsec(message, 'a.example.', 'b.example.', [46, 47])
    add_nsec(message, 'b.example.', 'z.example.', [46, 47])
    tamper_last_rrsig(message)

    result = verify(message, 'missing.example.', Resolv::DNS::Resource::IN::A)
    assert_equal :nxdomain, result.status
    refute_predicate result, :proven?
    refute_predicate result.signatures, :valid?
    assert_match(/cryptographic/, result.signatures.failures.map {|failure| failure[:reason]}.join)
  end

  def test_plain_empty_answer_is_not_inferred_as_nodata
    message = negative_message('missing.example.', Resolv::DNS::Resource::IN::A, 0)
    add_signed_soa(message)

    result = verify(message, 'missing.example.', Resolv::DNS::Resource::IN::A)
    assert_equal :nodata, result.status
    refute_predicate result, :proven?
    assert_equal 'no NSEC or NSEC3 range plus type bitmap proves NODATA', result.reason
  end

  def test_nsec3_nxdomain
    message = negative_message('host.example.', Resolv::DNS::Resource::IN::A, 3)
    add_signed_soa(message)
    add_nsec3param(message, 1, 0, 0, '')
    add_nsec3(message, nsec3_owner(ZONE, ''), zero_hash, 1, 0, 0, '', max_hash, [6, 50, 51])

    result = verify(message, 'host.example.', Resolv::DNS::Resource::IN::A)
    assert_equal :nxdomain, result.status
    assert_predicate result, :proven?
    assert_equal 1, result.records.length
  end

  def test_nsec3_hash_order_wraparound
    message = negative_message('host.example.', Resolv::DNS::Resource::IN::A, 3)
    add_signed_soa(message)
    add_nsec3param(message, 1, 0, 0, 'wrap')
    add_nsec3(message, nsec3_owner(ZONE, 'wrap'), nsec3_hash(ZONE, 'wrap'), 1, 0, 0, 'wrap', max_hash, [6, 50, 51])
    add_nsec3(message, owner_for_hash(max_hash, ZONE), max_hash, 1, 0, 0, 'wrap', zero_hash, [6, 50, 51])

    result = verify(message, 'host.example.', Resolv::DNS::Resource::IN::A)
    assert_equal :nxdomain, result.status
    assert_predicate result, :proven?
  end

  def test_nsec3_parameter_mismatch_is_unproven
    message = negative_message('host.example.', Resolv::DNS::Resource::IN::A, 3)
    add_signed_soa(message)
    add_nsec3param(message, 1, 0, 0, '')
    add_nsec3(message, nsec3_owner(ZONE, ''), nsec3_hash(ZONE, ''), 1, 0, 0, '', nsec3_hash('host.example.', ''), [6, 50, 51])
    add_nsec3(message, owner_for_hash(zero_hash, ZONE), zero_hash, 1, 0, 0, 'salted', nsec3_hash('host.example.', 'salted'), [50])

    result = verify(message, 'host.example.', Resolv::DNS::Resource::IN::A)
    assert_equal :unproven, result.status
    refute_predicate result, :proven?
  end

  def test_nsec3_opt_out_is_insecure_for_ds_not_nodata
    message = negative_message('host.example.', Resolv::DNS::Resource::IN::DS, 0)
    add_signed_soa(message)
    add_nsec3param(message, 1, 0, 0, '')
    add_nsec3(message, nsec3_owner(ZONE, ''), max_hash, 1, 1, 0, '', zero_hash, [6, 50, 51])

    result = verify(message, 'host.example.', Resolv::DNS::Resource::IN::DS)
    assert_equal :insecure_delegation, result.status
    refute_predicate result, :proven?
    assert_predicate result.signatures, :valid?
  end

  def test_nsec3_opt_out_does_not_prove_nodata_for_other_types
    message = negative_message('host.example.', Resolv::DNS::Resource::IN::A, 0)
    add_signed_soa(message)
    add_nsec3param(message, 1, 0, 0, '')
    add_nsec3(message, nsec3_owner(ZONE, ''), max_hash, 1, 1, 0, '', zero_hash, [6, 50, 51])

    result = verify(message, 'host.example.', Resolv::DNS::Resource::IN::A)
    assert_equal :nodata, result.status
    refute_predicate result, :proven?
  end

  def test_nsec3_wildcard_nodata
    message = negative_message('b.example.', Resolv::DNS::Resource::IN::A, 0)
    add_signed_soa(message)
    add_nsec3param(message, 1, 0, 0, 'wild')
    host_hash = nsec3_hash('b.example.', 'wild')
    wildcard_hash = nsec3_hash('*.example.', 'wild')
    add_nsec3(message, nsec3_owner(ZONE, 'wild'), nsec3_hash(ZONE, 'wild'), 1, 0, 0, 'wild', wildcard_hash, [6, 50, 51])
    add_nsec3(message, nsec3_owner('*.example.', 'wild'), wildcard_hash, 1, 0, 0, 'wild', host_hash, [46, 50])

    result = verify(message, 'b.example.', Resolv::DNS::Resource::IN::A)
    assert_equal :nodata, result.status
    assert_predicate result, :proven?
    assert_predicate result, :wildcard?
  end

  def test_wildcard_answer
    message = negative_message('host.example.', Resolv::DNS::Resource::IN::A, 0)
    answer = Resolv::DNS::Resource::IN::A.new('192.0.2.1')
    add_signed(message, :answer, 'host.example.', TTL, answer, labels: 1, owner_override: '*.example.')

    result = verify(message, 'host.example.', Resolv::DNS::Resource::IN::A)
    assert_equal :wildcard_match, result.status
    assert_predicate result, :proven?
    assert_predicate result, :wildcard?
  end

  private

  def verify(message, name, type)
    Resolv::DNS::Resource::DNSSEC.verify_negative_response(
      message.encode, name, type, { ZONE => @dnskey }
    )
  end

  def negative_message(name, type, rcode)
    message = Resolv::DNS::Message.new(0)
    message.qr = 1
    message.aa = 1
    message.rcode = rcode
    message.add_question(name, type)
    message
  end

  def add_signed_soa(message)
    soa = Resolv::DNS::Resource::IN::SOA.new(
      Resolv::DNS::Name.create('ns.example.'),
      Resolv::DNS::Name.create('admin.example.'),
      1, 1, 1, 1, 1
    )
    add_signed(message, :authority, ZONE, TTL, soa)
  end

  def add_nsec(message, owner, next_name, types, key = @key, dnskey = @dnskey)
    record = Resolv::DNS::Resource::IN::NSEC.new(Resolv::DNS::Name.create(next_name), types)
    add_signed(message, :authority, owner, TTL, record, key: key, dnskey: dnskey)
  end

  def add_nsec3param(message, algorithm, flags, iterations, salt)
    record = Resolv::DNS::Resource::IN::NSEC3PARAM.new(algorithm, flags, iterations, salt)
    add_signed(message, :authority, ZONE, TTL, record)
  end

  def add_nsec3(message, owner, owner_hash, algorithm, flags, iterations, salt, next_hash, types)
    record = Resolv::DNS::Resource::IN::NSEC3.new(
      algorithm, flags, iterations, salt, next_hash, types
    )
    add_signed(message, :authority, owner, TTL, record)
  end

  def add_signed(message, section, owner, ttl, record, key: @key, dnskey: @dnskey,
                 labels: nil, owner_override: nil)
    owner = Resolv::DNS::Name.create(owner)
    signature_owner = Resolv::DNS::Name.create(owner_override || owner)
    type = record.class::TypeValue
    rrset = [canonical_rr(owner, ttl, record)]
    signature = sign(key, dnskey, signature_owner, type, labels || signature_owner.length, ttl, rrset)
    message.public_send(section == :answer ? :add_answer : :add_authority, owner, ttl, record)
    message.public_send(section == :answer ? :add_answer : :add_authority, signature_owner, ttl, signature)
  end

  def tamper_last_rrsig(message)
    name, ttl, signature = message.authority.last
    signature.signature[-1] = (signature.signature.getbyte(-1) ^ 1).chr
    message.authority[-1] = [name, ttl, signature]
  end

  def canonical_rr(owner, ttl, record)
    Resolv::DNS::Resource::DNSSEC.canonical_rr(owner, record.class, ttl, record)
  end

  def sign(key, dnskey, owner, type, labels, ttl, rrset)
    expiration = @now + 3600
    inception = @now - 3600
    wire = [type, dnskey.algorithm, labels, ttl, expiration, inception,
            Resolv::DNS::Resource::DNSSEC.key_tag(dnskey)].pack('nCCNNNn') +
           Resolv::DNS::Resource::DNSSEC.canonical_name(ZONE) + rrset.sort.join
    Resolv::DNS::Resource::IN::RRSIG.new(
      type, dnskey.algorithm, labels, ttl, expiration, inception,
      Resolv::DNS::Resource::DNSSEC.key_tag(dnskey), ZONE,
      key.sign('sha256', wire)
    )
  end

  def nsec3_hash(name, salt)
    Resolv::DNS::Resource::DNSSEC.nsec3_hash(name, 1, 0, salt)
  end

  def nsec3_owner(name, salt)
    Resolv::DNS::Resource::DNSSEC.nsec3_owner(name, ZONE, 1, 0, salt)
  end

  def owner_for_hash(hash, zone)
    label = Resolv::DNS::Label::Str.new(Resolv::DNS::Resource::DNSSEC.base32hex_encode(hash).upcase)
    Resolv::DNS::Name.new([label] + Resolv::DNS::Name.create(zone).to_a, true)
  end

  def zero_hash
    "\0".b * 20
  end

  def max_hash
    "\xff".b * 20
  end

  def rsa_blob(key)
    asn1 = OpenSSL::ASN1.decode(key.public_key.to_der)
    rsa = OpenSSL::ASN1.decode(asn1.value[1].value)
    modulus = rsa.value[0].value.to_s(2)
    exponent = rsa.value[1].value.to_s(2)
    [exponent.bytesize].pack('C') + exponent + modulus
  end
end
