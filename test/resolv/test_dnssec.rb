# frozen_string_literal: true

require "resolv"
require "openssl"
require "digest"

# Offline DNSSEC denial-of-existence tests.  All fixtures are generated
# locally with OpenSSL (no network, no online resolver, no trust-anchor
# downloads).
class TestDNSSEC < Test::Unit::TestCase
  IN = Resolv::DNS::Resource::IN
  DNSSEC = Resolv::DNS::DNSSEC
  Name = Resolv::DNS::Name

  INCEPTION = Time.utc(2026, 1, 1).to_i
  EXPIRATION = Time.utc(2027, 1, 1).to_i
  NOW = Time.utc(2026, 6, 1)

  # Signs RRsets for one zone with a freshly generated key.
  class Signer
    attr_reader :zone, :algorithm, :dnskey

    def initialize(zone, algorithm: DNSSEC::ALGORITHM_ECDSAP256SHA256)
      @zone = zone
      @algorithm = algorithm
      case algorithm
      when DNSSEC::ALGORITHM_RSASHA256
        @key = OpenSSL::PKey::RSA.generate(2048)
        e = @key.e.to_s(2)
        m = @key.n.to_s(2)
        key_bytes = [e.bytesize].pack("C") + e + m
      when DNSSEC::ALGORITHM_ECDSAP256SHA256
        @key = OpenSSL::PKey::EC.generate("prime256v1")
        key_bytes = @key.public_key.to_octet_string(:uncompressed)[1..-1]
      when DNSSEC::ALGORITHM_ED25519
        @key = OpenSSL::PKey.generate_key("ED25519")
        key_bytes = @key.raw_public_key
      else
        raise "unsupported test algorithm: #{algorithm}"
      end
      @dnskey = IN::DNSKEY.new(257, 3, algorithm, key_bytes)
    end

    def sign(data)
      case algorithm
      when DNSSEC::ALGORITHM_RSASHA256
        @key.sign(OpenSSL::Digest::SHA256.new, data)
      when DNSSEC::ALGORITHM_ECDSAP256SHA256
        der = @key.sign(OpenSSL::Digest::SHA256.new, data)
        r, s = OpenSSL::ASN1.decode(der).value.map { |v| v.value.to_s(2) }
        r.rjust(32, "\0") + s.rjust(32, "\0")
      when DNSSEC::ALGORITHM_ED25519
        @key.sign(nil, data)
      end
    end

    def make_rrsig(name, type_value, rrs, ttl: 3600,
                   inception: INCEPTION, expiration: EXPIRATION)
      labels = Name.create(name).to_a.length
      template = IN::RRSIG.new(type_value, algorithm, labels, ttl,
                               expiration, inception, dnskey.key_tag, zone, "")
      data = DNSSEC.rrsig_signed_data(name, type_value, rrs, template)
      IN::RRSIG.new(type_value, algorithm, labels, ttl, expiration, inception,
                    dnskey.key_tag, zone, sign(data))
    end

    # Returns message entries [name, ttl, rr] for +rr+ plus its RRSIG.
    def signed(name, ttl, rr, **kw)
      [[name, ttl, rr], [name, ttl, make_rrsig(name, rr.class::TypeValue, [rr], ttl: ttl, **kw)]]
    end
  end

  def setup
    @signer = Signer.new("example.")
  end

  def dns_name(s)
    Name.create(s)
  end

  def message(rcode: 3, answer: [], authority: [], additional: [])
    msg = Resolv::DNS::Message.new(0)
    msg.qr = 1
    msg.aa = 1
    msg.rcode = rcode
    answer.each { |n, t, r| msg.add_answer(n, t, r) }
    authority.each { |n, t, r| msg.add_authority(n, t, r) }
    additional.each { |n, t, r| msg.add_additional(n, t, r) }
    msg
  end

  def verify(name:, type: IN::A, message:, anchors: nil, now: NOW)
    anchors ||= [[@signer.zone, @signer.dnskey]]
    DNSSEC.verify_denial(name: name, type: type, message: message,
                         trust_anchors: anchors, now: now)
  end

  def h160(bin)
    bin.unpack1("H*").to_i(16)
  end

  def to_h160(int)
    [(int % (1 << 160)).to_s(16).rjust(40, "0")].pack("H*")
  end

  def nsec3_owner(hash_bin, zone = "example.")
    "#{DNSSEC.base32hex_encode(hash_bin)}.#{zone}"
  end

  # Builds a signed NSEC3 record set proving NXDOMAIN for +qname+ with
  # closest encloser +zone+.  Yields the three records so tests can
  # tweak flags or parameters.
  def nsec3_nxdomain_records(signer, qname, zone: "example.", salt: "salt",
                             iterations: 2)
    ce_hash = DNSSEC.nsec3_hash(dns_name(zone), salt, iterations)
    nc_hash = DNSSEC.nsec3_hash(dns_name(qname), salt, iterations)
    w_hash = DNSSEC.nsec3_hash(dns_name("*.#{zone}"), salt, iterations)
    rec_ce = IN::NSEC3.new(1, 0, iterations, salt, to_h160(h160(ce_hash) + 1),
                           [IN::SOA, IN::NS, IN::DNSKEY])
    rec_nc = IN::NSEC3.new(1, 0, iterations, salt, to_h160(h160(nc_hash) + 1),
                           [IN::A])
    rec_w = IN::NSEC3.new(1, 0, iterations, salt, to_h160(h160(w_hash) + 1),
                          [IN::A])
    yield rec_ce, rec_nc, rec_w if block_given?
    entries = []
    entries.concat(signer.signed(nsec3_owner(ce_hash, zone), 3600, rec_ce))
    entries.concat(signer.signed(nsec3_owner(to_h160(h160(nc_hash) - 1), zone), 3600, rec_nc))
    entries.concat(signer.signed(nsec3_owner(to_h160(h160(w_hash) - 1), zone), 3600, rec_w))
    entries
  end

  def test_record_roundtrip
    records = [
      ["example.", 3600, IN::DNSKEY.new(257, 3, 13, "key-bytes")],
      ["example.", 3600, IN::DS.new(12345, 13, 2, "digest-bytes")],
      ["example.", 3600, IN::RRSIG.new(IN::A::TypeValue, 13, 2, 3600,
                                        EXPIRATION, INCEPTION, 12345,
                                        "example.", "signature")],
      ["example.", 3600, IN::NSEC.new("a.example.", [IN::A, IN::RRSIG, IN::NSEC])],
      ["abc.example.", 3600, IN::NSEC3.new(1, 1, 10, "salt", "next-hash",
                                           [IN::A, IN::DS, 32768])],
    ]
    msg = message(rcode: 0, authority: records)
    decoded = Resolv::DNS::Message.decode(msg.encode)
    decoded_records = []
    decoded.each_authority { |n, t, r| decoded_records << [n.to_s + ".", t, r] }
    assert_equal records.map { |n, t, r| [n, t, r] }.length, decoded_records.length
    records.zip(decoded_records) do |(n, ttl, rr), (dn, dttl, drr)|
      assert_equal dns_name(n), dns_name(dn)
      assert_equal ttl, dttl
      assert_equal rr, drr
    end
  end

  def test_nsec_nxdomain
    nsec = IN::NSEC.new("x.example.", [IN::SOA, IN::NS, IN::RRSIG, IN::NSEC])
    msg = message(authority: @signer.signed("example.", 3600, nsec))
    result = verify(name: "nx.example.", message: msg)
    assert_equal :nxdomain, result.proof
    assert_predicate result, :proved?
    assert_equal true, result.signatures_valid?
  end

  def test_nsec_nxdomain_wraparound
    apex = IN::NSEC.new("a.example.", [IN::SOA, IN::NS, IN::RRSIG, IN::NSEC])
    wrap = IN::NSEC.new("example.", [IN::A, IN::RRSIG, IN::NSEC])
    msg = message(authority: @signer.signed("example.", 3600, apex) +
                             @signer.signed("zzz.example.", 3600, wrap))
    result = verify(name: "zzzz.example.", message: msg)
    assert_equal :nxdomain, result.proof
    assert_predicate result, :proved?
  end

  def test_nsec_nodata
    nsec = IN::NSEC.new("example.", [IN::A, IN::RRSIG, IN::NSEC])
    msg = message(rcode: 0, authority: @signer.signed("www.example.", 3600, nsec))
    result = verify(name: "www.example.", type: IN::AAAA, message: msg)
    assert_equal :nodata, result.proof
    assert_predicate result, :proved?
  end

  def test_nsec_wildcard_match
    nsec1 = IN::NSEC.new("*.example.", [IN::SOA, IN::NS, IN::RRSIG, IN::NSEC])
    nsec2 = IN::NSEC.new("z.example.", [IN::A, IN::RRSIG, IN::NSEC])
    msg = message(authority: @signer.signed("example.", 3600, nsec1) +
                             @signer.signed("*.example.", 3600, nsec2))
    result = verify(name: "foo.example.", message: msg)
    assert_equal :wildcard_match, result.proof
    assert_predicate result, :proved?
  end

  def test_nsec_wildcard_nodata
    nsec1 = IN::NSEC.new("*.example.", [IN::SOA, IN::NS, IN::RRSIG, IN::NSEC])
    nsec2 = IN::NSEC.new("z.example.", [IN::TXT, IN::RRSIG, IN::NSEC])
    msg = message(rcode: 0, authority: @signer.signed("example.", 3600, nsec1) +
                                      @signer.signed("*.example.", 3600, nsec2))
    result = verify(name: "foo.example.", type: IN::AAAA, message: msg)
    assert_equal :nodata, result.proof
    assert_predicate result, :proved?
  end

  # Counterexample: the signature is perfectly valid but the NSEC interval
  # is unrelated to the query, so nothing is proven.
  def test_nsec_valid_signature_irrelevant_interval
    nsec = IN::NSEC.new("b.example.", [IN::A, IN::RRSIG, IN::NSEC])
    msg = message(authority: @signer.signed("a.example.", 3600, nsec))
    result = verify(name: "zz.example.", message: msg)
    assert_equal :unprovable, result.proof
    assert_not_predicate result, :proved?
    assert_equal true, result.signatures_valid?
  end

  def test_nsec_bad_signature
    nsec = IN::NSEC.new("x.example.", [IN::SOA, IN::NS, IN::RRSIG, IN::NSEC])
    rrsig = @signer.make_rrsig("example.", IN::NSEC::TypeValue, [nsec])
    bad_sig = rrsig.signature.dup
    bad_sig.setbyte(0, bad_sig.getbyte(0) ^ 1)
    bad = IN::RRSIG.new(rrsig.type_covered, rrsig.algorithm, rrsig.labels,
                        rrsig.original_ttl, rrsig.expiration, rrsig.inception,
                        rrsig.key_tag, rrsig.signer, bad_sig)
    msg = message(authority: [["example.", 3600, nsec], ["example.", 3600, bad]])
    result = verify(name: "nx.example.", message: msg)
    assert_equal :unprovable, result.proof
    assert_equal false, result.signatures_valid?
    assert_equal :invalid, result.signatures.first.status
  end

  def test_nsec_expired_signature
    nsec = IN::NSEC.new("x.example.", [IN::SOA, IN::NS, IN::RRSIG, IN::NSEC])
    entries = @signer.signed("example.", 3600, nsec,
                             inception: Time.utc(2020, 1, 1).to_i,
                             expiration: Time.utc(2021, 1, 1).to_i)
    msg = message(authority: entries)
    result = verify(name: "nx.example.", message: msg)
    assert_equal :unprovable, result.proof
    assert_equal false, result.signatures_valid?
    assert_equal :outside_validity_period, result.signatures.first.status
  end

  def test_nsec_untrusted_key
    other = Signer.new("other.example.")
    nsec = IN::NSEC.new("x.example.", [IN::SOA, IN::NS, IN::RRSIG, IN::NSEC])
    msg = message(authority: other.signed("example.", 3600, nsec))
    result = verify(name: "nx.example.", message: msg)
    assert_equal :unprovable, result.proof
    assert_equal false, result.signatures_valid?
    assert_equal :no_trusted_key, result.signatures.first.status
  end

  # An empty NXDOMAIN answer with no NSEC/NSEC3 evidence proves nothing.
  def test_empty_answer_proves_nothing
    msg = message(rcode: 3)
    result = verify(name: "nx.example.", message: msg)
    assert_equal :unprovable, result.proof
    assert_not_predicate result, :proved?
    assert_nil result.signatures_valid?
  end

  def test_nsec3_nxdomain
    entries = nsec3_nxdomain_records(@signer, "nx.example.")
    msg = message(authority: entries)
    result = verify(name: "nx.example.", message: msg)
    assert_equal :nxdomain, result.proof
    assert_predicate result, :proved?
    assert_equal true, result.signatures_valid?
  end

  def test_nsec3_nxdomain_wraparound_cover
    salt = "salt"
    iterations = 2
    zone = "example."
    qname = "nx.example."
    ce_hash = DNSSEC.nsec3_hash(dns_name(zone), salt, iterations)
    nc_hash = DNSSEC.nsec3_hash(dns_name(qname), salt, iterations)
    w_hash = DNSSEC.nsec3_hash(dns_name("*.#{zone}"), salt, iterations)
    rec_ce = IN::NSEC3.new(1, 0, iterations, salt, to_h160(h160(ce_hash) + 1),
                           [IN::SOA, IN::NS])
    # Covering span wraps around the end of the hash ring: owner > next,
    # and the next-closer hash falls inside the wrapped span.
    rec_nc = IN::NSEC3.new(1, 0, iterations, salt, to_h160(h160(nc_hash) - 10),
                           [IN::A])
    rec_w = IN::NSEC3.new(1, 0, iterations, salt, to_h160(h160(w_hash) + 1),
                          [IN::A])
    entries = []
    entries.concat(@signer.signed(nsec3_owner(ce_hash, zone), 3600, rec_ce))
    entries.concat(@signer.signed(nsec3_owner(to_h160(h160(nc_hash) - 5), zone), 3600, rec_nc))
    entries.concat(@signer.signed(nsec3_owner(to_h160(h160(w_hash) - 1), zone), 3600, rec_w))
    msg = message(authority: entries)
    result = verify(name: qname, message: msg)
    assert_equal :nxdomain, result.proof
  end

  def test_nsec3_nodata
    salt = "salt"
    iterations = 2
    qhash = DNSSEC.nsec3_hash(dns_name("www.example."), salt, iterations)
    rec = IN::NSEC3.new(1, 0, iterations, salt, to_h160(h160(qhash) + 1),
                        [IN::A, IN::RRSIG])
    msg = message(rcode: 0,
                  authority: @signer.signed(nsec3_owner(qhash), 3600, rec))
    result = verify(name: "www.example.", type: IN::AAAA, message: msg)
    assert_equal :nodata, result.proof
    assert_predicate result, :proved?
  end

  def test_nsec3_opt_out_is_insecure_not_nxdomain
    entries = nsec3_nxdomain_records(@signer, "nx.example.") do |_ce, rec_nc, _w|
      rec_nc.instance_variable_set(:@flags, DNSSEC::NSEC3_FLAG_OPT_OUT)
    end
    msg = message(authority: entries)
    result = verify(name: "nx.example.", message: msg)
    assert_equal :insecure, result.proof
    assert_not_predicate result, :proved?
    assert_predicate result, :insecure?
  end

  # The closest-encloser match and the covering records use different
  # NSEC3 parameters, so no single consistent hash ring proves anything.
  def test_nsec3_inconsistent_parameters
    salt_a = "aaaa"
    salt_b = "bbbb"
    iterations = 2
    zone = "example."
    qname = "nx.example."
    ce_hash = DNSSEC.nsec3_hash(dns_name(zone), salt_a, iterations)
    nc_hash = DNSSEC.nsec3_hash(dns_name(qname), salt_b, iterations)
    w_hash = DNSSEC.nsec3_hash(dns_name("*.#{zone}"), salt_b, iterations)
    rec_ce = IN::NSEC3.new(1, 0, iterations, salt_a, to_h160(h160(ce_hash) + 1),
                           [IN::SOA, IN::NS])
    rec_nc = IN::NSEC3.new(1, 0, iterations, salt_b, to_h160(h160(nc_hash) + 1),
                           [IN::A])
    rec_w = IN::NSEC3.new(1, 0, iterations, salt_b, to_h160(h160(w_hash) + 1),
                          [IN::A])
    entries = []
    entries.concat(@signer.signed(nsec3_owner(ce_hash, zone), 3600, rec_ce))
    entries.concat(@signer.signed(nsec3_owner(to_h160(h160(nc_hash) - 1), zone), 3600, rec_nc))
    entries.concat(@signer.signed(nsec3_owner(to_h160(h160(w_hash) - 1), zone), 3600, rec_w))
    msg = message(authority: entries)
    result = verify(name: qname, message: msg)
    assert_equal :unprovable, result.proof
    assert_match(/inconsistent NSEC3 parameters/, result.reason)
    assert_equal true, result.signatures_valid?
  end

  def test_nsec3_wildcard_match
    salt = "salt"
    iterations = 2
    zone = "example."
    qname = "foo.example."
    ce_hash = DNSSEC.nsec3_hash(dns_name(zone), salt, iterations)
    nc_hash = DNSSEC.nsec3_hash(dns_name(qname), salt, iterations)
    w_hash = DNSSEC.nsec3_hash(dns_name("*.#{zone}"), salt, iterations)
    rec_ce = IN::NSEC3.new(1, 0, iterations, salt, to_h160(h160(ce_hash) + 1),
                           [IN::SOA, IN::NS])
    rec_nc = IN::NSEC3.new(1, 0, iterations, salt, to_h160(h160(nc_hash) + 1),
                           [IN::A])
    rec_w = IN::NSEC3.new(1, 0, iterations, salt, to_h160(h160(w_hash) + 1),
                          [IN::A])
    entries = []
    entries.concat(@signer.signed(nsec3_owner(ce_hash, zone), 3600, rec_ce))
    entries.concat(@signer.signed(nsec3_owner(to_h160(h160(nc_hash) - 1), zone), 3600, rec_nc))
    entries.concat(@signer.signed(nsec3_owner(w_hash, zone), 3600, rec_w))
    msg = message(authority: entries)
    result = verify(name: qname, message: msg)
    assert_equal :wildcard_match, result.proof
    assert_predicate result, :proved?
  end

  def test_rsa_sha256_signatures
    signer = Signer.new("example.", algorithm: DNSSEC::ALGORITHM_RSASHA256)
    nsec = IN::NSEC.new("x.example.", [IN::SOA, IN::NS, IN::RRSIG, IN::NSEC])
    msg = message(authority: signer.signed("example.", 3600, nsec))
    result = verify(name: "nx.example.", message: msg,
                    anchors: [[signer.zone, signer.dnskey]])
    assert_equal :nxdomain, result.proof
    assert_equal true, result.signatures_valid?
  end

  def test_ed25519_signatures
    signer = Signer.new("example.", algorithm: DNSSEC::ALGORITHM_ED25519)
    nsec = IN::NSEC.new("x.example.", [IN::SOA, IN::NS, IN::RRSIG, IN::NSEC])
    msg = message(authority: signer.signed("example.", 3600, nsec))
    result = verify(name: "nx.example.", message: msg,
                    anchors: [[signer.zone, signer.dnskey]])
    assert_equal :nxdomain, result.proof
    assert_equal true, result.signatures_valid?
  end

  def test_ds_trust_anchor
    ds = IN::DS.new(@signer.dnskey.key_tag, @signer.algorithm, 2,
                    Digest::SHA256.digest(
                      DNSSEC.canonical_name_wire(dns_name(@signer.zone)) +
                      DNSSEC.dnskey_rdata(@signer.dnskey)))
    nsec = IN::NSEC.new("x.example.", [IN::SOA, IN::NS, IN::RRSIG, IN::NSEC])
    msg = message(authority: @signer.signed("example.", 3600, nsec),
                  additional: @signer.signed("example.", 3600, @signer.dnskey))
    result = verify(name: "nx.example.", message: msg,
                    anchors: [[@signer.zone, ds]])
    assert_equal :nxdomain, result.proof
    assert_equal true, result.signatures_valid?
  end

  def test_nsec3_hash_rfc5155_vectors
    salt = ["aabbccdd"].pack("H*")
    assert_equal "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
                 DNSSEC.base32hex_encode(DNSSEC.nsec3_hash(dns_name("example."), salt, 12))
    assert_equal "35mthgpgcu1qg68fab165klnsnk3dpvl",
                 DNSSEC.base32hex_encode(DNSSEC.nsec3_hash(dns_name("a.example."), salt, 12))
    assert_equal "jhsv97rodsnhc4f1ke4jh23egaa5agvp",
                 DNSSEC.base32hex_encode(DNSSEC.nsec3_hash(dns_name("*.example."), salt, 12))
  end
end
