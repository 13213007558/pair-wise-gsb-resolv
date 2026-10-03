# frozen_string_literal: false
require 'test/unit'
require 'resolv'
require 'socket'

class TestResolvTSIG < Test::Unit::TestCase
  TSIG = Resolv::DNS::TSIG
  Name = Resolv::DNS::Name
  Message = Resolv::DNS::Message
  Resource = Resolv::DNS::Resource

  SECRET = "0123456789abcdef0123456789abcdef".b
  KEY_NAME = 'tsig-key.example.'
  FIXED_TIME = 1_700_000_000
  FUDGE = 300

  # Wire format vectors produced with dnspython 2.8, an independent
  # RFC 8945 implementation, using SECRET and the clock frozen at
  # FIXED_TIME.  The chain is a signed AXFR request, a signed first
  # response, an unsigned middle response, and a signed final response.
  VECTOR_QUERY = '123401000001000000000001076578616d706c6503636f6d0000010001' \
                 '08747369672d6b6579076578616d706c650000fa00ff00000000003d0b686d61632d' \
                 '7368613235360000006553f100012c00204e8ffef9b90b5a27048e101b5da1728d7a' \
                 '82b5e95a95d107ce0a374ce73db685123400000000'
  VECTOR_REQUEST = '222200000001000000000001076578616d706c6503636f6d0000fc0001' \
                   '08747369672d6b6579076578616d706c650000fa00ff00000000003d0b686d61632d' \
                   '7368613235360000006553f100012c00207510105ba62bee57a9b6922e336a17662e' \
                   '2741d1fe3045d75f3ec1837c31b55a222200000000'
  VECTOR_REQUEST_MAC = '7510105ba62bee57a9b6922e336a17662e2741d1fe3045d75f3ec1837c31b55a'
  VECTOR_RESPONSE_1 = '222284000001000100000001076578616d706c6503636f6d0000fc0001c00c0006' \
                      '00010000012c0027036e7331c00c0a686f73746d6173746572c00c78c3d58500001c20' \
                      '00000e10001275000000012c08747369672d6b6579076578616d706c650000fa00ff00' \
                      '000000003d0b686d61632d7368613235360000006553f100012c0020ef2bd626bafb93' \
                      '0e15f39217af398b9dde0475ab3ad28d091ddffaccfb107766222200000000'
  VECTOR_RESPONSE_2 = '222284000001000100000000076578616d706c6503636f6d0000fc000103777777c0' \
                      '0c000100010000012c0004c0000201'
  VECTOR_RESPONSE_3 = '222284000001000100000001076578616d706c6503636f6d0000fc0001c00c0006' \
                      '00010000012c0027036e7331c00c0a686f73746d6173746572c00c78c3d58500001c20' \
                      '00000e10001275000000012c08747369672d6b6579076578616d706c650000fa00ff00' \
                      '000000003d0b686d61632d7368613235360000006553f100012c0020d40914bfffcaec' \
                      'f821044c005e44a45d3f8af4b630f1cc1bd3592232726ca466222200000000'

  def setup
    @key = TSIG::Key.new(KEY_NAME, SECRET)
    @clock = -> { FIXED_TIME }
  end

  def hex(string)
    [string].pack('H*')
  end

  def new_context(**options)
    TSIG::Context.new(@key, time_source: @clock, **options)
  end

  def query_message(id, name = 'example.com', typeclass = Resource::IN::A)
    message = Message.new(id)
    message.rd = 1
    message.add_question(name, typeclass)
    message
  end

  def axfr_type
    self.class.axfr_type
  end

  def self.axfr_type
    @axfr_type ||= Resource::Generic.create(252, Resource::IN::ClassValue)
  end

  def soa_record
    Resource::IN::SOA.new(Name.create('ns1.example.com.'),
                          Name.create('hostmaster.example.com.'),
                          2026100101, 7200, 3600, 1209600, 300)
  end

  def response_message(id, answers)
    message = Message.new(id)
    message.qr = 1
    message.aa = 1
    message.add_question('example.com', axfr_type)
    answers.each {|name, ttl, data| message.add_answer(name, ttl, data) }
    message
  end

  def test_rfc4231_hmac_sha256_vectors
    vectors = [
      ["\x0b".b * 20, 'Hi There',
       'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'],
      ['Jefe', 'what do ya want for nothing?',
       '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'],
      ["\xaa".b * 131, 'Test Using Larger Than Block-Size Key - Hash Key First',
       '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54'],
      ["\xaa".b * 131, "\xdd".b * 50,
       '124c7d2385aa1743aaad12204e3464f06305fd1a6d291250fa564dceffab0c8a'],
    ]
    vectors.each do |key, data, expected|
      assert_equal hex(expected), TSIG.hmac_sha256(key, data)
    end
  end

  def test_sign_matches_reference_vector
    wire = TSIG.sign(query_message(0x1234), @key, time: FIXED_TIME)
    assert_equal hex(VECTOR_QUERY), wire
  end

  def test_verify_reference_vector
    message = TSIG.verify(hex(VECTOR_QUERY), @key, time: FIXED_TIME)
    assert_equal 0x1234, message.id
    name, typeclass = message.question.first
    assert_equal Name.create('example.com.'), name
    assert_equal Resource::IN::A, typeclass
  end

  def test_verify_uses_original_id_when_message_id_was_rewritten
    wire = hex(VECTOR_QUERY)
    wire[0, 2] = [0xbeef].pack('n')
    message = TSIG.verify(wire, @key, time: FIXED_TIME)
    assert_equal 0xbeef, message.id
  end

  def test_verify_rejects_tampered_message
    wire = hex(VECTOR_QUERY)
    # flip a bit of the question type; the message stays parseable
    wire.setbyte(26, wire.getbyte(26) ^ 0x01)
    assert_raise(TSIG::BadSignatureError) {
      TSIG.verify(wire, @key, time: FIXED_TIME)
    }
  end

  def test_verify_rejects_unsigned_message
    wire = query_message(0x1234).encode
    assert_raise(TSIG::NotSignedError) { TSIG.verify(wire, @key) }
    context = new_context
    assert_raise(TSIG::NotSignedError) { context.verify(wire) }
  end

  def test_explicit_key_selection_from_keyring
    other = TSIG::Key.new('other-key.example.', 'another secret')
    ring = TSIG::KeyRing.new([other, @key])
    message = TSIG.verify(hex(VECTOR_QUERY), ring, time: FIXED_TIME)
    assert_equal 0x1234, message.id

    ring_without_key = TSIG::KeyRing.new([other])
    assert_raise(TSIG::UnknownKeyError) {
      TSIG.verify(hex(VECTOR_QUERY), ring_without_key, time: FIXED_TIME)
    }
    assert_raise(TSIG::UnknownKeyError) { ring_without_key.fetch(KEY_NAME) }
    assert_same @key, ring.fetch(KEY_NAME.sub(/\.$/, ''))
  end

  def test_unsupported_algorithm
    assert_raise(TSIG::UnsupportedAlgorithmError) {
      TSIG::Key.new(KEY_NAME, SECRET, algorithm: 'hmac-md5')
    }
    wire = TSIG.append_rr(query_message(0x1234).encode,
                          tsig_rr(algorithm: 'hmac-md5.sig-alg.reg.int'))
    assert_raise(TSIG::UnsupportedAlgorithmError) {
      TSIG.verify(wire, @key, time: FIXED_TIME)
    }
  end

  def test_time_signed_must_be_within_fudge
    wire = hex(VECTOR_QUERY)
    TSIG.verify(wire, @key, time: FIXED_TIME + FUDGE)
    TSIG.verify(wire, @key, time: FIXED_TIME - FUDGE)
    assert_raise(TSIG::BadTimeError) {
      TSIG.verify(wire, @key, time: FIXED_TIME + FUDGE + 1)
    }
    assert_raise(TSIG::BadTimeError) {
      TSIG.verify(wire, @key, time: FIXED_TIME - FUDGE - 1)
    }
  end

  def test_error_field_is_authenticated_and_reported
    context = new_context
    wire = context.sign(query_message(0x1234), error: 17)
    error = assert_raise(TSIG::RemoteError) {
      TSIG.verify(wire, @key, time: FIXED_TIME)
    }
    assert_include error.message, 'BADKEY'

    tampered = context.sign(query_message(0x1234))
    # the error field sits 6 octets before the end of the TSIG rdata
    tampered.setbyte(tampered.bytesize - 6, 17)
    assert_raise(TSIG::BadSignatureError) {
      TSIG.verify(tampered, @key, time: FIXED_TIME)
    }
  end

  def test_multiple_tsig_records_rejected
    wire = TSIG.sign(query_message(0x1234), @key, time: FIXED_TIME)
    extra = TSIG.encode_rr(@key, FIXED_TIME, FUDGE, 'm'.b * 32, 0x1234, 0, +'')
    assert_raise(TSIG::VerificationError) {
      TSIG.verify(TSIG.append_rr(wire, extra), @key, time: FIXED_TIME)
    }
  end

  def test_tsig_record_must_be_last
    wire = query_message(0x1234).encode
    rr = TSIG.encode_rr(@key, FIXED_TIME, FUDGE, 'm'.b * 32, 0x1234, 0, +'')
    a_rr = TSIG.canonical_name_wire('example.com.') +
           [Resource::IN::A::TypeValue, Resource::IN::A::ClassValue, 300, 4].pack('nnNn') +
           "\xc0\x00\x02\x01".b
    wire[10, 2] = [2].pack('n')
    wire << rr << a_rr
    assert_raise(TSIG::VerificationError) {
      TSIG.verify(wire, @key, time: FIXED_TIME)
    }
  end

  def tsig_rr(algorithm: 'hmac-sha256', mac: 'x'.b * 32, time: FIXED_TIME, fudge: FUDGE, error: 0, other: +'')
    rdata = TSIG.canonical_name_wire(algorithm)
    rdata << [(time >> 32) & 0xffff, time & 0xffffffff, fudge, mac.bytesize].pack('nNnn')
    rdata << mac
    rdata << [0x1234, error, other.bytesize].pack('nnn')
    rdata << other
    rr = TSIG.canonical_name_wire(KEY_NAME)
    rr << [TSIG::TypeValue, TSIG::ClassValue, 0, rdata.bytesize].pack('nnNn')
    rr << rdata
  end

  def test_truncated_mac
    context = new_context(mac_length: 16)
    wire = context.sign(query_message(0x1234))
    record, = TSIG.extract(wire)
    assert_equal 16, record.mac.bytesize
    full = TSIG.extract(TSIG.sign(query_message(0x1234), @key, time: FIXED_TIME))[0].mac
    assert_equal full.byteslice(0, 16), record.mac
    message = TSIG.verify(wire, @key, time: FIXED_TIME)
    assert_equal 0x1234, message.id
  end

  def test_mac_length_must_be_a_canonical_length
    [15, 33].each do |length|
      assert_raise(ArgumentError) {
        new_context(mac_length: length).sign(query_message(0x1234))
      }
    end
    [16, 32].each {|length| new_context(mac_length: length).sign(query_message(0x1234)) }

    # a forged record with a non-canonical MAC size is rejected before
    # the MAC itself is compared
    [15, 33].each do |length|
      wire = TSIG.append_rr(query_message(0x1234).encode, tsig_rr(mac: 'x'.b * length))
      assert_raise(TSIG::BadMacLengthError) {
        TSIG.verify(wire, @key, time: FIXED_TIME)
      }
    end
  end

  def test_chain_verification_matches_reference_vectors
    context = new_context
    assert_equal 0x2222, context.verify(hex(VECTOR_REQUEST)).id
    assert_equal 0x2222, context.verify(hex(VECTOR_RESPONSE_1)).id
    assert_equal 0x2222, context.verify(hex(VECTOR_RESPONSE_2)).id
    assert_equal 0x2222, context.verify(hex(VECTOR_RESPONSE_3)).id
  end

  def test_chain_signing_matches_reference_vectors
    client = new_context
    query = Message.new(0x2222)
    query.add_question('example.com', axfr_type)
    assert_equal hex(VECTOR_REQUEST), client.sign(query)

    server = new_context(request_mac: hex(VECTOR_REQUEST_MAC))
    assert_equal hex(VECTOR_RESPONSE_1),
                 server.sign(response_message(0x2222, [['example.com', 300, soa_record]]))
    assert_equal hex(VECTOR_RESPONSE_2),
                 server.sign(response_message(0x2222, [['www.example.com', 300, Resource::IN::A.new('192.0.2.1')]]),
                             tsig: false)
    assert_equal hex(VECTOR_RESPONSE_3),
                 server.sign(response_message(0x2222, [['example.com', 300, soa_record]]))
  end

  def test_one_shot_response_verification_uses_request_mac
    message = TSIG.verify(hex(VECTOR_RESPONSE_1), @key,
                          request_mac: hex(VECTOR_REQUEST_MAC),
                          time: FIXED_TIME)
    assert_equal 0x2222, message.id
  end

  def test_tampered_unsigned_middle_message_breaks_the_chain
    context = new_context
    context.verify(hex(VECTOR_REQUEST))
    context.verify(hex(VECTOR_RESPONSE_1))
    tampered = hex(VECTOR_RESPONSE_2)
    tampered.setbyte(tampered.bytesize - 1, tampered.getbyte(tampered.bytesize - 1) ^ 0x01)
    context.verify(tampered)
    assert_raise(TSIG::BadSignatureError) {
      context.verify(hex(VECTOR_RESPONSE_3))
    }
  end

  def test_per_message_verification_cannot_replace_chain_verification
    # The final message of the chain cannot be authenticated on its
    # own: its MAC covers the previous MAC and the unsigned middle
    # message, so a verifier without the conversation state must fail
    # even when every input is authentic.
    assert_raise(TSIG::BadSignatureError) {
      TSIG.verify(hex(VECTOR_RESPONSE_3), @key, time: FIXED_TIME)
    }
    assert_raise(TSIG::BadSignatureError) {
      TSIG.verify(hex(VECTOR_RESPONSE_3), @key,
                  request_mac: hex(VECTOR_REQUEST_MAC),
                  time: FIXED_TIME)
    }
  end

  def test_first_message_of_a_context_must_be_signed
    context = new_context
    assert_raise(TSIG::Error) { context.sign(query_message(0x1234), tsig: false) }
  end

  def test_concurrent_transfers_do_not_share_authentication_contexts
    client_a, server_a = new_context, new_context
    client_b, server_b = new_context, new_context

    request_a = client_a.sign(query_message(0xa001))
    request_b = client_b.sign(query_message(0xb002))
    server_a.verify(request_a)
    server_b.verify(request_b)

    answers_a = [['www.example.com', 300, Resource::IN::A.new('192.0.2.1')]]
    answers_b = [['www.example.com', 300, Resource::IN::A.new('192.0.2.2')]]
    response_a1 = server_a.sign(response_message(0xa001, answers_a))
    response_b1 = server_b.sign(response_message(0xb002, answers_b))
    response_a2 = server_a.sign(response_message(0xa001, answers_a), tsig: false)
    response_b2 = server_b.sign(response_message(0xb002, answers_b), tsig: false)
    response_a3 = server_a.sign(response_message(0xa001, answers_a))
    response_b3 = server_b.sign(response_message(0xb002, answers_b))

    # interleaved verification: each transfer authenticates with its
    # own context even though the messages alternate
    assert_equal 0xa001, client_a.verify(response_a1).id
    assert_equal 0xb002, client_b.verify(response_b1).id
    client_a.verify(response_a2)
    client_b.verify(response_b2)
    assert_equal 0xa001, client_a.verify(response_a3).id
    assert_equal 0xb002, client_b.verify(response_b3).id

    # a context must not authenticate the other transfer's messages
    assert_raise(TSIG::BadSignatureError) { server_a.verify(request_b) }
    assert_raise(TSIG::BadSignatureError) { client_a.verify(response_b1) }

    # a single context cannot serve two interleaved transfers either:
    # the second transfer's first message breaks the chain
    shared = new_context
    shared.verify(request_a)
    assert_raise(TSIG::BadSignatureError) { shared.verify(request_b) }
  end

  def test_local_tcp_transfer
    records = run_local_transfer
    assert_equal [soa_record, Resource::IN::A.new('192.0.2.1'),
                  Resource::IN::TXT.new('zone data'), soa_record],
                 records
  end

  def test_local_tcp_transfer_detects_tampered_unsigned_message
    assert_raise(TSIG::BadSignatureError) {
      run_local_transfer(tamper_frame: 1)
    }
  end

  def test_concurrent_tcp_transfers
    results = [nil, nil]
    threads = 2.times.map {|i|
      Thread.new { results[i] = run_local_transfer }
    }
    threads.each(&:join)
    results.each {|records| assert_equal 4, records.length }
  end

  # Runs a zone-transfer-style exchange over a loopback TCP
  # connection: a signed query, then a signed, an unsigned, and a
  # signed response message.  Returns the answer records the client
  # authenticated.  With +tamper_frame+ set, the client flips one byte
  # of that frame before verifying it.
  def run_local_transfer(tamper_frame: nil)
    zone = [
      [['example.com', 300, soa_record]],
      [['www.example.com', 300, Resource::IN::A.new('192.0.2.1')],
       ['example.com', 300, Resource::IN::TXT.new('zone data')]],
      [['example.com', 300, soa_record]],
    ]
    signed = [true, false, true]
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    server_context = TSIG::Context.new(@key)
    server_thread = Thread.new do
      socket = server.accept
      begin
        length = socket.read(2).unpack('n')[0]
        query = server_context.verify(socket.read(length))
        zone.each_with_index do |answers, i|
          frame = server_context.sign(response_message(query.id, answers),
                                      tsig: signed[i])
          socket.write([frame.bytesize].pack('n'), frame)
        end
      ensure
        socket.close
      end
    end
    records = []
    client_context = TSIG::Context.new(@key)
    TCPSocket.open('127.0.0.1', port) do |socket|
      query = Message.new(0x2222)
      query.add_question('example.com', axfr_type)
      frame = client_context.sign(query)
      socket.write([frame.bytesize].pack('n'), frame)
      zone.length.times do |i|
        length = socket.read(2).unpack('n')[0]
        frame = socket.read(length)
        if i == tamper_frame
          frame.setbyte(frame.bytesize - 1, frame.getbyte(frame.bytesize - 1) ^ 0x01)
        end
        message = client_context.verify(frame)
        message.each_answer {|_name, _ttl, data| records << data }
      end
    end
    server_thread.join
    server.close
    records
  end

  def test_key_material_never_appears_in_inspect_or_errors
    assert_not_include @key.inspect, SECRET
    errors = []
    begin
      TSIG::KeyRing.new([@key]).fetch('no-such-key.example.')
    rescue TSIG::Error => error
      errors << error
    end
    begin
      TSIG::Key.new(KEY_NAME, SECRET, algorithm: 'hmac-md5')
    rescue TSIG::Error => error
      errors << error
    end
    begin
      TSIG.verify(hex(VECTOR_RESPONSE_3), @key, time: FIXED_TIME)
    rescue TSIG::Error => error
      errors << error
    end
    begin
      TSIG.verify(hex(VECTOR_QUERY), @key, time: FIXED_TIME + 10_000)
    rescue TSIG::Error => error
      errors << error
    end
    assert_equal 4, errors.length
    errors.each {|error| assert_not_include error.message, SECRET }
  end
end
