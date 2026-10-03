# frozen_string_literal: false
require 'test/unit'
require 'resolv'
require 'socket'
require 'timeout'

class TestResolvDNSTSIG < Test::Unit::TestCase
  FIXED_QUERY_MAC = "92bbf8876e33ee4c28b180f5a415865acc542b0f79df1c36c7aadc7eac181fcb"
  FIXED_RESPONSE_MAC = "619c64ebfbde10ee12c1222525ca949a71d18c7c517b448975c5d0813bae004b"

  def setup
    @key = Resolv::DNS::TSIG::Key.new("key.example.", "secret".b)
  end

  def test_single_request_and_response_protocol_vector
    query = unsigned_query(0x1234)
    signed_query = Resolv::DNS::TSIG.sign(@key, query, time: 1000)
    assert_equal(FIXED_QUERY_MAC, mac_of(signed_query).unpack1("H*"))
    assert_nothing_raised do
      Resolv::DNS::TSIG.verify(@key, signed_query, time: 1300)
    end

    response = unsigned_response(0x1234)
    signed_response = Resolv::DNS::TSIG.sign(
      @key,
      response,
      request_mac: mac_of(signed_query),
      time: 1001
    )
    assert_equal(FIXED_RESPONSE_MAC, mac_of(signed_response).unpack1("H*"))
    assert_nothing_raised do
      Resolv::DNS::TSIG.verify(
        @key,
        signed_response,
        request_mac: mac_of(signed_query),
        time: 1002
      )
    end
  end

  def test_original_message_id_is_part_of_mac
    signed = Resolv::DNS::TSIG.sign(@key, unsigned_query(0x1234), time: 1000)
    record = Resolv::DNS::TSIG.extract(signed)
    altered_record = Resolv::DNS::Resource::TSIG.new(
      record.algorithm,
      record.time_signed,
      record.fudge,
      record.mac,
      0x4321,
      record.error,
      record.other_data
    )
    message = Resolv::DNS::Message.decode(signed)
    message.additional[-1] = [@key.name, 0, altered_record]
    reencoded = message.encode
    assert_raise(Resolv::DNS::TSIG::BadSignature) do
      Resolv::DNS::TSIG.verify(@key, reencoded, original_id: 0x1234, time: 1000)
    end
  end

  def test_time_fudge_and_peer_error_enter_mac_input
    other_data = [1000].pack("N") + [300].pack("n")
    signed = Resolv::DNS::TSIG.sign(
      @key,
      unsigned_query(0x1111),
      time: 1000,
      fudge: 10,
      error: Resolv::DNS::RCode::BADTIME,
      other_data: other_data
    )
    record = Resolv::DNS::TSIG.extract(signed)
    assert_equal(10, record.fudge)
    assert_equal(Resolv::DNS::RCode::BADTIME, record.error)
    assert_equal(other_data, record.other_data)
    assert_raise(Resolv::DNS::TSIG::PeerError) do
      Resolv::DNS::TSIG.verify(@key, signed, time: 1000, fudge: 10)
    end

    assert_raise(Resolv::DNS::TSIG::PeerError) do
      Resolv::DNS::TSIG.verify(@key, signed, time: 1011, fudge: 10)
    end
  end

  def test_explicit_wrong_key_is_rejected
    wrong = Resolv::DNS::TSIG::Key.new("wrong.example.", "secret".b)
    signed = Resolv::DNS::TSIG.sign(@key, unsigned_query(0x2222), time: 1000)
    assert_raise(Resolv::DNS::TSIG::BadKey) do
      Resolv::DNS::TSIG.verify(wrong, signed, time: 1000)
    end
  end

  def test_base64_key
    decoded = Resolv::DNS::TSIG::Key.base64("key.example.", "c2VjcmV0")
    assert_equal(@key, decoded)
  end

  def test_truncated_mac_must_match_canonical_length
    signed = Resolv::DNS::TSIG.sign(@key, unsigned_query(0x3333), time: 1000)
    record = Resolv::DNS::TSIG.extract(signed)
    mac_index = signed.index(record.mac)
    truncated = signed.dup
    mac_size_offset = mac_index - 2
    truncated[mac_size_offset, 2] = [16].pack("n")
    decoder = Resolv::DNS::Message::MessageDecoder.new(signed) {}
    _id, _flags, qdcount, ancount, nscount, arcount = decoder.get_unpack("nnnnnn")
    qdcount.times { decoder.get_name; decoder.get_unpack("nn") }
    (ancount + nscount + arcount - 1).times do
      decoder.get_name
      decoder.get_unpack("nnN")
      length, = decoder.get_unpack("n")
      decoder.get_bytes(length)
    end
    decoder.get_name
    decoder.get_unpack("nnN")
    rr_length_offset = decoder.index
    rr_length, = decoder.get_unpack("n")
    truncated[rr_length_offset, 2] = [rr_length - 16].pack("n")
    truncated.slice!(mac_index + 16, record.mac.bytesize - 16)
    assert_raise(Resolv::DNS::TSIG::BadTruncation) do
      Resolv::DNS::TSIG.verify(@key, truncated, time: 1000)
    end
  end

  def test_chain_fails_after_tampering_with_unsigned_intermediate
    query = unsigned_query(0x4444)
    sign_query = Resolv::DNS::TSIG::SignContext.new(@key)
    sign_query.prefix(nil)
    signed_query = sign_query.sign(query, time: 1000)

    first = unsigned_response(0x4444, "one")
    second = unsigned_response(0x4444, "two")
    final = unsigned_response(0x4444, "final")

    server_sign = Resolv::DNS::TSIG::SignContext.new(@key)
    server_sign.prefix(mac_of(signed_query))
    server_sign.update(first).update(second)
    signed_final = server_sign.finish(final, time: 1002)

    verifier = Resolv::DNS::TSIG::VerifyContext.new(@key)
    verifier.prefix(mac_of(signed_query))
    verifier.update(first).update(second)
    assert_nothing_raised { verifier.finish(signed_final, time: 1002) }

    tampered = first.raw.dup
    tampered.setbyte(-1, tampered.getbyte(-1) ^ 1)
    attacked = Resolv::DNS::TSIG::VerifyContext.new(@key)
    attacked.prefix(mac_of(signed_query))
    attacked.update(tampered).update(second)
    assert_raise(Resolv::DNS::TSIG::BadSignature) do
      attacked.finish(signed_final, time: 1002)
    end
    assert_raise(Resolv::DNS::TSIG::ContextError) do
      attacked.finish(signed_final, time: 1002)
    end
  end

  def test_each_message_alone_does_not_replace_chain_authentication
    query = unsigned_query(0x5555)
    signed_query = Resolv::DNS::TSIG.sign(@key, query, time: 1000)
    intermediate = unsigned_response(0x5555, "middle")
    final = unsigned_response(0x5555, "final")

    signer = Resolv::DNS::TSIG::SignContext.new(@key)
    signer.prefix(mac_of(signed_query))
    signer.update(intermediate)
    signed_final = signer.finish(final, time: 1001)

    verifier = Resolv::DNS::TSIG::VerifyContext.new(@key)
    verifier.prefix(mac_of(signed_query))
    assert_raise(Resolv::DNS::TSIG::MalformedMessage) do
      verifier.verify(intermediate, time: 1001)
    end

    final_only = Resolv::DNS::TSIG::VerifyContext.new(@key)
    final_only.prefix(mac_of(signed_query))
    assert_raise(Resolv::DNS::TSIG::BadSignature) do
      final_only.finish(signed_final, time: 1001)
    end
  end

  def test_context_is_not_shared_between_concurrent_tcp_transfers
    pairs = 2.times.map {|index| transfer_pair(index)}
    shared = Resolv::DNS::TSIG::SignContext.new(@key)
    shared.prefix(nil)
    shared.sign(unsigned_query(0x9999), time: 1000)
    results = pairs.map do |pair|
      Thread.new do
        begin
          pair[:sign].update(pair[:messages][1]).update(pair[:messages][2])
          signed_final = pair[:sign].finish(pair[:messages][3], time: 1100)
          pair[:verify].update(pair[:messages][1]).update(pair[:messages][2])
          pair[:verify].finish(signed_final, time: 1100)
        end
      end
    end.map(&:value)
    assert_equal([0x6666, 0x6666], results.map(&:id))
    assert_raise(Resolv::DNS::TSIG::ContextError) do
      shared.update(unsigned_response(0x9999, "late"))
    end
  end

  def test_local_tcp_transfer_authenticates_every_frame
    query = unsigned_query(0x7777)
    messages = [
      unsigned_response(0x7777, "first"),
      unsigned_response(0x7777, "second"),
      unsigned_response(0x7777, "third")
    ]
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    received = nil

    server_thread = Thread.new do
      client = server.accept
      signed_query = read_frame(client)
      request_verifier = Resolv::DNS::TSIG::VerifyContext.new(@key)
      request_verifier.prefix(nil)
      request_verifier.verify(signed_query, time: 1000)
      signer = Resolv::DNS::TSIG::SignContext.new(@key)
      signer.prefix(mac_of(signed_query))
      signer.update(messages[0]).update(messages[1])
      signed_final = signer.finish(messages[2], time: 1002)
      messages[0, 2].each {|message| write_frame(client, message)}
      write_frame(client, signed_final)
      received = signed_query
      client.close
    end

    client = TCPSocket.new("127.0.0.1", port)
    begin
      query_signer = Resolv::DNS::TSIG::SignContext.new(@key)
      query_signer.prefix(nil)
      signed_query = query_signer.sign(query, time: 1000)
      write_frame(client, signed_query)

      verifier = Resolv::DNS::TSIG::VerifyContext.new(@key)
      verifier.prefix(mac_of(signed_query))
      first = read_frame(client)
      second = read_frame(client)
      final = read_frame(client)
      verifier.update(first).update(second)
      assert_equal(0x7777, verifier.finish(final, time: 1002).id)
      assert_equal(signed_query, received)
    ensure
      client.close
      server_thread.join
      server.close
    end
  end

  def test_errors_and_inspection_do_not_contain_secret
    signed = Resolv::DNS::TSIG.sign(@key, unsigned_query(0x8888), time: 1000)
    begin
      Resolv::DNS::TSIG.verify(@key, signed, time: 2000)
    rescue Resolv::DNS::TSIG::BadTime => error
      assert_not_match(/secret/, error.message)
    else
      flunk("expected BadTime")
    end
    assert_not_match(/secret/, @key.inspect)
    assert_not_match(/c2VjcmV0/, @key.inspect)
  end

  private

  def unsigned_query(id)
    message = Resolv::DNS::Message.new(id)
    message.add_question("example.", Resolv::DNS::Resource::IN::A)
    message
  end

  def unsigned_response(id, label = "192.0.2.1")
    message = Resolv::DNS::Message.new(id)
    message.qr = 1
    message.add_question("example.", Resolv::DNS::Resource::IN::A)
    if label == "192.0.2.1"
      message.add_answer("example.", 0, Resolv::DNS::Resource::IN::A.new(label))
    else
      message.add_answer("example.", 0, Resolv::DNS::Resource::IN::TXT.new(label))
    end
    raw = message.encode
    message.raw = raw
    message
  end

  def mac_of(message)
    Resolv::DNS::TSIG.extract(message).mac
  end

  def transfer_pair(index)
    query = unsigned_query(0x6666)
    query_signer = Resolv::DNS::TSIG::SignContext.new(@key)
    query_signer.prefix(nil)
    signed_query = query_signer.sign(query, time: 1000 + index)
    verifier = Resolv::DNS::TSIG::VerifyContext.new(@key)
    verifier.prefix(mac_of(signed_query))
    signer = Resolv::DNS::TSIG::SignContext.new(@key)
    signer.prefix(mac_of(signed_query))
    {
      sign: signer,
      verify: verifier,
      messages: [
        query,
        unsigned_response(0x6666, "one-#{index}"),
        unsigned_response(0x6666, "two-#{index}"),
        unsigned_response(0x6666, "final-#{index}")
      ]
    }
  end

  def read_frame(socket)
    length, = Timeout.timeout(5) { socket.read(2) }.unpack("n")
    Timeout.timeout(5) { socket.read(length) }
  end

  def write_frame(socket, message)
    wire = message.is_a?(String) ? message : message.raw
    socket.write([wire.bytesize].pack("n") + wire)
  end
end
