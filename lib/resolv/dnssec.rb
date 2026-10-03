# frozen_string_literal: true

require "resolv" unless defined?(Resolv::DNS)
require "openssl"
require "digest"

class Resolv
  class DNS
    class Resource
      module IN
        ##
        # Delegation Signer resource. [RFC 4034]
        class DS < Resource
          TypeValue = 43
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self # :nodoc:

          def initialize(key_tag, algorithm, digest_type, digest)
            @key_tag = key_tag
            @algorithm = algorithm
            @digest_type = digest_type
            @digest = digest
          end

          attr_reader :key_tag, :algorithm, :digest_type, :digest

          def encode_rdata(msg) # :nodoc:
            msg.put_pack("nCC", @key_tag, @algorithm, @digest_type)
            msg.put_bytes(@digest)
          end

          def self.decode_rdata(msg) # :nodoc:
            key_tag, algorithm, digest_type = msg.get_unpack("nCC")
            new(key_tag, algorithm, digest_type, msg.get_bytes)
          end
        end

        ##
        # Signature over an RRset. [RFC 4034]
        class RRSIG < Resource
          TypeValue = 46
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self # :nodoc:

          def initialize(type_covered, algorithm, labels, original_ttl,
                         expiration, inception, key_tag, signer, signature)
            @type_covered = type_covered.is_a?(Integer) ? type_covered : type_covered::TypeValue
            @algorithm = algorithm
            @labels = labels
            @original_ttl = original_ttl
            @expiration = expiration
            @inception = inception
            @key_tag = key_tag
            @signer = Name.create(signer)
            @signature = signature
          end

          attr_reader :type_covered, :algorithm, :labels, :original_ttl,
                      :expiration, :inception, :key_tag, :signer, :signature

          def encode_rdata(msg) # :nodoc:
            msg.put_pack("nCCNNNn", @type_covered, @algorithm, @labels,
                         @original_ttl, @expiration, @inception, @key_tag)
            msg.put_name(@signer, compress: false)
            msg.put_bytes(@signature)
          end

          def self.decode_rdata(msg) # :nodoc:
            type_covered, algorithm, labels, original_ttl, expiration,
            inception, key_tag = msg.get_unpack("nCCNNNn")
            signer = msg.get_name
            new(type_covered, algorithm, labels, original_ttl, expiration,
                inception, key_tag, signer, msg.get_bytes)
          end
        end

        ##
        # Next Secure record: authenticated denial of existence. [RFC 4034]
        class NSEC < Resource
          TypeValue = 47
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self # :nodoc:

          def initialize(next_name, types)
            @next_name = Name.create(next_name)
            @types = DNSSEC.normalize_types(types)
          end

          attr_reader :next_name, :types

          def has_type?(type)
            @types.include?(type.is_a?(Integer) ? type : type::TypeValue)
          end

          def encode_rdata(msg) # :nodoc:
            msg.put_name(@next_name, compress: false)
            msg.put_bytes(DNSSEC.encode_type_bitmap(@types))
          end

          def self.decode_rdata(msg) # :nodoc:
            next_name = msg.get_name
            new(next_name, DNSSEC.decode_type_bitmap(msg.get_bytes))
          end
        end

        ##
        # Key and signing key resource. [RFC 4034]
        class DNSKEY < Resource
          TypeValue = 48
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self # :nodoc:

          def initialize(flags, protocol, algorithm, key)
            @flags = flags
            @protocol = protocol
            @algorithm = algorithm
            @key = key
          end

          attr_reader :flags, :protocol, :algorithm, :key

          def zone_key?
            @flags & 0x100 != 0
          end

          def secure_entry_point?
            @flags & 1 != 0
          end

          # The key tag used to identify this key. [RFC 4034 Appendix B]
          def key_tag
            rdata = DNSSEC.dnskey_rdata(self)
            ac = 0
            rdata.each_byte.with_index do |byte, i|
              ac += i.even? ? byte << 8 : byte
            end
            ac += (ac >> 16) & 0xffff
            ac & 0xffff
          end

          def encode_rdata(msg) # :nodoc:
            msg.put_pack("nCC", @flags, @protocol, @algorithm)
            msg.put_bytes(@key)
          end

          def self.decode_rdata(msg) # :nodoc:
            flags, protocol, algorithm = msg.get_unpack("nCC")
            new(flags, protocol, algorithm, msg.get_bytes)
          end
        end

        ##
        # Hashed authenticated denial of existence. [RFC 5155]
        class NSEC3 < Resource
          TypeValue = 50
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self # :nodoc:

          def initialize(hash_algorithm, flags, iterations, salt, next_hashed, types)
            @hash_algorithm = hash_algorithm
            @flags = flags
            @iterations = iterations
            @salt = salt
            @next_hashed = next_hashed
            @types = DNSSEC.normalize_types(types)
          end

          attr_reader :hash_algorithm, :flags, :iterations, :salt,
                      :next_hashed, :types

          def opt_out?
            @flags & DNSSEC::NSEC3_FLAG_OPT_OUT != 0
          end

          def has_type?(type)
            @types.include?(type.is_a?(Integer) ? type : type::TypeValue)
          end

          def encode_rdata(msg) # :nodoc:
            msg.put_pack("CCn", @hash_algorithm, @flags, @iterations)
            msg.put_string(@salt)
            msg.put_string(@next_hashed)
            msg.put_bytes(DNSSEC.encode_type_bitmap(@types))
          end

          def self.decode_rdata(msg) # :nodoc:
            hash_algorithm, flags, iterations = msg.get_unpack("CCn")
            salt = msg.get_string
            next_hashed = msg.get_string
            new(hash_algorithm, flags, iterations, salt, next_hashed,
                DNSSEC.decode_type_bitmap(msg.get_bytes))
          end
        end
      end
    end

    ##
    # Offline DNSSEC authenticated-denial verification.
    # [RFC 4034, RFC 4035, RFC 5155]
    #
    # This module answers a single question: given trust anchors (already
    # trusted DNSKEY or DS records), a query name/type and a complete DNS
    # response message, do the NSEC or NSEC3 records in that message
    # cryptographically prove the claimed non-existence condition?
    #
    # It performs no online recursion and never downloads trust anchors, and
    # it never infers non-existence from an empty answer alone: when the
    # evidence is insufficient the result is +:unprovable+.
    #
    # Signature validity and proof validity are reported separately.  A
    # response can carry perfectly valid signatures on NSEC records whose
    # intervals are irrelevant to the query; such a response has
    # Result#signatures_valid? == true but Result#proved? == false.
    #
    #   result = Resolv::DNS::DNSSEC.verify_denial(
    #     name: "gone.example.",
    #     type: Resolv::DNS::Resource::IN::A,
    #     message: Resolv::DNS::Message.decode(packet),
    #     trust_anchors: [["example.", dnskey_rr]],
    #   )
    #   result.proof              #=> :nxdomain, :nodata, :wildcard_match,
    #                             #    :insecure or :unprovable
    #   result.proved?            #=> true
    #   result.signatures_valid?  #=> true
    #
    module DNSSEC
      ALGORITHM_RSASHA1 = 5
      ALGORITHM_RSASHA1_NSEC3_SHA1 = 7
      ALGORITHM_RSASHA256 = 8
      ALGORITHM_RSASHA512 = 10
      ALGORITHM_ECDSAP256SHA256 = 13
      ALGORITHM_ECDSAP384SHA384 = 14
      ALGORITHM_ED25519 = 15

      SUPPORTED_ALGORITHMS = [
        ALGORITHM_RSASHA1, ALGORITHM_RSASHA1_NSEC3_SHA1,
        ALGORITHM_RSASHA256, ALGORITHM_RSASHA512,
        ALGORITHM_ECDSAP256SHA256, ALGORITHM_ECDSAP384SHA384,
        ALGORITHM_ED25519,
      ].freeze

      NSEC3_HASH_SHA1 = 1
      NSEC3_FLAG_OPT_OUT = 1

      TYPE_NS = 2
      TYPE_CNAME = 5
      TYPE_SOA = 6
      TYPE_DNAME = 39
      TYPE_DS = 43
      TYPE_RRSIG = 46
      TYPE_NSEC = 47
      TYPE_DNSKEY = 48
      TYPE_NSEC3 = 50

      BASE32HEX_ALPHABET = "0123456789abcdefghijklmnopqrstuv"

      ##
      # The outcome of evaluating one RRSIG against the trusted keys.
      class SignatureStatus
        attr_reader :owner, :type_value, :signer, :key_tag, :algorithm, :status

        def initialize(owner, type_value, signer, key_tag, algorithm, status) # :nodoc:
          @owner = owner
          @type_value = type_value
          @signer = signer
          @key_tag = key_tag
          @algorithm = algorithm
          @status = status
        end

        def valid?
          @status == :valid
        end

        def to_s
          "#{@owner} type=#{@type_value} signer=#{@signer} " \
            "key_tag=#{@key_tag} algorithm=#{@algorithm}: #{@status}"
        end
      end

      ##
      # The result of DNSSEC.verify_denial.
      #
      # #proof is one of:
      #
      # :nxdomain::       the query name provably does not exist
      # :nodata::         the query name provably exists without the query type
      # :wildcard_match:: the query name provably does not exist and is
      #                   synthesized from a proven wildcard
      # :insecure::       an opt-out span or missing proof means only an
      #                   insecure (unsigned) delegation can be concluded
      # :unprovable::     the evidence does not prove any denial condition
      class Result
        attr_reader :proof, :reason, :signatures

        def initialize(proof, reason, signatures) # :nodoc:
          @proof = proof
          @reason = reason
          @signatures = signatures
        end

        # True when a denial condition (:nxdomain, :nodata or
        # :wildcard_match) was proven.
        def proved?
          [:nxdomain, :nodata, :wildcard_match].include?(@proof)
        end

        # True when the records only support an insecure (unsigned
        # delegation) conclusion, e.g. through an NSEC3 opt-out span.
        def insecure?
          @proof == :insecure
        end

        # True/false when RRSIGs were evaluated, nil when the message
        # carried no denial records with signatures to check.
        def signatures_valid?
          return nil if @signatures.empty?
          @signatures.all?(&:valid?)
        end
      end

      # An RRset with its associated RRSIGs. :nodoc:
      RRset = Struct.new(:name, :type_value, :rrs, :rrsigs)

      module_function

      ##
      # Verifies whether +message+ proves a denial-of-existence condition
      # for +name+ and +type+.
      #
      # +trust_anchors+ is an array of [name, DNSKEY] or [name, DS] pairs
      # that are already trusted.  +now+ is the time used for RRSIG
      # validity-period checks.  Returns a Result.
      def verify_denial(name:, type:, message:, trust_anchors: [], now: Time.now)
        qname = Name.create(name)
        qtype = type.is_a?(Integer) ? type : type::TypeValue

        rrsets = collect_rrsets(message)
        trusted = build_trusted_keys(rrsets, trust_anchors, now)
        statuses = []
        nsecs, nsec3s = authenticated_denial_records(rrsets, trusted, now, statuses)
        proof, reason = prove_denial(qname, qtype, nsecs, nsec3s)
        Result.new(proof, reason, statuses)
      end

      ##
      # Canonical wire form of +name+: downcased, uncompressed. [RFC 4034 6.2]
      def canonical_name_wire(name)
        out = +"".b
        name.to_a.each do |label|
          s = label.to_s.b.downcase
          out << s.bytesize.chr << s
        end
        out << "\0".b
        out
      end

      ##
      # Canonical DNS name order. [RFC 4034 6.1]
      def canonical_compare(a, b)
        la = a.to_a.map { |l| l.to_s.b.downcase }
        lb = b.to_a.map { |l| l.to_s.b.downcase }
        i = 1
        while i <= la.length && i <= lb.length
          c = la[-i] <=> lb[-i]
          return c unless c == 0
          i += 1
        end
        la.length <=> lb.length
      end

      ##
      # True when the NSEC span (owner, next_name) covers +name+,
      # handling wraparound at the zone apex.
      def nsec_covers?(owner, next_name, name)
        if canonical_compare(owner, next_name) < 0
          canonical_compare(owner, name) < 0 && canonical_compare(name, next_name) < 0
        else
          canonical_compare(owner, name) < 0 || canonical_compare(name, next_name) < 0
        end
      end

      ##
      # The NSEC3 hash of +name+ (SHA-1, iterated, salted). [RFC 5155 5]
      def nsec3_hash(name, salt, iterations)
        h = Digest::SHA1.digest(canonical_name_wire(name) + salt)
        iterations.times { h = Digest::SHA1.digest(h + salt) }
        h
      end

      ##
      # True when the NSEC3 span (owner_hash, next_hash) covers +hash+,
      # handling wraparound of the hash ring.
      def nsec3_covers?(owner_hash, next_hash, hash)
        if owner_hash < next_hash
          owner_hash < hash && hash < next_hash
        elsif owner_hash == next_hash
          hash != owner_hash
        else
          hash > owner_hash || hash < next_hash
        end
      end

      def base32hex_encode(data)
        out = +""
        bits = 0
        nbits = 0
        data.each_byte do |byte|
          bits = (bits << 8) | byte
          nbits += 8
          while nbits >= 5
            nbits -= 5
            out << BASE32HEX_ALPHABET[(bits >> nbits) & 31]
          end
        end
        out << BASE32HEX_ALPHABET[(bits << (5 - nbits)) & 31] if nbits > 0
        out
      end

      def base32hex_decode(str)
        out = +"".b
        bits = 0
        nbits = 0
        str.downcase.each_char do |ch|
          v = BASE32HEX_ALPHABET.index(ch) or
            raise DecodeError, "invalid base32hex character: #{ch.inspect}"
          bits = (bits << 5) | v
          nbits += 5
          if nbits >= 8
            nbits -= 8
            out << ((bits >> nbits) & 0xff).chr
          end
        end
        out
      end

      ##
      # Encodes a list of type values (or resource classes) as an NSEC/NSEC3
      # type bitmap. [RFC 4034 4.1.2]
      def encode_type_bitmap(types)
        normalize_types(types).group_by { |t| t >> 8 }.sort.map { |window, ts|
          max = ts.max & 0xff
          block = "\0".b * (max / 8 + 1)
          ts.each do |t|
            b = t & 0xff
            block.setbyte(b / 8, block.getbyte(b / 8) | (0x80 >> (b % 8)))
          end
          [window, block.bytesize].pack("CC") << block
        }.join
      end

      def decode_type_bitmap(data)
        types = []
        until data.empty?
          raise DecodeError, "truncated type bitmap" if data.bytesize < 2
          window, len = data.unpack("CC")
          if len < 1 || len > 32 || data.bytesize < 2 + len
            raise DecodeError, "invalid type bitmap window"
          end
          data.byteslice(2, len).each_byte.with_index do |byte, i|
            8.times do |bit|
              types << ((window << 8) | (i * 8 + bit)) if byte & (0x80 >> bit) != 0
            end
          end
          data = data.byteslice(2 + len..-1)
        end
        types
      end

      def normalize_types(types)
        types.map { |t| t.is_a?(Integer) ? t : t::TypeValue }.uniq.sort
      end

      ##
      # The data covered by +rrsig+ over the RRset [+name+, +type_value+,
      # +rrs+]. [RFC 4034 3.1.8.1]
      def rrsig_signed_data(name, type_value, rrs, rrsig)
        data = [rrsig.type_covered, rrsig.algorithm, rrsig.labels,
                rrsig.original_ttl, rrsig.expiration, rrsig.inception,
                rrsig.key_tag].pack("nCCNNNn")
        data << canonical_name_wire(rrsig.signer)
        owner = Name.create(name)
        if rrsig.labels < owner.to_a.length
          owner = Name.new(["*"] + owner.to_a[-rrsig.labels..-1], true)
        end
        wire_owner = canonical_name_wire(owner)
        rrs.map { |rr| canonical_rdata(rr) }.sort.each do |rdata|
          data << wire_owner
          data << [type_value, Resource::IN::ClassValue,
                   rrsig.original_ttl, rdata.bytesize].pack("nnNn")
          data << rdata
        end
        data
      end

      def dnskey_rdata(dnskey)
        [dnskey.flags, dnskey.protocol, dnskey.algorithm].pack("nCC") << dnskey.key
      end

      ##
      # Builds an OpenSSL public key from a DNSKEY resource.
      def dnskey_public_key(dnskey)
        case dnskey.algorithm
        when ALGORITHM_RSASHA1, ALGORITHM_RSASHA1_NSEC3_SHA1,
             ALGORITHM_RSASHA256, ALGORITHM_RSASHA512
          key = dnskey.key
          e_len = key.getbyte(0)
          if e_len.zero?
            e_len = key.byteslice(1, 2).unpack1("n")
            exponent = key.byteslice(3, e_len)
            modulus = key.byteslice(3 + e_len..-1)
          else
            exponent = key.byteslice(1, e_len)
            modulus = key.byteslice(1 + e_len..-1)
          end
          raise DecodeError, "truncated RSA key" unless modulus && exponent
          rsa_der = OpenSSL::ASN1::Sequence([
            OpenSSL::ASN1::Integer(OpenSSL::BN.new(modulus, 2)),
            OpenSSL::ASN1::Integer(OpenSSL::BN.new(exponent, 2)),
          ]).to_der
          spki = OpenSSL::ASN1::Sequence([
            OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("rsaEncryption"),
                                     OpenSSL::ASN1::Null(nil)]),
            OpenSSL::ASN1::BitString(rsa_der),
          ]).to_der
          OpenSSL::PKey.read(spki)
        when ALGORITHM_ECDSAP256SHA256, ALGORITHM_ECDSAP384SHA384
          group = dnskey.algorithm == ALGORITHM_ECDSAP256SHA256 ?
                  "prime256v1" : "secp384r1"
          spki = OpenSSL::ASN1::Sequence([
            OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
                                     OpenSSL::ASN1::ObjectId(group)]),
            OpenSSL::ASN1::BitString("\x04".b + dnskey.key),
          ]).to_der
          OpenSSL::PKey.read(spki)
        when ALGORITHM_ED25519
          OpenSSL::PKey.new_raw_public_key("ED25519", dnskey.key)
        else
          raise DecodeError, "unsupported DNSKEY algorithm: #{dnskey.algorithm}"
        end
      end

      ##
      # Verifies a raw DNSSEC signature over +data+ with +pkey+.
      def verify_signature(pkey, algorithm, data, signature)
        case algorithm
        when ALGORITHM_RSASHA1, ALGORITHM_RSASHA1_NSEC3_SHA1
          pkey.verify(OpenSSL::Digest::SHA1.new, signature, data)
        when ALGORITHM_RSASHA256
          pkey.verify(OpenSSL::Digest::SHA256.new, signature, data)
        when ALGORITHM_RSASHA512
          pkey.verify(OpenSSL::Digest::SHA512.new, signature, data)
        when ALGORITHM_ECDSAP256SHA256, ALGORITHM_ECDSAP384SHA384
          size = algorithm == ALGORITHM_ECDSAP256SHA256 ? 32 : 48
          return false unless signature.bytesize == size * 2
          der = OpenSSL::ASN1::Sequence([
            OpenSSL::ASN1::Integer(OpenSSL::BN.new(signature.byteslice(0, size), 2)),
            OpenSSL::ASN1::Integer(OpenSSL::BN.new(signature.byteslice(size, size), 2)),
          ]).to_der
          digest = algorithm == ALGORITHM_ECDSAP256SHA256 ?
                   OpenSSL::Digest::SHA256.new : OpenSSL::Digest::SHA384.new
          pkey.verify(digest, der, data)
        when ALGORITHM_ED25519
          pkey.verify(nil, signature, data)
        else
          false
        end
      rescue OpenSSL::OpenSSLError
        false
      end

      # Serial number arithmetic comparison: true when +a+ is not later
      # than +b+. [RFC 4034 3.1.5]
      def serial_leq?(a, b)
        a == b || ((b - a) & 0xffffffff) < 0x80000000
      end

      def downcase_name(name)
        Name.new(name.to_a.map { |l| Label::Str.new(l.downcase) }, name.absolute?)
      end

      def wildcard_name(encloser)
        Name.new(["*"] + encloser.to_a, encloser.absolute?)
      end

      # The canonical RDATA of +rr+ used for RRSIG computation.  Domain
      # names embedded in the RDATA of the types listed in RFC 4034 6.2 are
      # downcased; names in RRSIG and NSEC RDATA are not. [RFC 6840 5.1]
      def canonical_rdata(rr)
        Message::MessageEncoder.new { |msg| encode_canonical_rdata(msg, rr) }.to_s
      end

      def encode_canonical_rdata(msg, rr)
        case rr
        when Resource::IN::NS, Resource::IN::CNAME, Resource::IN::PTR
          msg.put_name(downcase_name(rr.name), compress: false)
        when Resource::IN::SOA
          msg.put_name(downcase_name(rr.mname), compress: false)
          msg.put_name(downcase_name(rr.rname), compress: false)
          msg.put_pack("NNNNN", rr.serial, rr.refresh, rr.retry,
                       rr.expire, rr.minimum)
        when Resource::IN::MX
          msg.put_pack("n", rr.preference)
          msg.put_name(downcase_name(rr.exchange), compress: false)
        when Resource::IN::SRV
          msg.put_pack("nnn", rr.priority, rr.weight, rr.port)
          msg.put_name(downcase_name(rr.target), compress: false)
        when Resource::IN::MINFO
          msg.put_name(downcase_name(rr.rmailbx), compress: false)
          msg.put_name(downcase_name(rr.emailbx), compress: false)
        when Resource::IN::RRSIG
          msg.put_pack("nCCNNNn", rr.type_covered, rr.algorithm, rr.labels,
                       rr.original_ttl, rr.expiration, rr.inception, rr.key_tag)
          msg.put_name(rr.signer, compress: false)
          msg.put_bytes(rr.signature)
        when Resource::IN::NSEC
          msg.put_name(rr.next_name, compress: false)
          msg.put_bytes(encode_type_bitmap(rr.types))
        else
          rr.encode_rdata(msg)
        end
      end

      ##
      # Groups every RRset in +message+ (all sections) with its RRSIGs.
      def collect_rrsets(message)
        rrsets = {}
        message.each_resource do |name, ttl, data|
          if data.is_a?(Resource::IN::RRSIG)
            key = [canonical_name_wire(name), data.type_covered]
            rs = (rrsets[key] ||= RRset.new(name, data.type_covered, [], []))
            rs.rrsigs << data
          else
            key = [canonical_name_wire(name), data.class::TypeValue]
            rs = (rrsets[key] ||= RRset.new(name, data.class::TypeValue, [], []))
            rs.rrs << [ttl, data]
          end
        end
        rrsets
      end

      ##
      # Expands +anchors+ ([name, DNSKEY] / [name, DS] pairs) into the set
      # of trusted DNSKEYs, following self-signed DNSKEY RRsets in the
      # message.  Returns {canonical_wire_name => [DNSKEY, ...]}.
      def build_trusted_keys(rrsets, anchors, now)
        trusted = {}
        ds_anchors = []
        anchors.each do |entry|
          aname, rr = entry
          aname = Name.create(aname)
          case rr
          when Resource::IN::DNSKEY
            (trusted[canonical_name_wire(aname)] ||= []) << rr
          when Resource::IN::DS
            ds_anchors << [aname, rr]
          else
            raise ArgumentError, "trust anchor must be a DNSKEY or DS: #{rr.inspect}"
          end
        end

        dnskey_rrsets = rrsets.values.select { |rs| rs.type_value == TYPE_DNSKEY }
        changed = true
        while changed
          changed = false
          dnskey_rrsets.each do |rs|
            wire = canonical_name_wire(rs.name)
            known = (trusted[wire] ||= [])
            missing = rs.rrs.map { |_, rr| rr } - known
            next if missing.empty?
            if rs.rrsigs.any? { |sig| known.any? { |k| verify_rrsig(rs, sig, rs.name, k, now) == :valid } }
              known.concat(missing)
              changed = true
              next
            end
            ds_anchors.each do |(aname, ds)|
              next unless canonical_name_wire(aname) == wire
              missing.dup.each do |key|
                next unless ds_matches?(aname, key, ds)
                if rs.rrsigs.any? { |sig| verify_rrsig(rs, sig, rs.name, key, now) == :valid }
                  known << key
                  missing.delete(key)
                  changed = true
                end
              end
            end
          end
        end
        trusted
      end

      ##
      # True when +ds+ is a DS record for +dnskey+ owned by +name+.
      def ds_matches?(name, dnskey, ds)
        return false unless ds.key_tag == dnskey.key_tag
        return false unless ds.algorithm == dnskey.algorithm
        data = canonical_name_wire(name) + dnskey_rdata(dnskey)
        digest = case ds.digest_type
                 when 1 then Digest::SHA1.digest(data)
                 when 2 then Digest::SHA256.digest(data)
                 when 4 then Digest::SHA384.digest(data)
                 else return false
                 end
        digest == ds.digest
      end

      ##
      # Verifies one RRSIG over +rrset+ with +dnskey+, which must be
      # trusted for +signer_name+.  Returns a status symbol.
      def verify_rrsig(rrset, rrsig, signer_name, dnskey, now)
        return :signer_mismatch unless canonical_compare(rrsig.signer, signer_name) == 0
        return :algorithm_mismatch unless rrsig.algorithm == dnskey.algorithm
        return :key_tag_mismatch unless rrsig.key_tag == dnskey.key_tag
        return :unsupported_algorithm unless SUPPORTED_ALGORITHMS.include?(rrsig.algorithm)
        now_i = now.to_i
        unless serial_leq?(rrsig.inception, now_i) && serial_leq?(now_i, rrsig.expiration)
          return :outside_validity_period
        end
        data = rrsig_signed_data(rrset.name, rrset.type_value,
                                 rrset.rrs.map { |_, rr| rr }, rrsig)
        pkey = dnskey_public_key(dnskey)
        verify_signature(pkey, rrsig.algorithm, data, rrsig.signature) ? :valid : :invalid
      rescue DecodeError, OpenSSL::OpenSSLError
        :invalid
      end

      ##
      # Selects the NSEC/NSEC3 records backed by at least one valid
      # signature from a trusted key, recording a SignatureStatus for
      # every RRSIG evaluated.
      def authenticated_denial_records(rrsets, trusted, now, statuses)
        nsecs = []
        nsec3s = []
        rrsets.each_value do |rs|
          next unless rs.type_value == TYPE_NSEC || rs.type_value == TYPE_NSEC3
          next if rs.rrs.empty?
          valid = false
          if rs.rrsigs.empty?
            statuses << SignatureStatus.new(rs.name, rs.type_value, nil, nil, nil, :unsigned)
          end
          rs.rrsigs.each do |sig|
            keys = trusted[canonical_name_wire(sig.signer)]
            if keys.nil? || keys.empty?
              statuses << SignatureStatus.new(rs.name, rs.type_value, sig.signer,
                                              sig.key_tag, sig.algorithm, :no_trusted_key)
              next
            end
            results = keys.map { |k| verify_rrsig(rs, sig, sig.signer, k, now) }
            status = results.include?(:valid) ? :valid : results.first
            statuses << SignatureStatus.new(rs.name, rs.type_value, sig.signer,
                                            sig.key_tag, sig.algorithm, status)
            valid ||= status == :valid
          end
          next unless valid
          rs.rrs.each do |_, rr|
            if rs.type_value == TYPE_NSEC
              nsecs << [rs.name, rr]
            else
              nsec3s << [rs.name, rr]
            end
          end
        end
        [nsecs, nsec3s]
      end

      def prove_denial(qname, qtype, nsecs, nsec3s)
        results = []
        results << prove_with_nsec(qname, qtype, nsecs) unless nsecs.empty?
        results << prove_with_nsec3(qname, qtype, nsec3s) unless nsec3s.empty?
        conclusive = results.find { |proof, _| proof != :unprovable }
        return conclusive if conclusive
        return results.first if results.length == 1
        [:unprovable,
         "no authenticated NSEC or NSEC3 record proves a non-existence condition for #{qname}"]
      end

      ##
      # NSEC denial-of-existence proof. [RFC 4035 5.4]
      def prove_with_nsec(qname, qtype, nsecs)
        existing = {}
        nsecs.each do |owner, rr|
          existing[canonical_name_wire(owner)] = owner
          existing[canonical_name_wire(rr.next_name)] = rr.next_name
        end

        nsecs.each do |owner, rr|
          if rr.has_type?(TYPE_DNAME) &&
             (qname.subdomain_of?(owner) || canonical_compare(qname, owner) == 0)
            return [:unprovable, "DNAME at #{owner} redirects #{qname}"]
          end
        end

        if existing.key?(canonical_name_wire(qname))
          at_qname = nsecs.find { |owner, _| canonical_compare(owner, qname) == 0 }
          if at_qname
            rr = at_qname[1]
            return [:unprovable, "#{qname} is a CNAME alias"] if rr.has_type?(TYPE_CNAME)
            if rr.has_type?(TYPE_NS) && !rr.has_type?(TYPE_SOA) && qtype != TYPE_DS
              return [:unprovable, "#{qname} is a delegation point, not authoritative data"]
            end
            unless rr.has_type?(qtype)
              return [:nodata, "NSEC at #{qname} proves the name exists without the query type"]
            end
            return [:unprovable, "NSEC at #{qname} lists the query type"]
          end
          return [:nodata, "#{qname} is an empty non-terminal"]
        end

        ce = closest_encloser(qname) { |anc| existing.key?(canonical_name_wire(anc)) }
        return [:unprovable, "no NSEC proves an ancestor of #{qname} exists"] unless ce

        covering_qname = nsecs.find { |owner, rr| nsec_covers?(owner, rr.next_name, qname) }
        wildcard = wildcard_name(ce)
        wildcard_nsec = nsecs.find { |owner, _| canonical_compare(owner, wildcard) == 0 }

        if wildcard_nsec
          unless covering_qname
            return [:unprovable, "no NSEC covers #{qname} (needed to validate the wildcard match)"]
          end
          if wildcard_nsec[1].has_type?(qtype)
            return [:wildcard_match,
                    "#{qname} does not exist; it is synthesized from wildcard #{wildcard}"]
          end
          return [:nodata, "wildcard #{wildcard} exists but has no record of the query type"]
        end

        covering_wildcard = nsecs.find { |owner, rr| nsec_covers?(owner, rr.next_name, wildcard) }
        if covering_qname && covering_wildcard
          return [:nxdomain, "NSEC records prove #{qname} and wildcard #{wildcard} do not exist"]
        end
        [:unprovable, "NSEC records do not cover both #{qname} and wildcard #{wildcard}"]
      end

      ##
      # NSEC3 denial-of-existence proof.  Records with inconsistent hash
      # parameters form separate hash rings and are evaluated
      # independently. [RFC 5155 8.4-8.7]
      def prove_with_nsec3(qname, qtype, nsec3s)
        groups = nsec3s.group_by { |_, rr| [rr.hash_algorithm, rr.iterations, rr.salt] }
        results = []
        groups.each do |(alg, _, _), records|
          if alg != NSEC3_HASH_SHA1
            results << [:unprovable, "unsupported NSEC3 hash algorithm #{alg}"]
            next
          end
          results << prove_with_nsec3_params(qname, qtype, records)
        end
        conclusive = results.find { |proof, _| proof != :unprovable }
        return conclusive if conclusive
        if groups.length > 1
          return [:unprovable,
                  "inconsistent NSEC3 parameters (#{groups.length} parameter sets) " \
                  "and no single parameter set proves the denial"]
        end
        results.first || [:unprovable, "no NSEC3 records"]
      end

      def prove_with_nsec3_params(qname, qtype, records)
        salt = records[0][1].salt
        iterations = records[0][1].iterations
        by_hash = {}
        records.each do |owner, nsec3|
          by_hash[nsec3_owner_hash(owner)] = nsec3
        end

        qhash = nsec3_hash(qname, salt, iterations)
        if (exact = by_hash[qhash])
          return [:unprovable, "#{qname} is a CNAME alias"] if exact.has_type?(TYPE_CNAME)
          if exact.has_type?(TYPE_NS) && !exact.has_type?(TYPE_SOA) && qtype != TYPE_DS
            return [:unprovable, "#{qname} is a delegation point, not authoritative data"]
          end
          unless exact.has_type?(qtype)
            return [:nodata, "NSEC3 at the hash of #{qname} proves no record of the query type"]
          end
          return [:unprovable, "NSEC3 at the hash of #{qname} lists the query type"]
        end

        ce = closest_encloser(qname) { |anc| by_hash.key?(nsec3_hash(anc, salt, iterations)) }
        return [:unprovable, "no NSEC3 matches the closest encloser of #{qname}"] unless ce

        next_closer = next_closer_name(qname, ce)
        nc_hash = nsec3_hash(next_closer, salt, iterations)
        covering_nc = records.find { |owner, nsec3|
          nsec3_covers?(nsec3_owner_hash(owner), nsec3.next_hashed, nc_hash)
        }
        return [:unprovable, "no NSEC3 covers the next closer name #{next_closer}"] unless covering_nc
        if covering_nc[1].opt_out?
          return [:insecure,
                  "opt-out NSEC3 covers #{next_closer}; an unsigned delegation may exist"]
        end

        wildcard = wildcard_name(ce)
        w_hash = nsec3_hash(wildcard, salt, iterations)
        if (w = by_hash[w_hash])
          if w.has_type?(qtype)
            return [:wildcard_match,
                    "#{qname} does not exist; it is synthesized from wildcard #{wildcard}"]
          end
          return [:nodata, "wildcard #{wildcard} exists but has no record of the query type"]
        end
        covering_w = records.find { |owner, nsec3|
          nsec3_covers?(nsec3_owner_hash(owner), nsec3.next_hashed, w_hash)
        }
        if covering_w
          return [:nxdomain, "NSEC3 records prove #{qname} and wildcard #{wildcard} do not exist"]
        end
        [:unprovable, "no NSEC3 covers the wildcard #{wildcard}"]
      end

      def nsec3_owner_hash(owner)
        base32hex_decode(owner.to_a.first.to_s)
      end

      def closest_encloser(qname)
        labels = qname.to_a
        (1...labels.length).each do |i|
          anc = Name.new(labels[i..-1], qname.absolute?)
          return anc if yield anc
        end
        nil
      end

      def next_closer_name(qname, closest_encloser)
        labels = qname.to_a
        keep = closest_encloser.to_a.length + 1
        Name.new(labels[-keep..-1], qname.absolute?)
      end
    end
  end
end
