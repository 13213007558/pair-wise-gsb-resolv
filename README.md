# Resolv

Resolv is a thread-aware DNS resolver library written in Ruby.  Resolv can
handle multiple DNS requests concurrently without blocking the entire Ruby
interpreter.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'resolv'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install resolv
```

## Usage

```ruby
p Resolv.getaddress "www.ruby-lang.org"
p Resolv.getname "210.251.121.214"

Resolv::DNS.open do |dns|
  ress = dns.getresources "www.ruby-lang.org", Resolv::DNS::Resource::IN::A
  p ress.map(&:address)
  ress = dns.getresources "ruby-lang.org", Resolv::DNS::Resource::IN::MX
  p ress.map { |r| [r.exchange.to_s, r.preference] }
end
```

### Offline DNSSEC denial-of-existence validation

Pass a complete response, the question name/type, and an already trusted
DNSKEY to verify NSEC/NSEC3 denial proofs without making network requests.

```ruby
result = Resolv::DNS::DNSSEC.verify_negative_response(
  wire_response,
  "example.org",
  Resolv::DNS::Resource::IN::MX,
  { Resolv::DNS::Name.create("example.org.") => trusted_dnskey }
)

result.status       # :nxdomain, :nodata, :wildcard_match, :insecure_delegation, or :unproven
result.proven?      # denial interval/type bitmap and RRSIGs are both valid
result.signatures   # separate signature verification details
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ruby/resolv.
