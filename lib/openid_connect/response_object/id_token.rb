module OpenIDConnect
  class ResponseObject
    class IdToken < ConnectObject
      class InvalidToken < Exception; end
      class ExpiredToken < InvalidToken; end
      class InvalidIssuer < InvalidToken; end
      class InvalidNonce < InvalidToken; end
      class InvalidAudience < InvalidToken; end

      attr_required :iss, :sub, :aud, :exp, :iat
      attr_optional :acr, :amr, :azp, :jti, :sid, :auth_time, :nonce, :sub_jwk, :at_hash, :c_hash, :s_hash
      attr_accessor :access_token, :code, :state
      alias_method :subject, :sub
      alias_method :subject=, :sub=

      def initialize(attributes = {})
        super
        (all_attributes - [:aud, :exp, :iat, :auth_time, :sub_jwk]).each do |key|
          self.send "#{key}=", self.send(key).try(:to_s)
        end
        self.auth_time = auth_time.to_i unless auth_time.nil?
      end

      def verify!(expected = {})
        puts "#######"
        puts "#######"
        puts "VERIFYING ID TOKEN"
        puts iss
        puts expected[:issuer]
        puts expected[:microsoft_tenant] if expected[:microsoft_tenant]
        puts "#######"
        puts "#######"

        raise ExpiredToken.new('Invalid ID token: Expired token') unless exp.to_i > Time.now.to_i

        unless microsoft_tenant_issuer_valid?(iss, expected[:issuer], expected[:microsoft_tenant])
          raise InvalidIssuer.new('Invalid ID token: Issuer does not match')
        end

        raise InvalidNonce.new('Invalid ID Token: Nonce does not match') unless nonce == expected[:nonce]

        # aud(ience) can be a string or an array of strings
        unless Array(aud).include?(expected[:audience] || expected[:client_id])
          raise InvalidAudience.new('Invalid ID token: Audience does not match')
        end

        true
      end

      include JWTnizable
      def to_jwt(key, algorithm = :RS256, &block)
        hash_length = algorithm.to_s[2, 3].to_i
        if access_token
          token = case access_token
          when Rack::OAuth2::AccessToken
            access_token.access_token
          else
            access_token
          end
          self.at_hash = left_half_hash_of token, hash_length
        end
        if code
          self.c_hash = left_half_hash_of code, hash_length
        end
        if state
          self.s_hash = left_half_hash_of state, hash_length
        end
        super
      end

      private

      def left_half_hash_of(string, hash_length)
        digest = OpenSSL::Digest.new("SHA#{hash_length}").digest string
        Base64.urlsafe_encode64 digest[0, hash_length / (2 * 8)], padding: false
      end

      def microsoft_tenant_issuer_valid?(actual_issuer, expected_issuer, microsoft_tenant = nil)
        return actual_issuer == expected_issuer unless microsoft_tenant && is_microsoft_issuer?(expected_issuer)

        case microsoft_tenant.to_s.downcase
        when 'common'
          validate_microsoft_issuer(actual_issuer, allow_any_tenant: true)
        when 'organizations'
          validate_microsoft_issuer(actual_issuer, organizations_only: true)
        when 'consumers'
          validate_microsoft_issuer(actual_issuer, consumers_only: true)
        else
          actual_issuer == expected_issuer
        end
      end

      def is_microsoft_issuer?(issuer)
        return false unless issuer
        issuer.include?('microsoftonline.com') || issuer.include?('sts.windows.net')
      end

      def validate_microsoft_issuer(issuer, options = {})
        patterns = [
          %r{^https://login\.microsoftonline\.com/([0-9a-f\-]{36})/v\d+\.\d+$},  # Futuro-compatível
          %r{^https://sts\.windows\.net/([0-9a-f\-]{36})/$}                      # Legacy v1.0
        ]

        tenant_id = nil
        patterns.each do |pattern|
          match = pattern.match(issuer)
          if match
            tenant_id = match[1]
            break
          end
        end

        return false unless tenant_id

        if options[:allow_any_tenant]
          true
        elsif options[:organizations_only]
          tenant_id != '9188040d-6c67-4c5b-b112-36a304b66dad'
        elsif options[:consumers_only]
          tenant_id == '9188040d-6c67-4c5b-b112-36a304b66dad'
        else
          false
        end
      end

      class << self
        def decode(jwt_string, key_or_config)
          case key_or_config
          when :self_issued
            decode_self_issued jwt_string
          when OpenIDConnect::Discovery::Provider::Config::Response
            jwt = JSON::JWT.decode jwt_string, :skip_verification
            jwt.verify! key_or_config.jwk(jwt.kid)
            new jwt
          else
            new JSON::JWT.decode jwt_string, key_or_config
          end
        end

        def decode_self_issued(jwt_string)
          jwt = JSON::JWT.decode jwt_string, :skip_verification
          jwk = JSON::JWK.new jwt[:sub_jwk]
          raise InvalidToken.new('Missing sub_jwk') if jwk.blank?
          raise InvalidToken.new('Invalid subject') unless jwt[:sub] == jwk.thumbprint
          jwt.verify! jwk
          new jwt
        end

        def self_issued(attributes = {})
          attributes[:sub_jwk] ||= JSON::JWK.new attributes.delete(:public_key)
          _attributes_ = {
            iss: 'https://self-issued.me',
            sub: JSON::JWK.new(attributes[:sub_jwk]).thumbprint
          }.merge(attributes)
          new _attributes_
        end
      end
    end
  end
end
