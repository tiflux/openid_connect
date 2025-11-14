module OpenIDConnect
  module MicrosoftTenantValidator

    def microsoft_issuer_valid?(actual_issuer, expected_issuer)
      return actual_issuer == expected_issuer unless is_microsoft_issuer?(expected_issuer)

      microsoft_tenant = detect_tenant_type_from_expected_issuer(expected_issuer)

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

    private

    def detect_tenant_type_from_expected_issuer(expected_issuer)
      return nil unless expected_issuer

      if expected_issuer.include?('/common/')
        'common'
      elsif expected_issuer.include?('/organizations/')
        'organizations'
      elsif expected_issuer.include?('/consumers/')
        'consumers'
      else
        nil
      end
    end

    def is_microsoft_issuer?(issuer)
      return false unless issuer
      issuer.include?('microsoftonline.com') || issuer.include?('sts.windows.net')
    end

    def validate_microsoft_issuer(issuer, options = {})
      patterns = [
        %r{^https://login\.microsoftonline\.com/([0-9a-f\-]{36})/v\d+\.\d+$},  
        %r{^https://sts\.windows\.net/([0-9a-f\-]{36})/$}                      
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

  end
end