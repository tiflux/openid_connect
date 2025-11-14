module OpenIDConnect
  module MicrosoftTenantValidator

    def microsoft_issuer_valid?(actual_issuer, expected_issuer)
      return actual_issuer == expected_issuer unless is_microsoft_issuer?(expected_issuer)

      microsoft_tenant = detect_tenant_type_from_expected_issuer(expected_issuer)

      case microsoft_tenant.to_s.downcase
      when 'common'
        validate_microsoft_common_issuer(actual_issuer)
      else
        # Para casos não reconhecidos, usar validação padrão exata
        actual_issuer == expected_issuer
      end
    end

    private

    def detect_tenant_type_from_expected_issuer(expected_issuer)
      return nil unless expected_issuer

      if expected_issuer.include?('/common/')
        'common'
      else
        nil
      end
    end

    def is_microsoft_issuer?(issuer)
      return false unless issuer
      issuer.include?('microsoftonline.com') || issuer.include?('sts.windows.net')
    end

    def validate_microsoft_common_issuer(issuer)
      # Patterns para validar Microsoft common endpoint
      patterns = [
        %r{^https://login\.microsoftonline\.com/([0-9a-f\-]{36})/v\d+\.\d+$},           
        %r{^https://login\.microsoftonline\.com/common/v\d+\.\d+$},                                    # Placeholder (discovery)
        %r{^https://sts\.windows\.net/([0-9a-f\-]{36})/$}                              
      ]

      patterns.any? { |pattern| pattern.match?(issuer) }
    end

  end
end