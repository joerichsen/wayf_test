class SamlController < ApplicationController

  def init
    request = OneLogin::RubySaml::Authrequest.new
    Rails.logger.ap saml_settings
    Rails.logger.ap request.create(saml_settings)
    redirect_to(request.create(saml_settings))
  end

  def consume
    Rails.logger.ap params

    response          = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
    response.settings = saml_settings

    if response.is_valid? && user = current_account.users.find_by_email(response.name_id)
      authorize_success(user)
    else
      authorize_failure(user)
    end
  end

  private

  def saml_settings
    settings = OneLogin::RubySaml::Settings.new

    settings.assertion_consumer_service_url     = "http://#{request.host}/saml/consume"
    settings.issuer                             = request.protocol + request.host
    settings.protocol_binding                   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    settings.assertion_consumer_logout_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    settings.idp_sso_target_url                 = "https://testbridge.wayf.dk/saml2/idp/SSOService.php"
    settings.idp_cert_fingerprint               = 'MIIExTCCA62gAwIBAgIDBgNbMA0GCSqGSIb3DQEBBQUAMDwxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5HZW9UcnVzdCwgSW5jLjEUMBIGA1UEAxMLUmFwaWRTU0wgQ0EwHhcNMTIwNDA5MTMwMDA5WhcNMTcwNDEyMDAyNjQ3WjCB2TEpMCcGA1UEBRMgWWhjbmk0MDM2VTJHSkJPc1Jrems0NWp1dnRIUnpweW8xCzAJBgNVBAYTAkRLMRIwEAYDVQQKDAkqLndheWYuZGsxEzARBgNVBAsTCkdUMjE2NTU2MTcxMTAvBgNVBAsTKFNlZSB3d3cucmFwaWRzc2wuY29tL3Jlc291cmNlcy9jcHMgKGMpMTIxLzAtBgNVBAsTJkRvbWFpbiBDb250cm9sIFZhbGlkYXRlZCAtIFJhcGlkU1NMKFIpMRIwEAYDVQQDDAkqLndheWYuZGswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp6ny1k1GJrtfvDPWko'
    settings.name_identifier_format             = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

    # Signing stuff
    settings.sign_request = true
    raw = File.read "#{Rails.root}/config/certs/public.pem"
    settings.certificate = OpenSSL::X509::Certificate.new raw
    raw = File.read "#{Rails.root}/config/certs/saml.pem"
    settings.private_key = OpenSSL::PKey::RSA.new raw

    settings
  end
end