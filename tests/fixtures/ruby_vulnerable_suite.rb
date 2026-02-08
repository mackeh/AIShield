require 'digest'
require 'net/http'
require 'openssl'

class RubyVulnerableSuite
  def insecure_demo(user_input, token, provided, api_key, incoming_api_key, password, db)
    return true if token == provided
    return true if api_key == incoming_api_key

    Digest::MD5.hexdigest(password)

    sql = "SELECT * FROM users WHERE id = " + user_input
    db.execute(sql)

    eval(user_input)

    Net::HTTP.start('example.com', 443, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE)
  end
end
