require 'digest'
require 'net/http'
require 'openssl'
require 'securerandom'

class RubyVulnerableSuite
  def insecure_demo(user_input, token, provided, api_key, incoming_api_key, password, db, request, response)
    # AUTH: timing-unsafe token compare
    return true if token == provided
    # AUTH: insecure api key compare
    return true if api_key == incoming_api_key
    # AUTH: insecure password compare
    return true if password == provided
    # AUTH: hardcoded bearer token
    authorization = "Bearer " + token
    # AUTH: case-normalized token compare
    return true if token.downcase == provided.downcase

    # CRYPTO: weak hash MD5
    Digest::MD5.hexdigest(password)
    # CRYPTO: weak hash SHA1
    Digest::SHA1.hexdigest(password)
    # CRYPTO: weak cipher DES
    cipher = OpenSSL::Cipher::Cipher.new("DES-CBC")
    # CRYPTO: predictable random
    code = rand(1000000)
    # CRYPTO: weak RSA key size
    key = OpenSSL::PKey::RSA.new(1024)

    # INJECTION: SQL string concat
    sql = "SELECT * FROM users WHERE id = " + user_input
    db.execute(sql)
    # INJECTION: eval user input
    eval(user_input)
    # INJECTION: command injection via system
    system("ls " + user_input)
    # INJECTION: path traversal
    data = File.read("/var/data/" + user_input)
    # INJECTION: open redirect
    redirect_to params[:next]

    # MISCONFIG: TLS verify none
    Net::HTTP.start('example.com', 443, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE)
    # MISCONFIG: CORS wildcard
    response.headers["Access-Control-Allow-Origin"] = "*"
    # MISCONFIG: debug mode
    debug = true
    # MISCONFIG: listen all interfaces
    server.listen("0.0.0.0", 8080)
    # MISCONFIG: sensitive header logging
    logger.info("Authorization header: #{request.headers['Authorization']}")
  end
end
