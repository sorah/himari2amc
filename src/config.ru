# config.ru
require 'omniauth'
require 'omniauth-himari'
require 'rack'
require 'rack/session/cookie'
require 'secure_headers'
require 'apigatewayv2_rack'
require_relative './app'

require 'aws-sdk-secretsmanager'
secret = JSON.parse(Aws::SecretsManager::Client.new().get_secret_value(secret_id: ENV.fetch('AMC_SECRET_PARAMS_ARN'), version_stage: 'AWSCURRENT').secret_string)

use(Class.new do
  def initialize(app)
    @app = app
  end
  def call(env)
    env['rack.errors'] = $stderr
    @app.call(env)
  end
end)

use Rack::Logger
use Apigatewayv2Rack::Middlewares::CloudfrontXff
use Rack::CommonLogger

SecureHeaders::Configuration.default do |config|
  config.cookies = {secure: true, httponly: true, samesite: {lax: true}}
  config.hsts = "max-age=#{(90*86400)}"
end

if ENV['AMC_DEV'] == '1'
  require 'securerandom'
  use(Rack::Session::Cookie,
    key: 'amc-sess',
    path: '/',
    secure: false,
    expire_after: 3600 * 1,
    secret: SecureRandom.hex(96),
  )

else
  use SecureHeaders::Middleware
  use(Rack::Session::Cookie,
    key: '__Host-amc-sess',
    path: '/',
    secure: true,
    expire_after: 3600 * 1,
    secret: secret.fetch('SECRET_KEY_BASE'),
  )
end

use OmniAuth::Builder do
  configure do |conf|
    # Justify: protected resources are on all POST
    conf.allowed_request_methods = %i[get]
    conf.silence_get_warning = true
  end

  provider(
    :himari,
    site: ENV.fetch('AMC_HIMARI_SITE'),
    client_id: ENV['AMC_CLIENT_ID'] || secret.fetch('AMC_CLIENT_ID'),
    client_secret: ENV['AMC_CLIENT_SECRET'] || secret.fetch('AMC_CLIENT_SECRET'),
 )
end

use(Class.new do
  def initialize(app, hash)
    @app = app
    @hash = hash
  end

  def call(env)
    env.merge!(@hash)
    @app.call(env)
  end
end, {
  'amc.himari-site' => ENV.fetch('AMC_HIMARI_SITE'),
  'amc.client-id' => ENV['AMC_CLIENT_ID'] || secret.fetch('AMC_CLIENT_ID'),
  'amc.alt-client-ids' => (ENV['AMC_ALT_CLIENT_IDS'] || secret['AMC_ALT_CLIENT_IDS'] || ' ').split(' '),
})

run Amc::App

