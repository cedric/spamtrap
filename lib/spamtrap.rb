require 'openssl'

module Spamtrap
  class << self
    attr_writer :nonce_timeout

    def nonce_timeout
      @nonce_timeout || 1800
    end
  end

  require 'spamtrap/controller'
  require 'spamtrap/helper'
end
