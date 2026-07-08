require 'openssl'

module Spamtrap
  class << self
    attr_writer :nonce, :nonce_timeout, :mutate

    def nonce
      @nonce || false
    end

    def nonce_timeout
      @nonce_timeout || 1800
    end

    def mutate
      @mutate || false
    end
  end

  require 'spamtrap/crypto'
  require 'spamtrap/controller'
  require 'spamtrap/helper'
end
