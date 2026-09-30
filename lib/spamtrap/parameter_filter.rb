module Spamtrap
  # Rails logs params before any before_action runs, so mutated field names reach the log still
  # encrypted and never match the app's filter_parameters. The Railtie appends BLOCK to
  # filter_parameters; it decrypts each name and applies the app's own filters to the real one.
  module ParameterFilter
    # base64url of IV + at least one name byte + tag, then a date/time select's (Ni) suffix.
    TOKEN = /\A([A-Za-z0-9_-]{39,})(\(\d+[a-z]\))?\z/

    # Token key => parent paths, built once per params hash; weak so logged params aren't retained.
    PARENTS = ObjectSpace::WeakMap.new

    # Rails only calls blocks for leaf values no key filter matched, passing a copy of the
    # value to mutate and the top-level params.
    BLOCK = lambda do |key, value, params|
      # Cheapest checks first: this runs for every leaf param of every request Rails filters.
      next unless Spamtrap.filter_parameters && params.respond_to?(:key?)
      next unless params.key?('spamtrap_timestamp') || params.key?(:spamtrap_timestamp)
      next unless value.is_a?(String) && (token = TOKEN.match(key.to_s))

      masked = Spamtrap::ParameterFilter.mask(token, value, params)
      value.replace(masked) if masked
    end

    class << self
      # What the app's filters turn value into at the field's real path, or nil if they leave it.
      # Only leaf names are mutated, so the containers above the token give the real path. A token
      # shared by fields_for children has several parents; masking if any path would is the safe side.
      def mask(token, value, params)
        filter  = app_filter
        parents = (PARENTS[params] ||= parent_paths(params)).fetch(token[0], [[]])
        Spamtrap::Crypto.unverified_field_names(token[1]).each do |name|
          parents.each do |parent|
            path   = [*parent, "#{name}#{token[2]}"]
            result = path.inject(filter.filter(nest(path, value.dup))) { |node, key| node.is_a?(Hash) ? node[key] : node }
            return result.to_s unless result == value
          end
        end
        nil
      end

      # The app's filters without BLOCK itself, rebuilt when the list is reassigned or grows.
      def app_filter
        filters = Rails.application.config.filter_parameters
        signature = [filters.object_id, filters.size]
        return @app_filter if @app_filter_signature == signature

        # Filter before signature, so a concurrent reader never pairs the new signature with the old filter.
        @app_filter = ActiveSupport::ParameterFilter.new(filters.reject { |f| f.equal?(BLOCK) })
        @app_filter_signature = signature
        @app_filter
      end

      private

      # Array positions are left out of a path, as Rails leaves them out of dotted filter matching.
      def parent_paths(params)
        paths = Hash.new { |hash, key| hash[key] = [] }
        visit = lambda do |node, path|
          if node.is_a?(Array)
            node.each { |element| visit.call(element, path) }
          elsif node.is_a?(Hash)
            node.each do |key, child|
              paths[key.to_s] |= [path] if TOKEN.match?(key.to_s)
              visit.call(child, [*path, key.to_s])
            end
          end
        end
        visit.call(params, [])
        paths
      end

      def nest(path, value)
        path.reverse.inject(value) { |inner, key| { key => inner } }
      end
    end
  end
end
