require 'mogilefs/client'
require 'mogilefs/util'

##
# MogileFS File manipulation client.

class MogileFS::MogileFS < MogileFS::Client

  include MogileFS::Util
  include MogileFS::Bigfile

  ##
  # The domain of keys for this MogileFS client.

  attr_reader :domain

  ##
  # The timeout for get_file_data.  Defaults to five seconds.

  attr_accessor :get_file_data_timeout

  ##
  # Creates a new MogileFS::MogileFS instance.  +args+ must include a key
  # :domain specifying the domain of this client.

  def initialize(args = {})
    @domain = args[:domain]
    @allow_empty = args.include?(:allow_empty) ? args[:allow_empty] : false

    @get_file_data_timeout = 5

    raise ArgumentError, "you must specify a domain" unless @domain

    if @backend = args[:db_backend]
      @readonly = true
    else
      super
    end
  end

  ##
  # Enumerates keys starting with +key+.

  def each_key(prefix)
    after = nil

    keys, after = list_keys prefix

    until keys.nil? or keys.empty? do
      keys.each { |k| yield k }
      keys, after = list_keys prefix, after
    end

    nil
  end

  ##
  # Retrieves the contents of +key+.

  def get_file_data(key, count_to_read = nil, &block)
    paths = get_paths(key) or return nil
    paths.each do |path|
      begin
        sock = http_read_sock(URI.parse(path))
        begin
          return yield(sock) if block_given?
          count_to_read = sock.mogilefs_size if count_to_read.nil?
          count_to_read = sock.mogilefs_size if count_to_read > sock.mogilefs_size
          return sysread_full(sock, count_to_read, @get_file_data_timeout)
        ensure
          sock.close rescue nil
        end
      rescue MogileFS::Timeout, MogileFS::InvalidResponseError,
             Errno::ECONNREFUSED, EOFError, SystemCallError
      end
    end
    nil
  end

  ##
  # Get the paths for +key+.

  def get_paths(key, noverify = true, zone = nil)
    opts = { :domain => @domain, :key => key,
             :noverify => noverify ? 1 : 0, :zone => zone }
    @backend.respond_to?(:_get_paths) and return @backend._get_paths(opts)
    res = @backend.get_paths(opts)
    (1..res['paths'].to_i).map { |i| res["path#{i}"] }.compact
  end

  ##
  # Get the URIs for +key+.

  def get_uris(key, noverify = true, zone = nil)
    get_paths(key, noverify, zone).map { |path| URI.parse(path) }
  end

  ##
  # Get the paths for +key+ within +moment+

  def get_paths_with_offset(key, moment)
    res = @backend.get_paths_with_offset(:domain => @domain, :key => key,
                             :moment => moment)

    paths = (1..res['paths'].to_i).map { |i| res["path#{i}"] }
    return paths if paths.empty?
    return paths if paths.first =~ /^http:\/\//
    return paths.map { |path| File.join @root, path }
  end

  ##
  # Enforce offsets for +key+ in +domain+

  def set_offset_force(key, bo, eo)
    res = @backend.set_offset_force(:domain => @domain, :key => key,
                                    :beginning_offset => bo, :ending_offset => eo)

    return [res['beginning_offset'], res['ending_offset']]
  end

  ##
  # Softly set offsets for +key+ in +domain+

  def set_offset_soft(key, bo, eo)
    res = @backend.set_offset_soft(:domain => @domain, :key => key,
                                    :beginning_offset => bo, :ending_offset => eo)

    return [res['beginning_offset'], res['ending_offset']]
  end

  ##
  # Get offsets for file.
  # Fails if key not found or wrong domain
  # If offset are not set for this file, returns hash with 'ok' = 0
  # Else returns hash with 'ok' = 1, and 'begginning' and 'ending' are UNIX
  # timestamps of beginning and end of the file.
  def get_offsets(key)
    @backend.get_key_offset(:domain => @domain, :key => key)
  end

  ##
  # Creates a new file +key+ in +klass+.  +bytes+ is currently unused.
  #
  # The +block+ operates like File.open.

  def new_file(key, klass = nil, bytes = 0, &block) # :yields: file
    raise MogileFS::ReadOnlyError if readonly?
    opts = { :domain => @domain, :key => key, :multi_dest => 1 }
    opts[:class] = klass if klass
    res = @backend.create_open(opts)

    dests = if dev_count = res['dev_count'] # multi_dest succeeded
      (1..dev_count.to_i).map do |i|
        [res["devid_#{i}"], res["path_#{i}"]]
      end
    else # single destination returned
      # 0x0040:  d0e4 4f4b 2064 6576 6964 3d31 2666 6964  ..OK.devid=1&fid
      # 0x0050:  3d33 2670 6174 683d 6874 7470 3a2f 2f31  =3&path=http://1
      # 0x0060:  3932 2e31 3638 2e31 2e37 323a 3735 3030  92.168.1.72:7500
      # 0x0070:  2f64 6576 312f 302f 3030 302f 3030 302f  /dev1/0/000/000/
      # 0x0080:  3030 3030 3030 3030 3033 2e66 6964 0d0a  0000000003.fid..

      [[res['devid'], res['path']]]
    end

    case (dests[0][1] rescue nil)
    when nil, '' then
      raise MogileFS::EmptyPathError
    when /^http:\/\// then
      MogileFS::HTTPFile.open(self, res['fid'], klass, key,
                              dests, bytes, @allow_empty, &block)
    else
      raise MogileFS::UnsupportedPathError,
            "paths '#{dests.inspect}' returned by backend is not supported"
    end
  end

  ##
  # Copies the contents of +file+ into +key+ in class +klass+.  +file+ can be
  # either a file name or an object that responds to #sysread.
  # Returns size of +file+ stored

  def store_file(key, klass, file)
    raise MogileFS::ReadOnlyError if readonly?

    begin
      new_file key, klass do |mfp|
       if file.respond_to? :sysread then
          sysrwloop(file, mfp)
        else
          size = File.size(file)
          if !allow_empty? && size.zero?
            raise MogileFS::ZeroLengthError.new("We do not support empty files, key - #{key}, file name - #{file}!")
          end
          if size > 0x10000 # Bigass file, handle differently
            mfp.big_io = file
            size
          else
            File.open(file, "rb") { |fp| sysrwloop(fp, mfp) }
          end
        end
      end
    rescue MogileFS::ZeroLengthError => e
      puts e.to_s
    end
  end

  def allow_empty?
    @allow_empty
  end

  ##
  # Stores +content+ into +key+ in class +klass+.

  def store_content(key, klass, content)
    raise MogileFS::ReadOnlyError if readonly?
    begin
      if !allow_empty? && content.length.zero?
        raise MogileFS::ZeroLengthError.new("We do not support empty content, key - #{key}")
      end
      new_file key, klass do |mfp|
        if content.is_a?(MogileFS::Util::StoreContent)
          mfp.streaming_io = content
        else
          mfp << content
        end
      end
    rescue MogileFS::ZeroLengthError => e
      puts e.to_s
    end
    content.length
  end

  ##
  # Removes +key+.

  def delete(key)
    raise MogileFS::ReadOnlyError if readonly?

    @backend.delete :domain => @domain, :key => key
  end

  ##
  # Sleeps +duration+.

  def sleep(duration)
    @backend.sleep :duration => duration
  end

  ##
  # Renames a key +from+ to key +to+.

  def rename(from, to)
    raise MogileFS::ReadOnlyError if readonly?

    @backend.rename :domain => @domain, :from_key => from, :to_key => to
    nil
  end
  
  ##
  # Changes class of a key +key+ to class +klass+.

  def change_class(key, klass)
    raise MogileFS::ReadOnlyError if readonly?

    @backend.change_class :domain => @domain, :key => key, :class => klass    
  end  

  ##
  # Returns the size of +key+.
  def size(key)
    @backend.respond_to?(:_size) and return @backend._size(domain, key)
    paths = get_paths(key) or return nil
    paths_size(paths)
  end

  def paths_size(paths)
    paths.each do |path|
      begin
        return http_read_sock(URI.parse(path), "HEAD").mogilefs_size
      rescue MogileFS::InvalidResponseError, MogileFS::Timeout,
             Errno::ECONNREFUSED, EOFError, SystemCallError => err
        next
      end
    end
    nil
  end

  ##
  # Lists keys starting with +prefix+ follwing +after+ up to +limit+.  If
  # +after+ is nil the list starts at the beginning.

  def list_keys(prefix, after = nil, limit = 1000, &block)
    if @backend.respond_to?(:_list_keys)
      return @backend._list_keys(domain, prefix, after, limit, &block)
    end

    res = begin
      @backend.list_keys(:domain => domain, :prefix => prefix,
                         :after => after, :limit => limit)
    rescue MogileFS::Backend::NoneMatchError
      return nil
    end

    keys = (1..res['key_count'].to_i).map { |i| res["key_#{i}"] }

    if block_given?
      # emulate the MogileFS::Mysql interface, slowly...
      keys.each do |key|
        paths = get_paths(key) or next
        length = paths_size(paths) or next
        yield key, length, paths.size
      end
    end
  
    [ keys, res['next_after'] ]
  end

  ##
  # Gets all known channels with their fronts
  #
  def channel_fronts
    r = []
    res = @backend.get_channel_fronts
    0.upto(res['count'].to_i - 1) do |n|
      r << {
        :dmid => res["dmid#{n}"],
        :name => res["name#{n}"],
        :front => res["front#{n}"].to_i
      }
    end
    r
  end

  ## 
  # Gets channel front time
  def channel_front(channel)
    res = @backend.channel_front(:domain => domain, :channel => channel)
    
    return Time.at(res['front'].to_i)
  end  
  
  ##
  # Mass fetching of minutes states
  def minutes_states(channel_name, beginning, ending)
    beginning = beginning.is_a?(Integer) ? beginning : beginning.to_i
    ending = ending.is_a?(Integer) ? ending : ending.to_i
    
    @backend.have_minutes(:domain => domain, :channel => channel_name,
                          :beginning => beginning, :ending => ending)    
  end
  
  ##
  # Creates new fragment
  def create_fragment(channel_name, beginning, ending, ss_policy)
    beginning = beginning.is_a?(Integer) ? beginning : beginning.to_i
    ending = ending.is_a?(Integer) ? ending : ending.to_i
    
    res = @backend.create_fragment(:domain => domain, :channel => channel_name,
                                   :beginning => beginning, :ending => ending,
                                   :ss_policy => ss_policy)
    return res['frid'];
  end                  

  ##
  # Updates fragment screenshots
  def rescreenshot_fragment(frid)
    res = @backend.rescreenshot_fragment(:domain => domain, :frid => frid)
    return res;
  end  

  ##
  # Deletes fragment
  def delete_fragment(frid)
    @backend.delete_fragment(:domain => domain, :frid => frid)
  end  
  
  ##
  # Fetches fragment status
  def fragment_info(frid)
    res = @backend.fragment_info(:domain => domain, :frid => frid)
    return nil if res.nil?

    %w|frid screenshots_needed minutes_done screenshots_done minutes_needed screenshots_destroyed|.each do |key| 
      res[key] = res[key].to_i
    end

    %w|all_screenshots_done all_written ready_to_view|.each do |key|
      res[key] = res[key]=="1"
    end
    res
  end  

  ##
  # Returns a key to access specific minute on specific channel
  def channel_time_key(channel, time)
    time.getutc.strftime("encoded/#{channel}/%Y/%m/%d/%H/%M.flv")
  end

  protected
    # given a URI, this returns a readable socket with ready data from the
    # body of the response.
    def http_read_sock(uri, http_method = "GET")
      sock = Socket.mogilefs_new_request(uri.host, uri.port,
                    "#{http_method} #{uri.request_uri} HTTP/1.0\r\n\r\n",
                    @get_file_data_timeout)
      buf = sock.recv_nonblock(4096, Socket::MSG_PEEK)
      head, body = buf.split(/\r\n\r\n/, 2)

      # we're dealing with a seriously slow/stupid HTTP server if we can't
      # get the header in a single read(2) syscall.
      if head =~ %r{\AHTTP/\d+\.\d+\s+200\s*} &&
         head =~ %r{^Content-Length:\s*(\d+)}i
        sock.mogilefs_size = $1.to_i
        case http_method
        when "HEAD" then sock.close
        when "GET" then sock.recv(head.size + 4, 0)
        end
        return sock
      end
      sock.close rescue nil
      raise MogileFS::InvalidResponseError,
            "#{http_method} on #{uri} returned: #{head.inspect}"
    end # def http_read_sock
end

