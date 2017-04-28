begin
  require 'patron'

  ##
  # MogileFS Synchoronous File manipulation client.

  class MogileFS::MogileFS::Sync < MogileFS::MogileFS
    CHUNK_SIZE = 1024 * 1024

    def new_session
      sess = Patron::Session.new
      sess
    end

    def session
      @session ||= new_session
    end

    ##
    # Retrieves the contents of +key+.
    def get_file_data(key, count_to_read = nil, &block)
      paths = get_paths(key) or return nil
      paths.each do |path|
      begin
        resp = session.get(path)
        case resp.status
        when 200..299
          return resp.body
        else
          raise MogileFS::Error.new("Error retrieving #{path}, status #{resp.status}")
        end
      rescue MogileFS::Error
      end
      nil
    end
  end

  ##
  # Copies the contents of +file+ into +key+ in class +klass+.  +file+ can be
  # either a file name or an object that responds to #sysread.
  # Returns size of +file+ stored

  def store_file(key, klass, file)
    raise MogileFS::ReadOnlyError if readonly?

    new_file key, klass do |mfp|
      mfp.sync_mode!(session)
      mfp.file_to_put = file
    end
  end

  ##
  # Stores +content+ into +key+ in class +klass+.

  def store_content(key, klass, content)
    raise MogileFS::ReadOnlyError if readonly?

    new_file key, klass do |mfp|
      mfp.sync_mode!(session)
      mfp << content
    end

    content.length
  end

end

rescue LoadError
  MogileFS::MogileFS::Sync = MogileFS::MogileFS
end

