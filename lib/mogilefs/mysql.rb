require 'mogilefs'
require 'mogilefs/backend' # for the exceptions

# read-only interface that can be a backend for MogileFS::MogileFS
#
# This provides direct, read-only access to any slave MySQL database to
# provide better performance, scalability and eliminate mogilefsd as a
# point of failure
class MogileFS::Mysql

  attr_reader :my
  attr_reader :query_method
  attr_accessor :debug

  ##
  # Creates a new MogileFS::Mysql instance.  +args+ must include a key
  # :domain specifying the domain of this client and :mysql, specifying
  # an already-initialized Mysql object.
  #
  # The Mysql object can be either the standard Mysql driver or the
  # Mysqlplus one supporting c_async_query.
  def initialize(args = {})
    @my = args[:mysql]
    @query_method = @my.respond_to?(:c_async_query) ? :c_async_query : :query
    @last_update_device = @last_update_domain = @last_update_class = Time.at(0)
    @cache_domain = @cache_device = @cache_class = nil
    nns = query("SELECT COUNT(*) AS c FROM server_settings WHERE field = 'usual-file-next-fid'").fetch_row
    @new_naming_scheme = !nns.nil? && nns.first.to_i == 1
    @debug = args[:debug] || false
  end

  ##
  # Lists keys starting with +prefix+ follwing +after+ up to +limit+.  If
  # +after+ is nil the list starts at the beginning.
  def _list_keys(domain, prefix = '', after = '', limit = 1000, &block)
    # this code is based on server/lib/MogileFS/Worker/Query.pm
    dmid = get_dmid(domain)

    # don't modify passed arguments
    limit ||= 1000
    limit = limit.to_i
    limit = 1000 if limit > 1000 || limit <= 0
    after, prefix = "#{after}", "#{prefix}"

    if after.length > 0 && /^#{Regexp.quote(prefix)}/ !~ after
      raise MogileFS::Backend::AfterMismatchError
    end

    raise MogileFS::Backend::InvalidCharsError if /[%\\]/ =~ prefix
    prefix.gsub!(/_/, '\_') # not sure why MogileFS::Worker::Query does this...

    sql = <<-EOS
    SELECT dkey,length,devcount FROM file
    WHERE dmid = #{dmid}
      AND dkey LIKE '#{@my.quote(prefix)}%'
      AND dkey > '#{@my.quote(after)}'
    ORDER BY dkey LIMIT #{limit}
    EOS

    keys = []
    query(sql).each do |dkey,length,devcount|
      yield(dkey, length.to_i, devcount.to_i) if block_given?
      keys << dkey
    end

    keys.empty? ? nil : [ keys, (keys.last || '') ]
  end

  ##
  # Returns the size of +key+.
  def _size(domain, key)
    dmid = get_dmid(domain)

    sql = <<-EOS
    SELECT length FROM file
    WHERE dmid = #{dmid} AND dkey = '#{@my.quote(key)}'
    LIMIT 1
    EOS

    res = query(sql).fetch_row
    return res[0].to_i if res && res[0]
    raise MogileFS::Backend::UnknownKeyError
  end

  def uri_for(devid, fid)
    if @new_naming_scheme
      nfid = '%015u' % fid
      b, mmmmmmmm, ttt = /(\d)(\d{8})(\d{3})(?:\d{3})/.match(nfid)[1..3]
      "/dev#{devid}/#{b}/#{mmmmmmmm}/#{ttt}/#{nfid}.fid"
    else
      nfid = '%010u' % fid
      b, mmm, ttt = /(\d)(\d{3})(\d{3})(?:\d{3})/.match(nfid)[1..3]
      "/dev#{devid}/#{b}/#{mmm}/#{ttt}/#{nfid}.fid"
    end
  end

  ##
  # Change class for +key+.
  def change_class(domain, key, new_class)
    dmid = get_dmid(domain)
    classid = get_classid(domain, new_class)
    sql = "UPDATE file SET classid = #{classid} WHERE dmid = #{dmid} AND dkey = '#{@my.quote(key)}'"

    query(sql)
  end

  ##
  # Get the paths for +key+.
  def _get_paths(params = {})
    zone = params[:zone]
    noverify = (params[:noverify] == 1) # TODO this is unused atm
    dmid = get_dmid(params[:domain])
    devices = refresh_device or raise MogileFS::Backend::NoDevicesError
    urls = []
    sql = <<-EOS
    SELECT fid FROM file
    WHERE dmid = #{dmid} AND dkey = '#{@my.quote(params[:key])}'
    LIMIT 1
    EOS

    res = query(sql).fetch_row
    res && res[0] or raise MogileFS::Backend::UnknownKeyError
    fid = res[0]
    sql = "SELECT devid FROM file_on WHERE fid = '#{@my.quote(fid)}'"
    query(sql).each do |devid,|
      unless devinfo = devices[devid.to_i]
        devices = refresh_device(true)
        devinfo = devices[devid.to_i] or next
      end
      devinfo[:readable] or next
      port = devinfo[:http_get_port]
      host = zone && zone == 'alt' ? devinfo[:altip] : devinfo[:hostip]
      uri = uri_for(devid, fid)
      urls << "http://#{host}:#{port}#{uri}"
    end
    urls
  end

  MAX_GOP_LEN = 5120.freeze
  MAX_OFFSET = (60000 + MAX_GOP_LEN).freeze

  ##
  # Get the paths for +key+ with +offset_ms+.
  def _get_paths_with_offset(params = {})
    zone = params[:zone]
    noverify = (params[:noverify] == 1) # TODO this is unused atm
    offset_ms = params[:offset_ms].to_i
    offset_ms >= 0 && offset_ms <= MAX_OFFSET or raise MogileFS::Backend::UnknownKeyError
    dmid = get_dmid(params[:domain])
    devices = refresh_device or raise MogileFS::Backend::NoDevicesError
    urls = []
    quoted_key = if (offset_ms >= MAX_GOP_LEN) 
      # Это место точно в этой минуте, куда ж деватьcя?
      @my.quote(params[:key])
    else 
      # Здесь в теории возможны рейсы, НО
      #   1) оффсет прописывается один раз
      #   2) оффсет прописывается до закачки файла
      quoted_key = @my.quote(params[:key])
      sql = <<-EOS
      SELECT beginning_offset FROM file_offset
      WHERE dmid = #{dmid} AND dkey = '#{quoted_key}'
      LIMIT 1
      EOS

      res = query(sql).fetch_row
      minute_beginning = (res && res[0].to_i) || 0

      if minute_beginning <= offset_ms
        quoted_key
      else
        @my.quote(params[:prev_key])
      end
    end

    sql = <<-EOS
    SELECT fid FROM file
    WHERE dmid = #{dmid} AND dkey = '#{quoted_key}'
    LIMIT 1
    EOS

    res = query(sql).fetch_row
    res && res[0] or raise MogileFS::Backend::UnknownKeyError
    fid = res[0]

    sql = "SELECT devid FROM file_on WHERE fid = '#{@my.quote(fid)}'"
    query(sql).each do |devid,|
      unless devinfo = devices[devid.to_i]
        devices = refresh_device(true)
        devinfo = devices[devid.to_i] or next
      end
      devinfo[:readable] or next
      port = devinfo[:http_get_port]
      host = zone && zone == 'alt' ? devinfo[:altip] : devinfo[:hostip]
      uri = uri_for(devid, fid)
      urls << "http://#{host}:#{port}#{uri}"
    end
    urls
  end

  def sleep(params); Kernel.sleep(params[:duration] || 10); {}; end

  private

    unless defined? GET_DEVICES
      GET_DOMAINS = 'SELECT dmid,namespace FROM domain'.freeze
      GET_CLASSES = 'SELECT dmid, classid, classname FROM class'.freeze

      GET_DEVICES = <<-EOS
        SELECT d.devid, h.hostip, h.altip, h.http_port, h.http_get_port,
          d.status, h.status
        FROM device d
          LEFT JOIN host h ON d.hostid = h.hostid
      EOS
    end

    def query(sql)
      if debug
        puts sql
      end
      @my.send(@query_method, sql)
    end

    DEV_STATUS_READABLE = {
      "alive" => true,
      "readonly" => true,
      "drain" => true,
    }.freeze

    def refresh_device(force = false)
      return @cache_device if ! force && ((Time.now - @last_update_device) < 60)
      tmp = {}
      res = query(GET_DEVICES)
      res.each do |devid, hostip, altip, http_port, http_get_port,
                   dev_status, host_status|
        http_port = http_port ? http_port.to_i : 80
        tmp[devid.to_i] = {
          :hostip => hostip.freeze,
          :altip => (altip || hostip).freeze,
          :readable => (host_status == "alive" &&
                        DEV_STATUS_READABLE.include?(dev_status)),
          :http_port => http_port,
          :http_get_port => http_get_port ?  http_get_port.to_i : http_port,
        }.freeze
      end
      @last_update_device = Time.now
      @cache_device = tmp.freeze
    end

    def refresh_domain(force = false)
      return @cache_domain if ! force && ((Time.now - @last_update_domain) < 5)
      tmp = {}
      res = query(GET_DOMAINS)
      res.each { |dmid,namespace| tmp[namespace] = dmid.to_i }
      @last_update_domain = Time.now
      @cache_domain = tmp.freeze
    end

    def refresh_class(force = false)
      return @cache_class if ! force && ((Time.now - @last_update_class) < 5)
      tmp = {}
      res = query(GET_CLASSES)
      res.each do |dmid,classid,classname| 
        tmp[dmid.to_i] = {} unless tmp.include?(dmid.to_i)
        tmp[dmid.to_i][classname] = classid.to_i
      end
      @last_update_class = Time.now
      @cache_class = tmp.freeze
    end

    def get_dmid(domain)
      refresh_domain[domain] || refresh_domain(true)[domain] or \
        raise MogileFS::Backend::DomainNotFoundError, domain
    end

    def get_classid(domain, classname)
      dmid = get_dmid(domain)
      refresh_class[dmid][classname] || refresh_class(true)[dmid][classname] or \
        raise MogileFS::Backend::ClassNotFoundError, "#{domain}:#{classname}"
    rescue NoMethodError
      raise MogileFS::Backend::ClassNotFoundError, "#{domain}:#{classname}"
    end

end
