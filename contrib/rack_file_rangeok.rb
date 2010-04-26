require 'time'
require 'rack/utils'
require 'rack/mime'

# jme- modified version of rack::File to support range request
module Rack
  # Rack::File serves files below the +root+ given, according to the
  # path info of the Rack request.
  #
  # Handlers can detect if bodies are a Rack::File, and use mechanisms
  # like sendfile on the +path+.

  class FileRangeOk
    attr_accessor :root
    attr_accessor :path

    alias :to_path :path

    def initialize(root)
      @root = root
    end

    def call(env)
      dup._call(env)
    end

    F = ::File

    def _call(env)


      @path_info = Utils.unescape(env["PATH_INFO"])
      return forbidden  if @path_info.include? ".."

      @path = F.join(@root, @path_info)

	# determine @requested_off/@requested_len
	# - jme modification
	@http_range	= env['HTTP_RANGE']
	if env['HTTP_RANGE']
		matches		= @http_range.match(/bytes=(\d*)-(\d*)/)
		range_beg	= matches[1]
		range_end	= matches[2]		
		@requested_off	= range_beg.empty? ? 0			: range_beg.to_i
		requested_end	= range_end.empty? ? F.size?(@path)	: range_end.to_i
		@requested_len	= requested_end - @requested_off
	else
		@requested_off	= 0
		@requested_len	= F.size?(@path)
	end

      begin
        if F.file?(@path) && F.readable?(@path)
          serving
        else
          raise Errno::EPERM
        end
      rescue SystemCallError
        not_found
      end
    end

    def forbidden
      body = "Forbidden\n"
      [403, {"Content-Type" => "text/plain",
             "Content-Length" => body.size.to_s},
       [body]]
    end

    # NOTE:
    #   We check via File::size? whether this file provides size info
    #   via stat (e.g. /proc files often don't), otherwise we have to
    #   figure it out by reading the whole file into memory. And while
    #   we're at it we also use this as body then.

    def serving
      if size = F.size?(@path)
        body = self
      else
        body = [F.read(@path)]
        size = Utils.bytesize(body.first)
      end
      
	if @http_range.nil?
		[200, {
		  "Last-Modified"  => F.mtime(@path).httpdate,
		  "Content-Type"   => Mime.mime_type(F.extname(@path), 'text/plain'),
		  "Content-Length" => size.to_s
		}, body]
	else
		# return partial content
		[206, {
		  "Last-Modified"  => F.mtime(@path).httpdate,
		  "Content-Type"   => Mime.mime_type(F.extname(@path), 'text/plain'),
		  "Content-Length" => @requested_len.to_s,
		  "Content-Range"  => "#{@requested_off}-#{@requested_off+@requested_len-1}/#{@requested_off+@requested_len}"
		}, body]
	end
    end

    def not_found
      body = "File not found: #{@path_info}\n"
      [404, {"Content-Type" => "text/plain",
         "Content-Length" => body.size.to_s},
       [body]]
    end

    def each
	F.open(@path, "rb") { |file|
		file.seek(@requested_off)
		delivered_len	= 0
		while true
			remaining_len	= @requested_len-delivered_len
			len_to_read	= [8192, remaining_len].min
			part		= file.read(len_to_read)
			break unless part
			# update the delivered_len
			delivered_len	+= part.length
			
			yield part
			# break if ALL 
			break if delivered_len == @requested_len
		end
	}
    end
  end
end
