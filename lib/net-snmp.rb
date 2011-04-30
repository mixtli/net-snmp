require 'forwardable'
require 'nice-ffi'
require 'fiber'
require 'ffi-inliner'
#require 'ffi/libc'
%w( snmp snmp/debug snmp/wrapper snmp/version snmp/inline snmp/constants snmp/utility snmp/oid snmp/error snmp/pdu snmp/session snmp/trap_session snmp/varbind snmp/mib snmp/mib/node snmp/dispatcher).each do |f|
  require "#{File.dirname(__FILE__)}/net/#{f}"
end



Net::SNMP::MIB.init
Net::SNMP::MIB.read_all_mibs
Net::SNMP.init



#  XXX
#  I just monkeypatched this to take a nil first argument.  Seems to work
#  Should probably submit this as a patch

class NiceFFI::Struct < FFI::Struct
  def initialize( val = nil, options={} )
    # Stores certain kinds of member values so that we don't need
    # to create a new object every time they are read.
    @member_cache = {}

    options = {:autorelease => true}.merge!( options )

    case val

    when Hash
      super(FFI::Buffer.new(size))
      init_from_hash( val )         # Read the values from a Hash.

    # Note: plain "Array" would mean FFI::Struct::Array in this scope.
    when ::Array
      super(FFI::Buffer.new(size))
      init_from_array( val )        # Read the values from an Array.

    when String
      super(FFI::Buffer.new(size))
      init_from_bytes( val )        # Read the values from a bytestring.

    when self.class
      super(FFI::Buffer.new(size))
      init_from_bytes( val.to_bytes ) # Read the values from another instance.

    when FFI::Pointer, FFI::Buffer
      val = _make_autopointer( val, options[:autorelease] )

      # Normal FFI::Struct behavior to wrap the pointer.
      super( val )

    when nil
      super(val)
    else
      raise TypeError, "cannot create new #{self.class} from #{val.inspect}"

    end
  end
end
