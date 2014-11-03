# RequestContext class implements a DSL for handling requests in a Provider

module Net::SNMP
  class RequestContext
    include Debug

    def initialize
      @variable_index = 1
    end

    # Getters
    # -------

    # Notes:
    # - `varbind` is the current varbind. The RequestDispatcher
    #   resets this value for each varbind in the request, then
    #   execs the approriate provider's handler for that varbind
    #   in the context of this RequestContext object.

    attr_accessor :message, :varbind, :response_pdu

    def pdu
      message.pdu
    end

    def oid
      varbind.oid
    end

    def oid_str
      varbind.oid.to_s
    end

    def value
      varbind.value
    end

    # Setters
    # -------

    # Used to set a varbind on the response packet.
    # - If a hash is supplied, accepts the same options as
    #   PDU#add_varbind, except that if no oid is supplied,
    #   the oid from the current varbind is used.
    # - If the argument is not a hash, it is used as the value of the
    #   varbind, with the current varbind's oid, and the type is derived
    #   as with PDU#add_varbind
    def reply(varbind_options)
      if varbind_options.kind_of?(Hash)
        varbind_options[:oid] ||= varbind.oid
        add_varbind(varbind_options)
      else
        add_varbind(oid: varbind.oid, value: varbind_options)
      end
    end

    # add is more natural in a get_bulk
    alias add reply

    # Adds a copy of the current varbind to the response packet
    # Useful in a set, to indicate success to the manager
    def echo
      add_varbind(oid: varbind.oid, type: varbind.type, value: varbind.value)
    end

    # ok... saves two characters.
    alias ok echo

    # Adds a varbind to the response indicating that no such object
    # exists at the given oid. If no oid is supplied, or if oid is nil,
    # then the oid from the current varbind is used.
    def no_such_object(oid=nil)
      oid ||= varbind.oid
      add_varbind(oid: oid, type: Constants::SNMP_NOSUCHOBJECT)
    end

    # Adds a varbind to the response indicating that no such instance
    # exists at the given oid. If no oid is supplied, or if oid is nil,
    # then the oid from the current varbind is used.
    def no_such_instance(oid=nil)
      oid ||= varbind.oid
      add_varbind(oid: oid, type: Constants::SNMP_NOSUCHINSTANCE)
    end

    # Adds a varbind to the response PDU
    # MUST use this method (or one that delegates to it)
    # to set response varbinds on the response_pdu to make sure
    # the variable_index is maintained automatically.
    def add_varbind(options)
      response_pdu.add_varbind(options)
      @variable_index += 1
    end

    # Sets the error_status on the response pdu
    def error(the_error)
      response_pdu.error = the_error
      response_pdu.error_index = @variable_index
      # echo the varbind back to the manager so it can tell what object failed
      echo
    end
    alias errstat error
    alias error_status error

  end
end
