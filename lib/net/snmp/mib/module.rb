# Ruby api to the Wrapper::Module class (represents netsnmp's `struct module`)

module Net::SNMP
  class Module
    extend Forwardable
    def_delegators :struct, :modid, :no_imports

    # Gets a module node by its id
    def self.find(module_id)
      if module_id < 0
        nil
      else
        new(Wrapper.find_module(module_id))
      end
    end

    def initialize(struct)
      raise "Tried to initialize null module" if struct.null?
      @struct = struct
    end

    def name
      @struct.name.read_string
    end

    def file
      @struct.file.read_string
    end

    def next
      if @struct.next.null?
        nil
      else
        self.class.new(@struct.next)
      end
    end

  end
end
