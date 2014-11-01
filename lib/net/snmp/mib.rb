Net::SNMP::Wrapper.snmp_set_save_descriptions(1)
module Net
  module SNMP
    module MIB
=begin
      ENVIRONMENT VARIABLES

      The main use of environmental variables with respect to these API calls is to configure which MIB modules should be loaded, and where they are located.

      MIBDIRS
      A colon separated list of directories to search for MIB modules.
      Default: /usr/local/share/snmp/mibs
      Used by init_mib, netsnmp_read_module, read_all_mibs and (implicitly) by read_mib.

      MIBS
      A colon separated list of MIB modules to load.
      The default list of modules will depend on how the Net-SNMP software was originally compiled, but is typically: IP-MIB:IF-MIB:TCP-MIB:UDP-MIB:SNMPv2-MIB:RFC1213-MIB:UCD-SNMP-MIB:HOST-RESOURCES-MIB
      If the value of the MIBS environmental variable starts with a '+' character, then these MIB modules will be added to the default list. Otherwise these modules (plus any that they IMPORT from) will be loaded instead of the default list.
      If the MIBS environmental variable has the value ALL then read_all_mibs will be called to load the full collection of all available MIB modules.
      Used by init_mib only.

      MIBFILES
      A colon separated list of files to load.
      Default: (none)
      Used by init_mib only.
=end

      # Configures the MIB directory search path (using add_mibdir ), sets up the internal
      # MIB framework, and then loads the appropriate MIB modules (using netsnmp_read_module
      # and  read_mib). It should be called before any other routine that manipulates
      # or accesses the MIB tree (but after any additional add_mibdir calls).
      def self.init
        Wrapper.netsnmp_init_mib
      end

      # Read in all the MIB modules found on the MIB directory search list
      def self.read_all_mibs
        Wrapper.read_all_mibs
      end

      def self.get_node(oid)
        Node.get_node(oid)
      end

      # Add the specified directory to the path of locations which are searched
      # for files containing MIB modules. Note that this does not actually load
      # the MIB modules located in that directory
      def self.add_mibdir(dirname)
        Wrapper.add_mibdir(dirname)
      end

      # Takes the name of a MIB module (which need not be the same as the name
      # of the file that contains the module), locates this within the configured
      # list of MIB directories, and loads the definitions from the module into
      # the active MIB tree. It also loads any MIB modules listed in the IMPORTS
      # clause of this module.
      def self.read_module(name)
        Wrapper.netsnmp_read_module(name)
      end

      # Similar to read_module, but takes the name of the file containing the MIB
      # module. Note that this file need not be located within the MIB directory
      # search list (although any modules listed in the IMPORTS clause do).
      def self.read_mib(filename)
        Wrapper.read_mib(filename)
      end
    end
  end
end
