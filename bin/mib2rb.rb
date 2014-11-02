$: << '../lib'
require 'net-snmp'
require 'optparse'
require 'erb'
require 'logger'

Net::SNMP.init

default_template = '
<% nodes.each do |node| -%>
<%= node.module.nil? ? "" : "#{node.module.name}::" %><%= node.label %>
  - oid:       <%= node.oid %>
  - type:      <%= node.type %>
  - file:      <%= node.module.file unless node.module.nil? %>
  - descr:     <%= node.description %>
  - enums:     <%= node.enums.map { |e| "#{e[:label]}(#{e[:value]})" }.join(", ") %>
  - parent:    <%= node.parent.oid unless node.parent.nil? %>
  - peers:     <%= node.peers.map { |n| "#{n.label}(#{n.subid})"}.join(", ") %>
  - next:      <%= node.next.oid unless node.next.nil? %>
  - next_peer: <%= node.next_peer.oid unless node.next_peer.nil? %>
  - children:  <%= node.children.map { |n| "#{n.label}(#{n.subid})"}.join(", ") %>
<% end -%>
'.sub!("\n", "") # Remove leading newline

json_template = '
[
<% nodes.each_with_index { |node, index| -%>
<%= ",\n" if index > 0 -%>
  {
    "name": "<%= node.module.nil? ? "" : "#{node.module.name}::" %><%= node.label %>",
    "oid": "<%= node.oid %>",
    "type": <%= node.type %>,
<% if node.enums && node.enums.count > 0 -%>
    "enums": { <%= node.enums.map { |enum| "\"#{enum[:label]}\": #{enum[:value]}" }.join(", ") %> },
<% end -%>
    "parent": <%= node.parent ? %Q["#{node.parent.oid}"] : "undefined" %>
  }<% } -%>

]
'.sub!("\n", "")

usage = <<USAGE
Usage: mib2rb [OPTION]... ROOT_NODE [ERB_FILE]

Description
  Prints a mib subtree according to the ERB_FILE.
  Within the ERB file, the `root` variable contains the
  Net::SNMP::Node object corresponding to ROOT_NODE, and
  `nodes` is a collection of the root & all descendants.

Options
  -h,          Prints this usage information.

               Aliases:   --help

  -l LEVEL     Set the log level.
               Logs are piped to STDERR, so you can redirect
               STDOUT to a file without worrying about logs
               getting into the output.

               Values:   debug, info, warn, error, fatal, none
               Default:  none
               Aliases:  --log-level

  -f FORMAT    Select the output format.
               If this option is supplied with an ERB file,
               the option is ignored and the file is used instead.

               Values:   [d]efault, [j]son
               Default:  default
               Aliases:  --format

Arguments
  ROOT_NODE    [Required] The root node of the mib tree to translate.
               May be specified as numeric oid or mib name.

  ERB_FILE     [Optional] The template file to use for output.

               Default:  Builtin template specifying human readable output.
                         (See below)

Default ERB_FILE Template:

#{default_template.each_line.map { |l| "  #{l}" }.join}

USAGE

root_node = nil
erb_template = nil

optparse = OptionParser.new do|opts|
  opts.on( '-h', '--help') do
    puts usage
    exit
  end

  opts.on('-l', '--log-level LEVEL') do |level|
    break if level =~ /none/i

    Net::SNMP::Debug.logger = Logger.new(STDERR)
    Net::SNMP::Debug.logger.level = case level
      when /debug/i
        Logger::DEBUG
      when /info/i
        Logger::INFO
      when /warn/i
        Logger::WARN
      when /error/i
        Logger::ERROR
      when /fatal/i
        Logger::FATAL
      else
        puts "Invalid log level: #{level}"
        puts
        puts usage
        exit(1)
    end
  end

  opts.on('-f', '--format FORMAT') do |format|
    case format
    when /^d(efault)?$/i
      erb_template = default_template
    when /^j(son)?$/i
      erb_template = json_template
    else
      puts "Invalid format: #{format}"
      puts
      puts usage
      exit(1)
    end
  end

end
optparse.parse!

case ARGV.length
when 1
  root_node = Net::SNMP::MIB.get_node(ARGV[0])
  # If format wasn't set by -f option, default it here
  erb_template ||= default_template
when 2
  root_node = Net::SNMP::MIB.get_node(ARGV[0])
  erb_template = File.read(ARGV[1])
else
  puts "Invalid arguments..."
  puts
  puts usage
  exit(1)
end

def render(node, erb_template)
  root = node
  nodes = [root] + root.descendants.to_a
  erb = ERB.new(erb_template, nil, '-')
  puts erb.result binding
end

render(root_node, erb_template)
