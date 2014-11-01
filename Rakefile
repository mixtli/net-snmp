require 'bundler'
Bundler::GemHelper.install_tasks


task :console do
  require 'irb'
  require 'irb/completion'
  $: << 'lib'
  require 'net-snmp'
  Net::SNMP.init
  include Net::SNMP
  ARGV.clear
  IRB.start
end
