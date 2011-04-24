# -*- encoding: utf-8 -*-
lib = File.expand_path("../lib", __FILE__)
$:.unshift lib
#require 'net/snmp/version'

Gem::Specification.new do |s|
  s.name        = "net-snmp"
  s.version     = '0.1.5'
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Ron McClain"]
  s.email       = ["mixtli@github.com"]
  s.homepage    = ""
  s.summary     = %q{Object oriented wrapper around C net-snmp libraries}
  s.description = %q{Uses ffi to create an object oriented wrapper around C net-snmp libraries}

  s.rubyforge_project = "net-snmp"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
  s.add_development_dependency "rspec"
  s.add_development_dependency "eventmachine"
  #s.add_dependency "nice-ffi"
end
