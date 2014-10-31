# TODO: This is segfaulting... a lot
# require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
#
# describe "async" do
#   context "version 1" do
#     it "get should work" do
#       pending "Segfaulting too much"
#       did_callback = false
#       sess = Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic') do |s|
#         s.get(["sysDescr.0", "sysContact.0"]) do |op, pdu|
#           did_callback = true
#           pdu.varbinds[0].value.should eql("test.net-snmp.org")
#           pdu.varbinds[1].value.should match(/Coders/)
#         end
#       end
#       Net::SNMP::Dispatcher.select(false)
#       did_callback.should be(true)
#     end
#
#     it "get should return an error" do
#       # TODO Works when it isn't segfaulting... which is often
#       pending "Segfaulting too much"
#       Net::SNMP.thread_safe = true
#       did_callback = false
#       sess = Net::SNMP::Session.open(:peername => 'www.yahoo.com', :timeout => 1, :retries => 0) do |sess|
#         sess.get("sysDescr.0") do |op, pdu|
#           did_callback = true
#           op.should eql(:timeout)
#         end
#       end
#       sleep 2
#       pdu = sess.select(10)
#
#       pdu.should eql(0)
#       did_callback.should eq(true)
#       Net::SNMP.thread_safe = false
#     end
#
#     it "getnext should work" do
#       pending "Segfaulting too much"
#       did_callback = false
#       Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic') do |s|
#         s.get_next(["sysDescr", "sysContact"]) do |op, pdu|
#           did_callback = true
#           pdu.varbinds[0].value.should eql("test.net-snmp.org")
#           pdu.varbinds[1].value.should match(/Coders/)
#         end
#       end
#       Net::SNMP::Dispatcher.select(false)
#       did_callback.should be(true)
#     end
#   end
#
#   context "version 2" do
#     it "get should work" do
#       pending "Segfaulting too much"
#       did_callback = false
#       Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic', :version => '2c') do |s|
#         s.get(["sysDescr.0", "sysContact.0"]) do |op, pdu|
#           did_callback = true
#           pdu.varbinds[0].value.should eql("test.net-snmp.org")
#           pdu.varbinds[1].value.should match(/Coders/)
#         end
#       end
#       Net::SNMP::Dispatcher.select(false)
#       did_callback.should be(true)
#     end
#
#     it "getnext should work" do
#       pending "Segfaulting too much"
#       did_callback = false
#       Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic', :version => '2c') do |s|
#         s.get_next(["sysDescr", "sysContact"]) do |op, pdu|
#           did_callback = true
#           pdu.varbinds[0].value.should eql("test.net-snmp.org")
#           pdu.varbinds[1].value.should match(/Coders/)
#         end
#       end
#       Net::SNMP::Dispatcher.select(false)
#       did_callback.should be(true)
#     end
#
#   end
#
#   context "version 3" do
#     #failing intermittently
#     it "should get async using snmpv3" do
#       pending "Segfaulting too much"
#       did_callback = false
#       Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :version => 3, :username => 'MD5User',:security_level => Net::SNMP::Constants::SNMP_SEC_LEVEL_AUTHNOPRIV, :auth_protocol => :md5, :password => 'The Net-SNMP Demo Password') do |sess|
#           sess.get(["sysDescr.0"]) do |op, pdu|
#             did_callback = true
#             pdu.varbinds[0].value.should eql('test.net-snmp.org')
#           end
#           sleep(0.5)
#           Net::SNMP::Dispatcher.select(false)
#           #Net::SNMP::Dispatcher.select(false)
#           #puts "done select"
#           did_callback.should be(true)
#       end
#     end
#
#     it "get should work" do
#       pending "Segfaulting too much"
#       did_callback = false
#       sess = Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :version => 3, :username => 'MD5User',:security_level => Net::SNMP::Constants::SNMP_SEC_LEVEL_AUTHNOPRIV, :auth_protocol => :md5, :password => 'The Net-SNMP Demo Password') do |sess|
#         sess.get(["sysDescr.0", "sysContact.0"]) do |op,pdu|
#           did_callback = true
#           pdu.varbinds[0].value.should eql("test.net-snmp.org")
#           pdu.varbinds[1].value.should match(/Coders/)
#         end
#       end
#       Net::SNMP::Dispatcher.select(false)
#       sess.close
#       did_callback.should be(true)
#     end
#
#     #  XXX  occasionally segfaulting
#     it "getnext should work" do
#       pending "Segfaulting too much"
#       did_callback = false
#
#       sess = Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :version => 3, :username => 'MD5User',:security_level => Net::SNMP::Constants::SNMP_SEC_LEVEL_AUTHNOPRIV, :auth_protocol => :md5, :password => 'The Net-SNMP Demo Password') do |sess|
#         sess.get_next(["sysDescr", "sysContact"]) do |op, pdu|
#           did_callback = true
#           pdu.varbinds[0].value.should eql("test.net-snmp.org")
#           pdu.varbinds[1].value.should match(/Coders/)
#         end
#       end
#       Net::SNMP::Dispatcher.select(false)
#       sess.close
#       did_callback.should be(true)
#     end
#   end
# end
