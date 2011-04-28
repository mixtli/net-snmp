module Net::SNMP::Utility
  def self.oid_lex_cmp(a,b)
    [a,b].each do |i|
      i.sub!(/^\./,'')
      i.gsub!(/ /, '.0')
      i.replace(i.split('.').map(&:to_i).pack('N*'))
    end
    a <=> b
  end
end
