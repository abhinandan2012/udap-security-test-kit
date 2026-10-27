require_relative 'lib/udap_security_test_kit/version'

Gem::Specification.new do |spec|
  spec.name          = 'udap_security_test_kit'
  spec.version       = UDAPSecurityTestKit::VERSION
  spec.authors       = ['Stephen MacVicar', 'Alisa Wallace']
  spec.email         = ['inferno@groups.mitre.org']
  spec.summary       = 'UDAP Security IG Test Kit'
  spec.description   = 'UDAP Security IG Test Kit'
  spec.homepage      = 'https://github.com/inferno-framework/udap-security-test-kit'
  spec.license       = 'Apache-2.0'
  spec.add_dependency 'inferno_core', '~> 1.4', '>= 1.4.3'
  spec.add_dependency 'jwt', '~> 3.2'
  spec.required_ruby_version = Gem::Requirement.new('>= 3.3.6')
  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/inferno-framework/udap-security-test-kit'
  spec.metadata['inferno_test_kit'] = 'true'
  spec.files         = `[ -d .git ] && git ls-files -z lib config/presets LICENSE`.split("\x0")

  spec.require_paths = ['lib']
end
