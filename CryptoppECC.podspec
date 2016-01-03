
Pod::Spec.new do |s|

  s.name         = "CryptoppECC"
  s.version      = "0.0.1"
  s.summary      = "CryptoppECC-Encryption/Decryption using ECC(Elliptic curve cryptography)"


  s.description  = <<-DESC
                CryptoppECC-Encryption/Decryption using ECC(Elliptic curve cryptography)
                *Contains functions for encryption,decryption using ECC and verify a signed certificate using ECDSA.

                *Using https://groups.google.com/forum/#!topic/cryptopp-users/LvIfAP4llx4 made a patch for compatibility with Bouncy Castle.

                *Also took help from https://github.com/3ign0n/CryptoPP-for-iOS for calculating Hash.
                   DESC

  s.homepage     = "https://github.com/SandeepAggarwal/CryptoppECC"
  s.license      = { :type => "MIT", :file => "LICENSE.txt" }

  s.author             = { "Sandeep Aggarwal" => "smartSandeep1129@gmail.com" }
  s.social_media_url   = "https://twitter.com/sandeepCool77"
  s.ios.deployment_target = "7.0"
  s.osx.deployment_target = "10.8"
  s.prepare_command= "sudo sh CryptoppECC/CryptoppLibrary/builder.sh"

  s.source       = { :git => "https://github.com/SandeepAggarwal/CryptoppECC.git", :commit => "34a8441d5c89f63a93b49c8250695c36b7bb82ce" }
  s.source_files  = "CryptoppECC/CryptoppLibrary/*.h", "CryptoppECC/CryptoppWrapper/*.{h,mm}"
  s.public_header_files = "CryptoppECC/CryptoppWrapper/*.h"
  s.vendored_library ="CryptoppECC/CryptoppLibrary/bin/libcryptopp.a"
  s.prefix_header_file ="CryptoppECC/cryptodemolib.pch"

    s.osx.xcconfig =
    {
    'OTHER_LDFLAGS' => '-lc++'
    }


  s.requires_arc = true

end
