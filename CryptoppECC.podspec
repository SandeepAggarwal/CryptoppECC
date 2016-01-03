
Pod::Spec.new do |s|

  s.name         = "CryptoppECC"
  s.version      = "1.0.0"
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
  s.osx.deployment_target = "10.10"
  s.osx.xcconfig =
  {
   'OTHER_LDFLAGS' => '-lc++'
  }
  s.prepare_command=<<-CMD
                        sh CryptoppECC/CryptoppLibrary/builder.sh
                        CMD

  s.source       = { :git => "https://github.com/SandeepAggarwal/CryptoppECC.git", :tag =>"1.0.0" }
  s.source_files  = "CryptoppECC/CryptoppLibrary/*.h", "CryptoppECC/CryptoppWrapper/*.{h,mm}"
  s.public_header_files = "CryptoppECC/CryptoppWrapper/*.h"
  s.osx.vendored_library ="CryptoppECC/CryptoppLibrary/bin/macosx/libcryptopp.a"
  s.ios.vendored_library ="CryptoppECC/CryptoppLibrary/bin/ios/libcryptopp.a"
  s.prefix_header_file ="CryptoppECC/cryptodemolib.pch"

  s.requires_arc = true

end
