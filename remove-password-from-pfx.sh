PASSWORD_PFX=isopoh.pfx
NO_PASSWORD_PFX=isopoh-nopass.pfx
echo extract certificate
openssl pkcs12 -clcerts -nokeys -in ${PASSWORD_PFX} -out x.${PASSWORD_PFX}.certificate.crt
echo extract ca certificate
openssl pkcs12 -cacerts -nokeys -in ${PASSWORD_PFX} -out x.${PASSWORD_PFX}.ca-cert.ca
echo extract key
openssl pkcs12 -nocerts -in ${PASSWORD_PFX} -out x.${PASSWORD_PFX}.private.key -passout pass:TemporaryPassword
echo strip password
openssl rsa -in x.${PASSWORD_PFX}.private.key -out x.${PASSWORD_PFX}.nopass.private.key -passin pass:TemporaryPassword
echo pem in
cat x.${PASSWORD_PFX}.nopass.private.key x.${PASSWORD_PFX}.certificate.crt x.${PASSWORD_PFX}.ca-cert.ca > x.${PASSWORD_PFX}.pfx-in.pem
echo pfx out
openssl pkcs12 -export -nodes -CAfile x.${PASSWORD_PFX}.ca-cert.ca -in x.${PASSWORD_PFX}.pfx-in.pem -passin pass:TemporaryPassword -passout pass:"" -out ${NO_PASSWORD_PFX}
echo cleanup
rm x.${PASSWORD_PFX}.*
