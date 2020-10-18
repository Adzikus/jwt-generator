using System.Security.Cryptography;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace JwtGenerator
{
    public class Generator
    {
        #region private fields
        private readonly JwtGeneratorSettings _settings;

        #endregion

        public Generator(JwtGeneratorSettings settings)
        {
            _settings = settings;
        }

        public string CreateToken(SignType signMethod, Claim[] claims)
        {
            var token = string.Empty;
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = PreparteTokenDescriptor(claims);

            switch (signMethod)
            {
                case SignType.EDCSA:
                    tokenDescriptor.SigningCredentials = SignEDCSA();
                    break;
                case SignType.RSA:
                    tokenDescriptor.SigningCredentials = SignRSA();
                    break;
                default:
                    return token;
            }

            var secToken = tokenHandler.CreateToken(tokenDescriptor);
            token = tokenHandler.WriteToken(secToken);

            return token;
        }

        private SecurityTokenDescriptor PreparteTokenDescriptor(Claim[] claims)
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = string.IsNullOrEmpty(_settings.Issuer) ? "Unknown" : _settings.Issuer,
                Subject = new ClaimsIdentity(claims),
                Expires = _settings.TokenLifetime == TimeSpan.Zero ? DateTime.UtcNow.AddDays(7) : DateTime.UtcNow + _settings.TokenLifetime,
            };
            return tokenDescriptor;
        }

        private SigningCredentials SignEDCSA()
        {
            return new SigningCredentials(new ECDsaSecurityKey(LoadPrivateKey(_settings.EDCsaPrivateKeyPath)), SecurityAlgorithms.EcdsaSha256);
        }

        private SigningCredentials SignRSA()
        {
            var rsaParams = GetRsaParameters(File.ReadAllText(_settings.RSAPrivateKeyPath));
            return new SigningCredentials(new RsaSecurityKey(rsaParams), SecurityAlgorithms.RsaSha256);
        }

        private static ECDsa LoadPrivateKey(string privateKey)
        {
            var ecdsa = new ECDsaCng()
            {
                HashAlgorithm = CngAlgorithm.ECDsaP256
            };
            ecdsa.ImportECPrivateKey(File.ReadAllBytes(privateKey), out _);

            return ecdsa;
        }

        private static RSAParameters GetRsaParameters(string rsaPrivateKey)
        {
            var byteArray = Encoding.ASCII.GetBytes(rsaPrivateKey);
            using var ms = new MemoryStream(byteArray);
            using var sr = new StreamReader(ms);

            // use Bouncy Castle to convert the private key to RSA parameters
            var pemReader = new PemReader(sr);
            var keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
            return DotNetUtilities.ToRSAParameters(keyPair.Private as RsaPrivateCrtKeyParameters);
        }
    }
}
