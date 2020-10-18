using Xunit;
using JwtGenerator;
using System.Collections.Generic;
using System.Security.Claims;

namespace jwtGenerator.test
{
    public class TokenTest
    {
        [Fact]
        public void GenerateRSAToken()
        {
            var generator = new Generator(new JwtGeneratorSettings
            {
                RSAPrivateKeyPath = @"..\..\..\keys\privatekey.pem"
            });

            var claims = new List<Claim>
            {
                new Claim("algorytm", "RSA"),
                new Claim("claim2", "value2"),
                new Claim("claim3", "value3")
            };

            string token = generator.CreateToken(SignType.RSA, claims.ToArray());

            Assert.NotEmpty(token);
        }

        [Fact]
        public void GenerateECDsaToken()
        {
            //Given
            var generator = new Generator(new JwtGeneratorSettings
            {
                EDCsaPrivateKeyPath = @"..\..\..\keys\ecdsa\es256-private.der"
            });

            var claims = new List<Claim>
            {
                new Claim("algorytm", "ECDsa"),
                new Claim("claim2", "value2"),
                new Claim("claim3", "value3")
            };

            //When
            string token = generator.CreateToken(SignType.EDCSA, claims.ToArray());

            //Then
            Assert.NotEmpty(token);
        }
    }
}
