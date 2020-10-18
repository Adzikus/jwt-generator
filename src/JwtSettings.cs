using System;
namespace JwtGenerator
{
    public class JwtGeneratorSettings
    {
        public string Issuer { get; set; }
        public TimeSpan TokenLifetime { get; set; }
        public string EDCsaPrivateKeyPath { get; set; }
        public string RSAPrivateKeyPath { get; set; }
    }
}