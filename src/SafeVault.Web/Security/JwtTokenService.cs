using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace SafeVault.Web.Security;

public class JwtTokenService
{
    private readonly SymmetricSecurityKey _signingKey;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly TimeSpan _lifetime;

    public JwtTokenService(byte[] signingKeyBytes, string issuer, string audience, TimeSpan lifetime)
    {
        _signingKey = new SymmetricSecurityKey(signingKeyBytes);
        _issuer = issuer;
        _audience = audience;
        _lifetime = lifetime;
    }

    public string IssueToken(string username, string role)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Role, role),
        };

        var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            expires: DateTime.UtcNow.Add(_lifetime),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
