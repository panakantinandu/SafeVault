// Tests/TestInputValidation.cs
using NUnit.Framework;
using SafeVault.Web.Validation;

namespace SafeVault.Tests;

[TestFixture]
public class TestInputValidation
{
    private static readonly string[] SqlInjectionPayloads =
    {
        "admin' --",
        "' OR '1'='1",
        "'; DROP TABLE Users; --",
        "1; SELECT * FROM Users",
        "' UNION SELECT Username, Password FROM Users --"
    };

    private static readonly string[] XssPayloads =
    {
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>",
        "javascript:alert('xss')",
        "<a href=\"javascript:alert(1)\">click</a>"
    };

    [TestCaseSource(nameof(SqlInjectionPayloads))]
    public void TestForSQLInjection_UsernameRejectsPayload(string payload)
    {
        Assert.That(InputValidator.IsValidUsername(payload), Is.False,
            $"SQL injection payload should be rejected by username validation: {payload}");
    }

    [TestCaseSource(nameof(SqlInjectionPayloads))]
    public void TestForSQLInjection_EmailRejectsPayload(string payload)
    {
        Assert.That(InputValidator.IsValidEmail(payload), Is.False,
            $"SQL injection payload should be rejected by email validation: {payload}");
    }

    [TestCaseSource(nameof(XssPayloads))]
    public void TestForXSS_UsernameRejectsPayload(string payload)
    {
        Assert.That(InputValidator.IsValidUsername(payload), Is.False,
            $"XSS payload should be rejected by username validation: {payload}");
    }

    [TestCaseSource(nameof(XssPayloads))]
    public void TestForXSS_EncodingNeutralizesPayload(string payload)
    {
        var encoded = InputValidator.EncodeForHtml(payload);

        Assert.That(encoded, Does.Not.Contain("<script"));
        Assert.That(encoded, Does.Not.Contain("<img"));
        Assert.That(encoded, Does.Not.Contain("<svg"));
        Assert.That(encoded, Does.Not.Contain("<a "));
    }

    [TestCase("nandu_p")]
    [TestCase("nandu-99")]
    [TestCase("a.b.c")]
    public void ValidUsernames_AreAccepted(string username)
    {
        Assert.That(InputValidator.IsValidUsername(username), Is.True);
    }

    [TestCase("nandupanakanti@gmail.com")]
    [TestCase("user.name+tag@example.co")]
    public void ValidEmails_AreAccepted(string email)
    {
        Assert.That(InputValidator.IsValidEmail(email), Is.True);
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase(null)]
    [TestCase("ab")]
    public void InvalidUsernames_AreRejected(string? username)
    {
        Assert.That(InputValidator.IsValidUsername(username), Is.False);
    }

    [TestCase("")]
    [TestCase("not-an-email")]
    [TestCase(null)]
    [TestCase("missing-at-sign.com")]
    public void InvalidEmails_AreRejected(string? email)
    {
        Assert.That(InputValidator.IsValidEmail(email), Is.False);
    }

    [TestCase("Str0ngPassw0rd!")]
    [TestCase("exactly8")]
    public void ValidPasswords_AreAccepted(string password)
    {
        Assert.That(InputValidator.IsValidPassword(password), Is.True);
    }

    [TestCase("")]
    [TestCase("short1")]
    [TestCase(null)]
    public void InvalidPasswords_AreRejected(string? password)
    {
        Assert.That(InputValidator.IsValidPassword(password), Is.False);
    }

    [TestCaseSource(nameof(SqlInjectionPayloads))]
    public void SanitizeUsername_StripsSqlMetacharacters(string payload)
    {
        var sanitized = InputValidator.SanitizeUsername(payload);

        Assert.That(sanitized, Does.Not.Contain("'"));
        Assert.That(sanitized, Does.Not.Contain(";"));
        Assert.That(sanitized, Does.Not.Contain(" "));
    }

    [TestCaseSource(nameof(XssPayloads))]
    public void SanitizeUsername_StripsScriptSyntax(string payload)
    {
        var sanitized = InputValidator.SanitizeUsername(payload);

        Assert.That(sanitized, Does.Not.Contain("<"));
        Assert.That(sanitized, Does.Not.Contain(">"));
        Assert.That(sanitized, Does.Not.Contain("\""));
    }

    [Test]
    public void SanitizeUsername_PreservesAllowedCharacters()
    {
        Assert.That(InputValidator.SanitizeUsername("nandu_p-99.x"), Is.EqualTo("nandu_p-99.x"));
    }

    [TestCaseSource(nameof(SqlInjectionPayloads))]
    public void SanitizeSearchTerm_StripsSqlMetacharacters(string payload)
    {
        var sanitized = InputValidator.SanitizeSearchTerm(payload);

        Assert.That(sanitized, Does.Not.Contain("'"));
        Assert.That(sanitized, Does.Not.Contain(";"));
        Assert.That(sanitized, Does.Not.Contain("="));
    }
}
